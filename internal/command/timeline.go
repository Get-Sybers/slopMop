package command

import (
	"slices"
	"strconv"
	"strings"

	"github.com/get-sybers/slopmop/internal/activity"
	"github.com/get-sybers/slopmop/internal/mitre"
	"github.com/get-sybers/slopmop/internal/render"
	"github.com/get-sybers/slopmop/internal/trace"
)

// fewPeriods is how many periods the timeline shows: of more, the first
// half and the last, since how a run began and how it ended say most.
const fewPeriods = 40

// period is a stretch of the timeline: the files, one after another, that
// show something and show no tactic the first of them does not.
type period struct {
	first, last trace.Step
	// tactics are those of the first file, in the order of the tactic table.
	tactics []string
	// techniques are those of the activities its files show, and hits the
	// watchlist matches.
	techniques
	hits []string
}

// techniques are the techniques some files show, each once, in the order it
// is first shown. Each has its parents: the tactics of the activities that
// show it, of those its framework files it under.
type techniques struct {
	attack, atlas []string
	parents       map[string][]string
}

// add takes in the techniques of an activity a file shows.
func (t *techniques) add(p pipeline, hit activity.Hit) {
	if t.parents == nil {
		t.parents = map[string][]string{}
	}
	for _, id := range hit.Attack {
		t.attack = appendUnique(t.attack, id)
		for _, name := range hit.Tactics {
			if slices.Contains(p.catalogue.Attack.TacticsOf(id), p.tactics.Attack(name)) {
				t.parents[id] = appendUnique(t.parents[id], name)
			}
		}
	}
	for _, id := range p.atlasOf(hit) {
		t.atlas = appendUnique(t.atlas, id)
		for _, name := range hit.Tactics {
			if slices.Contains(p.catalogue.Atlas.TacticsOf(id), p.tactics.Atlas(name)) {
				t.parents[id] = appendUnique(t.parents[id], name)
			}
		}
	}
}

// periods cuts the timeline into its periods, and counts the files that are
// in none: a file that shows no tactic and no watchlist match tells nothing
// of what was done, however many of them there are.
func (w reportRun) periods() (all []period, quiet int) {
	order := w.pipe.tactics.Names()
	for _, s := range w.result.timeline.Steps {
		if len(s.Tactics) == 0 && len(s.IntelHits) == 0 {
			quiet++
			continue
		}
		// A period ends where a file shows a tactic its first file did not.
		begins := len(all) == 0 || slices.ContainsFunc(s.Tactics, func(name string) bool {
			return !slices.Contains(all[len(all)-1].tactics, name)
		})
		if begins {
			p := period{first: s}
			for _, name := range order {
				if slices.Contains(s.Tactics, name) {
					p.tactics = append(p.tactics, name)
				}
			}
			all = append(all, p)
		}
		p := &all[len(all)-1]
		p.last = s
		for _, a := range s.Activities {
			p.add(w.pipe, a)
		}
		for _, h := range s.IntelHits {
			p.hits = appendUnique(p.hits, h.Attribution+": "+h.Value)
		}
	}
	return all, quiet
}

// counted writes a number and the word for one of them or for more.
func counted(n int, one, more string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + more
}

// timeline is a line of blocks in the order of time: one for each intent
// where the files name intents, and one for each period otherwise. A block
// lists its tactics, each with its techniques; the saved trace holds every file.
func (w reportRun) timeline() []render.Group {
	if len(w.result.intents) > 0 {
		return w.intentBlocks()
	}
	all, quiet := w.periods()
	if len(all) == 0 {
		return nil
	}
	entries := make([]render.Entry, len(all))
	for i, p := range all {
		when := stepTime(p.first)
		if until := stepTime(p.last); until != when {
			when += " to " + until
		}
		name, level := "-", ""
		if len(p.tactics) > 0 {
			name, level = strings.Join(p.tactics, ", "), string(w.pipe.highest(p.tactics))
		}
		entries[i] = render.Entry{Level: level, Cells: []string{name, when}, Detail: w.named(p.tactics, p.techniques, p.hits)}
	}
	// A line that is no block stands in a group of its own.
	note := func(text string) render.Group {
		return render.Group{Entries: []render.Entry{{Cells: []string{text}}}}
	}
	groups := []render.Group{{Blocks: true, Entries: entries}}
	if more := len(entries) - fewPeriods; more > 0 {
		half := fewPeriods / 2
		groups = []render.Group{
			{Blocks: true, Entries: entries[:half]},
			note("and " + counted(more, "more period", "more periods") + " here, in the saved trace"),
			{Blocks: true, Entries: entries[len(entries)-half:]},
		}
	}
	if quiet > 0 {
		groups = append(groups, note("and "+counted(quiet, "file that shows", "files that show")+" no tactic, in the saved trace"))
	}
	return groups
}

// noTechnique stands where the files of a block show no technique.
const noTechnique = "no MITRE ATT&CK technique identified"

// named lists what a block shows: each tactic, in the order of the tactic
// table, with the techniques under it or that none was identified, and then
// the watchlist matches. A technique stands under each of its parents.
func (w reportRun) named(shown []string, found techniques, hits []string) []render.Detail {
	every, tactics := w.pipe.tactics.Names(), slices.Clone(shown)
	// The parents of a technique are the tactics its activities claim; where
	// they claim none, the tactics its framework files it under.
	parents := func(id string, framework mitre.Framework, identifier func(string) string) []string {
		if claimed := found.parents[id]; len(claimed) > 0 {
			return claimed
		}
		var filed []string
		for _, name := range every {
			if slices.Contains(framework.TacticsOf(id), identifier(name)) {
				filed = append(filed, name)
			}
		}
		return filed
	}
	// The names of the techniques of a block begin in one column.
	width := 0
	for _, id := range slices.Concat(found.attack, found.atlas) {
		width = max(width, len(id))
	}
	under := map[string][]string{}
	place := func(ids []string, framework mitre.Framework, identifier func(string) string) {
		for _, id := range ids {
			line := id + strings.Repeat(" ", width-len(id)) + "  " + or(framework.NameOf(id), "-")
			for _, name := range parents(id, framework, identifier) {
				under[name] = append(under[name], line)
				tactics = appendUnique(tactics, name)
			}
		}
	}
	place(found.attack, w.pipe.catalogue.Attack, w.pipe.tactics.Attack)
	place(found.atlas, w.pipe.catalogue.Atlas, w.pipe.tactics.Atlas)
	var out []render.Detail
	for _, name := range every {
		if !slices.Contains(tactics, name) {
			continue
		}
		label := name + " (" + w.pipe.tactics.Attack(name) + ", " + w.pipe.tactics.Atlas(name) + ")"
		for _, line := range under[name] {
			out = append(out, render.Detail{Label: label, Text: line})
		}
		if len(under[name]) == 0 {
			out = append(out, render.Detail{Label: label, Text: noTechnique})
		}
	}
	if len(out) == 0 {
		out = append(out, render.Detail{Text: noTechnique})
	}
	if len(hits) > 0 {
		out = append(out, render.Detail{Label: "watchlist", Text: fewOf(hits, fewFiles, ", ")})
	}
	return out
}
