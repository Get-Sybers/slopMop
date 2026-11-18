package command

import (
	"slices"
	"strconv"
	"strings"

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
	// attack and atlas are the techniques its files show, each once, in the
	// order it is first shown, and hits the watchlist matches.
	attack, atlas, hits []string
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
			p.attack = appendUnique(p.attack, a.Attack...)
			p.atlas = appendUnique(p.atlas, w.pipe.atlasOf(a)...)
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
// lists its tactics and its techniques; the saved trace holds every file.
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
		// The tactics of a period are its name, so they are not listed under it again.
		entries[i] = render.Entry{Level: level, Cells: []string{name, when}, Detail: w.named(nil, p.attack, p.atlas, p.hits)}
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

// noTechnique stands in a block whose files show no technique.
const noTechnique = "no MITRE ATT&CK technique identified"

// named lists what a block shows: its tactics, each under its identifiers
// of ATT&CK and ATLAS, in the order of the tactic table; its techniques by
// identifier and name, or that none was identified; and its watchlist matches.
func (w reportRun) named(tactics, attack, atlas, hits []string) []render.Detail {
	var out []render.Detail
	for _, name := range w.pipe.tactics.Names() {
		if slices.Contains(tactics, name) {
			out = append(out, render.Detail{Label: w.pipe.tactics.Attack(name) + ", " + w.pipe.tactics.Atlas(name), Text: name})
		}
	}
	for _, id := range attack {
		out = append(out, render.Detail{Label: id, Text: or(w.pipe.catalogue.Attack.NameOf(id), "-")})
	}
	for _, id := range atlas {
		out = append(out, render.Detail{Label: id, Text: or(w.pipe.catalogue.Atlas.NameOf(id), "-")})
	}
	// A tactic is of the tools a file runs; a technique is of an activity, and a file may show none.
	if len(attack)+len(atlas) == 0 {
		out = append(out, render.Detail{Text: noTechnique})
	}
	if len(hits) > 0 {
		out = append(out, render.Detail{Label: "watchlist", Text: fewOf(hits, fewFiles, ", ")})
	}
	return out
}
