package command

import (
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/get-sybers/slopmop/internal/activity"
	"github.com/get-sybers/slopmop/internal/render"
	"github.com/get-sybers/slopmop/internal/tactic"
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
	// techniques are those of the activities its files show, tools what
	// its files run, and hits the watchlist matches.
	techniques
	tools, hits []string
}

// techniques are the ATT&CK techniques some files show, each once, in the
// order it is first shown, and the ATLAS techniques they infer. Each has its
// parents: the tactics of what shows it that ATT&CK files it under.
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
	t.atlas = appendUnique(t.atlas, p.atlasOf(hit)...)
}

// run takes in the techniques the commands of a file are. A command is filed
// under its techniques, and the tactic that holds a technique is its parent.
func (t *techniques) run(p pipeline, tools []string) {
	for _, tool := range tools {
		for _, at := range p.tactics.Classify(tool) {
			id := at.Technique
			if id == "" {
				continue
			}
			if t.parents == nil {
				t.parents = map[string][]string{}
			}
			t.attack = appendUnique(t.attack, id)
			t.parents[id] = appendUnique(t.parents[id], at.Tactic)
			t.atlas = appendUnique(t.atlas, p.catalogue.AtlasFor([]string{id})...)
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
		p.tools = appendUnique(p.tools, s.Tools...)
		for _, a := range s.Activities {
			p.add(w.pipe, a)
		}
		p.run(w.pipe, s.Tools)
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
// lists its techniques and what follows from each; the saved trace holds every file.
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
		entries[i] = render.Entry{Level: level, Cells: []string{name, when}}
		entries[i].Rows, entries[i].Detail = w.block(p.tactics, p.techniques, p.tools, p.hits)
	}
	// A line that is no block stands in a group of its own.
	note := func(text string) render.Group {
		return render.Group{Entries: []render.Entry{{Cells: []string{text}}}}
	}
	groups := []render.Group{{Blocks: true, Heads: heads(), Entries: entries}}
	if more := len(entries) - fewPeriods; more > 0 {
		half := fewPeriods / 2
		groups = []render.Group{
			{Blocks: true, Heads: heads(), Entries: entries[:half]},
			note("and " + counted(more, "more period", "more periods") + " here, in the saved trace"),
			{Blocks: true, Heads: heads(), Entries: entries[len(entries)-half:]},
		}
	}
	if quiet > 0 {
		groups = append(groups, note("and "+counted(quiet, "file that shows", "files that show")+" no tactic, in the saved trace"))
	}
	return groups
}

// noTechnique stands where the files of a block show no technique.
const noTechnique = "no MITRE ATT&CK technique identified"

// fewTools is how many tools a row of a block names in full.
const fewTools = 6

// heads names what a row of a block names, in its order.
func heads() render.Heads {
	return render.Heads{"ATT&CK technique", "tactic", "ATLAS technique"}
}

// block lists what a block shows, in the order of the tactic table. A row is
// an ATT&CK technique and what follows from it, its tactics and its ATLAS
// techniques; the tools of a tactic that no technique is named for are a row.
func (w reportRun) block(shown []string, found techniques, tools, hits []string) ([]render.Row, []render.Detail) {
	every := w.pipe.tactics.Names()
	type part struct {
		at   int
		rows []render.Row
	}
	var parts []part
	var given []string
	for _, id := range found.attack {
		// The tactics of a technique are those its activities claim; where
		// they claim none, those ATT&CK files it under.
		var parents []string
		for _, name := range every {
			claimed := slices.Contains(found.parents[id], name)
			filed := len(found.parents[id]) == 0 && slices.Contains(w.pipe.catalogue.Attack.TacticsOf(id), w.pipe.tactics.Attack(name))
			if claimed || filed {
				parents = append(parents, name)
			}
		}
		given = appendUnique(given, parents...)
		atlas := w.pipe.catalogue.AtlasFor([]string{id})
		rows := make([]render.Row, max(1, len(parents), len(atlas)))
		rows[0][0] = render.Named{ID: id, Name: or(w.pipe.catalogue.Attack.NameOf(id), "-")}
		for i, name := range parents {
			rows[i][1] = render.Named{ID: w.pipe.tactics.Attack(name), Name: name}
		}
		for i, a := range atlas {
			rows[i][2] = render.Named{ID: a, Name: or(w.pipe.catalogue.Atlas.NameOf(a), "-")}
		}
		at := len(every)
		if len(parents) > 0 {
			at = slices.Index(every, parents[0])
		}
		parts = append(parts, part{at, rows})
	}
	for at, name := range every {
		var of []string
		for _, tool := range tools {
			if slices.Contains(w.pipe.tactics.Classify(tool), tactic.Place{Tactic: name}) {
				of = append(of, tool)
			}
		}
		row := render.Row{1: {ID: w.pipe.tactics.Attack(name), Name: name}}
		switch {
		case len(of) > 0:
			row[0] = render.Named{Kind: "tools", Name: fewOf(of, fewTools, ", ")}
		case !slices.Contains(shown, name) || slices.Contains(given, name):
			continue
		}
		parts = append(parts, part{at, []render.Row{row}})
	}
	sort.SliceStable(parts, func(i, j int) bool { return parts[i].at < parts[j].at })
	var rows []render.Row
	for _, p := range parts {
		rows = append(rows, p.rows...)
	}
	var detail []render.Detail
	if len(found.attack) == 0 {
		detail = append(detail, render.Detail{Text: noTechnique})
	}
	if len(hits) > 0 {
		detail = append(detail, render.Detail{Label: "watchlist", Text: fewOf(hits, fewFiles, ", ")})
	}
	return rows, detail
}
