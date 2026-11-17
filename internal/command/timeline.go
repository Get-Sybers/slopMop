package command

import (
	"slices"
	"strconv"
	"strings"

	"github.com/get-sybers/slopmop/internal/render"
	"github.com/get-sybers/slopmop/internal/trace"
)

const (
	// fewPeriods is how many periods the timeline shows: of more, the first
	// half and the last, since how a run began and how it ended say most.
	fewPeriods = 40
	// fewNamed is how many activities and tools a period names.
	fewNamed = 8
)

// period is a stretch of the timeline: the files, one after another, that
// show something and show no tactic the first of them does not.
type period struct {
	first, last trace.Step
	// tactics are those of the first file, in the order of the tactic table.
	tactics []string
	files   []string
	// What the files show, each once, in the order it is first shown.
	activities, tools, hits, intents []string
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
		p.files = append(p.files, s.File.Path)
		p.tools = appendUnique(p.tools, s.Tools...)
		for _, a := range s.Activities {
			p.activities = appendUnique(p.activities, a.Name)
		}
		for _, h := range s.IntelHits {
			p.hits = appendUnique(p.hits, h.Attribution+": "+h.Value)
		}
		if intent := w.result.intentOf[s.File.Path]; intent != "" {
			p.intents = appendUnique(p.intents, intent)
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

// timeline tells what was done, in the order of time: an entry is a period,
// not a file. The files are in the saved trace, every one of them.
func (w reportRun) timeline() []render.Group {
	all, quiet := w.periods()
	if len(all) == 0 {
		return nil
	}
	columns := []string{"from", "until", "files", "tactics"}
	entries := make([]render.Entry, len(all))
	for i, p := range all {
		from, until := stepTime(p.first), stepTime(p.last)
		if until == from {
			until = "-"
		}
		tactics := "-"
		if len(p.tactics) > 0 {
			tactics = strings.Join(p.tactics, ", ")
		}
		entries[i] = render.Entry{
			Cells: []string{from, until, strconv.Itoa(len(p.files)), tactics},
			Detail: []render.Detail{
				{Label: "intent", Text: fewOf(p.intents, fewNamed, ", ")},
				{Label: "activities", Text: fewOf(p.activities, fewNamed, ", ")},
				{Label: "tools", Text: fewOf(p.tools, fewNamed, ", ")},
				{Label: "watchlist", Text: fewOf(p.hits, fewFiles, ", ")},
				{Label: "files", Text: few(p.files)},
			},
		}
	}
	// A line that is no period stands in a group of its own, so its length
	// does not set the width of the columns.
	note := func(text string) render.Group {
		return render.Group{Entries: []render.Entry{{Cells: []string{text}}}}
	}
	groups := []render.Group{{Columns: columns, Entries: entries}}
	if more := len(entries) - fewPeriods; more > 0 {
		half := fewPeriods / 2
		groups = []render.Group{
			{Columns: columns, Entries: entries[:half]},
			note("and " + counted(more, "more period", "more periods") + " here, in the saved trace"),
			{Columns: columns, Entries: entries[len(entries)-half:]},
		}
	}
	if quiet > 0 {
		groups = append(groups, note("and "+counted(quiet, "file that shows", "files that show")+" no tactic, in the saved trace"))
	}
	return groups
}
