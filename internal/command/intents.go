package command

import (
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/get-sybers/slopmop/internal/intent"
	"github.com/get-sybers/slopmop/internal/render"
	"github.com/get-sybers/slopmop/internal/tactic"
	"github.com/get-sybers/slopmop/internal/trace"
)

// intentRun is one ARTEX intent: the files that are its own, the period in
// which they were made and the techniques they show.
type intentRun struct {
	ref intent.Ref
	// from and until are when the first and the last of its files were made.
	from, until time.Time
	// timed counts its files that have a time, and recorded those whose time
	// is the creation time their file system keeps.
	timed, recorded int
	files           []string
	tactics         []string
	activities      []string
	attack          []string
	atlas           []string
	level           tactic.Severity
}

// above is how many folders of the path to the folder read count as part of
// the path of a file: enough to read a run folder itself, tasks/<task>/i<number>.
const above = 3

// collectIntents groups the steps by the intent their path names, earliest first.
func (p pipeline) collectIntents(folder string, steps []trace.Step) ([]intentRun, map[string]string) {
	prefix := ""
	if whole, err := filepath.Abs(folder); err == nil {
		for range above {
			prefix = filepath.Base(whole) + "/" + prefix
			whole = filepath.Dir(whole)
		}
	}
	var runs []*intentRun
	at := map[string]*intentRun{}
	of := map[string]string{}
	for _, s := range steps {
		ref, ok := p.intents.Of(filepath.ToSlash(prefix) + s.File.Path)
		if !ok {
			continue
		}
		r := at[ref.ID]
		if r == nil {
			r = &intentRun{ref: ref}
			at[ref.ID] = r
			runs = append(runs, r)
		}
		if r.ref.Task == "" {
			r.ref.Task = ref.Task
		}
		of[s.File.Path] = ref.ID
		r.files = append(r.files, s.File.Path)
		r.tactics = appendUnique(r.tactics, s.Tactics...)
		for _, hit := range s.Activities {
			r.attack, r.atlas = appendUnique(r.attack, hit.Attack...), appendUnique(r.atlas, p.atlasOf(hit)...)
			r.activities = appendUnique(r.activities, hit.Name)
		}
		made, recorded := s.File.Made()
		if made.IsZero() {
			continue
		}
		if r.timed == 0 || made.Before(r.from) {
			r.from = made
		}
		if r.timed == 0 || made.After(r.until) {
			r.until = made
		}
		r.timed++
		if recorded {
			r.recorded++
		}
	}
	out := make([]intentRun, len(runs))
	for i, r := range runs {
		if len(r.tactics) > 0 {
			r.level = p.highest(r.tactics)
		}
		out[i] = *r
	}
	sort.SliceStable(out, func(i, j int) bool { return before(out[i], out[j]) })
	return out, of
}

// before orders two intents by when they begin; one without a time comes
// last, and the number of the intent settles a tie.
func before(a, b intentRun) bool {
	switch {
	case (a.timed > 0) != (b.timed > 0):
		return a.timed > 0
	case !a.from.Equal(b.from):
		return a.from.Before(b.from)
	case len(a.ref.ID) != len(b.ref.ID):
		return len(a.ref.ID) < len(b.ref.ID)
	default:
		return a.ref.ID < b.ref.ID
	}
}

// span is the time from the first file of the intent to the last.
func (r intentRun) span() (time.Duration, bool) {
	if r.timed == 0 {
		return 0, false
	}
	return r.until.Sub(r.from).Round(time.Second), true
}

// What the period of an intent is read from.
const (
	byCreation = "creation"
	byTimeline = "name or modified"
	byBoth     = "both"
)

// timedBy says which time of its files gives the period of an intent.
func (r intentRun) timedBy() string {
	switch {
	case r.timed == 0:
		return ""
	case r.recorded == r.timed:
		return byCreation
	case r.recorded == 0:
		return byTimeline
	default:
		return byBoth
	}
}

// intents is the timeline by intent, in the order the intents began: when
// each ran, its techniques and the files that are its own. Every intent is
// an entry, however many there are.
func (w reportRun) intents() []render.Group {
	all := w.result.intents
	if len(all) == 0 {
		return nil
	}
	columns := []string{"from", "until", "intent", "techniques"}
	entries := make([]render.Entry, len(all))
	files, recorded := 0, 0
	for i, r := range all {
		from, until := "-", "-"
		if r.timed > 0 {
			from = render.Stamp(r.from, nil)
			if last := render.Stamp(r.until, nil); last != from {
				until = last
			}
		}
		techniques := "-"
		if len(r.attack) > 0 {
			techniques = strings.Join(r.attack, ", ")
		}
		entries[i] = render.Entry{
			Level: string(r.level),
			Cells: []string{from, until, r.ref.ID, techniques},
			Detail: []render.Detail{
				{Label: "atlas", Text: strings.Join(r.atlas, ", ")},
				{Label: "files", Text: few(r.files)},
			},
		}
		files, recorded = files+len(r.files), recorded+r.recorded
	}
	groups := []render.Group{{Columns: columns, Entries: entries}}
	if other := files - recorded; other > 0 {
		// A line that is no intent stands in a group of its own, so its length
		// does not set the width of the columns.
		line := strconv.Itoa(other) + " of " + counted(files, "file is", "files are") +
			" timed by name or last change: their creation time is not recorded, or is that of a copy, which is after the last change"
		groups = append(groups, render.Group{Entries: []render.Entry{{Cells: []string{line}}}})
	}
	return groups
}

// intentRow fills one row of the intent class.
func intentRow(r intentRun, columns []render.Column) ([]render.Value, error) {
	list := func(items []string) render.Value {
		if len(items) == 0 {
			return render.NotApplicable()
		}
		return render.Text(strings.Join(items, ", "))
	}
	cells := map[string]render.Value{
		"intent":     render.Text(r.ref.ID),
		"task":       render.NotApplicable(),
		"first":      when(r.from),
		"last":       when(r.until),
		"seconds":    render.NotApplicable(),
		"timed_by":   render.NotApplicable(),
		"files":      list(r.files),
		"tactics":    list(r.tactics),
		"activities": list(r.activities),
		"attack":     list(r.attack),
		"atlas":      list(r.atlas),
		"severity":   render.NotApplicable(),
	}
	if r.ref.Task != "" {
		cells["task"] = render.Text(r.ref.Task)
	}
	if d, ok := r.span(); ok {
		cells["seconds"] = render.Int(int64(d / time.Second))
		cells["timed_by"] = render.Text(r.timedBy())
	}
	if r.level != "" {
		cells["severity"] = render.Text(string(r.level))
	}
	return orderCells("intent", cells, columns)
}

func (w reportRun) intentTable(columns []render.Column, add func([]render.Value) error) error {
	for _, r := range w.result.intents {
		row, err := intentRow(r, columns)
		if err != nil {
			return err
		}
		if err := add(row); err != nil {
			return err
		}
	}
	return nil
}

// intentCount is the count the summary gives, with no line when there is none.
func intentCount(a analysis) []metric {
	if len(a.intents) == 0 {
		return nil
	}
	return []metric{{name: "intents", value: len(a.intents)}}
}
