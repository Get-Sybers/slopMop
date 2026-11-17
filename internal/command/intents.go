package command

import (
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/get-sybers/slopmop/internal/evidence"
	"github.com/get-sybers/slopmop/internal/intent"
	"github.com/get-sybers/slopmop/internal/render"
	"github.com/get-sybers/slopmop/internal/tactic"
	"github.com/get-sybers/slopmop/internal/trace"
)

// intentRun is one ARTEX intent: the files of its run folder, the period
// they cover and the techniques they show.
type intentRun struct {
	ref intent.Ref
	// first and last are the files with the earliest and the latest time.
	first, last evidence.File
	timed       bool
	files       []string
	tactics     []string
	activities  []intentActivity
	attack      []string
	atlas       []string
	level       tactic.Severity
}

// intentActivity is an activity found in an intent, with its techniques.
type intentActivity struct {
	name   string
	attack []string
	atlas  []string
}

// fileTime is the time a file is placed at: the stamp in its name, or else
// when it was last modified. The zero time means it has neither.
func fileTime(f evidence.File) time.Time {
	if f.Stamped {
		return f.Stamp.Time
	}
	return f.Modified
}

// above is how many folders of the path to the folder read count as part of
// the path of a file: enough to read a run folder itself, tasks/<task>/i<number>.
const above = 3

// collectIntents groups the steps by the intent their path lies in, earliest first.
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
			atlas := p.atlasOf(hit)
			r.attack, r.atlas = appendUnique(r.attack, hit.Attack...), appendUnique(r.atlas, atlas...)
			if !containsActivity(r.activities, hit.Name) {
				r.activities = append(r.activities, intentActivity{name: hit.Name, attack: hit.Attack, atlas: atlas})
			}
		}
		when := fileTime(s.File)
		if when.IsZero() {
			continue
		}
		if !r.timed || when.Before(fileTime(r.first)) {
			r.first = s.File
		}
		if !r.timed || when.After(fileTime(r.last)) {
			r.last = s.File
		}
		r.timed = true
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

func containsActivity(list []intentActivity, name string) bool {
	for _, a := range list {
		if a.name == name {
			return true
		}
	}
	return false
}

// before orders two intents by when they begin; one without a time comes
// last, and the number of the intent settles a tie.
func before(a, b intentRun) bool {
	switch x, y := fileTime(a.first), fileTime(b.first); {
	case a.timed != b.timed:
		return a.timed
	case a.timed && !x.Equal(y):
		return x.Before(y)
	case len(a.ref.ID) != len(b.ref.ID):
		return len(a.ref.ID) < len(b.ref.ID)
	default:
		return a.ref.ID < b.ref.ID
	}
}

// span is the time from the first file of the intent to the last.
func (r intentRun) span() (time.Duration, bool) {
	if !r.timed {
		return 0, false
	}
	return fileTime(r.last).Sub(fileTime(r.first)).Round(time.Second), true
}

// pairs gives each activity with its ATT&CK techniques and the ATLAS
// techniques that go with them.
func (r intentRun) pairs() []string {
	lines := make([]string, len(r.activities))
	for i, a := range r.activities {
		lines[i] = a.name + ": " + or(strings.Join(a.attack, ", "), "no ATT&CK technique") +
			" with " + or(strings.Join(a.atlas, ", "), "no ATLAS technique")
	}
	return lines
}

func or(text, otherwise string) string {
	if text == "" {
		return otherwise
	}
	return text
}

// intents lists each intent in the order it began: its period, and under it
// its techniques, the activities they come from and its files.
func (w reportRun) intents() []render.Group {
	g := render.Group{Columns: []string{"intent", "first", "last", "span", "files"}}
	for _, r := range w.result.intents {
		first, last, length := "-", "-", "-"
		if d, ok := r.span(); ok {
			first, last = stepTime(trace.Step{File: r.first}), stepTime(trace.Step{File: r.last})
			length = d.String()
		}
		detail := []render.Detail{
			{Label: "task", Text: r.ref.Task},
			{Label: "tactics", Text: strings.Join(r.tactics, ", ")},
			{Label: "attack", Text: strings.Join(r.attack, ", ")},
			{Label: "atlas", Text: strings.Join(r.atlas, ", ")},
		}
		for _, line := range r.pairs() {
			detail = append(detail, render.Detail{Label: "found", Text: line})
		}
		detail = append(detail, render.Detail{Label: "files", Text: few(r.files)})
		g.Entries = append(g.Entries, render.Entry{
			Level:  string(r.level),
			Cells:  []string{r.ref.ID, first, last, length, plural(len(r.files), "file")},
			Detail: detail,
		})
	}
	return []render.Group{g}
}

// intentRow fills one row of the intent class.
func intentRow(r intentRun, columns []render.Column) ([]render.Value, error) {
	list := func(items []string) render.Value {
		if len(items) == 0 {
			return render.NotApplicable()
		}
		return render.Text(strings.Join(items, ", "))
	}
	names := make([]string, len(r.activities))
	for i, a := range r.activities {
		names[i] = a.name
	}
	cells := map[string]render.Value{
		"intent":     render.Text(r.ref.ID),
		"task":       render.NotApplicable(),
		"first":      render.NotApplicable(),
		"last":       render.NotApplicable(),
		"seconds":    render.NotApplicable(),
		"files":      list(r.files),
		"tactics":    list(r.tactics),
		"activities": list(names),
		"attack":     list(r.attack),
		"atlas":      list(r.atlas),
		"severity":   render.NotApplicable(),
	}
	if r.ref.Task != "" {
		cells["task"] = render.Text(r.ref.Task)
	}
	if d, ok := r.span(); ok {
		cells["first"], cells["last"] = timeCell(r.first), timeCell(r.last)
		cells["seconds"] = render.Int(int64(d / time.Second))
	}
	if r.level != "" {
		cells["severity"] = render.Text(string(r.level))
	}
	return orderCells("intent", cells, columns)
}

// timeCell is the time of a file as the trace class writes it: the file-name
// stamp read as UTC, or else the modified time, as one ISO-8601 instant so a
// reader never meets a bare token or epoch in a time column.
func timeCell(f evidence.File) render.Value {
	if t := fileTime(f); !t.IsZero() {
		return render.Time(t)
	}
	return render.NotApplicable()
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
	return []metric{{"intents", len(a.intents)}}
}
