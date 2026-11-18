package command

import (
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/get-sybers/slopmop/internal/evidence"
	"github.com/get-sybers/slopmop/internal/indicator"
	"github.com/get-sybers/slopmop/internal/render"
	"github.com/get-sybers/slopmop/internal/tactic"
)

const (
	kindActivity  = "activity"
	kindIndicator = "indicator"
	kindTactic    = "tactic"
)

// finding is one detection: an activity, a distinct indicator value, or a
// tactic cluster.
type finding struct {
	kind         string
	label        string
	severity     tactic.Severity
	tactics      []string
	indicator    string
	files        []string
	attributions []string
	// attack and atlas are technique identifiers on an activity and tactic
	// identifiers on a tactic.
	attack []string
	atlas  []string
	// first and last are the times of the earliest and the latest file that
	// shows it; both are zero when no file that shows it has a time.
	first, last time.Time
	// evidence holds the lines that show an activity.
	evidence []dated
}

// dated is one line of evidence and the time of its file.
type dated struct {
	cited
	at time.Time
}

// seen widens the period of a finding to hold the time of a file that shows it.
func (f *finding) seen(at time.Time) {
	if at.IsZero() {
		return
	}
	if f.first.IsZero() || at.Before(f.first) {
		f.first = at
	}
	if at.After(f.last) {
		f.last = at
	}
}

// lines writes each line of evidence with where it stands.
func (f finding) lines() []string {
	lines := make([]string, len(f.evidence))
	for i, e := range f.evidence {
		lines[i] = e.String()
	}
	return lines
}

// listFindings aggregates the timeline: one finding per activity, one per
// distinct indicator and one per tactic, most severe first.
func (p pipeline) listFindings(a analysis) []finding {
	tactics := p.tactics
	// An output inherits the tactics of the scripts that write it.
	inherited := map[string][]string{}
	for _, s := range a.timeline.Steps {
		for _, out := range s.Outputs {
			inherited[out] = append(inherited[out], s.Tactics...)
		}
	}
	byActivity := map[string]*finding{}
	byIndicator := map[string]*finding{}
	byTactic := map[string]*finding{}
	var order []*finding
	files := seenFiles{}
	for _, s := range a.timeline.Steps {
		path, at := s.File.Path, s.File.Time()
		for _, hit := range s.Activities {
			f, ok := byActivity[hit.Name]
			if !ok {
				f = &finding{
					kind: kindActivity, label: hit.Name, tactics: slices.Clone(hit.Tactics),
					attack: hit.Attack, atlas: p.atlasOf(hit),
				}
				byActivity[hit.Name] = f
				order = append(order, f)
			}
			if files.fresh("a\x00"+hit.Name, path) {
				f.files = append(f.files, path)
			}
			f.seen(at)
			for _, e := range hit.Evidence {
				if len(f.evidence) < maxCited {
					f.evidence = append(f.evidence, dated{cited: a.cited(path, e), at: at})
				}
			}
		}
		if s.File.Role == evidence.Script {
			for _, name := range s.Tactics {
				f, ok := byTactic[name]
				if !ok {
					f = &finding{
						kind: kindTactic, label: kindTactic, tactics: []string{name},
						attack: []string{tactics.Attack(name)}, atlas: []string{tactics.Atlas(name)},
					}
					byTactic[name] = f
					order = append(order, f)
				}
				if files.fresh("t\x00"+name, path) {
					f.files = append(f.files, path)
				}
				f.seen(at)
			}
		}
		for _, m := range s.Matches {
			key := m.Type + "\x00" + m.Value
			f, ok := byIndicator[key]
			if !ok {
				// A hash or a token is an indicator and a secret; it is masked as one.
				f = &finding{kind: kindIndicator, label: m.Type, indicator: a.redact(m.Value)}
				if a.watchlist != nil {
					for _, hit := range a.watchlist.Match([]indicator.Match{m}) {
						f.attributions = appendUnique(f.attributions, hit.Attribution)
					}
				}
				byIndicator[key] = f
				order = append(order, f)
			}
			if files.fresh("i\x00"+key, path) {
				f.files = append(f.files, path)
			}
			f.seen(at)
			f.tactics = appendUnique(f.tactics, s.Tactics...)
			f.tactics = appendUnique(f.tactics, inherited[path]...)
		}
	}
	findings := make([]finding, len(order))
	for i, f := range order {
		sort.Strings(f.tactics)
		sort.Strings(f.files)
		sort.Strings(f.attributions)
		f.severity = severityOf(*f, tactics)
		findings[i] = *f
	}
	sort.SliceStable(findings, func(i, j int) bool {
		x, y := findings[i], findings[j]
		if x.severity != y.severity {
			return x.severity.Rank() > y.severity.Rank()
		}
		if x.kind != y.kind {
			return x.kind < y.kind
		}
		if x.label != y.label {
			return x.label < y.label
		}
		if x.indicator != y.indicator {
			return x.indicator < y.indicator
		}
		return strings.Join(x.tactics, ",") < strings.Join(y.tactics, ",")
	})
	return findings
}

// severityOf is the highest severity among a finding's tactics. A watchlist
// match is high whatever the tactic.
func severityOf(f finding, tactics tactic.Table) tactic.Severity {
	if len(f.attributions) > 0 {
		return tactic.High
	}
	severity := tactic.Low
	for _, name := range f.tactics {
		if s := tactics.Severity(name); s.Rank() > severity.Rank() {
			severity = s
		}
	}
	return severity
}

func appendUnique(list []string, items ...string) []string {
	for _, item := range items {
		found := false
		for _, have := range list {
			if have == item {
				found = true
				break
			}
		}
		if !found {
			list = append(list, item)
		}
	}
	return list
}

// seenFiles remembers which files already name each key, so a list that grows
// with the timeline is not scanned on every file: over thousands of files that
// scan is quadratic. The caller keeps the order by appending only when fresh.
type seenFiles map[string]map[string]bool

func (s seenFiles) fresh(key, file string) bool {
	paths := s[key]
	if paths == nil {
		paths = map[string]bool{}
		s[key] = paths
	}
	if paths[file] {
		return false
	}
	paths[file] = true
	return true
}

// when is an instant, or the value that does not apply when there is none.
func when(at time.Time) render.Value {
	if at.IsZero() {
		return render.NotApplicable()
	}
	return render.Time(at)
}

func findingRow(f finding, columns []render.Column) ([]render.Value, error) {
	list := func(items []string) render.Value {
		if len(items) == 0 {
			return render.NotApplicable()
		}
		return render.Text(strings.Join(items, ", "))
	}
	cells := map[string]render.Value{
		"finding":     render.Text(f.label),
		"severity":    render.Text(string(f.severity)),
		"tactic":      list(f.tactics),
		"indicator":   render.NotApplicable(),
		"files":       list(f.files),
		"attribution": list(f.attributions),
		"first":       when(f.first),
		"last":        when(f.last),
		"attack":      list(f.attack),
		"atlas":       list(f.atlas),
		"evidence":    render.NotApplicable(),
	}
	if len(f.evidence) > 0 {
		items := make([][]render.Field, len(f.evidence))
		for i, e := range f.evidence {
			line := render.NotApplicable()
			if e.line > 0 {
				line = render.Int(int64(e.line))
			}
			items[i] = []render.Field{
				{Key: "time", Value: when(e.at)},
				{Key: "file", Value: render.Text(e.file)},
				{Key: "line", Value: line},
				{Key: "text", Value: render.Text(e.text)},
			}
		}
		cells["evidence"] = render.List(items)
	}
	if f.indicator != "" {
		cells["indicator"] = render.Text(f.indicator)
	}
	return orderCells("finding", cells, columns)
}
