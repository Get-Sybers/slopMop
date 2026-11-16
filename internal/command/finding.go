package command

import (
	"errors"
	"slices"
	"sort"
	"strings"

	"github.com/get-sybers/slopmop/internal/cli"
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
}

func (e Env) findingList(v verbSpec) (*cli.Verb, error) {
	if v.Name != "list" || len(v.Aliases) > 0 {
		return nil, errors.New("the global list verb takes its name and alias from cli.ListVerb")
	}
	pipe, err := loadPipeline()
	if err != nil {
		return nil, err
	}
	if _, err := findingRow(finding{}, v.Columns, false); err != nil {
		return nil, err
	}
	spec := cli.Spec{
		Selectors: map[string]string{
			kindActivity:  "show only activity findings",
			kindIndicator: "show only indicator findings",
			kindTactic:    "show only tactic findings",
		},
		Params:   map[string]string{inputDir: "<folder>", intelFile: "<file>"},
		Switches: recursiveSwitch(),
		Required: []string{inputDir},
	}
	return cli.ListVerb(v.Summary, spec, func(a *cli.Args) error {
		result, err := pipe.run(a)
		if err != nil {
			return err
		}
		wanted := map[string]bool{}
		for _, sel := range a.Selectors {
			wanted[sel] = true
		}
		shorten := a.Output.View == "" && !a.Output.Quiet
		table := render.Table{Columns: v.Columns}
		for _, f := range listFindings(result, pipe.tactics) {
			if !wanted[f.kind] {
				continue
			}
			row, err := findingRow(f, v.Columns, shorten)
			if err != nil {
				return err
			}
			table.Rows = append(table.Rows, row)
		}
		if err := render.Write(e.Stdout, table, e.options(a.Output)); err != nil {
			return err
		}
		return skippedError(result.skipped)
	}), nil
}

// listFindings aggregates the timeline: one finding per activity, one per
// distinct indicator and one per tactic, most severe first.
func listFindings(a analysis, tactics tactic.Table) []finding {
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
	for _, s := range a.timeline.Steps {
		path := s.File.Path
		for _, hit := range s.Activities {
			f, ok := byActivity[hit.Name]
			if !ok {
				f = &finding{kind: kindActivity, label: hit.Name, tactics: slices.Clone(hit.Tactics)}
				byActivity[hit.Name] = f
				order = append(order, f)
			}
			f.files = appendUnique(f.files, path)
		}
		if s.File.Role == evidence.Script {
			for _, name := range s.Tactics {
				f, ok := byTactic[name]
				if !ok {
					f = &finding{kind: kindTactic, label: kindTactic, tactics: []string{name}}
					byTactic[name] = f
					order = append(order, f)
				}
				f.files = appendUnique(f.files, path)
			}
		}
		for _, m := range s.Matches {
			key := m.Type + "\x00" + m.Value
			f, ok := byIndicator[key]
			if !ok {
				f = &finding{kind: kindIndicator, label: m.Type, indicator: m.Value}
				if a.watchlist != nil {
					for _, hit := range a.watchlist.Match([]indicator.Match{m}) {
						f.attributions = appendUnique(f.attributions, hit.Attribution)
					}
				}
				byIndicator[key] = f
				order = append(order, f)
			}
			f.files = appendUnique(f.files, path)
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

func findingRow(f finding, columns []render.Column, shorten bool) ([]render.Value, error) {
	list := func(items []string) render.Value {
		if len(items) == 0 {
			return render.NotApplicable()
		}
		joined := strings.Join(items, ", ")
		if shorten {
			joined = truncate(joined, listWidth)
		}
		return render.Text(joined)
	}
	cells := map[string]render.Value{
		"finding":     render.Text(f.label),
		"severity":    render.Text(string(f.severity)),
		"tactic":      list(f.tactics),
		"indicator":   render.NotApplicable(),
		"files":       list(f.files),
		"attribution": list(f.attributions),
	}
	if f.indicator != "" {
		value := f.indicator
		if shorten {
			value = truncate(value, listWidth)
		}
		cells["indicator"] = render.Text(value)
	}
	return orderCells("finding list", cells, columns)
}
