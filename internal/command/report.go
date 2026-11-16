package command

import (
	"errors"
	"sort"
	"strconv"
	"strings"

	"github.com/get-sybers/slopmop/internal/assess"
	"github.com/get-sybers/slopmop/internal/cli"
	"github.com/get-sybers/slopmop/internal/evidence"
	"github.com/get-sybers/slopmop/internal/render"
	"github.com/get-sybers/slopmop/internal/tactic"
)

// The sections of a report; each is a selector. A notable file's row
// carries its role as the section.
const (
	sectionSummary     = "summary"
	sectionFiles       = "files"
	sectionImpact      = "impact"
	sectionRemediation = assess.Remediation
	sectionMitigation  = assess.Mitigation
)

// severityParam sets how severe a finding makes a file notable.
const severityParam = "severity"

type metric struct {
	name  string
	value int
}

// reportRow is one line of a report: a count, a notable file, an impact or
// a recommended action.
type reportRow struct {
	item    string
	section string
	// count is the value of a summary row; level is the value of any other.
	count  int
	level  tactic.Severity
	detail string
	basis  []string
	files  []string
}

func (e Env) reportList(v verbSpec) (*cli.Verb, error) {
	if v.Name != "list" || len(v.Aliases) > 0 {
		return nil, errors.New("the global list verb takes its name and alias from cli.ListVerb")
	}
	pipe, err := loadPipeline()
	if err != nil {
		return nil, err
	}
	if _, err := reportCells(reportRow{}, v.Columns); err != nil {
		return nil, err
	}
	spec := cli.Spec{
		Selectors: map[string]string{
			sectionSummary:     "show only the counts",
			sectionFiles:       "show only the notable files",
			sectionImpact:      "show only the impact",
			sectionRemediation: "show only the remediation",
			sectionMitigation:  "show only the mitigation",
		},
		Params:   map[string]string{inputDir: "<folder>", intelFile: "<file>", severityParam: "low|medium|high"},
		Switches: recursiveSwitch(),
		Required: []string{inputDir},
	}
	return cli.ListVerb(v.Summary, spec, func(a *cli.Args) error {
		threshold := tactic.High
		if given, ok := a.Params[severityParam]; ok {
			threshold = tactic.Severity(given)
			if threshold.Rank() == 0 {
				return cli.Usagef("--%s takes low, medium or high, not %q", severityParam, given)
			}
		}
		result, err := pipe.run(a)
		if err != nil {
			return err
		}
		wanted := map[string]bool{}
		for _, sel := range a.Selectors {
			wanted[sel] = true
		}
		table := render.Table{Columns: v.Columns}
		for _, row := range pipe.report(result, threshold, wanted) {
			cells, err := reportCells(row, v.Columns)
			if err != nil {
				return err
			}
			table.Rows = append(table.Rows, cells)
		}
		if err := render.Write(e.Stdout, table, e.options(a.Output)); err != nil {
			return err
		}
		return skippedError(result.skipped)
	}), nil
}

// report assembles the wanted sections in their fixed order.
func (p pipeline) report(a analysis, threshold tactic.Severity, wanted map[string]bool) []reportRow {
	var rows []reportRow
	if wanted[sectionSummary] {
		for _, m := range listMetrics(a) {
			rows = append(rows, reportRow{item: m.name, section: sectionSummary, count: m.value})
		}
	}
	if wanted[sectionFiles] {
		rows = append(rows, p.notableFiles(a, threshold)...)
	}
	found := p.gather(a)
	if wanted[sectionImpact] {
		for _, r := range p.assessment.Impacts(found) {
			detail := r.Text
			if len(r.Affected) > 0 {
				detail += " Affected: " + strings.Join(r.Affected, ", ")
				if r.More > 0 {
					detail += " and " + plural(r.More, "other")
				}
				detail += "."
			}
			rows = append(rows, reportRow{item: r.Name, section: sectionImpact, level: r.Level, detail: detail, basis: r.Basis, files: r.Files})
		}
	}
	for _, r := range p.assessment.Actions(found) {
		if wanted[r.Kind] {
			rows = append(rows, reportRow{item: r.Name, section: r.Kind, level: r.Level, detail: r.Text, basis: r.Basis, files: r.Files})
		}
	}
	return rows
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}

// notableFiles lists, in timeline order, each file that holds a finding at
// or above the threshold, with what was found and the files linked to it.
func (p pipeline) notableFiles(a analysis, threshold tactic.Severity) []reportRow {
	// An output is linked to the scripts that write it.
	writers := map[string][]string{}
	for _, s := range a.timeline.Steps {
		for _, out := range s.Outputs {
			writers[out] = appendUnique(writers[out], s.File.Path)
		}
	}
	var rows []reportRow
	for _, s := range a.timeline.Steps {
		level := tactic.Severity("")
		var reasons []string
		note := func(reason string, severity tactic.Severity) {
			if severity.Rank() < threshold.Rank() {
				return
			}
			reasons = appendUnique(reasons, reason)
			if severity.Rank() > level.Rank() {
				level = severity
			}
		}
		for _, hit := range s.Activities {
			note(hit.Name, p.highest(hit.Tactics))
		}
		for _, tool := range s.Tools {
			if name := p.tactics.Classify(tool); name != "" {
				note(tool+" ("+name+")", p.tactics.Severity(name))
			}
		}
		// A watchlist match is high whatever else the file holds.
		for _, hit := range s.IntelHits {
			note("watchlist "+hit.Attribution, tactic.High)
		}
		if len(reasons) == 0 {
			continue
		}
		linked := s.Outputs
		if s.File.Role != evidence.Script {
			linked = writers[s.File.Path]
		}
		rows = append(rows, reportRow{
			item: s.File.Path, section: string(s.File.Role), level: level,
			detail: strings.Join(reasons, ", "), files: linked,
		})
	}
	return rows
}

func (p pipeline) highest(tactics []string) tactic.Severity {
	severity := tactic.Low
	for _, name := range tactics {
		if s := p.tactics.Severity(name); s.Rank() > severity.Rank() {
			severity = s
		}
	}
	return severity
}

// gather indexes what the timeline found by the files it was found in.
func (p pipeline) gather(a analysis) assess.Evidence {
	found := assess.Evidence{
		Activities: map[string][]string{},
		Tactics:    map[string][]string{},
		Hits:       map[string][]string{},
		Indicators: map[string]map[string][]string{},
	}
	for _, s := range a.timeline.Steps {
		path := s.File.Path
		for _, hit := range s.Activities {
			found.Activities[hit.Name] = appendUnique(found.Activities[hit.Name], path)
		}
		for _, tool := range s.Tools {
			if name := p.tactics.Classify(tool); name != "" {
				found.Tactics[name] = appendUnique(found.Tactics[name], path)
			}
		}
		for _, hit := range s.IntelHits {
			found.Hits[hit.Attribution] = appendUnique(found.Hits[hit.Attribution], path)
		}
		for _, m := range s.Matches {
			if found.Indicators[path] == nil {
				found.Indicators[path] = map[string][]string{}
			}
			found.Indicators[path][m.Type] = append(found.Indicators[path][m.Type], m.Value)
		}
	}
	return found
}

// listMetrics counts distinct values across the whole timeline; an activity
// row counts the lines that show it. The intel row is present only when a
// watchlist was given.
func listMetrics(a analysis) []metric {
	roles := map[evidence.Role]int{}
	indicators := map[string]map[string]bool{}
	tactics := map[string]bool{}
	hits := map[string]bool{}
	activities := map[string]int{}
	total := 0
	for _, s := range a.timeline.Steps {
		roles[s.File.Role]++
		for _, hit := range s.Activities {
			activities[hit.Name] += hit.Lines
		}
		for _, name := range s.Tactics {
			tactics[name] = true
		}
		for _, m := range s.Matches {
			if indicators[m.Type] == nil {
				indicators[m.Type] = map[string]bool{}
			}
			if !indicators[m.Type][m.Value] {
				indicators[m.Type][m.Value] = true
				total++
			}
		}
		for _, h := range s.IntelHits {
			hits[h.Type+"\x00"+h.Value+"\x00"+h.Attribution] = true
		}
	}
	metrics := []metric{
		{"files", len(a.timeline.Steps)},
		{"scripts", roles[evidence.Script]},
		{"outputs", roles[evidence.Output]},
		{"indicators", total},
	}
	types := make([]string, 0, len(indicators))
	for typ := range indicators {
		types = append(types, typ)
	}
	sort.Strings(types)
	for _, typ := range types {
		metrics = append(metrics, metric{"indicators " + typ, len(indicators[typ])})
	}
	metrics = append(metrics, metric{"activities", len(activities)})
	names := make([]string, 0, len(activities))
	for name := range activities {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		metrics = append(metrics, metric{"activities " + name, activities[name]})
	}
	metrics = append(metrics, metric{"tactics", len(tactics)})
	if a.watchlist != nil {
		metrics = append(metrics, metric{"intel hits", len(hits)})
	}
	return metrics
}

func reportCells(r reportRow, columns []render.Column) ([]render.Value, error) {
	list := func(items []string) render.Value {
		if len(items) == 0 {
			return render.NotApplicable()
		}
		return render.Text(strings.Join(items, ", "))
	}
	cells := map[string]render.Value{
		"item":    render.Text(r.item),
		"section": render.Text(r.section),
		"value":   render.Text(string(r.level)),
		"detail":  render.NotApplicable(),
		"basis":   list(r.basis),
		"files":   list(r.files),
	}
	if r.section == sectionSummary || r.level == "" {
		cells["value"] = render.Int(int64(r.count))
	}
	if r.detail != "" {
		cells["detail"] = render.Text(r.detail)
	}
	return orderCells("report list", cells, columns)
}
