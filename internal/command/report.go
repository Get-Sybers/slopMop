package command

import (
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/get-sybers/slopmop/internal/activity"
	"github.com/get-sybers/slopmop/internal/assess"
	"github.com/get-sybers/slopmop/internal/evidence"
	"github.com/get-sybers/slopmop/internal/mitre"
	"github.com/get-sybers/slopmop/internal/render"
	"github.com/get-sybers/slopmop/internal/tactic"
)

// The sections of a report; each is a selector. A notable file's row
// carries its role as the section.
const (
	sectionSummary     = "summary"
	sectionFiles       = "files"
	sectionImpact      = "impact"
	sectionRemediation = "remediation"
	sectionMitigation  = "mitigation"
)

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
	// attack and atlas are the techniques a file or an impact shows, or
	// those a mitigation addresses.
	attack []string
	atlas  []string
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
	found, shown := p.gather(a)
	impacts := p.assessment.Impacts(found)
	if wanted[sectionImpact] {
		for _, r := range impacts {
			detail := r.Text
			if len(r.Affected) > 0 {
				detail += " Affected: " + strings.Join(r.Affected, ", ")
				if r.More > 0 {
					detail += " and " + plural(r.More, "other")
				}
				detail += "."
			}
			row := reportRow{item: r.Name, section: sectionImpact, level: r.Level, detail: detail, basis: r.Basis, files: r.Files}
			row.attack, row.atlas = p.techniques(shown, r.Activities)
			row.atlas = appendUnique(row.atlas, r.Atlas...)
			rows = append(rows, row)
		}
	}
	if wanted[sectionRemediation] {
		for _, r := range p.assessment.Remediation(found) {
			rows = append(rows, reportRow{item: r.Name, section: sectionRemediation, level: r.Level, detail: r.Text, basis: r.Basis, files: r.Files})
		}
	}
	if wanted[sectionMitigation] {
		rows = append(rows, p.mitigations(shown, impacts)...)
	}
	return rows
}

// techniques returns the ATT&CK and ATLAS techniques of the named activities.
func (p pipeline) techniques(shown []shownActivity, names []string) (attack, atlas []string) {
	for _, s := range shown {
		if slices.Contains(names, s.hit.Name) {
			attack = appendUnique(attack, s.hit.Attack...)
			atlas = appendUnique(atlas, p.atlasOf(s.hit)...)
		}
	}
	return attack, atlas
}

// shownActivity is an activity the timeline found and the files that show it.
type shownActivity struct {
	hit   activity.Hit
	files []string
}

// cause is what showed a technique: the activities or impacts, their files
// and the highest severity among them.
type cause struct {
	names []string
	files []string
	level tactic.Severity
}

// mitigations lists what ATT&CK and then ATLAS say mitigates the techniques
// that were found. The link from technique to mitigation is the framework's.
func (p pipeline) mitigations(shown []shownActivity, impacts []assess.Result) []reportRow {
	attack, atlas := map[string]*cause{}, map[string]*cause{}
	note := func(by map[string]*cause, id, name string, files []string, level tactic.Severity) {
		c, ok := by[id]
		if !ok {
			c = &cause{level: tactic.Low}
			by[id] = c
		}
		c.names = appendUnique(c.names, name)
		c.files = appendUnique(c.files, files...)
		if level.Rank() > c.level.Rank() {
			c.level = level
		}
	}
	for _, s := range shown {
		level := p.highest(s.hit.Tactics)
		for _, id := range s.hit.Attack {
			note(attack, id, s.hit.Name, s.files, level)
		}
		for _, id := range p.atlasOf(s.hit) {
			note(atlas, id, s.hit.Name, s.files, level)
		}
	}
	// An impact can stand for an ATLAS technique that no single line shows.
	for _, im := range impacts {
		for _, id := range im.Atlas {
			note(atlas, id, im.Name, im.Files, im.Level)
		}
	}
	rows := mitigationRows(p.catalogue.Attack, attack, false)
	return append(rows, mitigationRows(p.catalogue.Atlas, atlas, true)...)
}

func mitigationRows(framework mitre.Framework, by map[string]*cause, isAtlas bool) []reportRow {
	found := make([]string, 0, len(by))
	for id := range by {
		found = append(found, id)
	}
	sort.Strings(found)
	var rows []reportRow
	for _, m := range framework.MitigationsFor(found) {
		row := reportRow{item: m.ID + " " + m.Name, section: sectionMitigation, level: tactic.Low, detail: m.Summary}
		for _, id := range m.Techniques {
			c := by[id]
			row.basis = appendUnique(row.basis, c.names...)
			row.files = appendUnique(row.files, c.files...)
			if c.level.Rank() > row.level.Rank() {
				row.level = c.level
			}
		}
		sort.Strings(row.files)
		if isAtlas {
			row.atlas = m.Techniques
		} else {
			row.attack = m.Techniques
		}
		rows = append(rows, row)
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].level.Rank() > rows[j].level.Rank() })
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
		row := reportRow{
			item: s.File.Path, section: string(s.File.Role), level: level,
			detail: strings.Join(reasons, ", "), files: linked,
		}
		for _, hit := range s.Activities {
			row.attack = appendUnique(row.attack, hit.Attack...)
			row.atlas = appendUnique(row.atlas, p.atlasOf(hit)...)
		}
		rows = append(rows, row)
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

// gather indexes what the timeline found by the files it was found in, and
// lists the activities in the order they were first seen.
func (p pipeline) gather(a analysis) (assess.Evidence, []shownActivity) {
	var shown []shownActivity
	index := map[string]int{}
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
			i, ok := index[hit.Name]
			if !ok {
				i = len(shown)
				index[hit.Name] = i
				shown = append(shown, shownActivity{hit: hit})
			}
			shown[i].files = appendUnique(shown[i].files, path)
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
	return found, shown
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
		"attack":  list(r.attack),
		"atlas":   list(r.atlas),
	}
	if r.section == sectionSummary || r.level == "" {
		cells["value"] = render.Int(int64(r.count))
	}
	if r.detail != "" {
		cells["detail"] = render.Text(r.detail)
	}
	return orderCells("report", cells, columns)
}
