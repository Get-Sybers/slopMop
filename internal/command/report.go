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
	sectionTargeted    = "targeted"
	sectionExposure    = "exposure"
	sectionImpact      = "impact"
	sectionRemediation = "remediation"
	sectionMitigation  = "mitigation"
)

const (
	// maxCited is how many lines one activity, or the tools of one tactic, keep as evidence.
	maxCited = 24
	// toolsSuffix ends the basis that names the tools of a tactic.
	toolsSuffix = " tools"
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
	// targets name what the row concerns: the account, the file, the host.
	targets []string
	// evidence holds the lines that show it, each with its file and line.
	evidence []string
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
	if wanted[sectionTargeted] {
		for _, t := range a.targeted {
			detail := t.kind.Name + ": " + t.origin
			if t.scope != "" {
				detail += ", " + t.scope
			}
			if t.origin == originDiscovered {
				detail += ", first held by " + t.from.String()
			}
			rows = append(rows, reportRow{
				item: t.value, section: sectionTargeted, level: t.level(), detail: detail, files: t.places(), evidence: t.lines,
			})
		}
	}
	if wanted[sectionExposure] {
		for _, e := range a.exposed {
			detail := e.seen
			if e.kind.Secret {
				detail = e.label() + ", " + e.seen
			}
			cites := make([]string, len(e.cites))
			for i, c := range e.cites {
				cites[i] = c.String()
			}
			rows = append(rows, reportRow{
				item: e.shown(), section: sectionExposure, level: tactic.Severity(e.kind.Severity),
				detail: e.kind.Name + ": " + detail, files: cites,
			})
		}
	}
	found, shown, tools := p.gather(a)
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
			row.targets, row.evidence = support(shown, tools, r)
			rows = append(rows, row)
		}
	}
	if wanted[sectionRemediation] {
		for _, r := range p.assessment.Remediation(found) {
			row := reportRow{item: r.Name, section: sectionRemediation, level: r.Level, detail: r.Text, basis: r.Basis, files: r.Files}
			row.targets, row.evidence = support(shown, tools, r)
			rows = append(rows, row)
		}
	}
	if wanted[sectionMitigation] {
		rows = append(rows, p.mitigations(shown, impacts)...)
	}
	return rows
}

// support names what an impact or an action concerns and the lines that
// show it: the subjects and lines of its activities, the commands of the
// tools behind its tactics, and the exposed values it lists.
func support(shown []shownActivity, tools map[string][]cited, r assess.Result) (targets, evidence []string) {
	quoted := map[cite]bool{}
	for _, name := range r.Activities {
		for _, s := range shown {
			if s.hit.Name != name {
				continue
			}
			for _, c := range s.cites {
				targets = appendUnique(targets, c.targets()...)
				evidence = append(evidence, name+": "+c.String())
				quoted[c.cite] = true
			}
		}
	}
	for _, basis := range r.Basis {
		if name, isTools := strings.CutSuffix(basis, toolsSuffix); isTools {
			for _, c := range tools[name] {
				// A line an activity already quotes is not quoted again for its tool.
				if c.line == 0 || !quoted[c.cite] {
					evidence = append(evidence, c.String())
				}
			}
		}
	}
	for _, l := range r.Exposed {
		for _, label := range l.Labels {
			if !strings.Contains(label, " ") {
				label = l.Kind + " " + label
			}
			targets = appendUnique(targets, label)
		}
		if l.More > 0 {
			targets = append(targets, "and "+strconv.Itoa(l.More)+" more of kind "+l.Kind)
		}
	}
	return targets, evidence
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

// shownActivity is an activity the timeline found, the files that show it
// and the first lines that do.
type shownActivity struct {
	hit   activity.Hit
	files []string
	cites []cited
}

// cited is one line of evidence in one file.
type cited struct {
	cite
	text     string
	subjects []activity.Subject
}

// cited keeps a line of evidence with every secret in it masked.
func (a analysis) cited(path string, e activity.Evidence) cited {
	subjects := make([]activity.Subject, len(e.Subjects))
	for i, s := range e.Subjects {
		subjects[i] = activity.Subject{Label: s.Label, Value: a.redact(s.Value)}
	}
	return cited{cite{path, e.Line}, a.redact(e.Text), subjects}
}

// String writes the line and where it stands.
func (c cited) String() string {
	return c.text + " (" + c.cite.String() + ")"
}

// targets names the subjects of the line, each with its label.
func (c cited) targets() []string {
	out := make([]string, len(c.subjects))
	for i, s := range c.subjects {
		out[i] = s.Label + " " + s.Value
	}
	return out
}

// subjects lists the targets of an activity across its lines, each once.
func (s shownActivity) subjects() []string {
	var out []string
	for _, c := range s.cites {
		out = appendUnique(out, c.targets()...)
	}
	return out
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
	rows = append(rows, mitigationRows(p.catalogue.Atlas, atlas, true)...)
	// A mitigation is advice of the framework; what it is for here makes it concrete.
	for i := range rows {
		for _, name := range rows[i].basis {
			for _, s := range shown {
				if subjects := s.subjects(); s.hit.Name == name && len(subjects) > 0 {
					rows[i].targets = append(rows[i].targets, name+": "+strings.Join(subjects, ", "))
				}
			}
		}
	}
	return rows
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

// gather indexes what the timeline found by the files it was found in, lists
// the activities in the order they were first seen, and keeps the commands
// of the tools behind each tactic.
func (p pipeline) gather(a analysis) (assess.Evidence, []shownActivity, map[string][]cited) {
	var shown []shownActivity
	index := map[string]int{}
	tools := map[string][]cited{}
	found := assess.Evidence{
		Activities: map[string][]string{},
		Tactics:    map[string][]string{},
		Hits:       map[string][]string{},
		Indicators: map[string]map[string][]string{},
		Exposed:    exposedEvidence(a.exposed),
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
			for _, e := range hit.Evidence {
				if len(shown[i].cites) < maxCited {
					shown[i].cites = append(shown[i].cites, a.cited(path, e))
				}
			}
		}
		for _, tool := range s.Tools {
			if name := p.tactics.Classify(tool); name != "" {
				found.Tactics[name] = appendUnique(found.Tactics[name], path)
			}
		}
		for _, c := range s.Commands {
			if name := p.tactics.Classify(c.Tool); name != "" && len(tools[name]) < maxCited {
				tools[name] = append(tools[name], cited{cite: cite{path, c.Line}, text: a.redact(c.Tool + ": " + c.Text)})
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
	return found, shown, tools
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
	aimed := make([]string, len(a.targeted))
	for i, t := range a.targeted {
		aimed[i] = t.kind.Name
	}
	metrics = append(metrics, perKind("targeted", aimed)...)
	held := make([]string, len(a.exposed))
	for i, e := range a.exposed {
		held[i] = e.kind.Name
	}
	metrics = append(metrics, perKind("exposed", held)...)
	metrics = append(metrics, intentCount(a)...)
	if a.watchlist != nil {
		metrics = append(metrics, metric{"intel hits", len(hits)})
	}
	return metrics
}

// perKind counts the kinds of a list that is sorted by kind: the total
// under name, then one count for each kind in the order it comes.
func perKind(name string, kinds []string) []metric {
	metrics := []metric{{name, len(kinds)}}
	for _, kind := range kinds {
		if last := &metrics[len(metrics)-1]; last.name == name+" "+kind {
			last.value++
		} else {
			metrics = append(metrics, metric{name + " " + kind, 1})
		}
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
		"targets": render.NotApplicable(),
		// One line of evidence is one line of the cell, so a command with a comma stays whole.
		"evidence": render.NotApplicable(),
	}
	if len(r.targets) > 0 {
		cells["targets"] = render.Text(strings.Join(r.targets, "; "))
	}
	if len(r.evidence) > 0 {
		cells["evidence"] = render.Text(strings.Join(r.evidence, "\n"))
	}
	if r.section == sectionSummary || r.level == "" {
		cells["value"] = render.Int(int64(r.count))
	}
	if r.detail != "" {
		cells["detail"] = render.Text(r.detail)
	}
	return orderCells("report", cells, columns)
}
