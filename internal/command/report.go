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

// The sections of a report that hold rows; each is a selector.
const (
	sectionSummary     = "summary"
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

// leftOut is the row of the summary that counts the files outside the window.
const leftOut = "left out"

type metric struct {
	name  string
	value int
	// detail says what the count is of, where the name alone does not.
	detail string
}

// reportRow is one line of a report: a count, a target, an exposed value,
// an impact, a recommended action or a mitigation.
type reportRow struct {
	item    string
	section string
	// count is the value of a summary row; level is the value of any other.
	count  int
	level  tactic.Severity
	detail string
	basis  []string
	files  []string
	// attack and atlas are the techniques an impact shows, or those a
	// mitigation addresses.
	attack []string
	atlas  []string
	// targets name what the row concerns: the account, the file, the host.
	targets []string
	// evidence holds the lines that show it, each with its file and line.
	evidence []string
	// exposed lists the exposed accounts and credentials the row concerns.
	exposed []listed
}

// report assembles the wanted sections in their fixed order.
func (p pipeline) report(a analysis, wanted map[string]bool) ([]reportRow, []shownActivity) {
	var rows []reportRow
	if wanted[sectionSummary] {
		for _, m := range listMetrics(a) {
			rows = append(rows, reportRow{item: m.name, section: sectionSummary, count: m.value, detail: m.detail})
		}
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
				item: e.value, section: sectionExposure, level: tactic.Severity(e.kind.Severity),
				detail: e.kind.Name + ": " + detail, files: cites,
			})
		}
	}
	found, shown, tools := p.gather(a)
	held := hold(a.exposed)
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
			row.exposed = held.concerning(r.Exposed, shownIn(found, r), citedBy(shown, tools, r.Activities, r.Basis))
			rows = append(rows, row)
		}
	}
	if wanted[sectionRemediation] {
		for _, r := range p.assessment.Remediation(found) {
			row := reportRow{item: r.Name, section: sectionRemediation, level: r.Level, detail: r.Text, basis: r.Basis, files: r.Files}
			row.targets, row.evidence = support(shown, tools, r)
			row.exposed = held.concerning(r.Exposed, shownIn(found, r), citedBy(shown, tools, r.Activities, r.Basis))
			rows = append(rows, row)
		}
	}
	if wanted[sectionMitigation] {
		for _, row := range p.mitigations(shown, impacts) {
			// A mitigation concerns what the files and the lines of its activities hold.
			var files []string
			for _, name := range row.basis {
				files = append(files, found.Activities[name]...)
			}
			row.exposed = held.concerning(nil, files, citedBy(shown, nil, row.basis, nil))
			rows = append(rows, row)
		}
	}
	return rows, shown
}

// citedBy lists the lines that show the named activities and the commands
// of the tools behind a basis: the accounts they name are what an entry concerns.
func citedBy(shown []shownActivity, tools map[string][]cited, activities, basis []string) []cite {
	var lines []cite
	for _, s := range shown {
		if slices.Contains(activities, s.hit.Name) {
			for _, c := range s.cites {
				lines = append(lines, c.cite)
			}
		}
	}
	for _, name := range basis {
		if tactic, isTools := strings.CutSuffix(name, toolsSuffix); isTools {
			for _, c := range tools[tactic] {
				lines = append(lines, c.cite)
			}
		}
	}
	return lines
}

// shownIn lists the files that show an entry by its activities and by the
// tools of its tactics: the credentials they hold are what the entry concerns.
func shownIn(found assess.Evidence, r assess.Result) []string {
	var files []string
	for _, name := range r.Activities {
		files = append(files, found.Activities[name]...)
	}
	for _, basis := range r.Basis {
		if name, isTools := strings.CutSuffix(basis, toolsSuffix); isTools {
			files = append(files, found.Tactics[name]...)
		}
	}
	return files
}

// support names what an impact or an action acts on and the lines that show
// it: the subjects and lines of its activities and the commands of the tools
// behind its tactics.
func support(shown []shownActivity, tools map[string][]cited, r assess.Result) (targets, evidence []string) {
	// The key is the place and the bare command, so the same line is quoted once
	// even in a structured output where it has no number: an audit record is not
	// quoted for its activity and again for its tool.
	quoted := map[string]bool{}
	for _, name := range r.Activities {
		for _, s := range shown {
			if s.hit.Name != name {
				continue
			}
			for _, c := range s.cites {
				targets = appendUnique(targets, c.targets()...)
				if quoted[c.key()] {
					continue
				}
				evidence = append(evidence, name+": "+c.String())
				quoted[c.key()] = true
			}
		}
	}
	for _, basis := range r.Basis {
		if name, isTools := strings.CutSuffix(basis, toolsSuffix); isTools {
			for _, c := range tools[name] {
				if quoted[c.key()] {
					continue
				}
				evidence = append(evidence, c.String())
				quoted[c.key()] = true
			}
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
	text string
	// command is the line without its activity or tool name, so the same line
	// quoted for an activity and for its tool is recognised as one.
	command  string
	subjects []activity.Subject
}

// cited keeps a line of evidence, where it stands and what it acts on.
func (a analysis) cited(path string, e activity.Evidence) cited {
	return cited{cite: cite{path, e.Line}, text: e.Text, command: e.Text, subjects: slices.Clone(e.Subjects)}
}

// String writes the line and where it stands.
func (c cited) String() string {
	return c.text + " (" + c.cite.String() + ")"
}

// key identifies the underlying line by its place and bare command, so it is
// the same whether the line is quoted for an activity or for its tool.
func (c cited) key() string {
	return c.cite.String() + "\x00" + c.command
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
	actFiles, tacFiles, hitFiles := seenFiles{}, seenFiles{}, seenFiles{}
	for _, s := range a.timeline.Steps {
		path := s.File.Path
		for _, hit := range s.Activities {
			i, ok := index[hit.Name]
			if !ok {
				i = len(shown)
				index[hit.Name] = i
				shown = append(shown, shownActivity{hit: hit})
			}
			if actFiles.fresh(hit.Name, path) {
				found.Activities[hit.Name] = append(found.Activities[hit.Name], path)
				shown[i].files = append(shown[i].files, path)
			}
			for _, e := range hit.Evidence {
				if len(shown[i].cites) < maxCited {
					shown[i].cites = append(shown[i].cites, a.cited(path, e))
				}
			}
		}
		for _, tool := range s.Tools {
			if name := p.tactics.Classify(tool); name != "" && tacFiles.fresh(name, path) {
				found.Tactics[name] = append(found.Tactics[name], path)
			}
		}
		for _, c := range s.Commands {
			if name := p.tactics.Classify(c.Tool); name != "" && len(tools[name]) < maxCited {
				tools[name] = append(tools[name], cited{cite: cite{path, c.Line}, text: c.Tool + ": " + c.Text, command: c.Text})
			}
		}
		for _, hit := range s.IntelHits {
			if hitFiles.fresh(hit.Attribution, path) {
				found.Hits[hit.Attribution] = append(found.Hits[hit.Attribution], path)
			}
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
		{name: "files", value: len(a.timeline.Steps)},
		{name: "scripts", value: roles[evidence.Script]},
		{name: "outputs", value: roles[evidence.Output]},
	}
	// A run that read a window of time says so, and how many files it left out.
	if a.window.set() {
		metrics = append(metrics, metric{name: leftOut, value: a.outside, detail: a.window.String()})
	}
	metrics = append(metrics, metric{name: "indicators", value: total})
	types := make([]string, 0, len(indicators))
	for typ := range indicators {
		types = append(types, typ)
	}
	sort.Strings(types)
	for _, typ := range types {
		metrics = append(metrics, metric{name: "indicators " + typ, value: len(indicators[typ])})
	}
	metrics = append(metrics, metric{name: "activities", value: len(activities)})
	names := make([]string, 0, len(activities))
	for name := range activities {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		metrics = append(metrics, metric{name: "activities " + name, value: activities[name]})
	}
	metrics = append(metrics, metric{name: "tactics", value: len(tactics)})
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
		metrics = append(metrics, metric{name: "intel hits", value: len(hits)})
	}
	return metrics
}

// perKind counts the kinds of a list that is sorted by kind: the total
// under name, then one count for each kind in the order it comes.
func perKind(name string, kinds []string) []metric {
	metrics := []metric{{name: name, value: len(kinds)}}
	for _, kind := range kinds {
		if last := &metrics[len(metrics)-1]; last.name == name+" "+kind {
			last.value++
		} else {
			metrics = append(metrics, metric{name: name + " " + kind, value: 1})
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
		"exposed":  render.NotApplicable(),
	}
	if len(r.exposed) > 0 {
		lines := make([]string, len(r.exposed))
		for i, e := range r.exposed {
			lines[i] = e.line
		}
		cells["exposed"] = render.Text(strings.Join(lines, "\n"))
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
