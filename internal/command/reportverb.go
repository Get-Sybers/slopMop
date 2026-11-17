package command

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/get-sybers/slopmop/internal/cli"
	"github.com/get-sybers/slopmop/internal/inventory"
	"github.com/get-sybers/slopmop/internal/render"
	"github.com/get-sybers/slopmop/internal/tactic"
	"github.com/get-sybers/slopmop/internal/trace"
)

const (
	// fewFiles is how many file names an entry of the readout lists in full.
	fewFiles = 3
	// fewLines is how many lines of evidence an entry of the readout shows.
	fewLines = 6
	// fewFindingLines is how many of them a finding shows.
	fewFindingLines = 3
	// fewTargets is how many targets an entry of the readout names.
	fewTargets = 12
	// fewExposed is how many values of one kind the readout lists.
	fewExposed = 40
)

type sectionSpec struct {
	Name    string `json:"name"`
	Title   string `json:"title"`
	Summary string `json:"summary"`
	Note    string `json:"note"`
}

// reportRun is one analysis and what every section and every table reads from it.
type reportRun struct {
	pipe   pipeline
	result analysis
	rows   []reportRow
	shown  []shownActivity
}

type sectionBuilder func(w reportRun) []render.Group

// kindSections is what the words of the report verb are called in help and errors.
const kindSections = "sections"

func checkSections(v verbSpec, builders map[string]sectionBuilder) error {
	if len(v.Sections) == 0 {
		return errors.New("commands.json: it needs a section")
	}
	seen := map[string]bool{}
	for _, s := range v.Sections {
		switch {
		case s.Name == "" || s.Title == "" || s.Summary == "":
			return fmt.Errorf("commands.json: section %q needs a name, a title and a summary", s.Name)
		case seen[s.Name]:
			return fmt.Errorf("commands.json: section %q is declared twice", s.Name)
		case builders[s.Name] == nil:
			return fmt.Errorf("commands.json declares the section %q, which has no implementation", s.Name)
		}
		seen[s.Name] = true
	}
	for name := range builders {
		if !seen[name] {
			return fmt.Errorf("commands.json does not declare the section %q", name)
		}
	}
	return nil
}

func sectionBuilders() map[string]sectionBuilder {
	return map[string]sectionBuilder{
		sectionSummary:     reportRun.summary,
		"timeline":         reportRun.timeline,
		"intents":          reportRun.intents,
		"findings":         reportRun.findings,
		sectionFiles:       reportRun.files,
		sectionTargeted:    reportRun.targeted,
		sectionExposure:    reportRun.exposure,
		sectionImpact:      func(w reportRun) []render.Group { return w.assessed(sectionImpact) },
		sectionRemediation: func(w reportRun) []render.Group { return w.assessed(sectionRemediation) },
		sectionMitigation:  reportRun.mitigation,
	}
}

// reportVerb reads the folder and everything below it once, saves every
// section and every table, and prints every section or those named.
func (e Env) reportVerb(v verbSpec, doc commandsDoc) (*cli.Verb, error) {
	builders := sectionBuilders()
	if err := checkSections(v, builders); err != nil {
		return nil, err
	}
	columns, err := checkSaved(v.Saved, doc)
	if err != nil {
		return nil, err
	}
	options := doc.options(v)
	for _, name := range []string{inputDir, intelFile, outDir, secrets, coresOption, memoryOption} {
		if !slices.ContainsFunc(options, func(o cli.Option) bool { return o.Name == name }) {
			return nil, fmt.Errorf("commands.json: it reads the option %q, which it does not name", name)
		}
	}
	pipe, err := loadPipeline()
	if err != nil {
		return nil, err
	}
	words := make([]cli.Word, len(v.Sections))
	for i, s := range v.Sections {
		words[i] = cli.Word{Name: s.Name, Summary: s.Summary}
	}
	run := func(a *cli.Args) error {
		folder := a.Options[inputDir]
		// A folder that cannot be written to is refused before the work is done.
		dir, err := outputDir(folder, a.Options[outDir], e.WorkDir, v.Saved.Prefix)
		if err != nil {
			return err
		}
		plain := false
		switch given, ok := a.Options[secrets]; {
		case ok && given == secretsShown:
			plain = true
		case ok && given != secretsMasked:
			return cli.Usagef("-%s takes %s or %s, not %q", secrets, secretsMasked, secretsShown, given)
		}
		cores, err := percentage(a, coresOption)
		if err != nil {
			return err
		}
		memory, err := percentage(a, memoryOption)
		if err != nil {
			return err
		}
		restore, err := limit(cores, memory)
		if err != nil {
			return err
		}
		defer restore()
		result, err := pipe.read(folder, inventory.MaxDepth, a.Options[intelFile], plain)
		if err != nil {
			return err
		}
		every := map[string]bool{
			sectionSummary: true, sectionFiles: true, sectionTargeted: true, sectionExposure: true, sectionImpact: true,
			sectionRemediation: true, sectionMitigation: true,
		}
		rows, shown := pipe.report(result, tactic.High, every)
		run := reportRun{pipe: pipe, result: result, rows: rows, shown: shown}
		// The disk holds every section; the screen holds those asked for.
		full := render.Readout{Title: "slopmop report   " + folder, Banner: run.banner(), Hints: v.Hints}
		screen := full
		for _, s := range v.Sections {
			section := render.Section{Title: s.Title, Note: s.Note, Groups: builders[s.Name](run)}
			if sectionEmpty(section) {
				continue
			}
			full.Sections = append(full.Sections, section)
			if slices.Contains(a.Words, s.Name) {
				screen.Sections = append(screen.Sections, section)
			}
		}
		// A failed save does not withhold the readout; it fails the command after it.
		names, saveErr := run.save(dir, v.Saved, columns, full)
		if saveErr == nil {
			screen.Hints = append([]string{"saved to " + dir + ": " + strings.Join(names, ", ")}, v.Hints...)
		}
		if err := render.WriteReadout(e.Stdout, screen, e.Colour); err != nil {
			return err
		}
		return errors.Join(saveErr, skippedError(result.skipped, inventory.MaxDepth))
	}
	return &cli.Verb{Name: v.Name, Summary: v.Summary, Kind: kindSections, Words: words, Options: options, Run: run}, nil
}

// banner gives the verdict: the impacts by severity, or that nothing was found.
func (w reportRun) banner() render.Banner {
	counts := map[tactic.Severity]int{}
	total := 0
	for _, r := range w.rows {
		if r.section == sectionImpact {
			counts[r.level]++
			total++
		}
	}
	if total == 0 {
		return render.Banner{Level: render.LevelClear, Text: "NOTHING FOUND in " + plural(len(w.result.timeline.Steps), "file")}
	}
	var parts []string
	top := tactic.Severity("")
	for _, level := range []tactic.Severity{tactic.High, tactic.Medium, tactic.Low} {
		if counts[level] == 0 {
			continue
		}
		if top == "" {
			top = level
		}
		parts = append(parts, strconv.Itoa(counts[level])+" "+string(level))
	}
	text := strings.ToUpper(string(top)) + " - " + plural(total, "impact") + ": " + strings.Join(parts, ", ")
	return render.Banner{Level: string(top), Text: text}
}

func sectionEmpty(s render.Section) bool {
	for _, g := range s.Groups {
		if len(g.Entries) > 0 {
			return false
		}
	}
	return true
}

// summary gives one line per count; the files and the indicators carry
// their breakdown, and each activity carries its own count in the findings.
func (w reportRun) summary() []render.Group {
	g := render.Group{Columns: []string{"item", "count", "of which"}}
	var roles, types, kinds, aims []string
	for _, r := range w.rows {
		if r.section != sectionSummary {
			continue
		}
		parent, part, nested := strings.Cut(r.item, " ")
		switch {
		case r.item == "scripts" || r.item == "outputs":
			roles = append(roles, strconv.Itoa(r.count)+" "+r.item)
		case nested && parent == "indicators":
			types = append(types, strconv.Itoa(r.count)+" "+part)
		case nested && parent == "exposed":
			kinds = append(kinds, w.kindTitle(part, false)+" "+strconv.Itoa(r.count))
		case nested && parent == "targeted":
			aims = append(aims, w.kindTitle(part, true)+" "+strconv.Itoa(r.count))
		case nested && parent == "activities":
		default:
			g.Entries = append(g.Entries, render.Entry{Cells: []string{r.item, strconv.Itoa(r.count)}})
		}
	}
	for i := range g.Entries {
		cells := &g.Entries[i].Cells
		switch (*cells)[0] {
		case "files":
			*cells = append(*cells, strings.Join(roles, ", "))
		case "indicators":
			*cells = append(*cells, strings.Join(types, ", "))
		case "exposed":
			*cells = append(*cells, strings.Join(kinds, ", "))
		case "targeted":
			*cells = append(*cells, strings.Join(aims, ", "))
		}
	}
	return []render.Group{g}
}

func (w reportRun) timeline() []render.Group {
	g := render.Group{Columns: []string{"step", "time", "role", "file"}}
	for _, s := range w.result.timeline.Steps {
		g.Entries = append(g.Entries, render.Entry{
			Cells:  []string{strconv.Itoa(s.Turn), stepTime(s), string(s.File.Role), s.File.Path},
			Detail: append([]render.Detail{{Label: "intent", Text: w.result.intentOf[s.File.Path]}}, stepDetail(s)...),
		})
	}
	return []render.Group{g}
}

// stepTime is the time the timeline shows for a file: the same instant it is
// ordered by, written as one ISO-8601 UTC stamp whether it came from the file
// name or the modified time.
func stepTime(s trace.Step) string {
	if t := fileTime(s.File); !t.IsZero() {
		return render.Stamp(t, nil)
	}
	return "-"
}

func stepDetail(s trace.Step) []render.Detail {
	list := func(items []string) string { return strings.Join(items, ", ") }
	activities := make([]string, len(s.Activities))
	for i, a := range s.Activities {
		activities[i] = a.Name
	}
	hits := make([]string, len(s.IntelHits))
	for i, h := range s.IntelHits {
		hits[i] = h.Attribution + ": " + h.Value
	}
	detail := []render.Detail{
		{Label: "tools", Text: list(s.Tools)},
		{Label: "tactics", Text: list(s.Tactics)},
		{Label: "activities", Text: list(activities)},
		{Label: "transforms", Text: list(s.Transforms)},
		{Label: "wrote", Text: list(s.Outputs)},
		{Label: "watchlist", Text: list(hits)},
		{Label: "note", Text: string(s.File.Note)},
	}
	if s.Indicators > 0 {
		detail = append(detail, render.Detail{Label: "indicators", Text: strconv.Itoa(s.Indicators)})
	}
	return detail
}

// kindTitle gives the title of a kind of exposure, or its title among the
// targets of the scripts; the name stands in when the kind has none.
func (w reportRun) kindTitle(name string, targeted bool) string {
	for _, k := range w.pipe.exposures.Kinds() {
		switch {
		case k.Name != name:
		case targeted && k.Targeted != "":
			return k.Targeted
		case !targeted:
			return k.Title
		}
	}
	return name
}

// findings groups the findings by kind; each group is most severe first.
func (w reportRun) findings() []render.Group {
	lines := map[string]int{}
	for _, r := range w.rows {
		if name, isActivity := strings.CutPrefix(r.item, "activities "); isActivity && r.section == sectionSummary {
			lines[name] = r.count
		}
	}
	groups := []render.Group{
		{Title: "activities", Columns: []string{"activity", "seen", "tactics", "techniques"}},
		{Title: "indicators", Columns: []string{"type", "value", "files"}},
		{Title: "tactics", Columns: []string{"tactic", "identifiers", "files"}},
	}
	more := 0
	for _, f := range w.pipe.listFindings(w.result) {
		e := render.Entry{Level: string(f.severity)}
		mitre := strings.Join(append(slices.Clone(f.attack), f.atlas...), ", ")
		at := 0
		switch f.kind {
		case kindActivity:
			e.Cells = []string{f.label, plural(lines[f.label], "line"), strings.Join(f.tactics, ", "), mitre}
			e.Detail = lined("what", f.evidence, fewFindingLines, "the saved findings")
		case kindIndicator:
			at = 1
			e.Cells = []string{f.label, f.indicator, few(f.files)}
			e.Detail = []render.Detail{{Label: "watchlist", Text: strings.Join(f.attributions, ", ")}}
		default:
			at = 2
			e.Cells = []string{strings.Join(f.tactics, ", "), mitre, few(f.files)}
		}
		if at == 1 && len(groups[at].Entries) == fewExposed {
			more++
			continue
		}
		groups[at].Entries = append(groups[at].Entries, e)
	}
	// A log can hold a hundred thousand indicators; the saved findings hold all of them.
	if more > 0 {
		groups[1].Entries = append(groups[1].Entries, render.Entry{Cells: []string{"and " + strconv.Itoa(more) + " more in the saved findings"}})
	}
	return groups
}

func (w reportRun) files() []render.Group {
	g := render.Group{Columns: []string{"role", "file"}}
	for _, r := range w.pipe.notableFiles(w.result, tactic.High) {
		g.Entries = append(g.Entries, render.Entry{
			Level: string(r.level),
			Cells: []string{r.section, r.item},
			Detail: []render.Detail{
				{Label: "found", Text: r.detail},
				{Label: "linked", Text: few(r.files)},
			},
		})
	}
	return []render.Group{g}
}

// assessed writes the impact or remediation rows of the report: what each
// says, what it concerns, and the lines of evidence that show it.
func (w reportRun) assessed(section string) []render.Group {
	g := render.Group{Columns: []string{section}}
	for _, r := range w.rows {
		if r.section != section {
			continue
		}
		detail := []render.Detail{{Text: r.detail}, {Label: "targets", Text: fewOf(r.targets, fewTargets, "; ")}}
		detail = append(detail, lined("what", r.evidence, fewLines, "report.json")...)
		detail = append(detail, render.Detail{Label: "basis", Text: strings.Join(r.basis, ", ")})
		if len(r.evidence) == 0 {
			detail = append(detail, render.Detail{Label: "files", Text: few(r.files)})
		}
		g.Entries = append(g.Entries, render.Entry{Level: string(r.level), Cells: []string{r.item}, Detail: detail})
	}
	return []render.Group{g}
}

// mitigation gives each mitigation with the techniques found that it
// addresses, the framework's own sentence, and what it is for in this evidence.
func (w reportRun) mitigation() []render.Group {
	g := render.Group{Columns: []string{"mitigation", "techniques"}}
	for _, r := range w.rows {
		if r.section != sectionMitigation {
			continue
		}
		detail := []render.Detail{{Text: r.detail}}
		detail = append(detail, lined("for", r.targets, fewLines, "report.json")...)
		if len(r.targets) == 0 {
			detail = append(detail, render.Detail{Label: "for", Text: strings.Join(r.basis, ", ")})
		}
		g.Entries = append(g.Entries, render.Entry{
			Level:  string(r.level),
			Cells:  []string{r.item, strings.Join(append(slices.Clone(r.attack), r.atlas...), ", ")},
			Detail: detail,
		})
	}
	return []render.Group{g}
}

// targeted lists what the scripts name outright, a group per kind: the
// value, whether the attacker knew it beforehand, the script lines that name
// it and, for a value the run learnt, the output that held it first.
func (w reportRun) targeted() []render.Group {
	var groups []render.Group
	at := map[string]int{}
	total := map[string]int{}
	for _, t := range w.result.targeted {
		total[t.kind.Name]++
	}
	for _, t := range w.result.targeted {
		i, ok := at[t.kind.Name]
		if !ok {
			i = len(groups)
			at[t.kind.Name] = i
			columns := []string{"value", "origin", "named in"}
			if t.scope != "" {
				columns = []string{"value", "scope", "origin", "named in"}
			}
			groups = append(groups, render.Group{Title: t.kind.Targeted + " (" + strconv.Itoa(total[t.kind.Name]) + ")", Columns: columns})
		}
		if len(groups[i].Entries) == fewExposed {
			continue
		}
		cells := []string{t.value, t.origin, few(t.places())}
		if t.scope != "" {
			cells = []string{t.value, t.scope, t.origin, few(t.places())}
		}
		var detail []render.Detail
		if t.origin == originDiscovered {
			detail = append(detail, render.Detail{Label: "from", Text: t.from.String()})
		}
		detail = append(detail, lined("what", t.lines, fewFindingLines, "the saved targeted file")...)
		groups[i].Entries = append(groups[i].Entries, render.Entry{Level: string(t.level()), Cells: cells, Detail: detail})
	}
	for name, i := range at {
		if more := total[name] - len(groups[i].Entries); more > 0 {
			groups[i].Entries = append(groups[i].Entries, render.Entry{Cells: []string{"and " + strconv.Itoa(more) + " more in the saved targeted file"}})
		}
	}
	groups = append(groups, w.subjectGroups()...)
	return groups
}

// subjectGroups builds one group per subject label from the shown activities.
func (w reportRun) subjectGroups() []render.Group {
	type entity struct {
		value      string
		activities []string
		level      tactic.Severity
		evidence   []string
	}
	labels := map[string][]entity{}
	keys := map[string]int{}
	var labelOrder []string
	for _, s := range w.shown {
		top := tactic.Low
		for _, name := range s.hit.Tactics {
			if sev := w.pipe.tactics.Severity(name); sev.Rank() > top.Rank() {
				top = sev
			}
		}
		for _, c := range s.cites {
			for _, sub := range c.subjects {
				k := sub.Label + "\x00" + sub.Value
				i, ok := keys[k]
				if !ok {
					if _, started := labels[sub.Label]; !started {
						labelOrder = append(labelOrder, sub.Label)
					}
					i = len(labels[sub.Label])
					keys[k] = i
					labels[sub.Label] = append(labels[sub.Label], entity{value: sub.Value, level: top})
				}
				ent := &labels[sub.Label][i]
				if top.Rank() > ent.level.Rank() {
					ent.level = top
				}
				if !slices.Contains(ent.activities, s.hit.Name) {
					ent.activities = append(ent.activities, s.hit.Name)
				}
				line := s.hit.Name + ": " + c.String()
				if len(ent.evidence) < fewFindingLines && !slices.Contains(ent.evidence, line) {
					ent.evidence = append(ent.evidence, line)
				}
			}
		}
	}
	var groups []render.Group
	for _, label := range labelOrder {
		entities := labels[label]
		g := render.Group{
			Title:   strings.ToUpper(label[:1]) + label[1:] + " (" + strconv.Itoa(len(entities)) + ")",
			Columns: []string{"value", "acted on by"},
		}
		for i, ent := range entities {
			if i == fewExposed {
				g.Entries = append(g.Entries, render.Entry{Cells: []string{"and " + strconv.Itoa(len(entities)-fewExposed) + " more in report.json"}})
				break
			}
			detail := lined("what", ent.evidence, fewFindingLines, "report.json")
			g.Entries = append(g.Entries, render.Entry{
				Level:  string(ent.level),
				Cells:  []string{ent.value, strings.Join(ent.activities, ", ")},
				Detail: detail,
			})
		}
		groups = append(groups, g)
	}
	return groups
}

// exposure lists what the evidence holds, a group per kind. A long list is
// cut here; the saved exposure file holds all of it.
func (w reportRun) exposure() []render.Group {
	var groups []render.Group
	at := map[string]int{}
	total := map[string]int{}
	for _, e := range w.result.exposed {
		total[e.kind.Name]++
	}
	for _, e := range w.result.exposed {
		i, ok := at[e.kind.Name]
		if !ok {
			i = len(groups)
			at[e.kind.Name] = i
			columns := []string{"value", "seen", "found in"}
			if e.kind.Secret {
				columns = []string{"value", "what", "seen", "found in"}
			}
			groups = append(groups, render.Group{Title: e.kind.Title + " (" + strconv.Itoa(total[e.kind.Name]) + ")", Columns: columns})
		}
		if len(groups[i].Entries) == fewExposed {
			continue
		}
		cites := make([]string, len(e.cites))
		for n, c := range e.cites {
			cites[n] = c.String()
		}
		entry := render.Entry{Level: e.kind.Severity, Cells: []string{e.shown(), e.seen, few(cites)}}
		if e.kind.Secret {
			whose := e.form
			if e.account != "" {
				whose += " of " + e.account
			}
			entry.Cells = []string{e.shown(), whose, e.seen, few(cites)}
		}
		groups[i].Entries = append(groups[i].Entries, entry)
	}
	for name, i := range at {
		if more := total[name] - len(groups[i].Entries); more > 0 {
			groups[i].Entries = append(groups[i].Entries, render.Entry{Cells: []string{"and " + strconv.Itoa(more) + " more in the saved exposure file"}})
		}
	}
	return groups
}

// lined gives each of the first lines a detail of its own under one label, and
// counts the rest, naming the saved file that holds every one of them: the
// screen and the saved report share this limit, so the overflow is only in JSON.
func lined(label string, lines []string, limit int, where string) []render.Detail {
	var out []render.Detail
	for i, line := range lines {
		if i == limit {
			out = append(out, render.Detail{Label: label, Text: "and " + strconv.Itoa(len(lines)-limit) + " more in " + where})
			break
		}
		out = append(out, render.Detail{Label: label, Text: line})
	}
	return out
}

// fewOf joins the first items and counts the rest.
func fewOf(items []string, limit int, separator string) string {
	if len(items) <= limit {
		return strings.Join(items, separator)
	}
	return strings.Join(items[:limit], separator) + separator + "and " + strconv.Itoa(len(items)-limit) + " more"
}

// few lists the first files and counts the rest.
func few(files []string) string {
	if len(files) <= fewFiles {
		return strings.Join(files, ", ")
	}
	return strings.Join(files[:fewFiles], ", ") + " and " + strconv.Itoa(len(files)-fewFiles) + " more"
}
