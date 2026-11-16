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

// fewFiles is how many file names an entry of the readout lists in full.
const fewFiles = 3

// wholeSpec declares the command that runs without a noun: one folder in,
// every section out.
type wholeSpec struct {
	Summary    string        `json:"summary"`
	Positional string        `json:"positional"`
	Sections   []sectionSpec `json:"sections"`
	Hints      []string      `json:"hints"`
	Saved      savedSpec     `json:"saved"`
}

type sectionSpec struct {
	Name    string `json:"name"`
	Title   string `json:"title"`
	Summary string `json:"summary"`
	Note    string `json:"note"`
}

// wholeRun is one analysis and what every section reads from it.
type wholeRun struct {
	pipe   pipeline
	result analysis
	rows   []reportRow
}

type sectionBuilder func(w wholeRun) []render.Group

func checkWhole(w wholeSpec, builders map[string]sectionBuilder) error {
	if w.Summary == "" || w.Positional == "" || len(w.Sections) == 0 {
		return errors.New("nouns.json: whole needs a summary, a positional and a section")
	}
	seen := map[string]bool{}
	for _, s := range w.Sections {
		switch {
		case s.Name == "" || s.Title == "" || s.Summary == "":
			return fmt.Errorf("nouns.json: whole: section %q needs a name, a title and a summary", s.Name)
		case seen[s.Name]:
			return fmt.Errorf("nouns.json: whole: section %q is declared twice", s.Name)
		case builders[s.Name] == nil:
			return fmt.Errorf("nouns.json: whole declares the section %q, which has no implementation", s.Name)
		}
		seen[s.Name] = true
	}
	for name := range builders {
		if !seen[name] {
			return fmt.Errorf("nouns.json: whole does not declare the section %q", name)
		}
	}
	return nil
}

func sectionBuilders() map[string]sectionBuilder {
	return map[string]sectionBuilder{
		sectionSummary:     wholeRun.summary,
		"timeline":         wholeRun.timeline,
		"findings":         wholeRun.findings,
		sectionFiles:       wholeRun.files,
		sectionImpact:      func(w wholeRun) []render.Group { return w.assessed(sectionImpact) },
		sectionRemediation: func(w wholeRun) []render.Group { return w.assessed(sectionRemediation) },
		sectionMitigation:  wholeRun.mitigation,
	}
}

// registerWhole binds the command without a noun: it reads the folder and
// everything below it once, saves every section and every table, and prints
// every section or those named.
func (e Env) registerWhole(app *cli.App, w wholeSpec, nouns []nounSpec) error {
	builders := sectionBuilders()
	if err := checkWhole(w, builders); err != nil {
		return err
	}
	columns, err := checkSaved(w.Saved, nouns)
	if err != nil {
		return err
	}
	pipe, err := loadPipeline()
	if err != nil {
		return err
	}
	words := make([]cli.Word, len(w.Sections))
	for i, s := range w.Sections {
		words[i] = cli.Word{Name: s.Name, Summary: s.Summary}
	}
	spec := cli.Spec{Params: map[string]string{intelFile: "<file>", outDir: "<folder>"}}
	return app.Whole(w.Summary, w.Positional, words, spec, func(a *cli.Args) error {
		folder := a.Pos[0]
		// A folder that cannot be written to is refused before the work is done.
		dir, err := outputDir(folder, a.Params[outDir], e.WorkDir, w.Saved.Prefix)
		if err != nil {
			return err
		}
		result, err := pipe.read(folder, inventory.MaxDepth, a.Params[intelFile])
		if err != nil {
			return err
		}
		every := map[string]bool{
			sectionSummary: true, sectionFiles: true, sectionImpact: true,
			sectionRemediation: true, sectionMitigation: true,
		}
		run := wholeRun{pipe: pipe, result: result, rows: pipe.report(result, tactic.High, every)}
		// The disk holds every section; the screen holds those asked for.
		full := render.Readout{Title: "slopmop   " + folder, Banner: run.banner(), Hints: w.Hints}
		shown := full
		for _, s := range w.Sections {
			section := render.Section{Title: s.Title, Note: s.Note, Groups: builders[s.Name](run)}
			full.Sections = append(full.Sections, section)
			if slices.Contains(a.Selectors, s.Name) {
				shown.Sections = append(shown.Sections, section)
			}
		}
		// A failed save does not withhold the readout; it fails the command after it.
		names, saveErr := run.save(dir, w.Saved, columns, full)
		if saveErr == nil {
			shown.Hints = append([]string{"saved to " + dir + ": " + strings.Join(names, ", ")}, w.Hints...)
		}
		if err := render.WriteReadout(e.Stdout, shown, e.Colour); err != nil {
			return err
		}
		return errors.Join(saveErr, skippedError(result.skipped))
	})
}

// banner gives the verdict: the impacts by severity, or that nothing was found.
func (w wholeRun) banner() render.Banner {
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

// summary gives one line per count; the files and the indicators carry
// their breakdown, and each activity carries its own count in the findings.
func (w wholeRun) summary() []render.Group {
	var g render.Group
	var roles, types []string
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
		}
	}
	return []render.Group{g}
}

func (w wholeRun) timeline() []render.Group {
	var g render.Group
	for _, s := range w.result.timeline.Steps {
		g.Entries = append(g.Entries, render.Entry{
			Cells:  []string{strconv.Itoa(s.Turn), stepTime(s), string(s.File.Role), s.File.Path},
			Detail: stepDetail(s),
		})
	}
	return []render.Group{g}
}

func stepTime(s trace.Step) string {
	switch {
	case s.File.Stamped:
		return s.File.Stamp.Text
	case !s.File.Modified.IsZero():
		return render.Stamp(s.File.Modified, nil)
	default:
		return "-"
	}
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

// findings groups the findings by kind; each group is most severe first.
func (w wholeRun) findings() []render.Group {
	lines := map[string]int{}
	for _, r := range w.rows {
		if name, isActivity := strings.CutPrefix(r.item, "activities "); isActivity && r.section == sectionSummary {
			lines[name] = r.count
		}
	}
	groups := []render.Group{{Title: "activities"}, {Title: "indicators"}, {Title: "tactics"}}
	for _, f := range w.pipe.listFindings(w.result) {
		e := render.Entry{Level: string(f.severity)}
		mitre := strings.Join(append(slices.Clone(f.attack), f.atlas...), ", ")
		at := 0
		switch f.kind {
		case kindActivity:
			e.Cells = []string{f.label, plural(lines[f.label], "line"), strings.Join(f.tactics, ", "), mitre}
			e.Detail = []render.Detail{{Label: "in", Text: few(f.files)}}
		case kindIndicator:
			at = 1
			e.Cells = []string{f.label, f.indicator, few(f.files)}
			e.Detail = []render.Detail{{Label: "watchlist", Text: strings.Join(f.attributions, ", ")}}
		default:
			at = 2
			e.Cells = []string{strings.Join(f.tactics, ", "), mitre, few(f.files)}
		}
		groups[at].Entries = append(groups[at].Entries, e)
	}
	return groups
}

func (w wholeRun) files() []render.Group {
	var g render.Group
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

// assessed writes the impact or remediation rows of the report.
func (w wholeRun) assessed(section string) []render.Group {
	var g render.Group
	for _, r := range w.rows {
		if r.section != section {
			continue
		}
		g.Entries = append(g.Entries, render.Entry{
			Level: string(r.level),
			Cells: []string{r.item},
			Detail: []render.Detail{
				{Text: r.detail},
				{Label: "basis", Text: strings.Join(r.basis, ", ")},
				{Label: "files", Text: few(r.files)},
			},
		})
	}
	return []render.Group{g}
}

// mitigation gives one line per mitigation: its name and the techniques
// found that it addresses.
func (w wholeRun) mitigation() []render.Group {
	var g render.Group
	for _, r := range w.rows {
		if r.section == sectionMitigation {
			g.Entries = append(g.Entries, render.Entry{
				Level: string(r.level),
				Cells: []string{r.item, strings.Join(append(slices.Clone(r.attack), r.atlas...), ", ")},
			})
		}
	}
	return []render.Group{g}
}

// few lists the first files and counts the rest.
func few(files []string) string {
	if len(files) <= fewFiles {
		return strings.Join(files, ", ")
	}
	return strings.Join(files[:fewFiles], ", ") + " and " + strconv.Itoa(len(files)-fewFiles) + " more"
}
