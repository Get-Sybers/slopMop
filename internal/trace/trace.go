// Package trace reconstructs the timeline of an AI agent's actions from
// the scripts and outputs in an evidence folder.
package trace

import (
	"sort"
	"strings"
	"time"

	"github.com/get-sybers/slopmop/internal/evidence"
	"github.com/get-sybers/slopmop/internal/indicator"
	"github.com/get-sybers/slopmop/internal/intel"
	"github.com/get-sybers/slopmop/internal/parse"
	"github.com/get-sybers/slopmop/internal/structured"
	"github.com/get-sybers/slopmop/internal/tactic"
)

// Step is one file placed in the timeline.
type Step struct {
	File       evidence.File
	Turn       int
	Tools      []string
	Tactics    []string
	Transforms []string
	Outputs    []string
	Indicators int
	Matches    []indicator.Match
	IntelHits  []intel.Hit
}

// Timeline holds the ordered steps and any reconstruction gaps.
type Timeline struct {
	Steps []Step
}

// Tables holds the data tables a timeline is built with. Watchlist may be
// nil; when it is set, extracted indicators are matched against it.
type Tables struct {
	Tactics   tactic.Table
	Patterns  indicator.Table
	Formats   structured.Table
	Watchlist *intel.Watchlist
}

// Build reads the inventory result and produces a trace timeline.
func Build(files []evidence.File, texts map[string]string, tables Tables) Timeline {
	ordered := sortByTime(files)
	// Each script is parsed once; the result serves both the step and the linking.
	parsed := map[string]parse.Script{}
	for _, f := range ordered {
		if f.Role != evidence.Script {
			continue
		}
		if text := texts[f.Path]; text != "" {
			parsed[f.Path] = parseScript(f, text)
		}
	}
	linked := linkOutputs(ordered, parsed)
	// A report is not a turn and links no output, so it stays out of the linking.
	content := map[string]string{}
	for _, f := range ordered {
		text := texts[f.Path]
		if p, decoded, ok := parseReport(f, text, tables.Formats); ok {
			parsed[f.Path] = p
			text = decoded
		}
		content[f.Path] = text
	}
	steps := make([]Step, len(ordered))
	turn := 0
	for i, f := range ordered {
		if f.Role == evidence.Script {
			turn++
		}
		s := Step{File: f, Turn: turn}
		if p, ok := parsed[f.Path]; ok {
			s.Tools = uniqueTools(p.Commands)
			s.Tactics = classifyTools(s.Tools, tables.Tactics)
			s.Transforms = uniqueMethods(p.Transforms)
		}
		if text := content[f.Path]; text != "" {
			matches := tables.Patterns.Extract(text)
			s.Indicators = len(matches)
			s.Matches = matches
			if tables.Watchlist != nil {
				s.IntelHits = tables.Watchlist.Match(matches)
			}
		}
		s.Outputs = linked[f.Path]
		steps[i] = s
	}
	return Timeline{Steps: steps}
}

func sortByTime(files []evidence.File) []evidence.File {
	sorted := make([]evidence.File, len(files))
	copy(sorted, files)
	sort.SliceStable(sorted, func(i, j int) bool {
		ti := effectiveTime(sorted[i])
		tj := effectiveTime(sorted[j])
		if !ti.Equal(tj) {
			return ti.Before(tj)
		}
		return sorted[i].Path < sorted[j].Path
	})
	return sorted
}

func effectiveTime(f evidence.File) time.Time {
	if f.Stamped {
		return f.Stamp.Time
	}
	return f.Modified
}

func parseScript(f evidence.File, text string) parse.Script {
	if isPowerShell(f) {
		return parse.ExtractPowerShell(text)
	}
	if isPython(f, text) {
		return parse.ExtractPython(text)
	}
	return parse.ExtractBash(text)
}

// parseReport decodes a structured file that is not a script. It returns
// the commands the report records and the decoded text to search for
// indicators; ok is false when the file has no format or is malformed.
func parseReport(f evidence.File, text string, formats structured.Table) (parse.Script, string, bool) {
	format, known := formats.Detect(f.Path)
	if !known || f.Role == evidence.Script || text == "" {
		return parse.Script{}, "", false
	}
	report, err := formats.Extract(format, text)
	if err != nil {
		return parse.Script{}, "", false
	}
	var s parse.Script
	for _, c := range report.Commands {
		p := parse.ExtractCommand(c)
		s.Commands = append(s.Commands, p.Commands...)
		s.Transforms = append(s.Transforms, p.Transforms...)
	}
	return s, strings.Join(report.Values, "\n"), true
}

func isPowerShell(f evidence.File) bool {
	lower := strings.ToLower(f.Path)
	return strings.HasSuffix(lower, ".ps1") || strings.HasSuffix(lower, ".psm1")
}

func isPython(f evidence.File, text string) bool {
	if strings.HasSuffix(strings.ToLower(f.Path), ".py") {
		return true
	}
	first, _, _ := strings.Cut(text, "\n")
	return strings.HasPrefix(first, "#!") && strings.Contains(first, "python")
}

func uniqueTools(cmds []parse.Command) []string {
	seen := map[string]bool{}
	var tools []string
	for _, c := range cmds {
		if !seen[c.Tool] {
			seen[c.Tool] = true
			tools = append(tools, c.Tool)
		}
	}
	return tools
}

func uniqueMethods(xforms []parse.Transform) []string {
	seen := map[string]bool{}
	var methods []string
	for _, x := range xforms {
		if !seen[x.Method] {
			seen[x.Method] = true
			methods = append(methods, x.Method)
		}
	}
	return methods
}

func classifyTools(tools []string, t tactic.Table) []string {
	seen := map[string]bool{}
	var tactics []string
	for _, tool := range tools {
		if tac := t.Classify(tool); tac != "" && !seen[tac] {
			seen[tac] = true
			tactics = append(tactics, tac)
		}
	}
	return tactics
}

// linkOutputs maps each script to the evidence files it writes. A write
// path seldom equals an evidence path ("./out.txt", "C:\\loot\\out.txt"), so
// the two are compared by base name. The links hold evidence paths.
func linkOutputs(ordered []evidence.File, parsed map[string]parse.Script) map[string][]string {
	known := map[string][]string{}
	for _, o := range ordered {
		name := baseName(o.Path)
		known[name] = append(known[name], o.Path)
	}
	links := map[string][]string{}
	for _, f := range ordered {
		p, ok := parsed[f.Path]
		if !ok {
			continue
		}
		seen := map[string]bool{}
		for _, w := range p.Writes {
			for _, path := range known[baseName(w)] {
				if path == f.Path || seen[path] {
					continue
				}
				seen[path] = true
				links[f.Path] = append(links[f.Path], path)
			}
		}
	}
	return links
}

// baseName is the part of a path after its last slash or backslash; scripts
// from either shell may use either separator.
func baseName(path string) string {
	path = strings.TrimRight(path, `/\`)
	if i := strings.LastIndexAny(path, `/\`); i >= 0 {
		return path[i+1:]
	}
	return path
}
