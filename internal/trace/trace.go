// Package trace reconstructs the timeline of an AI agent's actions from
// the scripts and outputs in an evidence folder.
package trace

import (
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/get-sybers/slopmop/internal/activity"
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
	Activities []activity.Hit
	// Commands holds the first command of each tool, as evidence of what ran.
	Commands   []parse.Command
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
	Tactics    tactic.Table
	Activities activity.Table
	Patterns   indicator.Table
	Formats    structured.Table
	Watchlist  *intel.Watchlist
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
	// asRead is how many bytes of a content are the file as it stands, where a line has its number.
	asRead := map[string]int{}
	for _, f := range ordered {
		text := texts[f.Path]
		asRead[f.Path] = len(text)
		if p, decoded, ok := parseReport(f, text, tables.Formats); ok {
			parsed[f.Path] = p
			text = decoded
			asRead[f.Path] = 0
		}
		// A .cmd file is an output by role, and is a batch file all the same.
		if _, done := parsed[f.Path]; !done && isBatch(f) && text != "" {
			parsed[f.Path] = parse.ExtractBatch(text)
		}
		if hidden, extra := decodePayloads(text); extra != "" {
			p := parsed[f.Path]
			p.Commands = append(p.Commands, hidden.Commands...)
			p.Transforms = append(p.Transforms, hidden.Transforms...)
			parsed[f.Path] = p
			text += "\n" + extra
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
			s.Commands = firstCommands(p.Commands, f.Role == evidence.Script)
			s.Tactics = classifyTools(s.Tools, tables.Tactics)
			s.Transforms = uniqueMethods(p.Transforms)
		}
		if text := content[f.Path]; text != "" {
			// An activity adds its tactics to those of the commands that ran.
			s.Activities = tables.Activities.Detect(text)
			numberLines(text, asRead[f.Path], s.Activities, nil)
			for _, a := range s.Activities {
				for _, name := range a.Tactics {
					if !slices.Contains(s.Tactics, name) {
						s.Tactics = append(s.Tactics, name)
					}
				}
			}
			matches := tables.Patterns.Extract(text)
			numberLines(text, asRead[f.Path], nil, matches)
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

// numberLines keeps a line number only where it is a line of the file: the
// first known bytes of text. A decoded report and a decoded payload have no
// lines of the file, so what is found in them carries line 0.
func numberLines(text string, known int, hits []activity.Hit, matches []indicator.Match) {
	lines := strings.Count(text[:known], "\n") + 1
	for _, h := range hits {
		for i := range h.Evidence {
			if known == 0 || h.Evidence[i].Line > lines {
				h.Evidence[i].Line = 0
			}
		}
	}
	if len(matches) == 0 || known == 0 {
		return
	}
	order := make([]int, len(matches))
	for i := range order {
		order[i] = i
	}
	sort.Slice(order, func(a, b int) bool { return matches[order[a]].Start < matches[order[b]].Start })
	line, counted := 1, 0
	for _, i := range order {
		start := matches[i].Start
		if start >= known {
			break
		}
		line += strings.Count(text[counted:start], "\n")
		counted = start
		matches[i].Line = line
	}
}

// maxCommands is how many commands a step keeps as evidence.
const maxCommands = 40

// firstCommands returns the first command of each tool, with its line when
// the file is a script: a command read out of a report has no line of the file.
func firstCommands(cmds []parse.Command, numbered bool) []parse.Command {
	seen := map[string]bool{}
	var first []parse.Command
	for _, c := range cmds {
		if seen[c.Tool] || len(first) == maxCommands {
			continue
		}
		seen[c.Tool] = true
		if !numbered {
			c.Line = 0
		}
		first = append(first, c)
	}
	return first
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

// payloadDepth is how many layers of encoding are read: a payload may
// itself carry an encoded command.
const payloadDepth = 2

// decodePayloads reads what a text carries encoded. It returns the commands
// of the PowerShell payloads and the text of every payload, so that the
// activities and indicators inside them are found too. Nothing is run.
func decodePayloads(text string) (parse.Script, string) {
	var hidden parse.Script
	var extra []string
	layer := []string{text}
	for depth := 0; depth < payloadDepth && len(layer) > 0; depth++ {
		var next []string
		for _, t := range layer {
			for _, p := range parse.Decoded(t) {
				extra = append(extra, p.Text)
				next = append(next, p.Text)
				var s parse.Script
				switch p.Shell {
				case parse.PowerShell:
					s = parse.ExtractPowerShell(p.Text)
				case parse.POSIX:
					s = parse.ExtractBash(p.Text)
				}
				hidden.Commands = append(hidden.Commands, s.Commands...)
				hidden.Transforms = append(hidden.Transforms, s.Transforms...)
			}
		}
		layer = next
	}
	return hidden, strings.Join(extra, "\n")
}

func parseScript(f evidence.File, text string) parse.Script {
	if isPowerShell(f) {
		return parse.ExtractPowerShell(text)
	}
	if isBatch(f) {
		return parse.ExtractBatch(text)
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

func isBatch(f evidence.File) bool {
	lower := strings.ToLower(f.Path)
	return strings.HasSuffix(lower, ".bat") || strings.HasSuffix(lower, ".cmd")
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
		name := parse.BaseName(o.Path)
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
			for _, path := range known[parse.BaseName(w)] {
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
