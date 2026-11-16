// Package trace reconstructs the timeline of an AI agent's actions from
// the scripts and outputs in an evidence folder.
package trace

import (
	"sort"
	"strings"
	"time"

	"github.com/get-sybers/slopmop/internal/evidence"
	"github.com/get-sybers/slopmop/internal/indicator"
	"github.com/get-sybers/slopmop/internal/parse"
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
}

// Timeline holds the ordered steps and any reconstruction gaps.
type Timeline struct {
	Steps []Step
}

// Build reads the inventory result and produces a trace timeline.
func Build(files []evidence.File, texts map[string]string, tactics tactic.Table, patterns indicator.Table) Timeline {
	ordered := sortByTime(files)
	linked := linkOutputs(ordered, texts)
	steps := make([]Step, len(ordered))
	turn := 0
	for i, f := range ordered {
		if f.Role == evidence.Script {
			turn++
		}
		s := Step{File: f, Turn: turn}
		if f.Role == evidence.Script {
			text := texts[f.Path]
			if text != "" {
				parsed := parseScript(f, text)
				s.Tools = uniqueTools(parsed.Commands)
				s.Tactics = classifyTools(s.Tools, tactics)
				s.Transforms = uniqueMethods(parsed.Transforms)
			}
		}
		text := texts[f.Path]
		if text != "" {
			s.Indicators = len(patterns.Extract(text))
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
	return parse.ExtractBash(text)
}

func isPowerShell(f evidence.File) bool {
	lower := strings.ToLower(f.Path)
	return strings.HasSuffix(lower, ".ps1") || strings.HasSuffix(lower, ".psm1")
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

func linkOutputs(ordered []evidence.File, texts map[string]string) map[string][]string {
	links := map[string][]string{}
	for _, f := range ordered {
		if f.Role != evidence.Script {
			continue
		}
		text := texts[f.Path]
		if text == "" {
			continue
		}
		var parsed parse.Script
		if isPowerShell(f) {
			parsed = parse.ExtractPowerShell(text)
		} else {
			parsed = parse.ExtractBash(text)
		}
		known := map[string]bool{}
		for _, o := range ordered {
			known[o.Path] = true
		}
		for _, w := range parsed.Writes {
			if known[w] {
				links[f.Path] = append(links[f.Path], w)
			}
		}
	}
	return links
}
