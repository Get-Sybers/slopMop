// Package indicator extracts security indicators from text.
package indicator

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
)

//go:embed indicators.json
var raw []byte

type entry struct {
	Type    string `json:"type"`
	Pattern string `json:"pattern"`
}

// Match is one indicator found in a text.
type Match struct {
	Type  string
	Value string
	Start int
}

// Table holds the compiled indicator patterns.
type Table struct {
	patterns []compiled
}

type compiled struct {
	typ string
	rx  *regexp.Regexp
}

// LoadPatterns decodes indicators.json and compiles each pattern.
func LoadPatterns() (Table, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var entries []entry
	if err := dec.Decode(&entries); err != nil {
		return Table{}, fmt.Errorf("indicators.json: %w", err)
	}
	if dec.More() {
		return Table{}, fmt.Errorf("indicators.json: trailing data")
	}
	if len(entries) == 0 {
		return Table{}, fmt.Errorf("indicators.json: empty")
	}
	patterns := make([]compiled, len(entries))
	for i, e := range entries {
		if e.Type == "" {
			return Table{}, fmt.Errorf("indicators.json[%d]: empty type", i)
		}
		if e.Pattern == "" {
			return Table{}, fmt.Errorf("indicators.json[%d]: empty pattern", i)
		}
		rx, err := regexp.Compile(e.Pattern)
		if err != nil {
			return Table{}, fmt.Errorf("indicators.json[%d] %s: %w", i, e.Type, err)
		}
		patterns[i] = compiled{typ: e.Type, rx: rx}
	}
	return Table{patterns: patterns}, nil
}

// Extract returns every indicator found in text, deduplicated by value and
// sorted by start position.
func (t Table) Extract(text string) []Match {
	seen := map[string]bool{}
	var matches []Match
	for _, p := range t.patterns {
		for _, loc := range p.rx.FindAllStringIndex(text, -1) {
			val := text[loc[0]:loc[1]]
			if seen[val] {
				continue
			}
			seen[val] = true
			matches = append(matches, Match{Type: p.typ, Value: val, Start: loc[0]})
		}
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].Start < matches[j].Start })
	return matches
}

// CountByType returns the number of distinct indicator values per type.
func (t Table) CountByType(text string) map[string]int {
	counts := map[string]int{}
	for _, m := range t.Extract(text) {
		counts[m.Type]++
	}
	return counts
}
