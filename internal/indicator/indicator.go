// Package indicator extracts security indicators from text.
package indicator

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/get-sybers/slopmop/internal/parallel"
	"github.com/get-sybers/slopmop/internal/sift"
)

//go:embed indicators.json
var raw []byte

type entry struct {
	Type    string `json:"type"`
	Pattern string `json:"pattern"`
	// NotFollowedBy is an optional pattern; a match is dropped when the text
	// immediately after it matches. Go's regexp (RE2) has no lookahead, so
	// the trailing context is checked here instead of inside Pattern.
	NotFollowedBy string `json:"not_followed_by,omitempty"`
	// NotPrecededBy is the same for the text that ends where the match
	// begins, on its line: what says the match is something else.
	NotPrecededBy string `json:"not_preceded_by,omitempty"`
}

// Match is one indicator found in a text.
type Match struct {
	Type  string
	Value string
	Start int
	// Line is the line of the file the match is on, from 1, when a caller
	// that knows the file sets it; 0 means the line is not known.
	Line int
}

// Table holds the compiled indicator patterns.
type Table struct {
	patterns []compiled
}

type compiled struct {
	typ string
	rx  *regexp.Regexp
	// notAfter, when non-nil, is anchored at the start of the text that
	// follows a match and rejects the match if it matches there. notBefore
	// does so for the text that leads up to it, read backwards from the match.
	notAfter, notBefore *regexp.Regexp
	// plan says where in a text the pattern is worth running, and rare holds
	// the texts its places are found by; with none, its shape finds them.
	plan sift.Plan
	rare []string
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
		plan, err := sift.Read(e.Pattern)
		if err != nil {
			return Table{}, fmt.Errorf("indicators.json[%d] %s: %w", i, e.Type, err)
		}
		patterns[i] = compiled{typ: e.Type, rx: rx, plan: plan, rare: plan.Rare()}
		if e.NotFollowedBy != "" {
			na, err := regexp.Compile(`^(?:` + e.NotFollowedBy + `)`)
			if err != nil {
				return Table{}, fmt.Errorf("indicators.json[%d] %s not_followed_by: %w", i, e.Type, err)
			}
			patterns[i].notAfter = na
		}
		if e.NotPrecededBy != "" {
			turned, err := sift.Backwards(e.NotPrecededBy)
			if err != nil {
				return Table{}, fmt.Errorf("indicators.json[%d] %s not_preceded_by: %w", i, e.Type, err)
			}
			nb, err := regexp.Compile(`^(?:` + turned + `)`)
			if err != nil {
				return Table{}, fmt.Errorf("indicators.json[%d] %s not_preceded_by: %w", i, e.Type, err)
			}
			patterns[i].notBefore = nb
		}
	}
	return Table{patterns: patterns}, nil
}

// Has reports whether the table declares the indicator type.
func (t Table) Has(typ string) bool {
	for _, p := range t.patterns {
		if p.typ == typ {
			return true
		}
	}
	return false
}

// find returns where the pattern matches between from and to. It is run
// only on the places that can hold a match, and over the whole stretch when
// the pattern names no place or the text may fold a letter the places miss.
func (p compiled) find(text string, lower []byte, from, to int) [][]int {
	if lower != nil && !sift.Holds(lower[from:to], p.plan.Needs) {
		return nil
	}
	if lower == nil || !p.plan.InLine || (p.rare == nil && !p.plan.Shaped) {
		found := p.rx.FindAllStringIndex(text[from:to], -1)
		for _, loc := range found {
			loc[0], loc[1] = loc[0]+from, loc[1]+from
		}
		return found
	}
	var found [][]int
	try := func(start, end int) {
		if end-start < p.plan.Least || !sift.Holds(lower[start:end], p.plan.Needs) {
			return
		}
		// A byte either side is kept, so a word boundary reads as it does in the text.
		if p.plan.Shaped {
			start, end = max(start-1, 0), min(end+1, len(text))
		}
		for _, loc := range p.rx.FindAllStringIndex(text[start:end], -1) {
			found = append(found, []int{start + loc[0], start + loc[1]})
		}
	}
	if p.rare != nil {
		for _, place := range p.places(text, lower, from, to) {
			try(place[0], place[1])
		}
		return found
	}
	// With no text to find it by, every run of the bytes a match is made of is a place.
	for at := from; at < to; {
		for at < to && !p.plan.Made[text[at]] {
			at++
		}
		start := at
		for at < to && p.plan.Made[text[at]] {
			at++
		}
		try(start, at)
	}
	return found
}

// places returns the stretches between from and to that hold a text the
// pattern is found by, in the order of the text and each once: the run of
// the bytes a match is made of around the text, or its line.
func (p compiled) places(text string, lower []byte, from, to int) [][2]int {
	var places [][2]int
	for _, need := range p.rare {
		for at := from; at < to; {
			i := bytes.Index(lower[at:to], []byte(need))
			if i < 0 {
				break
			}
			start, end := p.around(text, at+i, at+i+len(need), from, to)
			places = append(places, [2]int{start, end})
			at = end
		}
	}
	if len(p.rare) > 1 {
		sort.Slice(places, func(i, j int) bool { return places[i][0] < places[j][0] })
		places = slices.CompactFunc(places, func(a, b [2]int) bool { return a[0] == b[0] })
	}
	return places
}

// around widens a stretch to the place that holds it: the run of the bytes a
// match is made of, or the line.
func (p compiled) around(text string, start, end, from, to int) (first, last int) {
	if p.plan.Shaped {
		for start > from && p.plan.Made[text[start-1]] {
			start--
		}
		for end < to && p.plan.Made[text[end]] {
			end++
		}
		return start, end
	}
	start = from + strings.LastIndexByte(text[from:start], '\n') + 1
	if i := strings.IndexByte(text[end:to], '\n'); i >= 0 {
		return start, end + i
	}
	return start, to
}

const (
	// small is the size below which a text is searched on the caller's goroutine.
	small = 16 << 10
	// piece is about how much of a large text one search covers.
	piece = 256 << 10
)

// cut returns where each piece of text begins, and the length of text last.
// Every piece but the last ends with a line break.
func cut(text string) []int {
	bounds := []int{0}
	for at := piece; at < len(text); at += piece {
		i := strings.IndexByte(text[at:], '\n')
		if i < 0 {
			break
		}
		at += i + 1
		if at < len(text) {
			bounds = append(bounds, at)
		}
	}
	return append(bounds, len(text))
}

// search is one pattern over one stretch of the text.
type search struct {
	pattern  int
	from, to int
}

// Extract returns every indicator found in text, deduplicated by value and
// sorted by start position. A large text is searched on every processor:
// each pattern alone, and piece by piece where its matches stay in a line.
func (t Table) Extract(text string) []Match {
	bounds := []int{0, len(text)}
	if len(text) >= small {
		bounds = cut(text)
	}
	// The places of a pattern are looked for in lower case, unless the text
	// folds a letter that lower case does not show.
	var lower []byte
	if !sift.Folds(text) {
		lower = sift.Lower(text)
	}
	var searches []search
	for i, p := range t.patterns {
		if !p.plan.InLine {
			searches = append(searches, search{pattern: i, to: len(text)})
			continue
		}
		for b := 0; b+1 < len(bounds); b++ {
			searches = append(searches, search{pattern: i, from: bounds[b], to: bounds[b+1]})
		}
	}
	found := make([][][]int, len(searches))
	run := func(n int) {
		s := searches[n]
		found[n] = t.patterns[s.pattern].find(text, lower, s.from, s.to)
	}
	if len(text) < small {
		for n := range searches {
			run(n)
		}
	} else {
		parallel.Each(len(searches), run)
	}
	// The searches are in the order of the patterns and then of the text,
	// so the first pattern to find a value keeps it, as in one pass.
	seen := map[string]bool{}
	var matches []Match
	var turned []byte
	for n, s := range searches {
		p := t.patterns[s.pattern]
		for _, loc := range found[n] {
			start, end := loc[0], loc[1]
			val := text[start:end]
			// A value already kept is not looked at again, whatever stands around it.
			if seen[val] {
				continue
			}
			if p.notAfter != nil && p.notAfter.MatchString(text[end:]) {
				continue
			}
			if p.notBefore != nil {
				if turned = sift.Turned(turned[:0], leading(text, start)); p.notBefore.Match(turned) {
					continue
				}
			}
			seen[val] = true
			matches = append(matches, Match{Type: p.typ, Value: val, Start: start})
		}
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].Start < matches[j].Start })
	return matches
}

// behind is how many bytes before a match are read for what it must not follow.
const behind = 48

// leading returns the text that leads up to start on its line, behind bytes at most.
func leading(text string, start int) string {
	before := text[max(0, start-behind):start]
	return before[strings.LastIndexByte(before, '\n')+1:]
}

// CountByType returns the number of distinct indicator values per type.
func (t Table) CountByType(text string) map[string]int {
	counts := map[string]int{}
	for _, m := range t.Extract(text) {
		counts[m.Type]++
	}
	return counts
}
