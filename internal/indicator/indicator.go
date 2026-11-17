// Package indicator extracts security indicators from text.
package indicator

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"regexp/syntax"
	"sort"
	"strings"
	"unicode"

	"github.com/get-sybers/slopmop/internal/parallel"
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
	// follows a match and rejects the match if it matches there.
	notAfter *regexp.Regexp
	// inLine says no match holds a line break or leans on an end of the
	// text, so a text cut at line breaks gives the matches of the whole.
	inLine bool
	// needs is a text every match holds, or empty when none is known. A line
	// without it has no match, so it need not be searched.
	needs string
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
		patterns[i] = compiled{typ: e.Type, rx: rx, inLine: staysInLine(e.Pattern, rx), needs: needed(e.Pattern)}
		if e.NotFollowedBy != "" {
			na, err := regexp.Compile(`^(?:` + e.NotFollowedBy + `)`)
			if err != nil {
				return Table{}, fmt.Errorf("indicators.json[%d] %s not_followed_by: %w", i, e.Type, err)
			}
			patterns[i].notAfter = na
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

// staysInLine reports whether no match of the pattern can hold a line break,
// be empty, or depend on where the text begins and ends.
func staysInLine(pattern string, rx *regexp.Regexp) bool {
	tree, err := syntax.Parse(pattern, syntax.Perl)
	return err == nil && !rx.MatchString("") && inLine(tree)
}

func inLine(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpBeginText, syntax.OpEndText, syntax.OpAnyChar:
		return false
	case syntax.OpLiteral:
		for _, r := range re.Rune {
			if r == '\n' {
				return false
			}
		}
	case syntax.OpCharClass:
		for i := 0; i+1 < len(re.Rune); i += 2 {
			if re.Rune[i] <= '\n' && '\n' <= re.Rune[i+1] {
				return false
			}
		}
	}
	for _, sub := range re.Sub {
		if !inLine(sub) {
			return false
		}
	}
	return true
}

// needed returns the longest text that every match of the pattern holds,
// as far as its literals show: a stretch that is written one way only.
func needed(pattern string) string {
	tree, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return ""
	}
	longest := ""
	for _, text := range required(tree) {
		if len(text) > len(longest) {
			longest = text
		}
	}
	return longest
}

// required returns texts that every match of re holds.
func required(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		return fixed(re.Rune, re.Flags&syntax.FoldCase != 0)
	case syntax.OpCapture, syntax.OpPlus:
		return required(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min > 0 {
			return required(re.Sub[0])
		}
	case syntax.OpConcat:
		var all []string
		for _, sub := range re.Sub {
			all = append(all, required(sub)...)
		}
		return all
	case syntax.OpAlternate:
		// What every branch holds: a text of the first that is in a text of each other.
		var all []string
		for _, text := range required(re.Sub[0]) {
			inEach := true
			for _, sub := range re.Sub[1:] {
				inOne := false
				for _, other := range required(sub) {
					inOne = inOne || strings.Contains(other, text)
				}
				inEach = inEach && inOne
			}
			if inEach {
				all = append(all, text)
			}
		}
		return all
	}
	return nil
}

// fixed cuts a literal into the stretches that are written one way only:
// all of it, or with letters folded the stretches between the letters.
func fixed(runes []rune, folded bool) []string {
	var all []string
	var b strings.Builder
	flush := func() {
		if b.Len() > 0 {
			all = append(all, b.String())
			b.Reset()
		}
	}
	for _, r := range runes {
		if folded && unicode.SimpleFold(r) != r {
			flush()
			continue
		}
		b.WriteRune(r)
	}
	flush()
	return all
}

// find returns where the pattern matches between from and to. A pattern
// whose matches need a text is tried only on the lines that hold it, when
// fewer than half of the lines do.
func (p compiled) find(text string, from, to int) [][]int {
	part := text[from:to]
	whole := func() [][]int {
		found := p.rx.FindAllStringIndex(part, -1)
		for _, loc := range found {
			loc[0], loc[1] = loc[0]+from, loc[1]+from
		}
		return found
	}
	if !p.inLine || p.needs == "" {
		return whole()
	}
	holding := strings.Count(part, p.needs)
	if holding == 0 {
		return nil
	}
	if 2*holding > strings.Count(part, "\n")+1 {
		return whole()
	}
	var found [][]int
	for at := 0; at < len(part); {
		i := strings.Index(part[at:], p.needs)
		if i < 0 {
			break
		}
		start := strings.LastIndexByte(part[:at+i], '\n') + 1
		end := len(part)
		if j := strings.IndexByte(part[at+i:], '\n'); j >= 0 {
			end = at + i + j
		}
		for _, loc := range p.rx.FindAllStringIndex(part[start:end], -1) {
			found = append(found, []int{from + start + loc[0], from + start + loc[1]})
		}
		at = end + 1
	}
	return found
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
	var searches []search
	for i, p := range t.patterns {
		if !p.inLine {
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
		found[n] = t.patterns[s.pattern].find(text, s.from, s.to)
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
	for n, s := range searches {
		p := t.patterns[s.pattern]
		for _, loc := range found[n] {
			start, end := loc[0], loc[1]
			if p.notAfter != nil && p.notAfter.MatchString(text[end:]) {
				continue
			}
			val := text[start:end]
			if seen[val] {
				continue
			}
			seen[val] = true
			matches = append(matches, Match{Type: p.typ, Value: val, Start: start})
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
