// Package sift reads an expression once, when it is loaded, and says where
// in a text it is worth running: the texts every match holds, and the bytes
// a match is made of. Looking for either is far cheaper than the expression.
package sift

import (
	"bytes"
	"fmt"
	"regexp/syntax"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// rare is the length from which a text is seldom enough in a line to look for.
const rare = 3

// Plan is what an expression promises about each of its matches.
type Plan struct {
	// Needs holds sets of texts in lower case: every match holds at least
	// one text of each set, in a text for which Folds reports false.
	Needs [][]string
	// Shaped says a match is made only of the bytes of Made and is at least
	// Least bytes long, so it lies inside one run of such bytes.
	Shaped bool
	Made   [256]bool
	Least  int
	// InLine says no match holds a line break, is empty, or leans on where
	// the text begins and ends, so a line can be searched apart from the rest.
	InLine bool
}

// Read returns the plan of an expression.
func Read(expr string) (Plan, error) {
	tree, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return Plan{}, fmt.Errorf("sift: %w", err)
	}
	p := Plan{Needs: needs(tree), Least: least(tree)}
	p.InLine = p.Least > 0 && inLine(tree)
	p.Shaped = made(tree, &p.Made) && !everything(&p.Made)
	return p, nil
}

// Rare returns the set of needed texts that is seldom in a text: the one
// whose shortest text is longest, or nil when that text is too short to look for.
func (p Plan) Rare() []string {
	var best []string
	for _, set := range p.Needs {
		if shortest(set) > shortest(best) {
			best = set
		}
	}
	if shortest(best) < rare {
		return nil
	}
	return best
}

func shortest(set []string) int {
	if len(set) == 0 {
		return 0
	}
	n := len(set[0])
	for _, text := range set[1:] {
		n = min(n, len(text))
	}
	return n
}

// Lower returns the bytes of text with A to Z in lower case, so an offset
// in it is the same offset in text.
func Lower(text string) []byte {
	lower := []byte(text)
	for i, c := range lower {
		if c >= 'A' && c <= 'Z' {
			lower[i] = c + ('a' - 'A')
		}
	}
	return lower
}

// Holds reports whether lower, a stretch of what Lower returned, holds a
// text of every set.
func Holds(lower []byte, sets [][]string) bool {
	for _, set := range sets {
		if !slices.ContainsFunc(set, func(text string) bool { return bytes.Contains(lower, []byte(text)) }) {
			return false
		}
	}
	return true
}

// Folds reports whether a text holds a rune outside ASCII that an expression
// which ignores case reads as a letter of ASCII: the long s and the Kelvin
// sign. The needed texts say nothing of such a text.
func Folds(text string) bool {
	return strings.Contains(text, "ſ") || strings.Contains(text, "K")
}

// everything reports whether a match can hold every byte a line can.
func everything(set *[256]bool) bool {
	for b, in := range set {
		if !in && b != '\n' && b != '\r' {
			return false
		}
	}
	return true
}

func inLine(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpBeginText, syntax.OpEndText, syntax.OpAnyChar:
		return false
	case syntax.OpLiteral:
		if slices.Contains(re.Rune, '\n') {
			return false
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

// least returns a number of bytes no match of re is shorter than.
func least(re *syntax.Regexp) int {
	switch re.Op {
	case syntax.OpLiteral:
		return len(re.Rune)
	case syntax.OpCharClass, syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return 1
	case syntax.OpCapture, syntax.OpPlus:
		return least(re.Sub[0])
	case syntax.OpRepeat:
		return re.Min * least(re.Sub[0])
	case syntax.OpConcat:
		n := 0
		for _, sub := range re.Sub {
			n += least(sub)
		}
		return n
	case syntax.OpAlternate:
		n := least(re.Sub[0])
		for _, sub := range re.Sub[1:] {
			n = min(n, least(sub))
		}
		return n
	}
	return 0
}

// made adds to set every byte a match of re can hold, and reports false
// when a match can hold any byte at all.
func made(re *syntax.Regexp, set *[256]bool) bool {
	switch re.Op {
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return false
	case syntax.OpLiteral:
		for _, r := range re.Rune {
			add(set, r)
			if re.Flags&syntax.FoldCase != 0 {
				for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
					add(set, f)
				}
			}
		}
	case syntax.OpCharClass:
		for i := 0; i+1 < len(re.Rune); i += 2 {
			for r := re.Rune[i]; r <= re.Rune[i+1] && r < utf8.RuneSelf; r++ {
				set[r] = true
			}
			if re.Rune[i+1] >= utf8.RuneSelf {
				add(set, re.Rune[i+1])
			}
		}
	}
	for _, sub := range re.Sub {
		if !made(sub, set) {
			return false
		}
	}
	return true
}

// add puts a rune into set. A rune outside ASCII is several bytes, and any
// byte outside ASCII may be one of them.
func add(set *[256]bool, r rune) {
	if r < utf8.RuneSelf {
		set[r] = true
		return
	}
	for b := utf8.RuneSelf; b < len(set); b++ {
		set[b] = true
	}
}

// needs returns sets of texts in lower case: every match of re holds at
// least one text of each set.
func needs(re *syntax.Regexp) [][]string {
	switch re.Op {
	case syntax.OpLiteral:
		return texts(re.Rune)
	case syntax.OpCapture, syntax.OpPlus:
		return needs(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min > 0 {
			return needs(re.Sub[0])
		}
	case syntax.OpConcat:
		// Literals that stand side by side are one text, whatever case each is in.
		var all [][]string
		var run []rune
		for _, sub := range re.Sub {
			if sub.Op == syntax.OpLiteral {
				run = append(run, sub.Rune...)
				continue
			}
			all = append(append(all, texts(run)...), needs(sub)...)
			run = nil
		}
		return append(all, texts(run)...)
	case syntax.OpAlternate:
		// One branch matches, so the longest set of each branch, taken together, is one set.
		var union []string
		for _, sub := range re.Sub {
			var best []string
			for _, set := range needs(sub) {
				if shortest(set) > shortest(best) {
					best = set
				}
			}
			if best == nil {
				return nil
			}
			union = append(union, best...)
		}
		return [][]string{union}
	}
	return nil
}

// texts cuts a literal into its stretches of ASCII, in lower case, each a
// set of its own: a rune outside ASCII is not the same bytes in a text put
// in lower case.
func texts(runes []rune) [][]string {
	var all [][]string
	var b []byte
	for _, r := range runes {
		if r < 0 || r >= utf8.RuneSelf {
			if len(b) > 0 {
				all = append(all, []string{string(b)})
				b = nil
			}
			continue
		}
		c := byte(r)
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b = append(b, c)
	}
	if len(b) > 0 {
		all = append(all, []string{string(b)})
	}
	return all
}

// Finder looks for many texts in one pass over a text, where a search for
// each apart reads the text once for every one of them.
type Finder struct {
	texts [][]byte
	// maybe has a bit for each start of three bytes that may begin a text,
	// and begun lists the texts that begin so.
	maybe [1 << 10]uint64
	begun map[uint16][]int
}

// NewFinder returns a finder of texts, each of three bytes or more and with
// no line break. Lines gives its answers in the order of texts.
func NewFinder(texts []string) (*Finder, error) {
	f := &Finder{texts: make([][]byte, len(texts)), begun: map[uint16][]int{}}
	for i, text := range texts {
		if len(text) < rare || strings.Contains(text, "\n") {
			return nil, fmt.Errorf("sift: the text %q is shorter than %d bytes or holds a line break", text, rare)
		}
		f.texts[i] = []byte(text)
		h := slot(uint32(text[0])<<16 | uint32(text[1])<<8 | uint32(text[2]))
		f.maybe[h>>6] |= 1 << (h & 63)
		f.begun[h] = append(f.begun[h], i)
	}
	return f, nil
}

// slot spreads three bytes over the bits of maybe.
func slot(three uint32) uint16 {
	return uint16((three * 0x9E3779B1) >> 16)
}

// Lines returns, for each text, where each line that holds it begins, in
// the order of lower, which is what Lower returned.
func (f *Finder) Lines(lower []byte) [][]int {
	lines := make([][]int, len(f.texts))
	// noted is the line last added for each text, from 1, so a line is added once.
	noted := make([]int, len(f.texts))
	var three uint32
	begins := 0
	for i, c := range lower {
		three = (three<<8 | uint32(c)) & 0xFFFFFF
		if c == '\n' {
			begins = i + 1
			continue
		}
		h := slot(three)
		if i < rare-1 || f.maybe[h>>6]&(1<<(h&63)) == 0 {
			continue
		}
		for _, n := range f.begun[h] {
			if noted[n] != begins+1 && bytes.HasPrefix(lower[i-(rare-1):], f.texts[n]) {
				noted[n] = begins + 1
				lines[n] = append(lines[n], begins)
			}
		}
	}
	return lines
}
