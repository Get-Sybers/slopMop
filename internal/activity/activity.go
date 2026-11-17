// Package activity recognises what a line of evidence does: a role
// assignment, a mailbox read, a Key Vault secret read. A tactic table names
// the command that ran; this table names the operation it carried out.
package activity

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/get-sybers/slopmop/internal/vars"
)

//go:embed activities.json
var raw []byte

// continued joins a line that ends in a bash backslash or a PowerShell
// backtick to the next, with spaces of the same length, so offsets hold.
//
//nolint:gochecknoglobals // a constant replacer
var continued = strings.NewReplacer("\\\r\n", "   ", "\\\n", "  ", "`\r\n", "   ", "`\n", "  ")

const (
	// maxEvidence is how many lines one activity keeps from one text.
	maxEvidence = 12
	// maxText is how many bytes of a line are kept.
	maxText  = 200
	ellipsis = "..."
)

type document struct {
	// Contexts names patterns that say what a whole text is about.
	Contexts   map[string]string `json:"contexts"`
	Activities []entry           `json:"activities"`
}

type entry struct {
	Name    string   `json:"name"`
	Tactics []string `json:"tactics"`
	// Attack and Atlas name the techniques of ATT&CK and of ATLAS. An ATLAS
	// technique that refers to one of Attack need not be listed.
	Attack   []string `json:"attack"`
	Atlas    []string `json:"atlas,omitempty"`
	Patterns []string `json:"patterns,omitempty"`
	// Paths count only in a text that matches the entry's context: a script
	// often holds a host in one variable and builds each address from it.
	Context string   `json:"context,omitempty"`
	Paths   []string `json:"paths,omitempty"`
	// Unless is an optional pattern; a line that matches it does not count.
	// RE2 has no lookahead, so the exclusion is checked here.
	Unless string `json:"unless,omitempty"`
	// Subjects name what a matching line acts on: an account, a file, a host.
	Subjects []subjectEntry `json:"subjects,omitempty"`
}

// subjectEntry is a label and a pattern whose one group captures the subject.
type subjectEntry struct {
	Label   string `json:"label"`
	Pattern string `json:"pattern"`
}

// Hit is one activity found in a text.
type Hit struct {
	Name    string
	Tactics []string
	Attack  []string
	Atlas   []string
	// Lines is the number of distinct lines that show the activity.
	Lines int
	// Evidence holds the first of those lines, in the order of the text.
	Evidence []Evidence
}

// Evidence is one line that shows an activity.
type Evidence struct {
	// Line is the number of the line in the text, from 1.
	Line int
	// Text is the line without the space around it, cut to a fixed length.
	Text     string
	Subjects []Subject
}

// Subject is what a line acts on, and what kind of thing it is.
type Subject struct {
	Label string
	Value string
}

// Table holds the compiled activity patterns, in the order of the data file.
type Table struct {
	contexts   map[string]pattern
	activities []compiled
}

type compiled struct {
	name     string
	tactics  []string
	attack   []string
	atlas    []string
	patterns []pattern
	context  string
	paths    []pattern
	unless   *regexp.Regexp
	subjects []subject
}

type subject struct {
	label string
	rx    *regexp.Regexp
}

// pattern is a compiled expression and the literals one of which every
// match holds, in lower case. Looking for a literal is far cheaper than
// running the expression, so only the lines that hold one are tried.
type pattern struct {
	rx       *regexp.Regexp
	literals [][]byte
}

// LoadActivities decodes activities.json and compiles each pattern.
func LoadActivities() (Table, error) {
	return decode(raw)
}

func decode(data []byte) (Table, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var doc document
	if err := dec.Decode(&doc); err != nil {
		return Table{}, fmt.Errorf("activities.json: %w", err)
	}
	if dec.More() {
		return Table{}, fmt.Errorf("activities.json: trailing data")
	}
	if len(doc.Activities) == 0 {
		return Table{}, fmt.Errorf("activities.json: no activities")
	}
	t := Table{contexts: map[string]pattern{}}
	for name, expr := range doc.Contexts {
		p, err := compile(expr)
		if err != nil {
			return Table{}, fmt.Errorf("activities.json context %s: %w", name, err)
		}
		t.contexts[name] = p
	}
	seen := map[string]bool{}
	for i, e := range doc.Activities {
		_, known := t.contexts[e.Context]
		switch {
		case e.Name == "":
			return Table{}, fmt.Errorf("activities.json[%d]: empty name", i)
		case seen[e.Name]:
			return Table{}, fmt.Errorf("activities.json[%d]: %s is named twice", i, e.Name)
		case len(e.Tactics) == 0:
			return Table{}, fmt.Errorf("activities.json[%d] %s: no tactics", i, e.Name)
		case len(e.Attack) == 0:
			return Table{}, fmt.Errorf("activities.json[%d] %s: no ATT&CK technique", i, e.Name)
		case len(e.Patterns)+len(e.Paths) == 0:
			return Table{}, fmt.Errorf("activities.json[%d] %s: no patterns", i, e.Name)
		case (e.Context == "") != (len(e.Paths) == 0):
			return Table{}, fmt.Errorf("activities.json[%d] %s: paths and a context go together", i, e.Name)
		case e.Context != "" && !known:
			return Table{}, fmt.Errorf("activities.json[%d] %s: unknown context %q", i, e.Name, e.Context)
		}
		seen[e.Name] = true
		c := compiled{name: e.Name, tactics: e.Tactics, attack: e.Attack, atlas: e.Atlas, context: e.Context}
		var err error
		if c.patterns, err = compileAll(e.Patterns); err != nil {
			return Table{}, fmt.Errorf("activities.json[%d] %s: %w", i, e.Name, err)
		}
		if c.paths, err = compileAll(e.Paths); err != nil {
			return Table{}, fmt.Errorf("activities.json[%d] %s: %w", i, e.Name, err)
		}
		if e.Unless != "" {
			if c.unless, err = regexp.Compile(e.Unless); err != nil {
				return Table{}, fmt.Errorf("activities.json[%d] %s unless: %w", i, e.Name, err)
			}
		}
		for _, sub := range e.Subjects {
			rx, err := regexp.Compile(sub.Pattern)
			switch {
			case err != nil:
				return Table{}, fmt.Errorf("activities.json[%d] %s subject %s: %w", i, e.Name, sub.Label, err)
			case sub.Label == "" || rx.NumSubexp() != 1:
				return Table{}, fmt.Errorf("activities.json[%d] %s: a subject needs a label and a pattern with one group", i, e.Name)
			}
			c.subjects = append(c.subjects, subject{label: sub.Label, rx: rx})
		}
		t.activities = append(t.activities, c)
	}
	return t, nil
}

func compileAll(exprs []string) ([]pattern, error) {
	compiled := make([]pattern, 0, len(exprs))
	for _, expr := range exprs {
		p, err := compile(expr)
		if err != nil {
			return nil, err
		}
		compiled = append(compiled, p)
	}
	return compiled, nil
}

func compile(expr string) (pattern, error) {
	rx, err := regexp.Compile(expr)
	if err != nil {
		return pattern{}, err
	}
	p := pattern{rx: rx}
	if tree, err := syntax.Parse(expr, syntax.Perl); err == nil {
		for _, lit := range required(tree) {
			p.literals = append(p.literals, []byte(lit))
		}
	}
	return p, nil
}

// minLiteral is the shortest literal worth looking for; a shorter one is in
// nearly every line.
const minLiteral = 3

// required returns lower-case literals of which every match of re holds at
// least one, or nil when the expression promises none.
func required(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		lit := strings.ToLower(string(re.Rune))
		for _, r := range lit {
			if r >= utf8.RuneSelf {
				return nil
			}
		}
		if len(lit) < minLiteral {
			return nil
		}
		return []string{lit}
	case syntax.OpCapture, syntax.OpPlus:
		return required(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min > 0 {
			return required(re.Sub[0])
		}
	case syntax.OpConcat:
		// Every part must match, so any part's literals serve; the longest are the rarest.
		var best []string
		for _, sub := range re.Sub {
			if lits := required(sub); shortest(lits) > shortest(best) {
				best = lits
			}
		}
		return best
	case syntax.OpAlternate:
		var all []string
		for _, sub := range re.Sub {
			lits := required(sub)
			if lits == nil {
				return nil
			}
			all = append(all, lits...)
		}
		return all
	}
	return nil
}

func shortest(lits []string) int {
	if len(lits) == 0 {
		return 0
	}
	n := len(lits[0])
	for _, lit := range lits[1:] {
		n = min(n, len(lit))
	}
	return n
}

// Names lists the activities, in the order of the data file.
func (t Table) Names() []string {
	names := make([]string, len(t.activities))
	for i, a := range t.activities {
		names[i] = a.name
	}
	return names
}

// Each calls visit with every activity, in the order of the data file, so a
// caller that holds the other tables can check what an activity refers to.
func (t Table) Each(visit func(name string, tactics, attack, atlas []string)) {
	for _, a := range t.activities {
		visit(a.name, a.tactics, a.attack, a.atlas)
	}
}

// Tactics lists every tactic name the table assigns, so a caller that holds
// the tactic table can check that each one exists.
func (t Table) Tactics() []string {
	seen := map[string]bool{}
	var names []string
	for _, a := range t.activities {
		for _, name := range a.tactics {
			if !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}
	return names
}

// Detect returns the activities a text shows, in the order of the data
// file. A command continued over several lines counts as one line.
func (t Table) Detect(text string) []Hit {
	joined := text
	if strings.Contains(text, "\\\n") || strings.Contains(text, "\\\r") || strings.Contains(text, "`\n") || strings.Contains(text, "`\r") {
		joined = continued.Replace(text)
	}
	// Only A to Z are folded, so an offset in lower is the same offset in text.
	lower := []byte(joined)
	for i, c := range lower {
		if c >= 'A' && c <= 'Z' {
			lower[i] = c + ('a' - 'A')
		}
	}
	inContext := map[string]bool{}
	for name, p := range t.contexts {
		inContext[name] = len(p.lines(joined, lower, nil, 1)) > 0
	}
	var hits []Hit
	var variables vars.Set
	for _, a := range t.activities {
		patterns := a.patterns
		if inContext[a.context] {
			patterns = append(patterns[:len(patterns):len(patterns)], a.paths...)
		}
		lines := map[int]bool{}
		for _, p := range patterns {
			for _, start := range p.lines(joined, lower, a.unless, -1) {
				lines[start] = true
			}
		}
		if len(lines) == 0 {
			continue
		}
		if variables == nil && len(a.subjects) > 0 {
			variables = vars.Read(text)
		}
		hit := Hit{Name: a.name, Tactics: a.tactics, Attack: a.attack, Atlas: a.atlas, Lines: len(lines)}
		hit.Evidence = a.evidence(text, joined, lines, variables)
		hits = append(hits, hit)
	}
	return hits
}

// evidence returns the first lines of an activity. The line number is
// counted in text, where a continued command still spans its lines.
func (a compiled) evidence(text, joined string, lines map[int]bool, variables vars.Set) []Evidence {
	starts := make([]int, 0, len(lines))
	for start := range lines {
		starts = append(starts, start)
	}
	slices.Sort(starts)
	if len(starts) > maxEvidence {
		starts = starts[:maxEvidence]
	}
	found := make([]Evidence, 0, len(starts))
	number, counted := 1, 0
	for _, start := range starts {
		number += strings.Count(text[counted:start], "\n")
		counted = start
		_, end := lineAround(joined, start)
		line := strings.Join(strings.Fields(joined[start:end]), " ")
		e := Evidence{Line: number, Text: cut(line)}
		for _, sub := range a.subjects {
			m := sub.rx.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			// A variable the text never sets names nothing, so it is no subject.
			if value := resolve(strings.Trim(m[1], "\"'`;,()"), variables); value != "" && !rxUnset.MatchString(value) {
				e.Subjects = append(e.Subjects, Subject{Label: sub.label, Value: cut(value)})
			}
		}
		found = append(found, e)
	}
	return found
}

// cut shortens s to maxText bytes, ending in "..." and never inside a rune.
func cut(s string) string {
	if len(s) <= maxText {
		return s
	}
	end := maxText - len(ellipsis)
	for end > 0 && !utf8.RuneStart(s[end]) {
		end--
	}
	return s[:end] + ellipsis
}

// rxUnset is a value that is one variable and nothing else.
var rxUnset = regexp.MustCompile(`^(?:\$\{?[A-Za-z_]\w*\}?|%[A-Za-z_]\w*%)$`)

// resolve gives a subject that is one variable the value the text sets it
// to, and keeps the name beside it; anything else is returned as it is.
func resolve(value string, variables vars.Set) string {
	if set, ok := variables.Value(value); ok {
		return set + " (" + value + ")"
	}
	return value
}

// lines returns the start of each line the pattern matches and unless does
// not, stopping after limit lines when limit is positive.
func (p pattern) lines(text string, lower []byte, unless *regexp.Regexp, limit int) []int {
	var found []int
	tried := map[int]bool{}
	try := func(pos int) (next int) {
		start, end := lineAround(text, pos)
		if !tried[start] {
			tried[start] = true
			line := text[start:end]
			if p.rx.MatchString(line) && (unless == nil || !unless.MatchString(line)) {
				found = append(found, start)
			}
		}
		return end
	}
	if len(p.literals) == 0 {
		for pos := 0; pos < len(text) && len(found) != limit; pos++ {
			pos = try(pos)
		}
		return found
	}
	for _, lit := range p.literals {
		for pos := 0; len(found) != limit; {
			i := bytes.Index(lower[pos:], lit)
			if i < 0 {
				break
			}
			pos = try(pos + i)
		}
	}
	return found
}

// lineAround returns the bounds of the line that holds the byte at pos.
func lineAround(text string, pos int) (start, end int) {
	start = strings.LastIndexByte(text[:pos], '\n') + 1
	end = len(text)
	if i := strings.IndexByte(text[pos:], '\n'); i >= 0 {
		end = pos + i
	}
	return start, end
}
