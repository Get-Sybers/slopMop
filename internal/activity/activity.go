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
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/get-sybers/slopmop/internal/parallel"
	"github.com/get-sybers/slopmop/internal/sift"
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
	Contexts map[string]string `json:"contexts"`
	// Labels says how the subjects of a label are listed, for those that
	// are not listed by their value and then what acted on it.
	Labels     map[string]Listing `json:"labels,omitempty"`
	Activities []entry            `json:"activities"`
}

// Listing says how the subjects of a label are listed: what heads their
// column, and the labels whose subjects are listed beside each of them.
type Listing struct {
	Column string   `json:"column"`
	Beside []string `json:"beside,omitempty"`
	// After lists a subject after the activities that acted on it, not before.
	After bool `json:"after,omitempty"`
}

type entry struct {
	Name    string   `json:"name"`
	Tactics []string `json:"tactics"`
	// Attack names the ATT&CK techniques the activity shows. Its tactics
	// and its ATLAS techniques follow from them: internal/mitre.
	Attack   []string `json:"attack"`
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
	// Spread holds patterns of a record of connections, whose lines count only together.
	Spread *spreadEntry `json:"spread,omitempty"`
}

// spreadEntry is patterns with a group named to, what a line reaches, and one
// named at, where. The lines count once a text reaches one to at Least places,
// as a scan of its ports does and a visit to it does not.
type spreadEntry struct {
	Least    int      `json:"least"`
	Patterns []string `json:"patterns"`
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
	// Lines is the number of distinct lines that show the activity.
	Lines int
	// Evidence holds the first of those lines, in the order of the text.
	Evidence []Evidence
}

// Evidence is one line that shows an activity.
type Evidence struct {
	// Line is the number of the line in the text, from 1.
	Line int
	// Last is the line a command continued over lines ends on, and 0 for a line alone.
	Last int
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
	labels     map[string]Listing
	activities []compiled
	// finder looks for the literals of every pattern in one pass over a text.
	finder *sift.Finder
}

type compiled struct {
	name     string
	tactics  []string
	attack   []string
	patterns []pattern
	context  string
	paths    []pattern
	unless   *regexp.Regexp
	subjects []subject
	spread   []pattern
	least    int
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
	// found numbers the literals among those of the whole table, as the finder answers.
	found []int
	// sets hold every text the expression promises: a line that matches
	// holds one of each, so a line that lacks one is not tried.
	sets [][]string
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
		c := compiled{name: e.Name, tactics: e.Tactics, attack: e.Attack, context: e.Context}
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
		if e.Spread != nil {
			if c.spread, err = compileAll(e.Spread.Patterns); err != nil {
				return Table{}, fmt.Errorf("activities.json[%d] %s spread: %w", i, e.Name, err)
			}
			if c.least = e.Spread.Least; c.least < 2 || len(c.spread) == 0 {
				return Table{}, fmt.Errorf("activities.json[%d] %s: a spread needs a pattern and a least of two or more", i, e.Name)
			}
			for _, p := range c.spread {
				if p.rx.NumSubexp() != 2 || p.rx.SubexpIndex("to") < 0 || p.rx.SubexpIndex("at") < 0 {
					return Table{}, fmt.Errorf("activities.json[%d] %s: a spread pattern needs the groups to and at, and no other", i, e.Name)
				}
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
	if err := t.label(doc.Labels); err != nil {
		return Table{}, fmt.Errorf("activities.json labels: %w", err)
	}
	if err := t.number(); err != nil {
		return Table{}, fmt.Errorf("activities.json: %w", err)
	}
	return t, nil
}

// label keeps how the subjects of each label are listed. Every label it
// names is one some subject carries.
func (t *Table) label(entries map[string]Listing) error {
	used := map[string]bool{}
	for _, a := range t.activities {
		for _, sub := range a.subjects {
			used[sub.label] = true
		}
	}
	for name, e := range entries {
		switch {
		case !used[name]:
			return fmt.Errorf("%q is the label of no subject", name)
		case e.Column == "":
			return fmt.Errorf("%q has no column", name)
		}
		for _, beside := range e.Beside {
			if !used[beside] || beside == name {
				return fmt.Errorf("%q stands beside %q, which is itself or the label of no subject", name, beside)
			}
		}
	}
	t.labels = entries
	return nil
}

// Shown says how the subjects of a label are listed. It is empty for a
// label that is listed by its value and then what acted on it.
func (t Table) Shown(label string) Listing {
	return t.labels[label]
}

// number gives each literal of the table one number, and each pattern the
// numbers of its own, so one pass over a text serves every pattern.
func (t *Table) number() error {
	var texts []string
	numbers := map[string]int{}
	number := func(p pattern) pattern {
		for _, lit := range p.literals {
			n, known := numbers[string(lit)]
			if !known {
				n = len(texts)
				numbers[string(lit)] = n
				texts = append(texts, string(lit))
			}
			p.found = append(p.found, n)
		}
		return p
	}
	for name, p := range t.contexts {
		t.contexts[name] = number(p)
	}
	for _, a := range t.activities {
		for i := range a.patterns {
			a.patterns[i] = number(a.patterns[i])
		}
		for i := range a.paths {
			a.paths[i] = number(a.paths[i])
		}
		for i := range a.spread {
			a.spread[i] = number(a.spread[i])
		}
	}
	var err error
	t.finder, err = sift.NewFinder(texts)
	return err
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
	plan, err := sift.Read(expr)
	if err != nil {
		return pattern{}, err
	}
	p := pattern{rx: rx, sets: plan.Needs}
	for _, lit := range plan.Rare() {
		p.literals = append(p.literals, []byte(lit))
	}
	return p, nil
}

// Labels lists the labels of the subjects, each once, in the order of the
// data file, so a caller that files a subject by its label can check it.
func (t Table) Labels() []string {
	var labels []string
	for _, a := range t.activities {
		for _, sub := range a.subjects {
			if !slices.Contains(labels, sub.label) {
				labels = append(labels, sub.label)
			}
		}
	}
	return labels
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
func (t Table) Each(visit func(name string, tactics, attack []string)) {
	for _, a := range t.activities {
		visit(a.name, a.tactics, a.attack)
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

// small is the size below which a text is searched on the caller's goroutine.
const small = 16 << 10

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
	// A text that folds a letter outside ASCII shows it in no literal, so every line is tried.
	if sift.Folds(joined) || t.finder == nil {
		lower = nil
	}
	// One pass finds the lines of every literal; each pattern then reads its own.
	var held [][]int
	if lower != nil {
		held = t.finder.Lines(lower)
	}
	inContext := map[string]bool{}
	for name, p := range t.contexts {
		inContext[name] = len(p.lines(joined, lower, held, nil, 1)) > 0
	}
	// The lines of each activity are found apart from the others, on every
	// processor when the text is large; the hits are then made in order.
	found := make([]map[int]bool, len(t.activities))
	search := func(i int) {
		a := t.activities[i]
		patterns := a.patterns
		if inContext[a.context] {
			patterns = append(patterns[:len(patterns):len(patterns)], a.paths...)
		}
		lines := map[int]bool{}
		for _, p := range patterns {
			for _, start := range p.lines(joined, lower, held, a.unless, -1) {
				lines[start] = true
			}
		}
		for _, p := range a.spread {
			for _, start := range p.reached(joined, lower, held, a.unless, a.least) {
				lines[start] = true
			}
		}
		found[i] = lines
	}
	if len(text) < small {
		for i := range t.activities {
			search(i)
		}
	} else {
		parallel.Each(len(t.activities), search)
	}
	var hits []Hit
	var variables vars.Set
	for i, a := range t.activities {
		lines := found[i]
		if len(lines) == 0 {
			continue
		}
		if variables == nil && len(a.subjects) > 0 {
			variables = vars.Read(text)
		}
		hit := Hit{Name: a.name, Tactics: a.tactics, Attack: a.attack, Lines: len(lines)}
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
		if more := strings.Count(text[start:end], "\n"); more > 0 {
			e.Last = number + more
		}
		for _, sub := range a.subjects {
			m := sub.rx.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			if value := resolve(strings.Trim(m[1], "\"'`;,()"), variables); value != "" {
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

// resolve gives a subject that is one variable the value the text sets it
// to, and keeps the name beside it; anything else is returned as it is.
func resolve(value string, variables vars.Set) string {
	if set, ok := variables.Value(value); ok {
		return set + " (" + value + ")"
	}
	return value
}

// Plain returns the value without the name of the variable that held it,
// which resolve writes beside it.
func (s Subject) Plain() string {
	open := strings.LastIndex(s.Value, " (")
	if open < 0 || !strings.HasSuffix(s.Value, ")") || !vars.Refers(s.Value[open+2:len(s.Value)-1]) {
		return s.Value
	}
	return s.Value[:open]
}

// lines returns the start of each line the pattern matches and unless does
// not, stopping after limit lines when limit is positive. held gives the
// lines of each literal of the table; lower is nil when every line is tried.
func (p pattern) lines(text string, lower []byte, held [][]int, unless *regexp.Regexp, limit int) []int {
	var found []int
	tried := map[int]bool{}
	try := func(pos int) (next int) {
		start, end := lineAround(text, pos)
		if !tried[start] {
			tried[start] = true
			line := text[start:end]
			promised := lower == nil || sift.Holds(lower[start:end], p.sets)
			if promised && p.rx.MatchString(line) && (unless == nil || !unless.MatchString(line)) {
				found = append(found, start)
			}
		}
		return end
	}
	if len(p.found) == 0 || lower == nil {
		for pos := 0; pos < len(text) && len(found) != limit; pos++ {
			pos = try(pos)
		}
		return found
	}
	for _, n := range p.found {
		for _, start := range held[n] {
			if len(found) == limit {
				return found
			}
			try(start)
		}
	}
	return found
}

// maxReached is how many lines of a record of connections one pattern keeps from one text.
const maxReached = 200000

// reached returns the start of each line that reaches what the text reaches
// at least places or more: the lines a scan leaves, and not those of a visit.
func (p pattern) reached(text string, lower []byte, held [][]int, unless *regexp.Regexp, least int) []int {
	to, at := p.rx.SubexpIndex("to"), p.rx.SubexpIndex("at")
	type reach struct {
		start int
		to    string
	}
	var lines []reach
	places := map[string]map[string]bool{}
	tried := map[int]bool{}
	try := func(pos int) (next int) {
		start, end := lineAround(text, pos)
		if tried[start] {
			return end
		}
		tried[start] = true
		line := text[start:end]
		if lower != nil && !sift.Holds(lower[start:end], p.sets) {
			return end
		}
		m := p.rx.FindStringSubmatch(line)
		if m == nil || (unless != nil && unless.MatchString(line)) {
			return end
		}
		if places[m[to]] == nil {
			places[m[to]] = map[string]bool{}
		}
		places[m[to]][m[at]] = true
		lines = append(lines, reach{start: start, to: m[to]})
		return end
	}
	if len(p.found) == 0 || lower == nil {
		for pos := 0; pos < len(text) && len(lines) < maxReached; pos++ {
			pos = try(pos)
		}
	}
	for _, n := range p.found {
		if lower == nil {
			break
		}
		for _, start := range held[n] {
			if len(lines) == maxReached {
				break
			}
			try(start)
		}
	}
	var found []int
	for _, l := range lines {
		if len(places[l.to]) >= least {
			found = append(found, l.start)
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
