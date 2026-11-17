// Package exposure names what the evidence holds that an attacker can use:
// usernames, email addresses, passwords and other secrets, devices and IP
// addresses. It reads text only; exposures.json declares every rule.
package exposure

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/get-sybers/slopmop/internal/vars"
)

//go:embed exposures.json
var raw []byte

const (
	// maxLine is how much of one line is searched; a longer line is cut.
	maxLine = 8 << 10
	// near is how many lines after a username a secret is still taken as its own.
	near = 3
	// shownStart and maxStars shape a masked secret: its first runes, stars, its last rune.
	shownStart = 2
	maxStars   = 8
)

type document struct {
	Kinds []kindEntry `json:"kinds"`
}

type kindEntry struct {
	Name     string `json:"name"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	// Secret marks a kind whose values are shown masked.
	Secret bool `json:"secret,omitempty"`
	// Keys are field names, without case or punctuation, whose value is of the kind.
	Keys []string `json:"keys,omitempty"`
	// Suffixes are endings of a field name that say the same.
	Suffixes []suffixEntry `json:"suffixes,omitempty"`
	// With names a key that counts only beside one of the listed keys.
	With map[string][]string `json:"with,omitempty"`
	// Indicators are indicator types whose values are of the kind.
	Indicators []indicatorEntry `json:"indicators,omitempty"`
	Valid      string           `json:"valid,omitempty"`
	Reject     string           `json:"reject,omitempty"`
	Patterns   []patternEntry   `json:"patterns,omitempty"`
}

type suffixEntry struct {
	Suffix string `json:"suffix"`
	Form   string `json:"form,omitempty"`
}

type indicatorEntry struct {
	Type string `json:"type"`
	Form string `json:"form,omitempty"`
}

// patternEntry is an expression with a group named value and, where the
// line says whose the value is, one named account.
type patternEntry struct {
	Form string `json:"form,omitempty"`
	// Needs are lower-case texts one of which a line must hold to be tried.
	Needs   []string `json:"needs"`
	Unless  string   `json:"unless,omitempty"`
	Pattern string   `json:"pattern"`
}

// Kind is one category of exposure.
type Kind struct {
	Name, Title, Severity string
	Secret                bool
}

// Item is one value found on one line.
type Item struct {
	Kind  string
	Value string
	// Account is whose a secret is, when the evidence says.
	Account string
	// Form is what a secret is: a password, a hash, a token or a key.
	Form string
	// Line is the line of the text, from 1.
	Line int
	// Open marks a secret whose value here describes it and gives nothing away.
	Open bool
}

type rule struct {
	kind int
	form string
	// with lists the keys one of which must stand beside this one; nil for no condition.
	with []string
	// prefix is what stands before the ending that named the kind: "db" of "dbpassword".
	prefix string
}

type pattern struct {
	kind    int
	form    string
	needs   []string
	unless  *regexp.Regexp
	rx      *regexp.Regexp
	value   int
	account int
}

type compiledKind struct {
	Kind
	valid, reject *regexp.Regexp
}

// Table holds the compiled rules.
type Table struct {
	kinds      []compiledKind
	exact      map[string]rule
	suffixes   []suffix
	indicators map[string]rule
	patterns   []pattern
}

type suffix struct {
	text string
	rule rule
}

// rxPair is KEY: value or KEY = value, with either side quoted or not.
var rxPair = regexp.MustCompile(`["']?([A-Za-z_][\w. -]{0,40}?[\w])["']?[ \t]*[:=][ \t]*(?:"([^"\r\n]*)"|'([^'\r\n]*)'|([^\s,;&"']+))`)

// Load decodes exposures.json and compiles each rule.
func Load() (Table, error) {
	return decode(raw)
}

func decode(data []byte) (Table, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var doc document
	if err := dec.Decode(&doc); err != nil {
		return Table{}, fmt.Errorf("exposures.json: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Table{}, errors.New("exposures.json: data after the document")
	}
	if len(doc.Kinds) == 0 {
		return Table{}, errors.New("exposures.json: no kinds")
	}
	t := Table{exact: map[string]rule{}, indicators: map[string]rule{}}
	seen := map[string]bool{}
	for i, e := range doc.Kinds {
		if e.Name == "" || e.Title == "" || e.Severity == "" || seen[e.Name] {
			return Table{}, fmt.Errorf("exposures.json[%d]: %q is named twice or lacks a name, a title or a severity", i, e.Name)
		}
		seen[e.Name] = true
		k := compiledKind{Kind: Kind{Name: e.Name, Title: e.Title, Severity: e.Severity, Secret: e.Secret}}
		var err error
		if k.valid, err = optional(e.Valid); err != nil {
			return Table{}, fmt.Errorf("exposures.json %s valid: %w", e.Name, err)
		}
		if k.reject, err = optional(e.Reject); err != nil {
			return Table{}, fmt.Errorf("exposures.json %s reject: %w", e.Name, err)
		}
		t.kinds = append(t.kinds, k)
		if err := t.add(i, e); err != nil {
			return Table{}, fmt.Errorf("exposures.json %s: %w", e.Name, err)
		}
	}
	// The longest ending decides, so "accesstoken" is a token and not a "token" of another kind.
	sort.SliceStable(t.suffixes, func(i, j int) bool { return len(t.suffixes[i].text) > len(t.suffixes[j].text) })
	return t, nil
}

func optional(expr string) (*regexp.Regexp, error) {
	if expr == "" {
		return nil, nil //nolint:nilnil // no expression is a valid answer
	}
	return regexp.Compile(expr)
}

// add files the keys, endings, indicator types and patterns of one kind.
func (t *Table) add(i int, e kindEntry) error {
	for _, key := range e.Keys {
		if key != normalise(key) || key == "" {
			return fmt.Errorf("the key %q is not lower-case letters and digits", key)
		}
		if _, taken := t.exact[key]; taken {
			return fmt.Errorf("the key %q is in two kinds", key)
		}
		t.exact[key] = rule{kind: i}
	}
	for key, beside := range e.With {
		if _, taken := t.exact[key]; taken || key != normalise(key) || len(beside) == 0 {
			return fmt.Errorf("the key %q is in two kinds, is not lower case or stands beside nothing", key)
		}
		t.exact[key] = rule{kind: i, with: beside}
	}
	for _, s := range e.Suffixes {
		if s.Suffix != normalise(s.Suffix) || len(s.Suffix) < 3 {
			return fmt.Errorf("the ending %q is not three lower-case letters or digits or more", s.Suffix)
		}
		t.suffixes = append(t.suffixes, suffix{text: s.Suffix, rule: rule{kind: i, form: s.Form}})
	}
	for _, ind := range e.Indicators {
		if _, taken := t.indicators[ind.Type]; taken || ind.Type == "" {
			return fmt.Errorf("the indicator type %q is in two kinds or has no name", ind.Type)
		}
		t.indicators[ind.Type] = rule{kind: i, form: ind.Form}
	}
	for _, p := range e.Patterns {
		rx, err := regexp.Compile(p.Pattern)
		if err != nil {
			return err
		}
		c := pattern{kind: i, form: p.Form, needs: p.Needs, rx: rx, value: rx.SubexpIndex("value"), account: rx.SubexpIndex("account")}
		if c.value < 0 || len(p.Needs) == 0 {
			return fmt.Errorf("the pattern %s lacks a group named value or a needed text", p.Pattern)
		}
		for _, need := range p.Needs {
			if need == "" || need != strings.ToLower(need) {
				return fmt.Errorf("the needed text %q is empty or not lower case", need)
			}
		}
		if c.unless, err = optional(p.Unless); err != nil {
			return err
		}
		t.patterns = append(t.patterns, c)
	}
	return nil
}

// Kinds lists the kinds, in the order of the data file.
func (t Table) Kinds() []Kind {
	kinds := make([]Kind, len(t.kinds))
	for i, k := range t.kinds {
		kinds[i] = k.Kind
	}
	return kinds
}

// IndicatorTypes lists the indicator types the table refers to, so a caller
// that holds the indicator table can check that each one exists.
func (t Table) IndicatorTypes() []string {
	types := make([]string, 0, len(t.indicators))
	for typ := range t.indicators {
		types = append(types, typ)
	}
	sort.Strings(types)
	return types
}

// FromIndicator turns an indicator match into an item, when its type is of a kind.
func (t Table) FromIndicator(typ, value string, line int) (Item, bool) {
	r, ok := t.indicators[typ]
	if !ok {
		return Item{}, false
	}
	k := t.kinds[r.kind]
	if (k.valid != nil && !k.valid.MatchString(value)) || (k.reject != nil && k.reject.MatchString(value)) {
		return Item{}, false
	}
	item := Item{Kind: k.Name, Value: value, Form: r.form, Line: line}
	// The header of a key block names the key; the key itself is in the lines below it.
	if strings.HasPrefix(value, "-----BEGIN ") {
		item.Value = strings.ToLower(strings.Trim(strings.TrimPrefix(value, "-----BEGIN "), "- "))
		item.Open = true
	}
	return item, true
}

// Mask shows the first runes and the last rune of a secret and its length,
// enough to tell one secret from another and not enough to use it.
func Mask(secret string) string {
	n := utf8.RuneCountInString(secret)
	runes := []rune(secret)
	if n <= shownStart+2 {
		return strings.Repeat("*", n) + " (" + strconv.Itoa(n) + " chars)"
	}
	stars := min(n-shownStart-1, maxStars)
	return string(runes[:shownStart]) + strings.Repeat("*", stars) + string(runes[n-1:]) + " (" + strconv.Itoa(n) + " chars)"
}

func normalise(key string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(key) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// lookup finds the rule of a field name. beside holds the names around it,
// for a key that counts only in company; nil means the company is unknown.
func (t Table) lookup(key string, beside map[string]bool) (rule, bool) {
	key = normalise(key)
	if r, ok := t.exact[key]; ok {
		if r.with == nil {
			return r, true
		}
		return r, slices.ContainsFunc(r.with, func(k string) bool { return beside[k] })
	}
	for _, s := range t.suffixes {
		if strings.HasSuffix(key, s.text) {
			r := s.rule
			r.prefix = strings.TrimSuffix(key, s.text)
			return r, true
		}
	}
	return rule{}, false
}

// scanner collects the items of one text.
type scanner struct {
	t     Table
	vars  vars.Set
	items []Item
	seen  map[Item]bool
	// account is the last username read from a field, accountLine its line
	// and accountPrefix what its field name began with.
	account       string
	accountLine   int
	accountPrefix string
}

// Extract returns what a text holds, in the order it is found. A text that
// is JSON is read by its fields; any other is read line by line, and by its
// columns when its first line is a header.
func (t Table) Extract(text string) []Item {
	s := &scanner{t: t, vars: vars.Read(text), seen: map[Item]bool{}}
	if first := strings.TrimLeft(text, " \t\r\n\ufeff"); strings.HasPrefix(first, "{") || strings.HasPrefix(first, "[") {
		if s.json(text) {
			return s.items
		}
		s.items, s.seen = nil, map[Item]bool{}
	}
	lines := strings.Split(text, "\n")
	s.columns(lines)
	for i, line := range lines {
		s.line(line, i+1)
	}
	return s.items
}

// emit cleans a value and records it when the kind accepts it.
func (s *scanner) emit(kind int, value, account, form string, line int) (string, bool) {
	value = s.clean(value)
	k := s.t.kinds[kind]
	if !k.Secret {
		// A domain before a name says where the account lives, not who it is.
		if i := strings.LastIndexByte(value, '\\'); i >= 0 {
			value = value[i+1:]
		}
	}
	// A hash is taken as it stands: crypt hashes begin with "$", as a placeholder does.
	rejected := k.reject != nil && form != formHash && k.reject.MatchString(value)
	if value == "" || rejected || (k.valid != nil && !k.valid.MatchString(value)) {
		return "", false
	}
	item := Item{Kind: k.Name, Value: value, Line: line}
	if k.Secret {
		item.Account, item.Form = s.owner(account), form
		if item.Form == "" {
			item.Form = k.Name
		}
		// A pair of hashes is named by its second, in lower case, so one hash is one item however it is written.
		if m := rxHashPair.FindStringSubmatch(value); m != nil && item.Form == formHash {
			item.Value = strings.ToLower(m[1])
		}
	}
	if !s.seen[item] {
		s.seen[item] = true
		s.items = append(s.items, item)
	}
	return value, true
}

// owner cleans the account a secret is said to belong to.
func (s *scanner) owner(account string) string {
	account = s.clean(account)
	if i := strings.LastIndexByte(account, '\\'); i >= 0 {
		account = account[i+1:]
	}
	if strings.ContainsAny(account, "$`%") {
		return ""
	}
	return account
}

// clean drops the quotes around a value and gives a variable what the text sets it to.
func (s *scanner) clean(value string) string {
	value = strings.Trim(strings.TrimSpace(value), "\"'`")
	if set, ok := s.vars.Value(value); ok {
		return set
	}
	return s.vars.Expand(value)
}

// line reads the fields and the patterns of one line.
func (s *scanner) line(line string, number int) {
	if len(line) < 4 {
		return
	}
	if len(line) > maxLine {
		line = line[:maxLine]
	}
	if strings.ContainsAny(line, ":=") {
		s.pairs(line, number)
	}
	lower := strings.ToLower(line)
	for _, p := range s.t.patterns {
		if !slices.ContainsFunc(p.needs, func(need string) bool { return strings.Contains(lower, need) }) {
			continue
		}
		if p.unless != nil && p.unless.MatchString(line) {
			continue
		}
		for _, m := range p.rx.FindAllStringSubmatch(line, -1) {
			account := ""
			if p.account >= 0 {
				account = m[p.account]
			}
			s.emit(p.kind, m[p.value], account, p.form, number)
		}
	}
}

// pairs reads every KEY: value and KEY = value of a line. A secret takes the
// username of its own line, or the one read at most a few lines before it.
func (s *scanner) pairs(line string, number int) {
	type found struct {
		rule  rule
		value string
	}
	var fields []found
	for _, m := range rxPair.FindAllStringSubmatch(line, -1) {
		if r, ok := s.t.lookup(m[1], nil); ok {
			fields = append(fields, found{r, m[2] + m[3] + m[4]})
		}
	}
	for _, f := range fields {
		if !s.t.kinds[f.rule.kind].Secret {
			if value, ok := s.emit(f.rule.kind, f.value, "", "", number); ok && s.t.kinds[f.rule.kind].Name == usernameKind {
				s.account, s.accountLine, s.accountPrefix = value, number, f.rule.prefix
			}
		}
	}
	for _, f := range fields {
		if s.t.kinds[f.rule.kind].Secret {
			// DB_USER names whose DB_PASSWORD is, and not whose API_TOKEN is.
			related := s.accountPrefix == "" || f.rule.prefix == "" || s.accountPrefix == f.rule.prefix
			account := ""
			if s.account != "" && number-s.accountLine <= near && related {
				account = s.account
			}
			s.emit(f.rule.kind, f.value, account, f.rule.form, number)
		}
	}
}

const (
	// usernameKind is the kind whose value says whose a secret beside it is.
	usernameKind = "username"
	formHash     = "hash"
)

// rxHashPair is an NT hash, with or without the LM hash and the colon before it.
var rxHashPair = regexp.MustCompile(`^(?:[0-9a-fA-F]{0,32}:)?([0-9a-fA-F]{32})$`)

// record reads one set of fields that belong together: an object of JSON or
// a row under a header.
func (s *scanner) record(keys, values []string, line int) {
	beside := map[string]bool{}
	for _, key := range keys {
		beside[normalise(key)] = true
	}
	account := ""
	rules := make([]rule, len(keys))
	known := make([]bool, len(keys))
	for i, key := range keys {
		rules[i], known[i] = s.t.lookup(key, beside)
		if known[i] && !s.t.kinds[rules[i].kind].Secret {
			if value, ok := s.emit(rules[i].kind, values[i], "", "", line); ok && account == "" && s.t.kinds[rules[i].kind].Name == usernameKind {
				account = value
			}
		}
	}
	for i := range keys {
		if known[i] && s.t.kinds[rules[i].kind].Secret {
			s.emit(rules[i].kind, values[i], account, rules[i].form, line)
		}
	}
}

// columns reads a text whose first line is a header that names a known
// field: each later line is a record under it.
func (s *scanner) columns(lines []string) {
	if len(lines) < 2 {
		return
	}
	header := strings.TrimPrefix(strings.TrimRight(lines[0], "\r"), "\ufeff")
	for _, delimiter := range []string{"\t", ",", ";", "|"} {
		keys := split(header, delimiter)
		if len(keys) < 2 {
			continue
		}
		beside := map[string]bool{}
		for _, key := range keys {
			beside[normalise(key)] = true
		}
		if !slices.ContainsFunc(keys, func(key string) bool {
			_, ok := s.t.lookup(key, beside)
			return ok && len(key) <= 40
		}) {
			continue
		}
		for i, line := range lines[1:] {
			values := split(strings.TrimRight(line, "\r"), delimiter)
			if len(values) > len(keys) {
				values = values[:len(keys)]
			}
			s.record(keys[:len(values)], values, i+2)
		}
		return
	}
}

func split(line, delimiter string) []string {
	fields := strings.Split(line, delimiter)
	for i, f := range fields {
		fields[i] = strings.Trim(strings.TrimSpace(f), `"'`)
	}
	return fields
}

// json reads every document of a text that is JSON; it reports false, and
// the text is then read by its lines, when one is malformed.
func (s *scanner) json(text string) bool {
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	line, counted := 1, 0
	for {
		var doc any
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			return true
		}
		if err != nil {
			return false
		}
		// A document is named by the line it ends on, which is its own line in JSON Lines.
		end := int(dec.InputOffset())
		line += strings.Count(text[counted:end], "\n")
		counted = end
		s.walk(doc, line)
	}
}

func (s *scanner) walk(v any, line int) {
	switch x := v.(type) {
	case []any:
		for _, item := range x {
			s.walk(item, line)
		}
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var fields, values []string
		for _, k := range keys {
			switch value := x[k].(type) {
			case string:
				fields, values = append(fields, k), append(values, value)
				// A string that holds a command or a message is read as a line of its own.
				if strings.ContainsAny(value, " =:") {
					s.line(value, line)
				}
			default:
				s.walk(value, line)
			}
		}
		s.record(fields, values, line)
	case string:
		s.line(x, line)
	}
}
