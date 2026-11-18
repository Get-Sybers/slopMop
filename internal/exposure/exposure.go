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
	"strings"
	"unicode/utf8"

	"github.com/get-sybers/slopmop/internal/sift"
	"github.com/get-sybers/slopmop/internal/vars"
)

//go:embed exposures.json
var raw []byte

const (
	// maxLine is how much of one line is searched; a longer line is cut.
	maxLine = 8 << 10
	// near is how many lines after a username a secret is still taken as its own.
	near = 3
)

type document struct {
	Services []serviceEntry `json:"services,omitempty"`
	Kinds    []kindEntry    `json:"kinds"`
}

type kindEntry struct {
	Name     string `json:"name"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	// Secret marks a kind whose values are secrets: each opens something.
	Secret bool `json:"secret,omitempty"`
	// Keys are field names, without case or punctuation, whose value is of the kind.
	Keys []string `json:"keys,omitempty"`
	// Suffixes are endings of a field name that say the same.
	Suffixes []suffixEntry `json:"suffixes,omitempty"`
	// With names a key that counts only beside one of the listed keys.
	With map[string][]string `json:"with,omitempty"`
	// Indicators are indicator types whose values are of the kind.
	Indicators []indicatorEntry `json:"indicators,omitempty"`
	// Targeted puts the kind among what a script names outright.
	Targeted *targetedEntry `json:"targeted,omitempty"`
	Valid    string         `json:"valid,omitempty"`
	Reject   string         `json:"reject,omitempty"`
	Patterns []patternEntry `json:"patterns,omitempty"`
}

// targetedEntry is the title of a kind among the targets of the scripts and
// the indicator types that are of the kind only there: a domain a script
// names is a host it reaches for, and a domain in an output is not a device.
type targetedEntry struct {
	Title      string           `json:"title"`
	Indicators []indicatorEntry `json:"indicators,omitempty"`
}

type suffixEntry struct {
	Suffix string `json:"suffix"`
	Form   string `json:"form,omitempty"`
}

type indicatorEntry struct {
	Type string `json:"type"`
	Form string `json:"form,omitempty"`
	// Unless is an expression: a value that matches it is not of the kind.
	Unless string `json:"unless,omitempty"`
}

// patternEntry is an expression with a group named value and, where the
// line says whose the value is, one named account, and one named host
// where it says which host the value is for.
type patternEntry struct {
	Form string `json:"form,omitempty"`
	// Service names the service every value of the pattern is of.
	Service string `json:"service,omitempty"`
	// Needs are lower-case texts one of which a line must hold to be tried.
	Needs   []string `json:"needs"`
	Unless  string   `json:"unless,omitempty"`
	Pattern string   `json:"pattern"`
}

// Kind is one category of exposure.
type Kind struct {
	Name, Title, Severity string
	Secret                bool
	// Targeted is the title of the kind among what a script names outright;
	// empty when the kind is not listed there.
	Targeted string
}

// Item is one value found on one line.
type Item struct {
	Kind  string
	Value string
	// Account is whose a secret is, when the evidence says.
	Account string
	// Form is what a secret is: a password, a hash, a token or a key. A
	// value of another kind has a form where its kind holds several.
	Form string
	// Service is what the value gives access to: a cloud or the provider of
	// a key, or the host an SSH key is for.
	Service string
	// Line is the line of the text, from 1.
	Line int
}

type rule struct {
	kind int
	form string
	// with lists the keys one of which must stand beside this one; nil for no condition.
	with []string
	// prefix is what stands before the ending that named the kind: "db" of "dbpassword".
	prefix string
	// unless leaves out a value of an indicator that matches it.
	unless *regexp.Regexp
}

type pattern struct {
	kind  int
	form  string
	needs []string
	// sets hold the texts the expression itself promises: a line that
	// matches holds one of each, in a text that folds no letter.
	sets    [][]string
	unless  *regexp.Regexp
	rx      *regexp.Regexp
	value   int
	account int
	// host is the group that names the host a value is for, and service the
	// service every value is of; a host named on the line comes first.
	host    int
	service string
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
	// hardcoded maps the indicator types that are of a kind only in a script.
	hardcoded map[string]rule
	patterns  []pattern
	// names holds every key and ending: a field of a kind holds one of them.
	names [][]byte
	// services are what a value can be of, and words the words of a field
	// name that name one.
	services []service
	words    map[string]string
	// ofAny holds, for each kind, one expression that every value of some service matches.
	ofAny []*regexp.Regexp
	// finder looks for every needed text it takes in one pass, and found
	// says, for each needed text of each pattern, which of its answers that is; -1 for none.
	finder *sift.Finder
	found  [][]int
	// ascii says every needed text is ASCII, so a text put in lower case
	// byte by byte holds what a line put in lower case holds.
	ascii bool
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
	t := Table{exact: map[string]rule{}, indicators: map[string]rule{}, hardcoded: map[string]rule{}}
	seen := map[string]bool{}
	for i, e := range doc.Kinds {
		if e.Name == "" || e.Title == "" || e.Severity == "" || seen[e.Name] {
			return Table{}, fmt.Errorf("exposures.json[%d]: %q is named twice or lacks a name, a title or a severity", i, e.Name)
		}
		seen[e.Name] = true
		k := compiledKind{Kind: Kind{Name: e.Name, Title: e.Title, Severity: e.Severity, Secret: e.Secret}}
		if e.Targeted != nil {
			if e.Targeted.Title == "" || e.Secret {
				return Table{}, fmt.Errorf("exposures.json %s: targeted needs a title and a kind that is no secret", e.Name)
			}
			k.Targeted = e.Targeted.Title
		}
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
		if e.Targeted == nil {
			continue
		}
		for _, ind := range e.Targeted.Indicators {
			_, taken := t.hardcoded[ind.Type]
			if _, both := t.indicators[ind.Type]; taken || both || ind.Type == "" {
				return Table{}, fmt.Errorf("exposures.json %s: the indicator type %q is named twice or has no name", e.Name, ind.Type)
			}
			t.hardcoded[ind.Type] = rule{kind: i}
		}
	}
	if err := t.addServices(doc.Services); err != nil {
		return Table{}, fmt.Errorf("exposures.json: %w", err)
	}
	// The longest ending decides, so "accesstoken" is a token and not a "token" of another kind.
	sort.SliceStable(t.suffixes, func(i, j int) bool { return len(t.suffixes[i].text) > len(t.suffixes[j].text) })
	for key := range t.exact {
		t.names = append(t.names, []byte(key))
	}
	for _, s := range t.suffixes {
		t.names = append(t.names, []byte(s.text))
	}
	slices.SortFunc(t.names, bytes.Compare)
	// A text of three bytes or more on one line is left to the finder.
	var texts []string
	at := map[string]int{}
	t.found = make([][]int, len(t.patterns))
	for n, p := range t.patterns {
		t.found[n] = make([]int, len(p.needs))
		for k, need := range p.needs {
			t.found[n][k] = -1
			if len(need) < 3 || strings.Contains(need, "\n") {
				continue
			}
			if _, ok := at[need]; !ok {
				at[need] = len(texts)
				texts = append(texts, need)
			}
			t.found[n][k] = at[need]
		}
	}
	var err error
	if t.finder, err = sift.NewFinder(texts); err != nil {
		return Table{}, fmt.Errorf("exposures.json: %w", err)
	}
	t.ascii = !slices.ContainsFunc(t.patterns, func(p pattern) bool {
		return slices.ContainsFunc(p.needs, func(need string) bool {
			return strings.ContainsFunc(need, func(r rune) bool { return r >= utf8.RuneSelf })
		})
	})
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
		unless, err := optional(ind.Unless)
		if err != nil {
			return err
		}
		t.indicators[ind.Type] = rule{kind: i, form: ind.Form, unless: unless}
	}
	for _, p := range e.Patterns {
		rx, err := regexp.Compile(p.Pattern)
		if err != nil {
			return err
		}
		plan, err := sift.Read(p.Pattern)
		if err != nil {
			return err
		}
		c := pattern{
			kind: i, form: p.Form, needs: p.Needs, sets: plan.Needs, rx: rx, service: p.Service,
			value: rx.SubexpIndex("value"), account: rx.SubexpIndex("account"), host: rx.SubexpIndex("host"),
		}
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
	types := make([]string, 0, len(t.indicators)+len(t.hardcoded))
	for typ := range t.indicators {
		types = append(types, typ)
	}
	for typ := range t.hardcoded {
		types = append(types, typ)
	}
	sort.Strings(types)
	return types
}

// FromHardcoded turns an indicator match into an item of a kind that the
// type is of only in a script; a type that is of a kind anywhere is not one.
func (t Table) FromHardcoded(typ, value string, line int) (Item, bool) {
	r, ok := t.hardcoded[typ]
	if !ok {
		return Item{}, false
	}
	k := t.kinds[r.kind]
	if (k.valid != nil && !k.valid.MatchString(value)) || (k.reject != nil && k.reject.MatchString(value)) {
		return Item{}, false
	}
	return Item{Kind: k.Name, Value: value, Line: line}, true
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
	if r.unless != nil && r.unless.MatchString(value) {
		return Item{}, false
	}
	item := Item{Kind: k.Name, Value: value, Form: r.form, Service: t.serviceOf(r.kind, value, "", ""), Line: line}
	// The header of a key block names the key; the key itself is in the lines below it.
	if strings.HasPrefix(value, "-----BEGIN ") {
		item.Value = strings.ToLower(strings.Trim(strings.TrimPrefix(value, "-----BEGIN "), "- "))
	}
	return item, true
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
	// marks holds, for each pattern, a bit for each line worth trying it on;
	// nil when each line is searched for the needed texts as it is read.
	marks [][]uint64
	// flat is a line as a field name is compared: its letters and digits, in lower case.
	flat []byte
	// services holds the service of each value already asked about.
	services map[asked]string
}

// asked is what the service of a value is read from.
type asked struct {
	kind             int
	value, host, key string
}

// Extract returns what a text holds, in the order it is found. A text that
// is JSON is read by its fields; any other is read line by line, and by its
// columns when its first line is a header.
func (t Table) Extract(text string) []Item {
	s := &scanner{t: t, vars: vars.Read(text), seen: map[Item]bool{}, services: map[asked]string{}}
	if first := strings.TrimLeft(text, " \t\r\n\ufeff"); strings.HasPrefix(first, "{") || strings.HasPrefix(first, "[") {
		if s.json(text) {
			return s.items
		}
		s.items, s.seen = nil, map[Item]bool{}
	}
	lines := strings.Split(text, "\n")
	s.columns(lines)
	s.marks = s.t.mark(text, lines)
	for i, line := range lines {
		s.line(line, i+1)
	}
	return s.items
}

// source is what the rule that found a value says of it: whose it is, what
// it is, what it is for, and the name of the field it stood under.
type source struct {
	account, form, service, key string
}

// emit cleans a value and records it when the kind accepts it.
func (s *scanner) emit(kind int, value string, by source, line int) (string, bool) {
	form := by.form
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
	item := Item{Kind: k.Name, Value: value, Form: form, Line: line}
	// What the rule says nothing of is not cleaned: most values come alone.
	if by.account != "" {
		item.Account = s.owner(by.account)
	}
	host := ""
	if by.service != "" {
		// A host of known_hosts stands in brackets when it names a port.
		host = strings.NewReplacer("[", "", "]", "").Replace(s.owner(by.service))
	}
	// A text names the same value under the same field many times over.
	of := asked{kind, value, host, by.key}
	service, known := s.services[of]
	if !known {
		service = s.t.serviceOf(kind, value, host, by.key)
		s.services[of] = service
	}
	item.Service = service
	if form == formPublicKey {
		item.Value = fingerprint(value)
	}
	if k.Secret {
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
	if strings.ContainsAny(line, ":=") && s.named(line) {
		s.pairs(line, number)
	}
	lower := ""
	if s.marks == nil {
		lower = strings.ToLower(line)
	}
	for i, p := range s.t.patterns {
		if s.marks != nil {
			if m := s.marks[i]; m == nil || m[(number-1)/64]&(1<<((number-1)%64)) == 0 {
				continue
			}
		} else if !slices.ContainsFunc(p.needs, func(need string) bool { return strings.Contains(lower, need) }) {
			continue
		}
		if p.unless != nil && p.unless.MatchString(line) {
			continue
		}
		for _, m := range p.rx.FindAllStringSubmatch(line, -1) {
			by := source{form: p.form, service: p.service}
			if p.account >= 0 {
				by.account = m[p.account]
			}
			if p.host >= 0 && m[p.host] != "" {
				by.service = m[p.host]
			}
			s.emit(p.kind, m[p.value], by, number)
		}
	}
}

// named reports whether a line holds a key or an ending of some kind. A field
// name is compared by its letters and digits alone, so a line without one
// has no pair of any kind and is not read for pairs.
func (s *scanner) named(line string) bool {
	s.flat = s.flat[:0]
	for i := range len(line) {
		switch c := line[i]; {
		case c >= 'A' && c <= 'Z':
			s.flat = append(s.flat, c+('a'-'A'))
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			s.flat = append(s.flat, c)
		}
	}
	return slices.ContainsFunc(s.t.names, func(name []byte) bool { return bytes.Contains(s.flat, name) })
}

// mark finds the lines worth trying each pattern on by one search of the
// whole text for each needed text, which is far quicker than a search of
// every line. It returns nil for a text that must be read line by line.
func (t Table) mark(text string, lines []string) [][]uint64 {
	// The lower case of these runes is, or is matched as, a letter of ASCII.
	if !t.ascii || sift.Folds(text) || strings.Contains(text, "\u0130") {
		return nil
	}
	lower := sift.Lower(text)
	starts := make([]int, len(lines))
	at := 0
	for i, line := range lines {
		starts[i] = at
		at += len(line) + 1
	}
	marks := make([][]uint64, len(t.patterns))
	set := func(n, i int) {
		if marks[n] == nil {
			marks[n] = make([]uint64, (len(lines)+63)/64)
		}
		marks[n][i/64] |= 1 << (i % 64)
	}
	// The needed texts the finder takes are all looked for in one pass. A
	// line it names may hold its text past where a line is read to: the
	// pattern is then tried on it and finds nothing.
	found := t.finder.Lines(lower)
	for n, p := range t.patterns {
		for k, need := range p.needs {
			if at := t.found[n][k]; at >= 0 {
				for _, begins := range found[at] {
					i := sort.SearchInts(starts, begins)
					if len(lines[i]) >= 4 && sift.Holds(lower[begins:begins+min(len(lines[i]), maxLine)], p.sets) {
						set(n, i)
					}
				}
				continue
			}
			i := 0
			for at := 0; at < len(lower); at = starts[i] + len(lines[i]) + 1 {
				found := bytes.Index(lower[at:], []byte(need))
				if found < 0 {
					break
				}
				for i+1 < len(starts) && starts[i+1] <= at+found {
					i++
				}
				// A line is read to maxLine bytes, and one of fewer than four not at all.
				read := starts[i] + min(len(lines[i]), maxLine)
				if len(lines[i]) < 4 || at+found+len(need) > read || !sift.Holds(lower[starts[i]:read], p.sets) {
					continue
				}
				set(n, i)
			}
		}
	}
	return marks
}

// pairs reads every KEY: value and KEY = value of a line. A secret takes the
// username of its own line, or the one read at most a few lines before it.
func (s *scanner) pairs(line string, number int) {
	type found struct {
		rule       rule
		key, value string
	}
	var fields []found
	for _, m := range rxPair.FindAllStringSubmatch(line, -1) {
		if r, ok := s.t.lookup(m[1], nil); ok {
			fields = append(fields, found{r, m[1], m[2] + m[3] + m[4]})
		}
	}
	for _, f := range fields {
		if !s.t.kinds[f.rule.kind].Secret {
			if value, ok := s.emit(f.rule.kind, f.value, source{form: f.rule.form, key: f.key}, number); ok && s.t.kinds[f.rule.kind].Name == usernameKind {
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
			s.emit(f.rule.kind, f.value, source{account: account, form: f.rule.form, key: f.key}, number)
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
			if value, ok := s.emit(rules[i].kind, values[i], source{form: rules[i].form, key: keys[i]}, line); ok && account == "" && s.t.kinds[rules[i].kind].Name == usernameKind {
				account = value
			}
		}
	}
	for i := range keys {
		if known[i] && s.t.kinds[rules[i].kind].Secret {
			s.emit(rules[i].kind, values[i], source{account: account, form: rules[i].form, key: keys[i]}, line)
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
