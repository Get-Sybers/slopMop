package command

import (
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/get-sybers/slopmop/internal/assess"
	"github.com/get-sybers/slopmop/internal/evidence"
	"github.com/get-sybers/slopmop/internal/exposure"
	"github.com/get-sybers/slopmop/internal/render"
	"github.com/get-sybers/slopmop/internal/trace"
)

const (
	// deviceKind is the kind of exposure whose values are hosts.
	deviceKind = "device"
	// seenCollected marks a value first seen in an output: the scripts gathered it.
	seenCollected = "collected"
	// seenUsed marks a value first seen in a script: the attacker brought it.
	seenUsed = "used"
	// maxCites is how many places one exposed value names.
	maxCites = 5
	// fewServices is how many of the things a value is for the readout names.
	fewServices = 4
)

// cite is a place in the evidence: a file and, where it is known, a line.
type cite struct {
	file string
	line int
}

func (c cite) String() string {
	if c.line == 0 {
		return c.file
	}
	return c.file + ":" + strconv.Itoa(c.line)
}

// exposed is one value the evidence holds, wherever it holds it.
type exposed struct {
	kind    exposure.Kind
	value   string
	account string
	form    string
	// services are what the value gives access to: a cloud, the provider
	// of a key, or each host it is used against.
	services []string
	seen     string
	// begun is where the value is seen first, as seen says: the earliest
	// place of every sighting the value stands for.
	begun cite
	cites []cite
	// count is the number of lines that hold the value.
	count int
	// within names every file that holds a credential, and named every
	// line that names an account: what an entry of the report concerns is
	// read from them.
	within []string
	named  []cite
	// decoded is what an encoded secret says once it is decoded: the claims
	// of a token, the text of base64, the type of a key block.
	decoded string
}

// shown is the value as the report writes it: decoded, where it is encoded.
func (e exposed) shown() string {
	return or(e.decoded, e.value)
}

// assessed reports whether the assessment counts the value: every secret,
// and of the other kinds what the scripts collected, not what the attacker brought.
func (e exposed) assessed() bool {
	return e.kind.Secret || e.seen == seenCollected
}

// line says what an account or a credential is and gives its value, as an
// entry of the report lists it: "password of svc: Winter2026".
func (e exposed) line() string {
	what := e.what()
	if e.form == "" {
		what = strings.TrimSuffix(e.kind.Name+", "+what, ", ")
	}
	return what + ": " + e.shown()
}

// what says what a value is, whose it is and what it is for, as far as the
// evidence says: "token of svc, GitHub". It is empty for a value alone.
func (e exposed) what() string {
	text := e.form
	if e.account != "" {
		text = strings.TrimSpace(text + " of " + e.account)
	}
	of := fewOf(e.services, fewServices, ", ")
	if of != "" && text != "" {
		return text + ", " + of
	}
	return text + of
}

// label names the value as a reader acts on it: a secret by whose it is.
func (e exposed) label() string {
	switch {
	case !e.kind.Secret:
		return e.value
	case e.account != "":
		return e.form + " of " + e.account
	default:
		return e.form + " " + e.value
	}
}

func (e exposed) files() []string {
	var files []string
	for _, c := range e.cites {
		files = appendUnique(files, c.file)
	}
	return files
}

// collectExposed reads every file in the order of the timeline, so a value
// is collected or used by where it is seen first. It also gathers what the
// scripts name outright, which it returns for finish to quote.
func (p pipeline) collectExposed(steps []trace.Step, texts map[string]string, held map[string][]exposure.Item) ([]exposed, *targets) {
	kinds := map[string]int{}
	for i, k := range p.exposures.Kinds() {
		kinds[k.Name] = i
	}
	index := map[string]int{}
	var all []exposed
	named := newTargets(p.exposures.Kinds(), p.exposures.Vendor)
	add := func(it exposure.Item, s trace.Step) {
		if s.File.Role == evidence.Script {
			named.script(it, p.exposures.Kinds()[kinds[it.Kind]], s.File.Path)
		} else {
			named.output(it, s.File.Path)
		}
		key := strings.Join([]string{it.Kind, it.Value, it.Account, it.Form, it.Service}, "\x00")
		i, ok := index[key]
		if !ok {
			i = len(all)
			index[key] = i
			e := exposed{kind: p.exposures.Kinds()[kinds[it.Kind]], value: it.Value, account: it.Account, form: it.Form, seen: seenCollected}
			e.begun = cite{s.File.Path, it.Line}
			if it.Service != "" {
				e.services = []string{it.Service}
			}
			if s.File.Role == evidence.Script {
				e.seen = seenUsed
			}
			all = append(all, e)
		}
		all[i].count++
		if c := (cite{s.File.Path, it.Line}); len(all[i].cites) < maxCites && !containsCite(all[i].cites, c) {
			all[i].cites = append(all[i].cites, c)
		}
		// The files are read one after another, so a file is named once.
		switch e, c := &all[i], (cite{s.File.Path, it.Line}); {
		case e.kind.Credential && (len(e.within) == 0 || e.within[len(e.within)-1] != s.File.Path):
			e.within = append(e.within, s.File.Path)
		case e.kind.Account && it.Line > 0 && (len(e.named) == 0 || e.named[len(e.named)-1] != c):
			e.named = append(e.named, c)
		}
	}
	for _, s := range steps {
		// A line that signs in to a host names an account at it, which reads as an address and is none.
		logins := map[cite]bool{}
		for _, it := range held[s.File.Path] {
			add(it, s)
			if it.Kind == deviceKind && it.Line > 0 {
				logins[cite{strings.ToLower(it.Value), it.Line}] = true
			}
		}
		text := texts[s.File.Path]
		for _, m := range s.Matches {
			// "$USER@corp.example" reads as an address and is a variable and a domain.
			if m.Line > 0 && m.Start > 0 && m.Start <= len(text) && text[m.Start-1] == '$' {
				continue
			}
			if _, host, found := strings.Cut(m.Value, "@"); found && logins[cite{strings.ToLower(host), m.Line}] {
				continue
			}
			if it, ok := p.exposures.FromIndicator(m.Type, m.Value, m.Line); ok {
				add(it, s)
				// Whose a token is said to be is an account the evidence holds.
				if owner, owned := p.exposures.Owner(it); owned {
					add(owner, s)
				}
			}
			// A domain is a host only where a script names it; it is no exposure.
			if inPath(text, m.Start, m.Line) {
				continue
			}
			if it, ok := p.exposures.FromHardcoded(m.Type, m.Value, m.Line); ok {
				if s.File.Role == evidence.Script {
					named.script(it, p.exposures.Kinds()[kinds[it.Kind]], s.File.Path)
				} else {
					named.output(it, s.File.Path)
				}
			}
		}
	}
	all = mergeKinds(mergeOwned(all), kinds)
	for i, e := range all {
		if e.kind.Secret {
			all[i].decoded, _ = p.exposures.Decoded(e.value)
		}
	}
	sort.SliceStable(all, func(i, j int) bool {
		x, y := all[i], all[j]
		if x.kind.Name != y.kind.Name {
			return kinds[x.kind.Name] < kinds[y.kind.Name]
		}
		if x.seen != y.seen {
			return x.seen == seenCollected
		}
		if x.value != y.value {
			return x.value < y.value
		}
		return x.account < y.account
	})
	return all, named
}

// inPath reports whether the match at start is one element of a Windows
// path, as Microsoft.NET is in C:\Windows\Microsoft.NET\Framework: a single
// backslash stands before it. Two backslashes begin a share, whose host it is.
func inPath(text string, start, line int) bool {
	if line == 0 || start < 1 || start > len(text) || text[start-1] != '\\' {
		return false
	}
	return start < 2 || text[start-2] != '\\'
}

func containsCite(cites []cite, c cite) bool {
	for _, have := range cites {
		if have == c {
			return true
		}
	}
	return false
}

// mergeOwned folds a value into the same value seen with more said of it:
// whose it is, or what it is for. One secret of one account is one line,
// which names everything the secret is used against.
func mergeOwned(all []exposed) []exposed {
	// A secret is one secret whatever each place calls it; of another kind, what a value is tells two apart.
	key := func(e exposed) string {
		if e.kind.Secret {
			return e.kind.Name + "\x00" + e.value
		}
		return e.kind.Name + "\x00" + e.value + "\x00" + e.form
	}
	same := map[string][]int{}
	for i, e := range all {
		same[key(e)] = append(same[key(e)], i)
	}
	// covers reports whether b says all that a says of whose a value is and what it is for.
	covers := func(a, b exposed) bool {
		if a.account != "" && a.account != b.account {
			return false
		}
		return !slices.ContainsFunc(a.services, func(of string) bool { return !slices.Contains(b.services, of) })
	}
	// folds reports whether the value at i is the one at j, which stands for both.
	folds := func(i, j int) bool {
		a, b := all[i], all[j]
		if a.kind.Secret {
			return (sameAccount(a.account, b.account) && j < i) || (a.account == "" && b.account != "")
		}
		return covers(a, b) && (!covers(b, a) || j < i)
	}
	into := make([]int, len(all))
	for i, e := range all {
		into[i] = -1
		for _, j := range same[key(e)] {
			if j != i && folds(i, j) {
				into[i] = j
				break
			}
		}
	}
	kept := make([]exposed, 0, len(all))
	position := map[int]int{}
	for i, e := range all {
		if into[i] < 0 {
			position[i] = len(kept)
			kept = append(kept, e)
		}
	}
	first := map[int]int{}
	for i, e := range all {
		to := into[i]
		if to < 0 {
			continue
		}
		for into[to] >= 0 {
			to = into[to]
		}
		at := position[to]
		kept[at].fold(e)
		// A value is collected or used by where it is seen first.
		if earliest, folded := first[at]; i < to && (!folded || i < earliest) {
			first[at], kept[at].seen, kept[at].begun = i, e.seen, e.begun
		}
	}
	return kept
}

// sameAccount reports whether two names are one account: the same name, or
// a bare name and the same name with its domain after it.
func sameAccount(a, b string) bool {
	if strings.EqualFold(a, b) {
		return true
	}
	if a == "" || b == "" {
		return false
	}
	bare := func(name, full string) bool {
		local, _, qualified := strings.Cut(full, "@")
		return qualified && !strings.Contains(name, "@") && strings.EqualFold(name, local)
	}
	return bare(a, b) || bare(b, a)
}

// fold adds to a value what another place says of the same value: its
// lines, its files and what it is for.
func (e *exposed) fold(other exposed) {
	e.count += other.count
	e.within = union(e.within, other.within)
	e.named = append(e.named, other.named...)
	e.services = union(e.services, other.services)
	for _, c := range other.cites {
		if len(e.cites) < maxCites && !containsCite(e.cites, c) {
			e.cites = append(e.cites, c)
		}
	}
}

// union adds to a list the items of another that it lacks.
func union(files, more []string) []string {
	if len(more) == 0 {
		return files
	}
	have := make(map[string]bool, len(files))
	for _, f := range files {
		have[f] = true
	}
	for _, f := range more {
		if !have[f] {
			have[f] = true
			files = append(files, f)
		}
	}
	return files
}

// mergeKinds folds a secret or an account that two kinds hold into the kind
// the table lists last: a token that is the key of a service is listed as
// that key, and a username that is an email address as that address.
func mergeKinds(all []exposed, order map[string]int) []exposed {
	// The key is empty for a value that is folded into no other kind.
	key := func(e exposed) string {
		switch {
		case e.kind.Secret:
			return "secret\x00" + e.value
		case e.kind.Account:
			return "account\x00" + e.value
		}
		return ""
	}
	last := map[string]int{}
	for i, e := range all {
		if at, ok := last[key(e)]; key(e) != "" && (!ok || order[e.kind.Name] > order[all[at].kind.Name]) {
			last[key(e)] = i
		}
	}
	kept := all[:0:0]
	position := map[int]int{}
	for i, e := range all {
		if at, ok := last[key(e)]; !ok || all[at].kind.Name == e.kind.Name {
			position[i] = len(kept)
			kept = append(kept, e)
		}
	}
	first := map[int]int{}
	for i, e := range all {
		to, ok := last[key(e)]
		if !ok || all[to].kind.Name == e.kind.Name {
			continue
		}
		at := position[to]
		// Two kinds read the same lines, so the lines are not counted twice.
		lines := max(kept[at].count, e.count)
		kept[at].fold(e)
		kept[at].count = lines
		if kept[at].account == "" {
			kept[at].account = e.account
		}
		if earliest, folded := first[at]; i < to && (!folded || i < earliest) {
			first[at], kept[at].seen, kept[at].begun = i, e.seen, e.begun
		}
	}
	return kept
}

// exposedEvidence gives the assessment what is exposed: every secret, and of
// the other kinds what the scripts collected, not what the attacker brought.
func exposedEvidence(all []exposed) map[string][]assess.Exposed {
	out := map[string][]assess.Exposed{}
	for _, e := range all {
		if e.assessed() {
			out[e.kind.Name] = append(out[e.kind.Name], assess.Exposed{Label: e.label(), Files: e.files()})
		}
	}
	return out
}

// listed is one exposed account or credential as an entry of the report
// lists it, and the kind it is of.
type listed struct {
	kind, line string
}

// holdings indexes the exposed accounts and credentials: by kind those the
// assessment counts, the credentials by each file that holds one, and the
// accounts by each line that names one.
type holdings struct {
	all    []exposed
	byKind map[string][]int
	byFile map[string][]int
	byLine map[cite][]int
}

func hold(all []exposed) holdings {
	h := holdings{all: all, byKind: map[string][]int{}, byFile: map[string][]int{}, byLine: map[cite][]int{}}
	for i, e := range all {
		if !e.kind.Account && !e.kind.Credential {
			continue
		}
		if e.assessed() {
			h.byKind[e.kind.Name] = append(h.byKind[e.kind.Name], i)
		}
		for _, f := range e.within {
			h.byFile[f] = append(h.byFile[f], i)
		}
		for _, c := range e.named {
			h.byLine[c] = append(h.byLine[c], i)
		}
	}
	return h
}

// concerning lists what an entry concerns, the credentials first: those of
// the kinds it names, the credentials its files hold and the accounts its
// lines name. An account a listed credential is of is not listed again.
func (h holdings) concerning(kinds []assess.Listed, files []string, lines []cite) []listed {
	picked := map[int]bool{}
	var order []int
	pick := func(indexes []int) {
		for _, i := range indexes {
			if !picked[i] {
				picked[i] = true
				order = append(order, i)
			}
		}
	}
	for _, l := range kinds {
		pick(h.byKind[l.Kind])
	}
	for _, f := range files {
		pick(h.byFile[f])
	}
	for _, c := range lines {
		pick(h.byLine[c])
	}
	sort.Slice(order, func(a, b int) bool {
		x, y := h.all[order[a]].kind.Account, h.all[order[b]].kind.Account
		if x != y {
			return y
		}
		return order[a] < order[b]
	})
	owners := map[string]bool{}
	for _, i := range order {
		if e := h.all[i]; e.kind.Credential && e.account != "" {
			owners[strings.ToLower(e.account)] = true
		}
	}
	var out []listed
	for _, i := range order {
		e := h.all[i]
		if e.kind.Account && owners[strings.ToLower(e.value)] {
			continue
		}
		out = append(out, listed{kind: e.kind.Name, line: e.line()})
	}
	return out
}

func exposedRow(e exposed, columns []render.Column) ([]render.Value, error) {
	text := func(s string) render.Value {
		if s == "" {
			return render.NotApplicable()
		}
		return render.Text(s)
	}
	cites := make([]string, len(e.cites))
	for i, c := range e.cites {
		cites[i] = c.String()
	}
	cells := map[string]render.Value{
		"kind":     text(e.kind.Name),
		"value":    text(e.value),
		"decoded":  text(e.decoded),
		"account":  text(e.account),
		"form":     text(e.form),
		"service":  text(strings.Join(e.services, ", ")),
		"seen":     text(e.seen),
		"severity": text(e.kind.Severity),
		"count":    render.Int(int64(e.count)),
		"files":    text(strings.Join(cites, ", ")),
	}
	return orderCells("exposure", cells, columns)
}
