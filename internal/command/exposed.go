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
	// seenCollected marks a value first seen in an output: the scripts gathered it.
	seenCollected = "collected"
	// seenUsed marks a value first seen in a script: the attacker brought it.
	seenUsed = "used"
	// maxCites is how many places one exposed value names.
	maxCites = 5
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
	// service is what the value gives access to, or the host of an SSH key.
	service string
	seen    string
	cites   []cite
	// count is the number of lines that hold the value.
	count int
}

// what says what a value is, whose it is and what it is for, as far as the
// evidence says: "token of svc, GitHub". It is empty for a value alone.
func (e exposed) what() string {
	text := e.form
	if e.account != "" {
		text = strings.TrimSpace(text + " of " + e.account)
	}
	if e.service != "" && text != "" {
		return text + ", " + e.service
	}
	return text + e.service
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
	named := newTargets(p.exposures.Kinds())
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
			e := exposed{kind: p.exposures.Kinds()[kinds[it.Kind]], value: it.Value, account: it.Account, form: it.Form, service: it.Service, seen: seenCollected}
			if s.File.Role == evidence.Script {
				e.seen = seenUsed
			}
			all = append(all, e)
		}
		all[i].count++
		if c := (cite{s.File.Path, it.Line}); len(all[i].cites) < maxCites && !containsCite(all[i].cites, c) {
			all[i].cites = append(all[i].cites, c)
		}
	}
	for _, s := range steps {
		for _, it := range held[s.File.Path] {
			add(it, s)
		}
		text := texts[s.File.Path]
		for _, m := range s.Matches {
			// "$USER@corp.example" reads as an address and is a variable and a domain.
			if m.Line > 0 && m.Start > 0 && m.Start <= len(text) && text[m.Start-1] == '$' {
				continue
			}
			if it, ok := p.exposures.FromIndicator(m.Type, m.Value, m.Line); ok {
				add(it, s)
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
// whose it is, or what it is for. The evidence says so somewhere, so it is
// not two.
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
	// more reports whether b says all that a says, and something a does not.
	more := func(a, b exposed) bool {
		return (a.account == "" || a.account == b.account) && (a.service == "" || a.service == b.service) &&
			(a.account != b.account || a.service != b.service)
	}
	into := make([]int, len(all))
	for i, e := range all {
		into[i] = slices.IndexFunc(same[key(e)], func(j int) bool { return more(e, all[j]) })
		if into[i] >= 0 {
			into[i] = same[key(e)][into[i]]
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
	for i, e := range all {
		to := into[i]
		if to < 0 {
			continue
		}
		for into[to] >= 0 {
			to = into[to]
		}
		at := position[to]
		kept[at].count += e.count
		for _, c := range e.cites {
			if len(kept[at].cites) < maxCites && !containsCite(kept[at].cites, c) {
				kept[at].cites = append(kept[at].cites, c)
			}
		}
		// An output that held the value before any script said more of it collected it.
		if e.seen == seenCollected && i < to {
			kept[at].seen = seenCollected
		}
	}
	return kept
}

// mergeKinds folds a secret that two kinds hold into the kind the table
// lists last: a token that is the key of a service is listed as that key.
func mergeKinds(all []exposed, order map[string]int) []exposed {
	last := map[string]int{}
	for i, e := range all {
		if at, ok := last[e.value]; e.kind.Secret && (!ok || order[e.kind.Name] > order[all[at].kind.Name]) {
			last[e.value] = i
		}
	}
	kept := all[:0:0]
	position := map[int]int{}
	for i, e := range all {
		if at, ok := last[e.value]; !e.kind.Secret || !ok || all[at].kind.Name == e.kind.Name {
			position[i] = len(kept)
			kept = append(kept, e)
		}
	}
	for i, e := range all {
		to, ok := last[e.value]
		if !e.kind.Secret || !ok || all[to].kind.Name == e.kind.Name {
			continue
		}
		at := position[to]
		kept[at].count += e.count
		for _, c := range e.cites {
			if len(kept[at].cites) < maxCites && !containsCite(kept[at].cites, c) {
				kept[at].cites = append(kept[at].cites, c)
			}
		}
		if kept[at].account == "" {
			kept[at].account = e.account
		}
		if e.seen == seenCollected && i < to {
			kept[at].seen = seenCollected
		}
	}
	return kept
}

// exposedEvidence gives the assessment what is exposed: every secret, and of
// the other kinds what the scripts collected, not what the attacker brought.
func exposedEvidence(all []exposed) map[string][]assess.Exposed {
	out := map[string][]assess.Exposed{}
	for _, e := range all {
		if e.kind.Secret || e.seen == seenCollected {
			out[e.kind.Name] = append(out[e.kind.Name], assess.Exposed{Label: e.label(), Files: e.files()})
		}
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
		"account":  text(e.account),
		"form":     text(e.form),
		"service":  text(e.service),
		"seen":     text(e.seen),
		"severity": text(e.kind.Severity),
		"count":    render.Int(int64(e.count)),
		"files":    text(strings.Join(cites, ", ")),
	}
	return orderCells("exposure", cells, columns)
}
