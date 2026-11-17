package command

import (
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
	// open marks a secret whose value describes it and gives nothing away.
	open bool
	// plain marks a secret that the run was asked to write out as it is.
	plain bool
	seen  string
	cites []cite
	// count is the number of lines that hold the value.
	count int
}

// shown is the value as it is written out: a secret is masked unless the
// run was asked to show secrets.
func (e exposed) shown() string {
	if e.kind.Secret && !e.open && !e.plain {
		return exposure.Mask(e.value)
	}
	return e.value
}

// label names the value as a reader acts on it: a secret by whose it is.
func (e exposed) label() string {
	switch {
	case !e.kind.Secret:
		return e.value
	case e.account != "":
		return e.form + " of " + e.account
	default:
		return e.form + " " + e.shown()
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
// is collected or used by where it is seen first.
func (p pipeline) collectExposed(steps []trace.Step, texts map[string]string, plain bool) []exposed {
	kinds := map[string]int{}
	for i, k := range p.exposures.Kinds() {
		kinds[k.Name] = i
	}
	index := map[string]int{}
	var all []exposed
	add := func(it exposure.Item, s trace.Step) {
		key := strings.Join([]string{it.Kind, it.Value, it.Account, it.Form}, "\x00")
		i, ok := index[key]
		if !ok {
			i = len(all)
			index[key] = i
			e := exposed{kind: p.exposures.Kinds()[kinds[it.Kind]], value: it.Value, account: it.Account, form: it.Form, open: it.Open, plain: plain, seen: seenCollected}
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
		for _, it := range p.exposures.Extract(texts[s.File.Path]) {
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
		}
	}
	all = mergeOwned(all)
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
	return all
}

func containsCite(cites []cite, c cite) bool {
	for _, have := range cites {
		if have == c {
			return true
		}
	}
	return false
}

// mergeOwned folds a secret seen without an account into the same secret
// seen with one: the evidence says whose it is somewhere, so it is not two.
func mergeOwned(all []exposed) []exposed {
	key := func(e exposed) string { return e.kind.Name + "\x00" + e.value + "\x00" + e.form }
	unowned := func(e exposed) bool { return e.kind.Secret && e.account == "" }
	owner := map[string]int{}
	for i, e := range all {
		if _, ok := owner[key(e)]; e.kind.Secret && e.account != "" && !ok {
			owner[key(e)] = i
		}
	}
	kept := make([]exposed, 0, len(all))
	position := map[int]int{}
	for i, e := range all {
		if _, owned := owner[key(e)]; unowned(e) && owned {
			continue
		}
		position[i] = len(kept)
		kept = append(kept, e)
	}
	for i, e := range all {
		to, owned := owner[key(e)]
		if !unowned(e) || !owned {
			continue
		}
		at := position[to]
		kept[at].count += e.count
		for _, c := range e.cites {
			if len(kept[at].cites) < maxCites && !containsCite(kept[at].cites, c) {
				kept[at].cites = append(kept[at].cites, c)
			}
		}
		// An output that held the secret before any script named its owner collected it.
		if e.seen == seenCollected && i < to {
			kept[at].seen = seenCollected
		}
	}
	return kept
}

// minRedacted is the shortest secret that is masked wherever it stands; a
// shorter one would mask ordinary words.
const minRedacted = 6

// redactor returns a function that masks every secret in a text, so a
// command quoted as evidence does not give away what the exposure masks.
func redactor(all []exposed) func(string) string {
	var pairs []string
	seen := map[string]bool{}
	for _, e := range all {
		if e.kind.Secret && !e.open && !e.plain && len(e.value) >= minRedacted && !seen[e.value] {
			seen[e.value] = true
			pairs = append(pairs, e.value, exposure.Mask(e.value))
		}
	}
	if len(pairs) == 0 {
		return func(s string) string { return s }
	}
	// The longest secret is tried first, so one that holds another is masked whole.
	order := make([]int, len(pairs)/2)
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool { return len(pairs[2*order[a]]) > len(pairs[2*order[b]]) })
	sorted := make([]string, 0, len(pairs))
	for _, i := range order {
		sorted = append(sorted, pairs[2*i], pairs[2*i+1])
	}
	return strings.NewReplacer(sorted...).Replace
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
		"value":    text(e.shown()),
		"account":  text(e.account),
		"form":     text(e.form),
		"seen":     text(e.seen),
		"severity": text(e.kind.Severity),
		"count":    render.Int(int64(e.count)),
		"files":    text(strings.Join(cites, ", ")),
	}
	return orderCells("exposure", cells, columns)
}
