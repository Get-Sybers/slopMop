package command

import (
	"net/netip"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/get-sybers/slopmop/internal/exposure"
	"github.com/get-sybers/slopmop/internal/render"
	"github.com/get-sybers/slopmop/internal/tactic"
)

const (
	// originPrior marks a value no earlier output holds: the scripts were written knowing it.
	originPrior = "prior"
	// originDiscovered marks a value an earlier output holds: the run learnt it first.
	originDiscovered = "discovered"
	scopePrivate     = "private"
	scopePublic      = "public"
	// maxQuoted bounds one quoted script line.
	maxQuoted = 200
)

// targeted is one username, address, hostname or email address that a
// script names outright.
type targeted struct {
	kind   exposure.Kind
	value  string
	origin string
	// from is where an earlier output holds the value; the zero cite for a prior one.
	from cite
	// scope is private or public for an address and empty for any other kind.
	scope string
	cites []cite
	// count is the number of script lines that name the value.
	count int
	// lines quotes the script lines, each with its place.
	lines []string
}

// level ranks a target: what the attacker knew beforehand is the more telling.
func (t targeted) level() tactic.Severity {
	if t.origin == originPrior {
		return tactic.Medium
	}
	return tactic.Low
}

func (t targeted) places() []string {
	places := make([]string, len(t.cites))
	for i, c := range t.cites {
		places[i] = c.String()
	}
	return places
}

// targets gathers what the scripts name outright while the files are read
// in the order of the timeline.
type targets struct {
	order map[string]int
	index map[string]int
	// held maps a value to the first output that holds it.
	held map[string]cite
	all  []targeted
}

func newTargets(kinds []exposure.Kind) *targets {
	t := &targets{order: map[string]int{}, index: map[string]int{}, held: map[string]cite{}}
	for i, k := range kinds {
		t.order[k.Name] = i
	}
	return t
}

// key compares without case: a host and an account are the same in any case.
func targetKey(it exposure.Item) string {
	return it.Kind + "\x00" + strings.ToLower(it.Value)
}

// output notes that an output holds a value, so a later script that names
// it learnt it from the run.
func (t *targets) output(it exposure.Item, path string) {
	if _, ok := t.held[targetKey(it)]; !ok {
		t.held[targetKey(it)] = cite{path, it.Line}
	}
}

// script notes that a script names a value of a kind that is listed.
func (t *targets) script(it exposure.Item, kind exposure.Kind, path string) {
	if kind.Targeted == "" {
		return
	}
	key := targetKey(it)
	i, ok := t.index[key]
	if !ok {
		i = len(t.all)
		t.index[key] = i
		entry := targeted{kind: kind, value: it.Value, origin: originPrior, scope: scopeOf(kind, it.Value)}
		if from, held := t.held[key]; held {
			entry.origin, entry.from = originDiscovered, from
		}
		t.all = append(t.all, entry)
	}
	t.all[i].count++
	if c := (cite{path, it.Line}); len(t.all[i].cites) < maxCites && !containsCite(t.all[i].cites, c) {
		t.all[i].cites = append(t.all[i].cites, c)
	}
}

// finish quotes the script lines as they stand, and sorts: the
// kinds in their order, prior before discovered, then by value.
func (t *targets) finish(texts map[string]string) []targeted {
	lines := map[string][]string{}
	for i := range t.all {
		for _, c := range t.all[i].cites {
			if c.line == 0 {
				continue
			}
			if _, split := lines[c.file]; !split {
				lines[c.file] = strings.Split(texts[c.file], "\n")
			}
			if c.line <= len(lines[c.file]) {
				quoted := shorten(strings.Join(strings.Fields(lines[c.file][c.line-1]), " "))
				t.all[i].lines = append(t.all[i].lines, quoted+" ("+c.String()+")")
			}
		}
	}
	sort.SliceStable(t.all, func(i, j int) bool {
		x, y := t.all[i], t.all[j]
		if x.kind.Name != y.kind.Name {
			return t.order[x.kind.Name] < t.order[y.kind.Name]
		}
		if x.origin != y.origin {
			return x.origin == originPrior
		}
		return x.value < y.value
	})
	return t.all
}

// shorten cuts a line to maxQuoted bytes, ending in "..." and never inside a rune.
func shorten(line string) string {
	const ellipsis = "..."
	if len(line) <= maxQuoted {
		return line
	}
	end := maxQuoted - len(ellipsis)
	for end > 0 && !utf8.RuneStart(line[end]) {
		end--
	}
	return line[:end] + ellipsis
}

// scopeOf says whether an address is inside a private network; a range is
// judged by its first address.
func scopeOf(kind exposure.Kind, value string) string {
	if kind.Name != ipKind {
		return ""
	}
	host, _, _ := strings.Cut(value, "/")
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return ""
	}
	if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return scopePrivate
	}
	return scopePublic
}

// ipKind is the kind of exposure whose values are addresses.
const ipKind = "ip"

func targetedRow(t targeted, columns []render.Column) ([]render.Value, error) {
	text := func(s string) render.Value {
		if s == "" {
			return render.NotApplicable()
		}
		return render.Text(s)
	}
	from := ""
	if t.origin == originDiscovered {
		from = t.from.String()
	}
	cells := map[string]render.Value{
		"kind":     text(t.kind.Name),
		"value":    text(t.value),
		"origin":   text(t.origin),
		"from":     text(from),
		"scope":    text(t.scope),
		"count":    render.Int(int64(t.count)),
		"scripts":  text(strings.Join(t.places(), ", ")),
		"evidence": text(strings.Join(t.lines, "\n")),
	}
	return orderCells("targeted", cells, columns)
}
