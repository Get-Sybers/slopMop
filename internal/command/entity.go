package command

import (
	"fmt"
	"slices"
	"strings"

	"github.com/get-sybers/slopmop/internal/activity"
	"github.com/get-sybers/slopmop/internal/evidence"
	"github.com/get-sybers/slopmop/internal/exposure"
	"github.com/get-sybers/slopmop/internal/indicator"
	"github.com/get-sybers/slopmop/internal/render"
	"github.com/get-sybers/slopmop/internal/trace"
	"github.com/get-sybers/slopmop/internal/vars"
)

const (
	// findingClass is the class whose rows hold entities.
	findingClass = "finding"
	// mostRead is how much of one command is read for what it names.
	mostRead = 8 << 10
	ellipsis = "..."
)

// entities says which column of a finding holds each thing its lines name.
type entities struct {
	// columns are the columns the table fills, in its order.
	columns []string
	// byLabel, byKind and byType give the column of what a line acts on, of
	// a value of a kind of exposure and of an indicator.
	byLabel, byKind, byType map[string]string
	// apart are the types whose indicators the exposure does not read: on a
	// line, such an indicator is filed by its type.
	apart map[string]bool
}

// loadEntities reads the entities of the finding class and checks that each
// fills a column of its own from labels, kinds and types the other tables
// declare, and that no two read the same.
func loadEntities(doc commandsDoc, p pipeline) (entities, error) {
	t := entities{byLabel: map[string]string{}, byKind: map[string]string{}, byType: map[string]string{}, apart: map[string]bool{}}
	for _, c := range doc.Classes {
		if c.Name != findingClass && len(c.Entities) > 0 {
			return entities{}, fmt.Errorf("commands.json: the class %s names entities, which only the class %s holds", c.Name, findingClass)
		}
	}
	columns := doc.columns(findingClass)
	kinds := make([]string, len(p.exposures.Kinds()))
	for i, k := range p.exposures.Kinds() {
		kinds[i] = k.Name
	}
	labels := p.activities.Labels()
	for _, e := range doc.entities(findingClass) {
		switch {
		case !slices.ContainsFunc(columns, func(c render.Column) bool { return c.Key == e.Column }):
			return entities{}, fmt.Errorf("commands.json: the entity %q is no column of the class %s", e.Column, findingClass)
		case slices.Contains(t.columns, e.Column):
			return entities{}, fmt.Errorf("commands.json: the entity %q is named twice", e.Column)
		case len(e.Labels)+len(e.Kinds)+len(e.Indicators) == 0:
			return entities{}, fmt.Errorf("commands.json: the entity %q reads nothing", e.Column)
		}
		t.columns = append(t.columns, e.Column)
		sources := []struct {
			what   string
			names  []string
			known  func(string) bool
			column map[string]string
		}{
			{"label", e.Labels, func(name string) bool { return slices.Contains(labels, name) }, t.byLabel},
			{"kind of exposure", e.Kinds, func(name string) bool { return slices.Contains(kinds, name) }, t.byKind},
			{"indicator type", e.Indicators, p.patterns.Has, t.byType},
		}
		for _, s := range sources {
			for _, name := range s.names {
				if !s.known(name) {
					return entities{}, fmt.Errorf("commands.json: the entity %q reads the %s %q, which its table lacks", e.Column, s.what, name)
				}
				if _, read := s.column[name]; read {
					return entities{}, fmt.Errorf("commands.json: the entity %q reads the %s %q, which another reads", e.Column, s.what, name)
				}
				s.column[name] = e.Column
			}
		}
	}
	for name := range t.byType {
		t.apart[name] = !slices.Contains(p.exposures.IndicatorTypes(), name)
	}
	return t, nil
}

// mention is one thing a line of evidence names: what it acts on, by its
// label, a value of a kind of exposure, or an indicator of a type the
// exposure does not read.
type mention struct {
	label, kind, typ, value string
}

// file lists what a line of evidence names in the columns of the finding
// that hold it.
func (t entities) file(f *finding, named []mention) {
	for _, m := range named {
		switch {
		case m.label != "":
			f.name(t.byLabel[m.label], m.value)
		case m.typ != "":
			f.name(t.byType[m.typ], m.value)
		default:
			f.name(t.byKind[m.kind], m.value)
		}
	}
}

// name lists a value under a column of the finding, once in any case: a
// host and an account are the same in any case. No column lists nothing.
func (f *finding) name(column, value string) {
	if column == "" || value == "" {
		return
	}
	if slices.ContainsFunc(f.named[column], func(have string) bool { return strings.EqualFold(have, value) }) {
		return
	}
	if f.named == nil {
		f.named = map[string][]string{}
	}
	f.named[column] = append(f.named[column], value)
}

// mentions lists what a text names: the values the exposure found in it,
// what its indicators are of, and the indicators the exposure does not read.
func (p pipeline) mentions(text string, items []exposure.Item, script bool) []mention {
	var out []mention
	logins := map[cite]bool{}
	for _, it := range items {
		out = append(out, mention{kind: it.Kind, value: it.Value})
		if it.Kind == deviceKind {
			logins[cite{strings.ToLower(it.Value), 1}] = true
		}
	}
	// The text is read as one line, so every indicator in it is at a known place.
	matches := p.patterns.Extract(text)
	for i := range matches {
		matches[i].Line = 1
	}
	p.indicated(text, matches, logins, func(it exposure.Item, exposed bool) {
		// A domain is a host where a script names it, and the host of a vendor is none.
		if exposed || (script && !p.exposures.Vendor(it.Value)) {
			out = append(out, mention{kind: it.Kind, value: it.Value})
		}
	})
	for _, m := range matches {
		if p.entities.apart[m.Type] {
			out = append(out, mention{typ: m.Type, value: m.Value})
		}
	}
	return out
}

// indicated calls visit with what each indicator of a text is of: a value
// of a kind of exposure, or a host the text names outright, which is none.
// logins are the hosts a line signs in to, by the line.
func (p pipeline) indicated(text string, matches []indicator.Match, logins map[cite]bool, visit func(it exposure.Item, exposed bool)) {
	for _, m := range matches {
		// "$USER@corp.example" reads as an address and is a variable and a domain.
		if m.Line > 0 && m.Start > 0 && m.Start <= len(text) && text[m.Start-1] == '$' {
			continue
		}
		if _, host, found := strings.Cut(m.Value, "@"); found && logins[cite{strings.ToLower(host), m.Line}] {
			continue
		}
		if it, ok := p.exposures.FromIndicator(m.Type, m.Value, m.Line); ok {
			visit(it, true)
			// Whose a token is said to be is an account the evidence holds.
			if owner, owned := p.exposures.Owner(it); owned {
				visit(owner, true)
			}
		}
		// A domain is a host only where a script names it; it is no exposure.
		if inPath(text, m.Start, m.Line) {
			continue
		}
		if it, ok := p.exposures.FromHardcoded(m.Type, m.Value, m.Line); ok {
			visit(it, false)
		}
	}
}

// reader reads what the lines of evidence name out of the files that hold them.
type reader struct {
	p     pipeline
	texts map[string]string
	// held is what the exposure found in each file. lines and set are the
	// lines and the variables of each file a line of evidence was read from.
	held  map[string][]exposure.Item
	lines map[string][]string
	set   map[string]vars.Set
}

func (p pipeline) newReader(texts map[string]string, held map[string][]exposure.Item) *reader {
	return &reader{p: p, texts: texts, held: held, lines: map[string][]string{}, set: map[string]vars.Set{}}
}

// evidenceAt identifies a line of evidence: its file, its activity and
// which of the lines of that activity in the file it is.
type evidenceAt struct {
	file, activity string
	n              int
}

// kept calls visit with each line of evidence a finding keeps: of every
// activity the first maxCited, in the order of the timeline.
func kept(steps []trace.Step, visit func(s trace.Step, hit activity.Hit, n int)) {
	held := map[string]int{}
	for _, s := range steps {
		for _, hit := range s.Activities {
			for n := range hit.Evidence {
				if held[hit.Name] < maxCited {
					held[hit.Name]++
					visit(s, hit, n)
				}
			}
		}
	}
}

// read lists what each line of evidence a finding keeps names.
func (r *reader) read(steps []trace.Step) map[evidenceAt][]mention {
	out := map[evidenceAt][]mention{}
	if len(r.p.entities.columns) == 0 {
		return out
	}
	kept(steps, func(s trace.Step, hit activity.Hit, n int) {
		if named := r.mentions(s, hit.Evidence[n]); len(named) > 0 {
			out[evidenceAt{s.File.Path, hit.Name, n}] = named
		}
	})
	return out
}

// mentions lists what a line of evidence names: its subjects, what each of
// them holds, as the host of a URL, and what its command holds. A variable
// the file sets is given its value.
func (r *reader) mentions(s trace.Step, e activity.Evidence) []mention {
	path, script := s.File.Path, s.File.Role == evidence.Script
	if _, read := r.set[path]; !read {
		r.set[path] = vars.Read(r.texts[path])
	}
	var out []mention
	for _, sub := range e.Subjects {
		value := r.set[path].Expand(sub.Plain())
		out = append(out, mention{label: sub.Label, value: value})
		out = append(out, r.p.mentions(value, nil, script)...)
	}
	if e.Line == 0 {
		// A record of a structured output has no line: what is quoted of it is read.
		text := whole(e.Text)
		return append(out, r.p.mentions(text, r.p.exposures.Extract(text), script)...)
	}
	if _, split := r.lines[path]; !split {
		r.lines[path] = strings.Split(r.texts[path], "\n")
	}
	last := max(e.Line, e.Last)
	if last > len(r.lines[path]) {
		return out
	}
	var items []exposure.Item
	for _, it := range r.held[path] {
		if it.Line >= e.Line && it.Line <= last {
			items = append(items, it)
		}
	}
	text := whole(r.set[path].Expand(strings.Join(r.lines[path][e.Line-1:last], "\n")))
	return append(out, r.p.mentions(text, items, script)...)
}

// whole returns as much of a command as is read for what it names, without
// the word a cut ended in: a cut address is another address.
func whole(text string) string {
	cut := strings.HasSuffix(text, ellipsis)
	if len(text) > mostRead {
		text, cut = text[:mostRead], true
	}
	if !cut {
		return text
	}
	return text[:strings.LastIndexAny(text, " \t\n")+1]
}
