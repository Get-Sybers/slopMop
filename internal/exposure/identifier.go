package exposure

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// identifierEntry says what an identifier that an output holds shows, by
// its shape: a security identifier by its authority and its relative
// identifier, or a name that stands beside its relative identifier.
type identifierEntry struct {
	Activity  string `json:"activity"`
	Technique string `json:"technique"`
	// Needs are lower-case texts one of which a line must hold to be tried.
	Needs []string `json:"needs"`
	// Line is an expression with a group named found, which holds the identifier.
	Line string `json:"line"`
	// Plain marks a shape that says the least of an identifier: it counts
	// where no other shape says more of the identifier or of its line.
	Plain bool `json:"plain,omitempty"`
	// Group marks a shape whose identifier is of a group: a name that
	// stands on its line is the name of the group, and no account.
	Group bool `json:"group,omitempty"`
}

type finder struct {
	Shown
	needs        []string
	rx           *regexp.Regexp
	found        int
	plain, group bool
}

// Found is an identifier a line holds, and what its shape shows.
type Found struct {
	Shown
	Value        string
	Plain, Group bool
}

// finders compiles the entries, in the order of the data file: the first
// shape that finds an identifier on a line is its own. An activity that
// accounts show as well is of the same technique.
func finders(entries []identifierEntry, accounts []shape) ([]finder, error) {
	technique := map[string]string{}
	for _, s := range accounts {
		technique[s.Activity] = s.Technique
	}
	out := make([]finder, 0, len(entries))
	for i, e := range entries {
		if e.Activity == "" || e.Technique == "" {
			return nil, fmt.Errorf("identifiers[%d]: an activity and a technique are both needed", i)
		}
		if prev, ok := technique[e.Activity]; ok && prev != e.Technique {
			return nil, fmt.Errorf("identifiers[%d]: %s is %s and %s", i, e.Activity, prev, e.Technique)
		}
		technique[e.Activity] = e.Technique
		if len(e.Needs) == 0 || slices.ContainsFunc(e.Needs, func(need string) bool { return need == "" || need != strings.ToLower(need) }) {
			return nil, fmt.Errorf("identifiers[%d]: a lower-case text that a line must hold is needed", i)
		}
		rx, err := regexp.Compile(e.Line)
		if err != nil {
			return nil, fmt.Errorf("identifiers[%d]: %w", i, err)
		}
		f := finder{Shown: Shown{Activity: e.Activity, Technique: e.Technique}, needs: e.Needs, rx: rx, found: rx.SubexpIndex("found"), plain: e.Plain, group: e.Group}
		if f.found < 0 {
			return nil, fmt.Errorf("identifiers[%d]: the line has no group named found", i)
		}
		out = append(out, f)
	}
	return out, nil
}

// MayIdentify reports whether a text, in lower case, may hold an identifier:
// it holds a text that some shape needs.
func (t Table) MayIdentify(lower string) bool {
	return slices.ContainsFunc(t.identifiers, func(f finder) bool {
		return slices.ContainsFunc(f.needs, func(need string) bool { return strings.Contains(lower, need) })
	})
}

// Identified returns the identifiers a line holds, each once, in the order
// they are found: each with what the first shape that finds it there shows.
func (t Table) Identified(line string) []Found {
	lower := strings.ToLower(line)
	var out []Found
	for _, f := range t.identifiers {
		if !slices.ContainsFunc(f.needs, func(need string) bool { return strings.Contains(lower, need) }) {
			continue
		}
		for _, m := range f.rx.FindAllStringSubmatch(line, -1) {
			value := m[f.found]
			if value == "" || slices.ContainsFunc(out, func(have Found) bool { return strings.EqualFold(have.Value, value) }) {
				continue
			}
			out = append(out, Found{Shown: f.Shown, Value: value, Plain: f.plain, Group: f.group})
		}
	}
	return out
}

// ungrouped leaves out the usernames of a line that an identifier says is of
// a group: the name that stands there is the name of the group.
func (t Table) ungrouped(items []Item, lines []string) []Item {
	if len(t.identifiers) == 0 {
		return items
	}
	of := map[int]bool{}
	kept := items[:0]
	for _, it := range items {
		if it.Kind == usernameKind && it.Line > 0 && it.Line <= len(lines) {
			group, known := of[it.Line]
			if !known {
				group = slices.ContainsFunc(t.Identified(lines[it.Line-1]), func(f Found) bool { return f.Group })
				of[it.Line] = group
			}
			if group {
				continue
			}
		}
		kept = append(kept, it)
	}
	return kept
}
