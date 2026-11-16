package cli

import (
	"fmt"
	"maps"
	"slices"
	"strings"
)

// Spec declares what a verb accepts; parsing, validation and help all read it.
type Spec struct {
	Selectors  map[string]string // -name -> summary
	Params     map[string]string // --name -> value hint
	Switches   map[string]Switch // --name -> short form and summary
	Required   []string          // params the verb cannot run without
	Positional string            // usage text for the positionals, e.g. "[folder]"
	MinPos     int
	MaxPos     int  // -1 unlimited
	Rows       bool // the verb prints rows and takes the output flags
}

// Switch is a double-dash flag without a value: given or not.
type Switch struct {
	Short   string // one letter, typed as -x; empty for none
	Summary string
}

type Args struct {
	Selectors []string          // selected members, sorted
	Params    map[string]string // a key is present only when the param was given
	Switches  map[string]bool   // a key is present only when the switch was given
	Pos       []string
	Output    Output
}

func sortedKeys[V any](m map[string]V) []string {
	return slices.Sorted(maps.Keys(m))
}

// withHint appends a param's value hint; a param may be declared without one.
func withHint(text, hint string) string {
	if hint == "" {
		return text
	}
	return text + " " + hint
}

func (s Spec) selectorList() string {
	names := sortedKeys(s.Selectors)
	for i, name := range names {
		names[i] = "-" + name
	}
	return strings.Join(names, ", ")
}

func (s Spec) paramList() string {
	names := sortedKeys(s.Params)
	for i, name := range names {
		names[i] = withHint("--"+name, s.Params[name])
	}
	return strings.Join(names, ", ")
}

// switchName resolves a typed word to the switch it names; short reports the one-letter form.
func (s Spec) switchName(word string) (name string, short, ok bool) {
	if _, ok := s.Switches[word]; ok {
		return word, false, true
	}
	for _, name := range sortedKeys(s.Switches) {
		if s.Switches[name].Short == word {
			return name, true, true
		}
	}
	return "", false, false
}

func (s Spec) positionalRule() string {
	switch {
	case s.MaxPos == 0:
		return "no positional args"
	case s.MinPos == s.MaxPos:
		return fmt.Sprintf("%d positional arg(s)", s.MinPos)
	case s.MaxPos < 0:
		return fmt.Sprintf("at least %d positional arg(s)", s.MinPos)
	default:
		return fmt.Sprintf("%d to %d positional args", s.MinPos, s.MaxPos)
	}
}

// valid renders the list that closes an "unknown" message, or nothing when the list is empty.
func valid(kind, list string) string {
	if list == "" {
		return ""
	}
	return fmt.Sprintf(" (valid %s: %s)", kind, list)
}
