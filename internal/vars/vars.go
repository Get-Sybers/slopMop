// Package vars reads the variables a script sets to a plain value, so a
// command that names a variable can be shown with what the variable holds.
// Nothing is evaluated: a value that is computed is left out.
package vars

import (
	"regexp"
	"strings"
)

var (
	// rxAssign is NAME=value in a shell or a batch file and $NAME = value in PowerShell.
	rxAssign = regexp.MustCompile(`(?m)^[ \t]*(?:export[ \t]+|set[ \t]+|\$)?([A-Za-z_]\w*)[ \t]*=[ \t]*["']?([^"'\r\n]*?)["']?[ \t]*;?[ \t]*\r?$`)
	// rxReference is a value that is one variable and nothing else.
	rxReference = regexp.MustCompile(`^(?:\$\{?([A-Za-z_]\w*)\}?|%([A-Za-z_]\w*)%)$`)
	// rxDefault is ${NAME:-value}: the value stands when NAME is not set.
	rxDefault = regexp.MustCompile(`^\$\{[A-Za-z_]\w*:-([^}$]*)\}$`)
)

// Set maps a variable name, in lower case, to the value a text sets it to.
type Set map[string]string

// Read returns the variables of a text; the last assignment of a name wins,
// as it would when the script ran.
func Read(text string) Set {
	set := Set{}
	// An assignment is one line with nothing but its name before the first
	// equals sign, so only such lines are read, each alone.
	for at := 0; at < len(text); {
		i := strings.IndexByte(text[at:], '=')
		if i < 0 {
			break
		}
		sign := at + i
		start, end := strings.LastIndexByte(text[:sign], '\n')+1, len(text)
		if j := strings.IndexByte(text[sign:], '\n'); j >= 0 {
			end = sign + j
		}
		at = end + 1
		if !named(text[start:sign]) {
			continue
		}
		m := rxAssign.FindStringSubmatch(text[start:end])
		if m == nil {
			continue
		}
		value := m[2]
		if d := rxDefault.FindStringSubmatch(value); d != nil {
			value = d[1]
		}
		if value != "" && !strings.ContainsAny(value, "$`%") {
			set[strings.ToLower(m[1])] = value
		}
	}
	return set
}

// named reports whether what stands before an equals sign can be the name
// of an assignment: letters, digits, an underscore, a dollar, spaces and tabs.
func named(before string) bool {
	for i := range len(before) {
		switch c := before[i]; {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '$', c == ' ', c == '\t':
		default:
			return false
		}
	}
	return before != ""
}

// Value returns what a reference stands for: the value of the variable when
// ref is one variable the text sets, or the default of ${NAME:-default}.
func (s Set) Value(ref string) (string, bool) {
	if m := rxReference.FindStringSubmatch(ref); m != nil {
		value, ok := s[strings.ToLower(m[1]+m[2])]
		return value, ok
	}
	if d := rxDefault.FindStringSubmatch(ref); d != nil && d[1] != "" {
		return d[1], true
	}
	return "", false
}

// Refers reports whether a text is one variable and nothing else, with or
// without a default: what Value reads a value for.
func Refers(text string) bool {
	return rxReference.MatchString(text) || rxDefault.MatchString(text)
}

// rxInside is a variable that stands inside a longer text.
var rxInside = regexp.MustCompile(`\$\{?([A-Za-z_]\w*)\}?`)

// Expand writes the value of each variable the text sets into s, and leaves
// a variable it does not know as it stands.
func (s Set) Expand(text string) string {
	if !strings.Contains(text, "$") {
		return text
	}
	return rxInside.ReplaceAllStringFunc(text, func(ref string) string {
		if value, ok := s[strings.ToLower(strings.Trim(ref, "${}"))]; ok {
			return value
		}
		return ref
	})
}
