package cli

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	grammar = "[selectors] [--params] [output flags] [positional]"

	// flagColumn is the narrowest label column of a selector or param: "-" and ten characters, then a space.
	flagColumn = 12

	outputHelp = `
output flags:
  -o wide|json    every column, or JSON
  -q              column 1 only, one per line
  --no-headers    no header row
  --tz local|utc  zone of displayed times (default utc)
`
)

type entry struct{ label, text string }

func (a *App) rootHelp() string {
	var b strings.Builder
	fmt.Fprintf(&b, "usage: %s NOUN VERB %s\n", a.bin, grammar)
	if len(a.nouns) == 0 {
		return b.String()
	}
	entries := make([]entry, 0, len(a.nouns))
	for _, n := range a.nouns {
		entries = append(entries, entry{strings.Join(n.names(), ", "), n.Summary})
	}
	b.WriteString("\nnouns:\n")
	writeEntries(&b, entries, widest(entries)+2)
	fmt.Fprintf(&b, "\nmore help: %s NOUN -h, %s NOUN VERB -h\n", a.bin, a.bin)
	return b.String()
}

func (a *App) nounHelp(n *Noun) string {
	var b strings.Builder
	fmt.Fprintf(&b, "usage: %s %s VERB %s\n", a.bin, n.Name, grammar)
	if n.Summary != "" {
		b.WriteString(n.Summary + "\n")
	}
	if len(n.Verbs) == 0 {
		return b.String()
	}
	entries := make([]entry, 0, len(n.Verbs))
	for _, v := range n.Verbs {
		entries = append(entries, entry{strings.Join(v.names(), ", "), v.Summary})
	}
	b.WriteString("\nverbs:\n")
	writeEntries(&b, entries, widest(entries)+2)
	fmt.Fprintf(&b, "\nmore help: %s %s VERB -h\n", a.bin, n.Name)
	return b.String()
}

func (a *App) verbHelp(n *Noun, v *Verb) string {
	s := v.Spec
	var b strings.Builder
	fmt.Fprintf(&b, "usage: %s %s %s", a.bin, n.Name, v.Name)
	if len(s.Selectors) > 0 {
		b.WriteString(" [selectors]")
	}
	if len(s.Params) > 0 {
		b.WriteString(" [--params]")
	}
	if s.Rows {
		b.WriteString(" [output flags]")
	}
	if s.Positional != "" {
		b.WriteString(" " + s.Positional)
	}
	b.WriteString("\n")
	if v.Summary != "" {
		b.WriteString(v.Summary + "\n")
	}
	selectors, params := flagEntries("-", s.Selectors), flagEntries("--", s.Params)
	width := max(flagColumn, widest(selectors)+1, widest(params)+1)
	if len(selectors) > 0 {
		b.WriteString("\nselectors (single dash, pick any; none = all):\n")
		writeEntries(&b, selectors, width)
	}
	if len(params) > 0 {
		b.WriteString("\nparams (double dash, take a value):\n")
		writeEntries(&b, params, width)
	}
	if s.Rows {
		b.WriteString(outputHelp)
	}
	return b.String()
}

func flagEntries(prefix string, flags map[string]string) []entry {
	entries := make([]entry, 0, len(flags))
	for _, name := range sortedKeys(flags) {
		entries = append(entries, entry{prefix + name, flags[name]})
	}
	return entries
}

func widest(entries []entry) int {
	width := 0
	for _, e := range entries {
		width = max(width, utf8.RuneCountInString(e.label))
	}
	return width
}

// writeEntries pads each label to width; a line with no text carries no trailing space.
func writeEntries(b *strings.Builder, entries []entry, width int) {
	for _, e := range entries {
		line := fmt.Sprintf("  %-*s%s", width, e.label, e.text)
		b.WriteString(strings.TrimRight(line, " ") + "\n")
	}
}
