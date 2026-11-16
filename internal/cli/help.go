package cli

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

type entry struct{ label, text string }

// rootHelp lists the verbs and every option any of them takes.
func (a *App) rootHelp() string {
	var b strings.Builder
	fmt.Fprintf(&b, "usage: %s %s\n", a.bin, a.usage)
	if len(a.verbs) == 0 {
		return b.String()
	}
	verbs := make([]entry, len(a.verbs))
	var options []entry
	seen := map[string]bool{}
	for i, v := range a.verbs {
		verbs[i] = entry{v.Name, v.Summary}
		for _, o := range v.Options {
			if !seen[o.Name] {
				seen[o.Name] = true
				options = append(options, optionEntry(o))
			}
		}
	}
	width := max(widest(verbs), widest(options)) + 2
	b.WriteString("\nverbs:\n")
	writeEntries(&b, verbs, width)
	if len(options) > 0 {
		b.WriteString("\noptions (one dash or two; each takes a value):\n")
		writeEntries(&b, options, width)
	}
	fmt.Fprintf(&b, "\nmore help: %s VERB --help\n", a.bin)
	return b.String()
}

func (a *App) verbHelp(v *Verb) string {
	var b strings.Builder
	fmt.Fprintf(&b, "usage: %s", a.bin)
	for _, o := range v.Options {
		if o.Required {
			fmt.Fprintf(&b, " -%s %s", o.Name, o.Hint)
		}
	}
	b.WriteString(" " + v.Name)
	if len(v.Words) > 0 {
		fmt.Fprintf(&b, " [%s ...]", singular(v.Kind))
	}
	for _, o := range v.Options {
		if !o.Required {
			fmt.Fprintf(&b, " [-%s %s]", o.Name, o.Hint)
		}
	}
	b.WriteString("\n" + v.Summary + "\n")
	words := make([]entry, len(v.Words))
	for i, w := range v.Words {
		words[i] = entry{w.Name, w.Summary}
	}
	options := make([]entry, len(v.Options))
	for i, o := range v.Options {
		options[i] = optionEntry(o)
		if o.Required {
			options[i].text += " (required)"
		}
	}
	width := max(widest(words), widest(options)) + 2
	if len(words) > 0 {
		fmt.Fprintf(&b, "\n%s (name any to print only those; none = all):\n", v.Kind)
		writeEntries(&b, words, width)
	}
	if len(options) > 0 {
		b.WriteString("\noptions (one dash or two; each takes a value):\n")
		writeEntries(&b, options, width)
	}
	return b.String()
}

func optionEntry(o Option) entry {
	return entry{"-" + o.Name + " " + o.Hint, o.Summary}
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
