package cli

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

const optionsNote = " (one dash or two; each takes a value)"

type entry struct{ label, text string }

// block is a titled list of entries in help.
type block struct {
	title   string
	entries []entry
}

// point is how far a command line has come. Help is written for the point,
// so each word typed changes what help says comes next.
type point struct {
	typed []string
	verb  *Verb
	// given are the options with a value, once each, in the order typed.
	given []given
	// pending is an option typed without its value, and waiting says there is one.
	pending  Option
	waiting  bool
	words    []string
	problems []string
}

// resolve reads a line as far as it goes. What does not fit is a problem
// to report, not an error: help is asked for by someone who is unsure.
func (a *App) resolve(l line) point {
	p := point{typed: l.typed}
	if len(l.positionals) > 0 {
		if p.verb = a.verb(l.positionals[0]); p.verb == nil {
			p.problems = append(p.problems, a.unknownVerb(l.positionals[0]))
		}
	}
	for _, g := range l.options {
		o, ok := a.option(p.verb, g.name)
		switch {
		case !ok && p.verb != nil:
			p.problems = append(p.problems, p.verb.unknownOption(g))
		case !ok:
			p.problems = append(p.problems, "unknown option "+g.form)
		case !g.hasValue || g.value == "":
			p.pending, p.waiting = o, true
		case slices.ContainsFunc(p.given, func(had given) bool { return had.name == g.name }):
			p.problems = append(p.problems, "-"+g.name+" given more than once")
		default:
			p.given = append(p.given, g)
		}
	}
	if p.verb != nil {
		for _, word := range l.positionals[1:] {
			switch {
			case !p.verb.hasWord(word):
				p.problems = append(p.problems, p.verb.unknownWord(word))
			case !slices.Contains(p.words, word):
				p.words = append(p.words, word)
			}
		}
	}
	return p
}

// option finds an option of the verb, or of any verb while none is named.
func (a *App) option(v *Verb, name string) (Option, bool) {
	if v != nil {
		return v.option(name)
	}
	for _, each := range a.verbs {
		if o, ok := each.option(name); ok {
			return o, true
		}
	}
	return Option{}, false
}

// options lists the options of the verb, or of every verb while none is named.
func (a *App) options(v *Verb) []Option {
	if v != nil {
		return v.Options
	}
	var all []Option
	for _, each := range a.verbs {
		for _, o := range each.Options {
			if !slices.ContainsFunc(all, func(had Option) bool { return had.Name == o.Name }) {
				all = append(all, o)
			}
		}
	}
	return all
}

func (p point) has(name string) bool {
	return slices.ContainsFunc(p.given, func(g given) bool { return g.name == name })
}

// missing lists the required options of the verb that were not given.
func (p point) missing() []Option {
	var out []Option
	if p.verb != nil {
		for _, o := range p.verb.Options {
			if o.Required && !p.has(o.Name) {
				out = append(out, o)
			}
		}
	}
	return out
}

// help writes what a command line holds so far and what can follow it.
func (a *App) help(l line) string {
	p := a.resolve(l)
	var b strings.Builder
	if p.verb == nil {
		fmt.Fprintf(&b, "usage: %s %s\n", a.bin, a.usage)
	} else {
		b.WriteString(a.verbUsage(p.verb))
	}
	if len(a.verbs) == 0 {
		return b.String()
	}
	if len(p.typed) > 0 {
		b.WriteString("so far: " + a.shown(p.typed) + "\n")
	}
	blocks := a.blocks(p)
	width := 0
	for _, bl := range blocks {
		width = max(width, widest(bl.entries)+2)
	}
	for _, bl := range blocks {
		b.WriteString("\n" + bl.title + ":\n")
		writeEntries(&b, bl.entries, width)
	}
	if steps := a.steps(p); len(steps) > 0 {
		b.WriteString("\n")
		for _, step := range steps {
			b.WriteString(step.label + step.text + "\n")
		}
	}
	return b.String()
}

func (a *App) verbUsage(v *Verb) string {
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
	return b.String() + "\n" + v.Summary + "\n"
}

// blocks lists, in order: what is wrong, what was given, what is still
// needed and what can be added.
func (a *App) blocks(p point) []block {
	var out []block
	add := func(title string, entries []entry) {
		if len(entries) > 0 {
			out = append(out, block{title, entries})
		}
	}
	problems := make([]entry, len(p.problems))
	for i, text := range p.problems {
		problems[i] = entry{label: text}
	}
	add("problems", problems)
	var had []entry
	for _, g := range p.given {
		o, _ := a.option(p.verb, g.name)
		had = append(had, entry{"-" + g.name + " " + quoted(g.value), o.Summary})
	}
	add("given", had)
	if p.waiting {
		add("-"+p.pending.Name+" needs a value", []entry{optionEntry(p.pending)})
		return out
	}
	var needed, optional []entry
	for _, o := range a.options(p.verb) {
		switch {
		case p.has(o.Name):
		case o.Required && p.verb != nil:
			needed = append(needed, optionEntry(o))
		default:
			optional = append(optional, optionEntry(o))
		}
	}
	add("still needed", needed)
	if p.verb == nil {
		verbs := make([]entry, len(a.verbs))
		for i, v := range a.verbs {
			verbs[i] = entry{v.Name, v.Summary}
		}
		title := "verbs"
		if len(p.typed) > 0 {
			title = "add a verb"
		}
		add(title, verbs)
	} else {
		var chosen, free []entry
		for _, w := range p.verb.Words {
			if slices.Contains(p.words, w.Name) {
				chosen = append(chosen, entry{w.Name, w.Summary})
			} else {
				free = append(free, entry{w.Name, w.Summary})
			}
		}
		if len(chosen) == 0 {
			add(p.verb.Kind+" (name any to print only those; none = all)", free)
		} else {
			add(p.verb.Kind+" chosen", chosen)
			add(p.verb.Kind+" you can add", free)
		}
	}
	title := "options" + optionsNote
	if len(p.typed) > 0 {
		title = "options you can add" + optionsNote
	}
	add(title, optional)
	return out
}

// steps gives the command lines to type next: one that asks for the help of
// the next point, and the command itself once nothing is missing.
func (a *App) steps(p point) []entry {
	var out []entry
	next := func(command string) {
		out = append(out, entry{"next: ", command + " --help"})
	}
	switch {
	case p.waiting:
		next(a.command(p, []string{"-" + p.pending.Name, p.pending.Hint}, ""))
	case p.verb == nil && len(p.given) == 0:
		// The first verb shows the way: its required options come before any verb.
		var first []string
		for _, o := range a.verbs[0].Options {
			if o.Required {
				first = append(first, "-"+o.Name, o.Hint)
			}
		}
		if len(first) == 0 {
			first = []string{a.verbs[0].Name}
		}
		next(a.bin + " " + strings.Join(first, " "))
	case p.verb == nil:
		for _, v := range a.verbs {
			next(a.command(p, nil, v.Name))
		}
	default:
		complete := len(p.missing()) == 0 && len(p.problems) == 0
		for _, w := range p.verb.Words {
			if complete && !slices.Contains(p.words, w.Name) {
				next(a.command(p, nil, w.Name))
				break
			}
		}
		if !complete {
			next(a.command(p, nil, ""))
		} else {
			out = append(out, entry{"run:  ", a.command(p, nil, "")})
		}
	}
	return out
}

// command writes the line so far in the order of the usage line: required
// options, the verb, the words, then the other options. A required option
// that is missing stands as its hint; extra and word are appended to their parts.
func (a *App) command(p point, extra []string, word string) string {
	parts := []string{a.bin}
	var after []string
	for _, g := range p.given {
		o, _ := a.option(p.verb, g.name)
		if o.Required || p.verb == nil {
			parts = append(parts, "-"+g.name, quoted(g.value))
		} else {
			after = append(after, "-"+g.name, quoted(g.value))
		}
	}
	for _, o := range p.missing() {
		parts = append(parts, "-"+o.Name, o.Hint)
	}
	if p.verb == nil {
		parts = append(parts, extra...)
		if word != "" {
			parts = append(parts, word)
		}
		return strings.Join(parts, " ")
	}
	parts = append(parts, p.verb.Name)
	parts = append(parts, p.words...)
	if word != "" {
		parts = append(parts, word)
	}
	parts = append(parts, after...)
	return strings.Join(append(parts, extra...), " ")
}

// shown writes what was typed after the name of the binary.
func (a *App) shown(typed []string) string {
	parts := []string{a.bin}
	for _, t := range typed {
		parts = append(parts, quoted(t))
	}
	return strings.Join(parts, " ")
}

// quoted returns a value as it can be typed and read: unchanged when it is
// plain, and quoted when it holds a space or anything that is not printable.
func quoted(value string) string {
	for _, r := range value {
		if r == ' ' || r == '"' || !strconv.IsPrint(r) {
			return strconv.Quote(value)
		}
	}
	if value == "" || !utf8.ValidString(value) {
		return strconv.Quote(value)
	}
	return value
}

func optionEntry(o Option) entry {
	return entry{"-" + o.Name + " " + o.Hint, o.Summary}
}

func widest(entries []entry) int {
	width := 0
	for _, e := range entries {
		if e.text != "" {
			width = max(width, utf8.RuneCountInString(e.label))
		}
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
