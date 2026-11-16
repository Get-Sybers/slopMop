// Package cli implements the command grammar: options that take a value, a
// verb, and the words that follow the verb. It knows no verb of its own.
package cli

import (
	"fmt"
	"io"
	"slices"
	"strings"
)

// App holds the verbs of one binary.
type App struct {
	bin    string
	usage  string
	stdout io.Writer
	verbs  []*Verb
}

// Verb is one command. Its words are a closed set that may follow it; no
// word means every word.
type Verb struct {
	Name, Summary string
	// Kind names what a word is, in the plural: "sections".
	Kind    string
	Words   []Word
	Options []Option
	Run     func(a *Args) error
}

// Word is a bare word a verb takes.
type Word struct{ Name, Summary string }

// Option is written -name value, --name value or with = in place of the space.
type Option struct {
	Name, Hint, Summary string
	Required            bool
}

// Args is what a command line gave a verb.
type Args struct {
	// Words are the words given, or every word, in the order the verb declares them.
	Words []string
	// Options holds an option only when it was given.
	Options map[string]string
}

// New returns an App that names itself bin in help, shows usage after the
// name on the first line of help, and writes help to stdout.
func New(bin, usage string, stdout io.Writer) *App {
	return &App{bin: bin, usage: usage, stdout: stdout}
}

// Register adds a verb, or adds nothing and returns an error when the verb
// breaks a rule. That is a programming mistake, so it does not match ErrUsage.
func (a *App) Register(v *Verb) error {
	switch {
	case v.Name == "" || v.Summary == "" || v.Run == nil:
		return fmt.Errorf("register verb %q: it needs a name, a summary and a Run function", v.Name)
	case isHelp(v.Name) || strings.HasPrefix(v.Name, "-"):
		return fmt.Errorf("register verb %q: the name is reserved", v.Name)
	case a.verb(v.Name) != nil:
		return fmt.Errorf("register verb %q: the name is already taken", v.Name)
	case len(v.Words) > 0 && v.Kind == "":
		return fmt.Errorf("register verb %q: its words need a kind", v.Name)
	}
	seen := map[string]bool{}
	for _, w := range v.Words {
		if w.Name == "" || w.Summary == "" || seen[w.Name] || isHelp(w.Name) || strings.HasPrefix(w.Name, "-") {
			return fmt.Errorf("register verb %q: the word %q is repeated, reserved or lacks a name or a summary", v.Name, w.Name)
		}
		seen[w.Name] = true
	}
	seen = map[string]bool{}
	for _, o := range v.Options {
		if o.Name == "" || o.Hint == "" || o.Summary == "" || seen[o.Name] || isHelp(o.Name) || o.Name == "h" {
			return fmt.Errorf("register verb %q: the option %q is repeated, reserved or lacks a name, a hint or a summary", v.Name, o.Name)
		}
		seen[o.Name] = true
	}
	a.verbs = append(a.verbs, v)
	return nil
}

func (a *App) verb(name string) *Verb {
	for _, v := range a.verbs {
		if v.Name == name {
			return v
		}
	}
	return nil
}

func (a *App) verbList() string {
	names := make([]string, len(a.verbs))
	for i, v := range a.verbs {
		names[i] = v.Name
	}
	return strings.Join(names, ", ")
}

func isHelp(word string) bool {
	return word == "help"
}

// given is one option as it was typed.
type given struct {
	name, value string
	// form is the option with the dashes it was typed with, for messages.
	form     string
	hasValue bool
}

// line is a command line split into its options and its positionals.
type line struct {
	options     []given
	positionals []string
	help        bool
}

// lex splits args. Every option takes a value: the text after = or the next
// argument. "--" ends the options, and -h, --help and the word "help" ask for help.
func lex(args []string) line {
	var l line
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--":
			l.positionals = append(l.positionals, args[i+1:]...)
			return l
		case arg == "-h" || arg == "-help" || arg == "--help":
			l.help = true
		case len(arg) > 1 && arg[0] == '-':
			name, value, attached := strings.Cut(strings.TrimPrefix(strings.TrimPrefix(arg, "-"), "-"), "=")
			g := given{name: name, value: value, hasValue: attached, form: strings.TrimSuffix(arg, "="+value)}
			if !attached && i+1 < len(args) {
				i++
				g.value, g.hasValue = args[i], true
			}
			l.options = append(l.options, g)
		case isHelp(arg):
			l.help = true
		default:
			l.positionals = append(l.positionals, arg)
		}
	}
	return l
}

// Run dispatches args, the command line after the binary name. Requested help is not an
// error; a failure of the grammar matches ErrUsage; a verb's own error is returned as it is.
func (a *App) Run(args []string) error {
	l := lex(args)
	if len(l.positionals) == 0 {
		if l.help || len(args) == 0 {
			return a.writeHelp(a.rootHelp())
		}
		return Usagef("%s needs a verb%s", a.bin, valid("verbs", a.verbList()))
	}
	v := a.verb(l.positionals[0])
	if v == nil {
		return Usagef("unknown verb %q%s", l.positionals[0], valid("verbs", a.verbList()))
	}
	if l.help {
		return a.writeHelp(a.verbHelp(v))
	}
	parsed, err := v.parse(l)
	if err != nil {
		return err
	}
	return v.Run(parsed)
}

func (v *Verb) parse(l line) (*Args, error) {
	args := &Args{Options: map[string]string{}}
	for _, g := range l.options {
		o, ok := v.option(g.name)
		switch {
		case !ok:
			return nil, Usagef("unknown option %s%s", g.form, valid("options", v.optionList()))
		case !g.hasValue || g.value == "":
			return nil, Usagef("%s needs a value %s", g.form, o.Hint)
		}
		if _, twice := args.Options[o.Name]; twice {
			return nil, Usagef("-%s given more than once", o.Name)
		}
		args.Options[o.Name] = g.value
	}
	for _, o := range v.Options {
		if _, ok := args.Options[o.Name]; o.Required && !ok {
			return nil, Usagef("%s needs -%s %s", v.Name, o.Name, o.Hint)
		}
	}
	var chosen []string
	for _, word := range l.positionals[1:] {
		if !slices.ContainsFunc(v.Words, func(w Word) bool { return w.Name == word }) {
			if len(v.Words) == 0 {
				return nil, Usagef("%s takes no word, got %q", v.Name, word)
			}
			return nil, Usagef("%s has no %s %q%s", v.Name, singular(v.Kind), word, valid(v.Kind, v.wordList()))
		}
		chosen = append(chosen, word)
	}
	for _, w := range v.Words {
		if len(chosen) == 0 || slices.Contains(chosen, w.Name) {
			args.Words = append(args.Words, w.Name)
		}
	}
	return args, nil
}

func (v *Verb) option(name string) (Option, bool) {
	for _, o := range v.Options {
		if o.Name == name {
			return o, true
		}
	}
	return Option{}, false
}

func (v *Verb) optionList() string {
	forms := make([]string, len(v.Options))
	for i, o := range v.Options {
		forms[i] = "-" + o.Name + " " + o.Hint
	}
	return strings.Join(forms, ", ")
}

func (v *Verb) wordList() string {
	names := make([]string, len(v.Words))
	for i, w := range v.Words {
		names[i] = w.Name
	}
	return strings.Join(names, ", ")
}

func singular(kind string) string {
	return strings.TrimSuffix(kind, "s")
}

// valid renders the list that closes an "unknown" message, or nothing when the list is empty.
func valid(kind, list string) string {
	if list == "" {
		return ""
	}
	return fmt.Sprintf(" (%s: %s)", kind, list)
}

func (a *App) writeHelp(text string) error {
	if _, err := io.WriteString(a.stdout, text); err != nil {
		return fmt.Errorf("write help: %w", err)
	}
	return nil
}
