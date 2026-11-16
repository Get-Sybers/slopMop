// Package cli implements the NOUN VERB command grammar: specs, parsing, dispatch and generated help.
package cli

import (
	"fmt"
	"io"
	"strings"
)

type App struct {
	bin    string
	stdout io.Writer
	nouns  []*Noun
	index  map[string]*Noun
	// whole runs when the first argument names no noun; nil for none.
	whole *Verb
	// words are the sections of whole, in the order help lists them.
	words []Word
}

// Word is a bare word the command without a noun takes as a selector.
type Word struct{ Name, Summary string }

// New returns an App that names itself bin in help and writes help to stdout.
func New(bin string, stdout io.Writer) *App {
	return &App{bin: bin, stdout: stdout, index: map[string]*Noun{}}
}

// Run dispatches args, the command line after the binary name. Requested help is not an
// error; a failure of the grammar matches ErrUsage; a verb's own error is returned as it is.
func (a *App) Run(args []string) error {
	if len(args) == 0 || isHelp(args[0]) {
		return a.writeHelp(a.rootHelp())
	}
	noun, ok := a.index[args[0]]
	if !ok {
		return a.runWhole(args)
	}
	if len(args) == 1 || isHelp(args[1]) {
		return a.writeHelp(a.nounHelp(noun))
	}
	verb := noun.verb(args[1])
	if verb == nil {
		return usagef("%s has no verb %q", noun.Name, args[1])
	}
	tokens, help := lex(verb.Spec, args[2:])
	if help {
		return a.writeHelp(a.verbHelp(noun, verb))
	}
	parsed, err := parse(noun.Name+" "+verb.Name, verb.Spec, tokens)
	if err != nil {
		return err
	}
	return verb.Run(parsed)
}

// runWhole runs the command that takes a positional in place of a noun, or
// rejects the word when the App has no such command. A positional that is
// one of the command's words is a selector; any other is the positional.
func (a *App) runWhole(args []string) error {
	if a.whole == nil {
		return usagef("unknown noun %q", args[0])
	}
	spec := a.whole.Spec
	tokens, help := lex(spec, args)
	if help {
		return a.writeHelp(a.rootHelp())
	}
	var kept []token
	var words, others []string
	for _, t := range tokens {
		switch _, isWord := spec.Selectors[t.name]; {
		case t.dashes > 0:
			kept = append(kept, t)
		case isWord:
			words = append(words, t.name)
			kept = append(kept, token{dashes: 1, name: t.name})
		default:
			others = append(others, t.name)
			kept = append(kept, t)
		}
	}
	// The flags are checked first, so a wrong flag is not read as a second folder.
	flags := spec
	flags.MinPos, flags.MaxPos = 0, -1
	if _, err := parse(a.bin, flags, kept); err != nil {
		return err
	}
	usage := a.bin + " " + spec.Positional
	switch {
	case len(others) == 0 && len(words) > 0:
		return usagef("the word %q names a section; give the folder too: %s %s", words[0], usage, words[0])
	case len(others) == 0:
		return usagef("%s needs a folder: %s", a.bin, usage)
	case len(others) > 1:
		return usagef("%s reads one folder, got %q and %q%s", a.bin, others[0], others[1], valid("sections", a.wordList()))
	}
	parsed, err := parse(a.bin, spec, kept)
	if err != nil {
		return err
	}
	if len(parsed.Selectors) == 0 {
		parsed.Selectors = sortedKeys(spec.Selectors)
	}
	return a.whole.Run(parsed)
}

func (a *App) wordList() string {
	names := make([]string, len(a.words))
	for i, w := range a.words {
		names[i] = w.Name
	}
	return strings.Join(names, ", ")
}

func isHelp(arg string) bool {
	return arg == "help" || arg == "-h" || arg == "--help"
}

func (a *App) writeHelp(text string) error {
	if _, err := io.WriteString(a.stdout, text); err != nil {
		return fmt.Errorf("write help: %w", err)
	}
	return nil
}
