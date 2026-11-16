// Package cli implements the NOUN VERB command grammar: specs, parsing, dispatch and generated help.
package cli

import (
	"fmt"
	"io"
)

type App struct {
	bin    string
	stdout io.Writer
	nouns  []*Noun
	index  map[string]*Noun
}

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
		return usagef("unknown noun %q", args[0])
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

func isHelp(arg string) bool {
	return arg == "help" || arg == "-h" || arg == "--help"
}

func (a *App) writeHelp(text string) error {
	if _, err := io.WriteString(a.stdout, text); err != nil {
		return fmt.Errorf("write help: %w", err)
	}
	return nil
}
