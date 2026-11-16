// Package command binds the nouns to the packages that do the work.
package command

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/get-sybers/slopmop/internal/cli"
	"github.com/get-sybers/slopmop/internal/render"
)

// inputDir is the param every verb that reads evidence requires.
const inputDir = "inputdir"

type Env struct {
	Stdout io.Writer
	Local  *time.Location
}

type builder func(verbSpec) (*cli.Verb, error)

// Register adds every noun nouns.json declares. A declared verb without an
// implementation, or an implementation without a declaration, is an error.
func Register(app *cli.App, env Env) error {
	nouns, err := loadNouns()
	if err != nil {
		return err
	}
	return register(app, nouns, map[string]builder{
		"file list": env.fileList,
	})
}

func register(app *cli.App, nouns []nounSpec, builders map[string]builder) error {
	unbound := map[string]bool{}
	for name := range builders {
		unbound[name] = true
	}
	for _, n := range nouns {
		noun := &cli.Noun{Name: n.Name, Summary: n.Summary, Aliases: n.Aliases}
		for _, v := range n.Verbs {
			name := n.Name + " " + v.Name
			build, ok := builders[name]
			if !ok {
				return fmt.Errorf("nouns.json declares %s, which has no implementation", name)
			}
			verb, err := build(v)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			noun.Verbs = append(noun.Verbs, verb)
			delete(unbound, name)
		}
		if err := app.Register(noun); err != nil {
			return err
		}
	}
	if len(unbound) > 0 {
		missing := make([]string, 0, len(unbound))
		for name := range unbound {
			missing = append(missing, name)
		}
		sort.Strings(missing)
		return fmt.Errorf("nouns.json does not declare %s", strings.Join(missing, ", "))
	}
	return nil
}

func (e Env) options(o cli.Output) render.Options {
	opts := render.Options{Quiet: o.Quiet, NoHeaders: o.NoHeaders}
	switch o.View {
	case "wide":
		opts.View = render.Wide
	case "json":
		opts.View = render.JSON
	}
	if o.Local {
		opts.Location = e.Local
	}
	return opts
}
