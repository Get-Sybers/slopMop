// Package command declares the verbs in commands.json and binds them to the
// packages that do the work.
package command

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"

	"github.com/get-sybers/slopmop/internal/cli"
	"github.com/get-sybers/slopmop/internal/render"
)

// The options a verb reads; commands.json declares their hints and summaries.
const (
	inputDir     = "inputdir"
	intelFile    = "intelfile"
	outDir       = "outdir"
	secrets      = "secrets"
	coresOption  = "cores"
	memoryOption = "memory"
)

// The values of the secrets option.
const (
	secretsMasked = "masked"
	secretsShown  = "shown"
)

//go:embed commands.json
var commandsJSON []byte

type Env struct {
	Stdout io.Writer
	// Colour marks the readout with ANSI colours; a saved file never has any.
	Colour bool
	// WorkDir is where the output folder is made; empty is the current directory.
	WorkDir string
}

// commandsDoc is commands.json: the grammar, and the classes that are saved as JSON.
type commandsDoc struct {
	Usage   string       `json:"usage"`
	Options []optionSpec `json:"options"`
	Verbs   []verbSpec   `json:"verbs"`
	Classes []classSpec  `json:"classes"`
}

type optionSpec struct {
	Name    string `json:"name"`
	Hint    string `json:"hint"`
	Summary string `json:"summary"`
}

type verbSpec struct {
	Name    string `json:"name"`
	Summary string `json:"summary"`
	// Requires and Takes name the options the verb needs and those it accepts.
	Requires []string      `json:"requires"`
	Takes    []string      `json:"takes"`
	Sections []sectionSpec `json:"sections"`
	Hints    []string      `json:"hints"`
	Saved    savedSpec     `json:"saved"`
}

// classSpec is one kind of row and its columns; the JSON keys are the columns' keys.
type classSpec struct {
	Name    string          `json:"name"`
	Columns []render.Column `json:"columns"`
}

type builder func(v verbSpec, doc commandsDoc) (*cli.Verb, error)

// NewApp returns the App of bin with every verb commands.json declares. A
// declared verb without an implementation, or the reverse, is an error.
func NewApp(bin string, env Env) (*cli.App, error) {
	doc, err := decodeCommands(commandsJSON)
	if err != nil {
		return nil, err
	}
	app := cli.New(bin, doc.Usage, env.Stdout)
	return app, register(app, doc, map[string]builder{"report": env.reportVerb})
}

func register(app *cli.App, doc commandsDoc, builders map[string]builder) error {
	unbound := map[string]bool{}
	for name := range builders {
		unbound[name] = true
	}
	for _, v := range doc.Verbs {
		build, ok := builders[v.Name]
		if !ok {
			return fmt.Errorf("commands.json declares %s, which has no implementation", v.Name)
		}
		verb, err := build(v, doc)
		if err != nil {
			return fmt.Errorf("%s: %w", v.Name, err)
		}
		if err := app.Register(verb); err != nil {
			return err
		}
		delete(unbound, v.Name)
	}
	if len(unbound) > 0 {
		missing := make([]string, 0, len(unbound))
		for name := range unbound {
			missing = append(missing, name)
		}
		sort.Strings(missing)
		return fmt.Errorf("commands.json does not declare %s", strings.Join(missing, ", "))
	}
	return nil
}

func decodeCommands(data []byte) (commandsDoc, error) {
	var doc commandsDoc
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return doc, fmt.Errorf("commands.json: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return doc, errors.New("commands.json: data after the document")
	}
	if doc.Usage == "" || len(doc.Verbs) == 0 {
		return doc, errors.New("commands.json: no usage or no verbs")
	}
	options := map[string]bool{}
	for _, o := range doc.Options {
		if o.Name == "" || o.Hint == "" || o.Summary == "" || options[o.Name] {
			return doc, fmt.Errorf("commands.json: option %q is declared twice or lacks a name, a hint or a summary", o.Name)
		}
		options[o.Name] = true
	}
	for _, v := range doc.Verbs {
		if v.Name == "" || v.Summary == "" {
			return doc, fmt.Errorf("commands.json: verb %q needs a name and a summary", v.Name)
		}
		for i, name := range slices.Concat(v.Requires, v.Takes) {
			if !options[name] || slices.Index(slices.Concat(v.Requires, v.Takes), name) != i {
				return doc, fmt.Errorf("commands.json: %s: the option %q is not declared or is named twice", v.Name, name)
			}
		}
	}
	classes := map[string]bool{}
	for _, c := range doc.Classes {
		if c.Name == "" || classes[c.Name] {
			return doc, fmt.Errorf("commands.json: class %q is declared twice or has no name", c.Name)
		}
		classes[c.Name] = true
		if err := (render.Table{Columns: c.Columns}).Check(); err != nil {
			return doc, fmt.Errorf("commands.json: class %s: %w", c.Name, err)
		}
	}
	return doc, nil
}

// options returns the options of a verb as the grammar takes them, the required first.
func (doc commandsDoc) options(v verbSpec) []cli.Option {
	var out []cli.Option
	for i, name := range slices.Concat(v.Requires, v.Takes) {
		for _, o := range doc.Options {
			if o.Name == name {
				out = append(out, cli.Option{Name: o.Name, Hint: o.Hint, Summary: o.Summary, Required: i < len(v.Requires)})
			}
		}
	}
	return out
}

// columns returns the columns of the named class, or none.
func (doc commandsDoc) columns(class string) []render.Column {
	for _, c := range doc.Classes {
		if c.Name == class {
			return c.Columns
		}
	}
	return nil
}

// skippedError reports the sub-folders a read left out, after the output is written.
func skippedError(skipped []string, levels int) error {
	if len(skipped) == 0 {
		return nil
	}
	return fmt.Errorf("%d folder(s) not read (unreadable or more than %d levels down): %s",
		len(skipped), levels, strings.Join(skipped, ", "))
}
