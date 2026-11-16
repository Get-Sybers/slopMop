package command

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/get-sybers/slopmop/internal/cli"
	"github.com/get-sybers/slopmop/internal/inventory"
	"github.com/get-sybers/slopmop/internal/render"
	"github.com/get-sybers/slopmop/internal/state"
)

func (e Env) evidenceSelect(v verbSpec) (*cli.Verb, error) {
	return &cli.Verb{
		Name:    v.Name,
		Summary: v.Summary,
		Aliases: v.Aliases,
		Spec:    cli.Spec{Positional: v.Positional, MaxPos: 1},
		Run: func(a *cli.Args) error {
			if len(a.Pos) == 0 {
				return e.printSelection()
			}
			return e.selectFolder(a.Pos[0])
		},
	}, nil
}

func (e Env) printSelection() error {
	s, _, err := e.selection()
	if err != nil {
		return err
	}
	if s.Evidence == "" {
		_, err = fmt.Fprintln(e.Stdout, "no evidence folder selected")
		return err
	}
	_, err = fmt.Fprintln(e.Stdout, "selected:", render.Escape(s.Evidence))
	return err
}

// selectFolder never reads the old state file, so it also repairs a corrupt one.
func (e Env) selectFolder(folder string) error {
	if folder == "" {
		return fmt.Errorf("an empty string: %w", inventory.ErrNotFolder)
	}
	abs, err := filepath.Abs(folder)
	if err != nil {
		return fmt.Errorf("%s: %w", folder, err)
	}
	if info, statErr := os.Stat(abs); statErr != nil || !info.IsDir() {
		return fmt.Errorf("%s: %w", folder, inventory.ErrNotFolder)
	}
	path, err := e.StatePath()
	if err != nil {
		return err
	}
	if within(abs, path) {
		return fmt.Errorf("the state file %s lies inside the evidence folder, which stays untouched", path)
	}
	if err = (state.State{Evidence: abs}).Save(path); err != nil {
		return err
	}
	_, err = fmt.Fprintln(e.Stdout, "selected evidence folder", render.Escape(abs))
	return err
}

// within reports whether path lies in folder once links are resolved. The
// state file may not exist yet, so its nearest existing parent is resolved.
func within(folder, path string) bool {
	rel, err := filepath.Rel(resolve(folder), resolve(path))
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func resolve(path string) string {
	rest := ""
	for {
		resolved, err := filepath.EvalSymlinks(path)
		if err == nil {
			return filepath.Join(resolved, rest)
		}
		if !errors.Is(err, os.ErrNotExist) {
			return filepath.Join(path, rest)
		}
		parent := filepath.Dir(path)
		if parent == path {
			return filepath.Join(path, rest)
		}
		rest = filepath.Join(filepath.Base(path), rest)
		path = parent
	}
}
