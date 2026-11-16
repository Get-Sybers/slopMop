package command

import (
	"errors"
	"fmt"

	"github.com/get-sybers/slopmop/internal/cli"
	"github.com/get-sybers/slopmop/internal/evidence"
	"github.com/get-sybers/slopmop/internal/inventory"
	"github.com/get-sybers/slopmop/internal/render"
)

func (e Env) fileList(v verbSpec) (*cli.Verb, error) {
	if v.Name != "list" || len(v.Aliases) > 0 {
		return nil, errors.New("the global list verb takes its name and alias from cli.ListVerb")
	}
	roles, err := inventory.LoadRoles()
	if err != nil {
		return nil, err
	}
	selectors := map[string]string{}
	for _, r := range roles {
		selectors[string(r.Name)] = r.Summary
	}
	if _, err := fileRow(evidence.File{}, v.Columns); err != nil {
		return nil, err
	}
	spec := cli.Spec{
		Selectors: selectors,
		Params:    map[string]string{inputDir: "<folder>"},
		Required:  []string{inputDir},
	}
	return cli.ListVerb(v.Summary, spec, func(a *cli.Args) error {
		files, err := inventory.Read(a.Params[inputDir])
		if err != nil {
			return err
		}
		wanted := map[string]bool{}
		for _, role := range a.Selectors {
			wanted[role] = true
		}
		table := render.Table{Columns: v.Columns}
		unreadable := 0
		for _, f := range files {
			if !wanted[string(f.Role)] {
				continue
			}
			row, err := fileRow(f, v.Columns)
			if err != nil {
				return err
			}
			table.Rows = append(table.Rows, row)
			if f.Note == evidence.Unreadable {
				unreadable++
			}
		}
		if err := render.Write(e.Stdout, table, e.options(a.Output)); err != nil {
			return err
		}
		if unreadable > 0 {
			return fmt.Errorf("%d file(s) unreadable", unreadable)
		}
		return nil
	}), nil
}

// fileRow orders a file's cells by the declared columns, so the declaration
// and the code cannot drift apart unnoticed.
func fileRow(f evidence.File, columns []render.Column) ([]render.Value, error) {
	cells := map[string]render.Value{
		"name":      render.Text(f.Path),
		"role":      render.Text(string(f.Role)),
		"size":      render.Size(f.Size),
		"lines":     render.NotApplicable(),
		"modified":  render.NotApplicable(),
		"sha256":    render.NotApplicable(),
		"name_time": render.NotApplicable(),
		"note":      render.NotApplicable(),
	}
	if f.Note == "" {
		cells["lines"] = render.Int(int64(f.Lines))
	} else {
		cells["note"] = render.Text(string(f.Note))
	}
	if !f.Modified.IsZero() {
		cells["modified"] = render.Time(f.Modified)
	}
	if f.SHA256 != "" {
		cells["sha256"] = render.Hash(f.SHA256)
	}
	if f.Stamped {
		cells["name_time"] = render.Text(f.Stamp.Text)
	}
	if len(columns) != len(cells) {
		return nil, fmt.Errorf("file list declares %d columns and fills %d", len(columns), len(cells))
	}
	row := make([]render.Value, len(columns))
	for i, c := range columns {
		cell, ok := cells[c.Key]
		if !ok {
			return nil, fmt.Errorf("file list declares the column %q, which has no value", c.Key)
		}
		row[i] = cell
	}
	return row, nil
}
