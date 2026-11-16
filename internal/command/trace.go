package command

import (
	"errors"
	"fmt"
	"strings"

	"github.com/get-sybers/slopmop/internal/cli"
	"github.com/get-sybers/slopmop/internal/indicator"
	"github.com/get-sybers/slopmop/internal/inventory"
	"github.com/get-sybers/slopmop/internal/render"
	"github.com/get-sybers/slopmop/internal/tactic"
	"github.com/get-sybers/slopmop/internal/trace"
)

func (e Env) traceList(v verbSpec) (*cli.Verb, error) {
	if v.Name != "list" || len(v.Aliases) > 0 {
		return nil, errors.New("the global list verb takes its name and alias from cli.ListVerb")
	}
	tactics, err := tactic.LoadTactics()
	if err != nil {
		return nil, err
	}
	patterns, err := indicator.LoadPatterns()
	if err != nil {
		return nil, err
	}
	if _, err := traceRow(trace.Step{}, v.Columns); err != nil {
		return nil, err
	}
	spec := cli.Spec{
		Selectors: map[string]string{
			"script": "show only scripts",
			"output": "show only outputs",
			"other":  "show only other files",
		},
		Params:   map[string]string{inputDir: "<folder>"},
		Required: []string{inputDir},
	}
	return cli.ListVerb(v.Summary, spec, func(a *cli.Args) error {
		res, err := inventory.ReadAll(a.Params[inputDir])
		if err != nil {
			return err
		}
		timeline := trace.Build(res.Files, res.Texts, tactics, patterns)
		wanted := map[string]bool{}
		for _, sel := range a.Selectors {
			wanted[sel] = true
		}
		table := render.Table{Columns: v.Columns}
		for _, s := range timeline.Steps {
			if !wanted[string(s.File.Role)] {
				continue
			}
			row, err := traceRow(s, v.Columns)
			if err != nil {
				return err
			}
			table.Rows = append(table.Rows, row)
		}
		return render.Write(e.Stdout, table, e.options(a.Output))
	}), nil
}

func traceRow(s trace.Step, columns []render.Column) ([]render.Value, error) {
	cells := map[string]render.Value{
		"step":       render.Int(int64(s.Turn)),
		"name":       render.Text(s.File.Path),
		"role":       render.Text(string(s.File.Role)),
		"time":       render.NotApplicable(),
		"tools":      render.NotApplicable(),
		"tactics":    render.NotApplicable(),
		"outputs":    render.NotApplicable(),
		"indicators": render.NotApplicable(),
		"note":       render.NotApplicable(),
	}
	if !s.File.Modified.IsZero() {
		cells["time"] = render.Time(s.File.Modified)
	}
	if s.File.Stamped {
		cells["time"] = render.Text(s.File.Stamp.Text)
	}
	if len(s.Tools) > 0 {
		cells["tools"] = render.Text(joinTruncate(s.Tools, 60))
	}
	if len(s.Tactics) > 0 {
		cells["tactics"] = render.Text(joinTruncate(s.Tactics, 60))
	}
	if len(s.Outputs) > 0 {
		cells["outputs"] = render.Text(joinTruncate(s.Outputs, 60))
	}
	if s.Indicators > 0 {
		cells["indicators"] = render.Int(int64(s.Indicators))
	}
	if s.File.Note != "" {
		cells["note"] = render.Text(string(s.File.Note))
	}
	if len(columns) != len(cells) {
		return nil, fmt.Errorf("trace list declares %d columns and fills %d", len(columns), len(cells))
	}
	row := make([]render.Value, len(columns))
	for i, c := range columns {
		cell, ok := cells[c.Key]
		if !ok {
			return nil, fmt.Errorf("trace list declares the column %q, which has no value", c.Key)
		}
		row[i] = cell
	}
	return row, nil
}

func joinTruncate(items []string, limit int) string {
	s := strings.Join(items, ", ")
	if len(s) > limit {
		return s[:limit-3] + "..."
	}
	return s
}
