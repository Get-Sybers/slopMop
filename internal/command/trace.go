package command

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/get-sybers/slopmop/internal/cli"
	"github.com/get-sybers/slopmop/internal/intel"
	"github.com/get-sybers/slopmop/internal/render"
	"github.com/get-sybers/slopmop/internal/trace"
)

const (
	listWidth = 60
	ellipsis  = "..."
)

func (e Env) traceList(v verbSpec) (*cli.Verb, error) {
	if v.Name != "list" || len(v.Aliases) > 0 {
		return nil, errors.New("the global list verb takes its name and alias from cli.ListVerb")
	}
	pipe, err := loadPipeline()
	if err != nil {
		return nil, err
	}
	if _, err := traceRow(trace.Step{}, v.Columns, false); err != nil {
		return nil, err
	}
	spec := cli.Spec{
		Selectors: map[string]string{
			"script": "show only scripts",
			"output": "show only outputs",
			"other":  "show only other files",
		},
		Params:   map[string]string{inputDir: "<folder>", intelFile: "<file>"},
		Switches: recursiveSwitch(),
		Required: []string{inputDir},
	}
	return cli.ListVerb(v.Summary, spec, func(a *cli.Args) error {
		result, err := pipe.run(a)
		if err != nil {
			return err
		}
		wanted := map[string]bool{}
		for _, sel := range a.Selectors {
			wanted[sel] = true
		}
		// Only the default table shortens its lists; wide, quiet and JSON carry them whole.
		shorten := a.Output.View == "" && !a.Output.Quiet
		table := render.Table{Columns: v.Columns}
		for _, s := range result.timeline.Steps {
			if !wanted[string(s.File.Role)] {
				continue
			}
			row, err := traceRow(s, v.Columns, shorten)
			if err != nil {
				return err
			}
			table.Rows = append(table.Rows, row)
		}
		if err := render.Write(e.Stdout, table, e.options(a.Output)); err != nil {
			return err
		}
		return skippedError(result.skipped)
	}), nil
}

func loadIntelFile(path string) (intel.Watchlist, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return intel.Watchlist{}, fmt.Errorf("--intelfile: %w", err)
	}
	return intel.LoadWatchlist(data)
}

// traceRow fills one row. render has no list value, so a list is one text
// cell joined with ", "; shorten cuts it to listWidth for the default table.
func traceRow(s trace.Step, columns []render.Column, shorten bool) ([]render.Value, error) {
	list := func(items []string) render.Value {
		joined := strings.Join(items, ", ")
		if shorten {
			joined = truncate(joined, listWidth)
		}
		return render.Text(joined)
	}
	cells := map[string]render.Value{
		"step":       render.Int(int64(s.Turn)),
		"name":       render.Text(s.File.Path),
		"role":       render.Text(string(s.File.Role)),
		"time":       render.NotApplicable(),
		"tools":      render.NotApplicable(),
		"tactics":    render.NotApplicable(),
		"transforms": render.NotApplicable(),
		"activities": render.NotApplicable(),
		"outputs":    render.NotApplicable(),
		"indicators": render.NotApplicable(),
		"intel":      render.NotApplicable(),
		"note":       render.NotApplicable(),
	}
	if !s.File.Modified.IsZero() {
		cells["time"] = render.Time(s.File.Modified)
	}
	if s.File.Stamped {
		cells["time"] = render.Text(s.File.Stamp.Text)
	}
	if len(s.Tools) > 0 {
		cells["tools"] = list(s.Tools)
	}
	if len(s.Tactics) > 0 {
		cells["tactics"] = list(s.Tactics)
	}
	if len(s.Transforms) > 0 {
		cells["transforms"] = list(s.Transforms)
	}
	if len(s.Activities) > 0 {
		names := make([]string, len(s.Activities))
		for i, a := range s.Activities {
			names[i] = a.Name
		}
		cells["activities"] = list(names)
	}
	if len(s.Outputs) > 0 {
		cells["outputs"] = list(s.Outputs)
	}
	if s.Indicators > 0 {
		cells["indicators"] = render.Int(int64(s.Indicators))
	}
	if len(s.IntelHits) > 0 {
		labels := make([]string, len(s.IntelHits))
		for i, h := range s.IntelHits {
			labels[i] = h.Attribution + ": " + h.Value
		}
		cells["intel"] = list(labels)
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

// truncate cuts s to at most limit bytes, ending in "..." and never inside a rune.
func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	cut := limit - len(ellipsis)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + ellipsis
}
