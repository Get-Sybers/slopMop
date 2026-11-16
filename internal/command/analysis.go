package command

import (
	"fmt"

	"github.com/get-sybers/slopmop/internal/cli"
	"github.com/get-sybers/slopmop/internal/indicator"
	"github.com/get-sybers/slopmop/internal/intel"
	"github.com/get-sybers/slopmop/internal/inventory"
	"github.com/get-sybers/slopmop/internal/render"
	"github.com/get-sybers/slopmop/internal/tactic"
	"github.com/get-sybers/slopmop/internal/trace"
)

// analysis is the trace pipeline's result, shared by finding and report.
type analysis struct {
	timeline  trace.Timeline
	watchlist *intel.Watchlist
}

type pipeline struct {
	tactics  tactic.Table
	patterns indicator.Table
}

func loadPipeline() (pipeline, error) {
	tactics, err := tactic.LoadTactics()
	if err != nil {
		return pipeline{}, err
	}
	patterns, err := indicator.LoadPatterns()
	if err != nil {
		return pipeline{}, err
	}
	return pipeline{tactics: tactics, patterns: patterns}, nil
}

func (p pipeline) run(a *cli.Args) (analysis, error) {
	res, err := inventory.ReadAll(a.Params[inputDir], depth(a))
	if err != nil {
		return analysis{}, err
	}
	var watchlist *intel.Watchlist
	if path := a.Params[intelFile]; path != "" {
		wl, err := loadIntelFile(path)
		if err != nil {
			return analysis{}, err
		}
		watchlist = &wl
	}
	return analysis{
		timeline:  trace.Build(res.Files, res.Texts, p.tactics, p.patterns, watchlist),
		watchlist: watchlist,
	}, nil
}

// orderCells orders a row's cells by the declared columns, so the declaration
// and the code cannot drift apart unnoticed.
func orderCells(verb string, cells map[string]render.Value, columns []render.Column) ([]render.Value, error) {
	if len(columns) != len(cells) {
		return nil, fmt.Errorf("%s declares %d columns and fills %d", verb, len(columns), len(cells))
	}
	row := make([]render.Value, len(columns))
	for i, c := range columns {
		cell, ok := cells[c.Key]
		if !ok {
			return nil, fmt.Errorf("%s declares the column %q, which has no value", verb, c.Key)
		}
		row[i] = cell
	}
	return row, nil
}
