package command

import (
	"fmt"
	"slices"

	"github.com/get-sybers/slopmop/internal/activity"
	"github.com/get-sybers/slopmop/internal/assess"
	"github.com/get-sybers/slopmop/internal/cli"
	"github.com/get-sybers/slopmop/internal/indicator"
	"github.com/get-sybers/slopmop/internal/intel"
	"github.com/get-sybers/slopmop/internal/inventory"
	"github.com/get-sybers/slopmop/internal/render"
	"github.com/get-sybers/slopmop/internal/structured"
	"github.com/get-sybers/slopmop/internal/tactic"
	"github.com/get-sybers/slopmop/internal/trace"
)

// analysis is the trace pipeline's result, shared by finding and report.
type analysis struct {
	timeline  trace.Timeline
	watchlist *intel.Watchlist
	// skipped names the sub-folders a recursive read left out.
	skipped []string
}

type pipeline struct {
	tactics    tactic.Table
	activities activity.Table
	patterns   indicator.Table
	formats    structured.Table
	assessment assess.Table
}

func loadPipeline() (pipeline, error) {
	tactics, err := tactic.LoadTactics()
	if err != nil {
		return pipeline{}, err
	}
	activities, err := activity.LoadActivities()
	if err != nil {
		return pipeline{}, err
	}
	// The two tables are separate files; a tactic one names must exist in the other.
	for _, name := range activities.Tactics() {
		if !tactics.Has(name) {
			return pipeline{}, fmt.Errorf("activities.json names the tactic %q, which tactics.json lacks", name)
		}
	}
	patterns, err := indicator.LoadPatterns()
	if err != nil {
		return pipeline{}, err
	}
	formats, err := structured.LoadFormats()
	if err != nil {
		return pipeline{}, err
	}
	assessment, err := loadAssessment(tactics, activities, patterns)
	if err != nil {
		return pipeline{}, err
	}
	return pipeline{
		tactics: tactics, activities: activities, patterns: patterns, formats: formats, assessment: assessment,
	}, nil
}

// loadAssessment checks that the impact and action tables name only what
// the other tables declare.
func loadAssessment(tactics tactic.Table, activities activity.Table, patterns indicator.Table) (assess.Table, error) {
	table, err := assess.LoadTable()
	if err != nil {
		return assess.Table{}, err
	}
	known := activities.Names()
	named, namedTactics, namedTypes := table.Names()
	for _, name := range named {
		if !slices.Contains(known, name) {
			return assess.Table{}, fmt.Errorf("the assessment tables name the activity %q, which activities.json lacks", name)
		}
	}
	for _, name := range namedTactics {
		if !tactics.Has(name) {
			return assess.Table{}, fmt.Errorf("the assessment tables name the tactic %q, which tactics.json lacks", name)
		}
	}
	for _, typ := range namedTypes {
		if !patterns.Has(typ) {
			return assess.Table{}, fmt.Errorf("impacts.json names the indicator type %q, which indicators.json lacks", typ)
		}
	}
	return table, nil
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
	tables := trace.Tables{
		Tactics: p.tactics, Activities: p.activities, Patterns: p.patterns, Formats: p.formats, Watchlist: watchlist,
	}
	return analysis{
		timeline:  trace.Build(res.Files, res.Texts, tables),
		watchlist: watchlist,
		skipped:   res.Skipped,
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
