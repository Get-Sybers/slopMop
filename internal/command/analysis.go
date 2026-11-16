package command

import (
	"fmt"
	"slices"

	"github.com/get-sybers/slopmop/internal/activity"
	"github.com/get-sybers/slopmop/internal/assess"
	"github.com/get-sybers/slopmop/internal/exposure"
	"github.com/get-sybers/slopmop/internal/indicator"
	"github.com/get-sybers/slopmop/internal/intel"
	"github.com/get-sybers/slopmop/internal/inventory"
	"github.com/get-sybers/slopmop/internal/mitre"
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
	// exposed is what the evidence holds that an attacker can use.
	exposed []exposed
	// redact masks every secret among them in a text that quotes the evidence.
	redact func(string) string
}

type pipeline struct {
	tactics    tactic.Table
	activities activity.Table
	patterns   indicator.Table
	formats    structured.Table
	assessment assess.Table
	catalogue  mitre.Catalogue
	exposures  exposure.Table
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
	catalogue, err := loadCatalogue(tactics, activities)
	if err != nil {
		return pipeline{}, err
	}
	exposures, err := loadExposures(patterns)
	if err != nil {
		return pipeline{}, err
	}
	assessment, err := loadAssessment(tactics, activities, patterns, catalogue, exposures)
	if err != nil {
		return pipeline{}, err
	}
	return pipeline{
		tactics: tactics, activities: activities, patterns: patterns, formats: formats,
		assessment: assessment, catalogue: catalogue, exposures: exposures,
	}, nil
}

// loadExposures checks that the exposure table names only indicator types
// that exist and gives each kind a severity the tactic table knows.
func loadExposures(patterns indicator.Table) (exposure.Table, error) {
	table, err := exposure.Load()
	if err != nil {
		return exposure.Table{}, err
	}
	for _, typ := range table.IndicatorTypes() {
		if !patterns.Has(typ) {
			return exposure.Table{}, fmt.Errorf("exposures.json names the indicator type %q, which indicators.json lacks", typ)
		}
	}
	for _, k := range table.Kinds() {
		if tactic.Severity(k.Severity).Rank() == 0 {
			return exposure.Table{}, fmt.Errorf("exposures.json gives %s the severity %q, which is not low, medium or high", k.Name, k.Severity)
		}
	}
	return table, nil
}

// loadCatalogue checks that every ATT&CK and ATLAS identifier the tactic
// and activity tables give is one the catalogue lists.
func loadCatalogue(tactics tactic.Table, activities activity.Table) (mitre.Catalogue, error) {
	catalogue, err := mitre.Load()
	if err != nil {
		return mitre.Catalogue{}, err
	}
	for _, name := range tactics.Names() {
		if id := tactics.Attack(name); !catalogue.Attack.HasTactic(id) {
			return mitre.Catalogue{}, fmt.Errorf("tactics.json gives %s the ATT&CK tactic %q, which the catalogue lacks", name, id)
		}
		if id := tactics.Atlas(name); !catalogue.Atlas.HasTactic(id) {
			return mitre.Catalogue{}, fmt.Errorf("tactics.json gives %s the ATLAS tactic %q, which the catalogue lacks", name, id)
		}
	}
	activities.Each(func(name string, _, attack, atlas []string) {
		for _, id := range attack {
			if err == nil && !catalogue.Attack.HasTechnique(id) {
				err = fmt.Errorf("activities.json gives %s the ATT&CK technique %q, which the catalogue lacks", name, id)
			}
		}
		for _, id := range atlas {
			if err == nil && !catalogue.Atlas.HasTechnique(id) {
				err = fmt.Errorf("activities.json gives %s the ATLAS technique %q, which the catalogue lacks", name, id)
			}
		}
	})
	return catalogue, err
}

// atlasOf returns the ATLAS techniques of an activity: those it names and
// those that refer to one of its ATT&CK techniques.
func (p pipeline) atlasOf(hit activity.Hit) []string {
	return appendUnique(slices.Clone(hit.Atlas), p.catalogue.AtlasFor(hit.Attack)...)
}

// loadAssessment checks that the impact and action tables name only what
// the other tables declare.
func loadAssessment(tactics tactic.Table, activities activity.Table, patterns indicator.Table, catalogue mitre.Catalogue, exposures exposure.Table) (assess.Table, error) {
	table, err := assess.LoadTable()
	if err != nil {
		return assess.Table{}, err
	}
	known := activities.Names()
	named, namedTactics, namedTypes, namedAtlas, namedKinds := table.Names()
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
	for _, id := range namedAtlas {
		if !catalogue.Atlas.HasTechnique(id) {
			return assess.Table{}, fmt.Errorf("impacts.json names the ATLAS technique %q, which the catalogue lacks", id)
		}
	}
	for _, kind := range namedKinds {
		if !slices.ContainsFunc(exposures.Kinds(), func(k exposure.Kind) bool { return k.Name == kind }) {
			return assess.Table{}, fmt.Errorf("the assessment tables name the kind of exposure %q, which exposures.json lacks", kind)
		}
	}
	return table, nil
}

// read analyses a folder, levels deep, against the watchlist at path, if
// any. plain writes secrets out as they are; otherwise each is masked.
func (p pipeline) read(folder string, levels int, path string, plain bool) (analysis, error) {
	res, err := inventory.ReadAll(folder, levels)
	if err != nil {
		return analysis{}, err
	}
	var watchlist *intel.Watchlist
	if path != "" {
		wl, err := loadIntelFile(path)
		if err != nil {
			return analysis{}, err
		}
		watchlist = &wl
	}
	tables := trace.Tables{
		Tactics: p.tactics, Activities: p.activities, Patterns: p.patterns, Formats: p.formats, Watchlist: watchlist,
	}
	timeline := trace.Build(res.Files, res.Texts, tables)
	found := p.collectExposed(timeline.Steps, res.Texts, plain)
	return analysis{
		timeline:  timeline,
		watchlist: watchlist,
		skipped:   res.Skipped,
		exposed:   found,
		redact:    redactor(found),
	}, nil
}

// orderCells orders a row's cells by the declared columns, so the declaration
// and the code cannot drift apart unnoticed.
func orderCells(class string, cells map[string]render.Value, columns []render.Column) ([]render.Value, error) {
	if len(columns) != len(cells) {
		return nil, fmt.Errorf("the class %s declares %d columns and fills %d", class, len(columns), len(cells))
	}
	row := make([]render.Value, len(columns))
	for i, c := range columns {
		cell, ok := cells[c.Key]
		if !ok {
			return nil, fmt.Errorf("the class %s declares the column %q, which has no value", class, c.Key)
		}
		row[i] = cell
	}
	return row, nil
}
