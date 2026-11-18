package command

import (
	"fmt"
	"slices"
	"sync"

	"github.com/get-sybers/slopmop/internal/activity"
	"github.com/get-sybers/slopmop/internal/assess"
	"github.com/get-sybers/slopmop/internal/exposure"
	"github.com/get-sybers/slopmop/internal/indicator"
	"github.com/get-sybers/slopmop/internal/intel"
	"github.com/get-sybers/slopmop/internal/intent"
	"github.com/get-sybers/slopmop/internal/inventory"
	"github.com/get-sybers/slopmop/internal/mitre"
	"github.com/get-sybers/slopmop/internal/parallel"
	"github.com/get-sybers/slopmop/internal/progress"
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
	// window is the stretch of time the run read, and outside how many files
	// were not read because their time is not in it.
	window  window
	outside int
	// exposed is what the evidence holds that an attacker can use.
	exposed []exposed
	// targeted is what the scripts name outright: the accounts, addresses and hosts they aim at.
	targeted []targeted
	// intents are the ARTEX intents the files lie in, and intentOf names the one of each path.
	intents  []intentRun
	intentOf map[string]string
	// named is what each line of evidence a finding keeps names; a line that
	// names nothing is not in it.
	named map[evidenceAt][]mention
}

type pipeline struct {
	tactics    tactic.Table
	activities activity.Table
	patterns   indicator.Table
	formats    structured.Table
	assessment assess.Table
	catalogue  mitre.Catalogue
	exposures  exposure.Table
	intents    intent.Table
	// entities says where a finding lists what its lines name; a pipeline
	// that was given none lists nothing.
	entities entities
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
	if err = collected(exposures.Shows(), activities.Names(), tactics, catalogue); err != nil {
		return pipeline{}, err
	}
	intents, err := intent.Load()
	if err != nil {
		return pipeline{}, err
	}
	assessment, err := loadAssessment(tactics, activities, patterns, catalogue, exposures)
	if err != nil {
		return pipeline{}, err
	}
	return pipeline{
		tactics: tactics, activities: activities, patterns: patterns, formats: formats,
		assessment: assessment, catalogue: catalogue, exposures: exposures, intents: intents,
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
		if err := checkColumns(k); err != nil {
			return exposure.Table{}, err
		}
	}
	return table, nil
}

// The columns of a group of the exposure, by the names a kind orders them with.
const (
	columnValue = "value"
	columnWhat  = "what"
	columnSeen  = "seen"
	columnFound = "found in"
)

// exposureColumns are the columns of a group of the exposure, in the order
// of the report.
func exposureColumns() []string {
	return []string{columnValue, columnWhat, columnSeen, columnFound}
}

// checkColumns accepts a kind that orders no column, and one that names
// every column of its group once.
func checkColumns(k exposure.Kind) error {
	every := exposureColumns()
	if len(k.Columns) == 0 {
		return nil
	}
	if len(k.Columns) != len(every) || slices.ContainsFunc(every, func(c string) bool { return !slices.Contains(k.Columns, c) }) {
		return fmt.Errorf("exposures.json gives %s the columns %q, which are not each of %q once", k.Name, k.Columns, every)
	}
	return nil
}

// loadCatalogue checks that every ATT&CK and ATLAS identifier the tactic
// and activity tables give is one the catalogue lists, and that the tactic
// of a command and the tactics of an activity follow from a technique.
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
		if err = filed(name, tactics.Attack(name), tactics.Techniques(name), catalogue); err != nil {
			return mitre.Catalogue{}, err
		}
	}
	activities.Each(func(name string, shown, attack []string) {
		if err == nil {
			err = follows(name, shown, attack, tactics, catalogue)
		}
	})
	return catalogue, err
}

// filed checks that the techniques the commands of a tactic are filed under
// are of that tactic: ATT&CK lists each, and files it under the tactic.
func filed(name, attack string, techniques []string, catalogue mitre.Catalogue) error {
	for _, id := range techniques {
		if !catalogue.Attack.HasTechnique(id) {
			return fmt.Errorf("tactics.json files commands of %s under the technique %q, which the catalogue lacks", name, id)
		}
		if !slices.Contains(catalogue.Attack.TacticsOf(id), attack) {
			return fmt.Errorf("tactics.json files commands of %s under %s, which ATT&CK does not file under %s (%s)", name, id, name, attack)
		}
	}
	return nil
}

// collected checks what exposures.json says collecting an account shows: an
// activity that activities.json does not name as well, and a technique the
// catalogue lists and files under a tactic of the tactic table.
func collected(shows []exposure.Shown, activities []string, tactics tactic.Table, catalogue mitre.Catalogue) error {
	for _, s := range shows {
		switch {
		case slices.Contains(activities, s.Activity):
			return fmt.Errorf("exposures.json names the activity %s, which activities.json names as well", s.Activity)
		case !catalogue.Attack.HasTechnique(s.Technique):
			return fmt.Errorf("exposures.json gives %s the ATT&CK technique %q, which the catalogue lacks", s.Activity, s.Technique)
		case len(tacticsOf(s.Technique, tactics, catalogue)) == 0:
			return fmt.Errorf("exposures.json gives %s the technique %s, which ATT&CK files under no tactic of tactics.json", s.Activity, s.Technique)
		}
	}
	return nil
}

// tacticsOf names the tactics a technique is of: those of the tactic table
// that ATT&CK files the technique under, in the order of the table.
func tacticsOf(id string, tactics tactic.Table, catalogue mitre.Catalogue) []string {
	var names []string
	for _, name := range tactics.Names() {
		if slices.Contains(catalogue.Attack.TacticsOf(id), tactics.Attack(name)) {
			names = append(names, name)
		}
	}
	return names
}

// follows checks that a technique gives an activity each of its tactics:
// ATT&CK files every technique of the activity under one of its tactics,
// and under every tactic of the activity one of its techniques.
func follows(name string, shown, attack []string, tactics tactic.Table, catalogue mitre.Catalogue) error {
	under := func(id, tactic string) bool {
		return slices.Contains(catalogue.Attack.TacticsOf(id), tactics.Attack(tactic))
	}
	for _, id := range attack {
		if !catalogue.Attack.HasTechnique(id) {
			return fmt.Errorf("activities.json gives %s the ATT&CK technique %q, which the catalogue lacks", name, id)
		}
		if !slices.ContainsFunc(shown, func(tactic string) bool { return under(id, tactic) }) {
			return fmt.Errorf("activities.json gives %s the technique %s, which ATT&CK files under none of its tactics %q", name, id, shown)
		}
	}
	for _, tactic := range shown {
		if !slices.ContainsFunc(attack, func(id string) bool { return under(id, tactic) }) {
			return fmt.Errorf("activities.json gives %s the tactic %s, which ATT&CK files none of its techniques %q under", name, tactic, attack)
		}
	}
	return nil
}

// atlasOf returns the ATLAS techniques of an activity: those its ATT&CK
// techniques infer.
func (p pipeline) atlasOf(hit activity.Hit) []string {
	return p.catalogue.AtlasFor(hit.Attack)
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

// read analyses a folder, levels deep, against the watchlist at path, if any.
func (p pipeline) read(folder string, levels int, period window, path string, meter *progress.Meter) (analysis, error) {
	meter.Stage(stageRead, 0, 0)
	res, err := inventory.Scope{Depth: levels, From: period.start, Until: period.stop, Watch: meter.Begin}.ReadAll(folder)
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
	// What the files hold is read while the timeline is built: neither
	// needs the other, and both read every text.
	items := make([][]exposure.Item, len(res.Files))
	meter.Stage(stageAnalyse, len(res.Files), len(res.Files)+trace.Passes(res.Files))
	var reading sync.WaitGroup
	reading.Go(func() {
		parallel.Each(len(res.Files), func(i int) {
			defer meter.Begin(res.Files[i].Path)()
			items[i] = p.exposures.Extract(res.Texts[res.Files[i].Path])
		})
	})
	timeline := trace.BuildWatched(res.Files, res.Texts, tables, meter.Begin)
	reading.Wait()
	meter.Stage(stageGather, 0, 0)
	held := make(map[string][]exposure.Item, len(res.Files))
	for i, f := range res.Files {
		held[f.Path] = items[i]
	}
	found, named := p.collectExposed(timeline.Steps, res.Texts, held)
	p.discover(timeline.Steps, res.Texts, found)
	intents, intentOf := p.collectIntents(folder, timeline.Steps)
	return analysis{
		intents:   intents,
		intentOf:  intentOf,
		timeline:  timeline,
		watchlist: watchlist,
		skipped:   res.Skipped,
		window:    period,
		outside:   res.Outside,
		exposed:   found,
		targeted:  named.finish(res.Texts),
		// The lines are read here, while the texts are held; the findings are listed without them.
		named: p.newReader(res.Texts, held).read(timeline.Steps),
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
