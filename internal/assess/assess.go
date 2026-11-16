// Package assess turns what a timeline shows into its consequences and the
// actions they call for, using impacts.json and actions.json. It judges what
// the evidence says was done; it cannot tell whether a step succeeded.
package assess

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/get-sybers/slopmop/internal/tactic"
)

//go:embed impacts.json
var rawImpacts []byte

//go:embed actions.json
var rawActions []byte

// The kinds of action: one undoes what was done, the other prevents a repeat.
const (
	Remediation = "remediation"
	Mitigation  = "mitigation"
)

// maxAffected bounds the indicator values listed with one impact.
const maxAffected = 5

// trigger says what in the evidence brings an entry into the report.
type trigger struct {
	Activities []string `json:"activities,omitempty"`
	// Tactics are those of the tools that ran, not of the activities.
	Tactics   []string `json:"tactics,omitempty"`
	Watchlist bool     `json:"watchlist,omitempty"`
}

type impact struct {
	Name      string          `json:"name"`
	Severity  tactic.Severity `json:"severity"`
	Statement string          `json:"statement"`
	trigger
	// Affected names indicator types; their values in the evidence files are listed.
	Affected []string `json:"affected,omitempty"`
}

type action struct {
	Name     string          `json:"name"`
	Kind     string          `json:"kind"`
	Priority tactic.Severity `json:"priority"`
	Action   string          `json:"action"`
	trigger
}

// Table holds the impacts and actions, in the order of the data files.
type Table struct {
	impacts []impact
	actions []action
}

// Evidence is what a run found, by the files it was found in.
type Evidence struct {
	Activities map[string][]string
	// Tactics are those of the tools; an activity speaks for itself.
	Tactics map[string][]string
	// Hits maps a watchlist attribution to the files that matched it.
	Hits map[string][]string
	// Indicators maps a file to its indicator values by type.
	Indicators map[string]map[string][]string
}

// Result is one impact or one action that the evidence calls for.
type Result struct {
	Name string
	// Kind is empty for an impact, and Remediation or Mitigation for an action.
	Kind string
	// Level is the severity of an impact or the priority of an action.
	Level tactic.Severity
	Text  string
	// Basis names what in the evidence brought the entry in.
	Basis    []string
	Files    []string
	Affected []string
	// More counts the affected values beyond those listed.
	More int
}

// LoadTable reads and validates the embedded impacts.json and actions.json.
func LoadTable() (Table, error) {
	return decode(rawImpacts, rawActions)
}

func decode(impactsJSON, actionsJSON []byte) (Table, error) {
	var t Table
	if err := strict("impacts.json", impactsJSON, &t.impacts); err != nil {
		return Table{}, err
	}
	if err := strict("actions.json", actionsJSON, &t.actions); err != nil {
		return Table{}, err
	}
	seen := map[string]bool{}
	for i, e := range t.impacts {
		if err := check("impacts.json", i, e.Name, e.Statement, e.Severity, e.trigger, seen); err != nil {
			return Table{}, err
		}
	}
	seen = map[string]bool{}
	for i, e := range t.actions {
		if err := check("actions.json", i, e.Name, e.Action, e.Priority, e.trigger, seen); err != nil {
			return Table{}, err
		}
		if e.Kind != Remediation && e.Kind != Mitigation {
			return Table{}, fmt.Errorf("actions.json[%d] %s: kind %q is not remediation or mitigation", i, e.Name, e.Kind)
		}
	}
	return t, nil
}

func strict(file string, data []byte, into any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	if dec.More() {
		return fmt.Errorf("%s: trailing data", file)
	}
	return nil
}

func check(file string, i int, name, text string, level tactic.Severity, tr trigger, seen map[string]bool) error {
	switch {
	case name == "":
		return fmt.Errorf("%s[%d]: empty name", file, i)
	case seen[name]:
		return fmt.Errorf("%s[%d]: %s is named twice", file, i, name)
	case text == "":
		return fmt.Errorf("%s[%d] %s: no text", file, i, name)
	case level.Rank() == 0:
		return fmt.Errorf("%s[%d] %s: %q is not low, medium or high", file, i, name, level)
	case len(tr.Activities)+len(tr.Tactics) == 0 && !tr.Watchlist:
		return fmt.Errorf("%s[%d] %s: nothing triggers it", file, i, name)
	}
	seen[name] = true
	return nil
}

// Names lists every activity, tactic and indicator type the table refers
// to, so a caller that holds those tables can check that each one exists.
func (t Table) Names() (activities, tactics, indicators []string) {
	add := func(list []string, items []string) []string {
		for _, item := range items {
			if !slices.Contains(list, item) {
				list = append(list, item)
			}
		}
		return list
	}
	for _, e := range t.impacts {
		activities, tactics = add(activities, e.Activities), add(tactics, e.Tactics)
		indicators = add(indicators, e.Affected)
	}
	for _, e := range t.actions {
		activities, tactics = add(activities, e.Activities), add(tactics, e.Tactics)
	}
	return activities, tactics, indicators
}

// Covers reports whether an impact and an action each answer the activity.
func (t Table) Covers(activity string) bool {
	impacted, acted := false, false
	for _, e := range t.impacts {
		impacted = impacted || slices.Contains(e.Activities, activity)
	}
	for _, e := range t.actions {
		acted = acted || slices.Contains(e.Activities, activity)
	}
	return impacted && acted
}

// Impacts returns the impacts the evidence shows, most severe first.
func (t Table) Impacts(e Evidence) []Result {
	var results []Result
	for _, im := range t.impacts {
		basis, files := im.fired(e)
		if len(basis) == 0 {
			continue
		}
		r := Result{Name: im.Name, Level: im.Severity, Text: im.Statement, Basis: basis, Files: files}
		r.Affected, r.More = affected(im.Affected, files, e)
		results = append(results, r)
	}
	byLevel(results)
	return results
}

// Actions returns the actions the evidence calls for: remediation before
// mitigation, and the most urgent first within each.
func (t Table) Actions(e Evidence) []Result {
	var results []Result
	for _, a := range t.actions {
		if basis, files := a.fired(e); len(basis) > 0 {
			results = append(results, Result{Name: a.Name, Kind: a.Kind, Level: a.Priority, Text: a.Action, Basis: basis, Files: files})
		}
	}
	byLevel(results)
	sort.SliceStable(results, func(i, j int) bool {
		return results[i].Kind == Remediation && results[j].Kind == Mitigation
	})
	return results
}

func byLevel(results []Result) {
	sort.SliceStable(results, func(i, j int) bool {
		return results[i].Level.Rank() > results[j].Level.Rank()
	})
}

// fired returns what in the evidence triggers the entry and the files that
// show it; an empty basis means the entry does not apply.
func (tr trigger) fired(e Evidence) (basis, files []string) {
	note := func(label string, found []string) {
		if len(found) == 0 {
			return
		}
		basis = append(basis, label)
		for _, f := range found {
			if !slices.Contains(files, f) {
				files = append(files, f)
			}
		}
	}
	for _, name := range tr.Activities {
		note(name, e.Activities[name])
	}
	for _, name := range tr.Tactics {
		note(name+" tools", e.Tactics[name])
	}
	if tr.Watchlist {
		names := make([]string, 0, len(e.Hits))
		for name := range e.Hits {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			note("watchlist "+name, e.Hits[name])
		}
	}
	sort.Strings(files)
	return basis, files
}

// affected lists the values of the named indicator types in the files. An
// address is cut to its host: the vault matters, not each path read in it.
func affected(types, files []string, e Evidence) (values []string, more int) {
	for _, f := range files {
		for _, typ := range types {
			for _, v := range e.Indicators[f][typ] {
				if _, rest, isURL := strings.Cut(v, "://"); isURL {
					v, _, _ = strings.Cut(rest, "/")
					v, _, _ = strings.Cut(v, "?")
				}
				if !slices.Contains(values, v) {
					values = append(values, v)
				}
			}
		}
	}
	sort.Strings(values)
	if len(values) > maxAffected {
		more = len(values) - maxAffected
		values = values[:maxAffected]
	}
	return values, more
}
