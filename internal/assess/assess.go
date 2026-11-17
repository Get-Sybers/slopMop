// Package assess turns what a timeline shows into its consequences and the
// remediation they call for, using impacts.json and actions.json. It judges
// what the evidence says was done; it cannot tell whether a step succeeded.
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

const (
	// maxAffected bounds the indicator values listed with one impact.
	maxAffected = 5
	// maxExposed bounds the exposed values of one kind listed with one entry.
	maxExposed = 8
)

// trigger says what in the evidence brings an entry into the report.
type trigger struct {
	Activities []string `json:"activities,omitempty"`
	// Tactics are those of the tools that ran, not of the activities.
	Tactics   []string `json:"tactics,omitempty"`
	Watchlist bool     `json:"watchlist,omitempty"`
	// Always brings the entry in whenever the evidence shows anything at all.
	Always bool `json:"always,omitempty"`
	// Exposed names kinds of exposure: one value of a kind brings the entry
	// in, and the entry lists the values.
	Exposed []string `json:"exposed,omitempty"`
}

type impact struct {
	Name      string          `json:"name"`
	Severity  tactic.Severity `json:"severity"`
	Statement string          `json:"statement"`
	trigger
	// Affected names indicator types; their values in the evidence files are listed.
	Affected []string `json:"affected,omitempty"`
	// Atlas names ATLAS techniques the impact stands for by itself.
	Atlas []string `json:"atlas,omitempty"`
}

type action struct {
	Name     string          `json:"name"`
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
	// Exposed maps a kind of exposure to what the evidence holds of it.
	Exposed map[string][]Exposed
}

// Exposed is one exposed value, named as a reader acts on it, and its files.
type Exposed struct {
	Label string
	Files []string
}

// Listed is the exposed values of one kind that an entry concerns.
type Listed struct {
	Kind   string
	Labels []string
	// More counts the values beyond those listed.
	More int
}

// Result is one impact or one action that the evidence calls for.
type Result struct {
	Name string
	// Level is the severity of an impact or the priority of an action.
	Level tactic.Severity
	Text  string
	// Basis names what in the evidence brought the entry in, and Activities
	// the activities among it.
	Basis      []string
	Activities []string
	Files      []string
	// Atlas names the ATLAS techniques an impact stands for by itself.
	Atlas    []string
	Affected []string
	// More counts the affected values beyond those listed.
	More int
	// Exposed lists what the entry concerns, by kind of exposure.
	Exposed []Listed
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
	case len(tr.Activities)+len(tr.Tactics)+len(tr.Exposed) == 0 && !tr.Watchlist && !tr.Always:
		return fmt.Errorf("%s[%d] %s: nothing triggers it", file, i, name)
	}
	seen[name] = true
	return nil
}

// Names lists every activity, tactic, indicator type, ATLAS technique and
// kind of exposure the table refers to, so a caller that holds those tables
// can check each one.
func (t Table) Names() (activities, tactics, indicators, atlas, exposed []string) {
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
		indicators, atlas = add(indicators, e.Affected), add(atlas, e.Atlas)
		exposed = add(exposed, e.Exposed)
	}
	for _, e := range t.actions {
		activities, tactics = add(activities, e.Activities), add(tactics, e.Tactics)
		exposed = add(exposed, e.Exposed)
	}
	return activities, tactics, indicators, atlas, exposed
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
		basis, activities, files := im.fired(e)
		if len(basis) == 0 {
			continue
		}
		r := Result{
			Name: im.Name, Level: im.Severity, Text: im.Statement,
			Basis: basis, Activities: activities, Files: files, Atlas: im.Atlas,
		}
		r.Affected, r.More = affected(im.Affected, files, e)
		r.Exposed = im.listed(e)
		results = append(results, r)
	}
	byLevel(results)
	return results
}

// Remediation returns the actions that undo what the evidence shows, the
// most urgent first.
func (t Table) Remediation(e Evidence) []Result {
	var results []Result
	for _, a := range t.actions {
		if basis, activities, files := a.fired(e); len(basis) > 0 {
			results = append(results, Result{
				Name: a.Name, Level: a.Priority, Text: a.Action, Basis: basis, Activities: activities, Files: files,
				Exposed: a.listed(e),
			})
		}
	}
	byLevel(results)
	return results
}

func byLevel(results []Result) {
	sort.SliceStable(results, func(i, j int) bool {
		return results[i].Level.Rank() > results[j].Level.Rank()
	})
}

// fired returns what in the evidence triggers the entry, the activities
// among it and the files that show it; an empty basis means it does not apply.
func (tr trigger) fired(e Evidence) (basis, activities, files []string) {
	note := func(label string, found []string) bool {
		if len(found) == 0 {
			return false
		}
		if label != "" {
			basis = append(basis, label)
		}
		for _, f := range found {
			if !slices.Contains(files, f) {
				files = append(files, f)
			}
		}
		return true
	}
	for _, name := range tr.Activities {
		if note(name, e.Activities[name]) {
			activities = append(activities, name)
		}
	}
	for _, name := range tr.Tactics {
		note(name+" tools", e.Tactics[name])
	}
	// The files are gathered through a set for the same reason.
	held := map[string]bool{}
	for _, f := range files {
		held[f] = true
	}
	for _, kind := range tr.Exposed {
		if len(e.Exposed[kind]) > 0 {
			basis = append(basis, "exposed "+kind)
		}
		for _, x := range e.Exposed[kind] {
			for _, f := range x.Files {
				if !held[f] {
					held[f] = true
					files = append(files, f)
				}
			}
		}
	}
	if tr.Watchlist {
		for _, name := range sortedKeys(e.Hits) {
			note("watchlist "+name, e.Hits[name])
		}
	}
	if tr.Always && len(e.Activities)+len(e.Tactics) > 0 {
		basis = append(basis, "the premise of the tool")
		for _, name := range sortedKeys(e.Activities) {
			note("", e.Activities[name])
		}
		for _, name := range sortedKeys(e.Tactics) {
			note("", e.Tactics[name])
		}
	}
	sort.Strings(files)
	return basis, activities, files
}

// listed returns the exposed values the entry names, a bounded number of each kind.
func (tr trigger) listed(e Evidence) []Listed {
	var out []Listed
	for _, kind := range tr.Exposed {
		items := e.Exposed[kind]
		if len(items) == 0 {
			continue
		}
		// A set keeps this linear: a log can hold a hundred thousand addresses.
		l := Listed{Kind: kind}
		seen := map[string]bool{}
		for _, x := range items {
			if seen[x.Label] {
				continue
			}
			seen[x.Label] = true
			if len(l.Labels) < maxExposed {
				l.Labels = append(l.Labels, x.Label)
			}
		}
		l.More = len(seen) - len(l.Labels)
		out = append(out, l)
	}
	return out
}

func sortedKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
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
