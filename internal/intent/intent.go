// Package intent names the ARTEX intent a file of evidence belongs to. ARTEX
// gives each intent a run folder, tasks/<task>/i<number>, and a session name.
package intent

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
)

//go:embed paths.json
var raw []byte

const (
	groupID   = "id"
	groupTask = "task"
)

type ruleSpec struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
}

type rule struct {
	rx       *regexp.Regexp
	id, task int
}

// Table holds the rules that find an intent in a path, in the order they are tried.
type Table struct {
	rules  []rule
	reject []string
}

// Ref names an intent, and its task where the path gives one.
type Ref struct {
	ID   string
	Task string
}

// Load decodes and validates the embedded rules.
func Load() (Table, error) {
	return decode(raw)
}

func decode(data []byte) (Table, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var doc struct {
		Rules  []ruleSpec `json:"rules"`
		Reject []string   `json:"reject"`
	}
	if err := dec.Decode(&doc); err != nil {
		return Table{}, fmt.Errorf("paths.json: %w", err)
	}
	if dec.More() {
		return Table{}, errors.New("paths.json: trailing data")
	}
	if len(doc.Rules) == 0 {
		return Table{}, errors.New("paths.json: no rules")
	}
	table := Table{reject: doc.Reject}
	names := map[string]bool{}
	for _, spec := range doc.Rules {
		if spec.Name == "" || names[spec.Name] {
			return Table{}, fmt.Errorf("paths.json: the rule name %q is empty or used twice", spec.Name)
		}
		names[spec.Name] = true
		rx, err := regexp.Compile(spec.Pattern)
		if err != nil {
			return Table{}, fmt.Errorf("paths.json: %s: %w", spec.Name, err)
		}
		r := rule{rx: rx, id: rx.SubexpIndex(groupID), task: rx.SubexpIndex(groupTask)}
		if r.id < 0 {
			return Table{}, fmt.Errorf("paths.json: %s has no group named %s", spec.Name, groupID)
		}
		for _, group := range rx.SubexpNames() {
			if group != "" && group != groupID && group != groupTask {
				return Table{}, fmt.Errorf("paths.json: %s names the group %q, which is neither %s nor %s", spec.Name, group, groupID, groupTask)
			}
		}
		table.rules = append(table.rules, r)
	}
	for i, id := range doc.Reject {
		if id == "" || slices.Contains(doc.Reject[:i], id) {
			return Table{}, fmt.Errorf("paths.json: the rejected name %q is empty or listed twice", id)
		}
	}
	return table, nil
}

// Of returns the intent a slash-separated path lies in. The first rule that
// matches decides, by its last match: the folder nearest the file.
func (t Table) Of(path string) (Ref, bool) {
	for _, r := range t.rules {
		found := r.rx.FindAllStringSubmatch(path, -1)
		for i := len(found) - 1; i >= 0; i-- {
			ref := Ref{ID: found[i][r.id]}
			if r.task >= 0 {
				ref.Task = found[i][r.task]
			}
			if !slices.Contains(t.reject, ref.ID) {
				return ref, true
			}
		}
	}
	return Ref{}, false
}
