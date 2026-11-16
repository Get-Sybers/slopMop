// Package tactic classifies commands by MITRE ATT&CK tactic.
package tactic

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
)

//go:embed tactics.json
var raw []byte

type entry struct {
	Tactic   string   `json:"tactic"`
	Severity Severity `json:"severity"`
	Commands []string `json:"commands"`
}

// Table maps command names to tactics.
type Table struct {
	byCommand map[string]string
	severity  map[string]Severity
}

// Severity ranks a tactic; a higher value is more severe.
type Severity string

const (
	Low    Severity = "low"
	Medium Severity = "medium"
	High   Severity = "high"
)

// Rank orders severities: low 1, medium 2, high 3, anything else 0.
func (s Severity) Rank() int {
	switch s {
	case Low:
		return 1
	case Medium:
		return 2
	case High:
		return 3
	}
	return 0
}

// Severity is the severity of a tactic, or Low for a name the table lacks.
func (t Table) Severity(tactic string) Severity {
	if s, ok := t.severity[tactic]; ok {
		return s
	}
	return Low
}

// Has reports whether the table declares the tactic.
func (t Table) Has(tactic string) bool {
	_, ok := t.severity[tactic]
	return ok
}

// LoadTactics reads and validates the embedded tactics.json.
func LoadTactics() (Table, error) {
	entries, err := decode(raw)
	if err != nil {
		return Table{}, err
	}
	m := make(map[string]string, 512)
	severity := make(map[string]Severity, len(entries))
	for _, e := range entries {
		severity[e.Tactic] = e.Severity
		for _, c := range e.Commands {
			if prev, dup := m[c]; dup {
				return Table{}, fmt.Errorf("command %q in both %s and %s", c, prev, e.Tactic)
			}
			m[c] = e.Tactic
		}
	}
	return Table{byCommand: m, severity: severity}, nil
}

func decode(data []byte) ([]entry, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var entries []entry
	if err := dec.Decode(&entries); err != nil {
		return nil, fmt.Errorf("tactics.json: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("tactics.json: trailing data")
	}
	for i, e := range entries {
		if e.Tactic == "" {
			return nil, fmt.Errorf("tactics.json[%d]: empty tactic", i)
		}
		if e.Severity.Rank() == 0 {
			return nil, fmt.Errorf("tactics.json[%d] (%s): severity %q is not low, medium or high", i, e.Tactic, e.Severity)
		}
		if len(e.Commands) == 0 {
			return nil, fmt.Errorf("tactics.json[%d] (%s): no commands", i, e.Tactic)
		}
	}
	return entries, nil
}

// Classify returns the tactic for a command, or "" when unknown.
func (t Table) Classify(command string) string {
	low := strings.ToLower(command)
	if tac, ok := t.byCommand[low]; ok {
		return tac
	}
	for _, suffix := range []string{".exe", ".py"} {
		bare := strings.TrimSuffix(low, suffix)
		if bare != low {
			if tac, ok := t.byCommand[bare]; ok {
				return tac
			}
		}
	}
	return ""
}
