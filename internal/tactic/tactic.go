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
	Commands []string `json:"commands"`
}

// Table maps command names to tactics.
type Table struct {
	byCommand map[string]string
}

// LoadTactics reads and validates the embedded tactics.json.
func LoadTactics() (Table, error) {
	entries, err := decode(raw)
	if err != nil {
		return Table{}, err
	}
	m := make(map[string]string, 512)
	for _, e := range entries {
		for _, c := range e.Commands {
			if prev, dup := m[c]; dup {
				return Table{}, fmt.Errorf("command %q in both %s and %s", c, prev, e.Tactic)
			}
			m[c] = e.Tactic
		}
	}
	return Table{byCommand: m}, nil
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
