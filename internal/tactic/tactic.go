// Package tactic says what a command is by its name: the MITRE ATT&CK
// technique it is, and the tactic that technique is of.
package tactic

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

//go:embed tactics.json
var raw []byte

type entry struct {
	Tactic   string   `json:"tactic"`
	Severity Severity `json:"severity"`
	// ID and Atlas are the tactic's identifiers in ATT&CK and in ATLAS.
	ID    string `json:"id"`
	Atlas string `json:"atlas"`
	// Techniques files a command under the ATT&CK technique it is. Commands
	// holds the commands of the tactic whose technique is not named.
	Techniques map[string][]string `json:"techniques,omitempty"`
	Commands   []string            `json:"commands,omitempty"`
}

// Table maps command names to techniques and to tactics.
type Table struct {
	byCommand map[string]string
	// technique is the technique a command is filed under, and filed the
	// techniques of a tactic that have commands.
	technique map[string]string
	filed     map[string][]string
	severity  map[string]Severity
	ids       map[string][2]string
	names     []string
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
	return Parse(raw)
}

// Parse reads and validates a table written as tactics.json is.
func Parse(data []byte) (Table, error) {
	entries, err := decode(data)
	if err != nil {
		return Table{}, err
	}
	t := Table{
		byCommand: make(map[string]string, 512), technique: map[string]string{}, filed: map[string][]string{},
		severity: make(map[string]Severity, len(entries)), ids: make(map[string][2]string, len(entries)),
	}
	// A command stands once in the table, under one technique or under none.
	place := func(command, tactic, technique string) error {
		if prev, dup := t.byCommand[command]; dup {
			return fmt.Errorf("command %q in both %s and %s", command, prev, tactic)
		}
		t.byCommand[command] = tactic
		if technique != "" {
			t.technique[command] = technique
		}
		return nil
	}
	for _, e := range entries {
		t.severity[e.Tactic] = e.Severity
		t.ids[e.Tactic] = [2]string{e.ID, e.Atlas}
		t.names = append(t.names, e.Tactic)
		for id := range e.Techniques {
			t.filed[e.Tactic] = append(t.filed[e.Tactic], id)
		}
		slices.Sort(t.filed[e.Tactic])
		for _, id := range t.filed[e.Tactic] {
			for _, c := range e.Techniques[id] {
				if err := place(c, e.Tactic, id); err != nil {
					return Table{}, err
				}
			}
		}
		for _, c := range e.Commands {
			if err := place(c, e.Tactic, ""); err != nil {
				return Table{}, err
			}
		}
	}
	return t, nil
}

// Techniques lists the ATT&CK techniques the commands of a tactic are filed
// under, by identifier, so a caller that holds the catalogue can check them.
func (t Table) Techniques(tactic string) []string {
	return t.filed[tactic]
}

// Names lists the tactics, in the order of the data file.
func (t Table) Names() []string {
	return t.names
}

// Attack is the tactic's identifier in ATT&CK, or "" for a name the table lacks.
func (t Table) Attack(tactic string) string {
	return t.ids[tactic][0]
}

// Atlas is the tactic's identifier in ATLAS, or "" for a name the table lacks.
func (t Table) Atlas(tactic string) string {
	return t.ids[tactic][1]
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
		if e.ID == "" || e.Atlas == "" {
			return nil, fmt.Errorf("tactics.json[%d] (%s): an ATT&CK and an ATLAS identifier are both needed", i, e.Tactic)
		}
		if len(e.Commands) == 0 && len(e.Techniques) == 0 {
			return nil, fmt.Errorf("tactics.json[%d] (%s): no commands", i, e.Tactic)
		}
		for id, commands := range e.Techniques {
			if id == "" || len(commands) == 0 {
				return nil, fmt.Errorf("tactics.json[%d] (%s): the technique %q has no name or no command", i, e.Tactic, id)
			}
		}
	}
	return entries, nil
}

// Classify returns the tactic for a command, or "" when unknown.
func (t Table) Classify(command string) string {
	return t.byCommand[t.known(command)]
}

// Technique returns the ATT&CK technique a command is, or "" when the table
// names none for it: the tactic of the command then stands without one.
func (t Table) Technique(command string) string {
	return t.technique[t.known(command)]
}

// known returns the name the table holds a command under: the command in
// lower case, or that name without .exe or .py. An unknown command has none.
func (t Table) known(command string) string {
	low := strings.ToLower(command)
	if _, ok := t.byCommand[low]; ok {
		return low
	}
	for _, suffix := range []string{".exe", ".py"} {
		if bare := strings.TrimSuffix(low, suffix); bare != low {
			if _, ok := t.byCommand[bare]; ok {
				return bare
			}
		}
	}
	return ""
}
