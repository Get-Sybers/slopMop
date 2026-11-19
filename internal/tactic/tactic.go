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
	// places holds where each command stands, and filed the techniques of
	// a tactic that have commands.
	places   map[string][]Place
	filed    map[string][]string
	severity map[string]Severity
	ids      map[string][2]string
	names    []string
}

// Place is where a command stands in the table: a tactic, and the technique
// it is filed under there. Technique is "" where its technique is not named.
type Place struct {
	Tactic, Technique string
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
		places: make(map[string][]Place, 512), filed: map[string][]string{},
		severity: make(map[string]Severity, len(entries)), ids: make(map[string][2]string, len(entries)),
	}
	// A command stands once under a technique. Its technique is not named in
	// one tactic at most, and in none that files it under a technique.
	place := func(command, tactic, technique string) error {
		for _, at := range t.places[command] {
			switch {
			case at == (Place{tactic, technique}):
				return fmt.Errorf("command %q stands twice in %s%s", command, tactic, under(technique))
			case at.Tactic == tactic && (at.Technique == "" || technique == ""):
				return fmt.Errorf("command %q of %s stands under a technique and under none", command, tactic)
			case at.Technique == "" && technique == "":
				return fmt.Errorf("command %q in both %s and %s", command, at.Tactic, tactic)
			}
		}
		t.places[command] = append(t.places[command], Place{tactic, technique})
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

// under names a technique in a message, and says nothing of one not named.
func under(technique string) string {
	if technique == "" {
		return ""
	}
	return " under " + technique
}

// Classify returns where a command stands, in the order of the data file,
// the techniques of a tactic by their identifiers. An unknown command has no place.
func (t Table) Classify(command string) []Place {
	return t.places[t.known(command)]
}

// Tactics returns the tactics of a command, each once, in the order of the data file.
func (t Table) Tactics(command string) []string {
	var names []string
	for _, at := range t.Classify(command) {
		if !slices.Contains(names, at.Tactic) {
			names = append(names, at.Tactic)
		}
	}
	return names
}

// known returns the name the table holds a command under: the command in
// lower case, or that name without .exe or .py. An unknown command has none.
func (t Table) known(command string) string {
	low := strings.ToLower(command)
	if _, ok := t.places[low]; ok {
		return low
	}
	for _, suffix := range []string{".exe", ".py"} {
		if bare := strings.TrimSuffix(low, suffix); bare != low {
			if _, ok := t.places[bare]; ok {
				return bare
			}
		}
	}
	return ""
}
