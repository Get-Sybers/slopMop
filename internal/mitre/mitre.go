// Package mitre holds the identifiers, names and mitigation links of MITRE
// ATT&CK and MITRE ATLAS that the other tables refer to. catalogue.json is
// written by scripts/mitre.py from the two upstream files.
package mitre

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
)

//go:embed catalogue.json
var raw []byte

// Framework is one knowledge base: ATT&CK or ATLAS.
type Framework struct {
	Version     string                `json:"version"`
	Tactics     map[string]string     `json:"tactics"`
	Mitigations map[string]mitigation `json:"mitigations"`
	Techniques  map[string]technique  `json:"techniques"`
}

type mitigation struct {
	Name    string `json:"name"`
	Summary string `json:"summary"`
}

type technique struct {
	Name string `json:"name"`
	// Attack is the ATT&CK technique an ATLAS technique refers to.
	Attack      string   `json:"attack,omitempty"`
	Tactics     []string `json:"tactics"`
	Mitigations []string `json:"mitigations"`
}

// Catalogue is the two frameworks.
type Catalogue struct {
	Attack Framework `json:"attack"`
	Atlas  Framework `json:"atlas"`
}

// Mitigation is a mitigation and the techniques, of those asked about, that
// the framework says it addresses.
type Mitigation struct {
	ID         string
	Name       string
	Summary    string
	Techniques []string
}

// Load decodes and validates the embedded catalogue.
func Load() (Catalogue, error) {
	return decode(raw)
}

func decode(data []byte) (Catalogue, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var c Catalogue
	if err := dec.Decode(&c); err != nil {
		return Catalogue{}, fmt.Errorf("catalogue.json: %w", err)
	}
	if dec.More() {
		return Catalogue{}, fmt.Errorf("catalogue.json: trailing data")
	}
	for name, f := range map[string]Framework{"attack": c.Attack, "atlas": c.Atlas} {
		if err := f.check(); err != nil {
			return Catalogue{}, fmt.Errorf("catalogue.json %s: %w", name, err)
		}
	}
	return c, nil
}

func (f Framework) check() error {
	if f.Version == "" || len(f.Tactics) == 0 || len(f.Techniques) == 0 || len(f.Mitigations) == 0 {
		return fmt.Errorf("a version, tactics, techniques and mitigations are all needed")
	}
	for id, t := range f.Techniques {
		if t.Name == "" {
			return fmt.Errorf("%s has no name", id)
		}
		for _, tactic := range t.Tactics {
			if _, ok := f.Tactics[tactic]; !ok {
				return fmt.Errorf("%s names the tactic %s, which is not listed", id, tactic)
			}
		}
		for _, m := range t.Mitigations {
			if _, ok := f.Mitigations[m]; !ok {
				return fmt.Errorf("%s names the mitigation %s, which is not listed", id, m)
			}
		}
	}
	return nil
}

// HasTechnique reports whether the framework lists the technique.
func (f Framework) HasTechnique(id string) bool {
	_, ok := f.Techniques[id]
	return ok
}

// HasTactic reports whether the framework lists the tactic.
func (f Framework) HasTactic(id string) bool {
	_, ok := f.Tactics[id]
	return ok
}

// NameOf returns the name of the technique as the framework writes it in
// full, a sub-technique after the technique it is part of, or none.
func (f Framework) NameOf(technique string) string {
	own, ok := f.Techniques[technique]
	if !ok {
		return ""
	}
	if dot := strings.LastIndexByte(technique, '.'); dot > 0 {
		if whole, ok := f.Techniques[technique[:dot]]; ok {
			return whole.Name + ": " + own.Name
		}
	}
	return own.Name
}

// TacticsOf returns the tactics the framework files the technique under.
func (f Framework) TacticsOf(technique string) []string {
	return f.Techniques[technique].Tactics
}

// MitigationsFor returns the mitigations that address any of the techniques,
// by identifier, each with the techniques it addresses.
func (f Framework) MitigationsFor(techniques []string) []Mitigation {
	byID := map[string]*Mitigation{}
	for _, t := range techniques {
		for _, id := range f.Techniques[t].Mitigations {
			m, ok := byID[id]
			if !ok {
				m = &Mitigation{ID: id, Name: f.Mitigations[id].Name, Summary: f.Mitigations[id].Summary}
				byID[id] = m
			}
			if !slices.Contains(m.Techniques, t) {
				m.Techniques = append(m.Techniques, t)
			}
		}
	}
	found := make([]Mitigation, 0, len(byID))
	for _, m := range byID {
		sort.Strings(m.Techniques)
		found = append(found, *m)
	}
	sort.Slice(found, func(i, j int) bool { return found[i].ID < found[j].ID })
	return found
}

// AtlasFor returns the ATLAS techniques that refer to one of the ATT&CK
// techniques or to the technique it is a part of, by identifier.
func (c Catalogue) AtlasFor(attack []string) []string {
	var found []string
	for id, t := range c.Atlas.Techniques {
		for _, a := range attack {
			parent, _, _ := strings.Cut(a, ".")
			if t.Attack != "" && (t.Attack == a || t.Attack == parent) && !slices.Contains(found, id) {
				found = append(found, id)
			}
		}
	}
	sort.Strings(found)
	return found
}
