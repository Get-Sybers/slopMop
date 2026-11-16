package command

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/get-sybers/slopmop/internal/render"
)

//go:embed nouns.json
var nounsJSON []byte

type nounSpec struct {
	Name    string     `json:"name"`
	Aliases []string   `json:"aliases"`
	Summary string     `json:"summary"`
	Verbs   []verbSpec `json:"verbs"`
}

type verbSpec struct {
	Name    string          `json:"name"`
	Aliases []string        `json:"aliases"`
	Summary string          `json:"summary"`
	Columns []render.Column `json:"columns"`
}

func loadNouns() ([]nounSpec, error) {
	return decodeNouns(nounsJSON)
}

func decodeNouns(data []byte) ([]nounSpec, error) {
	var doc struct {
		Nouns []nounSpec `json:"nouns"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("nouns.json: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("nouns.json: data after the document")
	}
	if len(doc.Nouns) == 0 {
		return nil, errors.New("nouns.json: no nouns")
	}
	for _, n := range doc.Nouns {
		if n.Name == "" || n.Summary == "" || len(n.Verbs) == 0 {
			return nil, fmt.Errorf("nouns.json: noun %q needs a name, a summary and a verb", n.Name)
		}
		for _, v := range n.Verbs {
			if v.Name == "" || v.Summary == "" {
				return nil, fmt.Errorf("nouns.json: %s: verb %q needs a name and a summary", n.Name, v.Name)
			}
			if len(v.Columns) == 0 {
				continue
			}
			if err := (render.Table{Columns: v.Columns}).Check(); err != nil {
				return nil, fmt.Errorf("nouns.json: %s %s: %w", n.Name, v.Name, err)
			}
		}
	}
	return doc.Nouns, nil
}
