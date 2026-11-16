// Package intel matches extracted indicators against a threat intelligence
// watchlist supplied by the operator.
package intel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/get-sybers/slopmop/internal/indicator"
)

type entry struct {
	Value       string `json:"value"`
	Type        string `json:"type"`
	Attribution string `json:"attribution"`
}

// Hit records one indicator that matched the watchlist.
type Hit struct {
	Value       string
	Type        string
	Attribution string
}

// Watchlist holds the parsed entries from an operator-supplied file.
type Watchlist struct {
	entries []entry
}

// LoadWatchlist decodes a JSON watchlist from raw bytes.
func LoadWatchlist(data []byte) (Watchlist, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var entries []entry
	if err := dec.Decode(&entries); err != nil {
		return Watchlist{}, fmt.Errorf("intel watchlist: %w", err)
	}
	if dec.More() {
		return Watchlist{}, fmt.Errorf("intel watchlist: trailing data")
	}
	for i, e := range entries {
		if e.Value == "" {
			return Watchlist{}, fmt.Errorf("intel watchlist[%d]: empty value", i)
		}
		if e.Attribution == "" {
			return Watchlist{}, fmt.Errorf("intel watchlist[%d]: empty attribution", i)
		}
		entries[i].Value = strings.ToLower(e.Value)
	}
	return Watchlist{entries: entries}, nil
}

// Match checks extracted indicators against the watchlist and returns every
// hit. A match is case-insensitive on the indicator value. When an entry
// specifies a type, the indicator's type must also match.
func (w Watchlist) Match(indicators []indicator.Match) []Hit {
	var hits []Hit
	seen := map[string]bool{}
	for _, ind := range indicators {
		low := strings.ToLower(ind.Value)
		for _, e := range w.entries {
			if e.Value != low {
				continue
			}
			if e.Type != "" && !strings.EqualFold(e.Type, ind.Type) {
				continue
			}
			key := low + "\x00" + e.Attribution
			if seen[key] {
				continue
			}
			seen[key] = true
			hits = append(hits, Hit{
				Value:       ind.Value,
				Type:        ind.Type,
				Attribution: e.Attribution,
			})
		}
	}
	return hits
}

// Len returns the number of entries in the watchlist.
func (w Watchlist) Len() int { return len(w.entries) }
