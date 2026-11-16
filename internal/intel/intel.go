// Package intel matches extracted indicators against a threat intelligence
// watchlist supplied by the operator.
package intel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"github.com/get-sybers/slopmop/internal/indicator"
)

type entry struct {
	Value       string `json:"value"`
	Type        string `json:"type"`
	Attribution string `json:"attribution"`
	// prefix is set when Value is an address range such as 144.172.64.0/24.
	prefix netip.Prefix
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

// LoadWatchlist decodes a watchlist from raw bytes: a JSON array of
// entries, or a STIX 2.1 bundle, which is a JSON object.
func LoadWatchlist(data []byte) (Watchlist, error) {
	if trimmed := bytes.TrimLeft(data, " \t\r\n"); len(trimmed) > 0 && trimmed[0] == '{' {
		return loadBundle(data)
	}
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
	return Watchlist{entries: withPrefixes(entries)}, nil
}

// withPrefixes marks the entries whose value is an address range.
func withPrefixes(entries []entry) []entry {
	for i, e := range entries {
		if p, err := netip.ParsePrefix(e.Value); err == nil {
			entries[i].prefix = p.Masked()
		}
	}
	return entries
}

type bundle struct {
	Type    string         `json:"type"`
	Objects []bundleObject `json:"objects"`
}

type bundleObject struct {
	Type        string `json:"type"`
	ID          string `json:"id"`
	Name        string `json:"name"`
	Pattern     string `json:"pattern"`
	PatternType string `json:"pattern_type"`
}

// loadBundle reads the indicator objects of a STIX 2.1 bundle. Every quoted
// literal an equality compares in a STIX pattern becomes one entry,
// attributed to the indicator's name, or to its id when it has none.
func loadBundle(data []byte) (Watchlist, error) {
	var b bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return Watchlist{}, fmt.Errorf("intel watchlist: %w", err)
	}
	if b.Type != "bundle" {
		return Watchlist{}, fmt.Errorf("intel watchlist: object type %q, want a STIX bundle", b.Type)
	}
	literal := regexp.MustCompile(`=\s*'((?:[^'\\]|\\.)*)'`)
	unescape := strings.NewReplacer(`\'`, `'`, `\\`, `\`)
	var entries []entry
	for _, o := range b.Objects {
		if o.Type != "indicator" || (o.PatternType != "" && o.PatternType != "stix") {
			continue
		}
		attribution := o.Name
		if attribution == "" {
			attribution = o.ID
		}
		if attribution == "" {
			continue
		}
		for _, m := range literal.FindAllStringSubmatch(o.Pattern, -1) {
			if value := unescape.Replace(m[1]); value != "" {
				entries = append(entries, entry{Value: strings.ToLower(value), Attribution: attribution})
			}
		}
	}
	return Watchlist{entries: withPrefixes(entries)}, nil
}

// Match returns every watchlist hit: a case-insensitive match on the value,
// or an address inside an entry that is a range. An entry's type, when it
// has one, must also match.
func (w Watchlist) Match(indicators []indicator.Match) []Hit {
	var hits []Hit
	seen := map[string]bool{}
	for _, ind := range indicators {
		low := strings.ToLower(ind.Value)
		addr, isAddr := netip.Addr{}, false
		if a, err := netip.ParseAddr(low); err == nil {
			addr, isAddr = a, true
		}
		for _, e := range w.entries {
			inRange := isAddr && e.prefix.IsValid() && e.prefix.Contains(addr)
			if e.Value != low && !inRange {
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

// Campaign is one attribution and the number of watchlist entries that name it.
type Campaign struct {
	Attribution string
	Entries     int
}

// Campaigns lists the distinct attributions, sorted by name.
func (w Watchlist) Campaigns() []Campaign {
	counts := map[string]int{}
	for _, e := range w.entries {
		counts[e.Attribution]++
	}
	campaigns := make([]Campaign, 0, len(counts))
	for name, n := range counts {
		campaigns = append(campaigns, Campaign{Attribution: name, Entries: n})
	}
	sort.Slice(campaigns, func(i, j int) bool { return campaigns[i].Attribution < campaigns[j].Attribution })
	return campaigns
}
