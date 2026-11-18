package exposure

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// accountEntry says what collecting an account shows, by the shape of the
// account: the account itself, how it stands on a line, or its being of a
// service the table names. An entry with none of the three fits any account.
type accountEntry struct {
	Activity  string `json:"activity"`
	Technique string `json:"technique"`
	Value     string `json:"value,omitempty"`
	// Line is an expression with a group named account, where an account
	// of this shape stands on a line.
	Line    string `json:"line,omitempty"`
	Service bool   `json:"service,omitempty"`
}

// Shown is what collecting an account shows: an activity, and the ATT&CK
// technique the activity is.
type Shown struct {
	Activity, Technique string
}

type shape struct {
	Shown
	value, line *regexp.Regexp
	// account is the group of line that holds the account.
	account int
	service bool
}

// shapes compiles the entries, in the order of the data file: the first
// shape an account fits is its own.
func shapes(entries []accountEntry) ([]shape, error) {
	technique := map[string]string{}
	out := make([]shape, 0, len(entries))
	for i, e := range entries {
		if e.Activity == "" || e.Technique == "" {
			return nil, fmt.Errorf("accounts[%d]: an activity and a technique are both needed", i)
		}
		if prev, ok := technique[e.Activity]; ok && prev != e.Technique {
			return nil, fmt.Errorf("accounts[%d]: %s is %s and %s", i, e.Activity, prev, e.Technique)
		}
		technique[e.Activity] = e.Technique
		s := shape{Shown: Shown{Activity: e.Activity, Technique: e.Technique}, service: e.Service}
		var err error
		if s.value, err = optional(e.Value); err != nil {
			return nil, fmt.Errorf("accounts[%d]: %w", i, err)
		}
		if s.line, err = optional(e.Line); err != nil {
			return nil, fmt.Errorf("accounts[%d]: %w", i, err)
		}
		if s.line != nil {
			if s.account = s.line.SubexpIndex("account"); s.account < 0 {
				return nil, fmt.Errorf("accounts[%d]: the line has no group named account", i)
			}
		}
		out = append(out, s)
	}
	return out, nil
}

// Collected returns what a line that names a collected account shows: the
// first shape that fits the account by itself, by what it is of or by how it
// stands on the line. Plain says the shape fits any account; no other kind fits.
func (t Table) Collected(kind, value string, services []string, line string) (shown Shown, plain, ok bool) {
	if !slices.ContainsFunc(t.kinds, func(k compiledKind) bool { return k.Name == kind && k.Account }) {
		return Shown{}, false, false
	}
	served := slices.ContainsFunc(services, func(name string) bool {
		return slices.ContainsFunc(t.services, func(s service) bool { return s.Name == name })
	})
	for _, s := range t.accounts {
		switch {
		case s.service && !served:
		case s.value != nil && !s.value.MatchString(value):
		case s.line != nil && !s.stands(line, value):
		default:
			return s.Shown, s.value == nil && s.line == nil && !s.service, true
		}
	}
	return Shown{}, false, false
}

// stands reports whether the account stands on the line where the shape says one does.
func (s shape) stands(line, value string) bool {
	for _, m := range s.line.FindAllStringSubmatch(line, -1) {
		if strings.EqualFold(m[s.account], value) {
			return true
		}
	}
	return false
}

// Shows lists what collecting an account can show, each activity once, so a
// caller that holds the other tables can check its name and its technique.
func (t Table) Shows() []Shown {
	var out []Shown
	for _, s := range t.accounts {
		if !slices.Contains(out, s.Shown) {
			out = append(out, s.Shown)
		}
	}
	return out
}
