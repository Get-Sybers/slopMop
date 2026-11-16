package structured

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// extractJSON reads every document in text, so JSON Lines is read whole.
func (t Table) extractJSON(text string) (Report, error) {
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	var r Report
	for {
		var doc any
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			return r, nil
		}
		if err != nil {
			return Report{}, fmt.Errorf("json: %w", err)
		}
		t.walkJSON(doc, false, &r)
	}
}

// walkJSON visits keys in byte order so the report is deterministic. A key
// is a value too: reports key maps by address or hash.
func (t Table) walkJSON(v any, command bool, r *Report) {
	switch x := v.(type) {
	case string:
		r.addValue(x)
		if command {
			r.addCommand(x)
		}
	case []any:
		for _, item := range x {
			t.walkJSON(item, false, r)
		}
		if command {
			for _, c := range listCommands(x) {
				r.addCommand(c)
			}
		}
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			r.addValue(k)
			t.walkJSON(x[k], t.commandFields[normalise(k)], r)
		}
	}
}

// listCommands reads the strings of a list under a command field. A list
// whose items hold no space is one argument vector; otherwise each item is
// a command line.
func listCommands(items []any) []string {
	var words []string
	spaced := false
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			continue
		}
		words = append(words, s)
		spaced = spaced || strings.ContainsAny(strings.TrimSpace(s), " \t\n")
	}
	if spaced || len(words) == 0 {
		return words
	}
	return []string{strings.Join(words, " ")}
}
