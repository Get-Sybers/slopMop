// Package structured extracts the text values and the recorded commands
// from JSON, XML and HTML reports.
package structured

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

//go:embed formats.json
var raw []byte

// Format names one structured file format.
type Format string

const (
	JSON Format = "json"
	XML  Format = "xml"
	HTML Format = "html"
)

// Report is what one structured file yields. Values holds every decoded
// text value in document order; Commands holds the values a command field
// or command element carries.
type Report struct {
	Values   []string
	Commands []string
}

type formatSpec struct {
	Name       Format   `json:"name"`
	Extensions []string `json:"extensions"`
}

type document struct {
	Formats          []formatSpec `json:"formats"`
	CommandFields    []string     `json:"command_fields"`
	CommandElements  []string     `json:"command_elements"`
	VerbatimElements []string     `json:"verbatim_elements"`
	DroppedElements  []string     `json:"dropped_elements"`
}

// Table holds the validated contents of formats.json.
type Table struct {
	byExtension     map[string]Format
	commandFields   map[string]bool
	commandElements map[string]bool
	verbatim        map[string]bool
	dropped         map[string]bool
}

// LoadFormats reads and validates the embedded formats.json.
func LoadFormats() (Table, error) {
	return decodeFormats(raw)
}

func decodeFormats(data []byte) (Table, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var doc document
	if err := dec.Decode(&doc); err != nil {
		return Table{}, fmt.Errorf("formats.json: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Table{}, errors.New("formats.json: data after the document")
	}
	t, err := checkFormats(doc)
	if err != nil {
		return Table{}, fmt.Errorf("formats.json: %w", err)
	}
	return t, nil
}

func checkFormats(doc document) (Table, error) {
	want := []Format{JSON, XML, HTML}
	if len(doc.Formats) != len(want) {
		return Table{}, fmt.Errorf("%d formats, want %d", len(doc.Formats), len(want))
	}
	t := Table{byExtension: map[string]Format{}}
	for i, f := range doc.Formats {
		if f.Name != want[i] {
			return Table{}, fmt.Errorf("format %d is %q, want %q", i+1, f.Name, want[i])
		}
		if len(f.Extensions) == 0 {
			return Table{}, fmt.Errorf("format %q has no extensions", f.Name)
		}
		for _, ext := range f.Extensions {
			if len(ext) < 2 || ext[0] != '.' || ext != strings.ToLower(ext) {
				return Table{}, fmt.Errorf("format %q: extension %q is not a lower-case dot extension", f.Name, ext)
			}
			if prev, taken := t.byExtension[ext]; taken {
				return Table{}, fmt.Errorf("extension %q is in %q and %q", ext, prev, f.Name)
			}
			t.byExtension[ext] = f.Name
		}
	}
	if len(doc.CommandFields) == 0 {
		return Table{}, errors.New("no command fields")
	}
	lists := []struct {
		label string
		names []string
		into  *map[string]bool
	}{
		{"command field", doc.CommandFields, &t.commandFields},
		{"command element", doc.CommandElements, &t.commandElements},
		{"verbatim element", doc.VerbatimElements, &t.verbatim},
		{"dropped element", doc.DroppedElements, &t.dropped},
	}
	elements := map[string]string{}
	for i, l := range lists {
		set := map[string]bool{}
		for _, name := range l.names {
			if name == "" || name != normalise(name) {
				return Table{}, fmt.Errorf("%s %q is not lower-case letters and digits", l.label, name)
			}
			if set[name] {
				return Table{}, fmt.Errorf("%s %q is listed twice", l.label, name)
			}
			set[name] = true
			// The three element lists share one namespace; the fields have their own.
			if i == 0 {
				continue
			}
			if prev, taken := elements[name]; taken {
				return Table{}, fmt.Errorf("element %q is a %s and a %s", name, prev, l.label)
			}
			elements[name] = l.label
		}
		*l.into = set
	}
	return t, nil
}

// normalise folds a field name so that "CommandLine", "command_line" and
// "command-line" compare equal.
func normalise(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Detect names the format of a file by its lower-cased extension.
func (t Table) Detect(name string) (Format, bool) {
	i := strings.LastIndexByte(name, '.')
	if i < 0 {
		return "", false
	}
	f, ok := t.byExtension[strings.ToLower(name[i:])]
	return f, ok
}

// Extract decodes text as the named format. An error means the text is not
// well formed and the caller reads it as plain text instead.
func (t Table) Extract(f Format, text string) (Report, error) {
	switch f {
	case JSON:
		return t.extractJSON(text)
	case XML:
		return t.extractXML(text)
	case HTML:
		return t.extractHTML(text), nil
	}
	return Report{}, fmt.Errorf("unknown format %q", f)
}

func (r *Report) addValue(s string) {
	if s = strings.TrimSpace(s); s != "" {
		r.Values = append(r.Values, s)
	}
}

func (r *Report) addCommand(s string) {
	if s = strings.TrimSpace(s); s != "" {
		r.Commands = append(r.Commands, s)
	}
}
