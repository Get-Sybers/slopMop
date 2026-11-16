package render

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/get-sybers/slopmop/internal/golden"
)

func sampleReadout() Readout {
	return Readout{
		Title:  "slopmop   case42",
		Banner: Banner{Level: LevelHigh, Text: "HIGH - 2 impacts: 1 high, 1 low"},
		Sections: []Section{
			{Title: "Summary", Groups: []Group{{Entries: []Entry{
				{Cells: []string{"files", "3", "2 scripts, 1 output"}},
				{Cells: []string{"activities", "1", ""}},
			}}}},
			{Title: "Findings", Groups: []Group{
				{Title: "activities", Entries: []Entry{
					{Level: LevelHigh, Cells: []string{"LogDeletion", "1 line"}, Detail: []Detail{{Label: "in", Text: "a.sh"}}},
					{Level: LevelLow, Cells: []string{"Scan", "12 lines"}, Detail: []Detail{{Label: "in", Text: "b.sh"}, {Label: "watchlist"}}},
				}},
				{Title: "indicators"},
			}},
			{Title: "Impact", Note: "what it means", Groups: []Group{{Entries: []Entry{
				{Level: LevelMedium, Cells: []string{"Traces hidden"}, Detail: []Detail{{Text: "Files were removed."}, {Label: "basis", Text: "LogDeletion"}}},
			}}}},
			{Title: "Mitigation", Groups: []Group{{}}},
		},
		Hints: []string{"one section: slopmop <folder> impact"},
	}
}

func TestWriteReadout(t *testing.T) {
	for _, tt := range []struct {
		name   string
		colour bool
	}{{"readout", false}, {"readout-colour", true}} {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := WriteReadout(&out, sampleReadout(), tt.colour); err != nil {
				t.Fatal(err)
			}
			golden.Check(t, tt.name, out.Bytes())
			if hasEscape := strings.Contains(out.String(), "\x1b["); hasEscape != tt.colour {
				t.Errorf("ANSI codes present = %t, want %t", hasEscape, tt.colour)
			}
			for _, line := range strings.Split(out.String(), "\n") {
				if line != strings.TrimRight(line, " ") {
					t.Errorf("line %q ends in a space", line)
				}
			}
		})
	}
}

// Evidence reaches a readout in every text; none of it may reach the terminal raw.
func TestWriteReadoutEscapesEvidence(t *testing.T) {
	hostile := "x\x1b[2J\ny"
	r := Readout{
		Title:  hostile,
		Banner: Banner{Level: LevelClear, Text: hostile},
		Sections: []Section{{Title: hostile, Note: hostile, Groups: []Group{{Title: hostile, Entries: []Entry{
			{Level: LevelHigh, Cells: []string{hostile, hostile}, Detail: []Detail{{Label: "in", Text: hostile}, {Text: hostile}}},
		}}}}},
		Hints: []string{hostile},
	}
	var out bytes.Buffer
	if err := WriteReadout(&out, r, false); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(out.String(), '\x1b') {
		t.Errorf("an escape character reached the output: %q", out.String())
	}
	if got, want := strings.Count(out.String(), "\n"), 11; got != want {
		t.Errorf("%d lines, want %d: a line break in a text split a line\n%s", got, want, out.String())
	}
}

// One long cell does not push the next column off the screen for every row.
func TestWriteReadoutCapsAColumn(t *testing.T) {
	long := strings.Repeat("u", 90)
	r := Readout{Title: "t", Sections: []Section{{Title: "S", Groups: []Group{{Entries: []Entry{
		{Cells: []string{"URL", long, "a.sh"}},
		{Cells: []string{"IPv4", "192.0.2.1", "b.sh"}},
	}}}}}}
	var out bytes.Buffer
	if err := WriteReadout(&out, r, false); err != nil {
		t.Fatal(err)
	}
	want := "t\n\nS\n  URL   " + long + "  a.sh\n  IPv4  192.0.2.1" + strings.Repeat(" ", 51) + "  b.sh\n"
	if out.String() != want {
		t.Errorf("readout = %q, want %q", out.String(), want)
	}
}

func TestWriteReadoutPlainParts(t *testing.T) {
	var out bytes.Buffer
	if err := WriteReadout(&out, Readout{Title: "t", Sections: []Section{{Title: "Empty"}}}, false); err != nil {
		t.Fatal(err)
	}
	if got, want := out.String(), "t\n\nEmpty\n  none\n"; got != want {
		t.Errorf("readout = %q, want %q", got, want)
	}
	if err := WriteReadout(failingWriter{}, Readout{Title: "t"}, false); err == nil {
		t.Error("a failed write returned no error")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("closed") }
