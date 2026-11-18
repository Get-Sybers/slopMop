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
			{Title: "Summary", Groups: []Group{{Columns: []string{"item", "count", "of which"}, Entries: []Entry{
				{Cells: []string{"files", "3", "2 scripts, 1 output"}},
				{Cells: []string{"activities", "1", ""}},
			}}}},
			{Title: "Findings", Groups: []Group{
				{Title: "activities", Columns: []string{"activity"}, Entries: []Entry{
					{Level: LevelHigh, Cells: []string{"LogDeletion", "1 line"}, Detail: []Detail{{Label: "in", Text: "a.sh"}}},
					{Level: LevelLow, Cells: []string{"Scan", "12 lines"}, Detail: []Detail{{Label: "in", Text: "b.sh"}, {Label: "watchlist"}}},
				}},
				{Title: "indicators"},
			}},
			{Title: "Impact", Note: "what it means", Groups: []Group{{Entries: []Entry{
				{Level: LevelMedium, Cells: []string{"Traces hidden"}, Detail: []Detail{{Text: "Files were removed."}, {Label: "basis", Text: "LogDeletion"}}},
			}}}},
			{Title: "Intent timeline", Note: "a block for each intent", Groups: []Group{{Blocks: true, Entries: []Entry{
				{Level: LevelHigh, Cells: []string{"i7", "2026-10-22T09:00:00Z to 2026-10-22T09:05:00Z"}, Detail: []Detail{
					{Label: "Discovery", Note: "TA0007, AML.TA0008", Key: "T1083", Text: "File and Directory Discovery"},
					{Label: "Discovery", Note: "TA0007, AML.TA0008", Key: "AML.T0075", Text: "Enterprise Resource Discovery"},
					{Label: "CredentialAccess", Note: "TA0006, AML.TA0013", Key: "AML.T0055", Text: "Unsecured Credentials"},
					{Label: "Exfiltration", Note: "TA0010, AML.TA0010", Text: "no technique", None: true},
					{Label: "watchlist", Text: "APT-EXAMPLE: 203.0.113.9"},
				}},
				{Cells: []string{"i8", "2026-10-22T09:10:00Z"}, Detail: []Detail{{Text: "no technique"}}},
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
			{Level: LevelHigh, Cells: []string{hostile, hostile}, Detail: []Detail{{Label: "in", Note: hostile, Key: hostile, Text: hostile}, {Text: hostile}}},
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

// Lines that share a label stand under it; the label is written once.
func TestWriteReadoutSharesALabel(t *testing.T) {
	r := Readout{Title: "t", Sections: []Section{{Title: "S", Groups: []Group{{Entries: []Entry{{
		Cells: []string{"entry"},
		Detail: []Detail{
			{Text: "a sentence"}, {Label: "what", Text: "first"}, {Label: "what", Text: "second"},
			{Label: "what"}, {Label: "basis", Text: "third"}, {Label: "what", Text: "fourth"},
		},
	}}}}}}}
	var out bytes.Buffer
	if err := WriteReadout(&out, r, false); err != nil {
		t.Fatal(err)
	}
	want := "t\n\nS\n  entry\n      a sentence\n      what   first\n             second\n      basis  third\n      what   fourth\n"
	if out.String() != want {
		t.Errorf("readout = %q, want %q", out.String(), want)
	}
}

// The labels, their notes and the keys of a group each stand in one column,
// whichever entry a line is under, and a label is written once with its note.
func TestWriteReadoutLinesUpDetail(t *testing.T) {
	r := Readout{Title: "t", Sections: []Section{{Title: "S", Groups: []Group{{Blocks: true, Entries: []Entry{
		{Cells: []string{"one"}, Detail: []Detail{
			{Label: "Discovery", Note: "TA0007", Key: "T1083", Text: "first"},
			{Label: "Discovery", Note: "TA0007", Key: "AML.T0075", Text: "second"},
			{Label: "Exfiltration", Note: "TA0010", Text: "none found", None: true},
		}},
		{Cells: []string{"two"}, Detail: []Detail{
			{Label: "CredentialAccess", Note: "TA0006, AML.TA0013", Key: "T1552", Text: "third"},
			{Label: "watchlist", Text: "fourth"},
		}},
	}}}}}}
	var out bytes.Buffer
	if err := WriteReadout(&out, r, false); err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{"t", "", "S", "  one",
		"      Discovery         TA0007              T1083      first",
		"                                            AML.T0075  second",
		"      Exfiltration      TA0010              none found",
		"",
		"  two",
		"      CredentialAccess  TA0006, AML.TA0013  T1552      third",
		"      watchlist                             fourth",
		"",
	}, "\n")
	if out.String() != want {
		t.Errorf("readout =\n%s\nwant\n%s", out.String(), want)
	}
	out.Reset()
	if err := WriteReadout(&out, r, true); err != nil {
		t.Fatal(err)
	}
	for _, grey := range []string{sgrGrey + "TA0007" + sgrReset, sgrGrey + "none found" + sgrReset} {
		if !strings.Contains(out.String(), grey) {
			t.Errorf("the readout in colour lacks %q:\n%q", grey, out.String())
		}
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
