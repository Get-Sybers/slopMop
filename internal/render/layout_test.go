package render_test

import (
	"bytes"
	"strings"
	"testing"
	"text/tabwriter"
	"unicode/utf8"

	"github.com/get-sybers/slopmop/internal/render"
)

// aligned lays cells out as the contract describes, without text/tabwriter.
func aligned(lines ...[]string) string {
	widths := make([]int, len(lines[0])-1)
	for _, cells := range lines {
		for i := range widths {
			widths[i] = max(widths[i], utf8.RuneCountInString(cells[i]))
		}
	}
	var b strings.Builder
	for _, cells := range lines {
		for i, cell := range cells {
			b.WriteString(cell)
			if i < len(widths) {
				b.WriteString(strings.Repeat(" ", widths[i]-utf8.RuneCountInString(cell)+2))
			}
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func TestTextCannotBreakLayout(t *testing.T) {
	columns := []render.Column{
		{Header: "ID", Key: "id"},
		{Header: "EVIDENCE", Key: "evidence"},
		{Header: "AFTER", Key: "after"},
		{Header: "LAST", Key: "last", Wide: true},
	}
	headers := []string{"ID", "EVIDENCE", "AFTER", "LAST"}
	second := []string{"r2", "plain", "after", "end"}
	tests := []struct {
		name     string
		view     render.View
		shown    int
		position int
	}{
		{"default first cell", render.Default, 3, 0},
		{"default middle cell", render.Default, 3, 1},
		{"default last cell", render.Default, 3, 2},
		{"wide first cell", render.Wide, 4, 0},
		{"wide middle cell", render.Wide, 4, 1},
		{"wide last cell", render.Wide, 4, 3},
	}
	for _, tt := range tests {
		for _, group := range hostile() {
			t.Run(tt.name+"/"+group.name, func(t *testing.T) {
				for _, text := range group.values {
					first := []string{"r1", "seen", "after", "end"}
					first[tt.position] = text
					table := render.Table{Columns: columns, Rows: [][]render.Value{
						{render.Text(first[0]), render.Text(first[1]), render.Text(first[2]), render.Text(first[3])},
						{render.Text(second[0]), render.Text(second[1]), render.Text(second[2]), render.Text(second[3])},
					}}
					first[tt.position] = render.Escape(text)
					want := aligned(headers[:tt.shown], first[:tt.shown], second[:tt.shown])
					got := write(t, table, render.Options{View: tt.view})
					if got != want {
						t.Errorf("Text(%q) wrote\n%q, want\n%q", text, got, want)
					}
					checkPrintable(t, got)
				}
			})
		}
	}
}

func TestTextCannotBreakQuietLines(t *testing.T) {
	columns := []render.Column{{Header: "ID", Key: "id"}, {Header: "AFTER", Key: "after"}}
	for _, group := range hostile() {
		t.Run(group.name, func(t *testing.T) {
			for _, text := range group.values {
				table := render.Table{Columns: columns, Rows: [][]render.Value{
					{render.Text(text), render.Text("after")},
					{render.Text("r2"), render.Text("after")},
				}}
				got := write(t, table, render.Options{Quiet: true})
				if want := render.Escape(text) + "\nr2\n"; got != want {
					t.Errorf("Text(%q) wrote %q, want %q", text, got, want)
				}
				checkPrintable(t, got)
			}
		})
	}
}

// The control for the tests above: the same bytes, unescaped, do break text/tabwriter.
func TestTabwriterBreaksOnRawText(t *testing.T) {
	tests := []struct {
		name string
		text string
		want string
	}{
		{
			"0xff swallows every cell after it", "a\xffb",
			"ID  EVIDENCE  AFTER\nr1  a\xffb\tafter\nr2\tplain\tafter\n",
		},
		{
			"a pair of 0xff shifts the column", "a\xffb\xff",
			"ID  EVIDENCE  AFTER\nr1  a\xffb\xff        after\nr2  plain     after\n",
		},
		{
			"tab adds a cell", "a\tb",
			"ID  EVIDENCE  AFTER\nr1  a         b  after\nr2  plain     after\n",
		},
		{
			"newline breaks the row", "a\nb",
			"ID  EVIDENCE  AFTER\nr1  a\nb   after\nr2  plain  after\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			tw := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
			raw := "ID\tEVIDENCE\tAFTER\nr1\t" + tt.text + "\tafter\nr2\tplain\tafter\n"
			if _, err := tw.Write([]byte(raw)); err != nil {
				t.Fatalf("tabwriter write: %v", err)
			}
			if err := tw.Flush(); err != nil {
				t.Fatalf("tabwriter flush: %v", err)
			}
			if got := buf.String(); got != tt.want {
				t.Errorf("tabwriter wrote %q, want the broken table %q", got, tt.want)
			}
			table := render.Table{
				Columns: []render.Column{
					{Header: "ID", Key: "id"}, {Header: "EVIDENCE", Key: "evidence"}, {Header: "AFTER", Key: "after"},
				},
				Rows: [][]render.Value{
					{render.Text("r1"), render.Text(tt.text), render.Text("after")},
					{render.Text("r2"), render.Text("plain"), render.Text("after")},
				},
			}
			want := aligned(
				[]string{"ID", "EVIDENCE", "AFTER"},
				[]string{"r1", render.Escape(tt.text), "after"},
				[]string{"r2", "plain", "after"},
			)
			if got := write(t, table, render.Options{}); got != want {
				t.Errorf("Write wrote %q, want %q", got, want)
			}
		})
	}
}
