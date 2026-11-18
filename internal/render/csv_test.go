package render_test

import (
	"bytes"
	"encoding/csv"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/get-sybers/slopmop/internal/render"
)

// sheet writes the rows as CSV under the keys a, b, c and so on.
func sheet(t *testing.T, rows ...[]render.Value) string {
	t.Helper()
	columns := make([]render.Column, len(rows[0]))
	for i := range columns {
		columns[i] = render.Column{Header: string(rune('A' + i)), Key: string(rune('a' + i))}
	}
	var out bytes.Buffer
	table, err := render.NewCSV(&out, columns)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if err := table.Write(row); err != nil {
			t.Fatal(err)
		}
	}
	if err := table.Close(); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

// A table as CSV is a row of its keys and a row for each of its rows, with
// every value whole and a value that does not apply left empty.
func TestCSVWritesKeysThenRows(t *testing.T) {
	when := time.Date(2026, 10, 22, 11, 15, 0, 0, time.FixedZone("", 2*60*60))
	tests := []struct {
		name string
		row  []render.Value
		want string
	}{
		{"text and a count", []render.Value{render.Text("plain"), render.Int(7)}, "plain,7\n"},
		{"a size in bytes", []render.Value{render.Size(1536), render.Text("x")}, "1536,x\n"},
		{"a time in UTC", []render.Value{render.Time(when), render.Text("x")}, "2026-10-22T09:15:00Z,x\n"},
		{"a whole hash", []render.Value{render.Hash(strings.Repeat("ab", 32)), render.Text("x")}, strings.Repeat("ab", 32) + ",x\n"},
		{"what does not apply", []render.Value{render.NotApplicable(), render.Never()}, ",\n"},
		{"a comma and a quote", []render.Value{render.Text("a, b"), render.Text(`say "x"`)}, "\"a, b\",\"say \"\"x\"\"\"\n"},
		{"a path of Windows", []render.Value{render.Text(`C:\cases\run 1\a.ps1`), render.Text("x")}, "C:\\cases\\run 1\\a.ps1,x\n"},
		{"a line break", []render.Value{render.Text("a\nb"), render.Text("x")}, "\"\"\"a\\nb\"\"\",x\n"},
		{"a list", []render.Value{render.List([][]render.Field{
			{{Key: "file", Value: render.Text("a.sh")}, {Key: "line", Value: render.Int(3)}},
			{{Key: "file", Value: render.Text("b.sh")}, {Key: "line", Value: render.Int(9)}},
		}), render.Text("x")}, "a.sh 3; b.sh 9,x\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, want := sheet(t, tt.row), "a,b\n"+tt.want; got != want {
				t.Errorf("the table is %q, want %q", got, want)
			}
		})
	}
}

// Text from the evidence that a spreadsheet would run as a formula is not one.
func TestCSVGuardsFormulas(t *testing.T) {
	tests := []struct {
		name  string
		value render.Value
		want  string
	}{
		{"an equals sign", render.Text("=cmd|' /C calc'!A0"), "'=cmd|' /C calc'!A0"},
		{"a plus", render.Text("+1+1"), "'+1+1"},
		{"a minus", render.Text("-2+3"), "'-2+3"},
		{"an at sign", render.Text("@SUM(A1)"), "'@SUM(A1)"},
		{"a digest that is none", render.Hash("=1+1"), "'=1+1"},
		{"a list", render.List([][]render.Field{{{Key: "text", Value: render.Text("=1+1")}}}), "'=1+1"},
		{"a sign inside the text", render.Text("a=b"), "a=b"},
		{"a number below zero", render.Int(-5), "-5"},
		{"text in quotes", render.Text("\t=1+1"), `"\t=1+1"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			records, err := csv.NewReader(strings.NewReader(sheet(t, []render.Value{tt.value}))).ReadAll()
			if err != nil || len(records) != 2 {
				t.Fatalf("the table reads back as %q: %v", records, err)
			}
			if got := records[1][0]; got != tt.want {
				t.Errorf("the cell is %q, want %q", got, tt.want)
			}
		})
	}
}

// Hostile text is one line of printable text that reads back as the cell the report shows.
func TestCSVHostileTextIsOneRow(t *testing.T) {
	for _, group := range hostile() {
		t.Run(group.name, func(t *testing.T) {
			for _, text := range group.values {
				got := sheet(t, []render.Value{render.Text(text), render.Int(1)})
				checkPrintable(t, got)
				if strings.Count(got, "\n") != 2 {
					t.Errorf("Text(%q) is written as %q, want one line under the keys", text, got)
				}
				want := render.Escape(text)
				if strings.ContainsRune("=+-@", rune(want[0])) {
					want = "'" + want
				}
				records, err := csv.NewReader(strings.NewReader(got)).ReadAll()
				if err != nil || len(records) != 2 || !slices.Equal(records[1], []string{want, "1"}) {
					t.Errorf("Text(%q) reads back as %q (%v), want %q", text, records, err, want)
				}
			}
		})
	}
}

// A table larger than what is held reaches the writer before it is closed.
func TestCSVIsWrittenAsItIsAdded(t *testing.T) {
	sink := &recorder{}
	table, err := render.NewCSV(sink, rowColumns())
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Repeat("x", 64<<10)
	for i := range 40 {
		if err = table.Write([]render.Value{render.Int(int64(i)), render.Text(text), render.NotApplicable()}); err != nil {
			t.Fatal(err)
		}
	}
	if len(sink.writes) == 0 {
		t.Errorf("40 rows of 64 KiB made no write before the table was closed")
	}
	if err = table.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(bytes.NewReader(bytes.Join(sink.writes, nil))).ReadAll()
	if err != nil || len(records) != 41 {
		t.Errorf("the writes hold %d lines (%v), want the keys and 40 rows", len(records), err)
	}
}

func TestCSVErrors(t *testing.T) {
	errDisk := errors.New("disk full")
	row := []render.Value{render.Int(1), render.Text("text"), render.NotApplicable()}
	tests := []struct {
		name    string
		columns []render.Column
		row     []render.Value
		sink    *recorder
		want    string
		wantErr error
	}{
		{"no columns", nil, row, &recorder{}, "render: table has no columns", nil},
		{"two columns share a key", []render.Column{{Header: "A", Key: "k"}, {Header: "B", Key: "k"}}, row, &recorder{}, `render: columns 1 and 2 share the key "k"`, nil},
		{"row too short", rowColumns(), row[:2], &recorder{}, "render: row 1 has 2 values, want 3", nil},
		{"writer fails", rowColumns(), row, &recorder{err: errDisk}, "render: write table: disk full", errDisk},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			table, err := render.NewCSV(tt.sink, tt.columns)
			if err == nil {
				err = table.Write(tt.row)
			}
			if err == nil {
				err = table.Close()
			}
			if err == nil || err.Error() != tt.want {
				t.Fatalf("error is %v, want %q", err, tt.want)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("error %v does not wrap %v", err, tt.wantErr)
			}
		})
	}
}
