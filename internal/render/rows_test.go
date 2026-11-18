package render_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/get-sybers/slopmop/internal/render"
)

func rowColumns() []render.Column {
	return []render.Column{{Header: "N", Key: "n"}, {Header: "TEXT", Key: "text"}, {Header: "NONE", Key: "none"}}
}

// indented lays the rows out as encoding/json indents an array of objects.
func indented(t *testing.T, texts []string) string {
	t.Helper()
	var compact bytes.Buffer
	compact.WriteByte('[')
	for i, text := range texts {
		if i > 0 {
			compact.WriteByte(',')
		}
		quoted, err := json.Marshal(text)
		if err != nil {
			t.Fatal(err)
		}
		compact.WriteString(`{"n":` + strconv.Itoa(i) + `,"text":` + string(quoted) + `,"none":null}`)
	}
	compact.WriteByte(']')
	var out bytes.Buffer
	if err := json.Indent(&out, compact.Bytes(), "", "  "); err != nil {
		t.Fatal(err)
	}
	return out.String() + "\n"
}

// Rows written one at a time are the array encoding/json would indent.
func TestRowsAreAnIndentedArray(t *testing.T) {
	tests := []struct {
		name  string
		texts []string
	}{
		{"no row", nil},
		{"one row", []string{"only"}},
		{"three rows", []string{"first", `say "cheese"`, `C:\loot\out.txt`}},
		{"text json escapes", []string{"tab\there", "line\nbreak", "é and 日本"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got bytes.Buffer
			rows, err := render.NewRows(&got, rowColumns())
			if err != nil {
				t.Fatal(err)
			}
			for i, text := range tt.texts {
				if err := rows.Write([]render.Value{render.Int(int64(i)), render.Text(text), render.NotApplicable()}); err != nil {
					t.Fatal(err)
				}
			}
			if err := rows.Close(); err != nil {
				t.Fatal(err)
			}
			if want := indented(t, tt.texts); got.String() != want {
				t.Errorf("rows are\n%s\nwant\n%s", got.String(), want)
			}
		})
	}
}

// A table larger than what is held reaches the writer before it is closed.
func TestRowsAreWrittenAsTheyAreAdded(t *testing.T) {
	sink := &recorder{}
	rows, err := render.NewRows(sink, rowColumns())
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Repeat("x", 64<<10)
	for i := range 40 {
		if err := rows.Write([]render.Value{render.Int(int64(i)), render.Text(text), render.NotApplicable()}); err != nil {
			t.Fatal(err)
		}
	}
	if len(sink.writes) == 0 {
		t.Errorf("40 rows of 64 KiB made no write before the table was closed")
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	var table []map[string]any
	if err := json.Unmarshal(bytes.Join(sink.writes, nil), &table); err != nil || len(table) != 40 {
		t.Errorf("the writes hold %d rows (%v), want 40", len(table), err)
	}
}

func TestRowsErrors(t *testing.T) {
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
			rows, err := render.NewRows(tt.sink, tt.columns)
			if err == nil {
				err = rows.Write(tt.row)
			}
			if err == nil {
				err = rows.Close()
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

// A list is the array of objects encoding/json would indent, its keys in the order given.
func TestRowsWriteAListAsObjects(t *testing.T) {
	when := time.Date(2026, 10, 22, 9, 15, 0, 0, time.UTC)
	line := func(file string, n render.Value, text string) []render.Field {
		return []render.Field{
			{Key: "time", Value: render.Time(when)}, {Key: "file", Value: render.Text(file)},
			{Key: "line", Value: n}, {Key: "text", Value: render.Text(text)},
		}
	}
	tests := []struct {
		name string
		list render.Value
		want string
	}{
		{"no item", render.List(nil), `[]`},
		{"one item", render.List([][]render.Field{line("a.sh", render.Int(7), `say "x"`)}),
			`[{"time":"2026-10-22T09:15:00Z","file":"a.sh","line":7,"text":"say \"x\""}]`},
		{"two items and a line that is not known", render.List([][]render.Field{line("a.sh", render.Int(7), "id"), line("b.jsonl", render.NotApplicable(), "a\tb")}),
			`[{"time":"2026-10-22T09:15:00Z","file":"a.sh","line":7,"text":"id"},{"time":"2026-10-22T09:15:00Z","file":"b.jsonl","line":null,"text":"a\tb"}]`},
		{"a list in a list", render.List([][]render.Field{{{Key: "inner", Value: render.List([][]render.Field{{{Key: "n", Value: render.Int(1)}}})}}}),
			`[{"inner":[{"n":1}]}]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got bytes.Buffer
			rows, err := render.NewRows(&got, rowColumns())
			if err != nil {
				t.Fatal(err)
			}
			if err = rows.Write([]render.Value{render.Int(0), tt.list, render.NotApplicable()}); err != nil {
				t.Fatal(err)
			}
			if err = rows.Close(); err != nil {
				t.Fatal(err)
			}
			var want bytes.Buffer
			if err = json.Indent(&want, []byte(`[{"n":0,"text":`+tt.want+`,"none":null}]`), "", "  "); err != nil {
				t.Fatal(err)
			}
			if got.String() != want.String()+"\n" {
				t.Errorf("rows are\n%s\nwant\n%s", got.String(), want.String())
			}
		})
	}
}

// Text inside a list is escaped as text outside one is.
func TestRowsEscapeTextInAList(t *testing.T) {
	var got bytes.Buffer
	rows, err := render.NewRows(&got, rowColumns())
	if err != nil {
		t.Fatal(err)
	}
	list := render.List([][]render.Field{{{Key: "text", Value: render.Text("\x1b[2J\u202e<b>")}}})
	if err = rows.Write([]render.Value{render.Int(0), list, render.NotApplicable()}); err != nil {
		t.Fatal(err)
	}
	if err = rows.Close(); err != nil {
		t.Fatal(err)
	}
	checkPrintable(t, got.String())
	if want := `"text": "\u001b[2J\u202e<b>"`; !strings.Contains(got.String(), want) {
		t.Errorf("rows are\n%s\nwant them to hold %s", got.String(), want)
	}
}
