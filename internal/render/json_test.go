package render_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/get-sybers/slopmop/internal/render"
)

func single(key string, v render.Value) render.Table {
	return render.Table{
		Columns: []render.Column{{Header: "VALUE", Key: key}},
		Rows:    [][]render.Value{{v}},
	}
}

func TestJSONValues(t *testing.T) {
	tests := []struct {
		name  string
		value render.Value
		want  string
	}{
		{"text", render.Text("passwd"), `"passwd"`},
		{"empty text", render.Text(""), `""`},
		{"text is not passed through Escape", render.Text(" padded "), `" padded "`},
		{"text that looks like a sentinel", render.Text("-"), `"-"`},
		{"quote and backslash", render.Text(`C:\Temp\"a".txt`), `"C:\\Temp\\\"a\".txt"`},
		{"html is left alone", render.Text("<a href='x'>&</a>"), `"<a href='x'>&</a>"`},
		{"printable text outside ASCII", render.Text("証拠 résumé 🔥"), `"証拠 résumé 🔥"`},
		{"newline, tab and return", render.Text("a\nb\tc\rd"), `"a\nb\tc\rd"`},
		{"esc", render.Text("\x1b[2J"), `"\u001b[2J"`},
		{"nul", render.Text("a\x00b"), `"a\u0000b"`},
		{"del", render.Text("\x7f"), `"\u007f"`},
		{"c1 control", render.Text("\u009b"), `"\u009b"`},
		{"bidi override", render.Text("txt.\u202egpj"), `"txt.\u202egpj"`},
		{"line separator", render.Text("\u2028"), `"\u2028"`},
		{"unprintable above the basic plane", render.Text("\U000e0041"), `"\udb40\udc41"`},
		{"invalid bytes become U+FFFD", render.Text("a\xffb\xc3"), "\"a\ufffdb\ufffd\""},
		{"int", render.Int(214), "214"},
		{"negative int", render.Int(-7), "-7"},
		{"int beyond float precision", render.Int(9007199254740993), "9007199254740993"},
		{"size is a byte count", render.Size(54 << 20), "56623104"},
		{"hash is whole", render.Hash(digestA), `"` + digestA + `"`},
		{"time", render.Time(instant("2026-10-04T09:14:02Z")), `"2026-10-04T09:14:02Z"`},
		{"time from another zone", render.Time(instant("2026-10-04T11:14:02+02:00")), `"2026-10-04T09:14:02Z"`},
		{"time drops fractions", render.Time(instant("2026-10-04T09:14:02.999Z")), `"2026-10-04T09:14:02Z"`},
		{"year above 9999", render.Time(time.Date(10000, 1, 2, 3, 4, 5, 0, time.UTC)), `"10000-01-02T03:04:05Z"`},
		{"year far above 9999", render.Time(time.Date(123456, 12, 31, 23, 59, 59, 0, cest())), `"123456-12-31T21:59:59Z"`},
		{"not applicable", render.NotApplicable(), "null"},
		{"never", render.Never(), "null"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := write(t, single("value", tt.value), render.Options{View: render.JSON})
			if want := "[\n  {\n    \"value\": " + tt.want + "\n  }\n]\n"; got != want {
				t.Errorf("Write wrote %q, want %q", got, want)
			}
			if !json.Valid([]byte(got)) {
				t.Errorf("Write wrote invalid JSON: %q", got)
			}
		})
	}
}

func TestJSONIgnoresHeadersAndLocation(t *testing.T) {
	want := write(t, sample(), render.Options{View: render.JSON})
	tests := []struct {
		name string
		opts render.Options
	}{
		{"no headers", render.Options{View: render.JSON, NoHeaders: true}},
		{"location", render.Options{View: render.JSON, Location: cest()}},
		{"both", render.Options{View: render.JSON, NoHeaders: true, Location: cest()}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := write(t, sample(), tt.opts); got != want {
				t.Errorf("Write wrote\n%s\nwant\n%s", got, want)
			}
		})
	}
}

func TestJSONLayout(t *testing.T) {
	columns := []render.Column{
		{Header: "ZONE", Key: "zone"},
		{Header: "count", Key: "count"},
		{Header: "ADDED", Key: "added", Wide: true},
		{Header: "MASK", Key: "a\"b\n\x1b", Wide: true},
	}
	tests := []struct {
		name string
		rows [][]render.Value
		want string
	}{
		{"no rows", nil, "[]\n"},
		{
			"keys in column order, wide columns included",
			[][]render.Value{{render.Text("b"), render.Int(2), render.Never(), render.Int(24)}},
			`[
  {
    "zone": "b",
    "count": 2,
    "added": null,
    "a\"b\n\u001b": 24
  }
]
`,
		},
		{
			"one object for each row",
			[][]render.Value{
				{render.Text("b"), render.Int(2), render.Never(), render.Int(24)},
				{render.Text("a"), render.Int(1), render.NotApplicable(), render.Int(16)},
			},
			`[
  {
    "zone": "b",
    "count": 2,
    "added": null,
    "a\"b\n\u001b": 24
  },
  {
    "zone": "a",
    "count": 1,
    "added": null,
    "a\"b\n\u001b": 16
  }
]
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := write(t, render.Table{Columns: columns, Rows: tt.rows}, render.Options{View: render.JSON})
			if got != tt.want {
				t.Errorf("Write wrote %q, want %q", got, tt.want)
			}
			if !json.Valid([]byte(got)) {
				t.Errorf("Write wrote invalid JSON: %q", got)
			}
		})
	}
}

// Every Unicode scalar value must survive, and none may reach the terminal unprintable.
func TestJSONStringsReadBack(t *testing.T) {
	const block = 0x1000
	for start := rune(0); start <= utf8.MaxRune; start += block {
		var text strings.Builder
		for r := start; r < start+block; r++ {
			if utf8.ValidRune(r) {
				text.WriteRune(r)
			}
		}
		if text.Len() == 0 {
			continue
		}
		t.Run(fmt.Sprintf("U+%04X", start), func(t *testing.T) {
			got := write(t, single("text", render.Text(text.String())), render.Options{View: render.JSON})
			checkPrintable(t, got)
			var rows []struct {
				Text string `json:"text"`
			}
			if err := json.Unmarshal([]byte(got), &rows); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if len(rows) != 1 {
				t.Fatalf("Write wrote %d objects, want 1", len(rows))
			}
			if rows[0].Text != text.String() {
				t.Errorf("text read back as %+q, want %+q", rows[0].Text, text.String())
			}
		})
	}
}

// The oracle is encoding/json: hostile text must read back as its own encoding of it would.
func TestJSONHostileTextReadsBack(t *testing.T) {
	for _, group := range hostile() {
		t.Run(group.name, func(t *testing.T) {
			for _, text := range group.values {
				encoded, err := json.Marshal(text)
				if err != nil {
					t.Fatalf("Marshal(%q): %v", text, err)
				}
				var want string
				if err := json.Unmarshal(encoded, &want); err != nil {
					t.Fatalf("Unmarshal(%s): %v", encoded, err)
				}
				got := write(t, single("text", render.Text(text)), render.Options{View: render.JSON})
				checkPrintable(t, got)
				var rows []map[string]string
				if err := json.Unmarshal([]byte(got), &rows); err != nil {
					t.Errorf("Text(%q): Unmarshal: %v", text, err)
					continue
				}
				if len(rows) != 1 || rows[0]["text"] != want {
					t.Errorf("Text(%q) read back as %q, want one object holding %q", text, rows, want)
				}
			}
		})
	}
}
