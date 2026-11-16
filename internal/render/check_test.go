package render_test

import (
	"testing"

	"github.com/get-sybers/slopmop/internal/render"
)

func TestCheckAccepts(t *testing.T) {
	tests := []struct {
		name  string
		table render.Table
	}{
		{"every value kind", sample()},
		{"no rows", render.Table{Columns: []render.Column{{Header: "NAME", Key: "name"}}}},
		{"count first", render.Table{Columns: []render.Column{{Header: "count", Key: "count"}}}},
		{"distinct count", render.Table{Columns: []render.Column{{Header: "n-src", Key: "n_src"}}}},
		{"distinct count with digits and hyphens", render.Table{Columns: []render.Column{{Header: "n-ipv4-src", Key: "n"}}}},
		{"spaces and digits", render.Table{Columns: []render.Column{{Header: "LAST LOGIN 2", Key: "last"}}}},
		{"digits", render.Table{Columns: []render.Column{{Header: "SHA256", Key: "sha256"}}}},
		{"uppercase count is a field", render.Table{Columns: []render.Column{{Header: "COUNT", Key: "count"}}}},
		{
			"keys differ by case",
			render.Table{Columns: []render.Column{{Header: "NAME", Key: "name"}, {Header: "NAME", Key: "Name"}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.table.Check(); err != nil {
				t.Errorf("Check: %v", err)
			}
		})
	}
}

func TestCheckRejects(t *testing.T) {
	header := func(h string) render.Table {
		return render.Table{Columns: []render.Column{{Header: "NAME", Key: "name"}, {Header: h, Key: "other"}}}
	}
	badHeader := func(quoted string) string {
		return "render: column 2 has header " + quoted + ", want UPPERCASE, count or n-<field>"
	}
	name := render.Column{Header: "NAME", Key: "name"}
	size := render.Column{Header: "SIZE", Key: "size"}
	tests := []struct {
		name  string
		table render.Table
		want  string
	}{
		{"no columns", render.Table{}, "render: table has no columns"},
		{
			"rows without columns", render.Table{Rows: [][]render.Value{{render.Text("x")}}},
			"render: table has no columns",
		},
		{
			"column 1 is wide", render.Table{Columns: []render.Column{{Header: "NAME", Key: "name", Wide: true}, size}},
			"render: column 1 (NAME) is the selector and cannot be wide",
		},
		{
			"empty key", render.Table{Columns: []render.Column{name, {Header: "SIZE"}}},
			"render: column 2 (SIZE) has no key",
		},
		{
			"repeated key", render.Table{Columns: []render.Column{name, size, {Header: "OWNER", Key: "name"}}},
			`render: columns 1 and 3 share the key "name"`,
		},
		{
			"short row",
			render.Table{Columns: []render.Column{name, size}, Rows: [][]render.Value{
				{render.Text("a"), render.Size(1)}, {render.Text("b")},
			}},
			"render: row 2 has 1 values, want 2",
		},
		{
			"long row",
			render.Table{Columns: []render.Column{name, size}, Rows: [][]render.Value{
				{render.Text("a"), render.Size(1), render.Int(1)},
			}},
			"render: row 1 has 3 values, want 2",
		},
		{
			"empty row", render.Table{Columns: []render.Column{name}, Rows: [][]render.Value{nil}},
			"render: row 1 has 0 values, want 1",
		},
		{
			"bad header in column 1", render.Table{Columns: []render.Column{{Header: "name", Key: "name", Wide: true}}},
			`render: column 1 has header "name", want UPPERCASE, count or n-<field>`,
		},
		{"empty header", header(""), badHeader(`""`)},
		{"lowercase header", header("size"), badHeader(`"size"`)},
		{"mixed case header", header("Size"), badHeader(`"Size"`)},
		{"punctuation in header", header("CPU%"), badHeader(`"CPU%"`)},
		{"hyphen in uppercase header", header("LAST-LOGIN"), badHeader(`"LAST-LOGIN"`)},
		{"underscore in header", header("LAST_LOGIN"), badHeader(`"LAST_LOGIN"`)},
		{"letter outside ASCII", header("GRÖSSE"), badHeader(`"GRÖSSE"`)},
		{"leading space", header(" SIZE"), badHeader(`" SIZE"`)},
		{"trailing space", header("SIZE "), badHeader(`"SIZE "`)},
		{"only spaces", header("  "), badHeader(`"  "`)},
		{"tab in header", header("LAST\tLOGIN"), badHeader(`"LAST\tLOGIN"`)},
		{"newline in header", header("LAST\nLOGIN"), badHeader(`"LAST\nLOGIN"`)},
		{"0xff in header", header("SIZE\xff"), badHeader(`"SIZE\xff"`)},
		{"capitalised count", header("Count"), badHeader(`"Count"`)},
		{"plural count", header("counts"), badHeader(`"counts"`)},
		{"distinct count without a field", header("n-"), badHeader(`"n-"`)},
		{"distinct count in uppercase", header("N-SRC"), badHeader(`"N-SRC"`)},
		{"distinct count with an uppercase field", header("n-SRC"), badHeader(`"n-SRC"`)},
		{"distinct count with an underscore", header("n-last_src"), badHeader(`"n-last_src"`)},
		{"distinct count with a space", header("n-last src"), badHeader(`"n-last src"`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.table.Check()
			if err == nil {
				t.Fatalf("Check returned no error, want %q", tt.want)
			}
			if got := err.Error(); got != tt.want {
				t.Errorf("Check error is %q, want %q", got, tt.want)
			}
		})
	}
}
