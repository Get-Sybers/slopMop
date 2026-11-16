package render_test

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/get-sybers/slopmop/internal/golden"
	"github.com/get-sybers/slopmop/internal/render"
)

const (
	digestA = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	digestB = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
	digestC = "fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9"
)

func instant(value string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		panic(err)
	}
	return t
}

func cest() *time.Location { return time.FixedZone("CEST", 2*60*60) }

// sample holds every value kind, both sentinels and text that must be escaped.
func sample() render.Table {
	return render.Table{
		Columns: []render.Column{
			{Header: "NAME", Key: "name"},
			{Header: "SIZE", Key: "size"},
			{Header: "count", Key: "count"},
			{Header: "MODIFIED", Key: "modified"},
			{Header: "SHA256", Key: "sha256"},
			{Header: "n-src", Key: "n_src", Wide: true},
			{Header: "LAST READ", Key: "last_read", Wide: true},
			{Header: "NOTE", Key: "note", Wide: true},
		},
		Rows: [][]render.Value{
			{
				render.Text("passwd"), render.Size(1228), render.Int(214),
				render.Time(instant("2026-09-29T18:03:55Z")), render.Hash(digestA),
				render.Int(6), render.Time(instant("2026-10-04T11:14:02+02:00")), render.Text("world readable"),
			},
			{
				render.Text("etc/"), render.NotApplicable(), render.Int(0),
				render.Time(instant("2026-10-01T04:22:10Z")), render.NotApplicable(),
				render.Int(0), render.Never(), render.Text(""),
			},
			{
				render.Text("sudo"), render.Size(54 << 10), render.Int(3),
				render.Time(instant("2026-06-06T11:40:02.999999999Z")), render.Hash(digestB),
				render.Int(1), render.Time(instant("2026-10-03T23:59:59-05:00")), render.Text("setuid\troot"),
			},
			{
				render.Text(`C:\Users\Public\report final.docx`), render.Size(54 << 20), render.Int(1),
				render.Time(instant("2026-10-04T09:14:02Z")), render.Hash(digestC),
				render.Int(2), render.Never(), render.Text(`say "cheese"`),
			},
			{
				render.Text("wipe\x1b[2J.log"), render.Size(0), render.Int(40),
				render.Time(instant("2026-10-04T09:13:55Z")), render.Hash(digestA),
				render.Int(4), render.Time(instant("2026-10-04T09:13:56Z")), render.Text("first line\nsecond line"),
			},
			{
				render.Text("core.dump"), render.Size(3 << 29), render.Int(12),
				render.Time(instant("2026-12-31T23:30:00Z")), render.Hash(digestB),
				render.Int(1), render.Time(instant("2027-01-01T00:00:00Z")), render.Text(" padded "),
			},
		},
	}
}

func write(t *testing.T, table render.Table, o render.Options) string {
	t.Helper()
	var buf bytes.Buffer
	if err := render.Write(&buf, table, o); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return buf.String()
}

// checkPrintable fails when output could move the cursor, hide text or leave a trailing space.
func checkPrintable(t *testing.T, out string) {
	t.Helper()
	if !utf8.ValidString(out) {
		t.Errorf("output is not valid UTF-8: %q", out)
	}
	for _, r := range out {
		if r != '\n' && !strconv.IsPrint(r) {
			t.Errorf("output holds the unprintable rune %U: %q", r, out)
		}
	}
	for line := range strings.Lines(out) {
		if strings.HasSuffix(strings.TrimSuffix(line, "\n"), " ") {
			t.Errorf("line ends with a space: %q", line)
		}
	}
	if out != "" && !strings.HasSuffix(out, "\n") {
		t.Errorf("output does not end with a newline: %q", out)
	}
}

func TestWriteViews(t *testing.T) {
	tests := []struct {
		name string
		opts render.Options
	}{
		{"default", render.Options{}},
		{"default-no-headers", render.Options{NoHeaders: true}},
		{"default-zone", render.Options{Location: cest()}},
		{"wide", render.Options{View: render.Wide}},
		{"wide-no-headers", render.Options{View: render.Wide, NoHeaders: true}},
		{"wide-zone", render.Options{View: render.Wide, Location: cest()}},
		{"quiet", render.Options{Quiet: true}},
		{"json", render.Options{View: render.JSON}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := write(t, sample(), tt.opts)
			checkPrintable(t, got)
			golden.Check(t, tt.name, []byte(got))
		})
	}
}

func TestWriteEmptyTable(t *testing.T) {
	empty := sample()
	empty.Rows = nil
	tests := []struct {
		name string
		opts render.Options
		want string
	}{
		{"default", render.Options{}, "NAME  SIZE  count  MODIFIED  SHA256\n"},
		{"default no headers", render.Options{NoHeaders: true}, ""},
		{"wide", render.Options{View: render.Wide}, "NAME  SIZE  count  MODIFIED  SHA256  n-src  LAST READ  NOTE\n"},
		{"wide no headers", render.Options{View: render.Wide, NoHeaders: true}, ""},
		{"quiet", render.Options{Quiet: true}, ""},
		{"json", render.Options{View: render.JSON}, "[]\n"},
		{"json no headers", render.Options{View: render.JSON, NoHeaders: true}, "[]\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := write(t, empty, tt.opts); got != tt.want {
				t.Errorf("Write wrote %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWriteQuiet(t *testing.T) {
	one := func(v render.Value) render.Table {
		return render.Table{
			Columns: []render.Column{{Header: "ID", Key: "id"}, {Header: "SIZE", Key: "size"}},
			Rows:    [][]render.Value{{v, render.Size(4096)}, {render.Text("second"), render.Size(1)}},
		}
	}
	tests := []struct {
		name  string
		first render.Value
		opts  render.Options
		want  string
	}{
		{"text", render.Text("first"), render.Options{Quiet: true}, "first\nsecond\n"},
		{"escaped text", render.Text("a\tb"), render.Options{Quiet: true}, "\"a\\tb\"\nsecond\n"},
		{"whole hash", render.Hash(digestA), render.Options{Quiet: true}, digestA + "\nsecond\n"},
		{"raw size", render.Size(1536), render.Options{Quiet: true}, "1536\nsecond\n"},
		{"sentinel", render.Never(), render.Options{Quiet: true}, "never\nsecond\n"},
		{
			"time in the zone", render.Time(instant("2026-10-04T09:14:02Z")),
			render.Options{Quiet: true, Location: cest()}, "2026-10-04T11:14:02+02:00\nsecond\n",
		},
		{"no headers changes nothing", render.Text("first"), render.Options{Quiet: true, NoHeaders: true}, "first\nsecond\n"},
		{"over wide", render.Text("first"), render.Options{Quiet: true, View: render.Wide}, "first\nsecond\n"},
		{"over json", render.Text("first"), render.Options{Quiet: true, View: render.JSON}, "first\nsecond\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := write(t, one(tt.first), tt.opts); got != tt.want {
				t.Errorf("Write wrote %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWriteTimes(t *testing.T) {
	at := instant("2026-10-04T09:14:02.75Z")
	table := render.Table{
		Columns: []render.Column{{Header: "TIME", Key: "time"}},
		Rows:    [][]render.Value{{render.Time(at)}},
	}
	tests := []struct {
		name string
		loc  *time.Location
		want string
	}{
		{"nil is UTC", nil, "2026-10-04T09:14:02Z\n"},
		{"UTC", time.UTC, "2026-10-04T09:14:02Z\n"},
		{"east", cest(), "2026-10-04T11:14:02+02:00\n"},
		{"west with half hour", time.FixedZone("NDT", -(2*60*60 + 30*60)), "2026-10-04T06:44:02-02:30\n"},
		{"zone at offset zero", time.FixedZone("GMT", 0), "2026-10-04T09:14:02+00:00\n"},
		{"date changes", time.FixedZone("NZDT", 13*60*60), "2026-10-04T22:14:02+13:00\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, view := range []render.View{render.Default, render.Wide} {
				got := write(t, table, render.Options{View: view, NoHeaders: true, Location: tt.loc})
				if got != tt.want {
					t.Errorf("view %d wrote %q, want %q", view, got, tt.want)
				}
			}
		})
	}
}

func TestWriteHashes(t *testing.T) {
	tests := []struct {
		name     string
		hash     string
		want     string
		wantWide string
	}{
		{"sha256", digestA, "9f86d081884c\n", digestA + "\n"},
		{"thirteen", "0123456789abc", "0123456789ab\n", "0123456789abc\n"},
		{"twelve", "0123456789ab", "0123456789ab\n", "0123456789ab\n"},
		{"short", "abc", "abc\n", "abc\n"},
		{"empty", "", "\"\"\n", "\"\"\n"},
		{"not hex", "0123\t\xff89abcdefgh", "\"0123\\t\\xff89abcd\"\n", "\"0123\\t\\xff89abcdefgh\"\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			table := render.Table{
				Columns: []render.Column{{Header: "SHA256", Key: "sha256"}},
				Rows:    [][]render.Value{{render.Hash(tt.hash)}},
			}
			if got := write(t, table, render.Options{NoHeaders: true}); got != tt.want {
				t.Errorf("default view wrote %q, want %q", got, tt.want)
			}
			if got := write(t, table, render.Options{View: render.Wide, NoHeaders: true}); got != tt.wantWide {
				t.Errorf("wide view wrote %q, want %q", got, tt.wantWide)
			}
		})
	}
}

type recorder struct {
	writes [][]byte
	err    error
}

func (r *recorder) Write(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	r.writes = append(r.writes, bytes.Clone(p))
	return len(p), nil
}

func TestWriteReachesWriterWhole(t *testing.T) {
	tests := []struct {
		name string
		opts render.Options
	}{
		{"default", render.Options{}},
		{"wide", render.Options{View: render.Wide}},
		{"quiet", render.Options{Quiet: true}},
		{"json", render.Options{View: render.JSON}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sink recorder
			if err := render.Write(&sink, sample(), tt.opts); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if got := len(sink.writes); got != 1 {
				t.Errorf("Write made %d writes, want 1", got)
			}
		})
	}
}

func TestWriteErrors(t *testing.T) {
	errDisk := errors.New("disk full")
	broken := sample()
	broken.Rows[1] = broken.Rows[1][:3]
	tests := []struct {
		name    string
		table   render.Table
		opts    render.Options
		sink    *recorder
		want    string
		wantErr error
	}{
		{
			"table fails the check", broken, render.Options{}, &recorder{},
			"render: row 2 has 3 values, want 8", nil,
		},
		{
			"table fails the check in json", broken, render.Options{View: render.JSON}, &recorder{},
			"render: row 2 has 3 values, want 8", nil,
		},
		{
			"table fails the check in quiet", broken, render.Options{Quiet: true}, &recorder{},
			"render: row 2 has 3 values, want 8", nil,
		},
		{
			"unknown view", sample(), render.Options{View: render.JSON + 1}, &recorder{},
			"render: unknown view 3", nil,
		},
		{
			"negative view", sample(), render.Options{View: -1, Quiet: true}, &recorder{},
			"render: unknown view -1", nil,
		},
		{
			"writer fails", sample(), render.Options{}, &recorder{err: errDisk},
			"render: write table: disk full", errDisk,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := render.Write(tt.sink, tt.table, tt.opts)
			if err == nil {
				t.Fatalf("Write returned no error, want %q", tt.want)
			}
			if got := err.Error(); got != tt.want {
				t.Errorf("Write error is %q, want %q", got, tt.want)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("Write error %v does not wrap %v", err, tt.wantErr)
			}
			if got := len(tt.sink.writes); got != 0 {
				t.Errorf("Write made %d writes before failing, want 0", got)
			}
		})
	}
}
