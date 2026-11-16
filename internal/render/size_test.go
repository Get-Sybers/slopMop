package render_test

import (
	"math"
	"strconv"
	"testing"

	"github.com/get-sybers/slopmop/internal/render"
)

func TestSizes(t *testing.T) {
	const (
		kib = int64(1) << (10 * (iota + 1))
		mib
		gib
		tib
		pib
		eib
	)
	tests := []struct {
		bytes int64
		want  string
	}{
		{0, "0 B"},
		{1, "1 B"},
		{1023, "1023 B"},
		{1024, "1.0 KiB"},
		{1228, "1.2 KiB"},
		{1536, "1.5 KiB"},
		{1280, "1.3 KiB"},
		{1279, "1.2 KiB"},
		{10*kib - 52, "9.9 KiB"},
		{10*kib - 51, "10 KiB"},
		{10 * kib, "10 KiB"},
		{10*kib + 511, "10 KiB"},
		{10*kib + 512, "11 KiB"},
		{54 * kib, "54 KiB"},
		{1023*kib + 511, "1023 KiB"},
		{1023*kib + 512, "1.0 MiB"},
		{mib - 1, "1.0 MiB"},
		{mib, "1.0 MiB"},
		{54 * mib, "54 MiB"},
		{gib - 1, "1.0 GiB"},
		{gib, "1.0 GiB"},
		{3 * gib / 2, "1.5 GiB"},
		{512 * gib, "512 GiB"},
		{tib, "1.0 TiB"},
		{pib, "1.0 PiB"},
		{eib - 1, "1.0 EiB"},
		{eib, "1.0 EiB"},
		{math.MaxInt64, "8.0 EiB"},
		{-1, "-1 B"},
		{math.MinInt64, "-9223372036854775808 B"},
	}
	for _, tt := range tests {
		t.Run(strconv.FormatInt(tt.bytes, 10), func(t *testing.T) {
			table := render.Table{
				Columns: []render.Column{{Header: "SIZE", Key: "size"}},
				Rows:    [][]render.Value{{render.Size(tt.bytes)}},
			}
			raw := strconv.FormatInt(tt.bytes, 10)
			if got, want := write(t, table, render.Options{NoHeaders: true}), tt.want+"\n"; got != want {
				t.Errorf("default view wrote %q, want %q", got, want)
			}
			if got, want := write(t, table, render.Options{View: render.Wide, NoHeaders: true}), raw+"\n"; got != want {
				t.Errorf("wide view wrote %q, want %q", got, want)
			}
			want := "[\n  {\n    \"size\": " + raw + "\n  }\n]\n"
			if got := write(t, table, render.Options{View: render.JSON}); got != want {
				t.Errorf("json view wrote %q, want %q", got, want)
			}
		})
	}
}
