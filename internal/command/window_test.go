package command

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/get-sybers/slopmop/internal/cli"
	"github.com/get-sybers/slopmop/internal/evidencetest"
)

// A side of the window is a day or a day and a time, in UTC unless it names
// a zone; a day alone is the whole day.
func TestReadWindow(t *testing.T) {
	at := func(text string) time.Time {
		parsed, err := time.Parse(time.RFC3339Nano, text)
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	for _, tt := range []struct {
		name        string
		from, until string
		want        window
		fails       string
	}{
		{"neither", "", "", window{}, ""},
		{"a day on each side", "2026-10-22", "2026-10-23", window{at("2026-10-22T00:00:00Z"), at("2026-10-23T23:59:59.999999999Z")}, ""},
		{"one day", "2026-10-22", "2026-10-22", window{at("2026-10-22T00:00:00Z"), at("2026-10-22T23:59:59.999999999Z")}, ""},
		{"to the minute", "2026-10-22T09:30", "", window{from: at("2026-10-22T09:30:00Z")}, ""},
		{"to the second", "", "2026-10-22T09:30:15", window{until: at("2026-10-22T09:30:15Z")}, ""},
		{"with Z", "2026-10-22T09:30:00Z", "", window{from: at("2026-10-22T09:30:00Z")}, ""},
		{"with a zone", "2026-10-22T11:30:00+02:00", "2026-10-22T11:45+02:00", window{at("2026-10-22T09:30:00Z"), at("2026-10-22T09:45:00Z")}, ""},
		{"the same instant", "2026-10-22T09:30", "2026-10-22T09:30", window{at("2026-10-22T09:30:00Z"), at("2026-10-22T09:30:00Z")}, ""},
		{"not a time", "yesterday", "", window{}, `-from takes a day or a day and a time, such as 2026-10-22 or 2026-10-22T09:30:00Z, not "yesterday"`},
		{"no such day", "", "2026-02-30", window{}, `-until takes a day or a day and a time`},
		{"a time alone", "09:30", "", window{}, `-from takes a day or a day and a time`},
		{"the end before the beginning", "2026-10-23", "2026-10-22", window{}, "-until 2026-10-22 is before -from 2026-10-23"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := &cli.Args{Options: map[string]string{}}
			if tt.from != "" {
				a.Options[fromOption] = tt.from
			}
			if tt.until != "" {
				a.Options[untilOption] = tt.until
			}
			got, err := readWindow(a)
			switch {
			case tt.fails != "":
				if err == nil || !errors.Is(err, cli.ErrUsage) || !strings.Contains(err.Error(), tt.fails) {
					t.Errorf("error = %v, want a usage error that holds %q", err, tt.fails)
				}
			case err != nil:
				t.Fatal(err)
			case !got.from.Equal(tt.want.from) || !got.until.Equal(tt.want.until):
				t.Errorf("window = %v to %v, want %v to %v", got.from, got.until, tt.want.from, tt.want.until)
			}
		})
	}
}

// A run with a window reads the files in it, says in its summary what it
// left out, and saves only what it read. A run without one says nothing of it.
func TestReportWindow(t *testing.T) {
	folder := evidencetest.Copy(t, "linux")
	readout, saved := report(t, folder, "summary", "-from", "2026-10-22T09:10", "-until", "2026-10-22T09:20:00Z")
	for _, want := range []string{
		"  files       3   3 scripts, 0 outputs\n",
		"  left out    11  before 2026-10-22T09:10:00Z or after 2026-10-22T09:20:00Z\n",
	} {
		if !strings.Contains(readout, want) {
			t.Errorf("the summary lacks %q:\n%s", want, readout)
		}
	}
	if got := len(rows(t, filepath.Join(saved, "files.json"))); got != 3 {
		t.Errorf("files.json holds %d files, want the 3 in the window", got)
	}
	found := false
	for _, row := range rows(t, filepath.Join(saved, "report.json")) {
		if row["item"] == leftOut {
			found = row["section"] == sectionSummary && row["value"] == float64(11) && row["detail"] == "before 2026-10-22T09:10:00Z or after 2026-10-22T09:20:00Z"
		}
	}
	if !found {
		t.Errorf("report.json has no summary row that counts the 11 files left out")
	}
	for name, body := range map[string]string{"report.txt": readFile(t, filepath.Join(saved, "report.txt")), "report.md": readFile(t, filepath.Join(saved, "report.md"))} {
		if !strings.Contains(body, "left out") || strings.Contains(body, "step01_recon") {
			t.Errorf("%s does not state the window, or holds a file outside it", name)
		}
	}
	for side, want := range map[string]string{"-from": "  left out    13  before 2026-10-22T09:35:00Z\n", "-until": "  left out    13  after 2026-10-22T09:00:00Z\n"} {
		at := map[string]string{"-from": "2026-10-22T09:35", "-until": "2026-10-22T09:00"}[side]
		if one, _ := report(t, folder, "summary", side, at); !strings.Contains(one, want) {
			t.Errorf("%s alone: the summary lacks %q:\n%s", side, want, one)
		}
	}
	whole, all := report(t, folder, "summary")
	if strings.Contains(whole, "left out") || strings.Contains(readFile(t, filepath.Join(all, "report.json")), "left out") {
		t.Errorf("a run with no window speaks of files left out:\n%s", whole)
	}
	if _, err := run(t, "-inputdir", folder, "report", "-from", "soon"); !errors.Is(err, cli.ErrUsage) {
		t.Errorf("-from soon: error = %v, want a usage error", err)
	}
}
