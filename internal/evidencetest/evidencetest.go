// Package evidencetest gives tests the evidence fixtures as real folders.
package evidencetest

import (
	"embed"
	"encoding/csv"
	"encoding/json"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

//go:embed all:testdata
var fixtures embed.FS

// List returns the fixture names, sorted.
func List() []string {
	entries, err := fixtures.ReadDir("testdata")
	if err != nil {
		panic(err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names
}

// Copy writes a fixture into a temporary folder and sets each modified time
// from the fixture's manifest, because a checkout does not keep them.
func Copy(tb testing.TB, name string) string {
	tb.Helper()
	times := loadTimes(tb, name)
	entries, err := fixtures.ReadDir(path.Join("testdata", name))
	if err != nil {
		tb.Fatalf("fixture %s: %v", name, err)
	}
	if len(entries) != len(times) {
		tb.Fatalf("fixture %s: %d files, %d manifest entries", name, len(entries), len(times))
	}
	folder := tb.TempDir()
	for _, e := range entries {
		modified, ok := times[e.Name()]
		if !ok {
			tb.Fatalf("fixture %s: %s has no manifest entry", name, e.Name())
		}
		data, err := fs.ReadFile(fixtures, path.Join("testdata", name, e.Name()))
		if err != nil {
			tb.Fatalf("fixture %s: %v", name, err)
		}
		target := filepath.Join(folder, e.Name())
		if err := os.WriteFile(target, data, 0o600); err != nil {
			tb.Fatalf("fixture %s: %v", name, err)
		}
		if err := os.Chtimes(target, modified, modified); err != nil {
			tb.Fatalf("fixture %s: %v", name, err)
		}
	}
	return folder
}

func loadTimes(tb testing.TB, name string) map[string]time.Time {
	tb.Helper()
	data, err := fixtures.ReadFile(path.Join("testdata", name+".times.json"))
	if err != nil {
		tb.Fatalf("fixture %s: %v", name, err)
	}
	var times map[string]time.Time
	if err := json.Unmarshal(data, &times); err != nil {
		tb.Fatalf("fixture %s: %v", name, err)
	}
	return times
}

// Portable returns a saved table of files, as CSV, as every machine writes
// it: each whole path becomes <folder> and the name of the file below it, and
// each creation time, which is when the fixture was copied, <created>.
func Portable(tb testing.TB, table, folder string) string {
	tb.Helper()
	records, err := csv.NewReader(strings.NewReader(table)).ReadAll()
	if err != nil || len(records) == 0 {
		tb.Fatalf("the table of files is not CSV with a header: %v", err)
	}
	name, whole := slices.Index(records[0], "name"), slices.Index(records[0], "path")
	if name < 0 || whole < 0 {
		tb.Fatalf("the table of files has the columns %q, want name and path among them", records[0])
	}
	created := slices.Index(records[0], "created")
	for _, r := range records[1:] {
		if want := filepath.Join(folder, filepath.FromSlash(r[name])); r[whole] != want {
			tb.Errorf("the path of %s = %q, want %q", r[name], r[whole], want)
		}
		r[whole] = "<folder>/" + r[name]
		if created >= 0 {
			r[created] = "<created>"
		}
	}
	var out strings.Builder
	w := csv.NewWriter(&out)
	if err := w.WriteAll(records); err != nil {
		tb.Fatalf("the table of files: %v", err)
	}
	return out.String()
}
