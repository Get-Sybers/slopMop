// Package evidencetest gives tests the evidence fixtures as real folders.
package evidencetest

import (
	"embed"
	"encoding/json"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
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
