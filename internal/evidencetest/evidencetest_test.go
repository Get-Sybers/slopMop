package evidencetest

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestList(t *testing.T) {
	want := []string{"bash", "entra", "linux", "lolbin", "powershell"}
	if got := List(); !slices.Equal(got, want) {
		t.Errorf("List() = %v, want %v", got, want)
	}
}

func TestCopy(t *testing.T) {
	cases := []struct {
		fixture  string
		files    int
		file     string
		modified string
	}{
		{"bash", 17, "20250301_101500_step01_recon.sh", "2025-03-01T10:15:03Z"},
		{"bash", 17, "20250301_104100_ca_backup.p12", "2025-03-01T10:41:03Z"},
		{"bash", 17, "adsync_1740824625.txt", "2025-03-01T10:23:48Z"},
		{"entra", 11, "agent_20261015_093500.jsonl", "2026-10-15T09:35:03Z"},
		{"lolbin", 11, "20261020_103000_step07_cleanup.bat", "2026-10-20T10:30:03Z"},
		{"powershell", 16, "hosts_20250302_090030.csv", "2025-03-02T09:00:33Z"},
		{"powershell", 16, "ca01_20250302_092210.cer", "2025-03-02T09:22:13Z"},
	}
	for _, c := range cases {
		t.Run(c.fixture+"/"+c.file, func(t *testing.T) {
			folder := Copy(t, c.fixture)
			entries, err := os.ReadDir(folder)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != c.files {
				t.Errorf("%d files, want %d", len(entries), c.files)
			}
			got, err := os.ReadFile(filepath.Join(folder, c.file))
			if err != nil {
				t.Fatal(err)
			}
			want, err := fixtures.ReadFile("testdata/" + c.fixture + "/" + c.file)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("%d bytes on disk differ from the %d embedded", len(got), len(want))
			}
			info, err := os.Stat(filepath.Join(folder, c.file))
			if err != nil {
				t.Fatal(err)
			}
			if got := info.ModTime().UTC().Format(time.RFC3339); got != c.modified {
				t.Errorf("modified = %s, want %s", got, c.modified)
			}
		})
	}
}

func TestManifestsNameTheirFiles(t *testing.T) {
	for _, name := range List() {
		t.Run(name, func(t *testing.T) {
			times := loadTimes(t, name)
			entries, err := fixtures.ReadDir("testdata/" + name)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range entries {
				if _, ok := times[e.Name()]; !ok {
					t.Errorf("%s is not in the manifest", e.Name())
				}
				delete(times, e.Name())
			}
			for extra := range times {
				t.Errorf("the manifest names %s, which is not a fixture file", extra)
			}
		})
	}
}
