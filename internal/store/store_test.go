package store_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/get-sybers/slopmop/internal/store"
)

// write fills a database with three files out of timeline order, so the reads
// must restore it: an output, a script that writes it, and a later output.
func write(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open("")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	w, err := db.Writer()
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	files := []store.File{
		{Path: "b.sh", Name: "b.sh", Role: "script", SHA256: "aa", Effective: at(20)},
		{Path: "a.log", Name: "a.log", Role: "output", SHA256: "bb", Effective: at(10)},
		{Path: "c.log", Name: "c.log", Role: "output", SHA256: "cc", Effective: at(30), Modified: at(30)},
	}
	for id, f := range files {
		if err := w.AddFile(int64(id), f); err != nil {
			t.Fatalf("add file %d: %v", id, err)
		}
	}
	add := func(file int64, name string, ind ...store.Indicator) {
		if err := w.AddActivity(file, 0, store.Activity{Name: name, Lines: 1, Tactics: []string{"Execution"}}); err != nil {
			t.Fatalf("add activity: %v", err)
		}
		for i, m := range ind {
			if err := w.AddIndicator(file, i, m); err != nil {
				t.Fatalf("add indicator: %v", err)
			}
		}
	}
	add(0, "FileDownload", store.Indicator{Type: "IPv4", Value: "10.0.0.1"}, store.Indicator{Type: "IPv4", Value: "10.0.0.2"})
	add(1, "FileDownload", store.Indicator{Type: "IPv4", Value: "10.0.0.1"}, store.Indicator{Type: "URL", Value: "http://x"})
	add(2, "MailboxAccess", store.Indicator{Type: "URL", Value: "http://x"})
	if err := w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	return db
}

func at(sec int64) time.Time { return time.Unix(sec, 0).UTC() }

func TestFilesInTimelineOrder(t *testing.T) {
	db := write(t)
	defer func() { _ = db.Close() }()
	files, err := db.Files()
	if err != nil {
		t.Fatalf("files: %v", err)
	}
	wantPath := []string{"a.log", "b.sh", "c.log"}
	wantTurn := []int{0, 1, 1}
	if len(files) != len(wantPath) {
		t.Fatalf("got %d files, want %d", len(files), len(wantPath))
	}
	for i, f := range files {
		if f.Path != wantPath[i] || f.Turn != wantTurn[i] {
			t.Errorf("file %d: got (%s, turn %d), want (%s, turn %d)", i, f.Path, f.Turn, wantPath[i], wantTurn[i])
		}
	}
	if got := files[2].Modified; !got.Equal(at(30)) {
		t.Errorf("modified round-trip: got %v, want %v", got, at(30))
	}
}

func TestIndicatorCountsAreDistinct(t *testing.T) {
	db := write(t)
	defer func() { _ = db.Close() }()
	counts, err := db.IndicatorCounts()
	if err != nil {
		t.Fatalf("counts: %v", err)
	}
	want := []store.TypeCount{{Type: "IPv4", Count: 2}, {Type: "URL", Count: 1}}
	if !reflect.DeepEqual(counts, want) {
		t.Errorf("counts: got %v, want %v", counts, want)
	}
}

func TestFilesByActivityGroupInTimelineOrder(t *testing.T) {
	db := write(t)
	defer func() { _ = db.Close() }()
	got, err := db.FilesByActivity()
	if err != nil {
		t.Fatalf("by activity: %v", err)
	}
	want := []store.NameFiles{
		{Name: "FileDownload", Files: []string{"a.log", "b.sh"}},
		{Name: "MailboxAccess", Files: []string{"c.log"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("by activity: got %v, want %v", got, want)
	}
}
