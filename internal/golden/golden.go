// Package golden compares test output with the golden files under testdata.
package golden

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

//nolint:gochecknoglobals // one -update flag shared by every golden test
var update = flag.Bool("update", false, "rewrite golden files")

// Check compares got with testdata/<name>.golden beside the calling test.
func Check(tb testing.TB, name string, got []byte) {
	tb.Helper()
	path := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			tb.Fatalf("golden %s: %v", name, err)
		}
		if err := os.WriteFile(path, got, 0o600); err != nil {
			tb.Fatalf("golden %s: %v", name, err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		tb.Fatalf("golden %s: %v (run this package's tests with -update to write it)", name, err)
	}
	if !bytes.Equal(got, want) {
		tb.Errorf("golden %s differs\n--- got\n%s\n--- want\n%s", name, got, want)
	}
}
