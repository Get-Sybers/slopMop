package render

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// A buffer, a regular file and a closed file are not terminals, and the
// environment turns colour off whatever the writer is.
func TestTakesColour(t *testing.T) {
	file, err := os.Create(filepath.Join(t.TempDir(), "out.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if TakesColour(&bytes.Buffer{}) || TakesColour(file) {
		t.Error("a buffer or a regular file takes colour")
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if TakesColour(file) {
		t.Error("a closed file takes colour")
	}
	t.Setenv(noColour, "1")
	if TakesColour(os.Stdout) {
		t.Error("colour with the variable set")
	}
	t.Setenv(noColour, "")
	t.Setenv("TERM", "dumb")
	if TakesColour(os.Stdout) {
		t.Error("colour on a dumb terminal")
	}
}
