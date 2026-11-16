package golden

import (
	"os"
	"path/filepath"
	"testing"
)

// recorder stands in for a test so a failing Check can be observed.
type recorder struct {
	testing.TB
	failed bool
}

func (r *recorder) Helper()               {}
func (r *recorder) Errorf(string, ...any) { r.failed = true }
func (r *recorder) Fatalf(string, ...any) { r.failed = true }

func TestCheck(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.Mkdir("testdata", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("testdata", "kept.golden"), []byte("same\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		golden string
		got    string
		failed bool
	}{
		{"equal bytes pass", "kept", "same\n", false},
		{"a difference fails", "kept", "other\n", true},
		{"a missing file fails", "absent", "same\n", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := &recorder{TB: t}
			Check(r, c.golden, []byte(c.got))
			if r.failed != c.failed {
				t.Errorf("failed = %v, want %v", r.failed, c.failed)
			}
		})
	}
}
