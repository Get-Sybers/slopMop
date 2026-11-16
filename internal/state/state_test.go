package state

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSaveThenLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new", "state.json")
	want := State{Evidence: filepath.Join(t.TempDir(), "case")}
	if err := want.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("Load = %+v, want %+v", got, want)
	}
	if runtime.GOOS == "windows" {
		return
	}
	for name, want := range map[string]os.FileMode{path: 0o600, filepath.Dir(path): 0o700} {
		info, statErr := os.Stat(name)
		if statErr != nil {
			t.Fatal(statErr)
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("%s mode = %o, want %o", name, got, want)
		}
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("%d files beside the state file, want none", len(entries)-1)
	}
}

func TestLoadMissingFile(t *testing.T) {
	got, err := Load(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got != (State{}) {
		t.Errorf("Load = %+v, want the zero State", got)
	}
}

func TestLoadRejects(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want string
	}{
		{"not json", `{`, "unexpected"},
		{"unknown field", `{"evidence":"","node":"x"}`, "unknown field"},
		{"trailing data", `{"evidence":""} {}`, "after the document"},
		{"relative folder", `{"evidence":"case"}`, "not an absolute path"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			if err := os.WriteFile(path, []byte(c.doc), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("Load error = %v, want one containing %q", err, c.want)
			}
		})
	}
}

func TestPath(t *testing.T) {
	dir := t.TempDir()
	for _, key := range []string{"XDG_CONFIG_HOME", "AppData", "HOME"} {
		t.Setenv(key, dir)
	}
	got, err := Path()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join("slopmop", "state.json"); !strings.HasSuffix(got, want) || !strings.HasPrefix(got, dir) {
		t.Errorf("Path() = %s, want %s under %s", got, want, dir)
	}
}
