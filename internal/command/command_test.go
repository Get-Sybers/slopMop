package command

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/get-sybers/slopmop/internal/cli"
	"github.com/get-sybers/slopmop/internal/evidencetest"
	"github.com/get-sybers/slopmop/internal/golden"
	"github.com/get-sybers/slopmop/internal/inventory"
)

func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	app := cli.New("slopmop", &out)
	if err := Register(app, Env{Stdout: &out, Local: time.FixedZone("test", 10*60*60)}); err != nil {
		t.Fatal(err)
	}
	err := app.Run(args)
	return out.String(), err
}

func TestFileListViews(t *testing.T) {
	views := []struct {
		name string
		args []string
	}{
		{"default", nil},
		{"wide", []string{"-o", "wide"}},
		{"json", []string{"-o", "json"}},
		{"quiet", []string{"-q"}},
		{"no-headers", []string{"--no-headers"}},
		{"local", []string{"--tz", "local"}},
		{"scripts", []string{"-script"}},
		{"outputs-and-other", []string{"-output", "-other", "-o", "wide"}},
	}
	for _, fixture := range evidencetest.List() {
		folder := evidencetest.Copy(t, fixture)
		for _, v := range views {
			t.Run(fixture+"/"+v.name, func(t *testing.T) {
				out, err := run(t, append([]string{"file", "list", "--inputdir", folder}, v.args...)...)
				if err != nil {
					t.Fatal(err)
				}
				golden.Check(t, fixture+"-"+v.name, []byte(out))
			})
		}
	}
}

func TestFileListSelectorsAreTheRoles(t *testing.T) {
	roles, err := inventory.LoadRoles()
	if err != nil {
		t.Fatal(err)
	}
	every := []string{"file", "list", "--inputdir", evidencetest.Copy(t, "bash")}
	want, err := run(t, every...)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range roles {
		every = append(every, "-"+string(r.Name))
	}
	got, err := run(t, every...)
	if err != nil {
		t.Fatalf("a role is not a selector: %v", err)
	}
	if got != want {
		t.Errorf("every role selected differs from none selected")
	}
}

func TestFileListAliases(t *testing.T) {
	folder := evidencetest.Copy(t, "powershell")
	want, err := run(t, "file", "list", "--inputdir", folder)
	if err != nil {
		t.Fatal(err)
	}
	got, err := run(t, "files", "ls", "--inputdir="+folder)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("files ls differs from file list")
	}
}

func TestFileListNeedsInputDir(t *testing.T) {
	out, err := run(t, "file", "list")
	if !errors.Is(err, cli.ErrUsage) || err.Error() != "file list needs --inputdir <folder>" {
		t.Errorf("error = %v, want the usage error that names --inputdir", err)
	}
	if out != "" {
		t.Errorf("output = %q, want none", out)
	}
}

func TestFileListNotFolder(t *testing.T) {
	folder := evidencetest.Copy(t, "bash")
	paths := map[string]string{
		"a missing folder": folder + "/missing",
		"a file":           folder + "/20250301_103300_notes.txt",
	}
	for name, path := range paths {
		t.Run(name, func(t *testing.T) {
			if _, err := run(t, "file", "list", "--inputdir", path); !errors.Is(err, inventory.ErrNotFolder) {
				t.Errorf("error = %v, want ErrNotFolder", err)
			}
		})
	}
}

func TestRegisterBindsBothWays(t *testing.T) {
	nouns, err := loadNouns()
	if err != nil {
		t.Fatal(err)
	}
	env := Env{}
	var declared []string
	for _, n := range nouns {
		for _, v := range n.Verbs {
			declared = append(declared, n.Name+" "+v.Name)
		}
	}
	if want := []string{"file list"}; !slices.Equal(declared, want) {
		t.Errorf("nouns.json declares %v, want %v", declared, want)
	}

	if err := register(cli.New("slopmop", &bytes.Buffer{}), nouns, map[string]builder{}); err == nil ||
		!strings.Contains(err.Error(), "file list, which has no implementation") {
		t.Errorf("a declared verb without an implementation: error = %v", err)
	}
	builders := map[string]builder{"file list": env.fileList, "file show": env.fileList}
	if err := register(cli.New("slopmop", &bytes.Buffer{}), nouns, builders); err == nil ||
		!strings.Contains(err.Error(), "does not declare file show") {
		t.Errorf("an implementation without a declaration: error = %v", err)
	}
}

func TestDecodeNounsRejects(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want string
	}{
		{"not json", `{`, "unexpected"},
		{"unknown field", `{"nouns":[],"extra":1}`, "unknown field"},
		{"trailing data", `{"nouns":[]} []`, "after the document"},
		{"no nouns", `{"nouns":[]}`, "no nouns"},
		{"noun without verbs", `{"nouns":[{"name":"a","summary":"s"}]}`, "needs a name, a summary and a verb"},
		{"verb without a summary", `{"nouns":[{"name":"a","summary":"s","verbs":[{"name":"v"}]}]}`, "needs a name and a summary"},
		{"lower-case header", `{"nouns":[{"name":"a","summary":"s","verbs":[{"name":"v","summary":"s",` +
			`"columns":[{"header":"name","key":"name"}]}]}]}`, "a v:"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := decodeNouns([]byte(c.doc)); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("decodeNouns error = %v, want one containing %q", err, c.want)
			}
		})
	}
}
