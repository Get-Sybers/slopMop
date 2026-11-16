package command

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/get-sybers/slopmop/internal/cli"
	"github.com/get-sybers/slopmop/internal/evidencetest"
	"github.com/get-sybers/slopmop/internal/golden"
	"github.com/get-sybers/slopmop/internal/inventory"
)

// harness runs one command line against a private state file.
type harness struct {
	t         *testing.T
	statePath string
}

func newHarness(t *testing.T) harness {
	t.Helper()
	return harness{t: t, statePath: filepath.Join(t.TempDir(), "state.json")}
}

func (h harness) run(args ...string) (string, error) {
	h.t.Helper()
	var out bytes.Buffer
	app := cli.New("slopmop", &out)
	env := Env{
		Stdout:    &out,
		StatePath: func() (string, error) { return h.statePath, nil },
		Local:     time.FixedZone("test", 10*60*60),
	}
	if err := Register(app, env); err != nil {
		h.t.Fatal(err)
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
				args := append([]string{"file", "list", "--evidence", folder}, v.args...)
				out, err := newHarness(t).run(args...)
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
	folder := evidencetest.Copy(t, "bash")
	every := []string{"file", "list", "--evidence", folder}
	want, err := newHarness(t).run(every...)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range roles {
		every = append(every, "-"+string(r.Name))
	}
	got, err := newHarness(t).run(every...)
	if err != nil {
		t.Fatalf("a role is not a selector: %v", err)
	}
	if got != want {
		t.Errorf("every role selected differs from none selected")
	}
}

func TestFileListAliases(t *testing.T) {
	folder := evidencetest.Copy(t, "powershell")
	want, err := newHarness(t).run("file", "list", "--evidence", folder)
	if err != nil {
		t.Fatal(err)
	}
	got, err := newHarness(t).run("files", "ls", "--evidence="+folder)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("files ls differs from file list")
	}
}

func TestFolderPrecedence(t *testing.T) {
	bash, powershell := evidencetest.Copy(t, "bash"), evidencetest.Copy(t, "powershell")
	h := newHarness(t)

	if _, err := h.run("file", "list"); !errors.Is(err, ErrNoEvidence) {
		t.Fatalf("no selection: error = %v, want ErrNoEvidence", err)
	}
	if _, err := h.run("evidence", "select", bash); err != nil {
		t.Fatal(err)
	}
	selected, err := h.run("file", "list", "-q")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(selected, "step01_recon.sh") {
		t.Errorf("the selection is not read: %q", selected)
	}
	given, err := h.run("file", "list", "-q", "--evidence", powershell)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(given, "step01_inventory.ps1") || strings.Contains(given, "step01_recon.sh") {
		t.Errorf("--evidence does not win over the selection: %q", given)
	}
}

func TestEvidenceFlagNeedsNoState(t *testing.T) {
	h := newHarness(t)
	if err := os.WriteFile(h.statePath, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.run("file", "list", "--evidence", evidencetest.Copy(t, "bash")); err != nil {
		t.Errorf("a corrupt state file broke --evidence: %v", err)
	}
	if _, err := h.run("file", "list"); err == nil || !strings.Contains(err.Error(), "evidence select") {
		t.Errorf("error = %v, want one that names the repair", err)
	}
	if _, err := h.run("evidence", "select", t.TempDir()); err != nil {
		t.Errorf("evidence select did not replace the corrupt state file: %v", err)
	}
}

func TestFileListNotFolder(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := newHarness(t).run("file", "list", "--evidence", missing); !errors.Is(err, inventory.ErrNotFolder) {
		t.Errorf("error = %v, want ErrNotFolder", err)
	}
}

func TestEvidenceSelect(t *testing.T) {
	folder := t.TempDir()
	file := filepath.Join(folder, "file.txt")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t)

	out, err := h.run("evidence", "select")
	if err != nil || out != "no evidence folder selected\n" {
		t.Errorf("before a selection: %q, %v", out, err)
	}
	out, err = h.run("evidence", "select", folder)
	if err != nil || out != "selected evidence folder "+folder+"\n" {
		t.Errorf("select: %q, %v", out, err)
	}
	out, err = h.run("ev", "select")
	if err != nil || out != "selected: "+folder+"\n" {
		t.Errorf("after a selection: %q, %v", out, err)
	}

	rejected := []struct {
		name   string
		folder string
	}{
		{"a missing folder", filepath.Join(folder, "missing")},
		{"a file", file},
		{"an empty string", ""},
	}
	for _, c := range rejected {
		t.Run(c.name, func(t *testing.T) {
			if _, err := h.run("evidence", "select", c.folder); !errors.Is(err, inventory.ErrNotFolder) {
				t.Errorf("error = %v, want ErrNotFolder", err)
			}
		})
	}
	if out, _ := h.run("evidence", "select"); out != "selected: "+folder+"\n" {
		t.Errorf("a rejected folder replaced the selection: %q", out)
	}
}

func TestEvidenceSelectKeepsStateOutOfTheEvidence(t *testing.T) {
	folder := t.TempDir()
	h := harness{t: t, statePath: filepath.Join(folder, "config", "state.json")}
	if _, err := h.run("evidence", "select", folder); err == nil || !strings.Contains(err.Error(), "inside the evidence folder") {
		t.Errorf("error = %v, want a refusal", err)
	}
	if entries, err := os.ReadDir(folder); err != nil || len(entries) != 0 {
		t.Errorf("the evidence folder was written to: %v, %v", entries, err)
	}
}

func TestRegisterBindsBothWays(t *testing.T) {
	nouns, err := loadNouns()
	if err != nil {
		t.Fatal(err)
	}
	env := Env{}
	builders := map[string]builder{"evidence select": env.evidenceSelect, "file list": env.fileList}
	var declared []string
	for _, n := range nouns {
		for _, v := range n.Verbs {
			declared = append(declared, n.Name+" "+v.Name)
		}
	}
	if want := []string{"evidence select", "file list"}; !slices.Equal(declared, want) {
		t.Errorf("nouns.json declares %v, want %v", declared, want)
	}

	delete(builders, "file list")
	if err := register(cli.New("slopmop", &bytes.Buffer{}), nouns, builders); err == nil ||
		!strings.Contains(err.Error(), "file list, which has no implementation") {
		t.Errorf("a declared verb without an implementation: error = %v", err)
	}
	builders = map[string]builder{"evidence select": env.evidenceSelect, "file list": env.fileList, "file show": env.fileList}
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
