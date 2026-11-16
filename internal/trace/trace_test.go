package trace

import (
	"testing"

	"github.com/get-sybers/slopmop/internal/evidence"
	"github.com/get-sybers/slopmop/internal/evidencetest"
	"github.com/get-sybers/slopmop/internal/indicator"
	"github.com/get-sybers/slopmop/internal/inventory"
	"github.com/get-sybers/slopmop/internal/tactic"
)

func loadTables(t *testing.T) (tactic.Table, indicator.Table) {
	t.Helper()
	tac, err := tactic.LoadTactics()
	if err != nil {
		t.Fatal(err)
	}
	ind, err := indicator.LoadPatterns()
	if err != nil {
		t.Fatal(err)
	}
	return tac, ind
}

func TestBuildBash(t *testing.T) {
	folder := evidencetest.Copy(t, "bash")
	res, err := inventory.ReadAll(folder)
	if err != nil {
		t.Fatal(err)
	}
	tac, ind := loadTables(t)
	tl := Build(res.Files, res.Texts, tac, ind)
	if len(tl.Steps) == 0 {
		t.Fatal("no steps")
	}
	scripts := 0
	for _, s := range tl.Steps {
		if s.File.Role == evidence.Script {
			scripts++
			if s.Turn < 1 {
				t.Errorf("%s: turn %d, want >= 1", s.File.Path, s.Turn)
			}
		}
	}
	if scripts == 0 {
		t.Error("no scripts in timeline")
	}
}

func TestBuildHasToolsAndTactics(t *testing.T) {
	folder := evidencetest.Copy(t, "bash")
	res, err := inventory.ReadAll(folder)
	if err != nil {
		t.Fatal(err)
	}
	tac, ind := loadTables(t)
	tl := Build(res.Files, res.Texts, tac, ind)
	foundTools := false
	foundTactics := false
	for _, s := range tl.Steps {
		if len(s.Tools) > 0 {
			foundTools = true
		}
		if len(s.Tactics) > 0 {
			foundTactics = true
		}
	}
	if !foundTools {
		t.Error("no tools extracted from any script")
	}
	if !foundTactics {
		t.Error("no tactics classified for any script")
	}
}

func TestBuildHasIndicators(t *testing.T) {
	folder := evidencetest.Copy(t, "bash")
	res, err := inventory.ReadAll(folder)
	if err != nil {
		t.Fatal(err)
	}
	tac, ind := loadTables(t)
	tl := Build(res.Files, res.Texts, tac, ind)
	total := 0
	for _, s := range tl.Steps {
		total += s.Indicators
	}
	if total == 0 {
		t.Error("no indicators found in any file")
	}
}

func TestBuildEmpty(t *testing.T) {
	tac, ind := loadTables(t)
	tl := Build(nil, nil, tac, ind)
	if len(tl.Steps) != 0 {
		t.Errorf("steps = %d, want 0", len(tl.Steps))
	}
}

func TestSortByTime(t *testing.T) {
	a := evidence.File{Path: "b.sh"}
	b := evidence.File{Path: "a.sh"}
	sorted := sortByTime([]evidence.File{a, b})
	if sorted[0].Path != "a.sh" || sorted[1].Path != "b.sh" {
		t.Errorf("sorted = %v %v, want a.sh b.sh", sorted[0].Path, sorted[1].Path)
	}
}

func TestLinkOutputsByBaseName(t *testing.T) {
	files := []evidence.File{
		{Path: "run.sh", Role: evidence.Script},
		{Path: "run.ps1", Role: evidence.Script},
		{Path: "out.txt", Role: evidence.Output},
		{Path: "loot/dump.log", Role: evidence.Output},
		{Path: "unrelated.txt", Role: evidence.Output},
	}
	texts := map[string]string{
		"run.sh":  "id > ./out.txt\nid >> ./out.txt\n",
		"run.ps1": "whoami | Out-File -FilePath C:\\work\\dump.log\n",
	}
	tac, ind := loadTables(t)
	got := map[string][]string{}
	for _, s := range Build(files, texts, tac, ind).Steps {
		got[s.File.Path] = s.Outputs
	}
	if o := got["run.sh"]; len(o) != 1 || o[0] != "out.txt" {
		t.Errorf("run.sh outputs = %v, want [out.txt]", o)
	}
	if o := got["run.ps1"]; len(o) != 1 || o[0] != "loot/dump.log" {
		t.Errorf("run.ps1 outputs = %v, want [loot/dump.log]", o)
	}
}

func TestBaseName(t *testing.T) {
	cases := map[string]string{
		"out.txt":             "out.txt",
		"./out.txt":           "out.txt",
		"/tmp/a/out.txt":      "out.txt",
		`C:\loot\out.txt`:     "out.txt",
		`.\sub/mixed\out.txt`: "out.txt",
	}
	for in, want := range cases {
		if got := baseName(in); got != want {
			t.Errorf("baseName(%q) = %q, want %q", in, got, want)
		}
	}
}
