package command

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/get-sybers/slopmop/internal/activity"
	"github.com/get-sybers/slopmop/internal/cli"
	"github.com/get-sybers/slopmop/internal/evidence"
	"github.com/get-sybers/slopmop/internal/evidencetest"
	"github.com/get-sybers/slopmop/internal/exposure"
	"github.com/get-sybers/slopmop/internal/golden"
	"github.com/get-sybers/slopmop/internal/intent"
	"github.com/get-sybers/slopmop/internal/inventory"
	"github.com/get-sybers/slopmop/internal/render"
	"github.com/get-sybers/slopmop/internal/trace"
)

const watchlist = "testdata/watchlist.json"

// run drives the app as the binary does. A work folder of its own keeps an
// output folder out of the source tree.
func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	app, err := NewApp("slopmop", Env{Stdout: &out, WorkDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	err = app.Run(args)
	return out.String(), err
}

// report runs the report verb on a folder and returns the readout and the
// output folder; both paths are temporary, so the readout names placeholders.
func report(t *testing.T, folder string, extra ...string) (readout, saved string) {
	t.Helper()
	saved = filepath.Join(t.TempDir(), "out")
	out, err := run(t, append([]string{"-inputdir", folder, "report", "-outdir", saved}, extra...)...)
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(strings.ReplaceAll(out, saved, "<out>"), folder, "<folder>"), saved
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// rows reads a saved table, JSON or CSV. A cell of CSV is text, and nil when it is empty.
func rows(t *testing.T, path string) []map[string]any {
	t.Helper()
	var table []map[string]any
	if filepath.Ext(path) != ".csv" {
		if err := json.Unmarshal([]byte(readFile(t, path)), &table); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		return table
	}
	records, err := csv.NewReader(strings.NewReader(readFile(t, path))).ReadAll()
	if err != nil || len(records) == 0 {
		t.Fatalf("%s: not CSV with a header: %v", path, err)
	}
	for _, record := range records[1:] {
		row := map[string]any{}
		for i, key := range records[0] {
			row[key] = nil
			if record[i] != "" {
				row[key] = record[i]
			}
		}
		table = append(table, row)
	}
	return table
}

// tableText reads a saved table as it is compared with a golden file: the
// table of files without the temporary folder its whole paths begin with.
func tableText(t *testing.T, saved, folder, name string) string {
	t.Helper()
	text := readFile(t, filepath.Join(saved, name))
	if name == "files.csv" {
		return evidencetest.Portable(t, text, folder)
	}
	return text
}

// nest moves every file of a fixture copy whose name contains part into the sub-folder sub.
func nest(t *testing.T, folder, part, sub string) {
	t.Helper()
	entries, err := os.ReadDir(folder)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(folder, filepath.FromSlash(sub)), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Type().IsRegular() && strings.Contains(e.Name(), part) {
			if err := os.Rename(filepath.Join(folder, e.Name()), filepath.Join(folder, filepath.FromSlash(sub), e.Name())); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// Every fixture, as the screen shows it and as it is saved.
func TestReportViews(t *testing.T) {
	for _, fixture := range evidencetest.List() {
		folder := evidencetest.Copy(t, fixture)
		t.Run(fixture, func(t *testing.T) {
			readout, saved := report(t, folder)
			golden.Check(t, fixture+"-report", []byte(readout))
			for _, name := range []string{"files.csv", "trace.json", "findings.json", "targeted.json", "exposure.csv", "report.json"} {
				golden.Check(t, fixture+"-"+strings.Replace(name, ".", "-", 1), []byte(tableText(t, saved, folder, name)))
			}
		})
		t.Run(fixture+"/intel", func(t *testing.T) {
			readout, saved := report(t, folder, "-intelfile", watchlist)
			golden.Check(t, fixture+"-report-intel", []byte(readout))
			golden.Check(t, fixture+"-findings-intel-json", []byte(readFile(t, filepath.Join(saved, "findings.json"))))
		})
		t.Run(fixture+"/sections", func(t *testing.T) {
			readout, _ := report(t, folder, "remediation", "impact")
			golden.Check(t, fixture+"-report-impact", []byte(readout))
		})
	}
}

// What is saved is every section, whichever were asked for, in each format,
// and each class as JSON or CSV.
func TestReportSaves(t *testing.T) {
	folder := evidencetest.Copy(t, "linux")
	shown, saved := report(t, folder, "impact")
	if want := "-> saved to <out>: report.txt, report.md, report.html, files.csv, trace.json, intents.csv, findings.json, targeted.json, exposure.csv, report.json\n"; !strings.Contains(shown, want) {
		t.Errorf("the readout does not say where it was saved:\n%s", shown)
	}
	if strings.Contains(shown, "\nTimeline") {
		t.Errorf("the screen shows a section that was not asked for:\n%s", shown)
	}
	full, _ := report(t, folder)
	lines := slices.DeleteFunc(strings.Split(full, "\n"), func(l string) bool { return strings.HasPrefix(l, "-> saved to ") })
	text := strings.ReplaceAll(readFile(t, filepath.Join(saved, "report.txt")), folder, "<folder>")
	if text != strings.Join(lines, "\n") {
		t.Errorf("report.txt is not the full readout:\n%s", text)
	}
	if entries, err := os.ReadDir(saved); err != nil || len(entries) != 10 {
		t.Errorf("the output folder holds %d entries (%v), want 10", len(entries), err)
	}
	// Each format holds every section, and the evidence the text holds.
	markdown, page := readFile(t, filepath.Join(saved, "report.md")), readFile(t, filepath.Join(saved, "report.html"))
	for _, title := range []string{"Summary", "Tactics", "Timeline", "Findings", "Targeted", "Exposure", "Impact", "Remediation", "Mitigation"} {
		if !strings.Contains(markdown, "\n## "+title+"\n") {
			t.Errorf("report.md lacks the section %s", title)
		}
		if !strings.Contains(page, "<h2>"+title+"</h2>") {
			t.Errorf("report.html lacks the section %s", title)
		}
	}
	for _, gone := range []string{"\n## Notable files\n", "\n## Intent timeline\n", "\n### indicators\n"} {
		if strings.Contains(markdown, gone) {
			t.Errorf("report.md holds %q, which the report no longer has", gone)
		}
	}
	// The title names the folder as each format escapes it, which differs with the path.
	title, rest, _ := strings.Cut(markdown, "\n")
	if !strings.HasPrefix(title, "# slopmop report   ") {
		t.Errorf("report.md begins %q, want the title", title)
	}
	golden.Check(t, "linux-report-markdown", []byte("# slopmop report   <folder>\n"+rest))
	named := regexp.MustCompile(`(<(title|h1)>slopmop report   )[^<]*(</(title|h1)>)`)
	if got := len(named.FindAllString(page, -1)); got != 2 {
		t.Errorf("report.html names the folder in %d titles, want 2", got)
	}
	golden.Check(t, "linux-report-html", []byte(named.ReplaceAllString(page, "${1}&lt;folder&gt;${3}")))
	for _, held := range []string{"useradd -m -s /bin/bash svc", "20261022_091500_step04_persist.sh:7", "T1136.001", "password of app_rw"} {
		for name, body := range map[string]string{"report.txt": text, "report.md": markdown, "report.html": page} {
			if !strings.Contains(body, held) {
				t.Errorf("%s does not hold %q", name, held)
			}
		}
	}
	for name, least := range map[string]int{"files.csv": 14, "trace.json": 14, "findings.json": 30, "targeted.json": 5, "exposure.csv": 15, "report.json": 60} {
		if got := len(rows(t, filepath.Join(saved, name))); got < least {
			t.Errorf("%s holds %d rows, want at least %d", name, got, least)
		}
	}
}

// The sections print in the order of commands.json, whatever order they are named in.
func TestReportSections(t *testing.T) {
	folder := evidencetest.Copy(t, "lolbin")
	every, _ := report(t, folder)
	var titles []string
	for _, line := range strings.Split(every, "\n") {
		if line != "" && !strings.ContainsAny(line[:1], " [-") && !strings.HasPrefix(line, "slopmop") {
			titles = append(titles, strings.TrimSpace(strings.SplitN(line, "   ", 2)[0]))
		}
	}
	want := []string{"Summary", "Tactics", "Timeline", "Findings", "Targeted", "Exposure", "Impact", "Remediation", "Mitigation"}
	if !slices.Equal(titles, want) {
		t.Errorf("sections = %q, want %q", titles, want)
	}
	two, _ := report(t, folder, "mitigation", "tactics")
	if tactics, mitigation := strings.Index(two, "\nTactics"), strings.Index(two, "\nMitigation"); tactics < 0 || mitigation < tactics {
		t.Errorf("the sections are missing or out of order:\n%s", two)
	}
	if !strings.Contains(two, "[x] Persistence ") || !strings.Contains(two, "20261020_101500_step04_persist.ps1") || strings.Contains(two, "\nFindings") {
		t.Errorf("tactics: want the tactic of the persistence script, and no section that was not asked for:\n%s", two)
	}
}

// The findings are the activities alone: a tactic is in its own section,
// before the timeline, and an indicator is in the saved findings.
func TestReportFindingsAreActivities(t *testing.T) {
	readout, saved := report(t, evidencetest.Copy(t, "linux"), "tactics", "findings")
	tactics, findings, _ := strings.Cut(readout, "\nFindings")
	if !regexp.MustCompile(`\[x\] CredentialAccess +TA0006, AML\.TA0013 +\S`).MatchString(tactics) || strings.Contains(findings, "TA0006") {
		t.Errorf("the tactics are not in their own section:\n%s", readout)
	}
	if !strings.Contains(findings, "\n  activities\n") || strings.Contains(findings, "\n  indicators\n") || strings.Contains(findings, "\n  tactics\n") {
		t.Errorf("the findings hold more than the activities:\n%s", findings)
	}
	kinds := map[string]int{}
	for _, row := range rows(t, filepath.Join(saved, "findings.json")) {
		switch {
		case row["indicator"] != nil:
			kinds[kindIndicator]++
		case row["finding"] == kindTactic:
			kinds[kindTactic]++
		default:
			kinds[kindActivity]++
		}
	}
	if kinds[kindIndicator] == 0 || kinds[kindTactic] == 0 || kinds[kindActivity] == 0 {
		t.Errorf("findings.json holds %v, want activities, indicators and tactics", kinds)
	}
}

// artex lays a copy of the linux fixture out as ARTEX does: a run folder for
// each intent, a session file, a file that names its intent itself, and
// files that belong to no intent.
func artex(t *testing.T) string {
	t.Helper()
	folder := evidencetest.Copy(t, "linux")
	nest(t, folder, "step01", "data/tasks/7/i1041")
	nest(t, folder, "_0900", "data/tasks/7/i1041/cmd-output")
	nest(t, folder, "step02", "data/tasks/7/i1042")
	nest(t, folder, "_0905", "data/tasks/7/i1042/cmd-output")
	nest(t, folder, "step03", "data/tasks/7/i998")
	nest(t, folder, "step04", "data/tasks/7/i998")
	nest(t, folder, "step05", "data/lib/i386")
	if err := os.MkdirAll(filepath.Join(folder, "data", "noa"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(folder, "20261022_092500_step06_stage.sh"), filepath.Join(folder, "data", "noa", "exp3-worker-i1051.sh")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(folder, "audit_20261022_093500.jsonl"), filepath.Join(folder, "i1051_audit_20261022_093500.jsonl")); err != nil {
		t.Fatal(err)
	}
	return folder
}

// copied reports whether the files a run read are copies by their times: none
// has a creation time that is not after its last change.
func copied(t *testing.T, saved string) bool {
	t.Helper()
	for _, row := range rows(t, filepath.Join(saved, "files.csv")) {
		made, _ := row["created"].(string)
		changed, _ := row["modified"].(string)
		if made != "" && made <= changed {
			return false
		}
	}
	return true
}

// Each ARTEX intent is a row: its period, and the ATT&CK and ATLAS techniques
// of what its files do. A file that no folder and no name gives an intent
// belongs to none. The timeline is a block for each, and nothing else.
func TestReportIntents(t *testing.T) {
	folder := artex(t)
	readout, saved := report(t, folder, "summary", "timeline")
	// A fixture is a copy, made now and last changed when its manifest says.
	// Where a last change set to the past takes the creation time with it,
	// as on macOS, its files are as if made there, 3 seconds after their names.
	timedBy, first, last := byTimeline, "2026-10-22T09:00:00Z", "2026-10-22T09:00:40Z"
	if copied(t, saved) {
		golden.Check(t, "artex-report-intents", []byte(readout))
		golden.Check(t, "artex-intents-csv", []byte(readFile(t, filepath.Join(saved, "intents.csv"))))
	} else {
		timedBy, first, last = byCreation, "2026-10-22T09:00:03Z", "2026-10-22T09:00:43Z"
	}
	table := rows(t, filepath.Join(saved, "intents.csv"))
	var order []string
	for _, row := range table {
		order = append(order, row["intent"].(string))
	}
	if want := []string{"i1041", "i1042", "i998", "i1051"}; !slices.Equal(order, want) {
		t.Errorf("intents = %q, want %q: in the order they began", order, want)
	}
	row := find(t, table, map[string]string{"intent": "i1041", "task": "7"})
	if row["from"] != first || row["until"] != last || row["seconds"] != "40" {
		t.Errorf("i1041 runs from %v to %v, %v seconds, want %s to %s, 40", row["from"], row["until"], row["seconds"], first, last)
	}
	if row["attack"] != "T1083, T1552.005, T1007" || row["atlas"] != "AML.T0055" {
		t.Errorf("i1041 has ATT&CK %v and ATLAS %v", row["attack"], row["atlas"])
	}
	if session := find(t, table, map[string]string{"intent": "i1051"}); session["task"] != nil || session["files"] != "data/noa/exp3-worker-i1051.sh, i1051_audit_20261022_093500.jsonl" {
		t.Errorf("the session file and the file named for the intent give %v, want i1051 with no task and both files", session)
	}
	for _, row := range table {
		if row["timed_by"] != timedBy {
			t.Errorf("%v is timed by %v, want %s", row["intent"], row["timed_by"], timedBy)
		}
	}
	// The trace names the intent of each file, and leaves the others without one.
	trace := rows(t, filepath.Join(saved, "trace.json"))
	named := map[string]int{}
	for _, step := range trace {
		id, _ := step["intent"].(string)
		named[id]++
	}
	if want := map[string]int{"i1041": 5, "i1042": 3, "i998": 2, "i1051": 2, "": 2}; !maps.Equal(named, want) {
		t.Errorf("the trace names %v, want %v", named, want)
	}
	_, timeline, _ := strings.Cut(readout, "\nTimeline")
	for _, id := range []string{"i1041", "i1042", "i998", "i1051"} {
		block := `\n  \[x\] ` + id + ` +2026-10-22T09:\d\d:\d\dZ to 2026-10-22T09:\d\d:\d\dZ\n      (?:T\d{4}(?:\.\d{3})?|tools)  .+  TA\d{4}  \w+`
		if !regexp.MustCompile(block).MatchString(timeline) {
			t.Errorf("the timeline has no block for %s with its period and a row that ends in a tactic:\n%s", id, timeline)
		}
	}
	// A row is a technique, then its tactic and its ATLAS technique; a tactic
	// the Tactics section gives a file for its tools alone stands with them.
	_, block, _ := strings.Cut(timeline, "] i1042 ")
	block, _, _ = strings.Cut(block, "\n\n")
	for _, row := range []string{
		`\n      tools +\S.*  TA0007  Discovery\n`,
		`\n      T1003\.008  OS Credential Dumping: /etc/passwd and /etc/shadow +TA0006  CredentialAccess +AML\.T0090  OS Credential Dumping\n`,
		`\n      T1552\.004  Unsecured Credentials: Private Keys +TA0006  CredentialAccess +AML\.T0055  Unsecured Credentials\n`,
	} {
		if !regexp.MustCompile(row).MatchString(block + "\n") {
			t.Errorf("the block of i1042 lacks %q:\n%s", row, block)
		}
	}
	// A period is written as one stamp or as two with "to" between them, and never in columns.
	if regexp.MustCompile(`(?m)^  \S+Z  (?:\S+Z|-)  \d+  `).MatchString(timeline) {
		t.Errorf("the timeline holds a table of periods:\n%s", timeline)
	}
	for name, body := range map[string]string{"report.md": readFile(t, filepath.Join(saved, "report.md")), "report.html": readFile(t, filepath.Join(saved, "report.html"))} {
		for _, held := range []string{"Timeline", "i1042", "T1003.008", "OS Credential Dumping: /etc/passwd and /etc/shadow", "AML.T0090"} {
			if !strings.Contains(body, held) {
				t.Errorf("%s does not hold %q", name, held)
			}
		}
		if strings.Contains(body, "Intent timeline") {
			t.Errorf("%s holds a second timeline", name)
		}
	}
}

// A run folder that is read itself is one intent, and keeps its task.
func TestReportReadsOneIntent(t *testing.T) {
	folder := artex(t)
	_, saved := report(t, filepath.Join(folder, "data", "tasks", "7", "i1042"))
	table := rows(t, filepath.Join(saved, "intents.csv"))
	if len(table) != 1 || table[0]["intent"] != "i1042" || table[0]["task"] != "7" {
		t.Errorf("intents = %v, want i1042 of task 7 alone", table)
	}
}

// Evidence that no ARTEX run wrote has no intent, and its summary no count
// of them: its timeline is a block for each period.
func TestReportWithoutIntents(t *testing.T) {
	readout, saved := report(t, evidencetest.Copy(t, "bash"), "summary", "timeline")
	_, timeline, _ := strings.Cut(readout, "\nTimeline")
	for _, block := range []string{
		"\n  [i] Discovery                       2025-03-01T10:15:00Z\n" +
			"      tools  nmap                                          TA0007  Discovery\n" +
			"      no MITRE ATT&CK technique identified\n",
		"\n  [x] CredentialAccess, Exfiltration  2025-03-01T10:45:00Z\n" +
			"      T1649  Steal or Forge Authentication Certificates    TA0006  CredentialAccess\n" +
			"      T1048  Exfiltration Over Alternative Protocol        TA0010  Exfiltration        AML.T0025  Exfiltration via Cyber Means\n",
		"\n  and 10 files that show no tactic, in the saved trace\n",
	} {
		if !strings.Contains(timeline, block) {
			t.Errorf("the timeline lacks %q:\n%s", block, readout)
		}
	}
	if strings.Contains(readout, "\n  intents") {
		t.Errorf("the summary counts intents where there are none:\n%s", readout)
	}
	if got := len(rows(t, filepath.Join(saved, "intents.csv"))); got != 0 {
		t.Errorf("intents.csv holds %d rows, want none", got)
	}
}

// An intent whose files have no time comes last and has no period.
func TestIntentsWithoutATime(t *testing.T) {
	pipe, err := loadPipeline()
	if err != nil {
		t.Fatal(err)
	}
	when := time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)
	steps := []trace.Step{
		{File: evidence.File{Path: "i30/a.sh"}},
		{File: evidence.File{Path: "i200/a.sh", Modified: when.Add(time.Minute)}},
		{File: evidence.File{Path: "i7/a.sh"}},
		{File: evidence.File{Path: "i31/a.sh", Modified: when}},
		{File: evidence.File{Path: "i31/b.sh", Modified: when.Add(-90 * time.Second)}},
		{File: evidence.File{Path: "i31/c.sh"}},
		{File: evidence.File{Path: "i9/a.sh", Modified: when.Add(time.Minute)}},
	}
	runs, of := pipe.collectIntents(t.TempDir(), steps)
	var order []string
	for _, r := range runs {
		order = append(order, r.ref.ID)
	}
	if want := []string{"i31", "i9", "i200", "i7", "i30"}; !slices.Equal(order, want) {
		t.Errorf("intents = %q, want %q", order, want)
	}
	if d, ok := runs[0].span(); !ok || d != 90*time.Second || !runs[0].from.Equal(when.Add(-90*time.Second)) || !runs[0].until.Equal(when) {
		t.Errorf("i31 spans %v from %s to %s, want 1m30s from b.sh to a.sh", d, runs[0].from, runs[0].until)
	}
	if _, ok := runs[4].span(); ok || runs[4].level != "" || len(of) != len(steps) {
		t.Errorf("i30 has a period or a level, or a path has no intent: %+v, %v", runs[4], of)
	}
	doc, err := decodeCommands(commandsJSON)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := intentRow(runs[4], doc.columns("intent")); err != nil {
		t.Errorf("an intent without a time has no row: %v", err)
	}
	groups := reportRun{result: analysis{intents: runs}}.timeline()
	if got := groups[0].Entries[4]; !groups[0].Blocks || !slices.Equal(got.Cells, []string{"i30", "-"}) || !slices.Equal(got.Detail, []render.Detail{{Text: "no MITRE ATT&CK technique identified"}}) {
		t.Errorf("i30 is written %q with %v, want a block with no period that says no technique was identified", got.Cells, got.Detail)
	}
}

// The period of an intent runs from the first of its files to be made until
// the last, and a file belongs to the intent its own name gives it.
func TestIntentsRunFromWhenTheirFilesWereMade(t *testing.T) {
	pipe, err := loadPipeline()
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)
	made := func(path string, created, modified time.Duration, attack ...string) trace.Step {
		s := trace.Step{File: evidence.File{Path: path, Modified: at.Add(modified)}}
		if created != 0 {
			s.File.Created = at.Add(created)
		}
		if len(attack) > 0 {
			s.Activities = []activity.Hit{{Name: "Made" + attack[0], Attack: attack}}
		}
		return s
	}
	steps := []trace.Step{
		// Made where they lie: none was changed before it was made.
		made("i5_scan.sh", 10*time.Minute, 30*time.Minute, "T1046"),
		made("out/cmd-i5.stdout.txt", 12*time.Minute, 12*time.Minute, "T1018", "T1046"),
		made("i5/notes.txt", 11*time.Minute, 50*time.Minute),
		// Copies: made after their last change.
		made("i6_a.sh", 9*time.Hour, 20*time.Minute, "T1003.008"),
		made("i6_b.txt", 25*time.Minute+time.Second, 25*time.Minute),
		// One of each.
		made("i7_a.sh", 40*time.Minute, 41*time.Minute),
		made("i7_b.sh", 9*time.Hour, 45*time.Minute),
		// No creation time is recorded.
		made("i8_a.sh", 0, 55*time.Minute),
		made("plain.sh", 1*time.Minute, 2*time.Minute, "T1059.004"),
	}
	runs, of := pipe.collectIntents(t.TempDir(), steps)
	type want struct {
		id          string
		from, until time.Duration
		by          string
		files       []string
		attack      []string
	}
	wants := []want{
		{"i5", 10 * time.Minute, 12 * time.Minute, byCreation, []string{"i5_scan.sh", "out/cmd-i5.stdout.txt", "i5/notes.txt"}, []string{"T1046", "T1018"}},
		{"i6", 20 * time.Minute, 25 * time.Minute, byTimeline, []string{"i6_a.sh", "i6_b.txt"}, []string{"T1003.008"}},
		{"i7", 40 * time.Minute, 45 * time.Minute, byBoth, []string{"i7_a.sh", "i7_b.sh"}, nil},
		{"i8", 55 * time.Minute, 55 * time.Minute, byTimeline, []string{"i8_a.sh"}, nil},
	}
	if len(runs) != len(wants) {
		t.Fatalf("%d intents, want %d", len(runs), len(wants))
	}
	for i, w := range wants {
		r := runs[i]
		if r.ref.ID != w.id || !r.from.Equal(at.Add(w.from)) || !r.until.Equal(at.Add(w.until)) || r.timedBy() != w.by {
			t.Errorf("intent %d is %s from %s until %s by %s, want %s from %s until %s by %s", i, r.ref.ID, r.from, r.until, r.timedBy(), w.id, at.Add(w.from), at.Add(w.until), w.by)
		}
		if !slices.Equal(r.files, w.files) || !slices.Equal(r.attack, w.attack) {
			t.Errorf("%s owns the files %q and the techniques %q, want %q and %q", w.id, r.files, r.attack, w.files, w.attack)
		}
	}
	if _, owned := of["plain.sh"]; owned || len(of) != len(steps)-1 {
		t.Errorf("the files with an intent are %v, want every one but plain.sh", of)
	}
	groups := reportRun{pipe: pipe, result: analysis{intents: runs}}.timeline()
	// An activity that names no tactic leaves its technique with the tactic ATT&CK files it under.
	i5 := render.Entry{
		Cells: []string{"i5", "2026-10-22T09:10:00Z to 2026-10-22T09:12:00Z"},
		Rows:  []render.Row{row("T1046  Network Service Discovery", "TA0007  Discovery"), row("T1018  Remote System Discovery", "TA0007  Discovery")},
	}
	if got := groups[0].Entries[0]; !groups[0].Blocks || !reflect.DeepEqual(got, i5) {
		t.Errorf("i5 is the block %+v, want %+v", got, i5)
	}
	i8 := render.Entry{Cells: []string{"i8", "2026-10-22T09:55:00Z"}, Detail: []render.Detail{{Text: noTechnique}}}
	if got := groups[0].Entries[3]; !reflect.DeepEqual(got, i8) {
		t.Errorf("i8 is the block %+v, want %+v", got, i8)
	}
	if note := groups[len(groups)-1].Entries[0].Cells[0]; !strings.HasPrefix(note, "4 of 8 files are timed by name or last change") {
		t.Errorf("the last line is %q, want it to count the 4 files of 8 that no creation time places", note)
	}
}

// Files made where they are read give their intents the time they were
// made, whatever their names and their last changes say.
func TestReportIntentsByCreation(t *testing.T) {
	folder := t.TempDir()
	began := time.Now().Add(-2 * time.Second)
	later := time.Now().Add(time.Hour)
	for _, f := range []struct{ name, text string }{
		{"i7_20200101_000000_persist.sh", "#!/bin/bash\nuseradd -m -s /bin/bash svc\n"},
		{"cmd-i7.stdout.txt", "uid=0(root) gid=0(root)\n"},
		{"i8_creds.sh", "#!/bin/bash\ncat /etc/shadow\n"},
		{"notes.txt", "nothing of an intent\n"},
	} {
		path := filepath.Join(folder, f.name)
		if err := os.WriteFile(path, []byte(f.text), 0o600); err != nil {
			t.Fatal(err)
		}
		// A file made where it lies is changed after it is made.
		if err := os.Chtimes(path, later, later); err != nil {
			t.Fatal(err)
		}
	}
	readout, saved := report(t, folder, "timeline")
	for _, row := range rows(t, filepath.Join(saved, "files.csv")) {
		if row["created"] == nil {
			t.Skip("this file system records no creation time")
		}
	}
	ended := time.Now().Add(2 * time.Second)
	table := rows(t, filepath.Join(saved, "intents.csv"))
	if len(table) != 2 {
		t.Fatalf("intents.csv holds %d intents, want i7 and i8:\n%v", len(table), table)
	}
	for i, want := range []struct{ id, attack, files string }{
		{"i7", "T1136.001", "i7_20200101_000000_persist.sh, cmd-i7.stdout.txt"},
		{"i8", "T1003.008", "i8_creds.sh"},
	} {
		row := table[i]
		if row["intent"] != want.id || row["attack"] != want.attack || row["files"] != want.files || row["timed_by"] != byCreation {
			t.Errorf("intent %d is %v, want %s with %s and %s, timed by %s", i, row, want.id, want.attack, want.files, byCreation)
		}
		for _, key := range []string{"from", "until"} {
			text, _ := row[key].(string)
			at, err := time.Parse(time.RFC3339, text)
			if err != nil || at.Before(began) || at.After(ended) {
				t.Errorf("%s %s = %q (%v), want when the test made its files, from %s until %s", want.id, key, text, err, began.UTC(), ended.UTC())
			}
		}
	}
	if !strings.Contains(readout, "  [x] i7  ") || !regexp.MustCompile(`\n      T1136\.001  Create Account: Local Account +TA0003  Persistence +AML\.T0125  Create Account\n`).MatchString(readout) {
		t.Errorf("the readout has no block for i7 that names its technique under the tactic of its script:\n%s", readout)
	}
	if strings.Contains(readout, "timed by name or last change") {
		t.Errorf("the readout says a file is not timed by its creation:\n%s", readout)
	}
}

// Every intent has its block, however many there are: none is left for the saved file alone.
func TestIntentsAreAllShown(t *testing.T) {
	at := time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)
	var runs []intentRun
	for i := range 5 * fewPeriods {
		when := at.Add(time.Duration(i) * time.Minute)
		runs = append(runs, intentRun{ref: intent.Ref{ID: "i" + strconv.Itoa(100+i)}, from: when, until: when, timed: 1, recorded: 1, files: []string{"a.sh"}})
	}
	groups := reportRun{result: analysis{intents: runs}}.timeline()
	if len(groups) != 1 || !groups[0].Blocks || len(groups[0].Entries) != len(runs) {
		t.Fatalf("%d groups with %d entries in the first, want one group of a block for each of %d intents", len(groups), len(groups[0].Entries), len(runs))
	}
	for i, e := range groups[0].Entries {
		if e.Cells[0] != runs[i].ref.ID {
			t.Fatalf("block %d is %s, want %s: every intent in the order it began", i, e.Cells[0], runs[i].ref.ID)
		}
	}
}

// A report made on one processor is, byte for byte, the report made on all
// of them: the work is shared out, and its results are taken in order.
func TestReportIsTheSameOnEveryProcessor(t *testing.T) {
	folder := evidencetest.Copy(t, "linux")
	entries, err := os.ReadDir(folder)
	if err != nil {
		t.Fatal(err)
	}
	// One file large enough to be searched in pieces, with everything the fixture holds.
	var large strings.Builder
	for round := 0; large.Len() < 600<<10; round++ {
		for _, e := range entries {
			large.WriteString(strings.ReplaceAll(readFile(t, filepath.Join(folder, e.Name())), "203.0.113.", "203.0."+strconv.Itoa(round%200)+"."))
			large.WriteString("\n")
		}
	}
	if err := os.WriteFile(filepath.Join(folder, "agent_20261022_100000.log"), []byte(large.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	saved := func(processors int) map[string]string {
		defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(processors))
		_, dir := report(t, folder)
		files, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		held := map[string]string{}
		for _, f := range files {
			held[f.Name()] = readFile(t, filepath.Join(dir, f.Name()))
		}
		return held
	}
	one, all := saved(1), saved(max(4, runtime.NumCPU()))
	if len(one) != 10 || len(all) != len(one) {
		t.Fatalf("%d files on one processor and %d on all, want 10", len(one), len(all))
	}
	for name, body := range one {
		if all[name] != body {
			t.Errorf("%s differs between one processor and all of them", name)
		}
	}
}

// The sub-folders are read without being asked for, 16 levels down.
func TestReportReadsSubFolders(t *testing.T) {
	folder := evidencetest.Copy(t, "bash")
	nest(t, folder, "step0", "phase1")
	nest(t, folder, "adsync_", "phase1/dc01")
	nest(t, folder, "ca_", "loot")
	readout, saved := report(t, folder, "timeline")
	golden.Check(t, "nested-report-timeline", []byte(readout))
	golden.Check(t, "nested-files-csv", []byte(tableText(t, saved, folder, "files.csv")))
	golden.Check(t, "nested-trace-json", []byte(readFile(t, filepath.Join(saved, "trace.json"))))
}

// The whole path of a file does not depend on how the input folder was named.
func TestReportFilesHaveWholePaths(t *testing.T) {
	folder := evidencetest.Copy(t, "linux")
	t.Chdir(filepath.Dir(folder))
	_, saved := report(t, filepath.Base(folder))
	table := rows(t, filepath.Join(saved, "files.csv"))
	if len(table) != 14 {
		t.Fatalf("files.csv holds %d files, want 14", len(table))
	}
	for _, row := range table {
		name, _ := row["name"].(string)
		if want := filepath.Join(folder, name); row["path"] != want {
			t.Errorf("the path of %s = %v, want %s", name, row["path"], want)
		}
	}
}

func TestReportNamesFoldersBelowTheLimit(t *testing.T) {
	folder := t.TempDir()
	deep := folder + strings.Repeat("/d", inventory.MaxDepth)
	if err := os.MkdirAll(deep+"/e", 0o700); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{deep + "/kept.sh", deep + "/e/lost.sh"} {
		if err := os.WriteFile(p, []byte("id\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	kept := strings.Repeat("d/", inventory.MaxDepth)
	saved := filepath.Join(t.TempDir(), "out")
	out, err := run(t, "-inputdir", folder, "report", "timeline", "-outdir", saved)
	if want := "1 folder(s) not read (unreadable or more than 16 levels down): " + kept + "e"; err == nil || err.Error() != want {
		t.Errorf("error = %v, want %q", err, want)
	}
	if !strings.Contains(out, "\nTimeline") || strings.Contains(out, "lost.sh") {
		t.Errorf("output = %q, want the timeline of what was read and not lost.sh", out)
	}
	if files := rows(t, filepath.Join(saved, "files.csv")); len(files) != 1 || files[0]["name"] != kept+"kept.sh" {
		t.Errorf("files.csv holds %v, want the one file that was read", files)
	}
}

// The scenario of the entra fixture, with the attacker's range as the watchlist.
func TestReportWithARange(t *testing.T) {
	folder := evidencetest.Copy(t, "entra")
	ranges := filepath.Join(t.TempDir(), "ranges.json")
	if err := os.WriteFile(ranges, []byte(`[{"value": "144.172.64.0/24", "attribution": "STORM-0940"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	readout, saved := report(t, folder, "-intelfile", ranges)
	golden.Check(t, "entra-report-range", []byte(readout))
	golden.Check(t, "entra-trace-range-json", []byte(readFile(t, filepath.Join(saved, "trace.json"))))
	golden.Check(t, "entra-findings-range-json", []byte(readFile(t, filepath.Join(saved, "findings.json"))))
}

// Step 6 of the linux fixture runs a fetched script, an encoded one and a
// remote command; the lolbin fixture holds a batch file that is a script.
func TestReportScenarios(t *testing.T) {
	_, saved := report(t, evidencetest.Copy(t, "linux"))
	var staged map[string]any
	for _, row := range rows(t, filepath.Join(saved, "trace.json")) {
		if row["name"] == "20261022_092500_step06_stage.sh" {
			staged = row
		}
	}
	for key, wants := range map[string][]string{"tools": {"curl", "uname", "gzip"}, "activities": {"ShellDownloadAndExecute"}} {
		cell, _ := staged[key].(string)
		for _, want := range wants {
			if !slices.Contains(strings.Split(cell, ", "), want) {
				t.Errorf("step 6 %s = %q, want %s among them", key, cell, want)
			}
		}
	}
	_, saved = report(t, evidencetest.Copy(t, "lolbin"))
	for _, row := range rows(t, filepath.Join(saved, "files.csv")) {
		if row["name"] == "20261020_103000_step07_cleanup.bat" && row["role"] != "script" {
			t.Errorf("the batch file has the role %v, want script", row["role"])
		}
	}
}

// find returns the first row whose cells hold every given key and value.
func find(t *testing.T, table []map[string]any, want map[string]string) map[string]any {
	t.Helper()
	for _, row := range table {
		match := true
		for key, value := range want {
			match = match && row[key] == value
		}
		if match {
			return row
		}
	}
	t.Fatalf("no row with %v", want)
	return nil
}

// The exposure names what the files hold, by kind, with whose a secret is,
// whether the scripts collected it or the attacker brought it, and where.
func TestReportExposure(t *testing.T) {
	readout, saved := report(t, evidencetest.Copy(t, "linux"), "summary", "exposure")
	table := rows(t, filepath.Join(saved, "exposure.csv"))
	tests := []struct {
		row  map[string]string
		want map[string]any
	}{
		{map[string]string{"kind": "password", "account": "app_rw"},
			map[string]any{"value": "Fixture-Pass-01", "form": "password", "seen": "collected", "severity": "high", "files": "env_20261022_090540.txt:3"}},
		{map[string]string{"kind": "password", "account": "deploy"},
			map[string]any{"form": "hash", "seen": "collected", "files": "shadow_20261022_090530.txt:4"}},
		{map[string]string{"kind": "password", "form": "token"},
			map[string]any{"account": nil, "value": "fixture-token-0123456789", "files": "env_20261022_090540.txt:5"}},
		{map[string]string{"kind": "username", "value": "deploy"},
			map[string]any{"seen": "collected", "severity": "medium", "files": "passwd_20261022_090020.txt:3, shadow_20261022_090530.txt:4"}},
		{map[string]string{"kind": "username", "value": "ops"},
			map[string]any{"seen": "used", "files": "20261022_092500_step06_stage.sh:6"}},
		{map[string]string{"kind": "email", "value": "alerts@corp.example"},
			map[string]any{"seen": "collected", "files": "env_20261022_090540.txt:4"}},
		{map[string]string{"kind": "device", "value": "db01.corp.internal"},
			map[string]any{"seen": "collected", "severity": "low", "files": "hosts_20261022_090025.txt:2, env_20261022_090540.txt:1"}},
		{map[string]string{"kind": "ip", "value": "10.20.30.5"},
			map[string]any{"seen": "collected", "files": "hosts_20261022_090025.txt:2"}},
		{map[string]string{"kind": "ip", "value": "203.0.113.40"},
			map[string]any{"seen": "used"}},
	}
	for _, tt := range tests {
		row := find(t, table, tt.row)
		for key, want := range tt.want {
			if row[key] != want {
				t.Errorf("%v: %s = %v, want %v", tt.row, key, row[key], want)
			}
		}
	}
	for _, row := range table {
		if row["value"] == "127.0.0.1" || row["value"] == "localhost" {
			t.Errorf("the exposure lists %v, which names no host", row["value"])
		}
	}
	for _, want := range []string{
		"exposed     18  Passwords and secrets 3, Usernames 6, Email addresses 1, Devices 2, IP addresses 6",
		"\n  Passwords and secrets (3)\n",
		"[x] password of app_rw  collected  Fixture-Pass-01                                  env_20261022_090540.txt:3\n",
		"[x] token               collected  fixture-token-0123456789                         env_20261022_090540.txt:5\n",
		"\n  Usernames (6)\n",
		"\n  IP addresses (6)\n",
	} {
		if !strings.Contains(readout, want) {
			t.Errorf("the readout lacks %q:\n%s", want, readout)
		}
	}
}

// A secret is written as it stands wherever it stands: in the exposure, in a
// command quoted as evidence, among the indicators and in every saved file.
// No option hides it.
func TestReportShowsSecrets(t *testing.T) {
	folder := evidencetest.Copy(t, "bash")
	secret := []string{"Winter2025!", "Qw7#fakeMsolSecretValue99", "Zx9!fakeCloudSyncPass", "8846f7eaee8fb117ad06bdd830b7586c", "Export1!"}
	readout, saved := report(t, folder)
	for _, s := range secret {
		if !strings.Contains(readout, s) {
			t.Errorf("the readout does not hold %q", s)
		}
	}
	if !strings.Contains(readFile(t, filepath.Join(saved, "report.json")), "-p 'Winter2025!'") {
		t.Errorf("report.json does not quote the command with its password as it stands")
	}
	row := find(t, rows(t, filepath.Join(saved, "exposure.csv")), map[string]string{"kind": "password", "account": "svc_backup"})
	if row["value"] != "Winter2025!" || row["seen"] != "used" || row["service"] != "DC01, AADC01" {
		t.Errorf("the exposure holds %v, want the password as it stands, used by the scripts against both hosts", row)
	}
	if got := strings.Count(readFile(t, filepath.Join(saved, "exposure.csv")), "password,Winter2025!,"); got != 1 {
		t.Errorf("the exposure lists the password %d times, want one line for the one account", got)
	}
	for _, name := range []string{"report.txt", "report.md", "report.html", "exposure.csv", "targeted.json", "report.json"} {
		if !strings.Contains(readFile(t, filepath.Join(saved, name)), "Winter2025!") {
			t.Errorf("%s does not hold the password as it stands", name)
		}
	}
	if strings.Contains(readout, "(11 chars)") || strings.Contains(readout, "********") {
		t.Errorf("the readout masks a secret:\n%s", readout)
	}
}

// An impact, an action and a mitigation list the exposed accounts and
// credentials they concern and quote nothing; the saved report keeps what
// each acts on and the lines that show it. A finding quotes its lines.
func TestReportNamesWhat(t *testing.T) {
	readout, saved := report(t, evidencetest.Copy(t, "linux"), "impact", "remediation", "mitigation")
	table := rows(t, filepath.Join(saved, "report.json"))
	tests := []struct {
		section, item string
		exposed       []string
		targets       []string
		evidence      []string
	}{
		{"impact", "Persistence established", []string{"username: svc"},
			[]string{"account svc", "unit sync.service", "file ~/.ssh/authorized_keys", "file ~/.bashrc"},
			[]string{"AccountCreation: useradd -m -s /bin/bash svc (20261022_091500_step04_persist.sh:7)", "AccountCreation: useradd -m -s /bin/bash svc (audit_20261022_093500.jsonl)"}},
		{"impact", "Privileged access obtained", nil,
			[]string{"file /etc/sudoers.d/svc", "file /tmp/tool ($F)", "mount /:/host"},
			[]string{"SetuidBit: chmod u+s \"$F\" (20261022_091000_step03_privesc.sh:4)"}},
		{"impact", "Movement to other systems", []string{"username: ops"}, nil,
			[]string{"ssh: ssh ops@198.51.100.7 'cat /etc/hostname' (20261022_092500_step06_stage.sh:6)"}},
		{"impact", "Credentials exposed",
			[]string{"hash of deploy: $6$fixturesalt$fixturehashvalue0123456789abcdef", "password of app_rw: Fixture-Pass-01", "token: fixture-token-0123456789"},
			[]string{"file /etc/shadow"},
			[]string{"ShadowFileRead: sudo cat /etc/shadow > shadow_20261022_090530.txt (20261022_090500_step02_creds.sh:6)"}},
		{"impact", "Environment mapped", []string{"username: app_rw", "username: daemon", "username: deploy", "username: root", "email: alerts@corp.example"}, nil, nil},
		{"impact", "Commands generated by an AI agent", nil, nil, nil},
		{"remediation", "Remove persistence", []string{"username: svc"},
			[]string{"account svc", "unit sync.service"},
			[]string{"SystemdUnitCreation: systemctl enable --now sync.service (20261022_091500_step04_persist.sh:6)"}},
		{"remediation", "Rotate what was read",
			[]string{"hash of deploy: $6$fixturesalt$fixturehashvalue0123456789abcdef", "password of app_rw: Fixture-Pass-01", "token: fixture-token-0123456789"},
			[]string{"file ~/.ssh/id_rsa"}, nil},
		{"remediation", "Restore security tooling", nil, []string{"service auditd"},
			[]string{"SecurityToolDisabling: systemctl stop auditd (20261022_092000_step05_evade.sh:4)"}},
		{"mitigation", "M1032 Multi-factor Authentication", []string{"username: svc"}, []string{"AccountCreation: account svc"}, nil},
	}
	for _, tt := range tests {
		row := find(t, table, map[string]string{"section": tt.section, "item": tt.item})
		exposed, _ := row["exposed"].(string)
		if got := strings.Split(exposed, "\n"); !slices.Equal(got, tt.exposed) && (exposed != "" || len(tt.exposed) > 0) {
			t.Errorf("%s %s: exposed = %q, want %q", tt.section, tt.item, got, tt.exposed)
		}
		targets, _ := row["targets"].(string)
		for _, want := range tt.targets {
			if !slices.Contains(strings.Split(targets, "; "), want) {
				t.Errorf("%s %s: targets = %q, want %q among them", tt.section, tt.item, targets, want)
			}
		}
		evidence, _ := row["evidence"].(string)
		for _, want := range tt.evidence {
			if !slices.Contains(strings.Split(evidence, "\n"), want) {
				t.Errorf("%s %s: evidence = %q, want %q among it", tt.section, tt.item, evidence, want)
			}
		}
	}
	// An unresolved variable is kept so responders see what was targeted.
	if row := find(t, table, map[string]string{"section": "impact", "item": "Persistence established"}); !strings.Contains(row["targets"].(string), "$JOB") {
		t.Errorf("targets = %q, want $JOB among them", row["targets"])
	}
	for _, want := range []string{
		"  [x] Credentials exposed\n      Secrets, keys, certificates or stored passwords were read. Treat them as known to the attacker.\n" +
			"      exposed  hash of deploy: $6$fixturesalt$fixturehashvalue0123456789abcdef\n" +
			"               password of app_rw: Fixture-Pass-01\n" +
			"               token: fixture-token-0123456789\n" +
			"      basis    ShadowFileRead, PrivateKeyRead, CredentialFileRead, ShellHistoryRead, CloudMetadataAccess, ClusterSecretRead, exposed password\n",
		"      exposed  username: svc\n      basis    ScheduledJobCreation, SystemdUnitCreation, AccountCreation, SshKeyPersistence, ShellProfilePersistence, Persistence tools\n",
		"      exposed  username: svc\n      for      AccountCreation\n",
	} {
		if !strings.Contains(readout, want) {
			t.Errorf("the readout lacks %q:\n%s", want, readout)
		}
	}
	// The sections say what is concerned, and leave the commands to the findings.
	for _, gone := range []string{"\n      targets  ", "\n      what     ", "\n      files    ", "useradd -m", "crontab -", "20261022_091500_step04_persist.sh"} {
		if strings.Contains(readout, gone) {
			t.Errorf("the readout holds %q, which is a command, a script or what one acts on", gone)
		}
	}
	finding := find(t, rows(t, filepath.Join(saved, "findings.json")), map[string]string{"finding": "AccountCreation"})
	want := []any{
		map[string]any{"time": "2026-10-22T09:15:00Z", "file": "20261022_091500_step04_persist.sh", "line": float64(7), "text": "useradd -m -s /bin/bash svc"},
		map[string]any{"time": "2026-10-22T09:35:00Z", "file": "audit_20261022_093500.jsonl", "line": nil, "text": "useradd -m -s /bin/bash svc"},
	}
	if !reflect.DeepEqual(finding["evidence"], want) {
		t.Errorf("the evidence of the finding = %v, want %v", finding["evidence"], want)
	}
	if finding["first"] != "2026-10-22T09:15:00Z" || finding["last"] != "2026-10-22T09:35:00Z" {
		t.Errorf("the finding is from %v until %v, want the times of its two files", finding["first"], finding["last"])
	}
}

// The exposure names the tenants, the SSH keys with their hosts and the API
// keys with their services, and lists what is of Microsoft 365 and of Google
// Cloud in a group of its own.
func TestReportExposureOfServices(t *testing.T) {
	const tenant, app = "6f9619ff-8b86-4d11-b42d-00c04fc964ff", "1b2c3d4e-5f60-4718-8293-a4b5c6d7e8f9"
	const token = "ghp_Ab3dE9fGh1JkLm5nPq7RsTu2VwXy4Z0c8Ab3" //nolint:gosec // G101: a made-up value in the form of a key.
	folder := t.TempDir()
	for name, text := range map[string]string{
		"20261101_090000_step01_m365.sh": "#!/bin/bash\nexport AZURE_TENANT_ID=" + tenant + "\nexport AZURE_CLIENT_ID=" + app +
			"\nexport AZURE_CLIENT_SECRET=\"Qz8~fakeClientSecretValue.0123456789abc\"\ncurl -s https://contoso.sharepoint.com/sites/finance/_api/web\n",
		"20261101_090500_step02_gcp.sh":       "#!/bin/bash\ngcloud compute instances list --project=acme-prod-4711\ngsutil ls gs://acme-prod-backups/\n",
		"20261101_091000_step03_ssh.sh":       "#!/bin/bash\nssh -i ~/.ssh/id_ed25519 ops@10.20.30.5 'id'\n",
		"authorized_keys_20261101_091025.txt": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGJhY2tkb29yYmFja2Rvb3JiYWNrZG9vcmJhY2tkb29y backdoor@attacker-box\n",
		"env_20261101_091500.txt":             "GITHUB_TOKEN=" + token + "\nINTERNAL_API_KEY=9f8e7d6c5b4a3928\n",
	} {
		if err := os.WriteFile(filepath.Join(folder, name), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	readout, saved := report(t, folder, "exposure")
	table := rows(t, filepath.Join(saved, "exposure.csv"))
	for _, want := range []map[string]string{
		{"kind": "tenant", "value": tenant, "service": "Microsoft 365"},
		{"kind": "application", "value": app, "service": "Microsoft 365"},
		{"kind": "password", "form": "secret", "service": "Microsoft 365", "seen": "used"},
		{"kind": "resource", "value": "contoso.sharepoint.com", "form": "site", "service": "Microsoft 365"},
		{"kind": "resource", "value": "acme-prod-4711", "form": "project", "service": "Google Cloud"},
		{"kind": "resource", "value": "gs://acme-prod-backups", "form": "bucket", "service": "Google Cloud"},
		{"kind": "sshkey", "value": "~/.ssh/id_ed25519", "form": "key file", "account": "ops", "service": "10.20.30.5"},
		{"kind": "sshkey", "value": "ssh-ed25519 SHA256:Ddp3soYTdzq1tXKnpZgVrTfTOXeC2oHvS7SeMWqylYU", "form": "public key", "account": "backdoor", "service": "attacker-box"},
		{"kind": "apikey", "value": token, "form": "key", "service": "GitHub", "seen": "collected"},
		{"kind": "apikey", "value": "9f8e7d6c5b4a3928", "form": "key"},
	} {
		find(t, table, want)
	}
	for _, row := range table {
		if row["kind"] == "password" && row["form"] == "token" {
			t.Errorf("the token of GitHub is listed as a plain secret as well: %v", row)
		}
	}
	for _, want := range []string{
		"\n  Tenants (1)\n", "\n  SSH keys (2)\n", "\n  API keys (2)\n", "\n  Applications (1)\n", "\n  Cloud resources (3)\n",
		"\n  Microsoft 365 (4)\n", "\n  Google Cloud (2)\n",
		"key file of ops, 10.20.30.5  ", "public key of backdoor, attacker-box  ", "site, Microsoft 365  ",
	} {
		if !strings.Contains(readout, want) {
			t.Errorf("the readout lacks %q:\n%s", want, readout)
		}
	}
	if !strings.Contains(readout, token+"  key, GitHub  ") {
		t.Errorf("the readout does not hold the token as it stands:\n%s", readout)
	}
}

// What a script names outright is a target: prior when no earlier output
// holds it, discovered when one does, with the script lines that name it.
func TestReportTargeted(t *testing.T) {
	readout, saved := report(t, evidencetest.Copy(t, "bash"), "summary", "targeted")
	table := rows(t, filepath.Join(saved, "targeted.json"))
	tests := []struct {
		row  map[string]string
		want map[string]any
	}{
		{map[string]string{"kind": "ip", "value": "10.20.1.0/24"},
			map[string]any{"origin": "prior", "scope": "private", "evidence": `TARGET_NET="10.20.1.0/24" (20250301_101500_step01_recon.sh:3)`}},
		{map[string]string{"kind": "ip", "value": "10.20.1.5"},
			map[string]any{"origin": "discovered", "scope": "private", "from": "20250301_101530_step01_recon.txt:2"}},
		{map[string]string{"kind": "device", "value": "transfer.example.net"},
			map[string]any{"origin": "prior", "scripts": "20250301_104500_step07_exfil.sh:4"}},
		{map[string]string{"kind": "device", "value": "ca01.corp.example"},
			map[string]any{"origin": "discovered", "from": "20250301_101530_step01_recon.txt:6"}},
		{map[string]string{"kind": "email", "value": "administrator@corp.example"},
			map[string]any{"origin": "prior"}},
	}
	for _, tt := range tests {
		row := find(t, table, tt.row)
		for key, want := range tt.want {
			if row[key] != want {
				t.Errorf("%v: %s = %v, want %v", tt.row, key, row[key], want)
			}
		}
	}
	for _, row := range table {
		if row["kind"] == "password" || row["kind"] == "username" {
			t.Errorf("a secret or a username is listed as a target: %v", row)
		}
		// Every row is a value a script holds: its places are scripts.
		for _, place := range strings.Split(row["scripts"].(string), ", ") {
			if !strings.Contains(place, ".sh") {
				t.Errorf("%v names %s, which is no script", row["value"], place)
			}
		}
	}
	for _, want := range []string{
		"targeted    9   Email addresses 1, Hostnames 4, IP addresses 4",
		"\n  Hostnames (4)\n",
		"    [!] 10.20.1.0/24  private  prior       20250301_101500_step01_recon.sh:3\n",
		"        from  20250301_101530_step01_recon.txt:2\n",
	} {
		if !strings.Contains(readout, want) {
			t.Errorf("the readout lacks %q:\n%s", want, readout)
		}
	}
	if strings.Contains(readout, "\n  Usernames (") {
		t.Errorf("the targets list usernames:\n%s", readout)
	}
	// An address the attacker brought is public; nothing in an output makes it a discovery.
	_, saved = report(t, evidencetest.Copy(t, "lolbin"))
	row := find(t, rows(t, filepath.Join(saved, "targeted.json")), map[string]string{"kind": "ip", "value": "203.0.113.10"})
	if row["origin"] != "prior" || row["scope"] != "public" {
		t.Errorf("the download address: %v, want prior and public", row)
	}
	report := find(t, rows(t, filepath.Join(saved, "report.json")), map[string]string{"section": "targeted", "item": "203.0.113.10"})
	if report["value"] != "medium" || report["detail"] != "ip: prior, public" {
		t.Errorf("the row of the report: %v", report)
	}
}

// A folder of a Windows path that reads as a domain is no hostname; the
// host of a share is.
func TestInPath(t *testing.T) {
	text := `C:\Windows\Microsoft.NET\Framework64\MSBuild.exe \\files01.corp.local\share http://corp.example/x`
	for value, want := range map[string]bool{"Microsoft.NET": true, "files01.corp.local": false, "corp.example": false} {
		if got := inPath(text, strings.Index(text, value), 1); got != want {
			t.Errorf("inPath(%s) = %t, want %t", value, got, want)
		}
	}
	if inPath(text, strings.Index(text, "Microsoft.NET"), 0) || inPath(text, 0, 1) || inPath(text, len(text)+5, 1) {
		t.Error("a match without a line, at the start or past the end is in a path")
	}
	_, saved := report(t, evidencetest.Copy(t, "lolbin"))
	for _, row := range rows(t, filepath.Join(saved, "targeted.json")) {
		if row["value"] == "Microsoft.NET" {
			t.Errorf("a folder of a path is listed as a hostname: %v", row)
		}
	}
}

func TestScopeOf(t *testing.T) {
	ip := exposure.Kind{Name: ipKind}
	for value, want := range map[string]string{
		"10.20.1.5": scopePrivate, "192.168.0.0/16": scopePrivate, "172.16.4.4": scopePrivate, "169.254.169.254": scopePrivate,
		"127.0.0.1": scopePrivate, "203.0.113.10": scopePublic, "8.8.8.8": scopePublic, "not an address": "",
	} {
		if got := scopeOf(ip, value); got != want {
			t.Errorf("scopeOf(%s) = %q, want %q", value, got, want)
		}
	}
	if got := scopeOf(exposure.Kind{Name: "device"}, "10.20.1.5"); got != "" {
		t.Errorf("a kind that is no address has the scope %q", got)
	}
	if long := shorten(strings.Repeat("é", maxQuoted)); len(long) > maxQuoted || !strings.HasSuffix(long, "...") || !strings.HasPrefix(long, "é") {
		t.Errorf("shorten gave %d bytes ending %q", len(long), long[len(long)-5:])
	}
}

// A kind of exposure orders the columns of its group only by naming each
// of them once; the passwords and secrets say what each is before its value.
func TestCheckColumns(t *testing.T) {
	pipe, err := loadPipeline()
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range pipe.exposures.Kinds() {
		want := []string(nil)
		if k.Name == "password" {
			want = []string{"what", "seen", "value", "found in"}
		}
		if !slices.Equal(k.Columns, want) {
			t.Errorf("%s orders its columns %q, want %q", k.Name, k.Columns, want)
		}
	}
	for name, columns := range map[string][]string{
		"a column left out":      {"what", "seen", "value"},
		"a column twice":         {"what", "seen", "value", "value"},
		"a column of no group":   {"what", "seen", "value", "files"},
		"a column more than all": {"what", "seen", "value", "found in", "what"},
	} {
		if err := checkColumns(exposure.Kind{Name: "k", Columns: columns}); err == nil {
			t.Errorf("%s: checkColumns(%q) gave no error", name, columns)
		}
	}
	for _, columns := range [][]string{nil, {"found in", "value", "seen", "what"}} {
		if err := checkColumns(exposure.Kind{Name: "k", Columns: columns}); err != nil {
			t.Errorf("checkColumns(%q) = %v, want no error", columns, err)
		}
	}
}

// A secret seen without an account is the same secret seen with one.
func TestMergeOwned(t *testing.T) {
	secret := exposure.Kind{Name: "password", Secret: true}
	all := mergeOwned([]exposed{
		{kind: secret, value: "s1", form: "password", seen: seenCollected, count: 2, cites: []cite{{"loot.txt", 4}}},
		{kind: secret, value: "s1", form: "password", account: "alice", seen: seenUsed, count: 1, cites: []cite{{"a.sh", 2}}},
		{kind: secret, value: "s2", form: "password", seen: seenUsed, count: 1, cites: []cite{{"a.sh", 3}}},
		{kind: secret, value: "s1", form: "password", count: 1, seen: seenUsed, cites: []cite{{"a.sh", 2}, {"b.sh", 1}}},
		{kind: exposure.Kind{Name: "username"}, value: "s1", seen: seenUsed, count: 1},
	})
	if len(all) != 3 || all[0].account != "alice" || all[0].count != 4 || all[0].seen != seenCollected {
		t.Fatalf("merged = %+v, want the secret of alice with every count, collected because an output held it first", all)
	}
	if want := []cite{{"a.sh", 2}, {"loot.txt", 4}, {"b.sh", 1}}; !slices.Equal(all[0].cites, want) {
		t.Errorf("cites = %v, want %v", all[0].cites, want)
	}
	if all[1].value != "s2" || all[1].account != "" || all[2].kind.Name != "username" {
		t.Errorf("merged = %+v, want the secret with no owner and the username kept", all)
	}
	// One secret of one account is one line: it names each host it is used
	// against, under either way of writing the account, and is used or
	// collected by where it is seen first.
	all = mergeOwned([]exposed{
		{kind: secret, value: "s1", form: "password", account: "svc", seen: seenUsed, count: 1},
		{kind: secret, value: "s1", form: "password", account: "svc", services: []string{"DC01"}, seen: seenCollected, count: 1},
		{kind: secret, value: "s1", form: "hash", account: "SVC@corp.example", services: []string{"AADC01", "DC01"}, seen: seenCollected, count: 1},
		{kind: secret, value: "s1", form: "password", account: "bob", services: []string{"DC01"}, seen: seenCollected, count: 1},
		{kind: secret, value: "s1", form: "password", account: "svc@other.example", seen: seenCollected, count: 1},
	})
	if len(all) != 2 || all[0].account != "svc" || all[0].count != 4 || all[0].seen != seenUsed || !slices.Equal(all[0].services, []string{"DC01", "AADC01"}) {
		t.Errorf("merged = %+v, want one line for svc, used, for DC01 and AADC01", all)
	}
	if len(all) == 2 && (all[1].account != "bob" || all[1].count != 1) {
		t.Errorf("merged = %+v, want the same secret of another account kept apart", all)
	}
	for _, tt := range []struct {
		a, b string
		want bool
	}{
		{"svc", "SVC", true}, {"svc", "svc@corp.example", true}, {"svc@corp.example", "svc", true},
		{"svc@a.example", "svc@b.example", false}, {"svc", "svc2@corp.example", false}, {"", "svc", false}, {"", "", true},
	} {
		if got := sameAccount(tt.a, tt.b); got != tt.want {
			t.Errorf("sameAccount(%q, %q) = %t, want %t", tt.a, tt.b, got, tt.want)
		}
	}
	if got := (cite{"a.sh", 0}).String(); got != "a.sh" {
		t.Errorf("a cite without a line = %q", got)
	}
}

func TestReportFails(t *testing.T) {
	folder := evidencetest.Copy(t, "linux")
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte(`{`), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		args  []string
		usage bool
		want  string
	}{
		{"no verb", []string{"-inputdir", folder}, true, "slopmop needs a verb (verbs: report)"},
		{"no input folder", []string{"report"}, true, "report needs -inputdir <folder>"},
		{"an unknown verb", []string{"-inputdir", folder, "list"}, true, `unknown verb "list" (verbs: report)`},
		{"an unknown section", []string{"-inputdir", folder, "report", "impcat"}, true, `report has no section "impcat"`},
		{"an unknown option", []string{"-inputdir", folder, "report", "-o", "json"}, true, "unknown option -o"},
		{"a missing folder", []string{"-inputdir", filepath.Join(folder, "missing"), "report"}, false, "not a folder"},
		{"a file for a folder", []string{"-inputdir", filepath.Join(folder, "audit_20261022_093500.jsonl"), "report"}, false, "not a folder"},
		{"a missing watchlist", []string{"-inputdir", folder, "report", "-intelfile", bad + ".missing"}, false, "-intelfile:"},
		{"a broken watchlist", []string{"-inputdir", folder, "report", "-intelfile", bad}, false, "intel watchlist:"},
		{"an output folder in the evidence", []string{"-inputdir", folder, "report", "-outdir", filepath.Join(folder, "out")}, true, "is inside the folder that is read"},
		{"the option for secrets, which there is none of", []string{"-inputdir", folder, "report", "-secrets", "shown"}, true, "unknown option -secrets"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := run(t, tt.args...)
			if err == nil || !strings.Contains(err.Error(), tt.want) || errors.Is(err, cli.ErrUsage) != tt.usage {
				t.Errorf("error = %v, want one containing %q (usage error: %t)", err, tt.want, tt.usage)
			}
			if out != "" {
				t.Errorf("output on failure: %q", out)
			}
		})
	}
	if entries, err := os.ReadDir(folder); err != nil || len(entries) != 14 {
		t.Errorf("the evidence folder holds %d entries after the failures (%v), want 14", len(entries), err)
	}
}

// A save that fails does not withhold the readout; it fails the command after it.
func TestReportSaveFailure(t *testing.T) {
	folder := evidencetest.Copy(t, "linux")
	blocked := filepath.Join(t.TempDir(), "taken")
	if err := os.WriteFile(blocked, []byte("a file where the folder would be\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := run(t, "-inputdir", folder, "report", "summary", "-outdir", blocked)
	if err == nil || !strings.Contains(err.Error(), "output folder:") || errors.Is(err, cli.ErrUsage) {
		t.Errorf("error = %v, want the output folder that could not be made", err)
	}
	if !strings.Contains(out, "\nSummary\n") || strings.Contains(out, "saved to") {
		t.Errorf("readout = %q, want the summary and no claim that it was saved", out)
	}
}

// A save that fails part of the way leaves no file, whole or half written.
func TestReportSaveLeavesNoPart(t *testing.T) {
	folder := evidencetest.Copy(t, "linux")
	saved := filepath.Join(t.TempDir(), "out")
	// A folder that is not empty stands where one of the files is written, so that file cannot be made.
	inTheWay := filepath.Join(saved, "findings.json.part")
	if err := os.MkdirAll(filepath.Join(inTheWay, "held"), 0o700); err != nil {
		t.Fatal(err)
	}
	out, failure := run(t, "-inputdir", folder, "report", "summary", "-outdir", saved)
	if failure == nil || !strings.Contains(failure.Error(), "output folder:") {
		t.Errorf("error = %v, want the file that could not be made", failure)
	}
	if strings.Contains(out, "saved to") {
		t.Errorf("readout = %q, want no claim that it was saved", out)
	}
	left, err := os.ReadDir(saved)
	if err != nil || len(left) != 1 || left[0].Name() != filepath.Base(inTheWay) {
		t.Errorf("the output folder holds %d entries (%v), want only the folder that was in the way", len(left), err)
	}
	// The next run finds nothing in its way and saves every file under its own name.
	if err = os.RemoveAll(inTheWay); err != nil {
		t.Fatal(err)
	}
	if _, err = run(t, "-inputdir", folder, "report", "summary", "-outdir", saved); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(saved)
	if err != nil || len(entries) != 10 {
		t.Fatalf("the output folder holds %d entries (%v), want 10", len(entries), err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".part") {
			t.Errorf("%s was left in the output folder", e.Name())
		}
	}
}

// A name in the output folder that leads elsewhere takes no write there: the
// file is made new in the folder, and what the name led to is left as it was.
func TestReportWritesNothingThroughALink(t *testing.T) {
	folder := evidencetest.Copy(t, "linux")
	evidenceFile := filepath.Join(folder, "passwd_20261022_090020.txt")
	held := readFile(t, evidenceFile)
	links := []struct {
		name string
		make func(target, name string) error
	}{{"a symbolic link", os.Symlink}, {"a hard link", os.Link}}
	for _, link := range links {
		for _, name := range []string{"findings.json", "findings.json.part", "report.txt", "report.txt.part"} {
			t.Run(link.name+" named "+name, func(t *testing.T) {
				base := t.TempDir()
				saved, elsewhere := filepath.Join(base, "out"), filepath.Join(base, "elsewhere.txt")
				if err := os.Mkdir(saved, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(elsewhere, []byte("kept\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := link.make(elsewhere, filepath.Join(saved, name)); err != nil {
					t.Skipf("this system makes no such link: %v", err)
				}
				if _, err := run(t, "-inputdir", folder, "report", "summary", "-outdir", saved); err != nil {
					t.Fatal(err)
				}
				if got := readFile(t, elsewhere); got != "kept\n" {
					t.Errorf("the file outside the output folder now holds %d bytes: it was written through the link", len(got))
				}
				file := filepath.Join(saved, strings.TrimSuffix(name, ".part"))
				if info, err := os.Lstat(file); err != nil || !info.Mode().IsRegular() || info.Size() < 100 {
					t.Errorf("%s is not a file of its own that holds the output (%v)", filepath.Base(file), err)
				}
				if entries, err := os.ReadDir(saved); err != nil || len(entries) != 10 {
					t.Errorf("the output folder holds %d entries (%v), want 10", len(entries), err)
				}
			})
		}
	}
	// The same holds of a link that leads into the evidence.
	saved := filepath.Join(t.TempDir(), "out")
	if err := os.Mkdir(saved, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(evidenceFile, filepath.Join(saved, "trace.json.part")); err != nil {
		t.Skipf("this system makes no hard link: %v", err)
	}
	if _, err := run(t, "-inputdir", folder, "report", "summary", "-outdir", saved); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, evidenceFile); got != held {
		t.Errorf("the evidence was written through a link in the output folder")
	}
}

func TestReportOfNothing(t *testing.T) {
	readout, saved := report(t, t.TempDir(), "summary", "impact")
	if want := "[ok] NOTHING FOUND in 0 files"; !strings.Contains(readout, want) {
		t.Errorf("readout lacks %q:\n%s", want, readout)
	}
	if bad := "Impact"; strings.Contains(readout, bad) {
		t.Errorf("readout shows the empty Impact section:\n%s", readout)
	}
	if got := strings.TrimSpace(readFile(t, filepath.Join(saved, "trace.json"))); got != "[]" {
		t.Errorf("trace.json of an empty folder = %q, want an empty array", got)
	}
}

// The output folder is never in the evidence: not by default, not on request.
func TestOutputDir(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "case42")
	if err := os.MkdirAll(filepath.Join(input, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	elsewhere := t.TempDir()
	type test struct {
		name    string
		given   string
		workDir string
		want    string
		fails   string
	}
	tests := []test{
		{"the work folder", "", elsewhere, filepath.Join(elsewhere, "slopmop-case42"), ""},
		{"beside the input when the work folder is the input", "", input, filepath.Join(root, "slopmop-case42"), ""},
		{"beside the input when the work folder is inside it", "", filepath.Join(input, "sub"), filepath.Join(root, "slopmop-case42"), ""},
		{"a folder that is given", filepath.Join(elsewhere, "new", "out"), elsewhere, filepath.Join(elsewhere, "new", "out"), ""},
		{"given inside the input", filepath.Join(input, "out"), elsewhere, "", "is inside the folder that is read"},
		{"given as the input", input, elsewhere, "", "is inside the folder that is read"},
	}
	// A symbolic link needs a privilege on Windows, so the case runs where one can be made.
	if link := filepath.Join(elsewhere, "link"); os.Symlink(input, link) == nil {
		tests = append(tests, test{"given through a link into the input", filepath.Join(link, "out"), elsewhere, "", "is inside the folder that is read"})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := outputDir(input, tt.given, tt.workDir, "slopmop-")
			switch {
			case tt.fails != "":
				if err == nil || !strings.Contains(err.Error(), tt.fails) || !errors.Is(err, cli.ErrUsage) {
					t.Errorf("outputDir error = %v, want a usage error containing %q", err, tt.fails)
				}
			case err != nil || got != tt.want:
				t.Errorf("outputDir = %q, %v; want %q", got, err, tt.want)
			}
		})
	}
	if _, err := outputDir(string(filepath.Separator), "", string(filepath.Separator), "slopmop-"); err == nil {
		t.Error("the root of the file system has a folder outside it")
	}
}

// A folder is inside another by where it is, not by how its path is written.
func TestWithin(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "case42")
	if err := os.MkdirAll(filepath.Join(input, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name, folder, dir string
		want              bool
	}{
		{"itself", input, input, true},
		{"a folder in it", input, filepath.Join(input, "sub"), true},
		{"a folder to be made in it", input, filepath.Join(input, "new", "deeper"), true},
		{"its parent", input, root, false},
		{"a folder beside it", input, filepath.Join(root, "slopmop-case42"), false},
		{"a folder whose name begins the same", input, input + "-out", false},
		{"written with a way round", input, filepath.Join(root, "other", "..", "case42", "out"), true},
		{"an input that does not exist", filepath.Join(root, "missing"), filepath.Join(root, "out"), false},
		{"inside an input that does not exist", filepath.Join(root, "missing"), filepath.Join(root, "missing", "out"), true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := within(tt.folder, tt.dir); got != tt.want {
				t.Errorf("within(%q, %q) = %t, want %t", tt.folder, tt.dir, got, tt.want)
			}
		})
	}
}

func TestFolderName(t *testing.T) {
	if got := folderName(filepath.Join(t.TempDir(), "case42")); got != "case42" {
		t.Errorf("folderName = %q, want case42", got)
	}
	// A root without a volume has no letters to lend.
	if got := folderName(string(filepath.Separator)); got != "root" {
		t.Errorf("the root of the file system is named %q, want root", got)
	}
}

// A run from inside the evidence writes beside it and leaves it as it was.
func TestReportLeavesTheEvidenceAlone(t *testing.T) {
	folder := evidencetest.Copy(t, "bash")
	before, err := os.ReadDir(folder)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	app, err := NewApp("slopmop", Env{Stdout: &out, WorkDir: folder})
	if err != nil {
		t.Fatal(err)
	}
	if err = app.Run([]string{"-inputdir", folder, "report", "summary"}); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadDir(folder)
	if err != nil || len(after) != len(before) {
		t.Errorf("the evidence folder holds %d entries after the run and %d before (%v)", len(after), len(before), err)
	}
	beside := filepath.Join(filepath.Dir(folder), "slopmop-"+filepath.Base(folder))
	if _, err := os.Stat(filepath.Join(beside, "report.txt")); err != nil {
		t.Errorf("no report beside the evidence: %v", err)
	}
}

func TestRegisterBindsBothWays(t *testing.T) {
	doc, err := decodeCommands(commandsJSON)
	if err != nil {
		t.Fatal(err)
	}
	env := Env{Stdout: &bytes.Buffer{}}
	if err := register(cli.New("slopmop", doc.Usage, env.Stdout), doc, map[string]builder{}); err == nil ||
		!strings.Contains(err.Error(), "which has no implementation") {
		t.Errorf("a declared verb without an implementation: error = %v", err)
	}
	builders := map[string]builder{"report": env.reportVerb, "process": env.reportVerb}
	if err := register(cli.New("slopmop", doc.Usage, env.Stdout), doc, builders); err == nil ||
		!strings.Contains(err.Error(), "does not declare process") {
		t.Errorf("an implementation without a declaration: error = %v", err)
	}
	twice := doc
	twice.Verbs = append(twice.Verbs, doc.Verbs[0])
	if err := register(cli.New("slopmop", doc.Usage, env.Stdout), twice, map[string]builder{"report": env.reportVerb}); err == nil ||
		!strings.Contains(err.Error(), "already taken") {
		t.Errorf("a verb declared twice: error = %v", err)
	}
}

func TestDecodeCommandsRejects(t *testing.T) {
	const option = `"options":[{"name":"inputdir","hint":"<folder>","summary":"s"}]`
	cases := []struct {
		name string
		doc  string
		want string
	}{
		{"not json", `{`, "unexpected"},
		{"unknown field", `{"usage":"u","extra":1}`, "unknown field"},
		{"trailing data", `{"usage":"u","verbs":[{"name":"v","summary":"s"}]} []`, "after the document"},
		{"no verbs", `{"usage":"u"}`, "no usage or no verbs"},
		{"no usage", `{"verbs":[{"name":"v","summary":"s"}]}`, "no usage or no verbs"},
		{"an option without a hint", `{"usage":"u","options":[{"name":"x","summary":"s"}],"verbs":[{"name":"v","summary":"s"}]}`, "lacks a name, a hint or a summary"},
		{"an option twice", `{"usage":"u","options":[{"name":"x","hint":"h","summary":"s"},{"name":"x","hint":"h","summary":"s"}],"verbs":[{"name":"v","summary":"s"}]}`, "declared twice"},
		{"a verb without a summary", `{"usage":"u","verbs":[{"name":"v"}]}`, "needs a name and a summary"},
		{"an undeclared option", `{"usage":"u",` + option + `,"verbs":[{"name":"v","summary":"s","takes":["outdir"]}]}`, `the option "outdir" is not declared`},
		{"an option required and taken", `{"usage":"u",` + option + `,"verbs":[{"name":"v","summary":"s","requires":["inputdir"],"takes":["inputdir"]}]}`, "named twice"},
		{"a class twice", `{"usage":"u","verbs":[{"name":"v","summary":"s"}],"classes":[{"name":"c","columns":[{"header":"A","key":"a"}]},{"name":"c","columns":[{"header":"A","key":"a"}]}]}`, "declared twice"},
		{"a lower-case header", `{"usage":"u","verbs":[{"name":"v","summary":"s"}],"classes":[{"name":"c","columns":[{"header":"name","key":"name"}]}]}`, "class c:"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := decodeCommands([]byte(c.doc)); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("decodeCommands error = %v, want one containing %q", err, c.want)
			}
		})
	}
}

// reportSpec returns the report verb as commands.json declares it, to break in a test.
func reportSpec(t *testing.T) (verbSpec, commandsDoc) {
	t.Helper()
	doc, err := decodeCommands(commandsJSON)
	if err != nil {
		t.Fatal(err)
	}
	return doc.Verbs[0], doc
}

func TestReportVerbRejects(t *testing.T) {
	tests := []struct {
		name   string
		damage func(v *verbSpec, doc *commandsDoc)
		want   string
	}{
		{"no sections", func(v *verbSpec, _ *commandsDoc) { v.Sections = nil }, "needs a section"},
		{"a section without a title", func(v *verbSpec, _ *commandsDoc) { v.Sections[0].Title = "" }, "needs a name, a title and a summary"},
		{"a section twice", func(v *verbSpec, _ *commandsDoc) { v.Sections = append(v.Sections, v.Sections[0]) }, "declared twice"},
		{"an unknown section", func(v *verbSpec, _ *commandsDoc) { v.Sections[0].Name = "bogus" }, "which has no implementation"},
		{"a section left out", func(v *verbSpec, _ *commandsDoc) { v.Sections = v.Sections[1:] }, "does not declare the section"},
		{"an option it reads and does not name", func(v *verbSpec, _ *commandsDoc) { v.Takes = v.Takes[:1] }, `reads the option "outdir"`},
		{"a row that fills a column the class lacks", func(_ *verbSpec, doc *commandsDoc) { doc.Classes[4].Columns = doc.Classes[4].Columns[1:] }, "the class exposure declares 9 columns and fills 10"},
		{"a column the targeted row lacks", func(_ *verbSpec, doc *commandsDoc) { doc.Classes[3].Columns[2].Key = "bogus" }, `the class targeted declares the column "bogus"`},
		{"no prefix", func(v *verbSpec, _ *commandsDoc) { v.Saved.Prefix = "" }, "needs a prefix"},
		{"no tables", func(v *verbSpec, _ *commandsDoc) { v.Saved.Tables = nil }, "needs a prefix"},
		{"an unknown class", func(v *verbSpec, _ *commandsDoc) { v.Saved.Tables[0].Class = "bogus" }, "which has no table"},
		{"a path for a name", func(v *verbSpec, _ *commandsDoc) { v.Saved.Tables[0].File = "../f.json" }, "not a file name of its own"},
		{"a name twice", func(v *verbSpec, _ *commandsDoc) { v.Saved.Readouts[0].File = "trace.json" }, "not a file name of its own"},
		{"no readouts", func(v *verbSpec, _ *commandsDoc) { v.Saved.Readouts = nil }, "needs a prefix"},
		{"an unknown format", func(v *verbSpec, _ *commandsDoc) { v.Saved.Readouts[1].Format = "pdf" }, `"pdf" is not a format of its own`},
		{"a table in an unknown format", func(v *verbSpec, _ *commandsDoc) { v.Saved.Tables[0].Format = "xml" }, `"xml" is not a format of a table`},
		{"a table without a format", func(v *verbSpec, _ *commandsDoc) { v.Saved.Tables[1].Format = "" }, `"" is not a format of a table`},
		{"a format twice", func(v *verbSpec, _ *commandsDoc) { v.Saved.Readouts[2].Format = "text" }, `"text" is not a format of its own`},
		{"a readout under a table's name", func(v *verbSpec, _ *commandsDoc) { v.Saved.Readouts[2].File = v.Saved.Readouts[0].File }, "not a file name of its own"},
		{"a readout in a folder", func(v *verbSpec, _ *commandsDoc) { v.Saved.Readouts[1].File = "sub/report.md" }, "not a file name of its own"},
		{"a class without columns", func(_ *verbSpec, doc *commandsDoc) { doc.Classes = doc.Classes[1:] }, "which declares no columns"},
		{"a column the row lacks", func(_ *verbSpec, doc *commandsDoc) { doc.Classes[0].Columns[0].Key = "bogus" }, `the class file declares the column "bogus"`},
		{"a column left out", func(_ *verbSpec, doc *commandsDoc) { doc.Classes[1].Columns = doc.Classes[1].Columns[1:] }, "the class trace declares 12 columns and fills 13"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, doc := reportSpec(t)
			tt.damage(&v, &doc)
			if _, err := (Env{}).reportVerb(v, doc); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("reportVerb error = %v, want one containing %q", err, tt.want)
			}
		})
	}
}

// An activity with no impact or no action would be found and then left out
// of the report an analyst acts on.
func TestAssessmentCoversEveryActivity(t *testing.T) {
	pipe, err := loadPipeline()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range pipe.activities.Names() {
		if !pipe.assessment.Covers(name) {
			t.Errorf("%s has no impact or no action", name)
		}
	}
}

// A technique gives an activity each of its tactics: ATT&CK files every
// technique under one of them and under each of them a technique, and every
// identifier is one the catalogue lists. The embedded table is held to that.
func TestTacticsFollowFromTechniques(t *testing.T) {
	pipe, err := loadPipeline()
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name            string
		tactics, attack []string
		want            string
	}{
		{"a technique under its tactic", []string{"CommandAndControl"}, []string{"T1105"}, ""},
		{"a technique of two tactics", []string{"Persistence", "Execution"}, []string{"T1053.005"}, ""},
		{"a tactic ATT&CK gives the technique and the activity leaves out", []string{"Persistence"}, []string{"T1053.005"}, ""},
		{"a technique the catalogue lacks", []string{"Discovery"}, []string{"T0000"}, `the ATT&CK technique "T0000", which the catalogue lacks`},
		{"a technique under none of the tactics", []string{"Discovery"}, []string{"T1105"}, "the technique T1105, which ATT&CK files under none of its tactics"},
		{"a tactic no technique gives", []string{"CommandAndControl", "Discovery"}, []string{"T1105"}, "the tactic Discovery, which ATT&CK files none of its techniques"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := follows("Made", tt.tactics, tt.attack, pipe.tactics, pipe.catalogue)
			if (err == nil) != (tt.want == "") || (err != nil && !strings.Contains(err.Error(), tt.want)) {
				t.Errorf("follows = %v, want %q", err, tt.want)
			}
		})
	}
	pipe.activities.Each(func(name string, tactics, attack []string) {
		if err := follows(name, tactics, attack, pipe.tactics, pipe.catalogue); err != nil {
			t.Error(err)
		}
	})
}

// The mitigation section is derived: each row is a mitigation the framework
// links to a technique that was found.
func TestReportMitigationsComeFromTheCatalogue(t *testing.T) {
	pipe, err := loadPipeline()
	if err != nil {
		t.Fatal(err)
	}
	_, saved := report(t, evidencetest.Copy(t, "lolbin"))
	attack, atlas, guardrails := 0, 0, false
	for _, row := range rows(t, filepath.Join(saved, "report.json")) {
		if row["section"] != sectionMitigation {
			continue
		}
		item, _ := row["item"].(string)
		id, name, _ := strings.Cut(item, " ")
		guardrails = guardrails || item == "AML.M0020 Generative AI Guardrails"
		switch {
		case strings.HasPrefix(id, "AML.M"):
			atlas++
			if got := pipe.catalogue.Atlas.Mitigations[id].Name; got != name {
				t.Errorf("%s is named %q, the catalogue says %q", id, name, got)
			}
		case strings.HasPrefix(id, "M"):
			if atlas > 0 {
				t.Errorf("%s follows an ATLAS mitigation; ATT&CK comes first", id)
			}
			attack++
			if got := pipe.catalogue.Attack.Mitigations[id].Name; got != name {
				t.Errorf("%s is named %q, the catalogue says %q", id, name, got)
			}
		default:
			t.Errorf("row %q is not a mitigation of either framework", item)
		}
	}
	if attack == 0 || atlas == 0 {
		t.Errorf("%d ATT&CK and %d ATLAS mitigations, want some of each", attack, atlas)
	}
	// The premise of the tool brings in the ATLAS technique for generated commands.
	if !guardrails {
		t.Error("the mitigations lack the one ATLAS gives for generated commands")
	}
	_, saved = report(t, t.TempDir())
	for _, row := range rows(t, filepath.Join(saved, "report.json")) {
		if row["section"] != sectionSummary {
			t.Errorf("an empty folder gives the row %v, want counts only", row)
		}
	}
}

func TestPipelineRejectsAnUnknownTactic(t *testing.T) {
	pipe, err := loadPipeline()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range pipe.activities.Tactics() {
		if !pipe.tactics.Has(name) {
			t.Errorf("activities.json names %s, which tactics.json lacks", name)
		}
	}
	if pipe.tactics.Has("NoSuchTactic") {
		t.Error("Has reports a tactic the table lacks")
	}
}
