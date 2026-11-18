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
	if want := "-> saved to <out>: report.txt, report.md, report.html, files.csv, trace.json, intents.json, findings.json, targeted.json, exposure.csv, report.json\n"; !strings.Contains(shown, want) {
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
	for _, title := range []string{"Summary", "Timeline", "Findings", "Notable files", "Targeted", "Exposure", "Impact", "Remediation", "Mitigation"} {
		if !strings.Contains(markdown, "\n## "+title+"\n") {
			t.Errorf("report.md lacks the section %s", title)
		}
		if !strings.Contains(page, "<h2>"+title+"</h2>") {
			t.Errorf("report.html lacks the section %s", title)
		}
	}
	if strings.Contains(markdown, "\n## Intents\n") {
		t.Errorf("report.md shows the empty Intents section")
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
	for name, least := range map[string]int{"files.csv": 14, "trace.json": 14, "findings.json": 30, "targeted.json": 6, "exposure.csv": 15, "report.json": 60} {
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
	want := []string{"Summary", "Timeline", "Findings", "Notable files", "Targeted", "Exposure", "Impact", "Remediation", "Mitigation"}
	if !slices.Equal(titles, want) {
		t.Errorf("sections = %q, want %q", titles, want)
	}
	two, _ := report(t, folder, "mitigation", "files")
	if files, mitigation := strings.Index(two, "\nNotable files"), strings.Index(two, "\nMitigation"); files < 0 || mitigation < files {
		t.Errorf("the sections are missing or out of order:\n%s", two)
	}
	if !strings.Contains(two, "20261020_101500_step04_persist.ps1") || strings.Contains(two, "recon_20261020_100030.txt") {
		t.Errorf("notable files: want the persistence script and not the recon output:\n%s", two)
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
// belongs to none.
func TestReportIntents(t *testing.T) {
	folder := artex(t)
	readout, saved := report(t, folder, "summary", "intents")
	// A fixture is a copy, made now and last changed when its manifest says.
	// Where a last change set to the past takes the creation time with it,
	// as on macOS, its files are as if made there, 3 seconds after their names.
	timedBy, first, last := byTimeline, "2026-10-22T09:00:00Z", "2026-10-22T09:00:40Z"
	if copied(t, saved) {
		golden.Check(t, "artex-report-intents", []byte(readout))
		golden.Check(t, "artex-intents-json", []byte(readFile(t, filepath.Join(saved, "intents.json"))))
	} else {
		timedBy, first, last = byCreation, "2026-10-22T09:00:03Z", "2026-10-22T09:00:43Z"
	}
	table := rows(t, filepath.Join(saved, "intents.json"))
	var order []string
	for _, row := range table {
		order = append(order, row["intent"].(string))
	}
	if want := []string{"i1041", "i1042", "i998", "i1051"}; !slices.Equal(order, want) {
		t.Errorf("intents = %q, want %q: in the order they began", order, want)
	}
	row := find(t, table, map[string]string{"intent": "i1041", "task": "7"})
	if row["first"] != first || row["last"] != last || row["seconds"] != float64(40) {
		t.Errorf("i1041 runs from %v to %v, %v seconds, want %s to %s, 40", row["first"], row["last"], row["seconds"], first, last)
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
	timeline, _ := report(t, folder, "timeline")
	if !strings.Contains(timeline, "      intent      i1041, i1042\n") {
		t.Errorf("the timeline does not name the intents of a period:\n%s", timeline)
	}
	for name, body := range map[string]string{"report.md": readFile(t, filepath.Join(saved, "report.md")), "report.html": readFile(t, filepath.Join(saved, "report.html"))} {
		for _, held := range []string{"Intent timeline", "i1042", "T1003.008", "AML.T0090"} {
			if !strings.Contains(body, held) {
				t.Errorf("%s does not hold %q", name, held)
			}
		}
	}
}

// A run folder that is read itself is one intent, and keeps its task.
func TestReportReadsOneIntent(t *testing.T) {
	folder := artex(t)
	_, saved := report(t, filepath.Join(folder, "data", "tasks", "7", "i1042"))
	table := rows(t, filepath.Join(saved, "intents.json"))
	if len(table) != 1 || table[0]["intent"] != "i1042" || table[0]["task"] != "7" {
		t.Errorf("intents = %v, want i1042 of task 7 alone", table)
	}
}

// Evidence that no ARTEX run wrote has no intent, and its summary no count of them.
func TestReportWithoutIntents(t *testing.T) {
	readout, saved := report(t, evidencetest.Copy(t, "bash"), "summary", "intents")
	if strings.Contains(readout, "Intent timeline") {
		t.Errorf("the readout shows the empty section of the intents:\n%s", readout)
	}
	if strings.Contains(readout, "\n  intents") {
		t.Errorf("the summary counts intents where there are none:\n%s", readout)
	}
	if got := len(rows(t, filepath.Join(saved, "intents.json"))); got != 0 {
		t.Errorf("intents.json holds %d rows, want none", got)
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
	groups := reportRun{result: analysis{intents: runs}}.intents()
	if got := groups[0].Entries[4].Cells; !slices.Equal(got, []string{"-", "-", "i30", "-"}) {
		t.Errorf("i30 is written %q", got)
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
	groups := reportRun{result: analysis{intents: runs}}.intents()
	if got, want := groups[0].Entries[0].Cells, []string{"2026-10-22T09:10:00Z", "2026-10-22T09:12:00Z", "i5", "T1046, T1018"}; !slices.Equal(got, want) {
		t.Errorf("i5 is written %q, want %q", got, want)
	}
	if got, want := groups[0].Entries[3].Cells, []string{"2026-10-22T09:55:00Z", "-", "i8", "-"}; !slices.Equal(got, want) {
		t.Errorf("i8 is written %q, want %q", got, want)
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
	readout, saved := report(t, folder, "intents")
	for _, row := range rows(t, filepath.Join(saved, "files.csv")) {
		if row["created"] == nil {
			t.Skip("this file system records no creation time")
		}
	}
	ended := time.Now().Add(2 * time.Second)
	table := rows(t, filepath.Join(saved, "intents.json"))
	if len(table) != 2 {
		t.Fatalf("intents.json holds %d intents, want i7 and i8:\n%v", len(table), table)
	}
	for i, want := range []struct{ id, attack, files string }{
		{"i7", "T1136.001", "i7_20200101_000000_persist.sh, cmd-i7.stdout.txt"},
		{"i8", "T1003.008", "i8_creds.sh"},
	} {
		row := table[i]
		if row["intent"] != want.id || row["attack"] != want.attack || row["files"] != want.files || row["timed_by"] != byCreation {
			t.Errorf("intent %d is %v, want %s with %s and %s, timed by %s", i, row, want.id, want.attack, want.files, byCreation)
		}
		for _, key := range []string{"first", "last"} {
			text, _ := row[key].(string)
			at, err := time.Parse(time.RFC3339, text)
			if err != nil || at.Before(began) || at.After(ended) {
				t.Errorf("%s %s = %q (%v), want when the test made its files, from %s until %s", want.id, key, text, err, began.UTC(), ended.UTC())
			}
		}
	}
	if !strings.Contains(readout, "  i7  T1136.001\n") || !strings.Contains(readout, "      files  i7_20200101_000000_persist.sh, cmd-i7.stdout.txt\n") {
		t.Errorf("the readout does not give i7 its technique and its files:\n%s", readout)
	}
	if strings.Contains(readout, "timed by name or last change") {
		t.Errorf("the readout says a file is not timed by its creation:\n%s", readout)
	}
}

// Of more intents than the timeline of intents shows, the first and the last are shown.
func TestIntentsShowTheFirstAndTheLast(t *testing.T) {
	at := time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)
	var runs []intentRun
	for i := range fewPeriods + 5 {
		when := at.Add(time.Duration(i) * time.Minute)
		runs = append(runs, intentRun{ref: intent.Ref{ID: "i" + strconv.Itoa(100+i)}, from: when, until: when, timed: 1, recorded: 1, files: []string{"a.sh"}})
	}
	groups := reportRun{result: analysis{intents: runs}}.intents()
	if len(groups) != 3 || len(groups[0].Entries) != fewPeriods/2 || len(groups[2].Entries) != fewPeriods/2 {
		t.Fatalf("%d groups, want the first %d intents, a line and the last %d", len(groups), fewPeriods/2, fewPeriods/2)
	}
	if got, want := groups[1].Entries[0].Cells[0], "and 5 more intents here, in intents.json"; got != want {
		t.Errorf("the line between them is %q, want %q", got, want)
	}
	if first, last := groups[0].Entries[0].Cells[2], groups[2].Entries[fewPeriods/2-1].Cells[2]; first != "i100" || last != "i144" {
		t.Errorf("the intents shown run from %s to %s, want i100 to i144", first, last)
	}
	if all := (reportRun{result: analysis{intents: runs[:fewPeriods]}}).intents(); len(all) != 1 || len(all[0].Entries) != fewPeriods {
		t.Errorf("%d intents are not shown whole", fewPeriods)
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
	if !strings.Contains(out, kept+"kept.sh") || strings.Contains(out, "lost.sh") {
		t.Errorf("output = %q, want kept.sh and not lost.sh", out)
	}
	if got := len(rows(t, filepath.Join(saved, "files.csv"))); got != 1 {
		t.Errorf("files.csv holds %d rows, want the one file that was read", got)
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
			map[string]any{"value": "Fi********1 (15 chars)", "form": "password", "seen": "collected", "severity": "high", "files": "env_20261022_090540.txt:3"}},
		{map[string]string{"kind": "password", "account": "deploy"},
			map[string]any{"form": "hash", "seen": "collected", "files": "shadow_20261022_090530.txt:4"}},
		{map[string]string{"kind": "password", "form": "token"},
			map[string]any{"account": nil, "value": "fi********9 (24 chars)", "files": "env_20261022_090540.txt:5"}},
		{map[string]string{"kind": "username", "value": "deploy"},
			map[string]any{"seen": "collected", "severity": "medium", "files": "passwd_20261022_090020.txt:3"}},
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
		"exposed     19  Passwords and secrets 3, Usernames 7, Email addresses 1, Devices 2, IP addresses 6",
		"\n  Passwords and secrets (3)\n",
		"[x] Fi********1 (15 chars)  password of app_rw  collected  env_20261022_090540.txt:3\n",
		"[x] fi********9 (24 chars)  token               collected  env_20261022_090540.txt:5\n",
		"\n  Usernames (7)\n",
		"\n  IP addresses (6)\n",
	} {
		if !strings.Contains(readout, want) {
			t.Errorf("the readout lacks %q:\n%s", want, readout)
		}
	}
}

// A secret is masked wherever it would stand: in the exposure, in a command
// quoted as evidence and among the indicators. -secrets shown writes it out.
func TestReportMasksSecrets(t *testing.T) {
	folder := evidencetest.Copy(t, "bash")
	secret := []string{"Winter2025!", "Qw7#fakeMsolSecretValue99", "Zx9!fakeCloudSyncPass", "8846f7eaee8fb117ad06bdd830b7586c", "Export1!"}
	readout, saved := report(t, folder)
	holds := func(text string) []string {
		var found []string
		for _, s := range secret {
			if strings.Contains(text, s) {
				found = append(found, s)
			}
		}
		return found
	}
	if found := holds(readout); len(found) > 0 {
		t.Errorf("the readout holds %q", found)
	}
	entries, err := os.ReadDir(saved)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if found := holds(readFile(t, filepath.Join(saved, e.Name()))); len(found) > 0 {
			t.Errorf("%s holds %q", e.Name(), found)
		}
	}
	if !strings.Contains(readout, "-p 'Wi********! (11 chars)'") {
		t.Errorf("the readout does not quote the command with its password masked")
	}
	plain, saved := report(t, folder, "-secrets", "shown")
	if found := holds(plain); len(found) != len(secret) {
		t.Errorf("-secrets shown: the readout holds %q, want all of %q", found, secret)
	}
	row := find(t, rows(t, filepath.Join(saved, "exposure.csv")), map[string]string{"kind": "password", "account": "svc_backup"})
	if row["value"] != "Winter2025!" || row["seen"] != "used" {
		t.Errorf("-secrets shown: %v, want the password as it stands, used by the scripts", row)
	}
	masked, _ := report(t, folder, "-secrets", "masked")
	if masked != readout {
		t.Error("-secrets masked differs from the default")
	}
}

// An impact, an action and a mitigation name what they concern and quote the
// lines that show it; a finding quotes its lines.
func TestReportNamesWhat(t *testing.T) {
	readout, saved := report(t, evidencetest.Copy(t, "linux"), "impact", "remediation", "mitigation")
	table := rows(t, filepath.Join(saved, "report.json"))
	tests := []struct {
		section, item string
		targets       []string
		evidence      []string
	}{
		{"impact", "Persistence established",
			[]string{"account svc", "unit sync.service", "file ~/.ssh/authorized_keys", "file ~/.bashrc"},
			[]string{"AccountCreation: useradd -m -s /bin/bash svc (20261022_091500_step04_persist.sh:7)", "AccountCreation: useradd -m -s /bin/bash svc (audit_20261022_093500.jsonl)"}},
		{"impact", "Privileged access obtained",
			[]string{"file /etc/sudoers.d/svc", "file /tmp/tool ($F)", "mount /:/host"},
			[]string{"SetuidBit: chmod u+s \"$F\" (20261022_091000_step03_privesc.sh:4)"}},
		{"impact", "Movement to other systems", nil,
			[]string{"ssh: ssh ops@198.51.100.7 'cat /etc/hostname' (20261022_092500_step06_stage.sh:6)"}},
		{"impact", "Credentials exposed",
			[]string{"file /etc/shadow", "password of app_rw", "hash of deploy"},
			[]string{"ShadowFileRead: sudo cat /etc/shadow > shadow_20261022_090530.txt (20261022_090500_step02_creds.sh:6)"}},
		{"remediation", "Remove persistence",
			[]string{"account svc", "unit sync.service"},
			[]string{"SystemdUnitCreation: systemctl enable --now sync.service (20261022_091500_step04_persist.sh:6)"}},
		{"remediation", "Rotate what was read", []string{"password of app_rw", "hash of deploy", "file ~/.ssh/id_rsa"}, nil},
		{"remediation", "Restore security tooling", []string{"service auditd"},
			[]string{"SecurityToolDisabling: systemctl stop auditd (20261022_092000_step05_evade.sh:4)"}},
		{"remediation", "Follow what was enumerated", []string{"username deploy", "device db01.corp.internal", "ip 10.20.30.5"}, nil},
		{"mitigation", "M1032 Multi-factor Authentication", []string{"AccountCreation: account svc"}, nil},
	}
	for _, tt := range tests {
		row := find(t, table, map[string]string{"section": tt.section, "item": tt.item})
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
		"      targets  runs $JOB; unit sync.service; account svc;",
		"      what     ScheduledJobCreation: (crontab -l; echo \"$JOB\") | crontab - (20261022_091500_step04_persist.sh:3)\n",
		" more in report.json\n",
		"      for  AccountCreation: account svc\n",
	} {
		if !strings.Contains(readout, want) {
			t.Errorf("the readout lacks %q", want)
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

// What a script names outright is a target: prior when no earlier output
// holds it, discovered when one does, with the script lines that name it.
func TestReportTargeted(t *testing.T) {
	readout, saved := report(t, evidencetest.Copy(t, "bash"), "summary", "targeted")
	table := rows(t, filepath.Join(saved, "targeted.json"))
	tests := []struct {
		row  map[string]string
		want map[string]any
	}{
		{map[string]string{"kind": "username", "value": "svc_backup"},
			map[string]any{"origin": "prior", "from": nil, "scope": nil, "scripts": "20250301_101800_step02_enum.sh:4, 20250301_101800_step02_enum.sh:8, 20250301_102300_step03_adsync.sh:7"}},
		{map[string]string{"kind": "username", "value": "MSOL_0a1b2c3d4e5f"},
			map[string]any{"origin": "discovered", "from": "20250301_101910_step02_users.tsv:2", "evidence": `MSOL_USER="MSOL_0a1b2c3d4e5f" (20250301_103200_step05_certs.sh:3)`}},
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
		if row["kind"] == "password" {
			t.Errorf("a secret is listed as a target: %v", row)
		}
		// Every row is a value a script holds: its places are scripts.
		for _, place := range strings.Split(row["scripts"].(string), ", ") {
			if !strings.Contains(place, ".sh") {
				t.Errorf("%v names %s, which is no script", row["value"], place)
			}
		}
	}
	for _, want := range []string{
		"targeted    13  Usernames 4, Email addresses 1, Hostnames 4, IP addresses 4",
		"\n  Hostnames (4)\n",
		"    [!] 10.20.1.0/24  private  prior       20250301_101500_step01_recon.sh:3\n",
		"        from  20250301_101530_step01_recon.txt:2\n",
		"-u svc_backup -p 'Wi********! (11 chars)' -M msol",
	} {
		if !strings.Contains(readout, want) {
			t.Errorf("the readout lacks %q:\n%s", want, readout)
		}
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
	if got := (cite{"a.sh", 0}).String(); got != "a.sh" {
		t.Errorf("a cite without a line = %q", got)
	}
}

// A secret is masked inside a longer text, the longest first, and one too
// short to be told from an ordinary word is left.
func TestRedactor(t *testing.T) {
	secret := exposure.Kind{Name: "password", Secret: true}
	redact := redactor([]exposed{
		{kind: secret, value: "Winter2025!"},
		{kind: secret, value: "Winter2025!extra"},
		{kind: secret, value: "abc"},
		{kind: secret, value: "rsa private key", open: true},
		{kind: secret, value: "ShownValue1", plain: true},
		{kind: exposure.Kind{Name: "username"}, value: "svc_backup"},
	})
	got := redact("nxc -u svc_backup -p 'Winter2025!' ; x=Winter2025!extra abc rsa private key ShownValue1")
	want := "nxc -u svc_backup -p 'Wi********! (11 chars)' ; x=Wi********a (16 chars) abc rsa private key ShownValue1"
	if got != want {
		t.Errorf("redact = %q, want %q", got, want)
	}
	if same := redactor(nil)("unchanged"); same != "unchanged" {
		t.Errorf("no secrets: %q", same)
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
		{"a word for the secrets", []string{"-inputdir", folder, "report", "-secrets", "plain"}, true, `-secrets takes masked or shown, not "plain"`},
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
		{"a row that fills a column the class lacks", func(_ *verbSpec, doc *commandsDoc) { doc.Classes[4].Columns = doc.Classes[4].Columns[1:] }, "the class exposure declares 7 columns and fills 8"},
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

// A tactic an activity claims must be one ATT&CK files its techniques
// under, and every identifier must be one the catalogue lists.
func TestActivitiesAgreeWithTheCatalogue(t *testing.T) {
	pipe, err := loadPipeline()
	if err != nil {
		t.Fatal(err)
	}
	pipe.activities.Each(func(name string, tactics, attack, _ []string) {
		var official []string
		for _, id := range attack {
			official = append(official, pipe.catalogue.Attack.TacticsOf(id)...)
		}
		for _, tactic := range tactics {
			if id := pipe.tactics.Attack(tactic); !slices.Contains(official, id) {
				t.Errorf("%s claims %s (%s), which ATT&CK does not give to %q", name, tactic, id, attack)
			}
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
