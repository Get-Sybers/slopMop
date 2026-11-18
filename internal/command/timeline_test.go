package command

import (
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/get-sybers/slopmop/internal/activity"
	"github.com/get-sybers/slopmop/internal/evidence"
	"github.com/get-sybers/slopmop/internal/intel"
	"github.com/get-sybers/slopmop/internal/render"
	"github.com/get-sybers/slopmop/internal/tactic"
	"github.com/get-sybers/slopmop/internal/trace"
)

// stepAt is a file of the timeline, so many minutes after nine, and what it shows.
func stepAt(minute int, path string, tactics ...string) trace.Step {
	at := time.Date(2026, 10, 22, 9, minute, 0, 0, time.UTC)
	return trace.Step{File: evidence.File{Path: path, Role: evidence.Script, Modified: at}, Tactics: tactics}
}

func runOf(t *testing.T, steps []trace.Step, intentOf map[string]string) reportRun {
	t.Helper()
	pipe, err := loadPipeline()
	if err != nil {
		t.Fatal(err)
	}
	return reportRun{pipe: pipe, result: analysis{timeline: trace.Timeline{Steps: steps}, intentOf: intentOf}}
}

// brief writes a period as its first and last file and its tactics, so a
// test states what it expects on one line.
func (p period) brief() string {
	files := p.first.File.Path
	if p.last.File.Path != files {
		files += ".." + p.last.File.Path
	}
	return files + ": " + strings.Join(p.tactics, ",")
}

// A period is the files, one after another, that show no tactic its first
// file does not. A file that shows nothing is in none, and ends none.
func TestPeriods(t *testing.T) {
	recon := stepAt(0, "recon.sh", "Discovery")
	recon.Tools = []string{"nmap", "curl"}
	both := stepAt(5, "creds.sh", "CredentialAccess", "Discovery")
	both.Tools = []string{"cat", "curl"}
	both.Activities = []activity.Hit{{Name: "ShadowFileRead", Attack: []string{"T1003.008"}}, {Name: "PrivateKeyRead", Attack: []string{"T1552.004"}}}
	again := stepAt(7, "more.sh", "Discovery")
	again.Activities = []activity.Hit{{Name: "ShadowFileRead", Attack: []string{"T1003.008"}}, {Name: "ServiceDiscovery", Attack: []string{"T1007"}}}
	listed := stepAt(8, "c2.txt")
	listed.IntelHits = []intel.Hit{{Attribution: "APT-X", Value: "203.0.113.40"}}
	steps := []trace.Step{
		stepAt(0, "notes.md"), recon, stepAt(1, "resp_0001"), stepAt(2, "scan.txt"), both, stepAt(6, "shadow.txt"), again, listed,
		stepAt(9, "persist.sh", "Persistence"), stepAt(9, "resp_0002"),
	}
	all, quiet := runOf(t, steps, map[string]string{"creds.sh": "i12", "more.sh": "i12", "c2.txt": "i14"}).periods()
	var got []string
	for _, p := range all {
		got = append(got, p.brief())
	}
	want := []string{"recon.sh: Discovery", "creds.sh..c2.txt: Discovery,CredentialAccess", "persist.sh: Persistence"}
	if !slices.Equal(got, want) || quiet != 5 {
		t.Fatalf("periods = %q with %d files in none, want %q with 5", got, quiet, want)
	}
	second := all[1]
	if second.first.File.Path != "creds.sh" || second.last.File.Path != "c2.txt" {
		t.Errorf("the second period runs from %s to %s", second.first.File.Path, second.last.File.Path)
	}
	for name, pair := range map[string][2][]string{
		"techniques": {second.attack, {"T1003.008", "T1552.004", "T1007"}},
		"ATLAS":      {second.atlas, {"AML.T0090", "AML.T0055"}},
		"watchlist":  {second.hits, {"APT-X: 203.0.113.40"}},
	} {
		if !slices.Equal(pair[0], pair[1]) {
			t.Errorf("the %s of the second period are %q, want %q", name, pair[0], pair[1])
		}
	}
	// A watchlist match with no tactic before it is a period of its own.
	alone, _ := runOf(t, []trace.Step{listed, recon}, nil).periods()
	if len(alone) != 2 || alone[0].brief() != "c2.txt: " || alone[1].brief() != "recon.sh: Discovery" {
		t.Errorf("a watchlist match first gives %d periods", len(alone))
	}
}

// Where no file names an intent, the section holds a block for each period,
// however many files it has, and says how many files are in none.
func TestTimelineSection(t *testing.T) {
	found := stepAt(4, "b.sh", "Discovery")
	found.Activities = []activity.Hit{{Name: "ServiceDiscovery", Attack: []string{"T1007"}}}
	steps := []trace.Step{stepAt(0, "a.sh", "Discovery"), stepAt(1, "quiet.txt"), found, stepAt(9, "c.sh", "Persistence")}
	groups := runOf(t, steps, nil).timeline()
	if len(groups) != 2 || len(groups[0].Entries) != 2 || !groups[0].Blocks || len(groups[0].Columns) != 0 {
		t.Fatalf("the section has %d groups, want the blocks of the periods and a line for the other files", len(groups))
	}
	cells := func(e render.Entry) string { return strings.Join(e.Cells, " | ") }
	for i, want := range []string{"Discovery | 2026-10-22T09:00:00Z to 2026-10-22T09:04:00Z", "Persistence | 2026-10-22T09:09:00Z"} {
		if got := cells(groups[0].Entries[i]); got != want {
			t.Errorf("period %d is %q, want %q", i+1, got, want)
		}
	}
	first, second := groups[0].Entries[0], groups[0].Entries[1]
	if want := []render.Row{row("T1007  System Service Discovery", "TA0007  Discovery")}; !slices.Equal(first.Rows, want) || len(first.Detail) != 0 {
		t.Errorf("the first block lists %v and %v, want %v alone", first.Rows, first.Detail, want)
	}
	if want := []render.Row{row("", "TA0003  Persistence")}; !slices.Equal(second.Rows, want) || !slices.Equal(second.Detail, []render.Detail{{Text: noTechnique}}) {
		t.Errorf("the second block lists %v and %v, want %v and that no technique was identified", second.Rows, second.Detail, want)
	}
	if groups[0].Heads != heads() {
		t.Errorf("the blocks head their columns %q, want %q", groups[0].Heads, heads())
	}
	if got, want := cells(groups[1].Entries[0]), "and 1 file that shows no tactic, in the saved trace"; got != want {
		t.Errorf("the last line is %q, want %q", got, want)
	}
	if got := runOf(t, []trace.Step{stepAt(0, "quiet.txt")}, nil).timeline(); got != nil {
		t.Errorf("a folder that shows nothing has a timeline of %d groups, want none", len(got))
	}
}

// Of more periods than are shown, the first and the last stand, with the
// number left out between them.
func TestTimelineKeepsTheEnds(t *testing.T) {
	var steps []trace.Step
	for i := range fewPeriods + 7 {
		steps = append(steps, stepAt(i, "step"+strconv.Itoa(i)+".sh", []string{"Discovery", "Persistence"}[i%2]))
	}
	groups := runOf(t, steps, nil).timeline()
	if len(groups) != 3 || len(groups[0].Entries) != fewPeriods/2 || len(groups[2].Entries) != fewPeriods/2 {
		t.Fatalf("the section has %d groups, want the first periods, a line and the last periods", len(groups))
	}
	if got, want := groups[1].Entries[0].Cells[0], "and 7 more periods here, in the saved trace"; got != want {
		t.Errorf("the line between is %q, want %q", got, want)
	}
	first, last := groups[0].Entries[0].Cells, groups[2].Entries[fewPeriods/2-1].Cells
	if first[1] != "2026-10-22T09:00:00Z" || last[1] != "2026-10-22T09:"+strconv.Itoa(fewPeriods+6)+":00Z" {
		t.Errorf("the ends are at %q and %q, want the first and the last period", first[1], last[1])
	}
}

// A watchlist match of a file of an intent is named in the block of the
// intent, after its techniques.
func TestIntentBlocksNameWatchlistMatches(t *testing.T) {
	pipe, err := loadPipeline()
	if err != nil {
		t.Fatal(err)
	}
	step := trace.Step{File: evidence.File{Path: "i5/a.sh"}, IntelHits: []intel.Hit{{Attribution: "APT-X", Value: "203.0.113.40"}}}
	runs, _ := pipe.collectIntents(t.TempDir(), []trace.Step{step, {File: evidence.File{Path: "i6/b.sh"}}})
	groups := reportRun{pipe: pipe, result: analysis{intents: runs}}.timeline()
	if len(groups) == 0 || len(groups[0].Entries) != 2 {
		t.Fatalf("the timeline has %d groups, want a block for each of the two intents", len(groups))
	}
	if got, want := groups[0].Entries[0].Detail, []render.Detail{{Text: noTechnique}, {Label: "watchlist", Text: "APT-X: 203.0.113.40"}}; !slices.Equal(got, want) {
		t.Errorf("the block of i5 lists %v, want %v", got, want)
	}
	if got, want := groups[0].Entries[1].Detail, []render.Detail{{Text: noTechnique}}; !slices.Equal(got, want) {
		t.Errorf("the block of i6 lists %v, want %v", got, want)
	}
	if rows := slices.Concat(groups[0].Entries[0].Rows, groups[0].Entries[1].Rows); len(rows) != 0 {
		t.Errorf("the blocks have the rows %v, want none: their files show no tactic", rows)
	}
}

// row is a row of a block as a test writes it: "id  name" for a thing,
// "tools: names" for the tools that give a tactic, and "" for an empty place.
func row(things ...string) render.Row {
	var r render.Row
	for i, text := range things {
		if kind, names, ok := strings.Cut(text, ": "); ok && kind == "tools" {
			r[i] = render.Named{Kind: kind, Name: names}
		} else if id, name, ok := strings.Cut(text, "  "); ok {
			r[i] = render.Named{ID: id, Name: name}
		}
	}
	return r
}

// madeTactics is the command table of a test, so that what is filed in the
// embedded one does not decide it: a command under a technique, and others
// under none.
func madeTactics(t *testing.T) tactic.Table {
	t.Helper()
	table, err := tactic.Parse([]byte(`[
		{"tactic":"Discovery","severity":"low","id":"TA0007","atlas":"AML.TA0008","commands":["look","peek"]},
		{"tactic":"LateralMovement","severity":"high","id":"TA0008","atlas":"AML.TA0015","techniques":{"T1021.004":["hop"]},"commands":["leap"]},
		{"tactic":"Execution","severity":"medium","id":"TA0002","atlas":"AML.TA0005","commands":["run"]},
		{"tactic":"PrivilegeEscalation","severity":"high","id":"TA0004","atlas":"AML.TA0012","commands":["rise"]},
		{"tactic":"Persistence","severity":"high","id":"TA0003","atlas":"AML.TA0006","commands":["stay"]},
		{"tactic":"Collection","severity":"medium","id":"TA0009","atlas":"AML.TA0009","commands":["take"]},
		{"tactic":"CommandAndControl","severity":"high","id":"TA0011","atlas":"AML.TA0014","commands":["call"]}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	return table
}

// A row is a technique and what follows from it: the tactic that holds it,
// and the ATLAS techniques it infers. An activity shows a technique and so
// does a command that is filed under one; a command under none is a tool.
func TestBlocksListTechniquesFirst(t *testing.T) {
	pipe, err := loadPipeline()
	if err != nil {
		t.Fatal(err)
	}
	pipe.tactics = madeTactics(t)
	scan := stepAt(0, "i201_scan.sh", "Discovery")
	scan.Tools = []string{"look", "curl", "Peek.exe"}
	move := stepAt(5, "i202-move.sh", "CommandAndControl", "Discovery", "LateralMovement")
	move.Tools = []string{"leap", "hop", "look"}
	move.Activities = []activity.Hit{{Name: "FileDownload", Tactics: []string{"CommandAndControl"}, Attack: []string{"T1105"}}}
	// A scheduled task is of two tactics: both stand with its technique.
	task := stepAt(7, "i203_task.ps1", "Execution", "Persistence", "PrivilegeEscalation")
	task.Activities = []activity.Hit{
		{Name: "SharePointEnumeration", Tactics: []string{"Collection"}, Attack: []string{"T1213.002"}},
		{Name: "AccountCreation", Tactics: []string{"Persistence"}, Attack: []string{"T1136.001"}},
		{Name: "ScheduledTaskCreation", Tactics: []string{"Persistence", "Execution"}, Attack: []string{"T1053.005"}},
	}
	runs, _ := pipe.collectIntents(t.TempDir(), []trace.Step{scan, stepAt(1, "cmd-i201.stdout.txt"), move, task, stepAt(9, "i204.sh")})
	groups := reportRun{pipe: pipe, result: analysis{intents: runs}}.timeline()
	if len(groups) == 0 || len(groups[0].Entries) != 4 {
		t.Fatalf("the timeline has %d groups, want a block for each of the four intents", len(groups))
	}
	// The technique of a command is a technique of the intent, as that of an activity is.
	if got, want := runs[1].attack, []string{"T1105", "T1021.004"}; !slices.Equal(got, want) {
		t.Errorf("i202 has the techniques %q, want %q", got, want)
	}
	if got, want := runs[1].atlas, []string{"AML.T0072"}; !slices.Equal(got, want) || len(runs[0].attack) != 0 {
		t.Errorf("i202 has the ATLAS techniques %q, want %q, and i201 the techniques %q, want none", got, want, runs[0].attack)
	}
	none := []render.Detail{{Text: noTechnique}}
	wants := []render.Entry{
		{Rows: []render.Row{row("tools: look, Peek.exe", "TA0007  Discovery")}, Detail: none},
		// A tool whose tactic a technique gives is listed all the same: no technique is named for it.
		{Rows: []render.Row{
			row("tools: look", "TA0007  Discovery"),
			row("T1021.004  Remote Services: SSH", "TA0008  LateralMovement"),
			row("tools: leap", "TA0008  LateralMovement"),
			row("T1105  Ingress Tool Transfer", "TA0011  CommandAndControl", "AML.T0072  Cyber Communication Channel"),
		}},
		// The rows stand in the order of the tactic table, whichever technique was shown first.
		{Rows: []render.Row{
			row("T1053.005  Scheduled Task/Job: Scheduled Task", "TA0002  Execution"),
			row("", "TA0003  Persistence"),
			row("", "TA0004  PrivilegeEscalation"),
			row("T1136.001  Create Account: Local Account", "TA0003  Persistence", "AML.T0125  Create Account"),
			row("T1213.002  Data from Information Repositories: Sharepoint", "TA0009  Collection", "AML.T0036  Data from Information Repositories"),
			row("", "", "AML.T0126  Automated Collection"),
		}},
		{Detail: none},
	}
	for i, want := range wants {
		if got := groups[0].Entries[i]; !slices.Equal(got.Rows, want.Rows) || !slices.Equal(got.Detail, want.Detail) {
			t.Errorf("the block of %s lists\n  %v and %v, want\n  %v and %v", got.Cells[0], got.Rows, got.Detail, want.Rows, want.Detail)
		}
	}
	// A period lists the same under its name.
	periods := runOf(t, []trace.Step{stepAt(0, "scan.sh", "Discovery")}, nil).timeline()
	want := render.Entry{Level: "low", Cells: []string{"Discovery", "2026-10-22T09:00:00Z"}, Rows: []render.Row{row("", "TA0007  Discovery")}, Detail: none}
	if got := periods[0].Entries[0]; !reflect.DeepEqual(got, want) {
		t.Errorf("the block of a period is %+v, want %+v", got, want)
	}
}
