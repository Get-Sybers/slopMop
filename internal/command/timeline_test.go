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
	if got, want := groups[0].Entries[0].Detail, []render.Detail{{Label: "Discovery (TA0007, AML.TA0008)", Text: "T1007  System Service Discovery"}}; !slices.Equal(got, want) {
		t.Errorf("the first block lists %v, want %v", got, want)
	}
	if got, want := groups[0].Entries[1].Detail, []render.Detail{{Label: "Persistence (TA0003, AML.TA0006)", Text: noTechnique}}; !slices.Equal(got, want) {
		t.Errorf("the second block lists %v, want %v", got, want)
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
}

// A technique stands under its parent tactic: the tactic of the activity
// that shows it, where its framework files it there. A tactic that only a
// tool gives has no technique under it, and its block says so.
func TestBlocksListTechniquesUnderTactics(t *testing.T) {
	pipe, err := loadPipeline()
	if err != nil {
		t.Fatal(err)
	}
	scan := stepAt(0, "i201_scan.sh", "Discovery")
	move := stepAt(5, "i202-move.sh", "CommandAndControl", "Discovery", "LateralMovement")
	move.Activities = []activity.Hit{{Name: "FileDownload", Tactics: []string{"CommandAndControl"}, Attack: []string{"T1105"}, Atlas: []string{"AML.T0072"}}}
	// A scheduled task is of two tactics, and its technique stands under both.
	task := stepAt(7, "i203_task.ps1", "Execution", "Persistence", "PrivilegeEscalation")
	task.Activities = []activity.Hit{
		{Name: "ScheduledTaskCreation", Tactics: []string{"Persistence", "Execution"}, Attack: []string{"T1053.005"}},
		{Name: "AccountCreation", Tactics: []string{"Persistence"}, Attack: []string{"T1136.001"}},
	}
	runs, _ := pipe.collectIntents(t.TempDir(), []trace.Step{scan, stepAt(1, "cmd-i201.stdout.txt"), move, task, stepAt(9, "i204.sh")})
	groups := reportRun{pipe: pipe, result: analysis{intents: runs}}.timeline()
	if len(groups) == 0 || len(groups[0].Entries) != 4 {
		t.Fatalf("the timeline has %d groups, want a block for each of the four intents", len(groups))
	}
	const discovery, control = "Discovery (TA0007, AML.TA0008)", "CommandAndControl (TA0011, AML.TA0014)"
	const execution, escalation, persistence = "Execution (TA0002, AML.TA0005)", "PrivilegeEscalation (TA0004, AML.TA0012)", "Persistence (TA0003, AML.TA0006)"
	wants := [][]render.Detail{
		{{Label: discovery, Text: noTechnique}},
		{
			{Label: discovery, Text: noTechnique}, {Label: "LateralMovement (TA0008, AML.TA0015)", Text: noTechnique},
			{Label: control, Text: "T1105      Ingress Tool Transfer"}, {Label: control, Text: "AML.T0072  Cyber Communication Channel"},
		},
		{
			{Label: execution, Text: "T1053.005  Scheduled Task/Job: Scheduled Task"}, {Label: escalation, Text: noTechnique},
			{Label: persistence, Text: "T1053.005  Scheduled Task/Job: Scheduled Task"}, {Label: persistence, Text: "T1136.001  Create Account: Local Account"},
			{Label: persistence, Text: "AML.T0125  Create Account"},
		},
		{{Text: noTechnique}},
	}
	for i, want := range wants {
		if got := groups[0].Entries[i]; !slices.Equal(got.Detail, want) {
			t.Errorf("the block of %s lists\n  %v, want\n  %v", got.Cells[0], got.Detail, want)
		}
	}
	// A period lists the same under its name: each of its tactics with its identifiers and its techniques.
	periods := runOf(t, []trace.Step{stepAt(0, "scan.sh", "Discovery")}, nil).timeline()
	if got, want := periods[0].Entries[0], (render.Entry{Level: "low", Cells: []string{"Discovery", "2026-10-22T09:00:00Z"}, Detail: []render.Detail{{Label: discovery, Text: noTechnique}}}); !reflect.DeepEqual(got, want) {
		t.Errorf("the block of a period is %+v, want %+v", got, want)
	}
}

// Every technique of every activity has a parent among the tactics the
// activity names, in ATT&CK and in ATLAS: no technique is left without one.
func TestEveryTechniqueHasAParentTactic(t *testing.T) {
	pipe, err := loadPipeline()
	if err != nil {
		t.Fatal(err)
	}
	pipe.activities.Each(func(name string, tactics, attack, atlas []string) {
		var found techniques
		found.add(pipe, activity.Hit{Name: name, Tactics: tactics, Attack: attack, Atlas: atlas})
		for _, id := range slices.Concat(found.attack, found.atlas) {
			if len(found.parents[id]) == 0 {
				t.Errorf("%s: no tactic of %q is one its framework files %s under", name, tactics, id)
			}
		}
	})
}
