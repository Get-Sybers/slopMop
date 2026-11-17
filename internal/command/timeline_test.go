package command

import (
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

// brief writes a period as its files and its tactics, so a test states what
// it expects on one line.
func (p period) brief() string {
	return strings.Join(p.files, "+") + ": " + strings.Join(p.tactics, ",")
}

// A period is the files, one after another, that show no tactic its first
// file does not. A file that shows nothing is in none, and ends none.
func TestPeriods(t *testing.T) {
	recon := stepAt(0, "recon.sh", "Discovery")
	recon.Tools = []string{"nmap", "curl"}
	both := stepAt(5, "creds.sh", "CredentialAccess", "Discovery")
	both.Tools = []string{"cat", "curl"}
	both.Activities = []activity.Hit{{Name: "ShadowFileRead"}, {Name: "PrivateKeyRead"}}
	again := stepAt(7, "more.sh", "Discovery")
	again.Activities = []activity.Hit{{Name: "ShadowFileRead"}, {Name: "ServiceDiscovery"}}
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
	want := []string{"recon.sh: Discovery", "creds.sh+more.sh+c2.txt: Discovery,CredentialAccess", "persist.sh: Persistence"}
	if !slices.Equal(got, want) || quiet != 5 {
		t.Fatalf("periods = %q with %d files in none, want %q with 5", got, quiet, want)
	}
	second := all[1]
	if second.first.File.Path != "creds.sh" || second.last.File.Path != "c2.txt" {
		t.Errorf("the second period runs from %s to %s", second.first.File.Path, second.last.File.Path)
	}
	for name, pair := range map[string][2][]string{
		"activities": {second.activities, {"ShadowFileRead", "PrivateKeyRead", "ServiceDiscovery"}},
		"tools":      {second.tools, {"cat", "curl"}},
		"watchlist":  {second.hits, {"APT-X: 203.0.113.40"}},
		"intents":    {second.intents, {"i12", "i14"}},
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

// The section holds a period to an entry, however many files it has, and
// says how many files are in none.
func TestTimelineSection(t *testing.T) {
	steps := []trace.Step{stepAt(0, "a.sh", "Discovery"), stepAt(1, "quiet.txt"), stepAt(4, "b.sh", "Discovery"), stepAt(9, "c.sh", "Persistence")}
	groups := runOf(t, steps, nil).timeline()
	if len(groups) != 2 || len(groups[0].Entries) != 2 || !slices.Equal(groups[0].Columns, []string{"from", "until", "files", "tactics"}) {
		t.Fatalf("the section has %d groups, want the periods and a line for the other files", len(groups))
	}
	cells := func(e render.Entry) string { return strings.Join(e.Cells, " | ") }
	for i, want := range []string{"2026-10-22T09:00:00Z | 2026-10-22T09:04:00Z | 2 | Discovery", "2026-10-22T09:09:00Z | - | 1 | Persistence"} {
		if got := cells(groups[0].Entries[i]); got != want {
			t.Errorf("period %d is %q, want %q", i+1, got, want)
		}
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
	first, last := groups[0].Entries[0].Detail, groups[2].Entries[fewPeriods/2-1].Detail
	if first[len(first)-1].Text != "step0.sh" || last[len(last)-1].Text != "step"+strconv.Itoa(fewPeriods+6)+".sh" {
		t.Errorf("the ends are %q and %q, want the first and the last file", first[len(first)-1].Text, last[len(last)-1].Text)
	}
}
