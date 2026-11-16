package command

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/get-sybers/slopmop/internal/cli"
	"github.com/get-sybers/slopmop/internal/evidencetest"
	"github.com/get-sybers/slopmop/internal/golden"
)

const watchlist = "testdata/watchlist.json"

func TestAggregateViews(t *testing.T) {
	views := []struct {
		name string
		args []string
	}{
		{"finding", []string{"finding", "list"}},
		{"finding-wide", []string{"finding", "list", "-o", "wide"}},
		{"finding-json", []string{"finding", "list", "-o", "json"}},
		{"finding-intel", []string{"finding", "list", "--intelfile", watchlist}},
		{"finding-tactic", []string{"finding", "list", "-tactic"}},
		{"finding-indicator-quiet", []string{"finding", "list", "-indicator", "-q"}},
		{"report", []string{"report", "list"}},
		{"report-intel", []string{"report", "list", "--intelfile", watchlist}},
		{"report-json", []string{"report", "list", "-o", "json"}},
		{"report-files", []string{"report", "list", "-files", "-o", "wide", "--severity", "medium"}},
		{"report-impact", []string{"report", "list", "-impact", "-o", "wide"}},
		{"report-actions", []string{"report", "list", "-remediation", "-mitigation", "-o", "wide"}},
	}
	for _, fixture := range evidencetest.List() {
		folder := evidencetest.Copy(t, fixture)
		for _, v := range views {
			t.Run(fixture+"/"+v.name, func(t *testing.T) {
				out, err := run(t, append(v.args, "--inputdir", folder)...)
				if err != nil {
					t.Fatal(err)
				}
				golden.Check(t, fixture+"-"+v.name, []byte(out))
			})
		}
	}
}

// The command without a noun writes every section of every fixture; the
// folder is a temporary path, so the golden file names it <folder>.
func TestWholeViews(t *testing.T) {
	views := []struct {
		name string
		args []string
	}{
		{"whole", nil},
		{"whole-intel", []string{"--intelfile", watchlist}},
		{"whole-impact", []string{"impact", "remediation"}},
	}
	for _, fixture := range evidencetest.List() {
		folder := evidencetest.Copy(t, fixture)
		for _, v := range views {
			t.Run(fixture+"/"+v.name, func(t *testing.T) {
				saved := filepath.Join(t.TempDir(), "out")
				out, err := run(t, append([]string{folder, "--outdir", saved}, v.args...)...)
				if err != nil {
					t.Fatal(err)
				}
				out = strings.ReplaceAll(strings.ReplaceAll(out, saved, "<out>"), folder, "<folder>")
				golden.Check(t, fixture+"-"+v.name, []byte(out))
			})
		}
	}
}

// What is saved is what the nouns print: the readout with every section,
// whichever were asked for, and each class as its own JSON, every column.
func TestWholeSaves(t *testing.T) {
	folder := evidencetest.Copy(t, "linux")
	nest(t, folder, "step05", "later")
	saved := filepath.Join(t.TempDir(), "deep", "out")
	shown, err := run(t, folder, "impact", "--outdir", saved)
	if err != nil {
		t.Fatal(err)
	}
	if want := "-> saved to " + saved + ": readout.txt, files.json, trace.json, findings.json, report.json\n"; !strings.Contains(shown, want) {
		t.Errorf("the readout does not say where it was saved:\n%s", shown)
	}
	full, err := run(t, folder, "--outdir", filepath.Join(t.TempDir(), "other"))
	if err != nil {
		t.Fatal(err)
	}
	readout := readFile(t, filepath.Join(saved, "readout.txt"))
	if lines := strings.Split(full, "\n"); readout != strings.Join(slices.DeleteFunc(lines, func(l string) bool {
		return strings.HasPrefix(l, "-> saved to ")
	}), "\n") {
		t.Errorf("readout.txt is not the full readout:\n%s", readout)
	}
	for file, noun := range map[string]string{"files.json": "file", "trace.json": "trace", "findings.json": "finding", "report.json": "report"} {
		want, listErr := run(t, noun, "list", "--inputdir", folder, "-r", "-o", "json")
		if listErr != nil {
			t.Fatal(listErr)
		}
		if got := readFile(t, filepath.Join(saved, file)); got != want {
			t.Errorf("%s differs from %s list -r -o json:\n%s", file, noun, got)
		}
	}
	entries, err := os.ReadDir(saved)
	if err != nil || len(entries) != 5 {
		t.Errorf("the output folder holds %d entries (%v), want 5", len(entries), err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// The output folder is never in the evidence: not by default, not on request.
func TestOutputDir(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "case42")
	if err := os.MkdirAll(filepath.Join(input, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	elsewhere := t.TempDir()
	link := filepath.Join(elsewhere, "link")
	linked := os.Symlink(input, link) == nil
	tests := []struct {
		name    string
		given   string
		workDir string
		want    string
		fails   string
	}{
		{"the work folder", "", elsewhere, filepath.Join(elsewhere, "slopmop-case42"), ""},
		{"beside the input when the work folder is the input", "", input, filepath.Join(root, "slopmop-case42"), ""},
		{"beside the input when the work folder is inside it", "", filepath.Join(input, "sub"), filepath.Join(root, "slopmop-case42"), ""},
		{"a folder that is given", filepath.Join(elsewhere, "new", "out"), elsewhere, filepath.Join(elsewhere, "new", "out"), ""},
		{"given inside the input", filepath.Join(input, "out"), elsewhere, "", "is inside the folder that is read"},
		{"given as the input", input, elsewhere, "", "is inside the folder that is read"},
	}
	if linked {
		tests = append(tests, struct {
			name    string
			given   string
			workDir string
			want    string
			fails   string
		}{"given through a link into the input", filepath.Join(link, "out"), elsewhere, "", "is inside the folder that is read"})
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

// A run from inside the evidence writes beside it and leaves it as it was.
func TestWholeLeavesTheEvidenceAlone(t *testing.T) {
	folder := evidencetest.Copy(t, "bash")
	before, err := os.ReadDir(folder)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	app := cli.New("slopmop", &out)
	if err = Register(app, Env{Stdout: &out, WorkDir: folder}); err != nil {
		t.Fatal(err)
	}
	if err = app.Run([]string{folder, "summary"}); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadDir(folder)
	if err != nil || len(after) != len(before) {
		t.Errorf("the evidence folder holds %d entries after the run and %d before (%v)", len(after), len(before), err)
	}
	beside := filepath.Join(filepath.Dir(folder), "slopmop-"+filepath.Base(folder))
	if _, err := os.Stat(filepath.Join(beside, "readout.txt")); err != nil {
		t.Errorf("no readout beside the evidence: %v", err)
	}
	if _, err := run(t, folder, "--outdir", filepath.Join(folder, "out")); err == nil || !errors.Is(err, cli.ErrUsage) {
		t.Errorf("an output folder inside the evidence: error = %v", err)
	}
}

func TestCheckSavedRejects(t *testing.T) {
	nouns, err := loadNouns()
	if err != nil {
		t.Fatal(err)
	}
	table := savedFile{Noun: "trace", File: "trace.json"}
	tests := []struct {
		name  string
		saved savedSpec
		want  string
	}{
		{"no prefix", savedSpec{Readout: "r.txt", Tables: []savedFile{table}}, "needs a prefix"},
		{"no tables", savedSpec{Prefix: "p-", Readout: "r.txt"}, "needs a prefix"},
		{"an unknown noun", savedSpec{Prefix: "p-", Readout: "r.txt", Tables: []savedFile{{Noun: "bogus", File: "b.json"}}}, "which has no table"},
		{"a path for a name", savedSpec{Prefix: "p-", Readout: "r.txt", Tables: []savedFile{{Noun: "trace", File: "../t.json"}}}, "not a file name of its own"},
		{"a name twice", savedSpec{Prefix: "p-", Readout: "trace.json", Tables: []savedFile{table}}, "not a file name of its own"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := checkSaved(tt.saved, nouns); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("checkSaved error = %v, want one containing %q", err, tt.want)
			}
		})
	}
	if _, err := checkSaved(savedSpec{Prefix: "p-", Readout: "r.txt", Tables: []savedFile{table}}, nil); err == nil ||
		!strings.Contains(err.Error(), "declares no columns") {
		t.Errorf("a table whose noun is not declared: error = %v", err)
	}
}

// One read serves every section, and the sub-folders are read without a switch.
func TestWholeReadsSubFolders(t *testing.T) {
	folder := evidencetest.Copy(t, "linux")
	nest(t, folder, "step05", "later")
	out, err := run(t, folder, "timeline")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "later/20261022_092000_step05_evade.sh") {
		t.Errorf("the timeline lacks the file in the sub-folder:\n%s", out)
	}
	for _, absent := range []string{"Summary", "Findings", "Impact"} {
		if strings.Contains(out, "\n"+absent+"\n") {
			t.Errorf("the section %s was written though only the timeline was asked for", absent)
		}
	}
}

func TestWholeFails(t *testing.T) {
	folder := evidencetest.Copy(t, "linux")
	tests := []struct {
		name  string
		args  []string
		usage bool
		want  string
	}{
		{"not a folder", []string{filepath.Join(folder, "missing")}, false, "not a folder"},
		{"two folders", []string{folder, "other"}, true, "reads one folder"},
		{"a section alone", []string{"impact"}, true, "names a section"},
		{"an output flag", []string{folder, "-o", "json"}, true, "applies only to verbs that print rows"},
		{"a missing watchlist", []string{folder, "--intelfile", filepath.Join(folder, "missing.json")}, false, "--intelfile"},
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
}

func TestWholeOfNothing(t *testing.T) {
	out, err := run(t, t.TempDir(), "summary", "impact")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[ok] NOTHING FOUND in 0 files", "Impact\n  none\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("readout lacks %q:\n%s", want, out)
		}
	}
}

func TestCheckWholeRejects(t *testing.T) {
	section := sectionSpec{Name: "summary", Title: "Summary", Summary: "the counts"}
	builders := map[string]sectionBuilder{"summary": wholeRun.summary}
	tests := []struct {
		name  string
		whole wholeSpec
		want  string
	}{
		{"no summary", wholeSpec{Positional: "<folder>", Sections: []sectionSpec{section}}, "needs a summary"},
		{"no sections", wholeSpec{Summary: "s", Positional: "<folder>"}, "needs a summary"},
		{"a section without a title", wholeSpec{Summary: "s", Positional: "<folder>", Sections: []sectionSpec{{Name: "summary"}}}, "needs a name, a title and a summary"},
		{"a section twice", wholeSpec{Summary: "s", Positional: "<folder>", Sections: []sectionSpec{section, section}}, "declared twice"},
		{"an unknown section", wholeSpec{Summary: "s", Positional: "<folder>", Sections: []sectionSpec{{Name: "x", Title: "X", Summary: "x"}}}, "which has no implementation"},
		{"a section left out", wholeSpec{Summary: "s", Positional: "<folder>", Sections: []sectionSpec{section}}, "does not declare the section"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := builders
			if tt.name == "a section left out" {
				b = map[string]sectionBuilder{"summary": wholeRun.summary, "timeline": wholeRun.timeline}
			}
			if err := checkWhole(tt.whole, b); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("checkWhole error = %v, want one containing %q", err, tt.want)
			}
		})
	}
}

func TestCampaignListViews(t *testing.T) {
	views := []struct {
		name string
		args []string
	}{
		{"campaign", nil},
		{"campaign-json", []string{"-o", "json"}},
		{"campaign-quiet", []string{"-q"}},
	}
	for _, v := range views {
		t.Run(v.name, func(t *testing.T) {
			out, err := run(t, append([]string{"campaign", "list", "--intelfile", watchlist}, v.args...)...)
			if err != nil {
				t.Fatal(err)
			}
			golden.Check(t, v.name, []byte(out))
		})
	}
}

func TestAggregateAliases(t *testing.T) {
	folder := evidencetest.Copy(t, "bash")
	cases := []struct {
		name  string
		long  []string
		short []string
	}{
		{"finding", []string{"finding", "list", "--inputdir", folder}, []string{"findings", "ls", "--inputdir=" + folder}},
		{"report", []string{"report", "list", "--inputdir", folder}, []string{"reports", "ls", "--inputdir=" + folder}},
		{"campaign", []string{"campaign", "list", "--intelfile", watchlist}, []string{"campaigns", "ls", "--intelfile=" + watchlist}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			want, err := run(t, c.long...)
			if err != nil {
				t.Fatal(err)
			}
			got, err := run(t, c.short...)
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Errorf("%v differs from %v", c.short, c.long)
			}
		})
	}
}

func TestAggregateUsageErrors(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"finding without inputdir", []string{"finding", "list"}, "finding list needs --inputdir <folder>"},
		{"report without inputdir", []string{"report", "list"}, "report list needs --inputdir <folder>"},
		{"campaign without intelfile", []string{"campaign", "list"}, "campaign list needs --intelfile <file>"},
		{"campaign with inputdir", []string{"campaign", "list", "--intelfile", watchlist, "--inputdir", "x"},
			"unknown option --inputdir (valid params: --intelfile <file>)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := run(t, c.args...)
			if !errors.Is(err, cli.ErrUsage) || err.Error() != c.want {
				t.Errorf("error = %v, want the usage error %q", err, c.want)
			}
			if out != "" {
				t.Errorf("output = %q, want none", out)
			}
		})
	}
}

func TestIntelFileErrors(t *testing.T) {
	folder := evidencetest.Copy(t, "bash")
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte(`{`), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"finding, missing file", []string{"finding", "list", "--inputdir", folder, "--intelfile", bad + ".missing"}, "--intelfile:"},
		{"report, bad file", []string{"report", "list", "--inputdir", folder, "--intelfile", bad}, "intel watchlist:"},
		{"campaign, missing file", []string{"campaign", "list", "--intelfile", bad + ".missing"}, "--intelfile:"},
		{"campaign, bad file", []string{"campaign", "list", "--intelfile", bad}, "intel watchlist:"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := run(t, c.args...)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %v, want one containing %q", err, c.want)
			}
			if out != "" {
				t.Errorf("output = %q, want none", out)
			}
		})
	}
}

// A watchlist is operator-supplied text; a control character in an
// attribution never reaches the terminal raw.
func TestCampaignListEscapes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wl.json")
	doc := `[{"value": "a", "attribution": "evil\u001b[31m"}]`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := run(t, "campaign", "list", "--intelfile", path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(out, 0x1b) {
		t.Errorf("output carries a raw escape: %q", out)
	}
}
