package command

import (
	"errors"
	"os"
	"path/filepath"
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
				out, err := run(t, append([]string{folder}, v.args...)...)
				if err != nil {
					t.Fatal(err)
				}
				golden.Check(t, fixture+"-"+v.name, []byte(strings.ReplaceAll(out, folder, "<folder>")))
			})
		}
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
