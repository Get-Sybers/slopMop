package command

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/get-sybers/slopmop/internal/cli"
	"github.com/get-sybers/slopmop/internal/evidencetest"
)

// told runs the report with what the run says of itself written to said,
// and returns the readout with its paths replaced.
func told(t *testing.T, folder string, terminal bool, extra ...string) (readout, said string, err error) {
	t.Helper()
	var out, progress bytes.Buffer
	saved := filepath.Join(t.TempDir(), "out")
	app, err := NewApp("slopmop", Env{Stdout: &out, WorkDir: t.TempDir(), Progress: &progress, Terminal: terminal})
	if err != nil {
		t.Fatal(err)
	}
	err = app.Run(append([]string{"-inputdir", folder, "report", "summary", "-outdir", saved}, extra...))
	return strings.ReplaceAll(out.String(), saved, "<out>"), progress.String(), err
}

// A run says what it is doing only where that is wanted, and what it prints
// as its report is the same whether it says so or not.
func TestReportProgress(t *testing.T) {
	folder := evidencetest.Copy(t, "linux")
	quiet, said, err := told(t, folder, false)
	if err != nil || said != "" {
		t.Fatalf("off a terminal, with no option: error %v, said %q; want nothing said", err, said)
	}
	stages := []string{
		"[1/5] reading the folder  0s", "[2/5] analysing the files  0 of 14  0s", "[3/5] gathering what the files hold  0s",
		"[4/5] assembling the report  0s", "[5/5] saving the report  0 of 11  0s",
	}
	tests := []struct {
		name     string
		terminal bool
		extra    []string
		want     func(said string) bool
	}{
		{"shown off a terminal: a line for each stage", false, []string{"-progress", "shown"}, func(said string) bool {
			return said == strings.Join(stages, "\n")+"\n"
		}},
		{"hidden off a terminal", false, []string{"-progress", "hidden"}, func(said string) bool { return said == "" }},
		{"hidden on a terminal", true, []string{"-progress", "hidden"}, func(said string) bool { return said == "" }},
		{"on a terminal: one line, written over and taken off", true, nil, func(said string) bool {
			at := 0
			for _, stage := range stages {
				i := strings.Index(said[at:], "\r"+strings.TrimSuffix(stage, "  0s"))
				if i < 0 {
					return false
				}
				at += i + 1
			}
			return !strings.Contains(said, "\n") && strings.HasSuffix(said, " \r")
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			readout, said, err := told(t, folder, tt.terminal, tt.extra...)
			if err != nil {
				t.Fatal(err)
			}
			if !tt.want(said) {
				t.Errorf("the run said %q", said)
			}
			if readout != quiet {
				t.Errorf("the readout differs from that of a run that says nothing:\n%s", readout)
			}
		})
	}
	if _, said, err := told(t, folder, true, "-progress", "loud"); !errors.Is(err, cli.ErrUsage) || said != "" ||
		!strings.Contains(err.Error(), `-progress takes shown or hidden, not "loud"`) {
		t.Errorf("-progress loud: error %v, said %q; want a usage error and nothing said", err, said)
	}
}

// A run that fails takes its line off the terminal before the error is written.
func TestReportProgressOnFailure(t *testing.T) {
	_, said, err := told(t, filepath.Join(t.TempDir(), "missing"), true)
	if err == nil {
		t.Fatal("a folder that is missing gives no error")
	}
	if !strings.HasPrefix(said, "\r[1/5] reading the folder") || !strings.HasSuffix(said, " \r") {
		t.Errorf("the run said %q, want the first stage and then an empty line", said)
	}
}
