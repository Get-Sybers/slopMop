//go:build integration

package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/get-sybers/slopmop/internal/evidencetest"
	"github.com/get-sybers/slopmop/internal/golden"
)

// build builds the command and returns where it stands.
func build(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "slopmop")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// held lists what a folder holds, each file with the digest of its bytes
// and each folder by its name alone, so two listings show what was written.
func held(t *testing.T, folder string) map[string]string {
	t.Helper()
	found := map[string]string{}
	root, err := os.OpenRoot(folder)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	err = fs.WalkDir(root.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || path == "." {
			return err
		}
		if d.IsDir() {
			found[path] = "folder"
			return nil
		}
		data, err := fs.ReadFile(root.FS(), path)
		found[path] = fmt.Sprintf("%x", sha256.Sum256(data))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// TestBinaryWritesOnlyToTheOutputFolder runs the command where every folder
// it could write to is watched: the evidence, the folder it runs in, the
// home folder and the folder for temporary files.
func TestBinaryWritesOnlyToTheOutputFolder(t *testing.T) {
	bin := build(t)
	for _, tt := range []struct {
		name string
		// args follow the input folder, and all that is written is below under, in base.
		args  func(base string) []string
		under string
	}{
		{"a folder named with -outdir", func(base string) []string {
			return []string{"report", "-outdir", filepath.Join(base, "reports", "case 42")}
		}, "reports"},
		{"a folder named from where the command runs", func(string) []string { return []string{"report", "-outdir", filepath.Join("..", "beside")} }, "beside"},
		{"no folder named", func(string) []string { return []string{"report"} }, "work/slopmop-evidence"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			base := t.TempDir()
			for _, name := range []string{"evidence", "work", "home", "temp"} {
				if err := os.Mkdir(filepath.Join(base, name), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			input := filepath.Join(base, "evidence")
			if err := os.CopyFS(input, os.DirFS(evidencetest.Copy(t, "linux"))); err != nil {
				t.Fatal(err)
			}
			before := held(t, base)
			cmd := exec.Command(bin, append([]string{"-inputdir", input}, tt.args(base)...)...)
			cmd.Dir = filepath.Join(base, "work")
			home, temp := filepath.Join(base, "home"), filepath.Join(base, "temp")
			cmd.Env = append(os.Environ(), "HOME="+home, "USERPROFILE="+home, "TMPDIR="+temp, "TMP="+temp, "TEMP="+temp)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			after, saved := held(t, base), 0
			for path, digest := range after {
				inside := path == tt.under || strings.HasPrefix(path, tt.under+"/")
				switch {
				case inside && digest != "folder":
					saved++
				case !inside && before[path] != digest:
					t.Errorf("%s was written, and is not in the output folder %s", path, tt.under)
				}
			}
			for path := range before {
				if _, kept := after[path]; !kept {
					t.Errorf("%s was taken away", path)
				}
			}
			if saved != 10 {
				t.Errorf("the output folder holds %d files, want 10", saved)
			}
		})
	}
}

// TestBinary builds the command once and drives it as a user would.
func TestBinary(t *testing.T) {
	bin := build(t)
	folder := evidencetest.Copy(t, "bash")
	nested := evidencetest.Copy(t, "powershell")
	if err := os.Mkdir(filepath.Join(nested, "stage"), 0o700); err != nil {
		t.Fatal(err)
	}
	const moved = "staged_20250302_093010.b64"
	if err := os.Rename(filepath.Join(nested, moved), filepath.Join(nested, "stage", moved)); err != nil {
		t.Fatal(err)
	}
	// The binary runs in a folder of its own, where its output folder may land.
	work := t.TempDir()
	run := func(args ...string) (string, string, int) {
		cmd := exec.Command(bin, args...)
		cmd.Dir = work
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		var exit *exec.ExitError
		if err != nil && !errors.As(err, &exit) {
			t.Fatalf("%v: %v", args, err)
		}
		return stdout.String(), stderr.String(), cmd.ProcessState.ExitCode()
	}

	steps := []struct {
		name   string
		args   []string
		code   int
		golden string
		stderr string
	}{
		{name: "no arguments print help", code: 0, golden: "help"},
		{name: "help on an option", args: []string{"-inputdir", "--help"}, code: 0, golden: "help-option"},
		{name: "help with an input folder", args: []string{"-inputdir", "case42", "--help"}, code: 0, golden: "help-inputdir"},
		{name: "help with a verb", args: []string{"-inputdir", "case42", "report", "--help"}, code: 0, golden: "help-report"},
		{name: "help with a section", args: []string{"-inputdir", "case42", "report", "impact", "--help"}, code: 0,
			golden: "help-report-impact"},
		{name: "help with a verb and no folder", args: []string{"report", "--help"}, code: 0, golden: "help-report-bare"},
		{name: "no verb", args: []string{"-inputdir", folder}, code: 2, stderr: "error: slopmop needs a verb (verbs: report)"},
		{name: "unknown verb", args: []string{"-inputdir", folder, "list"}, code: 2, stderr: `error: unknown verb "list" (verbs: report)`},
		{name: "no input folder", args: []string{"report"}, code: 2, stderr: "error: report needs -inputdir <folder>"},
		{name: "unknown section", args: []string{"-inputdir", folder, "report", "bogus"}, code: 2,
			stderr: `error: report has no section "bogus"`},
		{name: "not a folder", args: []string{"-inputdir", filepath.Join(folder, "missing"), "report"}, code: 1,
			stderr: "not a folder"},
		{name: "output folder in the evidence", args: []string{"-inputdir", folder, "report", "-outdir", filepath.Join(folder, "out")}, code: 2,
			stderr: "error: -outdir is inside the folder that is read"},
	}
	for _, s := range steps {
		t.Run(s.name, func(t *testing.T) {
			stdout, stderr, code := run(s.args...)
			if code != s.code {
				t.Errorf("exit code %d, want %d\nstdout: %s\nstderr: %s", code, s.code, stdout, stderr)
			}
			if s.golden != "" {
				golden.Check(t, s.golden, []byte(stdout))
			}
			if !strings.Contains(stderr, s.stderr) {
				t.Errorf("stderr %q does not contain %q", stderr, s.stderr)
			}
			if s.code == 0 && stderr != "" {
				t.Errorf("stderr on success: %q", stderr)
			}
			if s.code != 0 && stdout != "" {
				t.Errorf("stdout on failure: %q", stdout)
			}
		})
	}

	// The report verb with nothing else: every section, the sub-folder
	// read, the output saved, and no colour off a terminal.
	stdout, stderr, code := run("-inputdir", nested, "report")
	if code != 0 || stderr != "" {
		t.Fatalf("report: exit code %d, stderr %q", code, stderr)
	}
	saved := "slopmop-" + filepath.Base(nested)
	for _, want := range []string{"\nTimeline", "\nImpact", "\nMitigation", "stage/" + moved, "-> saved to " + saved + ": report.txt"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("report: output lacks %q", want)
		}
	}
	if strings.Contains(stdout, "\x1b[") {
		t.Error("report: colour codes in output that is not a terminal")
	}
	for _, name := range []string{"report.txt", "report.md", "report.html", "files.csv", "trace.json", "intents.csv", "findings.json", "targeted.json", "exposure.csv", "report.json"} {
		if info, err := os.Stat(filepath.Join(work, saved, name)); err != nil || info.Size() == 0 {
			t.Errorf("report: %s was not saved: %v", name, err)
		}
	}
	out := filepath.Join(t.TempDir(), "out")
	stdout, _, code = run("-inputdir", nested, "report", "impact", "remediation", "-outdir", out)
	if code != 0 {
		t.Fatalf("report with sections: exit code %d", code)
	}
	golden.Check(t, "report-impact", []byte(strings.ReplaceAll(strings.ReplaceAll(stdout, out, "<out>"), nested, "<folder>")))
	golden.Check(t, "files-csv", []byte(evidencetest.Portable(t, readFile(t, filepath.Join(out, "files.csv")), nested)))
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
