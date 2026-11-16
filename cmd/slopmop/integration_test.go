//go:build integration

package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/get-sybers/slopmop/internal/evidencetest"
	"github.com/get-sybers/slopmop/internal/golden"
)

// TestBinary builds the command once and drives it as a user would.
func TestBinary(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "slopmop")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	folder := evidencetest.Copy(t, "bash")
	nested := evidencetest.Copy(t, "powershell")
	if err := os.Mkdir(filepath.Join(nested, "stage"), 0o700); err != nil {
		t.Fatal(err)
	}
	const moved = "staged_20250302_093010.b64"
	if err := os.Rename(filepath.Join(nested, moved), filepath.Join(nested, "stage", moved)); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (string, string, int) {
		cmd := exec.Command(bin, args...)
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
		{name: "verb help", args: []string{"file", "list", "-h"}, code: 0, golden: "help-file-list"},
		{name: "unknown noun", args: []string{"bogus", "list"}, code: 2, stderr: `error: unknown noun "bogus"`},
		{name: "no input directory", args: []string{"file", "list"}, code: 2,
			stderr: "error: file list needs --inputdir <folder>"},
		{name: "wrong prefix", args: []string{"file", "list", "-inputdir", folder}, code: 2,
			stderr: "error: -inputdir takes a value; use --inputdir <folder>"},
		{name: "not a folder", args: []string{"file", "list", "--inputdir", filepath.Join(folder, "missing")}, code: 1,
			stderr: "not a folder"},
		{name: "list", args: []string{"file", "list", "--inputdir", folder}, code: 0, golden: "file-list"},
		{name: "recursive", args: []string{"file", "list", "--inputdir", nested, "-r", "-q"}, code: 0,
			golden: "file-list-recursive"},
		{name: "recursive wrong prefix", args: []string{"trace", "list", "--inputdir", folder, "-recursive"}, code: 2,
			stderr: "error: -recursive is a switch; use --recursive"},
		{name: "list json", args: []string{"file", "ls", "--inputdir", folder, "-o", "json", "-script"}, code: 0,
			golden: "file-list-json"},
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
}
