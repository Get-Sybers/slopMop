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
	config := t.TempDir()
	run := func(args ...string) (string, string, int) {
		cmd := exec.Command(bin, args...)
		// A private configuration directory keeps the developer's selection out of the test.
		cmd.Env = append(os.Environ(), "XDG_CONFIG_HOME="+config, "HOME="+config, "AppData="+config)
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
		stdout string
		stderr string
	}{
		{name: "no arguments print help", code: 0, golden: "help"},
		{name: "verb help", args: []string{"file", "list", "-h"}, code: 0, golden: "help-file-list"},
		{name: "unknown noun", args: []string{"bogus", "list"}, code: 2, stderr: `error: unknown noun "bogus"`},
		{name: "wrong prefix", args: []string{"file", "list", "-evidence", folder}, code: 2,
			stderr: "error: -evidence takes a value; use --evidence <folder>"},
		{name: "no folder", args: []string{"file", "list"}, code: 1, stderr: "error: no evidence folder"},
		{name: "not a folder", args: []string{"file", "list", "--evidence", filepath.Join(folder, "missing")}, code: 1,
			stderr: "not a folder"},
		{name: "select", args: []string{"evidence", "select", folder}, code: 0, stdout: "selected evidence folder " + folder},
		{name: "selection persists", args: []string{"evidence", "select"}, code: 0, stdout: "selected: " + folder},
		{name: "list", args: []string{"file", "list"}, code: 0, golden: "file-list"},
		{name: "list json", args: []string{"file", "ls", "-o", "json", "-script"}, code: 0, golden: "file-list-json"},
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
			if !strings.Contains(stdout, s.stdout) {
				t.Errorf("stdout %q does not contain %q", stdout, s.stdout)
			}
			if !strings.Contains(stderr, s.stderr) {
				t.Errorf("stderr %q does not contain %q", stderr, s.stderr)
			}
			if s.code == 0 && stderr != "" {
				t.Errorf("stderr on success: %q", stderr)
			}
		})
	}
}
