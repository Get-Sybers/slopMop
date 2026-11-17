package command

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// lacking skips a test for want of something the machine lacks. The CI runner
// has it, so there the lack is a failure: a skip would pass for a test that ran.
func lacking(t *testing.T, what string) {
	t.Helper()
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		t.Fatalf("%s, on a runner that has one", what)
	}
	t.Skip(what)
}

// otherVolume makes a folder on a volume other than that of path, or skips
// the test when the machine has no second volume to write to.
func otherVolume(t *testing.T, path string) string {
	t.Helper()
	for letter := 'A'; letter <= 'Z'; letter++ {
		root := string(letter) + `:\`
		if strings.EqualFold(filepath.VolumeName(root), filepath.VolumeName(path)) {
			continue
		}
		dir, err := os.MkdirTemp(root, "slopmop-test-")
		if err != nil {
			continue
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		return dir
	}
	lacking(t, "no second volume to write to")
	return ""
}

// Two volumes are two places: the output of evidence on one drive goes to another.
func TestOutputDirOnAnotherVolume(t *testing.T) {
	input := filepath.Join(t.TempDir(), "case42")
	if err := os.MkdirAll(input, 0o700); err != nil {
		t.Fatal(err)
	}
	other := otherVolume(t, input)
	if within(input, other) || within(other, input) {
		t.Fatalf("%s and %s are on two volumes and one is said to be inside the other", input, other)
	}
	given := filepath.Join(other, "out")
	if got, err := outputDir(input, given, other, "slopmop-"); err != nil || got != given {
		t.Errorf("outputDir with -outdir on another volume = %q, %v; want %q", got, err, given)
	}
	if got, err := outputDir(input, "", other, "slopmop-"); err != nil || got != filepath.Join(other, "slopmop-case42") {
		t.Errorf("outputDir from a work folder on another volume = %q, %v", got, err)
	}
	if got, err := outputDir(other, "", input, "slopmop-"); err != nil || got != filepath.Join(input, "slopmop-"+filepath.Base(other)) {
		t.Errorf("outputDir for evidence on another volume = %q, %v", got, err)
	}
}

// A drive that is another name for the input folder is still the input
// folder, and a drive that is read whole lends its letter to the output folder.
func TestOutputDirThroughADriveLetter(t *testing.T) {
	input := filepath.Join(t.TempDir(), "case42")
	if err := os.MkdirAll(input, 0o700); err != nil {
		t.Fatal(err)
	}
	drive := ""
	for letter := 'Z'; letter >= 'H' && drive == ""; letter-- {
		name := string(letter) + ":"
		if _, err := os.Stat(name + `\`); err == nil {
			continue
		}
		if exec.Command("subst", name, input).Run() == nil {
			drive = name
		}
	}
	if drive == "" {
		lacking(t, "no drive letter could be given to the folder")
	}
	t.Cleanup(func() { _ = exec.Command("subst", drive, "/D").Run() })
	if !within(input, drive+`\out`) {
		t.Errorf("%s\\out is in %s under another name and is said to be outside it", drive, input)
	}
	if _, err := outputDir(input, drive+`\out`, t.TempDir(), "slopmop-"); err == nil {
		t.Errorf("-outdir %s\\out was taken, and it is inside the folder that is read", drive)
	}
	work := t.TempDir()
	want := filepath.Join(work, "slopmop-"+strings.TrimSuffix(drive, ":"))
	if got, err := outputDir(drive+`\`, "", work, "slopmop-"); err != nil || got != want {
		t.Errorf("outputDir for a whole drive = %q, %v; want %q", got, err, want)
	}
	if got := folderName(drive + `\`); got != strings.TrimSuffix(drive, ":") {
		t.Errorf("folderName(%s\\) = %q", drive, got)
	}
}
