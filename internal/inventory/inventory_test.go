package inventory

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/get-sybers/slopmop/internal/evidence"
	"github.com/get-sybers/slopmop/internal/evidencetest"
	"github.com/get-sybers/slopmop/internal/golden"
)

func TestReadFixtures(t *testing.T) {
	for _, name := range evidencetest.List() {
		t.Run(name, func(t *testing.T) {
			files, err := Read(evidencetest.Copy(t, name))
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			for _, f := range files {
				stamp := "-"
				if f.Stamped {
					stamp = f.Stamp.Text
				}
				fmt.Fprintf(&out, "%s\t%s\t%d\t%d\t%s\t%s\t%s\t%q\n", f.Path, f.Role, f.Size, f.Lines,
					f.Modified.Format(time.RFC3339), stamp, f.SHA256, f.Note)
			}
			golden.Check(t, name, out.Bytes())
		})
	}
}

func TestReadClassifies(t *testing.T) {
	utf16le := []byte{0xFF, 0xFE, 'a', 0, '\r', 0, '\n', 0, 'b', 0}
	utf16be := []byte{0xFE, 0xFF, 0, 'a', 0, '\n', 0, 'b', 0, '\n'}
	utf32le := []byte{0xFF, 0xFE, 0, 0, 'a', 0, 0, 0, '\n', 0, 0, 0}
	cases := []struct {
		name  string
		file  string
		data  []byte
		role  evidence.Role
		lines int
		note  evidence.Note
	}{
		{"script by extension", "a.sh", []byte("echo hi\n"), evidence.Script, 1, ""},
		{"extension case is ignored", "A.PS1", []byte("Get-Date\r\n"), evidence.Script, 1, ""},
		{"output by extension", "a.log", []byte("one\ntwo"), evidence.Output, 2, ""},
		{"staging extension", "a.bin", []byte("text"), evidence.Output, 1, ""},
		{"unknown extension", "a.xyz", []byte("text"), evidence.Other, 1, ""},
		{"empty file", "empty.txt", nil, evidence.Output, 0, ""},
		{"crlf folds", "crlf.txt", []byte("a\r\nb\r\n"), evidence.Output, 2, ""},
		{"lone cr is kept", "cr.txt", []byte("a\rb"), evidence.Output, 1, ""},
		{"utf-8 with a mark", "bom.txt", []byte("\xEF\xBB\xBFa\n"), evidence.Output, 1, ""},
		{"only a utf-8 mark", "onlybom.txt", []byte("\xEF\xBB\xBF"), evidence.Output, 0, ""},
		{"utf-16 little endian", "le.txt", utf16le, evidence.Output, 2, ""},
		{"utf-16 big endian", "be.txt", utf16be, evidence.Output, 2, ""},
		{"utf-16 with an odd byte", "odd.txt", append(bytes.Clone(utf16be), 0x41), evidence.Output, 3, ""},
		{"utf-32 little endian", "u32.txt", utf32le, evidence.Output, 1, ""},
		{"utf-32 big endian is binary", "u32be.txt", []byte{0, 0, 0xFE, 0xFF, 0, 0, 0, 'a'}, evidence.Output, 0, evidence.Binary},
		{"utf-16 without a mark is binary", "raw16.txt", []byte{'a', 0, 'b', 0}, evidence.Output, 0, evidence.Binary},
		{"nul byte", "nul.out", []byte("a\x00b"), evidence.Output, 0, evidence.Binary},
		{"nul after the sniffed bytes", "late.txt", append(bytes.Repeat([]byte("a"), sniff), 0), evidence.Output, 1, ""},
		{"invalid utf-8 is text", "bad.txt", []byte("a\xff\n"), evidence.Output, 1, ""},
		{"bash shebang", "run", []byte("#!/bin/bash\nid\n"), evidence.Script, 2, ""},
		{"sh shebang", "run", []byte("#! /bin/sh\n"), evidence.Script, 1, ""},
		{"pwsh shebang", "run", []byte("#!/usr/bin/env pwsh\n"), evidence.Script, 1, ""},
		{"env bash is not a shebang rule", "run", []byte("#!/usr/bin/env bash\n"), evidence.Other, 1, ""},
		{"python shebang", "run", []byte("#!/usr/bin/python3\n"), evidence.Other, 1, ""},
		{"shebang does not move an output", "run.txt", []byte("#!/bin/bash\n"), evidence.Output, 1, ""},
		{"shebang after the first byte", "run", []byte("\n#!/bin/bash\n"), evidence.Other, 2, ""},
		{"hidden file", ".bashrc", []byte("x\n"), evidence.Other, 1, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			folder := t.TempDir()
			if err := os.WriteFile(filepath.Join(folder, c.file), c.data, 0o600); err != nil {
				t.Fatal(err)
			}
			files, err := Read(folder)
			if err != nil {
				t.Fatal(err)
			}
			if len(files) != 1 {
				t.Fatalf("%d files, want 1", len(files))
			}
			f := files[0]
			if f.Path != c.file || f.Name != c.file {
				t.Errorf("path %q name %q, want %q", f.Path, f.Name, c.file)
			}
			if f.Role != c.role || f.Lines != c.lines || f.Note != c.note {
				t.Errorf("role %q lines %d note %q, want %q %d %q", f.Role, f.Lines, f.Note, c.role, c.lines, c.note)
			}
			if f.Size != int64(len(c.data)) {
				t.Errorf("size %d, want %d", f.Size, len(c.data))
			}
			if len(f.SHA256) != 64 {
				t.Errorf("sha256 %q is not 64 hex characters", f.SHA256)
			}
		})
	}
}

func TestReadOversize(t *testing.T) {
	folder := t.TempDir()
	for name, data := range map[string]string{"at.txt": "12345678", "over.sh": "123456789"} {
		if err := os.WriteFile(filepath.Join(folder, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	res, err := readAll(folder, 8, false)
	if err != nil {
		t.Fatal(err)
	}
	files := res.Files
	at, over := files[0], files[1]
	if at.Note != "" || at.Lines != 1 {
		t.Errorf("at the limit: note %q lines %d, want text with 1 line", at.Note, at.Lines)
	}
	if over.Note != evidence.Oversize || over.Lines != 0 || over.Role != evidence.Script {
		t.Errorf("over the limit: note %q lines %d role %q", over.Note, over.Lines, over.Role)
	}
	const want = "15e2b0d3c33891ebb0f1ef609ec419420c20e320ce94c65fbc8c3312448eb225"
	if over.SHA256 != want || over.Size != 9 {
		t.Errorf("over the limit: sha256 %s size %d, want %s 9", over.SHA256, over.Size, want)
	}
}

func TestReadSkipsWhatIsNotARegularFile(t *testing.T) {
	folder := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.txt")
	for _, p := range []string{filepath.Join(folder, "kept.txt"), outside} {
		if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(folder, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(folder, "sub", "deep.txt"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{"escape.txt": outside, "inside.txt": "kept.txt"} {
		if err := os.Symlink(target, filepath.Join(folder, link)); err != nil {
			t.Skipf("symbolic links are not available: %v", err)
		}
	}
	files, err := Read(folder)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Path != "kept.txt" {
		t.Errorf("files = %+v, want only kept.txt", files)
	}
}

func TestReadUnreadable(t *testing.T) {
	folder := t.TempDir()
	locked := filepath.Join(folder, "locked.txt")
	if err := os.WriteFile(locked, []byte("x\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	if h, err := os.Open(locked); err == nil {
		h.Close()
		t.Skip("this user can read a file with no permissions")
	}
	files, err := Read(folder)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Note != evidence.Unreadable || files[0].SHA256 != "" {
		t.Errorf("files = %+v, want one unreadable row without a hash", files)
	}
}

func TestReadEmptyFolder(t *testing.T) {
	files, err := Read(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Errorf("%d files, want 0", len(files))
	}
}

func TestReadNotFolder(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"missing": filepath.Join(t.TempDir(), "missing"), "a file": file} {
		t.Run(name, func(t *testing.T) {
			if _, err := Read(path); !errors.Is(err, ErrNotFolder) {
				t.Errorf("Read(%s) error = %v, want ErrNotFolder", name, err)
			}
		})
	}
}
