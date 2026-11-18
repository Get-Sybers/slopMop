// Package inventory reads the input directory into file records.
package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"time"

	"github.com/get-sybers/slopmop/internal/evidence"
	"github.com/get-sybers/slopmop/internal/nametime"
	"github.com/get-sybers/slopmop/internal/parallel"
)

var ErrNotFolder = errors.New("not a folder")

const maxTextBytes = 64 << 20

// MaxDepth is how many levels of sub-folder a recursive read walks.
const MaxDepth = 16

// Result holds what a read found.
type Result struct {
	Files []evidence.File
	Texts map[string]string // path → decoded text; absent for binary/oversize/unreadable
	// Skipped holds the sub-folders a recursive read did not walk: below the depth or unreadable.
	Skipped []string
	// Outside is how many files were not read: their time is not in the scope.
	Outside int
}

// Scope says how much of a folder is read.
type Scope struct {
	// Depth is how many levels of sub-folder are walked.
	Depth int
	// From and Until bound the time of the files that are read, as
	// evidence.File.Within counts it; a zero time leaves that side open.
	From, Until time.Time
	// Watch, when set, is told of each file as it is read.
	Watch Watch
}

// Read lists the regular files in folder, sorted by path, walking depth levels
// of sub-folder. It opens everything read-only through a root, so nothing
// outside the folder is reachable.
func Read(folder string, depth int) (Result, error) {
	return readAll(folder, maxTextBytes, Scope{Depth: depth}, false)
}

// ReadAll is Read plus the decoded text of every readable file.
func ReadAll(folder string, depth int) (Result, error) {
	return Scope{Depth: depth}.ReadAll(folder)
}

// Watch is told the path of a file as its reading begins, and returns what
// is called when the reading is done.
type Watch func(path string) (done func())

// ReadAll reads the files of folder that are in the scope, with the decoded
// text of every readable one. A file outside the scope is not opened.
func (s Scope) ReadAll(folder string) (Result, error) {
	return readAll(folder, maxTextBytes, s, true)
}

func readAll(folder string, limit int64, scope Scope, keepText bool) (Result, error) {
	roles, err := LoadRoles()
	if err != nil {
		return Result{}, err
	}
	root, err := os.OpenRoot(folder)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrNotFolder, err)
	}
	defer root.Close()
	r := reader{root: root, limit: limit, depth: scope.Depth, roles: newClassifier(roles)}
	if err := r.walk(".", 0); err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrNotFolder, err)
	}
	outside := r.keep(scope)
	// Each file is read on its own goroutine, into its own slot; the order of
	// the result is that of the path, not of when a read finished.
	reads := make([]read, len(r.found))
	parallel.Each(len(r.found), func(i int) {
		if scope.Watch != nil {
			defer scope.Watch(r.found[i].path)()
		}
		reads[i].file, reads[i].text = r.fileWithText(r.found[i].path, r.found[i].name)
	})
	res := Result{Files: make([]evidence.File, len(reads)), Skipped: r.skipped, Outside: outside}
	if keepText {
		res.Texts = make(map[string]string, len(reads))
	}
	for i := range reads {
		res.Files[i] = reads[i].file
		if res.Texts != nil && reads[i].text != "" {
			res.Texts[reads[i].file.Path] = reads[i].text
		}
	}
	sort.Slice(res.Files, func(i, j int) bool { return res.Files[i].Path < res.Files[j].Path })
	sort.Strings(res.Skipped)
	return res, nil
}

type reader struct {
	root    *os.Root
	limit   int64
	depth   int
	roles   classifier
	found   []found
	skipped []string
}

// found is a regular file the walk listed, read in the second pass.
type found struct {
	path, name string
	entry      os.DirEntry
}

// keep drops the files whose time is not in the scope, before any is
// opened, and returns how many it dropped. The time is the one the file is
// placed at once read: that of its name, or else when it was last modified.
func (r *reader) keep(scope Scope) (outside int) {
	if scope.From.IsZero() && scope.Until.IsZero() {
		return 0
	}
	kept := r.found[:0]
	for _, f := range r.found {
		file := evidence.File{}
		file.Stamp, file.Stamped = nametime.Detect(f.name)
		if info, err := f.entry.Info(); err == nil && !file.Stamped {
			file.Modified = info.ModTime().UTC()
		}
		if file.Within(scope.From, scope.Until) {
			kept = append(kept, f)
		} else {
			outside++
		}
	}
	r.found = kept
	return outside
}

// read is one file's record and its text.
type read struct {
	file evidence.File
	text string
}

// walk lists one folder, level folders below the root, collecting the regular
// files to read. A symbolic link is never a folder here, so the walk cannot
// loop or follow one.
func (r *reader) walk(dir string, level int) error {
	entries, err := r.list(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		p := path.Join(dir, e.Name())
		switch {
		case e.Type().IsRegular():
			r.found = append(r.found, found{path: p, name: e.Name(), entry: e})
		case e.IsDir() && r.depth > 0:
			if level == r.depth || r.walk(p, level+1) != nil {
				r.skipped = append(r.skipped, p)
			}
		}
	}
	return nil
}

func (r *reader) list(dir string) ([]os.DirEntry, error) {
	h, err := r.root.Open(dir)
	if err != nil {
		return nil, err
	}
	defer h.Close()
	return h.ReadDir(-1)
}

func (r *reader) fileWithText(p, name string) (evidence.File, string) {
	f := evidence.File{Path: p, Name: name, Role: r.roles.byName(name), Note: evidence.Unreadable}
	f.Stamp, f.Stamped = nametime.Detect(name)
	h, err := r.root.Open(p)
	if err != nil {
		return f, ""
	}
	defer h.Close()
	info, err := h.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return f, ""
	}
	f.Modified = info.ModTime().UTC()

	sum := sha256.New()
	kept := &capped{limit: r.limit}
	size, err := io.Copy(io.MultiWriter(sum, kept), h)
	f.Size = size
	if err != nil {
		return f, ""
	}
	f.SHA256 = hex.EncodeToString(sum.Sum(nil))
	if kept.over {
		f.Note = evidence.Oversize
		return f, ""
	}
	text, ok := decode(kept.data)
	if !ok {
		f.Note = evidence.Binary
		return f, ""
	}
	f.Note = ""
	f.Lines = countLines(text)
	if f.Role == evidence.Other {
		f.Role = r.roles.byText(text)
	}
	return f, text
}

// capped keeps what is written until the limit is passed, then keeps nothing.
type capped struct {
	limit int64
	data  []byte
	over  bool
}

func (c *capped) Write(p []byte) (int, error) {
	if c.over {
		return len(p), nil
	}
	if int64(len(c.data))+int64(len(p)) > c.limit {
		c.over, c.data = true, nil
		return len(p), nil
	}
	c.data = append(c.data, p...)
	return len(p), nil
}
