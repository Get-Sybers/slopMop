// Package inventory reads the input directory into file records.
package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/get-sybers/slopmop/internal/evidence"
	"github.com/get-sybers/slopmop/internal/nametime"
)

var ErrNotFolder = errors.New("not a folder")

const maxTextBytes = 64 << 20

// Read lists the regular files directly in folder, sorted by path. It opens
// files read-only through a root, so nothing outside the folder is reachable.
func Read(folder string) ([]evidence.File, error) {
	return read(folder, maxTextBytes)
}

func read(folder string, limit int64) ([]evidence.File, error) {
	roles, err := LoadRoles()
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(folder)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotFolder, err)
	}
	defer root.Close()
	dir, err := root.Open(".")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotFolder, err)
	}
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotFolder, err)
	}
	r := reader{root: root, limit: limit, roles: newClassifier(roles)}
	files := make([]evidence.File, 0, len(entries))
	for _, e := range entries {
		// Links, folders and special files are never opened.
		if e.Type().IsRegular() {
			files = append(files, r.file(e.Name()))
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

type reader struct {
	root  *os.Root
	limit int64
	roles classifier
}

func (r reader) file(name string) evidence.File {
	f := evidence.File{Path: name, Name: name, Role: r.roles.byName(name), Note: evidence.Unreadable}
	f.Stamp, f.Stamped = nametime.Detect(name)
	h, err := r.root.Open(name)
	if err != nil {
		return f
	}
	defer h.Close()
	info, err := h.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return f
	}
	f.Modified = info.ModTime().UTC()

	// One pass feeds the hash and keeps the bytes the text needs.
	sum := sha256.New()
	kept := &capped{limit: r.limit}
	size, err := io.Copy(io.MultiWriter(sum, kept), h)
	f.Size = size
	if err != nil {
		return f
	}
	f.SHA256 = hex.EncodeToString(sum.Sum(nil))
	if kept.over {
		f.Note = evidence.Oversize
		return f
	}
	text, ok := decode(kept.data)
	if !ok {
		f.Note = evidence.Binary
		return f
	}
	f.Note = ""
	f.Lines = countLines(text)
	if f.Role == evidence.Other {
		f.Role = r.roles.byText(text)
	}
	return f
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
