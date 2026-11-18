package command

import (
	"path/filepath"

	"github.com/get-sybers/slopmop/internal/evidence"
	"github.com/get-sybers/slopmop/internal/render"
)

// fileRow orders a file's cells by the declared columns, so the declaration
// and the code cannot drift apart unnoticed. The folder is the whole path of
// the input folder, as this system writes it.
func fileRow(f evidence.File, folder string, columns []render.Column) ([]render.Value, error) {
	cells := map[string]render.Value{
		"name":      render.Text(f.Path),
		"path":      render.Text(filepath.Join(folder, filepath.FromSlash(f.Path))),
		"role":      render.Text(string(f.Role)),
		"size":      render.Size(f.Size),
		"lines":     render.NotApplicable(),
		"modified":  render.NotApplicable(),
		"sha256":    render.NotApplicable(),
		"name_time": render.NotApplicable(),
		"note":      render.NotApplicable(),
	}
	if f.Note == "" {
		cells["lines"] = render.Int(int64(f.Lines))
	} else {
		cells["note"] = render.Text(string(f.Note))
	}
	if !f.Modified.IsZero() {
		cells["modified"] = render.Time(f.Modified)
	}
	if f.SHA256 != "" {
		cells["sha256"] = render.Hash(f.SHA256)
	}
	if f.Stamped {
		cells["name_time"] = render.Text(f.Stamp.Text)
	}
	return orderCells("file", cells, columns)
}
