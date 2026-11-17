package command

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/get-sybers/slopmop/internal/cli"
	"github.com/get-sybers/slopmop/internal/evidence"
	"github.com/get-sybers/slopmop/internal/render"
	"github.com/get-sybers/slopmop/internal/trace"
)

// savedSpec declares what a verb writes to disk.
type savedSpec struct {
	// Prefix and the name of the input folder make the default output folder.
	Prefix  string      `json:"prefix"`
	Readout string      `json:"readout"`
	Tables  []savedFile `json:"tables"`
}

// savedFile is one class written as JSON, every column.
type savedFile struct {
	Class string `json:"class"`
	File  string `json:"file"`
}

type tableBuilder func(w reportRun, columns []render.Column) (render.Table, error)

func tableBuilders() map[string]tableBuilder {
	return map[string]tableBuilder{
		"file":     reportRun.fileTable,
		"trace":    reportRun.traceTable,
		"finding":  reportRun.findingTable,
		"targeted": reportRun.targetedTable,
		"exposure": reportRun.exposureTable,
		"report":   reportRun.reportTable,
	}
}

// checkSaved returns the columns of each table, by class.
func checkSaved(s savedSpec, doc commandsDoc) (map[string][]render.Column, error) {
	if s.Prefix == "" || s.Readout == "" || len(s.Tables) == 0 {
		return nil, errors.New("commands.json: saved needs a prefix, a readout and a table")
	}
	builders := tableBuilders()
	columns := map[string][]render.Column{}
	names := map[string]bool{s.Readout: true}
	for _, t := range s.Tables {
		switch {
		case builders[t.Class] == nil:
			return nil, fmt.Errorf("commands.json: saved names the class %q, which has no table", t.Class)
		case t.File == "" || t.File != filepath.Base(t.File) || names[t.File]:
			return nil, fmt.Errorf("commands.json: saved: %q is not a file name of its own", t.File)
		case len(doc.columns(t.Class)) == 0:
			return nil, fmt.Errorf("commands.json: saved names the class %q, which declares no columns", t.Class)
		}
		names[t.File] = true
		columns[t.Class] = doc.columns(t.Class)
	}
	// A row fills every declared column, or the table cannot be written.
	checks := map[string]func([]render.Column) ([]render.Value, error){
		"file":     func(c []render.Column) ([]render.Value, error) { return fileRow(evidence.File{}, c) },
		"trace":    func(c []render.Column) ([]render.Value, error) { return traceRow(trace.Step{}, c) },
		"finding":  func(c []render.Column) ([]render.Value, error) { return findingRow(finding{}, c) },
		"targeted": func(c []render.Column) ([]render.Value, error) { return targetedRow(targeted{}, c) },
		"exposure": func(c []render.Column) ([]render.Value, error) { return exposedRow(exposed{}, c) },
		"report":   func(c []render.Column) ([]render.Value, error) { return reportCells(reportRow{}, c) },
	}
	for class, cols := range columns {
		if _, err := checks[class](cols); err != nil {
			return nil, err
		}
	}
	return columns, nil
}

func (w reportRun) fileTable(columns []render.Column) (render.Table, error) {
	steps := append([]trace.Step(nil), w.result.timeline.Steps...)
	sort.SliceStable(steps, func(i, j int) bool { return steps[i].File.Path < steps[j].File.Path })
	table := render.Table{Columns: columns}
	for _, s := range steps {
		row, err := fileRow(s.File, columns)
		if err != nil {
			return table, err
		}
		table.Rows = append(table.Rows, row)
	}
	return table, nil
}

func (w reportRun) traceTable(columns []render.Column) (render.Table, error) {
	table := render.Table{Columns: columns}
	for _, s := range w.result.timeline.Steps {
		row, err := traceRow(s, columns)
		if err != nil {
			return table, err
		}
		table.Rows = append(table.Rows, row)
	}
	return table, nil
}

func (w reportRun) findingTable(columns []render.Column) (render.Table, error) {
	table := render.Table{Columns: columns}
	for _, f := range w.pipe.listFindings(w.result) {
		row, err := findingRow(f, columns)
		if err != nil {
			return table, err
		}
		table.Rows = append(table.Rows, row)
	}
	return table, nil
}

func (w reportRun) targetedTable(columns []render.Column) (render.Table, error) {
	table := render.Table{Columns: columns}
	for _, t := range w.result.targeted {
		row, err := targetedRow(t, columns)
		if err != nil {
			return table, err
		}
		table.Rows = append(table.Rows, row)
	}
	return table, nil
}

func (w reportRun) exposureTable(columns []render.Column) (render.Table, error) {
	table := render.Table{Columns: columns}
	for _, e := range w.result.exposed {
		row, err := exposedRow(e, columns)
		if err != nil {
			return table, err
		}
		table.Rows = append(table.Rows, row)
	}
	return table, nil
}

func (w reportRun) reportTable(columns []render.Column) (render.Table, error) {
	table := render.Table{Columns: columns}
	for _, r := range w.rows {
		row, err := reportCells(r, columns)
		if err != nil {
			return table, err
		}
		table.Rows = append(table.Rows, row)
	}
	return table, nil
}

// outputDir chooses the folder to write to: the one given, or the prefix and
// the input folder's name in workDir. Beside the input folder is the fallback
// when workDir is inside it, because the evidence is never written to.
func outputDir(input, given, workDir, prefix string) (string, error) {
	if given != "" {
		if within(input, given) {
			return "", cli.Usagef("-%s is inside the folder that is read; the evidence is never written to", outDir)
		}
		return given, nil
	}
	whole, err := filepath.Abs(input)
	if err != nil {
		return "", fmt.Errorf("output folder: %w", err)
	}
	name := prefix + filepath.Base(whole)
	if dir := filepath.Join(workDir, name); !within(input, dir) {
		return dir, nil
	}
	if dir := filepath.Join(filepath.Dir(whole), name); !within(input, dir) {
		return dir, nil
	}
	return "", cli.Usagef("no folder outside %s to write to; name one with -%s <folder>", input, outDir)
}

// within reports whether dir is the folder or lies in it, with symbolic
// links resolved. A dir that does not exist yet is judged by its parent.
func within(folder, dir string) bool {
	root, err := resolved(folder)
	if err != nil {
		return true
	}
	target, err := resolved(dir)
	if err != nil {
		return true
	}
	rel, err := filepath.Rel(root, target)
	return err != nil || rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

func resolved(path string) (string, error) {
	whole, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	var rest []string
	for {
		target, err := filepath.EvalSymlinks(whole)
		if err == nil {
			return filepath.Join(append([]string{target}, rest...)...), nil
		}
		parent := filepath.Dir(whole)
		if parent == whole {
			return "", err
		}
		rest = append([]string{filepath.Base(whole)}, rest...)
		whole = parent
	}
}

// save writes the readout and each table into dir and returns the names written.
func (w reportRun) save(dir string, s savedSpec, columns map[string][]render.Column, readout render.Readout) ([]string, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("output folder: %w", err)
	}
	var text bytes.Buffer
	if err := render.WriteReadout(&text, readout, false); err != nil {
		return nil, err
	}
	names := []string{s.Readout}
	contents := [][]byte{text.Bytes()}
	builders := tableBuilders()
	for _, t := range s.Tables {
		table, err := builders[t.Class](w, columns[t.Class])
		if err != nil {
			return nil, err
		}
		var encoded bytes.Buffer
		if err := render.Write(&encoded, table, render.Options{View: render.JSON}); err != nil {
			return nil, err
		}
		names, contents = append(names, t.File), append(contents, encoded.Bytes())
	}
	for i, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), contents[i], 0o600); err != nil {
			return nil, fmt.Errorf("output folder: %w", err)
		}
	}
	return names, nil
}
