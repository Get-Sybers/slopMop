package command

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"unicode"

	"github.com/get-sybers/slopmop/internal/cli"
	"github.com/get-sybers/slopmop/internal/evidence"
	"github.com/get-sybers/slopmop/internal/render"
	"github.com/get-sybers/slopmop/internal/trace"
)

// savedSpec declares what a verb writes to disk.
type savedSpec struct {
	// Prefix and the name of the input folder make the default output folder.
	Prefix   string         `json:"prefix"`
	Readouts []savedReadout `json:"readouts"`
	Tables   []savedFile    `json:"tables"`
}

// savedReadout is the whole report written in one format.
type savedReadout struct {
	Format string `json:"format"`
	File   string `json:"file"`
}

type readoutWriter func(w io.Writer, r render.Readout) error

// readoutWriters are the formats a report is saved in, by name.
func readoutWriters() map[string]readoutWriter {
	return map[string]readoutWriter{
		"text":     func(w io.Writer, r render.Readout) error { return render.WriteReadout(w, r, false) },
		"markdown": render.WriteMarkdown,
		"html":     render.WriteHTML,
	}
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
		"intent":   reportRun.intentTable,
		"finding":  reportRun.findingTable,
		"targeted": reportRun.targetedTable,
		"exposure": reportRun.exposureTable,
		"report":   reportRun.reportTable,
	}
}

// checkSaved returns the columns of each table, by class.
func checkSaved(s savedSpec, doc commandsDoc) (map[string][]render.Column, error) {
	if s.Prefix == "" || len(s.Readouts) == 0 || len(s.Tables) == 0 {
		return nil, errors.New("commands.json: saved needs a prefix, a readout and a table")
	}
	writers, formats := readoutWriters(), map[string]bool{}
	names := map[string]bool{}
	for _, r := range s.Readouts {
		switch {
		case writers[r.Format] == nil || formats[r.Format]:
			return nil, fmt.Errorf("commands.json: saved: %q is not a format of its own", r.Format)
		case r.File == "" || r.File != filepath.Base(r.File) || names[r.File]:
			return nil, fmt.Errorf("commands.json: saved: %q is not a file name of its own", r.File)
		}
		formats[r.Format], names[r.File] = true, true
	}
	builders := tableBuilders()
	columns := map[string][]render.Column{}
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
		"trace":    func(c []render.Column) ([]render.Value, error) { return traceRow(trace.Step{}, "", c) },
		"intent":   func(c []render.Column) ([]render.Value, error) { return intentRow(intentRun{}, c) },
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
		row, err := traceRow(s, w.result.intentOf[s.File.Path], columns)
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
	name := prefix + folderName(whole)
	if dir := filepath.Join(workDir, name); !within(input, dir) {
		return dir, nil
	}
	if dir := filepath.Join(filepath.Dir(whole), name); !within(input, dir) {
		return dir, nil
	}
	return "", cli.Usagef("no folder outside %s to write to; name one with -%s <folder>", input, outDir)
}

// within reports whether dir is the folder or lies in it. Each folder from
// dir upwards is compared with the folder, by its path and by the file it is,
// so two volumes are never one place and two names of one folder are.
func within(folder, dir string) bool {
	root := located(folder)
	held, heldErr := os.Stat(folder)
	for at := located(dir); ; at = filepath.Dir(at) {
		if samePath(at, root) {
			return true
		}
		if info, err := os.Stat(at); heldErr == nil && err == nil && os.SameFile(held, info) {
			return true
		}
		if filepath.Dir(at) == at {
			return false
		}
	}
}

// located gives a path in full with its symbolic links resolved. A part that
// does not exist yet, or that its volume cannot resolve, stays as written.
func located(path string) string {
	whole, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	var rest []string
	for at := whole; ; {
		if target, err := filepath.EvalSymlinks(at); err == nil {
			return filepath.Join(append([]string{target}, rest...)...)
		}
		parent := filepath.Dir(at)
		if parent == at {
			return whole
		}
		rest = append([]string{filepath.Base(at)}, rest...)
		at = parent
	}
}

// samePath compares two paths as the system does: Windows ignores case.
func samePath(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// folderName is the name of the input folder. A drive or the root of the
// file system has none, and lends the letters of its volume, or "root".
func folderName(whole string) string {
	if name := filepath.Base(whole); name != string(filepath.Separator) && name != "." {
		return name
	}
	letters := strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return r
		}
		return -1
	}, filepath.VolumeName(whole))
	if letters == "" {
		return "root"
	}
	return letters
}

// save writes the readout in each format, and each table, into dir. It
// returns the names written.
func (w reportRun) save(dir string, s savedSpec, columns map[string][]render.Column, readout render.Readout) ([]string, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("output folder: %w", err)
	}
	var names []string
	var contents [][]byte
	writers := readoutWriters()
	for _, r := range s.Readouts {
		var written bytes.Buffer
		if err := writers[r.Format](&written, readout); err != nil {
			return nil, err
		}
		names, contents = append(names, r.File), append(contents, written.Bytes())
	}
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
