package command

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"unicode"

	"github.com/get-sybers/slopmop/internal/cli"
	"github.com/get-sybers/slopmop/internal/evidence"
	"github.com/get-sybers/slopmop/internal/parallel"
	"github.com/get-sybers/slopmop/internal/progress"
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

// savedFile is one class written in one format, every column.
type savedFile struct {
	Class  string `json:"class"`
	Format string `json:"format"`
	File   string `json:"file"`
}

// tableWriter takes a table row by row; Close ends it.
type tableWriter interface {
	Write(values []render.Value) error
	Close() error
}

// tableWriters are the formats a table is saved in, by name.
func tableWriters() map[string]func(io.Writer, []render.Column) (tableWriter, error) {
	return map[string]func(io.Writer, []render.Column) (tableWriter, error){
		"json": func(w io.Writer, c []render.Column) (tableWriter, error) { return render.NewRows(w, c) },
		"csv":  func(w io.Writer, c []render.Column) (tableWriter, error) { return render.NewCSV(w, c) },
	}
}

// tableBuilder hands add each row of a class in turn, so no table is held whole.
type tableBuilder func(w reportRun, columns []render.Column, add func([]render.Value) error) error

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
	builders, tables := tableBuilders(), tableWriters()
	columns := map[string][]render.Column{}
	for _, t := range s.Tables {
		switch {
		case builders[t.Class] == nil:
			return nil, fmt.Errorf("commands.json: saved names the class %q, which has no table", t.Class)
		case tables[t.Format] == nil:
			return nil, fmt.Errorf("commands.json: saved: %q is not a format of a table", t.Format)
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
		"file":     func(c []render.Column) ([]render.Value, error) { return fileRow(evidence.File{}, "", c) },
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

func (w reportRun) fileTable(columns []render.Column, add func([]render.Value) error) error {
	steps := append([]trace.Step(nil), w.result.timeline.Steps...)
	sort.SliceStable(steps, func(i, j int) bool { return steps[i].File.Path < steps[j].File.Path })
	for _, s := range steps {
		row, err := fileRow(s.File, w.folder, columns)
		if err != nil {
			return err
		}
		if err := add(row); err != nil {
			return err
		}
	}
	return nil
}

func (w reportRun) traceTable(columns []render.Column, add func([]render.Value) error) error {
	for _, s := range w.result.timeline.Steps {
		row, err := traceRow(s, w.result.intentOf[s.File.Path], columns)
		if err != nil {
			return err
		}
		if err := add(row); err != nil {
			return err
		}
	}
	return nil
}

func (w reportRun) findingTable(columns []render.Column, add func([]render.Value) error) error {
	for _, f := range w.found {
		row, err := findingRow(f, columns)
		if err != nil {
			return err
		}
		if err := add(row); err != nil {
			return err
		}
	}
	return nil
}

func (w reportRun) targetedTable(columns []render.Column, add func([]render.Value) error) error {
	for _, t := range w.result.targeted {
		row, err := targetedRow(t, columns)
		if err != nil {
			return err
		}
		if err := add(row); err != nil {
			return err
		}
	}
	return nil
}

func (w reportRun) exposureTable(columns []render.Column, add func([]render.Value) error) error {
	for _, e := range w.result.exposed {
		row, err := exposedRow(e, columns)
		if err != nil {
			return err
		}
		if err := add(row); err != nil {
			return err
		}
	}
	return nil
}

func (w reportRun) reportTable(columns []render.Column, add func([]render.Value) error) error {
	for _, r := range w.rows {
		row, err := reportCells(r, columns)
		if err != nil {
			return err
		}
		if err := add(row); err != nil {
			return err
		}
	}
	return nil
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

// partSuffix ends the name a saved file is written under until all are made.
const partSuffix = ".part"

// save writes the readout in each format, and each table, into dir, and
// returns the names written. A file takes its name only when all are made,
// so a run that fails leaves no saved file half written.
func (w reportRun) save(dir string, s savedSpec, columns map[string][]render.Column, readout render.Readout, meter *progress.Meter) ([]string, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("output folder: %w", err)
	}
	// The folder is opened as a root and every file is made through it, so
	// no name in the folder leads a write to a place outside it.
	out, opened := os.OpenRoot(dir)
	if opened != nil {
		return nil, fmt.Errorf("output folder: %w", opened)
	}
	defer out.Close()
	var names []string
	var makers []func(io.Writer) error
	writers := readoutWriters()
	for _, r := range s.Readouts {
		names = append(names, r.File)
		makers = append(makers, func(out io.Writer) error { return writers[r.Format](out, readout) })
	}
	builders, tables := tableBuilders(), tableWriters()
	for _, t := range s.Tables {
		names = append(names, t.File)
		makers = append(makers, func(out io.Writer) error {
			rows, err := tables[t.Format](out, columns[t.Class])
			if err != nil {
				return err
			}
			if err := builders[t.Class](w, columns[t.Class], rows.Write); err != nil {
				return err
			}
			return rows.Close()
		})
	}
	// Each file is made apart from the others, on every processor, and
	// written as it is made, so none is held whole in memory.
	failed := make([]error, len(makers))
	parallel.Each(len(makers), func(i int) {
		defer meter.Begin(names[i])()
		failed[i] = writePart(out, names[i]+partSuffix, makers[i])
	})
	failure := errors.Join(failed...)
	for i := 0; failure == nil && i < len(names); i++ {
		if err := out.Rename(names[i]+partSuffix, names[i]); err != nil {
			failure = fmt.Errorf("output folder: %w", err)
		}
	}
	if failure != nil {
		// What was not given its name is taken away again.
		for _, name := range names {
			_ = out.Remove(name + partSuffix)
		}
		return nil, failure
	}
	return names, nil
}

// writePart makes one new file in the folder with what fill writes to it.
// What stands under the name is taken away first, so the file written is
// never one that a link, in the folder or elsewhere, also leads to.
func writePart(out *os.Root, name string, fill func(io.Writer) error) error {
	if err := out.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("output folder: %w", err)
	}
	f, err := out.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("output folder: %w", err)
	}
	if err := fill(f); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("output folder: %w", err)
	}
	return nil
}
