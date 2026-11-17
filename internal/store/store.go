// Package store keeps a run's extracted records in a throwaway SQLite
// database, so evidence text is released as each file is read and the report
// is assembled by ordered queries, not by structures that grow with evidence.
package store

import (
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // the SQLite driver registers itself on import
)

//go:embed schema.sql
var schema string

// DB is one run's record database. A Writer is used by one goroutine; the
// readers may be called once the writer has closed.
type DB struct {
	db *sql.DB
}

// Open creates the database at path and applies the schema. An empty path, or
// ":memory:", keeps it in memory. The caller deletes the file when done.
func Open(path string) (*DB, error) {
	if path == "" {
		path = ":memory:"
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: schema: %w", err)
	}
	return &DB{db: db}, nil
}

// Close releases the database. It does not delete the file.
func (d *DB) Close() error {
	return d.db.Close()
}

// File is one evidence file. Effective is the time the timeline orders it by.
type File struct {
	Path, Name, Role, SHA256, Note string
	Size                           int64
	Lines                          int
	Stamped                        bool
	StampText                      string
	Modified, Stamp, Effective     time.Time
	// Turn is set by List: the number of scripts up to and including this file.
	Turn int
}

// Command is the first command of one tool.
type Command struct {
	Tool, Text string
	Line       int
}

// Activity is one activity a file shows, with the first lines that show it.
type Activity struct {
	Name                   string
	Lines                  int
	Tactics, Attack, Atlas []string
	Evidence               []Evidence
}

// Evidence is one line that shows an activity.
type Evidence struct {
	Line     int
	Text     string
	Subjects []Subject
}

// Subject is what a line acts on.
type Subject struct{ Label, Value string }

// Indicator is one indicator found in a file. Dollar marks a match a '$'
// stands before; InPath marks one that is an element of a Windows path.
type Indicator struct {
	Type, Value    string
	Start, Line    int
	Dollar, InPath bool
}

// IntelHit is one watchlist match.
type IntelHit struct{ Type, Value, Attribution string }

// Exposure is one value the evidence holds that an attacker can use.
type Exposure struct {
	Kind, Value, Account, Form string
	Line                       int
	Open                       bool
}

// Writer streams records into one transaction. Flush is not needed: the
// throwaway database writes pages straight through, so one transaction holds
// a whole run without growing in memory.
type Writer struct {
	tx    *sql.Tx
	stmts map[string]*sql.Stmt
}

// Writer begins the ingest transaction and prepares its statements.
func (d *DB) Writer() (*Writer, error) {
	tx, err := d.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("store: begin: %w", err)
	}
	w := &Writer{tx: tx, stmts: map[string]*sql.Stmt{}}
	for name, query := range inserts() {
		stmt, err := tx.Prepare(query)
		if err != nil {
			_ = tx.Rollback()
			return nil, fmt.Errorf("store: prepare %s: %w", name, err)
		}
		w.stmts[name] = stmt
	}
	return w, nil
}

func inserts() map[string]string {
	return map[string]string{
		"files":      `INSERT INTO files(id,path,name,role,size,lines,sha256,note,stamped,stamptext,modified,stamp,effsec,effnsec) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		"tools":      `INSERT INTO tools(file,seq,tool) VALUES(?,?,?)`,
		"tactics":    `INSERT INTO tactics(file,seq,tactic) VALUES(?,?,?)`,
		"transforms": `INSERT INTO transforms(file,seq,method) VALUES(?,?,?)`,
		"commands":   `INSERT INTO commands(file,seq,tool,text,line) VALUES(?,?,?,?,?)`,
		"activities": `INSERT INTO activities(file,seq,name,lines,tactics,attack,atlas,evidence) VALUES(?,?,?,?,?,?,?,?)`,
		"indicators": `INSERT INTO indicators(file,seq,type,value,start,line,dollar,inpath) VALUES(?,?,?,?,?,?,?,?)`,
		"intelhits":  `INSERT INTO intelhits(file,seq,type,value,attribution) VALUES(?,?,?,?,?)`,
		"exposures":  `INSERT INTO exposures(file,seq,kind,value,account,form,line,open) VALUES(?,?,?,?,?,?,?,?)`,
		"writes":     `INSERT INTO writes(file,seq,base) VALUES(?,?,?)`,
	}
}

// AddFile records one file under the identifier id, which the caller assigns
// and gives to every child record of the file.
func (w *Writer) AddFile(id int64, f File) error {
	modified, err := f.Modified.MarshalBinary()
	if err != nil {
		return fmt.Errorf("store: modified: %w", err)
	}
	stamp, err := f.Stamp.MarshalBinary()
	if err != nil {
		return fmt.Errorf("store: stamp: %w", err)
	}
	_, err = w.stmts["files"].Exec(id, f.Path, f.Name, f.Role, f.Size, f.Lines, f.SHA256, f.Note,
		boolInt(f.Stamped), f.StampText, modified, stamp, f.Effective.Unix(), int64(f.Effective.Nanosecond()))
	return err
}

func (w *Writer) AddTool(file int64, seq int, tool string) error {
	_, err := w.stmts["tools"].Exec(file, seq, tool)
	return err
}

func (w *Writer) AddTactic(file int64, seq int, tactic string) error {
	_, err := w.stmts["tactics"].Exec(file, seq, tactic)
	return err
}

func (w *Writer) AddTransform(file int64, seq int, method string) error {
	_, err := w.stmts["transforms"].Exec(file, seq, method)
	return err
}

func (w *Writer) AddCommand(file int64, seq int, c Command) error {
	_, err := w.stmts["commands"].Exec(file, seq, c.Tool, c.Text, c.Line)
	return err
}

func (w *Writer) AddActivity(file int64, seq int, a Activity) error {
	tactics, err := encode(a.Tactics)
	if err != nil {
		return err
	}
	attack, err := encode(a.Attack)
	if err != nil {
		return err
	}
	atlas, err := encode(a.Atlas)
	if err != nil {
		return err
	}
	evidence, err := encode(a.Evidence)
	if err != nil {
		return err
	}
	_, err = w.stmts["activities"].Exec(file, seq, a.Name, a.Lines, tactics, attack, atlas, evidence)
	return err
}

func (w *Writer) AddIndicator(file int64, seq int, m Indicator) error {
	_, err := w.stmts["indicators"].Exec(file, seq, m.Type, m.Value, m.Start, m.Line, boolInt(m.Dollar), boolInt(m.InPath))
	return err
}

func (w *Writer) AddIntelHit(file int64, seq int, h IntelHit) error {
	_, err := w.stmts["intelhits"].Exec(file, seq, h.Type, h.Value, h.Attribution)
	return err
}

func (w *Writer) AddExposure(file int64, seq int, e Exposure) error {
	_, err := w.stmts["exposures"].Exec(file, seq, e.Kind, e.Value, e.Account, e.Form, e.Line, boolInt(e.Open))
	return err
}

func (w *Writer) AddWrite(file int64, seq int, base string) error {
	_, err := w.stmts["writes"].Exec(file, seq, base)
	return err
}

// Close commits the transaction and finalises its statements.
func (w *Writer) Close() error {
	for _, stmt := range w.stmts {
		_ = stmt.Close()
	}
	if err := w.tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}

// Cancel discards the transaction.
func (w *Writer) Cancel() error {
	for _, stmt := range w.stmts {
		_ = stmt.Close()
	}
	return w.tx.Rollback()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func encode(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("store: encode: %w", err)
	}
	return string(b), nil
}
