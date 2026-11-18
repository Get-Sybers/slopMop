package render

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"strings"
)

// formulas are the bytes a spreadsheet reads the start of a formula from.
const formulas = "=+-@"

// CSV writes a table as comma-separated values one row at a time, so a table
// of any size is never held whole. Close ends the table.
type CSV struct {
	out     *bufio.Writer
	rows    *csv.Writer
	columns []Column
	cells   []string
	written int
}

// NewCSV checks the columns and begins a table on w with a row of their keys.
func NewCSV(w io.Writer, columns []Column) (*CSV, error) {
	if err := (Table{Columns: columns}).Check(); err != nil {
		return nil, err
	}
	out := bufio.NewWriterSize(w, held)
	c := &CSV{out: out, rows: csv.NewWriter(out), columns: columns, cells: make([]string, len(columns))}
	for i, col := range columns {
		c.cells[i] = col.Key
	}
	if err := c.rows.Write(c.cells); err != nil {
		return nil, fmt.Errorf("render: write table: %w", err)
	}
	return c, nil
}

// Write adds one row, which fills every column in order.
func (c *CSV) Write(values []Value) error {
	if len(values) != len(c.columns) {
		return fmt.Errorf("render: row %d has %d values, want %d", c.written+1, len(values), len(c.columns))
	}
	for i, v := range values {
		c.cells[i] = v.field()
	}
	c.written++
	if err := c.rows.Write(c.cells); err != nil {
		return fmt.Errorf("render: write table: %w", err)
	}
	return nil
}

// Close writes what is still held.
func (c *CSV) Close() error {
	c.rows.Flush()
	if err := c.rows.Error(); err != nil {
		return fmt.Errorf("render: write table: %w", err)
	}
	if err := c.out.Flush(); err != nil {
		return fmt.Errorf("render: write table: %w", err)
	}
	return nil
}

// field is a value as one cell of CSV: whole, with a value that does not
// apply left empty. Text that a spreadsheet would read as a formula follows
// an apostrophe, so opening the file runs nothing the evidence wrote.
func (v Value) field() string {
	switch v.kind {
	case kindNotApplicable, kindNever:
		return ""
	case kindInt, kindSize, kindTime:
		return v.cell(style{raw: true})
	}
	text := v.cell(style{raw: true})
	if text != "" && strings.IndexByte(formulas, text[0]) >= 0 {
		return "'" + text
	}
	return text
}
