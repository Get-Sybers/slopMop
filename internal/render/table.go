// Package render writes tables in the default, wide, quiet and JSON views.
package render

import "time"

// View selects how much of a table is written and in what form.
type View int

// The views a table can be written in.
const (
	Default View = iota
	Wide
	JSON
)

// Column describes one column of a table.
type Column struct {
	Header string // UPPERCASE (spaces allowed), or count, or n-<field>
	Key    string // JSON key
	Wide   bool   // shown only in wide and json
}

// Table is a set of rows under a fixed list of columns.
type Table struct {
	Columns []Column
	Rows    [][]Value
}

// Options are the output flags a table is written with.
type Options struct {
	View      View
	Quiet     bool
	NoHeaders bool
	Location  *time.Location // nil means UTC
}
