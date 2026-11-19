package render

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// held is how many bytes of a table wait in memory before they are written.
const held = 1 << 20

// Rows writes a table as JSON one row at a time, so a table of any size is
// never held whole. Close ends the table.
type Rows struct {
	out     *bufio.Writer
	columns []Column
	keys    [][]byte
	row     bytes.Buffer
	enc     *json.Encoder
	clean   []byte
	written int
}

// NewRows checks the columns and begins a table on w.
func NewRows(w io.Writer, columns []Column) (*Rows, error) {
	if err := (Table{Columns: columns}).Check(); err != nil {
		return nil, err
	}
	r := &Rows{out: bufio.NewWriterSize(w, held), columns: columns, keys: make([][]byte, len(columns))}
	r.enc = json.NewEncoder(&r.row)
	r.enc.SetEscapeHTML(false)
	for i, c := range columns {
		r.row.Reset()
		if err := r.value(c.Key); err != nil {
			return nil, err
		}
		r.keys[i] = bytes.Clone(r.row.Bytes())
	}
	return r, nil
}

// value adds v to the row. The encoder ends a value with a line break, which is dropped.
func (r *Rows) value(v any) error {
	if err := r.enc.Encode(v); err != nil {
		return fmt.Errorf("render: encode json: %w", err)
	}
	r.row.Truncate(r.row.Len() - 1)
	return nil
}

// rowIndent stands before each key of a row.
const rowIndent = "    "

// put adds v to the row. A list is an array of objects, one to an item, with
// each of its lines after indent.
func (r *Rows) put(v Value, indent string) error {
	if v.kind != kindList {
		return r.value(v.raw())
	}
	if len(v.items) == 0 {
		r.row.WriteString("[]")
		return nil
	}
	r.row.WriteByte('[')
	for n, item := range v.items {
		if n > 0 {
			r.row.WriteByte(',')
		}
		r.row.WriteString("\n" + indent + "  {")
		for k, f := range item {
			if k > 0 {
				r.row.WriteByte(',')
			}
			r.row.WriteString("\n" + indent + rowIndent)
			if err := r.value(f.Key); err != nil {
				return err
			}
			r.row.WriteString(": ")
			if err := r.put(f.Value, indent+rowIndent); err != nil {
				return err
			}
		}
		r.row.WriteString("\n" + indent + "  }")
	}
	r.row.WriteString("\n" + indent + "]")
	return nil
}

// Write adds one row, which fills every column in order.
func (r *Rows) Write(values []Value) error {
	if len(values) != len(r.columns) {
		return fmt.Errorf("render: row %d has %d values, want %d", r.written+1, len(values), len(r.columns))
	}
	r.row.Reset()
	if r.written == 0 {
		r.row.WriteString("[\n  {\n")
	} else {
		r.row.WriteString(",\n  {\n")
	}
	for i, v := range values {
		if i > 0 {
			r.row.WriteString(",\n")
		}
		r.row.WriteString(rowIndent)
		r.row.Write(r.keys[i])
		r.row.WriteString(": ")
		if err := r.put(v, rowIndent); err != nil {
			return err
		}
	}
	r.row.WriteString("\n  }")
	r.written++
	r.clean = escapeUnprintable(r.clean[:0], r.row.Bytes())
	if _, err := r.out.Write(r.clean); err != nil {
		return fmt.Errorf("render: write table: %w", err)
	}
	return nil
}

// Close ends the table and writes what is still held.
func (r *Rows) Close() error {
	end := "\n]\n"
	if r.written == 0 {
		end = "[]\n"
	}
	if _, err := r.out.WriteString(end); err != nil {
		return fmt.Errorf("render: write table: %w", err)
	}
	if err := r.out.Flush(); err != nil {
		return fmt.Errorf("render: write table: %w", err)
	}
	return nil
}

func encodeJSON(t Table) ([]byte, error) {
	var buf bytes.Buffer
	rows, err := NewRows(&buf, t.Columns)
	if err != nil {
		return nil, err
	}
	for _, values := range t.Rows {
		if err := rows.Write(values); err != nil {
			return nil, err
		}
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (v Value) raw() any {
	switch v.kind {
	case kindInt, kindSize:
		return v.num
	case kindTime:
		// time.Time refuses to marshal a year above 9999; the layout does not.
		return v.when.UTC().Format(utcLayout)
	case kindNotApplicable, kindNever:
		return nil
	case kindLines:
		lines := make([]string, len(v.items))
		for i, item := range v.items {
			lines[i] = item[0].Value.text
		}
		return strings.Join(lines, "\n")
	default:
		return v.text
	}
}

// escapeUnprintable adds encoded to out with the runes encoding/json leaves
// as they are escaped, so JSON is as safe on a terminal as a table. Such
// runes occur only in strings.
func escapeUnprintable(out, encoded []byte) []byte {
	for len(encoded) > 0 {
		if b := encoded[0]; b < 0x7f {
			out = append(out, b)
			encoded = encoded[1:]
			continue
		}
		r, size := utf8.DecodeRune(encoded)
		switch {
		case r > 0x7f && strconv.IsPrint(r):
			out = append(out, encoded[:size]...)
		case r > 0xFFFF:
			hi, lo := utf16.EncodeRune(r)
			out = fmt.Appendf(out, `\u%04x\u%04x`, hi, lo)
		default:
			out = fmt.Appendf(out, `\u%04x`, r)
		}
		encoded = encoded[size:]
	}
	return out
}
