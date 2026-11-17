package render

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/get-sybers/slopmop/internal/parallel"
)

// batch is how many rows are encoded at once; a large table is encoded in
// batches on every processor and joined in order.
const batch = 2000

func encodeJSON(t Table) ([]byte, error) {
	rows := make([]jsonRow, len(t.Rows))
	for i, values := range t.Rows {
		rows[i] = jsonRow{columns: t.Columns, values: values}
	}
	if len(rows) <= batch {
		return encodeRows(rows)
	}
	parts := make([][]byte, (len(rows)+batch-1)/batch)
	failed := make([]error, len(parts))
	parallel.Each(len(parts), func(i int) {
		part, err := encodeRows(rows[i*batch : min(len(rows), (i+1)*batch)])
		// An array of rows is "[\n", the rows, "\n]\n": the rows alone are kept.
		if err == nil {
			part = part[2 : len(part)-3]
		}
		parts[i], failed[i] = part, err
	})
	if err := errors.Join(failed...); err != nil {
		return nil, err
	}
	size := len("[\n") + len("\n]\n") + (len(parts)-1)*len(",\n")
	for _, part := range parts {
		size += len(part)
	}
	out := append(make([]byte, 0, size), "[\n"...)
	for i, part := range parts {
		if i > 0 {
			out = append(out, ",\n"...)
		}
		out = append(out, part...)
		// A batch is let go as soon as it is joined, so the table is not held twice for long.
		parts[i] = nil
	}
	return append(out, "\n]\n"...), nil
}

func encodeRows(rows []jsonRow) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rows); err != nil {
		return nil, fmt.Errorf("render: encode json: %w", err)
	}
	return escapeUnprintable(buf.Bytes()), nil
}

// jsonRow keeps the keys in column order; a map would sort them.
type jsonRow struct {
	columns []Column
	values  []Value
}

func (r jsonRow) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, v := range r.values {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := marshal(&buf, r.columns[i].Key); err != nil {
			return nil, err
		}
		buf.WriteByte(':')
		if err := marshal(&buf, v.raw()); err != nil {
			return nil, err
		}
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

func marshal(buf *bytes.Buffer, v any) error {
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return err
	}
	buf.Truncate(buf.Len() - 1)
	return nil
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
	default:
		return v.text
	}
}

// escapeUnprintable escapes the runes encoding/json leaves as they are, so
// JSON is as safe on a terminal as a table. Such runes occur only in strings.
func escapeUnprintable(encoded []byte) []byte {
	out := make([]byte, 0, len(encoded))
	for len(encoded) > 0 {
		r, size := utf8.DecodeRune(encoded)
		switch {
		case r < 0x7f, r > 0x7f && strconv.IsPrint(r):
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
