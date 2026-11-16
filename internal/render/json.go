package render

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

func encodeJSON(t Table) ([]byte, error) {
	rows := make([]jsonRow, len(t.Rows))
	for i, values := range t.Rows {
		rows[i] = jsonRow{columns: t.Columns, values: values}
	}
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
