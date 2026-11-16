package render

import (
	"fmt"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// encodeJSON writes the objects by hand: encoding/json would sort the keys of a map.
func encodeJSON(t Table) []byte {
	if len(t.Rows) == 0 {
		return []byte("[]\n")
	}
	b := []byte{'['}
	for i, row := range t.Rows {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, "\n  {"...)
		for j, v := range row {
			if j > 0 {
				b = append(b, ',')
			}
			b = append(b, "\n    "...)
			b = appendString(b, t.Columns[j].Key)
			b = append(b, ": "...)
			b = v.appendJSON(b)
		}
		b = append(b, "\n  }"...)
	}
	return append(b, "\n]\n"...)
}

func (v Value) appendJSON(b []byte) []byte {
	switch v.kind {
	case kindInt, kindSize:
		return strconv.AppendInt(b, v.num, 10)
	case kindTime:
		// time.Time refuses to marshal a year above 9999; the layout does not.
		return appendString(b, v.when.UTC().Format(utcLayout))
	case kindNotApplicable, kindNever:
		return append(b, "null"...)
	default:
		return appendString(b, v.text)
	}
}

// appendString escapes every rune that is not printable, so JSON is as safe on a terminal as a table.
func appendString(b []byte, s string) []byte {
	b = append(b, '"')
	for _, r := range s {
		switch {
		case r == '"':
			b = append(b, `\"`...)
		case r == '\\':
			b = append(b, `\\`...)
		case strconv.IsPrint(r):
			b = utf8.AppendRune(b, r)
		case r == '\n':
			b = append(b, `\n`...)
		case r == '\r':
			b = append(b, `\r`...)
		case r == '\t':
			b = append(b, `\t`...)
		case r > 0xFFFF:
			hi, lo := utf16.EncodeRune(r)
			b = fmt.Appendf(b, `\u%04x\u%04x`, hi, lo)
		default:
			b = fmt.Appendf(b, `\u%04x`, r)
		}
	}
	return append(b, '"')
}
