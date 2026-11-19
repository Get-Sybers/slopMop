package render

import (
	"strconv"
	"strings"
	"time"
)

const (
	utcLayout     = "2006-01-02T15:04:05Z"
	offsetLayout  = "2006-01-02T15:04:05-07:00"
	shortHash     = 12
	notApplicable = "-"
	never         = "never"
)

type kind uint8

const (
	kindText kind = iota
	kindInt
	kindSize
	kindTime
	kindHash
	kindNotApplicable
	kindNever
	kindList
	kindLines
)

// Value is one cell of a table; the zero Value is the empty text.
type Value struct {
	kind kind
	text string
	num  int64
	when time.Time
	// items are the items of a list, each a set of named values.
	items [][]Field
}

// Field is one named value of an item of a list.
type Field struct {
	Key   string
	Value Value
}

// Text is evidence or any other free text.
func Text(s string) Value { return Value{kind: kindText, text: s} }

// Int is a count or a numeric identifier.
func Int(n int64) Value { return Value{kind: kindInt, num: n} }

// Size is a number of bytes.
func Size(bytes int64) Value { return Value{kind: kindSize, num: bytes} }

// Time is an instant.
func Time(t time.Time) Value { return Value{kind: kindTime, when: t} }

// Hash is a digest in hexadecimal.
func Hash(hex string) Value { return Value{kind: kindHash, text: hex} }

// NotApplicable is the sentinel for a field that has no meaning in its row.
func NotApplicable() Value { return Value{kind: kindNotApplicable} }

// Never is the sentinel for an event that has not happened.
func Never() Value { return Value{kind: kindNever} }

// List is a list of items, each a set of named values in order, such as the
// lines of evidence behind a finding. JSON writes it as an array of objects.
func List(items [][]Field) Value { return Value{kind: kindList, items: items} }

// Lines is lines of text that stand one under another, such as the lines
// that show a finding. JSON writes them as one string, a line to each.
func Lines(lines []string) Value {
	items := make([][]Field, len(lines))
	for i, line := range lines {
		items[i] = []Field{{Value: Text(line)}}
	}
	return Value{kind: kindLines, items: items}
}

// style is how the views meant for reading write a cell.
type style struct {
	raw bool // byte counts and whole hashes
	loc *time.Location
}

func (v Value) cell(s style) string {
	switch v.kind {
	case kindInt:
		return strconv.FormatInt(v.num, 10)
	case kindSize:
		if s.raw {
			return strconv.FormatInt(v.num, 10)
		}
		return humanise(v.num)
	case kindTime:
		if s.loc == nil || s.loc == time.UTC {
			return v.when.UTC().Format(utcLayout)
		}
		return v.when.In(s.loc).Format(offsetLayout)
	case kindHash:
		// Escaped like text: nothing guarantees that the caller's digest is hexadecimal.
		if s.raw {
			return Escape(v.text)
		}
		return Escape(firstRunes(v.text, shortHash))
	case kindNotApplicable:
		return notApplicable
	case kindNever:
		return never
	case kindList, kindLines:
		// One cell holds the list: the values of an item side by side, item after item.
		items := make([]string, len(v.items))
		for i, item := range v.items {
			values := make([]string, len(item))
			for n, f := range item {
				values[n] = f.Value.cell(s)
			}
			items[i] = strings.Join(values, " ")
		}
		return strings.Join(items, "; ")
	default:
		return Escape(v.text)
	}
}

func firstRunes(s string, n int) string {
	for i := range s {
		if n == 0 {
			return s[:i]
		}
		n--
	}
	return s
}
