package render

import (
	"errors"
	"fmt"
	"strings"
)

const (
	countHeader    = "count"
	distinctPrefix = "n-"
)

// Check reports the first way in which t breaks the output conventions.
func (t Table) Check() error {
	if len(t.Columns) == 0 {
		return errors.New("render: table has no columns")
	}
	seen := make(map[string]int, len(t.Columns))
	for i, c := range t.Columns {
		n := i + 1
		if !validHeader(c.Header) {
			return fmt.Errorf("render: column %d has header %q, want UPPERCASE, count or n-<field>", n, c.Header)
		}
		if n == 1 && c.Wide {
			return fmt.Errorf("render: column 1 (%s) is the selector and cannot be wide", c.Header)
		}
		if c.Key == "" {
			return fmt.Errorf("render: column %d (%s) has no key", n, c.Header)
		}
		if first, ok := seen[c.Key]; ok {
			return fmt.Errorf("render: columns %d and %d share the key %q", first, n, c.Key)
		}
		seen[c.Key] = n
	}
	for i, row := range t.Rows {
		if len(row) != len(t.Columns) {
			return fmt.Errorf("render: row %d has %d values, want %d", i+1, len(row), len(t.Columns))
		}
	}
	return nil
}

func validHeader(h string) bool {
	if h == countHeader {
		return true
	}
	if field, ok := strings.CutPrefix(h, distinctPrefix); ok {
		return field != "" && all(field, isFieldByte)
	}
	// A header that began or ended with a space would leave a ragged or trailing-space line.
	return h != "" && h[0] != ' ' && h[len(h)-1] != ' ' && all(h, isHeaderByte)
}

func all(s string, ok func(byte) bool) bool {
	for i := range len(s) {
		if !ok(s[i]) {
			return false
		}
	}
	return true
}

func isHeaderByte(b byte) bool {
	return b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == ' '
}

func isFieldByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-'
}
