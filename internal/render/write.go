package render

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

const padding = 2

// Write checks t and writes it to w in the view o selects; Quiet takes precedence over View.
func Write(w io.Writer, t Table, o Options) error {
	if err := t.Check(); err != nil {
		return err
	}
	out, err := encode(t, o)
	if err != nil {
		return err
	}
	// One write, so a table reaches w whole or not at all.
	if _, err = w.Write(out); err != nil {
		return fmt.Errorf("render: write table: %w", err)
	}
	return nil
}

func encode(t Table, o Options) ([]byte, error) {
	switch {
	case o.View != Default && o.View != Wide && o.View != JSON:
		return nil, fmt.Errorf("render: unknown view %d", o.View)
	case o.Quiet:
		return quiet(t, o), nil
	case o.View == JSON:
		return encodeJSON(t)
	default:
		return grid(t, o)
	}
}

// quiet writes whole values: column 1 is what the reader hands back to the tool.
func quiet(t Table, o Options) []byte {
	var buf bytes.Buffer
	s := style{raw: true, loc: o.Location}
	for _, row := range t.Rows {
		buf.WriteString(row[0].cell(s))
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

func grid(t Table, o Options) ([]byte, error) {
	wide := o.View == Wide
	var shown []int
	for i, c := range t.Columns {
		if wide || !c.Wide {
			shown = append(shown, i)
		}
	}
	var text strings.Builder
	cells := make([]string, len(shown))
	if !o.NoHeaders {
		for n, i := range shown {
			cells[n] = t.Columns[i].Header
		}
		line(&text, cells)
	}
	s := style{raw: wide, loc: o.Location}
	for _, row := range t.Rows {
		for n, i := range shown {
			cells[n] = row[i].cell(s)
		}
		line(&text, cells)
	}
	return align(text.String())
}

// line leaves the last cell without a tab, so tabwriter pads nothing after it.
func line(text *strings.Builder, cells []string) {
	text.WriteString(strings.Join(cells, "\t"))
	text.WriteByte('\n')
}

func align(text string) ([]byte, error) {
	var buf bytes.Buffer
	tw := tabwriter.NewWriter(&buf, 0, 0, padding, ' ', 0)
	if _, err := io.WriteString(tw, text); err != nil {
		return nil, fmt.Errorf("render: align table: %w", err)
	}
	if err := tw.Flush(); err != nil {
		return nil, fmt.Errorf("render: align table: %w", err)
	}
	return buf.Bytes(), nil
}
