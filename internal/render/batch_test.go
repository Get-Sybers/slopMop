package render

import (
	"bytes"
	"strconv"
	"testing"
)

// A table encoded in batches is, byte for byte, the table encoded at once.
func TestEncodeJSONInBatches(t *testing.T) {
	columns := []Column{{Header: "N", Key: "n"}, {Header: "TEXT", Key: "text"}, {Header: "NONE", Key: "none"}}
	for _, n := range []int{0, 1, batch, batch + 1, 2*batch + 7} {
		table := Table{Columns: columns}
		rows := make([]jsonRow, n)
		for i := range n {
			values := []Value{Int(int64(i)), Text("row " + strconv.Itoa(i) + " \x1b[2J \"quoted\" <b> é \U0001F600"), NotApplicable()}
			table.Rows = append(table.Rows, values)
			rows[i] = jsonRow{columns: columns, values: values}
		}
		got, err := encodeJSON(table)
		if err != nil {
			t.Fatal(err)
		}
		want, err := encodeRows(rows)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%d rows: the batches give %d bytes that differ from the %d bytes of one pass", n, len(got), len(want))
		}
	}
}
