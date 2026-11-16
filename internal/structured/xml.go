package structured

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

func (t Table) extractXML(text string) (Report, error) {
	dec := xml.NewDecoder(strings.NewReader(text))
	dec.Strict = false
	dec.Entity = xml.HTMLEntity
	// The inventory has already decoded the bytes, whatever the declaration says.
	dec.CharsetReader = func(_ string, in io.Reader) (io.Reader, error) { return in, nil }
	var r Report
	var open []bool
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return r, nil
		}
		if err != nil {
			return Report{}, fmt.Errorf("xml: %w", err)
		}
		switch x := tok.(type) {
		case xml.StartElement:
			for _, a := range x.Attr {
				r.addValue(a.Value)
				if t.commandFields[normalise(a.Name.Local)] {
					r.addCommand(a.Value)
				}
			}
			open = append(open, t.commandFields[normalise(x.Name.Local)])
		case xml.EndElement:
			if len(open) > 0 {
				open = open[:len(open)-1]
			}
		case xml.CharData:
			r.addValue(string(x))
			if len(open) > 0 && open[len(open)-1] {
				r.addCommand(string(x))
			}
		case xml.Comment:
			r.addValue(string(x))
		}
	}
}
