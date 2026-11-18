package render

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"strconv"
	"strings"
)

//go:embed readout.html.tmpl
var htmlSource string

// htmlPage is a readout laid out for the template: every text is already
// free of control characters, and the template escapes it for HTML.
type htmlPage struct {
	Title, Banner, BannerLevel, Legend string
	Sections                           []htmlSection
	Hints                              []string
}

type htmlSection struct {
	ID, Title, Note string
	Empty           bool
	Groups          []htmlGroup
}

type htmlGroup struct {
	Title   string
	Columns []string
	Marked  bool
	// Blocks lays the rows out as blocks on a line, not as a table.
	Blocks bool
	Rows   []htmlRow
}

type htmlRow struct {
	Marked      bool
	Level, Mark string
	Cells       []string
	Detail      []htmlDetail
	// Span is how many columns the detail of the row lies across.
	Span int
}

// htmlDetail is a detail line. A label is written once, with its note: the
// lines under it that share both are Labelled and carry neither, as in the
// plain text. A line that Begins is the first of a label after another's.
type htmlDetail struct {
	Label, Note, Key, Text string
	Labelled, Begins, None bool
}

// WriteHTML writes r to w as one HTML page that needs nothing else: its
// style is inside it, it holds no script and no link out, and its policy
// lets a browser load nothing. The template escapes every text.
func WriteHTML(w io.Writer, r Readout) error {
	tmpl, err := template.New("readout").Parse(htmlSource)
	if err != nil {
		return fmt.Errorf("render: readout.html.tmpl: %w", err)
	}
	page := htmlPage{Title: Escape(r.Title), Hints: make([]string, len(r.Hints))}
	if r.Banner.Text != "" {
		glyph, _ := mark(r.Banner.Level)
		page.Banner, page.BannerLevel = strings.TrimSpace(glyph+" "+Escape(r.Banner.Text)), r.Banner.Level
	}
	if r.marked() {
		page.Legend = legend()
	}
	for i, h := range r.Hints {
		page.Hints[i] = Escape(h)
	}
	for i, s := range r.Sections {
		page.Sections = append(page.Sections, htmlOf(s, "section-"+strconv.Itoa(i+1)))
	}
	var b bytes.Buffer
	if err := tmpl.Execute(&b, page); err != nil {
		return fmt.Errorf("render: write html: %w", err)
	}
	// One write, so a readout reaches w whole or not at all.
	if _, err := w.Write(b.Bytes()); err != nil {
		return fmt.Errorf("render: write html: %w", err)
	}
	return nil
}

func htmlOf(s Section, id string) htmlSection {
	out := htmlSection{ID: id, Title: Escape(s.Title), Note: shown(s.Note), Empty: true}
	for _, g := range s.Groups {
		if len(g.Entries) == 0 {
			continue
		}
		out.Empty = false
		marked, width := g.marked(), g.width()
		group := htmlGroup{Title: shown(g.Title), Marked: marked, Blocks: g.Blocks}
		for _, c := range g.Columns {
			group.Columns = append(group.Columns, Escape(c))
		}
		// A header names every column, so a short list of names is filled out.
		for len(g.Columns) > 0 && len(group.Columns) < width {
			group.Columns = append(group.Columns, "")
		}
		for _, e := range g.Entries {
			row := htmlRow{Marked: marked, Level: e.Level, Cells: make([]string, width), Span: width}
			row.Mark, _ = mark(e.Level)
			if marked {
				row.Span++
			}
			for i, c := range e.Cells {
				row.Cells[i] = shown(c)
			}
			last := ""
			for _, d := range e.Detail {
				if d.Text == "" {
					continue
				}
				detail := htmlDetail{Label: shown(d.Label), Note: shown(d.Note), Key: shown(d.Key), Text: Escape(d.Text), Labelled: d.Label != "", None: d.None}
				// A table has two columns for a line: the note goes with the label, the key with the text.
				if !g.Blocks && d.Note != "" {
					detail.Label, detail.Note = detail.Label+" ("+detail.Note+")", ""
				}
				if !g.Blocks && d.Key != "" {
					detail.Key, detail.Text = "", detail.Key+gap+detail.Text
				}
				same := d.Label + "\x00" + d.Note
				if d.Label != "" && same == last {
					detail.Label, detail.Note = "", ""
				}
				detail.Begins = len(row.Detail) > 0 && same != last
				last = same
				row.Detail = append(row.Detail, detail)
			}
			group.Rows = append(group.Rows, row)
		}
		out.Groups = append(out.Groups, group)
	}
	return out
}
