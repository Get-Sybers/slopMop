package render

import (
	"bytes"
	"fmt"
	"io"
	"strings"
)

// WriteMarkdown writes r to w as Markdown. A group whose entries carry no
// detail is a table; any other is a list. Evidence is written in code spans,
// where a renderer makes nothing of it: no markup, no link.
func WriteMarkdown(w io.Writer, r Readout) error {
	var b bytes.Buffer
	b.WriteString("# " + mdText(r.Title) + "\n")
	if r.Banner.Text != "" {
		glyph, _ := mark(r.Banner.Level)
		b.WriteString("\n**" + mdText(strings.TrimSpace(glyph+" "+r.Banner.Text)) + "**\n")
	}
	if r.marked() {
		b.WriteString("\n" + mdText(legend()) + "\n")
	}
	for _, s := range r.Sections {
		b.WriteString("\n## " + mdText(s.Title) + "\n")
		if s.Note != "" {
			b.WriteString("\n_" + mdText(s.Note) + "_\n")
		}
		empty := true
		for _, g := range s.Groups {
			if len(g.Entries) == 0 {
				continue
			}
			empty = false
			if g.Title != "" {
				b.WriteString("\n### " + mdText(g.Title) + "\n")
			}
			b.WriteString("\n")
			if g.detailed() {
				mdList(&b, g)
			} else {
				mdTable(&b, g)
			}
		}
		if empty {
			b.WriteString("\nNone.\n")
		}
	}
	if len(r.Hints) > 0 {
		b.WriteString("\n---\n\n")
		for _, h := range r.Hints {
			b.WriteString("- " + mdCode(h, false) + "\n")
		}
	}
	// One write, so a readout reaches w whole or not at all.
	if _, err := w.Write(b.Bytes()); err != nil {
		return fmt.Errorf("render: write markdown: %w", err)
	}
	return nil
}

// detailed reports whether any entry of the group has a detail line to show.
func (g Group) detailed() bool {
	for _, e := range g.Entries {
		for _, d := range e.Detail {
			if d.Text != "" {
				return true
			}
		}
	}
	return false
}

// marked reports whether any entry of the group carries a level.
func (g Group) marked() bool {
	for _, e := range g.Entries {
		if e.Level != "" {
			return true
		}
	}
	return false
}

// width is the most cells any entry of the group has, or its columns if more.
func (g Group) width() int {
	n := len(g.Columns)
	for _, e := range g.Entries {
		n = max(n, len(e.Cells))
	}
	return n
}

func mdTable(b *bytes.Buffer, g Group) {
	marked, width := g.marked(), g.width()
	var header, rule []string
	if marked {
		header, rule = append(header, " "), append(rule, "---")
	}
	for i := range width {
		name := " "
		if i < len(g.Columns) {
			name = mdText(g.Columns[i])
		}
		header, rule = append(header, name), append(rule, "---")
	}
	b.WriteString("| " + strings.Join(header, " | ") + " |\n| " + strings.Join(rule, " | ") + " |\n")
	for _, e := range g.Entries {
		var cells []string
		if marked {
			glyph, _ := mark(e.Level)
			cells = append(cells, mdCode(glyph, true))
		}
		for i := range width {
			cell := ""
			if i < len(e.Cells) {
				cell = mdCode(e.Cells[i], true)
			}
			cells = append(cells, cell)
		}
		b.WriteString("| " + strings.Join(cells, " | ") + " |\n")
	}
}

func mdList(b *bytes.Buffer, g Group) {
	for _, e := range g.Entries {
		var parts []string
		if glyph, _ := mark(e.Level); glyph != "" {
			parts = append(parts, "**"+mdText(glyph+" "+e.Level)+"**")
		}
		for _, c := range e.Cells {
			if c != "" {
				parts = append(parts, mdCode(c, false))
			}
		}
		b.WriteString("- " + strings.Join(parts, " · ") + "\n")
		for _, d := range e.Detail {
			switch {
			case d.Text == "":
			case d.Label == "":
				// A line without a label is a sentence of the tool's own.
				b.WriteString("  - " + mdText(d.Text) + "\n")
			default:
				b.WriteString("  - **" + mdText(d.Label) + ":** " + mdCode(d.Text, false) + "\n")
			}
		}
	}
}

// mdEscaped lists what Markdown would read as markup in running text.
const mdEscaped = "\\`*_[]<>|~#"

// mdText writes a text of the tool's own, or a title, as plain Markdown.
func mdText(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range Escape(s) {
		switch {
		case r == '&':
			b.WriteString("&amp;")
		case strings.ContainsRune(mdEscaped, r):
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// mdCode writes a value from the evidence as a code span. The fence is one
// backtick longer than any run inside, and a pipe in a table cell is escaped,
// as a table needs even inside a code span.
func mdCode(s string, inTable bool) string {
	if s == "" {
		return ""
	}
	s = Escape(s)
	longest, run := 0, 0
	for _, r := range s {
		if r == '`' {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", longest+1)
	if inTable {
		s = strings.ReplaceAll(s, "|", "\\|")
	}
	if strings.HasPrefix(s, "`") || strings.HasSuffix(s, "`") {
		s = " " + s + " "
	}
	return fence + s + fence
}
