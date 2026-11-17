package render

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"
)

// The levels an entry or a banner is marked with; the empty level has no mark.
const (
	LevelHigh   = "high"
	LevelMedium = "medium"
	LevelLow    = "low"
	LevelClear  = "clear"
)

// Readout is an analysis written for reading: a title, a banner that gives
// the verdict, sections of entries, and hints on what to run next.
type Readout struct {
	Title    string
	Banner   Banner
	Sections []Section
	Hints    []string
}

// Banner is the one-line verdict under the title; an empty Text omits it.
type Banner struct {
	Level string
	Text  string
}

// Section is a titled part of a readout. A section without entries says so.
type Section struct {
	Title  string
	Note   string
	Groups []Group
}

// Group is a run of entries whose cells are aligned with one another.
type Group struct {
	Title   string
	Entries []Entry
}

// Entry is one line of cells and the detail lines under it.
type Entry struct {
	Level  string
	Cells  []string
	Detail []Detail
}

// Detail is one indented line under an entry; the label may be empty.
type Detail struct {
	Label string
	Text  string
}

const (
	sgrReset  = "\x1b[0m"
	sgrBold   = "\x1b[1m"
	sgrGrey   = "\x1b[90m"
	sgrGreen  = "\x1b[32m"
	sgrYellow = "\x1b[33m"
	sgrRed    = "\x1b[31m"
	sgrCyan   = "\x1b[36m"

	hintArrow = "->"
	gap       = "  "
	// widest is the most a column is padded to; a longer cell runs past it.
	widest = 60
)

// mark is the ASCII glyph of a level and its colour; ASCII keeps the columns aligned.
func mark(level string) (glyph, sgr string) {
	switch level {
	case LevelHigh:
		return "[x]", sgrRed
	case LevelMedium:
		return "[!]", sgrYellow
	case LevelLow:
		return "[i]", sgrGrey
	case LevelClear:
		return "[ok]", sgrGreen
	default:
		return "", ""
	}
}

type pen struct {
	buf    bytes.Buffer
	colour bool
}

func (p *pen) paint(sgr, s string) string {
	if !p.colour || sgr == "" || s == "" {
		return s
	}
	return sgr + s + sgrReset
}

func (p *pen) line(parts ...string) {
	p.buf.WriteString(strings.TrimRight(strings.Join(parts, ""), " "))
	p.buf.WriteByte('\n')
}

// WriteReadout writes r to w as plain lines, in colour when colour is set.
// Every text is escaped here, so a caller cannot pass evidence through raw.
func WriteReadout(w io.Writer, r Readout, colour bool) error {
	p := &pen{colour: colour}
	p.line(p.paint(sgrBold, Escape(r.Title)))
	if r.Banner.Text != "" {
		p.banner(r.Banner)
	}
	if r.marked() {
		p.line(p.paint(sgrGrey, legend()))
	}
	for _, s := range r.Sections {
		p.section(s)
	}
	// A long readout ends on its verdict, where a terminal leaves the reader.
	again := r.Banner.Text != "" && len(r.Sections) > 1
	if again || len(r.Hints) > 0 {
		p.line()
	}
	if again {
		p.banner(r.Banner)
	}
	for _, h := range r.Hints {
		p.line(p.paint(sgrCyan, hintArrow+" "+Escape(h)))
	}
	// One write, so a readout reaches w whole or not at all.
	if _, err := w.Write(p.buf.Bytes()); err != nil {
		return fmt.Errorf("render: write readout: %w", err)
	}
	return nil
}

func (p *pen) banner(b Banner) {
	glyph, sgr := mark(b.Level)
	p.line(p.paint(sgr, strings.TrimSpace(glyph+" "+Escape(b.Text))))
}

// marked reports whether any entry carries a level, so the legend is of use.
func (r Readout) marked() bool {
	for _, s := range r.Sections {
		for _, g := range s.Groups {
			for _, e := range g.Entries {
				if e.Level != "" {
					return true
				}
			}
		}
	}
	return false
}

func legend() string {
	var parts []string
	for _, level := range []string{LevelHigh, LevelMedium, LevelLow} {
		glyph, _ := mark(level)
		parts = append(parts, glyph+" "+level)
	}
	return strings.Join(parts, "   ")
}

func (p *pen) section(s Section) {
	p.line()
	title := p.paint(sgrBold, Escape(s.Title))
	if s.Note != "" {
		title += p.paint(sgrGrey, "   ("+Escape(s.Note)+")")
	}
	p.line(title)
	empty := true
	for _, g := range s.Groups {
		if len(g.Entries) == 0 {
			continue
		}
		empty = false
		indent := gap
		if g.Title != "" {
			p.line(gap, p.paint(sgrGrey, Escape(g.Title)))
			indent += gap
		}
		p.group(g, indent)
	}
	if empty {
		p.line(gap, p.paint(sgrGrey, "none"))
	}
}

func (p *pen) group(g Group, indent string) {
	var widths []int
	marked, label := 0, 0
	for _, e := range g.Entries {
		glyph, _ := mark(e.Level)
		marked = max(marked, len(glyph))
		for i, c := range e.Cells {
			if i == len(widths) {
				widths = append(widths, 0)
			}
			widths[i] = min(widest, max(widths[i], utf8.RuneCountInString(shown(c))))
		}
		for _, d := range e.Detail {
			if d.Text != "" {
				label = max(label, utf8.RuneCountInString(d.Label))
			}
		}
	}
	under := indent + strings.Repeat(" ", 2*len(gap))
	for _, e := range g.Entries {
		parts := []string{indent}
		if marked > 0 {
			glyph, sgr := mark(e.Level)
			parts = append(parts, p.paint(sgr, glyph), strings.Repeat(" ", marked-len(glyph)+1))
		}
		for i, c := range e.Cells {
			c = shown(c)
			parts = append(parts, c)
			// The last cell is not padded, so a line carries no trailing space.
			if i < len(e.Cells)-1 {
				parts = append(parts, strings.Repeat(" ", max(0, widths[i]-utf8.RuneCountInString(c))), gap)
			}
		}
		p.line(parts...)
		last := ""
		for _, d := range e.Detail {
			if d.Text == "" {
				continue
			}
			if d.Label == "" {
				p.line(under, Escape(d.Text))
				continue
			}
			// A label is written once; the lines under it that share it stand in its column.
			name := d.Label
			if name == last {
				name = ""
			}
			last = d.Label
			pad := strings.Repeat(" ", label-utf8.RuneCountInString(name))
			p.line(under, p.paint(sgrGrey, name), pad, gap, Escape(d.Text))
		}
	}
}

// shown escapes a cell; an empty cell stays empty, where Escape quotes it.
func shown(cell string) string {
	if cell == "" {
		return ""
	}
	return Escape(cell)
}

// Stamp writes an instant as the tables do, in loc or in UTC when loc is nil.
func Stamp(t time.Time, loc *time.Location) string {
	return Time(t).cell(style{loc: loc})
}
