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
	Title string
	// Columns name the cells, for the formats that draw a table; the plain
	// text has no header row.
	Columns []string
	Entries []Entry
	// Blocks sets each entry apart as a block, one under another: a timeline.
	// The first cell names the block, and its rows are a table whose columns
	// every block of the group shares; Heads names what each column holds.
	Blocks bool
	Heads  Heads
}

// Heads names the three things a row of a block names, for a format that
// heads its columns.
type Heads [3]string

// Entry is one line of cells and what stands under it: the rows of a block,
// and then the detail lines.
type Entry struct {
	Level  string
	Cells  []string
	Rows   []Row
	Detail []Detail
}

// Row is a line of a block. It names a thing and what follows from it, one
// beside another: a place that names nothing stays empty.
type Row [3]Named

// Named is a thing by its identifier and its name.
type Named struct {
	ID   string
	Name string
	// Kind stands where a thing has no identifier and says what it is, such
	// as tools. Its name is then what the evidence holds.
	Kind string
}

// first is what stands before the name: the identifier, or the kind.
func (n Named) first() string {
	if n.ID != "" {
		return shown(n.ID)
	}
	return shown(n.Kind)
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
	var ids, names [3]int
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
		// Every row of the group has its identifiers and its names in the same columns.
		for _, row := range e.Rows {
			for i, n := range row {
				ids[i] = max(ids[i], utf8.RuneCountInString(n.first()))
				names[i] = min(widest, max(names[i], utf8.RuneCountInString(shown(n.Name))))
			}
		}
	}
	// The labels of a block stand in the column of the first identifiers.
	label, ids[0] = max(label, ids[0]), max(label, ids[0])
	under := indent + strings.Repeat(" ", 2*len(gap))
	named, labelled := "", sgrGrey
	if g.Blocks {
		named, labelled = sgrBold, ""
	}
	for n, e := range g.Entries {
		if g.Blocks && n > 0 {
			p.line()
		}
		parts := []string{indent}
		if marked > 0 {
			glyph, sgr := mark(e.Level)
			parts = append(parts, p.paint(sgr, glyph), strings.Repeat(" ", marked-len(glyph)+1))
		}
		for i, c := range e.Cells {
			c = shown(c)
			if i == 0 {
				parts = append(parts, p.paint(named, c))
			} else {
				parts = append(parts, c)
			}
			// The last cell is not padded, so a line carries no trailing space.
			if i < len(e.Cells)-1 {
				parts = append(parts, strings.Repeat(" ", max(0, widths[i]-utf8.RuneCountInString(c))), gap)
			}
		}
		p.line(parts...)
		for _, row := range e.Rows {
			parts := []string{under}
			for i, n := range row {
				// A column that no row of the group fills takes no room.
				if ids[i] == 0 && names[i] == 0 {
					continue
				}
				id, name := n.first(), shown(n.Name)
				if n.ID == "" {
					id = p.paint(sgrGrey, id)
				}
				parts = append(parts, id, spaces(ids[i], n.first()), gap, name, spaces(names[i], name), gap, gap)
			}
			p.line(parts...)
		}
		last := ""
		for _, d := range e.Detail {
			if d.Text == "" {
				continue
			}
			if d.Label == "" {
				p.line(under, Escape(d.Text))
				last = ""
				continue
			}
			// A label is written once; the lines under it that share it stand in its column.
			name := d.Label
			if name == last {
				name = ""
			}
			last = d.Label
			p.line(under, p.paint(labelled, name), spaces(label, name), gap, Escape(d.Text))
		}
	}
}

// spaces fills a column of a width after the text that stands in it.
func spaces(width int, text string) string {
	return strings.Repeat(" ", max(0, width-utf8.RuneCountInString(text)))
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
