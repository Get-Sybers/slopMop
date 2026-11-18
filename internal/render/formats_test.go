package render

import (
	"bytes"
	"errors"
	"io"
	"regexp"
	"strings"
	"testing"

	"github.com/get-sybers/slopmop/internal/golden"
)

func TestWriteMarkdown(t *testing.T) {
	var out bytes.Buffer
	if err := WriteMarkdown(&out, sampleReadout()); err != nil {
		t.Fatal(err)
	}
	golden.Check(t, "readout-markdown", out.Bytes())
}

func TestWriteHTML(t *testing.T) {
	var out bytes.Buffer
	if err := WriteHTML(&out, sampleReadout()); err != nil {
		t.Fatal(err)
	}
	golden.Check(t, "readout-html", out.Bytes())
}

// hostileReadout carries one text in every place a readout has.
func hostileReadout(hostile string) Readout {
	return Readout{
		Title:  hostile,
		Banner: Banner{Level: LevelHigh, Text: hostile},
		Sections: []Section{{Title: hostile, Note: hostile, Groups: []Group{
			{Title: hostile, Columns: []string{hostile}, Entries: []Entry{{Level: LevelHigh, Cells: []string{hostile, hostile}}}},
			{Entries: []Entry{{Cells: []string{hostile}, Detail: []Detail{{Label: hostile, Note: hostile, Key: hostile, Text: hostile}, {Text: hostile}}}}},
			{Blocks: true, Entries: []Entry{{Level: LevelHigh, Cells: []string{hostile, hostile}, Detail: []Detail{
				{Label: hostile, Note: hostile, Key: hostile, Text: hostile}, {Label: hostile, Text: hostile, None: true}, {Text: hostile},
			}}}},
		}}},
		Hints: []string{hostile},
	}
}

// A value in a code span is shown as written, whatever it holds: the fence
// outruns its backticks, and a pipe does not end a table cell.
func TestMarkdownCodeSpan(t *testing.T) {
	for _, tt := range []struct {
		name, value string
		inTable     bool
		want        string
	}{
		{"plain", "curl -s http://198.51.100.7/a", false, "`curl -s http://198.51.100.7/a`"},
		{"empty", "", true, ""},
		{"markup", "<b>*x*</b> [a](http://b.example)", false, "`<b>*x*</b> [a](http://b.example)`"},
		{"backtick", "echo `id`", false, "`` echo `id` ``"},
		{"backticks", "a``b`c", false, "```a``b`c```"},
		{"leading backtick", "`id` x", false, "`` `id` x ``"},
		{"pipe in a list", "ps | grep x", false, "`ps | grep x`"},
		{"pipe in a table", "ps | grep x", true, "`ps \\| grep x`"},
		{"line break", "a\nb", false, "`\"a\\nb\"`"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := mdCode(tt.value, tt.inTable); got != tt.want {
				t.Errorf("mdCode(%q) = %s, want %s", tt.value, got, tt.want)
			}
		})
	}
}

// A title or a sentence is plain text: nothing in it is read as markup.
func TestMarkdownText(t *testing.T) {
	for _, tt := range []struct{ name, value, want string }{
		{"plain", "Impact (3)", "Impact (3)"},
		{"empty", "", ""},
		{"mark", "[x] high", "\\[x\\] high"},
		{"markup", "<b>*x*_y_`z`</b>", "\\<b\\>\\*x\\*\\_y\\_\\`z\\`\\</b\\>"},
		{"entity", "a &lt; b", "a &amp;lt; b"},
		{"table and heading", "a | b # c ~d~", "a \\| b \\# c \\~d\\~"},
		{"backslash", `C:\Users`, `C:\\Users`},
		{"line break", "a\nb", "\"a\\\\nb\""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := mdText(tt.value); got != tt.want {
				t.Errorf("mdText(%q) = %s, want %s", tt.value, got, tt.want)
			}
		})
	}
}

// Evidence cannot add a line, a control character or markup of its own.
func TestWriteMarkdownEscapesEvidence(t *testing.T) {
	plain := hostileReadout("x")
	var want bytes.Buffer
	if err := WriteMarkdown(&want, plain); err != nil {
		t.Fatal(err)
	}
	hostile := "x\x1b[2J\n# <script>alert(1)</script> | `y` [z](http://a.example)"
	var out bytes.Buffer
	if err := WriteMarkdown(&out, hostileReadout(hostile)); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(out.String(), '\x1b') {
		t.Errorf("an escape character reached the output: %q", out.String())
	}
	if got, want := strings.Count(out.String(), "\n"), strings.Count(want.String(), "\n"); got != want {
		t.Errorf("%d lines, want %d: a line break in a text split a line\n%s", got, want, out.String())
	}
	// Outside a code span, no character Markdown acts on is left unescaped.
	spans := regexp.MustCompile("``.*?``|`[^`]*`|\\\\.")
	for _, line := range strings.Split(out.String(), "\n") {
		outside := spans.ReplaceAllString(line, "")
		if strings.ContainsAny(outside, "<>[]`") {
			t.Errorf("markup is left in the line %q", line)
		}
	}
}

// A browser is given the evidence as text, and nothing to load or to run.
func TestWriteHTMLEscapesEvidence(t *testing.T) {
	hostile := "x\x1b[2J\n\"><script>alert(1)</script><img src=x onerror=alert(1)> <a href='http://a.example'>y</a> &amp;"
	var out bytes.Buffer
	if err := WriteHTML(&out, hostileReadout(hostile)); err != nil {
		t.Fatal(err)
	}
	page := out.String()
	if strings.ContainsRune(page, '\x1b') {
		t.Errorf("an escape character reached the page")
	}
	for _, raw := range []string{"<script", "<img", "<a href='", "onerror=alert(1)>"} {
		if strings.Contains(page, raw) {
			t.Errorf("the page holds %q as markup:\n%s", raw, page)
		}
	}
	if got, want := strings.Count(page, "&lt;script&gt;alert(1)&lt;/script&gt;"), 26; got != want {
		t.Errorf("the text is on the page %d times, want %d:\n%s", got, want, page)
	}
}

// The page stands alone: it has a policy that loads nothing, and no script,
// link out, image or form of its own.
func TestWriteHTMLStandsAlone(t *testing.T) {
	var out bytes.Buffer
	if err := WriteHTML(&out, sampleReadout()); err != nil {
		t.Fatal(err)
	}
	page := out.String()
	if policy := `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">`; !strings.Contains(page, policy) {
		t.Errorf("the page does not carry its policy:\n%s", page)
	}
	for _, loads := range []string{"<script", "<link", "<img", "<iframe", "<form", "src=", "http://", "https://", "url(", "@import"} {
		if strings.Contains(page, loads) {
			t.Errorf("the page holds %q", loads)
		}
	}
	if !strings.HasPrefix(page, "<!doctype html>\n") || !strings.HasSuffix(page, "</html>\n") {
		t.Errorf("the page is not one whole document")
	}
}

// A label is written once on the page, as in the plain text.
func TestWriteHTMLSharesALabel(t *testing.T) {
	r := Readout{Title: "t", Sections: []Section{{Title: "S", Groups: []Group{{Entries: []Entry{{
		Cells:  []string{"entry"},
		Detail: []Detail{{Text: "a sentence"}, {Label: "what", Text: "first"}, {Label: "what", Text: "second"}, {Label: "what"}},
	}}}}}}}
	var out bytes.Buffer
	if err := WriteHTML(&out, r); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"<p>a sentence</p>", `<span class="label">what</span><span class="value">first</span>`, `<span class="label"></span><span class="value">second</span>`} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the page lacks %s:\n%s", want, out.String())
		}
	}
	if got := strings.Count(out.String(), `class="value"`); got != 2 {
		t.Errorf("%d labelled lines, want 2: an empty detail is left out", got)
	}
}

// keyed holds every kind of line a detail has: two that share a label and
// its note, one that says nothing was found, one with no key, and a sentence.
func keyed(blocks bool) Readout {
	return Readout{Title: "t", Sections: []Section{{Title: "S", Groups: []Group{{Blocks: blocks, Entries: []Entry{{
		Level: LevelHigh, Cells: []string{"one"},
		Detail: []Detail{
			{Label: "Discovery", Note: "TA0007", Key: "T1083", Text: "first"},
			{Label: "Discovery", Note: "TA0007", Key: "AML.T0075", Text: "second"},
			{Label: "Exfiltration", Note: "TA0010", Text: "none found", None: true},
			{Label: "watchlist", Text: "third"},
			{Text: "a sentence"},
		},
	}}}}}}}
}

// The lines of a block are cells of the columns its group shares: a label
// and its note once, a key before its text, a text with no key across both.
func TestWriteHTMLLinesOfABlock(t *testing.T) {
	var out bytes.Buffer
	if err := WriteHTML(&out, keyed(true)); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`<ol class="blocks marked">`,
		`<div class="line"><span class="of"><span class="topic">Discovery</span><span class="aside">TA0007</span></span><span class="key">T1083</span><span class="text">first</span></div>`,
		`<div class="line"><span class="key">AML.T0075</span><span class="text">second</span></div>`,
		`<div class="line begins"><span class="of"><span class="topic">Exfiltration</span><span class="aside">TA0010</span></span><span class="text wide none">none found</span></div>`,
		`<div class="line begins"><span class="of"><span class="topic">watchlist</span></span><span class="text wide">third</span></div>`,
		`<div class="line begins"><span class="said">a sentence</span></div>`,
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the page lacks %s:\n%s", want, out.String())
		}
	}
	// A table has a label and a value for a line, so each takes what stands beside it.
	out.Reset()
	if err := WriteHTML(&out, keyed(false)); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`<span class="label">Discovery (TA0007)</span><span class="value">T1083  first</span>`,
		`<span class="label"></span><span class="value">AML.T0075  second</span>`,
		`<span class="label">Exfiltration (TA0010)</span><span class="value">none found</span>`,
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the page lacks %s:\n%s", want, out.String())
		}
	}
}

// Markdown lists the lines that have a key under their label, written once,
// and fills the keys to one width; a text that says nothing was found is plain.
func TestWriteMarkdownListsKeyedLines(t *testing.T) {
	var out bytes.Buffer
	if err := WriteMarkdown(&out, keyed(true)); err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{"# t", "", "\\[x\\] high   \\[!\\] medium   \\[i\\] low", "", "## S", "",
		"- **\\[x\\] high** · `one`",
		"  - **Discovery (TA0007):**",
		"    - `T1083      first`",
		"    - `AML.T0075  second`",
		"  - **Exfiltration (TA0010):** none found",
		"  - **watchlist:** `third`",
		"  - a sentence",
		"",
	}, "\n")
	if out.String() != want {
		t.Errorf("markdown =\n%s\nwant\n%s", out.String(), want)
	}
}

// A section without entries says so in every format, and a table without
// column names still has the header row Markdown needs.
func TestFormatsPlainParts(t *testing.T) {
	r := Readout{Title: "t", Sections: []Section{
		{Title: "Empty", Groups: []Group{{Title: "g"}}},
		{Title: "Bare", Groups: []Group{{Entries: []Entry{{Cells: []string{"a", "b"}}, {Cells: []string{"c"}}}}}},
	}}
	var md, page bytes.Buffer
	if err := WriteMarkdown(&md, r); err != nil {
		t.Fatal(err)
	}
	want := "# t\n\n## Empty\n\nNone.\n\n## Bare\n\n|   |   |\n| --- | --- |\n| `a` | `b` |\n| `c` |  |\n"
	if md.String() != want {
		t.Errorf("markdown = %q, want %q", md.String(), want)
	}
	if err := WriteHTML(&page, r); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`<p class="none">none</p>`, `<td class="cell">c</td><td class="cell"></td>`} {
		if !strings.Contains(page.String(), want) {
			t.Errorf("the page lacks %s:\n%s", want, page.String())
		}
	}
	if strings.Contains(page.String(), "<thead>") || strings.Contains(page.String(), "<h3>") {
		t.Errorf("the page has a header or a group title nothing gave it:\n%s", page.String())
	}
}

type failing struct{}

func (failing) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestFormatsReportAFailedWrite(t *testing.T) {
	for name, write := range map[string]func(io.Writer, Readout) error{"markdown": WriteMarkdown, "html": WriteHTML} {
		if err := write(failing{}, sampleReadout()); err == nil || !strings.Contains(err.Error(), "disk full") {
			t.Errorf("%s: err = %v, want the failed write", name, err)
		}
	}
}
