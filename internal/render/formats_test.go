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
			{Entries: []Entry{{Cells: []string{hostile}, Detail: []Detail{{Label: hostile, Text: hostile}, {Text: hostile}}}}},
			{Blocks: true, Heads: Heads{hostile, hostile, hostile}, Entries: []Entry{{
				Level: LevelHigh, Cells: []string{hostile, hostile},
				Rows:   []Row{{{ID: hostile, Name: hostile}, {Kind: hostile, Name: hostile}, {ID: hostile}}},
				Detail: []Detail{{Label: hostile, Text: hostile}, {Text: hostile}},
			}}},
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
	if got, want := strings.Count(page, "&lt;script&gt;alert(1)&lt;/script&gt;"), 28; got != want {
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

// rowed is a block with every kind of row: a technique of two tactics, one
// with an ATLAS technique, a tactic that tools give, and its detail lines.
func rowed() Readout {
	return Readout{Title: "t", Sections: []Section{{Title: "S", Groups: []Group{{
		Blocks: true, Heads: Heads{"technique", "tactic", "ATLAS technique"},
		Entries: []Entry{{
			Level: LevelHigh, Cells: []string{"one"},
			Rows: []Row{
				{{ID: "T1053.005", Name: "first"}, {ID: "TA0002", Name: "Execution"}},
				{{}, {ID: "TA0003", Name: "Persistence"}},
				{{ID: "T1552", Name: "second"}, {ID: "TA0006", Name: "CredentialAccess"}, {ID: "AML.T0055", Name: "third"}},
				{{Kind: "tools", Name: "nmap, id"}, {ID: "TA0007", Name: "Discovery"}},
			},
			Detail: []Detail{{Label: "watchlist", Text: "fourth"}, {Text: "a sentence"}},
		}},
	}}}}}
}

// The rows of a block are lines of six cells, an identifier and a name for
// each of the three things, so every line fills the columns the blocks share.
func TestWriteHTMLLinesOfABlock(t *testing.T) {
	var out bytes.Buffer
	if err := WriteHTML(&out, rowed()); err != nil {
		t.Fatal(err)
	}
	const none = `<span class="id"></span><span class="what"></span>`
	for _, want := range []string{
		`<ol class="blocks marked">`,
		`<li class="heads"><div class="line"><span>technique</span><span>tactic</span><span>ATLAS technique</span></div></li>`,
		`<div class="line"><span class="id">T1053.005</span><span class="what">first</span><span class="id far">TA0002</span><span class="what">Execution</span>` + none + `</div>`,
		`<div class="line"><span class="id"></span><span class="what"></span><span class="id far">TA0003</span><span class="what">Persistence</span>` + none + `</div>`,
		`<div class="line begins"><span class="id">T1552</span><span class="what">second</span><span class="id far">TA0006</span><span class="what">CredentialAccess</span><span class="id">AML.T0055</span><span class="what">third</span></div>`,
		`<div class="line begins"><span class="id kind">tools</span><span class="what">nmap, id</span><span class="id far">TA0007</span><span class="what">Discovery</span>` + none + `</div>`,
		`<div class="line more"><span class="tag">watchlist</span><span class="value">fourth</span></div>`,
		`<div class="line more"><span class="said">a sentence</span></div>`,
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the page lacks %s:\n%s", want, out.String())
		}
	}
	// A group that names no columns has no line of heads.
	bare := rowed()
	bare.Sections[0].Groups[0].Heads = Heads{}
	out.Reset()
	if err := WriteHTML(&out, bare); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), `class="heads"`) {
		t.Errorf("the page heads columns that have no name:\n%s", out.String())
	}
}

// Markdown writes a row as an item: the thing it names and what follows from
// it, with the rows after it that name no thing of their own.
func TestWriteMarkdownListsRows(t *testing.T) {
	var out bytes.Buffer
	if err := WriteMarkdown(&out, rowed()); err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{"# t", "", "\\[x\\] high   \\[!\\] medium   \\[i\\] low", "", "## S", "",
		"- **\\[x\\] high** · `one`",
		"  - `T1053.005  first` · `TA0002  Execution` · `TA0003  Persistence`",
		"  - `T1552  second` · `TA0006  CredentialAccess` · `AML.T0055  third`",
		"  - tools `nmap, id` · `TA0007  Discovery`",
		"  - **watchlist:** `fourth`",
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
