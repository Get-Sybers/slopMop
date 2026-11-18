package sift_test

import (
	"math/rand/v2"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/get-sybers/slopmop/internal/sift"
)

func read(t *testing.T, expr string) sift.Plan {
	t.Helper()
	plan, err := sift.Read(expr)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestReadRejects(t *testing.T) {
	if _, err := sift.Read(`a(b`); err == nil || !strings.HasPrefix(err.Error(), "sift: ") {
		t.Errorf("error = %v, want one that says the expression does not parse", err)
	}
}

// The texts an expression needs are read from its literals, in lower case:
// all of a sequence, and one of each branch of a choice.
func TestNeeds(t *testing.T) {
	for _, tt := range []struct {
		expr string
		want [][]string
		rare []string
	}{
		{`(?i)(?:https?|ftps?)://[^\s]+`, [][]string{{"http", "ftp"}, {"://"}}, []string{"http", "ftp"}},
		{`(?i)[a-z0-9]+@(?:[a-z0-9\-]+\.)+[a-z]{2,24}`, [][]string{{"@"}, {"."}}, nil},
		{`eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}`, [][]string{{"eyj"}, {".eyj"}}, []string{".eyj"}},
		{`-----BEGIN [A-Z ]*PRIVATE KEY-----`, [][]string{{"-----begin "}, {"private key-----"}}, []string{"private key-----"}},
		{`(?i)\bCVE-\d{4}-\d{4,7}\b`, [][]string{{"cve-"}, {"-"}}, []string{"cve-"}},
		{`(?:AKIA|ASIA)[A-Z0-9]{16}`, [][]string{{"a"}, {"kia", "sia"}}, []string{"kia", "sia"}},
		{`a=1|b=2`, [][]string{{"a=1", "b=2"}}, []string{"a=1", "b=2"}},
		{`key=(?:x|y)?value`, [][]string{{"key="}, {"value"}}, []string{"value"}},
		{`(?:ab){2,}c`, [][]string{{"ab"}, {"c"}}, nil},
		{`(?:ab){0,2}c`, [][]string{{"c"}}, nil},
		{`(?:ab)*c+`, [][]string{{"c"}}, nil},
		{`(?i)\b[a-f0-9]{64}\b`, nil, nil},
		{`a|[0-9]`, nil, nil},
		{`(?:[A-Za-z0-9+/]{4}){16,}`, nil, nil},
		{`caf\x{e9} cr\x{e8}me`, [][]string{{"caf"}, {" cr"}, {"me"}}, []string{"caf"}},
		{`(?i)-(?:EncodedCommand|enc)\s+[A-Za-z0-9+/=]{20,}`, [][]string{{"-enc"}}, []string{"-enc"}},
		{`x(?i)yz\d`, [][]string{{"xyz"}}, []string{"xyz"}},
		{`foo\bbar`, [][]string{{"foo"}, {"bar"}}, []string{"foo"}},
	} {
		plan := read(t, tt.expr)
		if !slices.EqualFunc(plan.Needs, tt.want, slices.Equal[[]string]) {
			t.Errorf("%s needs %q, want %q", tt.expr, plan.Needs, tt.want)
		}
		if got := plan.Rare(); !slices.Equal(got, tt.rare) {
			t.Errorf("%s is found by %q, want %q", tt.expr, got, tt.rare)
		}
	}
}

func TestInLine(t *testing.T) {
	for _, tt := range []struct {
		expr string
		want bool
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
		if got := read(t, tt.expr).InLine; got != tt.want {
			t.Errorf("%s in a line = %t, want %t", tt.expr, got, tt.want)
		}
	}
}

// The shape of an expression is the bytes its matches are made of and the
// fewest a match has; an expression that takes any byte has none.
func TestShape(t *testing.T) {
	for _, tt := range []struct {
		expr   string
		shaped bool
		least  int
		in     string
		out    string
	}{
		{`\b[a-f0-9]{32}\b`, true, 32, "09af", "gA-\x80"},
		{`(?i)\b[a-f0-9]{8}-[a-f0-9]{4}\b`, true, 13, "09afAF-", "g.\x80"},
		{`\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d\d?)?\b`, true, 7, "0123456789./", "a-:"},
		{`(?i)[a-z]+\.(?:com|io)`, true, 4, "azAZ.\x80\xff", "0-"},
		{`(?i)https?://[^\s'"]+`, true, 8, "h:/a\x80", " \t\n'\""},
		{`caf\x{e9}`, true, 4, "caf\xc3\xa9\xff", "e"},
		{`\bcurl\b.*\|\s*sh\b`, false, 7, "", ""},
		{`(?s)a.b`, false, 3, "", ""},
		{`[^\n]+`, false, 1, "", ""},
	} {
		plan := read(t, tt.expr)
		if plan.Shaped != tt.shaped || plan.Least != tt.least {
			t.Errorf("%s: shaped %t with at least %d bytes, want %t with %d", tt.expr, plan.Shaped, plan.Least, tt.shaped, tt.least)
		}
		for i := range len(tt.in) {
			if !plan.Made[tt.in[i]] {
				t.Errorf("%s: a match cannot hold %q, want it can", tt.expr, tt.in[i])
			}
		}
		for i := range len(tt.out) {
			if plan.Made[tt.out[i]] {
				t.Errorf("%s: a match can hold %q, want it cannot", tt.expr, tt.out[i])
			}
		}
	}
}

// What a plan promises holds of every match the expression finds.
func TestPlanHoldsOfEveryMatch(t *testing.T) {
	text := strings.Join([]string{
		"GET https://Graph.Microsoft.com/v1.0/users?$top=5 from 10.20.30.40/24, then 1.2.3.4.",
		"mail OPS@Corp.Example.COM cc bob@example.org; CVE-2026-12345 and cve-2024-0001",
		"d41d8cd98f00b204e9800998ecf8427e D41D8CD98F00B204E9800998ECF8427E 0123456789abcdef0123456789ABCDEF01234567",
		"guid 6F9619FF-8B86-D011-B42D-00C04FC964FF key AKIAIOSFODNN7EXAMPLE caf\u00e9.example.com",
		"powershell -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQ== | curl x | sh",
	}, "\n")
	lower := sift.Lower(text)
	for _, expr := range []string{
		`(?i)(?:https?|ftps?)://[^\s'"<>]+`,
		`\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:/(?:3[0-2]|[12]?\d))?\b`,
		`(?i)[a-z0-9][a-z0-9._%+\-]{0,63}@(?:[a-z0-9\-]+\.)+[a-z]{2,24}`,
		`(?i)\bCVE-\d{4}-\d{4,7}\b`,
		`(?i)\b[a-f0-9]{32}\b`,
		`(?i)\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b`,
		`(?:AKIA|ASIA)[A-Z0-9]{16}`,
		`(?i)(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org)\b`,
		`(?i)-(?:EncodedCommand|enc)\s+[A-Za-z0-9+/=]{20,}`,
		`(?i)\b(?:curl|wget)\b.*\|\s*sh\b`,
	} {
		plan := read(t, expr)
		found := regexp.MustCompile(expr).FindAllStringIndex(text, -1)
		if len(found) == 0 {
			t.Errorf("%s matches nothing: the text does not try it", expr)
		}
		for _, loc := range found {
			match := text[loc[0]:loc[1]]
			if !sift.Holds(lower[loc[0]:loc[1]], plan.Needs) {
				t.Errorf("%s: the match %q holds no text of one of %q", expr, match, plan.Needs)
			}
			if len(match) < plan.Least {
				t.Errorf("%s: the match %q is shorter than %d bytes", expr, match, plan.Least)
			}
			for i := 0; plan.Shaped && i < len(match); i++ {
				if !plan.Made[match[i]] {
					t.Errorf("%s: the match %q holds %q, which no match is made of", expr, match, match[i])
				}
			}
		}
	}
}

func TestLower(t *testing.T) {
	text := "AZaz09 \u00c9\u212a\n"
	if got, want := string(sift.Lower(text)), "azaz09 \u00c9\u212a\n"; got != want {
		t.Errorf("Lower(%q) = %q, want %q", text, got, want)
	}
}

func TestHolds(t *testing.T) {
	lower := []byte("curl -s http://x | sh")
	for _, tt := range []struct {
		sets [][]string
		want bool
	}{
		{nil, true},
		{[][]string{{"curl", "wget"}}, true},
		{[][]string{{"wget", "fetch"}}, false},
		{[][]string{{"curl"}, {"|"}}, true},
		{[][]string{{"curl"}, {"tee"}}, false},
	} {
		if got := sift.Holds(lower, tt.sets); got != tt.want {
			t.Errorf("Holds(%q) = %t, want %t", tt.sets, got, tt.want)
		}
	}
}

// Folds knows every rune outside ASCII that folds to a letter of ASCII: an
// expression that ignores case matches such a rune where a text in lower
// case does not hold the letter.
func TestFoldsKnowsEveryRune(t *testing.T) {
	var outside []rune
	for r := rune(utf8.RuneSelf); r <= unicode.MaxRune; r++ {
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < utf8.RuneSelf {
				outside = append(outside, r)
				break
			}
		}
	}
	for _, r := range outside {
		if !sift.Folds("a" + string(r) + "b") {
			t.Errorf("Folds does not know %U, which folds to a letter of ASCII", r)
		}
	}
	if len(outside) == 0 {
		t.Error("no rune outside ASCII folds to a letter of ASCII: the test tries nothing")
	}
	for _, text := range []string{"", "plain ASCII", "caf\u00e9 \u00df \u0130 \u0131"} {
		if sift.Folds(text) {
			t.Errorf("Folds(%q) is true, want false", text)
		}
	}
	// The expression matches the Kelvin sign as k, and the text in lower case holds no k.
	if text := "\u212aubectl"; !regexp.MustCompile(`(?i)kubectl`).MatchString(text) || !sift.Folds(text) {
		t.Errorf("%q: the expression and Folds must both take the Kelvin sign for k", text)
	}
}

func TestNewFinderRejects(t *testing.T) {
	for _, texts := range [][]string{{"curl", "ab"}, {"a\nbc"}, {""}} {
		if _, err := sift.NewFinder(texts); err == nil {
			t.Errorf("NewFinder(%q) gives no error, want one for a text that is short or holds a line break", texts)
		}
	}
}

// One pass for every text finds the lines a search for each text finds.
func TestFinderEqualsASearchForEach(t *testing.T) {
	texts := []string{
		"curl", "cur", "url", "wget", "systemctl", "://", "aaa", "aa a", `\currentversion\run`, "-enc", "café", "é x", "xyz",
	}
	finder, err := sift.NewFinder(texts)
	if err != nil {
		t.Fatal(err)
	}
	parts := []string{
		"curl", "cur", "url", "wget", "system", "ctl", "://", "a", "aa", " ", " ", "\n", "\n", "\r\n", `\currentversion`, `\run`, "-en", "c",
		"caf", "é", "x", "y", "z", "CURL", "\t",
	}
	rng := rand.New(rand.NewPCG(11, 12))
	held := 0
	for n := range 600 {
		var b strings.Builder
		for size := rng.IntN(60 + n); size > 0; size-- {
			b.WriteString(parts[rng.IntN(len(parts))])
		}
		text := b.String()
		lower := sift.Lower(text)
		want := make([][]int, len(texts))
		at := 0
		for line := range strings.SplitSeq(string(lower), "\n") {
			for i, need := range texts {
				if strings.Contains(line, need) {
					want[i] = append(want[i], at)
					held++
				}
			}
			at += len(line) + 1
		}
		if got := finder.Lines(lower); !slices.EqualFunc(got, want, slices.Equal[[]int]) {
			t.Fatalf("Lines(%q) = %v, a search for each text gives %v", text, got, want)
		}
	}
	if held < 2000 {
		t.Errorf("the texts are held %d times: the texts do not try the finder", held)
	}
}

func TestBackwardsRejects(t *testing.T) {
	if _, err := sift.Backwards(`(`); err == nil || !strings.HasPrefix(err.Error(), "sift: ") {
		t.Errorf("Backwards of a broken expression gives %v, want an error of sift", err)
	}
}

func TestTurned(t *testing.T) {
	tests := []struct{ name, text, want string }{
		{"nothing", "", ""},
		{"letters", "abc", "cba"},
		{"runes of several bytes", "aé日z", "z日éa"},
		{"a byte that is no rune", "a\xffb", "b�a"},
		{"a rune cut short", "\x82\xacok", "ko��"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(sift.Turned([]byte("kept:"), tt.text)); got != "kept:"+tt.want {
				t.Errorf("Turned(%q) = %q, want %q after what was there", tt.text, got, tt.want)
			}
		})
	}
}

// An expression turned round finds, at the start of a text turned round,
// exactly what the expression finds at the end of the text.
func TestBackwardsEqualsTheEndOfTheText(t *testing.T) {
	exprs := []string{
		`abc`, `a|bc`, `ab*c+d?`, `(?i:versions?|\bver\.?|\bbuild)[\s:=_-]*`, `\d\.|[\^~]|[A-Za-z]-`,
		`(ab|a)(c|bc)`, `a{2,3}b{0,2}`, `\bab\b`, `\Bb`, `^ab`, `ab$`, `(?m)^b|a$`, `\Aab|ab\z`,
		`[^a]b`, `.b`, `(?s).b`, `a.*?b`, `é日|日a`, `(?i)K|s\b`, `(?:==|>=|<=|~=)\s*`, `ax*`,
		`\d\.|(?i:versions?|\bver\.?|\bbuild)[\s:=_"'()\[\]<>,#/-]*|(?i:chrome|edg|browser)/|(?:==|>=)\s*|[\^~]|[A-Za-z]-`,
	}
	parts := []string{
		"a", "a", "a", "b", "b", "b", "c", "c", "ab", "bc", "abc",
		"d", "A", "B", "x", " ", "\n", "\t", ".", "-", "=", "==", ">=", "^", "~", "/", ":", "_", "0", "7",
		"ver", "Version", "build", "Chrome", "s", "K", "é", "日", "K", "ſ", "\xff", "\xe2\x82", "\x82",
	}
	rng := rand.New(rand.NewPCG(5, 8))
	for _, expr := range exprs {
		turned, err := sift.Backwards(expr)
		if err != nil {
			t.Fatalf("Backwards(%q): %v", expr, err)
		}
		forwards, backwards := regexp.MustCompile(`(?:`+expr+`)\z`), regexp.MustCompile(`\A(?:`+turned+`)`)
		matched := 0
		for range 2000 {
			var b strings.Builder
			for n := rng.IntN(6); n > 0; n-- {
				b.WriteString(parts[rng.IntN(len(parts))])
			}
			text := b.String()
			want := forwards.MatchString(text)
			if want {
				matched++
			}
			if got := backwards.Match(sift.Turned(nil, text)); got != want {
				t.Fatalf("%q turned is %q: on %q it finds %v, and the expression finds %v at the end", expr, turned, text, got, want)
			}
		}
		if matched == 0 || matched == 2000 {
			t.Errorf("%q matches %d of 2000 texts: the texts do not try it", expr, matched)
		}
	}
}
