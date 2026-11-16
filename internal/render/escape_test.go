package render_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/get-sybers/slopmop/internal/render"
)

func TestEscape(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain word", "passwd", "passwd"},
		{"interior space", "report final.docx", "report final.docx"},
		{"windows path", `C:\Windows\System32\config\SAM`, `C:\Windows\System32\config\SAM`},
		{"backslash", `a\tb`, `a\tb`},
		{"lone backslash", `\`, `\`},
		{"interior quote", `say "cheese"`, `say "cheese"`},
		{"trailing quote", `inch 5"`, `inch 5"`},
		{"accented", "résumé.pdf", "résumé.pdf"},
		{"cjk", "証拠.txt", "証拠.txt"},
		{"emoji", "🔥", "🔥"},
		{"replacement character", "\ufffd", "\ufffd"},
		{"empty", "", `""`},
		{"leading quote", `"quoted"`, `"\"quoted\""`},
		{"lone quote", `"`, `"\""`},
		{"leading space", " x", `" x"`},
		{"trailing space", "x ", `"x "`},
		{"only a space", " ", `" "`},
		{"esc", "\x1b[31mred\x1b[0m", `"\x1b[31mred\x1b[0m"`},
		{"newline", "one\ntwo", `"one\ntwo"`},
		{"carriage return", "one\rtwo", `"one\rtwo"`},
		{"tab", "a\tb", `"a\tb"`},
		{"vertical tab", "a\vb", `"a\vb"`},
		{"form feed", "a\fb", `"a\fb"`},
		{"nul", "a\x00b", `"a\x00b"`},
		{"bell", "\a", `"\a"`},
		{"del", "a\x7fb", `"a\x7fb"`},
		{"c1 control", "a\u009bb", `"a\u009bb"`},
		{"next line", "a\u0085b", `"a\u0085b"`},
		{"bidi override", "txt.\u202egpj", `"txt.\u202egpj"`},
		{"bidi isolate", "\u2066x\u2069", `"\u2066x\u2069"`},
		{"zero width space", "a\u200bb", `"a\u200bb"`},
		{"no-break space", "a\u00a0b", `"a\u00a0b"`},
		{"line separator", "a\u2028b", `"a\u2028b"`},
		{"byte order mark", "\ufeffx", `"\ufeffx"`},
		{"private use", "\ue000", `"\ue000"`},
		{"tag character", "a\U000e0041", `"a\U000e0041"`},
		{"0xff byte", "a\xffb", `"a\xffb"`},
		{"only 0xff", "\xff", `"\xff"`},
		{"truncated rune", "caf\xc3", `"caf\xc3"`},
		{"encoded surrogate", "\xed\xa0\x80", `"\xed\xa0\x80"`},
		{"overlong slash", "\xc0\xaf", `"\xc0\xaf"`},
		{"quote and backslash when quoted", "a\"b\\c\n", `"a\"b\\c\n"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := render.Escape(tt.in); got != tt.want {
				t.Errorf("Escape(%q) = %s, want %s", tt.in, got, tt.want)
			}
		})
	}
}

// A leading double quote marks quoted text and nothing else, so the reader can undo Escape.
func TestEscapeCanBeUndone(t *testing.T) {
	for _, group := range hostile() {
		t.Run(group.name, func(t *testing.T) {
			for _, in := range group.values {
				got := render.Escape(in)
				back := got
				if strings.HasPrefix(got, `"`) {
					var err error
					if back, err = strconv.Unquote(got); err != nil {
						t.Errorf("Escape(%q) = %s, which does not unquote: %v", in, got, err)
						continue
					}
				}
				if back != in {
					t.Errorf("Escape(%q) = %s, which reads back as %q", in, got, back)
				}
			}
		})
	}
}
