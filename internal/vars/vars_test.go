package vars

import (
	"maps"
	"math/rand/v2"
	"strings"
	"testing"
)

func TestRead(t *testing.T) {
	text := "export A=/tmp/a\nB = \"two words\"\n$c = 'three';\r\nset D=four\nE=$(date)\nF=\nA=/tmp/last\n  G=%TEMP%\\g\n" +
		"USER=\"${AD_USER:-svc_backup}\"\nif [ x = y ]; then\n"
	got := Read(text)
	want := Set{"a": "/tmp/last", "b": "two words", "c": "three", "d": "four", "user": "svc_backup"}
	if !maps.Equal(got, want) {
		t.Errorf("Read = %v, want %v", got, want)
	}
	tests := []struct {
		ref   string
		value string
		ok    bool
	}{
		{"$A", "/tmp/last", true},
		{"${b}", "two words", true},
		{"%D%", "four", true},
		{"${X:-fallback}", "fallback", true},
		{"${X:-}", "", false},
		{"$missing", "", false},
		{"$A/x", "", false},
		{"plain", "", false},
	}
	for _, tt := range tests {
		if value, ok := got.Value(tt.ref); value != tt.value || ok != tt.ok {
			t.Errorf("Value(%q) = %q, %t; want %q, %t", tt.ref, value, ok, tt.value, tt.ok)
		}
	}
	for text, want := range map[string]string{
		"$A/x and ${b}": "/tmp/last/x and two words", "$missing@host": "$missing@host", "plain": "plain", "${c}$d": "threefour",
	} {
		if expanded := got.Expand(text); expanded != want {
			t.Errorf("Expand(%q) = %q, want %q", text, expanded, want)
		}
	}
}

// onePass is Read as one search of the whole text: what the reading by line must equal.
func onePass(text string) Set {
	set := Set{}
	for _, m := range rxAssign.FindAllStringSubmatch(text, -1) {
		value := m[2]
		if d := rxDefault.FindStringSubmatch(value); d != nil {
			value = d[1]
		}
		if value != "" && !strings.ContainsAny(value, "$`%") {
			set[strings.ToLower(m[1])] = value
		}
	}
	return set
}

// Reading only the lines that can be an assignment finds what one pass finds.
func TestReadByLineEqualsOnePass(t *testing.T) {
	texts := []string{
		"", "=", "A=1", "A=1\n", "\nA=1", "A=1\r\nB=2\r", "A=1\rB=2", "a b=1\nc=d=e\n=x\n",
		"export  X = 'q' ;\n\tset Y=z\n$Z=\"v\"\nexportQ=1\n1A=2\nA-B=3\nA.B=4\nif [ $x = y ]\n",
		"URL=https://h/p?a=b&c=d\nK=\"a\"b\"\nL='x\nM=x'\nN=${O:-p}\nP=`cmd`\nQ=%R%\n \t S \t=\t t \t;\t \n",
		"caf\u00e9=1\nA=caf\u00e9\n\u00e9 A=1\nA=1 \u00e9\n",
	}
	parts := []string{
		"=", " ", "\t", "\r", ";", "\"", "'", "$", "%", "`", "export ", "set ", "A", "b_1", "9", "x y",
		"/tmp/a", "${V:-d}", "-", ".", "\u00e9", "",
	}
	rng := rand.New(rand.NewPCG(3, 4))
	pick := func(from ...string) string {
		// Now and then a part is not what an assignment has there.
		if rng.IntN(8) == 0 {
			return parts[rng.IntN(len(parts))]
		}
		return from[rng.IntN(len(from))]
	}
	for range 2000 {
		var b strings.Builder
		for n := 1 + rng.IntN(5); n > 0; n-- {
			quote := pick("", "", "\"", "'")
			b.WriteString(pick("", "", " ", "\t ") + pick("", "", "export ", "set ", "$") + pick("A", "b_1", "Name9") + pick("", " "))
			b.WriteString(pick("=") + pick("", " ") + quote + pick("v", "/tmp/a", "two words", "${V:-d}", "$x", "") + quote)
			b.WriteString(pick("", "", ";", " ; ") + pick("\n", "\n", "\r\n", ""))
		}
		texts = append(texts, b.String())
	}
	set := 0
	for _, text := range texts {
		got, want := Read(text), onePass(text)
		if !maps.Equal(got, want) {
			t.Fatalf("Read(%q) = %v, one pass gives %v", text, got, want)
		}
		set += len(want)
	}
	if set < 500 {
		t.Errorf("the texts set %d variables: they do not try the reading", set)
	}
}
