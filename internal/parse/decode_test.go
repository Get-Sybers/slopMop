package parse

import (
	"math/rand/v2"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The options are read by an expression that begins with the hyphen and a
// check of what stands before it. Together they find what one expression
// that reads both finds.
func TestEncodedArgsEqualsOnePass(t *testing.T) {
	whole := regexp.MustCompile(`(?i)(?:^|[\s"'])-(e[a-z]*)\s+['"]?([A-Za-z0-9+/]{16,}={0,2})`)
	payload := "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQ"
	texts := []string{
		"", "-enc " + payload, "x-enc " + payload, " -enc " + payload, "\t-E\n\n'" + payload + "=='",
		"powershell -NoP -EncodedCommand " + payload + "== -enc " + payload, "--enc " + payload, "'-ec " + payload + "\"-e " + payload,
		"-enc " + payload + "-enc " + payload, "-e " + payload[:15], "\v-enc " + payload, "é-enc " + payload, "-Knc " + payload,
	}
	parts := []string{
		"-e", "-enc", "-EncodedCommand", "-", "--", " ", " ", "\n", "\t", "\f", "\r", "\v", "\"", "'", "x", "e", "E", "/", "+", "=", "==",
		payload, payload, "QUJD", "powershell", "é", ".",
	}
	rng := rand.New(rand.NewPCG(5, 6))
	pick := func(from ...string) string {
		// Now and then a part is not what an option has there.
		if rng.IntN(6) == 0 {
			return parts[rng.IntN(len(parts))]
		}
		return from[rng.IntN(len(from))]
	}
	for range 3000 {
		var b strings.Builder
		for n := 1 + rng.IntN(4); n > 0; n-- {
			b.WriteString(pick("", " ", "\n", "\"", "'", "x", "-", "\v") + pick("-e", "-enc", "-EncodedCommand", "-Ec", "-e9"))
			b.WriteString(pick(" ", "\n\t", "  ", "") + pick("", "", "'", "\"") + pick(payload, payload, payload[:16], payload[:15]) + pick("", "=", "==", "==="))
		}
		texts = append(texts, b.String())
	}
	groups := func(found [][]string) []string {
		var all []string
		for _, m := range found {
			all = append(all, m[1], m[2])
		}
		return all
	}
	options := 0
	for _, text := range texts {
		got, want := groups(encodedArgs(text)), groups(whole.FindAllStringSubmatch(text, -1))
		if !slices.Equal(got, want) {
			t.Fatalf("encodedArgs(%q) = %q, one pass gives %q", text, got, want)
		}
		options += len(want) / 2
	}
	if options < 500 {
		t.Errorf("the texts hold %d options: they do not try the reading", options)
	}
}

// A large text is searched for a form only when it holds what the form
// needs, and what is found is what a search without that check finds.
func TestDecodedInALargeText(t *testing.T) {
	filler := strings.Repeat("Get-Process | Sort-Object CPU -Descending | Select-Object -First 5\n", small/60)
	hello := "aGVsbG8gZnJvbSBhIHBheWxvYWQ="
	for _, tt := range []struct {
		name, text string
		want       []Payload
	}{
		{"no payload", filler, nil},
		{"piped", filler + "echo " + hello + " | base64 -d | sh\n" + filler, []Payload{{Text: "hello from a payload", Shell: POSIX}}},
		{"here string", filler + "base64 -d <<< " + hello + "\n", []Payload{{Text: "hello from a payload"}}},
		{"literal", filler + "[Convert]::FromBase64String('" + hello + "')\n", []Payload{{Text: "hello from a payload"}}},
		{"literal in a text that folds", filler + "[Convert]::FromBaſe64String('" + hello + "')\n", []Payload{{Text: "hello from a payload"}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := Decoded(tt.text); !slices.Equal(got, tt.want) {
				t.Errorf("Decoded = %q, want %q", got, tt.want)
			}
		})
	}
}
