package parse

import (
	"encoding/base64"
	"regexp"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/get-sybers/slopmop/internal/parallel"
	"github.com/get-sybers/slopmop/internal/sift"
)

const (
	// maxPayload bounds the Base64 text of one payload, and maxPayloads how
	// many a text may yield: evidence is hostile and may be built to exhaust.
	maxPayload  = 1 << 20
	maxPayloads = 32
	// small is the size below which a text is searched on the caller's goroutine.
	small = 16 << 10
)

var (
	// rxEncodedArg begins with its hyphen, a text the engine can look for;
	// encodedArgs checks what stands before the hyphen.
	rxEncodedArg = regexp.MustCompile(`(?i)-(e[a-z]*)\s+['"]?([A-Za-z0-9+/]{16,}={0,2})`)
	rxB64Literal = regexp.MustCompile(`(?i)(?:FromBase64String|b64decode)\(\s*b?['"]([A-Za-z0-9+/]{24,}={0,2})['"]`)
	// rxB64Piped is Base64 text handed to "base64 -d", and the shell it is piped on to, if any.
	rxB64Piped = regexp.MustCompile(`(?:echo|printf)\s+(?:-[neE]+\s+)?['"]?([A-Za-z0-9+/]{16,}={0,2})['"]?\s*\|\s*base64\s+(?:-d|-D|--decode)\b(\s*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b)?`)
	rxB64Here  = regexp.MustCompile(`base64\s+(?:-d|-D|--decode)\s*<<<\s*['"]?([A-Za-z0-9+/]{16,}={0,2})`)
)

// The shells a payload can be a script of.
const (
	PowerShell = "powershell"
	POSIX      = "sh"
)

// Payload is text that a file carries encoded.
type Payload struct {
	Text string
	// Shell is PowerShell when the text was the argument of -EncodedCommand,
	// POSIX when it was decoded and piped into a shell, and empty otherwise.
	Shell string
}

// Decoded returns the readable payloads a text carries: the argument of
// -EncodedCommand, Base64 piped through "base64 -d", and a Base64 literal
// handed to a decoding call. Nothing is run, and what is not text is dropped.
func Decoded(text string) []Payload {
	var payloads []Payload
	add := func(b64, shell string) {
		if len(payloads) >= maxPayloads || len(b64) > maxPayload {
			return
		}
		if decoded, ok := decodeText(b64, shell == PowerShell); ok {
			payloads = append(payloads, Payload{Text: decoded, Shell: shell})
		}
	}
	// The four forms are searched for apart, on every processor when the
	// text is large, and their payloads are taken in the order of the forms.
	forms := []*regexp.Regexp{rxEncodedArg, rxB64Piped, rxB64Here, rxB64Literal}
	found := make([][][]string, len(forms))
	// A form is searched for only in a text that holds what each of its matches holds.
	var lower []byte
	if len(text) >= small && !sift.Folds(text) {
		lower = sift.Lower(text)
	}
	search := func(i int) {
		if lower != nil {
			if plan, err := sift.Read(forms[i].String()); err == nil && !sift.Holds(lower, plan.Needs) {
				return
			}
		}
		if i == 0 {
			found[i] = encodedArgs(text)
			return
		}
		found[i] = forms[i].FindAllStringSubmatch(text, -1)
	}
	if len(text) < small {
		for i := range forms {
			search(i)
		}
	} else {
		parallel.Each(len(forms), search)
	}
	for _, m := range found[0] {
		// PowerShell takes any prefix of -EncodedCommand, and -ec.
		const full = "encodedcommand"
		if flag := strings.ToLower(m[1]); flag == "ec" || (len(flag) <= len(full) && full[:len(flag)] == flag) {
			add(m[2], PowerShell)
		}
	}
	for _, m := range found[1] {
		shell := ""
		if m[2] != "" {
			shell = POSIX
		}
		add(m[1], shell)
	}
	for _, m := range found[2] {
		add(m[1], "")
	}
	for _, m := range found[3] {
		add(m[1], "")
	}
	return payloads
}

// encodedArgs returns each option that begins with -e and the Base64 after
// it: an option stands at the start of the text or after white space or a quote.
func encodedArgs(text string) [][]string {
	var found [][]string
	for _, loc := range rxEncodedArg.FindAllStringSubmatchIndex(text, -1) {
		if at := loc[0]; at == 0 || strings.IndexByte(" \t\n\f\r\"'", text[at-1]) >= 0 {
			found = append(found, []string{text[loc[0]:loc[1]], text[loc[2]:loc[3]], text[loc[4]:loc[5]]})
		}
	}
	return found
}

// decodeText decodes Base64 to text. An encoded command is UTF-16; a
// literal may be UTF-16 or UTF-8.
func decodeText(b64 string, wide bool) (string, bool) {
	raw, err := base64.StdEncoding.DecodeString(b64 + strings.Repeat("=", (4-len(b64)%4)%4))
	if err != nil {
		return "", false
	}
	if s, ok := fromUTF16(raw); ok {
		return s, true
	}
	if !wide && utf8.Valid(raw) && readable(string(raw)) {
		return string(raw), true
	}
	return "", false
}

func fromUTF16(raw []byte) (string, bool) {
	if len(raw) < 2 || len(raw)%2 != 0 {
		return "", false
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	s := string(utf16.Decode(units))
	return s, readable(s)
}

// readable reports whether nearly all of s is printable ASCII or white
// space, which a script is and a binary is not.
func readable(s string) bool {
	if len(s) < 4 {
		return false
	}
	plain := 0
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\t' || (r >= ' ' && r < 0x7f) {
			plain++
		}
	}
	return plain*10 >= utf8.RuneCountInString(s)*9
}
