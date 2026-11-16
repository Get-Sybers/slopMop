package parse

import (
	"encoding/base64"
	"regexp"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	// maxPayload bounds the Base64 text of one payload, and maxPayloads how
	// many a text may yield: evidence is hostile and may be built to exhaust.
	maxPayload  = 1 << 20
	maxPayloads = 32
)

var (
	rxEncodedArg = regexp.MustCompile(`(?i)(?:^|[\s"'])-(e[a-z]*)\s+['"]?([A-Za-z0-9+/]{16,}={0,2})`)
	rxB64Literal = regexp.MustCompile(`(?i)FromBase64String\(\s*['"]([A-Za-z0-9+/]{24,}={0,2})['"]`)
)

// Payload is text that a file carries encoded.
type Payload struct {
	Text string
	// Script is set when the text is a PowerShell command: it was the
	// argument of -EncodedCommand.
	Script bool
}

// Decoded returns the readable payloads a text carries: the argument of a
// PowerShell -EncodedCommand, and a Base64 literal handed to
// FromBase64String. Nothing is run; a payload that is not text is dropped.
func Decoded(text string) []Payload {
	var payloads []Payload
	add := func(b64 string, script bool) {
		if len(payloads) >= maxPayloads || len(b64) > maxPayload {
			return
		}
		if decoded, ok := decodeText(b64, script); ok {
			payloads = append(payloads, Payload{Text: decoded, Script: script})
		}
	}
	for _, m := range rxEncodedArg.FindAllStringSubmatch(text, -1) {
		// PowerShell takes any prefix of -EncodedCommand, and -ec.
		const full = "encodedcommand"
		if flag := strings.ToLower(m[1]); flag == "ec" || (len(flag) <= len(full) && full[:len(flag)] == flag) {
			add(m[2], true)
		}
	}
	for _, m := range rxB64Literal.FindAllStringSubmatch(text, -1) {
		add(m[1], false)
	}
	return payloads
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
