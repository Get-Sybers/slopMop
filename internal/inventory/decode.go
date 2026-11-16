package inventory

import (
	"bytes"
	"encoding/binary"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

const sniff = 4096

// decode returns the text of a file with LF newlines, or false for a binary
// file. A byte-order mark decides the encoding; without one a NUL in the
// first 4,096 bytes means binary.
func decode(b []byte) (string, bool) {
	var text string
	switch {
	case bytes.HasPrefix(b, []byte{0xFF, 0xFE, 0x00, 0x00}):
		text = decodeUTF32LE(b[4:])
	case bytes.HasPrefix(b, []byte{0xFF, 0xFE}):
		text = decodeUTF16(b[2:], binary.LittleEndian)
	case bytes.HasPrefix(b, []byte{0xFE, 0xFF}):
		text = decodeUTF16(b[2:], binary.BigEndian)
	case bytes.IndexByte(b[:min(len(b), sniff)], 0) >= 0:
		return "", false
	default:
		text = strings.ToValidUTF8(string(bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})), "�")
	}
	return strings.ReplaceAll(text, "\r\n", "\n"), true
}

func decodeUTF16(b []byte, order binary.ByteOrder) string {
	units := make([]uint16, 0, len(b)/2+1)
	for ; len(b) >= 2; b = b[2:] {
		units = append(units, order.Uint16(b))
	}
	if len(b) == 1 {
		units = append(units, utf8.RuneError)
	}
	return string(utf16.Decode(units))
}

func decodeUTF32LE(b []byte) string {
	var sb strings.Builder
	for ; len(b) >= 4; b = b[4:] {
		r := utf8.RuneError
		if u := binary.LittleEndian.Uint32(b); u <= unicode.MaxRune && utf8.ValidRune(rune(u)) {
			r = rune(u)
		}
		sb.WriteRune(r)
	}
	if len(b) > 0 {
		sb.WriteRune(utf8.RuneError)
	}
	return sb.String()
}

func countLines(text string) int {
	if text == "" {
		return 0
	}
	n := strings.Count(text, "\n")
	if !strings.HasSuffix(text, "\n") {
		n++
	}
	return n
}
