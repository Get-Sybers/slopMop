package render

import (
	"strconv"
	"unicode/utf8"
)

// Escape returns s unchanged when it is safe to print as one cell, and quoted otherwise.
func Escape(s string) string {
	if plain(s) {
		return s
	}
	return strconv.Quote(s)
}

// plain keeps a leading double quote for quoted text alone, so the two forms cannot be confused.
func plain(s string) bool {
	if s == "" || s[0] == '"' || s[0] == ' ' || s[len(s)-1] == ' ' || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !strconv.IsPrint(r) {
			return false
		}
	}
	return true
}
