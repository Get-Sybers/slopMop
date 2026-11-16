package parse

import "strings"

const maxText = 200

func truncate(s string) string {
	if len(s) <= maxText {
		return s
	}
	return s[:maxText]
}

func stripQuotes(s string) string {
	if len(s) >= 2 {
		if (s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// BaseName is the part of a path after its last slash or backslash. Evidence
// may use either separator, and the answer must not depend on the operating
// system that reads it, which filepath.Base would.
func BaseName(path string) string {
	path = strings.TrimRight(path, `/\`)
	if i := strings.LastIndexAny(path, `/\`); i >= 0 {
		return path[i+1:]
	}
	return path
}

func looksLikeFile(s string) bool {
	if s == "" || strings.HasPrefix(s, "-") || strings.HasPrefix(s, "$") {
		return false
	}
	return strings.Contains(s, ".") || strings.Contains(s, "/")
}

func shellWords(s string) []string {
	var words []string
	var buf strings.Builder
	inSingle := false
	inDouble := false

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && !inSingle:
			if i+1 < len(s) {
				buf.WriteByte(s[i+1])
				i++
			}
		case c == '\'' && !inDouble:
			inSingle = !inSingle
			buf.WriteByte(c)
		case c == '"' && !inSingle:
			inDouble = !inDouble
			buf.WriteByte(c)
		case !inSingle && !inDouble && (c == ' ' || c == '\t'):
			if buf.Len() > 0 {
				words = append(words, buf.String())
				buf.Reset()
			}
		default:
			buf.WriteByte(c)
		}
	}
	if buf.Len() > 0 {
		words = append(words, buf.String())
	}
	return words
}

func trimVarExpansion(s string) string {
	s = strings.ReplaceAll(s, "\"", "")
	s = strings.ReplaceAll(s, "'", "")
	if strings.HasPrefix(s, "$") {
		return ""
	}
	return s
}
