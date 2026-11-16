package structured

import (
	"html"
	"strings"
)

// htmlScan carries the state of one pass over an HTML text.
type htmlScan struct {
	report  Report
	text    strings.Builder
	command strings.Builder
	// inside names the open command element, or is empty.
	inside string
}

// extractHTML strips the tags and keeps the text, the attribute values and
// the comments. It accepts any input: a browser does, and so must this.
func (t Table) extractHTML(text string) Report {
	var s htmlScan
	for text != "" {
		lt := strings.IndexByte(text, '<')
		if lt < 0 {
			s.text.WriteString(text)
			break
		}
		s.text.WriteString(text[:lt])
		text = text[lt:]
		switch {
		case strings.HasPrefix(text, "<!--"):
			s.flush()
			body, rest, _ := strings.Cut(text[4:], "-->")
			s.report.addValue(body)
			text = rest
		case len(text) > 1 && isTagStart(text[1]):
			s.flush()
			text = t.readTag(&s, text)
		default:
			s.text.WriteByte('<')
			text = text[1:]
		}
	}
	s.flush()
	s.report.addCommand(s.command.String())
	return s.report
}

func isTagStart(c byte) bool {
	return c == '/' || c == '!' || c == '?' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// flush ends the pending run of text: it is one value, and part of the
// command when a command element is open.
func (s *htmlScan) flush() {
	if s.text.Len() == 0 {
		return
	}
	decoded := html.UnescapeString(s.text.String())
	s.text.Reset()
	s.report.addValue(decoded)
	if s.inside != "" {
		s.command.WriteString(decoded)
	}
}

// readTag consumes the tag that opens text and returns what follows it.
func (t Table) readTag(s *htmlScan, text string) string {
	tag := scanTag(text)
	for _, v := range tag.values {
		s.report.addValue(html.UnescapeString(v))
	}
	rest := tag.rest
	switch {
	case tag.closing:
		if tag.name == s.inside && s.inside != "" {
			s.report.addCommand(s.command.String())
			s.command.Reset()
			s.inside = ""
		}
	case t.verbatim[tag.name] || t.dropped[tag.name]:
		var body string
		body, rest = cutElement(rest, tag.name)
		if t.verbatim[tag.name] {
			s.report.addValue(body)
		}
	case t.commandElements[tag.name] && s.inside == "":
		s.inside = tag.name
	}
	return rest
}

type htmlTag struct {
	name    string
	closing bool
	values  []string
	rest    string
}

// scanTag reads one tag from its "<" to its ">". A ">" inside a quoted
// attribute value does not end the tag.
func scanTag(text string) htmlTag {
	var tag htmlTag
	i := 1
	if i < len(text) && text[i] == '/' {
		tag.closing = true
		i++
	}
	start := i
	for i < len(text) && !isSpace(text[i]) && text[i] != '>' && text[i] != '/' {
		i++
	}
	tag.name = strings.ToLower(text[start:i])
	for i < len(text) && text[i] != '>' {
		if isSpace(text[i]) || text[i] == '/' {
			i++
			continue
		}
		for i < len(text) && !isSpace(text[i]) && text[i] != '=' && text[i] != '>' {
			i++
		}
		for i < len(text) && isSpace(text[i]) {
			i++
		}
		if i >= len(text) || text[i] != '=' {
			continue
		}
		i++
		for i < len(text) && isSpace(text[i]) {
			i++
		}
		var value string
		value, i = scanValue(text, i)
		tag.values = append(tag.values, value)
	}
	if i < len(text) {
		i++
	}
	tag.rest = text[i:]
	return tag
}

// scanValue reads the attribute value at text[i:] and returns it with the
// index after it.
func scanValue(text string, i int) (string, int) {
	if i < len(text) && (text[i] == '"' || text[i] == '\'') {
		quote := text[i]
		end := strings.IndexByte(text[i+1:], quote)
		if end < 0 {
			return text[i+1:], len(text)
		}
		return text[i+1 : i+1+end], i + end + 2
	}
	start := i
	for i < len(text) && !isSpace(text[i]) && text[i] != '>' {
		i++
	}
	return text[start:i], i
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f'
}

// cutElement splits text at the closing tag of name and returns the body
// and what follows the closing tag.
func cutElement(text, name string) (body, rest string) {
	end := indexFold(text, "</"+name)
	if end < 0 {
		return text, ""
	}
	body, rest = text[:end], text[end:]
	if gt := strings.IndexByte(rest, '>'); gt >= 0 {
		return body, rest[gt+1:]
	}
	return body, ""
}

// indexFold is strings.Index with ASCII case folded; lower is lower-case.
// Lower-casing the whole text first could shift the byte offsets.
func indexFold(text, lower string) int {
	for i := 0; i+len(lower) <= len(text); i++ {
		if strings.EqualFold(text[i:i+len(lower)], lower) {
			return i
		}
	}
	return -1
}
