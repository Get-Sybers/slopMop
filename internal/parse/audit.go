package parse

import (
	"encoding/hex"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	// maxAudited bounds how many commands of an audit log are read, and
	// maxAuditedText the bytes they make: evidence is hostile.
	maxAudited     = 20000
	maxAuditedText = 4 << 20
	// maxTracedLine is the longest line of a trace that is read as a call.
	maxTracedLine = 64 << 10
)

var (
	rxAuditEvent = regexp.MustCompile(`\bmsg=audit\(([^)]{1,64})\)`)
	rxAuditArg   = regexp.MustCompile(`(?:^|\s)a(\d+)(?:\[\d+\])?=`)
	rxAuditTitle = regexp.MustCompile(`\bproctitle=`)
	rxAuditCmd   = regexp.MustCompile(`\bcmd=`)
	rxAuditEnd   = regexp.MustCompile(`\s(?:exe|terminal|res|cwd)=`)
	// rxTraced reads the arguments of an execve as strace prints the call.
	rxTraced    = regexp.MustCompile(`\bexecve\("(?:[^"\\]|\\.)+", \[((?:"(?:[^"\\]|\\.)*"(?:\.\.\.)?(?:, )?)+)\]`)
	rxTracedArg = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"`)
)

// Audited returns the commands an audit log of Linux records, each once:
// the arguments of an EXECVE record, the command of a USER_CMD record, and
// the title of a process whose event has no EXECVE record. Hexadecimal is decoded.
func Audited(text string) []string {
	if !strings.Contains(text, "msg=audit(") {
		return nil
	}
	var found []string
	size := 0
	seen, executed := map[string]bool{}, map[string]bool{}
	for len(text) > 0 && len(found) < maxAudited && size < maxAuditedText {
		line := text
		if i := strings.IndexByte(text, '\n'); i >= 0 {
			line, text = text[:i], text[i+1:]
		} else {
			text = ""
		}
		event := rxAuditEvent.FindStringSubmatchIndex(line)
		if event == nil {
			continue
		}
		id, rest := line[event[2]:event[3]], strings.TrimRight(line[event[1]:], "\r")
		// A record ausearch -i wrote names its day, and holds no hexadecimal: a number stays one.
		plain := strings.ContainsAny(id, "/ ")
		command := ""
		switch {
		case strings.Contains(line, "type=EXECVE"):
			command = auditedArguments(rest, plain)
			executed[id] = command != ""
		case strings.Contains(line, "type=PROCTITLE") && !executed[id]:
			if at := rxAuditTitle.FindStringIndex(rest); at != nil {
				command = strings.Join(strings.Fields(strings.ReplaceAll(auditedValue(rest[at[1]:], true, plain), "\x00", " ")), " ")
			}
		case strings.Contains(line, "type=USER_CMD"):
			if at := rxAuditCmd.FindStringIndex(rest); at != nil {
				value := rest[at[1]:]
				if end := rxAuditEnd.FindStringIndex(value); end != nil {
					value = value[:end[0]]
				}
				command = auditedValue(value, true, plain)
			}
		}
		if command = strings.TrimSpace(command); command == "" || seen[command] {
			continue
		}
		seen[command] = true
		found = append(found, command)
		size += len(command)
	}
	return found
}

// auditedArguments joins the arguments of an EXECVE record as a command
// line. An argument that was cut into pieces is put together again.
func auditedArguments(record string, plain bool) string {
	marks := rxAuditArg.FindAllStringSubmatchIndex(record, -1)
	var order []string
	pieces := map[string]string{}
	for i, m := range marks {
		end := len(record)
		if i+1 < len(marks) {
			end = marks[i+1][0]
		}
		n, value := record[m[2]:m[3]], strings.TrimSpace(record[m[1]:end])
		// A value in quotes or in hexadecimal ends where the next field begins.
		if cut := strings.IndexByte(value, ' '); cut > 0 && (value[0] == '"' || (!plain && isHex(value[:cut]))) {
			value = value[:cut]
		}
		if _, known := pieces[n]; !known {
			order = append(order, n)
		}
		pieces[n] += value
	}
	args := make([]string, 0, len(order))
	for _, n := range order {
		if arg := auditedValue(pieces[n], false, plain); arg != "(null)" {
			args = append(args, arg)
		}
	}
	return commandLine(args)
}

// commandLine joins arguments as a shell reads them: one that holds a space
// or a quote, or is empty, stands in quotes.
func commandLine(args []string) string {
	words := make([]string, 0, len(args))
	for _, arg := range args {
		if arg == "" || strings.ContainsAny(arg, " \t\"'") {
			arg = `"` + strings.ReplaceAll(arg, `"`, `\"`) + `"`
		}
		words = append(words, arg)
	}
	return strings.Join(words, " ")
}

// auditedValue reads one value of a record: the text between its quotes, or
// what its hexadecimal spells, unless the record is plain. whole says the
// value may hold spaces as it stands.
func auditedValue(value string, whole, plain bool) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, `"`) {
		if end := strings.IndexByte(value[1:], '"'); end >= 0 {
			return value[1 : 1+end]
		}
		return value[1:]
	}
	first := value
	if cut := strings.IndexAny(value, " \t'"); cut >= 0 {
		first = value[:cut]
	}
	if !plain && isHex(first) {
		if raw, err := hex.DecodeString(first); err == nil && spelled(raw) {
			return string(raw)
		}
	}
	if whole {
		return strings.TrimRight(value, "'")
	}
	return value
}

// isHex reports whether s is pairs of hexadecimal digits and nothing else.
func isHex(s string) bool {
	if len(s) < 2 || len(s)%2 != 0 {
		return false
	}
	for _, c := range []byte(s) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// spelled reports whether raw is text: valid UTF-8 with no control
// character but the NUL that parts the words of a process title, and space.
func spelled(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	for _, c := range raw {
		if c < ' ' && c != 0 && c != '\t' && c != '\n' {
			return false
		}
	}
	return true
}

// Traced returns the commands a trace of system calls records, each once:
// the arguments of every execve that did not fail, as strace prints them.
func Traced(text string) []string {
	if !strings.Contains(text, `execve("`) {
		return nil
	}
	var found []string
	size := 0
	seen := map[string]bool{}
	for len(text) > 0 && len(found) < maxAudited && size < maxAuditedText {
		line := text
		if i := strings.IndexByte(text, '\n'); i >= 0 {
			line, text = text[:i], text[i+1:]
		} else {
			text = ""
		}
		if len(line) > maxTracedLine || !strings.Contains(line, `execve("`) {
			continue
		}
		call := rxTraced.FindStringSubmatchIndex(line)
		if call == nil || strings.Contains(line[call[1]:], "= -1 ") {
			continue
		}
		var args []string
		for _, arg := range rxTracedArg.FindAllStringSubmatch(line[call[2]:call[3]], -1) {
			args = append(args, unescaped(arg[1]))
		}
		command := strings.TrimSpace(commandLine(args))
		if command == "" || seen[command] {
			continue
		}
		seen[command] = true
		found = append(found, command)
		size += len(command)
	}
	return found
}

// unescaped reads a string as C writes it: a backslash before a quote, a
// letter that names a control character, or the digits of a byte in octal.
func unescaped(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 == len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch c := s[i]; {
		case c == 'n' || c == 'r' || c == 't' || c == 'v' || c == 'f':
			b.WriteByte(' ')
		case c >= '0' && c <= '7':
			value, end := 0, i
			for end < len(s) && end < i+3 && s[end] >= '0' && s[end] <= '7' {
				value = value*8 + int(s[end]-'0')
				end++
			}
			if value >= ' ' && value < 0x7f {
				b.WriteByte(byte(value))
			} else {
				b.WriteByte(' ')
			}
			i = end - 1
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
