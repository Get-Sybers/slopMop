package parse

import (
	"path/filepath"
	"regexp"
	"strings"
)

//nolint:gochecknoglobals // constant lookup tables for the bash lexer
var (
	keywords = map[string]bool{
		"if": true, "then": true, "else": true, "elif": true,
		"do": true, "done": true, "for": true, "while": true,
		"until": true, "case": true, "esac": true, "fi": true,
		"in": true, "function": true, "{": true, "}": true,
		"!": true, "time": true, "select": true,
	}
	wrappers = map[string]bool{
		"sudo": true, "nohup": true, "env": true, "timeout": true,
		"xargs": true, "exec": true, "command": true,
		"proxychains": true, "proxychains4": true, "torsocks": true,
		"stdbuf": true, "nice": true, "sshpass": true,
	}
	noise = map[string]bool{
		"echo": true, "printf": true, "cd": true, "set": true,
		"shopt": true, "true": true, "false": true, "test": true,
		"[": true, "[[": true, "wait": true, "trap": true,
		"shift": true, "return": true, "exit": true, "break": true,
		"continue": true, "let": true, "sleep": true, "read": true,
		"mapfile": true, "readarray": true, ":": true, "unset": true,
	}
	declKeywords = map[string]bool{
		"export": true, "declare": true, "typeset": true,
		"local": true, "readonly": true,
	}
	outFlags = map[string]bool{
		"-o": true, "-oN": true, "-oG": true, "-oX": true, "-oA": true,
		"--output": true, "--output-file": true, "--outfile": true,
		"--log": true, "--logfile": true, "--log-file": true,
		"-out": true, "--out": true,
	}
	readCmds = map[string]bool{
		"cat": true, "awk": true, "head": true, "tail": true,
		"cut": true, "sort": true, "grep": true, "wc": true,
	}

	rxAssign  = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)(\+?=)(.*)$`)
	rxHereDoc = regexp.MustCompile(`<<-?\s*['"]?(\w+)['"]?\s*(?:>\s*(\S+))?`)
	rxInputRe = regexp.MustCompile(`<\s+(\S+)`)

	bashTransformCmds = map[string]string{
		"base64":  "Base64",
		"b64":     "Base64",
		"xxd":     "HexEncode",
		"od":      "HexEncode",
		"hexdump": "HexEncode",
		"gzip":    "GZip",
		"gunzip":  "GZip",
		"zcat":    "GZip",
		"xz":      "XZ",
		"bzip2":   "BZip2",
		"bunzip2": "BZip2",
		"lz4":     "LZ4",
		"zstd":    "Zstd",
		"gpg":     "GPG",
	}
	rxOpenSSLEnc = regexp.MustCompile(`(?i)\bopenssl\s+(?:enc|aes|des|bf|rc[24])`)
)

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

func looksLikeFile(s string) bool {
	if s == "" || strings.HasPrefix(s, "-") || strings.HasPrefix(s, "$") {
		return false
	}
	return strings.Contains(s, ".") || strings.Contains(s, "/")
}

// ExtractBash parses a bash script by line to find commands, variables and IO.
func ExtractBash(text string) Script {
	var s Script
	seen := map[string]bool{}
	lines := strings.Split(text, "\n")
	var hereEnd string

	for i, raw := range lines {
		lineNo := i + 1
		line := strings.TrimSpace(raw)
		if hereEnd != "" {
			if line == hereEnd {
				hereEnd = ""
			}
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if m := rxHereDoc.FindStringSubmatch(line); m != nil {
			hereEnd = m[1]
		}

		extractBashVars(line, lineNo, &s)
		extractBashRedirections(line, lineNo, &s, seen)
		extractBashReads(line, lineNo, &s, seen)
		extractBashCommands(line, lineNo, &s)
		extractBashTransforms(line, lineNo, &s)
	}
	return s
}

func extractBashVars(line string, lineNo int, s *Script) {
	work := line
	for _, kw := range []string{"export ", "declare ", "typeset ", "local ", "readonly "} {
		if strings.HasPrefix(work, kw) {
			work = strings.TrimPrefix(work, kw)
			work = strings.TrimLeft(work, "- ")
			for len(work) > 0 && work[0] == '-' {
				sp := strings.IndexByte(work, ' ')
				if sp < 0 {
					return
				}
				work = strings.TrimSpace(work[sp+1:])
			}
			break
		}
	}
	m := rxAssign.FindStringSubmatch(work)
	if m == nil {
		return
	}
	name := m[1]
	val := strings.TrimSpace(m[3])
	val = stripQuotes(val)
	if strings.HasPrefix(val, "(") && strings.HasSuffix(val, ")") {
		val = val[1 : len(val)-1]
	}
	s.Variables = append(s.Variables, Variable{Line: lineNo, Name: name, Value: val})
}

func extractBashRedirections(line string, _ int, s *Script, seen map[string]bool) {
	addWrite := func(f string) {
		f = stripQuotes(f)
		f = trimVarExpansion(f)
		if f != "" && !strings.HasPrefix(f, "/dev/") && !seen[f] {
			seen[f] = true
			s.Writes = append(s.Writes, f)
		}
	}

	inSQ := false
	inDQ := false
	for j := 0; j < len(line); j++ {
		c := line[j]
		if c == '\'' && !inDQ {
			inSQ = !inSQ
			continue
		}
		if c == '"' && !inSQ {
			inDQ = !inDQ
			continue
		}
		if inSQ || inDQ {
			continue
		}
		if c == '>' {
			rest := strings.TrimPrefix(line[j+1:], ">")
			rest = strings.TrimSpace(rest)
			if rest == "" {
				continue
			}
			if strings.HasPrefix(rest, "&") {
				continue
			}
			f := firstWord(rest)
			addWrite(f)
		}
	}

	m := rxHereDoc.FindStringSubmatch(line)
	if m != nil && m[2] != "" {
		addWrite(m[2])
	}

	for _, seg := range splitPipe(line) {
		seg = strings.TrimSpace(seg)
		words := shellWords(seg)
		if len(words) >= 2 {
			cmd := strings.ToLower(filepath.Base(words[0]))
			if cmd == "tee" {
				for k := 1; k < len(words); k++ {
					w := words[k]
					if w == "-a" || w == "--append" || strings.HasPrefix(w, "-") {
						continue
					}
					addWrite(w)
					break
				}
			}
		}
		for k := 0; k < len(words)-1; k++ {
			if outFlags[words[k]] {
				addWrite(words[k+1])
			}
		}
	}
}

func extractBashReads(line string, _ int, s *Script, seen map[string]bool) {
	addRead := func(f string) {
		f = stripQuotes(f)
		f = trimVarExpansion(f)
		key := "r:" + f
		if f != "" && !strings.HasPrefix(f, "-") && looksLikeFile(f) && !seen[key] {
			seen[key] = true
			s.Reads = append(s.Reads, f)
		}
	}

	scanForReads := func(text string) {
		m := rxInputRe.FindStringSubmatch(text)
		if m != nil {
			addRead(m[1])
		}
		for _, seg := range splitPipe(text) {
			seg = strings.TrimSpace(seg)
			words := shellWords(seg)
			if len(words) < 2 {
				continue
			}
			cmd := strings.ToLower(filepath.Base(words[0]))
			if !readCmds[cmd] {
				continue
			}
			skip := map[int]bool{}
			for k := 1; k < len(words); k++ {
				if strings.HasPrefix(words[k], "-") && k+1 < len(words) && !strings.HasPrefix(words[k+1], "-") {
					skip[k+1] = true
					k++
				}
			}
			for k := 1; k < len(words); k++ {
				if skip[k] || strings.HasPrefix(words[k], "-") {
					continue
				}
				if looksLikeFile(words[k]) {
					addRead(words[k])
				}
			}
		}
	}

	scanForReads(line)
	for _, sub := range extractSubstitutions(line) {
		scanForReads(sub)
	}
}

func extractSubstitutions(line string) []string {
	var subs []string
	for i := 0; i < len(line)-1; i++ {
		if line[i] == '$' && line[i+1] == '(' {
			depth := 1
			start := i + 2
			for j := start; j < len(line); j++ {
				if line[j] == '(' {
					depth++
				} else if line[j] == ')' {
					depth--
					if depth == 0 {
						subs = append(subs, line[start:j])
						break
					}
				}
			}
		}
	}
	return subs
}

func extractBashCommands(line string, lineNo int, s *Script) {
	for _, seg := range splitSegments(line) {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		words := shellWords(seg)
		tool := findTool(words)
		if tool == "" {
			continue
		}
		s.Commands = append(s.Commands, Command{
			Line: lineNo,
			Tool: tool,
			Text: truncate(seg),
		})
	}
}

func findTool(words []string) string {
	for _, w := range words {
		if rxAssign.MatchString(w) {
			continue
		}
		if strings.HasPrefix(w, "-") || strings.HasPrefix(w, "$") ||
			strings.HasPrefix(w, "'") || strings.HasPrefix(w, "\"") {
			continue
		}
		if !hasLetter(w) || len(w) < 2 {
			continue
		}
		if w[0] >= '0' && w[0] <= '9' {
			continue
		}

		name := strings.ToLower(filepath.Base(w))
		if keywords[name] {
			continue
		}
		if declKeywords[name] {
			continue
		}
		if noise[name] {
			return ""
		}
		if wrappers[name] {
			continue
		}
		return name
	}
	return ""
}

func hasLetter(s string) bool {
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			return true
		}
	}
	return false
}

func splitSegments(line string) []string {
	var segs []string
	depth := 0
	start := 0
	inSingle := false
	inDouble := false

	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '\\' && !inSingle:
			i++
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case inSingle || inDouble:
			// inside quotes
		case c == '(' || c == '{':
			depth++
		case c == ')' || c == '}':
			if depth > 0 {
				depth--
			}
		case depth == 0 && (c == '|' || c == ';' || c == '&'):
			if c == '&' && i > 0 && line[i-1] == '>' {
				break
			}
			if c == '&' && i > 1 && line[i-2] >= '0' && line[i-2] <= '9' && line[i-1] == '>' {
				break
			}
			segs = append(segs, line[start:i])
			start = i + 1
			if i+1 < len(line) && (line[i+1] == '|' || line[i+1] == '&') {
				i++
				start = i + 1
			}
		}
	}
	segs = append(segs, line[start:])
	return segs
}

func splitPipe(line string) []string {
	var segs []string
	depth := 0
	start := 0
	inSingle := false
	inDouble := false

	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '\\' && !inSingle:
			i++
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case inSingle || inDouble:
			// inside quotes
		case c == '(' || c == '{':
			depth++
		case c == ')' || c == '}':
			if depth > 0 {
				depth--
			}
		case depth == 0 && c == '|' && (i+1 >= len(line) || line[i+1] != '|'):
			segs = append(segs, line[start:i])
			start = i + 1
		}
	}
	segs = append(segs, line[start:])
	return segs
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

func firstWord(s string) string {
	s = strings.TrimSpace(s)
	for i, c := range s {
		if c == ' ' || c == '\t' || c == ';' || c == '&' || c == '|' || c == '\n' {
			return s[:i]
		}
	}
	return s
}

func trimVarExpansion(s string) string {
	s = strings.ReplaceAll(s, "\"", "")
	s = strings.ReplaceAll(s, "'", "")
	if strings.HasPrefix(s, "$") {
		return ""
	}
	return s
}

func extractBashTransforms(line string, lineNo int, s *Script) {
	for _, seg := range splitPipe(line) {
		seg = strings.TrimSpace(seg)
		words := shellWords(seg)
		if len(words) == 0 {
			continue
		}
		cmd := strings.ToLower(filepath.Base(words[0]))
		if method, ok := bashTransformCmds[cmd]; ok {
			s.Transforms = append(s.Transforms, Transform{
				Line: lineNo, Method: method, Text: truncate(seg),
			})
		}
	}
	if rxOpenSSLEnc.MatchString(line) {
		s.Transforms = append(s.Transforms, Transform{
			Line: lineNo, Method: "OpenSSLEncrypt", Text: truncate(line),
		})
	}
}
