package parse

import (
	"regexp"
	"strings"
)

// maxNesting bounds how deep a command that launches a command is followed.
const maxNesting = 4

//nolint:gochecknoglobals // constant lookup tables for the cmd.exe lexer
var (
	// nativeNoise are cmd.exe built-ins that say nothing about the intrusion.
	nativeNoise = map[string]bool{
		"echo": true, "rem": true, "title": true, "setlocal": true, "endlocal": true,
		"goto": true, "exit": true, "pause": true, "cls": true,
		"color": true, //nolint:misspell // the cmd.exe command is spelled so
		"shift": true, "pushd": true, "popd": true, "cd": true, "chdir": true,
		"set": true, "else": true, "prompt": true, "ver": true,
	}
	certutilTransforms = map[string]string{
		"decode": "Base64Decode", "encode": "Base64Encode",
		"decodehex": "HexDecode", "encodehex": "HexEncode",
	}

	rxCmdSwitch   = regexp.MustCompile(`(?i)\s/[ck]\s+(.+)$`)
	rxPsCommand   = regexp.MustCompile(`(?i)\s-c(?:ommand)?\s+(.+)$`)
	rxForIn       = regexp.MustCompile(`(?i)\bin\s*\(\s*'([^']+)'\s*\)`)
	rxForDo       = regexp.MustCompile(`(?i)\bdo\s+(.+)$`)
	rxSet         = regexp.MustCompile(`(?i)^set\s+(?:/[ap]\s+)?"?([A-Za-z_]\w*)=([^"]*)"?$`)
	rxNativeRedir = regexp.MustCompile(`(?:^|[^0-9>&^])>>?\s*("[^"]+"|[^\s&|)>]+)`)
	rxNativeName  = regexp.MustCompile(`^[A-Za-z0-9_.:\\/%~ ()-]+$`)
	rxHasLetter   = regexp.MustCompile(`[A-Za-z]`)
)

// native collects the commands of cmd.exe-style command lines. emit decides
// whether a tool is recorded, so each caller keeps its own de-duplication.
type native struct {
	s    *Script
	emit func(tool string, lineNo int, text string)
	// io is set for a batch file; PowerShell reads its own redirections.
	io bool
}

// ExtractBatch parses a batch file for commands, variables and IO.
func ExtractBatch(text string) Script {
	var s Script
	n := native{s: &s, io: true}
	n.emit = func(tool string, lineNo int, text string) {
		s.Commands = append(s.Commands, Command{Line: lineNo, Tool: tool, Text: truncate(text)})
	}
	var held string
	heldNo := 0
	for i, raw := range strings.Split(text, "\n") {
		lineNo := i + 1
		line := strings.TrimSpace(raw)
		if held != "" {
			line, lineNo, held = held+" "+line, heldNo, ""
		}
		// A caret at the end of a line continues the command on the next.
		if strings.HasSuffix(line, "^") && !strings.HasSuffix(line, "^^") {
			held, heldNo = strings.TrimSpace(strings.TrimSuffix(line, "^")), lineNo
			continue
		}
		line = strings.TrimSpace(strings.TrimLeft(line, "@"))
		lower := strings.ToLower(line)
		if line == "" || strings.HasPrefix(line, ":") || lower == "rem" || strings.HasPrefix(lower, "rem ") {
			continue
		}
		n.line(line, lineNo, 0)
	}
	return s
}

// line records the commands of one command line and of the commands it launches.
func (n native) line(line string, lineNo, depth int) {
	if depth > maxNesting {
		return
	}
	for _, seg := range splitNative(line) {
		n.segment(seg, lineNo, depth)
	}
}

func (n native) segment(seg string, lineNo, depth int) {
	seg = strings.TrimSpace(strings.Trim(strings.TrimSpace(seg), "()@"))
	if seg == "" {
		return
	}
	words := nativeWords(seg)
	lower := make([]string, len(words))
	for i, w := range words {
		lower[i] = strings.ToLower(w)
	}
	switch first := firstOf(lower); first {
	case "for":
		// The command of a for loop follows "do"; "in ('...')" runs one too.
		if m := rxForIn.FindStringSubmatch(seg); m != nil {
			n.line(m[1], lineNo, depth+1)
		}
		if m := rxForDo.FindStringSubmatch(seg); m != nil {
			n.line(m[1], lineNo, depth+1)
		}
		return
	case "if":
		if rest := afterCondition(words, lower); rest != "" {
			n.line(rest, lineNo, depth+1)
		}
		return
	case "call", "start":
		i := 1
		for i < len(words) && (words[i] == "" || strings.HasPrefix(words[i], "/")) {
			i++
		}
		// start takes a quoted window title before the command.
		if first == "start" && i+1 < len(words) && strings.Contains(words[i], " ") {
			i++
		}
		if i < len(words) {
			n.line(joinWords(words[i:]), lineNo, depth+1)
		}
		return
	}
	if n.io {
		if m := rxSet.FindStringSubmatch(seg); m != nil {
			n.s.Variables = append(n.s.Variables, Variable{Line: lineNo, Name: m[1], Value: m[2]})
		}
		for _, m := range rxNativeRedir.FindAllStringSubmatch(seg, -1) {
			if f := stripQuotes(m[1]); !strings.EqualFold(f, "nul") {
				n.s.Writes = append(n.s.Writes, f)
			}
		}
	}
	word := words[0]
	if !rxNativeName.MatchString(word) || !rxHasLetter.MatchString(word) || strings.ContainsAny(word[:1], "-/:") {
		return
	}
	tool := strings.ToLower(BaseName(word))
	if tool == "" || nativeNoise[tool] {
		return
	}
	n.emit(tool, lineNo, seg)
	n.transforms(tool, lower, seg, lineNo)
	n.launched(tool, words, lower, seg, lineNo, depth)
}

func firstOf(words []string) string {
	if len(words) == 0 {
		return ""
	}
	return words[0]
}

// afterCondition returns the command that follows the test of an if.
func afterCondition(words, lower []string) string {
	i := 1
	for i < len(lower) && (lower[i] == "/i" || lower[i] == "not") {
		i++
	}
	switch {
	case i >= len(lower):
		return ""
	case lower[i] == "exist" || lower[i] == "defined" || lower[i] == "errorlevel":
		i += 2
	case strings.Contains(lower[i], "=="):
		i++
	default:
		i += 3
	}
	if i >= len(words) {
		return ""
	}
	return joinWords(words[i:])
}

// joinWords rebuilds a command line, quoting a word that holds a space.
func joinWords(words []string) string {
	quoted := make([]string, len(words))
	for i, w := range words {
		if strings.ContainsAny(w, " \t") {
			w = `"` + w + `"`
		}
		quoted[i] = w
	}
	return strings.Join(quoted, " ")
}

// transforms notes what certutil does to a file besides fetching it.
func (n native) transforms(tool string, lower []string, seg string, lineNo int) {
	if strings.TrimSuffix(tool, ".exe") != "certutil" {
		return
	}
	for _, w := range lower[1:] {
		if method, ok := certutilTransforms[strings.TrimLeft(w, "-/")]; ok && w != strings.TrimLeft(w, "-/") {
			n.s.Transforms = append(n.s.Transforms, Transform{Line: lineNo, Method: method, Text: truncate(seg)})
		}
	}
}

// launched follows a command that names another command to run.
func (n native) launched(tool string, words, lower []string, seg string, lineNo, depth int) {
	after := func(flag string) string {
		for i, w := range lower {
			if w == flag && i+1 < len(words) {
				return words[i+1]
			}
		}
		return ""
	}
	switch strings.TrimSuffix(tool, ".exe") {
	case "cmd", "%comspec%":
		if m := rxCmdSwitch.FindStringSubmatch(seg); m != nil {
			n.line(stripQuotes(strings.TrimSpace(m[1])), lineNo, depth+1)
		}
	case "powershell", "pwsh":
		if m := rxPsCommand.FindStringSubmatch(seg); m != nil {
			n.powershell(stripQuotes(strings.TrimSpace(m[1])), lineNo, depth+1)
		}
	case "schtasks":
		n.line(after("/tr"), lineNo, depth+1)
	case "forfiles":
		n.line(after("/c"), lineNo, depth+1)
	case "wmic":
		for i := 0; i+3 < len(lower); i++ {
			if lower[i] == "process" && lower[i+1] == "call" && lower[i+2] == "create" {
				n.line(words[i+3], lineNo, depth+1)
			}
		}
	}
}

// powershell records the commands of a PowerShell command given inline.
func (n native) powershell(inline string, lineNo, depth int) {
	if depth > maxNesting {
		return
	}
	inner := ExtractPowerShell(inline)
	for _, c := range inner.Commands {
		n.emit(c.Tool, lineNo, c.Text)
	}
	for _, t := range inner.Transforms {
		t.Line = lineNo
		n.s.Transforms = append(n.s.Transforms, t)
	}
}

// splitNative cuts a command line at &, &&, || and | outside double quotes.
func splitNative(line string) []string {
	var segs []string
	start, quoted := 0, false
	for i := 0; i < len(line); i++ {
		switch c := line[i]; {
		case c == '^' && !quoted:
			i++
		case c == '"':
			quoted = !quoted
		case (c == '&' || c == '|') && !quoted:
			// "2>&1" joins two streams; it does not end the command.
			if c == '&' && i > 0 && line[i-1] == '>' {
				continue
			}
			segs = append(segs, line[start:i])
			if i+1 < len(line) && line[i+1] == c {
				i++
			}
			start = i + 1
		}
	}
	return append(segs, line[start:])
}

// nativeWords splits a command at white space outside double quotes and
// drops the quotes; cmd.exe has no other quoting.
func nativeWords(seg string) []string {
	var words []string
	var buf strings.Builder
	quoted, open := false, false
	flush := func() {
		if open {
			words = append(words, buf.String())
			buf.Reset()
			open = false
		}
	}
	for i := 0; i < len(seg); i++ {
		switch c := seg[i]; {
		case c == '"':
			quoted, open = !quoted, true
		case (c == ' ' || c == '\t') && !quoted:
			flush()
		default:
			buf.WriteByte(c)
			open = true
		}
	}
	flush()
	return words
}
