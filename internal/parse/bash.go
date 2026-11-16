package parse

import (
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
		"doas": true, "setsid": true, "watch": true, "ionice": true,
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
	rxHereDoc = regexp.MustCompile(`(?:^|[^<])<<-?[ \t]*['"]?(\w+)['"]?\s*(?:>\s*(\S+))?`)
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

// ExtractBash parses a bash script by line to find commands, variables and IO.
func ExtractBash(text string) Script {
	var s Script
	seen := map[string]bool{}
	lines := strings.Split(text, "\n")
	var hereEnd string
	// held is a command whose lines so far each ended in a backslash.
	var held string
	heldNo := 0

	for i, raw := range lines {
		lineNo := i + 1
		line := strings.TrimSpace(raw)
		if hereEnd != "" {
			if line == hereEnd {
				hereEnd = ""
			}
			continue
		}
		if held != "" {
			line, lineNo, held = held+" "+line, heldNo, ""
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasSuffix(line, `\`) && !strings.HasSuffix(line, `\\`) {
			held, heldNo = strings.TrimSpace(strings.TrimSuffix(line, `\`)), lineNo
			continue
		}
		if m := matchHereDoc(line); m != nil {
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

// matchHereDoc ignores "<<" inside arithmetic, where it is a shift.
func matchHereDoc(line string) []string {
	return rxHereDoc.FindStringSubmatch(blankArithmetic(line))
}

func blankArithmetic(line string) string {
	out := []byte(line)
	for i := 0; i+1 < len(out); i++ {
		if out[i] != '(' || out[i+1] != '(' {
			continue
		}
		depth := 0
		j := i
		for ; j < len(out); j++ {
			switch out[j] {
			case '(':
				depth++
			case ')':
				depth--
			}
			out[j] = ' '
			if depth == 0 {
				break
			}
		}
		i = j
	}
	return string(out)
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

	m := matchHereDoc(line)
	if m != nil && m[2] != "" {
		addWrite(m[2])
	}

	for _, seg := range splitPipe(line) {
		seg = strings.TrimSpace(seg)
		words := shellWords(seg)
		if len(words) >= 2 {
			cmd := strings.ToLower(BaseName(words[0]))
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
			cmd := strings.ToLower(BaseName(words[0]))
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
	bashCommands(line, lineNo, 0, s)
}

// bashCommands records the commands of a line and of the commands they
// launch: a subshell, a command substitution, a string handed to a shell.
func bashCommands(line string, lineNo, depth int, s *Script) {
	if depth > maxNesting {
		return
	}
	for _, seg := range splitSegments(line) {
		seg = strings.TrimSpace(seg)
		if inner, ok := unwrapGroup(seg); ok {
			bashCommands(inner, lineNo, depth+1, s)
			continue
		}
		if seg == "" {
			continue
		}
		masked, inners := substitutions(seg)
		words := shellWords(masked)
		if tool, at := findToolAt(words); tool != "" {
			s.Commands = append(s.Commands, Command{Line: lineNo, Tool: tool, Text: truncate(seg)})
			bashLaunched(tool, words[at+1:], lineNo, depth, s)
		}
		for _, inner := range inners {
			bashCommands(inner, lineNo, depth+1, s)
		}
	}
}

// unwrapGroup returns what a subshell "( ... )" or a group "{ ...; }" holds;
// a redirection may follow the closing bracket.
func unwrapGroup(seg string) (string, bool) {
	switch {
	case len(seg) >= 2 && seg[0] == '(' && seg[1] != '(':
		if end := strings.LastIndexByte(seg, ')'); end > 0 {
			return seg[1:end], true
		}
	case strings.HasPrefix(seg, "{ "):
		if end := strings.LastIndexByte(seg, '}'); end > 0 {
			return strings.TrimRight(strings.TrimSpace(seg[1:end]), ";"), true
		}
	}
	return "", false
}

// substitutions returns the commands a segment runs for their output: the
// inside of each $( ... ) and of each pair of backticks, outside single quotes.
// masked is the segment with each one cut down to "$_", so no word of it is read as a tool.
func substitutions(seg string) (masked string, found []string) {
	var b strings.Builder
	inSingle, from := false, 0
	cut := func(start, end int) {
		b.WriteString(seg[from:start])
		b.WriteString("$_")
		from = end
	}
	for i := 0; i < len(seg); i++ {
		switch c := seg[i]; {
		case c == '\\':
			i++
		case c == '\'':
			inSingle = !inSingle
		case inSingle:
		case c == '`':
			if end := strings.IndexByte(seg[i+1:], '`'); end >= 0 {
				found = append(found, seg[i+1:i+1+end])
				cut(i, i+end+2)
				i += end + 1
			}
		case c == '$' && i+2 < len(seg) && seg[i+1] == '(' && seg[i+2] != '(':
			depth, j := 1, i+2
			for ; j < len(seg) && depth > 0; j++ {
				switch seg[j] {
				case '(':
					depth++
				case ')':
					depth--
				}
			}
			if depth == 0 {
				found = append(found, seg[i+2:j-1])
				cut(i, j)
				i = j - 1
			}
		}
	}
	if len(found) == 0 {
		return seg, nil
	}
	b.WriteString(seg[from:])
	return b.String(), found
}

//nolint:gochecknoglobals // constant lookup tables for the bash lexer
var (
	shells = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "ash": true, "su": true}
	// sshValueFlags are the ssh options that take a value, which is not the host.
	sshValueFlags = map[string]bool{
		"-b": true, "-c": true, "-D": true, "-E": true, "-e": true, "-F": true, "-I": true, "-i": true,
		"-J": true, "-L": true, "-l": true, "-m": true, "-O": true, "-o": true, "-p": true, "-Q": true,
		"-R": true, "-S": true, "-W": true, "-w": true,
	}
	rxShellFlagC = regexp.MustCompile(`^-[A-Za-z]*c$`)
)

// bashLaunched follows a command that names another command to run.
func bashLaunched(tool string, args []string, lineNo, depth int, s *Script) {
	after := func(match func(string) bool) string {
		for i, a := range args {
			if match(a) && i+1 < len(args) {
				return stripQuotes(args[i+1])
			}
		}
		return ""
	}
	switch {
	case shells[tool]:
		bashCommands(after(rxShellFlagC.MatchString), lineNo, depth+1, s)
	case tool == "eval":
		bashCommands(unquoted(args), lineNo, depth+1, s)
	case tool == "ssh":
		bashCommands(remoteCommand(args), lineNo, depth+1, s)
	case tool == "find":
		for i, a := range args {
			if a == "-exec" || a == "-execdir" || a == "-ok" || a == "-okdir" {
				bashCommands(untilTerminator(args[i+1:]), lineNo, depth+1, s)
			}
		}
	case tool == "kubectl" || tool == "docker" || tool == "podman":
		bashCommands(containerCommand(args), lineNo, depth+1, s)
	case strings.HasPrefix(tool, "python"):
		if code := after(func(a string) bool { return a == "-c" }); code != "" {
			inline := ExtractPython(statements(code))
			for _, c := range inline.Commands {
				c.Line = lineNo
				s.Commands = append(s.Commands, c)
			}
		}
	}
}

// statements puts each statement of one line of Python on a line of its
// own: the code after -c is often written with semicolons.
func statements(code string) string {
	out := []byte(code)
	var quote byte
	for i, c := range out {
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == ';':
			out[i] = '\n'
		}
	}
	return string(out)
}

func unquoted(words []string) string {
	plain := make([]string, len(words))
	for i, w := range words {
		plain[i] = stripQuotes(w)
	}
	return strings.Join(plain, " ")
}

// remoteCommand returns what ssh is asked to run: the words after the host.
func remoteCommand(args []string) string {
	for i := 0; i < len(args); i++ {
		switch {
		case sshValueFlags[args[i]]:
			i++
		case strings.HasPrefix(args[i], "-"):
		default:
			return unquoted(args[i+1:])
		}
	}
	return ""
}

// untilTerminator returns the command find runs, up to its ";" or "+".
func untilTerminator(args []string) string {
	for i, a := range args {
		if a == ";" || a == "+" {
			return unquoted(args[:i])
		}
	}
	return unquoted(args)
}

// containerCommand returns the command run inside a container: what
// follows "--", or what follows the container of "exec".
func containerCommand(args []string) string {
	for i, a := range args {
		if a == "--" {
			return unquoted(args[i+1:])
		}
	}
	for i, a := range args {
		if a != "exec" {
			continue
		}
		for j := i + 1; j < len(args); j++ {
			if !strings.HasPrefix(args[j], "-") {
				return unquoted(args[j+1:])
			}
		}
	}
	return ""
}

func findTool(words []string) string {
	tool, _ := findToolAt(words)
	return tool
}

// findToolAt returns the command a list of words runs and its position.
func findToolAt(words []string) (string, int) {
	// The words of "for NAME in LIST" are data, not a command.
	if len(words) > 0 && (words[0] == "for" || words[0] == "select") {
		return "", 0
	}
	for i, w := range words {
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

		name := strings.ToLower(BaseName(w))
		if keywords[name] {
			continue
		}
		if declKeywords[name] {
			continue
		}
		if noise[name] {
			return "", 0
		}
		if wrappers[name] {
			continue
		}
		return name, i
	}
	return "", 0
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

func firstWord(s string) string {
	s = strings.TrimSpace(s)
	for i, c := range s {
		if c == ' ' || c == '\t' || c == ';' || c == '&' || c == '|' || c == '\n' {
			return s[:i]
		}
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
		cmd := strings.ToLower(BaseName(words[0]))
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
