package parse

import (
	"regexp"
	"strings"
)

//nolint:gochecknoglobals // constant lookup tables for the Python lexer
var (
	pyExecCalls = map[string]bool{
		"subprocess.run": true, "subprocess.call": true, "subprocess.Popen": true,
		"subprocess.check_call": true, "subprocess.check_output": true,
		"subprocess.getoutput": true, "subprocess.getstatusoutput": true,
		"os.system": true, "os.popen": true,
	}
	pyNetCalls = map[string]bool{
		"requests.get": true, "requests.post": true, "requests.put": true,
		"requests.patch": true, "requests.delete": true, "requests.head": true,
		"requests.request": true, "urllib.request.urlopen": true,
		"urllib.request.urlretrieve": true, "socket.create_connection": true,
	}
	pyCodeCalls      = map[string]bool{"eval": true, "exec": true}
	pyTransformCalls = map[string]string{
		"base64.b64encode":           "Base64Encode",
		"base64.urlsafe_b64encode":   "Base64Encode",
		"base64.standard_b64encode":  "Base64Encode",
		"base64.encodebytes":         "Base64Encode",
		"base64.b64decode":           "Base64Decode",
		"base64.urlsafe_b64decode":   "Base64Decode",
		"base64.standard_b64decode":  "Base64Decode",
		"base64.decodebytes":         "Base64Decode",
		"binascii.hexlify":           "HexEncode",
		"binascii.unhexlify":         "HexEncode",
		"bytes.fromhex":              "HexEncode",
		"gzip.compress":              "GZip",
		"gzip.decompress":            "GZip",
		"gzip.open":                  "GZip",
		"zlib.compress":              "Deflate",
		"zlib.decompress":            "Deflate",
		"bz2.compress":               "BZip2",
		"bz2.decompress":             "BZip2",
		"bz2.open":                   "BZip2",
		"lzma.compress":              "XZ",
		"lzma.decompress":            "XZ",
		"lzma.open":                  "XZ",
		"codecs.encode":              "TextEncoding",
		"codecs.decode":              "TextEncoding",
		"hashlib.md5":                "Crypto:MD5",
		"hashlib.sha1":               "Crypto:SHA1",
		"hashlib.sha256":             "Crypto:SHA256",
		"hashlib.sha512":             "Crypto:SHA512",
		"Crypto.Cipher.AES.new":      "Crypto:Aes",
		"Cryptodome.Cipher.AES.new":  "Crypto:Aes",
		"Crypto.Cipher.DES.new":      "Crypto:DES",
		"Crypto.Cipher.DES3.new":     "Crypto:TripleDES",
		"cryptography.fernet.Fernet": "Crypto:Fernet",
	}
	pyPathReads  = map[string]bool{"read_text": true, "read_bytes": true}
	pyPathWrites = map[string]bool{"write_text": true, "write_bytes": true}
	pyShells     = map[string]bool{"bash": true, "sh": true, "zsh": true, "dash": true}

	rxPyImport = regexp.MustCompile(`^import\s+(.+)$`)
	rxPyFrom   = regexp.MustCompile(`^from\s+([\w.]+)\s+import\s+(.+)$`)
	rxPyAssign = regexp.MustCompile(`(?s)^([A-Za-z_]\w*)\s*(?::\s*[\w.\[\], ]+?)?\s*=\s*([^=].*)$`)
	rxPyCall   = regexp.MustCompile(`[A-Za-z_][\w.]*\s*\(`)
	rxPyName   = regexp.MustCompile(`^[A-Za-z_]\w*$`)
	rxPyStr    = regexp.MustCompile(`(?s)^([rRbBuUfF]{0,2})(?:"""(.*?)"""|'''(.*?)'''|"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)')`)
	rxPyField  = regexp.MustCompile(`\{([A-Za-z_]\w*)\}`)
	rxPyMethod = regexp.MustCompile(`^\s*\.\s*(\w+)\s*\(`)
)

type pyLine struct {
	no   int
	text string
}

type pyState struct {
	s       *Script
	seen    map[string]bool
	aliases map[string]string
	values  map[string]string
}

// ExtractPython parses a Python script for imports, commands, variables and IO.
func ExtractPython(text string) Script {
	var s Script
	p := pyState{
		s:       &s,
		seen:    map[string]bool{},
		aliases: map[string]string{},
		values:  map[string]string{},
	}
	for _, l := range pyLogicalLines(text) {
		if p.extractImport(l.text) {
			continue
		}
		masked := pyMask(l.text)
		p.extractVar(l)
		p.extractCalls(l, masked)
		if strings.Contains(masked, "^") {
			s.Transforms = append(s.Transforms, Transform{Line: l.no, Method: "XOR", Text: truncate(l.text)})
		}
	}
	return s
}

// pyLogicalLines joins the physical lines of one statement and drops comments.
func pyLogicalLines(text string) []pyLine {
	var lines []pyLine
	var buf strings.Builder
	lineNo, start, depth := 1, 0, 0
	var quote byte
	triple := false
	emit := func() {
		if t := strings.TrimSpace(buf.String()); t != "" {
			lines = append(lines, pyLine{no: start, text: t})
		}
		buf.Reset()
		start = 0
	}
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c == '\r' {
			continue
		}
		if start == 0 && c != ' ' && c != '\t' && c != '\n' {
			start = lineNo
		}
		if c == '\n' {
			lineNo++
		}
		switch {
		case quote != 0:
			switch {
			case c == '\\' && i+1 < len(text):
				buf.WriteByte(c)
				i++
				if text[i] == '\n' {
					lineNo++
				}
				buf.WriteByte(text[i])
				continue
			case triple && c == quote && strings.HasPrefix(text[i:], strings.Repeat(string(quote), 3)):
				buf.WriteString(text[i : i+3])
				i += 2
				quote, triple = 0, false
				continue
			case !triple && c == quote:
				quote = 0
			case !triple && c == '\n':
				quote = 0
				buf.WriteByte(c)
				if depth == 0 {
					emit()
				}
				continue
			}
			buf.WriteByte(c)
		case c == '#':
			for i+1 < len(text) && text[i+1] != '\n' {
				i++
			}
		case c == '"' || c == '\'':
			quote = c
			if strings.HasPrefix(text[i:], strings.Repeat(string(c), 3)) {
				triple = true
				buf.WriteString(text[i : i+3])
				i += 2
				continue
			}
			buf.WriteByte(c)
		case c == '\\' && i+1 < len(text) && text[i+1] == '\n':
			buf.WriteByte(' ')
			i++
			lineNo++
		case c == '\n':
			if depth > 0 {
				buf.WriteByte(' ')
				continue
			}
			emit()
		default:
			switch c {
			case '(', '[', '{':
				depth++
			case ')', ']', '}':
				if depth > 0 {
					depth--
				}
			}
			buf.WriteByte(c)
		}
	}
	emit()
	return lines
}

// pyMask blanks the inside of every string literal and keeps the length.
func pyMask(line string) string {
	out := []byte(line)
	for i := 0; i < len(out); i++ {
		c := out[i]
		if c != '"' && c != '\'' {
			continue
		}
		end := string(c)
		if strings.HasPrefix(line[i:], strings.Repeat(end, 3)) {
			end = strings.Repeat(end, 3)
		}
		j := i + len(end)
		for j < len(out) && !strings.HasPrefix(line[j:], end) {
			if out[j] == '\\' && j+1 < len(out) {
				out[j] = ' '
				j++
			}
			out[j] = ' '
			j++
		}
		i = j + len(end) - 1
	}
	return string(out)
}

func (p *pyState) extractImport(line string) bool {
	if m := rxPyFrom.FindStringSubmatch(line); m != nil {
		p.addImport(m[1])
		for _, item := range strings.Split(strings.Trim(m[2], "() "), ",") {
			name, alias := pyAlias(item)
			if name != "" && name != "*" {
				p.aliases[alias] = m[1] + "." + name
			}
		}
		return true
	}
	m := rxPyImport.FindStringSubmatch(line)
	if m == nil {
		return false
	}
	for _, item := range strings.Split(m[1], ",") {
		name, alias := pyAlias(item)
		if name == "" {
			continue
		}
		p.addImport(name)
		p.aliases[alias] = name
	}
	return true
}

func (p *pyState) addImport(module string) {
	if !p.seen["i:"+module] {
		p.seen["i:"+module] = true
		p.s.Imports = append(p.s.Imports, module)
	}
}

func pyAlias(item string) (name, alias string) {
	f := strings.Fields(item)
	switch {
	case len(f) == 3 && f[1] == "as":
		return f[0], f[2]
	case len(f) == 1:
		return f[0], f[0]
	}
	return "", ""
}

func (p *pyState) extractVar(l pyLine) {
	m := rxPyAssign.FindStringSubmatch(l.text)
	if m == nil {
		return
	}
	raw := strings.TrimSpace(m[2])
	val := raw
	if lit, ok := p.literal(raw); ok {
		val = lit
	}
	p.values[m[1]] = raw
	p.s.Variables = append(p.s.Variables, Variable{Line: l.no, Name: m[1], Value: val})
}

func (p *pyState) extractCalls(l pyLine, masked string) {
	for _, loc := range rxPyCall.FindAllStringIndex(masked, -1) {
		if loc[0] > 0 && masked[loc[0]-1] == '.' {
			continue
		}
		called := strings.TrimSpace(masked[loc[0] : loc[1]-1])
		name := p.canonical(called)
		args, end := pyArgs(l.text, masked, loc[1])
		switch {
		case pyExecCalls[name]:
			p.addCommand(l, name)
			if len(args) > 0 {
				p.extractInvocation(args[0], l.no)
			}
		case pyNetCalls[name] || pyCodeCalls[name]:
			p.addCommand(l, name)
		case p.seen["i:socket"] && (strings.HasSuffix(called, ".connect") || strings.HasSuffix(called, ".connect_ex")):
			p.addCommand(l, "socket.connect")
		case name == "open" || name == "io.open":
			p.extractOpen(args)
		case name == "pathlib.Path":
			p.extractPathIO(args, masked[end:])
		default:
			p.extractPathVar(called)
		}
		if method, ok := pyTransformCalls[name]; ok {
			p.s.Transforms = append(p.s.Transforms, Transform{Line: l.no, Method: method, Text: truncate(l.text)})
		}
	}
}

func (p *pyState) addCommand(l pyLine, name string) {
	p.s.Commands = append(p.s.Commands, Command{Line: l.no, Tool: strings.ToLower(name), Text: truncate(l.text)})
}

// canonical resolves an import alias: "sp.run" becomes "subprocess.run".
func (p *pyState) canonical(name string) string {
	parts := strings.Split(name, ".")
	for i := len(parts); i > 0; i-- {
		if full, ok := p.aliases[strings.Join(parts[:i], ".")]; ok {
			return strings.Join(append([]string{full}, parts[i:]...), ".")
		}
	}
	return name
}

// pyArgs splits the arguments that open at start and returns the offset after the call.
func pyArgs(line, masked string, start int) ([]string, int) {
	var args []string
	depth := 0
	from := start
	for i := start; i < len(masked); i++ {
		switch masked[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth == 0 {
				return pyAppendArg(args, line[from:i]), i + 1
			}
			depth--
		case ',':
			if depth == 0 {
				args = pyAppendArg(args, line[from:i])
				from = i + 1
			}
		}
	}
	return pyAppendArg(args, line[from:]), len(masked)
}

func pyAppendArg(args []string, arg string) []string {
	if arg = strings.TrimSpace(arg); arg != "" {
		args = append(args, arg)
	}
	return args
}

// deref replaces a bare name with the expression last assigned to it.
func (p *pyState) deref(arg string) string {
	if rxPyName.MatchString(arg) {
		if raw, ok := p.values[arg]; ok {
			return raw
		}
	}
	return arg
}

// literal returns the string an expression opens with, with known f-string names filled in.
func (p *pyState) literal(arg string) (string, bool) {
	m := rxPyStr.FindStringSubmatch(p.deref(arg))
	if m == nil {
		return "", false
	}
	text := m[2] + m[3] + m[4] + m[5]
	if !strings.ContainsAny(m[1], "fF") {
		return text, true
	}
	return rxPyField.ReplaceAllStringFunc(text, func(field string) string {
		raw, ok := p.values[field[1:len(field)-1]]
		if !ok {
			return field
		}
		if sm := rxPyStr.FindStringSubmatch(raw); sm != nil {
			return sm[2] + sm[3] + sm[4] + sm[5]
		}
		return field
	}), true
}

// extractInvocation reads the command a process call runs, as an argument list or a shell string.
func (p *pyState) extractInvocation(arg string, lineNo int) {
	arg = p.deref(arg)
	if inner, ok := strings.CutPrefix(arg, "shlex.split("); ok {
		arg = strings.TrimSuffix(strings.TrimSpace(inner), ")")
	}
	if strings.HasPrefix(arg, "[") || strings.HasPrefix(arg, "(") {
		elems, _ := pyArgs(arg, pyMask(arg), 1)
		words := make([]string, len(elems))
		for i, e := range elems {
			if lit, ok := p.literal(e); ok {
				words[i] = lit
			} else {
				words[i] = "$" + e
			}
		}
		p.extractArgv(words, lineNo)
		return
	}
	if lit, ok := p.literal(arg); ok {
		p.extractShell(lit, lineNo)
	}
}

func (p *pyState) extractArgv(words []string, lineNo int) {
	tool := findTool(words)
	if tool == "" {
		return
	}
	text := truncate(strings.Join(words, " "))
	p.s.Commands = append(p.s.Commands, Command{Line: lineNo, Tool: tool, Text: text})
	if method, ok := bashTransformCmds[tool]; ok {
		p.s.Transforms = append(p.s.Transforms, Transform{Line: lineNo, Method: method, Text: text})
	}
	for k := 0; k+1 < len(words); k++ {
		switch {
		case outFlags[words[k]]:
			p.addWrite(words[k+1])
		case pyShells[tool] && words[k] == "-c":
			p.extractShell(words[k+1], lineNo)
		}
	}
}

func (p *pyState) extractShell(text string, lineNo int) {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		extractBashRedirections(line, lineNo, p.s, p.seen)
		extractBashReads(line, lineNo, p.s, p.seen)
		extractBashCommands(line, lineNo, p.s)
		extractBashTransforms(line, lineNo, p.s)
	}
}

func (p *pyState) extractOpen(args []string) {
	if len(args) == 0 {
		return
	}
	file, ok := p.literal(args[0])
	if !ok {
		return
	}
	mode := ""
	for i, a := range args[1:] {
		if kw, ok := strings.CutPrefix(a, "mode"); ok && strings.HasPrefix(strings.TrimSpace(kw), "=") {
			a = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(kw), "="))
		} else if i > 0 || strings.Contains(pyMask(a), "=") {
			continue
		}
		mode, _ = p.literal(a)
	}
	if strings.ContainsAny(mode, "wax+") {
		p.addWrite(file)
	}
	if mode == "" || strings.ContainsAny(mode, "r+") {
		p.addRead(file)
	}
}

// extractPathIO handles Path("f").read_text() and its write forms.
func (p *pyState) extractPathIO(args []string, rest string) {
	m := rxPyMethod.FindStringSubmatch(rest)
	if m == nil || len(args) == 0 {
		return
	}
	file, ok := p.literal(args[0])
	if !ok {
		return
	}
	p.addPathIO(file, m[1])
}

// extractPathVar handles p.read_text() where p was assigned a Path.
func (p *pyState) extractPathVar(called string) {
	recv, method, ok := strings.Cut(called, ".")
	if !ok || (!pyPathReads[method] && !pyPathWrites[method]) {
		return
	}
	raw, ok := p.values[recv]
	if !ok {
		return
	}
	open := strings.IndexByte(raw, '(')
	if open < 0 || p.canonical(strings.TrimSpace(raw[:open])) != "pathlib.Path" {
		return
	}
	args, _ := pyArgs(raw, pyMask(raw), open+1)
	if len(args) == 0 {
		return
	}
	if file, ok := p.literal(args[0]); ok {
		p.addPathIO(file, method)
	}
}

func (p *pyState) addPathIO(file, method string) {
	switch {
	case pyPathReads[method]:
		p.addRead(file)
	case pyPathWrites[method]:
		p.addWrite(file)
	}
}

// addWrite shares its seen key with the bash redirections.
func (p *pyState) addWrite(file string) {
	if file != "" && !p.seen[file] {
		p.seen[file] = true
		p.s.Writes = append(p.s.Writes, file)
	}
}

func (p *pyState) addRead(file string) {
	if file != "" && !p.seen["r:"+file] {
		p.seen["r:"+file] = true
		p.s.Reads = append(p.s.Reads, file)
	}
}
