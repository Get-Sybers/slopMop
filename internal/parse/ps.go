package parse

import (
	"regexp"
	"strings"
)

//nolint:gochecknoglobals // constant lookup tables for the PowerShell lexer
var (
	psNoise = map[string]bool{
		"write-host": true, "write-output": true, "write-verbose": true,
		"write-warning": true, "write-error": true, "write-debug": true,
		"write-information": true, "write-progress": true,
		"out-null": true, "out-host": true, "out-default": true,
		"start-sleep": true, "sleep": true, "set-strictmode": true,
		"clear-host": true, "cls": true, "echo": true,
	}
	psWriters = map[string]bool{
		"out-file": true, "set-content": true, "add-content": true,
		"tee-object": true, "export-csv": true, "export-clixml": true,
		"start-transcript": true,
	}
	// psKeywords open a statement without being a command.
	psKeywords = map[string]bool{
		"if": true, "else": true, "elseif": true, "switch": true, "default": true,
		"for": true, "foreach": true, "while": true, "do": true, "until": true, "in": true,
		"function": true, "filter": true, "param": true, "begin": true, "process": true,
		"end": true, "dynamicparam": true, "return": true, "break": true, "continue": true,
		"throw": true, "exit": true, "try": true, "catch": true, "finally": true, "trap": true,
		"class": true, "enum": true, "using": true, "data": true, "hidden": true, "static": true,
		"workflow": true, "parallel": true, "sequence": true, "inlinescript": true,
		"true": true, "false": true, "null": true,
	}
	psReaders = map[string]bool{
		"get-content": true, "gc": true, "cat": true, "type": true,
		"import-csv": true, "ipcsv": true,
	}

	rxCmdlet     = regexp.MustCompile(`(?i)\b([A-Z][a-z]+-[A-Z][A-Za-z]+)\b`)
	rxExe        = regexp.MustCompile(`\b(\w[\w.-]*\.exe)\b`)
	rxPsVar      = regexp.MustCompile(`^\s*\$([A-Za-z_]\w*)\s*=\s*(.*)$`)
	rxPsParam    = regexp.MustCompile(`(?i)^\s*\[(?:string|int|switch|bool)\]?\s*\$(\w+)\s*=\s*(.*)$`)
	rxPsPath     = regexp.MustCompile(`(?i)-(?:Path|LiteralPath|FilePath|OutFile|OutputFile|OutputPath)\s+['"]?([^\s'"]+)`)
	rxPsRedir    = regexp.MustCompile(`>>?\s*(\S+)`)
	rxStaticCall = regexp.MustCompile(`\[System\.IO\.File\]::(\w+)\s*\(\s*["']([^"']+)`)

	rxConvert     = regexp.MustCompile(`(?i)\[(?:System\.)?Convert\]::(To|From)Base64String`)
	rxGzip        = regexp.MustCompile(`(?i)\[(?:System\.IO\.)?Compression\.(GZipStream|DeflateStream)\]`)
	rxNewGzip     = regexp.MustCompile(`(?i)New-Object\s+(?:System\.)?IO\.Compression\.(GZipStream|DeflateStream)`)
	rxEncoding    = regexp.MustCompile(`(?i)\[(?:System\.)?Text\.Encoding\]::(UTF8|Unicode|ASCII|UTF7|UTF32|BigEndianUnicode|Default)`)
	rxGetEncoding = regexp.MustCompile(`(?i)\[(?:System\.)?Text\.Encoding\]::GetEncoding\s*\(`)
	rxCrypto      = regexp.MustCompile(`(?i)\[(?:System\.)?Security\.Cryptography\.(Aes|AesManaged|AesCryptoServiceProvider|RijndaelManaged|TripleDES|TripleDESCryptoServiceProvider|DES|DESCryptoServiceProvider|RSA|RSACryptoServiceProvider|SHA256|SHA512|MD5|HMACSHA256|HMACSHA512)\]`)
	rxNewCrypto   = regexp.MustCompile(`(?i)New-Object\s+(?:System\.)?Security\.Cryptography\.(Aes|AesManaged|AesCryptoServiceProvider|RijndaelManaged|TripleDES|TripleDESCryptoServiceProvider|DES|RSA|RC2|HMACSHA256|HMACSHA512)`)
	rxMemStream   = regexp.MustCompile(`(?i)\[(?:System\.)?IO\.(MemoryStream|StreamReader|StreamWriter|BinaryReader|BinaryWriter)\]`)
	rxNewStream   = regexp.MustCompile(`(?i)New-Object\s+(?:System\.)?IO\.(MemoryStream|StreamReader|StreamWriter|BinaryReader|BinaryWriter)`)
	rxBitConv     = regexp.MustCompile(`(?i)\[(?:System\.)?BitConverter\]::ToString`)
	rxBxor        = regexp.MustCompile(`(?i)-bxor\b`)
	rxCharArray   = regexp.MustCompile(`(?i)\.ToCharArray\s*\(`)
	rxArrReverse  = regexp.MustCompile(`(?i)\[array\]::Reverse\b`)
	rxPsAssign    = regexp.MustCompile(`^(?:\[[^\]]+\]\s*)*\$[\w:.]+(?:\[[^\]]*\])?\s*[-+*/]?=\s*(.*)$`)
	rxPsStart     = regexp.MustCompile(`(?i)\b(?:start-process|saps)\s+(?:-FilePath\s+)?['"]?([^\s'";|)]+)`)
	rxPsProcStart = regexp.MustCompile(`(?i)Process\]::Start\(\s*["']([^"']+)["']\s*(?:,\s*["']([^"']*)["'])?`)
	rxPsWord      = regexp.MustCompile(`^[A-Za-z0-9_.:\\/%~-]+`)
	rxPsNumber    = regexp.MustCompile(`(?i)^(?:0x[0-9a-f]+|[0-9.]+(?:[kmgtp]b|[dl])?)$`)
	rxPsCmdletish = regexp.MustCompile(`^[A-Za-z]+-[A-Za-z][A-Za-z0-9]*$`)
	rxEncCmd      = regexp.MustCompile(`(?i)-(?:(?:EncodedCommand|enc)\s+|(?:ec|e)\s+['"]?[A-Za-z0-9+/=]{20,})`)
	rxSecStr      = regexp.MustCompile(`(?i)(ConvertTo-SecureString|ConvertFrom-SecureString)`)
)

// ExtractPowerShell parses a PowerShell script for commands, variables and IO.
func ExtractPowerShell(text string) Script {
	var s Script
	seen := map[string]bool{}
	lines := strings.Split(text, "\n")
	// A here-string holds data and a block comment holds prose; neither is code.
	hereString, comment := false, false

	for i, raw := range lines {
		lineNo := i + 1
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if comment {
			comment = !strings.Contains(trimmed, "#>")
			continue
		}
		if strings.HasPrefix(trimmed, "<#") {
			comment = !strings.Contains(trimmed, "#>")
			continue
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		extractPsVars(trimmed, lineNo, &s)
		extractPsCmds(trimmed, lineNo, &s, seen)
		extractPsIO(trimmed, lineNo, &s, seen)
		extractPsTransforms(trimmed, lineNo, &s)
		switch {
		case hereString:
			hereString = !strings.HasPrefix(trimmed, `"@`) && !strings.HasPrefix(trimmed, "'@")
		case strings.HasSuffix(trimmed, `@"`) || strings.HasSuffix(trimmed, "@'"):
			hereString = true
		default:
			extractPsNative(trimmed, lineNo, &s, seen)
		}
	}
	return s
}

// extractPsNative records the native commands a line runs: a bare name at
// the start of a statement, after the call operator, or handed to a process
// starter. A cmdlet is already recorded by its Verb-Noun shape.
func extractPsNative(line string, lineNo int, s *Script, seen map[string]bool) {
	n := native{s: s}
	n.emit = func(tool string, lineNo int, text string) {
		key := "cmd:" + tool
		if psNoise[tool] || psKeywords[tool] || seen[key] {
			return
		}
		seen[key] = true
		s.Commands = append(s.Commands, Command{Line: lineNo, Tool: tool, Text: truncate(text)})
	}
	for _, seg := range psSegments(line) {
		seg = strings.TrimSpace(seg)
		if m := rxPsAssign.FindStringSubmatch(seg); m != nil {
			seg = strings.TrimSpace(m[1])
		}
		called := strings.HasPrefix(seg, "&")
		if called {
			seg = strings.TrimSpace(seg[1:])
		}
		word := rxPsWord.FindString(seg)
		if called && strings.HasPrefix(seg, `"`) || called && strings.HasPrefix(seg, "'") {
			if end := strings.IndexByte(seg[1:], seg[0]); end > 0 {
				// cmd.exe quoting is the double quote, whichever the script used.
				word = seg[1 : 1+end]
				seg = `"` + word + `"` + seg[end+2:]
			}
		}
		if !isPsNative(word, seg) {
			continue
		}
		n.line(strings.TrimRight(seg, ") \t"), lineNo, 0)
	}
	if m := rxPsStart.FindStringSubmatch(line); m != nil && !strings.ContainsAny(m[1][:1], "-$@(") {
		n.emit(strings.ToLower(BaseName(m[1])), lineNo, line)
	}
	if m := rxPsProcStart.FindStringSubmatch(line); m != nil {
		n.line(`"`+m[1]+`" `+m[2], lineNo, 0)
	}
}

// isPsNative reports whether the first word of a statement names a native
// command: not a keyword, a cmdlet, a member access or a hashtable key.
func isPsNative(word, seg string) bool {
	if word == "" || !rxHasLetter.MatchString(word) || strings.ContainsAny(word[:1], "-/:") {
		return false
	}
	// ".Trim()" continues an expression; ".\\tool.exe" runs a file.
	if word[0] == '.' && !strings.HasPrefix(word, `.\`) && !strings.HasPrefix(word, "./") && !strings.HasPrefix(word, "..") {
		return false
	}
	if strings.HasSuffix(word, ":") || strings.Contains(word, "::") || rxPsCmdletish.MatchString(word) || rxPsNumber.MatchString(word) {
		return false
	}
	rest := strings.TrimSpace(seg[strings.Index(seg, word)+len(word):])
	if strings.HasPrefix(rest, "=") || strings.HasPrefix(rest, ",") || strings.HasPrefix(rest, ".") || strings.HasPrefix(rest, "[") {
		return false
	}
	name := strings.ToLower(BaseName(word))
	return !psKeywords[name] && !psNoise[name]
}

// psSegments cuts a line into statements at ; | { } ( && and || outside
// quotes, and drops a trailing comment.
func psSegments(line string) []string {
	var segs []string
	start := 0
	var quote byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '`':
			i++
		case c == '"' || c == '\'':
			quote = c
		case c == '#' && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t'):
			return append(segs, line[start:i])
		case c == ';' || c == '|' || c == '{' || c == '}' || c == '(':
			segs = append(segs, line[start:i])
			start = i + 1
		case c == '&' && i+1 < len(line) && line[i+1] == '&':
			segs = append(segs, line[start:i])
			i++
			start = i + 1
		}
	}
	return append(segs, line[start:])
}

func extractPsVars(line string, lineNo int, s *Script) {
	m := rxPsVar.FindStringSubmatch(line)
	if m == nil {
		m = rxPsParam.FindStringSubmatch(line)
	}
	if m == nil {
		return
	}
	name := m[1]
	val := strings.TrimSpace(m[2])
	if strings.HasSuffix(val, ",") {
		val = strings.TrimRight(val, ",")
	}
	val = stripQuotes(val)
	s.Variables = append(s.Variables, Variable{Line: lineNo, Name: name, Value: val})
}

func extractPsCmds(line string, lineNo int, s *Script, seen map[string]bool) {
	for _, m := range rxCmdlet.FindAllStringSubmatch(line, -1) {
		name := strings.ToLower(m[1])
		if psNoise[name] {
			continue
		}
		key := "cmd:" + name
		if seen[key] {
			continue
		}
		seen[key] = true
		s.Commands = append(s.Commands, Command{
			Line: lineNo,
			Tool: name,
			Text: truncate(strings.TrimSpace(line)),
		})
	}

	for _, loc := range rxExe.FindAllStringIndex(line, -1) {
		if isArgument(line, loc[0]) {
			continue
		}
		name := strings.ToLower(BaseName(line[loc[0]:loc[1]]))
		key := "cmd:" + name
		if seen[key] {
			continue
		}
		seen[key] = true
		s.Commands = append(s.Commands, Command{
			Line: lineNo,
			Tool: name,
			Text: truncate(strings.TrimSpace(line)),
		})
	}

	if sm := rxStaticCall.FindStringSubmatch(line); sm != nil {
		tool := "[system.io.file]::" + strings.ToLower(sm[1])
		key := "cmd:" + tool
		if !seen[key] {
			seen[key] = true
			s.Commands = append(s.Commands, Command{
				Line: lineNo,
				Tool: tool,
				Text: truncate(strings.TrimSpace(line)),
			})
		}
	}
}

// isArgument reports whether the .exe name at pos is plainly not a command:
// part of an address, or the file an output option names.
func isArgument(line string, pos int) bool {
	start := strings.LastIndexAny(line[:pos], " \t\"'(") + 1
	token := strings.ToLower(line[start:pos])
	if strings.Contains(token, "://") || strings.HasPrefix(token, "/out:") || strings.HasPrefix(token, "-out:") {
		return true
	}
	// A path built from a variable is a file a command names, unless the
	// call operator runs it.
	if strings.HasPrefix(token, "$") || strings.HasPrefix(token, "%") {
		return !strings.HasSuffix(strings.TrimRight(line[:start], " \t\"'("), "&")
	}
	before := strings.Fields(strings.ToLower(line[:start]))
	if len(before) == 0 {
		return false
	}
	switch strings.Trim(before[len(before)-1], `"'`) {
	case "-outfile", "-destination", "-o", "-out", "-output", "-outputfile", "/out":
		return true
	}
	return false
}

func extractPsIO(line string, _ int, s *Script, seen map[string]bool) {
	lower := strings.ToLower(line)

	for _, seg := range strings.Split(line, "|") {
		seg = strings.TrimSpace(seg)
		words := shellWords(seg)
		if len(words) == 0 {
			continue
		}
		cmd := strings.ToLower(words[0])
		if psWriters[cmd] {
			for k := 1; k < len(words); k++ {
				w := words[k]
				if strings.HasPrefix(w, "-") {
					continue
				}
				f := stripQuotes(w)
				if f != "" && looksLikeFile(f) && !seen["w:"+f] {
					seen["w:"+f] = true
					s.Writes = append(s.Writes, f)
				}
				break
			}
		}
		if psReaders[cmd] {
			for k := 1; k < len(words); k++ {
				w := words[k]
				if strings.HasPrefix(w, "-") {
					continue
				}
				f := stripQuotes(w)
				if f != "" && looksLikeFile(f) && !seen["r:"+f] {
					seen["r:"+f] = true
					s.Reads = append(s.Reads, f)
				}
				break
			}
		}
	}

	if pm := rxPsPath.FindAllStringSubmatch(line, -1); pm != nil {
		for _, m := range pm {
			f := stripQuotes(m[1])
			f = trimVarExpansion(f)
			if f == "" || strings.HasPrefix(f, "Cert:") {
				continue
			}
			if strings.Contains(lower, "export-") || strings.Contains(lower, "out-file") ||
				strings.Contains(lower, "set-content") || strings.Contains(lower, "add-content") {
				if !seen["w:"+f] {
					seen["w:"+f] = true
					s.Writes = append(s.Writes, f)
				}
			}
			if strings.Contains(lower, "import-csv") || strings.Contains(lower, "get-content") {
				if !seen["r:"+f] {
					seen["r:"+f] = true
					s.Reads = append(s.Reads, f)
				}
			}
		}
	}

	if sm := rxStaticCall.FindStringSubmatch(line); sm != nil {
		method := strings.ToLower(sm[1])
		f := sm[2]
		if strings.HasPrefix(method, "write") {
			if !seen["w:"+f] {
				seen["w:"+f] = true
				s.Writes = append(s.Writes, f)
			}
		}
		if strings.HasPrefix(method, "read") {
			if !seen["r:"+f] {
				seen["r:"+f] = true
				s.Reads = append(s.Reads, f)
			}
		}
	}

	for _, m := range rxPsRedir.FindAllStringSubmatch(line, -1) {
		f := stripQuotes(m[1])
		f = trimVarExpansion(f)
		if f != "" && !strings.HasPrefix(f, "&") && !seen["w:"+f] {
			seen["w:"+f] = true
			s.Writes = append(s.Writes, f)
		}
	}
}

// psCompressionLabel matches the labels the bash parser emits.
func psCompressionLabel(class string) string {
	if strings.EqualFold(class, "DeflateStream") {
		return "Deflate"
	}
	return "GZip"
}

func extractPsTransforms(line string, lineNo int, s *Script) {
	add := func(method string) {
		s.Transforms = append(s.Transforms, Transform{
			Line: lineNo, Method: method, Text: truncate(line),
		})
	}

	if m := rxConvert.FindStringSubmatch(line); m != nil {
		if strings.EqualFold(m[1], "To") {
			add("Base64Encode")
		} else {
			add("Base64Decode")
		}
	}
	if m := rxGzip.FindStringSubmatch(line); m != nil {
		add(psCompressionLabel(m[1]))
	}
	if m := rxNewGzip.FindStringSubmatch(line); m != nil {
		add(psCompressionLabel(m[1]))
	}
	if rxEncoding.MatchString(line) || rxGetEncoding.MatchString(line) {
		add("TextEncoding")
	}
	if m := rxCrypto.FindStringSubmatch(line); m != nil {
		add("Crypto:" + m[1])
	}
	if m := rxNewCrypto.FindStringSubmatch(line); m != nil {
		add("Crypto:" + m[1])
	}
	if rxMemStream.MatchString(line) || rxNewStream.MatchString(line) {
		add("Stream")
	}
	if rxBitConv.MatchString(line) {
		add("HexEncode")
	}
	if rxBxor.MatchString(line) {
		add("XOR")
	}
	if rxCharArray.MatchString(line) || rxArrReverse.MatchString(line) {
		add("StringManip")
	}
	if rxEncCmd.MatchString(line) {
		add("EncodedCommand")
	}
	if m := rxSecStr.FindStringSubmatch(line); m != nil {
		add("SecureString")
	}
}
