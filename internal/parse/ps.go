package parse

import (
	"path/filepath"
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
	psReaders = map[string]bool{
		"get-content": true, "gc": true, "cat": true, "type": true,
		"import-csv": true, "ipcsv": true,
	}

	rxCmdlet     = regexp.MustCompile(`\b([A-Z][a-z]+-[A-Z][A-Za-z]+)\b`)
	rxExe        = regexp.MustCompile(`\b(\w[\w.-]*\.exe)\b`)
	rxPsVar      = regexp.MustCompile(`^\s*\$([A-Za-z_]\w*)\s*=\s*(.*)$`)
	rxPsParam    = regexp.MustCompile(`(?i)^\s*\[(?:string|int|switch|bool)\]?\s*\$(\w+)\s*=\s*(.*)$`)
	rxPsPath     = regexp.MustCompile(`(?i)-(?:Path|LiteralPath|FilePath|OutFile|OutputFile|OutputPath)\s+['"]?([^\s'"]+)`)
	rxPsRedir    = regexp.MustCompile(`>>?\s*(\S+)`)
	rxStaticCall = regexp.MustCompile(`\[System\.IO\.File\]::(\w+)\s*\(\s*["']([^"']+)`)
)

// ExtractPowerShell parses a PowerShell script for commands, variables and IO.
func ExtractPowerShell(text string) Script {
	var s Script
	seen := map[string]bool{}
	lines := strings.Split(text, "\n")

	for i, raw := range lines {
		lineNo := i + 1
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		extractPsVars(trimmed, lineNo, &s)
		extractPsCmds(trimmed, lineNo, &s, seen)
		extractPsIO(trimmed, lineNo, &s, seen)
	}
	return s
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

	for _, m := range rxExe.FindAllStringSubmatch(line, -1) {
		name := strings.ToLower(filepath.Base(m[1]))
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
