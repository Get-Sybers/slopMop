// Package parse extracts commands, variables and file references from scripts.
package parse

import "regexp"

// Script holds the static analysis of one script file.
type Script struct {
	Commands   []Command
	Variables  []Variable
	Writes     []string
	Reads      []string
	Transforms []Transform
	// Imports holds the modules a Python script imports.
	Imports []string
}

// Command is one tool invocation found in a script.
type Command struct {
	Line int
	Tool string
	Text string
}

// Variable is one assignment found in a script.
type Variable struct {
	Line  int
	Name  string
	Value string
}

// Transform is a data-encoding, compression or encryption operation.
type Transform struct {
	Line   int
	Method string
	Text   string
}

// ExtractCommand parses a command line found outside a script, where no
// file extension names the shell. A cmdlet or a PowerShell host decides for
// PowerShell, and a drive path, an .exe or a slash switch for cmd.exe.
func ExtractCommand(text string) Script {
	if rxPsShape.MatchString(text) {
		return ExtractPowerShell(text)
	}
	if rxNativeShape.MatchString(text) {
		return ExtractBatch(text)
	}
	return ExtractBash(text)
}

var (
	rxPsShape     = regexp.MustCompile(`\b[A-Z][a-z]+-[A-Z][A-Za-z]+\b|(?i)\b(?:powershell|pwsh)(?:\.exe)?\b`)
	rxNativeShape = regexp.MustCompile(`(?i)[a-z]:\\|\\\\[\w.-]+\\|\.exe\b|%\w+%|\s/[a-z]{1,2}(?:[:\s]|$)|\bprocess\s+call\s+create\b`)
)
