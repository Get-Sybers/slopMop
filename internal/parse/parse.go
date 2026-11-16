// Package parse extracts commands, variables and file references from scripts.
package parse

// Script holds the static analysis of one script file.
type Script struct {
	Commands   []Command
	Variables  []Variable
	Writes     []string
	Reads      []string
	Transforms []Transform
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
