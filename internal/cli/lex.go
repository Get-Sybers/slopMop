package cli

import "strings"

// token is one lexed argument: a flag when dashes is 1 or 2, a positional when it is 0.
type token struct {
	dashes   int
	name     string
	value    string
	hasValue bool
}

// lex splits a verb's arguments into tokens and reports a request for help. It is the
// one definition of a value position, so help and parsing cannot disagree about it.
func lex(s Spec, args []string) (tokens []token, help bool) {
	if len(args) == 1 && args[0] == "help" {
		return nil, true
	}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--":
			for _, arg := range args[i+1:] {
				tokens = append(tokens, token{name: arg})
			}
			return tokens, false
		case "-h", "--help":
			return nil, true
		}
		t := flagToken(args[i])
		if s.takesValue(t) && i+1 < len(args) {
			i++
			t.value, t.hasValue = args[i], true
		}
		tokens = append(tokens, t)
	}
	return tokens, false
}

func flagToken(arg string) token {
	dashes := 0
	switch {
	case strings.HasPrefix(arg, "--"):
		dashes = 2
	case len(arg) > 1 && arg[0] == '-':
		dashes = 1
	default:
		return token{name: arg}
	}
	name, value, attached := strings.Cut(arg[dashes:], "=")
	return token{dashes: dashes, name: name, value: value, hasValue: attached}
}

// takesValue reports whether the argument after t is t's value.
func (s Spec) takesValue(t token) bool {
	if t.hasValue {
		return false
	}
	if _, param := s.Params[t.name]; param && t.dashes == 2 {
		return true
	}
	return s.Rows && outputTakesValue(t)
}
