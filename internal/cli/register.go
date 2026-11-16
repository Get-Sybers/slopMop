package cli

import (
	"errors"
	"fmt"
	"slices"
)

// Register adds a noun, or adds nothing and returns an error when the noun breaks a rule
// of the grammar. That error is a programming mistake, so it does not match ErrUsage.
func (a *App) Register(n *Noun) error {
	if err := a.check(n); err != nil {
		return fmt.Errorf("register noun %q: %w", n.Name, err)
	}
	a.nouns = append(a.nouns, n)
	for _, name := range n.names() {
		a.index[name] = n
	}
	return nil
}

// Whole sets the command that runs when the first argument names no noun.
// It takes one positional and bare words that select its sections; no word
// means every section. It takes no output flags.
func (a *App) Whole(summary, positional string, words []Word, s Spec, run func(a *Args) error) error {
	s.Rows, s.Selectors = false, map[string]string{}
	s.Positional, s.MinPos, s.MaxPos = positional, 1, 1
	for _, w := range words {
		if _, twice := s.Selectors[w.Name]; twice || w.Name == "" || w.Summary == "" {
			return fmt.Errorf("the command without a noun: the word %q is repeated or lacks a name or a summary", w.Name)
		}
		s.Selectors[w.Name] = w.Summary
	}
	v := &Verb{Summary: summary, Spec: s, Run: run}
	switch {
	case a.whole != nil:
		return errors.New("the command without a noun is already set")
	case summary == "" || positional == "":
		return errors.New("the command without a noun needs a summary and a positional")
	}
	if err := checkVerb(v); err != nil {
		return fmt.Errorf("the command without a noun: %w", err)
	}
	a.whole, a.words = v, words
	return nil
}

func (a *App) check(n *Noun) error {
	nouns := map[string]bool{}
	for _, name := range n.names() {
		if _, taken := a.index[name]; taken || nouns[name] {
			return fmt.Errorf("noun name %q is already taken", name)
		}
		nouns[name] = true
	}
	verbs := map[string]bool{}
	for _, v := range n.Verbs {
		for _, name := range v.names() {
			if verbs[name] {
				return fmt.Errorf("verb name %q is repeated", name)
			}
			verbs[name] = true
		}
		if err := checkVerb(v); err != nil {
			return fmt.Errorf("verb %q: %w", v.Name, err)
		}
	}
	return nil
}

func checkVerb(v *Verb) error {
	if v.Run == nil {
		return errors.New("no Run function")
	}
	for _, name := range v.names() {
		global, alias, ok := globalVerb(name)
		if ok && (v.Name != global || !slices.Contains(v.Aliases, alias)) {
			return fmt.Errorf("%q is reserved for the pair %s/%s", name, global, alias)
		}
	}
	for _, name := range sortedKeys(v.Spec.Selectors) {
		if reserved(name) {
			return fmt.Errorf("selector name %q is reserved", name)
		}
		if _, both := v.Spec.Params[name]; both {
			return fmt.Errorf("%q is both a selector and a param", name)
		}
	}
	for _, name := range sortedKeys(v.Spec.Params) {
		if reserved(name) {
			return fmt.Errorf("param name %q is reserved", name)
		}
	}
	if err := checkSwitches(v.Spec); err != nil {
		return err
	}
	for _, name := range v.Spec.Required {
		if _, declared := v.Spec.Params[name]; !declared {
			return fmt.Errorf("required param %q is not declared", name)
		}
	}
	return nil
}

func checkSwitches(s Spec) error {
	shorts := map[string]bool{}
	for _, name := range sortedKeys(s.Switches) {
		if reserved(name) {
			return fmt.Errorf("switch name %q is reserved", name)
		}
		if s.declares(name) {
			return fmt.Errorf("%q is both a switch and a selector or param", name)
		}
		short := s.Switches[name].Short
		if short == "" {
			continue
		}
		if len(short) != 1 || short[0] < 'a' || short[0] > 'z' {
			return fmt.Errorf("short form %q of the switch %q is not one lower-case letter", short, name)
		}
		_, isSwitch := s.Switches[short]
		if reserved(short) || s.declares(short) || isSwitch || shorts[short] {
			return fmt.Errorf("short form %q of the switch %q is already taken", short, name)
		}
		shorts[short] = true
	}
	return nil
}

func (s Spec) declares(name string) bool {
	_, selector := s.Selectors[name]
	_, param := s.Params[name]
	return selector || param
}

// globalVerb returns the pair a global verb is spelt as on every noun.
func globalVerb(word string) (name, alias string, ok bool) {
	switch word {
	case "list", "ls":
		return "list", "ls", true
	case "get", "show":
		return "get", "show", true
	case "delete", "rm":
		return "delete", "rm", true
	default:
		return "", "", false
	}
}

func reserved(name string) bool {
	return isOutputFlag(name) || name == "h" || name == "help"
}
