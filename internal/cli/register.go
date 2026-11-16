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
	for _, name := range v.Spec.Required {
		if _, declared := v.Spec.Params[name]; !declared {
			return fmt.Errorf("required param %q is not declared", name)
		}
	}
	return nil
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
