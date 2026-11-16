package cli

// ListVerb is the one definition of the global verb: name list, alias ls, Rows true, no
// positionals; before run it replaces an empty selection with every selector, sorted.
func ListVerb(summary string, s Spec, run func(a *Args) error) *Verb {
	s.Rows = true
	s.Positional, s.MinPos, s.MaxPos = "", 0, 0
	v := &Verb{Name: "list", Aliases: []string{"ls"}, Summary: summary, Spec: s}
	if run == nil {
		return v
	}
	v.Run = func(a *Args) error {
		if len(a.Selectors) == 0 {
			a.Selectors = sortedKeys(s.Selectors)
		}
		return run(a)
	}
	return v
}
