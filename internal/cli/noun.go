package cli

import "slices"

type Verb struct {
	Name, Summary string
	Aliases       []string
	Spec          Spec
	Run           func(a *Args) error
}

type Noun struct {
	Name, Summary string
	Aliases       []string
	Verbs         []*Verb
}

func (v *Verb) names() []string {
	return append([]string{v.Name}, v.Aliases...)
}

func (n *Noun) names() []string {
	return append([]string{n.Name}, n.Aliases...)
}

func (n *Noun) verb(name string) *Verb {
	for _, v := range n.Verbs {
		if slices.Contains(v.names(), name) {
			return v
		}
	}
	return nil
}
