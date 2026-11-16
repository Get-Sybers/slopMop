package cli

import (
	"maps"
	"slices"
	"strings"
)

type parser struct {
	spec      Spec
	args      *Args
	chosen    map[string]bool
	viewGiven bool
	zoneGiven bool
}

// parse checks the tokens of one verb against its spec; name is "NOUN VERB" in canonical form.
func parse(name string, s Spec, tokens []token) (*Args, error) {
	p := &parser{spec: s, args: &Args{Params: map[string]string{}, Switches: map[string]bool{}}, chosen: map[string]bool{}}
	for _, t := range tokens {
		if err := p.take(t); err != nil {
			return nil, err
		}
	}
	for _, required := range s.Required {
		if _, given := p.args.Params[required]; !given {
			return nil, usagef("%s needs %s", name, withHint("--"+required, s.Params[required]))
		}
	}
	if p.args.Output.Quiet && p.viewGiven {
		return nil, usagef("-q cannot be combined with -o")
	}
	if n := len(p.args.Pos); n < s.MinPos || (s.MaxPos >= 0 && n > s.MaxPos) {
		return nil, usagef("%s expects %s, got %d", name, s.positionalRule(), n)
	}
	p.args.Selectors = slices.Sorted(maps.Keys(p.chosen))
	return p.args, nil
}

func (p *parser) take(t token) error {
	switch {
	case t.dashes == 0:
		p.args.Pos = append(p.args.Pos, t.name)
		return nil
	case isOutputFlag(t.name):
		return p.output(t)
	}
	if name, short, ok := p.spec.switchName(t.name); ok {
		return p.toggle(t, name, short)
	}
	if t.dashes == 2 {
		return p.param(t)
	}
	return p.selector(t)
}

func (p *parser) toggle(t token, name string, short bool) error {
	switch {
	case short && t.dashes == 2:
		return usagef("--%s is a short form; use -%s or --%s", t.name, t.name, name)
	case !short && t.dashes == 1:
		return usagef("-%s is a switch; use --%s", t.name, name)
	case t.hasValue:
		return usagef("%s%s takes no value", strings.Repeat("-", t.dashes), t.name)
	}
	p.args.Switches[name] = true
	return nil
}

func (p *parser) selector(t token) error {
	if _, ok := p.spec.Selectors[t.name]; !ok {
		if hint, isParam := p.spec.Params[t.name]; isParam {
			return usagef("-%s takes a value; use %s", t.name, withHint("--"+t.name, hint))
		}
		return usagef("unknown selector -%s%s", t.name, valid("selectors", p.spec.selectorList()))
	}
	if t.hasValue {
		return usagef("-%s takes no value", t.name)
	}
	p.chosen[t.name] = true
	return nil
}

func (p *parser) param(t token) error {
	hint, ok := p.spec.Params[t.name]
	if !ok {
		if _, isSelector := p.spec.Selectors[t.name]; isSelector {
			return usagef("--%s takes no value; %q is a selector, use -%s", t.name, t.name, t.name)
		}
		return usagef("unknown option --%s%s", t.name, valid("params", p.spec.paramList()))
	}
	if _, given := p.args.Params[t.name]; given {
		return usagef("--%s given more than once", t.name)
	}
	if t.value == "" {
		return usagef("%s", withHint("--"+t.name+" needs a value", hint))
	}
	p.args.Params[t.name] = t.value
	return nil
}
