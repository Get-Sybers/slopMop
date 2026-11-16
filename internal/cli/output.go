package cli

import "slices"

// Output holds the output flags, the same on every verb that prints rows.
type Output struct {
	View      string // "", "wide", "json"
	Quiet     bool
	NoHeaders bool
	Local     bool
}

const (
	viewHint = "wide|json"
	zoneHint = "local|utc"
)

func isOutputFlag(name string) bool {
	return slices.Contains([]string{"o", "q", "no-headers", "tz"}, name)
}

func outputTakesValue(t token) bool {
	return t.dashes == 1 && t.name == "o" || t.dashes == 2 && t.name == "tz"
}

// outputForm spells an output flag with its own prefix, whichever prefix was typed.
func outputForm(name string) string {
	if name == "o" || name == "q" {
		return "-" + name
	}
	return "--" + name
}

func (p *parser) output(t token) error {
	if !p.spec.Rows {
		return usagef("%s applies only to verbs that print rows", outputForm(t.name))
	}
	switch t.name {
	case "o":
		return p.view(t)
	case "q":
		return p.quiet(t)
	case "no-headers":
		return p.noHeaders(t)
	default:
		return p.zone(t)
	}
}

func (p *parser) view(t token) error {
	switch {
	case t.dashes == 2:
		return usagef("--o is an output flag; use -o %s", viewHint)
	case p.viewGiven:
		return usagef("-o given more than once")
	case t.value == "":
		return usagef("-o needs a value %s", viewHint)
	case t.value != "wide" && t.value != "json":
		return usagef("unknown view %q (valid views: json, wide)", t.value)
	}
	p.viewGiven = true
	p.args.Output.View = t.value
	return nil
}

func (p *parser) quiet(t token) error {
	switch {
	case t.dashes == 2:
		return usagef("--q takes no value; use -q")
	case t.hasValue:
		return usagef("-q takes no value")
	}
	p.args.Output.Quiet = true
	return nil
}

func (p *parser) noHeaders(t token) error {
	switch {
	case t.dashes == 1:
		return usagef("-no-headers is an output flag; use --no-headers")
	case t.hasValue:
		return usagef("--no-headers takes no value")
	}
	p.args.Output.NoHeaders = true
	return nil
}

func (p *parser) zone(t token) error {
	switch {
	case t.dashes == 1:
		return usagef("-tz takes a value; use --tz %s", zoneHint)
	case p.zoneGiven:
		return usagef("--tz given more than once")
	case t.value == "":
		return usagef("--tz needs a value %s", zoneHint)
	case t.value != "local" && t.value != "utc":
		return usagef("unknown zone %q (valid zones: local, utc)", t.value)
	}
	p.zoneGiven = true
	p.args.Output.Local = t.value == "local"
	return nil
}
