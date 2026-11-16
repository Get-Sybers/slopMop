package cli_test

import (
	"testing"

	"github.com/get-sybers/slopmop/internal/cli"
)

func TestSwitches(t *testing.T) {
	tests := []struct {
		cmd  string
		want cli.Args
	}{
		{"service list", cli.Args{}},
		{"service list --all", cli.Args{Switches: map[string]bool{"all": true}}},
		{"service list -a", cli.Args{Switches: map[string]bool{"all": true}}},
		{"service list -a --all -a", cli.Args{Switches: map[string]bool{"all": true}}},
		{"service list --verbose -a", cli.Args{Switches: map[string]bool{"all": true, "verbose": true}}},
		{"service list --node pve1 -a -q", cli.Args{
			Params: map[string]string{"node": "pve1"}, Switches: map[string]bool{"all": true}, Output: cli.Output{Quiet: true},
		}},
		{"service list --all --node pve1", cli.Args{
			Params: map[string]string{"node": "pve1"}, Switches: map[string]bool{"all": true},
		}},
		{"service list --node --all", cli.Args{Params: map[string]string{"node": "--all"}}},
	}
	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			app, c, _ := newApp(t)
			if err := app.Run(words(tt.cmd)); err != nil {
				t.Fatalf("Run(%q) = %v, want nil", tt.cmd, err)
			}
			checkCall(t, c, "service list", tt.want)
			if c.calls[0].args.Switches == nil {
				t.Errorf("Switches = nil, want a map that is safe to read")
			}
		})
	}
}

func TestSwitchUsageMessages(t *testing.T) {
	tests := []struct {
		cmd  string
		want string
	}{
		{"service list -all", "-all is a switch; use --all"},
		{"service list --a", "--a is a short form; use -a or --all"},
		{"service list --all=yes", "--all takes no value"},
		{"service list -a=1", "-a takes no value"},
		{"service list --all yes", "service list expects no positional args, got 1"},
		{"service list -v", "unknown selector -v"},
		{"node list -a", "unknown selector -a"},
		{"node list --all", "unknown option --all"},
	}
	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			app, c, out := newApp(t)
			checkUsage(t, app.Run(words(tt.cmd)), tt.want)
			checkNothingRan(t, c, out)
		})
	}
}

func TestRegisterRejectsSwitches(t *testing.T) {
	const prefix = `register noun "host": verb "scan": `
	tests := []struct {
		name string
		spec cli.Spec
		want string
	}{
		{"reserved name", cli.Spec{Switches: map[string]cli.Switch{"help": {}}}, `switch name "help" is reserved`},
		{
			"name of a selector",
			cli.Spec{Selectors: map[string]string{"deep": ""}, Switches: map[string]cli.Switch{"deep": {}}},
			`"deep" is both a switch and a selector or param`,
		},
		{
			"name of a param",
			cli.Spec{Params: map[string]string{"deep": ""}, Switches: map[string]cli.Switch{"deep": {}}},
			`"deep" is both a switch and a selector or param`,
		},
		{
			"long short form", cli.Spec{Switches: map[string]cli.Switch{"deep": {Short: "de"}}},
			`short form "de" of the switch "deep" is not one lower-case letter`,
		},
		{
			"upper-case short form", cli.Spec{Switches: map[string]cli.Switch{"deep": {Short: "D"}}},
			`short form "D" of the switch "deep" is not one lower-case letter`,
		},
		{
			"short form of an output flag", cli.Spec{Switches: map[string]cli.Switch{"quick": {Short: "q"}}},
			`short form "q" of the switch "quick" is already taken`,
		},
		{
			"short form of a selector",
			cli.Spec{Selectors: map[string]string{"d": ""}, Switches: map[string]cli.Switch{"deep": {Short: "d"}}},
			`short form "d" of the switch "deep" is already taken`,
		},
		{
			"short form of another switch",
			cli.Spec{Switches: map[string]cli.Switch{"deep": {Short: "d"}, "dry": {Short: "d"}}},
			`short form "d" of the switch "dry" is already taken`,
		},
		{
			"short form that is a switch name",
			cli.Spec{Switches: map[string]cli.Switch{"deep": {Short: "x"}, "x": {}}},
			`short form "x" of the switch "deep" is already taken`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, _, _ := newApp(t)
			noun := &cli.Noun{Name: "host", Verbs: []*cli.Verb{{Name: "scan", Spec: tt.spec, Run: ran}}}
			err := app.Register(noun)
			if err == nil || err.Error() != prefix+tt.want {
				t.Errorf("Register = %v, want %q", err, prefix+tt.want)
			}
		})
	}
}
