package cli_test

import (
	"strings"
	"testing"

	"github.com/get-sybers/slopmop/internal/cli"
)

func TestOutputFlags(t *testing.T) {
	tests := []struct {
		flags string
		want  cli.Output
	}{
		{"", cli.Output{}},
		{"-o wide", cli.Output{View: "wide"}},
		{"-o json", cli.Output{View: "json"}},
		{"-o=wide", cli.Output{View: "wide"}},
		{"-o=json", cli.Output{View: "json"}},
		{"-q", cli.Output{Quiet: true}},
		{"-q -q", cli.Output{Quiet: true}},
		{"--no-headers", cli.Output{NoHeaders: true}},
		{"--no-headers --no-headers", cli.Output{NoHeaders: true}},
		{"--tz local", cli.Output{Local: true}},
		{"--tz=local", cli.Output{Local: true}},
		{"--tz utc", cli.Output{}},
		{"--tz=utc", cli.Output{}},
		{"-q --no-headers", cli.Output{Quiet: true, NoHeaders: true}},
		{"--tz local --no-headers -o wide", cli.Output{View: "wide", NoHeaders: true, Local: true}},
		{"-o json --tz utc", cli.Output{View: "json"}},
	}
	for _, tt := range tests {
		t.Run(tt.flags, func(t *testing.T) {
			for _, cmd := range []string{"user get " + tt.flags + " alice", "user get alice " + tt.flags} {
				app, c, _ := newApp(t)
				if err := app.Run(words(cmd)); err != nil {
					t.Fatalf("Run(%q) = %v, want nil", cmd, err)
				}
				checkCall(t, c, "user get", cli.Args{Pos: []string{"alice"}, Output: tt.want})
			}
		})
	}
}

func TestOutputFlagsOnListVerb(t *testing.T) {
	app, c, _ := newApp(t)
	if err := app.Run(words("logs ls -auth -o json --node pve1 --tz local --no-headers")); err != nil {
		t.Fatalf("Run = %v, want nil", err)
	}
	checkCall(t, c, "logs list", cli.Args{
		Selectors: []string{"auth"},
		Params:    map[string]string{"node": "pve1"},
		Output:    cli.Output{View: "json", NoHeaders: true, Local: true},
	})
}

func TestOutputFlagErrors(t *testing.T) {
	const rows = "applies only to verbs that print rows"
	tests := []struct {
		args []string
		want string
	}{
		{words("user get alice -o"), "-o needs a value wide|json"},
		{words("user get alice -o="), "-o needs a value wide|json"},
		{[]string{"user", "get", "-o", "", "alice"}, "-o needs a value wide|json"},
		{words("user get alice -o yaml"), `unknown view "yaml" (valid views: json, wide)`},
		{words("user get alice -o=yaml"), `unknown view "yaml" (valid views: json, wide)`},
		{words("user get alice -o JSON"), `unknown view "JSON" (valid views: json, wide)`},
		{words("user get -o alice"), `unknown view "alice" (valid views: json, wide)`},

		{words("user get alice --tz"), "--tz needs a value local|utc"},
		{words("user get alice --tz="), "--tz needs a value local|utc"},
		{[]string{"user", "get", "--tz", "", "alice"}, "--tz needs a value local|utc"},
		{words("user get alice --tz cet"), `unknown zone "cet" (valid zones: local, utc)`},
		{words("user get alice --tz=UTC"), `unknown zone "UTC" (valid zones: local, utc)`},

		{words("user get alice -tz local"), "-tz takes a value; use --tz local|utc"},
		{words("user get alice -tz=local"), "-tz takes a value; use --tz local|utc"},
		{words("user get alice --q"), "--q takes no value; use -q"},
		{words("user get alice --q=1"), "--q takes no value; use -q"},
		{words("user get alice --o json"), "--o is an output flag; use -o wide|json"},
		{words("user get alice --o=json"), "--o is an output flag; use -o wide|json"},
		{words("user get alice -no-headers"), "-no-headers is an output flag; use --no-headers"},

		{words("user get alice -q=1"), "-q takes no value"},
		{words("user get alice --no-headers=1"), "--no-headers takes no value"},

		{words("user get alice -q -o json"), "-q cannot be combined with -o"},
		{words("user get alice -o wide -q"), "-q cannot be combined with -o"},
		{words("user get alice -o json -o wide"), "-o given more than once"},
		{words("user get alice -o json -o=json"), "-o given more than once"},
		{words("user get alice -o json -o"), "-o given more than once"},
		{words("user get alice --tz utc --tz local"), "--tz given more than once"},
		{words("user get alice --tz=utc --tz=utc"), "--tz given more than once"},

		{words("logs clear -sysmon -o json"), "-o " + rows},
		{words("logs clear -sysmon -o"), "-o " + rows},
		{words("logs clear -sysmon -q"), "-q " + rows},
		{words("logs clear -sysmon --no-headers"), "--no-headers " + rows},
		{words("logs clear -sysmon --tz local"), "--tz " + rows},
		{words("logs clear -sysmon --tz=local"), "--tz " + rows},
		{words("node select pve1 -q"), "-q " + rows},
		{words("file cp a b --no-headers"), "--no-headers " + rows},
		{words("logs clear -sysmon --o json"), "-o " + rows},
		{words("logs clear -sysmon --q"), "-q " + rows},
		{words("logs clear -sysmon -no-headers"), "--no-headers " + rows},
		{words("logs clear -sysmon -tz local"), "--tz " + rows},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			app, c, out := newApp(t)
			checkUsage(t, app.Run(tt.args), tt.want)
			checkNothingRan(t, c, out)
		})
	}
}
