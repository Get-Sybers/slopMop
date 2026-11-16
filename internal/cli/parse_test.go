package cli_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/get-sybers/slopmop/internal/cli"
)

func TestUsageMessages(t *testing.T) {
	const (
		selectors = " (valid selectors: -auth, -firewall, -kernel, -sysmon, -task)"
		params    = " (valid params: --node <node>|all, --since <time>)"
	)
	tests := []struct {
		args []string
		want string
	}{
		{words("bogus list"), `unknown noun "bogus"`},
		{words("bogus"), `unknown noun "bogus"`},
		{words("-x"), `unknown noun "-x"`},
		{words("logs bogus"), `logs has no verb "bogus"`},
		{words("logs -auth"), `logs has no verb "-auth"`},

		{words("logs list -bogus"), "unknown selector -bogus" + selectors},
		{words("logs list -bogus=1"), "unknown selector -bogus" + selectors},
		{words("logs list -help"), "unknown selector -help" + selectors},
		{words("node list -bogus"), "unknown selector -bogus"},
		{words("file cp -5 a"), "unknown selector -5"},
		{words("logs list -auth=1"), "-auth takes no value"},

		{words("logs list --bogus x"), "unknown option --bogus" + params},
		{words("logs list --bogus=x"), "unknown option --bogus" + params},
		{words("logs list --h"), "unknown option --h" + params},
		{words("node list --bogus"), "unknown option --bogus"},

		{words("logs list --auth"), `--auth takes no value; "auth" is a selector, use -auth`},
		{words("logs list --auth=1"), `--auth takes no value; "auth" is a selector, use -auth`},
		{words("logs list -node pve1"), "-node takes a value; use --node <node>|all"},
		{words("logs list -node=pve1"), "-node takes a value; use --node <node>|all"},
		{words("logs list -since"), "-since takes a value; use --since <time>"},

		{words("logs list --node"), "--node needs a value <node>|all"},
		{words("logs list -auth --since"), "--since needs a value <time>"},
		{words("logs list --node="), "--node needs a value <node>|all"},
		{[]string{"logs", "list", "--node", ""}, "--node needs a value <node>|all"},
		{[]string{"logs", "list", "--node", "", "-auth"}, "--node needs a value <node>|all"},

		{words("logs list --node pve1 --node pve2"), "--node given more than once"},
		{words("logs list --node=pve1 --node pve1"), "--node given more than once"},
		{words("logs list --node pve1 --since 1 --node=pve2"), "--node given more than once"},
		{words("logs list --node pve1 --node"), "--node given more than once"},

		{words("node list extra"), "node list expects no positional args, got 1"},
		{words("logs list a b"), "logs list expects no positional args, got 2"},
		{words("file cp"), "file cp expects 2 positional arg(s), got 0"},
		{words("file cp a b c"), "file cp expects 2 positional arg(s), got 3"},
		{words("user get"), "user get expects 1 positional arg(s), got 0"},
		{words("user delete"), "user delete expects at least 1 positional arg(s), got 0"},
		{words("node select a b"), "node select expects 0 to 1 positional args, got 2"},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			app, c, out := newApp(t)
			checkUsage(t, app.Run(tt.args), tt.want)
			checkNothingRan(t, c, out)
		})
	}
}

func TestEndOfFlags(t *testing.T) {
	tests := []struct {
		cmd  string
		verb string
		want cli.Args
	}{
		{"file cp -- -a -b", "file cp", cli.Args{Pos: []string{"-a", "-b"}}},
		{"file cp a -- --b", "file cp", cli.Args{Pos: []string{"a", "--b"}}},
		{"file cp -- a b", "file cp", cli.Args{Pos: []string{"a", "b"}}},
		{"file cp -- -- --", "file cp", cli.Args{Pos: []string{"--", "--"}}},
		{"file cp - a", "file cp", cli.Args{Pos: []string{"-", "a"}}},
		{"node select --", "node select", cli.Args{}},
		{"node select -- --node=x", "node select", cli.Args{Pos: []string{"--node=x"}}},
		{"logs clear -auth --node pve1 --", "logs clear", cli.Args{
			Selectors: []string{"auth"}, Params: map[string]string{"node": "pve1"},
		}},
		{"user delete -- -q -o --tz", "user delete", cli.Args{Pos: []string{"-q", "-o", "--tz"}}},
		{"user get -q -- -o", "user get", cli.Args{Pos: []string{"-o"}, Output: cli.Output{Quiet: true}}},
		{"logs clear -auth --node -- -task", "logs clear", cli.Args{
			Selectors: []string{"auth", "task"}, Params: map[string]string{"node": "--"},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			app, c, _ := newApp(t)
			if err := app.Run(words(tt.cmd)); err != nil {
				t.Fatalf("Run(%q) = %v, want nil", tt.cmd, err)
			}
			checkCall(t, c, tt.verb, tt.want)
		})
	}
}

func TestEndOfFlagsCountsPositionals(t *testing.T) {
	app, c, out := newApp(t)
	checkUsage(t, app.Run(words("logs list -- -auth")), "logs list expects no positional args, got 1")
	checkNothingRan(t, c, out)
}

func TestParams(t *testing.T) {
	every := []string{"auth", "firewall", "kernel", "sysmon", "task"}
	tests := []struct {
		cmd  string
		want map[string]string
	}{
		{"logs list", map[string]string{}},
		{"logs list --node pve1", map[string]string{"node": "pve1"}},
		{"logs list --node=pve1", map[string]string{"node": "pve1"}},
		{"logs list --node=a=b", map[string]string{"node": "a=b"}},
		{"logs list --node -auth", map[string]string{"node": "-auth"}},
		{"logs list --node --since", map[string]string{"node": "--since"}},
		{"logs list --node=-x", map[string]string{"node": "-x"}},
		{"logs list --since=09:00 --node all", map[string]string{"node": "all", "since": "09:00"}},
	}
	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			app, c, _ := newApp(t)
			if err := app.Run(words(tt.cmd)); err != nil {
				t.Fatalf("Run(%q) = %v, want nil", tt.cmd, err)
			}
			checkCall(t, c, "logs list", cli.Args{Selectors: every, Params: tt.want})
			if c.calls[0].args.Params == nil {
				t.Errorf("Params = nil, want a map that is safe to read and write")
			}
		})
	}
}

func TestParamWithoutHint(t *testing.T) {
	tests := []struct {
		cmd  string
		want string
	}{
		{"probe scan --bare", "--bare needs a value"},
		{"probe scan --bare=", "--bare needs a value"},
		{"probe scan -bare", "-bare takes a value; use --bare"},
		{"probe scan --bogus", "unknown option --bogus (valid params: --bare, --since <time>)"},
	}
	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			app := cli.New("slopmop", &bytes.Buffer{})
			noun := &cli.Noun{Name: "probe", Verbs: []*cli.Verb{{
				Name: "scan",
				Spec: cli.Spec{Params: map[string]string{"bare": "", "since": "<time>"}},
				Run:  ran,
			}}}
			if err := app.Register(noun); err != nil {
				t.Fatalf("Register = %v, want nil", err)
			}
			checkUsage(t, app.Run(words(tt.cmd)), tt.want)
		})
	}
}

func TestSelectors(t *testing.T) {
	tests := []struct {
		cmd  string
		want []string
	}{
		{"logs clear -auth --node all", []string{"auth"}},
		{"logs clear --node all -task -auth -kernel", []string{"auth", "kernel", "task"}},
		{"logs clear -sysmon --node all -sysmon -sysmon", []string{"sysmon"}},
		{"logs clear -task -sysmon -kernel -firewall -auth --node=all", []string{"auth", "firewall", "kernel", "sysmon", "task"}},
	}
	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			app, c, _ := newApp(t)
			if err := app.Run(words(tt.cmd)); err != nil {
				t.Fatalf("Run(%q) = %v, want nil", tt.cmd, err)
			}
			checkCall(t, c, "logs clear", cli.Args{Selectors: tt.want, Params: map[string]string{"node": "all"}})
		})
	}
}
