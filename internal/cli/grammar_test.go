package cli_test

import (
	"errors"
	"testing"

	"github.com/get-sybers/slopmop/internal/cli"
)

func TestShouldWork(t *testing.T) {
	every := []string{"auth", "firewall", "kernel", "sysmon", "task"}
	tests := []struct {
		cmd      string
		selected string
		verb     string
		want     cli.Args
	}{
		{cmd: "node list", verb: "node list"},
		{cmd: "nodes ls", verb: "node list"},
		{cmd: "node select pve2", verb: "node select", want: cli.Args{Pos: []string{"pve2"}}},
		{cmd: "node select", verb: "node select"},
		{cmd: "users list", verb: "user list"},
		{cmd: "groups list", verb: "group list"},
		{cmd: "logs list", verb: "logs list", want: cli.Args{Selectors: every}},
		{cmd: "logs list -auth", verb: "logs list", want: cli.Args{Selectors: []string{"auth"}}},
		{cmd: "logs list -auth -sysmon", verb: "logs list", want: cli.Args{Selectors: []string{"auth", "sysmon"}}},
		{
			cmd: "logs list --node pve1", verb: "logs list",
			want: cli.Args{Selectors: every, Params: map[string]string{"node": "pve1"}},
		},
		{
			cmd: "logs clear -sysmon", selected: "pve1", verb: "logs clear",
			want: cli.Args{Selectors: []string{"sysmon"}},
		},
		{
			cmd: "logs clear -sysmon --node all", verb: "logs clear",
			want: cli.Args{Selectors: []string{"sysmon"}, Params: map[string]string{"node": "all"}},
		},
		{cmd: "service list", verb: "service list"},
		{
			cmd: "service list --node all", selected: "pve1", verb: "service list",
			want: cli.Args{Params: map[string]string{"node": "all"}},
		},
		{cmd: "network ls --node pve1", verb: "network list", want: cli.Args{Params: map[string]string{"node": "pve1"}}},
		{
			cmd: "file cp pve1:/etc/hosts pve2:/tmp/hosts", verb: "file cp",
			want: cli.Args{Pos: []string{"pve1:/etc/hosts", "pve2:/tmp/hosts"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			app, c, out := newApp(t)
			c.selected = tt.selected
			if err := app.Run(words(tt.cmd)); err != nil {
				t.Fatalf("Run(%q) = %v, want nil", tt.cmd, err)
			}
			checkCall(t, c, tt.verb, tt.want)
			if out.Len() != 0 {
				t.Errorf("output = %q, want none", out.String())
			}
		})
	}
}

func TestShouldFail(t *testing.T) {
	tests := []struct {
		cmd   string
		want  string
		usage bool
	}{
		{
			cmd:  "logs clear",
			want: "clear needs a log type, e.g. -sysmon (valid: -auth, -firewall, -kernel, -sysmon, -task)",
		},
		{
			cmd:  "logs clear -sysmon",
			want: "no node: pass --node <name>|all or run `slopmop node select <name>`",
		},
		{
			cmd:   "logs list -bogus",
			want:  "unknown selector -bogus (valid selectors: -auth, -firewall, -kernel, -sysmon, -task)",
			usage: true,
		},
		{cmd: "logs list --auth", want: `--auth takes no value; "auth" is a selector, use -auth`, usage: true},
		{cmd: "service list -node pve1", want: "-node takes a value; use --node <node>|all", usage: true},
		{cmd: "service list --node", want: "--node needs a value <node>|all", usage: true},
		{cmd: "file cp onlyonepath", want: "file cp expects 2 positional arg(s), got 1", usage: true},
		{cmd: "node list -auth", want: "unknown selector -auth", usage: true},
		{cmd: "bogus list", want: `unknown noun "bogus"`, usage: true},
	}
	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			app, c, out := newApp(t)
			err := app.Run(words(tt.cmd))
			if err == nil {
				t.Fatalf("Run(%q) = nil, want %q", tt.cmd, tt.want)
			}
			if got := err.Error(); got != tt.want {
				t.Errorf("error = %q, want %q", got, tt.want)
			}
			if got := errors.Is(err, cli.ErrUsage); got != tt.usage {
				t.Errorf("errors.Is(err, ErrUsage) = %t, want %t", got, tt.usage)
			}
			checkNothingRan(t, c, out)
		})
	}
}
