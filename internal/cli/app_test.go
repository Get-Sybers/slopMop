package cli_test

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/get-sybers/slopmop/internal/cli"
)

func TestAliasesResolve(t *testing.T) {
	tests := []struct {
		cmd  string
		verb string
	}{
		{"node list", "node list"},
		{"node ls", "node list"},
		{"nodes list", "node list"},
		{"nodes ls", "node list"},
		{"nodes select pve1", "node select"},
		{"user get alice", "user get"},
		{"users show alice", "user get"},
		{"user delete alice", "user delete"},
		{"users rm alice bob", "user delete"},
		{"groups ls", "group list"},
		{"log ls", "logs list"},
		{"log clear -auth --node all", "logs clear"},
		{"services ls", "service list"},
		{"svc list", "service list"},
		{"networks list", "network list"},
		{"net ls", "network list"},
		{"files copy a b", "file cp"},
		{"file copy a b", "file cp"},
		{"files cp a b", "file cp"},
	}
	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			app, c, _ := newApp(t)
			if err := app.Run(words(tt.cmd)); err != nil {
				t.Fatalf("Run(%q) = %v, want nil", tt.cmd, err)
			}
			if len(c.calls) != 1 {
				t.Fatalf("verbs run = %d, want 1", len(c.calls))
			}
			if got := c.calls[0].verb; got != tt.verb {
				t.Errorf("verb = %q, want %q", got, tt.verb)
			}
		})
	}
}

func TestMessagesCarryCanonicalNames(t *testing.T) {
	tests := []struct {
		cmd  string
		want string
	}{
		{"log nope", `logs has no verb "nope"`},
		{"svc nope", `service has no verb "nope"`},
		{"nodes ls extra", "node list expects no positional args, got 1"},
		{"files copy a", "file cp expects 2 positional arg(s), got 1"},
		{"users show", "user get expects 1 positional arg(s), got 0"},
		{"users rm", "user delete expects at least 1 positional arg(s), got 0"},
		{"nodes select a b", "node select expects 0 to 1 positional args, got 2"},
	}
	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			app, c, out := newApp(t)
			checkUsage(t, app.Run(words(tt.cmd)), tt.want)
			checkNothingRan(t, c, out)
		})
	}
}

func TestVerbErrorPassesThrough(t *testing.T) {
	plain := errors.New("the node is on fire")
	tests := []struct {
		name  string
		err   error
		usage bool
	}{
		{"plain error", plain, false},
		{"wrapped error", fmt.Errorf("read node: %w", plain), false},
		{"an error the verb marks as usage", fmt.Errorf("pick one: %w", cli.ErrUsage), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := cli.New("slopmop", &bytes.Buffer{})
			noun := &cli.Noun{Name: "node", Verbs: []*cli.Verb{{
				Name: "burn", Run: func(*cli.Args) error { return tt.err },
			}}}
			if err := app.Register(noun); err != nil {
				t.Fatalf("Register = %v, want nil", err)
			}
			err := app.Run(words("node burn"))
			if err == nil {
				t.Fatalf("Run = nil, want %q", tt.err)
			}
			if !errors.Is(err, tt.err) || err.Error() != tt.err.Error() {
				t.Errorf("Run = %q, want %q unchanged", err, tt.err)
			}
			if got := errors.Is(err, cli.ErrUsage); got != tt.usage {
				t.Errorf("errors.Is(err, ErrUsage) = %t, want %t", got, tt.usage)
			}
		})
	}
}

func TestNounsOfSeparateAppsAreIndependent(t *testing.T) {
	first, _, _ := newApp(t)
	second := cli.New("slopmop", &bytes.Buffer{})
	if err := first.Run(words("node list")); err != nil {
		t.Errorf("first.Run = %v, want nil", err)
	}
	checkUsage(t, second.Run(words("node list")), `unknown noun "node"`)
}
