package cli_test

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/get-sybers/slopmop/internal/cli"
	"github.com/get-sybers/slopmop/internal/golden"
)

func TestHelp(t *testing.T) {
	tests := []struct {
		golden string
		cmds   []string
	}{
		{"help-root", []string{"", "help", "-h", "--help"}},
		{"help-noun-logs", []string{"logs", "logs help", "logs -h", "logs --help", "log", "log -h"}},
		{"help-noun-user", []string{"user", "users --help"}},
		{"help-verb-logs-list", []string{
			"logs list -h", "logs list --help", "logs list help", "log ls -h",
			"logs list -auth -h", "logs list -h -auth", "logs list --node pve1 --help",
			"logs list --node=pve1 -h", "logs list -o json -h", "logs list -h -- extra",
			"logs list -bogus -h", "logs list --bogus -h", "logs list -node -h", "logs list extra --help",
		}},
		{"help-verb-logs-clear", []string{"logs clear -h", "logs clear help", "logs clear -o -h", "logs clear --tz --help"}},
		{"help-verb-service-list", []string{"service list -h", "svc ls --help"}},
		{"help-verb-node-list", []string{"node list -h", "nodes ls help"}},
		{"help-verb-node-select", []string{"node select -h", "node select help", "node select pve1 --help"}},
		{"help-verb-user-get", []string{"user get -h", "users show alice -h"}},
		{"help-verb-user-delete", []string{"user delete -h", "users rm help"}},
		{"help-verb-file-cp", []string{"file cp -h", "files copy --help", "file cp a -h b"}},
	}
	for _, tt := range tests {
		for _, cmd := range tt.cmds {
			t.Run(tt.golden+"/"+cmd, func(t *testing.T) {
				app, c, out := newApp(t)
				if err := app.Run(words(cmd)); err != nil {
					t.Fatalf("Run(%q) = %v, want nil", cmd, err)
				}
				if len(c.calls) != 0 {
					t.Errorf("verbs run = %d, want 0", len(c.calls))
				}
				golden.Check(t, tt.golden, out.Bytes())
			})
		}
	}
}

func TestHelpColumnsFitLongNames(t *testing.T) {
	out := &bytes.Buffer{}
	app := cli.New("slopmop", out)
	noun := &cli.Noun{Name: "probe", Verbs: []*cli.Verb{{
		Name: "scan", Summary: "scan the probes",
		Spec: cli.Spec{
			Selectors: map[string]string{"application-log": "longer than the column", "kernel": "", "task": "task log"},
			Params:    map[string]string{"destination-folder": "<folder>", "since": "<time>", "bare": ""},
		},
		Run: ran,
	}}}
	if err := app.Register(noun); err != nil {
		t.Fatalf("Register = %v, want nil", err)
	}
	if err := app.Run(words("probe scan -h")); err != nil {
		t.Fatalf("Run = %v, want nil", err)
	}
	golden.Check(t, "help-verb-long-names", out.Bytes())
}

func TestHelpOmitsEmptyParts(t *testing.T) {
	const usage = "usage: tool NOUN VERB [selectors] [--params] [output flags] [positional]\n"
	tests := []struct {
		name string
		noun *cli.Noun
		cmd  string
		want string
	}{
		{name: "no nouns", cmd: "", want: usage},
		{
			name: "noun without summary",
			noun: &cli.Noun{Name: "thing"},
			cmd:  "",
			want: usage + "\nnouns:\n  thing\n\nmore help: tool NOUN -h, tool NOUN VERB -h\n",
		},
		{
			name: "noun without verbs",
			noun: &cli.Noun{Name: "thing"},
			cmd:  "thing",
			want: "usage: tool thing VERB [selectors] [--params] [output flags] [positional]\n",
		},
		{
			name: "verb with nothing declared",
			noun: &cli.Noun{Name: "thing", Verbs: []*cli.Verb{{Name: "do", Run: ran}}},
			cmd:  "thing do -h",
			want: "usage: tool thing do\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := &bytes.Buffer{}
			app := cli.New("tool", out)
			if tt.noun != nil {
				if err := app.Register(tt.noun); err != nil {
					t.Fatalf("Register = %v, want nil", err)
				}
			}
			if err := app.Run(words(tt.cmd)); err != nil {
				t.Fatalf("Run(%q) = %v, want nil", tt.cmd, err)
			}
			if got := out.String(); got != tt.want {
				t.Errorf("help = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHelpTokensThatAreArguments(t *testing.T) {
	tests := []struct {
		cmd  string
		verb string
		want cli.Args
	}{
		{"node select -- help", "node select", cli.Args{Pos: []string{"help"}}},
		{"node select -- -h", "node select", cli.Args{Pos: []string{"-h"}}},
		{"node select -- --help", "node select", cli.Args{Pos: []string{"--help"}}},
		{"file cp -- -h --help", "file cp", cli.Args{Pos: []string{"-h", "--help"}}},
		{"file cp a -- -h", "file cp", cli.Args{Pos: []string{"a", "-h"}}},
		{"file cp help a", "file cp", cli.Args{Pos: []string{"help", "a"}}},
		{"file cp a help", "file cp", cli.Args{Pos: []string{"a", "help"}}},
		{"logs clear -auth --node -h", "logs clear", cli.Args{
			Selectors: []string{"auth"}, Params: map[string]string{"node": "-h"},
		}},
		{"logs clear -auth --node --help", "logs clear", cli.Args{
			Selectors: []string{"auth"}, Params: map[string]string{"node": "--help"},
		}},
		{"logs clear -auth --node help", "logs clear", cli.Args{
			Selectors: []string{"auth"}, Params: map[string]string{"node": "help"},
		}},
		{"logs clear -auth --node=-h", "logs clear", cli.Args{
			Selectors: []string{"auth"}, Params: map[string]string{"node": "-h"},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			app, c, out := newApp(t)
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

func TestHelpTokensInOutputValuePositions(t *testing.T) {
	tests := []struct {
		cmd  string
		want string
	}{
		{"user get alice -o -h", `unknown view "-h" (valid views: json, wide)`},
		{"user get alice -o --help", `unknown view "--help" (valid views: json, wide)`},
		{"user get alice --tz -h", `unknown zone "-h" (valid zones: local, utc)`},
		{"user get alice --tz --help", `unknown zone "--help" (valid zones: local, utc)`},
		{"user get help -q -o json", "-q cannot be combined with -o"},
	}
	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			app, c, out := newApp(t)
			checkUsage(t, app.Run(words(tt.cmd)), tt.want)
			checkNothingRan(t, c, out)
		})
	}
}

type brokenWriter struct{ err error }

func (w brokenWriter) Write([]byte) (int, error) { return 0, w.err }

func TestHelpWriteFailure(t *testing.T) {
	for _, cmd := range []string{"", "thing", "thing do -h"} {
		t.Run(cmd, func(t *testing.T) {
			app := cli.New("tool", brokenWriter{err: io.ErrClosedPipe})
			noun := &cli.Noun{Name: "thing", Verbs: []*cli.Verb{{Name: "do", Run: ran}}}
			if err := app.Register(noun); err != nil {
				t.Fatalf("Register = %v, want nil", err)
			}
			err := app.Run(words(cmd))
			if !errors.Is(err, io.ErrClosedPipe) {
				t.Errorf("Run(%q) = %v, want an error wrapping %v", cmd, err, io.ErrClosedPipe)
			}
			if errors.Is(err, cli.ErrUsage) {
				t.Errorf("errors.Is(err, ErrUsage) = true, want false")
			}
			if err != nil && !strings.HasPrefix(err.Error(), "write help: ") {
				t.Errorf("error = %q, want the prefix %q", err, "write help: ")
			}
		})
	}
}
