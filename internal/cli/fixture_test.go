package cli_test

import (
	"bytes"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/get-sybers/slopmop/internal/cli"
)

type call struct {
	verb string
	args cli.Args
}

// cluster is the state behind the test nouns: the selected node and every verb that ran.
type cluster struct {
	selected string
	calls    []call
}

func (c *cluster) record(verb string) func(*cli.Args) error {
	return func(a *cli.Args) error {
		c.calls = append(c.calls, call{verb: verb, args: *a})
		return nil
	}
}

func (c *cluster) selectNode(a *cli.Args) error {
	if len(a.Pos) == 1 {
		c.selected = a.Pos[0]
	}
	return c.record("node select")(a)
}

func (c *cluster) clearLogs(a *cli.Args) error {
	if len(a.Selectors) == 0 {
		return errors.New("clear needs a log type, e.g. -sysmon (valid: -auth, -firewall, -kernel, -sysmon, -task)")
	}
	if c.selected == "" && a.Params["node"] == "" {
		return errors.New("no node: pass --node <name>|all or run `slopmop node select <name>`")
	}
	return c.record("logs clear")(a)
}

func logTypes() map[string]string {
	return map[string]string{
		"auth":     "authentication log",
		"sysmon":   "Sysmon events",
		"task":     "task / job log",
		"firewall": "firewall log",
		"kernel":   "kernel ring buffer",
	}
}

func nodeParam() map[string]string {
	return map[string]string{"node": "<node>|all"}
}

func (c *cluster) nouns() []*cli.Noun {
	return []*cli.Noun{
		{Name: "node", Summary: "cluster nodes", Aliases: []string{"nodes"}, Verbs: []*cli.Verb{
			cli.ListVerb("list every node", cli.Spec{}, c.record("node list")),
			{
				Name: "select", Summary: "set the current node; without a node, show it",
				Spec: cli.Spec{Positional: "[node]", MaxPos: 1}, Run: c.selectNode,
			},
		}},
		{Name: "user", Summary: "access users", Aliases: []string{"users"}, Verbs: []*cli.Verb{
			cli.ListVerb("list every user", cli.Spec{}, c.record("user list")),
			{
				Name: "get", Aliases: []string{"show"}, Summary: "show one user",
				Spec: cli.Spec{Positional: "<user>", MinPos: 1, MaxPos: 1, Rows: true}, Run: c.record("user get"),
			},
			{
				Name: "delete", Aliases: []string{"rm"}, Summary: "remove users",
				Spec: cli.Spec{Positional: "<user>...", MinPos: 1, MaxPos: -1}, Run: c.record("user delete"),
			},
		}},
		{Name: "group", Summary: "access groups", Aliases: []string{"groups"}, Verbs: []*cli.Verb{
			cli.ListVerb("list every group", cli.Spec{}, c.record("group list")),
		}},
		{Name: "logs", Summary: "node logs", Aliases: []string{"log"}, Verbs: []*cli.Verb{
			cli.ListVerb(
				"list log entries (no selector = every type, no --node = every node)",
				cli.Spec{Selectors: logTypes(), Params: map[string]string{"node": "<node>|all", "since": "<time>"}},
				c.record("logs list"),
			),
			{
				Name: "clear", Summary: "clear one or more log sources",
				Spec: cli.Spec{Selectors: logTypes(), Params: nodeParam()}, Run: c.clearLogs,
			},
		}},
		{Name: "service", Summary: "node services", Aliases: []string{"services", "svc"}, Verbs: []*cli.Verb{
			cli.ListVerb("list services (no --node = every node)", cli.Spec{
				Params: nodeParam(),
				Switches: map[string]cli.Switch{
					"all":     {Short: "a", Summary: "include stopped services"},
					"verbose": {},
				},
			}, c.record("service list")),
		}},
		{Name: "network", Summary: "node network interfaces", Aliases: []string{"networks", "net"}, Verbs: []*cli.Verb{
			cli.ListVerb("list interfaces (no --node = every node)", cli.Spec{Params: nodeParam()}, c.record("network list")),
		}},
		{Name: "file", Summary: "files on the nodes", Aliases: []string{"files"}, Verbs: []*cli.Verb{
			{
				Name: "cp", Aliases: []string{"copy"}, Summary: "copy node:/src to node:/dst",
				Spec: cli.Spec{Positional: "<node:/src> <node:/dst>", MinPos: 2, MaxPos: 2}, Run: c.record("file cp"),
			},
		}},
	}
}

func newApp(t *testing.T) (*cli.App, *cluster, *bytes.Buffer) {
	t.Helper()
	c := &cluster{}
	out := &bytes.Buffer{}
	app := cli.New("slopmop", out)
	for _, n := range c.nouns() {
		if err := app.Register(n); err != nil {
			t.Fatalf("Register(%s) = %v, want nil", n.Name, err)
		}
	}
	return app, c, out
}

func words(cmd string) []string {
	return strings.Fields(cmd)
}

// checkUsage fails unless err is a usage error whose whole text is want.
func checkUsage(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want %q", want)
	}
	if !errors.Is(err, cli.ErrUsage) {
		t.Errorf("errors.Is(%q, ErrUsage) = false, want true", err)
	}
	if got := err.Error(); got != want {
		t.Errorf("error = %q, want %q", got, want)
	}
}

// checkCall fails unless exactly one verb ran, and it was verb with the arguments in want.
func checkCall(t *testing.T, c *cluster, verb string, want cli.Args) {
	t.Helper()
	if len(c.calls) != 1 {
		t.Fatalf("verbs run = %d, want 1", len(c.calls))
	}
	got := c.calls[0]
	if got.verb != verb {
		t.Errorf("verb = %q, want %q", got.verb, verb)
	}
	if !slices.Equal(got.args.Selectors, want.Selectors) {
		t.Errorf("Selectors = %q, want %q", got.args.Selectors, want.Selectors)
	}
	if !maps.Equal(got.args.Params, want.Params) {
		t.Errorf("Params = %q, want %q", got.args.Params, want.Params)
	}
	if !maps.Equal(got.args.Switches, want.Switches) {
		t.Errorf("Switches = %v, want %v", got.args.Switches, want.Switches)
	}
	if !slices.Equal(got.args.Pos, want.Pos) {
		t.Errorf("Pos = %q, want %q", got.args.Pos, want.Pos)
	}
	if got.args.Output != want.Output {
		t.Errorf("Output = %+v, want %+v", got.args.Output, want.Output)
	}
}

// checkNothingRan fails when a rejected command line reached a verb or the writer.
func checkNothingRan(t *testing.T, c *cluster, out *bytes.Buffer) {
	t.Helper()
	if len(c.calls) != 0 {
		t.Errorf("verbs run = %d, want 0", len(c.calls))
	}
	if out.Len() != 0 {
		t.Errorf("output = %q, want none", out.String())
	}
}
