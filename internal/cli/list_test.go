package cli_test

import (
	"maps"
	"slices"
	"testing"

	"github.com/get-sybers/slopmop/internal/cli"
)

func TestListVerbShape(t *testing.T) {
	given := cli.Spec{
		Selectors:  map[string]string{"b": "second", "a": "first"},
		Params:     map[string]string{"node": "<node>"},
		Positional: "<ignored>",
		MinPos:     2,
		MaxPos:     5,
	}
	v := cli.ListVerb("list things", given, ran)

	if v.Name != "list" {
		t.Errorf("Name = %q, want %q", v.Name, "list")
	}
	if want := []string{"ls"}; !slices.Equal(v.Aliases, want) {
		t.Errorf("Aliases = %q, want %q", v.Aliases, want)
	}
	if v.Summary != "list things" {
		t.Errorf("Summary = %q, want %q", v.Summary, "list things")
	}
	if !v.Spec.Rows {
		t.Errorf("Spec.Rows = false, want true")
	}
	if v.Spec.Positional != "" || v.Spec.MinPos != 0 || v.Spec.MaxPos != 0 {
		t.Errorf("positionals = %q %d..%d, want none",
			v.Spec.Positional, v.Spec.MinPos, v.Spec.MaxPos)
	}
	if !maps.Equal(v.Spec.Selectors, given.Selectors) {
		t.Errorf("Spec.Selectors = %q, want %q", v.Spec.Selectors, given.Selectors)
	}
	if !maps.Equal(v.Spec.Params, given.Params) {
		t.Errorf("Spec.Params = %q, want %q", v.Spec.Params, given.Params)
	}
	if v.Run == nil {
		t.Errorf("Run = nil, want a function")
	}
}

func TestListVerbWithoutRun(t *testing.T) {
	if v := cli.ListVerb("list things", cli.Spec{}, nil); v.Run != nil {
		t.Errorf("Run is set, want nil so that Register rejects the verb")
	}
}

func TestListVerbFillsEmptySelection(t *testing.T) {
	members := map[string]string{"task": "", "auth": "", "sysmon": ""}
	tests := []struct {
		name      string
		selectors map[string]string
		selected  []string
		want      []string
	}{
		{"none selected", members, nil, []string{"auth", "sysmon", "task"}},
		{"empty selection", members, []string{}, []string{"auth", "sysmon", "task"}},
		{"one selected", members, []string{"task"}, []string{"task"}},
		{"two selected", members, []string{"auth", "task"}, []string{"auth", "task"}},
		{"no selectors", nil, nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			v := cli.ListVerb("list", cli.Spec{Selectors: tt.selectors}, func(a *cli.Args) error {
				got = a.Selectors
				return nil
			})
			if err := v.Run(&cli.Args{Selectors: tt.selected}); err != nil {
				t.Fatalf("Run = %v, want nil", err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("Selectors = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestListVerbThroughRun(t *testing.T) {
	tests := []struct {
		cmd  string
		want []string
	}{
		{"logs list", []string{"auth", "firewall", "kernel", "sysmon", "task"}},
		{"logs ls", []string{"auth", "firewall", "kernel", "sysmon", "task"}},
		{"logs list -task", []string{"task"}},
		{"logs list -task -auth", []string{"auth", "task"}},
		{"node list", nil},
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
			if got := c.calls[0].args.Selectors; !slices.Equal(got, tt.want) {
				t.Errorf("Selectors = %q, want %q", got, tt.want)
			}
		})
	}
}
