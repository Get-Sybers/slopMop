package cli_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/get-sybers/slopmop/internal/cli"
)

func ran(*cli.Args) error { return nil }

func verb(name string, aliases ...string) *cli.Verb {
	return &cli.Verb{Name: name, Aliases: aliases, Run: ran}
}

func host(verbs ...*cli.Verb) *cli.Noun {
	return &cli.Noun{Name: "host", Verbs: verbs}
}

// checkRegisterFails registers n beside the test nouns and compares the whole error text.
func checkRegisterFails(t *testing.T, n *cli.Noun, want string) {
	t.Helper()
	app, _, _ := newApp(t)
	err := app.Register(n)
	if err == nil {
		t.Fatalf("Register = nil, want %q", want)
	}
	if got := err.Error(); got != want {
		t.Errorf("error = %q, want %q", got, want)
	}
	if errors.Is(err, cli.ErrUsage) {
		t.Errorf("errors.Is(err, ErrUsage) = true, want false")
	}
}

func TestRegisterRejectsTakenNames(t *testing.T) {
	tests := []struct {
		name string
		noun *cli.Noun
		want string
	}{
		{"noun name is a name", &cli.Noun{Name: "node"}, `register noun "node": noun name "node" is already taken`},
		{"noun name is an alias", &cli.Noun{Name: "svc"}, `register noun "svc": noun name "svc" is already taken`},
		{
			"noun alias is a name", &cli.Noun{Name: "host", Aliases: []string{"hosts", "file"}},
			`register noun "host": noun name "file" is already taken`,
		},
		{
			"noun alias is an alias", &cli.Noun{Name: "host", Aliases: []string{"nodes"}},
			`register noun "host": noun name "nodes" is already taken`,
		},
		{
			"noun alias is its own name", &cli.Noun{Name: "host", Aliases: []string{"host"}},
			`register noun "host": noun name "host" is already taken`,
		},
		{
			"noun alias twice", &cli.Noun{Name: "host", Aliases: []string{"hosts", "hosts"}},
			`register noun "host": noun name "hosts" is already taken`,
		},
		{"verb name twice", host(verb("scan"), verb("scan")), `register noun "host": verb name "scan" is repeated`},
		{
			"verb alias is another name", host(verb("scan"), verb("probe", "scan")),
			`register noun "host": verb name "scan" is repeated`,
		},
		{
			"verb alias is another alias", host(verb("scan", "sc"), verb("probe", "sc")),
			`register noun "host": verb name "sc" is repeated`,
		},
		{"verb alias is its own name", host(verb("scan", "scan")), `register noun "host": verb name "scan" is repeated`},
		{"verb alias twice", host(verb("scan", "sc", "sc")), `register noun "host": verb name "sc" is repeated`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkRegisterFails(t, tt.noun, tt.want)
		})
	}
}

func TestRegisterRejectsReservedFlagNames(t *testing.T) {
	for _, name := range []string{"o", "q", "no-headers", "tz", "h", "help"} {
		flags := map[string]string{"plain": "", name: ""}
		tests := []struct {
			kind string
			verb *cli.Verb
			want string
		}{
			{
				"selector", &cli.Verb{Name: "scan", Spec: cli.Spec{Selectors: flags}, Run: ran},
				`register noun "host": verb "scan": selector name "` + name + `" is reserved`,
			},
			{
				"param", &cli.Verb{Name: "scan", Spec: cli.Spec{Params: flags}, Run: ran},
				`register noun "host": verb "scan": param name "` + name + `" is reserved`,
			},
			{
				"selector of a verb that prints rows", cli.ListVerb("", cli.Spec{Selectors: flags}, ran),
				`register noun "host": verb "list": selector name "` + name + `" is reserved`,
			},
			{
				"param of a verb that prints rows", cli.ListVerb("", cli.Spec{Params: flags}, ran),
				`register noun "host": verb "list": param name "` + name + `" is reserved`,
			},
		}
		for _, tt := range tests {
			t.Run(tt.kind+" "+name, func(t *testing.T) {
				checkRegisterFails(t, host(tt.verb), tt.want)
			})
		}
	}
}

func TestRegisterRejectsMalformedVerbs(t *testing.T) {
	const (
		list   = `register noun "host": verb "list": `
		scan   = `register noun "host": verb "scan": `
		listLs = `is reserved for the pair list/ls`
		getSh  = `is reserved for the pair get/show`
		delRm  = `is reserved for the pair delete/rm`
	)
	shared := cli.Spec{
		Selectors: map[string]string{"auth": "", "node": ""},
		Params:    map[string]string{"node": "", "since": ""},
	}
	tests := []struct {
		name string
		noun *cli.Noun
		want string
	}{
		{
			"selector and param share a name", host(&cli.Verb{Name: "scan", Spec: shared, Run: ran}),
			scan + `"node" is both a selector and a param`,
		},

		{"ls as a name", host(verb("ls")), `register noun "host": verb "ls": "ls" ` + listLs},
		{"ls with list as its alias", host(verb("ls", "list")), `register noun "host": verb "ls": "ls" ` + listLs},
		{"ls as the alias of another verb", host(verb("scan", "ls")), scan + `"ls" ` + listLs},
		{"list as the alias of another verb", host(verb("scan", "list")), scan + `"list" ` + listLs},
		{"list without ls", host(verb("list")), list + `"list" ` + listLs},
		{"list with the alias of another pair", host(verb("list", "show")), list + `"list" ` + listLs},
		{"list with ls and the alias of another pair", host(verb("list", "ls", "rm")), list + `"rm" ` + delRm},
		{"show as a name", host(verb("show")), `register noun "host": verb "show": "show" ` + getSh},
		{"show with get as its alias", host(verb("show", "get")), `register noun "host": verb "show": "show" ` + getSh},
		{"show as the alias of another verb", host(verb("scan", "show")), scan + `"show" ` + getSh},
		{"get without show", host(verb("get")), `register noun "host": verb "get": "get" ` + getSh},
		{"get as the alias of another verb", host(verb("scan", "get")), scan + `"get" ` + getSh},
		{"rm as a name", host(verb("rm")), `register noun "host": verb "rm": "rm" ` + delRm},
		{"rm as the alias of another verb", host(verb("remove", "rm")), `register noun "host": verb "remove": "rm" ` + delRm},
		{"delete without rm", host(verb("delete")), `register noun "host": verb "delete": "delete" ` + delRm},
		{"delete as the alias of another verb", host(verb("scan", "delete")), scan + `"delete" ` + delRm},

		{"verb without Run", host(&cli.Verb{Name: "scan"}), scan + "no Run function"},
		{"list verb without Run", host(cli.ListVerb("", cli.Spec{}, nil)), list + "no Run function"},
		{
			"second verb without Run", host(verb("scan"), &cli.Verb{Name: "probe"}),
			`register noun "host": verb "probe": no Run function`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkRegisterFails(t, tt.noun, tt.want)
		})
	}
}

func TestRegisterFailureAddsNothing(t *testing.T) {
	app, _, out := newApp(t)
	if err := app.Run(nil); err != nil {
		t.Fatalf("Run = %v, want nil", err)
	}
	before := out.String()
	out.Reset()

	bad := &cli.Noun{Name: "host", Aliases: []string{"hosts"}, Verbs: []*cli.Verb{{Name: "scan"}}}
	if err := app.Register(bad); err == nil {
		t.Fatalf("Register = nil, want an error")
	}
	for _, name := range []string{"host", "hosts"} {
		checkUsage(t, app.Run([]string{name}), `unknown noun "`+name+`"`)
	}
	if err := app.Run(nil); err != nil {
		t.Fatalf("Run = %v, want nil", err)
	}
	if got := out.String(); got != before {
		t.Errorf("help after a failed Register = %q, want %q", got, before)
	}
}

func TestRegisterAcceptsGlobalPairs(t *testing.T) {
	tests := []struct {
		name string
		verb *cli.Verb
	}{
		{"list verb", cli.ListVerb("list hosts", cli.Spec{}, ran)},
		{"list with ls", verb("list", "ls")},
		{"list with ls among other aliases", verb("list", "dir", "ls")},
		{"get with show", verb("get", "show")},
		{"delete with rm", verb("delete", "rm")},
		{"a name that only contains a global verb", verb("list-all", "lsa")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := cli.New("slopmop", &bytes.Buffer{})
			if err := app.Register(host(tt.verb)); err != nil {
				t.Errorf("Register = %v, want nil", err)
			}
		})
	}
}
