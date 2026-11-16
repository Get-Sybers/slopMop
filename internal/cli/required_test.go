package cli_test

import (
	"bytes"
	"testing"

	"github.com/get-sybers/slopmop/internal/cli"
)

func requiredApp(t *testing.T) (*cli.App, *bytes.Buffer, *int) {
	t.Helper()
	out, runs := &bytes.Buffer{}, new(int)
	app := cli.New("slopmop", out)
	spec := cli.Spec{
		Selectors: map[string]string{"script": "scripts"},
		Params:    map[string]string{"inputdir": "<folder>", "since": "<time>"},
		Required:  []string{"inputdir"},
	}
	noun := &cli.Noun{Name: "file", Verbs: []*cli.Verb{
		cli.ListVerb("list files", spec, func(*cli.Args) error { *runs++; return nil }),
	}}
	if err := app.Register(noun); err != nil {
		t.Fatal(err)
	}
	return app, out, runs
}

func TestRequiredParam(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want string
	}{
		{"given", "file list --inputdir case", ""},
		{"given with =", "file list --inputdir=case -script", ""},
		{"missing", "file list", "file list needs --inputdir <folder>"},
		{"missing beside another param", "file ls --since 9am", "file list needs --inputdir <folder>"},
		{"wrong prefix is reported first", "file list -inputdir case", "-inputdir takes a value; use --inputdir <folder>"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, _, runs := requiredApp(t)
			err := app.Run(words(tt.cmd))
			if tt.want == "" {
				if err != nil || *runs != 1 {
					t.Errorf("Run = %v after %d runs, want nil after 1", err, *runs)
				}
				return
			}
			checkUsage(t, err, tt.want)
			if *runs != 0 {
				t.Errorf("the verb ran without its required param")
			}
		})
	}
}

func TestRequiredParamInHelp(t *testing.T) {
	app, out, _ := requiredApp(t)
	if err := app.Run(words("file list -h")); err != nil {
		t.Fatal(err)
	}
	want := `usage: slopmop file list --inputdir <folder> [selectors] [--params] [output flags]
list files

selectors (single dash, pick any; none = all):
  -script     scripts

params (double dash, take a value):
  --inputdir  <folder> (required)
  --since     <time>

output flags:
  -o wide|json    every column, or JSON
  -q              column 1 only, one per line
  --no-headers    no header row
  --tz local|utc  zone of displayed times (default utc)
`
	if got := out.String(); got != want {
		t.Errorf("help =\n%s\nwant\n%s", got, want)
	}
}

func TestRegisterRejectsUndeclaredRequiredParam(t *testing.T) {
	v := verb("scan")
	v.Spec = cli.Spec{Params: map[string]string{"node": "<node>"}, Required: []string{"inputdir"}}
	checkRegisterFails(t, host(v), `register noun "host": verb "scan": required param "inputdir" is not declared`)
}
