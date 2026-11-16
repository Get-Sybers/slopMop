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

func reportVerb(run func(*cli.Args) error) *cli.Verb {
	return &cli.Verb{
		Name: "report", Summary: "prints the report", Kind: "sections",
		Words: []cli.Word{{Name: "summary", Summary: "the counts"}, {Name: "impact", Summary: "what it means"}},
		Options: []cli.Option{
			{Name: "inputdir", Hint: "<folder>", Summary: "the folder to read", Required: true},
			{Name: "outdir", Hint: "<folder>", Summary: "where the output is saved"},
		},
		Run: run,
	}
}

// newApp has the verbs report and version; ran holds the last verb run and its arguments.
func newApp(t *testing.T) (app *cli.App, ran map[string]*cli.Args, out *bytes.Buffer) {
	t.Helper()
	out, ran = &bytes.Buffer{}, map[string]*cli.Args{}
	app = cli.New("slopmop", "-inputdir <folder> VERB [section ...] [options]", out)
	record := func(name string) func(*cli.Args) error {
		return func(a *cli.Args) error {
			ran[name] = a
			return nil
		}
	}
	for _, v := range []*cli.Verb{
		reportVerb(record("report")),
		{Name: "version", Summary: "prints the version", Run: record("version")},
	} {
		if err := app.Register(v); err != nil {
			t.Fatal(err)
		}
	}
	return app, ran, out
}

func TestRun(t *testing.T) {
	every := []string{"summary", "impact"}
	tests := []struct {
		cmd     string
		words   []string
		options map[string]string
	}{
		{"-inputdir case42 report", every, map[string]string{"inputdir": "case42"}},
		{"--inputdir case42 report", every, map[string]string{"inputdir": "case42"}},
		{"-inputdir=case42 report", every, map[string]string{"inputdir": "case42"}},
		{"--inputdir=case42 report", every, map[string]string{"inputdir": "case42"}},
		{"report -inputdir case42", every, map[string]string{"inputdir": "case42"}},
		{"-inputdir case42 report impact", []string{"impact"}, map[string]string{"inputdir": "case42"}},
		{"-inputdir case42 report impact summary", every, map[string]string{"inputdir": "case42"}},
		{"-inputdir case42 report impact impact", []string{"impact"}, map[string]string{"inputdir": "case42"}},
		{"report impact -inputdir case42 -outdir out", []string{"impact"}, map[string]string{"inputdir": "case42", "outdir": "out"}},
		{"-inputdir -odd report", every, map[string]string{"inputdir": "-odd"}},
		{"-inputdir report report", every, map[string]string{"inputdir": "report"}},
		{"-inputdir case42 -- report impact", []string{"impact"}, map[string]string{"inputdir": "case42"}},
	}
	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			app, ran, _ := newApp(t)
			if err := app.Run(strings.Fields(tt.cmd)); err != nil {
				t.Fatalf("Run(%q) = %v", tt.cmd, err)
			}
			got := ran["report"]
			if got == nil {
				t.Fatal("the verb did not run")
			}
			if !slices.Equal(got.Words, tt.words) {
				t.Errorf("words = %q, want %q", got.Words, tt.words)
			}
			if !maps.Equal(got.Options, tt.options) {
				t.Errorf("options = %v, want %v", got.Options, tt.options)
			}
		})
	}
	app, ran, _ := newApp(t)
	if err := app.Run([]string{"version"}); err != nil || ran["version"] == nil || len(ran["version"].Words) != 0 {
		t.Errorf("a verb without words or options: %v, %v", err, ran["version"])
	}
}

func TestRunRejects(t *testing.T) {
	tests := []struct {
		cmd  string
		want string
	}{
		{"-inputdir case42", "slopmop needs a verb (verbs: report, version)"},
		{"-inputdir case42 bogus", `unknown verb "bogus" (verbs: report, version)`},
		{"report", "report needs -inputdir <folder>"},
		{"report -inputdir", "-inputdir needs a value <folder>"},
		{"report --inputdir=", "--inputdir needs a value <folder>"},
		{"report -inputdir a -inputdir b", "-inputdir given more than once"},
		{"report -inputdir a --inputdir=b", "-inputdir given more than once"},
		{"-inputdir a report bogus", `report has no section "bogus" (sections: summary, impact)`},
		{"-inputdir a report -bogus x", "unknown option -bogus (options: -inputdir <folder>, -outdir <folder>)"},
		{"-inputdir a report --bogus=x", "unknown option --bogus (options: -inputdir <folder>, -outdir <folder>)"},
		{"version extra", `version takes no word, got "extra"`},
		{"version -inputdir a", "unknown option -inputdir"},
	}
	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			app, ran, out := newApp(t)
			err := app.Run(strings.Fields(tt.cmd))
			if !errors.Is(err, cli.ErrUsage) || err.Error() != tt.want {
				t.Errorf("Run(%q) = %v, want the usage error %q", tt.cmd, err, tt.want)
			}
			if len(ran) != 0 || out.Len() != 0 {
				t.Errorf("a verb ran or help was written on a usage error")
			}
		})
	}
}

func TestRunReturnsTheVerbsError(t *testing.T) {
	failed := errors.New("disk full")
	app := cli.New("slopmop", "VERB", &bytes.Buffer{})
	if err := app.Register(reportVerb(func(*cli.Args) error { return failed })); err != nil {
		t.Fatal(err)
	}
	if err := app.Run([]string{"-inputdir", "a", "report"}); !errors.Is(err, failed) || errors.Is(err, cli.ErrUsage) {
		t.Errorf("Run = %v, want the verb's own error", err)
	}
	if err := cli.Usagef("bad %s", "value"); !errors.Is(err, cli.ErrUsage) || err.Error() != "bad value" {
		t.Errorf("Usagef = %v", err)
	}
}

const rootHelp = `usage: slopmop -inputdir <folder> VERB [section ...] [options]

verbs:
  report              prints the report
  version             prints the version

options (one dash or two; each takes a value):
  -inputdir <folder>  the folder to read
  -outdir <folder>    where the output is saved

more help: slopmop VERB --help
`

const reportHelp = `usage: slopmop -inputdir <folder> report [section ...] [-outdir <folder>]
prints the report

sections (name any to print only those; none = all):
  summary             the counts
  impact              what it means

options (one dash or two; each takes a value):
  -inputdir <folder>  the folder to read (required)
  -outdir <folder>    where the output is saved
`

func TestHelp(t *testing.T) {
	tests := []struct {
		cmd  string
		want string
	}{
		{"", rootHelp},
		{"-h", rootHelp},
		{"--help", rootHelp},
		{"-help", rootHelp},
		{"help", rootHelp},
		{"-inputdir case42 --help", rootHelp},
		{"report --help", reportHelp},
		{"help report", reportHelp},
		{"report help", reportHelp},
		{"-inputdir case42 report impact -h", reportHelp},
		{"report bogus --bogus x --help", reportHelp},
		{"version -h", "usage: slopmop version\nprints the version\n"},
	}
	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			app, ran, out := newApp(t)
			if err := app.Run(strings.Fields(tt.cmd)); err != nil {
				t.Fatalf("Run(%q) = %v", tt.cmd, err)
			}
			if out.String() != tt.want {
				t.Errorf("Run(%q) help:\n%s\nwant:\n%s", tt.cmd, out.String(), tt.want)
			}
			if len(ran) != 0 {
				t.Error("a verb ran when help was asked for")
			}
		})
	}
	bare := &bytes.Buffer{}
	if err := cli.New("slopmop", "VERB", bare).Run(nil); err != nil || bare.String() != "usage: slopmop VERB\n" {
		t.Errorf("help of an App without verbs = %q, %v", bare.String(), err)
	}
}

// The value of an option is never read as help or as a verb.
func TestHelpWordsThatAreValues(t *testing.T) {
	app, ran, out := newApp(t)
	if err := app.Run(strings.Fields("-inputdir help report -outdir --help")); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 || ran["report"] == nil || ran["report"].Options["inputdir"] != "help" || ran["report"].Options["outdir"] != "--help" {
		t.Errorf("help = %q, ran = %v; want the verb run with both values", out.String(), ran["report"])
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("closed") }

func TestHelpWriteFailure(t *testing.T) {
	err := cli.New("slopmop", "VERB", failingWriter{}).Run(nil)
	if err == nil || errors.Is(err, cli.ErrUsage) || !strings.Contains(err.Error(), "write help") {
		t.Errorf("Run = %v, want the write failure", err)
	}
}

func TestRegisterRejects(t *testing.T) {
	run := func(*cli.Args) error { return nil }
	word := []cli.Word{{Name: "a", Summary: "s"}}
	option := cli.Option{Name: "x", Hint: "<v>", Summary: "s"}
	tests := []struct {
		name string
		verb *cli.Verb
		want string
	}{
		{"no name", &cli.Verb{Summary: "s", Run: run}, "needs a name, a summary and a Run function"},
		{"no summary", &cli.Verb{Name: "v", Run: run}, "needs a name, a summary and a Run function"},
		{"no run", &cli.Verb{Name: "v", Summary: "s"}, "needs a name, a summary and a Run function"},
		{"help for a name", &cli.Verb{Name: "help", Summary: "s", Run: run}, "the name is reserved"},
		{"a dash in the name", &cli.Verb{Name: "-v", Summary: "s", Run: run}, "the name is reserved"},
		{"a name twice", &cli.Verb{Name: "report", Summary: "s", Run: run}, "the name is already taken"},
		{"words without a kind", &cli.Verb{Name: "v", Summary: "s", Run: run, Words: word}, "its words need a kind"},
		{"a word twice", &cli.Verb{Name: "v", Summary: "s", Run: run, Kind: "parts", Words: append(word, word...)}, `the word "a" is repeated`},
		{"a word without a summary", &cli.Verb{Name: "v", Summary: "s", Run: run, Kind: "parts", Words: []cli.Word{{Name: "a"}}}, `the word "a" is repeated, reserved or lacks`},
		{"help for a word", &cli.Verb{Name: "v", Summary: "s", Run: run, Kind: "parts", Words: []cli.Word{{Name: "help", Summary: "s"}}}, `the word "help"`},
		{"an option twice", &cli.Verb{Name: "v", Summary: "s", Run: run, Options: []cli.Option{option, option}}, `the option "x" is repeated`},
		{"an option without a hint", &cli.Verb{Name: "v", Summary: "s", Run: run, Options: []cli.Option{{Name: "x", Summary: "s"}}}, `the option "x" is repeated, reserved or lacks`},
		{"h for an option", &cli.Verb{Name: "v", Summary: "s", Run: run, Options: []cli.Option{{Name: "h", Hint: "<v>", Summary: "s"}}}, `the option "h"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, _, _ := newApp(t)
			err := app.Register(tt.verb)
			if err == nil || !strings.Contains(err.Error(), tt.want) || errors.Is(err, cli.ErrUsage) {
				t.Errorf("Register error = %v, want one containing %q that is not a usage error", err, tt.want)
			}
		})
	}
}
