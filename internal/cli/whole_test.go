package cli_test

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/get-sybers/slopmop/internal/cli"
)

func wholeWords() []cli.Word {
	return []cli.Word{{Name: "summary", Summary: "the counts"}, {Name: "impact", Summary: "what it means"}}
}

// wholeApp has one noun and the command without a noun; ran holds its last arguments.
func wholeApp(t *testing.T) (app *cli.App, ran *cli.Args, out *bytes.Buffer) {
	t.Helper()
	out, ran = &bytes.Buffer{}, &cli.Args{}
	app = cli.New("slopmop", out)
	spec := cli.Spec{Params: map[string]string{"intelfile": "<file>"}}
	err := app.Whole("reads a folder", "<folder>", wholeWords(), spec, func(a *cli.Args) error {
		*ran = *a
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	noun := &cli.Noun{Name: "file", Aliases: []string{"files"}, Summary: "files", Verbs: []*cli.Verb{
		cli.ListVerb("list the files", cli.Spec{}, func(*cli.Args) error { return nil }),
	}}
	if err := app.Register(noun); err != nil {
		t.Fatal(err)
	}
	return app, ran, out
}

func TestWholeRuns(t *testing.T) {
	tests := []struct {
		cmd       string
		folder    string
		sections  []string
		intelfile string
	}{
		{"case42", "case42", []string{"impact", "summary"}, ""},
		{"case42 impact", "case42", []string{"impact"}, ""},
		{"impact case42 summary", "case42", []string{"impact", "summary"}, ""},
		{"case42 -impact", "case42", []string{"impact"}, ""},
		{"--intelfile w.json case42", "case42", []string{"impact", "summary"}, "w.json"},
		{"case42 --intelfile=w.json summary", "case42", []string{"summary"}, "w.json"},
		{"./files", "./files", []string{"impact", "summary"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			app, ran, _ := wholeApp(t)
			if err := app.Run(strings.Fields(tt.cmd)); err != nil {
				t.Fatalf("Run(%q) = %v", tt.cmd, err)
			}
			if len(ran.Pos) != 1 || ran.Pos[0] != tt.folder {
				t.Errorf("positionals = %q, want the folder %q", ran.Pos, tt.folder)
			}
			if !slices.Equal(ran.Selectors, tt.sections) {
				t.Errorf("sections = %q, want %q", ran.Selectors, tt.sections)
			}
			if got := ran.Params["intelfile"]; got != tt.intelfile {
				t.Errorf("--intelfile = %q, want %q", got, tt.intelfile)
			}
		})
	}
}

func TestWholeRejects(t *testing.T) {
	tests := []struct {
		cmd  string
		want string
	}{
		{"impact", `the word "impact" names a section; give the folder too: slopmop <folder> impact`},
		{"--intelfile w.json", "slopmop needs a folder: slopmop <folder>"},
		{"case42 other", `slopmop reads one folder, got "case42" and "other" (valid sections: summary, impact)`},
		{"case42 -o json", "-o applies only to verbs that print rows"},
		{"case42 --bogus x", "unknown option --bogus (valid params: --intelfile <file>)"},
		{"case42 -bogus", "unknown selector -bogus (valid selectors: -impact, -summary)"},
		{"case42 --intelfile", "--intelfile needs a value <file>"},
		{"file bogus", `file has no verb "bogus"`},
	}
	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			app, _, _ := wholeApp(t)
			err := app.Run(strings.Fields(tt.cmd))
			if !errors.Is(err, cli.ErrUsage) || err.Error() != tt.want {
				t.Errorf("Run(%q) = %v, want the usage error %q", tt.cmd, err, tt.want)
			}
		})
	}
}

func TestWholeHelp(t *testing.T) {
	const want = `usage: slopmop <folder> [section ...] [--intelfile <file>]

reads a folder

sections (name any to print only those; none = all):
  summary      the counts
  impact       what it means

params (double dash, take a value):
  --intelfile  <file>

one view as a table or as JSON: slopmop NOUN VERB [selectors] [--params] [output flags] [positional]

nouns:
  file, files  files

more help: slopmop NOUN -h, slopmop NOUN VERB -h
`
	for _, cmd := range []string{"", "-h", "help", "case42 -h", "case42 impact --help"} {
		app, _, out := wholeApp(t)
		if err := app.Run(strings.Fields(cmd)); err != nil {
			t.Fatalf("Run(%q) = %v", cmd, err)
		}
		if out.String() != want {
			t.Errorf("Run(%q) help:\n%s\nwant:\n%s", cmd, out.String(), want)
		}
	}
}

func TestWholeIsCheckedWhenSet(t *testing.T) {
	run := func(*cli.Args) error { return nil }
	tests := []struct {
		name       string
		summary    string
		positional string
		words      []cli.Word
		spec       cli.Spec
		run        func(*cli.Args) error
		want       string
	}{
		{"no summary", "", "<folder>", nil, cli.Spec{}, run, "needs a summary and a positional"},
		{"no positional", "s", "", nil, cli.Spec{}, run, "needs a summary and a positional"},
		{"no run", "s", "<folder>", nil, cli.Spec{}, nil, "no Run function"},
		{"a word twice", "s", "<folder>", append(wholeWords(), wholeWords()...), cli.Spec{}, run, `the word "summary" is repeated`},
		{"a word without a summary", "s", "<folder>", []cli.Word{{Name: "x"}}, cli.Spec{}, run, `the word "x" is repeated or lacks`},
		{"a word that is a param", "s", "<folder>", wholeWords(), cli.Spec{Params: map[string]string{"impact": ""}}, run, "both a selector and a param"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cli.New("slopmop", &bytes.Buffer{}).Whole(tt.summary, tt.positional, tt.words, tt.spec, tt.run)
			if err == nil || !strings.Contains(err.Error(), tt.want) || errors.Is(err, cli.ErrUsage) {
				t.Errorf("Whole error = %v, want one containing %q that is not a usage error", err, tt.want)
			}
		})
	}
	app, _, _ := wholeApp(t)
	if err := app.Whole("s", "<folder>", nil, cli.Spec{}, run); err == nil || !strings.Contains(err.Error(), "already set") {
		t.Errorf("a second Whole: error = %v", err)
	}
}

// Without the command, a word that is no noun is an unknown noun, as before.
func TestNoWholeMeansUnknownNoun(t *testing.T) {
	app := cli.New("slopmop", &bytes.Buffer{})
	if err := app.Run([]string{"case42"}); err == nil || err.Error() != `unknown noun "case42"` {
		t.Errorf("Run = %v, want an unknown noun", err)
	}
}
