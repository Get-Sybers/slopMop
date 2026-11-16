package structured

import (
	"slices"
	"strings"
	"testing"
)

func loadFormats(t *testing.T) Table {
	t.Helper()
	table, err := LoadFormats()
	if err != nil {
		t.Fatal(err)
	}
	return table
}

func TestDetect(t *testing.T) {
	table := loadFormats(t)
	cases := []struct {
		name string
		want Format
		ok   bool
	}{
		{"report.json", JSON, true},
		{"events.JSONL", JSON, true},
		{"scan.xml", XML, true},
		{"summary.html", HTML, true},
		{"summary.HTM", HTML, true},
		{"notes.txt", "", false},
		{"json", "", false},
	}
	for _, c := range cases {
		got, ok := table.Detect(c.name)
		if got != c.want || ok != c.ok {
			t.Errorf("Detect(%q) = %q, %v; want %q, %v", c.name, got, ok, c.want, c.ok)
		}
	}
}

func TestExtract(t *testing.T) {
	table := loadFormats(t)
	cases := []struct {
		name     string
		format   Format
		text     string
		values   []string
		commands []string
	}{
		{
			name:   "json escapes are decoded",
			format: JSON,
			text:   `{"url": "http:\/\/198.51.100.7\/a", "path": "C:\\loot\\out.txt", "n": 3, "ok": true}`,
			values: []string{"n", "ok", "path", `C:\loot\out.txt`, "url", "http://198.51.100.7/a"},
		},
		{
			name:     "json command fields at any depth",
			format:   JSON,
			text:     `{"steps": [{"Command_Line": "nmap -sV 10.0.0.5"}, {"cmd": " whoami "}, {"note": "id"}]}`,
			values:   []string{"steps", "Command_Line", "nmap -sV 10.0.0.5", "cmd", "whoami", "note", "id"},
			commands: []string{"nmap -sV 10.0.0.5", "whoami"},
		},
		{
			name:     "json argument vector is one command",
			format:   JSON,
			text:     `{"argv": ["curl", "-s", "http://a.example/x"]}`,
			values:   []string{"argv", "curl", "-s", "http://a.example/x"},
			commands: []string{"curl -s http://a.example/x"},
		},
		{
			name:     "json list of command lines",
			format:   JSON,
			text:     `{"commands": ["id", "net user /domain", 7]}`,
			values:   []string{"commands", "id", "net user /domain"},
			commands: []string{"id", "net user /domain"},
		},
		{
			name:     "json lines",
			format:   JSON,
			text:     "{\"cmd\": \"id\"}\n{\"cmd\": \"hostname\"}\n",
			values:   []string{"cmd", "id", "cmd", "hostname"},
			commands: []string{"id", "hostname"},
		},
		{
			name:   "json keys are values",
			format: JSON,
			text:   `{"10.0.0.9": {"open": [445]}}`,
			values: []string{"10.0.0.9", "open"},
		},
		{
			name:     "xml text, attributes, entities and cdata",
			format:   XML,
			text:     `<?xml version="1.0" encoding="UTF-16"?><run host="10.0.0.5"><!-- by agent --><command>curl "http://a.example/x?a=1&amp;b=2"</command><out><![CDATA[uid=0 <root>]]></out><step cmdline="whoami /all"/></run>`,
			values:   []string{"10.0.0.5", "by agent", `curl "http://a.example/x?a=1&b=2"`, "uid=0 <root>", "whoami /all"},
			commands: []string{`curl "http://a.example/x?a=1&b=2"`, "whoami /all"},
		},
		{
			name:     "html text, attributes, comments and code",
			format:   HTML,
			text:     `<!DOCTYPE html><html><head><style>a { margin: 0 }</style><script>var c2 = "198.51.100.7";</script></head><body><h1>Run &amp; report</h1><!-- cve-2024-1234 --><a href="https://a.example/x?a=1&amp;b=2" title='a > b'>link</a><p>1 < 2<br/>done</p><code>nmap <b>-sV</b> 10.0.0.5</code></body></html>`,
			values:   []string{`var c2 = "198.51.100.7";`, "Run & report", "cve-2024-1234", "https://a.example/x?a=1&b=2", "a > b", "link", "1 < 2", "done", "nmap", "-sV", "10.0.0.5"},
			commands: []string{"nmap -sV 10.0.0.5"},
		},
		{
			name:     "html left unclosed",
			format:   HTML,
			text:     `<p>x<kbd>id<a href="http://a.example`,
			values:   []string{"x", "id", "http://a.example"},
			commands: []string{"id"},
		},
		{name: "empty json", format: JSON},
		{name: "empty xml", format: XML},
		{name: "empty html", format: HTML},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := table.Extract(c.format, c.text)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got.Values, c.values) {
				t.Errorf("values = %q, want %q", got.Values, c.values)
			}
			if !slices.Equal(got.Commands, c.commands) {
				t.Errorf("commands = %q, want %q", got.Commands, c.commands)
			}
		})
	}
}

func TestExtractRejects(t *testing.T) {
	table := loadFormats(t)
	cases := []struct {
		name   string
		format Format
		text   string
	}{
		{"truncated json", JSON, `{"cmd": "id"`},
		{"not json", JSON, "scan complete\n"},
		{"second document broken", JSON, "{}\n{]"},
		{"truncated xml", XML, `<run><command>id`},
		{"unknown format", Format("yaml"), "a: b"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := table.Extract(c.format, c.text)
			if err == nil {
				t.Fatalf("no error; report = %+v", got)
			}
			if len(got.Values)+len(got.Commands) > 0 {
				t.Errorf("a rejected text yields %+v", got)
			}
		})
	}
}

func TestDecodeFormatsRejects(t *testing.T) {
	const formats = `"formats": [{"name": "json", "extensions": [".json"]}, {"name": "xml", "extensions": [".xml"]}, {"name": "html", "extensions": [".html"]}]`
	cases := []struct {
		name string
		data string
		want string
	}{
		{"unknown field", `{"extra": 1}`, "unknown field"},
		{"trailing data", `{` + formats + `, "command_fields": ["cmd"]} {}`, "data after the document"},
		{"missing format", `{"formats": [], "command_fields": ["cmd"]}`, "0 formats, want 3"},
		{"wrong order", `{"formats": [{"name": "xml", "extensions": [".xml"]}, {"name": "json", "extensions": [".json"]}, {"name": "html", "extensions": [".html"]}], "command_fields": ["cmd"]}`, `format 1 is "xml"`},
		{"no extensions", `{"formats": [{"name": "json"}, {"name": "xml", "extensions": [".xml"]}, {"name": "html", "extensions": [".html"]}], "command_fields": ["cmd"]}`, "has no extensions"},
		{"upper-case extension", `{"formats": [{"name": "json", "extensions": [".JSON"]}, {"name": "xml", "extensions": [".xml"]}, {"name": "html", "extensions": [".html"]}], "command_fields": ["cmd"]}`, "not a lower-case dot extension"},
		{"shared extension", `{"formats": [{"name": "json", "extensions": [".x"]}, {"name": "xml", "extensions": [".x"]}, {"name": "html", "extensions": [".html"]}], "command_fields": ["cmd"]}`, `extension ".x" is in`},
		{"no command fields", `{` + formats + `}`, "no command fields"},
		{"field not normalised", `{` + formats + `, "command_fields": ["command_line"]}`, "not lower-case letters and digits"},
		{"field twice", `{` + formats + `, "command_fields": ["cmd", "cmd"]}`, "listed twice"},
		{"element in two lists", `{` + formats + `, "command_fields": ["cmd"], "command_elements": ["code"], "dropped_elements": ["code"]}`, `element "code" is a`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := decodeFormats([]byte(c.data))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %v, want one holding %q", err, c.want)
			}
		})
	}
}

// FuzzExtractHTML checks that the hand-written scanner ends on any input.
func FuzzExtractHTML(f *testing.F) {
	table, err := LoadFormats()
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range []string{"<a href='x'>y</a>", "<", "<<a =>", "<style>", "<!--", "<code a=\"", "</ >"} {
		f.Add(seed)
	}
	f.Fuzz(func(_ *testing.T, text string) {
		table.extractHTML(text)
	})
}
