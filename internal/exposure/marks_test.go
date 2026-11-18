package exposure

import (
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"github.com/get-sybers/slopmop/internal/vars"
)

// byLine is Extract of a text that is not JSON with every line searched for
// the needed texts as it is read: what the search of the whole text must equal.
func (t Table) byLine(text string) []Item {
	s := &scanner{t: t, vars: vars.Read(text), seen: map[Item]bool{}, services: map[asked]string{}}
	lines := strings.Split(text, "\n")
	s.columns(lines)
	for i, line := range lines {
		s.line(line, i+1)
	}
	return s.items
}

// lines are what the patterns and the fields of exposures.json read, and
// what they must leave alone.
func sampleLines() []string {
	return []string{
		"Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::",
		"svc_backup:$6$rounds=5000$salt$hashhashhashhash:19000:0:99999:7:::",
		"root:x:0:0:root:/root:/bin/bash",
		"[+] CORP\\alice:Summer2026! (Pwn3d!)",
		"crackmapexec smb 10.0.0.5 -u alice -p 'Summer2026!' --shares",
		"net use \\\\FS01\\share /user:CORP\\bob Winter2026!",
		"curl https://carol:S3cret@repo.corp.example/pkg.tgz -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9abcdef'",
		"DB_USER=app_rw", "DB_PASSWORD = \"Hunter2!\"", "api-key: 0123456789abcdef", "Host Name: WS-042", "plain words, no field",
		"ssh -i key dave@build01.corp.local 'id'", "SMB  10.0.0.9  445  DC01  [*] Windows Server", "Nmap scan report for web01.corp.internal",
		"sshpass -p 'Autumn2026!' ssh erin@10.0.0.7", "C:\\Users\\frank\\Desktop\\notes.txt", "/home/grace/.ssh/id_rsa",
		"2026-10-22T09:00:00Z sshd[1234]: Accepted publickey for svc from 10.0.0.1 port 22",
		"GET /api/v1/items?id=5 HTTP/1.1 200", "x", "", "a:b", strings.Repeat("pad ", 3000) + "password=TooFarAlong1!",
		"PASSWORD=Upper1! Token = abcDEF123456", "caf\u00e9 user=h\u00e9l\u00e8ne password=\u00e9t\u00e91234",
	}
}

// Marking the lines by one search of the whole text finds what a search of
// every line finds, whatever the lines are and in whatever order.
func TestExtractByMarksEqualsByLine(t *testing.T) {
	table := load(t)
	lines := sampleLines()
	texts := []string{strings.Join(lines, "\n"), strings.Join(lines, "\r\n") + "\n", "\n\n" + lines[4]}
	rng := rand.New(rand.NewPCG(7, 8))
	for range 300 {
		var b strings.Builder
		for n := 1 + rng.IntN(12); n > 0; n-- {
			b.WriteString(lines[rng.IntN(len(lines))])
			b.WriteString([]string{"\n", "\n", " ", "\t"}[rng.IntN(4)])
		}
		texts = append(texts, b.String())
	}
	found := 0
	for _, text := range texts {
		if table.mark(text, strings.Split(text, "\n")) == nil {
			t.Fatalf("the text %q is not marked: it does not try the marks", text)
		}
		got, want := table.Extract(text), table.byLine(text)
		if !slices.Equal(got, want) {
			t.Fatalf("Extract(%q) = %v, line by line gives %v", text, brief(got), brief(want))
		}
		found += len(want)
	}
	if found < 1000 {
		t.Errorf("the texts hold %d items: they do not try the marks", found)
	}
}

// A text whose lower case is not that of its ASCII letters is read line by line.
func TestMarkLeavesATextThatFolds(t *testing.T) {
	table := load(t)
	for _, text := range []string{"u\u017fer=alice password=Hunter2!\n", "\u212aEY=1 --password Hunter2!\n", "\u0130D=1 sshpass -p Hunter2! ssh a@b\n"} {
		if table.mark(text, strings.Split(text, "\n")) != nil {
			t.Errorf("the text %q is marked, want it read line by line", text)
		}
		if got, want := table.Extract(text), table.byLine(text); !slices.Equal(got, want) || len(want) == 0 {
			t.Errorf("Extract(%q) = %v, line by line gives %v", text, brief(got), brief(want))
		}
	}
}

// A line that names no field has no pair of any kind, so reading it for
// pairs would find nothing.
func TestNamedHoldsOfEveryPair(t *testing.T) {
	table := load(t)
	lines := sampleLines()
	parts := []string{
		"user", "USER", "pass word", "Pass-Word", "api_key", "host.name", "token", "x", "id", "name", "mail", "=", ":", " = ", ": ",
		"\"", "'", "alice", "Hunter2!", " ", ",", ";", "\u00e9", "9",
	}
	rng := rand.New(rand.NewPCG(9, 10))
	for range 3000 {
		var b strings.Builder
		for n := 1 + rng.IntN(8); n > 0; n-- {
			b.WriteString(parts[rng.IntN(len(parts))])
		}
		lines = append(lines, b.String())
	}
	named, read := 0, 0
	for _, line := range lines {
		s := &scanner{t: table, vars: vars.Set{}, seen: map[Item]bool{}, services: map[asked]string{}}
		s.pairs(line, 1)
		if len(s.items) > 0 {
			read++
			if !s.named(line) {
				t.Errorf("the line %q holds %v and is said to name no field", line, brief(s.items))
			}
		}
		if s.named(line) {
			named++
		}
	}
	if read < 150 || named == len(lines) {
		t.Errorf("%d of %d lines hold a pair and %d name a field: the lines do not try the check", read, len(lines), named)
	}
}
