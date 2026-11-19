package tactic

import "testing"

func TestLoadTactics(t *testing.T) {
	tab, err := LoadTactics()
	if err != nil {
		t.Fatal(err)
	}
	if len(tab.byCommand) == 0 {
		t.Fatal("table is empty")
	}
}

func TestClassify(t *testing.T) {
	tab, err := LoadTactics()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		command string
		want    string
	}{
		{"nmap", "Discovery"},
		{"ldapsearch", "Discovery"},
		{"mimikatz", "CredentialAccess"},
		{"secretsdump.py", "CredentialAccess"},
		{"certipy", "CredentialAccess"},
		{"ssh", "LateralMovement"},
		{"psexec.py", "LateralMovement"},
		{"python3", "Execution"},
		{"useradd", "Persistence"},
		{"shred", "Stealth"},
		{"mysqldump", "Collection"},
		{"scp", "Exfiltration"},
		{"chisel", "CommandAndControl"},

		// a name that does not say what the command does has no tactic
		{"curl", ""},
		{"certutil", ""},
		{"reg", ""},
		{"rclone", "Exfiltration"},

		// cloud
		{"Get-MgAuditLogDirectoryAudit", "Discovery"},
		{"Get-MgAuditLogSignIn", "Discovery"},
		{"Get-MgSecurityAlert", "Discovery"},
		{"Get-AzActivityLog", "Discovery"},
		{"Get-MgOauth2PermissionGrant", "Discovery"},
		{"Get-AzKeyVaultSecret", "CredentialAccess"},
		{"Backup-AzKeyVaultSecret", "CredentialAccess"},
		{"Backup-AzKeyVaultKey", "CredentialAccess"},
		{"Backup-AzKeyVaultCertificate", "CredentialAccess"},
		{"Get-AzStorageAccountKey", "CredentialAccess"},
		{"Get-MsalToken", "CredentialAccess"},
		{"Connect-IPPSSession", "LateralMovement"},
		{"Set-AzureADApplication", "Persistence"},
		{"New-MgApplicationFederatedIdentityCredential", "Persistence"},
		{"Set-MsolDomainFederationSettings", "Persistence"},
		{"New-MgServicePrincipalAppRoleAssignment", "Persistence"},
		{"New-MgOauth2PermissionGrant", "Persistence"},
		{"New-MgRoleManagementDirectoryRoleAssignment", "Persistence"},
		{"Set-AdminAuditLogConfig", "DefenseImpairment"},
		{"Set-MailboxAuditBypassAssociation", "DefenseImpairment"},
		{"Remove-AzDiagnosticSetting", "DefenseImpairment"},
		{"Export-Mailbox", "Collection"},
		{"New-MailboxExportRequest", "Collection"},
		{"Search-UnifiedAuditLog", "Collection"},
		{"New-ComplianceSearch", "Collection"},
		{"Start-ComplianceSearch", "Collection"},
		{"New-ComplianceSearchAction", "Collection"},

		// case insensitive
		{"Nmap", "Discovery"},
		{"MIMIKATZ", "CredentialAccess"},
		{"Invoke-Command", "LateralMovement"},

		// .exe stripping
		{"nmap.exe", "Discovery"},
		{"mimikatz.exe", "CredentialAccess"},

		// .py stripping: input has .py, table has bare form
		{"impacket-secretsdump.py", "CredentialAccess"},

		// unknown
		{"notarealcommand", ""},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			got := tab.Classify(tt.command)
			if got != tt.want {
				t.Errorf("Classify(%q) = %q, want %q", tt.command, got, tt.want)
			}
		})
	}
}

func TestDecodeRejectsEmpty(t *testing.T) {
	_, err := decode([]byte(`[{"tactic":"","commands":["x"]}]`))
	if err == nil {
		t.Fatal("expected error for empty tactic")
	}
	_, err = decode([]byte(`[{"tactic":"T","commands":[]}]`))
	if err == nil {
		t.Fatal("expected error for empty commands")
	}
}

// tacticOf is a tactic of a made-up table, with the fields every tactic needs.
func tacticOf(name, rest string) string {
	return `{"tactic":"` + name + `","severity":"low","id":"TA1","atlas":"AML.TA1",` + rest + `}`
}

// A command stands once in the table: in one tactic, under one technique or under none.
func TestParseRejectsDuplicate(t *testing.T) {
	for name, data := range map[string]string{
		"in two tactics":                   `[` + tacticOf("A", `"commands":["x"]`) + `,` + tacticOf("B", `"commands":["x"]`) + `]`,
		"under two techniques":             `[` + tacticOf("A", `"techniques":{"T1":["x"],"T2":["x"]}`) + `]`,
		"under a technique and under none": `[` + tacticOf("A", `"techniques":{"T1":["x"]},"commands":["x"]`) + `]`,
		"under a technique of two tactics": `[` + tacticOf("A", `"techniques":{"T1":["x"]}`) + `,` + tacticOf("B", `"techniques":{"T1":["x"]}`) + `]`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(data)); err == nil {
				t.Error("Parse gave no error")
			}
		})
	}
	if _, err := LoadTactics(); err != nil {
		t.Fatal("embedded file should not have duplicates:", err)
	}
}

// A command is filed under the technique it is, and its tactic is the one
// that holds the technique. A command under no technique has its tactic alone.
func TestTechnique(t *testing.T) {
	tab, err := Parse([]byte(`[` + tacticOf("A", `"techniques":{"T2":["y"],"T1":["x","w.py"]},"commands":["z"]`) + `,` + tacticOf("B", `"techniques":{"T3":["v"]}`) + `]`))
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ command, technique, tactic string }{
		{"x", "T1", "A"}, {"X.EXE", "T1", "A"}, {"w.py", "T1", "A"}, {"y", "T2", "A"}, {"v", "T3", "B"},
		{"z", "", "A"}, {"w", "", ""}, {"unknown", "", ""}, {"", "", ""},
	} {
		if got := tab.Technique(tt.command); got != tt.technique {
			t.Errorf("Technique(%q) = %q, want %q", tt.command, got, tt.technique)
		}
		if got := tab.Classify(tt.command); got != tt.tactic {
			t.Errorf("Classify(%q) = %q, want %q", tt.command, got, tt.tactic)
		}
	}
	if got := tab.Techniques("A"); len(got) != 2 || got[0] != "T1" || got[1] != "T2" {
		t.Errorf("Techniques(A) = %q, want T1 and T2 in order", got)
	}
	if got := tab.Techniques("C"); got != nil {
		t.Errorf("Techniques of an unknown tactic = %q", got)
	}
	for name, data := range map[string]string{
		"a technique with no command": `[` + tacticOf("A", `"techniques":{"T1":[]}`) + `]`,
		"a technique with no name":    `[` + tacticOf("A", `"techniques":{"":["x"]}`) + `]`,
		"a tactic with nothing":       `[` + tacticOf("A", `"techniques":{}`) + `]`,
	} {
		if _, err := Parse([]byte(data)); err == nil {
			t.Errorf("%s: Parse gave no error", name)
		}
	}
}

// A command of Discovery is filed under the technique its name alone gives.
// One whose flags or subcommand decide what it learns stands under none.
func TestDiscoveryTechniques(t *testing.T) {
	tab, err := LoadTactics()
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ command, want string }{
		{"Get-Service", "T1007"},
		{"ipconfig", "T1016"}, {"ifconfig", "T1016"}, {"ip", "T1016"}, {"route.exe", "T1016"},
		{"arp", "T1018"}, {"Get-ADComputer", "T1018"},
		{"whoami", "T1033"}, {"id", "T1033"}, {"quser", "T1033"},
		{"tcpdump", "T1040"}, {"nmap", "T1046"},
		{"netstat", "T1049"}, {"ss", "T1049"}, {"Get-NetTCPConnection", "T1049"},
		{"ps", "T1057"}, {"tasklist.exe", "T1057"}, {"Get-Process", "T1057"},
		{"groups", "T1069.001"}, {"Get-ADGroupMember", "T1069.002"}, {"Get-MgGroup", "T1069.003"},
		{"systeminfo", "T1082"}, {"uname", "T1082"}, {"dmidecode", "T1082"}, {"Get-ComputerInfo", "T1082"},
		{"ls", "T1083"}, {"dir", "T1083"}, {"tree", "T1083"}, {"Get-ChildItem", "T1083"},
		{"Get-LocalUser", "T1087.001"}, {"ldapsearch", "T1087.002"}, {"Get-ADUser", "T1087.002"},
		{"Get-GlobalAddressList", "T1087.003"}, {"Get-MgUser", "T1087.004"}, {"Get-Mailbox", "T1087.004"},
		{"ioreg", "T1120"}, {"timedatectl", "T1124"}, {"Get-SmbShare", "T1135"},
		{"Get-ADDefaultDomainPasswordPolicy", "T1201"}, {"Get-ADTrust", "T1482"},
		{"Get-MgApplication", "T1526"}, {"Get-AzResource", "T1580"},
		{"locale", "T1614.001"}, {"gpresult", "T1615"}, {"lsmod", "T1652"},
		{"journalctl", "T1654"}, {"Get-WinEvent", "T1654"}, {"Get-VM", "T1673"},
		{"lsblk", "T1680"}, {"Get-PSDrive", "T1680"},

		{"net", ""}, {"nltest", ""}, {"netsh", ""}, {"wmic", ""}, {"sc", ""}, {"query", ""},
		{"aws", ""}, {"az", ""}, {"gcloud", ""}, {"docker", ""}, {"kubectl", ""}, {"ping", ""}, {"dpkg", ""},
	} {
		if got := tab.Technique(tt.command); got != tt.want {
			t.Errorf("Technique(%q) = %q, want %q", tt.command, got, tt.want)
		}
		if got := tab.Classify(tt.command); got != "Discovery" {
			t.Errorf("Classify(%q) = %q, want Discovery", tt.command, got)
		}
	}
}

func TestDecodeRejectsTrailingData(t *testing.T) {
	_, err := decode([]byte(`[{"tactic":"A","commands":["x"]}] extra`))
	if err == nil {
		t.Fatal("expected error for trailing data")
	}
}

func TestDecodeRejectsUnknownFields(t *testing.T) {
	_, err := decode([]byte(`[{"tactic":"A","commands":["x"],"extra":true}]`))
	if err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestSeverity(t *testing.T) {
	tab, err := LoadTactics()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		tactic string
		want   Severity
	}{
		{"Discovery", Low},
		{"Execution", Medium},
		{"CredentialAccess", High},
		{"Exfiltration", High},
		{"NotATactic", Low},
	}
	for _, tt := range tests {
		t.Run(tt.tactic, func(t *testing.T) {
			if got := tab.Severity(tt.tactic); got != tt.want {
				t.Errorf("Severity(%q) = %q, want %q", tt.tactic, got, tt.want)
			}
		})
	}
	if High.Rank() <= Medium.Rank() || Medium.Rank() <= Low.Rank() || Low.Rank() <= Severity("").Rank() {
		t.Error("Rank does not order high, medium, low, unknown")
	}
}

func TestDecodeRejectsSeverity(t *testing.T) {
	if _, err := decode([]byte(`[{"tactic":"X","severity":"dire","commands":["a"]}]`)); err == nil {
		t.Error("an unknown severity is accepted")
	}
}

func TestHas(t *testing.T) {
	tab, err := LoadTactics()
	if err != nil {
		t.Fatal(err)
	}
	if tab.Attack("Stealth") != "TA0005" || tab.Atlas("CommandAndControl") != "AML.TA0014" || tab.Attack("NoSuchTactic") != "" {
		t.Error("a tactic's identifier is wrong")
	}
	if names := tab.Names(); len(names) != 13 || names[0] != "InitialAccess" || names[12] != "Impact" {
		t.Errorf("Names() = %q, want the 13 tactics in file order", names)
	}
	for _, name := range []string{"Discovery", "InitialAccess", "PrivilegeEscalation"} {
		if !tab.Has(name) {
			t.Errorf("Has(%q) = false, want true", name)
		}
		if tab.Severity(name).Rank() == 0 {
			t.Errorf("Severity(%q) has no rank", name)
		}
	}
	if tab.Has("NoSuchTactic") || tab.Has("") {
		t.Error("Has reports a tactic the table lacks")
	}
}
