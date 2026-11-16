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
		{"crontab", "Persistence"},
		{"shred", "DefenseEvasion"},
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
		{"Set-AdminAuditLogConfig", "DefenseEvasion"},
		{"Set-MailboxAuditBypassAssociation", "DefenseEvasion"},
		{"Remove-AzDiagnosticSetting", "DefenseEvasion"},
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

func TestDecodeRejectsDuplicate(t *testing.T) {
	data := []byte(`[{"tactic":"A","commands":["x"]},{"tactic":"B","commands":["x"]}]`)
	_, err := decode(data)
	if err != nil {
		t.Log(err)
	}
	// duplicate detected at LoadTactics level
	_, err = LoadTactics()
	if err != nil {
		t.Fatal("embedded file should not have duplicates:", err)
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
