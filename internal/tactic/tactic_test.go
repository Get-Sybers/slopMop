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
		{"curl", "Exfiltration"},
		{"rclone", "Exfiltration"},

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
