package parse

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

const bashDir = "../evidencetest/testdata/bash"

func readFixture(tb testing.TB, name string) string {
	tb.Helper()
	data, err := os.ReadFile(filepath.Join(bashDir, name))
	if err != nil {
		tb.Fatal(err)
	}
	return string(data)
}

func toolNames(s Script) []string {
	var names []string
	for _, c := range s.Commands {
		names = append(names, c.Tool)
	}
	return names
}

func varMap(s Script) map[string]string {
	m := make(map[string]string)
	for _, v := range s.Variables {
		m[v.Name] = v.Value
	}
	return m
}

func contains(ss []string, target string) bool {
	return slices.Contains(ss, target)
}

func TestBashStep01Recon(t *testing.T) {
	s := ExtractBash(readFixture(t, "20250301_101500_step01_recon.sh"))
	tools := toolNames(s)
	if !contains(tools, "nmap") {
		t.Errorf("commands = %v, want nmap", tools)
	}
	vars := varMap(s)
	if vars["TARGET_NET"] != "10.20.1.0/24" {
		t.Errorf("TARGET_NET = %q, want 10.20.1.0/24", vars["TARGET_NET"])
	}
	if vars["OUT"] != "20250301_101530_step01_recon.txt" {
		t.Errorf("OUT = %q, want 20250301_101530_step01_recon.txt", vars["OUT"])
	}
}

func TestBashStep02Enum(t *testing.T) {
	s := ExtractBash(readFixture(t, "20250301_101800_step02_enum.sh"))
	tools := toolNames(s)
	if !contains(tools, "nxc") {
		t.Errorf("commands = %v, want nxc", tools)
	}
	if !contains(tools, "ldapsearch") {
		t.Errorf("commands = %v, want ldapsearch", tools)
	}
	if !contains(s.Writes, "20250301_101845_step02_enum.log") {
		t.Errorf("writes = %v, want enum.log", s.Writes)
	}
	if !contains(s.Writes, "20250301_101910_step02_users.tsv") {
		t.Errorf("writes = %v, want users.tsv", s.Writes)
	}
}

func TestBashStep03Adsync(t *testing.T) {
	s := ExtractBash(readFixture(t, "20250301_102300_step03_adsync.sh"))
	tools := toolNames(s)
	if !contains(tools, "nxc") {
		t.Errorf("commands = %v, want nxc", tools)
	}
	if !contains(tools, "adconnectdump.py") {
		t.Errorf("commands = %v, want adconnectdump.py", tools)
	}
	if !contains(s.Reads, "20250301_101910_step02_users.tsv") {
		t.Errorf("reads = %v, want step02_users.tsv", s.Reads)
	}
}

func TestBashStep05Certs(t *testing.T) {
	s := ExtractBash(readFixture(t, "20250301_103200_step05_certs.sh"))
	tools := toolNames(s)
	if !contains(tools, "certipy") {
		t.Errorf("commands = %v, want certipy", tools)
	}
	if !contains(tools, "openssl") {
		t.Errorf("commands = %v, want openssl", tools)
	}
	if !contains(s.Writes, "20250301_103240_certipy_find.txt") {
		t.Errorf("writes = %v, want certipy_find.txt", s.Writes)
	}
	if !contains(s.Writes, "20250301_103300_notes.txt") {
		t.Errorf("writes = %v, want notes.txt", s.Writes)
	}
	if !contains(s.Reads, "20250301_101910_step02_users.tsv") {
		t.Errorf("reads = %v, want step02_users.tsv", s.Reads)
	}
}

func TestBashStep06Auth(t *testing.T) {
	s := ExtractBash(readFixture(t, "20250301_104000_step06_auth.sh"))
	tools := toolNames(s)
	if !contains(tools, "certipy") {
		t.Errorf("commands = %v, want certipy", tools)
	}
	if !contains(tools, "secretsdump.py") {
		t.Errorf("commands = %v, want secretsdump.py", tools)
	}
	if !contains(tools, "nxc") {
		t.Errorf("commands = %v, want nxc", tools)
	}
	if !contains(s.Writes, "20250301_104010_step06_auth.txt") {
		t.Errorf("writes = %v, want step06_auth.txt", s.Writes)
	}
	if !contains(s.Writes, "20250301_104030_ca_store.txt") {
		t.Errorf("writes = %v, want ca_store.txt", s.Writes)
	}
}

func TestBashStep07Exfil(t *testing.T) {
	s := ExtractBash(readFixture(t, "20250301_104500_step07_exfil.sh"))
	tools := toolNames(s)
	if !contains(tools, "nxc") {
		t.Errorf("commands = %v, want nxc", tools)
	}
	if !contains(tools, "curl") {
		t.Errorf("commands = %v, want curl", tools)
	}
	vars := varMap(s)
	if vars["CA_THUMB"] != "3f2a9c1e7b6d5a4f3e2d1c0b9a8f7e6d5c4b3a29" {
		t.Errorf("CA_THUMB = %q, want thumbprint", vars["CA_THUMB"])
	}
}

const psDir = "../evidencetest/testdata/powershell"

func readPsFixture(tb testing.TB, name string) string {
	tb.Helper()
	data, err := os.ReadFile(filepath.Join(psDir, name))
	if err != nil {
		tb.Fatal(err)
	}
	return string(data)
}

func TestPsStep01Inventory(t *testing.T) {
	s := ExtractPowerShell(readPsFixture(t, "20250302_090000_step01_inventory.ps1"))
	tools := toolNames(s)
	if !contains(tools, "get-adcomputer") {
		t.Errorf("commands = %v, want get-adcomputer", tools)
	}
	if !contains(tools, "select-object") {
		t.Errorf("commands = %v, want select-object", tools)
	}
	if !contains(tools, "export-csv") {
		t.Errorf("commands = %v, want export-csv", tools)
	}
	vars := varMap(s)
	if vars["Domain"] != "corp.example" {
		t.Errorf("Domain = %q, want corp.example", vars["Domain"])
	}
}

func TestPsStep02Sync(t *testing.T) {
	s := ExtractPowerShell(readPsFixture(t, "20250302_090500_step02_sync.ps1"))
	tools := toolNames(s)
	if !contains(tools, "import-csv") {
		t.Errorf("commands = %v, want import-csv", tools)
	}
	if !contains(tools, "invoke-command") {
		t.Errorf("commands = %v, want invoke-command", tools)
	}
}

func TestPsStep04Certs(t *testing.T) {
	s := ExtractPowerShell(readPsFixture(t, "20250302_091500_step04_certs.ps1"))
	tools := toolNames(s)
	if !contains(tools, "invoke-command") {
		t.Errorf("commands = %v, want invoke-command", tools)
	}
	if !contains(tools, "certutil.exe") {
		t.Errorf("commands = %v, want certutil.exe", tools)
	}
	if !contains(s.Writes, "cert_store_20250302_091530.txt") {
		t.Errorf("writes = %v, want cert_store", s.Writes)
	}
	if !contains(s.Writes, "ca_ping_20250302_091540.log") {
		t.Errorf("writes = %v, want ca_ping", s.Writes)
	}
}

func TestPsStep05Export(t *testing.T) {
	s := ExtractPowerShell(readPsFixture(t, "20250302_092200_step05_export.ps1"))
	tools := toolNames(s)
	if !contains(tools, "export-certificate") {
		t.Errorf("commands = %v, want export-certificate", tools)
	}
	if !contains(tools, "new-selfsignedcertificate") {
		t.Errorf("commands = %v, want new-selfsignedcertificate", tools)
	}
	if !contains(s.Writes, "export_summary_20250302_092215.txt") {
		t.Errorf("writes = %v, want export_summary", s.Writes)
	}
}
