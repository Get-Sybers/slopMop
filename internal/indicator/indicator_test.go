package indicator

import (
	"testing"
)

func TestLoadPatterns(t *testing.T) {
	tbl, err := LoadPatterns()
	if err != nil {
		t.Fatalf("LoadPatterns: %v", err)
	}
	if len(tbl.patterns) == 0 {
		t.Fatal("no patterns loaded")
	}
}

func TestExtract(t *testing.T) {
	tbl, err := LoadPatterns()
	if err != nil {
		t.Fatalf("LoadPatterns: %v", err)
	}
	tests := []struct {
		name    string
		text    string
		wantTyp string
		wantVal string
	}{
		{"ipv4", "nmap -sn 10.20.1.5", "IPv4", "10.20.1.5"},
		{"ipv4 cidr", "TARGET_NET=10.20.1.0/24", "IPv4", "10.20.1.0/24"},
		{"url", "curl https://transfer.example.net/upload", "URL", "https://transfer.example.net/upload"},
		{"cve", "exploit for CVE-2016-6662", "CVE", "CVE-2016-6662"},
		{"private key", "-----BEGIN RSA PRIVATE KEY-----", "PrivateKey", "-----BEGIN RSA PRIVATE KEY-----"},
		{"email", "user admin@corp.example", "Email", "admin@corp.example"},
		{"domain", "host ca01.corp.example", "Domain", "ca01.corp.example"},
		{"guid", "-TenantId 8F3C2A10-7b6d-4e21-9a55-0c1d2e3f4a5b", "GUID", "8F3C2A10-7b6d-4e21-9a55-0c1d2e3f4a5b"},
		{"graph", "irm https://graph.microsoft.com/v1.0/users?$top=5", "GraphEndpoint", "https://graph.microsoft.com/v1.0/users?$top=5"},
		{"graph bare host", "-Resource https://graph.microsoft.com", "GraphEndpoint", "https://graph.microsoft.com"},
		{"graph legacy", "https://graph.windows.net/me", "GraphEndpoint", "https://graph.windows.net/me"},
		{"management", "'https://management.azure.com/subscriptions?api-version=2022-12-01'", "AzureManagementEndpoint", "https://management.azure.com/subscriptions?api-version=2022-12-01"},
		{"login", "https://login.microsoftonline.com/common/oauth2/v2.0/token", "EntraLoginEndpoint", "https://login.microsoftonline.com/common/oauth2/v2.0/token"},
		{"key vault", "https://corp-kv01.vault.azure.net/secrets/sql?api-version=7.4", "KeyVaultEndpoint", "https://corp-kv01.vault.azure.net/secrets/sql?api-version=7.4"},
		{"scope default", "scope=https://graph.microsoft.com/.default", "OAuthScope", "https://graph.microsoft.com/.default"},
		{"scope app uri", "api://8f3c2a10-7b6d-4e21-9a55-0c1d2e3f4a5b/.default", "OAuthScope", "api://8f3c2a10-7b6d-4e21-9a55-0c1d2e3f4a5b/.default"},
		{"scope permission", "-Scopes 'Directory.ReadWrite.All'", "OAuthScope", "Directory.ReadWrite.All"},
		{"scope two parts", "Mail.Send", "OAuthScope", "Mail.Send"},
		{"scope qualifier", "RoleManagement.ReadWrite.Directory", "OAuthScope", "RoleManagement.ReadWrite.Directory"},
		{"scope offline", "openid offline_access", "OAuthScope", "offline_access"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := tbl.Extract(tt.text)
			found := false
			for _, m := range matches {
				if m.Type == tt.wantTyp && m.Value == tt.wantVal {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Extract(%q): wanted {%s %s}, got %v", tt.text, tt.wantTyp, tt.wantVal, matches)
			}
		})
	}
	t.Run("empty", func(t *testing.T) {
		matches := tbl.Extract("nothing here")
		if len(matches) != 0 {
			t.Errorf("expected no matches, got %v", matches)
		}
	})
}

func TestExtractDedup(t *testing.T) {
	tbl, err := LoadPatterns()
	if err != nil {
		t.Fatalf("LoadPatterns: %v", err)
	}
	text := "ping 10.20.1.5 then ping 10.20.1.5 again"
	matches := tbl.Extract(text)
	count := 0
	for _, m := range matches {
		if m.Value == "10.20.1.5" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 deduped match for 10.20.1.5, got %d", count)
	}
}

func TestExtractSorted(t *testing.T) {
	tbl, err := LoadPatterns()
	if err != nil {
		t.Fatalf("LoadPatterns: %v", err)
	}
	text := "curl https://evil.example.com then nmap 10.20.1.5"
	matches := tbl.Extract(text)
	for i := 1; i < len(matches); i++ {
		if matches[i].Start < matches[i-1].Start {
			t.Fatalf("matches not sorted by Start: %d before %d", matches[i-1].Start, matches[i].Start)
		}
	}
}

func TestCountByType(t *testing.T) {
	tbl, err := LoadPatterns()
	if err != nil {
		t.Fatalf("LoadPatterns: %v", err)
	}
	text := "nmap 10.20.1.5 10.20.1.17 https://example.com"
	counts := tbl.CountByType(text)
	if counts["IPv4"] != 2 {
		t.Errorf("IPv4 count: got %d, want 2", counts["IPv4"])
	}
	if counts["URL"] != 1 {
		t.Errorf("URL count: got %d, want 1", counts["URL"])
	}
}

func TestExtractBoundaries(t *testing.T) {
	tbl, err := LoadPatterns()
	if err != nil {
		t.Fatalf("LoadPatterns: %v", err)
	}
	tests := []struct {
		name string
		text string
		typ  string
		want []string
	}{
		{"ipv4 five octets", "ver 1.2.3.4.5", "IPv4", nil},
		{"ipv4 octet overflow", "ping 10.0.0.256", "IPv4", nil},
		{"ipv4 leading digits", "id 1234.1.1.1", "IPv4", nil},
		{"ipv4 sentence end", "ping 10.20.1.5.", "IPv4", []string{"10.20.1.5"}},
		{"ipv4 port", "nc 10.20.1.5:443", "IPv4", []string{"10.20.1.5"}},
		{"ipv4 list", "10.20.1.5,10.20.1.6", "IPv4", []string{"10.20.1.5", "10.20.1.6"}},
		{"ipv4 no network of zero", "0.1.5.3", "IPv4", nil},
		{"ipv4 the tail of a longer number", "0.1.5.3.2 and 300.1.2.3.4", "IPv4", nil},
		{"ipv4 any address", "bind 0.0.0.0:8080 route 0.0.0.0/0", "IPv4", []string{"0.0.0.0", "0.0.0.0/0"}},
		{"ipv4 after version", "version 1.2.3.4", "IPv4", nil},
		{"ipv4 after a version field", `"version": "2.0.0.1"`, "IPv4", nil},
		{"ipv4 after an assembly version", "Version=4.0.0.0, Culture=neutral", "IPv4", nil},
		{"ipv4 after a longer name that ends in version", "FileVersion: 6.1.2.3 PSVersion 5.1.2.3", "IPv4", nil},
		{"ipv4 after ver and build", "ver. 1.2.3.4 build 2.3.4.5 Build: 3.4.5.6", "IPv4", nil},
		{"ipv4 a pinned package", "pkg==1.2.3.4 other>=2.3.4.5 more~=3.4.5.6 last<=4.5.6.7", "IPv4", nil},
		{"ipv4 a range of versions", "^1.2.3.4 ~2.3.4.5", "IPv4", nil},
		{"ipv4 a package name", "openssl-1.1.1.1.tar.gz libfoo-2.0.0.1", "IPv4", nil},
		{"ipv4 before a pre-release", "1.2.3.4-beta 2.3.4.5-rc1 3.4.5.6+dev", "IPv4", nil},
		{"ipv4 a browser in a user agent", "Mozilla/5.0 (X11) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0 HeadlessChrome/119.0.0.0", "IPv4", nil},
		{"ipv4 a version after a slash", "Version/17.2.1.5", "IPv4", nil},
		{"ipv4 a package of a distribution", "1.2.3.4-1ubuntu2 2.3.4.5-3.el8 3.4.5.6+dfsg 4.5.6.7~rc1", "IPv4", nil},
		{"ipv4 a range to a last number", "10.0.0.1-50 10.0.0.60-10.0.0.70", "IPv4", []string{"10.0.0.1", "10.0.0.60", "10.0.0.70"}},
		{"ipv4 in a path", "scans/10.0.0.5/ports.txt loot/10.0.0.6.txt", "IPv4", []string{"10.0.0.5", "10.0.0.6"}},
		{"ipv4 a version on one line, an address on the next", "version\n10.0.0.1", "IPv4", []string{"10.0.0.1"}},
		{"ipv4 a version far before it", "version 3 of the scanner, run by the operator, found the host 10.0.0.1", "IPv4", []string{"10.0.0.1"}},
		{"ipv4 after a word that only holds ver", "server 10.0.0.1 driver 10.0.0.2 over 10.0.0.3", "IPv4", []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}},
		{"ipv4 after an equals sign", "ip=10.0.0.1 RHOST = 10.0.0.2", "IPv4", []string{"10.0.0.1", "10.0.0.2"}},
		{"ipv4 in a range of addresses", "10.0.0.1-10.0.0.5", "IPv4", []string{"10.0.0.1", "10.0.0.5"}},
		{"ipv4 after a slash", "http://10.0.0.1/x cifs/10.0.0.2 user@10.0.0.3", "IPv4", []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}},
		{"ipv4 a share", `\\\\10.0.0.1\\share`, "IPv4", []string{"10.0.0.1"}},
		{"ipv4 a version, then the same number as an address", "version 1.2.3.4 then ping 1.2.3.4", "IPv4", []string{"1.2.3.4"}},
		{"domain namespace", "[System.Net.Sockets.TcpClient]", "Domain", nil},
		{"domain io namespace", "[System.IO.File]::ReadAllText", "Domain", nil},
		{"domain property", "$obj.Count", "Domain", nil},
		{"domain sentence end", "see evil.example.com.", "Domain", []string{"evil.example.com"}},
		{"domain path", "evil.example.com/a", "Domain", []string{"evil.example.com"}},
		{"guid short", "id 8f3c2a10-7b6d-4e21-9a55-0c1d2e3f4a5", "GUID", nil},
		{"guid long", "id 8f3c2a10-7b6d-4e21-9a55-0c1d2e3f4a5b6", "GUID", nil},
		{"guid not hex", "id 8f3c2a10-7b6d-4e21-9a55-0c1d2e3f4a5g", "GUID", nil},
		{"guid braces", "{8f3c2a10-7b6d-4e21-9a55-0c1d2e3f4a5b}", "GUID", []string{"8f3c2a10-7b6d-4e21-9a55-0c1d2e3f4a5b"}},
		{"graph lookalike suffix", "https://graph.microsoft.com.evil.example/v1.0", "GraphEndpoint", nil},
		{"graph lookalike userinfo", "https://graph.microsoft.com@evil.example/", "GraphEndpoint", nil},
		{"graph lookalike prefix", "https://evilgraph.microsoft.com/v1.0", "GraphEndpoint", nil},
		{"graph not url", "https://graph.microsoft.com/v1.0/me", "URL", nil},
		{"graph sentence end", "see https://graph.microsoft.com.", "GraphEndpoint", []string{"https://graph.microsoft.com"}},
		{"management lookalike", "https://management.azure.com-evil.example/", "AzureManagementEndpoint", nil},
		{"key vault lookalike", "https://kv01.vault.azure.net.evil.example/secrets", "KeyVaultEndpoint", nil},
		{"scope method call", "$Stream.Read($buf, 0, 4)", "OAuthScope", nil},
		{"scope namespace", "[System.IO.File]::ReadAllText", "OAuthScope", nil},
		{"scope member chain", "Mail.Read.Length", "OAuthScope", nil},
		{"scope lower case", "$user.read", "OAuthScope", nil},
		{"scope list", "User.Read.All,Mail.ReadWrite", "OAuthScope", []string{"User.Read.All", "Mail.ReadWrite"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			for _, m := range tbl.Extract(tt.text) {
				if m.Type == tt.typ {
					got = append(got, m.Value)
				}
			}
			if len(got) != len(tt.want) {
				t.Fatalf("Extract(%q) %s: got %v, want %v", tt.text, tt.typ, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("Extract(%q) %s: got %v, want %v", tt.text, tt.typ, got, tt.want)
				}
			}
		})
	}
}
