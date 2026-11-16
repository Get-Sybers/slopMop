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
