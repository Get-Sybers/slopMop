package exposure

import (
	"slices"
	"strings"
	"testing"
)

// What collecting an account shows is told by its shape: how it stands on
// its line, the account itself, or what it is of. The first shape that fits
// is its own, and an account of no shape still shows that accounts were found.
func TestCollected(t *testing.T) {
	table := load(t)
	const office = "Microsoft 365"
	tests := []struct {
		name, kind, value, line string
		services                []string
		want                    string
		plain                   bool
	}{
		{"a name after its domain", "username", "jsmith", `CORP\jsmith`, nil, "DomainAccountDiscovery T1087.002", false},
		{"a name after its domain, in a field", "username", "svc_sql", `owner = "corp.example\svc_sql" S-1-5-21-1-2-3-1105`, nil, "DomainAccountDiscovery T1087.002", false},
		{"the name of an account of a directory", "username", "mhall", "SamAccountName : mhall", nil, "DomainAccountDiscovery T1087.002", false},
		{"a name at a domain that is not public", "username", "jdoe@corp.local", "UserPrincipalName : jdoe@corp.local", nil, "DomainAccountDiscovery T1087.002", false},
		{"an account of a service", "username", "alice@contoso.onmicrosoft.com", "userPrincipalName: alice@contoso.onmicrosoft.com", []string{office}, "CloudAccountDiscovery T1087.004", false},
		{"an account of a service, whatever its line", "email", "sa@p.iam.gserviceaccount.com", "", []string{"Google Cloud"}, "CloudAccountDiscovery T1087.004", false},
		{"a user of AWS", "username", "ci-bot", "arn:aws:iam::123456789012:user/build/ci-bot", nil, "CloudAccountDiscovery T1087.004", false},
		{"an address", "email", "bob@partner.example", "mail: bob@partner.example", nil, "EmailAccountDiscovery T1087.003", false},
		{"an address that a host is for is no account of a service", "email", "bob@partner.example", "", []string{"10.0.0.5"}, "EmailAccountDiscovery T1087.003", false},
		{"a line of the password file", "username", "deploy", "deploy:x:1000:1000::/home/deploy:/bin/bash", nil, "LocalAccountDiscovery T1087.001", false},
		{"who a command runs as", "username", "deploy", "uid=1000(deploy) gid=1000(deploy) groups=1000(deploy)", nil, "SystemUserDiscovery T1033", false},
		{"who is signed in", "username", "ops", "ops      pts/0        2026-11-01 09:00 (10.0.0.9)", nil, "SystemUserDiscovery T1033", false},
		{"a name of no shape", "username", "carol", "username: carol", nil, "AccountDiscovery T1087", true},
		{"a name with no line", "username", "carol", "", nil, "AccountDiscovery T1087", true},
		{"another account on a line of a shape", "username", "carol", `CORP\jsmith and carol`, nil, "AccountDiscovery T1087", true},
		{"a kind that is no account", "tenant", "contoso.onmicrosoft.com", "tenant: contoso.onmicrosoft.com", []string{office}, "", false},
		{"a kind the table lacks", "nothing", "x", "x", nil, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shown, plain, ok := table.Collected(tt.kind, tt.value, tt.services, tt.line)
			got := strings.TrimSpace(shown.Activity + " " + shown.Technique)
			if got != tt.want || plain != tt.plain || ok != (tt.want != "") {
				t.Errorf("Collected = %q, plain %t, ok %t; want %q, plain %t", got, plain, ok, tt.want, tt.plain)
			}
		})
	}
	shows := table.Shows()
	if len(shows) != 6 || !slices.Contains(shows, Shown{Activity: "AccountDiscovery", Technique: "T1087"}) {
		t.Errorf("Shows = %v, want the six activities, each once", shows)
	}
}

func TestShapesReject(t *testing.T) {
	for name, entries := range map[string][]accountEntry{
		"no activity":                   {{Technique: "T1087"}},
		"no technique":                  {{Activity: "A"}},
		"an activity of two techniques": {{Activity: "A", Technique: "T1"}, {Activity: "A", Technique: "T2"}},
		"a value that does not compile": {{Activity: "A", Technique: "T1", Value: "("}},
		"a line that does not compile":  {{Activity: "A", Technique: "T1", Line: "("}},
		"a line that names no account":  {{Activity: "A", Technique: "T1", Line: "^x"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := shapes(entries); err == nil {
				t.Error("shapes gave no error")
			}
		})
	}
	got, err := shapes([]accountEntry{{Activity: "A", Technique: "T1", Line: "^(?P<account>x)"}, {Activity: "A", Technique: "T1"}})
	if err != nil || len(got) != 2 {
		t.Errorf("two shapes of one activity: %v, %v", got, err)
	}
}
