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
	if len(shows) != 9 || !slices.Contains(shows, Shown{Activity: "AccountDiscovery", Technique: "T1087"}) || !slices.Contains(shows, Shown{Activity: "GroupDiscovery", Technique: "T1069"}) {
		t.Errorf("Shows = %v, want the nine activities of accounts and identifiers, each once", shows)
	}
}

// A security identifier says what it is of by its authority and its relative
// identifier, and by what its line calls it; a name beside its relative
// identifier is what its listing says. The first shape that finds it is its own.
func TestIdentified(t *testing.T) {
	table := load(t)
	const domain = "S-1-5-21-1111111111-2222222222-3333333333"
	tests := []struct {
		name, line string
		want       []string
	}{
		{"a group of the machine", `BUILTIN\Administrators  Alias  S-1-5-32-544  Mandatory group, Enabled by default`, []string{"LocalGroupDiscovery T1069.001 S-1-5-32-544"}},
		{"a group every domain has", `CORP\Domain Admins  Group  ` + domain + `-512  Mandatory group`, []string{"DomainGroupDiscovery T1069.002 " + domain + "-512"}},
		{"the group of every user, of a domain or of a machine", domain + "-513", []string{"GroupDiscovery T1069 " + domain + "-513"}},
		{"the account of the ticket service", "objectSid: " + domain + "-502", []string{"DomainAccountDiscovery T1087.002 " + domain + "-502"}},
		{"an account every machine and domain has", "Administrator  " + domain + "-500", []string{"AccountDiscovery T1087 " + domain + "-500"}},
		{"a group a machine was given", `PC01\Backup Team  Alias  ` + domain + `-1009  Mandatory group`, []string{"LocalGroupDiscovery T1069.001 " + domain + "-1009"}},
		{"a group a domain was given", `CORP\App Owners  Group  ` + domain + `-1109  Mandatory group`, []string{"DomainGroupDiscovery T1069.002 " + domain + "-1109"}},
		{"an identifier that says no more", "SID : " + domain + "-1105", []string{"AccountDiscovery T1087 " + domain + "-1105 plain"}},
		{"what follows the identifier calls it nothing", domain + "-1105  Mandatory group, Enabled group", []string{"AccountDiscovery T1087 " + domain + "-1105 plain"}},
		{"two identifiers of one line", "S-1-5-32-545 and " + domain + "-519 and S-1-5-32-545", []string{"LocalGroupDiscovery T1069.001 S-1-5-32-545", "DomainGroupDiscovery T1069.002 " + domain + "-519"}},
		{"an account in a listing of a domain", "user:[svc_sql] rid:[0x451]", []string{"DomainAccountDiscovery T1087.002 svc_sql"}},
		{"a group in a listing of a domain", "group:[Domain Admins] rid:[0x200]", []string{"DomainGroupDiscovery T1069.002 Domain Admins"}},
		{"an account by its relative identifier", `1105: CORP\jsmith (SidTypeUser)`, []string{`DomainAccountDiscovery T1087.002 CORP\jsmith`}},
		{"a group by its relative identifier", `512: CORP\Domain Admins (SidTypeGroup)`, []string{`DomainGroupDiscovery T1069.002 CORP\Domain Admins`}},
		{"a group of the machine by its relative identifier", `544: BUILTIN\Administrators (SidTypeAlias)`, []string{`LocalGroupDiscovery T1069.001 BUILTIN\Administrators`}},
		{"the system and everyone are of no shape", "S-1-5-18 S-1-1-0 S-1-16-12288", nil},
		{"a number that is no identifier", "RS-1-5-32-544x, version 1-5-21-1-2-3-512", nil},
		{"a line that holds none", "nothing of the kind", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			for _, f := range table.Identified(tt.line) {
				text := f.Activity + " " + f.Technique + " " + f.Value
				if f.Plain {
					text += " plain"
				}
				if f.Group != strings.HasSuffix(f.Activity, "GroupDiscovery") {
					t.Errorf("%s of %s is of a group: %t", f.Activity, f.Value, f.Group)
				}
				got = append(got, text)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("Identified = %q, want %q", got, tt.want)
			}
			if may := table.MayIdentify(strings.ToLower(tt.line)); !may && len(tt.want) > 0 {
				t.Error("MayIdentify says the line holds none")
			}
		})
	}
	if table.MayIdentify("nothing of the kind") {
		t.Error("MayIdentify finds an identifier in a text that holds none")
	}
}

// A name on a line whose identifier is of a group is the name of the group:
// it is no username. The name beside the identifier of an account is one.
func TestExtractLeavesOutTheNamesOfGroups(t *testing.T) {
	table := load(t)
	const domain = "S-1-5-21-1111111111-2222222222-3333333333"
	text := strings.Join([]string{
		`BUILTIN\Administrators   Alias   S-1-5-32-544   Mandatory group, Enabled by default`,
		`CORP\Enterprise Admins   Group   ` + domain + `-519   Mandatory group`,
		`CORP\App Owners   Group   ` + domain + `-1109   Mandatory group`,
		`corp\jdoe   ` + domain + `-1105`,
		`544: BUILTIN\Administrators (SidTypeAlias)`,
		`1105: CORP\jsmith (SidTypeUser)`,
		`User Name: CORP\mhall`,
	}, "\n")
	var got []string
	for _, it := range table.Extract(text) {
		if it.Kind == usernameKind {
			got = append(got, it.Value)
		}
	}
	slices.Sort(got)
	if want := []string{"jdoe", "jsmith", "mhall"}; !slices.Equal(got, want) {
		t.Errorf("usernames = %q, want %q: the names of the groups are no accounts", got, want)
	}
}

func TestFindersReject(t *testing.T) {
	good := identifierEntry{Activity: "A", Technique: "T1", Needs: []string{"s-1-"}, Line: `(?P<found>S-1-\d+)`}
	with := func(change func(*identifierEntry)) []identifierEntry {
		e := good
		change(&e)
		return []identifierEntry{e}
	}
	for name, entries := range map[string][]identifierEntry{
		"no activity":                   with(func(e *identifierEntry) { e.Activity = "" }),
		"no technique":                  with(func(e *identifierEntry) { e.Technique = "" }),
		"no text a line must hold":      with(func(e *identifierEntry) { e.Needs = nil }),
		"a text that is not lower":      with(func(e *identifierEntry) { e.Needs = []string{"S-1-"} }),
		"a line that does not compile":  with(func(e *identifierEntry) { e.Line = "(" }),
		"a line that finds nothing":     with(func(e *identifierEntry) { e.Line = `S-1-\d+` }),
		"an activity of two techniques": {good, with(func(e *identifierEntry) { e.Technique = "T2" })[0]},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := finders(entries, nil); err == nil {
				t.Error("finders gave no error")
			}
		})
	}
	// An activity that accounts show as well is of the technique they give it.
	if _, err := finders([]identifierEntry{good}, []shape{{Shown: Shown{Activity: "A", Technique: "T9"}}}); err == nil {
		t.Error("an activity of two techniques, one of an account, gave no error")
	}
	if got, err := finders([]identifierEntry{good, good}, []shape{{Shown: Shown{Activity: "A", Technique: "T1"}}}); err != nil || len(got) != 2 {
		t.Errorf("two shapes of one activity: %v, %v", got, err)
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
