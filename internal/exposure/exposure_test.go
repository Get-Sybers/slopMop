package exposure

import (
	"slices"
	"strings"
	"testing"
)

func load(t *testing.T) Table {
	t.Helper()
	table, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	return table
}

// brief writes items as kind=value, with the account and the form of a
// secret, so a test states what it expects on one line.
func brief(items []Item) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		s := it.Kind + "=" + it.Value
		if it.Account != "" {
			s += " of " + it.Account
		}
		if it.Form != "" && it.Form != it.Kind {
			s += " (" + it.Form + ")"
		}
		out = append(out, s)
	}
	return out
}

func TestExtractLines(t *testing.T) {
	table := load(t)
	tests := []struct {
		name string
		text string
		want []string
	}{
		{"a field", `Password: Zx9!fakeValue`, []string{"password=Zx9!fakeValue"}},
		{"a username and its password below it", "Username: sync@corp.example\n    Password: Zx9!fakeValue", []string{"username=sync@corp.example", "password=Zx9!fakeValue of sync@corp.example"}},
		{"a password too far below a username", "Username: bob\n\n\n\n\nPassword: Zx9!fakeValue", []string{"username=bob", "password=Zx9!fakeValue"}},
		{"both on one line", `user=alice password=Spring2026!`, []string{"username=alice", "password=Spring2026! of alice"}},
		{"fields that belong together by their names", "DB_USER=app_rw\nDB_PASSWORD=Fixture-Pass-01\nSMTP_USER=alerts\nAPI_TOKEN=fixture-token-0123", []string{"username=app_rw", "password=Fixture-Pass-01 of app_rw", "username=alerts", "password=fixture-token-0123 (token)"}},
		{"a quoted assignment", `PASS='Winter2025!'`, []string{"password=Winter2025!"}},
		{"a name that ends as a secret does", `MSOL_PASS="Qw7#fake"`, []string{"password=Qw7#fake"}},
		{"a token and a key by their names", "access_token=abcdef123456\napi_key: K-998877", []string{"password=abcdef123456 (token)", "password=K-998877 (key)"}},
		{"a variable given its value", "U=svc_backup\nP='Winter2025!'\nnxc smb 10.0.0.5 -u \"$U\" -p \"$P\"", []string{"password=Winter2025! of svc_backup", "username=svc_backup"}},
		{"a variable inside a name", "N=msol\ncertipy find -u \"$N@corp.example\" -p 'Qw7#fake'", []string{"password=Qw7#fake of msol@corp.example", "username=msol@corp.example"}},
		{"a default value", `USER="${AD_USER:-svc_backup}"`, []string{"username=svc_backup"}},
		{"a domain before a name", `$User = 'CORP\svc_backup'`, []string{"username=svc_backup"}},
		{"a login that worked", `SMB  10.20.1.5   445  DC01   [+] corp.example\svc_backup:Winter2025! valid`, []string{"password=Winter2025! of svc_backup", "username=svc_backup", "device=DC01"}},
		{"a login that failed", `SMB  10.20.1.23  445  CA01   [-] corp.example\svc_backup:Winter2025! STATUS_LOGON_FAILURE`, []string{"username=svc_backup", "device=CA01"}},
		{"a dumped account", `Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846F7EAEE8FB117AD06BDD830B7586C:::`, []string{"password=8846f7eaee8fb117ad06bdd830b7586c of Administrator (hash)", "username=Administrator"}},
		{"a hash named in prose", `[*] Got hash for 'administrator@corp.example': aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c`, []string{"password=8846f7eaee8fb117ad06bdd830b7586c of administrator@corp.example (hash)", "username=administrator@corp.example"}},
		{"a hash passed to a tool", `nxc winrm 10.20.1.23 -u administrator -H 8846f7eaee8fb117ad06bdd830b7586c -x "id"`, []string{"password=8846f7eaee8fb117ad06bdd830b7586c of administrator (hash)", "username=administrator"}},
		{"a shadow line", `svc:$6$saltsalt$abcdefghijklmnop:19000:0:99999:7:::`, []string{"password=$6$saltsalt$abcdefghijklmnop of svc (hash)"}},
		{"a locked shadow line", `root:*:19000:0:99999:7:::`, nil},
		{"a passwd line", `svc:x:1001:1001:Service:/home/svc:/bin/bash`, []string{"username=svc"}},
		{"a password in an address", `mount //files01/share -o x; curl ftp://backup:Hunter22@files01.corp.local/x`, []string{"password=Hunter22 of backup", "device=files01.corp.local"}},
		{"a remote login", `ssh -i k ops@build01 'id'`, []string{"username=ops", "device=build01"}},
		{"a remote login by address", `ssh ops@198.51.100.7 'cat /etc/hostname'`, []string{"username=ops"}},
		{"a share", `net use \\FILES01\c$ /user:CORP\helper Passw0rd!x`, []string{"username=helper", "password=Passw0rd!x of helper", "device=FILES01"}},
		{"a scan report", `Nmap scan report for dc01.corp.example (10.20.1.5)`, []string{"device=dc01.corp.example"}},
		{"a home folder", `ls -la /home/deploy/.ssh`, []string{"username=deploy"}},
		{"a profile folder", `dir C:\Users\j.smith\Desktop`, []string{"username=j.smith"}},
		{"a shared profile folder", `copy a.dll C:\Users\Public\a.dll`, nil},
		{"a registry path", `reg query HKLM\Software\Microsoft`, nil},
		{"a host and a certificate authority", `certutil.exe -config "CA01.corp.example\corp-CA01-CA" -ping`, nil},
		{"a host and what it serves", `Connecting to CA01.corp.example\corp-CA01-CA ...`, nil},
		{"a secure string", `$p = ConvertTo-SecureString "Autumn2026!" -AsPlainText -Force`, []string{"password=Autumn2026!"}},
		{"a bearer token", `Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345`, []string{"password=abcdefghijklmnopqrstuvwxyz012345 (token)"}},
		{"a placeholder", "password=$PASS\nsecret: <redacted>\npwd=***\ntoken_type=Bearer\npassword: null", nil},
		{"an ldap filter", `ldapsearch "(sAMAccountName=MSOL_*)" sAMAccountName`, nil},
		{"a fully qualified name inside a longer one", `-subj "/CN=adfs.corp.example"`, nil},
		{"a short line", `a=b`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := brief(table.Extract(tt.text)); !slices.Equal(got, tt.want) {
				t.Errorf("Extract(%q) =\n  %q, want\n  %q", tt.text, got, tt.want)
			}
		})
	}
}

func TestExtractRecords(t *testing.T) {
	table := load(t)
	tests := []struct {
		name string
		text string
		want []string
	}{
		{"a table with tabs", "account\thost\tdescription\nMSOL_0a1b\tAADC01\tsync account\nsvc_adsync\tAADC01\tservice", []string{"username=MSOL_0a1b", "device=AADC01", "username=svc_adsync", "device=AADC01"}},
		{"a quoted table", "\ufeff\"Name\",\"IPv4Address\",\"OperatingSystem\"\r\n\"DC01\",\"10.20.1.5\",\"Windows Server 2022\"\r\n", []string{"device=DC01"}},
		{"a name that is no device", "Name,Type\ncorp.example,AD\n", nil},
		{"a table with a secret", "username;password\nalice;Spring2026!\nbob;\n", []string{"username=alice", "password=Spring2026! of alice", "username=bob"}},
		{"an object", `{"userPrincipalName":"alice@corp.example","password":"Spring2026!","enabled":true,"id":7}`, []string{"username=alice@corp.example", "password=Spring2026! of alice@corp.example"}},
		{"objects in a list", `{"value":[{"userPrincipalName":"alice@corp.example"},{"userPrincipalName":"bob@corp.example"}]}`, []string{"username=alice@corp.example", "username=bob@corp.example"}},
		{"a nested object", `{"host":{"hostname":"web01"},"user":{"name":"x"},"client_secret":"s3cr3t-value"}`, []string{"device=web01", "password=s3cr3t-value (secret)"}},
		{"a command in a string", `{"cmd":"nxc smb 10.0.0.5 -u helper -p 'Autumn2026!'"}`, []string{"password=Autumn2026! of helper", "username=helper"}},
		{"a list of strings", `["ssh ops@build01 id", 4, null]`, []string{"username=ops", "device=build01"}},
		{"what is not JSON after all", "{not json\nuser=alice\n", []string{"username=alice"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := brief(table.Extract(tt.text)); !slices.Equal(got, tt.want) {
				t.Errorf("Extract(%q) =\n  %q, want\n  %q", tt.text, got, tt.want)
			}
		})
	}
}

// A line number is the line of the text; a document of JSON Lines is its own line.
func TestExtractLineNumbers(t *testing.T) {
	table := load(t)
	lines := func(items []Item) []int {
		out := make([]int, len(items))
		for i, it := range items {
			out[i] = it.Line
		}
		return out
	}
	if got := lines(table.Extract("# notes\n\nuser=alice\npassword=Spring2026!\n")); !slices.Equal(got, []int{3, 4}) {
		t.Errorf("text lines = %v, want [3 4]", got)
	}
	if got := lines(table.Extract("{\"user\":\"alice\"}\n{\"note\":\"x\"}\n{\"user\":\"bob\"}\n")); !slices.Equal(got, []int{1, 3}) {
		t.Errorf("JSON Lines = %v, want [1 3]", got)
	}
	if got := lines(table.Extract("account,host\nalice,web01\nbob,web02\n")); !slices.Equal(got, []int{2, 2, 3, 3}) {
		t.Errorf("table rows = %v, want [2 2 3 3]", got)
	}
	long := "user=alice " + strings.Repeat("x", maxLine) + " password=Spring2026!"
	if got := brief(table.Extract(long)); !slices.Equal(got, []string{"username=alice"}) {
		t.Errorf("a line longer than the limit: %q, want what its first part holds", got)
	}
	if got := table.Extract("user=alice\nuser=alice\n"); len(got) != 2 {
		t.Errorf("the same value on two lines gives %d items, want one per line", len(got))
	}
	if got := table.Extract("user=alice user=alice\n"); len(got) != 1 {
		t.Errorf("the same value twice on a line gives %d items, want 1", len(got))
	}
}

func TestFromIndicator(t *testing.T) {
	table := load(t)
	tests := []struct {
		typ, value string
		want       Item
		ok         bool
	}{
		{"Email", "alice@corp.example", Item{Kind: "email", Value: "alice@corp.example", Line: 3}, true},
		{"IPv4", "10.20.1.5", Item{Kind: "ip", Value: "10.20.1.5", Line: 3}, true},
		{"JWT", "eyJhbGciOiJ.eyJzdWIiOiI.sig", Item{Kind: "password", Value: "eyJhbGciOiJ.eyJzdWIiOiI.sig", Form: "token", Line: 3}, true},
		{"PrivateKey", "-----BEGIN RSA PRIVATE KEY-----", Item{Kind: "password", Value: "rsa private key", Form: "key", Line: 3, Open: true}, true},
		{"URL", "http://x", Item{}, false},
		{"IPv4", "127.0.0.1", Item{}, false},
		{"Email", "not an address", Item{}, false},
	}
	for _, tt := range tests {
		if got, ok := table.FromIndicator(tt.typ, tt.value, 3); got != tt.want || ok != tt.ok {
			t.Errorf("FromIndicator(%s) = %+v, %t; want %+v, %t", tt.typ, got, ok, tt.want, tt.ok)
		}
	}
	if got, want := table.IndicatorTypes(), []string{"AWSKey", "Email", "IPv4", "JWT", "PrivateKey"}; !slices.Equal(got, want) {
		t.Errorf("IndicatorTypes = %q, want %q", got, want)
	}
}

func TestKinds(t *testing.T) {
	var names []string
	for _, k := range load(t).Kinds() {
		names = append(names, k.Name)
		if k.Secret != (k.Name == "password") {
			t.Errorf("%s: secret = %t", k.Name, k.Secret)
		}
	}
	if want := []string{"password", "username", "email", "device", "ip"}; !slices.Equal(names, want) {
		t.Errorf("kinds = %q, want %q", names, want)
	}
}

func TestMask(t *testing.T) {
	for secret, want := range map[string]string{
		"":                                 " (0 chars)",
		"abcd":                             "**** (4 chars)",
		"Winter2025!":                      "Wi********! (11 chars)",
		"hunter":                           "hu***r (6 chars)",
		"pässwörd":                         "pä*****d (8 chars)",
		"8846f7eaee8fb117ad06bdd830b7586c": "88********c (32 chars)",
	} {
		if got := Mask(secret); got != want {
			t.Errorf("Mask(%q) = %q, want %q", secret, got, want)
		}
		if secret != "" && strings.Contains(Mask(secret), secret) {
			t.Errorf("Mask(%q) holds the secret", secret)
		}
	}
}

func TestDecodeRejects(t *testing.T) {
	one := func(fields string) string {
		return `{"kinds":[{"name":"k","title":"K","severity":"low"` + fields + `}]}`
	}
	if _, err := decode([]byte(one(``))); err != nil {
		t.Fatalf("the smallest valid table: %v", err)
	}
	tests := map[string]string{
		"not json":                     `{`,
		"trailing data":                one(``) + ` x`,
		"unknown field":                one(`,"extra":1`),
		"no kinds":                     `{"kinds":[]}`,
		"no title":                     `{"kinds":[{"name":"k","severity":"low"}]}`,
		"named twice":                  `{"kinds":[{"name":"k","title":"K","severity":"low"},{"name":"k","title":"K","severity":"low"}]}`,
		"a key in upper case":          one(`,"keys":["User"]`),
		"a key twice":                  one(`,"keys":["user","user"]`),
		"a key in two kinds":           `{"kinds":[{"name":"a","title":"A","severity":"low","keys":["user"]},{"name":"b","title":"B","severity":"low","keys":["user"]}]}`,
		"a key beside nothing":         one(`,"with":{"name":[]}`),
		"a key with and without":       one(`,"keys":["name"],"with":{"name":["os"]}`),
		"a short ending":               one(`,"suffixes":[{"suffix":"ab"}]`),
		"an indicator twice":           one(`,"indicators":[{"type":"Email"},{"type":"Email"}]`),
		"an indicator with no type":    one(`,"indicators":[{"form":"x"}]`),
		"a bad valid":                  one(`,"valid":"("`),
		"a bad reject":                 one(`,"reject":"("`),
		"a bad pattern":                one(`,"patterns":[{"needs":["a"],"pattern":"("}]`),
		"a pattern without a value":    one(`,"patterns":[{"needs":["a"],"pattern":"(a)"}]`),
		"a pattern that needs nothing": one(`,"patterns":[{"needs":[],"pattern":"(?P<value>a)"}]`),
		"a needed text in upper case":  one(`,"patterns":[{"needs":["A"],"pattern":"(?P<value>a)"}]`),
		"a bad unless":                 one(`,"patterns":[{"needs":["a"],"unless":"(","pattern":"(?P<value>a)"}]`),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := decode([]byte(data)); err == nil {
				t.Errorf("decode(%s) gave no error", data)
			}
		})
	}
}
