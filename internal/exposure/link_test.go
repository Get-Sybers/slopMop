package exposure

import (
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// webToken makes a JSON web token of the claims, signed by nothing.
func webToken(t *testing.T, claims string) string {
	t.Helper()
	if !json.Valid([]byte(claims)) {
		t.Fatalf("the claims %s are not JSON", claims)
	}
	part := func(text string) string { return base64.RawURLEncoding.EncodeToString([]byte(text)) }
	return part(`{"alg":"RS256","typ":"JWT"}`) + "." + part(claims) + "." + part("signature")
}

// An account is named where a field, a command or an output says who signs
// in. A word that follows a field name in a sentence is none, and neither is
// what only looks like a name.
func TestExtractAccounts(t *testing.T) {
	table := load(t)
	tests := []struct {
		name, text string
		want       []string
	}{
		{"a field", "User Name: CORP\\jdoe", []string{"username=jdoe"}},
		{"a field of an event", "Account Name:\t\tjdoe", []string{"username=jdoe"}},
		{"a field of a directory", "SamAccountName : jdoe", []string{"username=jdoe"}},
		{"a variable of the environment", "USERNAME=jdoe", []string{"username=jdoe"}},
		{"two fields on a line", "User: jdoe Domain: CORP", []string{"username=jdoe"}},
		{"a field that ends a sentence", "The user: admin.", []string{"username=admin"}},
		{"who an account is", "uid=1000(deploy) gid=1000(deploy) groups=1000(deploy),27(sudo)", []string{"username=deploy"}},
		{"who is asked", "corp\\jdoe", []string{"username=jdoe"}},
		{"who is asked, with the identifier", "corp\\jdoe S-1-5-21-1111111111-2222222222-3333333333-1105", []string{"username=jdoe"}},
		{"who is signed in", "deploy   pts/0        2026-10-20 10:00 (10.0.0.5)", []string{"username=deploy"}},
		{"who may run what", "User deploy may run the following commands on web01:", []string{"username=deploy"}},
		{"a rule of sudo", "deploy ALL=(ALL) NOPASSWD: ALL", []string{"username=deploy"}},
		{"an account that is made", "useradd -m -s /bin/bash svc_task", []string{"username=svc_task"}},
		{"an account that is changed", "usermod -aG sudo svc_task 2>/dev/null", []string{"username=svc_task"}},
		{"an account of Windows that is made", "net user backdoor P@ssw0rd123 /add", []string{"username=backdoor", "password=P@ssw0rd123 of backdoor"}},
		{"an account put in a group", "net localgroup administrators backdoor /add", []string{"username=backdoor"}},
		{"an account that is read", "net user jdoe /domain", []string{"username=jdoe"}},
		{"an account made by a cmdlet", `New-LocalUser -Name "svc_update" -Password $sec`, []string{"username=svc_update"}},
		{"a member of a group", `Add-LocalGroupMember -Group "Administrators" -Member "svc_update"`, []string{"username=svc_update"}},
		{"an account another runs as", "sudo -u www-data id", []string{"username=www-data"}},
		{"an account another becomes", "sudo su - postgres", []string{"username=postgres"}},
		{"an owner", "chown deploy:deploy /srv/app", []string{"username=deploy"}},
		{"an account of AWS", "arn:aws:iam::123456789012:user/alice", []string{"username=alice"}},
		{"a home folder", "/home/kali/tools/exploit.py -t 10.0.0.5", []string{"username=kali"}},

		{"a sentence after a field", "# Create user: backdoor account for persistence", nil},
		{"a sentence after a field that names no one", "# Check user: verify the account exists", nil},
		{"a time after a field", "Last login: Mon Oct 20 10:00:00 2026 from 10.0.0.5", nil},
		{"the system", "User: NT AUTHORITY\\SYSTEM", nil},
		{"an account that is storage", "Storage Account: mystorageacct", nil},
		{"a date", `"lastLogin": "2026-10-20"`, nil},
		{"an identifier", "uid: 3f2a1b4c-5d6e-4f70-8a9b-0c1d2e3f4a5b", nil},
		{"an option that is no account", "python3 -u script.py", nil},
		{"an option of git", "git push -u origin main", nil},
		{"an option of sort", "sort -u names.txt", nil},
		{"an option with no value", "pip install --user requests", nil},
		{"an image", "docker pull registry.io/image@sha256:abcdef", nil},
		{"a line break in a text", `echo "line1\nline2"`, nil},
		{"a file in a folder", `Get-Content logs\app.log`, nil},
		{"a folder in a folder", `cd tools\bin`, nil},
		{"a line of a report", "[+] URL:http://example.org/x", nil},
		{"a field that is no account", "identity: SystemAssigned", nil},
		{"a field that is no owner", "owner: team-platform", nil},
		{"a product after a field", "Server: Apache httpd 2.4.41", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := brief(table.Extract(tt.text)); !slices.Equal(got, tt.want) {
				t.Errorf("Extract(%q) =\n  %q, want\n  %q", tt.text, got, tt.want)
			}
		})
	}
}

// A secret is of the account its line names and for the host its line
// names, where the line names one of each; a token says both itself.
func TestExtractLinks(t *testing.T) {
	table := load(t)
	const app, secret = "1b2c3d4e-5f60-4718-8293-a4b5c6d7e8f9", "Qz8~fakeClientSecretValue.0123456789abc" //nolint:gosec // G101: a made-up value in the form of a secret.
	user := webToken(t, `{"aud":"https://graph.microsoft.com","iss":"https://sts.windows.net/6f9619ff-8b86-4d11-b42d-00c04fc964ff/","upn":"adm@contoso.onmicrosoft.com"}`)
	service := webToken(t, `{"aud":"https://vault.corp.example","appid":"`+app+`"}`)
	account := webToken(t, `{"iss":"kubernetes/serviceaccount","sub":"system:serviceaccount:kube-system:default"}`)
	key := base64.StdEncoding.EncodeToString([]byte(`{"type": "service_account", "project_id": "acme-prod-4711", "client_email": "deployer@acme-prod-4711.iam.gserviceaccount.com"}`))
	tests := []struct {
		name, text string
		want       []string
	}{
		{"a password and the login beside it", "sshpass -p 'Winter2026!' ssh root@10.0.0.5 id", []string{"username=root", "password=Winter2026! of root for 10.0.0.5"}},
		{"a password by its long option", "mysql --user=root --password=Secr3t! crm", []string{"username=root", "password=Secr3t! of root"}},
		{"a password joined to its option", "mysql -u root -pSecr3tDb crm", []string{"username=root", "password=Secr3tDb of root"}},
		{"a password after a name and a percent sign", "smbclient //fs01/share -U jdoe%Summer2026", []string{"username=jdoe", "password=Summer2026 of jdoe"}},
		{"a password of a remote desktop", "xfreerdp /u:admin /p:Passw0rd! /v:rdp01.corp.local", []string{"username=admin", "device=rdp01.corp.local", "password=Passw0rd! of admin for rdp01.corp.local"}},
		{"a password sent to another system", `schtasks /create /s dc01 /u corp\admin /p Passw0rd! /tn Updater /tr c:\x.exe`, []string{"username=admin", "password=Passw0rd! of admin for dc01"}},
		{"a password and a share", `psexec \\dc01 -u CORP\admin -p Passw0rd! cmd`, []string{"username=admin", "password=Passw0rd! of admin for dc01"}},
		{"a password of a directory", `ldapsearch -x -H ldap://dc01.corp.local -D "cn=svc_ldap,dc=corp,dc=local" -w 'Ld4pPass!' -b dc=corp,dc=local`,
			[]string{"device=dc01.corp.local", "password=Ld4pPass! of cn=svc_ldap,dc=corp,dc=local for dc01.corp.local"}},
		{"a password set through a pipe", `echo "svc_task:Chang3Me!" | chpasswd`, []string{"password=Chang3Me! of svc_task", "username=svc_task"}},
		{"a password in a secure string", `$cred = New-Object PSCredential("CORP\admin", (ConvertTo-SecureString "Winter2026!" -AsPlainText -Force))`, []string{"username=admin", "password=Winter2026! of admin"}},
		{"a password after a domain and a name", "secretsdump.py corp.local/admin:Passw0rd@10.0.0.5", []string{"username=admin", "device=corp.local", "password=Passw0rd of admin for 10.0.0.5"}},
		{"basic authentication in base64", `curl -H "Authorization: Basic c3ZjX2FwaTpTdXAzclMzY3JldCE=" https://jenkins.corp.local/api/json`,
			[]string{"device=jenkins.corp.local", "password=Sup3rS3cret! of svc_api for jenkins.corp.local", "username=svc_api"}},
		{"a name and a password of curl", "curl -u admin:Hunter2pass https://nexus.corp.local/status", []string{"device=nexus.corp.local", "password=Hunter2pass of admin for nexus.corp.local", "username=admin"}},
		{"a key and the address it is sent to", `curl -H "X-Api-Key: abcd1234efgh5678" -o /home/kali/out.json https://api.vendor.example/v1/x`, []string{"username=kali", "apikey=abcd1234efgh5678 (key) for api.vendor.example"}},
		{"a key sent to a service that is known", `curl -H "X-Api-Key: abcd1234efgh5678" https://api.cloudflare.com/client/v4/zones`, []string{"apikey=abcd1234efgh5678 (key) for Cloudflare"}},
		{"a secret of an application that signs in", `az login --service-principal --username ` + app + ` --password "` + secret + `"`,
			[]string{"application=" + app + " for Microsoft 365", "password=" + secret + " of " + app + " for Microsoft 365"}},
		{"a secret below its application", "$clientId = \"" + app + "\"\n$clientSecret = \"" + secret + "\"",
			[]string{"application=" + app + " for Microsoft 365", "password=" + secret + " of " + app + " (secret) for Microsoft 365"}},
		{"a secret beside its application", "client_id=" + app + "&client_secret=" + secret + "&grant_type=client_credentials",
			[]string{"application=" + app + " for Microsoft 365", "password=" + secret + " of " + app + " (secret) for Microsoft 365"}},
		{"a token of a user", `curl -H "Authorization: Bearer ` + user + `" https://graph.microsoft.com/v1.0/users`,
			[]string{"password=" + user + " of adm@contoso.onmicrosoft.com (token) for Microsoft 365", "username=adm@contoso.onmicrosoft.com for Microsoft 365"}},
		{"a token of an application, for what it names", "access_token=" + service, []string{"password=" + service + " of " + app + " (token) for https://vault.corp.example"}},
		{"a token in base64", "token: " + base64.StdEncoding.EncodeToString([]byte(account)), []string{"password=" + base64.StdEncoding.EncodeToString([]byte(account)) + " of system:serviceaccount:kube-system:default (token)"}},
		{"a key of a service account in base64", `"privateKeyData": "` + key + `"`,
			[]string{"password=" + key + " of deployer@acme-prod-4711.iam.gserviceaccount.com (key) for Google Cloud", "username=deployer@acme-prod-4711.iam.gserviceaccount.com for Google Cloud"}},

		{"two accounts on a line own nothing", "ssh -l alice bob@10.0.0.5 --password=Secr3t!", []string{"username=alice", "username=bob", "password=Secr3t! for 10.0.0.5"}},
		{"two hosts on a line are no host", "curl -x http://10.0.0.9:8080 -u admin:Hunter2pass https://nexus.corp.example/status", []string{"password=Hunter2pass of admin", "username=admin"}},
		{"the password of an exported key is of no one", `nxc winrm 10.20.1.23 -u administrator -x "certutil -exportPFX -p Export1! My $T ca.p12"`, []string{"username=administrator", "password=Export1!"}},
		{"a line under a heading is no secret", "===== Access Token =====", nil},
		{"a line of signs is no key", "=== API Key ==========", nil},
		{"a rule is no secret", "Secret Key: ----------------", nil},
		{"a sentence after a field is no secret", "password: must be at least 8 characters", nil},
		{"a rule of sudo holds no password", "deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl", []string{"username=deploy"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := brief(table.Extract(tt.text)); !slices.Equal(got, tt.want) {
				t.Errorf("Extract(%q) =\n  %q, want\n  %q", tt.text, got, tt.want)
			}
		})
	}
}

// A token brought in by its indicator names its owner, and the owner is an
// account of its own.
func TestOwner(t *testing.T) {
	table := load(t)
	token := webToken(t, `{"iss":"https://accounts.google.com","email":"deployer@acme-prod-4711.iam.gserviceaccount.com"}`)
	item, ok := table.FromIndicator("JWT", token, 7)
	if want := (Item{Kind: "password", Value: token, Account: "deployer@acme-prod-4711.iam.gserviceaccount.com", Form: "token", Service: "Google Cloud", Line: 7}); !ok || item != want {
		t.Fatalf("FromIndicator = %+v, %t; want %+v", item, ok, want)
	}
	owner, ok := table.Owner(item)
	if want := (Item{Kind: "username", Value: "deployer@acme-prod-4711.iam.gserviceaccount.com", Service: "Google Cloud", Line: 7}); !ok || owner != want {
		t.Errorf("Owner = %+v, %t; want %+v", owner, ok, want)
	}
	for _, it := range []Item{
		{Kind: "password", Value: "x"},
		{Kind: "username", Value: "alice", Account: "alice"},
		{Kind: "password", Value: "x", Account: "1b2c3d4e-5f60-4718-8293-a4b5c6d7e8f9"},
		{Kind: "password", Value: "x", Account: "cn=svc,dc=corp"},
	} {
		if got, ok := table.Owner(it); ok {
			t.Errorf("Owner(%+v) = %+v, want none", it, got)
		}
	}
}

// An encoded value is written as a reader takes it in; one that only looks
// encoded stands as it is.
func TestDecoded(t *testing.T) {
	table := load(t)
	token := webToken(t, `{"aud":"https://graph.microsoft.com","iss":"https://sts.windows.net/t/","tid":"t","appid":"a1","upn":"adm@contoso.onmicrosoft.com","unique_name":"adm@contoso.onmicrosoft.com","scp":"User.Read Mail.Read","roles":["Directory.Read.All","Mail.Send"],"exp":1793527200,"uti":"x"}`)
	other := webToken(t, `{"jti":"7","admin":true,"nested":{"a":1}}`)
	document := base64.StdEncoding.EncodeToString([]byte("{\n  \"type\": \"service_account\",\n  \"project_id\": \"acme-prod-4711\",\n  \"private_key\": \"-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\\n-----END PRIVATE KEY-----\\n\",\n  \"client_email\": \"deployer@acme-prod-4711.iam.gserviceaccount.com\"\n}"))
	tests := []struct {
		name, value, want string
	}{
		{"a token", token, "upn=adm@contoso.onmicrosoft.com; appid=a1; aud=https://graph.microsoft.com; scp=User.Read Mail.Read; roles=Directory.Read.All Mail.Send; exp=2026-11-01T10:00:00Z; tid=t; iss=https://sts.windows.net/t/"},
		{"a token of claims that are not listed", other, "jti=7; admin=true"},
		{"a token in base64", base64.StdEncoding.EncodeToString([]byte(other)), "jti=7; admin=true"},
		{"a document in base64", document, "type=service_account; project_id=acme-prod-4711; private_key=-----BEGIN PRIVATE KEY----- MIIEvQIBADANBgkqhkiG9w0BAQEFAASCB...; client_email=deployer@acme-prod-4711.iam.gserviceaccount.com"},
		{"a text in base64", base64.StdEncoding.EncodeToString([]byte("user=svc_api\npassword=Sup3rS3cret!\n")), "user=svc_api password=Sup3rS3cret!"},
		{"a text in the other alphabet, without padding", base64.RawURLEncoding.EncodeToString([]byte("the quick brown fox jumps >> over ?? the dog")), "the quick brown fox jumps >> over ?? the dog"},
		{"a key block", "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n-----END PRIVATE KEY-----\n", "PRIVATE KEY (PEM) SHA256:DH9xxBAhvCqRoJcb6/7pNDe+Z6hjjXppvW2mm9C8/Cs"},
		{"a key block that holds nothing", "-----BEGIN CERTIFICATE-----", "CERTIFICATE (PEM)"},
		{"a key of a service, which is not text", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", ""},
		{"a hash", "8846f7eaee8fb117ad06bdd830b7586c", ""},
		{"a password", "Winter2026!abcde", ""},
		{"a password in the letters of base64", "administrator123", ""},
		{"a token that is opaque", "0.AXoA_fake_refresh_token_value_that_is_opaque_and_long_enough_0123456789", ""},
		{"a short value", "dGVzdA==", ""},
		{"nothing", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := table.Decoded(tt.value)
			if got != tt.want || ok != (tt.want != "") {
				t.Errorf("Decoded(%q) = %q, %t; want %q", tt.value, got, ok, tt.want)
			}
		})
	}
	long, ok := table.Decoded(base64.StdEncoding.EncodeToString([]byte(strings.Repeat("word ", 200))))
	if !ok || len(long) != maxDecoded || !strings.HasSuffix(long, "...") {
		t.Errorf("a long text is written in %d bytes ending %q, want %d bytes that end in an ellipsis", len(long), long[max(0, len(long)-8):], maxDecoded)
	}
}

// A host of a vendor that any script reaches for is no target; a host that
// a tenant or a customer names under a vendor's domain is one.
func TestVendor(t *testing.T) {
	table := load(t)
	for host, want := range map[string]bool{
		"www.google.com": true, "google.com": true, "GRAPH.MICROSOFT.COM": true, "login.microsoftonline.com": true, "maps.googleapis.com": true,
		"archive.ubuntu.com": true, "pypi.org": true, "github.com": true, "raw.githubusercontent.com": true, "r3.o.lencr.org": true, "aka.ms.": true,
		"contoso.sharepoint.com": false, "contoso.onmicrosoft.com": false, "vault1.vault.azure.net": false, "acme.blob.core.windows.net": false,
		"vm1.eastus.cloudapp.azure.com": false, "acme.s3.amazonaws.com": false, "drive.google.com": false, "storage.googleapis.com": false,
		"notgoogle.com": false, "google.com.evil.example": false, "transfer.example.net": false, "10.0.0.5": false, "": false,
	} {
		if got := table.Vendor(host); got != want {
			t.Errorf("Vendor(%q) = %t, want %t", host, got, want)
		}
	}
	if _, ok := table.FromHardcoded("Domain", "www.google.com", 1); !ok {
		t.Error("a host of a vendor is not a host a script names: the caller leaves it out of the targets")
	}
}
