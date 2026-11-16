package activity

import (
	"slices"
	"strings"
	"testing"
)

func names(hits []Hit) []string {
	var out []string
	for _, h := range hits {
		out = append(out, h.Name)
	}
	return out
}

func TestDetect(t *testing.T) {
	table, err := LoadActivities()
	if err != nil {
		t.Fatal(err)
	}
	const ga = "62e90394-69f5-4237-9190-012177145e10"
	tests := []struct {
		name string
		line string
		want []string
	}{
		{"ga by template in the url", "Invoke-RestMethod -Method Post -Uri https://graph.microsoft.com/v1.0/directoryRoles/roleTemplateId=" + ga + "/members/$ref", []string{"GlobalAdministratorAssignment"}},
		{"ga by cmdlet", "New-MgRoleManagementDirectoryRoleAssignment -PrincipalId $sp -RoleDefinitionId " + ga + " -DirectoryScopeId /", []string{"GlobalAdministratorAssignment"}},
		{"ga by name", `Add-MsolRoleMember -RoleName "Company Administrator" -RoleMemberObjectId $id`, []string{"GlobalAdministratorAssignment"}},
		{"ga role only read", "Get-MgRoleManagementDirectoryRoleAssignment -Filter \"roleDefinitionId eq '" + ga + "'\"", nil},
		{"ga template listed in an output", "Global Administrator  " + ga + "  Can manage all aspects", nil},
		{"role member by ref", "curl -X POST https://graph.microsoft.com/v1.0/directoryRoles/9b8c/members/$ref -d @body.json", []string{"RoleAssignment"}},
		{"role assignment rest", `requests.post("https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments", json=body)`, []string{"RoleAssignment"}},
		{"role assignments read", "curl -s https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments", []string{"GraphDirectoryEnumeration"}},
		{"azure rbac", `az role assignment create --assignee $APP --role "User Access Administrator" --scope /`, []string{"RoleAssignment"}},
		{"azure rbac list", "az role assignment list --all", nil},
		{"app role rest", "POST https://graph.microsoft.com/v1.0/servicePrincipals/1f2e/appRoleAssignments", []string{"AppRoleAssignment"}},
		{"app role assigned to", `Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$id/appRoleAssignedTo" -Body $b`, []string{"AppRoleAssignment"}},
		{"app role cmdlet", "New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp -PrincipalId $sp -ResourceId $graph -AppRoleId $role", []string{"AppRoleAssignment"}},
		{"app role read", "curl -s https://graph.microsoft.com/v1.0/servicePrincipals/1f2e/appRoleAssignments", []string{"GraphDirectoryEnumeration"}},
		{"consent grant", "az ad app permission admin-consent --id $APP", []string{"AppRoleAssignment"}},
		{"add password rest", "curl -X POST https://graph.microsoft.com/v1.0/applications/77aa/addPassword -d '{}'", []string{"AppCredentialAddition"}},
		{"add password cmdlet", "Add-MgApplicationPassword -ApplicationId $app", []string{"AppCredentialAddition"}},
		{"credential reset", "az ad sp credential reset --id $APP --append", []string{"AppCredentialAddition"}},
		{"token endpoint", "curl -d grant_type=client_credentials https://login.microsoftonline.com/1111/oauth2/v2.0/token", []string{"TokenRequest"}},
		{"cli service principal", "az login --service-principal -u $APP -p $SECRET --tenant $T", []string{"TokenRequest"}},
		{"interactive cli", "az login", nil},
		{"graph sign-in as app", "Connect-MgGraph -TenantId $t -ClientSecretCredential $cred", []string{"TokenRequest"}},
		{"msal", "result = app.acquire_token_for_client(scopes=scope)", []string{"TokenRequest"}},
		{"graph users", "curl -H \"$AUTH\" https://graph.microsoft.com/v1.0/users?$top=999", []string{"GraphDirectoryEnumeration"}},
		{"graph cmdlet", "Get-MgServicePrincipal -All", []string{"GraphDirectoryEnumeration"}},
		{"cli directory", "az ad sp list --all", []string{"GraphDirectoryEnumeration"}},
		{"mailbox rest", "GET https://graph.microsoft.com/v1.0/users/alice@corp.example/messages?$top=50", []string{"MailboxAccess"}},
		{"mailbox cmdlet", "Get-MgUserMessage -UserId $u -All", []string{"MailboxAccess"}},
		{"ews", "https://outlook.office365.com/EWS/Exchange.asmx", []string{"MailboxAccess"}},
		{"teams folder", "https://graph.microsoft.com/v1.0/users/bob/mailFolders/TeamsMessagesData/messages", []string{"TeamsMessageAccess"}},
		{"teams chats", "https://graph.microsoft.com/v1.0/users/bob/chats/getAllMessages", []string{"TeamsMessageAccess"}},
		{"teams channel", "https://graph.microsoft.com/beta/teams/7a/channels/19:abc/messages", []string{"TeamsMessageAccess"}},
		{"sharepoint sites", "https://graph.microsoft.com/v1.0/sites?search=*", []string{"SharePointEnumeration"}},
		{"onedrive", "https://graph.microsoft.com/v1.0/users/bob/drive/root/children", []string{"SharePointEnumeration"}},
		{"sharepoint rest", "https://corp.sharepoint.com/sites/hr/_api/web/lists", []string{"SharePointEnumeration"}},
		{"sharepoint cmdlet", "Get-MgSite -Search '*'", []string{"SharePointEnumeration"}},
		{"secret rest", "curl https://corpvault.vault.azure.net/secrets?api-version=7.4", []string{"KeyVaultSecretRead"}},
		{"secret cli", "az keyvault secret show --vault-name corpvault --name db", []string{"KeyVaultSecretRead"}},
		{"secret cmdlet", "Get-AzKeyVaultSecret -VaultName corpvault", []string{"KeyVaultSecretRead"}},
		{"secret sdk", "value = client.get_secret(name).value", []string{"KeyVaultSecretRead"}},
		{"secret set", "az keyvault secret set --vault-name corpvault --name db --value x", nil},
		{"key list", "curl https://corpvault.vault.azure.net/keys?api-version=7.4", []string{"KeyVaultKeyEnumeration"}},
		{"key unwrap", "POST https://corpvault.vault.azure.net/keys/kek/0a1b/unwrapkey?api-version=7.4", []string{"KeyVaultKeyUnwrap"}},
		{"key unwrap cmdlet", "Invoke-AzKeyVaultKeyOperation -Operation UnwrapKey -VaultName corpvault -Name kek", []string{"KeyVaultKeyUnwrap"}},
		{"vault list", "az keyvault list --query [].name -o tsv", []string{"AzureResourceEnumeration"}},
		{"arm subscriptions", "curl https://management.azure.com/subscriptions?api-version=2022-12-01", []string{"AzureResourceEnumeration"}},
		{"arm write", "curl -X PUT https://management.azure.com/subscriptions/1/resourceGroups/rg?api-version=2022-12-01", nil},
		{"lookalike host", "https://graph.microsoft.com.evil.example/v1.0/users", nil},
		{"unrelated", "nmap -sn 10.20.1.0/24", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := names(table.Detect(tt.line)); !slices.Equal(got, tt.want) {
				t.Errorf("Detect(%q) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

func TestDetectCountsLinesOnce(t *testing.T) {
	table, err := LoadActivities()
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Join([]string{
		"az keyvault secret show --vault-name a --name x",
		"curl https://a.vault.azure.net/secrets/x && az keyvault secret show --vault-name a --name x",
		"echo done",
		"Get-AzKeyVaultSecret -VaultName b",
	}, "\r\n")
	hits := table.Detect(text)
	if len(hits) != 1 || hits[0].Name != "KeyVaultSecretRead" || hits[0].Lines != 3 {
		t.Errorf("hits = %+v, want KeyVaultSecretRead on 3 lines", hits)
	}
	if !slices.Equal(hits[0].Tactics, []string{"CredentialAccess"}) {
		t.Errorf("tactics = %q, want CredentialAccess", hits[0].Tactics)
	}
}

func TestDetectKeepsTableOrder(t *testing.T) {
	table, err := LoadActivities()
	if err != nil {
		t.Fatal(err)
	}
	text := "az keyvault list\nAdd-MgApplicationPassword -ApplicationId $a\n"
	if got, want := names(table.Detect(text)), []string{"AppCredentialAddition", "AzureResourceEnumeration"}; !slices.Equal(got, want) {
		t.Errorf("Detect = %q, want %q", got, want)
	}
	if got := table.Detect(""); got != nil {
		t.Errorf("Detect of nothing = %+v, want none", got)
	}
}

func TestTactics(t *testing.T) {
	table, err := LoadActivities()
	if err != nil {
		t.Fatal(err)
	}
	got := table.Tactics()
	for _, want := range []string{"PrivilegeEscalation", "InitialAccess", "Collection", "CredentialAccess"} {
		if !slices.Contains(got, want) {
			t.Errorf("Tactics() = %q, lacks %s", got, want)
		}
	}
	sorted := slices.Clone(got)
	slices.Sort(sorted)
	if len(slices.Compact(sorted)) != len(got) {
		t.Errorf("Tactics() = %q, has a duplicate", got)
	}
}

func TestDetectInContext(t *testing.T) {
	table, err := LoadActivities()
	if err != nil {
		t.Fatal(err)
	}
	const ga = "62e90394-69f5-4237-9190-012177145e10"
	tests := []struct {
		name string
		text string
		want []string
	}{
		{
			"powershell escapes the dollar of $ref",
			"Invoke-RestMethod -Method Post -Uri \"https://graph.microsoft.com/v1.0/directoryRoles/roleTemplateId=" + ga + "/members/`$ref\"",
			[]string{"GlobalAdministratorAssignment"},
		},
		{
			"an address built by concatenation",
			`requests.get("https://graph.microsoft.com/v1.0/users/" + user + "/messages?$top=500")`,
			[]string{"MailboxAccess"},
		},
		{
			"the host held in a variable",
			"GRAPH = \"https://graph.microsoft.com/v1.0\"\nr = requests.get(f\"{GRAPH}/users/{uid}/mailFolders\")\ns = requests.get(GRAPH + \"/sites?search=*\")\nu = requests.get(f\"{GRAPH}/users\")\n",
			[]string{"GraphDirectoryEnumeration", "MailboxAccess", "SharePointEnumeration"},
		},
		{
			"the same paths without the host anywhere",
			"r = requests.get(f\"{BASE}/users/{uid}/mailFolders\")\ns = requests.get(BASE + \"/sites?search=*\")\n",
			nil,
		},
		{
			"a file path is not a graph path",
			"GRAPH=https://graph.microsoft.com/v1.0\ncp /Users/bob/notes.txt C:/Users/bob/out\n",
			nil,
		},
		{
			"a curl command continued over lines",
			"curl -s -X POST \\\n  -H \"Authorization: Bearer $T\" \\\n  https://graph.microsoft.com/v1.0/servicePrincipals/$SP/appRoleAssignments\n",
			[]string{"AppRoleAssignment"},
		},
		{
			"a powershell command continued over lines",
			"Invoke-RestMethod -Method Post `\r\n  -Uri \"$graph/applications/$app/addPassword\"\r\n",
			[]string{"AppCredentialAddition"},
		},
		{
			"the vault held in a variable",
			"VAULT=https://corpvault.vault.azure.net\ncurl \"$VAULT/secrets?api-version=7.4\"\ncurl \"$VAULT/keys?api-version=7.4\"\n",
			[]string{"KeyVaultSecretRead", "KeyVaultKeyEnumeration"},
		},
		{
			"a local secrets folder beside a vault",
			"VAULT=https://corpvault.vault.azure.net\ncat /run/secrets/db ~/.ssh/keys\n",
			nil,
		},
		{
			"the token endpoint with the tenant in a variable",
			"curl -d grant_type=client_credentials \"https://login.microsoftonline.com/$TENANT/oauth2/v2.0/token\"",
			[]string{"TokenRequest"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := names(table.Detect(tt.text)); !slices.Equal(got, tt.want) {
				t.Errorf("Detect(%q) = %q, want %q", tt.text, got, tt.want)
			}
		})
	}
}

func TestDecodeRejects(t *testing.T) {
	one := func(fields string) string {
		return `{"contexts":{"c":"x"},"activities":[{"name":"A","tactics":["T"],` + fields + `}]}`
	}
	if _, err := decode([]byte(one(`"patterns":["a"]`))); err != nil {
		t.Fatalf("the smallest valid table: %v", err)
	}
	if _, err := decode([]byte(one(`"context":"c","paths":["a"]`))); err != nil {
		t.Fatalf("a table of paths only: %v", err)
	}
	tests := map[string]string{
		"not json":           `{`,
		"no activities":      `{"contexts":{},"activities":[]}`,
		"trailing data":      one(`"patterns":["a"]`) + ` x`,
		"unknown field":      one(`"patterns":["a"],"extra":1`),
		"empty name":         `{"activities":[{"name":"","tactics":["T"],"patterns":["a"]}]}`,
		"named twice":        `{"activities":[{"name":"A","tactics":["T"],"patterns":["a"]},{"name":"A","tactics":["T"],"patterns":["b"]}]}`,
		"no tactics":         `{"activities":[{"name":"A","tactics":[],"patterns":["a"]}]}`,
		"no patterns":        one(`"patterns":[]`),
		"bad pattern":        one(`"patterns":["("]`),
		"bad path":           one(`"context":"c","paths":["("]`),
		"bad unless":         one(`"patterns":["a"],"unless":"("`),
		"bad context":        `{"contexts":{"c":"("},"activities":[{"name":"A","tactics":["T"],"patterns":["a"]}]}`,
		"paths, no context":  one(`"paths":["a"]`),
		"context, no paths":  one(`"patterns":["a"],"context":"c"`),
		"an unknown context": one(`"context":"d","paths":["a"]`),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := decode([]byte(data)); err == nil {
				t.Errorf("decode(%s) gave no error", data)
			}
		})
	}
}

// A pattern is tried only on the lines that hold one of its literals, so a
// literal that is wrong hides matches. Every pattern must have literals, and
// every line a pattern matches must hold one of them.
func TestLiteralsAreSound(t *testing.T) {
	table, err := LoadActivities()
	if err != nil {
		t.Fatal(err)
	}
	corpus := []string{
		"Invoke-RestMethod -Method Post -Uri https://graph.microsoft.com/v1.0/directoryRoles/roleTemplateId=62e90394-69f5-4237-9190-012177145e10/members/$ref",
		`ADD-MSOLROLEMEMBER -RoleName "Company Administrator"`,
		"62e90394-69f5-4237-9190-012177145e10 given by role assignment", "Global Administrator role assignment",
		"New-MgRoleManagementDirectoryRoleAssignment -RoleDefinitionId 62e90394-69f5-4237-9190-012177145e10",
		"-Uri $g/roleManagement/directory/roleAssignments -Method Post", "$g/servicePrincipals/1/appRoleAssignments -Body $b",
		"NEW-AZROLEASSIGNMENT -ObjectId $id", "AZ ROLE ASSIGNMENT CREATE --role Owner",
		"curl --data @b https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments",
		"POST /v1.0/servicePrincipals/1/appRoleAssignedTo", "New-MgOauth2PermissionGrant", "az ad app permission grant",
		"servicePrincipals/1/addKey", "New-AzADSpCredential", "az ad sp credential reset",
		"https://LOGIN.MICROSOFTONLINE.COM/t/oauth2/token", "az login -u a --service-principal",
		"Connect-AzAccount -ServicePrincipal", "ClientSecretCredential(t, c, s)",
		"Get-AzureADUser", "az ad user list", "GRAPH/users", "GRAPH/groups", "x/roleManagement",
		"Get-MgUserMailFolderMessage", "outlook.office.com/api/v2.0/me", "Search-Mailbox", "/me/mailFolders", "/users/1/messages",
		"TEAMSMESSAGESDATA", "chats/getAllMessages", "Get-MgChatMessage", "/chats/19:x/messages",
		"corp.sharepoint.com/_api/web", "Get-MgDriveItem", "Get-PnPListItem", "/sites", "/drive",
		"x.vault.azure.net/secrets", "az keyvault secret download", "Backup-AzKeyVaultSecret", "list_properties_of_secrets(", "/secrets?api-version=7.4",
		"/keys/k/v/decrypt", "az keyvault key decrypt", "Invoke-AzKeyVaultKeyOperation -Operation Decrypt", "c.unwrap_key(",
		"x.vault.usgovcloudapi.net/keys", "az keyvault key show", "Get-AzKeyVaultKey", "list_properties_of_keys(", "/keys?api-version=7.4",
		"management.azure.com/subscriptions", "az storage account list", "az graph query", "Get-AzResourceGroup", "/subscriptions?api-version=1",
	}
	check := func(owner string, p pattern) {
		if len(p.literals) == 0 {
			t.Errorf("%s: %s has no literal, so it is tried on every line", owner, p.rx)
		}
		for _, line := range corpus {
			if !p.rx.MatchString(line) {
				continue
			}
			held := false
			for _, lit := range p.literals {
				held = held || strings.Contains(strings.ToLower(line), string(lit))
			}
			if !held {
				t.Errorf("%s: %s matches %q, which holds none of %q", owner, p.rx, line, p.literals)
			}
		}
	}
	matched := 0
	for name, p := range table.contexts {
		check("context "+name, p)
	}
	for _, a := range table.activities {
		for _, p := range append(a.patterns[:len(a.patterns):len(a.patterns)], a.paths...) {
			check(a.name, p)
			for _, line := range corpus {
				if p.rx.MatchString(line) {
					matched++
					break
				}
			}
		}
	}
	if total := countPatterns(table); matched != total {
		t.Errorf("the corpus exercises %d of %d patterns", matched, total)
	}
}

func countPatterns(t Table) int {
	n := 0
	for _, a := range t.activities {
		n += len(a.patterns) + len(a.paths)
	}
	return n
}

func TestRequired(t *testing.T) {
	tests := []struct {
		expr string
		want []string
	}{
		{`(?i)TeamsMessagesData`, []string{"teamsmessagesdata"}},
		{`(?i)\baz\s+keyvault\s+secret\s+(?:list|show)\b`, []string{"keyvault"}},
		{`(?i)\.get_secret\(|\blist_properties_of_secrets\(`, []string{".get_secret(", "list_properties_of_secrets("}},
		{`/(?:users|groups)\b`, []string{"users", "groups"}},
		{`(?:abc){2,}x`, []string{"abc"}},
		{`(?:abc)+`, []string{"abc"}},
		{`(abcd)`, []string{"abcd"}},
		{`(?:abc)*x`, nil},
		{`(?:abc){0,2}`, nil},
		{`abc|[0-9]+`, nil},
		{`ab|cd`, nil},
		{`\d+\.\d+`, nil},
		{`(?i)sécrets`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			p, err := compile(tt.expr)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, lit := range p.literals {
				got = append(got, string(lit))
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("literals of %s = %q, want %q", tt.expr, got, tt.want)
			}
		})
	}
}

func TestDetectWithoutLiterals(t *testing.T) {
	table, err := decode([]byte(`{"contexts":{"numbered":"^[0-9]+ "},"activities":[
		{"name":"Versioned","tactics":["T"],"patterns":["\\d+\\.\\d+\\.\\d+"],"unless":"skip"},
		{"name":"Dated","tactics":["T"],"context":"numbered","paths":["\\d{4}-\\d{2}"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	hits := table.Detect("1 release 1.2.3\n\nskip 4.5.6\n7.8.9 and 2026-10\nplain\n")
	if len(hits) != 2 || hits[0].Name != "Versioned" || hits[0].Lines != 2 || hits[1].Name != "Dated" || hits[1].Lines != 1 {
		t.Errorf("hits = %+v, want Versioned on 2 lines and Dated on 1", hits)
	}
	if hits := table.Detect("release 1.2.3 on 2026-10\n"); len(hits) != 1 {
		t.Errorf("hits = %+v, want Versioned alone outside the context", hits)
	}
}
