package activity

import (
	"slices"
	"testing"
)

// discoveryCases are commands that learn of a system, its network and its
// cloud, and commands that do not. They also feed the corpus of the literals.
//
//nolint:gochecknoglobals // a table shared by two tests
var discoveryCases = []struct {
	line string
	want []string
}{
	// T1007: the services of a system
	{`tasklist /svc`, []string{"ServiceDiscovery"}},
	{`net start`, []string{"ServiceDiscovery"}},
	{`launchctl list`, []string{"ServiceDiscovery"}},
	{`ls -la /etc/init.d`, []string{"ServiceDiscovery", "SecuritySoftwareDiscovery"}},
	{`cat /etc/init.d/ssh`, []string{"ServiceDiscovery", "SecuritySoftwareDiscovery"}},
	{`update-rc.d ssh defaults # links /etc/init.d/ssh`, nil},
	{`ps aux | grep com.apple.`, []string{"ServiceDiscovery", "SecuritySoftwareDiscovery", "BackupSoftwareDiscovery"}},
	{`net start Spooler`, nil},
	{`tasklist /fi "imagename eq x.exe"`, nil},
	{`launchctl load -w ~/Library/LaunchAgents/x.plist`, nil},

	// T1135: the shares macOS lists
	{`smbutil view //fs01`, []string{"NetworkShareDiscovery"}},
	{`sharing -l`, []string{"NetworkShareDiscovery"}},

	// T1010: the windows that are open
	{`xdotool search --onlyvisible --name Firefox`, []string{"ApplicationWindowDiscovery"}},
	{`wmctrl -l`, []string{"ApplicationWindowDiscovery"}},
	{`wmctrl -lp`, []string{"ApplicationWindowDiscovery"}},
	{`[Win32]::GetForegroundWindow()`, []string{"ApplicationWindowDiscovery"}},
	{`CGWindowListCopyWindowInfo(kCGWindowListOptionOnScreenOnly, kCGNullWindowID)`, []string{"ApplicationWindowDiscovery"}},
	{`Get-Process | Where-Object { $_.MainWindowTitle } | Select-Object MainWindowTitle`, []string{"ApplicationWindowDiscovery"}},
	{`osascript -e 'tell application "System Events" to get name of every window of every process'`, []string{"ApplicationWindowDiscovery"}},
	{`wmctrl -a Firefox`, nil},
	{`xdotool key ctrl+c`, nil},
	{`osascript -e 'tell application "Terminal" to close first window'`, nil},

	// T1016: how the network is set
	{`netsh interface show interface`, []string{"NetworkConfigurationDiscovery"}},
	{`netsh int ip show config`, []string{"NetworkConfigurationDiscovery"}},
	{`networksetup -listallhardwareports`, []string{"NetworkConfigurationDiscovery"}},
	{`system_profiler SPNetworkDataType`, []string{"NetworkConfigurationDiscovery"}},
	{`esxcli network nic list`, []string{"NetworkConfigurationDiscovery"}},
	{`esxcli network ip interface ipv4 get`, []string{"NetworkConfigurationDiscovery"}},
	{`ssh admin@10.0.0.1 "show ip interface brief"`, []string{"NetworkConfigurationDiscovery"}},
	{`show ip route`, []string{"NetworkConfigurationDiscovery"}},
	{`cat /proc/net/route`, []string{"NetworkConfigurationDiscovery"}},
	{`Get-WmiObject Win32_NetworkAdapterConfiguration | Where IPEnabled`, []string{"NetworkConfigurationDiscovery"}},
	{`wmic nicconfig get ipaddress,macaddress`, []string{"NetworkConfigurationDiscovery"}},
	{`netsh interface portproxy add v4tov4 listenport=8080 connectaddress=10.0.0.5`, nil},
	{`networksetup -setdnsservers Wi-Fi 10.0.0.1`, nil},
	{`ip route show`, nil},
	{`  -r, --route    show route table`, nil},

	// T1016.001: whether the Internet is reached
	{`ping -c 1 8.8.8.8`, []string{"InternetConnectionDiscovery"}},
	{`tracert google.com`, []string{"InternetConnectionDiscovery"}},
	{`Test-NetConnection www.microsoft.com`, []string{"InternetConnectionDiscovery"}},
	{`vmkping 1.1.1.1`, []string{"InternetConnectionDiscovery"}},
	{`curl -s http://connectivitycheck.gstatic.com/generate_204`, []string{"InternetConnectionDiscovery"}},
	{`curl -sI https://www.google.com > /dev/null`, []string{"InternetConnectionDiscovery"}},
	{`wget -q --spider http://google.com`, []string{"InternetConnectionDiscovery"}},
	{`ping -c 1 10.20.1.5`, nil},
	{`ping -c 1 8.8.8.80`, nil},
	{`curl https://www.google.com/search?q=x`, nil},
	{`curl -s https://storage.example.net/a.bin`, nil},

	// T1016.002: the wireless networks a host knows
	{`netsh wlan show profiles`, []string{"WifiDiscovery"}},
	{`netsh wlan show profile name="corp" key=clear`, []string{"WifiDiscovery"}},
	{`sudo cat /etc/NetworkManager/system-connections/corp.nmconnection`, []string{"WifiDiscovery"}},
	{`security find-generic-password -D "AirPort network password" -ga corp`, []string{"WifiDiscovery"}},
	{`[DllImport("wlanapi.dll")] static extern uint WlanEnumInterfaces(IntPtr h, IntPtr r, out IntPtr l);`, []string{"NativeApiCall", "WifiDiscovery"}},
	{`netsh wlan connect name=corp`, []string{"WifiDiscovery"}},
	{`NetworkManager[650]: <info> keyfile: load: "/etc/NetworkManager/system-connections/corp.nmconnection"`, nil},
	{`security find-generic-password -s github`, nil},

	// T1018: the other systems of a network
	{`net view`, []string{"NetworkShareDiscovery", "RemoteSystemDiscovery"}},
	{`net view /all /domain:corp`, []string{"NetworkShareDiscovery", "RemoteSystemDiscovery"}},
	{`nltest /dclist:corp.local`, []string{"RemoteSystemDiscovery"}},
	{`dsquery computer -limit 0`, []string{"RemoteSystemDiscovery"}},
	{`esxcli network diag ping -H 10.20.1.5`, []string{"RemoteSystemDiscovery"}},
	{`send "show cdp neighbors detail\r"`, []string{"RemoteSystemDiscovery"}}, //nolint:misspell // the device spells its command so
	{`show ip arp`, []string{"NetworkConfigurationDiscovery", "RemoteSystemDiscovery"}},
	{`cat /etc/hosts`, []string{"RemoteSystemDiscovery"}},
	{`for i in $(seq 1 254); do ping -c1 -W1 10.20.1.$i; done`, []string{"RemoteSystemDiscovery"}},
	{`for /L %i in (1,1,254) do ping -n 1 10.20.1.%i`, []string{"RemoteSystemDiscovery", "TimeBasedCheck"}},
	{`net view \\fs01`, []string{"NetworkShareDiscovery"}},
	{`cat /etc/hosts.allow`, nil},
	{`echo "10.0.0.5 dc01" >> /etc/hosts`, nil},
	{`For more information on name resolution see /etc/hosts`, nil},
	{`for now we do not ping the hosts`, nil},
	{`nltest /sc_query:corp`, nil},

	// T1033: who is signed in
	{`query user`, []string{"LoggedOnUserDiscovery"}},
	{`query session /server:fs01`, []string{"LoggedOnUserDiscovery"}},
	{`net_connect.send_command("show users")`, []string{"LoggedOnUserDiscovery"}},
	{`Get-WmiObject Win32_LoggedOnUser`, []string{"LoggedOnUserDiscovery"}},
	{`(Get-WmiObject Win32_ComputerSystem).UserName`, []string{"LoggedOnUserDiscovery"}},
	{`[System.Security.Principal.WindowsIdentity]::GetCurrent().Name`, []string{"LoggedOnUserDiscovery"}},
	{`echo $USER`, []string{"LoggedOnUserDiscovery"}},
	{`echo %USERNAME%`, []string{"LoggedOnUserDiscovery"}},
	{`echo "$USERS_FILE"`, nil},
	{`query termserver`, nil},
	{`The query user command displays information about user sessions on a server.`, nil},

	// T1040: traffic that is captured
	{`aws ec2 create-traffic-mirror-session --network-interface-id eni-1 --traffic-mirror-target-id tmt-1 --traffic-mirror-filter-id tmf-1 --session-number 1`, []string{"NetworkSniffing"}},
	{`az network vnet tap create -g rg -n tap1 --destination nic1`, []string{"NetworkSniffing"}},
	{`monitor capture CAP interface Gi0/1 both`, []string{"NetworkSniffing"}},
	{`netsh trace start capture=yes tracefile=c:\t.etl`, []string{"NetworkSniffing"}},
	{`pktmon start --etw`, []string{"NetworkSniffing"}},
	{`ip link set eth0 promisc on`, []string{"NetworkSniffing"}},
	{`aws ec2 describe-traffic-mirror-sessions`, []string{"NetworkSniffing", "CloudServiceDiscovery", "CloudInfrastructureDiscovery"}},
	{`pcap_t *h = pcap_open_live("eth0", 65535, 1, 1000, errbuf);`, []string{"NetworkSniffing"}},
	{`{"eventSource": "ec2.amazonaws.com", "eventName": "CreateTrafficMirrorSession"}`, []string{"NetworkSniffing"}},
	{`netsh trace stop`, nil},

	// T1046: the services of other hosts
	{`dns-sd -B _services._dns-sd._udp`, []string{"NetworkServiceDiscovery"}},
	{`nc -zv 10.0.0.5 22`, []string{"NetworkServiceDiscovery"}},
	{`nc -w1 -z 10.0.0.5 445`, []string{"NetworkServiceDiscovery"}},
	{`ncat -v -z 10.0.0.5 1-1024`, []string{"NetworkServiceDiscovery"}},
	{`Test-NetConnection -ComputerName 10.20.1.5 -Port 445`, []string{"NetworkServiceDiscovery"}},
	{`Test-NetConnection google.com -Port 443`, []string{"InternetConnectionDiscovery"}},
	{`nc -lvnp 4444`, nil},
	{`rsync -az src dst`, nil},
	{`dns-sd -R web _http._tcp local 80`, nil},

	// T1049: the connections of a system
	{`lsof -i`, []string{"NetworkConnectionDiscovery"}},
	{`lsof -nP -iTCP -sTCP:LISTEN`, []string{"NetworkConnectionDiscovery"}},
	{`esxcli network ip connection list`, []string{"NetworkConnectionDiscovery"}},
	{`"show ip sockets"`, []string{"NetworkConnectionDiscovery"}},
	{`aws ec2 describe-network-interfaces --region us-east-1`, []string{"NetworkConnectionDiscovery", "CloudServiceDiscovery"}},
	{`az network vnet subnet list -g rg --vnet-name v`, []string{"NetworkConnectionDiscovery"}},
	{`gcloud compute networks subnets list`, []string{"NetworkConnectionDiscovery"}},
	{`net session`, []string{"NetworkConnectionDiscovery"}},
	{`net use`, []string{"NetworkConnectionDiscovery"}},
	{`lsof -p 1234`, nil},
	{`net session \\10.0.0.5 /delete`, nil},
	{`az network vnet create -g rg -n v`, nil},

	// T1057: the processes that run
	{`esxcli system process list`, []string{"ProcessDiscovery"}},
	{`"show processes cpu"`, []string{"ProcessDiscovery"}},
	{`wmic process get name,processid,commandline`, []string{"ProcessDiscovery"}},
	{`CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)`, []string{"ProcessDiscovery"}},
	{`query process *`, []string{"ProcessDiscovery"}},
	{`Get-CimInstance Win32_Process | Select Name,CommandLine`, []string{"ProcessDiscovery"}},
	{`SHOW PROCESSLIST;`, nil},
	{`wmic process where name="x.exe" delete`, nil},

	// T1069.001: the groups of a system
	{`net localgroup administrators`, []string{"LocalGroupEnumeration"}},
	{`getent group sudo`, []string{"GroupEnumeration", "LocalGroupEnumeration"}},
	{`cat /etc/group`, []string{"LocalGroupEnumeration"}},
	{`dscl . -list /Groups`, []string{"LocalGroupEnumeration", "DomainGroupEnumeration"}},
	{`Get-WmiObject Win32_GroupUser`, []string{"LocalGroupEnumeration"}},
	{`wmic group get name,sid`, []string{"LocalGroupEnumeration"}},
	{`net localgroup administrators svc /add`, nil},
	{`NET LOCALGROUP [groupname [/COMMENT:"text"]] [/DOMAIN]`, nil},
	{`echo "svc:x:1001:" >> /etc/group`, nil},

	// T1069.002: the groups of a domain
	{`net group "Domain Admins" /domain`, []string{"GroupEnumeration", "DomainGroupEnumeration"}},
	{`net group`, []string{"GroupEnumeration", "DomainGroupEnumeration"}},
	{`ldapsearch -x -H ldap://10.20.1.5 -b "dc=corp,dc=example" "(objectClass=group)"`, []string{"DomainGroupEnumeration"}},
	{`dscacheutil -q group`, []string{"DomainGroupEnumeration"}},
	{`dscl "/Active Directory/CORP/All Domains" -list /Groups`, []string{"DomainGroupEnumeration"}},
	{`dsquery group -name "Domain*"`, []string{"DomainGroupEnumeration"}},
	{`wbinfo -g`, []string{"DomainGroupEnumeration"}},
	{`Get-DomainGroupMember -Identity "Domain Admins"`, []string{"DomainGroupEnumeration"}},
	{`net group "Domain Admins" svc /add /domain`, nil},
	{`NET GROUP [groupname [/COMMENT:"text"]] [/DOMAIN]`, nil},
	{`wbinfo -t`, nil},

	// T1069.003: the groups and roles of a cloud
	{`aws iam list-groups`, []string{"CloudGroupEnumeration"}},
	{`aws iam list-groups-for-user --user-name svc`, []string{"CloudGroupEnumeration"}},
	{`az role assignment list --all`, []string{"CloudGroupEnumeration"}},
	{`gcloud projects get-iam-policy corp-prod`, []string{"CloudGroupEnumeration"}},
	{`gcloud iam roles list`, []string{"CloudGroupEnumeration"}},
	{`aws iam create-group --group-name g`, nil},
	{`gcloud projects add-iam-policy-binding corp-prod --member user:a --role roles/owner`, nil},

	// T1082: what a system is
	{`cat /etc/os-release`, []string{"SystemInformationDiscovery"}},
	{`sysctl -a`, []string{"SystemInformationDiscovery"}},
	{`esxcli system version get`, []string{"SystemInformationDiscovery"}},
	{`esxcli hardware cpu list`, []string{"SystemInformationDiscovery"}},
	{`ssh admin@10.0.0.1 "show version"`, []string{"SystemInformationDiscovery"}},
	{`Get-WmiObject Win32_OperatingSystem | Select Caption,Version`, []string{"SystemInformationDiscovery"}},
	{`wmic os get caption,version`, []string{"SystemInformationDiscovery"}},
	{`reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName`, []string{"RegistryQuery", "SystemInformationDiscovery", "BackupSoftwareDiscovery"}},
	{`[Environment]::OSVersion`, []string{"SystemInformationDiscovery"}},
	{`  -V, --version   show version and exit`, nil},
	{`edge-rtr-01#show version`, []string{"SystemInformationDiscovery"}},
	{`# show version of the tool`, nil},
	{`sysctl -w net.ipv4.ip_forward=1`, nil},
	{`reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell /d x`, nil},

	// T1083: the files of a hypervisor and of a network device
	{`esxcli storage filesystem list`, []string{"FileAndDirectoryDiscovery", "LocalStorageDiscovery"}},
	{`"show flash"`, []string{"FileAndDirectoryDiscovery"}},
	{`dir nvram:`, []string{"FileAndDirectoryDiscovery"}},
	{`more nvram:startup-config`, []string{"FileAndDirectoryDiscovery"}},
	{`dir C:\Users`, nil},

	// T1087.001: the accounts of a system
	{`net user`, []string{"LoggedOnUserDiscovery", "LocalAccountEnumeration"}},
	{`net user administrator`, []string{"LoggedOnUserDiscovery", "LocalAccountEnumeration"}},
	{`cut -d: -f1 /etc/passwd`, []string{"LoggedOnUserDiscovery", "AccountEnumeration", "LocalAccountEnumeration"}},
	{`if [ -r /etc/passwd ]; then cat /etc/passwd; fi`, []string{"LoggedOnUserDiscovery", "AccountEnumeration", "LocalAccountEnumeration"}},
	{`getent passwd`, []string{"LocalAccountEnumeration"}},
	{`dscl . -list /Users`, []string{"LoggedOnUserDiscovery", "LocalAccountEnumeration"}},
	{`esxcli system account list`, []string{"AccountEnumeration", "LocalAccountEnumeration"}},
	{`Get-WmiObject Win32_UserAccount`, []string{"LocalAccountEnumeration"}},
	{`wmic useraccount get name,sid`, []string{"LocalAccountEnumeration"}},
	{`net user svc P@ssw0rd!`, nil},
	{`net user svc /active:no`, nil},
	{`echo "svc:x:0:0::/root:/bin/bash" >> /etc/passwd`, nil},

	// T1087.002: the accounts of a domain
	{`net user /domain`, []string{"DomainAccountEnumeration"}},
	{`net user administrator /domain`, []string{"DomainAccountEnumeration"}},
	{`wbinfo -u`, []string{"DomainAccountEnumeration"}},
	{`dscacheutil -q user`, []string{"DomainAccountEnumeration"}},
	{`dscl "/Active Directory/CORP/All Domains" -list /Users`, []string{"DomainAccountEnumeration"}},
	{`dsquery user -limit 0`, []string{"DomainAccountEnumeration"}},
	{`Get-DomainUser -SPN`, []string{"DomainAccountEnumeration"}},
	{`ldapsearch -x -H ldap://10.20.1.5 -b "dc=corp,dc=example" "(objectClass=user)" sAMAccountName`, []string{"DomainAccountEnumeration"}},
	{`net user svc "$P" /add /domain`, []string{"AccountCreation"}},

	// T1087.004: the accounts of a cloud
	{`aws iam list-users`, []string{"CloudAccountEnumeration"}},
	{`aws --profile prod iam list-roles`, []string{"CloudAccountEnumeration"}},
	{`gcloud iam service-accounts list`, []string{"CloudAccountEnumeration"}},
	{`curl -H "Authorization: Bearer $T" https://api.slack.com/scim/v1/Users`, []string{"CloudAccountEnumeration"}},
	{`curl -H "Authorization: SSWS $T" https://corp.okta.com/api/v1/users`, []string{"AccountEnumeration", "CloudAccountEnumeration", "CloudServiceDiscovery"}},
	{`curl -H "Authorization: Bearer $T" "https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer"`, []string{"EmailAccountEnumeration", "CloudAccountEnumeration"}},
	{`aws iam create-user --user-name svc`, nil},

	// T1087.003: the addresses of a mail system
	{`$gal = $outlook.Session.GetGlobalAddressList().AddressEntries`, []string{"EmailAccountEnumeration"}},

	// T1120: the devices that are attached
	{`udevadm monitor --udev`, []string{"PeripheralDeviceDiscovery"}},
	{`lshw -class usb`, []string{"PeripheralDeviceDiscovery"}},
	{`system_profiler SPUSBDataType`, []string{"PeripheralDeviceDiscovery"}},
	{`Get-WmiObject Win32_PnPEntity`, []string{"PeripheralDeviceDiscovery"}},
	{`Get-PnpDevice -PresentOnly`, []string{"PeripheralDeviceDiscovery"}},
	{`cat /sys/bus/usb/devices/*/product`, []string{"PeripheralDeviceDiscovery"}},
	{`udevadm control --reload`, nil},

	// T1124: the time of a system
	{`net time \\dc01`, []string{"SystemTimeDiscovery"}},
	{`w32tm /tz`, []string{"SystemTimeDiscovery"}},
	{`cat /etc/timezone`, []string{"SystemTimeDiscovery", "SystemLocationDiscovery"}},
	{`systemsetup -gettimezone`, []string{"SystemTimeDiscovery", "SystemLocationDiscovery", "SystemLanguageDiscovery"}},
	{`esxcli system clock get`, []string{"SystemTimeDiscovery"}},
	{`"show clock detail"`, []string{"SystemTimeDiscovery"}},
	{`net time \\dc01 /set /y`, nil},
	{`the net time saved was 5 hours`, nil},
	{`w32tm /resync`, nil},
	{`systemsetup -settimezone UTC`, nil},

	// T1201: the password policy
	{`net accounts`, []string{"PasswordPolicyDiscovery"}},
	{`net accounts /domain`, []string{"PasswordPolicyDiscovery"}},
	{`secedit /export /cfg c:\p.inf`, []string{"PasswordPolicyDiscovery"}},
	{`chage -l root`, []string{"PasswordPolicyDiscovery"}},
	{`grep -v "^#" /etc/login.defs`, []string{"PasswordPolicyDiscovery"}},
	{`cat /etc/pam.d/common-password`, []string{"PasswordPolicyDiscovery"}},
	{`pwpolicy -getaccountpolicies`, []string{"PasswordPolicyDiscovery"}},
	{`aws iam get-account-password-policy`, []string{"PasswordPolicyDiscovery"}},
	{`policy = iam.get_account_password_policy()`, []string{"PasswordPolicyDiscovery"}},
	{`Invoke-RestMethod -Headers $h -Uri "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy"`, []string{"PasswordPolicyDiscovery", "CloudServiceDiscovery"}},
	{`"show aaa servers"`, []string{"PasswordPolicyDiscovery"}},
	{`net accounts /minpwlen:0`, nil},
	{`NET ACCOUNTS [/FORCELOGOFF:{minutes | NO}] [/MINPWLEN:length]`, nil},
	{`net accounts receivable were 12`, nil},
	{`chage -M 99999 svc`, nil},
	{`aws iam update-account-password-policy --minimum-password-length 6`, nil},

	// T1217: what a browser keeps
	{`cat ~/.config/google-chrome/Default/Bookmarks`, []string{"BrowserInformationDiscovery"}},
	{`sqlite3 "$HOME/Library/Application Support/Google/Chrome/Default/History" "select url from urls"`, []string{"BrowserInformationDiscovery"}},
	{`Get-Content "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Bookmarks"`, []string{"BrowserInformationDiscovery"}},
	{`sqlite3 ~/.mozilla/firefox/abc.default/places.sqlite "select url from moz_places"`, []string{"BrowserInformationDiscovery"}},
	{`plutil -p ~/Library/Safari/Bookmarks.plist`, []string{"BrowserInformationDiscovery"}},
	{`apt-get install -y google-chrome-stable`, nil},

	// T1482: the trusts of a domain
	{`nltest /domain_trusts /all_trusts`, []string{"DomainTrustDiscovery"}},
	{`[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().GetAllTrustRelationships()`, []string{"DomainTrustDiscovery"}},
	{`Get-DomainTrust -API`, []string{"DomainTrustDiscovery"}},
	{`ldapsearch -x -b "cn=system,dc=corp,dc=example" "(objectClass=trustedDomain)"`, []string{"DomainTrustDiscovery"}},

	// T1497.001: whether a system is a virtual machine
	{`cat /sys/class/dmi/id/product_name`, []string{"VirtualMachineCheck"}},
	{`systemd-detect-virt`, []string{"VirtualMachineCheck"}},
	{`dmesg | grep -i hypervisor`, []string{"VirtualMachineCheck"}},
	{`lspci | grep -i vmware`, []string{"VirtualMachineCheck"}},
	{`grep -c hypervisor /proc/cpuinfo`, []string{"VirtualMachineCheck"}},
	{`system_profiler SPHardwareDataType`, []string{"VirtualMachineCheck"}},
	{`ioreg -l`, []string{"VirtualMachineCheck"}},
	{`ioreg -l | grep -i -c "VirtualBox\|VMware"`, []string{"VirtualMachineCheck"}},
	{`systeminfo | findstr /i "vmware virtualbox"`, []string{"VirtualMachineCheck"}},
	{`dmesg | tail -20`, nil},
	{`ii  virt-what  1.19-1  amd64  detect if we are running in a virtual machine`, nil},
	{`ioreg -p IOUSB`, nil},
	{`dmidecode -t memory`, nil},

	// T1497.002: whether a person is at the system
	{`xdotool getmouselocation`, []string{"UserActivityCheck"}},
	{`xinput list`, []string{"UserActivityCheck"}},
	{`CGEventSourceSecondsSinceLastEventType(kCGEventSourceStateHIDSystemState, kCGAnyInputEventType)`, []string{"UserActivityCheck"}},
	{`xdotool mousemove 10 10`, nil},

	// T1497.003: a wait that a function makes
	{`[System.Threading.Thread]::Sleep(600000)`, []string{"TimeBasedCheck"}},
	{`WaitForSingleObject(h, 300000);`, []string{"TimeBasedCheck"}},
	{`usleep(5000000);`, []string{"TimeBasedCheck"}},
	{`[NSTimer scheduledTimerWithTimeInterval:600 target:self selector:@selector(run) userInfo:nil repeats:NO];`, []string{"TimeBasedCheck"}},
	{`time.sleep(5)`, nil},
	{`sleep 5`, nil},

	// T1518: the software that is installed
	{`dpkg -l | grep -i ssh`, []string{"SoftwareDiscovery"}},
	{`rpm -qa`, []string{"SoftwareDiscovery"}},
	{`apt list --installed`, []string{"SoftwareDiscovery"}},
	{`system_profiler SPApplicationsDataType`, []string{"ProcessDiscovery", "SoftwareDiscovery"}},
	{`esxcli software vib list`, []string{"SoftwareDiscovery"}},
	{`aws ssm list-inventory --instance-id i-0a1b`, []string{"SoftwareDiscovery"}},
	{`{"eventSource": "ssm.amazonaws.com", "eventName": "ListInventory"}`, []string{"SoftwareDiscovery"}},
	{`az graph query -q "Resources | where type =~ \'microsoft.compute/virtualmachines/extensions\'"`, []string{"AzureResourceEnumeration", "SystemInformationDiscovery", "SoftwareDiscovery"}},
	{`Get-WmiObject -Class Win32_Product`, []string{"SoftwareDiscovery"}},
	{`wmic product get name,version`, []string{"SoftwareDiscovery"}},
	{`reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall /s`, []string{"RegistryQuery", "SoftwareDiscovery"}},
	{`dpkg -i tool.deb`, nil},
	{`rpm -ivh tool.rpm`, nil},

	// T1518.001: the security software
	{`Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct`, []string{"SecuritySoftwareDiscovery"}},
	{`wmic /namespace:\\root\securitycenter2 path antivirusproduct get displayname`, []string{"SecuritySoftwareDiscovery"}},
	{`Get-MpComputerStatus`, []string{"SecuritySoftwareDiscovery"}},
	{`netsh advfirewall show allprofiles`, []string{"SecuritySoftwareDiscovery"}},
	{`tasklist | findstr /i "MsMpEng"`, []string{"SecuritySoftwareDiscovery"}},
	{`ps aux | grep -i falcon`, []string{"SecuritySoftwareDiscovery", "BackupSoftwareDiscovery"}},
	{`sc query windefend`, []string{"ServiceDiscovery", "SecuritySoftwareDiscovery", "BackupSoftwareDiscovery"}},
	{`ls "/Applications/Little Snitch.app"`, []string{"SecuritySoftwareDiscovery"}},
	{`netsh advfirewall set allprofiles state off`, []string{"FirewallDisabling"}},
	{`sc stop windefend`, nil},
	{`The Service Control Manager reports that the Microsoft Defender Antivirus Service is running.`, nil},
	{`PS C:\> cd "C:\Program Files\Windows Defender"`, nil},
	{`Find the Defender settings under Windows Security.`, nil},
	{`ii  clamav  0.103.9  amd64  anti-virus utility for Unix - command-line interface`, nil},
	{`Set-MpPreference -DisableRealtimeMonitoring $true`, nil},

	// T1518.002: the backup software
	{`tasklist | findstr /i veeam`, []string{"BackupSoftwareDiscovery"}},
	{`sc query VeeamBackupSvc`, []string{"ServiceDiscovery", "SecuritySoftwareDiscovery", "BackupSoftwareDiscovery"}},
	{`reg query "HKLM\SOFTWARE\Veeam\Veeam Backup and Replication"`, []string{"RegistryQuery", "BackupSoftwareDiscovery"}},
	{`find /etc /opt -iname "*rsnapshot*"`, []string{"BackupSoftwareDiscovery"}},
	{`ls "/Applications/Time Machine.app"`, []string{"BackupSoftwareDiscovery"}},
	{`net stop veeam`, nil},

	// T1526: the services of a cloud
	{`gcloud projects list`, []string{"CloudServiceDiscovery"}},
	{`aws cloudformation describe-stacks`, []string{"CloudServiceDiscovery"}},
	{`aws --region eu-west-1 eks describe-cluster --name c`, []string{"CloudServiceDiscovery"}},
	{`az provider list --query "[].namespace"`, []string{"CloudServiceDiscovery"}},
	{`curl -H "Authorization: SSWS $T" https://corp.okta.com/api/v1/apps`, []string{"CloudServiceDiscovery"}},
	{`Get-MgSubscribedSku`, []string{"CloudServiceDiscovery"}},
	{`curl -H "Authorization: Bearer $T" "https://management.azure.com/providers?api-version=2021-04-01"`, []string{"CloudServiceDiscovery"}},
	{`curl -X PUT -H "Authorization: Bearer $T" https://management.azure.com/providers/Microsoft.Compute/register`, nil},
	{`gcloud projects create corp-new`, nil},

	// T1538: the console of a cloud
	{`Start-Process "https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade"`, []string{"CloudServiceDashboard"}},
	{`page.goto("https://console.aws.amazon.com/iam/home#/users")`, []string{"CloudServiceDashboard"}},
	{`open https://corp-admin.okta.com/admin/users`, []string{"CloudServiceDashboard"}},
	{`curl -s https://azure.microsoft.com/en-us/pricing/`, nil},

	// T1580: the infrastructure of a cloud
	{`aws ec2 describe-instances --query "Reservations[].Instances[].InstanceId"`, []string{"SystemInformationDiscovery", "CloudServiceDiscovery", "CloudInfrastructureDiscovery"}},
	{`aws s3api list-buckets`, []string{"CloudInfrastructureDiscovery"}},
	{`aws s3 ls`, []string{"CloudInfrastructureDiscovery"}},
	{`aws s3 ls --profile prod`, []string{"CloudInfrastructureDiscovery"}},
	{`aws rds describe-db-instances`, []string{"CloudServiceDiscovery", "CloudInfrastructureDiscovery"}},
	{`gcloud compute instances list`, []string{"CloudInfrastructureDiscovery"}},
	{`gcloud sql instances list`, []string{"CloudInfrastructureDiscovery"}},
	{`{"eventSource": "ec2.amazonaws.com", "eventName": "DescribeInstances"}`, []string{"SystemInformationDiscovery", "CloudInfrastructureDiscovery"}},
	{`for b in s3.list_buckets()["Buckets"]: print(b["Name"])`, []string{"CloudInfrastructureDiscovery"}},
	{`aws ec2 run-instances --image-id ami-1`, nil},
	{`gcloud compute instances create vm1`, nil},

	// T1613: the containers and what a cluster holds
	{`docker ps -a`, []string{"ContainerResourceDiscovery"}},
	{`docker image ls`, []string{"ContainerResourceDiscovery"}},
	{`kubectl get pods -n kube-system`, []string{"ContainerResourceDiscovery"}},
	{`kubectl -n prod describe deployment web`, []string{"ContainerResourceDiscovery"}},
	{`kubectl cluster-info`, []string{"ContainerResourceDiscovery"}},
	{`crictl ps`, []string{"ContainerResourceDiscovery"}},
	{`curl -sk -H "Authorization: Bearer $T" https://10.0.0.1:6443/api/v1/namespaces/default/pods`, []string{"ContainerResourceDiscovery"}},
	{`kubectl get secrets -n prod`, []string{"ClusterSecretRead"}},
	{`docker exec web ps aux`, []string{"SecuritySoftwareDiscovery", "BackupSoftwareDiscovery"}},
	{`docker images are built by the pipeline`, nil},
	{`kubectl apply -f deploy.yaml`, nil},

	// T1614: where a system is
	{`curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone`, []string{"CloudMetadataAccess", "SystemLocationDiscovery"}},
	{`curl -H Metadata:true "http://169.254.169.254/metadata/instance/compute/location?api-version=2021-02-01&format=text"`, []string{"CloudMetadataAccess", "SystemLocationDiscovery"}},
	{`GetLocaleInfoW(LOCALE_USER_DEFAULT, LOCALE_SISO3166CTRYNAME, buf, 9)`, []string{"SystemLocationDiscovery"}},

	// T1614.001: the language of a system
	{`echo $LANG`, []string{"SystemLanguageDiscovery"}},
	{`defaults read -g AppleLocale`, []string{"SystemLocationDiscovery", "SystemLanguageDiscovery"}},
	{`GetUserDefaultUILanguage()`, []string{"SystemLanguageDiscovery"}},
	{`reg query HKLM\SYSTEM\CurrentControlSet\Control\Nls\Language /v InstallLanguage`, []string{"RegistryQuery", "BackupSoftwareDiscovery", "SystemLanguageDiscovery"}},
	{`export LANG=C`, nil},
	{`defaults write -g AppleLocale en_US`, nil},

	// T1619: what a storage of a cloud holds
	{`aws s3 ls s3://corp-backups/ --recursive`, []string{"CloudStorageObjectDiscovery"}},
	{`aws s3api list-objects-v2 --bucket corp-backups`, []string{"CloudStorageObjectDiscovery"}},
	{`az storage blob list --account-name corp --container-name backups`, []string{"CloudStorageObjectDiscovery"}},
	{`gcloud storage ls gs://corp-backups`, []string{"CloudStorageObjectDiscovery"}},
	{`gsutil ls -r gs://corp-backups`, []string{"CloudStorageObjectDiscovery"}},
	{`curl "https://corp.blob.core.windows.net/backups?restype=container&comp=list"`, []string{"CloudStorageObjectDiscovery"}},
	{`curl "https://corp-backups.s3.amazonaws.com/?list-type=2"`, []string{"CloudStorageObjectDiscovery"}},
	{`{"eventSource": "s3.amazonaws.com", "eventName": "ListObjectsV2"}`, []string{"CloudStorageObjectDiscovery"}},
	{`aws s3 cp s3://corp-backups/db.sql .`, nil},
	{`gsutil cp a gs://b/a`, nil},

	// T1622: whether a debugger watches
	{`if (IsDebuggerPresent()) { ExitProcess(0); }`, []string{"DebuggerCheck"}},
	{`NtQueryInformationProcess(h, ProcessDebugPort, &port, sizeof(port), NULL);`, []string{"DebuggerCheck"}},
	{`grep TracerPid /proc/self/status`, []string{"DebuggerCheck"}},
	{`ptrace(PT_DENY_ATTACH, 0, 0, 0);`, []string{"DebuggerCheck"}},
	{`NtQueryInformationProcess(h, 7, &port, sizeof(port), NULL);`, []string{"DebuggerCheck"}},
	{`OutputDebugStringW(L"x");`, []string{"DebuggerCheck"}},
	{`if ([System.Diagnostics.Debugger]::IsAttached) { exit }`, []string{"DebuggerCheck"}},
	{`grep Cap /proc/self/status`, nil},
	{`TracerPid:	0`, nil},

	// T1652: the drivers of a system
	{`cat /proc/modules`, []string{"DeviceDriverDiscovery"}},
	{`EnumDeviceDrivers(drivers, sizeof(drivers), &needed)`, []string{"DeviceDriverDiscovery"}},
	{`Get-WmiObject Win32_SystemDriver`, []string{"DeviceDriverDiscovery"}},
	{`ls /System/Library/Extensions`, []string{"DeviceDriverDiscovery"}},

	// T1654: the logs of a system
	{`wevtutil qe Security /c:5`, []string{"LogEnumeration"}},
	{`wevtutil el`, []string{"LogEnumeration"}},
	{`tail /var/log/syslog`, []string{"LogEnumeration"}},
	{`grep -i "failed password" /var/log/auth.log`, []string{"LogEnumeration"}},
	{`cat /var/log/vmkernel.log`, []string{"LogEnumeration"}},
	{`sudo: deploy : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/tail -n 50 /var/log/auth.log`, []string{"LogEnumeration"}},
	{`E: Sub-process returned an error code. For more information see /var/log/dpkg.log`, nil},
	{`log show --last 1h --predicate \'eventMessage contains "ssh"\'`, []string{"LogEnumeration"}},
	{`C:\WindowsAzure\GuestAgent\CollectGuestLogs.exe -Mode:full`, []string{"LogEnumeration"}},
	{`aws logs get-log-events --log-group-name g --log-stream-name s`, []string{"LogEnumeration"}},
	{`aws cloudtrail lookup-events --max-results 50`, []string{"LogEnumeration"}},
	{`{"eventSource": "logs.amazonaws.com", "eventName": "GetLogEvents"}`, []string{"LogEnumeration"}},
	{`wevtutil cl Security`, []string{"EventLogClearing"}},
	{`rm -f /var/log/auth.log`, []string{"LogDeletion"}},
	{`cat /dev/null > /var/log/auth.log`, []string{"LogDeletion"}},
	{`git log show`, nil},

	// T1673: the virtual machines of a host
	{`esxcli vm process list`, []string{"VirtualMachineDiscovery"}},
	{`vim-cmd vmsvc/getallvms`, []string{"VirtualMachineDiscovery", "LocalStorageDiscovery"}},
	{`virsh -c qemu:///system list --all`, []string{"VirtualMachineDiscovery"}},
	{`VBoxManage list vms`, []string{"VirtualMachineDiscovery"}},
	{`vmrun list`, []string{"VirtualMachineDiscovery"}},
	{`prlctl list -a`, []string{"VirtualMachineDiscovery"}},
	{`qemu-img info disk.qcow2`, []string{"VirtualMachineDiscovery"}},
	{`esxcli vm process kill --type=force --world-id=1`, nil},
	{`virsh destroy vm1`, nil},
	{`VBoxManage startvm vm1`, nil},

	// T1680: the disks of a system
	{`fdisk -l`, []string{"LocalStorageDiscovery"}},
	{`lshw -class disk`, []string{"LocalStorageDiscovery"}},
	{`parted -l`, []string{"LocalStorageDiscovery"}},
	{`diskutil list`, []string{"LocalStorageDiscovery"}},
	{`system_profiler SPStorageDataType`, []string{"LocalStorageDiscovery"}},
	{`wmic logicaldisk get name,size,freespace`, []string{"LocalStorageDiscovery"}},
	{`Get-WmiObject Win32_LogicalDisk`, []string{"LocalStorageDiscovery"}},
	{`esxcli storage core device list`, []string{"LocalStorageDiscovery"}},
	{`GetLogicalDrives()`, []string{"LocalStorageDiscovery"}},
	{`fdisk /dev/sdb`, nil},
	{`diskutil eraseDisk JHFS+ x /dev/disk2`, nil},

	// AppleScript as a file of it reads: T1010, T1040
	{`set titles to name of every window of process "Safari"`, []string{"ApplicationWindowDiscovery"}},
	{`tell application "System Events" to get name of first application process whose frontmost is true`, []string{"ApplicationWindowDiscovery"}},
	{`the title of the window is shown above`, nil},
	{`do shell script "tcpdump -i en0 -w /tmp/c.pcap" with administrator privileges`, []string{"NetworkSniffing"}},

	// The mirror of a cloud: T1040
	{`New-AzVirtualNetworkTap -Name tap1 -ResourceGroupName rg -DestinationNetworkInterfaceIPConfiguration $ip`, []string{"NetworkSniffing"}},
	{`"type": "Microsoft.Network/virtualNetworkTaps",`, []string{"NetworkSniffing"}},
	{`"eventName": "DescribeTrafficMirrorSessions",`, []string{"NetworkSniffing"}},
	{`gcloud compute packet-mirrorings create m1 --region us-central1 --network default`, []string{"NetworkSniffing"}},

	// A row that gives a command to two techniques
	{`show arp`, []string{"NetworkConfigurationDiscovery", "RemoteSystemDiscovery"}},
	{`cat /etc/passwd`, []string{"LoggedOnUserDiscovery", "AccountEnumeration", "LocalAccountEnumeration"}},
	{`getent group`, []string{"GroupEnumeration", "LocalGroupEnumeration"}},
	{`esxcli storage nmp device list`, []string{"LocalStorageDiscovery"}},
	{`aws ec2 describe-instances --region us-east-1`, []string{"SystemInformationDiscovery", "CloudServiceDiscovery", "CloudInfrastructureDiscovery"}},
	{`sc.exe query windefend`, []string{"ServiceDiscovery", "SecuritySoftwareDiscovery", "BackupSoftwareDiscovery"}},
	{`ps aux`, []string{"SecuritySoftwareDiscovery", "BackupSoftwareDiscovery"}},
	{`ps -e`, []string{"SecuritySoftwareDiscovery"}},
	{`ps -ef | grep -i falcon`, []string{"SecuritySoftwareDiscovery"}},
	{`ps -p 4242 -o comm=`, nil},
	{`reg query HKLM\SOFTWARE\Veeam`, []string{"RegistryQuery", "BackupSoftwareDiscovery"}},

	// The name of who is signed in, read from the environment: T1033
	{`echo "home is /home/$USER"`, []string{"LoggedOnUserDiscovery"}},
	{`me="${LOGNAME}"`, []string{"LoggedOnUserDiscovery"}},
	{`if [ "$USER" != "root" ]; then exit 1; fi`, []string{"LoggedOnUserDiscovery"}},
	{`ls /home/${LOGNAME}/.ssh`, nil},
	{`nxc smb "$h" -u "$USER" -p "$PASS" --shares`, []string{"NetworkShareDiscovery"}},
	{`GetUserNameW(buf, &n);`, []string{"LoggedOnUserDiscovery"}},
	{`WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &info, &count);`, []string{"LoggedOnUserDiscovery"}},
	{`name = account.getUsername()`, nil},
	{`echo $USERNAME_PREFIX`, nil},

	// A scan as a script writes it, as a scanner answers and as a sensor names it: T1046
	{`if s.connect_ex((host, port)) == 0:`, []string{"NetworkServiceDiscovery"}},
	{`1..1024 | % { (New-Object Net.Sockets.TcpClient).Connect("10.0.0.5", $_) }`, []string{"NetworkSocket", "NetworkServiceDiscovery"}},
	{`for port in range(1, 1025):`, []string{"NetworkServiceDiscovery"}},
	{`(echo > /dev/tcp/$host/$port) >/dev/null 2>&1 && echo "$port open"`, []string{"ReverseShell", "NetworkServiceDiscovery"}},
	{`Invoke-Portscan -Hosts 10.0.0.0/24 -TopPorts 50`, []string{"NetworkServiceDiscovery"}},
	{`Nmap scan report for 10.0.0.5`, []string{"NetworkServiceDiscovery"}},
	{`Discovered open port 445/tcp on 10.0.0.5`, []string{"NetworkServiceDiscovery"}},
	{`22/tcp   open  ssh`, []string{"NetworkServiceDiscovery"}},
	{`Connection to 10.0.0.5 22 port [tcp/ssh] succeeded!`, []string{"NetworkServiceDiscovery"}},
	{`[**] [1:2001219:20] ET SCAN Potential SSH Scan [**]`, []string{"NetworkServiceDiscovery"}},
	{`(portscan) TCP Portsweep`, []string{"NetworkServiceDiscovery"}},
	{`# quick port scan of the subnet`, []string{"NetworkServiceDiscovery"}},
	{`export PORT=8080`, nil},
	{`scan the document for errors`, nil},

	// Groups by the functions of Windows, and the groups and roles of a cloud and of a service: T1069
	{`NetLocalGroupEnum(NULL, 1, &buf, MAX_PREFERRED_LENGTH, &read, &total, NULL);`, []string{"LocalGroupEnumeration"}},
	{`NetGroupEnum(server, 2, &buf, MAX_PREFERRED_LENGTH, &read, &total, NULL);`, []string{"DomainGroupEnumeration"}},
	{`"eventName": "ListGroupsForUser",`, []string{"CloudGroupEnumeration"}},
	{`groups = iam.list_groups()["Groups"]`, []string{"CloudGroupEnumeration"}},
	{`"Action": "iam:ListGroups",`, []string{"CloudGroupEnumeration"}},
	{`An error occurred (AccessDenied) when calling the ListGroups operation: User: arn:aws:iam::111122223333:user/dev is not authorized`, []string{"CloudGroupEnumeration"}},
	{`GET https://management.azure.com/subscriptions/0000/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01`, []string{"AzureResourceEnumeration", "CloudGroupEnumeration"}},
	{`"methodName": "google.iam.admin.v1.ListRoles",`, []string{"CloudGroupEnumeration"}},
	{`curl -H "Authorization: SSWS $T" https://acme.okta.com/api/v1/groups`, []string{"CloudGroupEnumeration", "CloudServiceDiscovery"}},
	{`GET https://admin.googleapis.com/admin/directory/v1/groups?customer=my_customer`, []string{"CloudGroupEnumeration"}},
	{`https://admin.googleapis.com/admin/directory/v1/customer/my_customer/roleassignments`, []string{"CloudGroupEnumeration"}},
	{`curl -H "Authorization: Bearer $SLACK" https://slack.com/api/usergroups.list`, []string{"CloudGroupEnumeration", "HostedServiceDiscovery"}},
	{`client.usergroups_users_list(usergroup="S0604QSJC")`, []string{"CloudGroupEnumeration"}},
	{`curl -H "Authorization: Bearer $ZOOM" https://api.zoom.us/v2/roles`, []string{"CloudGroupEnumeration"}},
	{`gh api /orgs/acme/teams`, []string{"CloudGroupEnumeration"}},
	{`curl -u me:$TOKEN "https://acme.atlassian.net/rest/api/3/group/bulk?maxResults=50"`, []string{"CloudGroupEnumeration"}},
	{`sf data query -q "SELECT Id, Name FROM PermissionSet"`, []string{"CloudGroupEnumeration"}},
	{`gam print groups members`, []string{"CloudGroupEnumeration"}},
	{`def list_groups(self):`, nil},

	// The instances of a cloud, and the functions and keys of Windows: T1082
	{`reservations = ec2.describe_instances()["Reservations"]`, []string{"SystemInformationDiscovery", "CloudInfrastructureDiscovery"}},
	{`az vm list -o table`, []string{"AzureResourceEnumeration", "SystemInformationDiscovery"}},
	{`Get-AzVM -Status`, []string{"AzureResourceEnumeration", "SystemInformationDiscovery"}},
	{`GET /subscriptions/0000/providers/Microsoft.Compute/virtualMachines?api-version=2023-03-01`, []string{"SystemInformationDiscovery"}},
	{`GetVersionExW(&osvi);`, []string{"SystemInformationDiscovery"}},
	{`GetNativeSystemInfo(&si);`, []string{"SystemInformationDiscovery"}},
	{`reg query "HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0"`, []string{"RegistryQuery", "SystemInformationDiscovery", "BackupSoftwareDiscovery"}},
	{`echo %PROCESSOR_ARCHITECTURE%`, []string{"SystemInformationDiscovery"}},

	// Accounts by the functions of a system, a macro, a cloud, an identity provider and a service: T1087
	{`NetUserEnum(NULL, 0, FILTER_NORMAL_ACCOUNT, &buf, MAX_PREFERRED_LENGTH, &read, &total, NULL);`, []string{"AccountEnumeration"}},
	{`LookupAccountSidW(NULL, sid, name, &cch, domain, &cchDomain, &use);`, []string{"AccountEnumeration"}},
	{`$searcher = New-Object System.DirectoryServices.DirectorySearcher`, []string{"DirectorySearch", "AccountEnumeration"}},
	{`$users = ([adsisearcher]"(objectCategory=person)").FindAll()`, []string{"DirectorySearch", "AccountEnumeration"}},
	{`(&(objectClass=user)(samAccountType=805306368))`, []string{"AccountEnumeration"}},
	{`let query = try ODQuery(node: node, forRecordTypes: kODRecordTypeUsers, attribute: nil)`, []string{"AccountEnumeration"}},
	{`Set objDomain = GetObject("WinNT://" & strDomain)`, []string{"AccountEnumeration"}},
	{`Set objUser = GetObject("LDAP://" & objSysInfo.UserName)`, []string{"AccountEnumeration"}},
	{`Set objSysInfo = CreateObject("ADSystemInfo")`, []string{"AccountEnumeration"}},
	{`objConnection.Provider = "ADsDSOObject"`, []string{"AccountEnumeration"}},
	{`Set net = CreateObject("WScript.Network")`, []string{"AccountEnumeration"}},
	{`CreateObject("WScript.Network").MapNetworkDrive "Z:", "\\fs\share"`, nil},
	{`MsgBox Application.UserName`, []string{"AccountEnumeration"}},
	{`user = Environ("USERNAME")`, []string{"AccountEnumeration"}},
	{`"eventName": "GetAccountAuthorizationDetails",`, []string{"AccountEnumeration", "CloudAccountEnumeration"}},
	{`users = iam.list_users()["Users"]`, []string{"AccountEnumeration", "CloudAccountEnumeration"}},
	{`report = client.get_credential_report()`, []string{"AccountEnumeration"}},
	{`"Action": ["iam:ListUsers", "iam:ListRoles"],`, []string{"AccountEnumeration", "CloudAccountEnumeration"}},
	{`An error occurred (AccessDenied) when calling the ListUsers operation: User: arn:aws:iam::111122223333:user/dev is not authorized`, []string{"AccountEnumeration", "CloudAccountEnumeration"}},
	{`curl -H "Authorization: Bearer $T" https://acme.auth0.com/api/v2/users`, []string{"AccountEnumeration"}},
	{`curl https://api.eu.onelogin.com/api/2/users`, []string{"AccountEnumeration"}},
	{`GET /admin/v1/users HTTP/1.1`, []string{"AccountEnumeration"}},
	{`curl -H "x-api-key: $K" https://console.jumpcloud.com/api/systemusers`, []string{"AccountEnumeration"}},
	{`curl -H "Authorization: Bearer $T" https://sso.corp.example/admin/realms/master/users`, []string{"AccountEnumeration"}},
	{`curl -u me:$TOKEN https://acme.atlassian.net/rest/api/3/users/search`, []string{"AccountEnumeration"}},
	{`gh api /orgs/acme/members --paginate`, []string{"AccountEnumeration"}},
	{`curl -H "Authorization: Bearer $ZOOM" "https://api.zoom.us/v2/users?page_size=300"`, []string{"AccountEnumeration"}},
	{`curl -H "Authorization: Bearer $SLACK" https://slack.com/api/users.list`, []string{"AccountEnumeration", "HostedServiceDiscovery"}},
	{`members = client.users_list()["members"]`, []string{"AccountEnumeration"}},
	{`sf data query -q "SELECT Id, Username, Email FROM User"`, []string{"AccountEnumeration"}},
	{`mysql -e "SELECT user, host FROM mysql.user"`, []string{"AccountEnumeration"}},
	{`users_list = []`, nil},
	{`app.get('/api/v1/users', listUsers)`, nil},
	{`select the option from user settings`, nil},
	{`ls /Users`, []string{"LocalAccountEnumeration"}},
	{`ls -la /Users/`, []string{"LocalAccountEnumeration"}},
	{`ls /Users/alice/Documents`, nil},
	{`gam print users`, []string{"CloudAccountEnumeration"}},
	{`aws sts get-caller-identity`, []string{"CloudAccountEnumeration"}},

	// The address list of a mail system: T1087.003
	{`Set entries = ns.AddressLists("Global Address List").AddressEntries`, []string{"EmailAccountEnumeration"}},
	{`<m:ResolveNames ReturnFullContactData="true" SearchScope="ActiveDirectory">`, []string{"EmailAccountEnumeration"}},
	{`GET /OAB/8c3b4c6e-2f0a/oab.xml HTTP/1.1`, []string{"EmailAccountEnumeration"}},

	// The devices of Windows: T1120
	{`fsutil fsinfo drives`, []string{"PeripheralDeviceDiscovery"}},
	{`reg query HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`, []string{"RegistryQuery", "PeripheralDeviceDiscovery", "BackupSoftwareDiscovery"}},
	{`Get-CimInstance Win32_Keyboard`, []string{"PeripheralDeviceDiscovery"}},
	{`SetupDiGetClassDevsW(&GUID_DEVCLASS_USB, NULL, NULL, DIGCF_PRESENT);`, []string{"PeripheralDeviceDiscovery"}},
	{`Get-WmiObject Win32_LogicalDisk -Filter "DriveType = 2"`, []string{"PeripheralDeviceDiscovery", "LocalStorageDiscovery"}},

	// The policy of the login window: T1201
	{`defaults read /Library/Preferences/com.apple.loginwindow`, []string{"PasswordPolicyDiscovery"}},

	// What a guest of a hypervisor leaves: T1497, T1497.001
	{`reg query "HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions"`, []string{"RegistryQuery", "VirtualMachineCheck", "BackupSoftwareDiscovery"}},
	{`reg query HKLM\HARDWARE\ACPI\DSDT\VBOX__`, []string{"RegistryQuery", "VirtualMachineCheck", "BackupSoftwareDiscovery"}},
	{`reg query HKLM\SYSTEM\CurrentControlSet\Services\VBoxGuest`, []string{"RegistryQuery", "VirtualMachineCheck", "BackupSoftwareDiscovery"}},
	{`reg query HKLM\HARDWARE\Description\System /v SystemBiosVersion`, []string{"RegistryQuery", "VirtualMachineCheck", "BackupSoftwareDiscovery"}},
	{`if exist C:\Windows\System32\drivers\VBoxMouse.sys exit`, []string{"VirtualMachineCheck"}},
	{`if proc.name().lower() in ("vmtoolsd.exe", "vboxservice.exe"):`, []string{"VirtualMachineCheck"}},
	{`tasklist | findstr /i vmtoolsd`, []string{"VirtualMachineCheck"}},
	{`sc query VBoxService`, []string{"ServiceDiscovery", "VirtualMachineCheck", "SecuritySoftwareDiscovery", "BackupSoftwareDiscovery"}},
	{`if (GetModuleHandleA("SbieDll.dll")) return 1;`, []string{"VirtualMachineCheck"}},
	{`if mac.startswith("00:0C:29"):`, []string{"VirtualMachineCheck"}},
	{`Get-NetAdapter | ? MacAddress -like "00-50-56*"`, []string{"VirtualMachineCheck"}},
	{`if mac.upper().startswith("08:00:27"):`, []string{"VirtualMachineCheck"}},
	{`2026-01-01 00:50:56 INFO started`, nil},
	{`link/ether 00:0c:29:ab:cd:ef brd ff:ff:ff:ff:ff:ff`, nil},
	{`SELECT * FROM MSAcpi_ThermalZoneTemperature`, []string{"VirtualMachineCheck"}},
	{`(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory`, []string{"SystemInformationDiscovery", "VirtualMachineCheck"}},
	{`GlobalMemoryStatusEx(&mem);`, []string{"VirtualMachineCheck"}},

	// What a person at a system leaves: T1497.002
	{`GetLastInputInfo(&lii);`, []string{"UserActivityCheck"}},
	{`dir "%APPDATA%\Microsoft\Windows\Recent"`, []string{"UserActivityCheck"}},
	{`reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"`, []string{"RegistryQuery", "UserActivityCheck", "BackupSoftwareDiscovery"}},
	{`(Get-ChildItem $env:USERPROFILE\Desktop).Count`, []string{"UserActivityCheck"}},
	{`[Environment]::GetFolderPath("Desktop")`, []string{"UserActivityCheck"}},
	{`ls ~/Desktop | wc -l`, []string{"UserActivityCheck"}},

	// A wait by any name: T1497.003
	{`ping -n 10 127.0.0.1 > nul`, []string{"TimeBasedCheck"}},
	{`ping -c 5 -i 2 10.0.0.1`, []string{"TimeBasedCheck"}},
	{`ping -i 3 -c 2 localhost`, []string{"TimeBasedCheck"}},
	{`nanosleep(&ts, NULL);`, []string{"TimeBasedCheck"}},
	{`WScript.Sleep 60000`, []string{"TimeBasedCheck"}},
	{`timeout /t 30 /nobreak`, []string{"TimeBasedCheck"}},

	// The software of Windows and of a cloud: T1518
	{`winget list`, []string{"SoftwareDiscovery"}},
	{`choco list --local-only`, []string{"SoftwareDiscovery"}},
	{`Get-WmiObject Win32Reg_AddRemovePrograms`, []string{"SoftwareDiscovery"}},
	{`POST https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01`, []string{"SoftwareDiscovery"}},

	// Backup software by its commands, its files and its name: T1518.002
	{`find /etc /opt /var -iname "*backup*"`, []string{"BackupSoftwareDiscovery"}},
	{`find / -name "*.bak"`, nil},
	{`ps aux | grep -i backup`, []string{"SecuritySoftwareDiscovery", "BackupSoftwareDiscovery"}},
	{`cat /etc/rsnapshot.conf`, []string{"BackupSoftwareDiscovery"}},
	{`ls -la /var/backups`, []string{"BackupSoftwareDiscovery"}},
	{`tar czf /var/backups/site.tgz /srv/www`, []string{"ArchiveCreation"}},
	{`wbadmin get versions`, []string{"BackupSoftwareDiscovery"}},
	{`vssadmin list shadows`, []string{"BackupSoftwareDiscovery"}},
	{`tmutil listbackups`, []string{"BackupSoftwareDiscovery"}},
	{`.\Get-DataInfo.ps1 method`, []string{"BackupSoftwareDiscovery"}},
	{`Get-VBRJob | select Name`, []string{"BackupSoftwareDiscovery"}},
	{`defaults read /Library/Preferences/com.apple.TimeMachine`, []string{"BackupSoftwareDiscovery"}},
	{`systemctl list-units | grep -i backup`, []string{"ServiceDiscovery", "BackupSoftwareDiscovery"}},

	// The services of a cloud, an identity provider and Microsoft 365, at the address each is asked at: T1526
	{`curl -H "Authorization: Bearer $T" "https://management.azure.com/subscriptions/0000/providers?api-version=2021-04-01"`, []string{"AzureResourceEnumeration"}},
	{`az resource list -o table`, []string{"AzureResourceEnumeration"}},
	{`curl -H "Authorization: Bearer $T" https://graph.microsoft.com/v1.0/subscribedSkus`, []string{"CloudServiceDiscovery"}},
	{`curl -H "Authorization: Bearer $T" https://graph.microsoft.com/v1.0/admin/serviceAnnouncement/healthOverviews`, []string{"CloudServiceDiscovery"}},
	{`curl -H "Authorization: SSWS $T" https://acme.okta.com/api/v1/apps`, []string{"CloudServiceDiscovery"}},
	{`curl -H "Authorization: SSWS $T" https://acme.okta.com/api/v1/org`, []string{"CloudServiceDiscovery"}},
	{`curl -X DELETE -H "Authorization: SSWS $T" https://acme.okta.com/api/v1/apps/0oa1`, nil},
	{`Invoke-AADIntReconAsOutsider -DomainName corp.example`, []string{"CloudServiceDiscovery"}},
	{`roadrecon gather`, []string{"CloudServiceDiscovery"}},
	{`curl "https://login.microsoftonline.com/getuserrealm.srf?login=a@corp.example&xml=1"`, []string{"CloudServiceDiscovery"}},
	{`curl https://login.microsoftonline.com/corp.example/.well-known/openid-configuration`, []string{"CloudServiceDiscovery"}},
	{`curl -H "Authorization: Bearer $T" https://manage.office.com/api/v1.0/$TENANT/activity/feed/subscriptions/list`, []string{"CloudServiceDiscovery"}},
	{`https://admin.googleapis.com/admin/directory/v1/customer/my_customer/domains`, []string{"CloudServiceDiscovery"}},
	{`https://admin.googleapis.com/admin/directory/v1/users/a@corp.example/tokens`, []string{"EmailAccountEnumeration", "CloudAccountEnumeration", "CloudServiceDiscovery"}},
	{`https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/token`, []string{"CloudServiceDiscovery"}},
	{`curl -H "Authorization: Bearer $T" "https://serviceusage.googleapis.com/v1/projects/p1/services?filter=state:ENABLED"`, []string{"CloudServiceDiscovery"}},
	{`gam print tokens`, []string{"CloudServiceDiscovery"}},
	{`curl -H "Authorization: Bearer $ZOOM" https://api.zoom.us/v2/accounts/me/settings`, []string{"CloudServiceDiscovery"}},
	{`curl -X POST -H "Authorization: Bearer $ZOOM" https://api.zoom.us/v2/users/me/meetings -d @m.json`, nil},

	// The services of Salesforce and of Slack, however the question is sent: T1526
	{`curl -H "Authorization: Bearer $SF" https://acme.my.salesforce.com/services/data/v59.0/sobjects/`, []string{"HostedServiceDiscovery"}},
	{`curl $INSTANCE/services/data/`, []string{"HostedServiceDiscovery"}},
	{`curl "$INSTANCE/services/data/v59.0/tooling/query/?q=SELECT+Id+FROM+ApexClass"`, []string{"HostedServiceDiscovery"}},
	{`sf data query -q "SELECT Id, Name FROM ConnectedApplication"`, []string{"HostedServiceDiscovery"}},
	{`sf org list`, []string{"HostedServiceDiscovery"}},
	{`sfdx force:org:list`, []string{"HostedServiceDiscovery"}},
	{`curl -X POST -H "Authorization: Bearer $SLACK" https://slack.com/api/team.info`, []string{"HostedServiceDiscovery"}},
	{`apps = client.admin_apps_approved_list()`, []string{"HostedServiceDiscovery"}},
	{`resp = client.conversations_list(limit=1000)`, []string{"HostedServiceDiscovery"}},
	{`requests.post("https://slack.com/api/team.integrationLogs", headers=h)`, []string{"HostedServiceDiscovery"}},
	{`curl -H "Authorization: Bearer $SLACK" https://slack.com/api/emoji.list`, []string{"HostedServiceDiscovery"}},
	{`curl -X POST https://slack.com/api/chat.postMessage -d text=hi`, nil},

	// A console as its address names it, and the sign-in to one as a log records it: T1538
	{`"eventName": "ConsoleLogin",`, []string{"CloudServiceDashboard"}},
	{`"eventSource": "signin.amazonaws.com",`, []string{"CloudServiceDashboard"}},
	{`"appId": "c44b4083-3bb0-49c1-b47d-974e53cbdf3c",`, []string{"CloudServiceDashboard"}},
	{`"eventType": "user.session.access_admin_app",`, []string{"CloudServiceDashboard"}},
	{`"appDisplayName": "Azure Portal",`, []string{"CloudServiceDashboard"}},
	{`open https://acme.lightning.force.com/lightning/setup/SetupOneHome/home`, []string{"CloudServiceDashboard"}},
	{`https://acme.slack.com/admin/settings`, []string{"CloudServiceDashboard"}},
	{`https://admin.exchange.microsoft.com/`, []string{"CloudServiceDashboard"}},

	// Where a virtual machine of a cloud stands, and what traces a process: T1614, T1622
	{`curl -H Metadata:true "http://169.254.169.254/metadata/instance?api-version=2021-02-01"`, []string{"CloudMetadataAccess", "SystemLocationDiscovery"}},
	{`cat /proc/self/status`, []string{"DebuggerCheck"}},
	{`ptrace(PTRACE_TRACEME, 0, 1, 0);`, []string{"DebuggerCheck"}},
}

// A command that a flag, a subcommand or a path makes a discovery shows its
// technique; the same command put to another use shows none.
func TestDetectDiscovery(t *testing.T) {
	table, err := LoadActivities()
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range discoveryCases {
		t.Run(tt.line, func(t *testing.T) {
			if got := names(table.Detect(tt.line)); !slices.Equal(got, tt.want) {
				t.Errorf("Detect(%q) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}
