# Step 4: certificates on the other two servers
$Hosts = @('10.20.1.5', '10.20.1.23')
$Tenant = '6f1d2c3b-4a5e-4f60-8b7c-9d0e1f2a3b4c'
foreach ($h in $Hosts) {
    Invoke-Command -ComputerName $h -ScriptBlock { Get-ChildItem Cert:\LocalMachine\My } >> cert_store_20250302_091530.txt
}
certutil.exe -config "CA01.corp.example\corp-CA01-CA" -ping > ca_ping_20250302_091540.log 2>&1
