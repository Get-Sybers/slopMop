# Step 5: export the CA certificate and make a test certificate
$Thumb = '5F2A9C1E7B3D4A6C8E0F1A2B3C4D5E6F7A8B9C0D'
$Dns = 'app01.corp.example'
$Store = "Cert:\LocalMachine\My\$Thumb"
Export-Certificate -Cert $Store -FilePath ca01_20250302_092210.cer | Out-Null
$new = New-SelfSignedCertificate -DnsName $Dns -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddYears(1)
$summary = @"
CA thumbprint : $Thumb
New cert      : $($new.Thumbprint)
"@
$summary | Set-Content -Path export_summary_20250302_092215.txt
[System.IO.File]::WriteAllText("$PWD\tenant_20250302_092220.txt", '6f1d2c3b-4a5e-4f60-8b7c-9d0e1f2a3b4c')
