$h = @{ Authorization = "Bearer $token" }
Invoke-RestMethod -Headers $h -Uri "https://graph.microsoft.com/v1.0/users?`$top=999" | ConvertTo-Json | Out-File directory_20261015_090530.txt
Invoke-RestMethod -Headers $h -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$top=999"
Invoke-RestMethod -Headers $h -Uri "https://graph.microsoft.com/v1.0/directoryRoles"
Get-MgApplication -All
