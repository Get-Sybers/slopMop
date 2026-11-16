$h = @{ Authorization = "Bearer $token" }
$sp = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"
Invoke-RestMethod -Method Post -Headers $h -Uri "https://graph.microsoft.com/v1.0/applications/66666666-7777-4888-9999-000000000000/addPassword" -Body '{}'
Invoke-RestMethod -Method Post -Headers $h -Uri "https://graph.microsoft.com/v1.0/directoryRoles/roleTemplateId=62e90394-69f5-4237-9190-012177145e10/members/`$ref" -Body $member
Invoke-RestMethod -Method Post -Headers $h -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$sp/appRoleAssignments" -Body $grant
