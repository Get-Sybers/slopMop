# Step 3: same again with the service account
$SyncHost = '10.20.1.17'
$User = 'CORP\svc_backup'
$Cred = Get-Credential -UserName $User -Message 'sync server'
$Log = "sync_{0}_retry_{1}.txt" -f $SyncHost, (Get-Date -Format 'yyyyMMdd_HHmmss')
$splat = @{
    ComputerName = $SyncHost
    Credential   = $Cred
}
Invoke-Command @splat -ScriptBlock {
    Get-ADSyncConnector | Select-Object Name, Type
    Get-ADSyncScheduler
} | Out-File -FilePath $Log -Encoding utf8
