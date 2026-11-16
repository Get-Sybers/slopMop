# Step 2: look at the sync server found in the host list
$SyncHost = (Import-Csv .\hosts_20250302_090030.csv | Where-Object { $_.Name -like 'AADC*' }).IPv4Address
$Log = "sync_${SyncHost}_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
Invoke-Command -ComputerName $SyncHost -ScriptBlock {
    Get-ADSyncConnector | Select-Object Name, Type
    Get-ADSyncScheduler
} | Out-File $Log
