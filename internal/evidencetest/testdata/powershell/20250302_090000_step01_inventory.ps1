# Step 1: list the servers of the domain
[CmdletBinding()]
param(
    [string]$Domain = 'corp.example',
    [string]$OutDir = 'C:\Work\agent'   # working folder
)
$ErrorActionPreference = 'Stop'
$Stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$Csv = Join-Path $OutDir "hosts_$Stamp.csv"
Get-ADComputer -Filter * -Server $Domain -Properties IPv4Address |
    Select-Object Name, IPv4Address, OperatingSystem |
    Export-Csv -Path $Csv -NoTypeInformation
Write-Host "Wrote $Csv"
