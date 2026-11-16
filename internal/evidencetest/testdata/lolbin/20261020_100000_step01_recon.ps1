whoami /all | Out-File -FilePath recon_20261020_100030.txt
nltest /dclist:corp.example >> recon_20261020_100030.txt
net.exe group "Domain Admins" /domain >> recon_20261020_100030.txt
wmic.exe process list brief
