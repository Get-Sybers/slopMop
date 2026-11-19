package activity

import (
	"fmt"
	"strings"
	"testing"
)

// spreadForms are records of one connection, each as a sensor writes it,
// with the port left to fill in.
//
//nolint:gochecknoglobals // a table shared by two tests
var spreadForms = map[string]string{
	"tcpdump":          "10:15:00.000001 IP 10.0.0.5.51234 > 10.0.0.9.%d: Flags [S], seq 1, win 1024, length 0",
	"netfilter":        "kernel: IN=eth0 OUT= SRC=10.0.0.5 DST=10.0.0.9 LEN=44 TTL=40 ID=1 PROTO=TCP SPT=51234 DPT=%d WINDOW=1024 RES=0x00 SYN URGP=0",
	"sysmon":           "<Data Name='SourceIp'>10.0.0.5</Data><Data Name='DestinationIp'>10.0.0.9</Data><Data Name='DestinationPort'>%d</Data>",
	"ecs":              `{"source":{"ip":"10.0.0.5","port":51234},"destination":{"ip":"10.0.0.9","port":%d},"event":{"code":"3"}}`,
	"auditd read":      "type=SOCKADDR msg=audit(03/01/2025 10:15:00.000:77) : saddr={ saddr_fam=inet laddr=10.0.0.9 lport=%d }",
	"auditd":           "type=SOCKADDR msg=audit(1740824100.000:77): saddr=0200%04X0A0000090000000000000000",
	"zeek":             "1740824100.000000\tCabc\t10.0.0.5\t51234\t10.0.0.9\t%d\ttcp\t-\t-\t-\t-\tREJ\tT\tF",
	"windows firewall": "2025-03-01 10:15:00 DROP TCP 10.0.0.5 10.0.0.9 51234 %d 0 - 0 0 0 - - - RECEIVE",
	"netflow":          "2025-03-01 10:15:00.000     0.000 TCP        10.0.0.5:51234 ->       10.0.0.9:%d        1       44     1",
	"strace":           `connect(3, {sa_family=AF_INET, sin_port=htons(%d), sin_addr=inet_addr("10.0.0.9")}, 16) = -1 ECONNREFUSED`,
}

// record writes a form once for each port from first to last.
func record(form string, first, last int) string {
	var b strings.Builder
	for port := first; port <= last; port++ {
		fmt.Fprintf(&b, form+"\n", port)
	}
	return b.String()
}

// A record of connections shows a scan where one host is reached at ten
// ports or more. Fewer ports, or one port many times, is a visit.
func TestDetectSpread(t *testing.T) {
	table, err := LoadActivities()
	if err != nil {
		t.Fatal(err)
	}
	scanned := func(text string) int {
		for _, hit := range table.Detect(text) {
			if hit.Name == "NetworkServiceDiscovery" {
				return hit.Lines
			}
		}
		return 0
	}
	for name, form := range spreadForms {
		if got := scanned(record(form, 20, 31)); got != 12 {
			t.Errorf("%s: a scan of 12 ports shows %d lines, want 12", name, got)
		}
		if got := scanned(record(form, 20, 28)); got != 0 {
			t.Errorf("%s: 9 ports show %d lines, want none", name, got)
		}
		if got := scanned(strings.Repeat(fmt.Sprintf(form+"\n", 443), 40)); got != 0 {
			t.Errorf("%s: one port reached 40 times shows %d lines, want none", name, got)
		}
		// The lines of a scan count; those of a visit beside it do not.
		other := strings.NewReplacer("10.0.0.9", "10.0.0.77", "0A000009", "0A00004D").Replace(record(form, 443, 445))
		if got := scanned(record(form, 20, 31) + other); got != 12 {
			t.Errorf("%s: a scan beside a visit shows %d lines, want 12", name, got)
		}
	}
	// A large text is searched by its literals, as a small one is.
	large := strings.Repeat("a line that reaches nothing\n", 2000) + record(spreadForms["tcpdump"], 1, 300)
	if got := scanned(large); got != 300 {
		t.Errorf("a scan in a large text shows %d lines, want 300", got)
	}
}

// Each pattern of a spread reads one form, and holds a literal to find it by.
func TestSpreadPatterns(t *testing.T) {
	table, err := LoadActivities()
	if err != nil {
		t.Fatal(err)
	}
	patterns := 0
	for _, a := range table.activities {
		for _, p := range a.spread {
			patterns++
			if len(p.literals) == 0 {
				t.Errorf("%s: %s has no literal, so it is tried on every line", a.name, p.rx)
			}
			read := 0
			for _, form := range spreadForms {
				if line := fmt.Sprintf(form, 22); p.rx.MatchString(line) {
					read++
					held := false
					for _, lit := range p.literals {
						held = held || strings.Contains(strings.ToLower(line), string(lit))
					}
					if !held {
						t.Errorf("%s: %s matches %q, which holds none of %q", a.name, p.rx, line, p.literals)
					}
				}
			}
			if read != 1 {
				t.Errorf("%s: %s reads %d forms, want one", a.name, p.rx, read)
			}
		}
	}
	if patterns != len(spreadForms) {
		t.Errorf("the table holds %d patterns of a spread and the forms %d", patterns, len(spreadForms))
	}
}
