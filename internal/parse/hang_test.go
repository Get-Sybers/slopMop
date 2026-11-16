package parse

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestHangIsolation(t *testing.T) {
	text := readFixture(t, "20250301_102300_step03_adsync.sh")
	lines := strings.Split(text, "\n")
	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		t.Run(fmt.Sprintf("line%d", i+1), func(t *testing.T) {
			funcs := []struct {
				name string
				fn   func()
			}{
				{"vars", func() { extractBashVars(line, i+1, &Script{}) }},
				{"redirs", func() { extractBashRedirections(line, i+1, &Script{}, map[string]bool{}) }},
				{"reads", func() { extractBashReads(line, i+1, &Script{}, map[string]bool{}) }},
				{"cmds", func() { extractBashCommands(line, i+1, &Script{}) }},
			}
			for _, f := range funcs {
				ch := make(chan struct{})
				go func() {
					f.fn()
					close(ch)
				}()
				select {
				case <-ch:
				case <-time.After(2 * time.Second):
					t.Fatalf("HANG in %s on: %s", f.name, line)
				}
			}
		})
	}
}
