package progress

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

// clock is a time that passes only when a test says so.
type clock struct{ at time.Time }

func (c *clock) now() time.Time       { return c.at }
func (c *clock) pass(d time.Duration) { c.at = c.at.Add(d) }
func start() *clock                   { return &clock{at: time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)} }
func (m *Meter) again()               { m.mu.Lock(); m.write(); m.mu.Unlock() }
func lines(out *bytes.Buffer) []string {
	return strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
}
func last(out *bytes.Buffer) string { all := lines(out); return all[len(all)-1] }

// Where every line stays, a line is written when a stage begins and when the
// meter is told to write again.
func TestLinesOfAStage(t *testing.T) {
	c, out := start(), &bytes.Buffer{}
	m := newMeter(out, false, 5, c.now)
	m.again()
	if out.Len() != 0 {
		t.Fatalf("a line is written before the first stage: %q", out.String())
	}
	m.Stage("reading the folder", 0, 0)
	read := m.Begin("a.txt")
	c.pass(time.Second)
	read()
	m.again()
	m.Stage("analysing the files", 10, 40)
	var done []func()
	for range 14 {
		done = append(done, m.Begin("b.txt"))
	}
	for _, d := range done[:13] {
		d()
	}
	c.pass(75 * time.Second)
	m.again()
	done[13]()
	m.Stage("saving the report", 3, 3)
	c.pass(2 * time.Hour)
	m.again()
	want := []string{
		"[1/5] reading the folder  0s",
		"[1/5] reading the folder  1 done  1s",
		"[2/5] analysing the files  0 of 10  0s",
		"[2/5] analysing the files  3 of 10  1m15s  on b.txt 1m15s",
		"[3/5] saving the report  0 of 3  0s",
		"[3/5] saving the report  0 of 3  2h00m",
	}
	if got := lines(out); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("the lines are\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// The line names the item that has been worked on for longest, once that is
// long, and never counts more than the stage has.
func TestLineNamesTheLongest(t *testing.T) {
	c, out := start(), &bytes.Buffer{}
	m := newMeter(out, false, 2, c.now)
	m.Stage("analysing the files", 2, 2)
	first := m.Begin("first.log")
	c.pass(time.Second)
	second := m.Begin("second.log")
	c.pass(500 * time.Millisecond)
	m.again()
	if got, want := last(out), "[1/2] analysing the files  0 of 2  1s"; got != want {
		t.Errorf("before an item is slow the line is %q, want %q", got, want)
	}
	c.pass(time.Second)
	m.again()
	if got, want := last(out), "[1/2] analysing the files  0 of 2  2s  on first.log 2s"; got != want {
		t.Errorf("the line is %q, want %q", got, want)
	}
	first()
	first()
	c.pass(time.Second)
	m.again()
	if got, want := last(out), "[1/2] analysing the files  1 of 2  3s  on second.log 2s"; got != want {
		t.Errorf("the line is %q, want %q", got, want)
	}
	second()
	extra := m.Begin("third.log")
	extra()
	m.again()
	if got, want := last(out), "[1/2] analysing the files  2 of 2  3s"; got != want {
		t.Errorf("the line is %q, want %q", got, want)
	}
}

// A name is evidence: it is escaped, and one too long for the line keeps its end.
func TestLineKeepsWithinTheWidth(t *testing.T) {
	const head = "[1/1] analysing the files  0 of 1  5s  on "
	for _, tt := range []struct {
		name, item string
		// want is the whole of what follows head, or its end when the name is cut.
		want string
		cut  bool
	}{
		{"a short name", "notes.txt", "notes.txt 5s", false},
		{"a long path", strings.Repeat("deep/", 30) + "20261022_step01_recon.sh", "/deep/20261022_step01_recon.sh 5s", true},
		{"a name that would move the cursor", "wipe\x1b[2J.log", `"wipe\x1b[2J.log" 5s`, false},
		{"a name of many bytes", strings.Repeat("\u65e5", 60) + ".txt", "\u65e5\u65e5\u65e5.txt 5s", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, out := start(), &bytes.Buffer{}
			m := newMeter(out, false, 1, c.now)
			m.Stage("analysing the files", 1, 1)
			m.Begin(tt.item)
			c.pass(5 * time.Second)
			m.again()
			got := last(out)
			rest, found := strings.CutPrefix(got, head)
			switch {
			case !found:
				t.Errorf("the line is %q, want it to begin %q", got, head)
			case !tt.cut && rest != tt.want:
				t.Errorf("the line names %q, want %q", rest, tt.want)
			case tt.cut && (!strings.HasPrefix(rest, cut) || !strings.HasSuffix(rest, tt.want) || utf8.RuneCountInString(got) != width):
				t.Errorf("the line %q of %d columns does not fill %d columns with the end of the name", got, utf8.RuneCountInString(got), width)
			}
			if strings.ContainsRune(got, '\x1b') {
				t.Errorf("the line %q holds a byte that moves the cursor", got)
			}
		})
	}
	// A stage whose own text nearly fills the line names no item.
	c, out := start(), &bytes.Buffer{}
	m := newMeter(out, false, 1, c.now)
	m.Stage(strings.Repeat("x", 60), 0, 0)
	m.Begin("a.txt")
	c.pass(5 * time.Second)
	m.again()
	if got := last(out); strings.Contains(got, " on ") {
		t.Errorf("the line %q names an item it has no room for", got)
	}
}

// On a terminal one line is written over, a shorter one wipes the rest of
// the longer, and Stop leaves the line empty.
func TestTerminalLineIsWrittenOver(t *testing.T) {
	c, out := start(), &bytes.Buffer{}
	m := newMeter(out, true, 2, c.now)
	m.Stage("analysing the files", 100, 100)
	m.Stage("saving", 0, 0)
	m.Stop()
	m.Stop()
	long, short := "[1/2] analysing the files  0 of 100  0s", "[2/2] saving  0s"
	want := "\r" + long + "\r" + short + strings.Repeat(" ", len(long)-len(short)) + "\r" + strings.Repeat(" ", len(short)) + "\r"
	if got := out.String(); got != want {
		t.Errorf("the terminal is written %q, want %q", got, want)
	}
}

// A meter that is nil, or stopped before a stage, writes nothing.
func TestSilentMeters(t *testing.T) {
	var none *Meter
	none.Stage("reading", 1, 1)
	none.Begin("a.txt")()
	none.Stop()
	out := &bytes.Buffer{}
	m := New(out, true, 3)
	m.Stop()
	if out.Len() != 0 {
		t.Errorf("a meter with no stage wrote %q", out.String())
	}
}

// A meter writes its line again as time passes, and stops when told to.
func TestMeterWritesAsTimePasses(t *testing.T) {
	out := &safe{}
	m := newMeter(out, true, 1, time.Now)
	m.stopped = make(chan struct{})
	go m.tick(time.Millisecond)
	m.Stage("analysing the files", 0, 0)
	for range 2000 {
		if out.count("\r") >= 3 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	m.Stop()
	if n := out.count("\r"); n < 3 {
		t.Errorf("the line was written %d times, want it written again as time passes", n)
	}
}

func TestSpan(t *testing.T) {
	for d, want := range map[time.Duration]string{
		0: "0s", 999 * time.Millisecond: "0s", 59 * time.Second: "59s", time.Minute: "1m00s", 65 * time.Second: "1m05s",
		time.Hour: "1h00m", 2*time.Hour + 3*time.Minute + 59*time.Second: "2h03m",
	} {
		if got := span(d); got != want {
			t.Errorf("span(%v) = %q, want %q", d, got, want)
		}
	}
}

// safe is a writer two goroutines may share.
type safe struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *safe) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *safe) count(text string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Count(s.buf.String(), text)
}
