// Package progress says, on the error stream, what a run is doing: the stage
// it is in, how far through it is, and what it has been at for longest.
package progress

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/get-sybers/slopmop/internal/render"
)

const (
	// width is how many columns a line may fill: a longer one wraps on a
	// terminal of 80 columns, and a line that wraps is not written over.
	width = 79
	// redraw is how often the line of a terminal is written again, and
	// repeat how often a line is written where every line stays.
	redraw = 150 * time.Millisecond
	repeat = 10 * time.Second
	// slow is how long an item is worked on before the line names it.
	slow = 2 * time.Second
	// cut stands for the start of a name too long for the line.
	cut = "..."
)

// Meter writes what a run is doing. A nil Meter writes nothing.
type Meter struct {
	w      io.Writer
	live   bool
	stages int
	now    func() time.Time

	mu    sync.Mutex
	stage int
	name  string
	// total is how many things the stage works through, units how many
	// pieces of work that is, and done how many of the pieces are done.
	total, units, done int
	began              time.Time
	// begun holds the items being worked on and when each was begun.
	begun map[int]item
	next  int
	// drawn is how many columns of the terminal the last line filled.
	drawn int

	end     sync.Once
	stop    chan struct{}
	stopped chan struct{}
}

type item struct {
	name  string
	since time.Time
}

// New returns a meter of a run of so many stages that writes to w. On a
// terminal one line is written over as the run goes on; elsewhere a line is
// written when a stage begins and now and then while it lasts.
func New(w io.Writer, terminal bool, stages int) *Meter {
	every := repeat
	if terminal {
		every = redraw
	}
	m := newMeter(w, terminal, stages, time.Now)
	m.stopped = make(chan struct{})
	go m.tick(every)
	return m
}

// newMeter returns a meter that writes only when it is told to: nothing
// writes its line again as time passes.
func newMeter(w io.Writer, terminal bool, stages int, now func() time.Time) *Meter {
	idle := make(chan struct{})
	close(idle)
	return &Meter{
		w: w, live: terminal, stages: stages, now: now, begun: map[int]item{},
		stop: make(chan struct{}), stopped: idle,
	}
}

// tick writes the line again at every interval until the meter is stopped.
func (m *Meter) tick(every time.Duration) {
	defer close(m.stopped)
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-ticker.C:
			m.mu.Lock()
			m.write()
			m.mu.Unlock()
		}
	}
}

// Stage begins the next stage. total is how many things it works through,
// or 0 when it counts none, and units how many times Begin is called for them.
func (m *Meter) Stage(name string, total, units int) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stage++
	m.name, m.total, m.units, m.done, m.began = name, total, units, 0, m.now()
	clear(m.begun)
	m.write()
}

// Begin says that work on an item has begun. The function it returns says
// that the work is done, and is called once.
func (m *Meter) Begin(name string) (done func()) {
	if m == nil {
		return func() {}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	id := m.next
	m.next++
	m.begun[id] = item{name: name, since: m.now()}
	return func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if _, ok := m.begun[id]; ok {
			delete(m.begun, id)
			m.done++
		}
	}
}

// Stop ends the meter and takes its line off the terminal, so what is
// written next stands alone. Calling it again does nothing.
func (m *Meter) Stop() {
	if m == nil {
		return
	}
	m.end.Do(func() {
		close(m.stop)
		<-m.stopped
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.live && m.drawn > 0 {
			_, _ = fmt.Fprint(m.w, "\r"+strings.Repeat(" ", m.drawn)+"\r")
		}
	})
}

// write puts the line out: over the last one on a terminal, below it
// elsewhere. Nothing is written before the first stage.
func (m *Meter) write() {
	if m.stage == 0 {
		return
	}
	line := m.line()
	if !m.live {
		_, _ = fmt.Fprintln(m.w, line)
		return
	}
	columns := utf8.RuneCountInString(line)
	_, _ = fmt.Fprint(m.w, "\r"+line+strings.Repeat(" ", max(m.drawn-columns, 0)))
	m.drawn = columns
}

// line is the stage, how far through it the run is, how long it has
// lasted and, when one item has taken long, which and for how long.
func (m *Meter) line() string {
	now := m.now()
	line := fmt.Sprintf("[%d/%d] %s", m.stage, m.stages, m.name)
	switch {
	case m.total > 0 && m.units > 0:
		line += fmt.Sprintf("  %d of %d", min(m.done*m.total/m.units, m.total), m.total)
	case m.done > 0:
		line += fmt.Sprintf("  %d done", m.done)
	}
	line += "  " + span(now.Sub(m.began))
	longest, found := item{}, false
	for _, it := range m.begun {
		if !found || it.since.Before(longest.since) || (it.since.Equal(longest.since) && it.name < longest.name) {
			longest, found = it, true
		}
	}
	if !found || now.Sub(longest.since) < slow {
		return line
	}
	// The name is evidence, so it is escaped, and its end says most about it.
	name, tail := []rune(render.Escape(longest.name)), " "+span(now.Sub(longest.since))
	room := width - utf8.RuneCountInString(line) - len("  on ") - len(tail)
	if room < len(cut)+4 {
		return line
	}
	if len(name) > room {
		name = append([]rune(cut), name[len(name)-room+len(cut):]...)
	}
	return line + "  on " + string(name) + tail
}

// span writes a length of time as a person reads it: 7s, 1m05s, 2h03m.
func span(d time.Duration) string {
	seconds := int(d / time.Second)
	switch {
	case seconds < 60:
		return fmt.Sprintf("%ds", seconds)
	case seconds < 3600:
		return fmt.Sprintf("%dm%02ds", seconds/60, seconds%60)
	default:
		return fmt.Sprintf("%dh%02dm", seconds/3600, seconds%3600/60)
	}
}
