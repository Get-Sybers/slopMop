package command

import (
	"time"

	"github.com/get-sybers/slopmop/internal/cli"
	"github.com/get-sybers/slopmop/internal/render"
)

// window is the stretch of time a run reads: a file whose time is outside it
// is not opened. With a start alone the run looks forward from it, and with
// a stop alone it looks back: a zero time leaves that side open.
type window struct {
	start, stop time.Time
}

// set reports whether either side of the window is given.
func (w window) set() bool { return !w.start.IsZero() || !w.stop.IsZero() }

// String says what the window leaves out, as the summary writes it.
func (w window) String() string {
	switch {
	case !w.start.IsZero() && !w.stop.IsZero():
		return "before " + render.Stamp(w.start, nil) + " or after " + render.Stamp(w.stop, nil)
	case !w.start.IsZero():
		return "before " + render.Stamp(w.start, nil)
	case !w.stop.IsZero():
		return "after " + render.Stamp(w.stop, nil)
	}
	return ""
}

// The forms a time is given in: a day alone, or a day and a time. One that
// names no zone is UTC, as every time of the report is.
const (
	dayLayout    = "2006-01-02"
	minuteLayout = "2006-01-02T15:04"
	secondLayout = "2006-01-02T15:04:05"
)

// readWindow reads -start and -stop. A day alone stands for the whole day:
// it begins the window at its first instant and ends it at its last.
func readWindow(a *cli.Args) (window, error) {
	var w window
	var err error
	if w.start, err = readTime(a, startOption, false); err != nil {
		return window{}, err
	}
	if w.stop, err = readTime(a, stopOption, true); err != nil {
		return window{}, err
	}
	if !w.start.IsZero() && !w.stop.IsZero() && w.stop.Before(w.start) {
		return window{}, cli.Usagef("-%s %s is before -%s %s", stopOption, a.Options[stopOption], startOption, a.Options[startOption])
	}
	return w, nil
}

// readTime reads one side of the window; ends says a day alone means its
// last instant and not its first.
func readTime(a *cli.Args, name string, ends bool) (time.Time, error) {
	text, given := a.Options[name]
	if !given {
		return time.Time{}, nil
	}
	if day, err := time.Parse(dayLayout, text); err == nil {
		if ends {
			return day.Add(24*time.Hour - time.Nanosecond), nil
		}
		return day, nil
	}
	for _, layout := range []string{time.RFC3339, minuteLayout + "Z07:00", secondLayout, minuteLayout} {
		if at, err := time.Parse(layout, text); err == nil {
			return at.UTC(), nil
		}
	}
	return time.Time{}, cli.Usagef("-%s takes a day or a day and a time, such as 2026-10-22 or 2026-10-22T09:30:00Z, not %q", name, text)
}
