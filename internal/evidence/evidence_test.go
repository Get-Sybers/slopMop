package evidence_test

import (
	"testing"
	"time"

	"github.com/get-sybers/slopmop/internal/evidence"
	"github.com/get-sybers/slopmop/internal/nametime"
)

func at(text string) time.Time {
	t, err := time.Parse(time.RFC3339, text)
	if err != nil {
		panic(err)
	}
	return t
}

func named(name string, modified time.Time) evidence.File {
	f := evidence.File{Name: name, Modified: modified}
	f.Stamp, f.Stamped = nametime.Detect(name)
	return f
}

// The time of a file is the one in its name, or else when it was last modified.
func TestTime(t *testing.T) {
	modified := at("2026-10-25T12:00:00Z")
	for _, tt := range []struct {
		name string
		file evidence.File
		want time.Time
	}{
		{"a name with a time", named("20261022_091500_step04.sh", modified), at("2026-10-22T09:15:00Z")},
		{"a name with a day", named("report_2026-10-22.txt", modified), at("2026-10-22T00:00:00Z")},
		{"a name with neither", named("notes.txt", modified), modified},
		{"no time at all", named("notes.txt", time.Time{}), time.Time{}},
	} {
		if got := tt.file.Time(); !got.Equal(tt.want) {
			t.Errorf("%s: Time = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// A file is within a window when its time is from the one instant until the
// other, both counted in; a day alone in a name is the whole of the day.
func TestWithin(t *testing.T) {
	timed := named("20261022_091500_step04.sh", at("2026-10-25T12:00:00Z"))
	dayOnly := named("report_2026-10-22.txt", at("2026-10-25T12:00:00Z"))
	plain := named("notes.txt", at("2026-10-22T09:15:00Z"))
	none := named("notes.txt", time.Time{})
	open := time.Time{}
	for _, tt := range []struct {
		name        string
		file        evidence.File
		from, until time.Time
		want        bool
	}{
		{"no window", timed, open, open, true},
		{"no window and no time", none, open, open, true},
		{"a window and no time", none, at("2026-10-22T00:00:00Z"), open, false},
		{"inside", timed, at("2026-10-22T09:00:00Z"), at("2026-10-22T10:00:00Z"), true},
		{"at its beginning", timed, at("2026-10-22T09:15:00Z"), open, true},
		{"at its end", timed, open, at("2026-10-22T09:15:00Z"), true},
		{"a second before it begins", timed, at("2026-10-22T09:15:01Z"), open, false},
		{"a second after it ends", timed, open, at("2026-10-22T09:14:59Z"), false},
		{"the name decides, not when it was modified", timed, at("2026-10-25T00:00:00Z"), open, false},
		{"modified, when the name has no time", plain, at("2026-10-22T09:00:00Z"), at("2026-10-22T09:30:00Z"), true},
		{"modified too late", plain, open, at("2026-10-22T09:00:00Z"), false},
		{"a day in the name, a window in that day", dayOnly, at("2026-10-22T09:00:00Z"), at("2026-10-22T10:00:00Z"), true},
		{"a day in the name, a window that ends in that day", dayOnly, open, at("2026-10-22T00:00:00Z"), true},
		{"a day in the name, a window that begins the day after", dayOnly, at("2026-10-23T00:00:00Z"), open, false},
		{"a day in the name, a window that ends the day before", dayOnly, open, at("2026-10-21T23:59:59Z"), false},
	} {
		if got := tt.file.Within(tt.from, tt.until); got != tt.want {
			t.Errorf("%s: Within = %t, want %t", tt.name, got, tt.want)
		}
	}
}
