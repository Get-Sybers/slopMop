// Package evidence holds the record of one file of evidence.
package evidence

import (
	"time"

	"github.com/get-sybers/slopmop/internal/nametime"
)

type Role string

const (
	Script Role = "script"
	Output Role = "output"
	Other  Role = "other"
)

type Note string

const (
	Binary     Note = "binary"
	Oversize   Note = "oversize"
	Unreadable Note = "unreadable"
)

type File struct {
	// Path is below the folder, slash separated and unique.
	Path string
	Name string
	Role Role
	Size int64
	// Lines is meaningful only when Note is empty.
	Lines    int
	Modified time.Time
	// Created is when the file was made, where its file system records it.
	Created time.Time
	Stamp   nametime.Stamp
	Stamped bool
	SHA256  string
	Note    Note
}

// Time is when a file is placed in the timeline: the time in its name, or
// else when it was last modified. The zero time means it has neither.
func (f File) Time() time.Time {
	if f.Stamped {
		return f.Stamp.Time
	}
	return f.Modified
}

// Made is when a file was made, and whether its file system says so. A
// creation time after the last change is that of a copy, made when it was
// copied: then, and where none is recorded, the time is that of the timeline.
func (f File) Made() (at time.Time, recorded bool) {
	if !f.Created.IsZero() && !f.Created.After(f.Modified) {
		return f.Created, true
	}
	return f.Time(), false
}

// Within reports whether the time of a file is from one instant until
// another, both counted in; a zero instant leaves that side open. A name
// that gives a day and no time stands for the whole day.
func (f File) Within(from, until time.Time) bool {
	if from.IsZero() && until.IsZero() {
		return true
	}
	first := f.Time()
	if first.IsZero() {
		return false
	}
	last := first
	if f.Stamped && f.Stamp.Precision == nametime.Day {
		last = first.Add(24*time.Hour - time.Nanosecond)
	}
	return (until.IsZero() || !first.After(until)) && (from.IsZero() || !last.Before(from))
}
