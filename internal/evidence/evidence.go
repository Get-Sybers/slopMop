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
	Stamp    nametime.Stamp
	Stamped  bool
	SHA256   string
	Note     Note
}
