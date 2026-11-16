// Package nametime detects the timestamp written into a file name.
package nametime

import (
	"regexp"
	"strconv"
	"time"
)

type Precision int

const (
	Second Precision = iota + 1
	Day
)

type Stamp struct {
	Time      time.Time
	Precision Precision
	Text      string
	// Local marks a date and time written without a zone.
	Local bool
}

// Go's regexp has no lookaround, so each rule consumes one non-digit or an
// edge on either side of the stamp and captures the stamp itself.
var (
	fullRx = regexp.MustCompile(`(?:^|[^0-9])((20[0-9]{2})[-_.]?(0[1-9]|1[0-2])[-_.]?(0[1-9]|[12][0-9]|3[01])` +
		`[-_.T ]?([01][0-9]|2[0-3])[-_.:hH]?([0-5][0-9])(?:[-_.:mM]?([0-5][0-9]))?(Z)?)(?:[^0-9]|$)`)
	epochRx = regexp.MustCompile(`(?:^|[^0-9])((1[5-9][0-9]{8})(?:[0-9]{3})?)(?:[^0-9]|$)`)
	dateRx  = regexp.MustCompile(`(?:^|[^0-9])((20[0-9]{2})[-_.]?(0[1-9]|1[0-2])[-_.]?(0[1-9]|[12][0-9]|3[01]))(?:[^0-9]|$)`)
)

// Detect tries a date and time, then a Unix epoch, then a date. Each rule
// looks at its first match only; an impossible date abandons that rule.
func Detect(name string) (Stamp, bool) {
	if m := fullRx.FindStringSubmatch(name); m != nil {
		if day, ok := calendar(m[2], m[3], m[4]); ok {
			clock := time.Duration(number(m[5]))*time.Hour +
				time.Duration(number(m[6]))*time.Minute +
				time.Duration(number(m[7]))*time.Second
			return Stamp{Time: day.Add(clock), Precision: Second, Text: m[1], Local: m[8] == ""}, true
		}
	}
	if m := epochRx.FindStringSubmatch(name); m != nil {
		return Stamp{Time: time.Unix(int64(number(m[2])), 0).UTC(), Precision: Second, Text: m[1]}, true
	}
	if m := dateRx.FindStringSubmatch(name); m != nil {
		if day, ok := calendar(m[2], m[3], m[4]); ok {
			return Stamp{Time: day, Precision: Day, Text: m[1]}, true
		}
	}
	return Stamp{}, false
}

// calendar rejects a date that time.Date would roll into the next month.
func calendar(year, month, day string) (time.Time, bool) {
	y, m, d := number(year), time.Month(number(month)), number(day)
	t := time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
	return t, t.Month() == m && t.Day() == d
}

func number(digits string) int {
	n, _ := strconv.Atoi(digits)
	return n
}
