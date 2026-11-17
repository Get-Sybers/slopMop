// Package device tells how much of the machine a run has: its processors
// and its memory. It reads the machine and changes nothing.
package device

import (
	"runtime"
	"strconv"
	"strings"
)

// Memory returns the bytes of memory the run can have: that of the machine,
// or of the container it runs in when that is less. It reports false where
// the system does not say.
func Memory() (uint64, bool) {
	total, ok := physical()
	return total, ok && total > 0
}

// Processors returns the share of the processors of the machine that a
// percentage from 1 to 100 comes to, and never fewer than one.
func Processors(percent int) int {
	return max(1, runtime.NumCPU()*percent/100)
}

// Share returns the part of total that a percentage from 1 to 100 comes to.
func Share(total uint64, percent int) uint64 {
	// The hundredths left over are shared out apart, so a large total does not overflow.
	p := uint64(min(max(percent, 0), 100))
	return total/100*p + total%100*p/100
}

// meminfoTotal reads the memory of the machine from the text of
// /proc/meminfo, where it stands in kilobytes on the line MemTotal.
func meminfoTotal(text string) (uint64, bool) {
	for _, line := range strings.Split(text, "\n") {
		rest, found := strings.CutPrefix(line, "MemTotal:")
		if !found {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) != 2 || fields[1] != "kB" {
			return 0, false
		}
		kilobytes, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil || kilobytes > 1<<53 {
			return 0, false
		}
		return kilobytes << 10, true
	}
	return 0, false
}

// groupLimit reads the memory limit of a control group: a count of bytes,
// or a word or a number past any machine where there is no limit.
func groupLimit(text string) (uint64, bool) {
	limit, err := strconv.ParseUint(strings.TrimSpace(text), 10, 64)
	if err != nil || limit == 0 || limit >= 1<<60 {
		return 0, false
	}
	return limit, true
}
