package command

import (
	"errors"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/get-sybers/slopmop/internal/cli"
	"github.com/get-sybers/slopmop/internal/device"
)

// memoryShare is the percentage of the memory of the machine a run tries to
// stay within when -memory is not given.
const memoryShare = 75

// share is a part of the machine a run may use; given is false when the
// option was left out.
type share struct {
	percent int
	given   bool
}

// percentage reads an option that is a share of the machine: a whole number
// from 1 to 100, with or without a percent sign.
func percentage(a *cli.Args, name string) (share, error) {
	text, given := a.Options[name]
	if !given {
		return share{}, nil
	}
	n, err := strconv.Atoi(strings.TrimSuffix(text, "%"))
	if err != nil || n < 1 || n > 100 {
		return share{}, cli.Usagef("-%s takes a percentage from 1 to 100, not %q", name, text)
	}
	return share{percent: n, given: true}, nil
}

// limit holds a run to its share of the processors and of the memory of the
// machine, and returns what puts both back as they were.
func limit(cores, memory share) (restore func(), err error) {
	total, known := device.Memory()
	switch {
	case memory.given && !known:
		return nil, errors.New("-" + memoryOption + ": this system does not say how much memory the machine has")
	case !memory.given && os.Getenv("GOMEMLIMIT") == "":
		// With nothing asked for, the run still leaves the machine a part of its memory.
		memory = share{percent: memoryShare, given: known}
	}
	restore = func() {}
	if cores.given {
		before := runtime.GOMAXPROCS(device.Processors(cores.percent))
		restore = func() { runtime.GOMAXPROCS(before) }
	}
	if memory.given {
		// The limit is one the collector works to keep: what a run must hold, it still holds.
		before, undo := debug.SetMemoryLimit(int64(min(device.Share(total, memory.percent), 1<<62))), restore
		restore = func() {
			debug.SetMemoryLimit(before)
			undo()
		}
	}
	return restore, nil
}
