package command

import (
	"errors"
	"math"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"

	"github.com/get-sybers/slopmop/internal/cli"
	"github.com/get-sybers/slopmop/internal/device"
	"github.com/get-sybers/slopmop/internal/evidencetest"
)

func TestPercentage(t *testing.T) {
	for _, tt := range []struct {
		name, text string
		given      bool
		want       share
		fails      bool
	}{
		{"left out", "", false, share{}, false},
		{"a number", "50", true, share{50, true}, false},
		{"with its sign", "75%", true, share{75, true}, false},
		{"the least", "1", true, share{1, true}, false},
		{"the most", "100%", true, share{100, true}, false},
		{"nothing", "0", true, share{}, true},
		{"more than there is", "101", true, share{}, true},
		{"negative", "-5", true, share{}, true},
		{"a fraction", "12.5", true, share{}, true},
		{"a word", "half", true, share{}, true},
		{"only the sign", "%", true, share{}, true},
		{"empty", "", true, share{}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			args := &cli.Args{Options: map[string]string{}}
			if tt.given {
				args.Options[coresOption] = tt.text
			}
			got, err := percentage(args, coresOption)
			switch {
			case tt.fails:
				if !errors.Is(err, cli.ErrUsage) || !strings.Contains(err.Error(), "-cores takes a percentage from 1 to 100") {
					t.Errorf("percentage(%q) error = %v, want a usage error", tt.text, err)
				}
			case err != nil || got != tt.want:
				t.Errorf("percentage(%q) = %+v, %v; want %+v", tt.text, got, err, tt.want)
			}
		})
	}
}

// A run is held to its share of the machine, and the machine is as it was after it.
func TestLimit(t *testing.T) {
	total, known := device.Memory()
	if !known {
		t.Skip("this system does not say how much memory the machine has")
	}
	t.Setenv("GOMEMLIMIT", "")
	procs, unlimited := runtime.GOMAXPROCS(0), debug.SetMemoryLimit(-1)
	check := func(name string, wantProcs int, wantMemory int64) {
		t.Helper()
		if got := runtime.GOMAXPROCS(0); got != wantProcs {
			t.Errorf("%s: %d processors, want %d", name, got, wantProcs)
		}
		if got := debug.SetMemoryLimit(-1); got != wantMemory {
			t.Errorf("%s: a memory limit of %d, want %d", name, got, wantMemory)
		}
	}
	restore, err := limit(share{50, true}, share{40, true})
	if err != nil {
		t.Fatal(err)
	}
	check("half the processors, two fifths of the memory", device.Processors(50), int64(min(device.Share(total, 40), math.MaxInt64)))
	restore()
	check("after it", procs, unlimited)

	// With nothing asked for, every processor is used and a part of the memory is left.
	restore, err = limit(share{}, share{})
	if err != nil {
		t.Fatal(err)
	}
	check("nothing asked for", procs, int64(min(device.Share(total, memoryShare), math.MaxInt64)))
	restore()
	check("after it", procs, unlimited)

	// A limit the environment sets is left alone.
	t.Setenv("GOMEMLIMIT", "1GiB")
	restore, err = limit(share{}, share{})
	if err != nil {
		t.Fatal(err)
	}
	check("a limit in the environment", procs, unlimited)
	restore()
	if unlimited != math.MaxInt64 {
		t.Logf("the test ran under a memory limit of %d", unlimited)
	}
}

// The options change how much of the machine a run uses, and nothing it writes.
func TestReportWithLimits(t *testing.T) {
	folder := evidencetest.Copy(t, "linux")
	plain, _ := report(t, folder)
	limited, _ := report(t, folder, "-cores", "50%", "-memory", "25")
	if limited != plain {
		t.Errorf("the report differs under -cores and -memory:\n%s", limited)
	}
	for _, tt := range []struct{ option, value string }{
		{"-cores", "0"}, {"-cores", "all"}, {"-memory", "150"}, {"-memory", "2GB"},
	} {
		_, err := run(t, "-inputdir", folder, "report", tt.option, tt.value)
		if want := tt.option + " takes a percentage from 1 to 100, not " + strconv.Quote(tt.value); !errors.Is(err, cli.ErrUsage) || !strings.Contains(err.Error(), want) {
			t.Errorf("%s %s: error = %v, want a usage error saying %q", tt.option, tt.value, err, want)
		}
	}
}

// The summary of -memory names the share a run takes when it is not given.
func TestMemoryShareIsDeclared(t *testing.T) {
	doc, err := decodeCommands(commandsJSON)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range doc.Options {
		if o.Name == memoryOption && !strings.Contains(o.Summary, "; "+strconv.Itoa(memoryShare)+" when not given") {
			t.Errorf("commands.json says of -memory %q, and a run takes %d", o.Summary, memoryShare)
		}
	}
}
