package device

import (
	"runtime"
	"testing"
)

// The systems the tool is built for say how much memory they have.
func TestMemory(t *testing.T) {
	total, ok := Memory()
	switch runtime.GOOS {
	case "linux", "windows", "darwin":
		if !ok || total < 256<<20 || total > 1<<50 {
			t.Errorf("Memory() = %d, %t; want what a machine has", total, ok)
		}
	default:
		if ok {
			t.Errorf("Memory() = %d on a system that is not read", total)
		}
	}
}

func TestProcessors(t *testing.T) {
	all := runtime.NumCPU()
	for _, tt := range []struct{ percent, want int }{
		{100, all},
		{50, max(1, all/2)},
		{1, max(1, all/100)},
		{99, max(1, all*99/100)},
	} {
		if got := Processors(tt.percent); got != tt.want || got < 1 || got > all {
			t.Errorf("Processors(%d) = %d, want %d of %d", tt.percent, got, tt.want, all)
		}
	}
}

func TestShare(t *testing.T) {
	const gigabyte = 1 << 30
	for _, tt := range []struct {
		total   uint64
		percent int
		want    uint64
	}{
		{16 * gigabyte, 100, 16 * gigabyte},
		{16 * gigabyte, 75, 12 * gigabyte},
		{16 * gigabyte, 1, 16 * gigabyte / 100},
		{1 << 62, 100, 1 << 62},
		{1<<64 - 1, 100, 1<<64 - 1},
		{199, 50, 99},
		{0, 50, 0},
	} {
		if got := Share(tt.total, tt.percent); got != tt.want {
			t.Errorf("Share(%d, %d) = %d, want %d", tt.total, tt.percent, got, tt.want)
		}
	}
}

func TestMeminfoTotal(t *testing.T) {
	for _, tt := range []struct {
		name, text string
		want       uint64
		ok         bool
	}{
		{"as the kernel writes it", "MemTotal:       16303428 kB\nMemFree:         1024 kB\n", 16303428 << 10, true},
		{"not the first line", "MemFree: 1 kB\nMemTotal: 2048 kB\n", 2048 << 10, true},
		{"no such line", "MemFree: 1 kB\n", 0, false},
		{"another unit", "MemTotal: 16 MB\n", 0, false},
		{"not a number", "MemTotal: lots kB\n", 0, false},
		{"a number no machine has", "MemTotal: 18446744073709551615 kB\n", 0, false},
		{"empty", "", 0, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got, ok := meminfoTotal(tt.text); got != tt.want || ok != tt.ok {
				t.Errorf("meminfoTotal = %d, %t; want %d, %t", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestGroupLimit(t *testing.T) {
	for _, tt := range []struct {
		name, text string
		want       uint64
		ok         bool
	}{
		{"a limit", "8589934592\n", 8 << 30, true},
		{"no limit, version 2", "max\n", 0, false},
		{"no limit, version 1", "9223372036854771712\n", 0, false},
		{"zero", "0\n", 0, false},
		{"empty", "", 0, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got, ok := groupLimit(tt.text); got != tt.want || ok != tt.ok {
				t.Errorf("groupLimit = %d, %t; want %d, %t", got, ok, tt.want, tt.ok)
			}
		})
	}
}
