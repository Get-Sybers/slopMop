package parallel

import (
	"runtime"
	"sync/atomic"
	"testing"
)

func TestEach(t *testing.T) {
	for _, n := range []int{0, 1, 2, 7, 1000} {
		seen := make([]int32, n)
		var calls atomic.Int64
		Each(n, func(i int) {
			atomic.AddInt32(&seen[i], 1)
			calls.Add(1)
		})
		if calls.Load() != int64(n) {
			t.Errorf("Each(%d) made %d calls", n, calls.Load())
		}
		for i, count := range seen {
			if count != 1 {
				t.Errorf("Each(%d) called index %d %d times", n, i, count)
			}
		}
	}
}

// On one processor the work runs in order on the caller's goroutine.
func TestEachOnOneProcessor(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	var order []int
	Each(5, func(i int) { order = append(order, i) })
	for i, got := range order {
		if got != i {
			t.Fatalf("order = %v, want 0 to 4", order)
		}
	}
	if len(order) != 5 {
		t.Fatalf("order = %v, want five calls", order)
	}
}

// A call inside a call finishes too: the work of one index may spread its own.
func TestEachNested(t *testing.T) {
	var calls atomic.Int64
	Each(8, func(int) {
		Each(8, func(int) { calls.Add(1) })
	})
	if calls.Load() != 64 {
		t.Errorf("nested calls = %d, want 64", calls.Load())
	}
}
