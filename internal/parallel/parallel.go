// Package parallel runs independent pieces of work on every processor.
package parallel

import (
	"runtime"
	"sync"
)

// Each calls work once for every index below n and returns when all calls
// are done. The calls run on as many goroutines as there are processors, so
// work writes only to what belongs to its own index.
func Each(n int, work func(i int)) {
	workers := min(n, runtime.GOMAXPROCS(0))
	if workers <= 1 {
		for i := range n {
			work(i)
		}
		return
	}
	var next sync.Mutex
	at := 0
	var done sync.WaitGroup
	for range workers {
		done.Go(func() {
			for {
				next.Lock()
				i := at
				at++
				next.Unlock()
				if i >= n {
					return
				}
				work(i)
			}
		})
	}
	done.Wait()
}
