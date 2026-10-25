// SPDX-License-Identifier: MIT

// Fastest-in-the-field side of `zig build bench-workerpool`
// (modules/workerpool/tools/bench.zig): times panjf2000/ants v2.12.0 (pinned
// by go.mod/go.sum), Go's most used goroutine pool, on the rows of
// tools/c_bench/main.c through its public API only. One pool of 4 workers
// (`NewPoolWithFunc(4, f, WithPreAlloc(true))`, blocking `Invoke` -- ants has
// no queue: Invoke waits for a free worker), created before the timing;
// "wait" is a sync.WaitGroup the job function marks done, the idiom of its
// README. Usage: go_fast_bench <workload>. Prints one line: name, ns/op,
// count, sum (tab-separated), as the C side does.
package main

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/panjf2000/ants/v2"
)

const (
	burst       = 100_000
	pingpongN   = 10_000
	producers   = 4
	perProducer = 25_000
)

var count, sum atomic.Uint64
var wg sync.WaitGroup

func splitmix64(x *uint64) uint64 {
	*x += 0x9e3779b97f4a7c15
	z := *x
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

func jobNoop(arg any) {
	count.Add(1)
	sum.Add(uint64(arg.(uintptr)))
	wg.Done()
}

func jobWork(arg any) {
	s := uint64(arg.(uintptr))
	var h uint64
	for i := 0; i < 64; i++ {
		h ^= splitmix64(&s)
	}
	count.Add(1)
	sum.Add(h)
	wg.Done()
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go_fast_bench <workload>")
		os.Exit(2)
	}
	name := os.Args[1]
	newPool := func(f func(any)) *ants.PoolWithFunc {
		p, err := ants.NewPoolWithFunc(4, f, ants.WithPreAlloc(true))
		if err != nil {
			panic(err)
		}
		return p
	}
	noop, work := newPool(jobNoop), newPool(jobWork)
	var op func()
	switch name {
	case "burst_noop", "burst_work":
		p := noop
		if name == "burst_work" {
			p = work
		}
		op = func() {
			wg.Add(burst)
			for i := uintptr(0); i < burst; i++ {
				p.Invoke(i + 1)
			}
			wg.Wait()
		}
	case "pingpong":
		op = func() {
			for i := uintptr(0); i < pingpongN; i++ {
				wg.Add(1)
				noop.Invoke(i + 1)
				wg.Wait()
			}
		}
	case "multi_producer":
		op = func() {
			wg.Add(producers * perProducer)
			var prod sync.WaitGroup
			for k := 0; k < producers; k++ {
				prod.Add(1)
				go func(base uintptr) {
					for i := uintptr(0); i < perProducer; i++ {
						noop.Invoke(base + i + 1)
					}
					prod.Done()
				}(uintptr(k * perProducer))
			}
			prod.Wait()
			wg.Wait()
		}
	case "allocs":
		// Heap allocations per job in the steady state: a warm-up burst, then
		// runtime.MemStats.Mallocs over a second one (100 000 jobs).
		burstOnce := func() {
			wg.Add(burst)
			for i := uintptr(0); i < burst; i++ {
				noop.Invoke(i + 1)
			}
			wg.Wait()
		}
		burstOnce()
		var a, b runtime.MemStats
		runtime.ReadMemStats(&a)
		burstOnce()
		runtime.ReadMemStats(&b)
		n := b.Mallocs - a.Mallocs
		fmt.Printf("allocs\t%.3f\t%d\t%d\n", float64(n)/burst, burst, n)
		return
	default:
		fmt.Fprintln(os.Stderr, "unknown workload", name)
		os.Exit(2)
	}
	once := func() {
		count.Store(0)
		sum.Store(0)
		op()
	}
	// Timing as the C side: double the batch past 100 ms, best of five.
	n := 1
	for {
		t := time.Now()
		for i := 0; i < n; i++ {
			once()
		}
		if time.Since(t) > 100*time.Millisecond {
			break
		}
		n *= 2
	}
	best := time.Duration(1<<63 - 1)
	for k := 0; k < 5; k++ {
		t := time.Now()
		for i := 0; i < n; i++ {
			once()
		}
		if d := time.Since(t); d < best {
			best = d
		}
	}
	fmt.Printf("%s\t%.1f\t%d\t%d\n", name, float64(best.Nanoseconds())/float64(n), count.Load(), sum.Load())
}
