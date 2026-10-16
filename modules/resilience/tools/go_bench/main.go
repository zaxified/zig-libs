// SPDX-License-Identifier: MIT
//
// Go side of `zig build bench-resilience` (modules/resilience/tools/bench.zig):
// times the Go libraries the card compares with on the workload named by the
// argument. Prints one line: name, ns/op, user-mode cycles/op (0 without a
// counter; for the threaded rows the counter sees only the timing thread, so
// the Zig side compares those by wall time), the op's count. Workloads:
//
//	gobreaker_pair / failsafe_pair -- a closed breaker's admit + success
//	    report, 1000 times per op (gobreaker TwoStepCircuitBreaker Allow +
//	    done(nil); failsafe-go circuitbreaker TryAcquirePermit + RecordSuccess);
//	*_pair_8t -- the same, 8 goroutines x 100000 on one breaker per op;
//	failsafe_rate_pair -- failsafe-go with a count-based ratio threshold
//	    (WithFailureThresholdRatio(50, 100)), 1000 admit + success;
//	failsafe_bulkhead / failsafe_bulkhead_8t -- TryAcquirePermit +
//	    ReleasePermit, 1000 per op (8 goroutines x 100000);
//	gobreaker_execute -- gobreaker Execute(no-op), 1000 per op (`run` with
//	    a breaker);
//	failsafe_run -- failsafe.With(retry, breaker).Get(no-op), 1000 per op
//	    (`run` with retry + breaker);
//	cenkalti_schedule -- Reset + 10 NextBackOff (randomization 0.5), 1000
//	    schedules per op.
//
// Third-party modules (MIT, BSD-3 bitset) were swept before the first build
// (2026-10-16): no cgo, unsafe, os, net, syscall, exec, linkname or embed in
// the compiled closure; one init() fills a log10 table; reflect only for
// error matching. Built with CGO_ENABLED=0, GOPROXY=off.
package main

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/cenkalti/backoff/v5"
	"github.com/failsafe-go/failsafe-go"
	"github.com/failsafe-go/failsafe-go/bulkhead"
	"github.com/failsafe-go/failsafe-go/circuitbreaker"
	"github.com/failsafe-go/failsafe-go/retrypolicy"
	"github.com/sony/gobreaker/v2"
)

var sink int

func perfOpen() int {
	var attr [16]uint64 // 128 bytes
	attr[0] = 0 | 128<<32
	attr[1] = 0           // PERF_COUNT_HW_CPU_CYCLES
	attr[5] = 1<<5 | 1<<6 // exclude_kernel, exclude_hv
	fd, _, errno := syscall.Syscall6(syscall.SYS_PERF_EVENT_OPEN, uintptr(unsafe.Pointer(&attr[0])), 0, ^uintptr(0), ^uintptr(0), 0, 0)
	if errno != 0 {
		return -1
	}
	return int(fd)
}

func perfRead(fd int) float64 {
	if fd < 0 {
		return 0
	}
	var v uint64
	_, _, errno := syscall.Syscall(syscall.SYS_READ, uintptr(fd), uintptr(unsafe.Pointer(&v)), 8)
	if errno != 0 {
		return 0
	}
	return float64(v)
}

func bench(name string, threaded bool, f func() int) {
	runtime.LockOSThread()
	fd := perfOpen()
	n := 1
	for {
		t := time.Now()
		for i := 0; i < n; i++ {
			sink += f()
		}
		if time.Since(t) > 100*time.Millisecond {
			break
		}
		n *= 2
	}
	best, bestc := time.Duration(1<<63-1), 1e300
	count := 0
	for k := 0; k < 5; k++ {
		t := time.Now()
		c0 := perfRead(fd)
		for i := 0; i < n; i++ {
			count = f()
		}
		c := perfRead(fd) - c0
		if d := time.Since(t); d < best {
			best = d
		}
		if c < bestc {
			bestc = c
		}
	}
	if fd < 0 || threaded {
		bestc = 0 // the counter sees one thread: wall time decides
	}
	_ = name // the label above is for a reader; the driver matches the workload
	fmt.Printf("%s\t%.1f\t%.1f\t%d\n", os.Args[2], float64(best.Nanoseconds())/float64(n), bestc/float64(n), count)
}

const inner = 1000
const threads = 8

// Per goroutine in the threaded rows: long enough that starting an OS thread
// on the Zig side (~10 us) is noise next to the work.
const inner8 = 100_000

// par runs body (inner8 iterations) on 8 goroutines and waits.
func par(body func()) int {
	var wg sync.WaitGroup
	wg.Add(threads)
	for t := 0; t < threads; t++ {
		go func() {
			body()
			wg.Done()
		}()
	}
	wg.Wait()
	return threads * inner8
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go_bench <work dir> <workload>")
		os.Exit(2)
	}
	w := os.Args[2]
	fmt.Fprintln(os.Stderr, runtime.Version(), "gobreaker v2.4.0, failsafe-go v0.9.8, cenkalti/backoff v5.0.3")
	runtime.GOMAXPROCS(threads + 1)

	gb := gobreaker.NewTwoStepCircuitBreaker[any](gobreaker.Settings{Name: "b", Timeout: 30 * time.Second})
	gbx := gobreaker.NewCircuitBreaker[int](gobreaker.Settings{Name: "x", Timeout: 30 * time.Second})
	fcb := circuitbreaker.NewBuilder[any]().WithFailureThreshold(5).WithDelay(30 * time.Second).Build()
	fcr := circuitbreaker.NewBuilder[any]().WithFailureThresholdRatio(50, 100).WithDelay(30 * time.Second).Build()
	fbh := bulkhead.New[any](threads * 2)
	fcbInt := circuitbreaker.NewBuilder[int]().WithFailureThreshold(5).WithDelay(30 * time.Second).Build()
	rp := retrypolicy.NewBuilder[int]().WithMaxRetries(2).WithBackoff(100*time.Millisecond, 30*time.Second).Build()
	exec := failsafe.With[int](rp, fcbInt)

	gbPair := func() {
		for i := 0; i < inner; i++ {
			done, err := gb.Allow()
			if err != nil {
				panic(err)
			}
			done(nil)
		}
	}
	fsPair := func() {
		for i := 0; i < inner; i++ {
			if !fcb.TryAcquirePermit() {
				panic("refused")
			}
			fcb.RecordSuccess()
		}
	}
	fsRate := func() {
		for i := 0; i < inner; i++ {
			if !fcr.TryAcquirePermit() {
				panic("refused")
			}
			fcr.RecordSuccess()
		}
	}
	fsBulk := func() {
		for i := 0; i < inner; i++ {
			if fbh.TryAcquirePermit() {
				fbh.ReleasePermit()
			}
		}
	}
	gbPair8 := func() {
		for i := 0; i < inner8; i++ {
			done, err := gb.Allow()
			if err != nil {
				panic(err)
			}
			done(nil)
		}
	}
	fsPair8 := func() {
		for i := 0; i < inner8; i++ {
			if !fcb.TryAcquirePermit() {
				panic("refused")
			}
			fcb.RecordSuccess()
		}
	}
	fsBulk8 := func() {
		for i := 0; i < inner8; i++ {
			if fbh.TryAcquirePermit() {
				fbh.ReleasePermit()
			}
		}
	}
	noop := func() (int, error) { return 1, nil }

	switch w {
	case "breaker_pair":
		bench("gobreaker_pair", false, func() int { gbPair(); return inner })
	case "breaker_pair_alt":
		bench("failsafe_pair", false, func() int { fsPair(); return inner })
	case "breaker_pair_8t":
		bench("gobreaker_pair_8t", true, func() int { return par(gbPair8) })
	case "breaker_pair_8t_alt":
		bench("failsafe_pair_8t", true, func() int { return par(fsPair8) })
	case "rate_pair":
		bench("failsafe_rate_pair", false, func() int { fsRate(); return inner })
	case "bulkhead_pair":
		bench("failsafe_bulkhead", false, func() int { fsBulk(); return inner })
	case "bulkhead_pair_8t":
		bench("failsafe_bulkhead_8t", true, func() int { return par(fsBulk8) })
	case "run_breaker":
		bench("gobreaker_execute", false, func() int {
			s := 0
			for i := 0; i < inner; i++ {
				v, err := gbx.Execute(noop)
				if err != nil {
					panic(err)
				}
				s += v
			}
			return s
		})
	case "run_retry_breaker":
		bench("failsafe_run", false, func() int {
			s := 0
			for i := 0; i < inner; i++ {
				v, err := exec.Get(noop)
				if err != nil {
					panic(err)
				}
				s += v
			}
			return s
		})
	case "schedule":
		b := backoff.NewExponentialBackOff()
		b.InitialInterval = 100 * time.Millisecond
		b.Multiplier = 2
		b.MaxInterval = 30 * time.Second
		bench("cenkalti_schedule", false, func() int {
			var s time.Duration
			for i := 0; i < inner; i++ {
				b.Reset()
				for k := 0; k < 10; k++ {
					s += b.NextBackOff()
				}
			}
			sink += int(s)
			return inner * 10
		})
	default:
		fmt.Fprintln(os.Stderr, "unknown workload", w)
		os.Exit(2)
	}
}
