// SPDX-License-Identifier: MIT

// Go side of `zig build bench-ratelimit` (modules/ratelimit/tools/bench.zig):
// times golang.org/x/time/rate (pinned by go.mod/go.sum) over the request
// sequence the Zig program writes into the directory given as the first
// argument, for the one workload named by the second, through its public API
// only. Prints one line: name, ns/op, result count (tab-separated). One op =
// the whole sequence once.
//
//	bucket  one rate.Limiter, AllowN(t, 1) at each step's time
//	keyed   what a Go server does per client: a map[string]*rate.Limiter under
//	        a sync.Mutex, a limiter created on first sight of a key, then
//	        AllowN(t, 1). (x/time/rate has no keyed limiter, no key cap, no
//	        LRU and no idle expiry; the Zig module has all four.)
//
// count = requests allowed. Every pass starts one second later than the last
// (the sequence spans 0.15 s and a bucket refills in far less than 1 s), so
// each pass begins from full buckets and answers the same.
//
// Timing matches the Zig side: double the batch until it takes over 100 ms,
// then keep the best of five.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

var sink int

func timeIt(f func() int) (float64, int) {
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
	best := time.Duration(1<<63 - 1)
	count := 0
	for k := 0; k < 5; k++ {
		t := time.Now()
		for i := 0; i < n; i++ {
			count = f()
		}
		if d := time.Since(t); d < best {
			best = d
		}
	}
	return float64(best.Nanoseconds()) / float64(n), count
}

func lines(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go_bench <work dir> <workload>")
		os.Exit(2)
	}
	dir, name := os.Args[1], os.Args[2]
	keys := lines(filepath.Join(dir, "keys.txt"))
	base := time.Unix(1_000_000_000, 0).UTC()
	var idx []int
	var at []time.Duration
	for _, l := range lines(filepath.Join(dir, "seq.tsv")) {
		f := strings.Split(l, "\t")
		i, _ := strconv.Atoi(f[0])
		ns, _ := strconv.ParseInt(f[1], 10, 64)
		idx = append(idx, i)
		at = append(at, time.Duration(ns))
	}
	cfg := strings.Split(lines(filepath.Join(dir, "cfg.txt"))[0], "\t")
	bucketRate, _ := strconv.ParseFloat(cfg[0], 64)
	bucketBurst, _ := strconv.Atoi(cfg[1])
	keyedRate, _ := strconv.ParseFloat(cfg[2], 64)
	keyedBurst, _ := strconv.Atoi(cfg[3])

	pass := time.Duration(0)
	var f func() int
	switch name {
	case "bucket":
		lim := rate.NewLimiter(rate.Limit(bucketRate), bucketBurst)
		f = func() int {
			pass += time.Second
			n := 0
			for _, d := range at {
				if lim.AllowN(base.Add(pass+d), 1) {
					n++
				}
			}
			return n
		}
	case "keyed":
		var mu sync.Mutex
		m := map[string]*rate.Limiter{}
		f = func() int {
			pass += time.Second
			n := 0
			for j, i := range idx {
				mu.Lock()
				l, ok := m[keys[i]]
				if !ok {
					l = rate.NewLimiter(rate.Limit(keyedRate), keyedBurst)
					m[keys[i]] = l
				}
				mu.Unlock()
				if l.AllowN(base.Add(pass+at[j]), 1) {
					n++
				}
			}
			return n
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown workload", name)
		os.Exit(2)
	}
	ns, count := timeIt(f)
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
}
