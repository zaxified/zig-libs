// SPDX-License-Identifier: MIT

// Go side of `zig build bench-ramcache` (modules/ramcache/tools/bench.zig):
// times maypok86/otter v2.3.0 (pinned by go.mod/go.sum), through its public API
// only, on the workload named by the second argument. The first argument (the
// Zig program's work directory) is accepted for symmetry with the other
// comparative benchmarks and unused: every workload is generated here, from the
// same splitmix64 stream and key names as the Zig side. Prints one line: name,
// ns/op, result count (tab-separated). One op = one pass (see passOps).
//
//	get_hit      8000 keys preloaded into a 10000-entry cache; GetIfPresent round-robin
//	get_miss     the same cache; GetIfPresent of keys that were never stored
//	put_update   the same cache; Set over resident keys, round-robin
//	put_evict    a full 10000-entry cache; Set of a stream of fresh keys (every Set evicts)
//	zipf_mixed   100000-key zipf(s=1.0) trace over a 10000-entry cache: 90 % of
//	             the ops are a lookup that stores on a miss, 10 % an unconditional Set
//	ttl_get_hit  get_hit with ExpiryWriting(1 h) (otter reads its clock per op)
//	map_baseline a plain Go map lookup round-robin (info only, not in the verdict)
//
// count = hits + value bytes returned + misses for the get rows, bytes stored
// for the Set rows, plus (where the contents are deterministic) the number of
// entries resident afterwards; zipf_mixed's count is its hit total and is only
// printed, not compared (admission details differ).
//
// otter does its maintenance (policy bookkeeping, eviction) asynchronously, in
// goroutines, with buffers drained later (Options.Executor defaults to
// goroutines; cache_impl.go: scheduleDrainBuffers / afterWrite). Left as
// shipped. To make the timed window like-for-like, Cache.CleanUp (cache.go:391,
// "performs any pending maintenance") runs before the clock starts and again
// before it stops, so every drain the batch triggered is finished inside the
// measurement, while the parallelism otter gets from its goroutines still
// counts in its favour.
//
// Timing matches the Zig side: double the batch until one batch takes over
// 100 ms, then keep the best of five.
package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/maypok86/otter/v2"
)

const (
	capacity     = 10_000
	preload      = 8_000 // below capacity so no hash imbalance can evict on the Zig side's shards
	passOps      = 10_000
	valueLen     = 64
	freshKeys    = 1 << 20
	zipfUniverse = 100_000
	zipfOps      = 100_000
	zipfSeed     = 0x853C49E6748FEA9B
)

var sink int

func timeIt(f func() int, settle func()) (float64, int) {
	batch := func(n int) time.Duration {
		settle()
		t := time.Now()
		for i := 0; i < n; i++ {
			sink += f()
		}
		settle()
		return time.Since(t)
	}
	n := 1
	for {
		if batch(n) > 100*time.Millisecond {
			break
		}
		n *= 2
	}
	best := time.Duration(1<<63 - 1)
	for k := 0; k < 5; k++ {
		if d := batch(n); d < best {
			best = d
		}
	}
	count := f()
	return float64(best.Nanoseconds()) / float64(n), count
}

func splitmix(s *uint64) uint64 {
	*s += 0x9E3779B97F4A7C15
	z := *s
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}

func keys(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = prefix + strconv.Itoa(i)
	}
	return out
}

func newCache(ttl bool) *otter.Cache[string, []byte] {
	o := &otter.Options[string, []byte]{MaximumSize: capacity}
	if ttl {
		o.ExpiryCalculator = otter.ExpiryWriting[string, []byte](time.Hour)
	}
	return otter.Must(o)
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go_bench <work dir> <workload>")
		os.Exit(2)
	}
	name := os.Args[2]

	value := make([]byte, valueLen)
	for i := range value {
		value[i] = byte('a' + i%26)
	}
	hot := keys("k", preload)

	var (
		f      func() int
		extra  func() int
		settle = func() {}
	)

	// getPass: passOps lookups round-robin over ks; the count mixes hits,
	// returned bytes and misses so a wrong hit count cannot cancel out.
	getPass := func(c *otter.Cache[string, []byte], ks []string) func() int {
		return func() int {
			hits, bytes, misses := 0, 0, 0
			for i := 0; i < passOps; i++ {
				if v, ok := c.GetIfPresent(ks[i%len(ks)]); ok {
					hits++
					bytes += len(v)
				} else {
					misses++
				}
			}
			return hits + bytes + misses
		}
	}
	preloaded := func(ttl bool) *otter.Cache[string, []byte] {
		c := newCache(ttl)
		for _, k := range hot {
			c.Set(k, value)
		}
		c.CleanUp()
		settle = c.CleanUp
		extra = func() int { c.CleanUp(); return c.EstimatedSize() }
		return c
	}

	switch name {
	case "get_hit":
		f = getPass(preloaded(false), hot)
	case "ttl_get_hit":
		f = getPass(preloaded(true), hot)
	case "get_miss":
		f = getPass(preloaded(false), keys("m", passOps))
	case "put_update":
		c := preloaded(false)
		f = func() int {
			for i := 0; i < passOps; i++ {
				c.Set(hot[i%len(hot)], value)
			}
			return passOps * valueLen
		}
	case "put_evict":
		c := newCache(false)
		for _, k := range keys("w", capacity) {
			c.Set(k, value)
		}
		c.CleanUp()
		settle = c.CleanUp
		fresh := keys("f", freshKeys)
		pos := 0
		f = func() int {
			for i := 0; i < passOps; i++ {
				c.Set(fresh[pos], value)
				pos = (pos + 1) & (freshKeys - 1)
			}
			return passOps * valueLen
		}
	case "zipf_mixed":
		cdf := make([]float64, zipfUniverse)
		total := 0.0
		for i := range cdf {
			total += 1.0 / float64(i+1)
			cdf[i] = total
		}
		ids := make([]int, zipfOps)
		writes := make([]bool, zipfOps)
		state := uint64(zipfSeed)
		for i := range ids {
			u := float64(splitmix(&state)>>11) * (1.0 / 9007199254740992.0) * total
			lo, hi := 0, zipfUniverse-1
			for lo < hi {
				mid := (lo + hi) / 2
				if cdf[mid] < u {
					lo = mid + 1
				} else {
					hi = mid
				}
			}
			ids[i] = lo
			writes[i] = splitmix(&state)%10 == 0
		}
		zk := keys("z", zipfUniverse)
		c := newCache(false)
		settle = c.CleanUp
		f = func() int {
			hits := 0
			for i, id := range ids {
				k := zk[id]
				if writes[i] {
					c.Set(k, value)
				} else if _, ok := c.GetIfPresent(k); ok {
					hits++
				} else {
					c.Set(k, value)
				}
			}
			return hits
		}
	case "map_baseline":
		m := make(map[string][]byte, preload)
		for _, k := range hot {
			m[k] = value
		}
		f = func() int {
			hits, bytes, misses := 0, 0, 0
			for i := 0; i < passOps; i++ {
				if v, ok := m[hot[i%len(hot)]]; ok {
					hits++
					bytes += len(v)
				} else {
					misses++
				}
			}
			return hits + bytes + misses
		}
		extra = func() int { return len(m) }
	default:
		fmt.Fprintln(os.Stderr, "unknown workload", name)
		os.Exit(2)
	}

	ns, count := timeIt(f, settle)
	if extra != nil {
		count += extra()
	}
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
}
