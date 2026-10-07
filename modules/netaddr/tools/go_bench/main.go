// SPDX-License-Identifier: MIT

// Go side of `zig build bench-netaddr` (modules/netaddr/tools/bench.zig):
// times Go's net/netip and go4.org/netipx (pinned by go.mod/go.sum) over the
// inputs that program writes into the directory given as the only argument,
// through their public APIs only. Prints one line per workload: name, ns/op,
// result count — tab-separated.
//
// Timing matches the Zig side: double the iteration count until one batch
// takes over 100 ms, then keep the best of five batches.
package main

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"go4.org/netipx"
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

func lines(dir, name string) []string {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}

func addrs(ss []string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

func prefixes(ss []string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

func report(name string, f func() int) {
	ns, count := timeIt(f)
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go_bench <work dir>")
		os.Exit(2)
	}
	dir := os.Args[1]
	v4 := lines(dir, "v4.txt")
	v6text := lines(dir, "v6.txt")
	v6 := addrs(v6text)
	mixed := addrs(lines(dir, "mixed.txt"))
	pfx := prefixes(lines(dir, "prefixes.txt"))
	probes := addrs(lines(dir, "probes.txt"))
	setPfx := prefixes(lines(dir, "set.txt"))

	report("parse_v4", func() int {
		k := 0
		for _, s := range v4 {
			if _, err := netip.ParseAddr(s); err == nil {
				k++
			}
		}
		return k
	})
	report("parse_v6", func() int {
		k := 0
		for _, s := range v6text {
			if _, err := netip.ParseAddr(s); err == nil {
				k++
			}
		}
		return k
	})
	var buf [64]byte
	report("format_v6", func() int {
		k := 0
		for _, a := range v6 {
			k += len(a.AppendTo(buf[:0]))
		}
		return k
	})
	report("prefix_contains", func() int {
		k := 0
		for i, p := range pfx {
			if p.Contains(probes[i]) {
				k++
			}
		}
		return k
	})
	scratch := make([]netip.Addr, len(mixed))
	report("sort_mixed", func() int {
		copy(scratch, mixed)
		slices.SortFunc(scratch, func(a, b netip.Addr) int { return a.Compare(b) })
		for i, a := range scratch {
			if a.Is6() {
				return i
			}
		}
		return len(scratch)
	})
	report("set_build", func() int {
		var b netipx.IPSetBuilder
		for _, p := range setPfx {
			b.AddPrefix(p)
		}
		s, err := b.IPSet()
		if err != nil {
			panic(err)
		}
		return len(s.Ranges())
	})
	var sb netipx.IPSetBuilder
	for _, p := range setPfx {
		sb.AddPrefix(p)
	}
	set, err := sb.IPSet()
	if err != nil {
		panic(err)
	}
	report("set_contains", func() int {
		k := 0
		for _, a := range probes {
			if set.Contains(a) {
				k++
			}
		}
		return k
	})
}
