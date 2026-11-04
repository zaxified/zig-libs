// SPDX-License-Identifier: MIT

// Go side of `zig build bench-uci` (modules/uci/tools/bench.zig): times
// github.com/digineo/go-uci (MIT, pinned in go.mod) loading the config files
// the Zig program writes into the directory given as the first argument, for
// the workload named by the second (parse_small, parse_large, parse_quoted). Prints one line:
// name, ns/op, result count (tab-separated); the count is the number of
// sections of type "iface" after a load, taken once outside the timed loop.
//
// Timing matches the Zig side: double the batch until it takes over 100 ms,
// then keep the best of five.
package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/digineo/go-uci"
)

func timeIt(f func()) float64 {
	n := 1
	for {
		t := time.Now()
		for i := 0; i < n; i++ {
			f()
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
			f()
		}
		if d := time.Since(t); d < best {
			best = d
		}
	}
	return float64(best.Nanoseconds()) / float64(n)
}

func die(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go_bench <work dir> <workload>")
		os.Exit(2)
	}
	dir, name := os.Args[1], os.Args[2]
	if !strings.HasPrefix(name, "parse_") {
		fmt.Fprintln(os.Stderr, "go-uci has no export of a loaded config: only parse_* workloads")
		os.Exit(2)
	}
	cfg := "small"
	if strings.HasSuffix(name, "_large") {
		cfg = "large"
	} else if strings.HasSuffix(name, "_quoted") {
		cfg = "quoted"
	}
	fmt.Fprintln(os.Stderr, "github.com/digineo/go-uci v0.0.0-20210918132103-37c7b10c14fa")
	t := uci.NewTree(dir)
	if err := t.LoadConfig(cfg, true); err != nil {
		die(err)
	}
	secs, ok := t.GetSections(cfg, "iface")
	if !ok {
		die(fmt.Errorf("config not loaded"))
	}
	count := len(secs)
	ns := timeIt(func() {
		if err := t.LoadConfig(cfg, true); err != nil {
			die(err)
		}
	})
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
}
