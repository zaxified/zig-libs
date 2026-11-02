// SPDX-License-Identifier: MIT

// Go side of `zig build bench-jsonshape` (modules/jsonshape/tools/bench.zig):
// times github.com/theory/jsonpath v0.12.2 (workload names as they are) and
// github.com/ohler55/ojg v1.28.9 `jp` (names with the prefix `ojg_`) over the
// doc.json and paths.txt the Zig program writes into the directory given as the
// first argument, for the workload named by the second. Prints one line: name,
// ns/op, count (tab-separated). See bench.zig for what each workload does.
//
// Timing matches the Zig side: double the batch until it takes over 100 ms,
// then keep the best of five.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ohler55/ojg/jp"
	"github.com/theory/jsonpath"
)

func measure(f func() uint64) (float64, uint64) {
	n := 1
	var count uint64
	for {
		t := time.Now()
		for i := 0; i < n; i++ {
			count = f()
		}
		if time.Since(t) > 100*time.Millisecond {
			break
		}
		n *= 2
	}
	best := time.Duration(1<<63 - 1)
	for r := 0; r < 5; r++ {
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

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func main() {
	dir, full := os.Args[1], os.Args[2]
	name := strings.TrimPrefix(full, "ojg_")
	useOjg := name != full

	raw, err := os.ReadFile(filepath.Join(dir, "doc.json"))
	if err != nil {
		die("%v", err)
	}
	listing, err := os.ReadFile(filepath.Join(dir, "paths.txt"))
	if err != nil {
		die("%v", err)
	}
	text := ""
	for _, line := range strings.Split(string(listing), "\n") {
		if f := strings.SplitN(line, "\t", 2); len(f) == 2 && f[0] == name {
			text = f[1]
		}
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		die("%v", err)
	}
	runtime.GC()

	var f func() uint64
	switch {
	case name == "doc_parse":
		f = func() uint64 {
			var v any
			if err := json.Unmarshal(raw, &v); err != nil {
				die("%v", err)
			}
			return uint64(len(raw))
		}
	case strings.HasPrefix(name, "compile_") && useOjg:
		f = func() uint64 {
			if _, err := jp.ParseString(text); err != nil {
				die("%v", err)
			}
			return uint64(len(text))
		}
	case strings.HasPrefix(name, "compile_"):
		f = func() uint64 {
			if _, err := jsonpath.Parse(text); err != nil {
				die("%v", err)
			}
			return uint64(len(text))
		}
	case useOjg:
		x, err := jp.ParseString(text)
		if err != nil {
			die("%v", err)
		}
		f = func() uint64 { return uint64(len(x.Get(doc))) }
	case strings.HasPrefix(name, "located_"):
		p := jsonpath.MustParse(text)
		f = func() uint64 {
			var total uint64
			for np := range p.SelectLocated(doc).Paths() {
				total += uint64(len(np.String()))
			}
			return total
		}
	default:
		p := jsonpath.MustParse(text)
		f = func() uint64 { return uint64(len(p.Select(doc))) }
	}
	ns, count := measure(f)
	if useOjg {
		fmt.Fprintln(os.Stderr, "ojg v1.28.9 jp")
	} else {
		fmt.Fprintln(os.Stderr, "theory/jsonpath v0.12.2")
	}
	fmt.Printf("%s\t%.1f\t%d\n", full, ns, count)
}
