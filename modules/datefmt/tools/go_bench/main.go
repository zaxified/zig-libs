// SPDX-License-Identifier: MIT

// Go side of `zig build bench-datefmt` (modules/datefmt/tools/bench.zig): times
// Go's standard `time` package over the timestamps the Zig program writes into
// the directory given as the first argument, for the one workload named by the
// second. Prints one line: name, ns/op, result count (tab-separated). One op =
// every timestamp once. Standard library only.
//
//	fmt_imf      time.Unix(s,0).UTC().Format(http.TimeFormat)
//	fmt_rfc3339  ... .Format(time.RFC3339)
//	parse_imf    time.Parse(http.TimeFormat, s).Unix()
//	parse_rfc    time.Parse(time.RFC3339, s).Unix()      (Z, whole seconds)
//	parse_rfcns  time.Parse(time.RFC3339, s)             (fraction + offset)
//	fmt_rfc3339_tokens  ... .Format("2006-01-02T15:04:05Z")  (same text as
//	             fmt_rfc3339, a layout Go does not special-case)
//	*_layout, *_canned, parse_rfc3339_parts  the Go side of the row they
//	             extend (fmt_rfc3339_layout: of fmt_rfc3339_tokens); the Zig
//	             side uses a precompiled layout or a canned function there
//
// Timing matches the Zig side: double the batch until it takes over 100 ms,
// then keep the best of five.
package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
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

func sum(s string) int {
	t := 0
	for i := 0; i < len(s); i++ {
		t += int(s[i])
	}
	return t
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go_bench <work dir> <workload>")
		os.Exit(2)
	}
	dir, name := os.Args[1], os.Args[2]
	var unix []int64
	for _, l := range lines(filepath.Join(dir, "unix.txt")) {
		v, _ := strconv.ParseInt(l, 10, 64)
		unix = append(unix, v)
	}
	imf := lines(filepath.Join(dir, "imf.txt"))
	rfc := lines(filepath.Join(dir, "rfc.txt"))
	rfcns := lines(filepath.Join(dir, "rfcns.txt"))

	var f func() int
	switch name {
	case "fmt_imf", "fmt_imf_layout", "fmt_imf_canned":
		f = func() int {
			t := 0
			for _, u := range unix {
				t += sum(time.Unix(u, 0).UTC().Format(http.TimeFormat))
			}
			return t
		}
	case "fmt_rfc3339_tokens", "fmt_rfc3339_layout":
		f = func() int {
			t := 0
			for _, u := range unix {
				t += sum(time.Unix(u, 0).UTC().Format("2006-01-02T15:04:05Z"))
			}
			return t
		}
	case "fmt_rfc3339":
		f = func() int {
			t := 0
			for _, u := range unix {
				t += sum(time.Unix(u, 0).UTC().Format(time.RFC3339))
			}
			return t
		}
	case "parse_imf", "parse_imf_layout", "parse_imf_canned":
		f = func() int {
			t := 0
			for _, s := range imf {
				v, err := time.Parse(http.TimeFormat, s)
				if err != nil {
					panic(err)
				}
				t += int(v.Unix())
			}
			return t
		}
	case "parse_rfc3339":
		f = func() int {
			t := 0
			for _, s := range rfc {
				v, err := time.Parse(time.RFC3339, s)
				if err != nil {
					panic(err)
				}
				t += int(v.Unix())
			}
			return t
		}
	case "parse_rfc3339_frac", "parse_rfc3339_parts":
		f = func() int {
			t := 0
			for _, s := range rfcns {
				v, err := time.Parse(time.RFC3339, s)
				if err != nil {
					panic(err)
				}
				t += int(v.Unix()) + v.Nanosecond()
			}
			return t
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown workload", name)
		os.Exit(2)
	}
	ns, count := timeIt(f)
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
}
