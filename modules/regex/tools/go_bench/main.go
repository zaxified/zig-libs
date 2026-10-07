// SPDX-License-Identifier: MIT

// Go side of `zig build bench-regex` (modules/regex/tools/bench.zig): times
// Go's regexp over the workloads and texts that program writes into the
// directory given as the only argument, and prints one line per workload:
// name, ns/op, result count — tab-separated. Standard library only.
//
// Timing matches the Zig side: double the iteration count until one batch
// takes over 100 ms, then keep the best of five batches.
package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go_bench <work dir>")
		os.Exit(2)
	}
	dir := os.Args[1]
	list, err := os.Open(filepath.Join(dir, "workloads.tsv"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer list.Close()
	texts := map[string]string{}
	sc := bufio.NewScanner(list)
	for sc.Scan() {
		f := strings.Split(sc.Text(), "\t")
		if len(f) != 4 {
			fmt.Fprintf(os.Stderr, "bad workload line %q\n", sc.Text())
			os.Exit(1)
		}
		name, mode, pattern, file := f[0], f[1], f[2], f[3]
		s, ok := texts[file]
		if !ok {
			b, err := os.ReadFile(filepath.Join(dir, file))
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			s = string(b)
			texts[file] = s
		}
		re := regexp.MustCompile(pattern)
		var fn func() int
		switch mode {
		case "match":
			fn = func() int {
				if re.MatchString(s) {
					return 1
				}
				return 0
			}
		case "findall":
			fn = func() int { return len(re.FindAllStringIndex(s, -1)) }
		case "findallsub":
			fn = func() int { return len(re.FindAllStringSubmatchIndex(s, -1)) }
		case "submatch":
			fn = func() int { return len(re.FindStringSubmatchIndex(s)) }
		case "compile_submatch":
			fn = func() int { return len(regexp.MustCompile(pattern).FindStringSubmatchIndex(s)) }
		default:
			fmt.Fprintf(os.Stderr, "unknown mode %q\n", mode)
			os.Exit(1)
		}
		ns, count := timeIt(fn)
		fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
