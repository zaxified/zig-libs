// SPDX-License-Identifier: MIT

// Go side of `zig build bench-ini` (modules/ini/tools/bench.zig): times
// gopkg.in/ini.v1 v1.67.3 over the texts the Zig program writes into the
// directory given as the first argument, for the workload named by the second.
// Prints one line: name, ns/op, result count (tab-separated). See bench.zig for
// what each workload does and how the count is formed.
//
// Timing matches the Zig side: double the batch until it takes over 100 ms,
// then keep the best of five.
package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/ini.v1"
)

var sink uint64

func timeIt(f func() uint64) (float64, uint64) {
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
	var count uint64
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

func die(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

type probe struct{ section, key, miss string }

func readProbes(path string) []probe {
	b, err := os.ReadFile(path)
	if err != nil {
		die(err)
	}
	var out []probe
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		f := strings.Split(l, "\t")
		out = append(out, probe{f[0], f[1], f[2]})
	}
	return out
}

func load(data []byte) *ini.File {
	// The same reading as the other sides: see bench.zig.
	f := ini.Empty(ini.LoadOptions{
		IgnoreInlineComment:     true,
		IgnoreContinuation:      true,
		PreserveSurroundedQuote: true,
		KeyValueDelimiters:      "=",
	})
	f.BlockMode = false
	if err := f.Append(data); err != nil {
		die(err)
	}
	return f
}

func parseProbes(data []byte, probes []probe) uint64 {
	f := load(data)
	var t uint64
	for _, p := range probes {
		k, err := f.Section(p.section).GetKey(p.key)
		if err != nil {
			die(err)
		}
		t += uint64(len(k.Value()))
	}
	return t
}

func main() {
	dir, name := os.Args[1], os.Args[2]
	read := func(n string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			die(err)
		}
		return b
	}
	small, large := read("small.ini"), read("large.ini")
	probes := readProbes(filepath.Join(dir, "probes.txt"))
	smallProbes := readProbes(filepath.Join(dir, "small_probes.txt"))
	ini.PrettyFormat = false
	ini.PrettyEqual = false
	doc := load(large)
	var buf bytes.Buffer

	var f func() uint64
	switch name {
	case "parse_small":
		f = func() uint64 { return parseProbes(small, smallProbes) }
	case "parse_large":
		f = func() uint64 { return parseProbes(large, probes[:16]) }
	case "get_hit":
		f = func() uint64 {
			var t uint64
			for _, p := range probes {
				k, err := doc.Section(p.section).GetKey(p.key)
				if err != nil {
					die(err)
				}
				t += uint64(len(k.Value()))
			}
			return t
		}
	case "get_miss":
		f = func() uint64 {
			var t uint64
			for _, p := range probes {
				if _, err := doc.Section(p.section).GetKey(p.miss); err != nil {
					t++
				}
			}
			return t
		}
	case "write":
		f = func() uint64 {
			buf.Reset()
			if _, err := doc.WriteTo(&buf); err != nil {
				die(err)
			}
			return uint64(bytes.Count(buf.Bytes(), []byte("=")))
		}
	case "edit":
		f = func() uint64 {
			d := load(large)
			for _, p := range probes[:16] {
				d.Section(p.section).Key(p.key).SetValue("edited value")
			}
			buf.Reset()
			if _, err := d.WriteTo(&buf); err != nil {
				die(err)
			}
			return uint64(bytes.Count(buf.Bytes(), []byte("=")))
		}
	default:
		die(fmt.Errorf("no workload %q", name))
	}
	ns, count := timeIt(f)
	fmt.Fprintln(os.Stderr, "gopkg.in/ini.v1 v1.67.3")
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
}
