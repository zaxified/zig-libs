// SPDX-License-Identifier: MIT

// Go side of `zig build bench-filestore` (modules/filestore/tools/bench.zig):
// times peterbourgon/diskv v3.0.0 (pinned by go.mod/go.sum) through its public
// API only, over the workload named by the second argument, in a store under
// the first argument (the Zig side's work directory, on the real disk). Prints
// one line: name, ns/op, count (tab-separated). One op = 16 records of 1 KiB
// (keys k00..k15), except `keys` (one walk over 1,000 records).
//
// diskv is configured for its ATOMIC mode (TempDir on the same filesystem,
// diskv.go:79-84): a temp file, chmod, optional fsync, rename. It never
// fsyncs a directory (diskv.go:228-287), so its strongest level equals the
// Zig side's `durability = .data`:
//
//	put_none   Write (no fsync)                         = ours .none
//	put_data   WriteStream(..., sync = true)             = ours .data
//	put_full   WriteStream(..., sync = true) again: diskv has nothing stronger;
//	           the Zig row adds the directory fsync (info only, not a verdict)
//	get        Read of 16 existing records (no cache: CacheSizeMax 0)
//	has        Has of 16 existing records
//	keys       Keys(nil) drained, 1,000 records
//
// count = bytes read (get), records found (has, keys) or bytes written (puts).
// Timing matches the Zig side: double the batch until one batch takes over
// 100 ms, then keep the best of five.
package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/peterbourgon/diskv/v3"
)

const nRec = 16
const recLen = 1024
const nKeys = 1000

func timeIt(once func() uint64) (float64, uint64) {
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
	var count uint64
	for r := 0; r < 5; r++ {
		t := time.Now()
		for i := 0; i < n; i++ {
			count = once()
		}
		if d := time.Since(t); d < best {
			best = d
		}
	}
	return float64(best.Nanoseconds()) / float64(n), count
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go_bench <work dir> <workload>")
		os.Exit(2)
	}
	work, name := os.Args[1], os.Args[2]
	base := filepath.Join(work, "diskv-"+name)
	must(os.RemoveAll(base))
	must(os.RemoveAll(base + "-tmp"))
	d := diskv.New(diskv.Options{BasePath: base, TempDir: base + "-tmp"})
	val := bytes.Repeat([]byte{'v'}, recLen)
	keys := make([]string, nRec)
	for i := range keys {
		keys[i] = fmt.Sprintf("k%02d", i)
	}
	put := func(sync bool) func() uint64 {
		return func() uint64 {
			var sum uint64
			for _, k := range keys {
				must(d.WriteStream(k, bytes.NewReader(val), sync))
				sum += recLen
			}
			return sum
		}
	}
	var once func() uint64
	switch name {
	case "put_none":
		once = put(false)
	case "put_data", "put_full":
		once = put(true)
	case "get":
		put(false)()
		once = func() uint64 {
			var sum uint64
			for _, k := range keys {
				b, err := d.Read(k)
				must(err)
				sum += uint64(len(b))
			}
			return sum
		}
	case "has":
		put(false)()
		once = func() uint64 {
			var n uint64
			for _, k := range keys {
				if d.Has(k) {
					n++
				}
			}
			return n
		}
	case "keys":
		for i := 0; i < nKeys; i++ {
			must(d.Write(fmt.Sprintf("key%04d", i), val[:16]))
		}
		once = func() uint64 {
			var n uint64
			for range d.Keys(nil) {
				n++
			}
			return n
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown workload", name)
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, "peterbourgon/diskv v3.0.0 (TempDir atomic mode), go", "runtime")
	ns, count := timeIt(once)
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
	must(os.RemoveAll(base))
	must(os.RemoveAll(base + "-tmp"))
}
