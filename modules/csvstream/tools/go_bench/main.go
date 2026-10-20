// SPDX-License-Identifier: MIT

// Go side of `zig build bench-csvstream` (modules/csvstream/tools/bench.zig):
// Go's encoding/csv over the SAME generated files the Zig side reads. Standard
// library only.
//
//	go_bench <work dir> <workload>           time it: name, ns/op, count (stderr: banner)
//	go_bench <work dir> <workload> check     print "records fields checksum" once
//
// Reader workloads (ReuseRecord = true, LazyQuotes = true, FieldsPerRecord = -1,
// every record read to the end):
//
//	narrow, wide, quoted, multiline   os.File -> csv.NewReader (file-backed)
//	mem_narrow                        bytes.Reader over the file read into RAM first
//
// Every field is "touched" by the same checksum as the Zig side: per field
// h = (h ^ len) * P, then (h ^ first byte) * P and (h ^ last byte) * P when the
// field is not empty; per record h = (h ^ field count) * P. The checksum is the
// op's count; the Zig side must produce the same value.
//
//	write   1000-record pool (read from pool-v1.csv once, not timed) cycled to
//	        1 000 000 records through csv.Writer into a pre-grown bytes.Buffer
//	        (LF terminator); count = bytes written.
package main

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const prime = 0x100000001b3

const writeRecords = 1_000_000

var sink uint64

func fail(err error) {
	fmt.Fprintln(os.Stderr, "go_bench:", err)
	os.Exit(1)
}

var files = map[string]string{
	"narrow":     "narrow-v1.csv",
	"wide":       "wide-v1.csv",
	"quoted":     "quoted-v1.csv",
	"multiline":  "multiline-v1.csv",
	"mem_narrow": "narrow-v1.csv",
	"write":      "pool-v1.csv",
}

type result struct{ records, fields, h uint64 }

func scan(r io.Reader) result {
	cr := csv.NewReader(r)
	cr.ReuseRecord = true
	cr.LazyQuotes = true
	cr.FieldsPerRecord = -1
	var res result
	h := uint64(0xcbf29ce484222325)
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			fail(err)
		}
		for _, f := range rec {
			h = (h ^ uint64(len(f))) * prime
			if len(f) > 0 {
				h = (h ^ uint64(f[0])) * prime
				h = (h ^ uint64(f[len(f)-1])) * prime
			}
		}
		h = (h ^ uint64(len(rec))) * prime
		res.records++
		res.fields += uint64(len(rec))
	}
	res.h = h
	return res
}

func readPool(path string) [][]string {
	f, err := os.Open(path)
	if err != nil {
		fail(err)
	}
	defer f.Close()
	cr := csv.NewReader(f)
	cr.LazyQuotes = true
	cr.FieldsPerRecord = -1
	recs, err := cr.ReadAll()
	if err != nil {
		fail(err)
	}
	return recs
}

func writeAll(buf *bytes.Buffer, pool [][]string) {
	buf.Reset()
	w := csv.NewWriter(buf)
	for i := 0; i < writeRecords; i++ {
		if err := w.Write(pool[i%len(pool)]); err != nil {
			fail(err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		fail(err)
	}
}

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

func main() {
	if len(os.Args) != 3 && !(len(os.Args) == 4 && os.Args[3] == "check") {
		fmt.Fprintln(os.Stderr, "usage: go_bench <work dir> <workload> [check]")
		os.Exit(2)
	}
	dir, name := os.Args[1], os.Args[2]
	check := len(os.Args) == 4
	file, ok := files[name]
	if !ok {
		fail(fmt.Errorf("unknown workload %q", name))
	}
	path := filepath.Join(dir, file)

	var op func() uint64
	switch name {
	case "write":
		pool := readPool(path)
		var buf bytes.Buffer
		writeAll(&buf, pool) // size the buffer once
		if check {
			hh := fnv.New64a()
			hh.Write(buf.Bytes())
			fmt.Printf("%d %d %d\n", writeRecords, buf.Len(), hh.Sum64())
			return
		}
		op = func() uint64 {
			writeAll(&buf, pool)
			return uint64(buf.Len())
		}
	case "mem_narrow":
		data, err := os.ReadFile(path)
		if err != nil {
			fail(err)
		}
		if check {
			r := scan(bytes.NewReader(data))
			fmt.Printf("%d %d %d\n", r.records, r.fields, r.h)
			return
		}
		op = func() uint64 { return scan(bytes.NewReader(data)).h }
	default:
		fileOp := func() result {
			f, err := os.Open(path)
			if err != nil {
				fail(err)
			}
			defer f.Close()
			return scan(f)
		}
		if check {
			r := fileOp()
			fmt.Printf("%d %d %d\n", r.records, r.fields, r.h)
			return
		}
		op = func() uint64 { return fileOp().h }
	}
	ns, count := timeIt(op)
	fmt.Fprintf(os.Stderr, "%s encoding/csv (ReuseRecord, LazyQuotes, FieldsPerRecord=-1; std only)\n", runtime.Version())
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
}
