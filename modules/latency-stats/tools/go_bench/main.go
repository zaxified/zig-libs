// SPDX-License-Identifier: MIT
//
// Go side of `zig build bench-latency-stats` (modules/latency-stats/tools/bench.zig):
// github.com/HdrHistogram/hdrhistogram-go v1.4.0 (MIT) doing the same work as
// c_bench/foreign_bench.c; the workload list and what one op does are in the C
// file's header. Config: lowest 1, highest 3.6e12, 3 significant figures.
//
//	go_bench <work dir> <workload>     name \t ns/op \t count
package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"time"

	hdr "github.com/HdrHistogram/hdrhistogram-go"
)

const highest = 3_600_000_000_000
const interval = 1_000_000

var sink uint64

func main() {
	if len(os.Args) != 3 {
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1] + "/values.bin")
	if err != nil {
		os.Exit(3)
	}
	vals := make([]int64, len(raw)/8)
	for i := range vals {
		vals[i] = int64(binary.LittleEndian.Uint64(raw[i*8:]))
	}
	h := hdr.New(1, highest, 3)
	src := hdr.New(1, highest, 3)
	for _, v := range vals {
		_ = src.RecordValue(v)
	}
	name := os.Args[2]
	if name == "interop" {
		// ours.b64 (our encodeCompressed, base64) must decode here to exactly
		// `src`; our decoder reads go.b64, what this library encodes from `src`.
		text, err := os.ReadFile(os.Args[1] + "/ours.b64")
		if err != nil {
			os.Exit(3)
		}
		d, err := hdr.Decode(text)
		if err != nil {
			fmt.Fprintln(os.Stderr, "hdrhistogram-go refused our compressed histogram:", err)
			os.Exit(1)
		}
		if !d.Equals(src) || d.TotalCount() != src.TotalCount() || d.Max() != src.Max() || d.Min() != src.Min() {
			fmt.Fprintln(os.Stderr, "hdrhistogram-go decoded our histogram to something else")
			os.Exit(1)
		}
		enc, err := src.Encode(hdr.V2CompressedEncodingCookieBase)
		if err != nil {
			os.Exit(4)
		}
		_ = os.WriteFile(os.Args[1]+"/go.b64", enc, 0o644)
		fmt.Fprintln(os.Stderr, "hdrhistogram-go v1.4.0 interop ok")
		return
	}
	var op func() uint64
	switch name {
	case "record":
		op = func() uint64 {
			h.Reset()
			for _, v := range vals {
				_ = h.RecordValue(v)
			}
			return uint64(h.TotalCount())
		}
	case "record_corrected":
		op = func() uint64 {
			h.Reset()
			for _, v := range vals {
				_ = h.RecordCorrectedValue(v, interval)
			}
			return uint64(h.TotalCount())
		}
	case "percentiles":
		op = func() uint64 {
			var sum uint64
			for j := 0; j < 1000; j++ {
				sum += uint64(src.ValueAtQuantile((100.0*float64(j) + 0.7) / 1000.0))
			}
			return sum
		}
	case "merge":
		op = func() uint64 {
			h.Reset()
			_ = h.RecordValue(1)
			h.Merge(src)
			return uint64(h.TotalCount())
		}
	case "merge_empty":
		op = func() uint64 {
			h.Reset()
			h.Merge(src)
			return uint64(h.TotalCount())
		}
	case "mean_stddev":
		op = func() uint64 { return uint64(src.Mean()) + uint64(src.StdDev()) }
	default:
		os.Exit(5)
	}
	n := 1
	for {
		t := time.Now()
		for i := 0; i < n; i++ {
			sink += op()
		}
		if time.Since(t) > 100*time.Millisecond {
			break
		}
		n *= 2
	}
	best := 1e300
	var count uint64
	for r := 0; r < 5; r++ {
		t := time.Now()
		for i := 0; i < n; i++ {
			count = op()
		}
		d := float64(time.Since(t).Nanoseconds()) / float64(n)
		if d < best {
			best = d
		}
	}
	fmt.Fprintln(os.Stderr, "hdrhistogram-go v1.4.0 (Go 1.26)")
	fmt.Printf("%s\t%.3f\t%d\n", name, best, count)
}
