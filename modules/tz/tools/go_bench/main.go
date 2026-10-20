// SPDX-License-Identifier: MIT

// Go side of `zig build bench-tz` (modules/tz/tools/bench.zig): Go's time package
// over the SAME pinned tzdata tree the module was generated from (the zone files
// are read from the directory named in <work dir>/tzdir.txt and handed to
// time.LoadLocationFromTZData; the host's zoneinfo and Go's embedded copy are
// never used). Standard library only.
//
//	go_bench <work dir> <workload>                  time it: name, ns/op, count
//	go_bench <work dir> <workload> dump <outfile>   write one i64 per input
//
// <work dir>/<workload>.in holds u64 lens[4] followed by the inputs of the four
// zones in order (i64 instants, or 6 x i32 {y,m,d,hh,mm,ss} records for
// local_to_utc).
//
//	utc_to_offset_table / utc_to_offset_footer   time.Unix(t,0).In(loc).Zone() offset
//	local_to_utc                                 time.Date(..., loc).Unix()
//	abbrev                                       the zone name from Zone(), hashed
//
// One op = all four zones' inputs once. Timing matches the other sides: double
// the batch until one batch takes over 100 ms, then the best of five.
package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var zoneNames = [4]string{"Europe/Prague", "America/New_York", "Australia/Sydney", "Asia/Kolkata"}

const (
	kOffset = iota
	kLocal
	kAbbrev
)

var sink uint64

func fail(err error) {
	fmt.Fprintln(os.Stderr, "go_bench:", err)
	os.Exit(1)
}

func hashAbbr(s string) uint64 {
	var h uint64
	for i := 0; i < len(s); i++ {
		h = h*131 + uint64(s[i])
	}
	return h
}

type input struct {
	kind  int
	locs  [4]*time.Location
	times [4][]int64 // instants
	recs  [4][]int32 // local records, 6 per input
}

func (in *input) count(z int) int {
	if in.kind == kLocal {
		return len(in.recs[z]) / 6
	}
	return len(in.times[z])
}

// runZone converts every input of zone z; out, when non-nil, receives one value each.
func (in *input) runZone(z int, out []int64) uint64 {
	var sum uint64
	loc := in.locs[z]
	switch in.kind {
	case kLocal:
		r := in.recs[z]
		for i := 0; i < len(r); i += 6 {
			v := time.Date(int(r[i]), time.Month(r[i+1]), int(r[i+2]), int(r[i+3]), int(r[i+4]), int(r[i+5]), 0, loc).Unix()
			sum += uint64(v)
			if out != nil {
				out[i/6] = v
			}
		}
	case kOffset:
		for i, t := range in.times[z] {
			_, off := time.Unix(t, 0).In(loc).Zone()
			sum += uint64(int64(off))
			if out != nil {
				out[i] = int64(off)
			}
		}
	default:
		for i, t := range in.times[z] {
			name, _ := time.Unix(t, 0).In(loc).Zone()
			h := hashAbbr(name)
			sum += h
			if out != nil {
				out[i] = int64(h)
			}
		}
	}
	return sum
}

func (in *input) op() uint64 {
	var sum uint64
	for z := 0; z < 4; z++ {
		sum += in.runZone(z, nil)
	}
	return sum
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
	if len(os.Args) != 3 && !(len(os.Args) == 5 && os.Args[3] == "dump") {
		fmt.Fprintln(os.Stderr, "usage: go_bench <work dir> <workload> [dump <outfile>]")
		os.Exit(2)
	}
	dir, name := os.Args[1], os.Args[2]
	in := &input{}
	switch name {
	case "utc_to_offset_table", "utc_to_offset_footer":
		in.kind = kOffset
	case "local_to_utc":
		in.kind = kLocal
	case "abbrev":
		in.kind = kAbbrev
	default:
		fail(fmt.Errorf("unknown workload %q", name))
	}

	tzb, err := os.ReadFile(filepath.Join(dir, "tzdir.txt"))
	if err != nil {
		fail(err)
	}
	tzdir := strings.TrimSpace(string(tzb))
	for z, zn := range zoneNames {
		b, err := os.ReadFile(filepath.Join(tzdir, zn))
		if err != nil {
			fail(err)
		}
		loc, err := time.LoadLocationFromTZData(zn, b)
		if err != nil {
			fail(err)
		}
		in.locs[z] = loc
	}

	raw, err := os.ReadFile(filepath.Join(dir, name+".in"))
	if err != nil {
		fail(err)
	}
	var lens [4]uint64
	for z := range lens {
		lens[z] = binary.LittleEndian.Uint64(raw[8*z:])
	}
	p := raw[32:]
	for z := 0; z < 4; z++ {
		n := int(lens[z])
		if in.kind == kLocal {
			r := make([]int32, 6*n)
			for i := range r {
				r[i] = int32(binary.LittleEndian.Uint32(p[4*i:]))
			}
			in.recs[z] = r
			p = p[24*n:]
		} else {
			t := make([]int64, n)
			for i := range t {
				t[i] = int64(binary.LittleEndian.Uint64(p[8*i:]))
			}
			in.times[z] = t
			p = p[8*n:]
		}
	}

	if len(os.Args) == 5 {
		var all []byte
		for z := 0; z < 4; z++ {
			out := make([]int64, in.count(z))
			in.runZone(z, out)
			for _, v := range out {
				all = binary.LittleEndian.AppendUint64(all, uint64(v))
			}
		}
		if err := os.WriteFile(os.Args[4], all, 0o644); err != nil {
			fail(err)
		}
		return
	}

	ns, count := timeIt(in.op)
	fmt.Fprintf(os.Stderr, "%s time (std only; LoadLocationFromTZData from TZDIR=%s)\n", runtime.Version(), tzdir)
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
}
