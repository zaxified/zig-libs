// SPDX-License-Identifier: Apache-2.0

// Second Go side of `zig build bench-dataset`: github.com/go-gota/gota v0.12.0
// (Apache-2.0), a Go DataFrame whose Series hold one boxed Element per cell
// (the closest row/boxed-cell table model among the Go libraries). Gota has no
// binary wire format and no row-wise builder with nulls, so only the column
// reads are paired: `col_f64` (price as []float64, summed) and `col_text`
// (name as []string, total byte length). The table is the one described in
// tools/bench.zig, generated from the same formulas.
//
// Prints one line: name, ns/op, result count (tab-separated).
package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/go-gota/gota/dataframe"
	"github.com/go-gota/gota/series"
)

const nrows = 20000

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

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go_bench_gota WORKDIR WORKLOAD")
		os.Exit(2)
	}
	name := os.Args[2]
	fmt.Fprintf(os.Stderr, "Go, github.com/go-gota/gota v0.12.0, %d rows\n", nrows)
	var id []int
	var price []float64
	var names []string
	for k := 0; k < nrows; k++ {
		i := uint64(k)
		id = append(id, k)
		price = append(price, float64(i)*0.25+float64(i%97))
		names = append(names, "item-"+strconv.FormatUint((i*2654435761)%100000, 10))
	}
	df := dataframe.New(
		series.New(id, series.Int, "id"),
		series.New(price, series.Float, "price"),
		series.New(names, series.String, "name"),
	)
	var f func() uint64
	switch name {
	case "col_f64":
		f = func() uint64 {
			var s float64
			for _, v := range df.Col("price").Float() {
				s += v
			}
			return uint64(s)
		}
	case "col_text":
		f = func() uint64 {
			var s uint64
			for _, v := range df.Col("name").Records() {
				s += uint64(len(v))
			}
			return s
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown workload", name)
		os.Exit(2)
	}
	ns, count := timeIt(f)
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
}
