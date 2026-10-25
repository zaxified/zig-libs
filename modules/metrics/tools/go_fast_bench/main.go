// SPDX-License-Identifier: MIT

// Fastest-in-the-field side of `zig build bench-metrics`
// (modules/metrics/tools/bench.zig): times VictoriaMetrics/metrics v1.44.1
// (pinned by go.mod/go.sum), the "lightweight alternative to client_golang",
// for the one workload named by the second argument, through its public API
// only. The first argument is the work directory (unused; kept so the argv
// matches go_bench). Prints one line: name, ns/op, result count
// (tab-separated). Workloads as in go_bench, in VictoriaMetrics' own idiom:
//
//	counter_inc   4096 x Counter.Inc on a held counter
//	observe       4096 x PrometheusHistogram.Update (client_golang's default
//	              buckets, via NewPrometheusHistogramExt) on a held histogram
//	counter_vec   4096 x Set.GetOrCreateCounter(`name{method="..",code=".."}`).Inc()
//	              -- labels live in the name; the 20 names are built once, so
//	              the timed path is the lookup by name plus the increment
//	scrape        Set.WritePrometheus of the registry go_bench builds, metadata
//	              (# HELP/# TYPE) on (ExposeMetadata(true)) like the others;
//	              result = number of sample lines (195), since the libraries
//	              format floats and order series differently
//
// Timing matches the Zig side: double the batch until one batch takes over
// 100 ms, then keep the best of five.
package main

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"github.com/VictoriaMetrics/metrics"
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

const nObs = 4096

var methods = []string{"GET", "POST", "PUT", "DELETE"}
var codes = []string{"200", "201", "400", "404", "500"}

// client_golang's DefBuckets, the buckets every side of the bench uses.
var defBuckets = []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10}

func obsValue(k int) float64 { return float64((k*37)%700) / 64.0 }

func sampleLines(b []byte) int {
	n := 0
	start := true
	for _, c := range b {
		if start && c != '#' && c != '\n' {
			n++
		}
		start = c == '\n'
	}
	return n
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go_fast_bench <work dir> <workload>")
		os.Exit(2)
	}
	name := os.Args[2]
	metrics.ExposeMetadata(true)
	s := metrics.NewSet()
	var f func() int
	switch name {
	case "counter_inc":
		c := s.NewCounter("bench_total")
		f = func() int {
			for i := 0; i < nObs; i++ {
				c.Inc()
			}
			return nObs
		}
	case "observe":
		h := s.NewPrometheusHistogramExt("bench_seconds", defBuckets)
		vals := make([]float64, nObs)
		for i := range vals {
			vals[i] = obsValue(i)
		}
		f = func() int {
			for _, v := range vals {
				h.Update(v)
			}
			return nObs
		}
	case "counter_vec":
		var names [20]string
		for i := range names {
			names[i] = fmt.Sprintf(`bench_total{method=%q,code=%q}`, methods[i&3], codes[i>>2])
		}
		f = func() int {
			for i := 0; i < nObs; i++ {
				s.GetOrCreateCounter(names[(i&3)+4*((i>>2)%5)]).Inc()
			}
			return nObs
		}
	case "scrape":
		for mi, m := range methods {
			for ci, c := range codes {
				s.NewCounter(fmt.Sprintf(`http_requests_total{method=%q,code=%q}`, m, c)).Add(1 + (mi*5+ci)*37)
			}
		}
		s.NewGauge("app_in_flight", nil).Set(3)
		for i := 0; i < 6; i++ {
			s.NewGauge(fmt.Sprintf(`app_temp_celsius{room="room%d"}`, i), nil).Set(float64(i) * 0.5)
		}
		for mi, m := range methods {
			h := s.NewPrometheusHistogramExt(fmt.Sprintf(`http_request_duration_seconds{method=%q}`, m), defBuckets)
			for k := 0; k < 100; k++ {
				h.Update(obsValue(mi*100 + k))
			}
		}
		for oi := 0; oi < 8; oi++ {
			h := s.NewPrometheusHistogramExt(fmt.Sprintf(`app_op_seconds{op="op%d"}`, oi), defBuckets)
			for k := 0; k < 100; k++ {
				h.Update(obsValue(oi*100 + k + 7))
			}
		}
		var bb bytes.Buffer
		f = func() int {
			bb.Reset()
			s.WritePrometheus(&bb)
			return sampleLines(bb.Bytes())
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown workload", name)
		os.Exit(2)
	}
	ns, count := timeIt(f)
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
}
