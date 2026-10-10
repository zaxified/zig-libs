// SPDX-License-Identifier: MIT

// Go side of `zig build bench-metrics` (modules/metrics/tools/bench.zig): times
// prometheus/client_golang v1.24.1 (pinned by go.mod/go.sum) for the one
// workload named by the second argument, through its public API only. The
// first argument is the work directory the Zig program writes the request
// bytes of the `serve_*` workloads into. Prints one line: name, ns/op, result
// count (tab-separated). One op = what the workload below says.
//
//	counter_inc   4096 x Counter.Inc on a held counter
//	observe       4096 x Histogram.Observe (default buckets) on a held histogram
//	counter_vec   4096 x CounterVec.WithLabelValues(method, code).Inc()
//	scrape        promhttp.HandlerFor(registry) answering one GET /metrics into
//	              a httptest.ResponseRecorder; the registry holds 5 families,
//	              20+1+6 counter/gauge series and 12 histogram series
//	serve_plain   http.ReadRequest + a trivial handler into a buffer (16 requests)
//	serve_metrics  the same with promhttp.InstrumentHandlerInFlight +
//	              InstrumentHandlerCounter({code,method}) + InstrumentHandlerDuration({method})
//
// Timing matches the Zig side: double the batch until one batch takes over
// 100 ms, then keep the best of five.
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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

type wire struct {
	h      http.Header
	buf    bytes.Buffer
	status int
}

func (w *wire) Header() http.Header { return w.h }
func (w *wire) WriteHeader(code int) {
	if w.status != 0 {
		return
	}
	w.status = code
	fmt.Fprintf(&w.buf, "HTTP/1.1 %d %s\r\n", code, http.StatusText(code))
	w.h.Write(&w.buf)
	w.buf.WriteString("\r\n")
}
func (w *wire) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.buf.Write(p)
}

const nObs = 4096

var methods = []string{"GET", "POST", "PUT", "DELETE"}
var codes = []string{"200", "201", "400", "404", "500"}

func obsValue(k int) float64 { return float64((k*37)%700) / 64.0 }

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go_bench <work dir> <workload>")
		os.Exit(2)
	}
	dir, name := os.Args[1], os.Args[2]
	var f func() int
	switch name {
	case "counter_inc":
		c := prometheus.NewCounter(prometheus.CounterOpts{Name: "bench_total", Help: "bench"})
		f = func() int {
			for i := 0; i < nObs; i++ {
				c.Inc()
			}
			return nObs
		}
	case "observe":
		h := prometheus.NewHistogram(prometheus.HistogramOpts{Name: "bench_seconds", Help: "bench", Buckets: prometheus.DefBuckets})
		vals := make([]float64, nObs)
		for i := range vals {
			vals[i] = obsValue(i)
		}
		f = func() int {
			for _, v := range vals {
				h.Observe(v)
			}
			return nObs
		}
	case "counter_vec":
		v := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "bench_total", Help: "bench"}, []string{"method", "code"})
		f = func() int {
			for i := 0; i < nObs; i++ {
				v.WithLabelValues(methods[i&3], codes[(i>>2)%5]).Inc()
			}
			return nObs
		}
	case "scrape":
		reg := prometheus.NewRegistry()
		req := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "http_requests_total", Help: "Total HTTP requests served."}, []string{"method", "code"})
		g := prometheus.NewGauge(prometheus.GaugeOpts{Name: "app_in_flight", Help: "Requests in flight."})
		temp := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "app_temp_celsius", Help: "Room temperature."}, []string{"room"})
		dur := prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "http_request_duration_seconds", Help: "Request latency.", Buckets: prometheus.DefBuckets}, []string{"method"})
		op := prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "app_op_seconds", Help: "Operation latency.", Buckets: prometheus.DefBuckets}, []string{"op"})
		reg.MustRegister(req, g, temp, dur, op)
		for mi, m := range methods {
			for ci, c := range codes {
				req.WithLabelValues(m, c).Add(float64(1 + (mi*5+ci)*37))
			}
		}
		g.Set(3)
		for i := 0; i < 6; i++ {
			temp.WithLabelValues(fmt.Sprintf("room%d", i)).Set(float64(i) * 0.5)
		}
		for mi, m := range methods {
			for k := 0; k < 100; k++ {
				dur.WithLabelValues(m).Observe(obsValue(mi*100 + k))
			}
		}
		for oi := 0; oi < 8; oi++ {
			for k := 0; k < 100; k++ {
				op.WithLabelValues(fmt.Sprintf("op%d", oi)).Observe(obsValue(oi*100 + k + 7))
			}
		}
		h := promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
		f = func() int {
			rec := httptest.NewRecorder()
			r, _ := http.NewRequest("GET", "/metrics", nil)
			h.ServeHTTP(rec, r)
			t := 0
			for _, c := range rec.Body.Bytes() {
				t += int(c)
			}
			return t
		}
	case "serve_plain", "serve_metrics":
		b, err := os.ReadFile(filepath.Join(dir, "serve.wire"))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		var wires [][]byte
		for _, l := range strings.Split(strings.TrimRight(string(b), "\x00"), "\x00") {
			wires = append(wires, []byte(l))
		}
		var h http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/missing" {
				w.WriteHeader(404)
			}
			w.Write([]byte("ok"))
		})
		if name == "serve_metrics" {
			reg := prometheus.NewRegistry()
			cnt := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "http_requests_total", Help: "Total HTTP requests served."}, []string{"method", "code"})
			hist := prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "http_request_duration_seconds", Help: "Request latency.", Buckets: prometheus.DefBuckets}, []string{"method"})
			inflight := prometheus.NewGauge(prometheus.GaugeOpts{Name: "http_requests_in_flight", Help: "In flight."})
			reg.MustRegister(cnt, hist, inflight)
			h = promhttp.InstrumentHandlerInFlight(inflight, promhttp.InstrumentHandlerCounter(cnt, promhttp.InstrumentHandlerDuration(hist, h)))
		}
		f = func() int {
			total := 0
			for _, bb := range wires {
				req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(bb)))
				if err != nil {
					panic(err)
				}
				w := &wire{h: http.Header{}}
				h.ServeHTTP(w, req)
				if w.status == 0 {
					w.WriteHeader(http.StatusOK)
				}
				total += w.status
			}
			return total
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown workload", name)
		os.Exit(2)
	}
	ns, count := timeIt(f)
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
}
