// go_golden prints client_golang's text and OpenMetrics exposition of a fixed
// registry; root.zig's golden_go_text / golden_go_openmetrics are its output.
// Run: GOTOOLCHAIN=local GOPROXY=off GOFLAGS=-mod=mod go run .

package main

import (
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
)

func main() {
	reg := prometheus.NewRegistry()
	// Families named so Go's sort = our registration order.
	a := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "a_requests_total", Help: "Requests \"served\" \\ by\nmethod."}, []string{"method"})
	b := prometheus.NewCounter(prometheus.CounterOpts{Name: "b_events", Help: "No _total suffix."})
	c := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "c_temp", Help: "Gauge."}, []string{"room"})
	d := prometheus.NewHistogram(prometheus.HistogramOpts{Name: "d_seconds", Help: "Hist.", Buckets: []float64{0.5, 1, 2.5, 1e6}})
	e := prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "e_func", Help: "Func."}, func() float64 { return 0.000012 })
	f := prometheus.NewCounterFunc(prometheus.CounterOpts{Name: "f_cpu_seconds_total", Help: "CPU."}, func() float64 { return 12.25 })
	g := prometheus.NewSummaryVec(prometheus.SummaryOpts{Name: "g_lat_seconds", Help: "Summary.", Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001}}, []string{"op"})
	reg.MustRegister(a, b, c, d, e, f, g)
	for i := 1; i <= 100; i++ {
		g.WithLabelValues("read").Observe(float64(i) / 10)
	}
	a.WithLabelValues("GET").Add(3)
	a.WithLabelValues("POST").Add(1)
	b.Add(0)
	c.WithLabelValues("hall").Set(1234567.5)
	c.WithLabelValues("lab").Set(-1)
	for _, v := range []float64{0.25, 0.5, 2, 3, 7} {
		d.Observe(v)
	}
	mfs, err := reg.Gather()
	if err != nil {
		panic(err)
	}
	for _, kind := range []expfmt.Format{expfmt.NewFormat(expfmt.TypeTextPlain), expfmt.NewFormat(expfmt.TypeOpenMetrics)} {
		os.Stdout.WriteString("=== " + string(kind) + "\n")
		enc := expfmt.NewEncoder(os.Stdout, kind)
		for _, mf := range mfs {
			if err := enc.Encode(mf); err != nil {
				panic(err)
			}
		}
		if cl, ok := enc.(expfmt.Closer); ok {
			cl.Close()
		}
	}
}
