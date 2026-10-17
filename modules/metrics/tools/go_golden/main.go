// go_golden prints client_golang's text and OpenMetrics exposition of a fixed
// registry; root.zig's golden_go_text / golden_go_openmetrics are its output.
// Run: GOTOOLCHAIN=local GOPROXY=off GOFLAGS=-mod=mod go run .

package main

import (
	"os"
	"time"

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
	// Exemplars (OpenMetrics only); fixed timestamps through the const API.
	xreg := prometheus.NewRegistry()
	ts := time.Unix(1700000000, 250000000)
	xc := prometheus.NewDesc("x_hits_total", "Hits.", nil, nil)
	xh := prometheus.NewDesc("x_lat_seconds", "Lat.", nil, nil)
	xreg.MustRegister(constCollector{
		prometheus.MustNewMetricWithExemplars(prometheus.MustNewConstMetric(xc, prometheus.CounterValue, 3),
			prometheus.Exemplar{Value: 2, Labels: prometheus.Labels{"trace_id": "4bf92f\"x"}, Timestamp: ts}),
		prometheus.MustNewMetricWithExemplars(prometheus.MustNewConstHistogram(xh, 3, 9.5, map[float64]uint64{1: 1, 5: 2}),
			prometheus.Exemplar{Value: 0.5, Labels: prometheus.Labels{"span": "a"}, Timestamp: ts},
			prometheus.Exemplar{Value: 6, Labels: prometheus.Labels{"span": "b"}, Timestamp: ts}),
	})
	xmfs, err := xreg.Gather()
	if err != nil {
		panic(err)
	}
	os.Stdout.WriteString("=== exemplars\n")
	xenc := expfmt.NewEncoder(os.Stdout, expfmt.NewFormat(expfmt.TypeOpenMetrics))
	for _, mf := range xmfs {
		if err := xenc.Encode(mf); err != nil {
			panic(err)
		}
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

type constCollector []prometheus.Metric

func (c constCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, m := range c {
		ch <- m.Desc()
	}
}

func (c constCollector) Collect(ch chan<- prometheus.Metric) {
	for _, m := range c {
		ch <- m
	}
}
