// SPDX-License-Identifier: MIT

// The probe behind the metrics card's correctness lead (`**Ahead:**` in
// SPEC.md; pinned for this module by src/lead_test.zig). Six rows, each a
// thing an instrumented service does, each with ONE right scrape result:
// what the Prometheus server's own parser (model/textparse v0.315.0) must
// read from the exposition. Judged here for prometheus/client_golang v1.24.1
// and VictoriaMetrics/metrics v1.44.1 (run in this process) and for
// prometheus-client 0.25.1 (client_rust; its expositions are written by
// `rust_fast_bench probe <dir>` into <dir>/rust_<row>.txt, OpenMetrics text).
//
//	quote      a counter series with label path=`a"b`, +1
//	newline    the same with path="a<LF>b"
//	backslash  the same with path=`a\b`
//	help       a counter whose HELP is "x<LF>probe_injected 7": the scrape
//	           must hold probe_total 1 and nothing else
//	negative   Observe(-1) on a histogram with client_golang's DefBuckets:
//	           _count 1, _sum -1, every bucket 1 (negative observations are
//	           legal in a classic histogram)
//	big        a counter at 2^53, then +1: the sample must read
//	           9007199254740993 exactly (text compared, since a float64
//	           cannot tell)
//
// VictoriaMetrics has no HELP text (row `help` is n/a); its labels live in
// the metric name, so for quote/newline/backslash the caller writes them
// escaped per the text format -- its documented idiom.
//
// Usage (in this directory, GOPROXY=off): go run . <dir with rust_*.txt>
// (and ours_*.txt: run the module tests with METRICS_LEAD_OUT=<dir>)
// Prints one verdict line per (library, row) and a summary.
package main

import (
	"bytes"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"

	vm "github.com/VictoriaMetrics/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/textparse"
)

var rows = []string{"quote", "newline", "backslash", "help", "negative", "big"}

var labelValue = map[string]string{"quote": `a"b`, "newline": "a\nb", "backslash": `a\b`}

const injectedHelp = "x\nprobe_injected 7"

var defBuckets = []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10}

// want: the samples the scrape must hold, keyed by textparse's label string.
func want(row string) map[string]float64 {
	switch row {
	case "quote", "newline", "backslash":
		return map[string]float64{labels.FromStrings("__name__", "probe_total", "path", labelValue[row]).String(): 1}
	case "help":
		return map[string]float64{labels.FromStrings("__name__", "probe_total").String(): 1}
	case "negative":
		m := map[string]float64{
			labels.FromStrings("__name__", "probe_seconds_count").String(): 1,
			labels.FromStrings("__name__", "probe_seconds_sum").String():   -1,
		}
		for _, b := range defBuckets {
			m[labels.FromStrings("__name__", "probe_seconds_bucket", "le", fmt.Sprint(b)).String()] = 1
		}
		m[labels.FromStrings("__name__", "probe_seconds_bucket", "le", "+Inf").String()] = 1
		return m
	}
	return nil // big: judged on the text
}

// scrape: what textparse reads; `le` normalized to Go's float spelling.
func scrape(text []byte, contentType string) (map[string]float64, error) {
	p, err := textparse.New(text, contentType, labels.NewSymbolTable(), textparse.ParserOptions{})
	if err != nil {
		return nil, err
	}
	out := map[string]float64{}
	for {
		e, err := p.Next()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if e != textparse.EntrySeries {
			continue
		}
		_, _, v := p.Series()
		var ls labels.Labels
		p.Labels(&ls)
		b := labels.NewBuilder(ls)
		if le := ls.Get("le"); le != "" && le != "+Inf" {
			var f float64
			fmt.Sscan(le, &f)
			b.Set("le", fmt.Sprint(f))
		}
		k := b.Labels().String()
		if _, dup := out[k]; dup {
			return nil, fmt.Errorf("duplicate series %s", k)
		}
		out[k] = v
	}
}

// judge: "" when right, else why.
func judge(row string, text []byte, contentType string) string {
	got, err := scrape(text, contentType)
	if err != nil {
		return "scrape fails: " + err.Error()
	}
	if row == "big" {
		for _, l := range strings.Split(string(text), "\n") {
			if strings.HasPrefix(l, "probe_total ") {
				f := strings.Fields(l)
				exact, ok := new(big.Float).SetPrec(200).SetString(f[1])
				if !ok {
					return "unparsable value " + f[1]
				}
				if exact.Cmp(new(big.Float).SetPrec(200).SetUint64(1<<53+1)) != 0 {
					return "reads " + f[1] + ", not 9007199254740993"
				}
				return ""
			}
		}
		return "no probe_total sample"
	}
	w := want(row)
	var bad []string
	for k, v := range w {
		if g, ok := got[k]; !ok {
			bad = append(bad, "missing "+k)
		} else if g != v {
			bad = append(bad, fmt.Sprintf("%s = %v, want %v", k, g, v))
		}
	}
	for k := range got {
		if _, ok := w[k]; !ok {
			bad = append(bad, "extra "+k)
		}
	}
	sort.Strings(bad)
	return strings.Join(bad, "; ")
}

const promText = "text/plain; version=0.0.4; charset=utf-8"

func golang(row string) []byte {
	reg := prometheus.NewRegistry()
	switch row {
	case "quote", "newline", "backslash":
		c := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "probe_total", Help: "probe"}, []string{"path"})
		reg.MustRegister(c)
		c.WithLabelValues(labelValue[row]).Inc()
	case "help":
		c := prometheus.NewCounter(prometheus.CounterOpts{Name: "probe_total", Help: injectedHelp})
		reg.MustRegister(c)
		c.Inc()
	case "negative":
		h := prometheus.NewHistogram(prometheus.HistogramOpts{Name: "probe_seconds", Help: "probe", Buckets: defBuckets})
		reg.MustRegister(h)
		h.Observe(-1)
	case "big":
		c := prometheus.NewCounter(prometheus.CounterOpts{Name: "probe_total", Help: "probe"})
		reg.MustRegister(c)
		c.Add(1 << 53)
		c.Inc()
	}
	mfs, err := reg.Gather()
	if err != nil {
		panic(err)
	}
	var b bytes.Buffer
	enc := expfmt.NewEncoder(&b, expfmt.NewFormat(expfmt.TypeTextPlain))
	for _, mf := range mfs {
		if err := enc.Encode(mf); err != nil {
			panic(err)
		}
	}
	return b.Bytes()
}

// escape: the text format's label-value escaping, which a VictoriaMetrics
// caller writes into the metric name.
func escape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

// victoria: "" text for a row it cannot express.
func victoria(row string) []byte {
	vm.ExposeMetadata(true)
	s := vm.NewSet()
	switch row {
	case "quote", "newline", "backslash":
		s.NewCounter(`probe_total{path="` + escape(labelValue[row]) + `"}`).Inc()
	case "help":
		return nil
	case "negative":
		s.NewPrometheusHistogramExt("probe_seconds", defBuckets).Update(-1)
	case "big":
		c := s.NewCounter("probe_total")
		c.Set(1 << 53)
		c.Inc()
	}
	var b bytes.Buffer
	s.WritePrometheus(&b)
	return b.Bytes()
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go_field_probe <dir with rust_<row>.txt>")
		os.Exit(2)
	}
	off := map[string]int{}
	for _, row := range rows {
		type side struct {
			name, ct string
			text     []byte
		}
		rust, err := os.ReadFile(filepath.Join(os.Args[1], "rust_"+row+".txt"))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		sides := []side{
			{"client_golang v1.24.1", promText, golang(row)},
			{"VictoriaMetrics/metrics v1.44.1", promText, victoria(row)},
			{"prometheus-client 0.25.1", "application/openmetrics-text; version=1.0.0; charset=utf-8", rust},
		}
		// This module's expositions, when src/lead_test.zig wrote them.
		if ours, err := os.ReadFile(filepath.Join(os.Args[1], "ours_"+row+".txt")); err == nil {
			sides = append(sides, side{"zig-libs metrics", promText, ours})
		}
		for _, s := range sides {
			if s.text == nil {
				fmt.Printf("%-10s %-32s n/a\n", row, s.name)
				continue
			}
			v := judge(row, s.text, s.ct)
			if v == "" {
				fmt.Printf("%-10s %-32s ok\n", row, s.name)
			} else {
				off[s.name]++
				fmt.Printf("%-10s %-32s OFF  %s\n", row, s.name, v)
			}
		}
	}
	fmt.Printf("\noff: client_golang %d, VictoriaMetrics %d, client_rust %d, zig-libs metrics %d (of %d rows)\n",
		off["client_golang v1.24.1"], off["VictoriaMetrics/metrics v1.44.1"], off["prometheus-client 0.25.1"], off["zig-libs metrics"], len(rows))
}
