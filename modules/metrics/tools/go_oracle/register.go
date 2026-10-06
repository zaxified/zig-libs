// SPDX-License-Identifier: MIT

// `go_oracle register OUT`: the registration rules. Each case is a sequence
// of get-or-register calls (kind, name, help, label pairs, buckets) as this
// module's Registry takes them. Every call runs on a client_golang registry
// too: the family through New*Vec + Register (an AlreadyRegisteredError of
// the same kind counts as getting the existing family, as the module's
// get-or-register does), the series through WithLabelValues, and then
// Gather plus a textparse scrape of the exposition, so a registration that
// is accepted but breaks the scrape shows. Metric and label names are
// judged by prometheus/common's legacy rules -- client_golang itself now
// takes UTF-8 names, which text format 0.0.4 cannot carry; the module keeps
// the legacy charset (documented). Writes the Zig vectors to OUT.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"os"
	"runtime"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

type RegOp struct {
	Kind    string
	Name    string
	Help    string
	Labels  [][2]string
	Buckets []float64
	// Why `want` is not client_golang's verdict, when it is not.
	Class string
}

type RegCase struct {
	Ops []RegOp
}

func op(kind, name string, labels ...string) RegOp {
	o := RegOp{Kind: kind, Name: name, Help: "h"}
	for i := 0; i+1 < len(labels); i += 2 {
		o.Labels = append(o.Labels, [2]string{labels[i], labels[i+1]})
	}
	if kind == "histogram" {
		o.Buckets = []float64{1, 2}
	}
	return o
}

func one(o RegOp) RegCase { return RegCase{Ops: []RegOp{o}} }

func with(o RegOp, f func(*RegOp)) RegOp { f(&o); return o }

var regClasses = map[string]string{
	"TOO_MANY_LABELS": "more than `max_labels` (8) labels: client_golang has no limit; the module's fixed-size series " +
		"key does -- refused (documented)",
	"BUCKETS_DIFFER": "a histogram re-registered with other buckets: client_golang's descriptor ignores buckets, so " +
		"Register hands back the existing family with the OLD buckets and no error; the module refuses " +
		"(`BucketsMismatch`) -- refused",
	"NONFINITE_BUCKET": "a non-finite bucket bound: client_golang strips a trailing +Inf and takes -Inf and NaN " +
		"(an `le=\"NaN\"` bucket nothing is ever counted in); the module refuses every non-finite bound " +
		"(documented) -- refused",
	"LABEL_ORDER": "the same label names in another order: client_golang's descriptor ignores the order, hands back " +
		"the existing family and assigns WithLabelValues positionally -- the values land under each other's " +
		"names; the module refuses (`LabelMismatch`) -- refused",
	"EMPTY_BUCKETS": "no buckets: client_golang substitutes DefBuckets, the module keeps only +Inf; both accept",
}

func regCases() []RegCase {
	var cs []RegCase
	for _, n := range []string{"a", "a1", "_a", ":a", "a:b", "__a", "1a", "a-b", "a.b", "é", "", "a b", "A_Z09"} {
		cs = append(cs, one(op("counter", n)))
	}
	for _, l := range []string{"a", "_a", "a1", "A", "__a", "__", "1a", "a:b", "a-b", "é", "", "le", "quantile"} {
		cs = append(cs, one(op("counter", "m", l, "v")))
		cs = append(cs, one(op("histogram", "m", l, "v")))
	}
	cs = append(cs, one(op("gauge", "m", "quantile", "v")))
	cs = append(cs, one(op("gauge", "m", "le", "v")))
	cs = append(cs, one(op("counter", "m", "a", "1", "a", "2")))
	cs = append(cs, one(op("counter", "m", "a", "1", "b", "2", "a", "3")))
	nine := []string{}
	for i := 0; i < 9; i++ {
		nine = append(nine, fmt.Sprintf("l%d", i), "v")
	}
	cs = append(cs, one(with(op("counter", "m", nine...), func(o *RegOp) { o.Class = "TOO_MANY_LABELS" })))
	cs = append(cs, one(op("counter", "m", nine[:16]...)))
	cs = append(cs, one(op("counter", "m", "a", "\xff")))
	cs = append(cs, one(op("counter", "m", "a", "")))
	cs = append(cs, one(with(op("counter", "m"), func(o *RegOp) { o.Help = "\xff" })))
	cs = append(cs, one(with(op("counter", "m"), func(o *RegOp) { o.Help = "" })))
	// Re-registration.
	cs = append(cs, RegCase{Ops: []RegOp{op("counter", "m", "a", "1"), op("counter", "m", "a", "1"), op("counter", "m", "a", "2")}})
	cs = append(cs, RegCase{Ops: []RegOp{op("counter", "m"), with(op("counter", "m"), func(o *RegOp) { o.Help = "other" })}})
	cs = append(cs, RegCase{Ops: []RegOp{op("counter", "m", "a", "1"), op("counter", "m", "b", "1")}})
	cs = append(cs, RegCase{Ops: []RegOp{op("counter", "m", "a", "1"), op("counter", "m")}})
	cs = append(cs, RegCase{Ops: []RegOp{op("counter", "m", "a", "1", "b", "2"), with(op("counter", "m", "b", "2", "a", "1"), func(o *RegOp) { o.Class = "LABEL_ORDER" })}})
	cs = append(cs, RegCase{Ops: []RegOp{op("counter", "m", "a", "1"), op("counter", "m", "a", "1", "b", "2")}})
	cs = append(cs, RegCase{Ops: []RegOp{op("counter", "m"), op("gauge", "m")}})
	cs = append(cs, RegCase{Ops: []RegOp{op("gauge", "m"), op("histogram", "m")}})
	cs = append(cs, RegCase{Ops: []RegOp{op("histogram", "m"), with(op("histogram", "m"), func(o *RegOp) {
		o.Buckets = []float64{1, 3}
		o.Class = "BUCKETS_DIFFER"
	})}})
	cs = append(cs, RegCase{Ops: []RegOp{op("histogram", "m", "a", "1"), op("histogram", "m", "a", "2")}})
	// Derived histogram names against other families, both orders.
	for _, suf := range []string{"_bucket", "_sum", "_count"} {
		cs = append(cs, RegCase{Ops: []RegOp{op("histogram", "h"), op("counter", "h"+suf)}})
		cs = append(cs, RegCase{Ops: []RegOp{op("gauge", "h"+suf), op("histogram", "h")}})
		cs = append(cs, RegCase{Ops: []RegOp{op("counter", "h"+suf), op("counter", "h")}})
	}
	cs = append(cs, RegCase{Ops: []RegOp{op("histogram", "h"), op("histogram", "h_bucket")}})
	cs = append(cs, RegCase{Ops: []RegOp{op("histogram", "h"), op("counter", "h_total")}})
	// Buckets.
	for _, b := range []struct {
		b     []float64
		class string
	}{
		{[]float64{}, "EMPTY_BUCKETS"}, {[]float64{1}, ""}, {[]float64{-1, 0, 1}, ""}, {[]float64{1, 1}, ""},
		{[]float64{2, 1}, ""}, {[]float64{1, math.Inf(1)}, "NONFINITE_BUCKET"}, {[]float64{math.Inf(-1), 1}, "NONFINITE_BUCKET"},
		{[]float64{math.NaN()}, "NONFINITE_BUCKET"}, {[]float64{1, math.NaN()}, "NONFINITE_BUCKET"},
	} {
		o := op("histogram", "h")
		o.Buckets, o.Class = b.b, b.class
		cs = append(cs, one(o))
	}
	return cs
}

type regVerdict struct {
	ok  bool
	why string
}

// goRegister runs one case on client_golang: per op, accepted or the reason.
func goRegister(c RegCase) []regVerdict {
	reg := prometheus.NewRegistry()
	vecs := map[string]any{}
	kinds := map[string]string{}
	var out []regVerdict
	for _, o := range c.Ops {
		out = append(out, goRegOne(reg, vecs, kinds, o))
	}
	return out
}

func goRegOne(reg *prometheus.Registry, vecs map[string]any, kinds map[string]string, o RegOp) (v regVerdict) {
	defer func() {
		if r := recover(); r != nil {
			v = regVerdict{false, fmt.Sprint("panic: ", r)}
		}
	}()
	if !model.LegacyValidation.IsValidMetricName(o.Name) {
		return regVerdict{false, "legacy: invalid metric name"}
	}
	names := make([]string, len(o.Labels))
	values := make([]string, len(o.Labels))
	for i, l := range o.Labels {
		if !model.LegacyValidation.IsValidLabelName(l[0]) {
			return regVerdict{false, "legacy: invalid label name"}
		}
		names[i], values[i] = l[0], l[1]
	}
	var vec any
	switch o.Kind {
	case "counter":
		vec = prometheus.NewCounterVec(prometheus.CounterOpts{Name: o.Name, Help: o.Help}, names)
	case "gauge":
		vec = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: o.Name, Help: o.Help}, names)
	case "histogram":
		vec = prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: o.Name, Help: o.Help, Buckets: o.Buckets}, names)
	}
	if err := reg.Register(vec.(prometheus.Collector)); err != nil {
		var are prometheus.AlreadyRegisteredError
		if !errors.As(err, &are) || kinds[o.Name] != o.Kind {
			return regVerdict{false, "register: " + err.Error()}
		}
		vec = vecs[o.Name]
	} else {
		vecs[o.Name] = vec
		kinds[o.Name] = o.Kind
	}
	switch x := vec.(type) {
	case *prometheus.CounterVec:
		x.WithLabelValues(values...).Inc()
	case *prometheus.GaugeVec:
		x.WithLabelValues(values...).Set(1)
	case *prometheus.HistogramVec:
		x.WithLabelValues(values...).Observe(1)
	}
	mfs, err := reg.Gather()
	if err != nil {
		return regVerdict{false, "gather: " + err.Error()}
	}
	var buf bytes.Buffer
	enc := expfmt.NewEncoder(&buf, expfmt.NewFormat(expfmt.TypeTextPlain))
	for _, mf := range mfs {
		if err := enc.Encode(mf); err != nil {
			return regVerdict{false, "encode: " + err.Error()}
		}
	}
	if _, err := scrape(buf.Bytes()); err != nil {
		return regVerdict{false, "scrape: " + err.Error()}
	}
	return regVerdict{true, ""}
}

func zfloat(v float64) string {
	switch {
	case math.IsNaN(v):
		return "std.math.nan(f64)"
	case math.IsInf(v, 1):
		return "std.math.inf(f64)"
	case math.IsInf(v, -1):
		return "-std.math.inf(f64)"
	}
	return zf64(v)
}

func short(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 120 {
		s = s[:120] + "..."
	}
	return s
}

func register(outPath string) int {
	var b strings.Builder
	b.WriteString("// SPDX-License-Identifier: MIT\n")
	fmt.Fprintf(&b, "// GENERATED by modules/metrics/tools/go_oracle (register; client_golang v1.24.1, prometheus/common v0.71.0, prometheus v0.315.0, %s) -- do not hand-edit.\n", runtime.Version())
	b.WriteString("//! Registration sequences and client_golang's verdict on each call, replayed by `go_register_test.zig`.\n\n")
	b.WriteString("const std = @import(\"std\");\n\n")
	b.WriteString("pub const Kind = enum { counter, gauge, histogram };\n")
	b.WriteString("pub const Label = struct { name: []const u8, value: []const u8 };\n")
	b.WriteString("/// `go`: client_golang's reason for refusing (empty: it accepted, the scrape included). `want`: what\n")
	b.WriteString("/// the module's get-or-register must do; `class` names the rule in go_oracle/register.go that decided\n")
	b.WriteString("/// it when it is not client_golang's verdict.\n")
	b.WriteString("pub const Op = struct { kind: Kind, name: []const u8, help: []const u8, labels: []const Label, buckets: []const f64, go: []const u8, want: bool, class: []const u8 };\n\n")
	b.WriteString("pub const classes = [_][]const u8{")
	var cls []string
	for _, k := range []string{"TOO_MANY_LABELS", "BUCKETS_DIFFER", "NONFINITE_BUCKET", "LABEL_ORDER", "EMPTY_BUCKETS"} {
		cls = append(cls, zstr(k))
	}
	b.WriteString(" " + strings.Join(cls, ", ") + " };\n\n")
	b.WriteString("pub const cases = [_][]const Op{\n")
	for _, c := range regCases() {
		vs := goRegister(c)
		b.WriteString("    &.{\n")
		for i, o := range c.Ops {
			want := vs[i].ok
			switch o.Class {
			case "TOO_MANY_LABELS", "BUCKETS_DIFFER", "NONFINITE_BUCKET", "LABEL_ORDER":
				if !vs[i].ok {
					fmt.Fprintf(os.Stderr, "class %s on an op client_golang refuses: %s\n", o.Class, vs[i].why)
					return 1
				}
				want = false
			}
			var ls []string
			for _, l := range o.Labels {
				ls = append(ls, fmt.Sprintf(".{ .name = %s, .value = %s }", zstr(l[0]), zstr(l[1])))
			}
			var bs []string
			for _, x := range o.Buckets {
				bs = append(bs, zfloat(x))
			}
			fmt.Fprintf(&b, "        .{ .kind = .%s, .name = %s, .help = %s, .labels = &.{%s}, .buckets = &.{%s}, .go = %s, .want = %v, .class = %s },\n",
				o.Kind, zstr(o.Name), zstr(o.Help), strings.Join(ls, ", "), strings.Join(bs, ", "), zstr(short(vs[i].why)), want, zstr(o.Class))
		}
		b.WriteString("    },\n")
	}
	b.WriteString("};\n")
	if err := os.WriteFile(outPath, []byte(b.String()), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
