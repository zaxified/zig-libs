// SPDX-License-Identifier: MIT

// The metrics oracle: Prometheus client_golang (Apache-2.0) as the reference
// registry, and two foreign parsers -- prometheus/common expfmt and the
// Prometheus server's own scrape parser (model/textparse) -- as the judges of
// this module's exposition text. All run as black boxes; no source is copied.
//
//	go_oracle gen -n N -seed S          scripts (JSON) on stdout
//	go_oracle judge SCRIPTS OURS OUT    verdicts; writes the Zig vectors to OUT
//
// A script declares metric families (name, help, kind, label names, buckets)
// and a sequence of operations on series (inc/add/set/sub/dec/observe). OURS
// holds this module's `writeText` after each script (tools/interop.zig runs
// them). For every script the same operations run on a client_golang registry;
// expfmt parses our text, textparse must scrape it without error and see the
// same samples, and the two family sets must be equal (names, help, type,
// series by label set, values, cumulative buckets, sum, count). Where they
// differ by a documented design difference the case carries its class
// (EMPTY_BUCKETS: client_golang turns an empty bucket list into DefBuckets,
// this module keeps only +Inf -- compared without buckets).
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"math/rand"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/textparse"
)

type Family struct {
	Name    string    `json:"name"`
	Help    string    `json:"help"`
	Kind    string    `json:"kind"`
	Labels  []string  `json:"labels"`
	Buckets []float64 `json:"-"`
	// Buckets as strings: JSON has no NaN/Inf, and the Zig side parses these.
	BucketsS []string `json:"buckets"`
}

type Op struct {
	Fam    int      `json:"fam"`
	Values []string `json:"values"`
	Op     string   `json:"op"`
	N      uint64   `json:"n"`
	V      float64  `json:"-"`
	VS     string   `json:"v"`
}

type Script struct {
	Families []Family `json:"families"`
	Ops      []Op     `json:"ops"`
}

func fstr(v float64) string { return strconv.FormatFloat(v, 'g', -1, 64) }

var (
	names      = []string{"req_total", "temp", "lat_seconds", "a", "b_c", "x:y", "q"}
	helps      = []string{"", "plain", "back\\slash", "new\nline", "quote\"s", "é ünïcode", "tab\tx", "both\\n\n"}
	labelNames = []string{"method", "code", "path", "a", "b"}
	values     = []string{"", "GET", "a\"b", "back\\slash", "new\nline", "é", "200", "x y", "{}", "=,"}
	bucketSets = [][]float64{{}, {1}, {0.1, 0.5, 1}, {-1, 0, 1}, {1e-9, 1e9}, {0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}}
	gaugeVals  = []float64{0, math.Copysign(0, -1), 1, -1, 0.5, 0.1, 3, 1e-300, 1e300, math.MaxFloat64, math.SmallestNonzeroFloat64, math.NaN(), math.Inf(1), math.Inf(-1)}
	counterNs  = []uint64{0, 1, 2, 10, 1 << 53, 1 << 62}
)

func gen(n int, seed int64) []Script {
	rng := rand.New(rand.NewSource(seed))
	pick := func(xs []string) string { return xs[rng.Intn(len(xs))] }
	var out []Script
	for s := 0; s < n; s++ {
		var sc Script
		used := map[string]bool{}
		nf := 1 + rng.Intn(4)
		for len(sc.Families) < nf {
			name := pick(names)
			if used[name] {
				continue
			}
			used[name] = true
			f := Family{Name: name, Help: pick(helps), Kind: []string{"counter", "gauge", "histogram"}[rng.Intn(3)]}
			nl := rng.Intn(4)
			seen := map[string]bool{}
			for len(f.Labels) < nl {
				l := pick(labelNames)
				if !seen[l] {
					seen[l] = true
					f.Labels = append(f.Labels, l)
				}
			}
			if f.Kind == "histogram" {
				f.Buckets = bucketSets[rng.Intn(len(bucketSets))]
			}
			sc.Families = append(sc.Families, f)
		}
		nops := 1 + rng.Intn(14)
		for i := 0; i < nops; i++ {
			fi := rng.Intn(len(sc.Families))
			f := sc.Families[fi]
			op := Op{Fam: fi}
			for range f.Labels {
				op.Values = append(op.Values, pick(values))
			}
			switch f.Kind {
			case "counter":
				if rng.Intn(2) == 0 {
					op.Op = "inc"
				} else {
					op.Op, op.N = "add", counterNs[rng.Intn(len(counterNs))]
				}
			case "gauge":
				op.Op = []string{"set", "add", "sub", "inc", "dec"}[rng.Intn(5)]
				op.V = gaugeVals[rng.Intn(len(gaugeVals))]
			case "histogram":
				op.Op = "observe"
				cands := []float64{0, -1, 1e300, math.NaN(), math.Inf(1), math.Inf(-1), 0.3}
				for _, b := range f.Buckets {
					cands = append(cands, b, math.Nextafter(b, math.Inf(1)), math.Nextafter(b, math.Inf(-1)))
				}
				op.V = cands[rng.Intn(len(cands))]
			}
			sc.Ops = append(sc.Ops, op)
		}
		out = append(out, sc)
	}
	// Crafted, whatever the seed draws: a counter past float64's integer range,
	// every gauge special in one family, a histogram with no buckets.
	out = append(out,
		Script{Families: []Family{{Name: "big_total", Help: "h", Kind: "counter"}},
			Ops: []Op{{Fam: 0, Op: "add", N: 1 << 53}, {Fam: 0, Op: "inc"}, {Fam: 0, Op: "inc"}}},
		Script{Families: []Family{{Name: "g", Help: "h", Kind: "gauge", Labels: []string{"v"}}},
			Ops: []Op{{Fam: 0, Values: []string{"nan"}, Op: "set", V: math.NaN()}, {Fam: 0, Values: []string{"inf"}, Op: "set", V: math.Inf(1)},
				{Fam: 0, Values: []string{"-inf"}, Op: "set", V: math.Inf(-1)}, {Fam: 0, Values: []string{"-0"}, Op: "set", V: math.Copysign(0, -1)},
				{Fam: 0, Values: []string{"max"}, Op: "set", V: math.MaxFloat64}, {Fam: 0, Values: []string{"tiny"}, Op: "set", V: math.SmallestNonzeroFloat64}}},
		Script{Families: []Family{{Name: "h", Help: "h", Kind: "histogram", Buckets: []float64{}}},
			Ops: []Op{{Fam: 0, Op: "observe", V: 1}, {Fam: 0, Op: "observe", V: math.NaN()}}},
	)
	for i := range out {
		for j := range out[i].Families {
			f := &out[i].Families[j]
			f.BucketsS = []string{}
			for _, b := range f.Buckets {
				f.BucketsS = append(f.BucketsS, fstr(b))
			}
			if f.Labels == nil {
				f.Labels = []string{}
			}
		}
		for j := range out[i].Ops {
			o := &out[i].Ops[j]
			o.VS = fstr(o.V)
			if o.Values == nil {
				o.Values = []string{}
			}
		}
	}
	return out
}

// ── normalized families ──────────────────────────────────────────────────────

type Series struct {
	Labels  map[string]string // non-empty values only
	Value   float64
	Buckets map[float64]uint64 // le (finite) -> cumulative count
	Count   uint64
	Sum     float64
}

type Fam struct {
	Help   string
	Type   string
	Series map[string]*Series // canonical label set -> series
}

func labelKey(pairs []*dto.LabelPair) string {
	var kv []string
	for _, p := range pairs {
		if p.GetValue() == "" { // Prometheus: an empty label value is an absent label
			continue
		}
		kv = append(kv, strconv.Quote(p.GetName())+"="+strconv.Quote(p.GetValue()))
	}
	sort.Strings(kv)
	return "{" + strings.Join(kv, ",") + "}"
}

func normalize(mfs []*dto.MetricFamily) map[string]*Fam {
	out := map[string]*Fam{}
	for _, mf := range mfs {
		f := &Fam{Help: mf.GetHelp(), Type: strings.ToLower(mf.GetType().String()), Series: map[string]*Series{}}
		for _, m := range mf.Metric {
			s := &Series{Labels: map[string]string{}}
			for _, p := range m.Label {
				if p.GetValue() != "" {
					s.Labels[p.GetName()] = p.GetValue()
				}
			}
			switch {
			case m.Counter != nil:
				s.Value = m.Counter.GetValue()
			case m.Gauge != nil:
				s.Value = m.Gauge.GetValue()
			case m.Untyped != nil:
				s.Value = m.Untyped.GetValue()
			case m.Histogram != nil:
				s.Buckets = map[float64]uint64{}
				for _, b := range m.Histogram.Bucket {
					if !math.IsInf(b.GetUpperBound(), 1) {
						s.Buckets[b.GetUpperBound()] = b.GetCumulativeCount()
					}
				}
				s.Count, s.Sum = m.Histogram.GetSampleCount(), m.Histogram.GetSampleSum()
			}
			f.Series[labelKey(m.Label)] = s
		}
		out[mf.GetName()] = f
	}
	return out
}

func feq(a, b float64) bool { return a == b || (math.IsNaN(a) && math.IsNaN(b)) }

// diff describes the first difference between two normalized sets, "" when equal.
func diff(want, got map[string]*Fam, skipBuckets map[string]bool) string {
	for name, w := range want {
		g, ok := got[name]
		if !ok {
			return "family " + name + " missing"
		}
		if w.Help != g.Help {
			return fmt.Sprintf("%s help %q vs %q", name, w.Help, g.Help)
		}
		if w.Type != g.Type {
			return fmt.Sprintf("%s type %s vs %s", name, w.Type, g.Type)
		}
		for k, ws := range w.Series {
			gs, ok := g.Series[k]
			if !ok {
				return name + k + " missing"
			}
			if !feq(ws.Value, gs.Value) {
				return fmt.Sprintf("%s%s value %v vs %v", name, k, ws.Value, gs.Value)
			}
			if ws.Count != gs.Count || !feq(ws.Sum, gs.Sum) {
				return fmt.Sprintf("%s%s count/sum %d/%v vs %d/%v", name, k, ws.Count, ws.Sum, gs.Count, gs.Sum)
			}
			if !skipBuckets[name] {
				if len(ws.Buckets) != len(gs.Buckets) {
					return fmt.Sprintf("%s%s %d buckets vs %d", name, k, len(ws.Buckets), len(gs.Buckets))
				}
				for le, c := range ws.Buckets {
					if gs.Buckets[le] != c {
						return fmt.Sprintf("%s%s le=%v %d vs %d", name, k, le, c, gs.Buckets[le])
					}
				}
			}
		}
		if len(w.Series) != len(g.Series) {
			return fmt.Sprintf("%s %d series vs %d", name, len(w.Series), len(g.Series))
		}
	}
	if len(want) != len(got) {
		return fmt.Sprintf("%d families vs %d", len(want), len(got))
	}
	return ""
}

// reference runs a script on client_golang and returns the gathered families.
func reference(sc Script) (map[string]*Fam, map[string]bool) {
	reg := prometheus.NewRegistry()
	vecs := make([]any, len(sc.Families))
	empty := map[string]bool{}
	for i, f := range sc.Families {
		switch f.Kind {
		case "counter":
			v := prometheus.NewCounterVec(prometheus.CounterOpts{Name: f.Name, Help: f.Help}, f.Labels)
			reg.MustRegister(v)
			vecs[i] = v
		case "gauge":
			v := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: f.Name, Help: f.Help}, f.Labels)
			reg.MustRegister(v)
			vecs[i] = v
		case "histogram":
			b := f.Buckets
			if len(b) == 0 {
				// client_golang turns no buckets into DefBuckets; this module keeps
				// only +Inf. Compared without buckets (class EMPTY_BUCKETS).
				empty[f.Name] = true
				b = []float64{1}
			}
			v := prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: f.Name, Help: f.Help, Buckets: b}, f.Labels)
			reg.MustRegister(v)
			vecs[i] = v
		}
	}
	for _, o := range sc.Ops {
		switch v := vecs[o.Fam].(type) {
		case *prometheus.CounterVec:
			c := v.WithLabelValues(o.Values...)
			if o.Op == "inc" {
				c.Inc()
			} else {
				c.Add(float64(o.N))
			}
		case *prometheus.GaugeVec:
			g := v.WithLabelValues(o.Values...)
			switch o.Op {
			case "set":
				g.Set(o.V)
			case "add":
				g.Add(o.V)
			case "sub":
				g.Sub(o.V)
			case "inc":
				g.Inc()
			case "dec":
				g.Dec()
			}
		case *prometheus.HistogramVec:
			v.WithLabelValues(o.Values...).Observe(o.V)
		}
	}
	mfs, err := reg.Gather()
	if err != nil {
		panic(err)
	}
	return normalize(mfs), empty
}

// scrape: what the Prometheus server's own parser reads from `text`.
func scrape(text []byte) (map[string]float64, error) {
	p, err := textparse.New(text, "text/plain; version=0.0.4; charset=utf-8", labels.NewSymbolTable(), textparse.ParserOptions{})
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
		// An empty value is an absent label; `le` as a number, not as spelled.
		m := map[string]string{}
		ls.Range(func(l labels.Label) {
			if l.Value == "" {
				return
			}
			if l.Name == "le" && l.Value != "+Inf" {
				l.Value = fstr(parseF(l.Value))
			}
			m[l.Name] = l.Value
		})
		k := labels.FromMap(m).String()
		if _, dup := out[k]; dup {
			return nil, fmt.Errorf("duplicate series %s", k)
		}
		out[k] = v
	}
}

// samples flattens normalized families into textparse's series keys.
func samples(fams map[string]*Fam) map[string]float64 {
	out := map[string]float64{}
	key := func(name string, ls map[string]string, le string) string {
		m := map[string]string{"__name__": name}
		for k, v := range ls {
			m[k] = v
		}
		if le != "" {
			m["le"] = le
		}
		return labels.FromMap(m).String()
	}
	for name, f := range fams {
		for _, s := range f.Series {
			if f.Type != "histogram" {
				out[key(name, s.Labels, "")] = s.Value
				continue
			}
			for le, c := range s.Buckets {
				out[key(name+"_bucket", s.Labels, fstr(le))] = float64(c)
			}
			out[key(name+"_bucket", s.Labels, "+Inf")] = float64(s.Count)
			out[key(name+"_sum", s.Labels, "")] = s.Sum
			out[key(name+"_count", s.Labels, "")] = float64(s.Count)
		}
	}
	return out
}

// ── Zig output ───────────────────────────────────────────────────────────────

func zstr(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, c := range []byte(s) {
		switch {
		case c == '"':
			b.WriteString(`\"`)
		case c == '\\':
			b.WriteString(`\\`)
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\t':
			b.WriteString(`\t`)
		case c >= 0x20 && c < 0x7f:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, `\x%02x`, c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func zf64(v float64) string {
	switch {
	case math.IsNaN(v):
		return "nan"
	case math.IsInf(v, 1):
		return "inf"
	case math.IsInf(v, -1):
		return "-inf"
	case v == 0 && math.Signbit(v):
		return "-0.0"
	}
	s := fstr(v)
	if !strings.ContainsAny(s, ".e") {
		s += ".0"
	}
	return s
}

func zstrs(xs []string) string {
	var p []string
	for _, x := range xs {
		p = append(p, zstr(x))
	}
	return "&.{ " + strings.Join(p, ", ") + " }"
}

func parseF(s string) float64 {
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		panic(err)
	}
	return v
}

func judge(scriptsPath, oursPath, outPath string) int {
	var scripts []Script
	var ours []string
	must(readJSON(scriptsPath, &scripts))
	must(readJSON(oursPath, &ours))
	if len(ours) != len(scripts) {
		fmt.Fprintf(os.Stderr, "%d scripts, %d expositions\n", len(scripts), len(ours))
		return 1
	}
	var o bytes.Buffer
	fmt.Fprintf(&o, "// SPDX-License-Identifier: MIT\n")
	fmt.Fprintf(&o, "// GENERATED by modules/metrics/tools/go_oracle (%s, client_golang v1.24.1, common v0.71.0, prometheus v0.315.0) -- do not hand-edit.\n", runtime.Version())
	fmt.Fprintf(&o, "//! Operation scripts, this module's exposition after each, and the class that decided any\n")
	fmt.Fprintf(&o, "//! difference from client_golang; replayed by `go_oracle_test.zig`. Regenerate: `zig build interop-metrics`.\n\n")
	fmt.Fprintf(&o, "const std = @import(\"std\");\n")
	fmt.Fprintf(&o, "// Evaluated once: a call per literal exhausts the comptime branch quota.\n")
	fmt.Fprintf(&o, "const nan: f64 = std.math.nan(f64);\nconst inf: f64 = std.math.inf(f64);\n\n")
	fmt.Fprintf(&o, "pub const Kind = enum { counter, gauge, histogram };\n")
	fmt.Fprintf(&o, "pub const Family = struct { name: []const u8, help: []const u8, kind: Kind, labels: []const []const u8, buckets: []const f64 };\n")
	fmt.Fprintf(&o, "pub const OpKind = enum { inc, add, set, sub, dec, observe };\n")
	fmt.Fprintf(&o, "/// `n`: a counter `add`; `v`: every gauge/histogram operation.\n")
	fmt.Fprintf(&o, "pub const Op = struct { fam: u8, values: []const []const u8, op: OpKind, n: u64 = 0, v: f64 = 0 };\n")
	fmt.Fprintf(&o, "/// `text`: what `writeText` wrote after `ops` -- the bytes the judges read.\n")
	fmt.Fprintf(&o, "pub const Script = struct { families: []const Family, ops: []const Op, text: []const u8, class: []const u8 };\n\n")
	fmt.Fprintf(&o, "pub const scripts = [_]Script{\n")
	bad := 0
	classes := map[string]int{}
	for i, sc := range scripts {
		for j := range sc.Families {
			for _, b := range sc.Families[j].BucketsS {
				sc.Families[j].Buckets = append(sc.Families[j].Buckets, parseF(b))
			}
		}
		for j := range sc.Ops {
			sc.Ops[j].V = parseF(sc.Ops[j].VS)
		}
		text := []byte(ours[i])
		want, empty := reference(sc)
		parser := expfmt.NewTextParser(model.UTF8Validation)
		parsed, err := parser.TextToMetricFamilies(bytes.NewReader(text))
		class := ""
		var why string
		if err != nil {
			why = "expfmt: " + err.Error()
		} else {
			var list []*dto.MetricFamily
			for _, mf := range parsed {
				list = append(list, mf)
			}
			got := normalize(list)
			why = diff(want, got, empty)
			if why == "" && len(empty) > 0 && class == "" {
				class = "EMPTY_BUCKETS"
			}
			if why == "" {
				sc, err := scrape(text)
				if err != nil {
					why = "textparse: " + err.Error()
				} else {
					exp := samples(got)
					for k, v := range exp {
						if gv, ok := sc[k]; !ok || !feq(gv, v) {
							why = fmt.Sprintf("textparse: %s = %v, expfmt read %v", k, sc[k], v)
							break
						}
					}
					if why == "" && len(sc) != len(exp) {
						why = fmt.Sprintf("textparse: %d samples, expfmt %d", len(sc), len(exp))
					}
				}
			}
		}
		if why != "" {
			bad++
			fmt.Fprintf(os.Stderr, "script %d: %s\n--- ours\n%s---\n", i, why, text)
			class = "MISMATCH"
		}
		classes[class]++
		var fams, ops []string
		for _, f := range sc.Families {
			var bs []string
			for _, b := range f.Buckets {
				bs = append(bs, zf64(b))
			}
			fams = append(fams, fmt.Sprintf(".{ .name = %s, .help = %s, .kind = .%s, .labels = %s, .buckets = &.{ %s } }",
				zstr(f.Name), zstr(f.Help), f.Kind, zstrs(f.Labels), strings.Join(bs, ", ")))
		}
		for _, op := range sc.Ops {
			s := fmt.Sprintf(".{ .fam = %d, .values = %s, .op = .%s", op.Fam, zstrs(op.Values), op.Op)
			if op.Op == "add" && sc.Families[op.Fam].Kind == "counter" {
				s += fmt.Sprintf(", .n = %d", op.N)
			} else if op.Op != "inc" && op.Op != "dec" {
				s += ", .v = " + zf64(op.V)
			}
			ops = append(ops, s+" }")
		}
		fmt.Fprintf(&o, "    .{ .families = &.{ %s }, .ops = &.{ %s }, .text = %s, .class = %s },\n",
			strings.Join(fams, ", "), strings.Join(ops, ", "), zstr(string(text)), zstr(class))
	}
	fmt.Fprintf(&o, "};\n")
	fmt.Fprintf(os.Stderr, "%d scripts; classes %v; %d mismatches\n", len(scripts), classes, bad)
	must(os.WriteFile(outPath, o.Bytes(), 0o644))
	if bad != 0 {
		return 1
	}
	return 0
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: go_oracle gen -n N -seed S | judge SCRIPTS OURS OUT")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "gen":
		fs := flag.NewFlagSet("gen", flag.ExitOnError)
		n := fs.Int("n", 160, "scripts")
		seed := fs.Int64("seed", 2026, "seed")
		fs.Parse(os.Args[2:])
		must(json.NewEncoder(os.Stdout).Encode(gen(*n, *seed)))
	case "register":
		if len(os.Args) < 3 {
			os.Exit(2)
		}
		os.Exit(register(os.Args[2]))
	case "judge":
		if len(os.Args) < 5 {
			os.Exit(2)
		}
		os.Exit(judge(os.Args[2], os.Args[3], os.Args[4]))
	default:
		os.Exit(2)
	}
}
