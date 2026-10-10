// SPDX-License-Identifier: MIT

// Go side of `zig build bench-tracecontext` (modules/tracecontext/tools/bench.zig):
// times OpenTelemetry Go's W3C propagator (go.opentelemetry.io/otel v1.46.0,
// pinned by go.mod/go.sum) over the request bytes the Zig program writes into
// the directory given as the first argument, for the one workload named by the
// second, through its public API only. Prints one line: name, ns/op, result
// count (tab-separated). One op = every request once.
//
// Each op is http.ReadRequest over the bytes + a handler writing the status
// line, headers and body into a buffer. The handler does what the Zig module's
// middleware does:
//
//	plain      nothing (the HTTP-stack baseline; excluded from the verdict)
//	propagate  propagation.TraceContext.Extract the incoming traceparent, make a
//	           child span id, Inject traceparent on the response
//	state      the same with a tracestate header (Extract parses it, Inject
//	           writes it back)
//	fresh      no incoming traceparent: a new trace id and span id, sampled,
//	           Inject
//
// The OTel SDK's id generator is not in the pinned modules; ids come from
// math/rand/v2 (what the SDK's default generator uses). count = the sum of the
// status codes + per response: 1 for a 55-byte traceparent, 1 for a
// tracestate header, and (propagate/state) the byte sums of the trace id and
// the flags in the echoed traceparent.
//
// Timing matches the Zig side: double the batch until one batch takes over
// 100 ms, then keep the best of five.
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
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

func sum(s string) int {
	t := 0
	for i := 0; i < len(s); i++ {
		t += int(s[i])
	}
	return t
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go_bench <work dir> <workload>")
		os.Exit(2)
	}
	dir, name := os.Args[1], os.Args[2]
	b, err := os.ReadFile(filepath.Join(dir, name+".wire"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var wires [][]byte
	for _, l := range strings.Split(strings.TrimRight(string(b), "\x00"), "\x00") {
		wires = append(wires, []byte(l))
	}

	prop := propagation.TraceContext{}
	handler := func(w http.ResponseWriter, r *http.Request) {
		if name != "plain" {
			ctx := prop.Extract(r.Context(), propagation.HeaderCarrier(r.Header))
			sc := trace.SpanContextFromContext(ctx)
			var sid trace.SpanID
			a := rand.Uint64()
			for i := 0; i < 8; i++ {
				sid[i] = byte(a >> (8 * i))
			}
			if sc.IsValid() {
				sc = sc.WithSpanID(sid)
			} else {
				var tid trace.TraceID
				a, c := rand.Uint64(), rand.Uint64()
				for i := 0; i < 8; i++ {
					tid[i] = byte(a >> (8 * i))
					tid[8+i] = byte(c >> (8 * i))
				}
				sc = trace.NewSpanContext(trace.SpanContextConfig{TraceID: tid, SpanID: sid, TraceFlags: trace.FlagsSampled})
			}
			ctx = trace.ContextWithSpanContext(ctx, sc)
			prop.Inject(ctx, propagation.HeaderCarrier(w.Header()))
		}
		w.Write([]byte("ok"))
	}

	ns, count := timeIt(func() int {
		total := 0
		for _, bb := range wires {
			req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(bb)))
			if err != nil {
				panic(err)
			}
			w := &wire{h: http.Header{}}
			handler(w, req)
			if w.status == 0 {
				w.WriteHeader(http.StatusOK)
			}
			total += w.status
			if tp := w.h.Get("traceparent"); len(tp) == 55 {
				total++
				if name == "propagate" || name == "state" {
					total += sum(tp[3:35]) + sum(tp[53:55])
				}
			}
			if w.h.Get("tracestate") != "" {
				total++
			}
		}
		return total
	})
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
}
