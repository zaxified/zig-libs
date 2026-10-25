// SPDX-License-Identifier: MIT

// Fastest-in-the-field side of `zig build bench-accesslog`
// (modules/accesslog/tools/bench.zig): writes the same JSON Lines access-log
// records as the reference row `json_encoding` with the fastest Go loggers --
// rs/zerolog, uber-go/zap and phuslu/log (pinned by go.mod/go.sum) -- through
// their public APIs, over the entries that program writes into the directory
// given as the first argument; the second names the contender. Absent fields
// are written as null, as ours and encoding/json do. Prints: workload, ns/op,
// bytes -- tab-separated.
//
// phuslu/log cannot drop its clock time header: its "ts" field is the wall
// clock in Unix milliseconds (13 digits, ours is the entry's 19-digit
// nanoseconds), so its line is 6 bytes shorter per record and the byte count
// is reported with that difference added back (`BENCH_DUMP=1` shows the
// lines). Timing as the other sides: double the batch until it takes over
// 100 ms, keep the best of five.
package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	plog "github.com/phuslu/log"
	"github.com/rs/zerolog"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
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

type entry struct {
	Ts                                             int64
	RemoteAddr                                     *string
	Method, Target, Protocol                       string
	Status                                         int
	ReqBytes, RespBytes, LatencyNs                 *uint64
	UserAgent, Referer, RequestID, TraceID, SpanID *string
}

const absent = "\x01"

func optS(s string) *string {
	if s == absent {
		return nil
	}
	return &s
}

func optU(s string) *uint64 {
	if s == absent {
		return nil
	}
	v, _ := strconv.ParseUint(s, 10, 64)
	return &v
}

var null = []byte("null")

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go_fast_bench <work dir> <contender>")
		os.Exit(2)
	}
	dir, who := os.Args[1], os.Args[2]
	b, err := os.ReadFile(filepath.Join(dir, "entries.tsv"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var es []entry
	for _, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		f := strings.Split(l, "\t")
		ts, _ := strconv.ParseInt(f[0], 10, 64)
		st, _ := strconv.Atoi(f[5])
		es = append(es, entry{Ts: ts, RemoteAddr: optS(f[1]), Method: f[2], Target: f[3], Protocol: f[4], Status: st,
			ReqBytes: optU(f[6]), RespBytes: optU(f[7]), LatencyNs: optU(f[8]), UserAgent: optS(f[9]), Referer: optS(f[10]),
			RequestID: optS(f[11]), TraceID: optS(f[12]), SpanID: optS(f[13])})
	}

	var buf bytes.Buffer
	var f func() int
	switch who {
	case "zerolog":
		l := zerolog.New(&buf)
		s := func(e *zerolog.Event, k string, p *string) *zerolog.Event {
			if p == nil {
				return e.RawJSON(k, null)
			}
			return e.Str(k, *p)
		}
		u := func(e *zerolog.Event, k string, p *uint64) *zerolog.Event {
			if p == nil {
				return e.RawJSON(k, null)
			}
			return e.Uint64(k, *p)
		}
		f = func() int {
			buf.Reset()
			for i := range es {
				x := &es[i]
				e := l.Log().Int64("ts", x.Ts)
				e = s(e, "remote_addr", x.RemoteAddr).Str("method", x.Method).Str("target", x.Target).Str("protocol", x.Protocol).Int("status", x.Status)
				e = u(e, "request_bytes", x.ReqBytes)
				e = u(e, "response_bytes", x.RespBytes)
				e = u(e, "latency_ns", x.LatencyNs)
				e = s(e, "user_agent", x.UserAgent)
				e = s(e, "referer", x.Referer)
				e = s(e, "request_id", x.RequestID)
				e = s(e, "trace_id", x.TraceID)
				e = s(e, "span_id", x.SpanID)
				e.Send()
			}
			return buf.Len()
		}
	case "zap":
		enc := zapcore.NewJSONEncoder(zapcore.EncoderConfig{LineEnding: "\n"})
		l := zap.New(zapcore.NewCore(enc, zapcore.AddSync(&buf), zapcore.DebugLevel))
		s := func(k string, p *string) zap.Field {
			if p == nil {
				return zap.Reflect(k, nil)
			}
			return zap.String(k, *p)
		}
		u := func(k string, p *uint64) zap.Field {
			if p == nil {
				return zap.Reflect(k, nil)
			}
			return zap.Uint64(k, *p)
		}
		f = func() int {
			buf.Reset()
			for i := range es {
				x := &es[i]
				l.Info("", zap.Int64("ts", x.Ts), s("remote_addr", x.RemoteAddr), zap.String("method", x.Method),
					zap.String("target", x.Target), zap.String("protocol", x.Protocol), zap.Int("status", x.Status),
					u("request_bytes", x.ReqBytes), u("response_bytes", x.RespBytes), u("latency_ns", x.LatencyNs),
					s("user_agent", x.UserAgent), s("referer", x.Referer), s("request_id", x.RequestID),
					s("trace_id", x.TraceID), s("span_id", x.SpanID))
			}
			return buf.Len()
		}
	case "phuslu":
		l := plog.Logger{Writer: plog.IOWriter{Writer: &buf}, TimeField: "ts", TimeFormat: plog.TimeFormatUnixMs}
		s := func(e *plog.Entry, k string, p *string) *plog.Entry {
			if p == nil {
				return e.RawJSON(k, null)
			}
			return e.Str(k, *p)
		}
		u := func(e *plog.Entry, k string, p *uint64) *plog.Entry {
			if p == nil {
				return e.RawJSON(k, null)
			}
			return e.Uint64(k, *p)
		}
		f = func() int {
			buf.Reset()
			for i := range es {
				x := &es[i]
				e := l.Log()
				e = s(e, "remote_addr", x.RemoteAddr).Str("method", x.Method).Str("target", x.Target).Str("protocol", x.Protocol).Int("status", x.Status)
				e = u(e, "request_bytes", x.ReqBytes)
				e = u(e, "response_bytes", x.RespBytes)
				e = u(e, "latency_ns", x.LatencyNs)
				e = s(e, "user_agent", x.UserAgent)
				e = s(e, "referer", x.Referer)
				e = s(e, "request_id", x.RequestID)
				e = s(e, "trace_id", x.TraceID)
				e = s(e, "span_id", x.SpanID)
				e.Msg("")
			}
			return buf.Len() + 6*len(es)
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown contender", who)
		os.Exit(2)
	}
	ns, count := timeIt(f)
	fmt.Printf("json_encoding\t%.1f\t%d\n", ns, count)
	if os.Getenv("BENCH_DUMP") != "" {
		f()
		os.Stderr.Write(buf.Bytes())
	}
}
