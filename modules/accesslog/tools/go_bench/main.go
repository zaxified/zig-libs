// SPDX-License-Identifier: MIT

// Go side of `zig build bench-accesslog` (modules/accesslog/tools/bench.zig):
// times Go's own ways of writing an access-log line over the entries the Zig
// program writes into the directory given as the first argument
// (`entries.tsv`, 14 tab-separated fields, \x01 = absent), for the one
// workload named by the second. Prints one line: name, ns/op, result count
// (tab-separated). One op = all 16 entries written to a reused buffer; count =
// the number of bytes written. Standard library + go-logfmt v0.6.1 (pinned by
// go.mod/go.sum).
//
//	json_encoding  encoding/json Encoder (SetEscapeHTML(false)) over a struct
//	               with pointer fields (absent = null), one Encode per entry
//	json_slog      log/slog JSONHandler.Handle with one record per entry, the
//	               built-in time/level/msg dropped through ReplaceAttr
//	logfmt         github.com/go-logfmt/logfmt Encoder.EncodeKeyval per field,
//	               absent fields skipped, EndRecord per entry
//
// Timing matches the Zig side: double the batch until one batch takes over
// 100 ms, then keep the best of five.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-logfmt/logfmt"
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
	Ts         int64   `json:"ts"`
	RemoteAddr *string `json:"remote_addr"`
	Method     string  `json:"method"`
	Target     string  `json:"target"`
	Protocol   string  `json:"protocol"`
	Status     int     `json:"status"`
	ReqBytes   *uint64 `json:"request_bytes"`
	RespBytes  *uint64 `json:"response_bytes"`
	LatencyNs  *uint64 `json:"latency_ns"`
	UserAgent  *string `json:"user_agent"`
	Referer    *string `json:"referer"`
	RequestID  *string `json:"request_id"`
	TraceID    *string `json:"trace_id"`
	SpanID     *string `json:"span_id"`
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

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go_bench <work dir> <workload>")
		os.Exit(2)
	}
	dir, name := os.Args[1], os.Args[2]
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
	switch name {
	case "json_encoding":
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		f = func() int {
			buf.Reset()
			for i := range es {
				if err := enc.Encode(&es[i]); err != nil {
					panic(err)
				}
			}
			return buf.Len()
		}
	case "json_slog":
		h := slog.NewJSONHandler(&buf, &slog.HandlerOptions{ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && (a.Key == slog.LevelKey || a.Key == slog.MessageKey || a.Key == slog.TimeKey) {
				return slog.Attr{}
			}
			return a
		}})
		ctx := context.Background()
		optStr := func(k string, p *string) slog.Attr {
			if p == nil {
				return slog.Any(k, nil)
			}
			return slog.String(k, *p)
		}
		optUint := func(k string, p *uint64) slog.Attr {
			if p == nil {
				return slog.Any(k, nil)
			}
			return slog.Uint64(k, *p)
		}
		f = func() int {
			buf.Reset()
			for i := range es {
				e := &es[i]
				r := slog.NewRecord(time.Time{}, slog.LevelInfo, "", 0)
				r.AddAttrs(slog.Int64("ts", e.Ts), optStr("remote_addr", e.RemoteAddr), slog.String("method", e.Method),
					slog.String("target", e.Target), slog.String("protocol", e.Protocol), slog.Int("status", e.Status),
					optUint("request_bytes", e.ReqBytes), optUint("response_bytes", e.RespBytes), optUint("latency_ns", e.LatencyNs),
					optStr("user_agent", e.UserAgent), optStr("referer", e.Referer), optStr("request_id", e.RequestID),
					optStr("trace_id", e.TraceID), optStr("span_id", e.SpanID))
				if err := h.Handle(ctx, r); err != nil {
					panic(err)
				}
			}
			return buf.Len()
		}
	case "logfmt":
		enc := logfmt.NewEncoder(&buf)
		kvS := func(k string, p *string) {
			if p != nil {
				enc.EncodeKeyval(k, *p)
			}
		}
		kvU := func(k string, p *uint64) {
			if p != nil {
				enc.EncodeKeyval(k, *p)
			}
		}
		f = func() int {
			buf.Reset()
			for i := range es {
				e := &es[i]
				enc.EncodeKeyval("ts", e.Ts)
				kvS("remote_addr", e.RemoteAddr)
				enc.EncodeKeyval("method", e.Method)
				enc.EncodeKeyval("target", e.Target)
				enc.EncodeKeyval("protocol", e.Protocol)
				enc.EncodeKeyval("status", e.Status)
				kvU("request_bytes", e.ReqBytes)
				kvU("response_bytes", e.RespBytes)
				kvU("latency_ns", e.LatencyNs)
				kvS("user_agent", e.UserAgent)
				kvS("referer", e.Referer)
				kvS("request_id", e.RequestID)
				kvS("trace_id", e.TraceID)
				kvS("span_id", e.SpanID)
				if err := enc.EndRecord(); err != nil {
					panic(err)
				}
			}
			return buf.Len()
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown workload", name)
		os.Exit(2)
	}
	ns, count := timeIt(f)
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
	if os.Getenv("BENCH_DUMP") != "" {
		f()
		os.Stderr.Write(buf.Bytes())
	}
}
