// SPDX-License-Identifier: MIT

// "Fastest in the field" side of `zig build bench-health`
// (modules/health/tools/bench.zig): times the healthcheck middleware of
// github.com/gofiber/fiber/v3 v3.6.1 (middleware/healthcheck; pinned with its
// dependencies, fasthttp v1.75.0 among them, by go.mod/go.sum) through fiber's
// public API only, over the request bytes the Zig program writes into the
// directory given as the first argument, for the one workload named by the
// second and the contender named by the third (only "fiber" today). Prints one
// line, tab-separated: name, ns/op, count. A workload the contender cannot do
// prints `name<TAB>unsupported` and exits 3 (the Zig side drops the row for it);
// none is unsupported today.
//
//	passthrough           fiber app, one route /other, no healthcheck
//	liveness              GET /healthz, Probe always true
//	readiness_3_up        GET /readyz, Probe = three atomic flags, all set
//	readiness_3_down      the same, one flag clear -> 503
//	readiness_3_nodetail  identical to readiness_3_down (fiber has no detail
//	                      switch: its body is never more than the status)
//
// What differs from our module and from the reference (alexliesenfeld/health),
// stated so the rows are not read as more than they are:
//   - fiber's healthcheck has no registry of named checks and no per-check
//     detail: it calls ONE Probe func(fiber.Ctx) bool and answers
//     {"status":"OK"} / {"status":"Service Unavailable"} (ResponseFormat
//     FormatJSON; the default is plain text). The three checks are folded into
//     that one Probe (three atomic loads, the same loads the other sides do), so
//     the readiness bodies are SHORTER than ours and the detail rows do the
//     same work as the nodetail one. The count compares only the status code
//     and the `{"status":"` body prefix, which every side produces.
//   - fiber evaluates no timeout, cache or concurrency around the probe; ours
//     and the reference run each check through their own bookkeeping.
//   - the HTTP stack is fasthttp, driven in-process without sockets: one
//     fasthttp.RequestCtx, Request.Read over the bytes, the app's Handler(),
//     Response.Write into a buffer. No Date/Server headers are added (those are
//     the fasthttp Server's, which is not in the loop), unlike the net/http
//     `wire` writer of the other Go sides which also adds none. The plain row
//     (passthrough) measures this stack so the Zig side can take the net cost.
//
// Timing matches the Zig side: double the batch until one batch takes over
// 100 ms, then keep the best of five.
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/healthcheck"
	"github.com/valyala/fasthttp"
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

func probe(flags ...*atomic.Bool) func(fiber.Ctx) bool {
	return func(fiber.Ctx) bool {
		for _, f := range flags {
			if !f.Load() {
				return false
			}
		}
		return true
	}
}

func appFor(name string) *fiber.App {
	var up, down atomic.Bool
	up.Store(true)
	app := fiber.New()
	app.Get("/other", func(c fiber.Ctx) error {
		return c.SendString("<none>")
	})
	cfg := healthcheck.Config{ResponseFormat: healthcheck.FormatJSON}
	switch name {
	case "passthrough":
		return app
	case "liveness":
		app.Get("/healthz", healthcheck.New(cfg))
	case "readiness_3_up":
		cfg.Probe = probe(&up, &up, &up)
		app.Get("/readyz", healthcheck.New(cfg))
	case "readiness_3_down", "readiness_3_nodetail":
		cfg.Probe = probe(&up, &down, &up)
		app.Get("/readyz", healthcheck.New(cfg))
	default:
		fmt.Fprintln(os.Stderr, "unknown workload", name)
		os.Exit(2)
	}
	return app
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: go_fast_bench <work dir> <workload> <contender>")
		os.Exit(2)
	}
	dir, name, who := os.Args[1], os.Args[2], os.Args[3]
	if who != "fiber" {
		fmt.Fprintln(os.Stderr, "unknown contender", who)
		os.Exit(2)
	}
	b, err := os.ReadFile(filepath.Join(dir, name+".wire"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var wires [][]byte
	for _, l := range strings.Split(strings.TrimRight(string(b), "\x00"), "\x00") {
		wires = append(wires, []byte(l))
	}

	handler := appFor(name).Handler()
	prefix := []byte(`{"status":"`)
	var ctx fasthttp.RequestCtx
	var in bytes.Reader
	br := bufio.NewReader(&in)
	var out bytes.Buffer
	bw := bufio.NewWriter(&out)

	ns, count := timeIt(func() int {
		sum := 0
		for _, bb := range wires {
			ctx.Request.Reset()
			ctx.Response.Reset()
			in.Reset(bb)
			br.Reset(&in)
			if err := ctx.Request.Read(br); err != nil {
				panic(err)
			}
			handler(&ctx)
			out.Reset()
			bw.Reset(&out)
			if err := ctx.Response.Write(bw); err != nil {
				panic(err)
			}
			if err := bw.Flush(); err != nil {
				panic(err)
			}
			sum += ctx.Response.StatusCode()
			if bytes.HasPrefix(ctx.Response.Body(), prefix) {
				sum++
			}
		}
		return sum
	})
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
}
