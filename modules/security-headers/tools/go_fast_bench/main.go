// SPDX-License-Identifier: MIT

// "Fastest in the field" side of `zig build bench-security-headers`
// (modules/security-headers/tools/bench.zig): times the helmet middleware of
// github.com/gofiber/fiber/v3 v3.6.1 (middleware/helmet; pinned with its
// dependencies, fasthttp v1.75.0 among them, by go.mod/go.sum) through fiber's
// public API only, for the one workload named by the second argument and the
// contender named by the third (only "fiber" today; the first argument, the
// work directory, is unused: the request is built here). Prints one line,
// tab-separated: name, ns/op, count. A workload the contender cannot do prints
// `name<TAB>unsupported` and exits 3 (the Zig side drops the row for it).
// One op = 64 responses, as on the other sides.
//
//	apply_default / apply_static
//	            the default header set of the Zig side (9 headers, see bench.zig)
//	csp_nonce   UNSUPPORTED: helmet takes a fixed ContentSecurityPolicy string;
//	            it has no per-request nonce (no template, no hook), so a like
//	            for like row does not exist. (A Next/own middleware drawing a
//	            nonce would be our code, not the contender's.)
//
// What differs from our module, stated so the rows are not read as more than
// they are:
//   - helmet cannot switch a header off: every empty Config field is replaced
//     by its default in configDefault. It therefore ALSO emits
//     Cross-Origin-Embedder-Policy: require-corp, Origin-Agent-Cluster: ?1 and
//     X-Download-Options: noopen, which the Zig side leaves off. They are real
//     work in the timing (a handicap for fiber, 3 of 12 header sets) but are
//     left out of the count, which tallies only the 9 headers both sides emit.
//   - Strict-Transport-Security is gated on c.Secure(). In process there is no
//     TLS, so the request carries X-Forwarded-Proto: https from a trusted
//     (loopback) proxy address; fiber scans the request headers for it on every
//     response (a gate of fiber's own, ours has none).
//   - XFrameOptions is set to DENY (default SAMEORIGIN); HSTSMaxAge 31536000
//     with subdomains (the default) matches ours.
//   - the HTTP stack is fasthttp, driven in-process without sockets: a
//     fasthttp.RequestCtx whose request is parsed once, the app's Handler()
//     run per response over it. Routing and ctx acquisition are fiber's, not
//     the middleware's, so they are measured by the identical app WITHOUT
//     helmet and subtracted: the printed ns is (with helmet - without), the net
//     cost of the middleware, floored at 0.1. Ours and unrolled/secure have no
//     such stack in their rows.
//   - the count is taken outside the timed region (one pass over the 64
//     responses, tallying the nine names case-insensitively; fiber canonicalises
//     names, X-Xss-Protection vs X-XSS-Protection, same length).
//
// Timing matches the Zig side: double the batch until one batch takes over
// 100 ms, then keep the best of five.
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/helmet"
	"github.com/valyala/fasthttp"
)

const perOp = 64

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

// the nine headers both sides emit, lower case
var counted = [][]byte{
	[]byte("strict-transport-security"),
	[]byte("x-content-type-options"),
	[]byte("x-frame-options"),
	[]byte("referrer-policy"),
	[]byte("cross-origin-opener-policy"),
	[]byte("cross-origin-resource-policy"),
	[]byte("x-xss-protection"),
	[]byte("x-dns-prefetch-control"),
	[]byte("x-permitted-cross-domain-policies"),
}

func tally(h *fasthttp.ResponseHeader) int {
	sum := 0
	for k, v := range h.All() {
		for _, c := range counted {
			if bytes.EqualFold(k, c) {
				sum += 1 + len(k) + len(v)
				break
			}
		}
	}
	return sum
}

func appFor(withHelmet bool) *fiber.App {
	app := fiber.New(fiber.Config{
		TrustProxy:       true,
		TrustProxyConfig: fiber.TrustProxyConfig{Loopback: true},
	})
	if withHelmet {
		app.Use(helmet.New(helmet.Config{
			XFrameOptions: "DENY",
			HSTSMaxAge:    31536000, // includeSubDomains by default
		}))
	}
	app.Get("/", func(c fiber.Ctx) error { return nil })
	return app
}

func newCtx() *fasthttp.RequestCtx {
	var ctx fasthttp.RequestCtx
	wire := "GET / HTTP/1.1\r\nHost: t\r\nX-Forwarded-Proto: https\r\n\r\n"
	if err := ctx.Request.Read(bufio.NewReader(bytes.NewReader([]byte(wire)))); err != nil {
		panic(err)
	}
	ctx.SetRemoteAddr(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000})
	return &ctx
}

// loop returns the timed function: perOp responses through the handler.
func loop(handler fasthttp.RequestHandler, ctx *fasthttp.RequestCtx, count int) func() int {
	return func() int {
		for i := 0; i < perOp; i++ {
			ctx.Response.Reset()
			handler(ctx)
		}
		return count
	}
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: go_fast_bench <work dir> <workload> <contender>")
		os.Exit(2)
	}
	name, who := os.Args[2], os.Args[3]
	if who != "fiber" {
		fmt.Fprintln(os.Stderr, "unknown contender", who)
		os.Exit(2)
	}
	switch name {
	case "apply_default", "apply_static":
	case "csp_nonce":
		fmt.Printf("%s\tunsupported\n", name)
		os.Exit(3)
	default:
		fmt.Fprintln(os.Stderr, "unknown workload", name)
		os.Exit(2)
	}

	hh, hctx := appFor(true).Handler(), newCtx()
	bh, bctx := appFor(false).Handler(), newCtx()

	// the count, outside the timed region
	count := 0
	for i := 0; i < perOp; i++ {
		hctx.Response.Reset()
		hh(hctx)
		count += tally(&hctx.Response.Header)
	}
	bare := 0
	for i := 0; i < perOp; i++ {
		bctx.Response.Reset()
		bh(bctx)
		bare += tally(&bctx.Response.Header)
	}
	if bare != 0 {
		panic("the app without helmet emitted a counted header")
	}

	withNs, _ := timeIt(loop(hh, hctx, count))
	bareNs, _ := timeIt(loop(bh, bctx, 0))
	ns := withNs - bareNs
	if ns < 0.1 {
		ns = 0.1
	}
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
}
