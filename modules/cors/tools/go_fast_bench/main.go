// SPDX-License-Identifier: MIT

// "Fastest in the field" side of `zig build bench-cors`
// (modules/cors/tools/bench.zig): times the CORS middleware of
// github.com/labstack/echo/v5 v5.4.2 (pinned by go.mod/go.sum) through Echo's
// public API only, over the request bytes the Zig program writes into the
// directory given as the first argument, for the one workload named by the
// second and the contender named by the third (only "echo" today). Prints one
// line, tab-separated: name, ns/op, count. A workload the contender cannot do
// prints `name<TAB>unsupported` and exits 3 (the Zig side drops the row for it).
//
//	plain       Echo router + trivial handler, no CORS middleware
//	preflight   OPTIONS from a listed origin, ACRM PUT + ACRH
//	actual      GET from a listed origin
//	disallowed  GET from an origin on no list
//	wildcard    UNSUPPORTED: Echo's AllowOrigins is compared whole,
//	            case-insensitively (strings.EqualFold), with no pattern; the
//	            only way is UnsafeAllowOriginFunc with a hand-written matcher,
//	            which would time our code, not the library's.
//
// Policy: the four listed origins, methods GET/POST/PUT, allowed headers
// Content-Type/Authorization/X-Requested-With, MaxAge 600, no credentials.
// Each op is http.ReadRequest over the bytes + Echo.ServeHTTP writing the
// status line, headers and body into a buffer (the `wire` writer of
// ../go_bench). count = the sum of the status codes + one per response
// carrying an Access-Control-Allow-Origin header.
//
// What differs from the reference (rs/cors), stated so the rows are not read
// as more than they are: Echo's middleware does LESS than rs/cors and ours on
// a preflight. It does not check Access-Control-Request-Method against the
// allowed methods, nor the requested headers against the allowed ones (it
// answers with the configured lists), and it answers a preflight from an
// unlisted origin with 204 and no CORS headers. The workloads here only send
// preflights that are granted by every implementation, so the counts agree;
// the work done is not the same.
//
// Timing matches the Zig side: double the batch until one batch takes over
// 100 ms, then keep the best of five.
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
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

// A ResponseWriter that renders what a server would put on the wire.
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

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: go_fast_bench <work dir> <workload> <contender>")
		os.Exit(2)
	}
	dir, name, who := os.Args[1], os.Args[2], os.Args[3]
	if who != "echo" {
		fmt.Fprintln(os.Stderr, "unknown contender", who)
		os.Exit(2)
	}
	if name == "wildcard" {
		fmt.Printf("%s\tunsupported\n", name)
		os.Exit(3)
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

	e := echo.New()
	if name != "plain" {
		e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
			AllowOrigins: []string{
				"https://app.example", "https://admin.example",
				"http://localhost:5173", "https://portal.example",
			},
			AllowMethods: []string{http.MethodGet, http.MethodPost, http.MethodPut},
			AllowHeaders: []string{"Content-Type", "Authorization", "X-Requested-With"},
			MaxAge:       600,
		}))
	}
	e.GET("/", func(c *echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	ns, count := timeIt(func() int {
		sum := 0
		for _, bb := range wires {
			req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(bb)))
			if err != nil {
				panic(err)
			}
			w := &wire{h: http.Header{}}
			e.ServeHTTP(w, req)
			if w.status == 0 {
				w.WriteHeader(http.StatusOK)
			}
			sum += w.status
			if w.h.Get("Access-Control-Allow-Origin") != "" {
				sum++
			}
		}
		return sum
	})
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
}
