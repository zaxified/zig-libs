// SPDX-License-Identifier: MIT

// Go side of `zig build bench-aaa-gate` (modules/aaa-gate/tools/bench.zig):
// times labstack/echo v5.4.0 `middleware.KeyAuthWithConfig` (pinned by
// go.mod/go.sum) as middleware of an echo instance with one trivial route,
// over the request bytes the Zig program writes into the directory given as
// the first argument, for the one workload named by the second, through
// echo's public API only. Prints one line: name, ns/op, result count
// (tab-separated). One op = every request (64) once.
//
// Workloads (the `_plain` twin of each runs the same bytes through an echo
// instance WITHOUT the middleware; the Zig side subtracts it, see bench.zig):
//
//	bearer_ok          KeyLookup "header:Authorization:Bearer ", valid token
//	bearer_denied      same lookup, a token that is on no list (401)
//	api_key_header_ok  KeyLookup "header:X-Api-Key"
//	api_key_query_ok   KeyLookup "query:api_key"
//	no_credential      the bearer lookup, no credential sent (401)
//
// echo leaves the comparison to the Validator, so the validator is the
// documented constant-time one (KeyAuthValidator's own "SECURE" example):
// subtle.ConstantTimeCompare of the presented key against each of the three
// configured keys, returning on the first match. Each op is Echo.ServeHTTP
// over requests parsed once beforehand (http.ReadRequest, untimed), into a
// ResponseWriter that renders the
// status line, headers and body into a buffer (as a server would put them
// on the wire). count = the sum of the status codes.
//
// Timing matches the Zig side: double the batch until one batch takes over
// 100 ms, then keep the best of five.
package main

import (
	"bufio"
	"bytes"
	"crypto/subtle"
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

// The three configured keys (the same for tokens and API keys, as in bench.zig).
var keys = [][]byte{
	[]byte("tok-alpha-0123456789abcdef"),
	[]byte("tok-bravo-0123456789abcdef"),
	[]byte("tok-charlie-0123456789abcd"),
}

// echo's KeyAuthValidator documentation's constant-time example.
func validator(c *echo.Context, key string, source middleware.ExtractorSource) (bool, error) {
	kb := []byte(key)
	for _, k := range keys {
		if subtle.ConstantTimeCompare(kb, k) == 1 {
			return true, nil
		}
	}
	return false, nil
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
	// Parsed once, outside the timed region: the layer is "router + middleware
	// + response rendering", not head parsing (as on the Zig side).
	var reqs []*http.Request
	for _, l := range strings.Split(strings.TrimRight(string(b), "\x00"), "\x00") {
		req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(l)))
		if err != nil {
			panic(err)
		}
		reqs = append(reqs, req)
	}

	lookup := ""
	switch strings.TrimSuffix(name, "_plain") {
	case "bearer_ok", "bearer_denied", "no_credential":
		lookup = "header:Authorization:Bearer "
	case "api_key_header_ok":
		lookup = "header:X-Api-Key"
	case "api_key_query_ok":
		lookup = "query:api_key"
	default:
		fmt.Fprintln(os.Stderr, "unknown workload", name)
		os.Exit(2)
	}

	e := echo.New()
	if !strings.HasSuffix(name, "_plain") {
		e.Use(middleware.KeyAuthWithConfig(middleware.KeyAuthConfig{KeyLookup: lookup, Validator: validator}))
	}
	e.GET("/", func(c *echo.Context) error { return c.String(http.StatusOK, "ok") })

	ns, count := timeIt(func() int {
		sum := 0
		for _, req := range reqs {
			w := &wire{h: http.Header{}}
			e.ServeHTTP(w, req)
			if w.status == 0 {
				w.WriteHeader(http.StatusOK)
			}
			sum += w.status
		}
		return sum
	})
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
}
