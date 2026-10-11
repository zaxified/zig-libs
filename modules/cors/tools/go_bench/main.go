// SPDX-License-Identifier: MIT

// Go side of `zig build bench-cors` (modules/cors/tools/bench.zig): times
// github.com/rs/cors v1.11.1 (pinned by go.mod/go.sum) as a handler wrapped
// around a trivial one, over the request bytes the Zig program writes into the
// directory given as the first argument, for the one workload named by the
// second, through rs/cors's public API only. Prints one line: name, ns/op,
// result count (tab-separated). One op = every request once.
//
//	plain       trivial handler, no CORS (the same bytes as actual)
//	preflight   OPTIONS from a listed origin, ACRM PUT + ACRH
//	actual      GET from a listed origin
//	disallowed  GET from an origin on no list
//	wildcard    GET from an origin matching "https://*.tenant.example"
//
// The policy is the one in bench.zig: four listed origins plus the wildcard
// pattern, methods GET/POST/PUT, allowed headers Content-Type, Authorization,
// X-Requested-With, MaxAge 600, no credentials. Each op is http.ReadRequest
// over the bytes + the handler writing the status line, headers and body into
// a buffer. count = the sum of the status codes + one per response carrying an
// Access-Control-Allow-Origin header.
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

	"github.com/rs/cors"
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

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	var h http.Handler = mux
	if name != "plain" {
		h = cors.New(cors.Options{
			AllowedOrigins: []string{
				"https://app.example", "https://admin.example",
				"http://localhost:5173", "https://portal.example",
				"https://*.tenant.example",
			},
			AllowedMethods: []string{http.MethodGet, http.MethodPost, http.MethodPut},
			AllowedHeaders: []string{"Content-Type", "Authorization", "X-Requested-With"},
			MaxAge:         600,
		}).Handler(mux)
	}

	ns, count := timeIt(func() int {
		sum := 0
		for _, bb := range wires {
			req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(bb)))
			if err != nil {
				panic(err)
			}
			w := &wire{h: http.Header{}}
			h.ServeHTTP(w, req)
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
