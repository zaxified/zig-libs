// SPDX-License-Identifier: MIT

// Go side of `zig build bench-requestid` (modules/requestid/tools/bench.zig):
// times go-chi/chi v5.3.2 (pinned by go.mod/go.sum) with and without
// middleware.RequestID, over the request bytes the Zig program writes into the
// directory given as the first argument, for the one workload named by the
// second, through chi's public API only. Prints one line: name, ns/op, result
// count (tab-separated). One op = every request once.
//
//	plain     Mux with one route "/", no middleware
//	generate  ... + middleware.RequestID, requests without X-Request-Id
//	adopt     ... + middleware.RequestID, requests carrying X-Request-Id
//
// Each op is http.ReadRequest over the bytes + Mux.ServeHTTP writing the status
// line, headers and body into a buffer. chi's RequestID only puts the id in the
// request context; to match the Zig module (which echoes it on the response
// and shows it to the handler) the handler here sets the response header from
// middleware.GetReqID and writes the id as the body. count = the sum of the
// status codes + one per response carrying an X-Request-Id header.
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

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
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

	mux := chi.NewRouter()
	if name != "plain" {
		mux.Use(middleware.RequestID)
	}
	mux.Get("/", func(w http.ResponseWriter, r *http.Request) {
		if name != "plain" {
			id := middleware.GetReqID(r.Context())
			w.Header().Set("X-Request-Id", id)
			w.Write([]byte(id))
			return
		}
		w.Write([]byte("<none>"))
	})

	ns, count := timeIt(func() int {
		sum := 0
		for _, bb := range wires {
			req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(bb)))
			if err != nil {
				panic(err)
			}
			w := &wire{h: http.Header{}}
			mux.ServeHTTP(w, req)
			if w.status == 0 {
				w.WriteHeader(http.StatusOK)
			}
			sum += w.status
			if w.h.Get("X-Request-Id") != "" {
				sum++
			}
		}
		return sum
	})
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
}
