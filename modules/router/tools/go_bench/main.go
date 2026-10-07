// SPDX-License-Identifier: MIT

// Go side of `zig build bench-router` (modules/router/tools/bench.zig): times
// go-chi/chi v5.3.2 (pinned by go.mod/go.sum) over the route table and the
// requests that program writes into the directory given as the only argument,
// through chi's public API only. Prints one line per workload: name, ns/op,
// result count — tab-separated. One op = every request once.
//
//	lookup  chi's Mux.Match with a reset route context; count = matches
//	serve   http.ReadRequest over the request bytes + Mux.ServeHTTP writing
//	        the status line, headers and body into a buffer; count = the sum
//	        of the status codes
//
// Timing matches the Zig side: double the iteration count until one batch
// takes over 100 ms, then keep the best of five batches.
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

func readTSV(path string) [][2]string {
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var out [][2]string
	for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 2 {
			fmt.Fprintf(os.Stderr, "bad line %q\n", line)
			os.Exit(1)
		}
		out = append(out, [2]string{f[0], f[1]})
	}
	return out
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
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go_bench <work dir>")
		os.Exit(2)
	}
	dir := os.Args[1]
	routes := readTSV(filepath.Join(dir, "routes.tsv"))
	reqs := readTSV(filepath.Join(dir, "requests.tsv"))

	mux := chi.NewRouter()
	ok := func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }
	for _, r := range routes {
		mux.MethodFunc(r[0], r[1], ok)
	}

	rctx := chi.NewRouteContext()
	ns, count := timeIt(func() int {
		found := 0
		for _, q := range reqs {
			rctx.Reset()
			if mux.Match(rctx, q[0], q[1]) {
				found++
			}
		}
		return found
	})
	fmt.Printf("lookup\t%.1f\t%d\n", ns, count)

	wires := make([][]byte, len(reqs))
	for i, q := range reqs {
		wires[i] = []byte(q[0] + " " + q[1] + " HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
	}
	ns, count = timeIt(func() int {
		sum := 0
		for _, b := range wires {
			req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(b)))
			if err != nil {
				panic(err)
			}
			w := &wire{h: http.Header{}}
			mux.ServeHTTP(w, req)
			if w.status == 0 {
				w.WriteHeader(http.StatusOK)
			}
			sum += w.status
		}
		return sum
	})
	fmt.Printf("serve\t%.1f\t%d\n", ns, count)
}
