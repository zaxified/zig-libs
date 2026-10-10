// SPDX-License-Identifier: MIT

// Go side of `zig build bench-staticfiles` (modules/staticfiles/tools/bench.zig):
// times Go's net/http FileServer(http.Dir) over the file tree and the request
// bytes the Zig program writes into the directory given as the first argument
// (`root/` and `<workload>.wire`, request bytes NUL-separated), for the
// workload named by the second. Prints one
// line: name, ns/op, result count (tab-separated). One op = every request once.
// Standard library only.
//
//	small, large, cond, miss -- the request sets listed in bench.zig, each:
//	       http.ReadRequest over the bytes + FileServer.ServeHTTP writing the
//	       status line, headers and body into a buffer; count = the sum of the
//	       status codes + the body bytes of every 200 / 206
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
	body   int
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
	w.body += len(p)
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
	fs := http.FileServer(http.Dir(filepath.Join(dir, "root")))
	ns, count := timeIt(func() int {
		total := 0
		for _, bb := range wires {
			req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(bb)))
			if err != nil {
				panic(err)
			}
			w := &wire{h: http.Header{}}
			fs.ServeHTTP(w, req)
			if w.status == 0 {
				w.WriteHeader(http.StatusOK)
			}
			total += w.status
			if w.status == 200 || w.status == 206 {
				total += w.body
			}
		}
		return total
	})
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
}
