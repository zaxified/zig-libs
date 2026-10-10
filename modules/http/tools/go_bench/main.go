// SPDX-License-Identifier: MIT

// Go side of `zig build bench-http` (modules/http/tools/bench.zig): times Go's
// net/http request parser and ResponseWriter plumbing over the request bytes
// the Zig program writes into the directory given as the first argument
// (`<workload>.wire`: 16 keep-alive requests back to back, the last with
// `Connection: close`), for the workload named by the second. Prints one line:
// name, ns/op, result count (tab-separated). One op = the whole byte stream.
// Standard library only.
//
// One op = a bufio.Reader over the bytes, then http.ReadRequest in a loop (the
// way a connection goroutine reads), a handler, and the response rendered
// (status line, headers, body) into a per-request buffer, the way the real
// server would write it to the socket minus the syscall and the Date header.
// The handlers are the same as the Zig side's:
//
//	get      read User-Agent; set Content-Type, X-Request-Cost, Cache-Control and
//	         Content-Length; write a 200-byte JSON body
//	post     read the whole 1 KiB request body; answer "ok"
//	chunked  the same for a chunked request body (3 x 500 bytes)
//	large    set Content-Length 65536; write 16 x 4096 bytes
//	headers  GET carrying 40 headers; look one up; answer "ok"
//
// count = per request 200 + the request-body bytes read + the response-body
// bytes written + the length of the header looked up. Before timing, one op is
// run and must have produced exactly 16 "HTTP/1.1 200 " responses.
//
// Timing matches the Zig side: double the batch until one batch takes over
// 100 ms, then keep the best of five.
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
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

const jsonBody = `{"id":42,"name":"example","tags":["a","b","c"],"active":true,"score":3.14159,"description":"A short JSON document returned by the benchmark handler so that the response has a body of a realistic size.","n":1}` + "                    "

var block = bytes.Repeat([]byte("x"), 4096)
var ok = []byte("ok")

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go_bench <work dir> <workload>")
		os.Exit(2)
	}
	dir, name := os.Args[1], os.Args[2]
	input, err := os.ReadFile(filepath.Join(dir, name+".wire"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	body := []byte(jsonBody[:200])
	responses := 0
	op := func() int {
		total := 0
		responses = 0
		br := bufio.NewReader(bytes.NewReader(input))
		for {
			req, err := http.ReadRequest(br)
			if err == io.EOF {
				break
			}
			if err != nil {
				panic(err)
			}
			w := &wire{h: http.Header{}}
			switch name {
			case "get":
				total += len(req.Header.Get("User-Agent"))
				w.h.Set("Content-Type", "application/json")
				w.h.Set("X-Request-Cost", "12")
				w.h.Set("Cache-Control", "no-store")
				w.h.Set("Content-Length", strconv.Itoa(len(body)))
				w.Write(body)
				total += len(body)
			case "post", "chunked":
				n, _ := io.Copy(io.Discard, req.Body)
				total += int(n)
				w.h.Set("Content-Length", "2")
				w.Write(ok)
				total += 2
			case "large":
				w.h.Set("Content-Length", "65536")
				for i := 0; i < 16; i++ {
					w.Write(block)
				}
				total += 65536
			case "headers":
				total += len(req.Header.Get("X-Trace-Id"))
				w.h.Set("Content-Length", "2")
				w.Write(ok)
				total += 2
			default:
				fmt.Fprintln(os.Stderr, "unknown workload", name)
				os.Exit(2)
			}
			io.Copy(io.Discard, req.Body)
			if w.status == 0 {
				w.WriteHeader(http.StatusOK)
			}
			total += w.status
			if bytes.HasPrefix(w.buf.Bytes(), []byte("HTTP/1.1 200 ")) {
				responses++
			}
		}
		return total
	}
	op()
	if responses != 16 {
		fmt.Fprintf(os.Stderr, "expected 16 responses, got %d\n", responses)
		os.Exit(1)
	}
	ns, count := timeIt(op)
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
}
