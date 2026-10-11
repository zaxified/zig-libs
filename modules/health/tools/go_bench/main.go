// SPDX-License-Identifier: MIT

// Go side of `zig build bench-health` (modules/health/tools/bench.zig): times
// github.com/alexliesenfeld/health v0.8.1 (pinned by go.mod/go.sum) over the
// request bytes the Zig program writes into the directory given as the first
// argument, for the one workload named by the second, through its public API
// only. Prints one line: name, ns/op, result count (tab-separated). One op =
// every request once.
//
//	passthrough         a bare handler writing a fixed body (the net baseline)
//	liveness            NewHandler over a checker with no checks
//	readiness_3_up      three checks, all passing
//	readiness_3_down    three checks, one failing
//	readiness_3_nodetail  the same, WithDisabledDetails
//
// The checker runs with the cache OFF (WithDisabledCache) and autostart off, so
// every request runs every check, as the Zig module does; the checks are atomic
// flag loads on both sides. Each op is http.ReadRequest over the bytes + the
// handler writing the status line, headers and body into a buffer. count = the
// sum of the status codes + one per response whose body starts with
// `{"status":"` (the Go library also writes a timestamp per check, which the
// Zig module deliberately does not, so body lengths are not compared).
//
// Timing matches the Zig side: double the batch until one batch takes over
// 100 ms, then keep the best of five.
package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/alexliesenfeld/health"
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

var errDown = errors.New("down")

func flagCheck(name string, flag *atomic.Bool) health.Check {
	return health.Check{
		Name: name,
		Check: func(ctx context.Context) error {
			if flag.Load() {
				return nil
			}
			return errDown
		},
	}
}

func handlerFor(name string) http.Handler {
	var up, down atomic.Bool
	up.Store(true)
	var opts []health.CheckerOption
	switch name {
	case "passthrough":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("<none>"))
		})
	case "liveness":
	case "readiness_3_up":
		opts = append(opts, health.WithChecks(flagCheck("database", &up), flagCheck("cache", &up), flagCheck("queue", &up)))
	case "readiness_3_down":
		opts = append(opts, health.WithChecks(flagCheck("database", &up), flagCheck("cache", &down), flagCheck("queue", &up)))
	case "readiness_3_nodetail":
		opts = append(opts, health.WithDisabledDetails(), health.WithChecks(flagCheck("database", &up), flagCheck("cache", &down), flagCheck("queue", &up)))
	default:
		fmt.Fprintln(os.Stderr, "unknown workload", name)
		os.Exit(2)
	}
	opts = append(opts, health.WithDisabledCache(), health.WithDisabledAutostart(), health.WithTimeout(10*time.Second))
	return health.NewHandler(health.NewChecker(opts...))
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

	h := handlerFor(name)

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
			body := w.buf.Bytes()
			if i := bytes.Index(body, []byte("\r\n\r\n")); i >= 0 && bytes.HasPrefix(body[i+4:], []byte(`{"status":"`)) {
				sum++
			}
		}
		return sum
	})
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
}
