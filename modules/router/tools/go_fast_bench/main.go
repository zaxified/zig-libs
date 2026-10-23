// SPDX-License-Identifier: MIT

// Go side of the "fastest in the field" part of `zig build bench-router`
// (modules/router/tools/bench.zig): times the fastest-by-reputation Go routers
// over the route table and the requests that program writes into the directory
// given as the second argument, through each router's public API only.
//
//	go_fast_bench <contender> <work dir>
//
// contenders (versions pinned by go.mod/go.sum):
//
//	httprouter  julienschmidt/httprouter v1.3.0   Router.Lookup(method, path)
//	echo        labstack/echo/v4 v4.16.2          Router.Find(method, path, ctx), then
//	                                              the matched handler is called
//	bunrouter   uptrace/bunrouter v1.0.23         Router.ServeHTTPError over a
//	                                              prebuilt *http.Request (bunrouter
//	                                              has no public lookup call)
//
// The work dir holds routes_plain.tsv and requests_plain.tsv: the subset of the
// benchmark's table that routers with the colon syntax can express (whole-segment
// `{name}` captures, static segments, a trailing `*`; no regexp constraints, no
// captures inside a segment). A route this program cannot translate faithfully
// is an error (exit 3, `unsupported` on stdout): it is never dropped or
// rewritten here, so the table is the same for every contender and for us.
//
// Output: one line, `lookup<TAB>ns/op<TAB>count`, where one op is every request
// once and count is the number of requests that reach a handler (a 404, a 405
// and a redirect hint all count as "no match"). Timing matches go_bench and the
// Zig side: double the iteration count until one batch takes over 100 ms, then
// keep the best of five batches.
package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/labstack/echo/v4"
	"github.com/uptrace/bunrouter"
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

// colon rewrites a pattern of the benchmark's `{name}` syntax into the colon
// syntax: `{name}` as a whole segment becomes `:name`, a final `*` becomes
// wildcard (httprouter and bunrouter need it named). Anything else that
// contains a brace, a colon or a star is refused.
func colon(pattern, wildcard string) (string, bool) {
	segs := strings.Split(pattern, "/")
	for i, s := range segs {
		switch {
		case strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") && len(s) > 2:
			name := s[1 : len(s)-1]
			if strings.ContainsAny(name, "{}:*") {
				return "", false
			}
			segs[i] = ":" + name
		case s == "*":
			if i != len(segs)-1 {
				return "", false
			}
			segs[i] = wildcard
		case strings.ContainsAny(s, "{}:*"):
			return "", false
		}
	}
	return strings.Join(segs, "/"), true
}

func unsupported(why string, route [2]string) {
	fmt.Fprintf(os.Stderr, "unsupported route %s %s: %s\n", route[0], route[1], why)
	fmt.Println("lookup\tunsupported")
	os.Exit(3)
}

func httprouterOp(routes, reqs [][2]string) func() int {
	r := httprouter.New()
	h := func(http.ResponseWriter, *http.Request, httprouter.Params) {}
	for _, rt := range routes {
		p, ok := colon(rt[1], "*filepath")
		if !ok {
			unsupported("pattern outside the colon syntax", rt)
		}
		r.Handle(rt[0], p, h) // panics on a conflicting table: that is a refusal, not a silent change
	}
	return func() int {
		found := 0
		for _, q := range reqs {
			if h, _, _ := r.Lookup(q[0], q[1]); h != nil {
				found++
			}
		}
		return found
	}
}

func echoOp(routes, reqs [][2]string) func() int {
	e := echo.New()
	ok := func(echo.Context) error { return nil }
	for _, rt := range routes {
		p, good := colon(rt[1], "*")
		if !good {
			unsupported("pattern outside the colon syntax", rt)
		}
		e.Router().Add(rt[0], p, ok)
	}
	// Created after the routes: the context sizes its parameter slice from
	// the largest route seen so far.
	// A real request and recorder: echo's 405 handler writes the Allow header,
	// so a nil response panics. Its cost lands on echo's 405 requests only.
	c := e.NewContext(httptest.NewRequest("GET", "/", nil), httptest.NewRecorder())
	return func() int {
		found := 0
		for _, q := range reqs {
			// Find leaves the previous handler in place when nothing
			// matched at all, so reset it to the 404 handler first.
			c.SetHandler(echo.NotFoundHandler)
			e.Router().Find(q[0], q[1], c)
			if c.Handler()(c) == nil {
				found++
			}
		}
		return found
	}
}

// nullWriter is never written to: the handlers below do not touch it.
type nullWriter struct{}

func (nullWriter) Header() http.Header         { return nil }
func (nullWriter) Write(p []byte) (int, error) { return len(p), nil }
func (nullWriter) WriteHeader(int)             {}

func bunrouterOp(routes, reqs [][2]string) func() int {
	hit := 0
	ok := func(http.ResponseWriter, bunrouter.Request) error { hit = 1; return nil }
	miss := func(http.ResponseWriter, bunrouter.Request) error { hit = 0; return nil }
	r := bunrouter.New(bunrouter.WithNotFoundHandler(miss), bunrouter.WithMethodNotAllowedHandler(miss))
	for _, rt := range routes {
		p, good := colon(rt[1], "*filepath")
		if !good {
			unsupported("pattern outside the colon syntax", rt)
		}
		r.Handle(rt[0], p, ok)
	}
	hreqs := make([]*http.Request, len(reqs))
	for i, q := range reqs {
		req, err := http.NewRequest(q[0], q[1], nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		hreqs[i] = req
	}
	var w nullWriter
	return func() int {
		found := 0
		for _, req := range hreqs {
			hit = 0
			_ = r.ServeHTTPError(w, req)
			found += hit
		}
		return found
	}
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go_fast_bench <httprouter|echo|bunrouter> <work dir>")
		os.Exit(2)
	}
	dir := os.Args[2]
	routes := readTSV(filepath.Join(dir, "routes_plain.tsv"))
	reqs := readTSV(filepath.Join(dir, "requests_plain.tsv"))

	var op func() int
	switch os.Args[1] {
	case "httprouter":
		op = httprouterOp(routes, reqs)
	case "echo":
		op = echoOp(routes, reqs)
	case "bunrouter":
		op = bunrouterOp(routes, reqs)
	default:
		fmt.Fprintf(os.Stderr, "unknown contender %q\n", os.Args[1])
		os.Exit(2)
	}
	ns, count := timeIt(op)
	fmt.Printf("lookup\t%.1f\t%d\n", ns, count)
}
