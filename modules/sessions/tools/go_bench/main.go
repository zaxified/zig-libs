// SPDX-License-Identifier: MIT

// Go side of `zig build bench-sessions` (modules/sessions/tools/bench.zig):
// times alexedwards/scs v2.9.0 (pinned by go.mod/go.sum) with its in-memory
// store, over the workload named by the second argument, through scs's public
// API only. Prints one line: name, ns/op, result count (tab-separated). The
// first argument (the Zig side's work directory) is unused: the requests are
// built here, because the cookies they carry come from this side's own
// sessions. One op = 16 requests.
//
//	passthrough  a bare handler, no session work (the net baseline)
//	new_session  no cookie; the handler Puts one value -> Set-Cookie
//	load_read    a valid cookie; the handler Gets the value, writes nothing
//	load_write   a valid cookie; the handler Puts a new value
//	destroy      8 x (a request that creates a session, then one that Destroys it)
//
// Store: memstore.NewWithCleanupInterval(0) -- 0 starts no cleanup goroutine
// (memstore.go:30-41). Driven through LoadAndSave with httptest.NewRecorder +
// httptest.NewRequest (no sockets). IdleTimeout is set to the Zig side's idle
// timeout (30 min): with IdleTimeout > 0 Load marks every loaded session
// Modified (data.go:78-83), so LoadAndSave commits it and writes the cookie on
// every request, which is what the Zig middleware's rolling window does.
// count = the sum of the status codes + one per response carrying a Set-Cookie
// header + the body lengths.
//
// Timing matches the Zig side: double the batch until one batch takes over
// 100 ms, then keep the best of five.
package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/alexedwards/scs/v2/memstore"
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

const nReq = 16

var (
	sm       *scs.SessionManager
	sessionH http.Handler
	bare     http.Handler
)

// do runs one request through h and returns its contribution to the count and
// the session token the response set (if any).
func do(h http.Handler, path, token string) (int, string) {
	req := httptest.NewRequest("GET", path, nil)
	if token != "" {
		req.AddCookie(&http.Cookie{Name: "session", Value: token})
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	sum := rec.Code + rec.Body.Len()
	tok := ""
	if sc := rec.Header().Values("Set-Cookie"); len(sc) > 0 {
		sum++
		if v, ok := strings.CutPrefix(sc[0], "session="); ok {
			tok, _, _ = strings.Cut(v, ";")
		}
	}
	return sum, tok
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go_bench <work dir> <workload>")
		os.Exit(2)
	}
	name := os.Args[2]

	sm = scs.New()
	sm.Store = memstore.NewWithCleanupInterval(0)
	sm.IdleTimeout = 30 * time.Minute
	sm.Lifetime = 12 * time.Hour
	sm.Cookie.Secure = true

	mux := http.NewServeMux()
	mux.HandleFunc("/new", func(w http.ResponseWriter, r *http.Request) {
		sm.Put(r.Context(), "uid", "42")
		w.Write([]byte("created"))
	})
	mux.HandleFunc("/read", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(sm.GetString(r.Context(), "uid")))
	})
	mux.HandleFunc("/write", func(w http.ResponseWriter, r *http.Request) {
		sm.Put(r.Context(), "uid", "43")
		w.Write([]byte("updated"))
	})
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		if err := sm.Destroy(r.Context()); err != nil {
			panic(err)
		}
		w.Write([]byte("bye"))
	})
	sessionH = sm.LoadAndSave(mux)
	bare = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<none>"))
	})

	// Sessions for the load rows, created through the same handlers.
	var tokens [nReq]string
	if name == "load_read" || name == "load_write" {
		for i := range tokens {
			_, tokens[i] = do(sessionH, "/new", "")
			if tokens[i] == "" {
				panic("no session cookie from /new")
			}
		}
	}

	var op func() int
	switch name {
	case "passthrough":
		op = func() int {
			sum := 0
			for i := 0; i < nReq; i++ {
				s, _ := do(bare, "/", "")
				sum += s
			}
			return sum
		}
	case "new_session":
		op = func() int {
			sum := 0
			for i := 0; i < nReq; i++ {
				s, _ := do(sessionH, "/new", "")
				sum += s
			}
			return sum
		}
	case "load_read", "load_write":
		path := "/read"
		if name == "load_write" {
			path = "/write"
		}
		op = func() int {
			sum := 0
			for i := 0; i < nReq; i++ {
				s, _ := do(sessionH, path, tokens[i])
				sum += s
			}
			return sum
		}
	case "destroy":
		op = func() int {
			sum := 0
			for i := 0; i < nReq/2; i++ {
				s, tok := do(sessionH, "/new", "")
				sum += s
				s, _ = do(sessionH, "/logout", tok)
				sum += s
			}
			return sum
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown workload", name)
		os.Exit(2)
	}

	ns, count := timeIt(op)
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
}
