// SPDX-License-Identifier: MIT
//
// Lead probe: modules/sessions vs github.com/alexedwards/scs/v2 v2.9.0.
//
// Claim: scs has no cross-request guard. A request that loaded a session
// before a concurrent request destroyed or rotated it still commits that
// session under the OLD token when it finishes, so the logged-out (or
// rotated-away, possibly stolen) cookie works again. LoadAndSave commits
// whenever the status is Modified, and Load marks EVERY loaded session
// Modified when IdleTimeout > 0, so with an idle timeout even a read-only
// request resurrects.
//   scs session.go:161-165 (commit after handler), data.go:81-83 (idle =>
//   Modified), data.go:99-123 (Commit stores sd.token unconditionally),
//   data.go:129-150 (Destroy = store delete, no tombstone/version),
//   data.go:282-305 (RenewToken = store delete of the old token),
//   memstore/memstore.go:64-73 (Commit = blind map write, no compare).
//
// The race is interleaved by hand (B's handler blocks on a channel while A
// runs to completion), so the output is deterministic. httptest only.
//
// Run (from this directory, offline):
//   GOTOOLCHAIN=local GOPROXY=off GOFLAGS=-mod=readonly go run .
package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	"github.com/alexedwards/scs/v2"
)

type rig struct {
	sm      *scs.SessionManager
	h       http.Handler
	started chan struct{}
	release chan struct{}
}

func newRig(idle time.Duration) *rig {
	r := &rig{sm: scs.New(), started: make(chan struct{}), release: make(chan struct{})}
	r.sm.IdleTimeout = idle
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, q *http.Request) {
		r.sm.Put(q.Context(), "uid", "7")
	})
	mux.HandleFunc("/whoami", func(w http.ResponseWriter, q *http.Request) {
		fmt.Fprint(w, r.sm.GetString(q.Context(), "uid"))
	})
	mux.HandleFunc("/logout", func(w http.ResponseWriter, q *http.Request) {
		_ = r.sm.Destroy(q.Context())
	})
	mux.HandleFunc("/renew", func(w http.ResponseWriter, q *http.Request) {
		_ = r.sm.RenewToken(q.Context())
	})
	// Slow request: loads the session, optionally writes, then waits.
	mux.HandleFunc("/slow-read", func(w http.ResponseWriter, q *http.Request) {
		_ = r.sm.GetString(q.Context(), "uid")
		r.started <- struct{}{}
		<-r.release
	})
	mux.HandleFunc("/slow-write", func(w http.ResponseWriter, q *http.Request) {
		r.sm.Put(q.Context(), "cart", "book")
		r.started <- struct{}{}
		<-r.release
	})
	r.h = r.sm.LoadAndSave(mux)
	return r
}

func (r *rig) do(path, cookie string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", path, nil)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: "session", Value: cookie})
	}
	rec := httptest.NewRecorder()
	r.h.ServeHTTP(rec, req)
	return rec
}

func cookieOf(rec *httptest.ResponseRecorder) string {
	for _, c := range rec.Result().Cookies() {
		if c.Name == "session" {
			return c.Value
		}
	}
	return ""
}

// scenario: log in, start the slow request B, run A to completion, release B,
// then replay the cookie the attacker/old tab still holds.
func scenario(idle time.Duration, slow, a string) (replayed string, ok bool) {
	r := newRig(idle)
	old := cookieOf(r.do("/login", ""))
	done := make(chan struct{})
	go func() { r.do(slow, old); close(done) }()
	<-r.started // B has loaded the session and is inside its handler
	ra := r.do(a, old)
	nc := cookieOf(ra) // A's replacement cookie (renew), "" for logout
	r.release <- struct{}{}
	<-done
	rec := r.do("/whoami", old)
	_ = nc
	uid := rec.Body.String()
	return uid, uid == "7"
}

func main() {
	fmt.Println("case\tscs_outcome\tours")
	type c struct {
		name, ours string
		idle       time.Duration
		slow, a    string
	}
	cases := []c{
		{"logout-vs-concurrent-write", "cross-request race: a stale save cannot resurrect a session destroyed by a concurrent request", 0, "/slow-write", "/logout"},
		{"logout-vs-concurrent-read-only(IdleTimeout=30m)", "cross-request race: a stale save cannot resurrect a session destroyed by a concurrent request", 30 * time.Minute, "/slow-read", "/logout"},
		{"logout-vs-concurrent-read-only(IdleTimeout=0)", "(not a resurrection in scs: unchanged session is not committed)", 0, "/slow-read", "/logout"},
		{"renew-vs-concurrent-write", "cross-request race: a stale save cannot resurrect a session rotated by a concurrent regenerate", 0, "/slow-write", "/renew"},
		{"renew-vs-concurrent-read-only(IdleTimeout=30m)", "cross-request race: a stale save cannot resurrect a session rotated by a concurrent regenerate", 30 * time.Minute, "/slow-read", "/renew"},
	}
	bad := 0
	for _, k := range cases {
		uid, alive := scenario(k.idle, k.slow, k.a)
		out := "old cookie dead (whoami=\"\")"
		if alive {
			out = fmt.Sprintf("OLD COOKIE ALIVE AGAIN (whoami=%q)", uid)
			bad++
		}
		fmt.Printf("%s\t%s\t%s\n", k.name, out, k.ours)
	}
	fmt.Printf("resurrections\t%d\n", bad)
	if bad == 0 {
		os.Exit(1)
	}
}
