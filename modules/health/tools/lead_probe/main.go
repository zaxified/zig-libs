// SPDX-License-Identifier: MIT

// Evidence behind the health card's `**Ahead:**` claims. alexliesenfeld/health
// v0.8.1, in its default configuration (NewChecker + NewHandler, as the README
// shows):
//
//  1. leak: the default JSON body carries every failing check's raw error
//     string (config.go:74-80 WithDisabledDetails is opt-in; check.go:154-166
//     CheckResult.MarshalJSON emits `cr.Error.Error()`; check.go:405-409
//     mapStateToCheckerResult copies checkState.Result). A Go error from a
//     database/HTTP client usually names the address, port or DSN fragment, so
//     an unauthenticated prober learns internal topology.
//  2. method: the handler never looks at r.Method (handler.go:67-81), so a
//     POST/PUT/DELETE/PATCH/OPTIONS to the health path runs every dependency
//     check (check.go:267-277, 286-304) and returns the same leaky body. A
//     probe path is thus a state-independent trigger for dependency I/O from
//     any client, with a 1 s result cache (check.go:60-65) as the only brake.
//
// Ours (not executed here): Check returns bool, so there is no error string in
// any body (root.zig:82-88 Check, :124 `detail`; text body 'not ready:
// <name>' lines, `detail = false` -> 'not ready'); only GET/HEAD are probes
// (root.zig:148-149 probeFor, :170-172 isProbeMethod) and every other method
// passes to the app without calling any check (root.zig:178-179).
//
//	cd modules/health/tools/lead_probe && GOTOOLCHAIN=local GOPROXY=off GOFLAGS=-mod=readonly go run .
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"time"

	"github.com/alexliesenfeld/health"
)

func main() {
	var calls atomic.Int64
	checker := health.NewChecker(
		// no cache: so that every request below is a fresh probe and the
		// call counts are exact (the default 1 s cache only hides repeats)
		health.WithCacheDuration(0),
		health.WithCheck(health.Check{
			Name: "database",
			Check: func(ctx context.Context) error {
				calls.Add(1)
				return errors.New("dial tcp 10.0.3.7:5432: connect: connection refused")
			},
		}),
	)
	defer checker.Stop()
	h := health.NewHandler(checker)
	time.Sleep(50 * time.Millisecond) // let the autostart background Check finish
	calls.Store(0)

	fmt.Println("case\tmethod\tref_status\tref_check_calls\tref_body_names_internal_addr\tours (contract)")
	oursGET := "GET: probe, body 'not ready: database' (name only), 1 check call"
	oursOther := "not a probe, passes to app, 0 check calls, no body from health"
	for _, m := range []string{"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"} {
		before := calls.Load()
		w := httptest.NewRecorder()
		h(w, httptest.NewRequest(m, "http://svc.example/health", nil))
		leak := strings.Contains(w.Body.String(), "10.0.3.7:5432")
		ours := oursOther
		if m == "GET" || m == "HEAD" {
			ours = oursGET
		}
		fmt.Printf("default\t%s\t%d\t%d\t%v\t%s\n", m, w.Code, calls.Load()-before, leak, ours)
		if m == "GET" {
			fmt.Printf("body\tGET\t-\t-\t-\t%s\n", strings.TrimSpace(w.Body.String()))
		}
	}
	_ = http.StatusOK
}
