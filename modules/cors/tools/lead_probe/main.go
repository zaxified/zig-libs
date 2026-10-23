// SPDX-License-Identifier: MIT

// The evidence behind the cors card's `**Ahead:**` correctness claim: rs/cors
// v1.11.1 with AllowCredentials and AllowedOrigins `*` answers both a preflight
// and an actual request with `Access-Control-Allow-Origin: *` AND
// `Access-Control-Allow-Credentials: true` -- a pair the Fetch standard makes
// the browser refuse for a credentialed request, so the policy silently does
// not work. This module refuses that policy at `init` (tests "wildcard +
// credentials is rejected at init", "init rejects a credentialed wildcard
// spelled as a LIST entry").
//
//	cd modules/cors/tools/lead_probe && GOTOOLCHAIN=local GOPROXY=off GOFLAGS=-mod=mod go run .
//
// 2026-10-23: OPTIONS 204 ACAO="*" ACAC="true"; GET 200 ACAO="*" ACAC="true".

package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/rs/cors"
)

func main() {
	c := cors.New(cors.Options{AllowedOrigins: []string{"*"}, AllowCredentials: true, AllowedMethods: []string{"GET", "PUT"}})
	h := c.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	for _, m := range []string{"OPTIONS", "GET"} {
		r := httptest.NewRequest(m, "http://api.example/x", nil)
		r.Header.Set("Origin", "https://evil.example")
		if m == "OPTIONS" {
			r.Header.Set("Access-Control-Request-Method", "PUT")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		fmt.Printf("%s %d ACAO=%q ACAC=%q\n", m, w.Code, w.Header().Get("Access-Control-Allow-Origin"), w.Header().Get("Access-Control-Allow-Credentials"))
	}
}
