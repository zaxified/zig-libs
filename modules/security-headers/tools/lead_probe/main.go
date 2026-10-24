// SPDX-License-Identifier: MIT
//
// Lead probe: security-headers vs unrolled/secure v1.17.0 (+ fiber v3.6.1
// middleware/helmet by source), 2026-10-24. helmet 8.3.0 (Node) is not
// available offline and was not run.
//
// Claim: config that the HSTS preload list / the CSP grammar would reject or
// corrupt is accepted silently by the field members and shipped as a header:
//
//	(a) unrolled/secure.go:414-424 builds "max-age=%d[; includeSubDomains][; preload]"
//	    with no validation: preload with max-age=60 and without includeSubDomains
//	    (the preload list rejects it) and a negative max-age ("max-age=-1") are
//	    emitted. fiber helmet.go:18-31 / config.go:109-114 refuses only
//	    negative max-age and preload+exclude-subdomains; preload with a short
//	    max-age is emitted ("max-age=60; includeSubDomains; preload", pinned as
//	    expected output by its own helmet_test.go:218-221 with HSTSMaxAge 60).
//	(b) unrolled/secure.go:159-160,449,458 turns the whole CSP string into a
//	    fmt.Sprintf format when "$NONCE" is present, so any '%' in the policy
//	    (percent-encoded source, e.g. https://cdn.example/a%20b) is eaten as a
//	    verb: the delivered policy differs from the configured one.
//
// Ours: init refuses preload below 1 year / without includeSubDomains
// (InvalidHstsPreload, root.zig:146-147,370), max_age_s is u64 (no negative),
// the CSP is rendered by copy, never as a format string (csp.zig:191 renderImpl).
//
// Run (from zig-libs root):
//
//	hw run --slots 1 --name sh-lead -- bash -c 'cd modules/security-headers/tools/lead_probe && GOTOOLCHAIN=local GOPROXY=off GOFLAGS=-mod=readonly go run .'
package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/unrolled/secure"
)

func serve(o secure.Options, forceTLS bool) http.Header {
	if forceTLS {
		o.ForceSTSHeader = true
	}
	h := secure.New(o).Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	return rec.Header()
}

func row(c, member, ours string) { fmt.Printf("%s\t%s\t%s\n", c, member, ours) }

func main() {
	fmt.Println("case\tunrolled/secure v1.17.0 outcome\tours (pinning test)")
	h := serve(secure.Options{STSSeconds: 60, STSPreload: true}, true)
	row("hsts_preload_60s_no_subdomains", h.Get("Strict-Transport-Security"),
		"init error InvalidHstsPreload (root.zig test \"HSTS preload: refused unless max-age >= 1 year and includeSubDomains (init error)\")")
	h = serve(secure.Options{STSSeconds: -1}, true)
	row("hsts_negative_max_age", h.Get("Strict-Transport-Security"),
		"unrepresentable: max_age_s is u64 (type; no test needed)")
	h = serve(secure.Options{ContentSecurityPolicy: "script-src $NONCE https://cdn.example/a%20b"}, false)
	csp := h.Get("Content-Security-Policy")
	row("csp_nonce_with_percent_source", csp,
		"rendered by copy; '%' passes through unchanged (MISSING test: csp.zig renderNonce with a '%' source)")
	h = serve(secure.Options{ContentSecurityPolicy: "script-src $NONCE; img-src 'self' 100%"}, false)
	row("csp_nonce_trailing_percent", h.Get("Content-Security-Policy"),
		"same (MISSING test)")

	// Control: CRLF in a value. Go's server sanitizes on the wire (no injection).
	ln := httptest.NewServer(secure.New(secure.Options{CustomFrameOptionsValue: "DENY\r\nX-Injected: 1"}).
		Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})))
	defer ln.Close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(ln.URL, "http://"))
	if err != nil {
		panic(err)
	}
	fmt.Fprintf(conn, "GET / HTTP/1.0\r\n\r\n")
	br := bufio.NewReader(conn)
	var lines []string
	for {
		l, err := br.ReadString('\n')
		if err != nil || strings.TrimSpace(l) == "" {
			break
		}
		if strings.HasPrefix(l, "X-") {
			lines = append(lines, strings.TrimSpace(l))
		}
	}
	conn.Close()
	row("crlf_in_value_control", strings.Join(lines, " | ")+" (sanitized to a space: no injection, NOT a lead)",
		"init error InvalidHeaderValue (root.zig test at :1404)")
}
