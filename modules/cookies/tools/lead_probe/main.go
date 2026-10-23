// SPDX-License-Identifier: MIT

// The evidence behind the cookies card's `**Ahead:**` correctness claim: what
// Go's net/http writes, and calls Valid(), for cookies a browser drops or reads
// otherwise (a `__Host-`/`__Secure-` prefix without its constraints,
// `SameSite=None` without `Secure`, a relative Path). This module's
// `SetCookie.write` refuses every one of them (tests "SetCookie: ...").
//
//	cd modules/cookies/tools/lead_probe && GOTOOLCHAIN=local GOPROXY=off go run .
//
// 2026-10-23, Go 1.26: all five written, Valid() true; the invalid Domain is
// dropped with a log line.

package main

import (
	"fmt"
	"net/http"
)

func main() {
	cs := []*http.Cookie{
		{Name: "__Host-sid", Value: "1"},
		{Name: "__Host-sid", Value: "1", Secure: true, Path: "/", Domain: "example.com"},
		{Name: "__Secure-sid", Value: "1"},
		{Name: "sid", Value: "1", SameSite: http.SameSiteNoneMode},
		{Name: "sid", Value: "1", Path: "relative"},
		{Name: "sid", Value: "1", Domain: "exa mple.com"},
	}
	for _, c := range cs {
		fmt.Printf("valid=%v  %q\n", c.Valid() == nil, c.String())
	}
}
