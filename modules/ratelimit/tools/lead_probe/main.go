// SPDX-License-Identifier: MIT

// Lead probe for modules/ratelimit's `**Ahead:**` line (nothing committed is
// generated from it): golang.org/x/time/rate v0.15.0, the reference, restores
// a reservation's tokens AGAIN on every repeated CancelAt, so a holder that
// cancels the same reservation repeatedly admits far beyond the burst at a
// single instant. TokenBucket.cancelAt zeroes the reservation; a second
// cancel is a no-op (test "TokenBucket: reserveNAt honours max_wait; a second
// cancel is a no-op (deliberate x/time/rate divergence)").
//
//	cd modules/ratelimit/tools/lead_probe && GOTOOLCHAIN=local GOPROXY=off GOFLAGS=-mod=readonly go run .
package main

import (
	"fmt"
	"time"

	"golang.org/x/time/rate"
)

var t0 = time.Unix(1_000_000_000, 0).UTC()

func main() {
	// 1 token/s, burst 3: at one instant at most 3 events may be admitted.
	l := rate.NewLimiter(rate.Limit(1), 3)
	admitted := 0
	if l.AllowN(t0, 3) {
		admitted += 3
	}
	r := l.ReserveN(t0, 3) // ok, due in 3 s; the balance goes to -3
	fmt.Printf("reserve ok=%t delay=%v tokens=%.1f\n", r.OK(), r.DelayFrom(t0), l.TokensAt(t0))
	for i := 1; i <= 10; i++ {
		r.CancelAt(t0) // the same reservation, cancelled again
		if l.AllowN(t0, 3) {
			admitted += 3
		}
		fmt.Printf("cancel #%-2d tokens before AllowN=%.1f admitted so far=%d\n", i, l.TokensAt(t0)+3, admitted)
	}
	fmt.Printf("x/time/rate v0.15.0: %d events admitted at one instant with burst 3 (limit allows 3)\n", admitted)
}
