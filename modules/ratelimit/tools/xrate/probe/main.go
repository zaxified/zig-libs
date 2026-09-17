// SPDX-License-Identifier: MIT
// Out-of-contract probe: a backwards timestamp on an ALLOWED call moves
// x/time/rate's `last` backwards, so later calls refill from the earlier
// instant. TokenBucket.allowAt never moves `updated_ns` backwards.
package main

import (
	"fmt"
	"time"

	"golang.org/x/time/rate"
)

var base = time.Unix(1_000_000_000, 0).UTC()

func at(ms int64) time.Time { return base.Add(time.Duration(ms) * time.Millisecond) }

func main() {
	l := rate.NewLimiter(rate.Limit(1), 3)
	for _, ms := range []int64{0, 5000, 1000, 2000, 2000, 2000} {
		ok := l.AllowN(at(ms), 1)
		fmt.Printf("t=%6d ms  allowed=%-5t  tokens_after=%.6f\n", ms, ok, l.TokensAt(at(ms)))
	}
}
