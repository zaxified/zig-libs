// SPDX-License-Identifier: MIT
// `go run . ops > ../../src/xrate_ops_vectors.zig`: capture seeded random
// operation sequences on ONE golang.org/x/time/rate limiter -- AllowN,
// ReserveN, Reservation.CancelAt, SetLimitAt, SetBurstAt -- and the limiter's
// TokensAt after each, as frozen vectors for `ratelimit`'s TokenBucket
// reservation/reconfiguration API. Public API only; nothing is replayed, every
// number is what the reference returned.

package main

import (
	"fmt"
	"math/rand"
	"os"

	"golang.org/x/time/rate"
)

type opKase struct {
	rate   float64
	brst   int
	seed   int64 // 0: scripted, ops given in `script`
	nops   int
	script []op
}

type op struct {
	ms      uint64
	kind    string
	n       int
	ref     int
	newRate float64
}

// Scripted: an AllowN admitted BEFORE an outstanding reservation's time to
// act (possible only after SetLimitAt raised the rate), then that
// reservation cancelled -- whether an admitted AllowN counts as the latest
// event decides how much the cancel gives back. Random sequences never
// produced this order.
var scripted = []opKase{
	{rate: 1, brst: 10, script: []op{
		{ms: 0, kind: "allow", n: 10},
		{ms: 0, kind: "reserve", n: 2},
		{ms: 100, kind: "set_limit", newRate: 5},
		{ms: 500, kind: "allow", n: 0},
		{ms: 500, kind: "cancel", ref: 1},
		{ms: 600, kind: "allow", n: 1},
	}},
	{rate: 1, brst: 10, script: []op{
		{ms: 0, kind: "allow", n: 10},
		{ms: 0, kind: "reserve", n: 3},
		{ms: 100, kind: "set_limit", newRate: 10},
		{ms: 700, kind: "allow", n: 2},
		{ms: 800, kind: "cancel", ref: 1},
		{ms: 900, kind: "allow", n: 3},
	}},
}

func randomOps(k opKase) []op {
	rng := rand.New(rand.NewSource(k.seed))
	rates := []float64{0.5, 1, 2, 3, 10, 50}
	burst := k.brst
	var ms uint64
	var reserves []int
	var ops []op
	for i := 0; i < k.nops; i++ {
		switch rng.Intn(4) {
		case 0: // same instant
		case 1:
			ms += uint64(rng.Intn(50))
		case 2:
			ms += uint64(rng.Intn(1000))
		default:
			ms += uint64(rng.Intn(5000))
		}
		o := op{ms: ms, kind: "allow"}
		switch r := rng.Intn(10); {
		case r < 3:
			o.n = rng.Intn(burst + 2) // 0..burst+1: hits n == 0 and n > burst
		case r < 6:
			o.kind = "reserve"
			o.n = rng.Intn(burst + 2)
			reserves = append(reserves, i)
		case r < 8:
			// A random earlier reservation (may be already cancelled,
			// already due, or not OK -- all must be no-ops or partial).
			o.kind = "cancel"
			o.ref = -1
			if len(reserves) > 0 {
				o.ref = reserves[rng.Intn(len(reserves))]
			}
		case r < 9:
			o.kind = "set_limit"
			o.newRate = rates[rng.Intn(len(rates))]
		default:
			o.kind = "set_burst"
			o.n = 1 + rng.Intn(8)
			burst = o.n
		}
		ops = append(ops, o)
	}
	return ops
}

func emitOps() {
	kases := []opKase{
		{rate: 1, brst: 3, seed: 1, nops: 60},
		{rate: 2, brst: 1, seed: 2, nops: 60},
		{rate: 0.5, brst: 5, seed: 3, nops: 60},
		{rate: 10, brst: 4, seed: 4, nops: 80},
		{rate: 3, brst: 10, seed: 5, nops: 80},
		{rate: 100, brst: 2, seed: 6, nops: 60},
		{rate: 7, brst: 6, seed: 7, nops: 120},
		{rate: 0.25, brst: 2, seed: 8, nops: 60},
	}
	kases = append(kases, scripted...)

	out := os.Stdout
	fmt.Fprint(out, opsHeader)
	fmt.Fprintln(out, "pub const cases = [_]Case{")
	for _, k := range kases {
		ops := k.script
		if k.seed != 0 {
			ops = randomOps(k)
		}
		lim := rate.NewLimiter(rate.Limit(k.rate), k.brst)
		res := make([]*rate.Reservation, len(ops))
		fmt.Fprintf(out, "    .{\n        .rate_per_s = %s, // %g\n        .burst = %d,\n        .seed = %d,\n        .ops = &.{\n",
			hexf(k.rate), k.rate, k.brst, k.seed)
		for i, o := range ops {
			t := at(o.ms)
			ok := true
			var delay int64
			switch o.kind {
			case "allow":
				ok = lim.AllowN(t, o.n)
			case "reserve":
				res[i] = lim.ReserveN(t, o.n)
				ok = res[i].OK()
				if ok {
					delay = int64(res[i].DelayFrom(t))
				}
			case "cancel":
				if o.ref >= 0 {
					res[o.ref].CancelAt(t)
				}
			case "set_limit":
				lim.SetLimitAt(t, rate.Limit(o.newRate))
			case "set_burst":
				lim.SetBurstAt(t, o.n)
			}
			fmt.Fprintf(out, "            .{ .at_ms = %d, .kind = .%s, .n = %d, .ref = %d, .rate_per_s = %s, .ok = %t, .delay_ns = %d, .tokens_after = %s },\n",
				o.ms, o.kind, o.n, o.ref, hexf(o.newRate), ok, delay, hexf(lim.TokensAt(t)))
		}
		fmt.Fprintf(out, "        },\n    },\n")
	}
	fmt.Fprintln(out, "};")
}

const opsHeader = `// SPDX-License-Identifier: MIT
//! Frozen operation traces captured from Go ` + "`golang.org/x/time/rate`" + ` v0.15.0
//! (` + "`h1:bbrp8t3bGUeFOx08pvsMYRTCVSMk89u4tKbNOZbp88U=`" + `), BSD-3-Clause, *run* through its
//! public API only -- nothing copied or translated.
//!
//! * Driver:   ` + "`modules/ratelimit/tools/xrate/ops.go`" + `
//! * Command:  ` + "`cd modules/ratelimit/tools/xrate && go run . ops > ../../src/xrate_ops_vectors.zig`" + `
//! * Captured: 2026-10-11, Go 1.26 linux/amd64.
//!
//! Each case runs ONE limiter through a seeded random sequence of operations
//! (times only move forward; several ops may share an instant), or -- ` + "`seed`" + `
//! 0 -- a scripted one the random cases never reach (see the driver):
//!
//! * ` + "`allow`" + `     -- ` + "`ok = lim.AllowN(t, n)`" + `, n in 0..burst+1
//! * ` + "`reserve`" + `   -- ` + "`r = lim.ReserveN(t, n)`" + `; ` + "`ok = r.OK()`" + `, ` + "`delay_ns = r.DelayFrom(t)`" + ` when ok
//! * ` + "`cancel`" + `    -- ` + "`res[ref].CancelAt(t)`" + ` on an earlier reserve op (any state: due,
//!   cancelled before, not ok); ` + "`ref = -1`" + ` when there was none
//! * ` + "`set_limit`" + ` -- ` + "`lim.SetLimitAt(t, rate_per_s)`" + `
//! * ` + "`set_burst`" + ` -- ` + "`lim.SetBurstAt(t, n)`" + `
//!
//! and records ` + "`tokens_after = lim.TokensAt(t)`" + ` after every op (hex float).
//!
//! ## Deliberately not captured: a second CancelAt of the same reservation
//!
//! x/time/rate v0.15.0 restores the tokens AGAIN on a second ` + "`CancelAt`" + ` (seen
//! 2026-10-11: a reservation of 3 cancelled twice at 800 ms took the balance
//! 2.1 -> 7.4 -> 10), so a holder that cancels twice admits more than the
//! limit. ` + "`TokenBucket.cancelAt`" + ` zeroes the reservation and makes the second
//! call a no-op. The random cases happen to repeat cancels only where both
//! sides do nothing (due or fully built upon); the scripted ones cancel once.

pub const Kind = enum { allow, reserve, cancel, set_limit, set_burst };

pub const Op = struct {
    at_ms: u64,
    kind: Kind,
    n: u32,
    /// ` + "`cancel`" + `: index of the reserve op in this case's ` + "`ops`" + `, or -1.
    ref: i32,
    /// ` + "`set_limit`" + `: the new rate; 0 otherwise.
    rate_per_s: f64,
    ok: bool,
    /// ` + "`reserve`" + ` with ok: the reference delay, nanoseconds; 0 otherwise.
    delay_ns: u64,
    tokens_after: f64,
};

pub const Case = struct {
    rate_per_s: f64,
    burst: u32,
    seed: i64,
    ops: []const Op,
};

`
