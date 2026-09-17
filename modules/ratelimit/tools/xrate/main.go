// SPDX-License-Identifier: MIT
// Capture a reference AllowN trace from Go's golang.org/x/time/rate and emit
// it as a Zig source file of frozen vectors for zig-libs' `ratelimit` module.
//
// Needs a Go toolchain, which is why it lives in tools/ and never in src/.
// Run once, commit the output.
//
//	go run . > modules/ratelimit/src/xrate_vectors.zig
//
// Everything the reference is asked for comes from x/time/rate's PUBLIC API:
//
//	allowed      = lim.AllowN(t, 1)
//	tokens_after = lim.TokensAt(t)                    (after the AllowN)
//	wait_ns      = lim.ReserveN(t, 1).DelayFrom(t)    (before the AllowN)
//	reset_ns     = lim.ReserveN(t, burst).DelayFrom(t) (after the AllowN)
//
// ReserveN mutates the limiter, so each probe runs on its own limiter replayed
// from scratch over the same prefix of AllowN calls. O(n^2) in a trace of ~10
// steps: irrelevant, and it keeps every number a real reference output rather
// than something this driver computed.
package main

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"time"

	"golang.org/x/time/rate"
)

type kase struct {
	name string
	note string
	rate float64
	brst int
	ms   []uint64
}

// A fixed, arbitrary wall instant. Only differences matter; x/time/rate's
// zero-valued `last` means the first call always sees a full bucket, which is
// exactly `TokenBucket.full(cfg, t0)` on our side.
var base = time.Unix(1_000_000_000, 0).UTC()

func at(ms uint64) time.Time {
	return base.Add(time.Duration(ms) * time.Millisecond)
}

func replay(k kase, upto int) *rate.Limiter {
	l := rate.NewLimiter(rate.Limit(k.rate), k.brst)
	for i := 0; i < upto; i++ {
		l.AllowN(at(k.ms[i]), 1)
	}
	return l
}

// Zig hex-float literal, byte-exact for an f64 (no decimal rounding anywhere).
func hexf(f float64) string {
	return strconv.FormatFloat(f, 'x', -1, 64)
}

func main() {
	cases := []kase{
		{
			name: "rate=1 burst=3 — the row's (1,3) triple: burst at t0, deny, refill at 1s/3s, long idle",
			note: "offsets 0/500/1000/3000/100000 ms",
			rate: 1, brst: 3,
			ms: []uint64{0, 0, 0, 0, 500, 1000, 1000, 3000, 3000, 3000, 3000, 100_000},
		},
		{
			name: "rate=2 burst=2 — the row's (2,2) triple at offsets 0/250/500 ms, then a long idle",
			note: "250 ms at 2 tok/s = half a token: still denied",
			rate: 2, brst: 2,
			ms: []uint64{0, 0, 250, 500, 600, 100_000, 100_000, 100_000},
		},
		{
			name: "rate=3 burst=1 — the row's (3,1) triple; step 2 lands on the reported retry_after",
			note: "deny at t0 reports ceil(1000/3)=334 ms; waiting exactly that must pass",
			rate: 3, brst: 1,
			ms: []uint64{0, 0, 334, 334, 667, 1000},
		},
		{
			name: "rate=0.5 burst=5 — sub-unit rate, drain the burst then wait 2 s per token",
			note: "exercises a fractional refill rate and a 5-deep burst",
			rate: 0.5, brst: 5,
			ms: []uint64{0, 0, 0, 0, 0, 0, 1000, 2000, 2000, 60_000},
		},
		{
			name: "rate=100 burst=1 — sub-10 ms recovery, exercises millisecond rounding",
			note: "one token per 10 ms",
			rate: 100, brst: 1,
			ms: []uint64{0, 0, 5, 10, 10, 15, 20},
		},
	}

	out := os.Stdout
	fmt.Fprint(out, header)
	fmt.Fprintln(out, "pub const cases = [_]Case{")
	for _, k := range cases {
		fmt.Fprintf(out, "    .{\n")
		fmt.Fprintf(out, "        .name = %q,\n", k.name)
		fmt.Fprintf(out, "        .note = %q,\n", k.note)
		fmt.Fprintf(out, "        .rate_per_s = %s, // %g\n", hexf(k.rate), k.rate)
		fmt.Fprintf(out, "        .burst = %d,\n", k.brst)
		fmt.Fprintf(out, "        .steps = &.{\n")
		for i, ms := range k.ms {
			t := at(ms)

			// Wait before the decision (x/time/rate's own waitDuration).
			waitNs := replay(k, i).ReserveN(t, 1).DelayFrom(t)

			// The decision itself, and the balance it leaves behind.
			lim := replay(k, i)
			allowed := lim.AllowN(t, 1)
			tokensAfter := lim.TokensAt(t)

			// Time to a completely full bucket, after the decision.
			s := replay(k, i)
			s.AllowN(t, 1)
			resetNs := s.ReserveN(t, k.brst).DelayFrom(t)

			fmt.Fprintf(out,
				"            .{ .at_ms = %d, .allowed = %t, .remaining = %d, .wait_ns = %d, .reset_ns = %d, .tokens_after = %s },\n",
				ms, allowed, uint32(math.Floor(tokensAfter)), int64(waitNs), int64(resetNs), hexf(tokensAfter))
		}
		fmt.Fprintf(out, "        },\n")
		fmt.Fprintf(out, "    },\n")
	}
	fmt.Fprintln(out, "};")
}

const header = `//! Frozen reference trace captured from Go ` + "`golang.org/x/time/rate`" + `.
//!
//! ` + "`TokenBucket`" + ` is modelled on that package (see the type's doc comment). Its
//! own tests assert hand-computed expectations, which are self-authored and so
//! cannot disagree with us; this table is the external oracle. Audit finding
//! ` + "`ratelimit` F2" + `.
//!
//! ## Provenance
//!
//! * Reference:  ` + "`golang.org/x/time/rate`" + `, module ` + "`golang.org/x/time` v0.15.0" + `
//!               ` + "`h1:bbrp8t3bGUeFOx08pvsMYRTCVSMk89u4tKbNOZbp88U=`" + `
//! * Licence:    BSD-3-Clause (The Go Authors). Nothing from it is copied or
//!               translated into this repo -- the package was *run* and its
//!               outputs recorded, so no foreign condition attaches here.
//! * Driver:     ` + "`modules/ratelimit/tools/xrate/main.go`" + ` (outside the repo;
//!               zig-libs keeps zero external dependencies and no ` + "`go`" + ` reference
//!               under ` + "`modules/`" + `).
//! * Command:    ` + "`go run . > modules/ratelimit/src/xrate_vectors.zig`" + `
//! * Captured:   2026-08-09, Go 1.26.0 linux/amd64.
//!
//! Every number below is a reference output, obtained through x/time/rate's
//! public API only:
//!
//! * ` + "`allowed`" + `      -- ` + "`lim.AllowN(t, 1)`" + `
//! * ` + "`tokens_after`" + ` -- ` + "`lim.TokensAt(t)`" + ` after that call
//! * ` + "`wait_ns`" + `      -- ` + "`lim.ReserveN(t, 1).DelayFrom(t)`" + ` before it (0 when allowed)
//! * ` + "`reset_ns`" + `     -- ` + "`lim.ReserveN(t, burst).DelayFrom(t)`" + ` after it
//! * ` + "`remaining`" + `    -- ` + "`floor(tokens_after)`" + `
//!
//! ` + "`ReserveN`" + ` mutates, so each probe ran on its own limiter replayed over the
//! same prefix of ` + "`AllowN`" + ` calls.
//!
//! ## Regenerating
//!
//! This file is a permanent, offline fixture: the tests that read it never
//! shell out and never skip. Regenerating is only needed to re-anchor against a
//! newer x/time -- see the driver's own header for the two commands.
//!
//! ## Deliberately not captured: a backwards clock
//!
//! ` + "`TokenBucket.allowAt`" + ` documents ` + "`now_ns`" + ` as monotonic and treats a backwards
//! step as no time passing. x/time/rate instead clamps its ` + "`last`" + ` to the earlier
//! ` + "`t`" + ` and, on an allowed call, moves ` + "`last`" + ` *backwards*, so a later call refills
//! from the earlier instant and yields more tokens than we would. That is a
//! genuine divergence, but only for input both sides call out of contract, so
//! no backwards timestamp appears in any schedule here.

/// One ` + "`AllowN(t, 1)`" + ` and everything x/time/rate reported about it.
pub const Step = struct {
    /// Milliseconds after the case's start instant.
    at_ms: u64,
    allowed: bool,
    remaining: u32,
    /// Reference wait until one token is free, nanoseconds (0 when allowed).
    wait_ns: u64,
    /// Reference wait until the bucket is full again, nanoseconds.
    reset_ns: u64,
    /// Reference float balance after the call (hex float: byte-exact).
    tokens_after: f64,
};

pub const Case = struct {
    name: []const u8,
    note: []const u8,
    rate_per_s: f64,
    burst: u32,
    steps: []const Step,
};

`
