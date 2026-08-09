//! Frozen reference trace captured from Go `golang.org/x/time/rate`.
//!
//! `TokenBucket` is modelled on that package (see the type's doc comment). Its
//! own tests assert hand-computed expectations, which are self-authored and so
//! cannot disagree with us; this table is the external oracle. Audit finding
//! `ratelimit` F2.
//!
//! ## Provenance
//!
//! * Reference:  `golang.org/x/time/rate`, module `golang.org/x/time` v0.15.0
//!               `h1:bbrp8t3bGUeFOx08pvsMYRTCVSMk89u4tKbNOZbp88U=`
//! * Licence:    BSD-3-Clause (The Go Authors). Nothing from it is copied or
//!               translated into this repo -- the package was *run* and its
//!               outputs recorded, so no foreign condition attaches here.
//! * Driver:     `~/.cache/zig-libs-ratelimit/xrate/main.go` (outside the repo;
//!               zig-libs keeps zero external dependencies and no `go` reference
//!               under `modules/`).
//! * Command:    `go run . > modules/ratelimit/src/xrate_vectors.zig`
//! * Captured:   2026-08-09, Go 1.26.0 linux/amd64.
//!
//! Every number below is a reference output, obtained through x/time/rate's
//! public API only:
//!
//! * `allowed`      -- `lim.AllowN(t, 1)`
//! * `tokens_after` -- `lim.TokensAt(t)` after that call
//! * `wait_ns`      -- `lim.ReserveN(t, 1).DelayFrom(t)` before it (0 when allowed)
//! * `reset_ns`     -- `lim.ReserveN(t, burst).DelayFrom(t)` after it
//! * `remaining`    -- `floor(tokens_after)`
//!
//! `ReserveN` mutates, so each probe ran on its own limiter replayed over the
//! same prefix of `AllowN` calls.
//!
//! ## Regenerating
//!
//! This file is a permanent, offline fixture: the tests that read it never
//! shell out and never skip. Regenerating is only needed to re-anchor against a
//! newer x/time -- see the driver's own header for the two commands.
//!
//! ## Deliberately not captured: a backwards clock
//!
//! `TokenBucket.allowAt` documents `now_ns` as monotonic and treats a backwards
//! step as no time passing. x/time/rate instead clamps its `last` to the earlier
//! `t` and, on an allowed call, moves `last` *backwards*, so a later call refills
//! from the earlier instant and yields more tokens than we would. That is a
//! genuine divergence, but only for input both sides call out of contract, so
//! no backwards timestamp appears in any schedule here.

/// One `AllowN(t, 1)` and everything x/time/rate reported about it.
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

pub const cases = [_]Case{
    .{
        .name = "rate=1 burst=3 — the row's (1,3) triple: burst at t0, deny, refill at 1s/3s, long idle",
        .note = "offsets 0/500/1000/3000/100000 ms",
        .rate_per_s = 0x1p+00, // 1
        .burst = 3,
        .steps = &.{
            .{ .at_ms = 0, .allowed = true, .remaining = 2, .wait_ns = 0, .reset_ns = 1000000000, .tokens_after = 0x1p+01 },
            .{ .at_ms = 0, .allowed = true, .remaining = 1, .wait_ns = 0, .reset_ns = 2000000000, .tokens_after = 0x1p+00 },
            .{ .at_ms = 0, .allowed = true, .remaining = 0, .wait_ns = 0, .reset_ns = 3000000000, .tokens_after = 0x0p+00 },
            .{ .at_ms = 0, .allowed = false, .remaining = 0, .wait_ns = 1000000000, .reset_ns = 3000000000, .tokens_after = 0x0p+00 },
            .{ .at_ms = 500, .allowed = false, .remaining = 0, .wait_ns = 500000000, .reset_ns = 2500000000, .tokens_after = 0x1p-01 },
            .{ .at_ms = 1000, .allowed = true, .remaining = 0, .wait_ns = 0, .reset_ns = 3000000000, .tokens_after = 0x0p+00 },
            .{ .at_ms = 1000, .allowed = false, .remaining = 0, .wait_ns = 1000000000, .reset_ns = 3000000000, .tokens_after = 0x0p+00 },
            .{ .at_ms = 3000, .allowed = true, .remaining = 1, .wait_ns = 0, .reset_ns = 2000000000, .tokens_after = 0x1p+00 },
            .{ .at_ms = 3000, .allowed = true, .remaining = 0, .wait_ns = 0, .reset_ns = 3000000000, .tokens_after = 0x0p+00 },
            .{ .at_ms = 3000, .allowed = false, .remaining = 0, .wait_ns = 1000000000, .reset_ns = 3000000000, .tokens_after = 0x0p+00 },
            .{ .at_ms = 3000, .allowed = false, .remaining = 0, .wait_ns = 1000000000, .reset_ns = 3000000000, .tokens_after = 0x0p+00 },
            .{ .at_ms = 100000, .allowed = true, .remaining = 2, .wait_ns = 0, .reset_ns = 1000000000, .tokens_after = 0x1p+01 },
        },
    },
    .{
        .name = "rate=2 burst=2 — the row's (2,2) triple at offsets 0/250/500 ms, then a long idle",
        .note = "250 ms at 2 tok/s = half a token: still denied",
        .rate_per_s = 0x1p+01, // 2
        .burst = 2,
        .steps = &.{
            .{ .at_ms = 0, .allowed = true, .remaining = 1, .wait_ns = 0, .reset_ns = 500000000, .tokens_after = 0x1p+00 },
            .{ .at_ms = 0, .allowed = true, .remaining = 0, .wait_ns = 0, .reset_ns = 1000000000, .tokens_after = 0x0p+00 },
            .{ .at_ms = 250, .allowed = false, .remaining = 0, .wait_ns = 250000000, .reset_ns = 750000000, .tokens_after = 0x1p-01 },
            .{ .at_ms = 500, .allowed = true, .remaining = 0, .wait_ns = 0, .reset_ns = 1000000000, .tokens_after = 0x0p+00 },
            .{ .at_ms = 600, .allowed = false, .remaining = 0, .wait_ns = 400000000, .reset_ns = 900000000, .tokens_after = 0x1.999999999999ap-03 },
            .{ .at_ms = 100000, .allowed = true, .remaining = 1, .wait_ns = 0, .reset_ns = 500000000, .tokens_after = 0x1p+00 },
            .{ .at_ms = 100000, .allowed = true, .remaining = 0, .wait_ns = 0, .reset_ns = 1000000000, .tokens_after = 0x0p+00 },
            .{ .at_ms = 100000, .allowed = false, .remaining = 0, .wait_ns = 500000000, .reset_ns = 1000000000, .tokens_after = 0x0p+00 },
        },
    },
    .{
        .name = "rate=3 burst=1 — the row's (3,1) triple; step 2 lands on the reported retry_after",
        .note = "deny at t0 reports ceil(1000/3)=334 ms; waiting exactly that must pass",
        .rate_per_s = 0x1.8p+01, // 3
        .burst = 1,
        .steps = &.{
            .{ .at_ms = 0, .allowed = true, .remaining = 0, .wait_ns = 0, .reset_ns = 333333333, .tokens_after = 0x0p+00 },
            .{ .at_ms = 0, .allowed = false, .remaining = 0, .wait_ns = 333333333, .reset_ns = 333333333, .tokens_after = 0x0p+00 },
            .{ .at_ms = 334, .allowed = true, .remaining = 0, .wait_ns = 0, .reset_ns = 333333333, .tokens_after = 0x0p+00 },
            .{ .at_ms = 334, .allowed = false, .remaining = 0, .wait_ns = 333333333, .reset_ns = 333333333, .tokens_after = 0x0p+00 },
            .{ .at_ms = 667, .allowed = false, .remaining = 0, .wait_ns = 333333, .reset_ns = 333333, .tokens_after = 0x1.ff7ced916872cp-01 },
            .{ .at_ms = 1000, .allowed = true, .remaining = 0, .wait_ns = 0, .reset_ns = 333333333, .tokens_after = 0x0p+00 },
        },
    },
    .{
        .name = "rate=0.5 burst=5 — sub-unit rate, drain the burst then wait 2 s per token",
        .note = "exercises a fractional refill rate and a 5-deep burst",
        .rate_per_s = 0x1p-01, // 0.5
        .burst = 5,
        .steps = &.{
            .{ .at_ms = 0, .allowed = true, .remaining = 4, .wait_ns = 0, .reset_ns = 2000000000, .tokens_after = 0x1p+02 },
            .{ .at_ms = 0, .allowed = true, .remaining = 3, .wait_ns = 0, .reset_ns = 4000000000, .tokens_after = 0x1.8p+01 },
            .{ .at_ms = 0, .allowed = true, .remaining = 2, .wait_ns = 0, .reset_ns = 6000000000, .tokens_after = 0x1p+01 },
            .{ .at_ms = 0, .allowed = true, .remaining = 1, .wait_ns = 0, .reset_ns = 8000000000, .tokens_after = 0x1p+00 },
            .{ .at_ms = 0, .allowed = true, .remaining = 0, .wait_ns = 0, .reset_ns = 10000000000, .tokens_after = 0x0p+00 },
            .{ .at_ms = 0, .allowed = false, .remaining = 0, .wait_ns = 2000000000, .reset_ns = 10000000000, .tokens_after = 0x0p+00 },
            .{ .at_ms = 1000, .allowed = false, .remaining = 0, .wait_ns = 1000000000, .reset_ns = 9000000000, .tokens_after = 0x1p-01 },
            .{ .at_ms = 2000, .allowed = true, .remaining = 0, .wait_ns = 0, .reset_ns = 10000000000, .tokens_after = 0x0p+00 },
            .{ .at_ms = 2000, .allowed = false, .remaining = 0, .wait_ns = 2000000000, .reset_ns = 10000000000, .tokens_after = 0x0p+00 },
            .{ .at_ms = 60000, .allowed = true, .remaining = 4, .wait_ns = 0, .reset_ns = 2000000000, .tokens_after = 0x1p+02 },
        },
    },
    .{
        .name = "rate=100 burst=1 — sub-10 ms recovery, exercises millisecond rounding",
        .note = "one token per 10 ms",
        .rate_per_s = 0x1.9p+06, // 100
        .burst = 1,
        .steps = &.{
            .{ .at_ms = 0, .allowed = true, .remaining = 0, .wait_ns = 0, .reset_ns = 10000000, .tokens_after = 0x0p+00 },
            .{ .at_ms = 0, .allowed = false, .remaining = 0, .wait_ns = 10000000, .reset_ns = 10000000, .tokens_after = 0x0p+00 },
            .{ .at_ms = 5, .allowed = false, .remaining = 0, .wait_ns = 5000000, .reset_ns = 5000000, .tokens_after = 0x1p-01 },
            .{ .at_ms = 10, .allowed = true, .remaining = 0, .wait_ns = 0, .reset_ns = 10000000, .tokens_after = 0x0p+00 },
            .{ .at_ms = 10, .allowed = false, .remaining = 0, .wait_ns = 10000000, .reset_ns = 10000000, .tokens_after = 0x0p+00 },
            .{ .at_ms = 15, .allowed = false, .remaining = 0, .wait_ns = 5000000, .reset_ns = 5000000, .tokens_after = 0x1p-01 },
            .{ .at_ms = 20, .allowed = true, .remaining = 0, .wait_ns = 0, .reset_ns = 10000000, .tokens_after = 0x0p+00 },
        },
    },
};
