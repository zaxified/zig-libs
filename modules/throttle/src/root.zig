// SPDX-License-Identifier: MIT

//! throttle — global concurrency limiting / load shedding: a max-in-flight
//! semaphore plus a `router` middleware answering **503 + Retry-After**.
//!
//! `ratelimit` bounds request *rate per key*; `abuseguard` bounds
//! *connections per IP*. `throttle` bounds **total concurrent in-flight
//! requests**, protecting the backend from overload regardless of who is
//! calling — when the server is saturated it **sheds load** (a fast 503)
//! instead of collapsing under an unbounded queue. This is the "survive a
//! spike" piece.
//!
//! Layers (each usable on its own):
//! - `Throttle.tryAcquire()`/`release()` — the bare counting semaphore: at
//!   most `max_in_flight` slots out at once, lock-free (a CAS loop on one
//!   atomic counter), zero allocation, no clock, no I/O. The counter can
//!   never exceed the cap (the CAS refuses) nor go negative (`release`
//!   asserts in Debug and saturates at 0 in release builds).
//! - `Throttle.acquire()` — the bounded-wait variant (`max_wait_ms` > 0):
//!   waits up to the deadline for a slot instead of shedding immediately,
//!   with the waiter set itself capped (`max_waiters`) — an unbounded wait
//!   queue is just a slower way to fall over, and is itself a memory DoS
//!   (SEDA's bounded-queue rule). With the default `max_wait_ms = 0` it is
//!   exactly `tryAcquire`.
//! - `Throttle.middleware()` — a `router.Middleware`: a slot is acquired on
//!   entry and released via `defer` (also on handler error); at capacity the
//!   request gets **503 Service Unavailable** + `Retry-After` + a short
//!   plain body, and `next` is never called.
//!
//! Model after (semantics adopted where the spec left a choice):
//! - **Go `golang.org/x/sync/semaphore`:** `tryAcquire` never blocks and a
//!   failed acquire consumes nothing; every successful acquire must be paired
//!   with exactly one `release`. Deviation: Go hands freed slots to waiters
//!   in FIFO order; we wake all waiters and let them re-contend with new
//!   arrivals (barging). Under sustained saturation a waiter can lose every
//!   race until its deadline and shed at `max_wait_ms` — acceptable here
//!   because shedding under overload is the point (and it needs no
//!   per-waiter queue memory). Go's waiter set is also unbounded; ours is
//!   capped (`max_waiters`) per the SEDA rule above.
//! - **SEDA / Netflix concurrency-limits:** static limit + bounded queue +
//!   fast rejection. The static `max_in_flight` is the required primary; the
//!   opt-in `Options.adaptive` discovers the limit below it from observed
//!   latency (Netflix `Gradient2Limit`, or `AIMDLimit`), see `Adaptive`.
//!
//! Thread-safety: pure atomics — no mutex, no hidden globals, no allocation;
//! every call may race from any thread (the middleware runs on
//! `http.Server`'s per-connection tasks). All orderings are deliberately
//! `seq_cst`: the waiter/releaser handoff involves three atomic locations
//! (slot counter, waiter counter, release generation) and the no-lost-wakeup
//! audit is only simple under a single total order — a few stronger atomic
//! ops per HTTP request is noise next to the request itself.
//!
//! Bounded wait needs an `Io`: the deadline wait blocks on
//! `Io.futexWaitTimeout` (Zig 0.16 moved futexes onto the Io vtable), so
//! `Options.io` is required when `max_wait_ms > 0` — pass the same
//! `std.Io.Threaded` the server runs on. The default (shed immediately)
//! touches no Io at all. While a request waits it keeps occupying its server
//! connection task — that *is* the backpressure, bounded by
//! `max_waiters × max_wait_ms`.

const std = @import("std");
const clock_lib = @import("clock");
const testkit = @import("testkit");
const router = @import("router");
const http = @import("http");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Global concurrency limit + load-shedding → 503",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "posix",
    .targets = .{.linux64},
    .platform = .posix, // default clock uses the posix clock_gettime errno form
    .role = .util,
    // Internally synchronized with atomics only (documented seq_cst policy);
    // all calls may race across the accept loop and every connection task.
    .concurrency = .threadsafe,
    .model_after = "Go golang.org/x/sync/semaphore (slot semantics) + SEDA / Netflix concurrency-limits (bounded queue, load shedding)",
    .deps = .{ "router", "http", "clock" },
};

// ── clock injection ─────────────────────────────────────────────────────────

/// Monotonic time source, injected so the bounded-wait deadline is testable.
/// Implementations must be non-decreasing; the absolute origin is irrelevant
/// (only differences are used). Only consulted when `max_wait_ms > 0`.
pub const Clock = clock_lib.Clock;

// ── options ─────────────────────────────────────────────────────────────────

pub const Options = struct {
    /// Hard cap on concurrently held slots (in-flight requests). Must be ≥ 1.
    max_in_flight: u32,
    /// Bounded wait (backpressure): instead of shedding immediately when at
    /// capacity, `acquire` waits up to this long for a slot to free, then
    /// sheds. 0 (default) = shed immediately. Requires `io` when non-zero.
    max_wait_ms: u32 = 0,
    /// Cap on simultaneous waiters (only meaningful with `max_wait_ms > 0`):
    /// when the wait queue is full, further arrivals shed immediately — an
    /// unbounded waiter set is itself a memory/thread DoS. null (default) =
    /// same as `max_in_flight` (queue depth = service capacity, the SEDA
    /// rule of thumb); an explicit 0 disables waiting entirely.
    max_waiters: ?u32 = null,
    /// Value for the `Retry-After` header on a shed (503) response, rounded
    /// up to whole seconds, minimum 1. Unlike `ratelimit`, no exact
    /// free-slot time is computable (it depends on in-flight handler
    /// durations), so this is a configured hint.
    retry_after_ms: u64 = 1_000,
    /// Required when `max_wait_ms > 0`: the Io the wait blocks on
    /// (`futexWaitTimeout`) — pass the same `std.Io.Threaded` the server
    /// uses. Ignored otherwise.
    io: ?std.Io = null,
    /// Time source for the wait deadline — inject a fake for deterministic
    /// tests. Never consulted when `max_wait_ms = 0` and `adaptive` is null.
    clock: Clock = .monotonic,
    /// Opt-in adaptive limit discovery: `max_in_flight` becomes the ceiling and
    /// the admitted limit moves below it with the observed latency of the
    /// requests that report it (`acquirePermit` / `releasePermit`, or the
    /// middleware). null (default) = the static limit, nothing changes.
    adaptive: ?Adaptive = null,
};

/// Adaptive limit discovery, modelled on Netflix concurrency-limits'
/// `Gradient2Limit` and `AIMDLimit` (defaults are theirs: initial and minimum
/// limit 20, smoothing 0.2, RTT tolerance 1.5, long window 600 samples, queue
/// size 4, back-off 0.9, timeout 5 s). The limit stays in
/// `[min_limit, Options.max_in_flight]`; both bounds are clamped to the
/// ceiling, so a ceiling below 20 simply pins the limit there.
///
/// Samples are applied under a try-lock: a sample that finds another being
/// applied is skipped (a statistical estimator loses nothing, and the hot path
/// never blocks).
pub const Adaptive = struct {
    pub const Algorithm = enum {
        /// Latency gradient: the limit shrinks when the current RTT rises
        /// above the long-term RTT (a queue is building) and grows by
        /// `queue_size` per sample otherwise.
        gradient2,
        /// Additive increase while at least half the limit is in use,
        /// multiplicative decrease by `backoff_ratio` on a drop or an RTT past
        /// `timeout_ms`.
        aimd,
    };
    algorithm: Algorithm = .gradient2,
    /// First limit; null = `min(20, max_in_flight)`.
    initial_limit: ?u32 = null,
    min_limit: u32 = 20,
    /// `gradient2`: blend of the new estimate (0 < smoothing <= 1).
    smoothing: f64 = 0.2,
    /// `gradient2`: how much the RTT may exceed the long-term RTT before the
    /// limit shrinks (>= 1).
    rtt_tolerance: f64 = 1.5,
    /// `gradient2`: the long-term RTT is a mean over the first 10 samples,
    /// then an exponential average over about this many samples.
    long_window: u32 = 600,
    /// `gradient2`: slots the limit may grow by per sample (a constant).
    queue_size: u32 = 4,
    /// `aimd`: factor applied on a drop or timeout (0.5 <= ratio < 1).
    backoff_ratio: f64 = 0.9,
    /// `aimd`: an RTT past this counts as a drop.
    timeout_ms: u32 = 5_000,
};

/// How a request that held a `Permit` ended, for `releasePermit`.
pub const Outcome = enum {
    /// Completed: its latency is a sample.
    success,
    /// Shed or timed out by something downstream: `aimd` backs off (as the
    /// reference does; `gradient2` ignores drops, also as the reference does).
    dropped,
    /// Says nothing about capacity (a client error, a cancel): no sample.
    ignore,
};

/// A held slot plus what the adaptive limit needs to judge the request.
pub const Permit = struct {
    start_ns: u64,
    /// Requests in flight when this one was admitted (itself included).
    in_flight: u32,
};

// ── the semaphore ───────────────────────────────────────────────────────────

/// Global concurrency limiter. See the module doc for semantics; all methods
/// are thread-safe (pure atomics). Never allocates — there is no gpa to pass
/// and `deinit` only poisons the memory (kept for API symmetry; it asserts
/// that every acquired slot was released). The Throttle must outlive any
/// Router its `middleware()` is registered on.
pub const Throttle = struct {
    options: Options,
    /// Slots currently held (0 ≤ n ≤ max_in_flight, CAS-enforced).
    in_flight_count: std.atomic.Value(u32) = .init(0),
    /// Bounded-wait waiters currently parked (0 ≤ n ≤ max_waiters).
    waiting_count: std.atomic.Value(u32) = .init(0),
    /// Release notification word (the futex): bumped by `release` whenever
    /// waiters exist, so a parked `acquire` re-contends. Wraparound is fine —
    /// the futex only compares for equality.
    release_gen: std.atomic.Value(u32) = .init(0),
    /// The admitted limit; 0 = not set yet (`limit()` then reads
    /// `Options.max_in_flight`, or the adaptive initial limit).
    limit_now: std.atomic.Value(u32) = .init(0),
    /// Try-lock over the adaptive estimator below.
    adapt_busy: std.atomic.Value(bool) = .init(false),
    /// Estimator state (guarded by `adapt_busy`): the unrounded limit and the
    /// long-term RTT, 0 = not set yet.
    est_limit: f64 = 0,
    long_rtt_ns: f64 = 0,
    long_n: u32 = 0,

    pub fn init(options: Options) Throttle {
        std.debug.assert(options.max_in_flight >= 1);
        if (options.adaptive) |a| {
            std.debug.assert(a.min_limit >= 1 and a.rtt_tolerance >= 1.0);
            std.debug.assert(a.smoothing > 0 and a.smoothing <= 1.0);
            std.debug.assert(a.backoff_ratio >= 0.5 and a.backoff_ratio < 1.0);
        }
        // Bounded wait blocks on the Io futex — there is no io-less wait in
        // Zig 0.16 std (std.Thread.Condition/Futex are gone).
        if (options.max_wait_ms != 0) std.debug.assert(options.io != null);
        return .{ .options = options };
    }

    /// Nothing to free (the Throttle never allocates); asserts no slot is
    /// still held and nobody is waiting.
    pub fn deinit(t: *Throttle) void {
        std.debug.assert(t.in_flight_count.load(.seq_cst) == 0);
        std.debug.assert(t.waiting_count.load(.seq_cst) == 0);
        t.* = undefined;
    }

    /// Take a slot if one is free — never blocks, never over-admits (the
    /// CAS refuses at `max_in_flight`); a failed attempt consumes nothing
    /// (x/sync `TryAcquire`). Pair every success with exactly one `release`.
    pub fn tryAcquire(t: *Throttle) bool {
        var cur = t.in_flight_count.load(.seq_cst);
        while (true) {
            if (cur >= t.limit()) return false;
            cur = t.in_flight_count.cmpxchgWeak(cur, cur + 1, .seq_cst, .seq_cst) orelse
                return true;
        }
    }

    /// `tryAcquire`, plus the bounded wait when configured: at capacity with
    /// `max_wait_ms > 0`, park on the release futex until a slot frees or
    /// the deadline passes — false = shed (send the 503). When the waiter
    /// set is already at `max_waiters` the call sheds immediately without
    /// waiting (bounded queue). A canceled Io wait (server shutdown) also
    /// sheds. With `max_wait_ms = 0` this is exactly `tryAcquire`.
    pub fn acquire(t: *Throttle) bool {
        if (t.tryAcquire()) return true;
        if (t.options.max_wait_ms == 0) return false;
        // `init` asserts this, and `std.debug.assert` is compiled out in
        // ReleaseFast — where `.?` on a null optional is illegal behaviour,
        // not a panic. Shedding instead is this module's own release-mode
        // shape for a violated precondition (`release` saturates at 0 rather
        // than wrapping), and it is the safe direction: a caller who asked
        // for a bounded wait without an `Io` gets exactly the behaviour of
        // `max_wait_ms = 0`. The README's new "Without the router" section
        // invites direct construction by callers who never read the module
        // doc, which is what turned this from theory into a live edge.
        const io = t.options.io orelse return false;

        // Join the (bounded) waiter set. The increment must precede the
        // generation snapshot below: `release` only bumps/wakes when it
        // observes a waiter, and seq_cst gives the two sides one total
        // order — if the releaser missed this increment, the increment
        // (and everything after it) came later and sees the freed slot.
        var w = t.waiting_count.load(.seq_cst);
        while (true) {
            if (w >= t.maxWaiters()) return false; // queue full → shed now
            w = t.waiting_count.cmpxchgWeak(w, w + 1, .seq_cst, .seq_cst) orelse break;
        }
        defer _ = t.waiting_count.fetchSub(1, .seq_cst);

        const clock = t.options.clock;
        const deadline_ns = clock.now() +| @as(u64, t.options.max_wait_ms) * std.time.ns_per_ms;
        while (true) {
            // Snapshot the generation BEFORE the acquire attempt: a release
            // landing after a failed attempt bumps the generation first, so
            // the futex wait below returns immediately — no lost wakeup.
            const gen = t.release_gen.load(.seq_cst);
            if (t.tryAcquire()) return true;
            const now_ns = clock.now();
            if (now_ns >= deadline_ns) return false; // waited long enough → shed
            io.futexWaitTimeout(u32, &t.release_gen.raw, gen, .{ .duration = .{
                .raw = .fromNanoseconds(@intCast(deadline_ns - now_ns)),
                .clock = .awake,
            } }) catch return false; // Canceled (shutdown) → shed
            // Woken (release / timeout / spurious): loop re-checks.
        }
    }

    /// Return a slot taken by a successful `tryAcquire`/`acquire`. Releasing
    /// more than was acquired is a caller bug: asserts in Debug; in release
    /// builds the counter saturates at 0 instead of wrapping (never
    /// negative). Frees exactly one waiter batch: when waiters exist, the
    /// release generation is bumped and all of them are woken to re-contend.
    pub fn release(t: *Throttle) void {
        var cur = t.in_flight_count.load(.seq_cst);
        while (true) {
            std.debug.assert(cur > 0); // release without a matching acquire
            if (cur == 0) return; // ReleaseFast: saturate, don't wrap
            cur = t.in_flight_count.cmpxchgWeak(cur, cur - 1, .seq_cst, .seq_cst) orelse
                break;
        }
        // Hand the freed slot to any parked waiters (see `acquire` for the
        // ordering audit). Bump before wake, so a waiter between its failed
        // tryAcquire and its futexWait sees the new generation and retries.
        if (t.waiting_count.load(.seq_cst) != 0) {
            _ = t.release_gen.fetchAdd(1, .seq_cst);
            if (t.options.io) |io|
                io.futexWake(u32, &t.release_gen.raw, std.math.maxInt(u32));
        }
    }

    // ── adaptive limit ──────────────────────────────────────────────────

    /// The limit in force now: `max_in_flight` for a static throttle, the
    /// discovered value (in `[min_limit, max_in_flight]`) for an adaptive one.
    pub fn limit(t: *const Throttle) u32 {
        const l = t.limit_now.load(.seq_cst);
        if (l != 0) return l;
        const a = t.options.adaptive orelse return t.options.max_in_flight;
        return @min(a.initial_limit orelse 20, t.options.max_in_flight);
    }

    /// `acquire`, plus the start time and load that `releasePermit` needs to
    /// turn the request into a sample. null = shed. Without `Options.adaptive`
    /// the clock is not read.
    pub fn acquirePermit(t: *Throttle) ?Permit {
        if (!t.acquire()) return null;
        if (t.options.adaptive == null) return .{ .start_ns = 0, .in_flight = 0 };
        return .{ .start_ns = t.options.clock.now(), .in_flight = t.in_flight_count.load(.seq_cst) };
    }

    /// Return the slot of `acquirePermit` and, with `Options.adaptive`, feed
    /// the request's latency to the limit (see `Outcome`).
    pub fn releasePermit(t: *Throttle, p: Permit, outcome: Outcome) void {
        if (t.options.adaptive != null and outcome != .ignore)
            t.sample(t.options.clock.since(p.start_ns), p.in_flight, outcome == .dropped);
        t.release();
    }

    /// Apply one sample to the limit (`Adaptive` has the rules).
    fn sample(t: *Throttle, rtt_ns: u64, in_flight: u32, dropped: bool) void {
        const a = t.options.adaptive orelse return;
        if (t.adapt_busy.swap(true, .acquire)) return; // another sample is being applied: skip
        defer t.adapt_busy.store(false, .release);
        const ceiling = t.options.max_in_flight;
        const floor_limit = @min(a.min_limit, ceiling);
        const cur: u32 = t.limit();
        var next: f64 = @floatFromInt(cur);
        switch (a.algorithm) {
            .aimd => {
                if (dropped or rtt_ns > @as(u64, a.timeout_ms) * std.time.ns_per_ms) {
                    next = @floatFromInt(@as(u32, @intFromFloat(next * a.backoff_ratio)));
                } else if (@as(u64, in_flight) * 2 >= cur) {
                    next += 1;
                }
            },
            .gradient2 => {
                if (dropped) return; // the reference ignores drops here
                if (t.est_limit == 0) t.est_limit = next;
                const short: f64 = @floatFromInt(@max(rtt_ns, 1));
                // Long-term RTT: a mean over the first 10 samples, then an
                // exponential average with alpha = 2 / (window + 1).
                const warmup = 10;
                if (t.long_n < warmup) {
                    t.long_rtt_ns = (t.long_rtt_ns * @as(f64, @floatFromInt(t.long_n)) + short) / @as(f64, @floatFromInt(t.long_n + 1));
                    t.long_n += 1;
                } else {
                    const alpha = 2.0 / (@as(f64, @floatFromInt(a.long_window)) + 1.0);
                    t.long_rtt_ns = t.long_rtt_ns * (1.0 - alpha) + short * alpha;
                }
                const long = t.long_rtt_ns;
                // Drift: a long-term RTT far above the current one is pulled down.
                if (long / short > 2.0) t.long_rtt_ns *= 0.95;
                // Do not grow while the application, not the limit, is the bound.
                if (@as(f64, @floatFromInt(in_flight)) < t.est_limit / 2.0) return;
                const gradient = @max(0.5, @min(1.0, a.rtt_tolerance * long / short));
                const raw = t.est_limit * gradient + @as(f64, @floatFromInt(a.queue_size));
                next = t.est_limit * (1.0 - a.smoothing) + raw * a.smoothing;
                next = @max(@as(f64, @floatFromInt(floor_limit)), @min(@as(f64, @floatFromInt(ceiling)), next));
                t.est_limit = next;
            },
        }
        next = @max(@as(f64, @floatFromInt(floor_limit)), @min(@as(f64, @floatFromInt(ceiling)), next));
        t.limit_now.store(@max(1, @as(u32, @intFromFloat(next))), .seq_cst);
    }

    // ── observability ───────────────────────────────────────────────────

    /// Slots currently held. A point-in-time snapshot — pair with
    /// `maxInFlight()` to chart utilization.
    pub fn inFlight(t: *const Throttle) usize {
        return t.in_flight_count.load(.seq_cst);
    }

    /// Requests currently parked in the bounded wait (0 when waiting is
    /// disabled).
    pub fn waiting(t: *const Throttle) usize {
        return t.waiting_count.load(.seq_cst);
    }

    /// The configured hard cap (denominator for utilization metrics); with
    /// `Options.adaptive` the ceiling, see `limit` for the value in force.
    pub fn maxInFlight(t: *const Throttle) u32 {
        return t.options.max_in_flight;
    }

    /// The effective waiter cap (resolves the `max_waiters = null` default).
    pub fn maxWaiters(t: *const Throttle) u32 {
        return t.options.max_waiters orelse t.options.max_in_flight;
    }

    // ── the middleware ──────────────────────────────────────────────────

    /// A `router.Middleware` enforcing this limiter (`state` = the Throttle —
    /// per-instance state, no globals). Admitted requests hold a slot for
    /// the rest of the chain, released via `defer` (also when the handler
    /// errors). Shed requests get **503 Service Unavailable** with
    /// `Retry-After` (whole seconds, rounded up, ≥ 1) and a short plain
    /// body; `next` is never called. Register it router-level (before
    /// routes — chi's rule) so 404/405 traffic is throttled too, or on a
    /// group to guard only that subtree.
    pub fn middleware(t: *Throttle) router.Middleware {
        return .{ .state = t, .run = middlewareRun };
    }
};

fn middlewareRun(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    const t: *Throttle = @ptrCast(@alignCast(state.?));
    if (t.options.adaptive == null) {
        if (!t.acquire()) return shed(t, ctx);
        defer t.release();
        return next.run(ctx);
    }
    // Adaptive: the request's latency is a sample; a handler error says
    // nothing about capacity (a client mistake looks the same), so it is not.
    const p = t.acquirePermit() orelse return shed(t, ctx);
    next.run(ctx) catch |e| {
        t.releasePermit(p, .ignore);
        return e;
    };
    t.releasePermit(p, .success);
}

/// The 503 path, mirroring ratelimit's 429: the `Retry-After` value is
/// formatted on this stack frame; `setHeader` copies it into the response
/// writer's own storage at call time, so it only has to outlive the call and
/// this branch no longer forces an early `end()`. Handing the head back to
/// the serving loop is the point, not a side effect: this is a middleware,
/// and an OUTER one that works after `next.run` — `sessions` saves its
/// cookie there, `csrf` issues its token there — could not touch a 503 whose
/// head had already gone out.
fn shed(t: *Throttle, ctx: *router.Ctx) anyerror!void {
    return shedAfter(t.options.retry_after_ms, ctx);
}

fn shedAfter(retry_after_ms: u64, ctx: *router.Ctx) anyerror!void {
    var retry_buf: [24]u8 = undefined;
    const retry_s = @max(1, std.math.divCeil(u64, retry_after_ms, std.time.ms_per_s) catch unreachable);
    ctx.res.setStatus(503);
    try ctx.res.setHeader("Retry-After", std.mem.print(&retry_buf, "{d}", .{retry_s}) catch unreachable);
    try ctx.res.setHeader("Content-Type", "text/plain");
    try ctx.res.writeAll("Service Unavailable\n");
}

// ── partitioned limiter ─────────────────────────────────────────────────────

/// Most partitions a `Partitioned` can hold (fixed storage, no allocation).
pub const max_partitions = 16;

pub const PartitionError = error{
    /// `shares_percent` is empty.
    NoPartitions,
    /// More than `max_partitions` shares.
    TooManyPartitions,
    /// The shares add up to more than 100 %.
    SharesExceed100,
    /// `max_in_flight` is 0.
    ZeroLimit,
};

pub const PartitionedOptions = struct {
    /// Total budget the partitions share. Must be >= 1.
    max_in_flight: u32,
    /// One entry per partition: its guaranteed percentage of `max_in_flight`
    /// (rounded down). The sum must be <= 100; the unassigned rest is only
    /// ever borrowable. 0 is allowed (a pure borrower).
    shares_percent: []const u8,
    /// `Retry-After` hint for the 503 of `middleware()` (same meaning as
    /// `Options.retry_after_ms`).
    retry_after_ms: u64 = 1_000,
    /// Picks the partition of a request for `middleware()` (e.g. by path or
    /// header). null = every request is partition 0. An index out of range
    /// is shed.
    classify: ?*const fn (ctx: *router.Ctx) usize = null,
};

/// Netflix `PartitionedLimiter` shape: each partition has a guaranteed share
/// of the budget and may borrow what the others leave unused. A request of
/// partition `p` is admitted when `p` holds fewer slots than its guarantee,
/// OR the total in flight is below `max_in_flight` (borrowing). Hence a flood
/// in one partition fills at most the whole budget and can never take away a
/// slot another partition is still entitled to: that partition's own
/// guaranteed requests are admitted even then. The price (same as Netflix):
/// the total may exceed `max_in_flight` while guaranteed requests land on a
/// fully borrowed budget, by at most the sum of the guarantees (so at most
/// 2 x `max_in_flight`). No waiting: a refused request sheds at once.
/// Lock-free (atomics only), no allocation, `release(p)` must name the
/// partition the matching acquire used.
pub const Partitioned = struct {
    retry_after_ms: u64,
    classify: ?*const fn (ctx: *router.Ctx) usize,
    max_in_flight: u32,
    count: usize,
    guarantee: [max_partitions]u32 = @splat(0),
    busy: [max_partitions]std.atomic.Value(u32) = @splat(.init(0)),
    total: std.atomic.Value(u32) = .init(0),

    pub fn init(options: PartitionedOptions) PartitionError!Partitioned {
        if (options.max_in_flight == 0) return error.ZeroLimit;
        if (options.shares_percent.len == 0) return error.NoPartitions;
        if (options.shares_percent.len > max_partitions) return error.TooManyPartitions;
        var sum: u32 = 0;
        for (options.shares_percent) |sh| sum += sh; // <= 16 * 255, no overflow
        if (sum > 100) return error.SharesExceed100;
        var p: Partitioned = .{
            .retry_after_ms = options.retry_after_ms,
            .classify = options.classify,
            .max_in_flight = options.max_in_flight,
            .count = options.shares_percent.len,
        };
        for (options.shares_percent, 0..) |sh, i| {
            p.guarantee[i] = @intCast(@as(u64, options.max_in_flight) * sh / 100);
        }
        return p;
    }

    /// Asserts that every slot was released.
    pub fn deinit(p: *Partitioned) void {
        std.debug.assert(p.total.load(.seq_cst) == 0);
        p.* = undefined;
    }

    /// Take a slot for `partition`; false = shed (also for an index out of
    /// range). A failed attempt consumes nothing. Pair every success with one
    /// `release(partition)`.
    pub fn tryAcquire(p: *Partitioned, partition: usize) bool {
        if (partition >= p.count) return false;
        const b = &p.busy[partition];
        // Guaranteed path: under the partition's own share.
        var cur = b.load(.seq_cst);
        while (cur < p.guarantee[partition]) {
            cur = b.cmpxchgWeak(cur, cur + 1, .seq_cst, .seq_cst) orelse {
                _ = p.total.fetchAdd(1, .seq_cst);
                return true;
            };
        }
        // Borrow path: the whole budget still has room.
        var t = p.total.load(.seq_cst);
        while (t < p.max_in_flight) {
            t = p.total.cmpxchgWeak(t, t + 1, .seq_cst, .seq_cst) orelse {
                _ = b.fetchAdd(1, .seq_cst);
                return true;
            };
        }
        return false;
    }

    /// Return a slot taken for `partition`. An index out of range or a
    /// release without a matching acquire is a caller bug: it asserts in
    /// Debug (the index case just returns) and saturates at 0 in release
    /// builds, never wrapping.
    pub fn release(p: *Partitioned, partition: usize) void {
        if (partition >= p.count) return;
        const b = &p.busy[partition];
        var cur = b.load(.seq_cst);
        while (true) {
            std.debug.assert(cur > 0);
            if (cur == 0) return;
            cur = b.cmpxchgWeak(cur, cur - 1, .seq_cst, .seq_cst) orelse break;
        }
        _ = p.total.fetchSub(1, .seq_cst);
    }

    /// Slots currently held across all partitions.
    pub fn inFlight(p: *const Partitioned) usize {
        return p.total.load(.seq_cst);
    }

    /// Slots currently held by `partition` (0 for an index out of range).
    pub fn inFlightIn(p: *const Partitioned, partition: usize) usize {
        if (partition >= p.count) return 0;
        return p.busy[partition].load(.seq_cst);
    }

    /// The guaranteed slot count of `partition` (0 for an index out of range).
    pub fn guaranteed(p: *const Partitioned, partition: usize) u32 {
        if (partition >= p.count) return 0;
        return p.guarantee[partition];
    }

    /// A `router.Middleware` like `Throttle.middleware`: the partition comes
    /// from `PartitionedOptions.classify`; shed = 503 + `Retry-After`.
    pub fn middleware(p: *Partitioned) router.Middleware {
        return .{ .state = p, .run = partitionedRun };
    }
};

fn partitionedRun(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    const p: *Partitioned = @ptrCast(@alignCast(state.?));
    const part = if (p.classify) |f| f(ctx) else 0;
    if (!p.tryAcquire(part)) return shedAfter(p.retry_after_ms, ctx);
    defer p.release(part);
    return next.run(ctx);
}

// ── tests: the bare semaphore (no clock, no Io, no HTTP) ────────────────────

const testing = std.testing;

test "tryAcquire/release: acquire to the cap, next fails, release frees" {
    var th: Throttle = .init(.{ .max_in_flight = 3 });
    defer th.deinit();
    try testing.expectEqual(3, th.maxInFlight());
    try testing.expectEqual(0, th.inFlight());

    try testing.expect(th.tryAcquire());
    try testing.expect(th.tryAcquire());
    try testing.expect(th.tryAcquire());
    try testing.expectEqual(3, th.inFlight());

    // At capacity: every further attempt fails and consumes nothing.
    try testing.expect(!th.tryAcquire());
    try testing.expect(!th.tryAcquire());
    try testing.expectEqual(3, th.inFlight());

    // One release frees exactly one slot.
    th.release();
    try testing.expectEqual(2, th.inFlight());
    try testing.expect(th.tryAcquire());
    try testing.expect(!th.tryAcquire());

    // Full drain returns to zero and the slots stay reusable.
    th.release();
    th.release();
    th.release();
    try testing.expectEqual(0, th.inFlight());
    try testing.expect(th.tryAcquire());
    th.release();
}

test "acquire with max_wait_ms=0 is exactly tryAcquire (no Io needed)" {
    var th: Throttle = .init(.{ .max_in_flight = 1 });
    defer th.deinit();
    try testing.expect(th.acquire()); // fast path
    try testing.expect(!th.acquire()); // full → immediate shed
    try testing.expectEqual(0, th.waiting());
    th.release();
    try testing.expect(th.acquire());
    th.release();
}

test "max_waiters=0 disables waiting even with max_wait_ms set" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var th: Throttle = .init(.{
        .max_in_flight = 1,
        .max_wait_ms = 60_000,
        .max_waiters = 0,
        .io = threaded.io(),
    });
    defer th.deinit();
    try testing.expect(th.tryAcquire());
    try testing.expect(!th.acquire()); // would wait, but the queue holds 0
    th.release();
}

test "stress: N threads hammering tryAcquire/release never exceed the cap" {
    const cap = 4;
    const n_threads = 8;
    const iters = 20_000;

    var th: Throttle = .init(.{ .max_in_flight = cap });
    defer th.deinit();

    const Shared = struct {
        gauge: std.atomic.Value(i32) = .init(0),
        violations: std.atomic.Value(u32) = .init(0),
        successes: std.atomic.Value(u64) = .init(0),
    };
    const Worker = struct {
        fn run(t: *Throttle, s: *Shared) void {
            for (0..iters) |_| {
                if (t.tryAcquire()) {
                    const cur = s.gauge.fetchAdd(1, .seq_cst) + 1;
                    if (cur > cap) _ = s.violations.fetchAdd(1, .seq_cst);
                    std.atomic.spinLoopHint(); // hold the slot briefly
                    _ = s.gauge.fetchSub(1, .seq_cst);
                    t.release();
                    _ = s.successes.fetchAdd(1, .seq_cst);
                }
            }
        }
    };

    var shared: Shared = .{};
    var handles: [n_threads]std.Thread = undefined;
    for (&handles) |*h| h.* = try std.Thread.spawn(.{}, Worker.run, .{ &th, &shared });
    for (handles) |h| h.join();

    try testing.expectEqual(0, shared.violations.load(.seq_cst));
    try testing.expectEqual(0, shared.gauge.load(.seq_cst));
    try testing.expectEqual(0, th.inFlight()); // count returns to zero
    try testing.expect(shared.successes.load(.seq_cst) > 0);
}

// ── tests: the bounded wait (Io futex, real threads, no HTTP) ───────────────

fn sleepMs(io: std.Io, ms: u32) !void {
    const d: std.Io.Clock.Duration = .{ .raw = .fromMilliseconds(ms), .clock = .awake };
    d.sleep(io) catch return error.Canceled;
}

test "bounded wait: sheds after the deadline when nobody releases" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var th: Throttle = .init(.{
        .max_in_flight = 1,
        .max_wait_ms = 100,
        .io = threaded.io(),
    });
    defer th.deinit();

    try testing.expect(th.tryAcquire()); // saturate
    const t0 = Clock.monotonic.now();
    try testing.expect(!th.acquire()); // parks, then sheds at the deadline
    const elapsed_ms = (Clock.monotonic.now() - t0) / std.time.ns_per_ms;
    try testing.expect(elapsed_ms >= 100); // the full bounded wait was honored
    try testing.expectEqual(0, th.waiting());
    th.release();
}

test "bounded wait: a release inside the window hands over the slot" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var th: Throttle = .init(.{
        .max_in_flight = 1,
        .max_wait_ms = 30_000, // deadline far away: success must come via release
        .io = io,
    });
    defer th.deinit();

    try testing.expect(th.tryAcquire()); // saturate

    const Releaser = struct {
        fn run(t: *Throttle, io_: std.Io) void {
            sleepMs(io_, 20) catch {};
            t.release();
        }
    };
    const releaser = try std.Thread.spawn(.{}, Releaser.run, .{ &th, io });
    defer releaser.join();

    try testing.expect(th.acquire()); // woken well before the 30 s deadline
    try testing.expectEqual(1, th.inFlight());
    th.release();
}

test "bounded wait: full waiter queue sheds immediately; the waiter still wins" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var th: Throttle = .init(.{
        .max_in_flight = 1,
        .max_wait_ms = 60_000,
        .max_waiters = 1,
        .io = io,
    });
    defer th.deinit();

    try testing.expect(th.tryAcquire()); // saturate

    const Waiter = struct {
        fn run(t: *Throttle, got: *std.atomic.Value(u8)) void {
            got.store(if (t.acquire()) 1 else 2, .seq_cst);
        }
    };
    var got: std.atomic.Value(u8) = .init(0);
    const waiter = try std.Thread.spawn(.{}, Waiter.run, .{ &th, &got });
    defer waiter.join();

    // Wait until the waiter is parked (occupies the whole queue).
    var tries: usize = 0;
    while (th.waiting() != 1) : (tries += 1) {
        if (tries > 1000) return error.TestTimeout;
        try sleepMs(io, 10);
    }

    // Queue full → this acquire sheds without waiting (a wait would block
    // this test for the full 60 s — its promptness is the proof).
    try testing.expect(!th.acquire());

    // Free the slot: the parked waiter takes it (joined by the defer).
    th.release();
    tries = 0;
    while (got.load(.seq_cst) == 0) : (tries += 1) {
        if (tries > 1000) return error.TestTimeout;
        try sleepMs(io, 10);
    }
    try testing.expectEqual(1, got.load(.seq_cst));
    try testing.expectEqual(1, th.inFlight());
    try testing.expectEqual(0, th.waiting());
    th.release(); // on the waiter's behalf
    try testing.expectEqual(0, th.inFlight());
}

test "stress: bounded-wait acquire/release across threads keeps every invariant" {
    const cap = 2;
    const n_threads = 8;
    const iters = 2_000;

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var th: Throttle = .init(.{
        .max_in_flight = cap,
        .max_wait_ms = 1_000,
        .max_waiters = n_threads,
        .io = threaded.io(),
    });
    defer th.deinit();

    const Shared = struct {
        gauge: std.atomic.Value(i32) = .init(0),
        violations: std.atomic.Value(u32) = .init(0),
        successes: std.atomic.Value(u64) = .init(0),
        sheds: std.atomic.Value(u64) = .init(0),
    };
    const Worker = struct {
        fn run(t: *Throttle, s: *Shared) void {
            for (0..iters) |_| {
                if (t.acquire()) {
                    const cur = s.gauge.fetchAdd(1, .seq_cst) + 1;
                    if (cur > cap) _ = s.violations.fetchAdd(1, .seq_cst);
                    std.atomic.spinLoopHint();
                    _ = s.gauge.fetchSub(1, .seq_cst);
                    t.release();
                    _ = s.successes.fetchAdd(1, .seq_cst);
                } else {
                    _ = s.sheds.fetchAdd(1, .seq_cst);
                }
            }
        }
    };

    var shared: Shared = .{};
    var handles: [n_threads]std.Thread = undefined;
    for (&handles) |*h| h.* = try std.Thread.spawn(.{}, Worker.run, .{ &th, &shared });
    for (handles) |h| h.join();

    try testing.expectEqual(0, shared.violations.load(.seq_cst));
    try testing.expectEqual(0, shared.gauge.load(.seq_cst));
    try testing.expectEqual(0, th.inFlight());
    try testing.expectEqual(0, th.waiting());
    try testing.expect(shared.successes.load(.seq_cst) > 0);
}

test "STRESS: release must wake a parked waiter promptly (lost-wakeup detector)" {
    // `acquire`'s own deadline means a lost wakeup can never hang this test —
    // `futexWaitTimeout` is always bounded by `max_wait_ms`. But that same
    // deadline is exactly what would HIDE a lost wakeup from a naive test: if
    // `release` forgets to wake a parked waiter, the waiter still eventually
    // returns `true` — the slot was freed, and the loop always retries
    // `tryAcquire` once the futex wait's own timeout elapses — just late, at
    // (almost) the full `max_wait_ms` instead of promptly. So a lost wakeup
    // must be caught on TIMING, not on the boolean result: a genuinely woken
    // waiter returns within a few ms of the release; one that fell through to
    // the deadline takes close to the whole window. Many short rounds (not
    // one long one) maximize how often the release lands while the waiter is
    // actually parked in the futex wait.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const rounds = 30;
    const max_wait_ms = 300;
    const release_delay_ms = 10; // gives the waiter time to actually park
    // A genuine wake returns in low single-digit ms even under scheduler
    // noise; a lost wakeup falls back to (most of) the full deadline.
    const slow_threshold_ms = max_wait_ms / 2;

    var slow_wakeups: u32 = 0;
    var round: u32 = 0;
    while (round < rounds) : (round += 1) {
        var th: Throttle = .init(.{
            .max_in_flight = 1,
            .max_wait_ms = max_wait_ms,
            .io = io,
        });
        defer th.deinit();

        try testing.expect(th.tryAcquire()); // saturate the only slot

        const Releaser = struct {
            fn run(t: *Throttle, io_: std.Io) void {
                sleepMs(io_, release_delay_ms) catch {};
                t.release();
            }
        };
        const releaser = try std.Thread.spawn(.{}, Releaser.run, .{ &th, io });
        defer releaser.join();

        const t0 = Clock.monotonic.now();
        try testing.expect(th.acquire()); // must be woken, not merely outlast the deadline
        const elapsed_ms = (Clock.monotonic.now() - t0) / std.time.ns_per_ms;
        th.release(); // on the (already-returned) waiter's behalf

        if (elapsed_ms > slow_threshold_ms) slow_wakeups += 1;
    }

    // A stray slow round can happen under host scheduling noise; a systemic
    // lost wakeup makes every round slow (it always falls through to the
    // deadline) — the threshold catches the systemic case without being
    // flaky on occasional noise.
    try testing.expect(slow_wakeups * 2 < rounds); // fewer than half slow
}

// ── tests: middleware over the socket-free server codec ─────────────────────

const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

/// Drive a router through `http.Server.serveStream` with canned wire bytes
/// (same harness as the router/ratelimit tests).
fn runWire(r: *router.Router, bytes: []const u8, out_buf: []u8) []const u8 {
    var in: Reader = .fixed(bytes);
    var out: Writer = .fixed(out_buf);
    var head_buf: [2048]u8 = undefined;
    var request_body_buf: [256]u8 = undefined;
    var response_body_buf: [512]u8 = undefined;
    var chunk_buf: [128]u8 = undefined;
    http.Server.serveStream(.{
        .handler = r.handler(),
        .context = r,
        .server_name = null, // keep goldens free of Server/Date noise
    }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    return out.buffered();
}

fn wire(comptime target: []const u8) []const u8 {
    return "GET " ++ target ++ " HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n";
}

fn expectStatus(got: []const u8, comptime status: []const u8) !void {
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 " ++ status));
}

fn expectHeaderLine(got: []const u8, comptime line: []const u8) !void {
    try testing.expect(std.mem.find(u8, got, "\r\n" ++ line ++ "\r\n") != null);
}

fn hCount(ctx: *router.Ctx) anyerror!void {
    const n: *u32 = @ptrCast(@alignCast(ctx.state.?));
    n.* += 1;
    try ctx.res.writeAll("ok");
}

fn hBoom(_: *router.Ctx) anyerror!void {
    return error.Boom;
}

test "middleware: pass-through when free, golden 503 when full, recovery after release" {
    var th: Throttle = .init(.{ .max_in_flight = 1 });
    defer th.deinit();

    var hits: u32 = 0;
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &hits;
    try r.use(th.middleware());
    try r.get("/t", hCount);

    var buf: [1024]u8 = undefined;
    // Free: the request flows to the handler; the slot is back afterwards.
    try expectStatus(runWire(&r, wire("/t"), &buf), "200");
    try testing.expectEqual(1, hits);
    try testing.expectEqual(0, th.inFlight());

    // Occupy the only slot (as a concurrent in-flight request would).
    try testing.expect(th.tryAcquire());
    try testing.expectEqualStrings("HTTP/1.1 503 Service Unavailable\r\n" ++
        "Retry-After: 1\r\n" ++
        "Content-Type: text/plain\r\n" ++
        "Connection: close\r\n" ++
        "Content-Length: 20\r\n" ++
        "\r\n" ++
        "Service Unavailable\n", runWire(&r, wire("/t"), &buf));
    try testing.expectEqual(1, hits); // handler never ran

    // Slot freed → served again.
    th.release();
    try expectStatus(runWire(&r, wire("/t"), &buf), "200");
    try testing.expectEqual(2, hits);
    try testing.expectEqual(0, th.inFlight());
}

/// A synthetic "outer" middleware shaped like `sessions`/`csrf`: it lets the
/// chain run, then tries to write a header afterward, swallowing failure
/// the way `csrf.issue` swallows `addSetCookie`'s error with `catch {}`.
/// Registered *before* `throttle` in the chain, so it wraps it — its own
/// `next.run` call is what runs `throttle`'s `middlewareRun`, `shed`'s 503
/// short-circuit included.
fn mwOuterCookie(_: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    try next.run(ctx);
    ctx.res.addSetCookie("session=abc") catch {};
}

test "shed: an OUTER middleware writing after next.run still lands its header" {
    // Before this task, `shed` forced an early `end()`, so an outer
    // middleware working after `next.run` — exactly `sessions` (save/
    // destroy) and `csrf` (issue) — would have this call return
    // `error.HeadersSent`, swallowed silently by the `catch {}` both use.
    // This is the throttle analogue of the defect `6ba5d7d` found and
    // fixed for `ratelimit`'s 429, and of `cors`'s preflight anchor.
    var th: Throttle = .init(.{ .max_in_flight = 1 });
    defer th.deinit();

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(.{ .run = mwOuterCookie });
    try r.use(th.middleware());
    try r.get("/t", hCount);

    try testing.expect(th.tryAcquire()); // occupy the only slot so shed() runs

    var buf: [1024]u8 = undefined;
    const got = runWire(&r, wire("/t"), &buf);
    try expectStatus(got, "503");
    try expectHeaderLine(got, "Set-Cookie: session=abc");

    th.release(); // balance the manual tryAcquire above
}

/// Dispatch through a frame that is then abandoned — see the test below.
/// `noinline` so `shed`'s `retry_buf` really lives in the frame the clobber
/// reuses.
noinline fn dispatchInDoomedFrame(
    r: *router.Router,
    req: *http.Server.Request,
    rw: *http.Server.ResponseWriter,
) anyerror!void {
    return r.dispatch(req, rw);
}

/// Reuse it, bigger than the 24-byte `retry_buf` the `Retry-After` value
/// used to point at.
noinline fn clobberDoomedFrame() void {
    var scratch: [8192]u8 = undefined;
    @memset(&scratch, '#');
    std.mem.doNotOptimizeAway(&scratch);
}

test "shed: the Retry-After value outlives the frame it was formatted in" {
    // `shed` used to force an early `end()` because its `Retry-After` value
    // pointed into its own stack frame; `http`'s `setHeader` copies the
    // bytes now, so the head is left to the serving loop. That makes this
    // dependent on the copy — and `runWire` cannot see it, because the loop
    // offers no seam between the handler returning and `end()` in which to
    // reuse the dead frame. So the request and the writer are built by hand
    // here and the two are driven in the loop's own order, with the
    // scribble in between.
    var th: Throttle = .init(.{ .max_in_flight = 1 });
    defer th.deinit();
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(th.middleware());
    try r.get("/t", hCount);

    try testing.expect(th.tryAcquire()); // occupy the only slot so shed() runs

    var in: Reader = .fixed("GET /t HTTP/1.1\r\nHost: t\r\n\r\n");
    var head_buf: [512]u8 = undefined;
    const head = try http.h1.RequestHead.parse(try http.h1.readHead(&in, &head_buf));
    var body_scratch: [64]u8 = undefined;
    var body: http.Server.RequestBody = .init(&head, &in, &body_scratch);
    var req: http.Server.Request = .{
        .method = .get,
        .target = head.target,
        .path = head.target,
        .query = "",
        .head = head,
        .body = &body,
        .context = null,
    };

    var out_buf: [1024]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var response_body_buf: [256]u8 = undefined;
    var chunk_buf: [64]u8 = undefined;
    var rw: http.Server.ResponseWriter = .init(&out, &response_body_buf, &chunk_buf, .{});

    try dispatchInDoomedFrame(&r, &req, &rw);
    clobberDoomedFrame();
    try rw.end();

    const got = out.buffered();
    try expectStatus(got, "503");
    try expectHeaderLine(got, "Retry-After: 1");
    try testing.expect(std.mem.find(u8, got, "#") == null);
    th.release(); // balance the manual tryAcquire above
}

test "middleware: the slot is released even when the handler errors" {
    var th: Throttle = .init(.{ .max_in_flight = 1 });
    defer th.deinit();

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(th.middleware());
    try r.get("/boom", hBoom);

    var buf: [1024]u8 = undefined;
    // The handler error becomes the server's 500; the defer still ran.
    try expectStatus(runWire(&r, wire("/boom"), &buf), "500");
    try testing.expectEqual(0, th.inFlight());
    // And the throttle still works.
    try testing.expect(th.tryAcquire());
    th.release();
}

test "middleware: 404/405 traffic is throttled too (router-level chain)" {
    var th: Throttle = .init(.{ .max_in_flight = 1 });
    defer th.deinit();

    var hits: u32 = 0;
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &hits;
    try r.use(th.middleware());
    try r.get("/t", hCount);

    var buf: [1024]u8 = undefined;
    try expectStatus(runWire(&r, wire("/nope"), &buf), "404"); // free → 404
    try testing.expect(th.tryAcquire());
    try expectStatus(runWire(&r, wire("/nope"), &buf), "503"); // full → shed
    th.release();
}

test "middleware: retry_after_ms is rounded up to whole seconds" {
    var th: Throttle = .init(.{ .max_in_flight = 1, .retry_after_ms = 2_500 });
    defer th.deinit();

    var hits: u32 = 0;
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &hits;
    try r.use(th.middleware());
    try r.get("/t", hCount);

    try testing.expect(th.tryAcquire());
    var buf: [1024]u8 = undefined;
    const got = runWire(&r, wire("/t"), &buf);
    try expectStatus(got, "503");
    try expectHeaderLine(got, "Retry-After: 3"); // ceil(2500 ms)
    th.release();
}

test "middleware: bounded wait serves the request once a slot frees (no 503)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var th: Throttle = .init(.{
        .max_in_flight = 1,
        .max_wait_ms = 30_000, // success must come from the release, not luck
        .io = io,
    });
    defer th.deinit();

    var hits: u32 = 0;
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &hits;
    try r.use(th.middleware());
    try r.get("/t", hCount);

    try testing.expect(th.tryAcquire()); // saturate
    const Releaser = struct {
        fn run(t: *Throttle, io_: std.Io) void {
            sleepMs(io_, 20) catch {};
            t.release();
        }
    };
    const releaser = try std.Thread.spawn(.{}, Releaser.run, .{ &th, io });
    defer releaser.join();

    var buf: [1024]u8 = undefined;
    // Blocks in the middleware's bounded wait until the release, then 200.
    try expectStatus(runWire(&r, wire("/t"), &buf), "200");
    try testing.expectEqual(1, hits);
    try testing.expectEqual(0, th.inFlight());
}

test "middleware: bounded wait sheds with 503 once the deadline passes" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var th: Throttle = .init(.{
        .max_in_flight = 1,
        .max_wait_ms = 50,
        .io = threaded.io(),
    });
    defer th.deinit();

    var hits: u32 = 0;
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &hits;
    try r.use(th.middleware());
    try r.get("/t", hCount);

    try testing.expect(th.tryAcquire()); // saturated for good
    var buf: [1024]u8 = undefined;
    const got = runWire(&r, wire("/t"), &buf);
    try expectStatus(got, "503");
    try expectHeaderLine(got, "Retry-After: 1");
    try testing.expectEqual(0, hits);
    try testing.expectEqual(0, th.waiting());
    th.release();
}

// ── tests: in-process integration (router + http.Server + http.Client) ──────

fn serveWrap(s: *http.Server) void {
    s.serve() catch {};
}

/// Caller-controlled signal the blocking handler parks on: each ticket lets
/// exactly one handler finish.
const Gate = struct {
    io: std.Io,
    entered: std.atomic.Value(u32) = .init(0),
    tickets: std.atomic.Value(u32) = .init(0),

    fn takeTicket(g: *Gate) bool {
        var cur = g.tickets.load(.seq_cst);
        while (cur > 0) {
            cur = g.tickets.cmpxchgWeak(cur, cur - 1, .seq_cst, .seq_cst) orelse return true;
        }
        return false;
    }
};

fn hGateBlock(ctx: *router.Ctx) anyerror!void {
    const g: *Gate = @ptrCast(@alignCast(ctx.state.?));
    _ = g.entered.fetchAdd(1, .seq_cst);
    var tries: u32 = 0;
    while (!g.takeTicket()) : (tries += 1) {
        if (tries > 30_000) return error.TestGateTimeout; // ≈ 30 s safety net
        try sleepMs(g.io, 1);
    }
    try ctx.res.writeAll("done");
}

fn hPing(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll("pong");
}

/// One worker = one live client request that occupies a slot until the gate
/// hands it a ticket. Reports the response status (999/998 = transport
/// failure).
fn blockWorker(io: std.Io, port: u16, status_out: *std.atomic.Value(u16)) void {
    var client = http.Client.init(io, testing.allocator, .{});
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url = std.mem.print(&url_buf, "http://127.0.0.1:{d}/block", .{port}) catch unreachable;
    var res = client.request(.get, url, .{}) catch {
        status_out.store(999, .seq_cst);
        return;
    };
    defer res.deinit();
    const body = res.readAllAlloc(testing.allocator, 1024) catch {
        status_out.store(998, .seq_cst);
        return;
    };
    testing.allocator.free(body);
    status_out.store(res.status, .seq_cst);
}

test "integration: N slots occupied → 503 + Retry-After; a freed slot serves again" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var th: Throttle = .init(.{ .max_in_flight = 2 });
    defer th.deinit();
    var gate: Gate = .{ .io = io };

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &gate;
    try r.use(th.middleware());
    try r.get("/block", hGateBlock);
    try r.get("/ping", hPing);

    var server = http.Server.init(io, testing.allocator, .{
        .handler = r.handler(),
        .context = &r,
    });
    defer server.deinit();
    server.bind() catch |err| {
        return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    };
    const thread = try std.Thread.spawn(.{}, serveWrap, .{&server});
    defer thread.join();
    defer server.shutdown();
    const port = server.boundAddress().getPort();

    // Two live requests occupy both slots (their handlers park on the gate).
    var s1: std.atomic.Value(u16) = .init(0);
    var s2: std.atomic.Value(u16) = .init(0);
    const w1 = try std.Thread.spawn(.{}, blockWorker, .{ io, port, &s1 });
    defer w1.join();
    const w2 = try std.Thread.spawn(.{}, blockWorker, .{ io, port, &s2 });
    defer w2.join();
    // Runs before the joins above (LIFO): whatever happens, unblock every
    // parked handler so the test never hangs on a failed expectation.
    defer gate.tickets.store(1_000_000, .seq_cst);

    var tries: usize = 0;
    while (gate.entered.load(.seq_cst) != 2) : (tries += 1) {
        if (tries > 1000) return error.TestTimeout;
        try sleepMs(io, 10);
    }
    try testing.expectEqual(2, th.inFlight()); // both slots held

    var client = http.Client.init(io, testing.allocator, .{});
    defer client.deinit();
    var url_buf: [64]u8 = undefined;

    { // request N+1 → shed: 503 with a usable Retry-After, nothing queued
        const url = try std.mem.print(&url_buf, "http://127.0.0.1:{d}/ping", .{port});
        var res = try client.request(.get, url, .{});
        defer res.deinit();
        try testing.expectEqual(503, res.status);
        try testing.expectEqualStrings("1", res.header("retry-after").?);
        const body = try res.readAllAlloc(testing.allocator, 1024);
        defer testing.allocator.free(body);
        try testing.expectEqualStrings("Service Unavailable\n", body);
    }
    try testing.expectEqual(2, th.inFlight()); // the shed borrowed no slot

    // Release the signal for exactly one handler → one slot frees.
    _ = gate.tickets.fetchAdd(1, .seq_cst);
    tries = 0;
    while (th.inFlight() != 1) : (tries += 1) {
        if (tries > 1000) return error.TestTimeout;
        try sleepMs(io, 10);
    }

    { // a fresh request now succeeds in the freed slot
        const url = try std.mem.print(&url_buf, "http://127.0.0.1:{d}/ping", .{port});
        var res = try client.request(.get, url, .{});
        defer res.deinit();
        try testing.expectEqual(200, res.status);
        const body = try res.readAllAlloc(testing.allocator, 1024);
        defer testing.allocator.free(body);
        try testing.expectEqualStrings("pong", body);
    }

    // Let the second handler finish; everything drains to zero.
    _ = gate.tickets.fetchAdd(1, .seq_cst);
    tries = 0;
    while (th.inFlight() != 0) : (tries += 1) {
        if (tries > 1000) return error.TestTimeout;
        try sleepMs(io, 10);
    }
    tries = 0;
    while (s1.load(.seq_cst) == 0 or s2.load(.seq_cst) == 0) : (tries += 1) {
        if (tries > 1000) return error.TestTimeout;
        try sleepMs(io, 10);
    }
    try testing.expectEqual(200, s1.load(.seq_cst)); // both blocked requests completed fine
    try testing.expectEqual(200, s2.load(.seq_cst));
}

test "acquire sheds instead of unwrapping a null io when the precondition is violated" {
    // `init`'s `io != null` check is a Debug-only assert, so ReleaseFast
    // reached `.?` on a null optional -- illegal behaviour rather than a
    // panic. Shedding matches what `release` already does for its own
    // violated precondition.
    var t: Throttle = .{ .options = .{ .max_in_flight = 1, .max_wait_ms = 50, .io = null } };
    try testing.expect(t.acquire()); // the free slot still goes through tryAcquire
    try testing.expect(!t.acquire()); // full + no io → shed, not a wild read
    t.release();
}

// ── tests: mutation-run additions (2026-10-04) ──────────────────────────────

/// Scripted clock: every reading advances by `step_ns`; an optional hook runs
/// on one chosen reading. Lets a test pin exactly which `Clock.now` call
/// `acquire` makes where, without any real waiting for the deadline logic.
const FakeClock = struct {
    t: u64 = 0,
    step_ns: u64,
    calls: u32 = 0,
    release_on_call: u32 = 0,
    th: ?*Throttle = null,

    fn now(ctx: ?*anyopaque) u64 {
        const c: *FakeClock = @ptrCast(@alignCast(ctx.?));
        const reading = c.t;
        c.t += c.step_ns;
        c.calls += 1;
        if (c.calls == c.release_on_call) c.th.?.release();
        return reading;
    }

    fn clock(c: *FakeClock) Clock {
        return .{ .ctx = c, .nowFn = now };
    }
};

test "bounded wait: deadline is the first clock reading plus max_wait_ms, reached with >=" {
    // WHY these numbers (derived from the documented rule "wait up to
    // max_wait_ms", not from observed output): `acquire` reads the clock once
    // to set the deadline, then once per loop turn. With readings 0, 50, 100
    // ms and max_wait_ms = 100 the deadline is 100 ms; the third reading is
    // exactly at the deadline, so the wait is over (a wait that has used its
    // whole budget must not start another) -> 3 readings. A step of 30 ms
    // gives readings 0, 30, 60, 90, 120: the first at/after the deadline is
    // the fifth -> 5 readings. Fewer readings = shed too early, more = waited
    // past the budget. A clock that is ignored (the real one used instead)
    // would not produce these counts at all.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const cases = [_]struct { step_ms: u64, readings: u32 }{
        .{ .step_ms = 50, .readings = 3 },
        .{ .step_ms = 30, .readings = 5 },
    };
    for (cases) |cs| {
        var fc: FakeClock = .{ .step_ns = cs.step_ms * std.time.ns_per_ms };
        var th: Throttle = .init(.{
            .max_in_flight = 1,
            .max_wait_ms = 100,
            .io = threaded.io(),
            .clock = fc.clock(),
        });
        try testing.expect(th.tryAcquire()); // saturate
        try testing.expect(!th.acquire());
        try testing.expectEqual(cs.readings, fc.calls);
        try testing.expectEqual(0, th.waiting());
        th.release();
        th.deinit();
    }
}

test "bounded wait: a release between the failed attempt and the futex wait is not lost" {
    // The clock reading right after the failed `tryAcquire` runs inside the
    // window the generation counter exists for. The scripted clock performs
    // the release there (call 2 = first loop turn). `release` must bump the
    // generation so the futex wait on the stale snapshot returns at once and
    // the retry takes the slot. A lost wakeup would park until the 3 s
    // deadline instead (invariant: the "no lost wakeup" audit in `acquire`).
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var fc: FakeClock = .{ .step_ns = std.time.ns_per_ms, .release_on_call = 2 };
    var th: Throttle = .init(.{
        .max_in_flight = 1,
        .max_wait_ms = 3_000,
        .io = threaded.io(),
        .clock = fc.clock(),
    });
    fc.th = &th;
    try testing.expect(th.tryAcquire()); // saturate; the clock hook frees it
    const t0 = Clock.monotonic.now();
    try testing.expect(th.acquire());
    const elapsed_ms = (Clock.monotonic.now() - t0) / std.time.ns_per_ms;
    try testing.expect(elapsed_ms < 1_500); // promptly, not at the deadline
    try testing.expectEqual(1, th.inFlight());
    try testing.expectEqual(0, th.waiting());
    th.release();
    th.deinit();
}

fn acquireTask(t: *Throttle) bool {
    return t.acquire();
}

test "bounded wait: a canceled Io wait sheds at once instead of waiting out the deadline" {
    // Documented: "A canceled Io wait (server shutdown) also sheds."
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var th: Throttle = .init(.{ .max_in_flight = 1, .max_wait_ms = 20_000, .io = io });
    defer th.deinit();
    try testing.expect(th.tryAcquire()); // saturate

    var fut = try io.concurrent(acquireTask, .{&th});
    var tries: usize = 0;
    while (th.waiting() != 1) : (tries += 1) {
        if (tries > 1000) {
            _ = fut.cancel(io);
            return error.TestTimeout;
        }
        try sleepMs(io, 10);
    }
    const t0 = Clock.monotonic.now();
    const got = fut.cancel(io);
    const elapsed_ms = (Clock.monotonic.now() - t0) / std.time.ns_per_ms;
    try testing.expect(!got);
    try testing.expect(elapsed_ms < 5_000);
    try testing.expectEqual(0, th.waiting());
    try testing.expectEqual(1, th.inFlight()); // the saturating slot is untouched
    th.release();
}

test "middleware: Retry-After is ceil(ms / 1000) with a floor of 1 second" {
    // Documented: "rounded up to whole seconds, minimum 1". 0 ms and 1 ms
    // would be 0 s without the floor; 1000 is exact; 1001 rounds up to 2.
    const cases = [_]struct { ms: u64, line: []const u8 }{
        .{ .ms = 0, .line = "Retry-After: 1" },
        .{ .ms = 1, .line = "Retry-After: 1" },
        .{ .ms = 999, .line = "Retry-After: 1" },
        .{ .ms = 1_000, .line = "Retry-After: 1" },
        .{ .ms = 1_001, .line = "Retry-After: 2" },
        .{ .ms = 60_000, .line = "Retry-After: 60" },
    };
    for (cases) |cs| {
        var th: Throttle = .init(.{ .max_in_flight = 1, .retry_after_ms = cs.ms });
        var r = router.Router.init(testing.allocator);
        try r.use(th.middleware());
        try r.get("/t", hBoom);
        try testing.expect(th.tryAcquire());
        var buf: [1024]u8 = undefined;
        const got = runWire(&r, wire("/t"), &buf);
        try expectStatus(got, "503");
        const needle = try testing.allocator.print("\r\n{s}\r\n", .{cs.line});
        defer testing.allocator.free(needle);
        try testing.expect(std.mem.find(u8, got, needle) != null);
        th.release();
        r.deinit();
        th.deinit();
    }
}

test "Clock.monotonic keeps sub-second resolution and advances across a sleep" {
    // A 20 ms sleep must advance a monotonic clock by at least 20 ms and, with
    // generous scheduler slack, well under a second. A reading that dropped
    // the nanosecond part would advance by 0 or by a whole second.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const a = Clock.monotonic.now();
    try sleepMs(threaded.io(), 20);
    const b = Clock.monotonic.now();
    try testing.expect(b >= a + 20 * std.time.ns_per_ms);
    try testing.expect(b - a < 900 * std.time.ns_per_ms);
}

// ── tests: partitioned limiter ──────────────────────────────────────────────

test "Partitioned.init: refuses bad shares with errors, never panics" {
    try testing.expectError(error.ZeroLimit, Partitioned.init(.{ .max_in_flight = 0, .shares_percent = &.{50} }));
    try testing.expectError(error.NoPartitions, Partitioned.init(.{ .max_in_flight = 10, .shares_percent = &.{} }));
    try testing.expectError(error.SharesExceed100, Partitioned.init(.{ .max_in_flight = 10, .shares_percent = &.{ 60, 41 } }));
    try testing.expectError(error.SharesExceed100, Partitioned.init(.{ .max_in_flight = 10, .shares_percent = &.{ 255, 255 } }));
    const many: [max_partitions + 1]u8 = @splat(1);
    try testing.expectError(error.TooManyPartitions, Partitioned.init(.{ .max_in_flight = 10, .shares_percent = &many }));
    const full: [max_partitions]u8 = @splat(1);
    var ok = try Partitioned.init(.{ .max_in_flight = 100, .shares_percent = &full });
    defer ok.deinit();
    var exact = try Partitioned.init(.{ .max_in_flight = 10, .shares_percent = &.{ 60, 40 } });
    defer exact.deinit();
    try testing.expectEqual(@as(u32, 6), exact.guaranteed(0));
    try testing.expectEqual(@as(u32, 4), exact.guaranteed(1));
    try testing.expectEqual(@as(u32, 0), exact.guaranteed(2));
}

test "Partitioned: a flood in one partition cannot starve another's guaranteed share" {
    var p = try Partitioned.init(.{ .max_in_flight = 10, .shares_percent = &.{ 50, 30 } });
    defer p.deinit();
    // Flood A: borrows the whole budget (5 guaranteed + 5 borrowed).
    var a: usize = 0;
    while (p.tryAcquire(0)) a += 1;
    try testing.expectEqual(@as(usize, 10), a);
    try testing.expect(!p.tryAcquire(0));
    // B still gets exactly its guarantee, though the budget is full.
    var b: usize = 0;
    while (p.tryAcquire(1)) b += 1;
    try testing.expectEqual(@as(usize, 3), b);
    try testing.expectEqual(@as(usize, 13), p.inFlight());
    // Past its share B may only borrow, and the budget is still over-full.
    p.release(0);
    try testing.expect(!p.tryAcquire(1)); // total 12 >= 10
    for (0..3) |_| p.release(0);
    try testing.expect(p.tryAcquire(1)); // total 9 < 10: the borrow succeeds
    try testing.expectEqual(@as(usize, 4), p.inFlightIn(1));
    while (p.inFlightIn(0) > 0) p.release(0);
    while (p.inFlightIn(1) > 0) p.release(1);
}

test "Partitioned: borrowing when the other partition is idle, then reclaiming" {
    var p = try Partitioned.init(.{ .max_in_flight = 10, .shares_percent = &.{ 50, 50 } });
    defer p.deinit();
    var a: usize = 0;
    while (p.tryAcquire(0)) a += 1;
    try testing.expectEqual(@as(usize, 10), a); // 5 own + 5 borrowed from idle B
    try testing.expectEqual(@as(usize, 10), p.inFlightIn(0));
    // B's guaranteed requests are admitted at once although the budget is full.
    for (0..5) |_| try testing.expect(p.tryAcquire(1));
    try testing.expect(!p.tryAcquire(1));
    // Drain everything: counters return to zero.
    for (0..10) |_| p.release(0);
    for (0..5) |_| p.release(1);
    try testing.expectEqual(@as(usize, 0), p.inFlight());
    try testing.expectEqual(@as(usize, 0), p.inFlightIn(0));
    try testing.expectEqual(@as(usize, 0), p.inFlightIn(1));
}

test "Partitioned: release accounting, bad index, unassigned share is borrowable" {
    var p = try Partitioned.init(.{ .max_in_flight = 10, .shares_percent = &.{ 20, 20 } });
    defer p.deinit();
    try testing.expect(!p.tryAcquire(2)); // out of range: shed, nothing consumed
    p.release(2); // out of range: no-op
    try testing.expectEqual(@as(usize, 0), p.inFlight());
    try testing.expectEqual(@as(usize, 0), p.inFlightIn(7));
    // 60 % unassigned: partition 0 can reach 10 only by borrowing.
    for (0..10) |_| try testing.expect(p.tryAcquire(0));
    try testing.expectEqual(@as(usize, 10), p.inFlightIn(0));
    p.release(0);
    try testing.expectEqual(@as(usize, 9), p.inFlight());
    try testing.expectEqual(@as(usize, 9), p.inFlightIn(0));
    // Freed room is borrowable by the other partition once its guarantee is used up.
    try testing.expect(p.tryAcquire(1));
    try testing.expectEqual(@as(usize, 10), p.inFlight());
    for (0..9) |_| p.release(0);
    p.release(1);
    try testing.expectEqual(@as(usize, 0), p.inFlight());
}

test "Partitioned: a zero-share partition only borrows" {
    var p = try Partitioned.init(.{ .max_in_flight = 4, .shares_percent = &.{ 100, 0 } });
    defer p.deinit();
    for (0..4) |_| try testing.expect(p.tryAcquire(0));
    try testing.expect(!p.tryAcquire(1)); // no guarantee, no room
    p.release(0);
    try testing.expect(p.tryAcquire(1)); // borrows the freed slot
    p.release(1);
    for (0..3) |_| p.release(0);
}

fn classifyByPath(ctx: *router.Ctx) usize {
    return if (std.mem.eql(u8, ctx.req.path, "/health")) 1 else 0;
}

test "Partitioned.middleware: classify picks the partition, 503 when its partition is out of budget" {
    var p = try Partitioned.init(.{
        .max_in_flight = 2,
        .shares_percent = &.{ 50, 50 },
        .classify = classifyByPath,
    });
    defer p.deinit();
    var hits: u32 = 0;
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &hits;
    try r.use(p.middleware());
    try r.get("/t", hCount);
    try r.get("/health", hCount);

    var buf: [1024]u8 = undefined;
    // Partition 0 saturated (borrowing the whole budget).
    try testing.expect(p.tryAcquire(0));
    try testing.expect(p.tryAcquire(0));
    try expectStatus(runWire(&r, wire("/t"), &buf), "503");
    try expectHeaderLine(runWire(&r, wire("/t"), &buf), "Retry-After: 1");
    try testing.expectEqual(0, hits);
    // Partition 1 is still served from its guarantee, and the slot comes back.
    try expectStatus(runWire(&r, wire("/health"), &buf), "200");
    try testing.expectEqual(1, hits);
    try testing.expectEqual(2, p.inFlight());
    p.release(0);
    p.release(0);
    try expectStatus(runWire(&r, wire("/t"), &buf), "200");
    try testing.expectEqual(0, p.inFlight());
}

test "Partitioned: 8 threads never lose accounting and guaranteed share holds" {
    var p = try Partitioned.init(.{ .max_in_flight = 8, .shares_percent = &.{ 50, 25 } });
    defer p.deinit();
    const W = struct {
        fn run(pp: *Partitioned, part: usize) void {
            for (0..20_000) |_| {
                if (pp.tryAcquire(part)) pp.release(part);
            }
        }
    };
    var ts: [8]std.Thread = undefined;
    for (&ts, 0..) |*t, i| t.* = std.Thread.spawn(.{}, W.run, .{ &p, i % 2 }) catch return error.SkipZigTest;
    for (ts) |t| t.join();
    try testing.expectEqual(@as(usize, 0), p.inFlight());
    try testing.expectEqual(@as(usize, 0), p.inFlightIn(0));
    try testing.expectEqual(@as(usize, 0), p.inFlightIn(1));
}

// ── adaptive limit ──────────────────────────────────────────────────────────

test "adaptive: off by default, limit() is max_in_flight and tryAcquire is unchanged" {
    var th: Throttle = .init(.{ .max_in_flight = 3 });
    try testing.expectEqual(@as(u32, 3), th.limit());
    const p = th.acquirePermit().?; // no clock read, no sample
    try testing.expectEqual(@as(u64, 0), p.start_ns);
    th.releasePermit(p, .success);
    try testing.expectEqual(@as(u32, 3), th.limit());
    th.deinit();
}

test "adaptive aimd: +1 while half the limit is in use, x0.9 (floored) on a drop or a timeout, clamped" {
    var th: Throttle = .init(.{ .max_in_flight = 30, .adaptive = .{ .algorithm = .aimd, .initial_limit = 20, .min_limit = 10 } });
    try testing.expectEqual(@as(u32, 20), th.limit());
    th.sample(1_000, 5, false); // 5 * 2 < 20: under-used, no growth
    try testing.expectEqual(@as(u32, 20), th.limit());
    th.sample(1_000, 10, false); // 10 * 2 >= 20
    try testing.expectEqual(@as(u32, 21), th.limit());
    th.sample(1_000, 21, true); // drop: floor(21 * 0.9) = 18
    try testing.expectEqual(@as(u32, 18), th.limit());
    th.sample(6 * std.time.ns_per_s, 1, false); // past the 5 s timeout: floor(18 * 0.9) = 16
    try testing.expectEqual(@as(u32, 16), th.limit());
    for (0..40) |_| th.sample(1_000, 100, true); // never below min_limit
    try testing.expectEqual(@as(u32, 10), th.limit());
    for (0..100) |_| th.sample(1_000, 100, false); // never above the ceiling
    try testing.expectEqual(@as(u32, 30), th.limit());
    th.deinit();
}

test "adaptive gradient2: grows while latency is flat, shrinks when it rises, ignores drops and an idle app" {
    var th: Throttle = .init(.{ .max_in_flight = 200, .adaptive = .{ .initial_limit = 50, .min_limit = 5 } });
    const ms = std.time.ns_per_ms;
    // Flat 10 ms: gradient 1, the limit grows by about queue_size * smoothing = 0.8 a sample.
    for (0..60) |_| th.sample(10 * ms, th.limit(), false);
    const grown = th.limit();
    try testing.expect(grown > 90 and grown <= 200);
    // An idle application (in flight < limit / 2) neither grows nor shrinks it.
    th.sample(10 * ms, 1, false);
    th.sample(500 * ms, 1, false);
    try testing.expectEqual(grown, th.limit());
    // A drop is not a gradient2 signal.
    th.sample(10 * ms, grown, true);
    try testing.expectEqual(grown, th.limit());
    // The RTT jumps to 5x the long-term value: gradient 0.5, est * 0.9 + 0.8 a sample, towards min_limit.
    for (0..80) |_| th.sample(50 * ms, th.limit(), false);
    try testing.expect(th.limit() < grown / 2);
    try testing.expect(th.limit() >= 5);
    th.deinit();
}

test "adaptive: tryAcquire admits at most the discovered limit, never above the ceiling" {
    var th: Throttle = .init(.{ .max_in_flight = 4, .adaptive = .{ .algorithm = .aimd, .initial_limit = 2, .min_limit = 1 } });
    try testing.expect(th.tryAcquire());
    try testing.expect(th.tryAcquire());
    try testing.expect(!th.tryAcquire()); // limit 2, ceiling 4
    th.sample(1_000, 2, false); // grows to 3
    try testing.expect(th.tryAcquire());
    try testing.expect(!th.tryAcquire());
    for (0..5) |_| th.sample(1_000, 3, false);
    try testing.expectEqual(@as(u32, 4), th.limit());
    try testing.expect(th.tryAcquire());
    try testing.expect(!th.tryAcquire());
    for (0..4) |_| th.release();
    th.deinit();
}

test "adaptive: a permit measures with the injected clock, an ignored outcome is no sample" {
    var mc = clock_lib.ManualClock.init(1_000);
    var th: Throttle = .init(.{
        .max_in_flight = 30,
        .clock = mc.clock(),
        .adaptive = .{ .algorithm = .aimd, .initial_limit = 20, .min_limit = 10, .timeout_ms = 100 },
    });
    const slow = th.acquirePermit().?;
    try testing.expectEqual(@as(u32, 1), slow.in_flight);
    mc.advance(200 * std.time.ns_per_ms); // past the 100 ms timeout
    th.releasePermit(slow, .success);
    try testing.expectEqual(@as(u32, 18), th.limit());
    const skipped = th.acquirePermit().?;
    mc.advance(200 * std.time.ns_per_ms);
    th.releasePermit(skipped, .ignore);
    try testing.expectEqual(@as(u32, 18), th.limit());
    try testing.expectEqual(@as(usize, 0), th.inFlight());
    th.deinit();
}

test "adaptive: a ceiling below the default minimum pins the limit there" {
    var th: Throttle = .init(.{ .max_in_flight = 5, .adaptive = .{} });
    try testing.expectEqual(@as(u32, 5), th.limit());
    for (0..20) |_| th.sample(1_000, 5, false);
    th.sample(5 * std.time.ns_per_s, 5, false);
    try testing.expectEqual(@as(u32, 5), th.limit());
    th.deinit();
}

test "adaptive middleware: a served request is a sample, a handler error is not, the 503 path is unchanged" {
    var mc = clock_lib.ManualClock.init(1_000);
    var th: Throttle = .init(.{
        .max_in_flight = 10,
        .clock = mc.clock(),
        .adaptive = .{ .algorithm = .aimd, .initial_limit = 2, .min_limit = 1 },
    });
    defer th.deinit();
    var hits: u32 = 0;
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &hits;
    try r.use(th.middleware());
    try r.get("/t", hCount);
    try r.get("/boom", hBoom);

    var buf: [1024]u8 = undefined;
    // One request alone: in flight 1, 1 * 2 >= 2, so the limit grows to 3.
    try expectStatus(runWire(&r, wire("/t"), &buf), "200");
    try testing.expectEqual(@as(u32, 3), th.limit());
    try testing.expectEqual(0, th.inFlight());
    // An erroring handler (the server's 500) is not a sample: the limit stays.
    try expectStatus(runWire(&r, wire("/boom"), &buf), "500");
    try testing.expectEqual(@as(u32, 3), th.limit());
    try testing.expectEqual(0, th.inFlight());
    // At the discovered limit the request is shed with the usual 503.
    for (0..3) |_| try testing.expect(th.tryAcquire());
    try expectStatus(runWire(&r, wire("/t"), &buf), "503");
    for (0..3) |_| th.release();
}
