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
//!   fast rejection. TODO: the adaptive variant (Netflix Gradient-style
//!   AIMD on observed latency, discovering the limit instead of a static
//!   number) — the static `max_in_flight` is the required primary.
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
const router = @import("router");
const http = @import("http");

pub const meta = .{
    .platform = .posix, // default clock uses the posix clock_gettime errno form
    .role = .util,
    // Internally synchronized with atomics only (documented seq_cst policy);
    // all calls may race across the accept loop and every connection task.
    .concurrency = .threadsafe,
    .model_after = "Go golang.org/x/sync/semaphore (slot semantics) + SEDA / Netflix concurrency-limits (bounded queue, load shedding)",
    .deps = .{ "router", "http" },
};

// ── clock injection ─────────────────────────────────────────────────────────

/// Monotonic time source, injected so the bounded-wait deadline is testable.
/// Implementations must be non-decreasing; the absolute origin is irrelevant
/// (only differences are used). Only consulted when `max_wait_ms > 0`.
pub const Clock = struct {
    ctx: ?*anyopaque = null,
    nowFn: *const fn (?*anyopaque) u64,

    /// The OS monotonic clock (CLOCK_MONOTONIC via the posix `clock_gettime`
    /// errno form) — the production default, and the only place in the
    /// module that touches a real clock.
    pub const monotonic: Clock = .{ .nowFn = monotonicNowNs };

    pub fn now(c: Clock) u64 {
        return c.nowFn(c.ctx);
    }
};

fn monotonicNowNs(_: ?*anyopaque) u64 {
    var ts: std.posix.timespec = undefined;
    if (std.posix.errno(std.posix.system.clock_gettime(.MONOTONIC, &ts)) != .SUCCESS)
        return 0;
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

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
    /// tests. Never consulted when `max_wait_ms = 0`.
    clock: Clock = .monotonic,
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

    pub fn init(options: Options) Throttle {
        std.debug.assert(options.max_in_flight >= 1);
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
            if (cur >= t.options.max_in_flight) return false;
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
        const io = t.options.io.?; // asserted at init

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

    /// The configured hard cap (denominator for utilization metrics).
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
    if (!t.acquire()) return shed(t, ctx);
    defer t.release();
    return next.run(ctx);
}

/// The 503 path, mirroring ratelimit's 429: the `Retry-After` value is
/// formatted on this stack frame, so the head must reach the wire before the
/// frame unwinds — `end()` is idempotent and the serving loop's own
/// end()+flush still run.
fn shed(t: *Throttle, ctx: *router.Ctx) anyerror!void {
    var retry_buf: [24]u8 = undefined;
    const retry_s = @max(1, std.math.divCeil(u64, t.options.retry_after_ms, std.time.ms_per_s) catch unreachable);
    ctx.res.setStatus(503);
    try ctx.res.setHeader("Retry-After", std.fmt.bufPrint(&retry_buf, "{d}", .{retry_s}) catch unreachable);
    try ctx.res.setHeader("Content-Type", "text/plain");
    try ctx.res.writeAll("Service Unavailable\n");
    try ctx.res.end();
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
    try testing.expect(std.mem.indexOf(u8, got, "\r\n" ++ line ++ "\r\n") != null);
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
    const url = std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/block", .{port}) catch unreachable;
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
        std.debug.print("loopback bind failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
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
        const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/ping", .{port});
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
        const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/ping", .{port});
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
