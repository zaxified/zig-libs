// SPDX-License-Identifier: MIT

//! resilience — client-side fault tolerance for calling flaky upstreams:
//! **circuit breaker + retry-with-backoff + timeout**, generic over any
//! fallible operation. std-only — it wraps an arbitrary operation; the
//! caller composes it with `http.Client` (or anything else that can fail).
//!
//! Layers (each usable on its own):
//! - `CircuitBreaker` — `closed → open → half_open`; trips open after
//!   `failure_threshold` **consecutive** failures (Polly's classic breaker).
//!   `RateCircuitBreaker(n)` — the same machine tripping on the failure rate
//!   (and slow-call rate) over the last `n` calls or `n` time buckets
//!   (resilience4j's default). While open, `allow()` fast-fails until
//!   `cooldown_ms` elapses; then `half_open` admits up to `half_open_probes`
//!   probe calls, of which `half_open_required_successes` (default all) close
//!   it. `forceOpen`/`disable`/`reset`, a state-change listener, `counts()`.
//!   Thread-safe (documented spinlock). Time via an injected `Clock`.
//! - `Retry` — pure backoff policy: `max_attempts`, exponential delay
//!   (`base_delay_ms × factor^(attempt-1)`, capped at `max_delay_ms`),
//!   jitter (**full jitter** is the recommended flavor — AWS "Exponential
//!   Backoff And Jitter"; `equal` and `none` also available), and a
//!   `retryable(err)` predicate. `nextDelay()` is a pure function — the
//!   caller (or `run`) does the waiting via an injected `Delay`.
//! - `Bulkhead` — bounded concurrent execution (resilience4j's semaphore
//!   bulkhead): at most `max_concurrent` calls in flight at once. When
//!   full, `acquire()` fails fast with `error.BulkheadFull`; with
//!   `max_wait_ns > 0` it instead waits up to that budget for a slot
//!   (a poll over the injected `Clock`/`Delay` — see the type doc).
//!   `Bulkhead.run(op)` wraps acquire → call → release (the slot is
//!   returned on the error path too).
//! - `Deadline` — a cooperative time budget (`expired()`/`remainingMs()`)
//!   the operation can check or map onto its own I/O timeouts.
//! - `run(op, policy)` — one-call composition: bulkhead → breaker → retry →
//!   timeout around a generic operation (see "Composition" below), with
//!   error classification, retry on a result, a server-suggested delay and
//!   an `on_retry` listener.
//!
//! ## The operation
//!
//! An operation is any value with a `call()` method returning an error
//! union: `pub fn call(self: *Self) E!T`. Pass `&op` when `call` mutates
//! state. A bare "fn ptr + ctx" pair is the same thing spelled as a
//! two-field struct — or use the `operation(ctx, f)` adapter. Example,
//! wrapping this collection's `http.Client` (illustrative only — this
//! module has NO http dependency):
//!
//! ```zig
//! const Fetch = struct {
//!     client: *http.Client,
//!     url: []const u8,
//!     pub fn call(self: *Fetch) !u16 {
//!         var res = try self.client.request(.get, self.url, .{});
//!         defer res.deinit();
//!         if (res.status >= 500) return error.UpstreamDown; // count 5xx as failure
//!         return res.status;
//!     }
//! };
//!
//! var breaker: resilience.CircuitBreaker = .init(.{
//!     .failure_threshold = 5,
//!     .cooldown_ms = 30_000,
//! });
//! var prng = std.Random.DefaultPrng.init(seed);
//! var op: Fetch = .{ .client = &client, .url = "https://upstream/api" };
//! const status = try resilience.run(&op, .{
//!     .breaker = breaker.handle(),
//!     .retry = .{ .max_attempts = 3, .base_delay_ms = 100, .jitter = .full },
//!     .timeout_ms = 2_000,
//!     .random = prng.random(),
//! });
//! ```
//!
//! ## Composition (`run`) — ordering
//!
//! `bulkhead → breaker → retry → timeout`: a `Policy.bulkhead` slot is held
//! for the whole run (every attempt and wait); the rest applies **per
//! attempt**:
//!
//! 1. `breaker.allow()` gates *every* attempt (including the first) — an
//!    open breaker fast-fails the whole `run` with `error.CircuitOpen`,
//!    before any delay or call.
//! 2. Each admitted attempt is timeout-classified (below) and its outcome —
//!    success, error, or timeout — is recorded to the breaker.
//! 3. A failed attempt is retried while attempts remain and
//!    `retry.retryable(err)` says yes, sleeping `retry.nextDelay()` via the
//!    injected `Delay` in between.
//!
//! This is observably resilience4j's default decoration order
//! `Retry(CircuitBreaker(TimeLimiter(call)))` — there too the breaker
//! admits/records each attempt and `CallNotPermitted` aborts the retry
//! loop. One deliberate deviation: a breaker denial is **never** retried
//! within one `run` (resilience4j would retry it if the retry config is
//! permissive) — fast-fail is the point of an open breaker; call `run`
//! again later to probe after the cooldown.
//!
//! ## Timeout — what it can and cannot do (honesty note)
//!
//! `Policy.timeout_ms` bounds each attempt **observationally and
//! cooperatively** — it does NOT preempt the operation:
//! - *Observational:* the attempt is stopwatched with the injected clock;
//!   when `call()` comes back after the budget, its result — **even a
//!   success** — is discarded and classified `error.Timeout` (a too-late
//!   answer is a failure; it feeds the breaker and the retry decision, the
//!   spirit of resilience4j's TimeLimiter).
//! - *Cooperative:* if the operation type declares
//!   `pub fn setDeadline(self, d: Deadline) void`, `run` hands it the
//!   attempt's deadline before each call — map `remainingMs()` onto your
//!   own I/O timeouts (e.g. an http.Client connect/read timeout) or poll
//!   `expired()` in a loop.
//! - *It cannot interrupt anything.* A `call()` stuck in a blocking syscall
//!   blocks `run` past the timeout — same caveat as the repo's http
//!   connect-timeout. There is no thread/signal machinery here; if you need
//!   hard cancellation, run the operation somewhere preemptible and make
//!   `call()` await it with its own timeout.
//!
//! ## Thread-safety
//!
//! `CircuitBreaker` is internally synchronized — all methods may race from
//! any thread. The lock is a spinlock (`std.atomic.Mutex` + `spinLoopHint`,
//! the std SmpAllocator pattern — Zig 0.16 std has no io-less blocking
//! mutex); every critical section is a few branches on plain fields, no
//! allocation, no I/O. `Bulkhead` is lock-free (a CAS loop on one atomic
//! counter). `Retry` and `Deadline` are immutable values
//! (reentrant). `run` itself owns no shared state — concurrent `run`s may
//! share one `*CircuitBreaker` (that is the intended use) but each needs
//! its own operation value unless the operation synchronizes itself; an
//! injected `std.Random` is NOT thread-safe — give each thread its own.
//!
//! No allocation anywhere — there is no allocator to pass and nothing to
//! deinit. No hidden globals; every timed path is clock/delay-injected
//! (the only places touching the real OS are the `.monotonic` clock and the
//! `.blocking` delay defaults).

const std = @import("std");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Circuit breaker (consecutive or failure-rate window) + retry/backoff + timeout + bulkhead for calling upstreams (generic, zero-alloc)",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "posix",
    // Default Clock (posix clock_gettime errno form) and default Delay
    // (posix nanosleep) are posix; both are injectable, everything else is
    // pure logic.
    .targets = .{.linux64},
    .platform = .posix,
    .role = .util,
    // CircuitBreaker internally synchronized (documented spinlock);
    // Bulkhead is pure atomics; Retry/Deadline are immutable values.
    .concurrency = .threadsafe,
    .model_after = "resilience4j (composition + breaker states + semaphore Bulkhead) + Polly (consecutive-failure trip) + failsafe-go (delay shapes) + AWS full-jitter backoff",
    .deps = .{},
};

// ── clock injection ─────────────────────────────────────────────────────────

/// Monotonic time source, injected so every timed path is deterministic
/// under test. Implementations must be non-decreasing; the absolute origin
/// is irrelevant (only differences are used).
pub const Clock = struct {
    ctx: ?*anyopaque = null,
    nowFn: *const fn (?*anyopaque) u64,

    /// The OS monotonic clock (CLOCK_MONOTONIC via the posix
    /// `clock_gettime` errno form) — the production default, and one of
    /// only two places in the module that touch the real OS (the other is
    /// `Delay.blocking`).
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

// ── delay injection ─────────────────────────────────────────────────────────

/// How `run` waits between retry attempts, injected so tests never sleep
/// for real. Production default = `.blocking`; tests inject a recording
/// no-op.
pub const Delay = struct {
    ctx: ?*anyopaque = null,
    sleepFn: *const fn (?*anyopaque, u64) void,

    /// Actually blocks the calling thread (posix `nanosleep` in the same
    /// errno form as the clock, resumed on EINTR). The production default.
    pub const blocking: Delay = .{ .sleepFn = blockingSleepNs };

    /// Never waits. For tests, or when the caller schedules the wait itself
    /// (e.g. re-arms a timer with `Retry.nextDelay` instead of blocking).
    pub const none: Delay = .{ .sleepFn = noopSleepNs };

    pub fn sleep(d: Delay, ns: u64) void {
        d.sleepFn(d.ctx, ns);
    }
};

fn blockingSleepNs(_: ?*anyopaque, ns: u64) void {
    var req: std.posix.timespec = .{
        .sec = @intCast(ns / std.time.ns_per_s),
        .nsec = @intCast(ns % std.time.ns_per_s),
    };
    var rem: std.posix.timespec = undefined;
    while (std.posix.errno(std.posix.system.nanosleep(&req, &rem)) == .INTR) req = rem;
}

fn noopSleepNs(_: ?*anyopaque, _: u64) void {}

// ── circuit breaker ─────────────────────────────────────────────────────────

/// Breaker state as callers see it. `forceOpen()` reports `.open` and
/// `disable()` reports `.closed` (see `Mode`), so code that asks "is it
/// open?" keeps working whatever the mode.
pub const BreakerState = enum { closed, open, half_open };

/// How the breaker is being driven. `normal` is the state machine below;
/// `forced_open` (resilience4j FORCED_OPEN, failsafe-go `Open()`) refuses
/// every call until `reset()` — a latch that never thaws on a timer;
/// `disabled` (resilience4j DISABLED) admits every call and evaluates
/// nothing. Outcomes reported in either are counted in `counts()` only.
pub const Mode = enum { normal, forced_open, disabled };

/// What one call amounts to for the breaker (`record`). `ignore` is neither
/// a success nor a failure — an error that says nothing about the
/// upstream's health (a 404, a validation error): it releases a half-open
/// probe slot like `abandonProbe` and touches no window.
pub const Outcome = enum { success, failure, ignore };

/// Called on every state change, AFTER the breaker's lock is released, on
/// the thread whose call caused the change (gobreaker `OnStateChange`,
/// resilience4j's state-transition event). Two threads racing transitions
/// may deliver their calls in either order; `counts().transitions` is the
/// authoritative sequence count.
pub const StateListener = struct {
    ctx: ?*anyopaque = null,
    onStateChange: *const fn (ctx: ?*anyopaque, from: BreakerState, to: BreakerState) void,
};

/// A point-in-time snapshot (`counts()`), for metrics and dashboards.
pub const Counts = struct {
    state: BreakerState,
    mode: Mode,
    /// Lifetime totals of reported outcomes (every mode, every state).
    successes: u64 = 0,
    failures: u64 = 0,
    ignored: u64 = 0,
    /// Lifetime successes and failures slower than `slow_call_duration_ms`.
    slow: u64 = 0,
    /// Lifetime `allow()` refusals (open, forced open, probe slots full).
    not_permitted: u64 = 0,
    /// State changes since `init`.
    transitions: u64 = 0,
    /// Closed state, consecutive mode: the current failure streak.
    consecutive_failures: u32 = 0,
    /// Closed state, rate mode: calls / failures / slow calls in the
    /// current window (0 in consecutive mode).
    window_calls: u32 = 0,
    window_failures: u32 = 0,
    window_slow: u32 = 0,
};

/// Circuit breaker over **consecutive** failures (Polly's classic breaker,
/// gobreaker's default `ReadyToTrip`): `failure_threshold` failures in a
/// row trip it; any success resets the streak. `RateCircuitBreaker(n)` is the
/// failure-rate variant over a sliding window.
pub const CircuitBreaker = Breaker(ConsecutiveTrip);

/// Circuit breaker over the failure **rate** and slow-call rate in a sliding
/// window (resilience4j's default; failsafe-go's ratio thresholds): with
/// `kind = .count` the window is the last `n` calls, with `.time` it is `n`
/// buckets of `bucket_ms` (the last `n × bucket_ms`). It trips once the
/// window holds at least `minimum_calls` calls and `failure_rate_pct` of
/// them failed, or `slow_call_rate_pct` of them were slower than
/// `slow_call_duration_ms`. The window lives inside the struct (`n` slots of
/// 16 bytes) — no allocation.
pub fn RateCircuitBreaker(comptime n: u32) type {
    return Breaker(RateTrip(n));
}

/// The common state machine; `Trip` decides when `closed` trips.
///
/// State machine:
/// - `closed` — calls flow; outcomes feed the trip rule (`Trip`).
/// - `open` — `allow()` returns false (fast-fail) until `cooldown_ms` has
///   elapsed since the trip; the first `allow()` after that moves to
///   `half_open` (the transition is lazy — `state()` reports `.open` until
///   someone asks to be admitted).
/// - `half_open` — up to `half_open_probes` calls are admitted, the rest
///   fast-fail. Once `half_open_required_successes` (default: all of them)
///   succeeded the breaker closes; once so many failed that the rest can no
///   longer reach that number, it re-opens with a fresh cooldown (with the
///   default, the first failure). A probe slower than
///   `slow_call_duration_ms` (when set) counts as a failure.
///
/// Usage contract: ask `allow()` before each call; when it returns true,
/// report the outcome with **exactly one** of `onSuccess()`/`onFailure()`/
/// `record()`. A half-open probe whose outcome is never reported occupies
/// its probe slot until `Options.probe_timeout_ms` (default: `cooldown_ms`)
/// elapses, or until `abandonProbe()` releases it. Results reported while
/// `open` (from calls admitted before the trip that finished late) are
/// ignored: they neither extend the cooldown nor count as probes.
///
/// Thread-safe: all methods may race from any thread (documented spinlock,
/// O(1) critical sections except a time window's bucket roll, ≤ `n` slots;
/// no allocation). The listener runs outside the lock. No deinit — the
/// breaker owns no resources.
fn Breaker(comptime Trip: type) type {
    return struct {
        const Self = @This();
        pub const Options = Trip.Options;
        pub const State = BreakerState;

        options: Options,
        lock: std.atomic.Mutex = .unlocked,
        cur_state: BreakerState = .closed,
        cur_mode: Mode = .normal,
        trip_state: Trip = .{},
        /// Open only: instant of the trip (cooldown anchor).
        opened_at_ns: u64 = 0,
        /// Half-open only: probes admitted / succeeded / failed so far.
        probes_admitted: u32 = 0,
        probes_succeeded: u32 = 0,
        probes_failed: u32 = 0,
        /// Half-open only: instant of the most recent probe admission — the
        /// anchor for `Options.probe_timeout_ms`.
        last_admit_ns: u64 = 0,
        totals: Counts = .{ .state = .closed, .mode = .normal },

        pub fn init(options: Options) Self {
            std.debug.assert(options.half_open_probes >= 1);
            if (options.half_open_required_successes) |k|
                std.debug.assert(k >= 1 and k <= options.half_open_probes);
            Trip.check(options);
            return .{ .options = options };
        }

        /// A type-erased handle for `Policy.breaker` (and any code that
        /// drives breakers of either kind through one type). Valid while
        /// `self` is.
        pub fn handle(self: *Self) BreakerHandle {
            return .{ .ptr = self, .vtable = &vtable };
        }

        const vtable: BreakerHandle.VTable = .{
            .allow = struct {
                fn f(p: *anyopaque) bool {
                    return @as(*Self, @ptrCast(@alignCast(p))).allow();
                }
            }.f,
            .record = struct {
                fn f(p: *anyopaque, o: Outcome, duration_ns: ?u64) void {
                    @as(*Self, @ptrCast(@alignCast(p))).record(o, duration_ns);
                }
            }.f,
            .timesCalls = struct {
                fn f(p: *anyopaque) bool {
                    return @as(*Self, @ptrCast(@alignCast(p))).options.slow_call_duration_ms != null;
                }
            }.f,
        };

        /// May this call proceed? `false` = fast-fail now (breaker open, or
        /// all half-open probe slots taken). A `true` from a non-closed
        /// breaker admits a probe — report its outcome (see the usage
        /// contract).
        pub fn allow(cb: *Self) bool {
            var tr: ?[2]BreakerState = null;
            const ok = blk: {
                lockSpin(&cb.lock);
                defer cb.lock.unlock();
                switch (cb.cur_mode) {
                    .disabled => break :blk true,
                    .forced_open => {
                        cb.totals.not_permitted += 1;
                        break :blk false;
                    },
                    .normal => {},
                }
                switch (cb.cur_state) {
                    .closed => break :blk true,
                    .open => {
                        const now_ns = cb.options.clock.now();
                        if (now_ns -| cb.opened_at_ns < cb.options.cooldown_ms *| std.time.ns_per_ms) {
                            cb.totals.not_permitted += 1;
                            break :blk false;
                        }
                        // Cooldown over: become half-open and admit this
                        // caller as the first probe.
                        tr = cb.moveTo(.half_open);
                        cb.probes_admitted = 1;
                        cb.probes_succeeded = 0;
                        cb.probes_failed = 0;
                        cb.last_admit_ns = now_ns;
                        break :blk true;
                    },
                    .half_open => {
                        const now_ns = cb.options.clock.now();
                        cb.reclaimStaleProbes(now_ns);
                        if (cb.probes_admitted >= cb.options.half_open_probes) {
                            cb.totals.not_permitted += 1;
                            break :blk false;
                        }
                        cb.probes_admitted += 1;
                        cb.last_admit_ns = now_ns;
                        break :blk true;
                    },
                }
            };
            cb.notify(tr);
            return ok;
        }

        /// Probes admitted and not yet reported.
        fn outstanding(cb: *const Self) u32 {
            return cb.probes_admitted -| (cb.probes_succeeded + cb.probes_failed);
        }

        /// Reclaim probe slots whose outcome never arrived (see
        /// `Options.probe_timeout_ms`). Caller holds the lock.
        ///
        /// Coarse ON PURPOSE: it releases the whole outstanding set at once
        /// rather than timing each probe individually, which would need
        /// per-probe storage. That is exact at the default
        /// `half_open_probes = 1` — the configuration the wedge actually
        /// bites — and conservative above it: the only effect is that MORE
        /// probes may be admitted. It never closes the breaker and never
        /// re-opens it, so no failure verdict can be manufactured by a clock
        /// reading.
        fn reclaimStaleProbes(cb: *Self, now_ns: u64) void {
            const timeout_ms = cb.options.probe_timeout_ms orelse cb.options.cooldown_ms;
            if (timeout_ms == 0) return; // reclamation disabled
            if (cb.outstanding() == 0) return;
            if (now_ns -| cb.last_admit_ns < timeout_ms *| std.time.ns_per_ms) return;
            cb.probes_admitted = cb.probes_succeeded + cb.probes_failed;
        }

        /// Release ONE outstanding half-open probe slot, for a caller that
        /// knows it has lost a probe's outcome and does not want to wait out
        /// `probe_timeout_ms`. Returns true if a slot was actually released.
        ///
        /// Deliberately not `onSuccess`/`onFailure`: abandoning a probe is
        /// not a verdict about the downstream service, and must not count
        /// toward closing the breaker or toward re-opening it. No-op outside
        /// `half_open`.
        pub fn abandonProbe(cb: *Self) bool {
            lockSpin(&cb.lock);
            defer cb.lock.unlock();
            if (cb.cur_mode != .normal or cb.cur_state != .half_open) return false;
            if (cb.outstanding() == 0) return false;
            cb.probes_admitted -= 1;
            return true;
        }

        /// Report a successful call (no duration: never slow).
        pub fn onSuccess(cb: *Self) void {
            cb.record(.success, null);
        }

        /// Report a failed call.
        pub fn onFailure(cb: *Self) void {
            cb.record(.failure, null);
        }

        /// Report a call's outcome and, optionally, how long it took (for the
        /// slow-call rule; `null` = not slow). Closed: feeds the trip rule.
        /// Half-open: counts the probe (a slow success counts as a failure)
        /// and closes or re-opens once decided. Open: ignored (late result).
        /// `ignore` releases a half-open probe slot and changes nothing else.
        pub fn record(cb: *Self, outcome: Outcome, duration_ns: ?u64) void {
            var tr: ?[2]BreakerState = null;
            {
                lockSpin(&cb.lock);
                defer cb.lock.unlock();
                const slow = if (cb.options.slow_call_duration_ms) |ms|
                    if (duration_ns) |d| outcome != .ignore and d > ms *| std.time.ns_per_ms else false
                else
                    false;
                switch (outcome) {
                    .success => cb.totals.successes += 1,
                    .failure => cb.totals.failures += 1,
                    .ignore => cb.totals.ignored += 1,
                }
                if (slow) cb.totals.slow += 1;
                if (cb.cur_mode == .normal) switch (cb.cur_state) {
                    // The clock is read only when a time window needs it
                    // or the breaker trips.
                    .closed => if (outcome != .ignore) {
                        if (cb.trip_state.record(&cb.options, outcome == .failure, slow))
                            tr = cb.trip(cb.options.clock.now());
                    },
                    .half_open => switch (outcome) {
                        .ignore => {
                            if (cb.outstanding() > 0) cb.probes_admitted -= 1;
                        },
                        .success, .failure => {
                            // Never count more verdicts than there are
                            // outstanding probes: after a stale slot has been
                            // reclaimed the lost probe may still report, and
                            // an unguarded count would let a result nobody
                            // was waiting for decide the breaker.
                            if (cb.outstanding() == 0) return;
                            if (outcome == .success and !slow) cb.probes_succeeded += 1 else cb.probes_failed += 1;
                            const need = cb.options.half_open_required_successes orelse cb.options.half_open_probes;
                            if (cb.probes_succeeded >= need) {
                                tr = cb.moveTo(.closed);
                                cb.trip_state.clear();
                            } else if (cb.options.half_open_probes -| cb.probes_failed < need) {
                                tr = cb.trip(cb.options.clock.now());
                            }
                        },
                    },
                    .open => {},
                };
            }
            cb.notify(tr);
        }

        /// Current state. Note the lazy `open → half_open` transition: after
        /// the cooldown this still reports `.open` until an `allow()` asks to
        /// probe. Forced open reports `.open`, disabled `.closed`.
        pub fn state(cb: *Self) BreakerState {
            lockSpin(&cb.lock);
            defer cb.lock.unlock();
            return cb.visibleState();
        }

        fn visibleState(cb: *const Self) BreakerState {
            return switch (cb.cur_mode) {
                .normal => cb.cur_state,
                .forced_open => .open,
                .disabled => .closed,
            };
        }

        pub fn mode(cb: *Self) Mode {
            lockSpin(&cb.lock);
            defer cb.lock.unlock();
            return cb.cur_mode;
        }

        /// Consecutive mode: the current failure streak (closed state; 0
        /// otherwise). Rate mode: failures in the current window.
        pub fn failureCount(cb: *Self) u32 {
            const c = cb.counts();
            return if (Trip.is_rate) c.window_failures else c.consecutive_failures;
        }

        /// Lifetime totals plus the current window — a snapshot.
        pub fn counts(cb: *Self) Counts {
            lockSpin(&cb.lock);
            defer cb.lock.unlock();
            var c = cb.totals;
            c.state = cb.visibleState();
            c.mode = cb.cur_mode;
            if (cb.cur_mode == .normal and cb.cur_state == .closed)
                cb.trip_state.fill(&cb.options, &c, cb.options.clock.now());
            return c;
        }

        /// Back to `closed` in `normal` mode with an empty window and no
        /// probes — from any state or mode (resilience4j `reset`; the way out
        /// of `forceOpen` and `disable`).
        pub fn reset(cb: *Self) void {
            cb.setMode(.normal);
        }

        /// Latch open: refuse every call until `reset()`, whatever the clock
        /// says (a permanent refusal from the upstream, an operator's kill
        /// switch).
        pub fn forceOpen(cb: *Self) void {
            cb.setMode(.forced_open);
        }

        /// Admit every call and evaluate nothing until `reset()`.
        pub fn disable(cb: *Self) void {
            cb.setMode(.disabled);
        }

        fn setMode(cb: *Self, m: Mode) void {
            var tr: ?[2]BreakerState = null;
            {
                lockSpin(&cb.lock);
                defer cb.lock.unlock();
                const before = cb.visibleState();
                cb.cur_mode = m;
                cb.cur_state = .closed;
                cb.trip_state.clear();
                cb.probes_admitted = 0;
                cb.probes_succeeded = 0;
                cb.probes_failed = 0;
                const after = cb.visibleState();
                if (before != after) {
                    cb.totals.transitions += 1;
                    tr = .{ before, after };
                }
            }
            cb.notify(tr);
        }

        // Lock held. Returns the transition for `notify`.
        fn moveTo(cb: *Self, to: BreakerState) ?[2]BreakerState {
            const from = cb.cur_state;
            if (from == to) return null;
            cb.cur_state = to;
            cb.totals.transitions += 1;
            return .{ from, to };
        }

        // Lock held.
        fn trip(cb: *Self, now_ns: u64) ?[2]BreakerState {
            const t = cb.moveTo(.open);
            cb.opened_at_ns = now_ns;
            cb.trip_state.clear();
            return t;
        }

        // Lock NOT held.
        fn notify(cb: *Self, tr: ?[2]BreakerState) void {
            const t = tr orelse return;
            if (cb.options.listener) |l| l.onStateChange(l.ctx, t[0], t[1]);
        }
    };
}

/// A breaker of either kind behind one pointer — what `Policy.breaker`
/// holds. Get one with `breaker.handle()`.
pub const BreakerHandle = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        allow: *const fn (*anyopaque) bool,
        record: *const fn (*anyopaque, Outcome, ?u64) void,
        /// Does the breaker want call durations (slow-call rule set)?
        timesCalls: *const fn (*anyopaque) bool,
    };

    pub fn allow(h: BreakerHandle) bool {
        return h.vtable.allow(h.ptr);
    }
    pub fn record(h: BreakerHandle, o: Outcome, duration_ns: ?u64) void {
        h.vtable.record(h.ptr, o, duration_ns);
    }
    pub fn timesCalls(h: BreakerHandle) bool {
        return h.vtable.timesCalls(h.ptr);
    }
};

// The options every breaker kind shares, documented once; each `Trip`'s
// `Options` repeats them field for field (Zig has no struct embedding).
//
// - `cooldown_ms` — how long `open` fast-fails before probing.
// - `half_open_probes` — probe calls admitted while `half_open` (≥ 1).
// - `half_open_required_successes` — successes among them that close the
//   breaker (`null` = all of them; failsafe-go's success threshold).
// - `probe_timeout_ms` — how long an admitted half-open probe may go
//   unreported before its slot is reclaimed. `null` (the default) means
//   `cooldown_ms`; `0` disables reclamation. Without it, a single probe
//   whose outcome is never reported pins the breaker half-open FOREVER at
//   `half_open_probes = 1`. `run()` cannot cause that (it reports exactly
//   one outcome per admitted attempt), a hand-driven caller can.
// - `slow_call_duration_ms` — a reported duration above this is a slow call
//   (`null` = no slow-call rule; `run` then does not time calls for the
//   breaker). In half-open a slow success counts as a failure.
// - `clock` — time source; inject a fake for deterministic tests.
// - `listener` — state-change callback (see `StateListener`).

const ConsecutiveTrip = struct {
    const is_rate = false;
    consecutive_failures: u32 = 0,

    pub const Options = struct {
        /// Consecutive failures that trip `closed → open`. Must be ≥ 1.
        failure_threshold: u32 = 5,
        cooldown_ms: u64 = 30_000,
        half_open_probes: u32 = 1,
        half_open_required_successes: ?u32 = null,
        probe_timeout_ms: ?u64 = null,
        slow_call_duration_ms: ?u64 = null,
        clock: Clock = .monotonic,
        listener: ?StateListener = null,
    };

    fn check(o: Options) void {
        std.debug.assert(o.failure_threshold >= 1);
    }

    /// A slow success is still a success here: the consecutive rule counts
    /// failures only (slow calls show in `counts().slow`).
    fn record(t: *ConsecutiveTrip, o: *const Options, failed: bool, _: bool) bool {
        if (!failed) {
            t.consecutive_failures = 0;
            return false;
        }
        t.consecutive_failures += 1;
        return t.consecutive_failures >= o.failure_threshold;
    }

    fn clear(t: *ConsecutiveTrip) void {
        t.consecutive_failures = 0;
    }

    fn fill(t: *const ConsecutiveTrip, _: *const Options, c: *Counts, _: u64) void {
        c.consecutive_failures = t.consecutive_failures;
    }
};

pub const WindowKind = enum {
    /// The last `n` calls.
    count,
    /// The last `n` buckets of `bucket_ms` each.
    time,
};

fn RateTrip(comptime n: u32) type {
    comptime std.debug.assert(n >= 1);
    return struct {
        const Self = @This();
        const is_rate = true;
        const Slot = struct { epoch: u64 = 0, calls: u32 = 0, failures: u32 = 0, slow: u32 = 0 };

        slots: [n]Slot = @splat(.{}),
        /// Count mode: the next slot to write; time mode: unused.
        head: u32 = 0,
        calls: u32 = 0,
        failures: u32 = 0,
        slow: u32 = 0,
        /// Time mode: the newest bucket epoch seen (`now / bucket`).
        last_epoch: u64 = 0,

        pub const Options = struct {
            kind: WindowKind = .count,
            /// Time mode: one bucket's span. The window is `n × bucket_ms`.
            bucket_ms: u64 = 1_000,
            /// No verdict before the window holds this many calls
            /// (resilience4j `minimumNumberOfCalls`). Default: `n` in count
            /// mode — a full window.
            minimum_calls: ?u32 = null,
            /// Trip when failures ≥ this percentage of the window's calls
            /// (1..100; resilience4j default 50).
            failure_rate_pct: u8 = 50,
            /// Trip when slow calls ≥ this percentage (1..100; `null` = no
            /// slow-call rate rule). Needs `slow_call_duration_ms`.
            slow_call_rate_pct: ?u8 = null,
            cooldown_ms: u64 = 30_000,
            half_open_probes: u32 = 1,
            half_open_required_successes: ?u32 = null,
            probe_timeout_ms: ?u64 = null,
            slow_call_duration_ms: ?u64 = null,
            clock: Clock = .monotonic,
            listener: ?StateListener = null,
        };

        fn check(o: Options) void {
            std.debug.assert(o.failure_rate_pct >= 1 and o.failure_rate_pct <= 100);
            if (o.slow_call_rate_pct) |p| {
                std.debug.assert(p >= 1 and p <= 100);
                std.debug.assert(o.slow_call_duration_ms != null);
            }
            if (o.kind == .time) std.debug.assert(o.bucket_ms >= 1);
            if (o.minimum_calls) |m| std.debug.assert(m >= 1);
        }

        fn minCalls(o: *const Options) u32 {
            return o.minimum_calls orelse switch (o.kind) {
                .count => n,
                .time => 1,
            };
        }

        /// Time mode: drop the buckets that have left the window as of
        /// `epoch` (at most `n` of them).
        fn roll(t: *Self, epoch: u64) void {
            if (epoch <= t.last_epoch) return;
            const gone = @min(epoch - t.last_epoch, n);
            var e = epoch - gone + 1;
            while (e <= epoch) : (e += 1) t.drop(&t.slots[@intCast(e % n)]);
            t.last_epoch = epoch;
        }

        fn drop(t: *Self, s: *Slot) void {
            t.calls -= s.calls;
            t.failures -= s.failures;
            t.slow -= s.slow;
            s.* = .{};
        }

        fn record(t: *Self, o: *const Options, failed: bool, slow: bool) bool {
            const s = switch (o.kind) {
                .count => blk: {
                    const s = &t.slots[t.head];
                    t.drop(s);
                    t.head = if (t.head + 1 == n) 0 else t.head + 1;
                    break :blk s;
                },
                .time => blk: {
                    const epoch = o.clock.now() / (o.bucket_ms *| std.time.ns_per_ms);
                    t.roll(epoch);
                    break :blk &t.slots[@intCast(epoch % n)];
                },
            };
            s.calls += 1;
            t.calls += 1;
            if (failed) {
                s.failures += 1;
                t.failures += 1;
            }
            if (slow) {
                s.slow += 1;
                t.slow += 1;
            }
            if (t.calls < minCalls(o)) return false;
            // Percentages compared in integers: x / calls ≥ p / 100.
            const calls: u64 = t.calls;
            if (@as(u64, t.failures) * 100 >= @as(u64, o.failure_rate_pct) * calls) return true;
            if (o.slow_call_rate_pct) |p| {
                if (@as(u64, t.slow) * 100 >= @as(u64, p) * calls) return true;
            }
            return false;
        }

        fn clear(t: *Self) void {
            t.* = .{};
        }

        fn fill(t: *Self, o: *const Options, c: *Counts, now_ns: u64) void {
            if (o.kind == .time) t.roll(now_ns / (o.bucket_ms *| std.time.ns_per_ms));
            c.window_calls = t.calls;
            c.window_failures = t.failures;
            c.window_slow = t.slow;
        }
    };
}

/// Spin with exponential backoff: a failed `tryLock` waits 1, 2, 4 … 64
/// pause hints before the next attempt, so contending threads stop
/// hammering the lock's cache line (the bare retry loop made 8 threads on
/// one breaker 2× slower than a parking mutex, bench 2026-10-16).
fn lockSpin(m: *std.atomic.Mutex) void {
    var pause: u32 = 1;
    while (!m.tryLock()) {
        for (0..pause) |_| std.atomic.spinLoopHint();
        pause = @min(pause * 2, 64);
    }
}

// ── bulkhead (bounded concurrent execution) ─────────────────────────────────

/// Bounded concurrent-execution limiter: at most `max_concurrent` calls may
/// be in flight at once — the "don't let one slow dependency eat every
/// thread" isolation piece, sibling to the breaker (which reacts to
/// *failures*; the bulkhead reacts to *saturation*).
///
/// Provenance: clean-room — models resilience4j's semaphore Bulkhead
/// (Apache-2.0; behavior only: `maxConcurrentCalls` + `maxWaitDuration`,
/// full ⇒ `BulkheadFullException` ⇒ `error.BulkheadFull` here). No source
/// consulted or copied.
///
/// Modes:
/// - `max_wait_ns = 0` (default) — non-blocking: a full bulkhead rejects
///   with `error.BulkheadFull` immediately; a failed acquire consumes
///   nothing.
/// - `max_wait_ns > 0` — bounded wait: `acquire()` re-tries for up to the
///   budget before rejecting. The wait is a **poll** over the injected
///   `Clock`/`Delay` (granularity `poll_ns`) — this module is std-only with
///   no `Io`, so there is no futex to park on (the `throttle` sibling has
///   the futex variant); tests inject a virtual clock/delay and never sleep.
///
/// Usage contract: pair every successful `tryAcquire()`/`acquire()` with
/// exactly one `release()` — or use `run(op)`, which releases on the error
/// path too. Thread-safe: a CAS loop on one atomic counter (the counter can
/// never exceed the cap — the CAS refuses — nor go negative: `release`
/// asserts in Debug and saturates at 0 in release builds). No allocation,
/// nothing to deinit.
pub const Bulkhead = struct {
    options: Options,
    /// Slots currently held (0 ≤ n ≤ max_concurrent, CAS-enforced).
    in_flight: std.atomic.Value(u32) = .init(0),

    /// The one error the bulkhead adds: no slot within the (possibly zero)
    /// wait budget. Fast-fail and shed/queue elsewhere — that is the point.
    pub const Error = error{BulkheadFull};

    pub const Options = struct {
        /// Hard cap on concurrently admitted calls. Must be ≥ 1.
        max_concurrent: u32,
        /// How long `acquire()` may wait for a slot before giving up.
        /// 0 (default) = never wait, reject immediately.
        max_wait_ns: u64 = 0,
        /// Poll granularity of the bounded wait (clamped to the remaining
        /// budget). Only consulted when `max_wait_ns > 0`.
        poll_ns: u64 = 100 * std.time.ns_per_us,
        /// Time source for the wait deadline — inject a fake for
        /// deterministic tests. Never consulted when `max_wait_ns = 0`.
        clock: Clock = .monotonic,
        /// How the bounded wait sleeps between polls — tests inject a
        /// virtual delay that advances the fake clock. Never consulted when
        /// `max_wait_ns = 0`.
        delay: Delay = .blocking,
    };

    pub fn init(options: Options) Bulkhead {
        std.debug.assert(options.max_concurrent >= 1);
        return .{ .options = options };
    }

    /// Take a slot if one is free — never blocks, never over-admits; a
    /// failed attempt consumes nothing. Pair every success with exactly one
    /// `release()`.
    pub fn tryAcquire(b: *Bulkhead) bool {
        var cur = b.in_flight.load(.seq_cst);
        var pause: u32 = 1;
        while (true) {
            if (cur >= b.options.max_concurrent) return false;
            cur = b.in_flight.cmpxchgWeak(cur, cur + 1, .seq_cst, .seq_cst) orelse
                return true;
            // Lost the race: back off before re-reading (see `lockSpin`).
            for (0..pause) |_| std.atomic.spinLoopHint();
            pause = @min(pause * 2, 64);
        }
    }

    /// `tryAcquire` as an error union, plus the bounded wait when
    /// configured: at capacity with `max_wait_ns > 0`, poll for a freed
    /// slot until the deadline, then reject. A rejected acquire holds
    /// nothing — do not `release()` after `error.BulkheadFull`.
    pub fn acquire(b: *Bulkhead) Error!void {
        if (b.tryAcquire()) return;
        if (b.options.max_wait_ns == 0) return error.BulkheadFull;

        const clock = b.options.clock;
        const deadline_ns = clock.now() +| b.options.max_wait_ns;
        while (true) {
            const now_ns = clock.now();
            if (now_ns >= deadline_ns) return error.BulkheadFull;
            b.options.delay.sleep(@max(1, @min(b.options.poll_ns, deadline_ns - now_ns)));
            if (b.tryAcquire()) return;
        }
    }

    /// Return a slot taken by a successful `tryAcquire`/`acquire`.
    /// Releasing more than was acquired is a caller bug: asserts in Debug;
    /// in release builds the counter saturates at 0 instead of wrapping.
    pub fn release(b: *Bulkhead) void {
        var cur = b.in_flight.load(.seq_cst);
        var pause: u32 = 1;
        while (true) {
            std.debug.assert(cur > 0); // release without a matching acquire
            if (cur == 0) return; // ReleaseFast: saturate, don't wrap
            cur = b.in_flight.cmpxchgWeak(cur, cur - 1, .seq_cst, .seq_cst) orelse
                return;
            for (0..pause) |_| std.atomic.spinLoopHint();
            pause = @min(pause * 2, 64);
        }
    }

    /// Slots currently held — a point-in-time snapshot (observability).
    pub fn activeCount(b: *const Bulkhead) u32 {
        return b.in_flight.load(.seq_cst);
    }

    /// Slots currently free (`max_concurrent - activeCount`) — a racy
    /// snapshot: a true answer here does not reserve anything, only
    /// `tryAcquire`/`acquire` admit.
    pub fn availableSlots(b: *const Bulkhead) u32 {
        return b.options.max_concurrent -| b.activeCount();
    }

    /// The result type `run(op)` returns for an operation of type `Op`:
    /// the operation's own error union widened with `error.BulkheadFull`.
    pub fn RunResult(comptime Op: type) type {
        const info = @typeInfo(CallReturn(Op)).error_union;
        return (info.error_set || Error)!info.payload;
    }

    /// Run `op` (same operation shape as the module-level `run`: any value
    /// with a `call()` method returning an error union) inside one slot:
    /// acquire → call → release. The slot is released whether the call
    /// succeeds or errors; a full bulkhead returns `error.BulkheadFull`
    /// without invoking the operation at all.
    pub fn run(b: *Bulkhead, op: anytype) Bulkhead.RunResult(@TypeOf(op)) {
        try b.acquire();
        defer b.release();
        return op.call();
    }
};

// ── retry with backoff ──────────────────────────────────────────────────────

/// How a computed backoff delay is randomized. Jitter de-synchronizes
/// retrying clients so they don't stampede a recovering upstream in lock
/// step.
pub const Jitter = enum {
    /// No randomization — delays are exactly the exponential schedule.
    /// Not the default (audit F2): synchronized retrying clients would
    /// stampede a recovering upstream in lockstep, the exact failure mode
    /// this type exists to prevent. Still explicitly available for tests
    /// (byte-exact delay assertions) and genuinely single-client callers
    /// where there's no herd to desynchronize.
    none,
    /// **Full jitter** (recommended, and the default): uniform in `[0, d]`.
    /// Best contention spread per AWS "Exponential Backoff And Jitter"
    /// (Brooker, 2015). Only takes effect when `Policy.random` (or
    /// `nextDelay`'s `random` argument) is non-null — Zig 0.16 std has no
    /// ambient entropy and this module has no hidden globals, so a caller
    /// who never supplies randomness gets the plain `.none` schedule
    /// regardless of this default (see `nextDelay`'s doc). Production
    /// callers with many clients should pass a seeded `std.Random`.
    full,
    /// Equal jitter: uniform in `[d/2, d]` — keeps at least half the
    /// backoff when a minimum spacing matters more than maximum spread.
    equal,
    /// Jitter by factor: uniform in `[d × (1 − f), d × (1 + f)]` with
    /// `f = Retry.jitter_factor` (cenkalti/backoff's randomization factor,
    /// failsafe-go's jitter factor), clamped to `max_delay_ms`.
    proportional,
};

/// Retry policy — a pure value: `nextDelay` computes, the caller (or `run`)
/// waits. Semantics follow resilience4j's `IntervalFunction` family
/// (exponential backoff, cap, randomization) with the jitter flavors named
/// after the AWS taxonomy.
pub const Retry = struct {
    /// Total attempts including the first call (resilience4j `maxAttempts`).
    /// 1 = no retries; 0 is treated as 1.
    max_attempts: u32 = 3,
    /// Delay before the first retry (i.e. after attempt 1).
    base_delay_ms: u64 = 100,
    /// Exponential growth per attempt. Must be ≥ 1.0 and finite.
    factor: f64 = 2.0,
    /// Upper bound on any single delay (applied before jitter, so it also
    /// bounds every jittered delay).
    max_delay_ms: u64 = 30_000,
    /// Default `.full` (audit F2 — was `.none`; see `Jitter`'s doc). Harmless
    /// to leave at the default: it only changes behavior once a real
    /// `random` is also supplied (`Policy.random` / `nextDelay`'s argument),
    /// so a caller who hasn't wired up entropy gets today's un-jittered
    /// schedule exactly as before.
    jitter: Jitter = .full,
    /// `.proportional` only: the relative spread, in `[0, 1]`.
    jitter_factor: f64 = 0.5,
    /// Total time budget for the attempts and the waits between them, from
    /// the start of `run` (failsafe-go max duration, cenkalti
    /// `MaxElapsedTime`); 0 = unbounded. A retry whose wait would end past
    /// the budget is not made — `run` returns the last failure instead.
    max_elapsed_ms: u64 = 0,
    /// Only errors this returns true for are retried (resilience4j
    /// `retryExceptions`); anything else propagates immediately. The
    /// default retries everything — including `error.Timeout` from the
    /// composed timeout. Zig errors are globally unique, so an `anyerror`
    /// predicate can match any operation's error set.
    retryable: *const fn (anyerror) bool = &retryAllErrors,

    /// Delay in ms to wait after failed attempt `attempt` (1-based: pass 1
    /// after the first call failed). Exponential: `base × factor^(attempt-1)`,
    /// capped at `max_delay_ms`, then jittered. Pure — same inputs, same
    /// output (for `.none`; jittered flavors draw from `random`).
    /// `random` may be null only with `.none` jitter — with a jittered
    /// flavor and no rng the delay deterministically falls back to the
    /// un-jittered value (documented, so Debug and ReleaseFast agree).
    pub fn nextDelay(r: Retry, attempt: u32, random: ?std.Random) u64 {
        const rnd = random orelse return r.nextDelayFrom(attempt, null);
        if (r.jitter == .none) return r.nextDelayFrom(attempt, null);
        return r.nextDelayFrom(attempt, rnd.int(u64));
    }

    /// `nextDelay` with the randomness handed in as 64 bits the caller drew
    /// itself (`null` = un-jittered) -- e.g. `prng.next()` straight from a
    /// concrete generator, without `std.Random`'s indirect call and byte
    /// fill, which cost as much as the rest of a jittered delay (bench
    /// 2026-10-16). Same bits, same delay.
    pub fn nextDelayFrom(r: Retry, attempt: u32, bits: ?u64) u64 {
        std.debug.assert(attempt >= 1);
        std.debug.assert(r.factor >= 1.0 and std.math.isFinite(r.factor));
        const d = r.expDelayMs(attempt);
        const x = bits orelse return d;
        return switch (r.jitter) {
            .none => d,
            .full => upTo(x, d),
            .equal => d / 2 + upTo(x, d - d / 2),
            .proportional => blk: {
                std.debug.assert(r.jitter_factor >= 0 and r.jitter_factor <= 1);
                const df: f64 = @floatFromInt(d);
                const spread: u64 = @intFromFloat(df * r.jitter_factor);
                const lo = d - @min(d, spread);
                break :blk @min(r.max_delay_ms, lo +| upTo(x, 2 *| spread));
            },
        };
    }

    /// Uniform in `[0, max]` from one 64-bit draw `x`: the high half of
    /// `x × (max + 1)` (Lemire's map without the rejection step; its bias is
    /// below `(max + 1) / 2^64`, nothing next to a millisecond delay).
    fn upTo(x: u64, max: u64) u64 {
        if (max == std.math.maxInt(u64)) return x;
        const wide = @as(u128, x) * (@as(u128, max) + 1);
        return @intCast(wide >> 64);
    }

    /// The un-jittered exponential schedule (overflow-safe: anything that
    /// leaves f64's exact range lands on `max_delay_ms`).
    fn expDelayMs(r: Retry, attempt: u32) u64 {
        // factor 2 (the default) in integers: `base << k` is exactly what
        // the f64 product below gives while it is under the cap, and no
        // `pow` (~2/3 of a delay's cost, bench 2026-10-16).
        if (r.factor == 2.0) {
            const k = attempt - 1;
            if (k >= 64) return if (r.base_delay_ms == 0) 0 else r.max_delay_ms;
            const sh = @shlWithOverflow(r.base_delay_ms, @as(u6, @intCast(k)));
            if (sh[1] != 0 or sh[0] >= r.max_delay_ms) return if (r.base_delay_ms == 0) 0 else r.max_delay_ms;
            return sh[0];
        }
        const max_f: f64 = @floatFromInt(r.max_delay_ms);
        const grown = @as(f64, @floatFromInt(r.base_delay_ms)) *
            std.math.pow(f64, r.factor, @floatFromInt(attempt - 1));
        // NaN/inf/≥max all cap (the comparison is written to be false for
        // NaN, so the `return max` branch catches it).
        if (!(grown < max_f)) return r.max_delay_ms;
        return @intFromFloat(grown);
    }
};

/// Default `Retry.retryable`: every error is retryable.
pub fn retryAllErrors(_: anyerror) bool {
    return true;
}

// ── deadline (cooperative timeout) ──────────────────────────────────────────

/// A time budget the operation can check cooperatively — created by `run`
/// for each attempt when `Policy.timeout_ms` is set (and handed to the
/// operation's `setDeadline` if it has one), or by hand for standalone use.
/// See the module doc's honesty note: a deadline informs, it never
/// interrupts.
pub const Deadline = struct {
    clock: Clock,
    deadline_ns: u64,

    /// A deadline `timeout_ms` from now on `clock`.
    pub fn init(clock: Clock, timeout_ms: u64) Deadline {
        return .{ .clock = clock, .deadline_ns = clock.now() +| timeout_ms *| std.time.ns_per_ms };
    }

    pub fn expired(d: Deadline) bool {
        return d.clock.now() >= d.deadline_ns;
    }

    /// Time left, 0 when past. Map this onto your own I/O timeouts.
    pub fn remainingNs(d: Deadline) u64 {
        return d.deadline_ns -| d.clock.now();
    }

    pub fn remainingMs(d: Deadline) u64 {
        return d.remainingNs() / std.time.ns_per_ms;
    }
};

// ── composition ─────────────────────────────────────────────────────────────

/// Errors `run` adds on top of the operation's own error set.
pub const PolicyError = error{
    /// The circuit breaker refused the call (open, or half-open with all
    /// probe slots taken). Fast-fail — the operation was not invoked.
    CircuitOpen,
    /// The attempt exceeded `Policy.timeout_ms` (its actual result, even a
    /// success, was discarded — see the module doc's honesty note).
    Timeout,
};

/// What `run` applies around the operation. All parts optional — an empty
/// policy is a plain passthrough call.
pub const Policy = struct {
    /// Shared breaker gating every attempt (`breaker.handle()`, either
    /// kind); null = no breaker. Outlives the call; one breaker per upstream,
    /// shared across threads, is the intended shape. BREAKING 2026-10-16:
    /// was `?*CircuitBreaker` (`.breaker = &cb` → `.breaker = cb.handle()`).
    breaker: ?BreakerHandle = null,
    /// A slot held for the whole `run` (every attempt and every wait), taken
    /// before the first attempt: a full bulkhead returns
    /// `error.BulkheadFull` without calling anything (resilience4j's
    /// Bulkhead outside Retry).
    bulkhead: ?*Bulkhead = null,
    /// Retry policy; null = single attempt.
    retry: ?Retry = null,
    /// Per-attempt time budget in ms; 0 = unbounded. Observational +
    /// cooperative only (see the module doc — it cannot interrupt a
    /// blocking call).
    timeout_ms: u64 = 0,
    /// Stopwatch for the timeout — inject a fake for deterministic tests.
    clock: Clock = .monotonic,
    /// How to wait between attempts — tests inject a recording no-op.
    delay: Delay = .blocking,
    /// Entropy for jittered retry delays (give each thread its own). May be
    /// null when `retry.jitter == .none`; with a jittered flavor and no rng
    /// the delays fall back to the un-jittered schedule.
    random: ?std.Random = null,
    /// What an error from the operation means for the breaker (resilience4j
    /// record/ignore exceptions, gobreaker `IsSuccessful`/`IsExcluded`).
    /// `.failure` (the default for every error) counts against the upstream
    /// and may be retried; `.success` and `.ignore` (a 404, a validation
    /// error) are returned at once, never retried, recorded as such.
    /// `error.Timeout` is always a failure.
    classify: *const fn (anyerror) Outcome = &everyErrorIsFailure,
    /// Called before each wait between attempts.
    on_retry: ?RetryListener = null,
};

/// Default `Policy.classify`.
pub fn everyErrorIsFailure(_: anyerror) Outcome {
    return .failure;
}

/// `Policy.on_retry`: `attempt` just failed (1-based), the next starts after
/// `delay_ms`. `failure` is the error, or null when the operation's
/// `retryOnResult` asked for the retry.
pub const RetryListener = struct {
    ctx: ?*anyopaque = null,
    onRetry: *const fn (ctx: ?*anyopaque, attempt: u32, failure: ?anyerror, delay_ms: u64) void,
};

/// The result type `run(op, …)` returns for an operation of type `Op`:
/// the operation's own error union widened with `PolicyError`.
pub fn RunResult(comptime Op: type) type {
    const ret = CallReturn(Op);
    const info = @typeInfo(ret).error_union;
    return (info.error_set || PolicyError || Bulkhead.Error)!info.payload;
}

fn OperationType(comptime Op: type) type {
    return switch (@typeInfo(Op)) {
        .pointer => |p| p.child,
        else => Op,
    };
}

fn CallReturn(comptime Op: type) type {
    const T = OperationType(Op);
    switch (@typeInfo(T)) {
        .@"struct", .@"union", .@"enum", .@"opaque" => {},
        else => @compileError("resilience.run: operation must be a container with a call() method, got " ++ @typeName(T)),
    }
    if (!@hasDecl(T, "call"))
        @compileError("resilience.run: operation type " ++ @typeName(T) ++ " has no call() method");
    const ret = @typeInfo(@TypeOf(T.call)).@"fn".return_type.?;
    if (@typeInfo(ret) != .error_union)
        @compileError("resilience.run: call() must return an error union, got " ++ @typeName(ret));
    return ret;
}

/// Run `op` under `policy`: bulkhead → breaker → retry → timeout (see the
/// module doc for the exact ordering and the resilience4j note).
///
/// `op` is any value with a `call()` method returning an error union —
/// pass `&op` when `call` takes `*Self`. Optional hooks, used when the
/// operation type declares them:
/// - `pub fn setDeadline(self, d: Deadline) void` — each attempt's deadline,
///   handed over before the call when a timeout is set (cooperative
///   cancellation);
/// - `pub fn retryOnResult(self, value: *const T) bool` — a SUCCESSFUL
///   result that should still be retried (an HTTP 503 inside an Ok
///   response; resilience4j `retryOnResultPredicate`). It counts as a
///   failure for the breaker; when no attempt is left, that last value is
///   returned;
/// - `pub fn retryAfterMs(self) ?u64` — after a failed attempt, a
///   server-suggested wait (`Retry-After`) that replaces `nextDelay`,
///   clamped to `max_delay_ms`.
///
/// Returns the first accepted attempt's value, or: `error.BulkheadFull`
/// when the bulkhead is full, `error.CircuitOpen` when the breaker refuses
/// an attempt (never retried within this run), `error.Timeout` for an
/// over-budget attempt that exhausted the policy, or the operation's own
/// error. Retried attempts may repeat side effects — only wrap idempotent
/// work (the standard retry caveat).
pub fn run(op: anytype, policy: Policy) RunResult(@TypeOf(op)) {
    const T = OperationType(@TypeOf(op));
    const Payload = @typeInfo(CallReturn(@TypeOf(op))).error_union.payload;
    if (policy.bulkhead) |b| try b.acquire();
    defer if (policy.bulkhead) |b| b.release();

    const timeout_ns = policy.timeout_ms *| std.time.ns_per_ms;
    const max_attempts: u32 = if (policy.retry) |r| @max(1, r.max_attempts) else 1;
    const budget_ns: u64 = if (policy.retry) |r| r.max_elapsed_ms *| std.time.ns_per_ms else 0;
    const run_start_ns: u64 = if (budget_ns != 0) policy.clock.now() else 0;
    // The clock is read around a call only when someone needs the duration.
    const time_calls = policy.timeout_ms != 0 or
        (if (policy.breaker) |h| h.timesCalls() else false);

    var attempt: u32 = 1;
    while (true) : (attempt += 1) {
        if (policy.breaker) |h| {
            if (!h.allow()) return error.CircuitOpen;
        }
        if (comptime @hasDecl(T, "setDeadline")) {
            if (policy.timeout_ms != 0)
                op.setDeadline(Deadline.init(policy.clock, policy.timeout_ms));
        }

        const started_ns = if (time_calls) policy.clock.now() else 0;
        const result = op.call();
        const duration_ns: ?u64 = if (time_calls) policy.clock.now() -| started_ns else null;
        const timed_out = policy.timeout_ms != 0 and duration_ns.? > timeout_ns;

        // `failure` is the error to return if this attempt is the last one;
        // `rejected` the value a `retryOnResult` turned down.
        var rejected: ?Payload = null;
        const failure: anyerror = blk: {
            if (result) |value| {
                if (!timed_out) {
                    if (comptime @hasDecl(T, "retryOnResult")) {
                        if (op.retryOnResult(&value)) {
                            if (policy.breaker) |h| h.record(.failure, duration_ns);
                            rejected = value;
                            break :blk error.Timeout; // unused: `rejected` wins below
                        }
                    }
                    if (policy.breaker) |h| h.record(.success, duration_ns);
                    return value;
                }
                break :blk error.Timeout; // too-late success = failure
            } else |err| {
                if (timed_out) break :blk error.Timeout;
                const outcome = policy.classify(err);
                if (policy.breaker) |h| h.record(outcome, duration_ns);
                if (outcome != .failure) return err;
                break :blk err;
            }
        };
        if (rejected == null and failure == error.Timeout and timed_out) {
            if (policy.breaker) |h| h.record(.failure, duration_ns);
        }

        const give_up = attempt >= max_attempts or
            (rejected == null and !policy.retry.?.retryable(failure));
        if (!give_up) {
            const retry = policy.retry.?; // max_attempts > 1 implies a retry policy
            var wait_ms = retry.nextDelay(attempt, policy.random);
            if (comptime @hasDecl(T, "retryAfterMs")) {
                if (op.retryAfterMs()) |ms| wait_ms = @min(ms, retry.max_delay_ms);
            }
            const over_budget = budget_ns != 0 and
                (policy.clock.now() -| run_start_ns) +| wait_ms *| std.time.ns_per_ms > budget_ns;
            if (!over_budget) {
                if (policy.on_retry) |l| l.onRetry(l.ctx, attempt, if (rejected == null) failure else null, wait_ms);
                if (wait_ms != 0) policy.delay.sleep(wait_ms *| std.time.ns_per_ms);
                continue;
            }
        }
        if (rejected) |v| return v;
        return @errorCast(failure);
    }
}

/// The type `operation(ctx, f)` returns — a zero-cost adapter turning a
/// plain function + context value into an operation for `run`.
pub fn Operation(comptime Ctx: type, comptime f: anytype) type {
    return struct {
        ctx: Ctx,
        pub fn call(self: @This()) @typeInfo(@TypeOf(f)).@"fn".return_type.? {
            return f(self.ctx);
        }
    };
}

/// Adapt "fn + ctx" into an operation: `resilience.run(operation(&state, doFetch), policy)`.
/// `f` must be `fn (@TypeOf(ctx)) E!T`. For stateful calls make `ctx` a
/// pointer.
pub fn operation(ctx: anytype, comptime f: anytype) Operation(@TypeOf(ctx), f) {
    return .{ .ctx = ctx };
}

// ── tests: deterministic harness (no real clock, no real sleep) ─────────────

const testing = std.testing;

/// Deterministic test clock (same shape as the ratelimit/throttle siblings).
const TestClock = struct {
    ns: u64 = 0,

    fn clock(t: *TestClock) Clock {
        return .{ .ctx = t, .nowFn = nowFn };
    }
    fn nowFn(ctx: ?*anyopaque) u64 {
        const t: *TestClock = @ptrCast(@alignCast(ctx.?));
        return t.ns;
    }
    fn advanceMs(t: *TestClock, ms: u64) void {
        t.ns += ms * std.time.ns_per_ms;
    }
};

/// Recording virtual sleep — `run`'s waits land here, no time passes.
const TestDelay = struct {
    log_ms: [16]u64 = @splat(0),
    count: usize = 0,

    fn delay(t: *TestDelay) Delay {
        return .{ .ctx = t, .sleepFn = sleepFn };
    }
    fn sleepFn(ctx: ?*anyopaque, ns: u64) void {
        const t: *TestDelay = @ptrCast(@alignCast(ctx.?));
        t.log_ms[t.count] = ns / std.time.ns_per_ms;
        t.count += 1;
    }
    fn logged(t: *const TestDelay) []const u64 {
        return t.log_ms[0..t.count];
    }
};

const ScriptErr = error{ Boom, Fatal };

/// Fail-scripted synthetic operation: step k of the script decides call
/// k's result and how much virtual time the call "takes" (advancing the
/// shared TestClock). The last step repeats forever.
const ScriptedOp = struct {
    script: []const Step,
    tc: ?*TestClock = null,
    calls: usize = 0,

    const Step = struct {
        result: ScriptErr!u32,
        takes_ms: u64 = 0,
    };

    pub fn call(self: *ScriptedOp) ScriptErr!u32 {
        const step = self.script[@min(self.calls, self.script.len - 1)];
        self.calls += 1;
        if (self.tc) |tc| tc.advanceMs(step.takes_ms);
        return step.result;
    }
};

// ── tests: circuit breaker ──────────────────────────────────────────────────

test "CircuitBreaker: trips open after threshold consecutive failures; success resets the streak" {
    var tc: TestClock = .{};
    var cb: CircuitBreaker = .init(.{ .failure_threshold = 3, .cooldown_ms = 1000, .clock = tc.clock() });

    try testing.expect(cb.allow());
    cb.onFailure();
    cb.onFailure();
    try testing.expectEqual(.closed, cb.state());
    try testing.expectEqual(2, cb.failureCount());

    // A success in between resets the consecutive streak.
    cb.onSuccess();
    try testing.expectEqual(0, cb.failureCount());
    cb.onFailure();
    cb.onFailure();
    try testing.expectEqual(.closed, cb.state());

    // The Nth consecutive failure trips it.
    cb.onFailure();
    try testing.expectEqual(.open, cb.state());
    try testing.expect(!cb.allow());
    try testing.expect(!cb.allow()); // fast-fail stays
}

test "CircuitBreaker: cooldown elapses -> half_open probe; probe success closes" {
    var tc: TestClock = .{};
    var cb: CircuitBreaker = .init(.{ .failure_threshold = 1, .cooldown_ms = 1000, .clock = tc.clock() });

    cb.onFailure(); // threshold 1: instant trip
    try testing.expectEqual(.open, cb.state());

    tc.advanceMs(999);
    try testing.expect(!cb.allow()); // still cooling down
    tc.advanceMs(1);
    try testing.expectEqual(.open, cb.state()); // transition is lazy…
    try testing.expect(cb.allow()); // …the probe request performs it
    try testing.expectEqual(.half_open, cb.state());

    cb.onSuccess();
    try testing.expectEqual(.closed, cb.state());
    try testing.expect(cb.allow());
}

test "CircuitBreaker: probe failure re-opens with a fresh cooldown" {
    var tc: TestClock = .{};
    var cb: CircuitBreaker = .init(.{ .failure_threshold = 1, .cooldown_ms = 1000, .clock = tc.clock() });

    cb.onFailure();
    tc.advanceMs(1000);
    try testing.expect(cb.allow()); // half-open probe
    cb.onFailure(); // probe fails
    try testing.expectEqual(.open, cb.state());

    // The cooldown is anchored at the re-trip, not the original one.
    tc.advanceMs(999);
    try testing.expect(!cb.allow());
    tc.advanceMs(1);
    try testing.expect(cb.allow());
    cb.onSuccess();
    try testing.expectEqual(.closed, cb.state());
}

test "CircuitBreaker: half_open admits at most half_open_probes; all must succeed to close" {
    var tc: TestClock = .{};
    var cb: CircuitBreaker = .init(.{
        .failure_threshold = 1,
        .cooldown_ms = 1000,
        .half_open_probes = 2,
        .clock = tc.clock(),
    });

    cb.onFailure();
    tc.advanceMs(1000);
    try testing.expect(cb.allow()); // probe 1
    try testing.expect(cb.allow()); // probe 2
    try testing.expect(!cb.allow()); // budget spent — fast-fail

    cb.onSuccess(); // 1 of 2
    try testing.expectEqual(.half_open, cb.state());
    try testing.expect(!cb.allow()); // still deciding
    cb.onSuccess(); // 2 of 2 — closed
    try testing.expectEqual(.closed, cb.state());
    try testing.expect(cb.allow());
}

test "CircuitBreaker: a probe whose outcome is never reported does not wedge the breaker (audit F1)" {
    var tc: TestClock = .{};
    var cb: CircuitBreaker = .init(.{ .failure_threshold = 1, .cooldown_ms = 1000, .clock = tc.clock() });

    cb.onFailure();
    tc.advanceMs(1000);
    try testing.expect(cb.allow()); // probe admitted…
    try testing.expectEqual(.half_open, cb.state());
    // …and its outcome is LOST — no onSuccess, no onFailure. At the default
    // half_open_probes = 1 this used to pin the breaker half-open forever:
    // never admitting, never closing.
    tc.advanceMs(999);
    try testing.expect(!cb.allow()); // slot still legitimately held

    tc.advanceMs(1); // probe_timeout_ms defaults to cooldown_ms = 1000
    try testing.expect(cb.allow()); // slot reclaimed, a new probe gets in
    try testing.expectEqual(.half_open, cb.state()); // …and only that: no verdict invented

    // The reclaimed run still behaves normally.
    cb.onSuccess();
    try testing.expectEqual(.closed, cb.state());
}

test "CircuitBreaker: a lost probe's late success cannot close the breaker after reclamation" {
    var tc: TestClock = .{};
    var cb: CircuitBreaker = .init(.{
        .failure_threshold = 1,
        .cooldown_ms = 1000,
        .half_open_probes = 2,
        .clock = tc.clock(),
    });

    cb.onFailure();
    tc.advanceMs(1000);
    try testing.expect(cb.allow()); // probe 1 — outcome will be lost
    try testing.expect(cb.allow()); // probe 2 — outcome will be lost
    try testing.expect(!cb.allow());

    tc.advanceMs(1000); // both go stale
    try testing.expect(cb.allow()); // reclaimed: one fresh probe
    cb.onSuccess(); // 1 of 2
    try testing.expectEqual(.half_open, cb.state());

    // Now the two LOST probes finally report success. They must not be counted
    // — nobody was waiting for them — so the breaker stays half-open.
    cb.onSuccess();
    cb.onSuccess();
    try testing.expectEqual(.half_open, cb.state());
}

test "CircuitBreaker: abandonProbe releases a slot without pronouncing a verdict" {
    var tc: TestClock = .{};
    var cb: CircuitBreaker = .init(.{ .failure_threshold = 1, .cooldown_ms = 1000, .clock = tc.clock() });

    try testing.expect(!cb.abandonProbe()); // closed: nothing to abandon
    cb.onFailure();
    try testing.expect(!cb.abandonProbe()); // open: nothing to abandon

    tc.advanceMs(1000);
    try testing.expect(cb.allow());
    try testing.expect(!cb.allow()); // budget spent
    try testing.expect(cb.abandonProbe()); // caller admits it lost the result
    try testing.expect(!cb.abandonProbe()); // …and only the one slot existed
    try testing.expectEqual(.half_open, cb.state()); // NOT a success, NOT a failure
    try testing.expect(cb.allow()); // the freed slot is usable immediately
    cb.onSuccess();
    try testing.expectEqual(.closed, cb.state());
}

test "CircuitBreaker: probe bookkeeping across a re-open, the reclaim anchor, abandon while open" {
    // Mutation 2026-10-04: three survivors, one assertion each.
    var tc: TestClock = .{};
    var cb: CircuitBreaker = .init(.{
        .failure_threshold = 1,
        .cooldown_ms = 1000,
        .half_open_probes = 2,
        .probe_timeout_ms = 10,
        .clock = tc.clock(),
    });
    cb.onFailure();
    tc.advanceMs(1000);
    try testing.expect(cb.allow()); // half-open, probe 1
    cb.onSuccess(); // 1 of 2
    try testing.expect(cb.allow()); // probe 2
    cb.onFailure(); // re-opens with a fresh cooldown
    // `abandonProbe` doc: "No-op outside `half_open`" -- even with the old
    // half-open counters still lying around.
    try testing.expect(!cb.abandonProbe());

    // A new half-open episode starts from zero successes: the probe it just
    // admitted is outstanding, so it can be abandoned. (Keeping the old
    // success count made that probe look already answered.)
    tc.advanceMs(1000);
    try testing.expect(cb.allow());
    try testing.expect(cb.abandonProbe());

    // `last_admit_ns` is "the instant of the most recent probe admission":
    // admitting probe 2 at +8 ms moves the reclaim anchor, so at +12 ms
    // (4 ms after the last admission, under the 10 ms timeout) nothing is
    // reclaimed and the full budget still refuses.
    try testing.expect(cb.allow()); // probe 1 again, t = 0
    tc.advanceMs(8);
    try testing.expect(cb.allow()); // probe 2, t = 8 ms
    tc.advanceMs(4);
    try testing.expect(!cb.allow()); // t = 12 ms: no reclaim yet
}

const CountingClock = struct {
    reads: u32 = 0,
    fn now(ctx: ?*anyopaque) u64 {
        const self: *CountingClock = @ptrCast(@alignCast(ctx.?));
        self.reads += 1;
        return 0;
    }
    fn clock(self: *CountingClock) Clock {
        return .{ .ctx = self, .nowFn = now };
    }
};

test "Bulkhead: with max_wait_ns = 0 a full bulkhead never consults the clock" {
    // `Bulkhead.Options.clock` doc: "Never consulted when `max_wait_ns = 0`"
    // -- the non-blocking mode rejects without a time read. Mutation
    // 2026-10-04: entering the wait loop with a zero budget survived (it
    // still rejected, but read the clock).
    var cc: CountingClock = .{};
    var b: Bulkhead = .init(.{ .max_concurrent = 1, .clock = cc.clock() });
    try b.acquire();
    try testing.expectError(error.BulkheadFull, b.acquire());
    b.release();
    try testing.expectEqual(@as(u32, 0), cc.reads);
}

test "CircuitBreaker: probe_timeout_ms = 0 keeps the strict never-reclaim behaviour" {
    var tc: TestClock = .{};
    var cb: CircuitBreaker = .init(.{
        .failure_threshold = 1,
        .cooldown_ms = 1000,
        .probe_timeout_ms = 0,
        .clock = tc.clock(),
    });
    cb.onFailure();
    tc.advanceMs(1000);
    try testing.expect(cb.allow());
    tc.advanceMs(1_000_000); // an eternity
    try testing.expect(!cb.allow()); // opted out: the slot is held forever
    try testing.expect(cb.abandonProbe()); // the explicit escape hatch still works
    try testing.expect(cb.allow());
}

test "CircuitBreaker: late results while open are ignored" {
    var tc: TestClock = .{};
    var cb: CircuitBreaker = .init(.{ .failure_threshold = 1, .cooldown_ms = 1000, .clock = tc.clock() });

    cb.onFailure();
    tc.advanceMs(500);
    // Results of calls admitted before the trip straggle in mid-cooldown:
    // neither closes the breaker nor re-anchors the cooldown.
    cb.onSuccess();
    cb.onFailure();
    try testing.expectEqual(.open, cb.state());
    try testing.expect(!cb.allow());
    tc.advanceMs(500); // 1000 since the *original* trip
    try testing.expect(cb.allow());
}

test "CircuitBreaker: concurrent failure counting and probe admission stay exact" {
    const n_threads = 8;
    const iters = 1000;

    var tc: TestClock = .{};
    var cb: CircuitBreaker = .init(.{
        .failure_threshold = n_threads * iters + 1,
        .cooldown_ms = 1000,
        .half_open_probes = 3,
        .clock = tc.clock(),
    });

    // Part 1: every failure is counted, none lost, no premature trip.
    const Failer = struct {
        fn hammer(b: *CircuitBreaker) void {
            for (0..iters) |_| b.onFailure();
        }
    };
    var handles: [n_threads]std.Thread = undefined;
    for (&handles) |*h| h.* = try std.Thread.spawn(.{}, Failer.hammer, .{&cb});
    for (handles) |h| h.join();
    try testing.expectEqual(.closed, cb.state());
    try testing.expectEqual(n_threads * iters, cb.failureCount());
    cb.onFailure(); // the exact threshold-crossing failure
    try testing.expectEqual(.open, cb.state());

    // Part 2: racing allow() in half-open admits exactly half_open_probes.
    tc.advanceMs(1000);
    const Prober = struct {
        fn probe(b: *CircuitBreaker, admitted: *std.atomic.Value(u32)) void {
            if (b.allow()) _ = admitted.fetchAdd(1, .seq_cst);
        }
    };
    var admitted: std.atomic.Value(u32) = .init(0);
    for (&handles) |*h| h.* = try std.Thread.spawn(.{}, Prober.probe, .{ &cb, &admitted });
    for (handles) |h| h.join();
    try testing.expectEqual(3, admitted.load(.seq_cst));
    try testing.expectEqual(.half_open, cb.state());
}

// ── tests: bulkhead ─────────────────────────────────────────────────────────

/// Virtual sleep for the bulkhead's bounded wait: advances the shared
/// TestClock by the requested amount and can free a slot after a scripted
/// number of sleeps (a "concurrent release" in virtual time).
const BulkheadTestDelay = struct {
    tc: *TestClock,
    bh: ?*Bulkhead = null,
    /// Release one slot on the Nth sleep (0 = never release).
    release_after: usize = 0,
    sleeps: usize = 0,

    fn delay(t: *BulkheadTestDelay) Delay {
        return .{ .ctx = t, .sleepFn = sleepFn };
    }
    fn sleepFn(ctx: ?*anyopaque, ns: u64) void {
        const t: *BulkheadTestDelay = @ptrCast(@alignCast(ctx.?));
        t.tc.ns += ns;
        t.sleeps += 1;
        if (t.bh) |bh| {
            if (t.sleeps == t.release_after) bh.release();
        }
    }
};

test "Bulkhead: N acquires succeed, N+1 rejects immediately (non-blocking); release frees" {
    var bh: Bulkhead = .init(.{ .max_concurrent = 3 });
    try testing.expectEqual(0, bh.activeCount());
    try testing.expectEqual(3, bh.availableSlots());

    try bh.acquire();
    try bh.acquire();
    try bh.acquire();
    try testing.expectEqual(3, bh.activeCount());
    try testing.expectEqual(0, bh.availableSlots());

    // Full: rejects immediately, consumes nothing — repeatably.
    try testing.expectError(error.BulkheadFull, bh.acquire());
    try testing.expect(!bh.tryAcquire());
    try testing.expectError(error.BulkheadFull, bh.acquire());
    try testing.expectEqual(3, bh.activeCount());

    // One release frees exactly one slot.
    bh.release();
    try testing.expectEqual(1, bh.availableSlots());
    try testing.expect(bh.tryAcquire());
    try testing.expect(!bh.tryAcquire());

    // Full drain returns to zero and the slots stay reusable.
    bh.release();
    bh.release();
    bh.release();
    try testing.expectEqual(0, bh.activeCount());
    try bh.acquire();
    bh.release();
}

test "Bulkhead.run: slot released on success AND on the error path; full = fast-fail, op not invoked" {
    var bh: Bulkhead = .init(.{ .max_concurrent = 1 });

    // Success path: value passes through, slot returned.
    var ok: ScriptedOp = .{ .script = &.{.{ .result = 7 }} };
    try testing.expectEqual(7, try bh.run(&ok));
    try testing.expectEqual(0, bh.activeCount());

    // Error path: the operation's error propagates and the slot is still
    // returned (release on the error path).
    var bad: ScriptedOp = .{ .script = &.{.{ .result = error.Boom }} };
    try testing.expectError(error.Boom, bh.run(&bad));
    try testing.expectEqual(0, bh.activeCount());
    try testing.expectEqual(1, bad.calls);

    // Full bulkhead: BulkheadFull without invoking the operation at all.
    try bh.acquire();
    var never: ScriptedOp = .{ .script = &.{.{ .result = 9 }} };
    try testing.expectError(error.BulkheadFull, bh.run(&never));
    try testing.expectEqual(0, never.calls);
    bh.release();
    // And the bulkhead still works after all of the above.
    try testing.expectEqual(9, try bh.run(&never));
    try testing.expectEqual(0, bh.activeCount());
}

test "Bulkhead: bounded wait succeeds when a slot frees within the budget (virtual time)" {
    var tc: TestClock = .{};
    var td: BulkheadTestDelay = .{ .tc = &tc };
    var bh: Bulkhead = .init(.{
        .max_concurrent = 1,
        .max_wait_ns = 10 * std.time.ns_per_ms,
        .poll_ns = 1 * std.time.ns_per_ms,
        .clock = tc.clock(),
        .delay = td.delay(),
    });
    td.bh = &bh;
    td.release_after = 3; // a "concurrent" holder releases on the 3rd poll

    try testing.expect(bh.tryAcquire()); // saturate
    try bh.acquire(); // polls 3 times in virtual time, then takes the slot
    try testing.expectEqual(3, td.sleeps);
    try testing.expectEqual(3 * std.time.ns_per_ms, tc.ns); // well inside the budget
    try testing.expectEqual(1, bh.activeCount()); // handed over, not leaked
    bh.release();
}

test "Bulkhead: bounded wait times out with BulkheadFull when nobody releases (virtual time)" {
    var tc: TestClock = .{};
    var td: BulkheadTestDelay = .{ .tc = &tc }; // never releases
    var bh: Bulkhead = .init(.{
        .max_concurrent = 1,
        .max_wait_ns = 10 * std.time.ns_per_ms,
        .poll_ns = 1 * std.time.ns_per_ms,
        .clock = tc.clock(),
        .delay = td.delay(),
    });

    try testing.expect(bh.tryAcquire()); // saturate
    try testing.expectError(error.BulkheadFull, bh.acquire());
    try testing.expectEqual(10, td.sleeps); // exactly the budget, poll by poll
    try testing.expectEqual(10 * std.time.ns_per_ms, tc.ns); // full wait honored
    try testing.expectEqual(1, bh.activeCount()); // the holder's slot untouched
    bh.release();

    // The poll is clamped to the remaining budget: a poll_ns larger than
    // max_wait_ns still times out after exactly one (shortened) sleep.
    var tc2: TestClock = .{};
    var td2: BulkheadTestDelay = .{ .tc = &tc2 };
    var bh2: Bulkhead = .init(.{
        .max_concurrent = 1,
        .max_wait_ns = 5 * std.time.ns_per_ms,
        .poll_ns = 100 * std.time.ns_per_ms,
        .clock = tc2.clock(),
        .delay = td2.delay(),
    });
    try testing.expect(bh2.tryAcquire());
    try testing.expectError(error.BulkheadFull, bh2.acquire());
    try testing.expectEqual(1, td2.sleeps);
    try testing.expectEqual(5 * std.time.ns_per_ms, tc2.ns);
    bh2.release();
}

test "Bulkhead: blocking acquire is handed a slot freed by another thread (real time)" {
    var bh: Bulkhead = .init(.{
        .max_concurrent = 1,
        .max_wait_ns = 30 * std.time.ns_per_s, // success must come via the release
    });
    try testing.expect(bh.tryAcquire()); // saturate

    const Releaser = struct {
        fn run(b: *Bulkhead) void {
            Delay.blocking.sleep(20 * std.time.ns_per_ms);
            b.release();
        }
    };
    const t = try std.Thread.spawn(.{}, Releaser.run, .{&bh});
    defer t.join();

    try bh.acquire(); // woken well before the 30 s budget
    try testing.expectEqual(1, bh.activeCount());
    bh.release();
}

test "Bulkhead: concurrent run() never exceeds max_concurrent and leaks no slot" {
    const cap = 4;
    const n_threads = 8;
    const iters = 10_000;

    var bh: Bulkhead = .init(.{ .max_concurrent = cap });

    const Shared = struct {
        gauge: std.atomic.Value(i32) = .init(0),
        violations: std.atomic.Value(u32) = .init(0),
        successes: std.atomic.Value(u64) = .init(0),
        rejections: std.atomic.Value(u64) = .init(0),
    };
    // The wrapped operation itself audits the in-flight invariant — if run()
    // ever admits more than `cap` concurrently, the gauge catches it.
    const GaugeOp = struct {
        s: *Shared,
        pub fn call(self: *@This()) error{Never}!u32 {
            const cur = self.s.gauge.fetchAdd(1, .seq_cst) + 1;
            if (cur > cap) _ = self.s.violations.fetchAdd(1, .seq_cst);
            std.atomic.spinLoopHint(); // hold the slot briefly
            _ = self.s.gauge.fetchSub(1, .seq_cst);
            return 1;
        }
    };
    const Worker = struct {
        fn hammer(b: *Bulkhead, s: *Shared) void {
            for (0..iters) |_| {
                var op: GaugeOp = .{ .s = s };
                if (b.run(&op)) |_| {
                    _ = s.successes.fetchAdd(1, .seq_cst);
                } else |_| {
                    _ = s.rejections.fetchAdd(1, .seq_cst);
                }
            }
        }
    };

    var shared: Shared = .{};
    var handles: [n_threads]std.Thread = undefined;
    for (&handles) |*h| h.* = try std.Thread.spawn(.{}, Worker.hammer, .{ &bh, &shared });
    for (handles) |h| h.join();

    try testing.expectEqual(0, shared.violations.load(.seq_cst));
    try testing.expectEqual(0, shared.gauge.load(.seq_cst));
    try testing.expectEqual(0, bh.activeCount()); // every slot came back
    try testing.expect(shared.successes.load(.seq_cst) > 0);
}

// ── tests: retry backoff ────────────────────────────────────────────────────

test "Retry.nextDelay: exponential progression capped at max_delay_ms (no jitter)" {
    const r: Retry = .{ .base_delay_ms = 100, .factor = 2.0, .max_delay_ms = 1000 };
    try testing.expectEqual(100, r.nextDelay(1, null));
    try testing.expectEqual(200, r.nextDelay(2, null));
    try testing.expectEqual(400, r.nextDelay(3, null));
    try testing.expectEqual(800, r.nextDelay(4, null));
    try testing.expectEqual(1000, r.nextDelay(5, null)); // 1600 capped
    try testing.expectEqual(1000, r.nextDelay(60, null)); // f64 overflow-safe

    const constant: Retry = .{ .base_delay_ms = 250, .factor = 1.0, .max_delay_ms = 1000 };
    try testing.expectEqual(250, constant.nextDelay(1, null));
    try testing.expectEqual(250, constant.nextDelay(7, null));
}

test "Retry.nextDelay: jitter bounds and seeded determinism" {
    const full: Retry = .{ .base_delay_ms = 100, .factor = 2.0, .max_delay_ms = 10_000, .jitter = .full };
    const equal: Retry = .{ .base_delay_ms = 100, .factor = 2.0, .max_delay_ms = 10_000, .jitter = .equal };

    var prng = std.Random.DefaultPrng.init(1234);
    const rnd = prng.random();
    for (0..200) |i| {
        const attempt: u32 = @intCast(i % 6 + 1);
        const exp = full.expDelayMs(attempt);
        const df = full.nextDelay(attempt, rnd);
        try testing.expect(df <= exp); // full: [0, exp]
        const de = equal.nextDelay(attempt, rnd);
        try testing.expect(de >= exp / 2 and de <= exp); // equal: [exp/2, exp]
    }

    // Same seed, same sequence — jitter is reproducible under test.
    var prng_a = std.Random.DefaultPrng.init(42);
    var prng_b = std.Random.DefaultPrng.init(42);
    for (0..32) |i| {
        const attempt: u32 = @intCast(i % 6 + 1);
        try testing.expectEqual(
            full.nextDelay(attempt, prng_a.random()),
            full.nextDelay(attempt, prng_b.random()),
        );
    }

    // A jittered policy without an rng falls back to the plain schedule.
    try testing.expectEqual(200, full.nextDelay(2, null));
}

test "Retry.nextDelay: jitter defaults to .full — supplying randomness alone is enough to jitter (audit F2)" {
    // No `.jitter` set — relies entirely on `Retry`'s field default.
    const r: Retry = .{ .base_delay_ms = 1000, .factor = 1.0, .max_delay_ms = 1000 };
    var prng = std.Random.DefaultPrng.init(7);
    const rnd = prng.random();
    // Un-jittered (the old default, `.none`), every draw would be exactly
    // 1000 — `nextDelay` would never look at `rnd` at all. With the new
    // default (`.full`) and real entropy supplied, a uniform draw in
    // [0, 1000] lands strictly below the ceiling with overwhelming
    // probability at least once across 49 attempts (odds of all 49 landing
    // exactly on 1000 are ~(1/1001)^49) — proof the default flavor actually
    // took effect, not just that `nextDelay` ran.
    var saw_below_ceiling = false;
    for (1..50) |attempt| {
        const d = r.nextDelay(@intCast(attempt), rnd);
        try testing.expect(d <= 1000);
        if (d < 1000) saw_below_ceiling = true;
    }
    try testing.expect(saw_below_ceiling);
}

test "Deadline: expired/remaining through the injected clock" {
    var tc: TestClock = .{};
    const d: Deadline = .init(tc.clock(), 50);
    try testing.expect(!d.expired());
    try testing.expectEqual(50, d.remainingMs());
    tc.advanceMs(30);
    try testing.expectEqual(20, d.remainingMs());
    tc.advanceMs(20);
    try testing.expect(d.expired());
    try testing.expectEqual(0, d.remainingMs());
    tc.advanceMs(100);
    try testing.expectEqual(0, d.remainingMs()); // saturates, never wraps
}

// ── tests: run (composition) ────────────────────────────────────────────────

test "run: empty policy is a plain passthrough" {
    var ok: ScriptedOp = .{ .script = &.{.{ .result = 7 }} };
    try testing.expectEqual(7, try run(&ok, .{}));
    try testing.expectEqual(1, ok.calls);

    var bad: ScriptedOp = .{ .script = &.{.{ .result = error.Boom }} };
    try testing.expectError(error.Boom, run(&bad, .{}));
    try testing.expectEqual(1, bad.calls); // no retry without a policy
}

test "run: retries to success with exact backoff delays" {
    var td: TestDelay = .{};
    var op: ScriptedOp = .{ .script = &.{
        .{ .result = error.Boom },
        .{ .result = error.Boom },
        .{ .result = 7 },
    } };
    const got = try run(&op, .{
        .retry = .{ .max_attempts = 5, .base_delay_ms = 100, .factor = 2.0 },
        .delay = td.delay(),
    });
    try testing.expectEqual(7, got);
    try testing.expectEqual(3, op.calls);
    try testing.expectEqualSlices(u64, &.{ 100, 200 }, td.logged());
}

test "run: exhausts exactly max_attempts and returns the last error" {
    var td: TestDelay = .{};
    var op: ScriptedOp = .{ .script = &.{.{ .result = error.Boom }} };
    try testing.expectError(error.Boom, run(&op, .{
        .retry = .{ .max_attempts = 3, .base_delay_ms = 100, .factor = 2.0 },
        .delay = td.delay(),
    }));
    try testing.expectEqual(3, op.calls);
    try testing.expectEqualSlices(u64, &.{ 100, 200 }, td.logged()); // attempts-1 waits
}

fn onlyBoomRetryable(err: anyerror) bool {
    return err == error.Boom;
}

test "run: a non-retryable error returns immediately (no retry, no delay)" {
    var td: TestDelay = .{};
    var op: ScriptedOp = .{ .script = &.{.{ .result = error.Fatal }} };
    try testing.expectError(error.Fatal, run(&op, .{
        .retry = .{ .max_attempts = 5, .retryable = &onlyBoomRetryable },
        .delay = td.delay(),
    }));
    try testing.expectEqual(1, op.calls);
    try testing.expectEqual(0, td.count);
}

test "run: timeout fires on a slow attempt — even a slow success" {
    var tc: TestClock = .{};

    // A slow *success* past the budget is discarded and classified Timeout.
    var slow_ok: ScriptedOp = .{ .tc = &tc, .script = &.{.{ .result = 7, .takes_ms = 60 }} };
    try testing.expectError(error.Timeout, run(&slow_ok, .{ .timeout_ms = 50, .clock = tc.clock() }));

    // A slow failure is also a Timeout (the budget, not the error, decides).
    var slow_bad: ScriptedOp = .{ .tc = &tc, .script = &.{.{ .result = error.Boom, .takes_ms = 60 }} };
    try testing.expectError(error.Timeout, run(&slow_bad, .{ .timeout_ms = 50, .clock = tc.clock() }));

    // On-time work passes through untouched.
    var fast: ScriptedOp = .{ .tc = &tc, .script = &.{.{ .result = 7, .takes_ms = 50 }} };
    try testing.expectEqual(7, try run(&fast, .{ .timeout_ms = 50, .clock = tc.clock() }));
}

test "run: timeouts are retryable by default" {
    var tc: TestClock = .{};
    var td: TestDelay = .{};
    var op: ScriptedOp = .{
        .tc = &tc,
        .script = &.{
            .{ .result = 1, .takes_ms = 100 }, // too slow — discarded
            .{ .result = error.Boom, .takes_ms = 100 }, // too slow — Timeout, not Boom
            .{ .result = 7, .takes_ms = 10 },
        },
    };
    const got = try run(&op, .{
        .retry = .{ .max_attempts = 5, .base_delay_ms = 100, .factor = 2.0 },
        .timeout_ms = 50,
        .clock = tc.clock(),
        .delay = td.delay(),
    });
    try testing.expectEqual(7, got);
    try testing.expectEqual(3, op.calls);
    try testing.expectEqualSlices(u64, &.{ 100, 200 }, td.logged());
}

test "run: composition — M<threshold failures then success never trips the breaker" {
    var tc: TestClock = .{};
    var td: TestDelay = .{};
    var cb: CircuitBreaker = .init(.{ .failure_threshold = 5, .cooldown_ms = 1000, .clock = tc.clock() });
    var op: ScriptedOp = .{ .script = &.{
        .{ .result = error.Boom },
        .{ .result = error.Boom },
        .{ .result = error.Boom },
        .{ .result = 7 },
    } };
    const got = try run(&op, .{
        .breaker = cb.handle(),
        .retry = .{ .max_attempts = 10, .base_delay_ms = 10, .factor = 1.0 },
        .clock = tc.clock(),
        .delay = td.delay(),
    });
    try testing.expectEqual(7, got);
    try testing.expectEqual(4, op.calls);
    try testing.expectEqual(.closed, cb.state());
    try testing.expectEqual(0, cb.failureCount()); // the success reset the streak
}

test "run: composition — persistent failure trips mid-run, then fast-fails" {
    var tc: TestClock = .{};
    var td: TestDelay = .{};
    var cb: CircuitBreaker = .init(.{ .failure_threshold = 3, .cooldown_ms = 1000, .clock = tc.clock() });
    var op: ScriptedOp = .{ .script = &.{.{ .result = error.Boom }} };
    const policy: Policy = .{
        .breaker = cb.handle(),
        .retry = .{ .max_attempts = 10, .base_delay_ms = 10, .factor = 1.0 },
        .clock = tc.clock(),
        .delay = td.delay(),
    };

    // Attempts 1–3 fail and trip the breaker; attempt 4 is denied.
    try testing.expectError(error.CircuitOpen, run(&op, policy));
    try testing.expectEqual(3, op.calls);
    try testing.expectEqual(.open, cb.state());

    // Subsequent runs fast-fail without invoking the operation at all.
    try testing.expectError(error.CircuitOpen, run(&op, policy));
    try testing.expectEqual(3, op.calls);

    // After the cooldown, a healthy run probes and closes the breaker.
    tc.advanceMs(1000);
    var healthy: ScriptedOp = .{ .script = &.{.{ .result = 9 }} };
    try testing.expectEqual(9, try run(&healthy, policy));
    try testing.expectEqual(.closed, cb.state());
}

/// Operation that receives the cooperative deadline and records what it saw.
const DeadlineAwareOp = struct {
    tc: *TestClock,
    deadline: ?Deadline = null,
    seen_remaining_ms: u64 = 0,
    expired_after_work: bool = false,

    pub fn setDeadline(self: *DeadlineAwareOp, d: Deadline) void {
        self.deadline = d;
    }

    pub fn call(self: *DeadlineAwareOp) error{Never}!u32 {
        const d = self.deadline.?;
        self.seen_remaining_ms = d.remainingMs();
        self.tc.advanceMs(30); // simulate work
        self.expired_after_work = d.expired();
        return 1;
    }
};

test "run: the cooperative deadline reaches the operation via setDeadline" {
    var tc: TestClock = .{};
    var op: DeadlineAwareOp = .{ .tc = &tc };
    try testing.expectEqual(1, try run(&op, .{ .timeout_ms = 50, .clock = tc.clock() }));
    try testing.expectEqual(50, op.seen_remaining_ms); // full budget at call start
    try testing.expect(!op.expired_after_work); // 30 of 50 ms used

    // With a 20 ms budget the same 30 ms of work blows the deadline: the
    // operation could see it (`expired()` true) and `run` classifies the
    // late success as a Timeout.
    var op2: DeadlineAwareOp = .{ .tc = &tc };
    try testing.expectError(error.Timeout, run(&op2, .{ .timeout_ms = 20, .clock = tc.clock() }));
    try testing.expectEqual(20, op2.seen_remaining_ms);
    try testing.expect(op2.expired_after_work); // 30 > 20: op could have bailed
}

fn countedFetch(calls: *u32) error{Boom}!u32 {
    calls.* += 1;
    if (calls.* < 3) return error.Boom;
    return 40 + calls.*;
}

test "run: fn + ctx adapter (operation) composes like any operation" {
    var td: TestDelay = .{};
    var calls: u32 = 0;
    const got = try run(operation(&calls, countedFetch), .{
        .retry = .{ .max_attempts = 5, .base_delay_ms = 10, .factor = 1.0 },
        .delay = td.delay(),
    });
    try testing.expectEqual(43, got);
    try testing.expectEqual(3, calls);
    try testing.expectEqualSlices(u64, &.{ 10, 10 }, td.logged());
}

test "run: jittered delays stay within bounds and reproduce under one seed" {
    const retry: Retry = .{ .max_attempts = 4, .base_delay_ms = 100, .factor = 2.0, .jitter = .full };

    var logs: [2]TestDelay = .{ .{}, .{} };
    for (&logs) |*td| {
        var prng = std.Random.DefaultPrng.init(2026);
        var op: ScriptedOp = .{ .script = &.{.{ .result = error.Boom }} };
        try testing.expectError(error.Boom, run(&op, .{
            .retry = retry,
            .delay = td.delay(),
            .random = prng.random(),
        }));
        try testing.expectEqual(4, op.calls);
        try testing.expectEqual(3, td.count);
        for (td.logged(), 1..) |ms, attempt|
            try testing.expect(ms <= retry.expDelayMs(@intCast(attempt))); // full jitter: [0, exp]
    }
    try testing.expectEqualSlices(u64, logs[0].logged(), logs[1].logged());
}

test "RateCircuitBreaker: a busy endpoint with interleaved successes trips on the failure rate" {
    var tc: TestClock = .{};
    var cb: RateCircuitBreaker(10) = .init(.{ .failure_rate_pct = 50, .minimum_calls = 10, .clock = tc.clock() });
    // success, failure, success, failure ... a consecutive breaker never trips on this.
    for (0..9) |i| {
        try testing.expect(cb.allow());
        if (i % 2 == 0) cb.onSuccess() else cb.onFailure();
    }
    try testing.expectEqual(.closed, cb.state()); // 9 calls < minimum_calls
    try testing.expect(cb.allow());
    cb.onFailure(); // 5 of 10 failed = 50 %
    try testing.expectEqual(.open, cb.state());
    try testing.expectEqual(@as(u64, 5), cb.counts().failures);
}

test "RateCircuitBreaker: a time window forgets calls older than n buckets; slow calls trip on their own rate" {
    var tc: TestClock = .{};
    var cb: RateCircuitBreaker(4) = .init(.{
        .kind = .time,
        .bucket_ms = 1_000,
        .minimum_calls = 3,
        .failure_rate_pct = 60,
        .slow_call_duration_ms = 200,
        .slow_call_rate_pct = 100,
        .clock = tc.clock(),
    });
    cb.onFailure();
    cb.onFailure();
    tc.advanceMs(4_000); // both failures leave the 4 s window
    try testing.expectEqual(@as(u32, 0), cb.counts().window_calls);
    cb.onSuccess();
    cb.onFailure();
    try testing.expectEqual(.closed, cb.state()); // 2 calls < minimum_calls
    // Three successes, every one slower than 200 ms: no failure-rate trip
    // (1 of 5 failed), but 100 % of... only 3 of 5 are slow, so no slow trip.
    for (0..3) |_| cb.record(.success, 250 * std.time.ns_per_ms);
    try testing.expectEqual(.closed, cb.state());
    try testing.expectEqual(@as(u32, 3), cb.counts().window_slow);
    tc.advanceMs(4_000);
    for (0..3) |_| cb.record(.success, 250 * std.time.ns_per_ms);
    try testing.expectEqual(.open, cb.state()); // 3 of 3 slow
}

test "CircuitBreaker: forceOpen latches until reset, disable admits everything; the listener sees each change" {
    const Seen = struct {
        log: [8][2]BreakerState = undefined,
        n: usize = 0,
        fn on(ctx: ?*anyopaque, from: BreakerState, to: BreakerState) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.log[self.n] = .{ from, to };
            self.n += 1;
        }
    };
    var seen: Seen = .{};
    var tc: TestClock = .{};
    var cb: CircuitBreaker = .init(.{
        .failure_threshold = 1,
        .cooldown_ms = 10,
        .clock = tc.clock(),
        .listener = .{ .ctx = &seen, .onStateChange = Seen.on },
    });
    cb.forceOpen();
    tc.advanceMs(1_000_000); // no cooldown thaws a latch
    try testing.expect(!cb.allow());
    try testing.expectEqual(.open, cb.state());
    try testing.expectEqual(.forced_open, cb.mode());
    cb.disable();
    for (0..5) |_| {
        try testing.expect(cb.allow());
        cb.onFailure(); // counted, never evaluated
    }
    try testing.expectEqual(.closed, cb.state());
    try testing.expectEqual(@as(u64, 5), cb.counts().failures);
    cb.reset();
    try testing.expect(cb.allow());
    cb.onFailure(); // threshold 1: trips
    try testing.expectEqualSlices([2]BreakerState, &.{
        .{ .closed, .open }, // forceOpen
        .{ .open, .closed }, // disable
        .{ .closed, .open }, // the trip after reset (reset itself: closed -> closed, no event)
    }, seen.log[0..seen.n]);
    try testing.expectEqual(@as(u64, 3), cb.counts().transitions);
}

test "CircuitBreaker: half-open closes on k of n probes; an ignored outcome frees its probe slot" {
    var tc: TestClock = .{};
    var cb: CircuitBreaker = .init(.{
        .failure_threshold = 1,
        .cooldown_ms = 10,
        .half_open_probes = 3,
        .half_open_required_successes = 2,
        .clock = tc.clock(),
    });
    cb.onFailure();
    tc.advanceMs(10);
    for (0..3) |_| try testing.expect(cb.allow());
    try testing.expect(!cb.allow()); // all three slots taken
    cb.record(.ignore, null); // a 404: says nothing about health
    try testing.expect(cb.allow()); // its slot came back
    cb.onFailure(); // 1 failed: 2 successes still reachable
    try testing.expectEqual(.half_open, cb.state());
    cb.onSuccess();
    cb.onSuccess();
    try testing.expectEqual(.closed, cb.state());
}

const PoliteOp = struct {
    script: []const anyerror!u16,
    i: usize = 0,
    pub fn call(self: *PoliteOp) !u16 {
        defer self.i += 1;
        return self.script[self.i];
    }
    /// A 503 inside a successful response is still a reason to retry.
    pub fn retryOnResult(_: *PoliteOp, status: *const u16) bool {
        return status.* == 503;
    }
    /// The server asked for 7 s.
    pub fn retryAfterMs(_: *PoliteOp) ?u64 {
        return 7_000;
    }
};

fn notFoundIsIgnored(err: anyerror) Outcome {
    return if (err == error.NotFound) .ignore else .failure;
}

test "run: retryOnResult, retryAfterMs (clamped), classify, the bulkhead and the on_retry listener" {
    var td: TestDelay = .{};
    var tc: TestClock = .{};
    var cb: CircuitBreaker = .init(.{ .failure_threshold = 10, .clock = tc.clock() });
    var bh: Bulkhead = .init(.{ .max_concurrent = 1 });
    const Retries = struct {
        n: u32 = 0,
        fn on(ctx: ?*anyopaque, _: u32, _: ?anyerror, _: u64) void {
            @as(*@This(), @ptrCast(@alignCast(ctx.?))).n += 1;
        }
    };
    var retries: Retries = .{};
    const policy: Policy = .{
        .breaker = cb.handle(),
        .bulkhead = &bh,
        .retry = .{ .max_attempts = 4, .base_delay_ms = 100, .max_delay_ms = 5_000, .jitter = .none },
        .clock = tc.clock(),
        .delay = td.delay(),
        .classify = notFoundIsIgnored,
        .on_retry = .{ .ctx = &retries, .onRetry = Retries.on },
    };
    var op: PoliteOp = .{ .script = &.{ 503, error.Unavailable, 200 } };
    try testing.expectEqual(@as(u16, 200), try run(&op, policy));
    try testing.expectEqualSlices(u64, &.{ 5_000, 5_000 }, td.logged()); // 7 s clamped to max_delay_ms
    try testing.expectEqual(@as(u32, 2), retries.n);
    try testing.expectEqual(@as(u64, 2), cb.counts().failures); // the 503 counted as one
    try testing.expectEqual(@as(u32, 0), bh.activeCount());

    var missing: PoliteOp = .{ .script = &.{error.NotFound} };
    try testing.expectError(error.NotFound, run(&missing, policy)); // ignored: no retry
    try testing.expectEqual(@as(usize, 1), missing.i);
    try testing.expectEqual(@as(u64, 1), cb.counts().ignored);

    _ = bh.tryAcquire(); // someone else holds the only slot
    var never: PoliteOp = .{ .script = &.{200} };
    try testing.expectError(error.BulkheadFull, run(&never, policy));
    try testing.expectEqual(@as(usize, 0), never.i);
}

test "run: max_elapsed_ms stops retrying when the next wait would overrun the budget" {
    var tc: TestClock = .{};
    const Slow = struct {
        clock: *TestClock,
        calls: u32 = 0,
        pub fn call(self: *@This()) error{Down}!u8 {
            self.calls += 1;
            self.clock.advanceMs(300);
            return error.Down;
        }
    };
    // Waits pass on the same virtual clock.
    const Wait = struct {
        fn sleep(ctx: ?*anyopaque, ns: u64) void {
            @as(*TestClock, @ptrCast(@alignCast(ctx.?))).ns += ns;
        }
    };
    var op: Slow = .{ .clock = &tc };
    try testing.expectError(error.Down, run(&op, .{
        .retry = .{ .max_attempts = 10, .base_delay_ms = 100, .factor = 1, .jitter = .none, .max_elapsed_ms = 1_000 },
        .clock = tc.clock(),
        .delay = .{ .ctx = &tc, .sleepFn = Wait.sleep },
    }));
    // 300 + 100 + 300 + 100 + 300 = 1100 > 1000: the third wait is not made.
    try testing.expectEqual(@as(u32, 3), op.calls);
}

test "Retry.nextDelayFrom: the same bits give the same delay as nextDelay through std.Random" {
    const r: Retry = .{ .base_delay_ms = 100, .jitter = .proportional, .jitter_factor = 0.5 };
    var a = std.Random.DefaultPrng.init(42);
    var b = std.Random.DefaultPrng.init(42);
    for (1..12) |k| {
        const d = r.nextDelayFrom(@intCast(k), b.random().int(u64));
        try testing.expectEqual(r.nextDelay(@intCast(k), a.random()), d);
        const plain = r.nextDelayFrom(@intCast(k), null);
        try testing.expect(d >= plain - plain / 2 and d <= @min(r.max_delay_ms, plain + plain / 2));
    }
}

test {
    _ = @import("model_test.zig");
}
