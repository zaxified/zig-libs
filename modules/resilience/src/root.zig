// SPDX-License-Identifier: MIT

//! resilience — client-side fault tolerance for calling flaky upstreams:
//! **circuit breaker + retry-with-backoff + timeout**, generic over any
//! fallible operation. std-only — it wraps an arbitrary operation; the
//! caller composes it with `http.Client` (or anything else that can fail).
//!
//! Layers (each usable on its own):
//! - `CircuitBreaker` — `closed → open → half_open`; trips open after
//!   `failure_threshold` **consecutive** failures (count-based, Polly's
//!   classic breaker; resilience4j's failure-*rate* over a sliding window is
//!   the noted alternative — see the type doc). While open, `allow()`
//!   fast-fails until `cooldown_ms` elapses; then `half_open` admits up to
//!   `half_open_probes` probe calls — all probes succeeding closes the
//!   breaker, any probe failure re-opens it. Thread-safe (documented
//!   spinlock). Time via an injected `Clock`.
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
//! - `run(op, policy)` — one-call composition: breaker → retry → timeout
//!   around a generic operation (see "Composition" below).
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
//!     .breaker = &breaker,
//!     .retry = .{ .max_attempts = 3, .base_delay_ms = 100, .jitter = .full },
//!     .timeout_ms = 2_000,
//!     .random = prng.random(),
//! });
//! ```
//!
//! ## Composition (`run`) — ordering
//!
//! `breaker → retry → timeout`, applied **per attempt**:
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
    // Default Clock (posix clock_gettime errno form) and default Delay
    // (posix nanosleep) are posix; both are injectable, everything else is
    // pure logic.
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

/// Circuit breaker over consecutive failures (count-based, Polly's classic
/// breaker; the alternative — resilience4j's failure-rate over a sliding
/// call window, which tolerates interleaved successes — is a possible
/// future extension, noted, not built).
///
/// State machine:
/// - `closed` — calls flow; `failure_threshold` **consecutive** failures
///   (any success resets the streak) trip it to `open`.
/// - `open` — `allow()` returns false (fast-fail) until `cooldown_ms` has
///   elapsed since the trip; the first `allow()` after that moves to
///   `half_open` (the transition is lazy — `state()` reports `.open` until
///   someone asks to be admitted).
/// - `half_open` — up to `half_open_probes` calls are admitted, the rest
///   fast-fail. When that many successes accumulate the breaker closes; any
///   failure re-opens it with a fresh cooldown.
///
/// Usage contract: ask `allow()` before each call; when it returns true,
/// report the outcome with **exactly one** of `onSuccess()`/`onFailure()`.
/// A half-open probe whose outcome is never reported permanently occupies
/// its probe slot (nothing times probes out) — don't lose results. Results
/// reported while `open` (from calls admitted before the trip that finished
/// late) are ignored: they neither extend the cooldown nor count as probes.
///
/// Thread-safe: all methods may race from any thread (documented spinlock,
/// O(1) critical sections, no allocation). No deinit — the breaker owns no
/// resources.
pub const CircuitBreaker = struct {
    options: Options,
    lock: std.atomic.Mutex = .unlocked,
    cur_state: State = .closed,
    /// Closed only: current streak of consecutive failures.
    consecutive_failures: u32 = 0,
    /// Open only: instant of the trip (cooldown anchor).
    opened_at_ns: u64 = 0,
    /// Half-open only: probes admitted / succeeded so far.
    probes_admitted: u32 = 0,
    probes_succeeded: u32 = 0,

    pub const State = enum { closed, open, half_open };

    pub const Options = struct {
        /// Consecutive failures that trip `closed → open`. Must be ≥ 1.
        failure_threshold: u32 = 5,
        /// How long `open` fast-fails before probing (`half_open`).
        cooldown_ms: u64 = 30_000,
        /// Probe calls admitted while `half_open`; all of them must succeed
        /// to close the breaker (one failure re-opens). Must be ≥ 1.
        half_open_probes: u32 = 1,
        /// Time source — inject a fake for deterministic tests. The breaker
        /// never reads a wall clock on its own.
        clock: Clock = .monotonic,
    };

    pub fn init(options: Options) CircuitBreaker {
        std.debug.assert(options.failure_threshold >= 1);
        std.debug.assert(options.half_open_probes >= 1);
        return .{ .options = options };
    }

    /// May this call proceed? `false` = fast-fail now (breaker open, or all
    /// half-open probe slots taken). A `true` from a non-closed breaker
    /// admits a probe — report its outcome (see the usage contract).
    pub fn allow(cb: *CircuitBreaker) bool {
        lockSpin(&cb.lock);
        defer cb.lock.unlock();
        switch (cb.cur_state) {
            .closed => return true,
            .open => {
                const now_ns = cb.options.clock.now();
                if (now_ns -| cb.opened_at_ns < cb.options.cooldown_ms *| std.time.ns_per_ms)
                    return false;
                // Cooldown over: become half-open and admit this caller as
                // the first probe.
                cb.cur_state = .half_open;
                cb.probes_admitted = 1;
                cb.probes_succeeded = 0;
                return true;
            },
            .half_open => {
                if (cb.probes_admitted >= cb.options.half_open_probes) return false;
                cb.probes_admitted += 1;
                return true;
            },
        }
    }

    /// Report a successful call. Closed: resets the failure streak.
    /// Half-open: counts the probe; once all `half_open_probes` succeeded,
    /// closes. Open: ignored (late result — see the usage contract).
    pub fn onSuccess(cb: *CircuitBreaker) void {
        lockSpin(&cb.lock);
        defer cb.lock.unlock();
        switch (cb.cur_state) {
            .closed => cb.consecutive_failures = 0,
            .half_open => {
                cb.probes_succeeded += 1;
                if (cb.probes_succeeded >= cb.options.half_open_probes) {
                    cb.cur_state = .closed;
                    cb.consecutive_failures = 0;
                }
            },
            .open => {},
        }
    }

    /// Report a failed call. Closed: extends the streak and trips to open
    /// at `failure_threshold`. Half-open: re-opens immediately with a fresh
    /// cooldown. Open: ignored (late result).
    pub fn onFailure(cb: *CircuitBreaker) void {
        lockSpin(&cb.lock);
        defer cb.lock.unlock();
        switch (cb.cur_state) {
            .closed => {
                cb.consecutive_failures += 1;
                if (cb.consecutive_failures >= cb.options.failure_threshold) cb.trip();
            },
            .half_open => cb.trip(),
            .open => {},
        }
    }

    /// Current state. Note the lazy `open → half_open` transition: after
    /// the cooldown this still reports `.open` until an `allow()` asks to
    /// probe.
    pub fn state(cb: *CircuitBreaker) State {
        lockSpin(&cb.lock);
        defer cb.lock.unlock();
        return cb.cur_state;
    }

    /// Current consecutive-failure streak (closed state; 0 otherwise) — an
    /// observability/testing aid.
    pub fn failureCount(cb: *CircuitBreaker) u32 {
        lockSpin(&cb.lock);
        defer cb.lock.unlock();
        return cb.consecutive_failures;
    }

    // Callee of onFailure — lock already held.
    fn trip(cb: *CircuitBreaker) void {
        cb.cur_state = .open;
        cb.opened_at_ns = cb.options.clock.now();
        cb.consecutive_failures = 0;
    }
};

fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
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
        while (true) {
            if (cur >= b.options.max_concurrent) return false;
            cur = b.in_flight.cmpxchgWeak(cur, cur + 1, .seq_cst, .seq_cst) orelse
                return true;
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
        while (true) {
            std.debug.assert(cur > 0); // release without a matching acquire
            if (cur == 0) return; // ReleaseFast: saturate, don't wrap
            cur = b.in_flight.cmpxchgWeak(cur, cur - 1, .seq_cst, .seq_cst) orelse
                return;
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
    /// The default only because randomness must be injected (Zig 0.16 std
    /// has no ambient entropy and this module has no hidden globals) —
    /// production callers with many clients should pass a seeded
    /// `std.Random` and pick `.full`.
    none,
    /// **Full jitter** (recommended): uniform in `[0, d]`. Best contention
    /// spread per AWS "Exponential Backoff And Jitter" (Brooker, 2015).
    full,
    /// Equal jitter: uniform in `[d/2, d]` — keeps at least half the
    /// backoff when a minimum spacing matters more than maximum spread.
    equal,
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
    jitter: Jitter = .none,
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
        std.debug.assert(attempt >= 1);
        std.debug.assert(r.factor >= 1.0 and std.math.isFinite(r.factor));
        const d = r.expDelayMs(attempt);
        const rnd = random orelse return d;
        return switch (r.jitter) {
            .none => d,
            .full => rnd.uintAtMost(u64, d),
            .equal => d / 2 + rnd.uintAtMost(u64, d - d / 2),
        };
    }

    /// The un-jittered exponential schedule (overflow-safe: anything that
    /// leaves f64's exact range lands on `max_delay_ms`).
    fn expDelayMs(r: Retry, attempt: u32) u64 {
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
    /// Shared breaker gating every attempt; null = no breaker. Outlives the
    /// call; one breaker per upstream, shared across threads, is the
    /// intended shape.
    breaker: ?*CircuitBreaker = null,
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
};

/// The result type `run(op, …)` returns for an operation of type `Op`:
/// the operation's own error union widened with `PolicyError`.
pub fn RunResult(comptime Op: type) type {
    const ret = CallReturn(Op);
    const info = @typeInfo(ret).error_union;
    return (info.error_set || PolicyError)!info.payload;
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

/// Run `op` under `policy`: breaker → retry → timeout, per attempt (see
/// the module doc for the exact ordering and the resilience4j note).
///
/// `op` is any value with a `call()` method returning an error union —
/// pass `&op` when `call` takes `*Self`. If the operation type declares
/// `pub fn setDeadline(self, d: Deadline) void` and a timeout is set, each
/// attempt's deadline is handed to it before the call (cooperative
/// cancellation).
///
/// Returns the first successful attempt's value, or: `error.CircuitOpen`
/// when the breaker refuses an attempt (never retried within this run),
/// `error.Timeout` for an over-budget attempt that exhausted the policy,
/// or the operation's own error. Retried attempts may repeat side effects —
/// only wrap idempotent work (the standard retry caveat).
pub fn run(op: anytype, policy: Policy) RunResult(@TypeOf(op)) {
    const T = OperationType(@TypeOf(op));
    const timeout_ns = policy.timeout_ms *| std.time.ns_per_ms;
    const max_attempts: u32 = if (policy.retry) |r| @max(1, r.max_attempts) else 1;

    var attempt: u32 = 1;
    while (true) : (attempt += 1) {
        if (policy.breaker) |cb| {
            if (!cb.allow()) return error.CircuitOpen;
        }
        if (comptime @hasDecl(T, "setDeadline")) {
            if (policy.timeout_ms != 0)
                op.setDeadline(Deadline.init(policy.clock, policy.timeout_ms));
        }

        const started_ns = policy.clock.now();
        const result = op.call();
        const timed_out = policy.timeout_ms != 0 and
            policy.clock.now() -| started_ns > timeout_ns;

        const failure = blk: {
            if (result) |value| {
                if (!timed_out) {
                    if (policy.breaker) |cb| cb.onSuccess();
                    return value;
                }
                break :blk error.Timeout; // too-late success = failure
            } else |err| {
                break :blk if (timed_out) error.Timeout else err;
            }
        };
        if (policy.breaker) |cb| cb.onFailure();

        if (attempt >= max_attempts) return failure;
        const retry = policy.retry.?; // max_attempts > 1 implies a retry policy
        if (!retry.retryable(failure)) return failure;
        const wait_ms = retry.nextDelay(attempt, policy.random);
        if (wait_ms != 0) policy.delay.sleep(wait_ms *| std.time.ns_per_ms);
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
        .breaker = &cb,
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
        .breaker = &cb,
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
