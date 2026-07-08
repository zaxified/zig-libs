// SPDX-License-Identifier: MIT

//! upstream — a load-balanced upstream pool with health: the piece an API
//! gateway needs to route calls across a backend fleet with failover. It
//! composes the siblings: per-upstream `resilience.CircuitBreaker` (passive
//! health), optional per-upstream `resilience.Bulkhead` (concurrency cap),
//! and active health checks through `probe`'s `Connector` seam.
//!
//! Layers (each usable on its own):
//! - **Registration** — `Pool.add(.{ .id, .address = "host:port", .weight })`
//!   builds the fleet: per-upstream breaker + optional bulkhead + counters.
//!   Bounded (`max_upstreams`); a malformed address is a typed error, never
//!   a panic.
//! - **`pick()`** — the next healthy upstream per the configured `Strategy`
//!   (`round_robin`, `random`, `weighted_round_robin`, `least_connections`,
//!   `ewma_latency`), SKIPPING any upstream that is marked down (active
//!   health), whose breaker refuses the call, or whose bulkhead is full;
//!   `null` when none qualifies. A successful pick is a full admission —
//!   it takes the bulkhead slot and the breaker admission — so **every
//!   successful `pick()` must be followed by exactly one `report()`**.
//! - **`report(u, ok, rtt_ns)`** — passive health: feeds the upstream's
//!   breaker (trips on consecutive failures), returns the bulkhead slot,
//!   decrements in-flight, and folds the RTT into the rolling latency +
//!   EWMA.
//! - **`healthTick(now_ns)`** — caller-driven active health: at most once
//!   per `health_interval_ns`, runs the injected `HealthChecker` against
//!   every upstream — a failing check marks it down (pick skips it), a
//!   passing check marks it up and doubles as the breaker's recovery probe
//!   (open → half_open → closed across ticks once the cooldown allows).
//!   No hidden clock — the caller passes `now_ns` (mirrors resilience/
//!   probe). The default checker shape is a TCP connect through any
//!   `probe.Connector` (see `ConnectorHealthChecker`); tests inject a fake.
//! - **`call(op, .{ .max_tries })`** — the gateway's route-+ -failover
//!   primitive: pick an upstream, run the caller's operation against it
//!   (`op.call(upstream)`), report the outcome; on failure try the next
//!   healthy upstream up to `max_tries`, returning the last operation error
//!   when the pool is exhausted (or `error.NoHealthyUpstream` when nothing
//!   was pickable at all).
//!
//! ## Thread-safety
//!
//! Registration (`add`) and `deinit` are setup/teardown — single-owner,
//! complete them before concurrent use. After that, `pick`/`report`/`call`/
//! `healthTick`/stats may race from any thread: strategy state (cursor,
//! PRNG, smooth-WRR credits, latency) lives under a pool spinlock (the
//! documented `std.atomic.Mutex` pattern of the resilience sibling);
//! counters are atomics; breaker/bulkhead synchronize themselves. The
//! injected `HealthChecker` runs outside the pool lock (it may do I/O).
//!
//! ## Usage
//!
//! ```zig
//! var pool: upstream.Pool = .init(gpa, .{
//!     .strategy = .least_connections,
//!     .breaker = .{ .failure_threshold = 5, .cooldown_ms = 30_000 },
//!     .max_per_upstream = 64,
//!     .seed = boot_entropy,
//! });
//! defer pool.deinit();
//! _ = try pool.add(.{ .id = "api-1", .address = "10.0.0.1:8080" });
//! _ = try pool.add(.{ .id = "api-2", .address = "10.0.0.2:8080", .weight = 2 });
//!
//! const Fetch = struct {
//!     pub fn call(self: *@This(), u: *upstream.Upstream) !u16 {
//!         _ = self;
//!         return doRequest(u.address); // 5xx → return error.UpstreamDown
//!     }
//! };
//! var op: Fetch = .{};
//! const status = try pool.call(&op, .{ .max_tries = 3 });
//! ```
//!
//! Provenance: clean-room — models the upstream-cluster behavior of Envoy
//! (Apache-2.0) and HAProxy (documented behavior only): health-checked
//! member set, pluggable load-balancing policy, per-member circuit breaking
//! and concurrency caps. Round-robin, smooth weighted round-robin (the
//! nginx algorithm), least-connections and EWMA latency balancing are
//! public, decades-old techniques. No third-party source consulted or
//! copied. See ../../NOTICE.

const std = @import("std");
const resilience = @import("resilience");
const probe = @import("probe");

const Allocator = std.mem.Allocator;

pub const meta = .{
    .status = .gap, // no pure-Zig LB upstream pool with health + failover exists
    .platform = .any, // pure logic; health I/O goes through the injected seam
    .role = .client,
    // pick/report/call/healthTick internally synchronized (pool spinlock +
    // atomics); add/deinit are single-owner setup/teardown.
    .concurrency = .threadsafe,
    .model_after = "Envoy/HAProxy upstream cluster + resilience4j Bulkhead",
    .deps = .{ "resilience", "probe" },
};

// ── model ───────────────────────────────────────────────────────────────────

/// How `pick()` chooses among the healthy upstreams.
pub const Strategy = enum {
    /// Strict rotation over the healthy set (Envoy/HAProxy default).
    round_robin,
    /// Uniform over the healthy set, from a seeded PRNG (`Options.seed`) —
    /// Zig 0.16 std has no ambient entropy and this module has no hidden
    /// globals.
    random,
    /// Smooth weighted round-robin (the nginx algorithm): over any window
    /// of `sum(weights)` picks each healthy upstream is chosen exactly
    /// `weight` times, interleaved rather than bursty.
    weighted_round_robin,
    /// The healthy upstream with the fewest in-flight calls (ties → lowest
    /// registration index).
    least_connections,
    /// The healthy upstream with the lowest EWMA latency (`ewma_alpha`
    /// smoothing over reported RTTs; never-measured upstreams score 0 and
    /// are tried first — deliberate warm-up).
    ewma_latency,
};

/// One member of the fleet. Created by `Pool.add`; stable address for the
/// pool's lifetime (pick hands out `*Upstream`). `id` and `address.host`
/// are borrowed slices — the caller's storage must outlive the pool.
/// Mutate nothing directly; go through the Pool API.
pub const Upstream = struct {
    id: []const u8,
    address: probe.Target,
    weight: u32,

    /// Passive health: trips on consecutive reported failures.
    breaker: resilience.CircuitBreaker,
    /// Per-upstream concurrency cap (null = uncapped).
    bulkhead: ?resilience.Bulkhead,
    /// Active health verdict (`healthTick`): true = skip in `pick`.
    down: std.atomic.Value(bool) = .init(false),

    /// Calls admitted by `pick` and not yet `report`ed.
    in_flight: std.atomic.Value(u32) = .init(0),
    picks: std.atomic.Value(u64) = .init(0),
    failures: std.atomic.Value(u64) = .init(0),

    // Rolling latency over reported RTTs + smooth-WRR credit — guarded by
    // the pool lock.
    lat_count: u64 = 0,
    lat_sum_ns: u64 = 0,
    lat_min_ns: u64 = std.math.maxInt(u64),
    lat_max_ns: u64 = 0,
    ewma_ns: f64 = 0,
    wrr_current: i64 = 0,
};

/// What `Pool.add` takes. `id` must be unique in the pool; `address` is
/// `host:port` / `[v6]:port` (parsed via `probe.Target.parse` — Go
/// `SplitHostPort` semantics); `weight` is clamped to ≥ 1 and only
/// consulted by `.weighted_round_robin`.
pub const UpstreamSpec = struct {
    id: []const u8,
    address: []const u8,
    weight: u32 = 1,
};

// ── active health seam ──────────────────────────────────────────────────────

/// The active-health seam: one check of one upstream address within
/// `timeout_ns`, true = healthy. Injecting a fake makes `healthTick` fully
/// offline-testable; the production default shape is a TCP connect through
/// any `probe.Connector` (`ConnectorHealthChecker`). Keep it cheap-ish — it
/// runs synchronously inside `healthTick` (outside the pool lock).
pub const HealthChecker = struct {
    ctx: *anyopaque,
    checkFn: *const fn (ctx: *anyopaque, address: probe.Target, timeout_ns: u64) bool,

    pub fn check(hc: HealthChecker, address: probe.Target, timeout_ns: u64) bool {
        return hc.checkFn(hc.ctx, address, timeout_ns);
    }
};

/// Adapt any `probe.Connector` (e.g. `probe.LiveConnector` for the real
/// network) into a `HealthChecker`: healthy = the TCP handshake completed
/// (`.up`) — refused/timeout/error all count as down. Hold one and pass
/// `healthChecker()` to `Options`; it must outlive the pool.
pub const ConnectorHealthChecker = struct {
    conn: probe.Connector,

    pub fn healthChecker(self: *ConnectorHealthChecker) HealthChecker {
        return .{ .ctx = self, .checkFn = checkImpl };
    }

    fn checkImpl(ctx: *anyopaque, address: probe.Target, timeout_ns: u64) bool {
        const self: *ConnectorHealthChecker = @ptrCast(@alignCast(ctx));
        return self.conn.connect(address, timeout_ns).status == .up;
    }
};

// ── options ─────────────────────────────────────────────────────────────────

pub const Options = struct {
    strategy: Strategy = .round_robin,
    /// Per-upstream breaker config (passive health). Inject a fake
    /// `.clock` here for deterministic tests — every upstream's breaker
    /// gets this same configuration.
    breaker: resilience.CircuitBreaker.Options = .{},
    /// Per-upstream concurrency cap (`resilience.Bulkhead`); 0 (default) =
    /// uncapped, no bulkhead is created.
    max_per_upstream: u32 = 0,
    /// PRNG seed for `.random` (and nothing else) — pass real entropy in
    /// production; a fixed seed makes tests reproducible.
    seed: u64 = 0,
    /// EWMA smoothing factor for `.ewma_latency`, in (0, 1] — higher =
    /// reacts faster to the latest RTT.
    ewma_alpha: f64 = 0.3,
    /// Active health checks; null (default) = passive only (`healthTick`
    /// is a no-op).
    health_checker: ?HealthChecker = null,
    /// Minimum spacing between effective `healthTick`s — ticks arriving
    /// earlier are no-ops. 0 = every tick runs.
    health_interval_ns: u64 = 10 * std.time.ns_per_s,
    /// Per-check budget handed to the `HealthChecker`.
    health_timeout_ns: u64 = 1 * std.time.ns_per_s,
    /// Stopwatch for the RTT that `call()` reports — inject a fake for
    /// deterministic tests. `pick`/`report`/`healthTick` never read it.
    clock: resilience.Clock = .monotonic,
    /// Hard bound on the fleet size (`add` rejects beyond it).
    max_upstreams: usize = 1024,
};

// ── the pool ────────────────────────────────────────────────────────────────

pub const AddError = error{ TooManyUpstreams, DuplicateId, OutOfMemory } ||
    probe.Target.ParseError;

/// The error `call()` adds on top of the operation's own error set.
pub const CallError = error{
    /// `pick()` found no admissible upstream and no attempt had failed yet
    /// (every upstream down, breaker-open, or bulkhead-full). When at least
    /// one attempt ran, `call` returns that last operation error instead.
    NoHealthyUpstream,
};

pub const CallOptions = struct {
    /// Upper bound on attempts (distinct upstreams are not guaranteed —
    /// with one healthy upstream every try lands on it). Must be ≥ 1;
    /// 0 is treated as 1.
    max_tries: u32 = 3,
};

pub const Pool = struct {
    gpa: Allocator,
    options: Options,
    upstreams: std.ArrayList(*Upstream) = .empty,
    /// Selection scratch for the candidate-elimination loop (capacity ==
    /// upstreams.len, grown by `add`) — guarded by `lock`.
    scratch: []*Upstream = &.{},
    prng: std.Random.DefaultPrng,
    lock: std.atomic.Mutex = .unlocked,
    rr_cursor: usize = 0,
    last_health_ns: ?u64 = null,

    pub fn init(gpa: Allocator, options: Options) Pool {
        std.debug.assert(options.ewma_alpha > 0 and options.ewma_alpha <= 1);
        return .{
            .gpa = gpa,
            .options = options,
            .prng = std.Random.DefaultPrng.init(options.seed),
        };
    }

    pub fn deinit(pool: *Pool) void {
        for (pool.upstreams.items) |u| pool.gpa.destroy(u);
        pool.upstreams.deinit(pool.gpa);
        pool.gpa.free(pool.scratch);
        pool.* = undefined;
    }

    /// Register one upstream. Setup-phase only (single-owner — complete all
    /// `add`s before concurrent `pick`/`call` use). The returned pointer is
    /// stable for the pool's lifetime. Typed errors, never a panic:
    /// `TooManyUpstreams` past `max_upstreams`, `DuplicateId`,
    /// `InvalidHostPort` for a malformed address.
    pub fn add(pool: *Pool, spec: UpstreamSpec) AddError!*Upstream {
        if (pool.upstreams.items.len >= pool.options.max_upstreams)
            return error.TooManyUpstreams;
        if (pool.getById(spec.id) != null) return error.DuplicateId;
        const target = try probe.Target.parse(spec.address);

        const u = try pool.gpa.create(Upstream);
        errdefer pool.gpa.destroy(u);
        u.* = .{
            .id = spec.id,
            .address = target,
            .weight = @max(1, spec.weight),
            .breaker = .init(pool.options.breaker),
            .bulkhead = if (pool.options.max_per_upstream != 0)
                resilience.Bulkhead.init(.{ .max_concurrent = pool.options.max_per_upstream })
            else
                null,
        };
        try pool.upstreams.append(pool.gpa, u);
        errdefer _ = pool.upstreams.pop();
        pool.scratch = try pool.gpa.realloc(pool.scratch, pool.upstreams.items.len);
        return u;
    }

    pub fn getById(pool: *Pool, id: []const u8) ?*Upstream {
        for (pool.upstreams.items) |u| {
            if (std.mem.eql(u8, u.id, id)) return u;
        }
        return null;
    }

    pub fn count(pool: *const Pool) usize {
        return pool.upstreams.items.len;
    }

    // ── pick ────────────────────────────────────────────────────────────

    /// The next upstream per the strategy, skipping every upstream that is
    /// marked down, whose breaker refuses, or whose bulkhead is full; null
    /// when none qualifies (shed/queue upstream of here — that is the
    /// signal). A non-null pick is a full admission (bulkhead slot +
    /// breaker admission + in-flight): **follow it with exactly one
    /// `report()`** — a lost report leaks the slot and, in a half-open
    /// breaker, the probe budget.
    pub fn pick(pool: *Pool) ?*Upstream {
        lockSpin(&pool.lock);
        defer pool.lock.unlock();
        return pool.pickLocked();
    }

    fn pickLocked(pool: *Pool) ?*Upstream {
        const items = pool.upstreams.items;
        const n = items.len;
        if (n == 0) return null;

        if (pool.options.strategy == .round_robin) {
            // Strict rotation: walk from the cursor, first admissible wins.
            for (0..n) |off| {
                const i = (pool.rr_cursor + off) % n;
                if (admit(items[i])) {
                    pool.rr_cursor = (i + 1) % n;
                    return items[i];
                }
            }
            return null;
        }

        // Candidate-elimination: select per strategy among the not-down
        // set; when the selected one's breaker/bulkhead refuses, drop it
        // and re-select among the rest.
        var len: usize = 0;
        for (items) |u| {
            if (u.down.load(.seq_cst)) continue;
            pool.scratch[len] = u;
            len += 1;
        }
        while (len > 0) {
            const idx = pool.selectIndex(pool.scratch[0..len]);
            const cand = pool.scratch[idx];
            if (admit(cand)) return cand;
            pool.scratch[idx] = pool.scratch[len - 1];
            len -= 1;
        }
        return null;
    }

    /// Strategy selection among `set` (non-empty, pool lock held).
    fn selectIndex(pool: *Pool, set: []*Upstream) usize {
        switch (pool.options.strategy) {
            .round_robin => unreachable, // handled inline in pickLocked
            .random => return pool.prng.random().uintLessThan(usize, set.len),
            .weighted_round_robin => {
                // Smooth WRR (nginx): everyone earns its weight, the
                // richest is chosen and pays back the total.
                var total: i64 = 0;
                var best: usize = 0;
                for (set, 0..) |c, i| {
                    c.wrr_current += c.weight;
                    total += c.weight;
                    if (c.wrr_current > set[best].wrr_current) best = i;
                }
                set[best].wrr_current -= total;
                return best;
            },
            .least_connections => {
                var best: usize = 0;
                for (set[1..], 1..) |c, i| {
                    if (c.in_flight.load(.seq_cst) < set[best].in_flight.load(.seq_cst))
                        best = i;
                }
                return best;
            },
            .ewma_latency => {
                var best: usize = 0;
                for (set[1..], 1..) |c, i| {
                    if (c.ewma_ns < set[best].ewma_ns) best = i;
                }
                return best;
            },
        }
    }

    // ── passive health / accounting ─────────────────────────────────────

    /// Report the outcome of a call admitted by `pick` — exactly once per
    /// successful pick. Feeds the breaker (passive health), returns the
    /// bulkhead slot, decrements in-flight, counts the failure, and (when
    /// `rtt_ns` is non-null) folds the RTT into the rolling latency + EWMA.
    pub fn report(pool: *Pool, u: *Upstream, ok: bool, rtt_ns: ?u64) void {
        if (ok) u.breaker.onSuccess() else {
            u.breaker.onFailure();
            _ = u.failures.fetchAdd(1, .monotonic);
        }
        if (u.bulkhead) |*bh| bh.release();
        // In-flight decrement: a report without a matching pick is a caller
        // bug — assert in Debug, saturate at 0 in release builds.
        var cur = u.in_flight.load(.seq_cst);
        while (true) {
            std.debug.assert(cur > 0);
            if (cur == 0) break;
            cur = u.in_flight.cmpxchgWeak(cur, cur - 1, .seq_cst, .seq_cst) orelse break;
        }

        if (rtt_ns) |rtt| {
            lockSpin(&pool.lock);
            defer pool.lock.unlock();
            u.lat_count += 1;
            u.lat_sum_ns +|= rtt;
            u.lat_min_ns = @min(u.lat_min_ns, rtt);
            u.lat_max_ns = @max(u.lat_max_ns, rtt);
            const rtt_f: f64 = @floatFromInt(rtt);
            u.ewma_ns = if (u.lat_count == 1)
                rtt_f
            else
                pool.options.ewma_alpha * rtt_f + (1.0 - pool.options.ewma_alpha) * u.ewma_ns;
        }
    }

    /// `report` by id (for callers that only carry the id across the call
    /// boundary); false = unknown id, nothing reported.
    pub fn reportById(pool: *Pool, id: []const u8, ok: bool, rtt_ns: ?u64) bool {
        const u = pool.getById(id) orelse return false;
        pool.report(u, ok, rtt_ns);
        return true;
    }

    // ── active health ───────────────────────────────────────────────────

    /// Caller-driven active health: no-op unless a `health_checker` is
    /// configured and `health_interval_ns` has elapsed since the last
    /// effective tick (per the caller-supplied `now_ns` — no hidden clock;
    /// call this from your event/accept loop). Each upstream is checked
    /// once: fail → marked down (pick skips it); pass → marked up, and the
    /// passing check doubles as the breaker's recovery probe — once the
    /// breaker's cooldown admits one, the probe success walks it
    /// open → half_open → closed across ticks, without risking a live
    /// request on a possibly-dead upstream.
    pub fn healthTick(pool: *Pool, now_ns: u64) void {
        const hc = pool.options.health_checker orelse return;
        {
            lockSpin(&pool.lock);
            defer pool.lock.unlock();
            if (pool.last_health_ns) |last| {
                if (now_ns -| last < pool.options.health_interval_ns) return;
            }
            pool.last_health_ns = now_ns;
        }
        // Checks run outside the lock (the checker may do real I/O); the
        // upstream list is registration-frozen by the `add` contract.
        for (pool.upstreams.items) |u| {
            if (hc.check(u.address, pool.options.health_timeout_ns)) {
                u.down.store(false, .seq_cst);
                if (u.breaker.state() != .closed) {
                    // Recovery probe: admissible only after the cooldown
                    // (allow() is a no-op false before that).
                    if (u.breaker.allow()) u.breaker.onSuccess();
                }
            } else {
                u.down.store(true, .seq_cst);
            }
        }
    }

    // ── failover call ───────────────────────────────────────────────────

    /// Route + failover: pick an upstream, run `op.call(upstream)` against
    /// it, `report` the outcome (with the RTT stopwatched on
    /// `Options.clock`); on failure try the next healthy upstream, up to
    /// `max_tries` attempts total. Returns the first success, the last
    /// operation error once picks are exhausted, or
    /// `error.NoHealthyUpstream` when nothing was pickable and no attempt
    /// ever ran. Retried attempts may repeat side effects — route only
    /// idempotent work through the failover (the standard retry caveat).
    ///
    /// `op` is any value with `pub fn call(self, u: *Upstream) E!T` — pass
    /// `&op` when `call` takes `*Self`.
    pub fn call(pool: *Pool, op: anytype, opts: CallOptions) CallResult(@TypeOf(op)) {
        const Err = @typeInfo(CallReturn(@TypeOf(op))).error_union.error_set;
        const max_tries = @max(1, opts.max_tries);

        var last_err: ?Err = null;
        var tries: u32 = 0;
        while (tries < max_tries) : (tries += 1) {
            const u = pool.pick() orelse break;
            const started_ns = pool.options.clock.now();
            if (op.call(u)) |value| {
                pool.report(u, true, pool.options.clock.now() -| started_ns);
                return value;
            } else |err| {
                pool.report(u, false, null);
                last_err = err;
            }
        }
        return last_err orelse error.NoHealthyUpstream;
    }

    // ── stats ───────────────────────────────────────────────────────────

    /// Point-in-time snapshot of one upstream.
    pub fn upstreamStats(pool: *Pool, u: *Upstream) UpstreamStats {
        const breaker_state = u.breaker.state();
        lockSpin(&pool.lock);
        defer pool.lock.unlock();
        return .{
            .id = u.id,
            .healthy = !u.down.load(.seq_cst) and breaker_state != .open,
            .breaker_state = breaker_state,
            .in_flight = u.in_flight.load(.seq_cst),
            .picks = u.picks.load(.seq_cst),
            .failures = u.failures.load(.seq_cst),
            .latency = .{
                .samples = u.lat_count,
                .min_ns = if (u.lat_count == 0) 0 else u.lat_min_ns,
                .avg_ns = if (u.lat_count == 0) 0 else u.lat_sum_ns / u.lat_count,
                .max_ns = u.lat_max_ns,
            },
        };
    }

    /// Point-in-time snapshot of the whole pool.
    pub fn stats(pool: *Pool) PoolStats {
        var s: PoolStats = .{ .upstreams = pool.upstreams.items.len };
        for (pool.upstreams.items) |u| {
            if (!u.down.load(.seq_cst) and u.breaker.state() != .open) s.healthy += 1;
            s.in_flight += u.in_flight.load(.seq_cst);
            s.picks += u.picks.load(.seq_cst);
            s.failures += u.failures.load(.seq_cst);
        }
        return s;
    }
};

/// Full admission of one candidate (bulkhead slot first — an unpaired
/// breaker admission would leak a half-open probe slot, an unpaired
/// bulkhead slot is returned on the spot).
fn admit(u: *Upstream) bool {
    if (u.down.load(.seq_cst)) return false;
    if (u.bulkhead) |*bh| {
        if (!bh.tryAcquire()) return false; // bulkhead full → skip
    }
    if (!u.breaker.allow()) {
        if (u.bulkhead) |*bh| bh.release();
        return false; // breaker open / probe budget spent → skip
    }
    _ = u.in_flight.fetchAdd(1, .seq_cst);
    _ = u.picks.fetchAdd(1, .monotonic);
    return true;
}

pub const UpstreamStats = struct {
    id: []const u8,
    /// Not marked down by active health, and the breaker is not open.
    healthy: bool,
    breaker_state: resilience.CircuitBreaker.State,
    in_flight: u32,
    picks: u64,
    failures: u64,
    latency: Latency,

    pub const Latency = struct {
        samples: u64,
        min_ns: u64,
        avg_ns: u64,
        max_ns: u64,
    };
};

pub const PoolStats = struct {
    upstreams: usize,
    healthy: usize = 0,
    in_flight: u64 = 0,
    picks: u64 = 0,
    failures: u64 = 0,
};

// ── operation-type plumbing (mirrors resilience.run) ────────────────────────

/// The result type `Pool.call(op, …)` returns for an operation of type
/// `Op`: the operation's own error union widened with `CallError`.
pub fn CallResult(comptime Op: type) type {
    const info = @typeInfo(CallReturn(Op)).error_union;
    return (info.error_set || CallError)!info.payload;
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
        else => @compileError("upstream.Pool.call: operation must be a container with a call() method, got " ++ @typeName(T)),
    }
    if (!@hasDecl(T, "call"))
        @compileError("upstream.Pool.call: operation type " ++ @typeName(T) ++ " has no call() method");
    const ret = @typeInfo(@TypeOf(T.call)).@"fn".return_type.?;
    if (@typeInfo(ret) != .error_union)
        @compileError("upstream.Pool.call: call() must return an error union, got " ++ @typeName(ret));
    return ret;
}

fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

// ── tests: deterministic scripted harness (no sockets, no real clock) ───────

const testing = std.testing;

/// Deterministic test clock (same shape as the resilience sibling's).
const TestClock = struct {
    ns: u64 = 0,

    fn clock(t: *TestClock) resilience.Clock {
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

/// Scripted active-health fake: per-host up/down state, flip-able mid-test;
/// counts checks so interval gating is assertable.
const FakeChecker = struct {
    entries: []Entry,
    calls: usize = 0,

    const Entry = struct { host: []const u8, up: bool };

    fn healthChecker(f: *FakeChecker) HealthChecker {
        return .{ .ctx = f, .checkFn = checkImpl };
    }
    fn checkImpl(ctx: *anyopaque, address: probe.Target, timeout_ns: u64) bool {
        _ = timeout_ns;
        const f: *FakeChecker = @ptrCast(@alignCast(ctx));
        f.calls += 1;
        for (f.entries) |e| {
            if (std.mem.eql(u8, e.host, address.host)) return e.up;
        }
        return false;
    }
    fn set(f: *FakeChecker, host: []const u8, up: bool) void {
        for (f.entries) |*e| {
            if (std.mem.eql(u8, e.host, host)) e.up = up;
        }
    }
};

const OpErr = error{UpstreamDown};

/// Scripted fake operation for `call()`: fails on the listed upstream ids,
/// succeeds elsewhere; records the order of upstreams it was run against.
const ScriptedCallOp = struct {
    down_ids: []const []const u8 = &.{},
    tried: [16][]const u8 = undefined,
    tried_len: usize = 0,

    pub fn call(self: *ScriptedCallOp, u: *Upstream) OpErr!u32 {
        self.tried[self.tried_len] = u.id;
        self.tried_len += 1;
        for (self.down_ids) |id| {
            if (std.mem.eql(u8, id, u.id)) return error.UpstreamDown;
        }
        return 7;
    }

    fn triedIds(self: *const ScriptedCallOp) []const []const u8 {
        return self.tried[0..self.tried_len];
    }
};

fn addThree(pool: *Pool) !void {
    _ = try pool.add(.{ .id = "a", .address = "10.0.0.1:80" });
    _ = try pool.add(.{ .id = "b", .address = "10.0.0.2:80" });
    _ = try pool.add(.{ .id = "c", .address = "10.0.0.3:80" });
}

/// pick + immediate ok-report — one routed call in zero time.
fn pickReport(pool: *Pool) ?*Upstream {
    const u = pool.pick() orelse return null;
    pool.report(u, true, null);
    return u;
}

test "add: parse errors, duplicate ids, and the fleet bound are typed errors" {
    var pool: Pool = .init(testing.allocator, .{ .max_upstreams = 2 });
    defer pool.deinit();

    try testing.expectEqual(null, pool.pick()); // empty pool → null, no panic
    try testing.expectError(error.InvalidHostPort, pool.add(.{ .id = "x", .address = "no-port" }));
    try testing.expectError(error.InvalidHostPort, pool.add(.{ .id = "x", .address = "host:99999" }));

    const a = try pool.add(.{ .id = "a", .address = "10.0.0.1:8080", .weight = 0 });
    try testing.expectEqual(1, a.weight); // weight clamped to ≥ 1
    try testing.expectEqualStrings("10.0.0.1", a.address.host);
    try testing.expectEqual(8080, a.address.port);
    try testing.expectError(error.DuplicateId, pool.add(.{ .id = "a", .address = "10.0.0.9:80" }));

    _ = try pool.add(.{ .id = "b", .address = "[::1]:443" });
    try testing.expectError(error.TooManyUpstreams, pool.add(.{ .id = "c", .address = "10.0.0.3:80" }));
    try testing.expectEqual(2, pool.count());
    try testing.expect(pool.getById("b") != null);
    try testing.expectEqual(null, pool.getById("nope"));
}

test "round_robin cycles the healthy upstreams in order" {
    var pool: Pool = .init(testing.allocator, .{});
    defer pool.deinit();
    try addThree(&pool);

    const expected = [_][]const u8{ "a", "b", "c", "a", "b", "c" };
    for (expected) |want|
        try testing.expectEqualStrings(want, pickReport(&pool).?.id);
}

test "a failing upstream trips its breaker and pick skips it; cooldown re-admits" {
    var tc: TestClock = .{};
    var pool: Pool = .init(testing.allocator, .{
        .breaker = .{ .failure_threshold = 2, .cooldown_ms = 1000, .clock = tc.clock() },
    });
    defer pool.deinit();
    _ = try pool.add(.{ .id = "a", .address = "10.0.0.1:80" });
    _ = try pool.add(.{ .id = "b", .address = "10.0.0.2:80" });

    // Fail "a" to its threshold (interleaved with healthy "b" picks).
    var failed: usize = 0;
    while (failed < 2) {
        const u = pool.pick().?;
        if (std.mem.eql(u8, u.id, "a")) {
            pool.report(u, false, null);
            failed += 1;
        } else {
            pool.report(u, true, null);
        }
    }
    try testing.expectEqual(.open, pool.getById("a").?.breaker.state());

    // While open, every pick lands on "b".
    for (0..4) |_| try testing.expectEqualStrings("b", pickReport(&pool).?.id);

    // After the cooldown, "a" is probed again; a probe success closes it.
    tc.advanceMs(1000);
    var saw_a = false;
    for (0..2) |_| {
        const u = pool.pick().?;
        if (std.mem.eql(u8, u.id, "a")) saw_a = true;
        pool.report(u, true, null);
    }
    try testing.expect(saw_a);
    try testing.expectEqual(.closed, pool.getById("a").?.breaker.state());
}

test "pick skips a bulkhead-full upstream and returns null when all are full" {
    var pool: Pool = .init(testing.allocator, .{ .max_per_upstream = 1 });
    defer pool.deinit();
    _ = try pool.add(.{ .id = "a", .address = "10.0.0.1:80" });
    _ = try pool.add(.{ .id = "b", .address = "10.0.0.2:80" });

    const a = pool.pick().?; // holds a's only slot
    try testing.expectEqualStrings("a", a.id);
    const b = pool.pick().?; // a is full → b
    try testing.expectEqualStrings("b", b.id);
    try testing.expectEqual(null, pool.pick()); // both full → null

    pool.report(a, true, null); // frees a's slot
    try testing.expectEqualStrings("a", pool.pick().?.id);
    pool.report(pool.getById("a").?, true, null);
    pool.report(b, true, null);
    try testing.expectEqual(0, pool.stats().in_flight); // nothing leaked
}

test "least_connections picks the least-loaded upstream" {
    var pool: Pool = .init(testing.allocator, .{ .strategy = .least_connections });
    defer pool.deinit();
    try addThree(&pool);

    // Nothing reported back yet → in-flight ramps: a(0), b(0), c(0) → ties
    // resolve to the lowest index, so a, b, c, then a again.
    const a1 = pool.pick().?;
    try testing.expectEqualStrings("a", a1.id);
    const b1 = pool.pick().?;
    try testing.expectEqualStrings("b", b1.id);
    const c1 = pool.pick().?;
    try testing.expectEqualStrings("c", c1.id);
    const a2 = pool.pick().?;
    try testing.expectEqualStrings("a", a2.id);

    // b finishes its call → b is now the least loaded.
    pool.report(b1, true, null);
    try testing.expectEqualStrings("b", pool.pick().?.id);

    pool.report(a1, true, null);
    pool.report(c1, true, null);
    pool.report(a2, true, null);
    pool.report(pool.getById("b").?, true, null);
    try testing.expectEqual(0, pool.stats().in_flight);
}

test "weighted_round_robin distributes exactly by weight (smooth WRR)" {
    var pool: Pool = .init(testing.allocator, .{ .strategy = .weighted_round_robin });
    defer pool.deinit();
    _ = try pool.add(.{ .id = "a", .address = "10.0.0.1:80", .weight = 1 });
    _ = try pool.add(.{ .id = "b", .address = "10.0.0.2:80", .weight = 2 });
    _ = try pool.add(.{ .id = "c", .address = "10.0.0.3:80", .weight = 3 });

    var counts = [3]u32{ 0, 0, 0 };
    var max_streak: u32 = 0;
    var streak: u32 = 0;
    var prev: u8 = 0;
    for (0..600) |_| {
        const u = pickReport(&pool).?;
        counts[u.id[0] - 'a'] += 1;
        if (u.id[0] == prev) streak += 1 else streak = 1;
        prev = u.id[0];
        max_streak = @max(max_streak, streak);
    }
    // 600 picks = 100 full weight windows of 6 → exactly proportional.
    try testing.expectEqual(100, counts[0]);
    try testing.expectEqual(200, counts[1]);
    try testing.expectEqual(300, counts[2]);
    // Smooth, not bursty: never more than ceil-ish runs of the same peer.
    try testing.expect(max_streak <= 2);
}

test "random: seeded and deterministic, covers all healthy, never picks a down one" {
    var seq_a: [12]u8 = undefined;
    var seq_b: [12]u8 = undefined;
    for ([_]*[12]u8{ &seq_a, &seq_b }) |seq| {
        var pool: Pool = .init(testing.allocator, .{ .strategy = .random, .seed = 42 });
        defer pool.deinit();
        try addThree(&pool);
        for (seq) |*slot| slot.* = pickReport(&pool).?.id[0];
    }
    // Same seed → same pick sequence (reproducible tests).
    try testing.expectEqualSlices(u8, &seq_a, &seq_b);

    var pool: Pool = .init(testing.allocator, .{ .strategy = .random, .seed = 7 });
    defer pool.deinit();
    try addThree(&pool);
    pool.getById("b").?.down.store(true, .seq_cst); // as healthTick would

    var picked = [3]u32{ 0, 0, 0 };
    for (0..120) |_| picked[pickReport(&pool).?.id[0] - 'a'] += 1;
    try testing.expect(picked[0] > 0);
    try testing.expectEqual(0, picked[1]); // down: never picked
    try testing.expect(picked[2] > 0);
}

test "ewma_latency prefers the historically fastest upstream" {
    var pool: Pool = .init(testing.allocator, .{ .strategy = .ewma_latency });
    defer pool.deinit();
    _ = try pool.add(.{ .id = "a", .address = "10.0.0.1:80" });
    _ = try pool.add(.{ .id = "b", .address = "10.0.0.2:80" });

    // Warm-up: unmeasured upstreams score 0 and get tried first.
    const a = pool.pick().?;
    try testing.expectEqualStrings("a", a.id);
    pool.report(a, true, 100 * std.time.ns_per_ms); // a is slow
    const b = pool.pick().?;
    try testing.expectEqualStrings("b", b.id); // b still unmeasured → next
    pool.report(b, true, 10 * std.time.ns_per_ms); // b is fast

    // From here on the fast one wins every time (as long as it stays fast).
    for (0..5) |_| {
        const u = pool.pick().?;
        try testing.expectEqualStrings("b", u.id);
        pool.report(u, true, 10 * std.time.ns_per_ms);
    }
}

test "call: fails over to the next healthy upstream and reports both outcomes" {
    var pool: Pool = .init(testing.allocator, .{
        .breaker = .{ .failure_threshold = 5, .cooldown_ms = 1000 },
    });
    defer pool.deinit();
    try addThree(&pool);

    var op: ScriptedCallOp = .{ .down_ids = &.{"a"} };
    const got = try pool.call(&op, .{ .max_tries = 3 });
    try testing.expectEqual(7, got);
    // Round-robin order: tried a (failed), then b (succeeded).
    try testing.expectEqual(2, op.triedIds().len);
    try testing.expectEqualStrings("a", op.triedIds()[0]);
    try testing.expectEqualStrings("b", op.triedIds()[1]);
    try testing.expectEqual(1, pool.getById("a").?.failures.load(.seq_cst));
    try testing.expectEqual(1, pool.getById("a").?.breaker.failureCount());
    try testing.expectEqual(0, pool.stats().in_flight); // every pick reported
}

test "call: max_tries bounds the attempts; the last error comes back" {
    var pool: Pool = .init(testing.allocator, .{});
    defer pool.deinit();
    try addThree(&pool);

    var op: ScriptedCallOp = .{ .down_ids = &.{ "a", "b", "c" } };
    try testing.expectError(error.UpstreamDown, pool.call(&op, .{ .max_tries = 2 }));
    try testing.expectEqual(2, op.triedIds().len); // stopped at the bound
}

test "call: when everything is down — last error, then NoHealthyUpstream" {
    var tc: TestClock = .{};
    var pool: Pool = .init(testing.allocator, .{
        .breaker = .{ .failure_threshold = 1, .cooldown_ms = 1000, .clock = tc.clock() },
    });
    defer pool.deinit();
    _ = try pool.add(.{ .id = "a", .address = "10.0.0.1:80" });
    _ = try pool.add(.{ .id = "b", .address = "10.0.0.2:80" });

    // Both upstreams fail; threshold 1 trips each breaker on first failure.
    var op: ScriptedCallOp = .{ .down_ids = &.{ "a", "b" } };
    try testing.expectError(error.UpstreamDown, pool.call(&op, .{ .max_tries = 5 }));
    try testing.expectEqual(2, op.triedIds().len); // a, b, then no pick left

    // Pool exhausted before any attempt → the pool-level error.
    try testing.expectEqual(null, pool.pick());
    var op2: ScriptedCallOp = .{};
    try testing.expectError(error.NoHealthyUpstream, pool.call(&op2, .{ .max_tries = 5 }));
    try testing.expectEqual(0, op2.triedIds().len);

    // Empty pool behaves the same.
    var empty: Pool = .init(testing.allocator, .{});
    defer empty.deinit();
    var op3: ScriptedCallOp = .{};
    try testing.expectError(error.NoHealthyUpstream, empty.call(&op3, .{}));
}

test "healthTick: a failing check marks down (pick skips), a passing one recovers" {
    var checker_entries = [_]FakeChecker.Entry{
        .{ .host = "10.0.0.1", .up = true },
        .{ .host = "10.0.0.2", .up = true },
    };
    var checker: FakeChecker = .{ .entries = &checker_entries };
    var pool: Pool = .init(testing.allocator, .{
        .health_checker = checker.healthChecker(),
        .health_interval_ns = 0, // every tick runs
    });
    defer pool.deinit();
    _ = try pool.add(.{ .id = "a", .address = "10.0.0.1:80" });
    _ = try pool.add(.{ .id = "b", .address = "10.0.0.2:80" });

    checker.set("10.0.0.1", false);
    pool.healthTick(0);
    try testing.expect(pool.getById("a").?.down.load(.seq_cst));
    for (0..3) |_| try testing.expectEqualStrings("b", pickReport(&pool).?.id);

    checker.set("10.0.0.1", true);
    pool.healthTick(1);
    try testing.expect(!pool.getById("a").?.down.load(.seq_cst));
    // Back in rotation.
    var saw_a = false;
    for (0..2) |_| {
        if (std.mem.eql(u8, pickReport(&pool).?.id, "a")) saw_a = true;
    }
    try testing.expect(saw_a);
}

test "healthTick: a recovered upstream walks the breaker open → half_open → closed" {
    var tc: TestClock = .{};
    var checker_entries = [_]FakeChecker.Entry{
        .{ .host = "10.0.0.1", .up = true },
    };
    var checker: FakeChecker = .{ .entries = &checker_entries };
    var pool: Pool = .init(testing.allocator, .{
        .breaker = .{ .failure_threshold = 1, .cooldown_ms = 1000, .clock = tc.clock() },
        .health_checker = checker.healthChecker(),
        .health_interval_ns = 0,
    });
    defer pool.deinit();
    const a = try pool.add(.{ .id = "a", .address = "10.0.0.1:80" });

    // Passive failure trips the breaker; pick refuses during the cooldown.
    pool.report(pool.pick().?, false, null);
    try testing.expectEqual(.open, a.breaker.state());
    try testing.expectEqual(null, pool.pick());

    // A passing check during the cooldown cannot probe yet (still open).
    pool.healthTick(tc.ns);
    try testing.expectEqual(.open, a.breaker.state());

    // After the cooldown, the passing active check IS the recovery probe.
    tc.advanceMs(1000);
    pool.healthTick(tc.ns);
    try testing.expectEqual(.closed, a.breaker.state());
    try testing.expectEqualStrings("a", pickReport(&pool).?.id); // serving again
}

test "healthTick: the interval gates effective ticks" {
    var checker_entries = [_]FakeChecker.Entry{
        .{ .host = "10.0.0.1", .up = true },
    };
    var checker: FakeChecker = .{ .entries = &checker_entries };
    var pool: Pool = .init(testing.allocator, .{
        .health_checker = checker.healthChecker(),
        .health_interval_ns = 1000,
    });
    defer pool.deinit();
    _ = try pool.add(.{ .id = "a", .address = "10.0.0.1:80" });

    pool.healthTick(0); // first tick always runs
    try testing.expectEqual(1, checker.calls);
    pool.healthTick(500); // too soon → no-op
    try testing.expectEqual(1, checker.calls);
    pool.healthTick(1000); // interval elapsed → runs
    try testing.expectEqual(2, checker.calls);
    pool.healthTick(1001); // anchored at the last effective tick
    try testing.expectEqual(2, checker.calls);
}

test "healthTick without a checker is a no-op" {
    var pool: Pool = .init(testing.allocator, .{});
    defer pool.deinit();
    _ = try pool.add(.{ .id = "a", .address = "10.0.0.1:80" });
    pool.healthTick(0);
    pool.healthTick(1_000_000_000);
    try testing.expectEqualStrings("a", pickReport(&pool).?.id);
}

test "stats: per-upstream and pool-level snapshots" {
    var tc: TestClock = .{};
    var pool: Pool = .init(testing.allocator, .{
        .breaker = .{ .failure_threshold = 2, .cooldown_ms = 1000, .clock = tc.clock() },
    });
    defer pool.deinit();
    _ = try pool.add(.{ .id = "a", .address = "10.0.0.1:80" });
    _ = try pool.add(.{ .id = "b", .address = "10.0.0.2:80" });

    const ms = std.time.ns_per_ms;
    // a: two successful calls (10 ms, 30 ms), b: two failures (breaker opens).
    var u = pool.pick().?; // a
    pool.report(u, true, 10 * ms);
    u = pool.pick().?; // b
    pool.report(u, false, null);
    u = pool.pick().?; // a
    pool.report(u, true, 30 * ms);
    u = pool.pick().?; // b
    pool.report(u, false, null);

    const sa = pool.upstreamStats(pool.getById("a").?);
    try testing.expect(sa.healthy);
    try testing.expectEqual(.closed, sa.breaker_state);
    try testing.expectEqual(0, sa.in_flight);
    try testing.expectEqual(2, sa.picks);
    try testing.expectEqual(0, sa.failures);
    try testing.expectEqual(2, sa.latency.samples);
    try testing.expectEqual(10 * ms, sa.latency.min_ns);
    try testing.expectEqual(20 * ms, sa.latency.avg_ns);
    try testing.expectEqual(30 * ms, sa.latency.max_ns);

    const sb = pool.upstreamStats(pool.getById("b").?);
    try testing.expect(!sb.healthy);
    try testing.expectEqual(.open, sb.breaker_state);
    try testing.expectEqual(2, sb.failures);
    try testing.expectEqual(0, sb.latency.samples);
    try testing.expectEqual(0, sb.latency.min_ns); // no samples → zeros, no max-int leak

    const ps = pool.stats();
    try testing.expectEqual(2, ps.upstreams);
    try testing.expectEqual(1, ps.healthy);
    try testing.expectEqual(0, ps.in_flight);
    try testing.expectEqual(4, ps.picks);
    try testing.expectEqual(2, ps.failures);
}

test "concurrent call(): per-upstream bulkhead cap is never exceeded, nothing leaks" {
    const cap = 2;
    const n_threads = 4;
    const iters = 2_000;

    var pool: Pool = .init(testing.allocator, .{
        .strategy = .least_connections,
        .max_per_upstream = cap,
    });
    defer pool.deinit();
    _ = try pool.add(.{ .id = "a", .address = "10.0.0.1:80" });
    _ = try pool.add(.{ .id = "b", .address = "10.0.0.2:80" });

    const Shared = struct {
        violations: std.atomic.Value(u32) = .init(0),
        successes: std.atomic.Value(u64) = .init(0),
    };
    // The operation audits the invariant from inside the admitted call:
    // in-flight on its upstream must never exceed the bulkhead cap.
    const AuditOp = struct {
        s: *Shared,
        pub fn call(self: *@This(), u: *Upstream) error{Never}!u32 {
            if (u.in_flight.load(.seq_cst) > cap)
                _ = self.s.violations.fetchAdd(1, .seq_cst);
            std.atomic.spinLoopHint(); // hold the slot briefly
            return 1;
        }
    };
    const Worker = struct {
        fn hammer(p: *Pool, s: *Shared) void {
            for (0..iters) |_| {
                var op: AuditOp = .{ .s = s };
                if (p.call(&op, .{ .max_tries = 2 })) |_| {
                    _ = s.successes.fetchAdd(1, .seq_cst);
                } else |_| {}
            }
        }
    };

    var shared: Shared = .{};
    var handles: [n_threads]std.Thread = undefined;
    for (&handles) |*h| h.* = try std.Thread.spawn(.{}, Worker.hammer, .{ &pool, &shared });
    for (handles) |h| h.join();

    try testing.expectEqual(0, shared.violations.load(.seq_cst));
    try testing.expect(shared.successes.load(.seq_cst) > 0);
    const ps = pool.stats();
    try testing.expectEqual(0, ps.in_flight); // every admission reported back
    try testing.expectEqual(2, ps.healthy);
}
