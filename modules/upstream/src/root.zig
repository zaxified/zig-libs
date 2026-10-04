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
//! Only `deinit` is single-owner teardown. `add`/`remove`/`drain`/`reap`
//! may run while the pool serves, and `pick`/`report`/`call`/
//! `healthTick`/stats may race from any thread: membership and strategy state (cursor,
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
//! copied. See ../../../NOTICE.

const std = @import("std");
const resilience = @import("resilience");
const probe = @import("probe");

const Allocator = std.mem.Allocator;

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Load-balanced upstream pool + failover — round-robin/weighted/least-conn/P2C/EWMA/consistent-hash ring, add/remove/drain while serving, per-upstream breaker+bulkhead, active+passive health checks",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any, // pure logic; health I/O goes through the injected seam
    .role = .client,
    // pick/report/call/healthTick and add/remove/drain/reap internally
    // synchronized (pool spinlock + atomics); deinit is single-owner teardown.
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
    /// Power of two choices (Envoy's `LEAST_REQUEST` default): two distinct
    /// healthy upstreams drawn at random from the seeded PRNG, the one with
    /// fewer in-flight calls wins (ties → the first drawn). Near
    /// least-connections quality without scanning the fleet, and no herd on
    /// the single least-loaded member. Weights are not consulted.
    least_request,
    /// Consistent hashing on a ring (Envoy `RING_HASH`, nginx `hash …
    /// consistent`): `pickByKey(key)` maps a key to the first ring point at or
    /// after `XxHash64(key)`; each upstream owns `weight ×
    /// ring_points_per_weight` points hashed from its `id`, so adding or
    /// removing one member moves only the keys it gains or loses. A key whose
    /// owner is not admissible walks on to the next distinct upstream on the
    /// ring. `pick()` without a key hashes a PRNG draw (Envoy's behaviour
    /// for a request without a hash key).
    ring_hash,
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
    /// Administratively drained (`Pool.drain`, or removed): `pick` skips it,
    /// calls already admitted finish and `report` normally.
    draining: std.atomic.Value(bool) = .init(false),
    /// `Pool.remove`d: no longer in the member list; freed by `Pool.reap`
    /// (or `deinit`) once nothing is in flight on it. Guarded by the pool lock.
    retired: bool = false,
    /// `healthTick` holds of a member while its check runs outside the lock;
    /// `reap` never frees a pinned upstream.
    pins: std.atomic.Value(u32) = .init(0),
    /// Scratch mark for one ring walk ("already refused"). Pool lock.
    ring_refused: bool = false,

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

/// Adapt any `probe.Connector` (use `probe.PosixConnector` for the real
/// network) into a `HealthChecker`: healthy = the TCP handshake completed
/// (`.up`) — refused/timeout/error all count as down. Hold one and pass
/// `healthChecker()` to `Options`; it must outlive the pool.
///
/// The connector choice is load-bearing here, not a preference: `healthTick`
/// runs each check inline, so a connector that cannot abort a connect lets a
/// handful of black-holed backends occupy workers for the OS default timeout
/// (measured 134 s per attempt through `probe.LiveConnector`).
/// `probe.PosixConnector` bounds each attempt to the `timeout_ns` passed here;
/// its `.literal_only` mode additionally keeps name resolution — which no
/// connect timeout can bound — out of the tick entirely.
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
    /// `.ring_hash`: ring points per unit of weight (nginx and ketama use
    /// 160). Scaled down, never below one point per upstream, when the ring
    /// would exceed `max_ring_points`.
    ring_points_per_weight: u32 = 160,
    /// `.ring_hash`: hard bound on the ring's size (16 bytes a point).
    max_ring_points: usize = 1 << 20,
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

/// A `pick()` outcome scoped for a `defer`-paired `report()` — see
/// `Pool.pickGuarded`'s doc comment for the intended usage and what this
/// does and does not guarantee (audit `upstream` F1).
pub const PickGuard = struct {
    pool: *Pool,
    upstream: *Upstream,

    /// Exactly `pool.report(upstream, ok, rtt_ns)` — see `Pool.report`'s doc
    /// for what each parameter does.
    pub fn report(g: PickGuard, ok: bool, rtt_ns: ?u64) void {
        g.pool.report(g.upstream, ok, rtt_ns);
    }
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
    /// `remove`d members still referenced (in flight or pinned); `reap`
    /// frees the idle ones.
    retired: std.ArrayList(*Upstream) = .empty,
    /// `.ring_hash`: the ring, sorted by hash; `idx` indexes `upstreams`.
    /// Rebuilt under the lock on every membership change.
    ring: []RingPoint = &.{},
    /// A `healthTick` is running its checks (outside the lock).
    health_busy: bool = false,

    pub fn init(gpa: Allocator, options: Options) Pool {
        std.debug.assert(options.ewma_alpha > 0 and options.ewma_alpha <= 1);
        return .{
            .gpa = gpa,
            .options = options,
            .prng = std.Random.DefaultPrng.init(options.seed),
        };
    }

    /// Frees every member and every retired one — nothing may be in flight.
    pub fn deinit(pool: *Pool) void {
        for (pool.upstreams.items) |u| pool.gpa.destroy(u);
        pool.upstreams.deinit(pool.gpa);
        for (pool.retired.items) |u| pool.gpa.destroy(u);
        pool.retired.deinit(pool.gpa);
        pool.gpa.free(pool.scratch);
        pool.gpa.free(pool.ring);
        pool.* = undefined;
    }

    /// Register one upstream — at setup or while the pool is serving (it
    /// takes the pool lock, and allocates under it). The returned pointer is
    /// stable until the member is `remove`d and then `reap`ed. Typed errors,
    /// never a panic: `TooManyUpstreams` past `max_upstreams`, `DuplicateId`
    /// (among current members — a removed id may be added again),
    /// `InvalidHostPort` for a malformed address.
    pub fn add(pool: *Pool, spec: UpstreamSpec) AddError!*Upstream {
        const target = try probe.Target.parse(spec.address);
        lockSpin(&pool.lock);
        defer pool.lock.unlock();
        if (pool.upstreams.items.len >= pool.options.max_upstreams)
            return error.TooManyUpstreams;
        if (pool.getByIdLocked(spec.id) != null) return error.DuplicateId;

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
        if (pool.scratch.len < pool.upstreams.items.len)
            pool.scratch = try pool.gpa.realloc(pool.scratch, pool.upstreams.items.len);
        try pool.rebuildRingLocked();
        return u;
    }

    /// Stop routing new calls to `u`; calls already admitted finish and
    /// report normally. Undo with `undrain`. Independent of active health:
    /// a drained upstream stays drained through passing checks.
    pub fn drain(pool: *Pool, u: *Upstream) void {
        _ = pool;
        u.draining.store(true, .seq_cst);
    }

    /// Route to a drained upstream again (not to a removed one).
    pub fn undrain(pool: *Pool, u: *Upstream) void {
        lockSpin(&pool.lock);
        defer pool.lock.unlock();
        if (!u.retired) u.draining.store(false, .seq_cst);
    }

    /// Take the member `id` out of the pool while it is serving: it is
    /// drained at once, leaves the member list (and the ring — only its keys
    /// move), and its memory stays valid for calls still in flight and for
    /// `report`s on it, until `reap` (or `deinit`) frees it. False = no such
    /// member. The id can be `add`ed again at once.
    pub fn remove(pool: *Pool, id: []const u8) error{OutOfMemory}!bool {
        lockSpin(&pool.lock);
        defer pool.lock.unlock();
        const items = pool.upstreams.items;
        const i = for (items, 0..) |u, k| {
            if (std.mem.eql(u8, u.id, id)) break k;
        } else return false;
        try pool.retired.ensureUnusedCapacity(pool.gpa, 1);
        const u = items[i];
        u.draining.store(true, .seq_cst);
        u.retired = true;
        _ = pool.upstreams.orderedRemove(i);
        pool.retired.appendAssumeCapacity(u);
        // Keep the rotation where it was: the member after the removed one
        // is next.
        if (pool.rr_cursor > i) pool.rr_cursor -= 1;
        if (pool.rr_cursor >= pool.upstreams.items.len) pool.rr_cursor = 0;
        // A smaller ring never needs more memory; on the impossible failure
        // the old ring is dropped and `.ring_hash` picks see an empty ring.
        pool.rebuildRingLocked() catch {
            pool.gpa.free(pool.ring);
            pool.ring = &.{};
        };
        return true;
    }

    /// Free every removed upstream that nothing references any more (no
    /// call in flight, no health check running on it); the number freed.
    /// After this, pointers to the freed members are dangling — call it from
    /// the owner that stopped handing them out.
    pub fn reap(pool: *Pool) usize {
        lockSpin(&pool.lock);
        defer pool.lock.unlock();
        var freed: usize = 0;
        var i: usize = 0;
        while (i < pool.retired.items.len) {
            const u = pool.retired.items[i];
            if (u.in_flight.load(.seq_cst) == 0 and u.pins.load(.seq_cst) == 0) {
                _ = pool.retired.swapRemove(i);
                pool.gpa.destroy(u);
                freed += 1;
            } else i += 1;
        }
        return freed;
    }

    /// Removed members not yet freed by `reap`.
    pub fn retiredCount(pool: *Pool) usize {
        lockSpin(&pool.lock);
        defer pool.lock.unlock();
        return pool.retired.items.len;
    }

    /// The current member `id`, or null. The pointer is valid until the
    /// member is removed and reaped.
    pub fn getById(pool: *Pool, id: []const u8) ?*Upstream {
        lockSpin(&pool.lock);
        defer pool.lock.unlock();
        return pool.getByIdLocked(id);
    }

    fn getByIdLocked(pool: *Pool, id: []const u8) ?*Upstream {
        for (pool.upstreams.items) |u| {
            if (std.mem.eql(u8, u.id, id)) return u;
        }
        return null;
    }

    /// Current members (removed ones not counted).
    pub fn count(pool: *const Pool) usize {
        // The lock is interior state; `count` stays callable on a const pool.
        const lock = @constCast(&pool.lock);
        lockSpin(lock);
        defer lock.unlock();
        return pool.upstreams.items.len;
    }

    // ── consistent-hash ring ────────────────────────────────────────────

    fn rebuildRingLocked(pool: *Pool) error{OutOfMemory}!void {
        if (pool.options.strategy != .ring_hash) return;
        const items = pool.upstreams.items;
        var total_weight: u64 = 0;
        for (items) |u| total_weight += u.weight;
        var points: usize = 0;
        for (items) |u| points += pool.ringPoints(u.weight, total_weight);
        const ring = try pool.gpa.alloc(RingPoint, points);
        var n: usize = 0;
        for (items, 0..) |u, idx| {
            const k = pool.ringPoints(u.weight, total_weight);
            for (0..k) |j| {
                ring[n] = .{ .hash = pointHash(u.id, j), .idx = @intCast(idx) };
                n += 1;
            }
        }
        std.mem.sortUnstable(RingPoint, ring, {}, RingPoint.lessThan);
        pool.gpa.free(pool.ring);
        pool.ring = ring;
    }

    /// Points of a member of `weight` in a fleet of `total_weight`:
    /// `weight × ring_points_per_weight`, or — when that would put more
    /// than `max_ring_points` on the ring — its proportional share of
    /// `max_ring_points`; never fewer than one. The ring is therefore at
    /// most `max_ring_points + members` long.
    fn ringPoints(pool: *const Pool, weight: u32, total_weight: u64) usize {
        const ppw: u128 = pool.options.ring_points_per_weight;
        const max: u128 = pool.options.max_ring_points;
        const k: u128 = if (@as(u128, total_weight) * ppw <= max)
            @as(u128, weight) * ppw
        else
            @as(u128, weight) * max / total_weight;
        return @intCast(@max(1, k));
    }

    /// The upstream for `key` under `.ring_hash` (see `Strategy.ring_hash`);
    /// for any other strategy this is `pick()`. Same admission contract as
    /// `pick`: a non-null result must be `report`ed exactly once.
    pub fn pickByKey(pool: *Pool, key: []const u8) ?*Upstream {
        if (pool.options.strategy != .ring_hash) return pool.pick();
        lockSpin(&pool.lock);
        defer pool.lock.unlock();
        return pool.pickRingLocked(std.hash.XxHash64.hash(0, key));
    }

    /// The member that owns `key` on the ring, admissible or not — for
    /// tests and for routing decisions made elsewhere. Null when the ring is
    /// empty or the strategy is not `.ring_hash`.
    pub fn ringOwner(pool: *Pool, key: []const u8) ?*Upstream {
        lockSpin(&pool.lock);
        defer pool.lock.unlock();
        if (pool.ring.len == 0) return null;
        const at = ringIndex(pool.ring, std.hash.XxHash64.hash(0, key));
        return pool.upstreams.items[pool.ring[at].idx];
    }

    fn pickRingLocked(pool: *Pool, h: u64) ?*Upstream {
        const ring = pool.ring;
        if (ring.len == 0) return null;
        const items = pool.upstreams.items;
        // Walk the ring from the key's point; each distinct upstream is
        // tried once (`ring_refused` marks the refused ones, `scratch` lists
        // them for the reset), so the walk is at most one lap: O(points).
        var refused: usize = 0;
        defer for (pool.scratch[0..refused]) |u| {
            u.ring_refused = false;
        };
        const start = ringIndex(ring, h);
        var off: usize = 0;
        while (off < ring.len and refused < items.len) : (off += 1) {
            const u = items[ring[(start + off) % ring.len].idx];
            if (u.ring_refused) continue;
            if (admit(u)) return u;
            u.ring_refused = true;
            pool.scratch[refused] = u;
            refused += 1;
        }
        return null;
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

    /// `pick()` wrapped in a value that scopes the mandatory `report()` call
    /// to a `defer` right where the pick happens, instead of two calls a
    /// later refactor can accidentally separate (audit F1 — the bare
    /// `pick`/`report` seam is an easy-to-misuse hazard for callers who
    /// don't go through `call()`, which already encapsulates the pairing
    /// correctly and does not need this).
    ///
    /// ```
    /// const g = pool.pickGuarded() orelse return error.NoHealthyUpstream;
    /// defer g.report(ok, rtt_ns); // set `ok`/`rtt_ns` before this fires
    /// var ok = false;
    /// var rtt_ns: ?u64 = null;
    /// // ... do the call, then set ok/rtt_ns before falling out of scope ...
    /// ```
    ///
    /// This does not (cannot — Zig has no destructors) *enforce* the
    /// discipline; it only makes the correct shape a single `defer` instead
    /// of a call the caller must remember to place on every exit path
    /// (including error returns) by hand. `g.upstream` is `pick()`'s
    /// return value; `g.report` is exactly `pool.report(g.upstream, ...)`.
    pub fn pickGuarded(pool: *Pool) ?PickGuard {
        const u = pool.pick() orelse return null;
        return .{ .pool = pool, .upstream = u };
    }

    fn pickLocked(pool: *Pool) ?*Upstream {
        const items = pool.upstreams.items;
        const n = items.len;
        if (n == 0) return null;

        if (pool.options.strategy == .ring_hash)
            return pool.pickRingLocked(pool.prng.random().int(u64));

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
            if (u.down.load(.seq_cst) or u.draining.load(.seq_cst)) continue;
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
            .round_robin, .ring_hash => unreachable, // handled inline in pickLocked
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
            .least_request => {
                if (set.len == 1) return 0;
                const r = pool.prng.random();
                const a = r.uintLessThan(usize, set.len);
                // A second, distinct draw: one of the other len-1 members.
                var b = r.uintLessThan(usize, set.len - 1);
                if (b >= a) b += 1;
                return if (set[b].in_flight.load(.seq_cst) < set[a].in_flight.load(.seq_cst)) b else a;
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

        // In-flight decrement LAST: it is the release of this call's hold
        // on `u` — once it reaches 0 a removed `u` may be freed by `reap`
        // on another thread, so nothing below may touch `u`. A report
        // without a matching pick is a caller bug — assert in Debug,
        // saturate at 0 in release builds.
        var cur = u.in_flight.load(.seq_cst);
        while (true) {
            std.debug.assert(cur > 0);
            if (cur == 0) break;
            cur = u.in_flight.cmpxchgWeak(cur, cur - 1, .seq_cst, .seq_cst) orelse break;
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
    ///
    /// Membership may change while the checks run: the tick works on a
    /// snapshot of the members taken under the lock, each pinned so `reap`
    /// cannot free it mid-check. One tick runs at a time — a tick arriving
    /// while another is checking is a no-op; so is one that cannot allocate
    /// its snapshot.
    pub fn healthTick(pool: *Pool, now_ns: u64) void {
        const hc = pool.options.health_checker orelse return;
        const snap: []*Upstream = blk: {
            lockSpin(&pool.lock);
            defer pool.lock.unlock();
            if (pool.health_busy) return;
            if (pool.last_health_ns) |last| {
                if (now_ns -| last < pool.options.health_interval_ns) return;
            }
            const snap = pool.gpa.dupe(*Upstream, pool.upstreams.items) catch return;
            pool.last_health_ns = now_ns;
            pool.health_busy = true;
            for (snap) |u| _ = u.pins.fetchAdd(1, .seq_cst);
            break :blk snap;
        };
        defer {
            lockSpin(&pool.lock);
            for (snap) |u| _ = u.pins.fetchSub(1, .seq_cst);
            pool.health_busy = false;
            pool.lock.unlock();
            pool.gpa.free(snap);
        }
        // Checks run outside the lock (the checker may do real I/O).
        for (snap) |u| {
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
            .healthy = !u.down.load(.seq_cst) and !u.draining.load(.seq_cst) and breaker_state != .open,
            .draining = u.draining.load(.seq_cst),
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
        lockSpin(&pool.lock);
        defer pool.lock.unlock();
        var s: PoolStats = .{ .upstreams = pool.upstreams.items.len, .retired = pool.retired.items.len };
        for (pool.upstreams.items) |u| {
            if (!u.down.load(.seq_cst) and !u.draining.load(.seq_cst) and u.breaker.state() != .open) s.healthy += 1;
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
    if (u.down.load(.seq_cst) or u.draining.load(.seq_cst)) return false;
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
    /// Not marked down by active health, not drained, and the breaker is
    /// not open.
    healthy: bool,
    /// Drained or removed (`Pool.drain`, `Pool.remove`).
    draining: bool = false,
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
    /// Current members.
    upstreams: usize,
    /// Removed members not yet freed by `reap`.
    retired: usize = 0,
    healthy: usize = 0,
    in_flight: u64 = 0,
    picks: u64 = 0,
    failures: u64 = 0,
};

/// One point of the `.ring_hash` ring.
pub const RingPoint = struct {
    hash: u64,
    idx: u32,

    fn lessThan(_: void, a: RingPoint, b: RingPoint) bool {
        return a.hash < b.hash or (a.hash == b.hash and a.idx < b.idx);
    }
};

/// Point `j` of member `id`: XxHash64 (seed 0) of `id ++ "-" ++ decimal(j)`
/// — a function of the id alone, so a member keeps its points across
/// rebuilds and address changes.
fn pointHash(id: []const u8, j: usize) u64 {
    var h = std.hash.XxHash64.init(0);
    h.update(id);
    var buf: [21]u8 = undefined;
    h.update(std.fmt.bufPrint(&buf, "-{d}", .{j}) catch unreachable);
    return h.final();
}

/// The first point with `hash >= h`, wrapping to 0 past the end.
fn ringIndex(ring: []const RingPoint, h: u64) usize {
    var lo: usize = 0;
    var hi: usize = ring.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (ring[mid].hash < h) lo = mid + 1 else hi = mid;
    }
    return if (lo == ring.len) 0 else lo;
}

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

test "pickGuarded: defer-scoped report survives an early error return where bare pick/report leaks (audit F1)" {
    // First, reproduce the hazard F1 describes with the bare seam: a
    // caller that does real work between pick() and report(), with an
    // early-return error path that forgets to call report() before
    // returning — an easy mistake, and exactly what F1 flags.
    {
        var pool: Pool = .init(testing.allocator, .{ .max_per_upstream = 1 });
        defer pool.deinit();
        _ = try pool.add(.{ .id = "a", .address = "10.0.0.1:80" });

        const BareWork = struct {
            fn run(pool_: *Pool, fail: bool) !void {
                const u = pool_.pick() orelse return error.NoHealthyUpstream;
                if (fail) return error.SimulatedFailure; // BUG: no report() here
                pool_.report(u, true, null);
            }
        };
        try testing.expectError(error.SimulatedFailure, BareWork.run(&pool, true));
        // The slot from the failed attempt was never released: a second
        // pick on this single-slot upstream finds nothing.
        try testing.expectError(error.NoHealthyUpstream, BareWork.run(&pool, false));
        try testing.expectEqual(1, pool.stats().in_flight); // leaked, as F1 describes
    }

    // Now the same shape through `pickGuarded`: the mandatory report is a
    // single `defer` right after the pick, so it fires on every exit path
    // (including the early error return) without the caller having to
    // remember to place a matching call on each one by hand.
    {
        var pool: Pool = .init(testing.allocator, .{ .max_per_upstream = 1 });
        defer pool.deinit();
        _ = try pool.add(.{ .id = "a", .address = "10.0.0.1:80" });

        const GuardedWork = struct {
            fn run(pool_: *Pool, fail: bool) !void {
                const g = pool_.pickGuarded() orelse return error.NoHealthyUpstream;
                var ok = false;
                defer g.report(ok, null);
                if (fail) return error.SimulatedFailure;
                ok = true;
            }
        };
        try testing.expectError(error.SimulatedFailure, GuardedWork.run(&pool, true));
        // No leak this time: the defer fired on the error return too, so
        // the slot is free again for the next pick.
        try GuardedWork.run(&pool, false);
        try testing.expectEqual(0, pool.stats().in_flight); // nothing leaked
    }
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

test "weighted_round_robin: equal-weight tie breaks to the lower registration index" {
    // The distribution test above only pins AGGREGATE counts over 600 picks,
    // which are conserved regardless of which peer wins a same-credit tie
    // (a mutation of the tie-break's `>` to `>=` was verified to leave that
    // test fully green). Equal weights make the very first pick a genuine
    // tie (both start at wrr_current 0, both gain the same credit) — pin
    // the deterministic winner directly, matching `least_connections`'
    // documented "ties → lowest registration index".
    var pool: Pool = .init(testing.allocator, .{ .strategy = .weighted_round_robin });
    defer pool.deinit();
    _ = try pool.add(.{ .id = "a", .address = "10.0.0.1:80", .weight = 1 });
    _ = try pool.add(.{ .id = "b", .address = "10.0.0.2:80", .weight = 1 });

    try testing.expectEqualStrings("a", pickReport(&pool).?.id);
    try testing.expectEqualStrings("b", pickReport(&pool).?.id);
    try testing.expectEqualStrings("a", pickReport(&pool).?.id);
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

// ── core (2026-10-04): membership while serving, ring hash, P2C ─────────────

test "remove while a call is in flight: the report still lands, reap frees only the idle" {
    var pool: Pool = .init(testing.allocator, .{});
    defer pool.deinit();
    try addThree(&pool);

    const a = pool.pick().?; // round robin: a, held
    try testing.expectEqualStrings("a", a.id);
    try testing.expect(try pool.remove("a"));
    try testing.expect(!try pool.remove("a")); // gone from the member list
    try testing.expectEqual(2, pool.count());
    try testing.expectEqual(1, pool.retiredCount());
    for (0..6) |_| try testing.expect(!std.mem.eql(u8, "a", pickReport(&pool).?.id));

    // In flight → not freed; the late report is safe and counted.
    try testing.expectEqual(0, pool.reap());
    pool.report(a, false, 5);
    try testing.expectEqual(1, a.failures.load(.seq_cst));
    try testing.expectEqual(1, pool.reap());
    try testing.expectEqual(0, pool.retiredCount());

    // The id is free again, at a new address.
    const a2 = try pool.add(.{ .id = "a", .address = "10.0.0.9:81" });
    try testing.expectEqual(81, a2.address.port);
    try testing.expectEqual(a2, pool.getById("a").?);
    try testing.expectEqual(3, pool.stats().upstreams);
}

test "remove keeps the rotation: the member after the removed one is next" {
    var pool: Pool = .init(testing.allocator, .{});
    defer pool.deinit();
    try addThree(&pool);
    try testing.expectEqualStrings("a", pickReport(&pool).?.id); // cursor → b
    try testing.expect(try pool.remove("a")); // [b, c]; cursor was past a
    try testing.expectEqualStrings("b", pickReport(&pool).?.id);
    try testing.expectEqualStrings("c", pickReport(&pool).?.id);
    try testing.expect(try pool.remove("c")); // cursor at 0 stays
    try testing.expectEqualStrings("b", pickReport(&pool).?.id);
    try testing.expect(try pool.remove("b"));
    try testing.expectEqual(null, pool.pick());
    try testing.expectEqual(3, pool.reap());
}

test "drain: skipped by every strategy, in-flight work finishes, undrain restores" {
    for ([_]Strategy{ .round_robin, .random, .weighted_round_robin, .least_connections, .ewma_latency, .least_request, .ring_hash }) |st| {
        var pool: Pool = .init(testing.allocator, .{ .strategy = st, .seed = 7 });
        defer pool.deinit();
        try addThree(&pool);
        const b = pool.getById("b").?;
        pool.drain(b);
        for (0..30) |i| {
            var kb: [8]u8 = undefined;
            const u = pool.pickByKey(std.fmt.bufPrint(&kb, "k{d}", .{i}) catch unreachable).?;
            try testing.expect(u != b);
            pool.report(u, true, null);
        }
        try testing.expect(!pool.upstreamStats(b).healthy);
        try testing.expect(pool.upstreamStats(b).draining);
        try testing.expectEqual(2, pool.stats().healthy);
        // Undrained, with the other two drained, b is the only choice left.
        pool.undrain(b);
        pool.drain(pool.getById("a").?);
        pool.drain(pool.getById("c").?);
        try testing.expectEqual(b, pickReport(&pool).?);
        try testing.expectEqual(b, pool.pickByKey("any").?);
        pool.report(b, true, null);
    }
}

test "healthTick pins its snapshot: a member removed mid-check is not freed under it" {
    // The checker removes and reaps "b" while the tick is checking it — the
    // check runs outside the pool lock, exactly where a concurrent owner
    // could do this.
    const Remover = struct {
        pool: *Pool,
        reaped_during: usize = 99,
        fn hc(r: *@This()) HealthChecker {
            return .{ .ctx = r, .checkFn = check };
        }
        fn check(ctx: *anyopaque, address: probe.Target, _: u64) bool {
            const r: *@This() = @ptrCast(@alignCast(ctx));
            if (std.mem.eql(u8, address.host, "10.0.0.2")) {
                _ = r.pool.remove("b") catch unreachable;
                r.reaped_during = r.pool.reap();
            }
            return true;
        }
    };
    var pool: Pool = .init(testing.allocator, .{ .health_interval_ns = 0 });
    defer pool.deinit();
    var rm: Remover = .{ .pool = &pool };
    pool.options.health_checker = rm.hc();
    try addThree(&pool);
    pool.healthTick(1);
    try testing.expectEqual(0, rm.reaped_during); // pinned by the tick
    try testing.expectEqual(1, pool.reap()); // unpinned after it
    try testing.expectEqual(2, pool.count());
}

// The expected owners below come from Python's `xxhash` package (a black-box
// XxHash64), building the same ring by the rule `pointHash` documents: points
// `xxh64(id ++ "-" ++ j, seed 0)` for j < weight × 160, sorted by (hash,
// member index), a key owned by the first point with hash ≥ xxh64(key).

test "ring_hash: owners match the Python xxhash oracle, and removal moves only the removed member's keys" {
    var pool: Pool = .init(testing.allocator, .{ .strategy = .ring_hash });
    defer pool.deinit();
    const ids = [_][]const u8{ "m0", "m1", "m2", "m3", "m4" };
    const addrs = [_][]const u8{ "10.0.1.0:80", "10.0.1.1:80", "10.0.1.2:80", "10.0.1.3:80", "10.0.1.4:80" };
    for (ids, addrs) |id, ad| _ = try pool.add(.{ .id = id, .address = ad });
    const want = [_][]const u8{ "m2", "m0", "m3", "m1", "m0", "m4", "m1", "m2" };
    for (want, 1..) |w, k| {
        var kb: [16]u8 = undefined;
        const key = std.fmt.bufPrint(&kb, "user-{d}", .{k}) catch unreachable;
        try testing.expectEqualStrings(w, pool.ringOwner(key).?.id);
        const u = pool.pickByKey(key).?;
        try testing.expectEqualStrings(w, u.id);
        pool.report(u, true, null);
    }
    try testing.expect(try pool.remove("m2"));
    const want2 = [_][]const u8{ "m0", "m0", "m3", "m1", "m0", "m4", "m1", "m1" };
    for (want2, 1..) |w, k| {
        var kb: [16]u8 = undefined;
        try testing.expectEqualStrings(w, pool.ringOwner(std.fmt.bufPrint(&kb, "user-{d}", .{k}) catch unreachable).?.id);
    }
}

test "ring_hash: minimal disruption over 5000 keys, both ways" {
    var pool: Pool = .init(testing.allocator, .{ .strategy = .ring_hash });
    defer pool.deinit();
    const ids = [_][]const u8{ "m0", "m1", "m2", "m3", "m4" };
    for (ids, 0..) |id, i| {
        var ab: [16]u8 = undefined;
        _ = try pool.add(.{ .id = id, .address = std.fmt.bufPrint(&ab, "10.0.2.{d}:80", .{i}) catch unreachable });
    }
    var before: [5000][]const u8 = undefined;
    for (&before, 0..) |*b, k| {
        var kb: [16]u8 = undefined;
        b.* = pool.ringOwner(std.fmt.bufPrint(&kb, "k{d}", .{k}) catch unreachable).?.id;
    }
    try testing.expect(try pool.remove("m3"));
    var moved: usize = 0;
    for (before, 0..) |b, k| {
        var kb: [16]u8 = undefined;
        const now = pool.ringOwner(std.fmt.bufPrint(&kb, "k{d}", .{k}) catch unreachable).?.id;
        if (std.mem.eql(u8, b, "m3")) {
            try testing.expect(!std.mem.eql(u8, now, "m3"));
            moved += 1;
        } else try testing.expectEqualStrings(b, now); // nobody else's key moved
    }
    try testing.expect(moved > 500 and moved < 1500); // ~1/5 of 5000
    // Adding a member takes keys only for itself.
    _ = try pool.add(.{ .id = "m5", .address = "10.0.2.5:80" });
    var gained: usize = 0;
    for (0..5000) |k| {
        var kb: [16]u8 = undefined;
        const key = std.fmt.bufPrint(&kb, "k{d}", .{k}) catch unreachable;
        const now = pool.ringOwner(key).?.id;
        const prev = if (std.mem.eql(u8, before[k], "m3")) null else before[k];
        if (std.mem.eql(u8, now, "m5")) gained += 1 else if (prev) |p| try testing.expectEqualStrings(p, now);
    }
    try testing.expect(gained > 500 and gained < 1500);
    _ = pool.reap();
}

test "ring_hash: weights 1:2:3 split 30000 keys exactly as the Python oracle does" {
    var pool: Pool = .init(testing.allocator, .{ .strategy = .ring_hash });
    defer pool.deinit();
    _ = try pool.add(.{ .id = "w1", .address = "10.0.3.1:80", .weight = 1 });
    _ = try pool.add(.{ .id = "w2", .address = "10.0.3.2:80", .weight = 2 });
    _ = try pool.add(.{ .id = "w3", .address = "10.0.3.3:80", .weight = 3 });
    try testing.expectEqual(@as(usize, 960), pool.ring.len);
    var counts = [_]usize{ 0, 0, 0 };
    for (0..30000) |k| {
        var kb: [16]u8 = undefined;
        const id = pool.ringOwner(std.fmt.bufPrint(&kb, "k{d}", .{k}) catch unreachable).?.id;
        counts[id[1] - '1'] += 1;
    }
    try testing.expectEqual([_]usize{ 4539, 9666, 15795 }, counts);
}

test "ring_hash: a down owner's keys walk to the next member; everyone else's stay" {
    var hosts = [_]FakeChecker.Entry{ .{ .host = "10.0.0.1", .up = true }, .{ .host = "10.0.0.2", .up = false }, .{ .host = "10.0.0.3", .up = true } };
    var fc: FakeChecker = .{ .entries = &hosts };
    var pool: Pool = .init(testing.allocator, .{ .strategy = .ring_hash, .health_checker = fc.healthChecker(), .health_interval_ns = 0 });
    defer pool.deinit();
    try addThree(&pool);
    pool.healthTick(1); // b down
    var b_keys: usize = 0;
    for (0..2000) |k| {
        var kb: [16]u8 = undefined;
        const key = std.fmt.bufPrint(&kb, "k{d}", .{k}) catch unreachable;
        const owner = pool.ringOwner(key).?;
        const got = pool.pickByKey(key).?;
        defer pool.report(got, true, null);
        if (std.mem.eql(u8, owner.id, "b")) {
            b_keys += 1;
            try testing.expect(got != owner);
        } else try testing.expectEqual(owner, got);
    }
    try testing.expect(b_keys > 300);
    // Every member refused → null, and the walk terminated.
    pool.drain(pool.getById("a").?);
    pool.drain(pool.getById("c").?);
    try testing.expectEqual(null, pool.pickByKey("k1"));
    try testing.expectEqual(null, pool.pick());
}

test "ring_hash: the ring is bounded by max_ring_points, every member keeps a point" {
    var pool: Pool = .init(testing.allocator, .{ .strategy = .ring_hash, .max_ring_points = 100 });
    defer pool.deinit();
    _ = try pool.add(.{ .id = "heavy", .address = "10.0.4.1:80", .weight = 1_000_000 });
    _ = try pool.add(.{ .id = "light", .address = "10.0.4.2:80", .weight = 1 });
    // heavy: 1e6 × 100 / 1 000 001 = 99 points; light: max(1, 0) = 1.
    try testing.expectEqual(@as(usize, 100), pool.ring.len);
    var light: usize = 0;
    for (pool.ring) |p| light += @intFromBool(p.idx == 1);
    try testing.expectEqual(@as(usize, 1), light);
}

test "least_request (P2C): the loaded member never wins a pair; one member is always chosen" {
    var pool: Pool = .init(testing.allocator, .{ .strategy = .least_request, .seed = 3 });
    defer pool.deinit();
    _ = try pool.add(.{ .id = "solo", .address = "10.0.5.1:80" });
    const s = pool.pick().?;
    try testing.expectEqualStrings("solo", s.id);
    pool.report(s, true, null);
    try testing.expect(try pool.remove("solo"));
    _ = pool.reap();
    try addThree(&pool);
    // Five calls held on a: a has more in flight than b or c, so in any
    // pair it loses — it is never picked while they are idle.
    var held: [5]*Upstream = undefined;
    const a = pool.getById("a").?;
    for (&held) |*h| {
        h.* = a;
        try testing.expect(admit(a));
    }
    var hits = [_]usize{ 0, 0, 0 };
    for (0..200) |_| {
        const u = pickReport(&pool).?;
        hits[u.id[0] - 'a'] += 1;
    }
    try testing.expectEqual(0, hits[0]);
    try testing.expect(hits[1] > 50 and hits[2] > 50);
    for (held) |h| pool.report(h, true, null);
}

// ── seeded model sweep: membership churn under every strategy ──────────────
//
// Random add/remove/drain/undrain/pick/report/healthTick/reap sequences,
// checked after every step against a model: a pick never returns a member
// that is removed, drained or down; the pool's in-flight count per member is
// exactly the number of picks the model holds; `reap` frees exactly the
// removed members with nothing held; nothing leaks (testing.allocator).

test "sweep: membership churn keeps every invariant under every strategy" {
    const strategies = [_]Strategy{ .round_robin, .random, .weighted_round_robin, .least_connections, .ewma_latency, .least_request, .ring_hash };
    var reach = struct { picks: usize = 0, removes: usize = 0, reaped: usize = 0, drained_skips: usize = 0, null_picks: usize = 0 }{};
    const id_names = [_][]const u8{ "u0", "u1", "u2", "u3", "u4", "u5" };
    const addr_names = [_][]const u8{ "10.9.0.0:80", "10.9.0.1:80", "10.9.0.2:80", "10.9.0.3:80", "10.9.0.4:80", "10.9.0.5:80" };
    for (0..140) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        const r = prng.random();
        var hosts: [6]FakeChecker.Entry = undefined;
        for (&hosts, addr_names) |*h, ad| h.* = .{ .host = ad[0..8], .up = true };
        var fc: FakeChecker = .{ .entries = &hosts };
        var pool: Pool = .init(testing.allocator, .{
            .strategy = strategies[seed % strategies.len],
            .seed = seed,
            .health_checker = fc.healthChecker(),
            .health_interval_ns = 0,
            .max_per_upstream = 3,
            .ring_points_per_weight = 8,
        });
        defer pool.deinit();
        var held: std.ArrayList(*Upstream) = .empty;
        defer held.deinit(testing.allocator);
        for (0..300) |_| {
            switch (r.uintLessThan(u8, 10)) {
                0 => {
                    const i = r.uintLessThan(usize, id_names.len);
                    _ = pool.add(.{ .id = id_names[i], .address = addr_names[i], .weight = r.intRangeAtMost(u32, 1, 4) }) catch |e| switch (e) {
                        error.DuplicateId => {},
                        else => return e,
                    };
                },
                1 => if (try pool.remove(id_names[r.uintLessThan(usize, id_names.len)])) {
                    reach.removes += 1;
                },
                2 => if (pool.getById(id_names[r.uintLessThan(usize, id_names.len)])) |u| {
                    if (r.boolean()) pool.drain(u) else pool.undrain(u);
                },
                3 => {
                    fc.entries[r.uintLessThan(usize, 6)].up = r.uintLessThan(u8, 4) != 0;
                    pool.healthTick(1);
                },
                4, 5, 6 => {
                    var kb: [8]u8 = undefined;
                    const key = std.fmt.bufPrint(&kb, "{d}", .{r.int(u16)}) catch unreachable;
                    const got = if (r.boolean()) pool.pick() else pool.pickByKey(key);
                    if (got) |u| {
                        reach.picks += 1;
                        if (u.retired or u.draining.load(.seq_cst) or u.down.load(.seq_cst)) return error.PickedInadmissible;
                        try held.append(testing.allocator, u);
                    } else {
                        reach.null_picks += 1;
                        // Null only when no current member is admissible
                        // by the model's view: none up, undrained and
                        // under its bulkhead cap.
                        for (pool.upstreams.items) |u| {
                            if (!u.down.load(.seq_cst) and !u.draining.load(.seq_cst) and u.in_flight.load(.seq_cst) < 3 and u.breaker.state() == .closed)
                                return error.NullWithAdmissibleMember;
                        }
                    }
                },
                7, 8 => if (held.items.len > 0) {
                    const u = held.swapRemove(r.uintLessThan(usize, held.items.len));
                    pool.report(u, r.uintLessThan(u8, 5) != 0, r.uintAtMost(u64, 1000));
                },
                else => {
                    var idle_retired: usize = 0;
                    for (pool.retired.items) |u| {
                        var h: usize = 0;
                        for (held.items) |x| h += @intFromBool(x == u);
                        idle_retired += @intFromBool(h == 0);
                    }
                    const freed = pool.reap();
                    if (freed != idle_retired) return error.ReapMismatch;
                    reach.reaped += freed;
                },
            }
            // Per-member in-flight equals what the model holds.
            for (pool.upstreams.items) |u| {
                var h: u32 = 0;
                for (held.items) |x| h += @intFromBool(x == u);
                if (u.in_flight.load(.seq_cst) != h) return error.InFlightDrift;
                if (u.draining.load(.seq_cst)) reach.drained_skips += 1;
            }
            if (pool.options.strategy == .ring_hash) {
                for (pool.ring) |p| if (p.idx >= pool.upstreams.items.len) return error.RingIndexStale;
            }
        }
        for (held.items) |u| pool.report(u, true, null);
        held.clearRetainingCapacity();
        _ = pool.reap();
        try testing.expectEqual(0, pool.retiredCount());
    }
    // Measured 2026-10-04: picks 8286, null picks 4295 (each checked against
    // the model), removes 1899, reaped 1564, drained member-steps 25473.
    try testing.expect(reach.picks > 7000);
    try testing.expect(reach.null_picks > 3000);
    try testing.expect(reach.removes > 1500);
    try testing.expect(reach.reaped > 1200);
    try testing.expect(reach.drained_skips > 20000);
}

test "concurrent call() while another thread removes, re-adds and reaps members" {
    // Freed memory is overwritten (0xAA) in safe builds, so a call or report
    // that touched a reaped member would see a garbage id or trip the
    // in-flight assertion; the op checks the id from inside the call.
    const ids = [_][]const u8{ "a", "b", "c" };
    const addrs = [_][]const u8{ "10.0.0.1:80", "10.0.0.2:80", "10.0.0.3:80" };
    var pool: Pool = .init(testing.allocator, .{ .strategy = .least_request, .max_per_upstream = 4, .seed = 1 });
    defer pool.deinit();
    for (ids, addrs) |id, ad| _ = try pool.add(.{ .id = id, .address = ad });

    const Shared = struct {
        bad: std.atomic.Value(u32) = .init(0),
        done: std.atomic.Value(bool) = .init(false),
    };
    const Op = struct {
        s: *Shared,
        pub fn call(self: *@This(), u: *Upstream) error{Never}!u32 {
            const ok = u.id.len == 1 and u.id[0] >= 'a' and u.id[0] <= 'c';
            if (!ok) _ = self.s.bad.fetchAdd(1, .seq_cst);
            std.atomic.spinLoopHint();
            return 1;
        }
    };
    const Worker = struct {
        fn hammer(p: *Pool, s: *Shared) void {
            while (!s.done.load(.seq_cst)) {
                var op: Op = .{ .s = s };
                _ = p.call(&op, .{ .max_tries = 2 }) catch {};
            }
        }
        fn churn(p: *Pool, s: *Shared) void {
            for (0..3000) |i| {
                const k = i % 3;
                _ = p.remove(ids[k]) catch {};
                _ = p.reap();
                _ = p.add(.{ .id = ids[k], .address = addrs[k] }) catch {};
            }
            s.done.store(true, .seq_cst);
        }
    };
    var shared: Shared = .{};
    var workers: [3]std.Thread = undefined;
    for (&workers) |*h| h.* = try std.Thread.spawn(.{}, Worker.hammer, .{ &pool, &shared });
    const churner = try std.Thread.spawn(.{}, Worker.churn, .{ &pool, &shared });
    churner.join();
    for (workers) |h| h.join();
    try testing.expectEqual(0, shared.bad.load(.seq_cst));
    _ = pool.reap();
    try testing.expectEqual(0, pool.retiredCount());
    try testing.expectEqual(0, pool.stats().in_flight);
}

// ── tests added for mutation survivors (2026-10-04) ─────────────────────────

test "remove of the member the rotation points at: the one after it is next" {
    var pool: Pool = .init(testing.allocator, .{});
    defer pool.deinit();
    try addThree(&pool);
    try testing.expectEqualStrings("a", pickReport(&pool).?.id); // cursor → b
    try testing.expect(try pool.remove("b")); // [a, c]; b was next, so c is
    try testing.expectEqualStrings("c", pickReport(&pool).?.id);
    try testing.expectEqualStrings("a", pickReport(&pool).?.id);
    _ = pool.reap();
}

test "a removed member reports drained in its stats, and undrain cannot revive it" {
    // Its stats must say it takes no traffic: a dashboard reading a removed
    // member that is still finishing calls would otherwise show it healthy.
    var pool: Pool = .init(testing.allocator, .{});
    defer pool.deinit();
    try addThree(&pool);
    const a = pool.pick().?;
    try testing.expect(try pool.remove("a"));
    try testing.expect(pool.upstreamStats(a).draining);
    try testing.expect(!pool.upstreamStats(a).healthy);
    pool.undrain(a);
    try testing.expect(pool.upstreamStats(a).draining);
    pool.report(a, true, null);
    try testing.expectEqual(1, pool.reap());
}

test "weighted_round_robin with a drained member splits exactly by the others' weights" {
    // A drained member must not take part in the credit exchange at all:
    // over every window of sum(weights of the rest) picks each remaining
    // member is chosen exactly its weight times.
    var pool: Pool = .init(testing.allocator, .{ .strategy = .weighted_round_robin });
    defer pool.deinit();
    _ = try pool.add(.{ .id = "a", .address = "10.0.0.1:80", .weight = 1 });
    _ = try pool.add(.{ .id = "b", .address = "10.0.0.2:80", .weight = 2 });
    _ = try pool.add(.{ .id = "c", .address = "10.0.0.3:80", .weight = 3 });
    pool.drain(pool.getById("c").?);
    for (0..4) |_| {
        var hits = [_]usize{ 0, 0, 0 };
        for (0..3) |_| hits[pickReport(&pool).?.id[0] - 'a'] += 1;
        try testing.expectEqual([_]usize{ 1, 2, 0 }, hits);
    }
}

test "ring_hash: a key equal to a point lands on that point's member (lower bound)" {
    // The ring rule is "the first point at or after the key's hash": a key
    // spelled like point j of member m hashes to exactly that point.
    var pool: Pool = .init(testing.allocator, .{ .strategy = .ring_hash });
    defer pool.deinit();
    try addThree(&pool);
    for ([_][]const u8{ "a", "b", "c" }) |id| {
        for (0..20) |j| {
            var kb: [16]u8 = undefined;
            const key = std.fmt.bufPrint(&kb, "{s}-{d}", .{ id, j }) catch unreachable;
            try testing.expectEqualStrings(id, pool.ringOwner(key).?.id);
        }
    }
}

test "ring_hash: pick() without a key spreads over every member" {
    var pool: Pool = .init(testing.allocator, .{ .strategy = .ring_hash, .seed = 11 });
    defer pool.deinit();
    try addThree(&pool);
    var hits = [_]usize{ 0, 0, 0 };
    for (0..300) |_| hits[pickReport(&pool).?.id[0] - 'a'] += 1;
    for (hits) |h| try testing.expect(h > 50);
}

test "healthTick: a tick started from inside a running tick's check is a no-op" {
    // One tick at a time: the snapshot and its pins belong to one tick.
    const Nested = struct {
        pool: *Pool,
        calls: usize = 0,
        fn hc(n: *@This()) HealthChecker {
            return .{ .ctx = n, .checkFn = check };
        }
        fn check(ctx: *anyopaque, _: probe.Target, _: u64) bool {
            const n: *@This() = @ptrCast(@alignCast(ctx));
            n.calls += 1;
            n.pool.healthTick(n.calls * 1000);
            return true;
        }
    };
    var pool: Pool = .init(testing.allocator, .{ .health_interval_ns = 0 });
    defer pool.deinit();
    var n: Nested = .{ .pool = &pool };
    pool.options.health_checker = n.hc();
    try addThree(&pool);
    pool.healthTick(1);
    try testing.expectEqual(3, n.calls);
}
