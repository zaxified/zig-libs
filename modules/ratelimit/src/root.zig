//! ratelimit — token-bucket request limiting: a pure keyed limiter plus a
//! `router` middleware answering **429 + Retry-After**.
//!
//! Layering (each usable on its own):
//! - `TokenBucket` — the bare algorithm (Go `golang.org/x/time/rate`
//!   semantics: float token balance, lazy refill, burst cap). No clock, no
//!   locking, no allocation — the caller passes `now_ns`.
//! - `Limiter` — per-key buckets in a bounded store (`max_keys` cap with LRU
//!   eviction + idle TTL), internally synchronized, clock injected via
//!   `Options.clock` (defaults to the OS monotonic clock; the algorithm
//!   itself never reads a wall clock).
//! - `Limiter.middleware()` — a `router.Middleware`: allowed requests flow
//!   to `next` untouched; denied ones get a 429 with `Retry-After` and IETF
//!   draft `RateLimit-*` headers, and `next` is never called.
//!
//! ## Client-key trust policy (X-Forwarded-For)
//!
//! The default key (`KeySource.forwarded_ip`) is the client IP **as
//! established by a trusted reverse proxy** (the intended deployment is
//! behind Caddy, which terminates TLS and always appends the peer address to
//! `X-Forwarded-For`). Policy, in order:
//!
//! 1. **Rightmost element of the last `X-Forwarded-For` header.** Every
//!    compliant proxy hop *appends* the address it observed, so the final
//!    element of the final header line is written by the nearest — trusted —
//!    proxy and is the only part of the header a client cannot forge.
//!    Leftmost elements (and whole extra header lines) are attacker-supplied
//!    and are deliberately ignored.
//! 2. **`X-Real-IP`** as a fallback for proxies that set it instead
//!    (nginx-style). Only trustworthy when your proxy overwrites it —
//!    a client talking to the server directly can forge it.
//! 3. **`fallback_key`** — one shared bucket for everything else.
//!    `http.Server` does not expose the socket peer address to handlers, so
//!    direct (unproxied) clients cannot be told apart; behind the intended
//!    proxy deployment this case never happens (XFF is always present).
//!
//! This "rightmost, one trusted hop" policy assumes the app is reachable
//! *only* through the proxy. If clients can reach the server directly, they
//! can forge any of these headers and choose their own bucket — bind to
//! localhost / a private network so only the proxy can connect.

const std = @import("std");
const builtin = @import("builtin");
const router = @import("router");
const http = @import("http");

pub const meta = .{
    .status = .gap,
    .platform = .any,
    .role = .util,
    // `Limiter` is internally synchronized (documented spinlock around an
    // O(1) critical section); the bare `TokenBucket` is single_owner.
    .concurrency = .threadsafe,
    .model_after = "Go golang.org/x/time/rate (token bucket) + nginx limit_req (keyed store)",
    .deps = .{ "router", "http" },
};

const Allocator = std.mem.Allocator;

// ── clock injection ─────────────────────────────────────────────────────────

/// Monotonic time source, injected so the algorithm is deterministic under
/// test. Implementations must be non-decreasing; absolute origin is
/// irrelevant (only differences are used).
pub const Clock = struct {
    ctx: ?*anyopaque = null,
    nowFn: *const fn (?*anyopaque) u64,

    /// The OS monotonic clock (CLOCK_MONOTONIC; QueryPerformanceCounter on
    /// Windows). This is the production default — and the only place in the
    /// module that touches a real clock.
    pub const monotonic: Clock = .{ .nowFn = monotonicNowNs };

    pub fn now(c: Clock) u64 {
        return c.nowFn(c.ctx);
    }
};

fn monotonicNowNs(_: ?*anyopaque) u64 {
    switch (builtin.os.tag) {
        .windows => {
            const windows = std.os.windows;
            var qpf: windows.LARGE_INTEGER = undefined;
            var qpc: windows.LARGE_INTEGER = undefined;
            if (!windows.ntdll.RtlQueryPerformanceFrequency(&qpf).toBool()) return 0;
            if (!windows.ntdll.RtlQueryPerformanceCounter(&qpc).toBool()) return 0;
            const freq: u64 = @bitCast(qpf);
            const count: u64 = @bitCast(qpc);
            return @intCast(@as(u128, count) * std.time.ns_per_s / freq);
        },
        else => {
            var ts: std.posix.timespec = undefined;
            if (std.posix.errno(std.posix.system.clock_gettime(.MONOTONIC, &ts)) != .SUCCESS)
                return 0;
            return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
        },
    }
}

// ── the pure algorithm ──────────────────────────────────────────────────────

/// The outcome of one `allow` call.
pub const Decision = struct {
    allowed: bool,
    /// Denied only: time until one token frees up, rounded **up** to whole
    /// milliseconds — waiting exactly this long guarantees the next attempt
    /// passes (absent other traffic). 0 when allowed.
    retry_after_ms: u64,
    /// Whole tokens left after this decision (floor of the balance).
    remaining: u32,
    /// Time until the bucket is completely full again — the IETF draft
    /// `RateLimit-Reset` value (rounded up to whole milliseconds).
    reset_after_ms: u64,
};

/// Token bucket, mirroring Go `golang.org/x/time/rate`: a float token
/// balance refilled lazily at `rate_per_s`, capped at `burst`; one token per
/// event; denials consume nothing. Pure state + math — no clock, no locking
/// (single owner; `Limiter` adds keying and synchronization).
pub const TokenBucket = struct {
    /// Current fractional token balance (0 ≤ tokens ≤ burst).
    tokens: f64,
    /// Instant of the last `allowAt` (refill is computed lazily from here —
    /// x/time/rate's `last`).
    updated_ns: u64,

    pub const Config = struct {
        /// Sustained refill, tokens per second. Must be > 0 and finite.
        rate_per_s: f64,
        /// Bucket capacity — the burst allowance. Must be ≥ 1.
        burst: u32,
    };

    /// A full bucket as of `now_ns`.
    pub fn full(cfg: Config, now_ns: u64) TokenBucket {
        return .{ .tokens = @floatFromInt(cfg.burst), .updated_ns = now_ns };
    }

    /// Decide one event at `now_ns` (x/time/rate `AllowN(now, 1)`); consumes
    /// a token when allowed. `now_ns` must be monotonic — a backwards step
    /// is treated as no time passing (never a negative refill).
    pub fn allowAt(b: *TokenBucket, cfg: Config, now_ns: u64) Decision {
        std.debug.assert(cfg.rate_per_s > 0 and cfg.burst >= 1);
        if (now_ns > b.updated_ns) {
            const elapsed_s = @as(f64, @floatFromInt(now_ns - b.updated_ns)) / ns_per_s_f;
            b.tokens = @min(@as(f64, @floatFromInt(cfg.burst)), b.tokens + elapsed_s * cfg.rate_per_s);
            b.updated_ns = now_ns;
        }
        const burst_f: f64 = @floatFromInt(cfg.burst);
        if (b.tokens >= 1.0) {
            b.tokens -= 1.0;
            return .{
                .allowed = true,
                .retry_after_ms = 0,
                .remaining = @intFromFloat(b.tokens),
                .reset_after_ms = ceilMs((burst_f - b.tokens) / cfg.rate_per_s),
            };
        }
        return .{
            .allowed = false,
            .retry_after_ms = ceilMs((1.0 - b.tokens) / cfg.rate_per_s),
            .remaining = 0,
            .reset_after_ms = ceilMs((burst_f - b.tokens) / cfg.rate_per_s),
        };
    }
};

const ns_per_s_f: f64 = @floatFromInt(std.time.ns_per_s);

/// Seconds (float) → whole milliseconds, rounded up, saturated at u64 max.
fn ceilMs(seconds: f64) u64 {
    if (!(seconds > 0)) return 0; // negatives and NaN
    const ms = @ceil(seconds * 1000.0);
    if (ms >= @as(f64, @floatFromInt(std.math.maxInt(u64)))) return std.math.maxInt(u64);
    return @intFromFloat(ms);
}

// ── the keyed limiter ───────────────────────────────────────────────────────

/// Caller-supplied key extraction for the middleware.
pub const KeyFn = struct {
    ctx: ?*anyopaque = null,
    /// Must return a key valid for the duration of the call (the store
    /// copies what it keeps).
    keyFor: *const fn (?*anyopaque, *router.Ctx) []const u8,
};

/// What identifies a client for the middleware (the pure `Limiter.allow`
/// takes explicit keys and ignores this).
pub const KeySource = union(enum) {
    /// Trusted-proxy client IP — see the trust policy in the module doc:
    /// rightmost element of the last `X-Forwarded-For`, else `X-Real-IP`,
    /// else `fallback_key`.
    forwarded_ip,
    /// Value of this request header (e.g. an API key). Requests without the
    /// header fall back to the `forwarded_ip` chain.
    header: []const u8,
    /// Fully custom extraction.
    custom: KeyFn,
};

/// Key used when no forwarded/real-IP header is present. `http.Server` does
/// not expose the socket peer address to handlers, so all direct (unproxied)
/// clients share this one bucket; behind the intended proxy deployment the
/// forwarded header is always present.
pub const fallback_key = "(no-client-ip)";

pub const Options = struct {
    /// Sustained per-key rate, tokens (requests) per second. Must be > 0.
    rate_per_s: f64,
    /// Per-key burst capacity. Must be ≥ 1.
    burst: u32,
    /// At most this many distinct keys tracked (memory bound); beyond it the
    /// least-recently-used key is evicted — an evicted key seen again starts
    /// over with a full bucket. Must be ≥ 1.
    max_keys: usize = 4096,
    /// Idle expiry: a key untouched this long is dropped (swept from the LRU
    /// tail when new keys arrive) or reset to a full bucket on its next hit.
    /// 0 disables. Memory stays bounded by `max_keys` either way — the TTL
    /// only releases idle keys' memory early.
    ttl_ms: u64 = 10 * std.time.ms_per_min,
    /// Time source — inject a fake for deterministic tests. The algorithm
    /// never reads a wall clock on its own.
    clock: Clock = .monotonic,
    /// Client-key extraction used by `middleware()`.
    key: KeySource = .forwarded_ip,
};

/// Per-key token buckets in a bounded LRU store.
///
/// Thread-safety: internally synchronized — all public calls may race from
/// any number of threads (the middleware runs on `http.Server`'s
/// per-connection threads). The lock is a spinlock (`std.atomic.Mutex` +
/// `spinLoopHint`, the std SmpAllocator pattern — Zig 0.16 std has no
/// io-less blocking mutex); the critical section is a hash lookup plus an
/// O(1) LRU relink, with a gpa alloc/free only when a key is inserted or
/// evicted. Do not hold across it anything of your own.
///
/// Failure policy: `allow` is infallible — if tracking a *new* key fails on
/// allocator exhaustion the request is allowed untracked (fail-open: a
/// limiter must not turn OOM into a full outage). Eviction keeps the store
/// within `max_keys` before any insert, so this is truly exceptional.
pub const Limiter = struct {
    gpa: Allocator,
    options: Options,
    lock: std.atomic.Mutex = .unlocked,
    /// Keyed by `Entry.key` (gpa-owned copies).
    map: std.StringHashMapUnmanaged(*Entry) = .empty,
    /// Front = most recently used; evictions pop the back.
    lru: std.DoublyLinkedList = .{},

    const Entry = struct {
        node: std.DoublyLinkedList.Node = .{},
        key: []u8,
        bucket: TokenBucket,
    };

    pub fn init(gpa: Allocator, options: Options) Limiter {
        std.debug.assert(options.rate_per_s > 0 and std.math.isFinite(options.rate_per_s));
        std.debug.assert(options.burst >= 1);
        std.debug.assert(options.max_keys >= 1);
        return .{ .gpa = gpa, .options = options };
    }

    pub fn deinit(l: *Limiter) void {
        var it = l.map.valueIterator();
        while (it.next()) |e| {
            l.gpa.free(e.*.key);
            l.gpa.destroy(e.*);
        }
        l.map.deinit(l.gpa);
        l.* = undefined;
    }

    /// Decide one request for `key` at the injected clock's now.
    /// Thread-safe; never fails (see the fail-open note on the type).
    pub fn allow(l: *Limiter, key: []const u8) Decision {
        return l.allowAt(key, l.options.clock.now());
    }

    /// `allow` at an explicit instant — the deterministic-test entry point.
    /// `now_ns` must be non-decreasing across calls.
    pub fn allowAt(l: *Limiter, key: []const u8, now_ns: u64) Decision {
        const cfg: TokenBucket.Config = .{ .rate_per_s = l.options.rate_per_s, .burst = l.options.burst };
        const ttl_ns = l.options.ttl_ms *| std.time.ns_per_ms;

        lockSpin(&l.lock);
        defer l.lock.unlock();

        if (l.map.get(key)) |e| {
            // Idle-expired keys start over with a full bucket (the bucket
            // would have refilled to full long ago anyway; this also resets
            // `updated_ns` so the entry stops looking expired).
            if (ttl_ns != 0 and now_ns -| e.bucket.updated_ns > ttl_ns)
                e.bucket = .full(cfg, now_ns);
            l.lru.remove(&e.node);
            l.lru.prepend(&e.node);
            return e.bucket.allowAt(cfg, now_ns);
        }

        // New key. First sweep idle-expired keys off the LRU tail (releases
        // idle memory without a timer thread), then enforce the cap.
        if (ttl_ns != 0) {
            while (l.lru.last) |tail| {
                const e: *Entry = @fieldParentPtr("node", tail);
                if (now_ns -| e.bucket.updated_ns <= ttl_ns) break;
                l.removeEntry(e);
            }
        }
        if (l.map.count() >= l.options.max_keys)
            l.removeEntry(@fieldParentPtr("node", l.lru.last.?));

        var bucket: TokenBucket = .full(cfg, now_ns);
        const decision = bucket.allowAt(cfg, now_ns);
        l.insert(key, bucket) catch {}; // OOM → fail open (documented)
        return decision;
    }

    /// Number of keys currently tracked (diagnostics / tests).
    pub fn keyCount(l: *Limiter) usize {
        lockSpin(&l.lock);
        defer l.lock.unlock();
        return l.map.count();
    }

    fn insert(l: *Limiter, key: []const u8, bucket: TokenBucket) Allocator.Error!void {
        const e = try l.gpa.create(Entry);
        errdefer l.gpa.destroy(e);
        e.* = .{ .key = try l.gpa.dupe(u8, key), .bucket = bucket };
        errdefer l.gpa.free(e.key);
        try l.map.put(l.gpa, e.key, e);
        l.lru.prepend(&e.node);
    }

    fn removeEntry(l: *Limiter, e: *Entry) void {
        const removed = l.map.remove(e.key);
        std.debug.assert(removed);
        l.lru.remove(&e.node);
        l.gpa.free(e.key);
        l.gpa.destroy(e);
    }

    // ── the middleware ──────────────────────────────────────────────────

    /// A `router.Middleware` enforcing this limiter (`state` = the Limiter —
    /// per-instance state, no globals). Allowed requests pass to `next`
    /// untouched. Denied requests get **429** with `Retry-After` (whole
    /// seconds, rounded up, ≥ 1), the IETF draft `RateLimit-Limit` /
    /// `RateLimit-Remaining` / `RateLimit-Reset` headers and a short plain
    /// body; `next` is never called. The Limiter must outlive the Router.
    pub fn middleware(l: *Limiter) router.Middleware {
        return .{ .state = l, .run = middlewareRun };
    }
};

fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

fn middlewareRun(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    const l: *Limiter = @ptrCast(@alignCast(state.?));
    const decision = l.allow(keyOf(l, ctx));
    if (decision.allowed) return next.run(ctx);

    // Deny. Header values are formatted on this stack frame, so the head
    // must reach the wire before the frame unwinds — `end()` is idempotent
    // and the serving loop's own end()+flush still run (same trick as the
    // router's trailing-slash redirect).
    //
    // RateLimit-* headers only appear on 429s: on allowed responses the head
    // is written after this frame is gone, so per-request values would
    // dangle (`ResponseWriter` retains header slices until the head is
    // sent).
    var retry_buf: [24]u8 = undefined;
    var limit_buf: [24]u8 = undefined;
    var reset_buf: [24]u8 = undefined;
    const retry_s = @max(1, ceilDivMsToS(decision.retry_after_ms));
    ctx.res.setStatus(429);
    try ctx.res.setHeader("Retry-After", std.fmt.bufPrint(&retry_buf, "{d}", .{retry_s}) catch unreachable);
    try ctx.res.setHeader("RateLimit-Limit", std.fmt.bufPrint(&limit_buf, "{d}", .{l.options.burst}) catch unreachable);
    try ctx.res.setHeader("RateLimit-Remaining", "0");
    try ctx.res.setHeader("RateLimit-Reset", std.fmt.bufPrint(&reset_buf, "{d}", .{ceilDivMsToS(decision.reset_after_ms)}) catch unreachable);
    try ctx.res.setHeader("Content-Type", "text/plain");
    try ctx.res.writeAll("Too Many Requests\n");
    try ctx.res.end();
}

fn ceilDivMsToS(ms: u64) u64 {
    return std.math.divCeil(u64, ms, std.time.ms_per_s) catch unreachable;
}

// ── key extraction ──────────────────────────────────────────────────────────

fn keyOf(l: *const Limiter, ctx: *router.Ctx) []const u8 {
    switch (l.options.key) {
        .forwarded_ip => return forwardedClientKey(ctx.req),
        .header => |name| {
            if (ctx.req.header(name)) |v| {
                const trimmed = std.mem.trim(u8, v, " \t");
                if (trimmed.len != 0) return trimmed;
            }
            return forwardedClientKey(ctx.req);
        },
        .custom => |k| return k.keyFor(k.ctx, ctx),
    }
}

/// The client key per the module's trust policy (see the module doc):
/// rightmost element of the **last** `X-Forwarded-For` header (the one the
/// nearest trusted proxy appended — the only part a client cannot forge),
/// else `X-Real-IP`, else `fallback_key`. Exposed for reuse by other
/// middleware (logging, abuseguard).
pub fn forwardedClientKey(req: *const http.Server.Request) []const u8 {
    var xff: ?[]const u8 = null;
    var it = req.iterateHeaders();
    while (it.next()) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "x-forwarded-for")) xff = h.value;
    }
    if (xff) |v| {
        const start = if (std.mem.lastIndexOfScalar(u8, v, ',')) |i| i + 1 else 0;
        const ip = std.mem.trim(u8, v[start..], " \t");
        if (ip.len != 0) return ip;
    }
    if (req.header("x-real-ip")) |v| {
        const ip = std.mem.trim(u8, v, " \t");
        if (ip.len != 0) return ip;
    }
    return fallback_key;
}

// ── tests: the pure algorithm (no clock, no HTTP) ───────────────────────────

const testing = std.testing;

test "TokenBucket: burst allowed, then throttled with exact retry_after" {
    const cfg: TokenBucket.Config = .{ .rate_per_s = 1, .burst = 3 };
    var b: TokenBucket = .full(cfg, 0);

    // The whole burst passes at one instant, remaining counts down.
    var i: u32 = 3;
    while (i > 0) : (i -= 1) {
        const d = b.allowAt(cfg, 0);
        try testing.expect(d.allowed);
        try testing.expectEqual(i - 1, d.remaining);
    }
    // Empty: denied, one token frees in exactly 1s at 1 token/s.
    const d = b.allowAt(cfg, 0);
    try testing.expect(!d.allowed);
    try testing.expectEqual(@as(u64, 1000), d.retry_after_ms);
    try testing.expectEqual(@as(u32, 0), d.remaining);
    try testing.expectEqual(@as(u64, 3000), d.reset_after_ms); // full again in 3s
}

test "TokenBucket: refill over time, fractional rates, burst cap" {
    const cfg: TokenBucket.Config = .{ .rate_per_s = 2, .burst = 2 };
    var b: TokenBucket = .full(cfg, 0);
    try testing.expect(b.allowAt(cfg, 0).allowed);
    try testing.expect(b.allowAt(cfg, 0).allowed);

    // 250 ms at 2 tokens/s = 0.5 tokens: still denied, 250 ms to a token.
    const quarter = 250 * std.time.ns_per_ms;
    const denied = b.allowAt(cfg, quarter);
    try testing.expect(!denied.allowed);
    try testing.expectEqual(@as(u64, 250), denied.retry_after_ms);

    // At 500 ms one token exists again.
    try testing.expect(b.allowAt(cfg, 500 * std.time.ns_per_ms).allowed);

    // A long idle period refills to burst, never beyond.
    const later = 100 * std.time.ns_per_s;
    try testing.expect(b.allowAt(cfg, later).allowed);
    try testing.expect(b.allowAt(cfg, later).allowed);
    try testing.expect(!b.allowAt(cfg, later).allowed);
}

test "TokenBucket: waiting exactly retry_after_ms guarantees the next token" {
    const cfg: TokenBucket.Config = .{ .rate_per_s = 3, .burst = 1 };
    var b: TokenBucket = .full(cfg, 0);
    try testing.expect(b.allowAt(cfg, 0).allowed);
    const d = b.allowAt(cfg, 0);
    try testing.expect(!d.allowed);
    try testing.expectEqual(@as(u64, 334), d.retry_after_ms); // ceil(1000/3)
    try testing.expect(b.allowAt(cfg, d.retry_after_ms * std.time.ns_per_ms).allowed);
}

test "TokenBucket: denials consume nothing; backwards clock is a no-op" {
    const cfg: TokenBucket.Config = .{ .rate_per_s = 1, .burst = 1 };
    var b: TokenBucket = .full(cfg, 1000);
    try testing.expect(b.allowAt(cfg, 1000).allowed);
    // Repeated denials at the same instant keep reporting the same wait.
    try testing.expectEqual(@as(u64, 1000), b.allowAt(cfg, 1000).retry_after_ms);
    try testing.expectEqual(@as(u64, 1000), b.allowAt(cfg, 1000).retry_after_ms);
    // A step back in time must not produce a negative refill.
    try testing.expectEqual(@as(u64, 1000), b.allowAt(cfg, 500).retry_after_ms);
}

// ── tests: the keyed limiter (injected clock, no HTTP) ──────────────────────

/// Deterministic test clock.
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

test "Limiter: burst-then-throttle and refill through the injected clock" {
    var tc: TestClock = .{};
    var l = Limiter.init(testing.allocator, .{
        .rate_per_s = 1,
        .burst = 2,
        .clock = tc.clock(),
    });
    defer l.deinit();

    try testing.expect(l.allow("k").allowed);
    try testing.expect(l.allow("k").allowed);
    const d = l.allow("k");
    try testing.expect(!d.allowed);
    try testing.expectEqual(@as(u64, 1000), d.retry_after_ms);

    tc.advanceMs(400);
    try testing.expectEqual(@as(u64, 600), l.allow("k").retry_after_ms);
    tc.advanceMs(600);
    try testing.expect(l.allow("k").allowed);
    try testing.expect(!l.allow("k").allowed);
}

test "Limiter: per-key isolation" {
    var tc: TestClock = .{};
    var l = Limiter.init(testing.allocator, .{ .rate_per_s = 1, .burst = 1, .clock = tc.clock() });
    defer l.deinit();

    try testing.expect(l.allow("alice").allowed);
    try testing.expect(!l.allow("alice").allowed);
    // A throttled alice never affects bob.
    try testing.expect(l.allow("bob").allowed);
    try testing.expect(!l.allow("bob").allowed);
    try testing.expect(!l.allow("alice").allowed);
    try testing.expectEqual(@as(usize, 2), l.keyCount());
}

test "Limiter: LRU eviction at max_keys; evicted keys restart fresh" {
    var tc: TestClock = .{};
    var l = Limiter.init(testing.allocator, .{
        .rate_per_s = 1,
        .burst = 2,
        .max_keys = 2,
        .ttl_ms = 0,
        .clock = tc.clock(),
    });
    defer l.deinit();

    _ = l.allow("a"); // a: 1 token left
    _ = l.allow("b");
    try testing.expectEqual(@as(usize, 2), l.keyCount());

    _ = l.allow("a"); // touch a → b becomes LRU; a now empty
    _ = l.allow("c"); // at cap → evicts b, not a
    try testing.expectEqual(@as(usize, 2), l.keyCount());

    // a kept its (drained) state…
    try testing.expect(!l.allow("a").allowed);
    // …which makes a the MRU again, so inserting b evicts c. b starts over
    // with a full bucket (the price of eviction, documented).
    try testing.expect(l.allow("b").allowed);
    try testing.expect(l.allow("b").allowed);
    try testing.expectEqual(@as(usize, 2), l.keyCount());
}

test "Limiter: TTL resets idle keys and sweeps their memory" {
    var tc: TestClock = .{};
    // Refill is negligible (0.01/s) so a passing `allow` after the idle gap
    // can only come from the TTL reset, not from refill.
    var l = Limiter.init(testing.allocator, .{
        .rate_per_s = 0.01,
        .burst = 2,
        .ttl_ms = 1000,
        .clock = tc.clock(),
    });
    defer l.deinit();

    _ = l.allow("a");
    _ = l.allow("a");
    try testing.expect(!l.allow("a").allowed); // drained
    _ = l.allow("b");

    tc.advanceMs(1500); // both idle past the 1s TTL

    // Hit on an expired key: state resets to a full bucket.
    const d = l.allow("a");
    try testing.expect(d.allowed);
    try testing.expectEqual(@as(u32, 1), d.remaining);

    // Insert of a new key sweeps the expired b off the LRU tail.
    try testing.expect(l.allow("c").allowed);
    try testing.expectEqual(@as(usize, 2), l.keyCount()); // a + c; b swept
}

test "Limiter: fail-open when the allocator is exhausted" {
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var tc: TestClock = .{};
    var l = Limiter.init(failing.allocator(), .{ .rate_per_s = 1, .burst = 1, .clock = tc.clock() });
    defer l.deinit();

    // Tracking the key fails → request allowed, nothing stored.
    try testing.expect(l.allow("k").allowed);
    try testing.expectEqual(@as(usize, 0), l.keyCount());
}

test "Limiter: concurrent allow admits exactly burst (no over-admission)" {
    const threads = 8;
    const attempts_per_thread = 100;
    const burst = 100;

    var tc: TestClock = .{}; // frozen clock → zero refill during the race
    var l = Limiter.init(testing.allocator, .{
        .rate_per_s = 0.000001,
        .burst = burst,
        .clock = tc.clock(),
    });
    defer l.deinit();

    const Worker = struct {
        fn run(lim: *Limiter, allowed: *std.atomic.Value(u32)) void {
            for (0..attempts_per_thread) |_| {
                if (lim.allow("shared").allowed) _ = allowed.fetchAdd(1, .monotonic);
            }
        }
    };

    var allowed: std.atomic.Value(u32) = .init(0);
    var handles: [threads]std.Thread = undefined;
    for (&handles) |*h| h.* = try std.Thread.spawn(.{}, Worker.run, .{ &l, &allowed });
    for (handles) |h| h.join();

    try testing.expectEqual(@as(u32, burst), allowed.load(.monotonic));
    try testing.expectEqual(@as(usize, 1), l.keyCount());
}

// ── tests: middleware over the socket-free server codec ─────────────────────

const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

/// Drive a router through `http.Server.serveStream` with canned wire bytes
/// (same harness as the router's own tests).
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

fn wire(comptime headers: []const u8) []const u8 {
    return "GET /t HTTP/1.1\r\nHost: t\r\n" ++ headers ++ "Connection: close\r\n\r\n";
}

fn expectStatus(got: []const u8, comptime status: []const u8) !void {
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 " ++ status));
}

fn hCount(ctx: *router.Ctx) anyerror!void {
    const n: *u32 = @ptrCast(@alignCast(ctx.state.?));
    n.* += 1;
    try ctx.res.writeAll("ok");
}

const RouterUnderLimit = struct {
    r: router.Router,
    hits: u32 = 0,

    fn init(l: *Limiter) !RouterUnderLimit {
        var r = router.Router.init(testing.allocator);
        errdefer r.deinit();
        try r.use(l.middleware());
        try r.get("/t", hCount);
        return .{ .r = r };
    }

    fn start(rl: *RouterUnderLimit) void {
        rl.r.state = &rl.hits; // self-referential: only valid once settled
    }

    fn deinit(rl: *RouterUnderLimit) void {
        rl.r.deinit();
    }
};

test "middleware: burst then golden 429 with Retry-After; deny skips the handler" {
    var tc: TestClock = .{};
    var l = Limiter.init(testing.allocator, .{ .rate_per_s = 1, .burst = 2, .clock = tc.clock() });
    defer l.deinit();
    var rl = try RouterUnderLimit.init(&l);
    defer rl.deinit();
    rl.start();

    const caddy_xff = "X-Forwarded-For: 9.9.9.9, 1.2.3.4\r\n"; // spoof, real
    var buf: [1024]u8 = undefined;
    try expectStatus(runWire(&rl.r, wire(caddy_xff), &buf), "200");
    try expectStatus(runWire(&rl.r, wire(caddy_xff), &buf), "200");
    try testing.expectEqual(@as(u32, 2), rl.hits);

    // Third request: the full golden 429 — Retry-After 1s (rate 1/s, empty
    // bucket), RateLimit-Reset 2s (burst 2 refills in 2s).
    try testing.expectEqualStrings("HTTP/1.1 429 Too Many Requests\r\n" ++
        "Retry-After: 1\r\n" ++
        "RateLimit-Limit: 2\r\n" ++
        "RateLimit-Remaining: 0\r\n" ++
        "RateLimit-Reset: 2\r\n" ++
        "Content-Type: text/plain\r\n" ++
        "Connection: close\r\n" ++
        "Content-Length: 18\r\n" ++
        "\r\n" ++
        "Too Many Requests\n", runWire(&rl.r, wire(caddy_xff), &buf));
    try testing.expectEqual(@as(u32, 2), rl.hits); // handler never ran

    // A forged *leftmost* entry does not escape the bucket (rightmost policy).
    try expectStatus(runWire(&rl.r, wire("X-Forwarded-For: 8.8.8.8, 1.2.3.4\r\n"), &buf), "429");

    // A different real client (different rightmost) is unaffected.
    try expectStatus(runWire(&rl.r, wire("X-Forwarded-For: 9.9.9.9, 5.6.7.8\r\n"), &buf), "200");

    // After Retry-After elapses the original client passes again.
    tc.advanceMs(1000);
    try expectStatus(runWire(&rl.r, wire(caddy_xff), &buf), "200");
}

test "middleware: key extraction — XFF forms, X-Real-IP, fallback key" {
    var tc: TestClock = .{};
    var l = Limiter.init(testing.allocator, .{ .rate_per_s = 0.01, .burst = 1, .clock = tc.clock() });
    defer l.deinit();
    var rl = try RouterUnderLimit.init(&l);
    defer rl.deinit();
    rl.start();
    var buf: [1024]u8 = undefined;

    // Single-element XFF: the element itself is the key.
    try expectStatus(runWire(&rl.r, wire("X-Forwarded-For: 1.2.3.4\r\n"), &buf), "200");
    // Same client via a longer (spoof-prefixed) chain: same bucket → 429.
    try expectStatus(runWire(&rl.r, wire("X-Forwarded-For: 6.6.6.6, 1.2.3.4\r\n"), &buf), "429");
    // Multiple XFF header lines: the LAST line's rightmost element wins
    // (earlier lines are attacker-supplied pass-through).
    try expectStatus(runWire(&rl.r, wire("X-Forwarded-For: 6.6.6.6\r\nX-Forwarded-For: 7.7.7.7, 1.2.3.4\r\n"), &buf), "429");

    // X-Real-IP is the fallback when no XFF is present…
    try expectStatus(runWire(&rl.r, wire("X-Real-IP: 5.5.5.5\r\n"), &buf), "200");
    try expectStatus(runWire(&rl.r, wire("X-Real-IP: 5.5.5.5\r\n"), &buf), "429");
    // …and XFF wins over X-Real-IP when both exist.
    try expectStatus(runWire(&rl.r, wire("X-Forwarded-For: 3.3.3.3\r\nX-Real-IP: 5.5.5.5\r\n"), &buf), "200");

    // No client headers at all: everything shares the one fallback bucket.
    try expectStatus(runWire(&rl.r, wire(""), &buf), "200");
    try expectStatus(runWire(&rl.r, wire(""), &buf), "429");
    // Empty XFF value also falls through to the fallback bucket.
    try expectStatus(runWire(&rl.r, wire("X-Forwarded-For:\r\n"), &buf), "429");
}

test "middleware: API-key header as the key, with forwarded-IP fallback" {
    var tc: TestClock = .{};
    var l = Limiter.init(testing.allocator, .{
        .rate_per_s = 0.01,
        .burst = 1,
        .clock = tc.clock(),
        .key = .{ .header = "X-Api-Key" },
    });
    defer l.deinit();
    var rl = try RouterUnderLimit.init(&l);
    defer rl.deinit();
    rl.start();
    var buf: [1024]u8 = undefined;

    try expectStatus(runWire(&rl.r, wire("X-Api-Key: alpha\r\n"), &buf), "200");
    try expectStatus(runWire(&rl.r, wire("X-Api-Key: beta\r\n"), &buf), "200");
    try expectStatus(runWire(&rl.r, wire("X-Api-Key: alpha\r\n"), &buf), "429");
    // The same API key from another IP is still the same bucket.
    try expectStatus(runWire(&rl.r, wire("X-Api-Key: alpha\r\nX-Forwarded-For: 4.4.4.4\r\n"), &buf), "429");
    // Without the header, keying falls back to the forwarded IP.
    try expectStatus(runWire(&rl.r, wire("X-Forwarded-For: 4.4.4.4\r\n"), &buf), "200");
    try expectStatus(runWire(&rl.r, wire("X-Forwarded-For: 4.4.4.4\r\n"), &buf), "429");
}

fn keyByPath(_: ?*anyopaque, ctx: *router.Ctx) []const u8 {
    return ctx.req.path;
}

test "middleware: custom key function" {
    var tc: TestClock = .{};
    var l = Limiter.init(testing.allocator, .{
        .rate_per_s = 0.01,
        .burst = 1,
        .clock = tc.clock(),
        .key = .{ .custom = .{ .keyFor = keyByPath } },
    });
    defer l.deinit();
    var rl = try RouterUnderLimit.init(&l);
    defer rl.deinit();
    rl.start();
    var buf: [1024]u8 = undefined;

    // Keyed by path: two clients on /t share one bucket.
    try expectStatus(runWire(&rl.r, wire("X-Forwarded-For: 1.1.1.1\r\n"), &buf), "200");
    try expectStatus(runWire(&rl.r, wire("X-Forwarded-For: 2.2.2.2\r\n"), &buf), "429");
}

// ── tests: in-process integration (router + http.Server + http.Client) ──────

fn serveWrap(s: *http.Server) void {
    s.serve() catch {};
}

test "integration: limited route over loopback — 200s, 429 + Retry-After, key isolation" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Real monotonic clock; refill is slow (0.1/s) so the burst can't
    // recover within the test even on a very slow machine.
    var l = Limiter.init(testing.allocator, .{ .rate_per_s = 0.1, .burst = 2 });
    defer l.deinit();

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(l.middleware());
    try r.get("/limited", hHello);

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
    var client = http.Client.init(io, testing.allocator, .{});
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/limited", .{port});

    // What Caddy would forward for one client: spoofable leftmost entries
    // vary, the trusted rightmost entry stays 1.2.3.4 → one bucket.
    const client_a: []const http.Header = &.{.{ .name = "X-Forwarded-For", .value = "9.9.9.9, 1.2.3.4" }};
    const client_a2: []const http.Header = &.{.{ .name = "X-Forwarded-For", .value = "8.8.8.8, 1.2.3.4" }};
    const client_b: []const http.Header = &.{.{ .name = "X-Forwarded-For", .value = "9.9.9.9, 5.6.7.8" }};

    { // burst passes (2 requests, differing spoofed prefixes = same key)
        var res = try client.request(.get, url, .{ .headers = client_a });
        defer res.deinit();
        try testing.expectEqual(@as(u16, 200), res.status);
        const body = try res.readAllAlloc(testing.allocator, 1024);
        defer testing.allocator.free(body);
        try testing.expectEqualStrings("hello", body);
    }
    {
        var res = try client.request(.get, url, .{ .headers = client_a2 });
        defer res.deinit();
        try testing.expectEqual(@as(u16, 200), res.status);
    }

    { // third request from the same client → 429 with usable Retry-After
        var res = try client.request(.get, url, .{ .headers = client_a });
        defer res.deinit();
        try testing.expectEqual(@as(u16, 429), res.status);
        const retry_s = try std.fmt.parseInt(u64, res.header("retry-after").?, 10);
        try testing.expect(retry_s >= 1 and retry_s <= 10); // 1 token at 0.1/s
        try testing.expectEqualStrings("2", res.header("ratelimit-limit").?);
        try testing.expectEqualStrings("0", res.header("ratelimit-remaining").?);
        const body = try res.readAllAlloc(testing.allocator, 1024);
        defer testing.allocator.free(body);
        try testing.expectEqualStrings("Too Many Requests\n", body);
    }

    { // a different forwarded client is not throttled
        var res = try client.request(.get, url, .{ .headers = client_b });
        defer res.deinit();
        try testing.expectEqual(@as(u16, 200), res.status);
    }

    { // no forwarded header → the shared fallback bucket, still fresh
        var res = try client.request(.get, url, .{});
        defer res.deinit();
        try testing.expectEqual(@as(u16, 200), res.status);
    }

    try testing.expectEqual(@as(usize, 3), l.keyCount()); // 1.2.3.4, 5.6.7.8, fallback
}

fn hHello(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll("hello");
}
