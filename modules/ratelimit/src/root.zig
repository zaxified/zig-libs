// SPDX-License-Identifier: MIT

//! ratelimit — token-bucket limiting: a pure keyed limiter plus a `router`
//! middleware answering **429 + Retry-After**, and a per-user limiter for
//! new *connections* on the accept loop.
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
//! - `ConnectionLimiter` (conn.zig) — a different question: how fast may a
//!   **user** open new connections. Keyed by configured CIDR prefixes, not
//!   by request headers, and plugged into `http.Server.Options.on_connect`
//!   so a refusal costs one `close` and no response bytes. See its own
//!   module doc for the identity model and for what an address-rotating
//!   attacker does and does not get.
//!
//! ## Client-key trust policy (X-Forwarded-For / socket peer)
//!
//! The default key (`KeySource.forwarded_ip`) is the client IP — as
//! established by a trusted reverse proxy when one is in front, or the
//! socket peer address when the server faces the internet directly. Policy,
//! in order:
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
//! 3. **The socket peer address** (`http.Server.Request.peerAddress`) —
//!    the real client when no proxy is in the way (direct-internet
//!    deployment). Keys are the IP only (ports vary per connection);
//!    IPv4-mapped IPv6 peers key as their plain IPv4 form.
//! 4. **`fallback_key`** — one shared bucket, only reachable when even the
//!    socket peer is unknown (driving the codec socket-free via
//!    `serveStream` without a `peer`).
//!
//! **Caveat when directly reachable:** clients can then send forged
//! `X-Forwarded-For` / `X-Real-IP` headers and steps 1–2 will honor them —
//! choosing their own bucket (a per-client limiter, not an unkeyed
//! bypass). If you are *not* behind a proxy that always sets XFF, use a
//! `KeySource.custom` extractor that goes straight to
//! `req.peerAddress()`, or strip those headers at the edge.

const std = @import("std");
const builtin = @import("builtin");
const router = @import("router");
const http = @import("http");
const netaddr = @import("netaddr");

pub const meta = .{
    .platform = .any,
    .role = .util,
    // `Limiter` is internally synchronized (documented spinlock around an
    // O(1) critical section); the bare `TokenBucket` is single_owner.
    .concurrency = .threadsafe,
    .model_after = "Go golang.org/x/time/rate (token bucket) + nginx limit_req (keyed store)",
    .deps = .{ "router", "http", "netaddr" },
};

const Allocator = std.mem.Allocator;

// ── connection-establishment limiting (conn.zig) ────────────────────────────

const conn = @import("conn.zig");

/// Per-user limiter for **new connections**, for
/// `http.Server.Options.on_connect`. See conn.zig's module doc.
pub const ConnectionLimiter = conn.ConnectionLimiter;
/// A configured user: a name plus the CIDR prefixes that identify it.
pub const ConnUser = conn.User;
/// Configuration for `ConnectionLimiter`.
pub const ConnOptions = conn.Options;
/// Owner's ruling: 4 new connections per second per user, burst 8.
pub const default_conn_rate_per_s = conn.default_conn_rate_per_s;
pub const default_conn_burst = conn.default_conn_burst;

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
    /// Client IP — see the trust policy in the module doc: rightmost
    /// element of the last `X-Forwarded-For`, else `X-Real-IP`, else the
    /// socket peer address, else `fallback_key`.
    forwarded_ip,
    /// Value of this request header (e.g. an API key). Requests without the
    /// header fall back to the `forwarded_ip` chain.
    header: []const u8,
    /// Fully custom extraction.
    custom: KeyFn,
};

/// Key used when neither a forwarded/real-IP header nor a socket peer
/// address exists — only possible when the codec is driven socket-free
/// (`http.Server.serveStream` without `StreamOptions.peer`); a socket-served
/// request always has a peer.
pub const fallback_key = "(no-client-ip)";

/// Buffer size for `clientKey`'s peer-address formatting.
pub const peer_key_len_max = netaddr.max_ip_text_len;

pub const Options = struct {
    /// Sustained per-key rate, tokens (requests) per second. Must be > 0.
    rate_per_s: f64,
    /// Per-key burst capacity. Must be ≥ 1.
    burst: u32,
    /// At most this many distinct keys tracked (memory bound); beyond it the
    /// least-recently-used key is evicted — an evicted key seen again starts
    /// over with a full bucket. Must be ≥ 1.
    max_keys: usize = 4096,
    /// At most this many bytes of a key are stored/looked-up; a longer key is
    /// truncated to this prefix before it ever reaches the map. Bounds
    /// per-entry memory when `key = .forwarded_ip` and the deployment is
    /// directly internet-facing, where the stored key is an attacker-chosen,
    /// otherwise-unbounded `X-Forwarded-For`/`X-Real-IP` header value. Two
    /// distinct long keys sharing the same first `max_key_len` bytes
    /// deliberately collide into one bucket — a coarser key, not a bypass.
    /// Must be ≥ 1.
    max_key_len: usize = 128,
    /// Idle expiry: a key untouched this long is dropped (swept from the LRU
    /// tail when new keys arrive) or reset to a full bucket on its next hit.
    /// 0 disables. Memory stays bounded by `max_keys` either way — the TTL
    /// only releases idle keys' memory early.
    ttl_ms: u64 = 10 * std.time.ms_per_min,
    /// Time source — inject a fake for deterministic tests. The algorithm
    /// never reads a wall clock on its own.
    clock: Clock = .monotonic,
    /// Client-key extraction used by `middleware()`. **No default, by
    /// design** (audit F1): `.forwarded_ip` is the right choice behind a
    /// trusted reverse proxy but is client-forgeable — a direct-internet
    /// deployment that silently inherited it as a default would let an
    /// attacker rotate `X-Forwarded-For` values to dodge the limiter almost
    /// entirely (a fresh bucket per forged value, not just "their own
    /// bucket"). There is no universally-safe default either way: flipping
    /// it to peer-address-only would silently misbehave for the (likely
    /// more common) proxied deployment, collapsing every client behind the
    /// proxy into one shared bucket. Forcing an explicit choice here trades
    /// a silent footgun for a compile-time decision point — see the module
    /// doc comment's "Client-key trust policy" section before picking.
    key: KeySource,
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
        std.debug.assert(options.max_key_len >= 1);
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
    pub fn allowAt(l: *Limiter, raw_key: []const u8, now_ns: u64) Decision {
        const cfg: TokenBucket.Config = .{ .rate_per_s = l.options.rate_per_s, .burst = l.options.burst };
        const ttl_ns = l.options.ttl_ms *| std.time.ns_per_ms;
        // Cap the stored/looked-up key length (F3 hardening — see
        // `Options.max_key_len`) before it ever reaches the map.
        const key = raw_key[0..@min(raw_key.len, l.options.max_key_len)];

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
    var peer_buf: [peer_key_len_max]u8 = undefined; // outlives the allow call; the store copies
    const decision = l.allow(keyOf(l, ctx, &peer_buf));
    if (decision.allowed) return next.run(ctx);

    // Deny. Header values are formatted on this stack frame; `setHeader`
    // copies them into the response writer's own storage at call time, so
    // they only have to outlive the call and this branch no longer forces an
    // early `end()`. Handing the head back to the serving loop is the point,
    // not a side effect: this is a middleware, and an OUTER one that works
    // after `next.run` — `sessions` saves its cookie there, `csrf` issues its
    // token there — could not touch a 429 whose head had already gone out.
    //
    // RateLimit-* headers only appear on 429s: they are formatted fresh in
    // this branch and set immediately, so allowed responses never see them.
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
}

fn ceilDivMsToS(ms: u64) u64 {
    return std.math.divCeil(u64, ms, std.time.ms_per_s) catch unreachable;
}

// ── key extraction ──────────────────────────────────────────────────────────

fn keyOf(l: *const Limiter, ctx: *router.Ctx, peer_buf: *[peer_key_len_max]u8) []const u8 {
    switch (l.options.key) {
        .forwarded_ip => return clientKey(ctx.req, peer_buf),
        .header => |name| {
            if (ctx.req.header(name)) |v| {
                const trimmed = std.mem.trim(u8, v, " \t");
                if (trimmed.len != 0) return trimmed;
            }
            return clientKey(ctx.req, peer_buf);
        },
        .custom => |k| return k.keyFor(k.ctx, ctx),
    }
}

/// The client key per the module's trust policy (see the module doc):
/// rightmost element of the **last** `X-Forwarded-For` header (the one the
/// nearest trusted proxy appended — the only part a client cannot forge),
/// else `X-Real-IP`, else the **socket peer IP** (formatted into
/// `peer_buf`, port excluded so one client is one bucket; IPv4-mapped IPv6
/// unified with plain IPv4), else `fallback_key`. The result either borrows
/// from the request or points into `peer_buf` — treat its lifetime as the
/// shorter of the two. Exposed for reuse by other middleware (logging,
/// abuseguard).
pub fn clientKey(req: *const http.Server.Request, peer_buf: *[peer_key_len_max]u8) []const u8 {
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
    if (req.peerAddress()) |peer| {
        const ip: netaddr.Ip = switch (peer) {
            .ip4 => |a| .{ .v4 = a.bytes },
            .ip6 => |a| .{ .v6 = a.bytes },
        };
        return netaddr.formatIp(ip.unmap(), peer_buf);
    }
    return fallback_key;
}

// ── tests: the pure algorithm (no clock, no HTTP) ───────────────────────────

const testing = std.testing;

test {
    // Pull conn.zig's tests into this module's test binary. Zig only
    // collects tests from files it actually *analyses*, and a
    // container-level `@import` whose decls no test references is never
    // analysed: without this line `zig build test-ratelimit` reported
    // "18/18 tests passed" while all 8 connection-limiter tests silently
    // did not exist — a whole file's worth of green that was never run.
    _ = @import("conn.zig");
}

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

// ── tests: the external anchor (captured x/time/rate trace) ────────────────

/// Frozen reference trace from Go `golang.org/x/time/rate` — the package this
/// bucket is modelled on. See the file header for provenance; it is a plain
/// data table, so this test runs offline and can never skip.
const xrate = @import("xrate_vectors.zig");

/// Nanoseconds → whole milliseconds, rounded up, in integer arithmetic. Applied
/// to the *reference's* durations so the comparison against `retry_after_ms` /
/// `reset_after_ms` does not go back through `ceilMs`, the very function under
/// test.
fn ceilNsToMs(ns: u64) u64 {
    return (ns + std.time.ns_per_ms - 1) / std.time.ns_per_ms;
}

test "TokenBucket: replays a captured golang.org/x/time/rate AllowN trace" {
    // The other `TokenBucket` tests assert hand-computed expectations: honest,
    // but self-authored, so they cannot disagree with us. This one replays a
    // sequence produced by the reference implementation itself.
    //
    // Float balances are compared with a tolerance, not bit-for-bit: x/time/rate
    // converts elapsed time via `time.Duration.Seconds()` (a split
    // seconds+nanos sum) where we divide a single u64 by 1e9, so the two can
    // land an ULP apart. Everything a caller can observe — the allow/deny
    // decision, `remaining`, `retry_after_ms`, `reset_after_ms` — is compared
    // exactly.
    const tokens_tolerance = 1e-12;

    for (xrate.cases) |c| {
        const cfg: TokenBucket.Config = .{ .rate_per_s = c.rate_per_s, .burst = c.burst };
        // Every captured case opens at its start instant, where x/time/rate's
        // zero-valued `last` has already refilled the bucket to `burst`.
        try testing.expectEqual(@as(u64, 0), c.steps[0].at_ms);
        var b: TokenBucket = .full(cfg, 0);

        for (c.steps, 0..) |s, i| {
            const d = b.allowAt(cfg, s.at_ms * std.time.ns_per_ms);
            errdefer std.debug.print(
                "\nx/time/rate vector mismatch: case \"{s}\" step {d} at {d} ms\n" ++
                    "  reference: allowed={} remaining={d} wait={d} ns reset={d} ns tokens={d}\n" ++
                    "  ours:      allowed={} remaining={d} retry_after={d} ms reset_after={d} ms tokens={d}\n",
                .{
                    c.name,      i,                s.at_ms,
                    s.allowed,   s.remaining,      s.wait_ns,
                    s.reset_ns,  s.tokens_after,   d.allowed,
                    d.remaining, d.retry_after_ms, d.reset_after_ms,
                    b.tokens,
                },
            );
            try testing.expectEqual(s.allowed, d.allowed);
            try testing.expectEqual(s.remaining, d.remaining);
            try testing.expectEqual(ceilNsToMs(s.wait_ns), d.retry_after_ms);
            try testing.expectEqual(ceilNsToMs(s.reset_ns), d.reset_after_ms);
            try testing.expect(@abs(s.tokens_after - b.tokens) <= tokens_tolerance);
        }
    }
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
        .key = .forwarded_ip,
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
    var l = Limiter.init(testing.allocator, .{ .rate_per_s = 1, .burst = 1, .clock = tc.clock(), .key = .forwarded_ip });
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
        .key = .forwarded_ip,
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

test "Limiter: max_key_len truncates over-long keys instead of storing them whole" {
    var tc: TestClock = .{};
    var l = Limiter.init(testing.allocator, .{
        .rate_per_s = 1,
        .burst = 1,
        .max_key_len = 8,
        .clock = tc.clock(),
        .key = .forwarded_ip,
    });
    defer l.deinit();

    // Two distinct 12-byte keys sharing the same first 8 bytes. Without
    // truncation each gets its own bucket (both allowed, keyCount == 2). With
    // `max_key_len = 8` they collide into one stored 8-byte key: the first
    // request spends the single burst token and the second — for a
    // *different* raw key — is denied because it lands on the same,
    // already-exhausted bucket.
    const key_a = "12345678AAAA";
    const key_b = "12345678BBBB";
    try testing.expect(l.allow(key_a).allowed);
    try testing.expect(!l.allow(key_b).allowed);
    try testing.expectEqual(@as(usize, 1), l.keyCount());
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
        .key = .forwarded_ip,
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
    var l = Limiter.init(failing.allocator(), .{ .rate_per_s = 1, .burst = 1, .clock = tc.clock(), .key = .forwarded_ip });
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
        .key = .forwarded_ip,
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
/// (same harness as the router's own tests), optionally with a socket peer.
fn runWirePeer(r: *router.Router, bytes: []const u8, out_buf: []u8, peer: ?std.Io.net.IpAddress) []const u8 {
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
        .peer = peer,
    }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    return out.buffered();
}

fn runWire(r: *router.Router, bytes: []const u8, out_buf: []u8) []const u8 {
    return runWirePeer(r, bytes, out_buf, null);
}

fn wire(comptime headers: []const u8) []const u8 {
    return "GET /t HTTP/1.1\r\nHost: t\r\n" ++ headers ++ "Connection: close\r\n\r\n";
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
    var l = Limiter.init(testing.allocator, .{ .rate_per_s = 1, .burst = 2, .clock = tc.clock(), .key = .forwarded_ip });
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

/// A synthetic "outer" middleware shaped like `sessions`/`csrf`: it lets the
/// chain run, then tries to write a header afterward, swallowing failure
/// the way `csrf.issue` swallows `addSetCookie`'s error with `catch {}`.
/// Registered *before* `ratelimit` in the chain, so it wraps it — its own
/// `next.run` call is what runs `ratelimit`'s `middlewareRun`, the 429
/// branch included.
fn mwOuterCookie(_: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    try next.run(ctx);
    ctx.res.addSetCookie("session=abc") catch {};
}

test "middleware: an OUTER middleware writing after next.run still lands its header" {
    // Before this task, the 429 branch forced an early `end()`, so an outer
    // middleware working after `next.run` — exactly `sessions` (save/
    // destroy) and `csrf` (issue) — would have this call return
    // `error.HeadersSent`, swallowed silently by the `catch {}` both use.
    // `ratelimit` is where this fix originated (`6ba5d7d`); `throttle` and
    // `cors` copied it a few commits later and each got this same
    // regression test — this module never did until now.
    var tc: TestClock = .{};
    var l = Limiter.init(testing.allocator, .{ .rate_per_s = 1, .burst = 1, .clock = tc.clock(), .key = .forwarded_ip });
    defer l.deinit();

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(.{ .run = mwOuterCookie });
    try r.use(l.middleware());
    try r.get("/t", hCount);

    var hits: u32 = 0;
    r.state = &hits;

    var buf: [1024]u8 = undefined;
    try expectStatus(runWire(&r, wire(""), &buf), "200"); // consumes the one burst token
    const got = runWire(&r, wire(""), &buf); // second request: denied
    try expectStatus(got, "429");
    try expectHeaderLine(got, "Set-Cookie: session=abc");
}

/// The handler half of the dead-frame test below: format the 429's
/// `Retry-After` / `RateLimit-*` values into buffers that die with THIS
/// frame — the exact shape of the deny branch in `middlewareRun`
/// (`root.zig:432-440`, `retry_buf`/`limit_buf`/`reset_buf`) — and hand them
/// to `setHeader`. Mirrors `http`'s and `tracecontext`'s own
/// `setFromDeadFrame`.
///
/// A separate `noinline` function, not a block inside the test: Zig gives
/// each local its own slot for the enclosing function's entire body in
/// Debug, so a block scope frees nothing and the bug this guards would stay
/// invisible. Only a returned frame is really reusable.
noinline fn denyFromDeadFrame(res: *http.Server.ResponseWriter) !void {
    var retry_buf: [24]u8 = undefined;
    var limit_buf: [24]u8 = undefined;
    var reset_buf: [24]u8 = undefined;
    res.setStatus(429);
    try res.setHeader("Retry-After", std.fmt.bufPrint(&retry_buf, "{d}", .{1}) catch unreachable);
    try res.setHeader("RateLimit-Limit", std.fmt.bufPrint(&limit_buf, "{d}", .{2}) catch unreachable);
    try res.setHeader("RateLimit-Remaining", "0");
    try res.setHeader("RateLimit-Reset", std.fmt.bufPrint(&reset_buf, "{d}", .{2}) catch unreachable);
}

/// Reuse the frame `denyFromDeadFrame` just left, the way the next call down
/// the stack would have. Bigger than that frame so it covers every slot in
/// it, `noinline` + `doNotOptimizeAway` so neither the call nor the stores
/// can be optimized out.
noinline fn clobberDeny429DeadFrame() void {
    var scratch: [2048]u8 = undefined;
    @memset(&scratch, '#');
    std.mem.doNotOptimizeAway(&scratch);
}

test "middleware: 429 Retry-After/RateLimit-* values survive the caller's dead frame" {
    // What this pins: `middlewareRun`'s deny branch formats
    // `Retry-After`/`RateLimit-*` into plain locals that die once
    // `middlewareRun` returns — well before `end()` runs. This leans
    // entirely on `http`'s `ResponseWriter.setHeader` copying the bytes
    // into its own storage rather than borrowing the caller's; `runWire`
    // drives dispatch with no seam in which to clobber the stack on
    // purpose, so the writer is built and driven by hand here, mirroring
    // `http`'s and `tracecontext`'s own dead-frame tests.
    var out_buf: [1024]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var body_buf: [64]u8 = undefined;
    var chunk_buf: [32]u8 = undefined;
    var rw: http.Server.ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});

    try denyFromDeadFrame(&rw);
    clobberDeny429DeadFrame();

    try rw.writeAll("Too Many Requests\n");
    try rw.end();
    const got = out.buffered();

    try expectHeaderLine(got, "Retry-After: 1");
    try expectHeaderLine(got, "RateLimit-Limit: 2");
    try expectHeaderLine(got, "RateLimit-Remaining: 0");
    try expectHeaderLine(got, "RateLimit-Reset: 2");
    // …and not one byte of the clobber pattern anywhere on it.
    try testing.expect(std.mem.indexOf(u8, got, "#") == null);
}

test "middleware: key extraction — XFF forms, X-Real-IP, fallback key" {
    var tc: TestClock = .{};
    var l = Limiter.init(testing.allocator, .{ .rate_per_s = 0.01, .burst = 1, .clock = tc.clock(), .key = .forwarded_ip });
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

    // No client headers and no socket peer (this harness is socket-free):
    // everything shares the one fallback bucket.
    try expectStatus(runWire(&rl.r, wire(""), &buf), "200");
    try expectStatus(runWire(&rl.r, wire(""), &buf), "429");
    // Empty XFF value also falls through to the fallback bucket.
    try expectStatus(runWire(&rl.r, wire("X-Forwarded-For:\r\n"), &buf), "429");
}

test "middleware: socket peer address is the fallback key (port-insensitive, v4-mapped unified)" {
    var tc: TestClock = .{};
    var l = Limiter.init(testing.allocator, .{ .rate_per_s = 0.01, .burst = 1, .clock = tc.clock(), .key = .forwarded_ip });
    defer l.deinit();
    var rl = try RouterUnderLimit.init(&l);
    defer rl.deinit();
    rl.start();
    var buf: [1024]u8 = undefined;

    const ip = std.Io.net.IpAddress;
    const peer_a1: ip = ip.parseIp4("10.0.0.1", 1111) catch unreachable;
    const peer_a2: ip = ip.parseIp4("10.0.0.1", 2222) catch unreachable;
    const peer_a6: ip = ip.parseIp6("::ffff:10.0.0.1", 3333) catch unreachable;
    const peer_b: ip = ip.parseIp4("10.0.0.2", 1111) catch unreachable;

    // Without forwarded headers the socket peer is the key…
    try expectStatus(runWirePeer(&rl.r, wire(""), &buf, peer_a1), "200");
    // …the port is excluded (a new connection is not a new bucket)…
    try expectStatus(runWirePeer(&rl.r, wire(""), &buf, peer_a2), "429");
    // …and an IPv4-mapped IPv6 peer is the same client as its IPv4 form.
    try expectStatus(runWirePeer(&rl.r, wire(""), &buf, peer_a6), "429");
    // A different peer IP is a different bucket.
    try expectStatus(runWirePeer(&rl.r, wire(""), &buf, peer_b), "200");
    // Forwarded headers still win over the socket peer when present.
    try expectStatus(runWirePeer(&rl.r, wire("X-Forwarded-For: 9.9.9.9\r\n"), &buf, peer_a1), "200");
    try testing.expectEqual(@as(usize, 3), l.keyCount()); // 10.0.0.1, 10.0.0.2, 9.9.9.9
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
    var l = Limiter.init(testing.allocator, .{ .rate_per_s = 0.1, .burst = 2, .key = .forwarded_ip });
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

    { // no forwarded header → keyed by the socket peer (127.0.0.1), fresh
        var res = try client.request(.get, url, .{});
        defer res.deinit();
        try testing.expectEqual(@as(u16, 200), res.status);
    }

    try testing.expectEqual(@as(usize, 3), l.keyCount()); // 1.2.3.4, 5.6.7.8, 127.0.0.1
}

fn hHello(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll("hello");
}
