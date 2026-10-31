// SPDX-License-Identifier: MIT

//! ratelimit — token-bucket limiting: a pure keyed limiter plus a `router`
//! middleware answering **429 + Retry-After**, and a per-user limiter for
//! new *connections* on the accept loop.
//!
//! Layering (each usable on its own):
//! - `TokenBucket` — the bare algorithm (Go `golang.org/x/time/rate`
//!   semantics: float token balance, lazy refill, burst cap). No clock, no
//!   locking, no allocation — the caller passes `now_ns`.
//! - `Limiter` — per-key buckets in a bounded store (`max_keys` cap with
//!   second-chance eviction, the CLOCK approximation of LRU, + idle TTL), internally synchronized, clock injected via
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
//! bypass). If you are *not* behind a proxy that always sets XFF — or are
//! reachable both through it and directly — use
//! `KeySource{ .forwarded_ip_trusted = .loopback }` (or `.{ .set = &proxies }`):
//! the headers then count only when the socket peer is a trusted proxy
//! (`clientIp`, Express `trust proxy` shape). `.none` keys by the peer alone.

const std = @import("std");
const testkit = @import("testkit");
const builtin = @import("builtin");
const router = @import("router");
const http = @import("http");
const netaddr = @import("netaddr");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Token-bucket per-client rate limit → 429 + Retry-After; per-user connection-rate limit for `on_connect`",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
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
    /// Denied only: time until the requested tokens are free, rounded **up**
    /// to whole milliseconds — waiting exactly this long guarantees the next
    /// attempt passes (absent other traffic). 0 when allowed;
    /// `std.math.maxInt(u64)` when the request can never pass (more tokens
    /// than `burst`).
    retry_after_ms: u64,
    /// Whole tokens left after this decision (floor of the balance; 0 while
    /// reservations hold it below zero).
    remaining: u32,
    /// Time until the bucket is completely full again — the IETF draft
    /// `RateLimit-Reset` value (rounded up to whole milliseconds).
    reset_after_ms: u64,
    /// The burst the decision was made against — the IETF draft
    /// `RateLimit-Limit` value. Carried here so a reader sees the burst the
    /// decision used even while `Limiter.setBurst` runs on another thread.
    limit: u32 = 0,
};

/// A claim on future tokens from `TokenBucket.reserveNAt` (x/time/rate's
/// `Reservation`). The holder waits `delayNs(now)` and then acts — or hands
/// it back with `TokenBucket.cancelAt`.
pub const Reservation = struct {
    /// False: nothing was taken (more than `burst` tokens, or the wait would
    /// exceed the caller's `max_wait_ns`). The other fields are then 0.
    ok: bool,
    /// Tokens taken; 0 after a cancel (a second cancel is a no-op).
    n: u32 = 0,
    /// The instant the reserved tokens are available.
    time_to_act_ns: u64 = 0,
    /// The rate in force when the reservation was made; a cancel restores
    /// against it, not against a later `setLimit`.
    rate_per_s: f64 = 0,

    /// How long the holder must wait from `now_ns` before acting.
    pub fn delayNs(r: Reservation, now_ns: u64) u64 {
        return r.time_to_act_ns -| now_ns;
    }
};

/// Token bucket, mirroring Go `golang.org/x/time/rate`: a float token
/// balance refilled lazily at `rate_per_s`, capped at `burst`; `n` tokens per
/// event (one for `allowAt`); denials consume nothing; reservations may take
/// the balance below zero (future tokens). Pure state + math — no clock, no
/// locking (single owner; `Limiter` adds keying and synchronization).
///
/// The config is the caller's, passed on every call. To change it at run
/// time, call `advanceAt(old_cfg, now)` first and pass the new one from then
/// on (x/time/rate's `SetLimitAt`/`SetBurstAt`): tokens earned so far are
/// kept at the old rate, a smaller burst caps the balance.
pub const TokenBucket = struct {
    /// Current fractional token balance: ≤ burst, negative while
    /// reservations hold future tokens.
    tokens: f64,
    /// Instant the balance was last brought up to date (refill is computed
    /// lazily from here — x/time/rate's `last`).
    updated_ns: u64,
    /// Instant of the latest admitted event or reservation (x/time/rate's
    /// `lastEvent`); `cancelAt` reads it to see whether later reservations
    /// already spent what the cancelled one would give back.
    last_event_ns: u64 = 0,

    pub const Config = struct {
        /// Sustained refill, tokens per second. Must be > 0 and finite
        /// (`allowNAt`/`reserveNAt` panic otherwise, in every build mode).
        rate_per_s: f64,
        /// Bucket capacity — the burst allowance. Must be ≥ 1 (same check).
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
        return b.allowNAt(cfg, now_ns, 1);
    }

    /// Decide an event costing `n` tokens at `now_ns` (x/time/rate
    /// `AllowN`): all `n` are taken, or none. `n > burst` can never pass;
    /// `n == 0` passes unless reservations hold the balance below zero.
    pub fn allowNAt(b: *TokenBucket, cfg: Config, now_ns: u64, n: u32) Decision {
        checkConfig(cfg);
        const allowed = b.takeNAt(cfg, now_ns, n);
        return decision(cfg, n, allowed, b.tokens);
    }

    /// The state change of `allowNAt`: advance, then take `n` tokens or none.
    fn takeNAt(b: *TokenBucket, cfg: Config, now_ns: u64, n: u32) bool {
        b.advanceAt(cfg, now_ns);
        const n_f: f64 = @floatFromInt(n);
        const allowed = n <= cfg.burst and b.tokens >= n_f;
        if (allowed) {
            b.tokens -= n_f;
            b.last_event_ns = now_ns;
        }
        return allowed;
    }

    /// The report of `allowNAt` from the balance it left (`tokens`) — pure,
    /// so `Limiter` computes it after releasing its lock.
    fn decision(cfg: Config, n: u32, allowed: bool, tokens: f64) Decision {
        const burst_f: f64 = @floatFromInt(cfg.burst);
        const n_f: f64 = @floatFromInt(n);
        return .{
            .allowed = allowed,
            .retry_after_ms = if (allowed) 0 else if (n > cfg.burst)
                std.math.maxInt(u64)
            else
                ceilMs((n_f - tokens) / cfg.rate_per_s),
            .remaining = wholeTokens(tokens),
            .reset_after_ms = ceilMs((burst_f - tokens) / cfg.rate_per_s),
            .limit = cfg.burst,
        };
    }

    /// Take `n` tokens now or from the future (x/time/rate `ReserveN`, and
    /// with a finite `max_wait_ns` the reservation `Wait` makes). The tokens
    /// are taken at once and the balance may go negative; the caller waits
    /// `Reservation.delayNs(now)` before acting. Not ok — nothing taken —
    /// when `n > burst` or the wait would exceed `max_wait_ns`
    /// (`std.math.maxInt(u64)`: no limit).
    pub fn reserveNAt(b: *TokenBucket, cfg: Config, now_ns: u64, n: u32, max_wait_ns: u64) Reservation {
        checkConfig(cfg);
        b.advanceAt(cfg, now_ns);
        if (n > cfg.burst) return .{ .ok = false };
        const left = b.tokens - @as(f64, @floatFromInt(n));
        const wait_ns: u64 = if (left < 0) durationNs(-left, cfg.rate_per_s) else 0;
        if (wait_ns > max_wait_ns) return .{ .ok = false };
        b.tokens = left;
        b.last_event_ns = now_ns +| wait_ns;
        return .{ .ok = true, .n = n, .time_to_act_ns = b.last_event_ns, .rate_per_s = cfg.rate_per_s };
    }

    /// Hand a reservation's tokens back (x/time/rate `Reservation.CancelAt`),
    /// as far as later reservations have not already counted on them. A
    /// no-op once the reservation's time has come, for a not-ok one, and for
    /// a second cancel (it zeroes `r.n`).
    pub fn cancelAt(b: *TokenBucket, cfg: Config, r: *Reservation, now_ns: u64) void {
        if (!r.ok or r.n == 0 or r.time_to_act_ns < now_ns) return;
        // Tokens reserved after this one were granted on top of it; only
        // what they did not build on can come back.
        const later_ns: f64 = @as(f64, @floatFromInt(b.last_event_ns)) - @as(f64, @floatFromInt(r.time_to_act_ns));
        const restore = @as(f64, @floatFromInt(r.n)) - later_ns / ns_per_s_f * r.rate_per_s;
        const n = r.n;
        r.n = 0;
        if (restore <= 0) return;
        b.advanceAt(cfg, now_ns);
        b.tokens = @min(b.tokens + restore, @as(f64, @floatFromInt(cfg.burst)));
        if (r.time_to_act_ns == b.last_event_ns) {
            const prev = r.time_to_act_ns -| durationNs(@floatFromInt(n), r.rate_per_s);
            if (prev >= now_ns) b.last_event_ns = prev;
        }
    }

    /// The balance at `now_ns` without changing the bucket (x/time/rate
    /// `TokensAt`); negative while reservations hold future tokens.
    pub fn tokensAt(b: TokenBucket, cfg: Config, now_ns: u64) f64 {
        var copy = b;
        copy.advanceAt(cfg, now_ns);
        return copy.tokens;
    }

    /// Bring the balance up to `now_ns` under `cfg`: refill for the time
    /// elapsed, cap at `cfg.burst`. Every decision does this first; call it
    /// directly before switching to a new config (see the type doc).
    pub fn advanceAt(b: *TokenBucket, cfg: Config, now_ns: u64) void {
        if (now_ns > b.updated_ns) {
            // rate per ns first: that division depends on the config only,
            // so it runs beside the bucket's loads instead of after them.
            const per_ns = cfg.rate_per_s / ns_per_s_f;
            b.tokens += @as(f64, @floatFromInt(now_ns - b.updated_ns)) * per_ns;
            b.updated_ns = now_ns;
        }
        b.tokens = @min(b.tokens, @as(f64, @floatFromInt(cfg.burst)));
    }

    /// The instant from which the bucket counts as idle: its last update, or
    /// a reservation's later time to act.
    fn idleSince(b: TokenBucket) u64 {
        return @max(b.updated_ns, b.last_event_ns);
    }

    /// How long an empty bucket takes to refill to `cfg.burst`, rounded up,
    /// saturating. From `idleSince` on the balance is ≥ 0 (a reservation's
    /// time to act is when its tokens have accrued), so a bucket idle this
    /// long is full.
    fn refillNs(cfg: Config) u64 {
        return durationNs(@floatFromInt(cfg.burst), cfg.rate_per_s) +| 1;
    }
};

const ns_per_s_f: f64 = @floatFromInt(std.time.ns_per_s);

/// A usable refill rate: positive and finite (NaN fails both).
pub fn validRate(r: f64) bool {
    return r > 0 and std.math.isFinite(r);
}

/// Why `Limiter.init` refuses `options` (it panics with this), or null.
pub fn optionsError(options: Options) ?[]const u8 {
    if (configError(options.rate_per_s, options.burst)) |msg| return msg;
    if (options.max_keys < 1) return "ratelimit: max_keys must be >= 1";
    if (options.max_key_len < 1) return "ratelimit: max_key_len must be >= 1";
    if (options.v6_key_bits > 128) return "ratelimit: v6_key_bits must be <= 128";
    return null;
}

/// Why a rate/burst (null = unchanged) is refused, or null.
fn configError(rate_per_s: ?f64, burst: ?u32) ?[]const u8 {
    if (rate_per_s) |r| if (!validRate(r)) return "ratelimit: rate_per_s must be > 0 and finite";
    if (burst) |b| if (b < 1) return "ratelimit: burst must be >= 1";
    return null;
}

/// The caller's `cfg` checked in every build mode, as `Limiter.init` checks
/// its options: an `assert` here was UB in ReleaseFast on a config the
/// caller passes (no-panic sweep 2026-10-28, RL-1).
fn checkConfig(cfg: TokenBucket.Config) void {
    if (configError(cfg.rate_per_s, cfg.burst)) |msg| @panic(msg);
}

/// floor(tokens) as a count, 0 for a negative balance.
fn wholeTokens(tokens: f64) u32 {
    if (!(tokens > 0)) return 0;
    return @intFromFloat(@min(tokens, @as(f64, @floatFromInt(std.math.maxInt(u32)))));
}

/// Time for `tokens` to accrue at `rate_per_s`, in whole nanoseconds
/// (truncated, as x/time/rate's duration conversion does), saturated.
fn durationNs(tokens: f64, rate_per_s: f64) u64 {
    const ns = ns_per_s_f * (tokens / rate_per_s);
    if (!(ns > 0)) return 0;
    if (ns >= @as(f64, @floatFromInt(std.math.maxInt(u64)))) return std.math.maxInt(u64);
    return @intFromFloat(ns);
}

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
    ///
    /// `buf` is scratch owned by the calling thread, for a key that has to
    /// be FORMATTED rather than borrowed from the request — which is what
    /// the module doc's own advice ("go straight to `req.peerAddress()`")
    /// requires. Without it that advice could not be followed race-free:
    /// `router.Ctx` carries no allocator or scratch, a buffer owned by the
    /// `KeyFn` is shared across the server's per-connection threads, and a
    /// slice of a stack local does not outlive the callback. A key borrowed
    /// from the request (a header value, `ctx.req.path`) ignores `buf`.
    /// Reported by a consumer of the sibling `aaa-gate`, 2026-09-17.
    keyFor: *const fn (?*anyopaque, *router.Ctx, *[peer_key_len_max]u8) []const u8,
};

/// What identifies a client for the middleware (the pure `Limiter.allow`
/// takes explicit keys and ignores this).
pub const KeySource = union(enum) {
    /// Client IP — see the trust policy in the module doc: rightmost
    /// element of the last `X-Forwarded-For`, else `X-Real-IP`, else the
    /// socket peer address, else `fallback_key`.
    forwarded_ip,
    /// Value of this request header (e.g. an API key). Requests without the
    /// header fall back to the `forwarded_ip` chain. ⚠ Only behind
    /// something that rejects invalid values first (an auth middleware
    /// ahead of this one): taken as it is, the header is chosen by the
    /// client, and a new value per request is a new full bucket — a bypass,
    /// and a way to flush other keys out of the table (review 2026-10-24).
    header: []const u8,
    /// Client IP from forwarding headers only when the socket peer is a
    /// trusted proxy (`clientIp`); a peer outside `TrustedProxies` is the
    /// client itself, whatever headers it sends. For a server reachable both
    /// through its proxy and directly, where `forwarded_ip` would let a direct
    /// client pick its own bucket.
    forwarded_ip_trusted: TrustedProxies,
    /// Fully custom extraction.
    custom: KeyFn,
};

/// Which socket peers may tell `clientIp` who the client is, through
/// `X-Forwarded-For` / `X-Real-IP` (Express `trust proxy`, Go `RemoteIP`).
pub const TrustedProxies = union(enum) {
    /// None: the socket peer is always the client; the headers are ignored.
    none,
    /// A proxy on this host (127.0.0.0/8, ::1, and their IPv4-mapped forms).
    loopback,
    /// Peers inside this set. Borrowed: it must outlive every request.
    set: *const netaddr.IpSet,

    pub fn trusts(t: TrustedProxies, ip: netaddr.Ip) bool {
        const u = ip.unmap();
        return switch (t) {
            .none => false,
            .loopback => u.isLoopback(),
            .set => |s| s.contains(u),
        };
    }
};

/// The client's address, trusting forwarding headers only from a trusted
/// peer. A peer `trusted` does not trust is the client. A trusted one's
/// last `X-Forwarded-For` line is walked from the right, past entries that
/// are themselves trusted (a chain of proxies), to the first one that is
/// not: the nearest address no trusted hop vouches for. An entry that is
/// not an address (`unknown`, an obfuscated id) stops the walk at the hop
/// to its right, which a client cannot forge. Without `X-Forwarded-For`,
/// `X-Real-IP` from a trusted peer; without either, the peer. A `:port`
/// on an entry (`1.2.3.4:80`, `[::1]:80`) is dropped. IPv4-mapped IPv6 is
/// returned as IPv4.
///
/// Null only when the request has no socket peer (`serveStream` without
/// `StreamOptions.peer`).
pub fn clientIp(req: *const http.Server.Request, trusted: TrustedProxies) ?netaddr.Ip {
    const peer = netaddr.Ip.fromStd(req.peerAddress() orelse return null).unmap();
    if (!trusted.trusts(peer)) return peer;
    var xff: ?[]const u8 = null;
    var it = req.iterateHeaders();
    while (it.next()) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "x-forwarded-for")) xff = h.value;
    }
    if (xff) |list| {
        var hop = peer;
        var rest = list;
        while (rest.len != 0) {
            const comma = std.mem.findScalarLast(u8, rest, ',');
            const entry = std.mem.trim(u8, rest[if (comma) |c| c + 1 else 0..], " \t");
            rest = if (comma) |c| rest[0..c] else rest[0..0];
            if (entry.len == 0) continue;
            const ip = forwardedEntryIp(entry) orelse return hop;
            if (!trusted.trusts(ip)) return ip;
            hop = ip;
        }
        // Every entry is a trusted proxy: the leftmost one is the client.
        return hop;
    }
    if (req.header("x-real-ip")) |v| {
        if (forwardedEntryIp(std.mem.trim(u8, v, " \t"))) |ip| return ip;
    }
    return peer;
}

/// One `X-Forwarded-For` element as an address: bare, or with a port.
fn forwardedEntryIp(entry: []const u8) ?netaddr.Ip {
    if (netaddr.parseIp(entry)) |ip| return ip.unmap();
    if (netaddr.parseAddrPort(entry)) |ap| return ap.ip.unmap();
    return null;
}

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
    /// At most this many distinct keys tracked (memory bound); beyond it a
    /// key is evicted by second chance (CLOCK, an LRU approximation): the
    /// oldest key not used since the eviction hand last passed it, so a key
    /// used about once per `max_keys` new keys stays, as under LRU, and keys
    /// a flood never reuses go first. An evicted key seen again starts over
    /// with a full bucket. Must be ≥ 1.
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
    /// The `forwarded_ip` key (and the `header` source's fallback to it) of
    /// an IPv6 client is its first `v6_key_bits` bits: one end site
    /// usually holds a whole /64 and can rotate through it, so a per-address
    /// key would hand each new address a fresh bucket. 128 keys every
    /// address apart. IPv4 is always the whole address. Same default as
    /// `ConnectionLimiter.Options.unlisted_v6_bits`.
    v6_key_bits: u8 = 64,
    /// Idle expiry: a key untouched this long is dropped (swept from the
    /// eviction hand's end when new keys arrive) or reset to a full bucket on its next hit.
    /// Never shorter than the time an empty bucket takes to refill
    /// (`burst / rate_per_s`), so expiry admits nothing the bucket would not
    /// have: with 5/hour the effective TTL is an hour, whatever is set here.
    /// 0 disables. Memory stays bounded by `max_keys` either way — the TTL
    /// only releases idle keys' memory early. Eviction at `max_keys` is the
    /// exception: an evicted key comes back full.
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

/// Per-key token buckets in a bounded store (second-chance eviction).
///
/// Thread-safety: internally synchronized — all public calls may race from
/// any number of threads (the middleware runs on `http.Server`'s
/// per-connection threads). The lock is a spinlock (`std.atomic.Mutex` +
/// `spinLoopHint`, the std SmpAllocator pattern — Zig 0.16 std has no
/// io-less blocking mutex); the critical section is a hash lookup and the
/// bucket update (the key is hashed before it, the `Decision` computed
/// after it), with a gpa alloc/free only when a key is inserted or evicted. Do not hold across it anything of your own.
///
/// Failure policy: `allow` is infallible — if tracking a *new* key fails on
/// allocator exhaustion the request is allowed untracked (fail-open: a
/// limiter must not turn OOM into a full outage). Eviction keeps the store
/// within `max_keys` before any insert, so this is truly exceptional.
pub const Limiter = struct {
    gpa: Allocator,
    options: Options,
    lock: std.atomic.Mutex = .unlocked,
    /// The entries themselves, hashed and compared by `Entry.key` (a copy
    /// inside the entry's own allocation): a set of pointers, so a probe
    /// reads one dense 8-byte slot and then the entry it names.
    map: std.HashMapUnmanaged(*Entry, void, EntryContext, std.hash_map.default_max_load_percentage) = .empty,
    /// The idle expiry in force: `ttl_ms`, raised to the refill time of the
    /// config in force; 0 = none. Recomputed with the config.
    idle_ns: u64 = 0,
    /// The eviction hand's queue: new keys and rotated ones at the front,
    /// the hand at the back (see `victimLocked`).
    lru: std.DoublyLinkedList = .{},

    const Entry = struct {
        node: std.DoublyLinkedList.Node = .{},
        key: []u8,
        bucket: TokenBucket,
        /// Used since the eviction hand last passed it (second chance).
        referenced: bool = false,
    };

    /// `std.StringHashMap`'s key hash, inlined.
    const KeyContext = struct {
        pub fn hash(_: KeyContext, k: []const u8) u64 {
            return @call(.always_inline, std.hash.Wyhash.hash, .{ 0, k });
        }
    };

    /// The map's own context: an entry hashes as its key; two entries are
    /// equal only when they are the same entry (keys are unique in the map).
    const EntryContext = struct {
        pub fn hash(_: EntryContext, e: *Entry) u64 {
            return KeyContext.hash(.{}, e.key);
        }
        pub fn eql(_: EntryContext, a: *Entry, b: *Entry) bool {
            return a == b;
        }
    };

    /// Key compare the hot path inlines: client keys (addresses, short API
    /// keys) are 8–16 bytes, two overlapping word loads apiece.
    inline fn keyEql(a: []const u8, b: []const u8) bool {
        if (a.len != b.len) return false;
        if (a.len >= 8 and a.len <= 16) {
            const r = std.mem.readInt;
            return r(u64, a[0..8], .little) == r(u64, b[0..8], .little) and
                r(u64, a[a.len - 8 ..][0..8], .little) == r(u64, b[b.len - 8 ..][0..8], .little);
        }
        return std.mem.eql(u8, a, b);
    }

    /// Looks an entry up by its key, with a hash computed earlier (outside
    /// the lock).
    const HashedKey = struct {
        h: u64,
        pub fn hash(k: HashedKey, _: []const u8) u64 {
            return k.h;
        }
        pub inline fn eql(_: HashedKey, key: []const u8, e: *Entry) bool {
            return keyEql(key, e.key);
        }
    };

    fn idleNs(options: Options) u64 {
        if (options.ttl_ms == 0) return 0;
        const cfg: TokenBucket.Config = .{ .rate_per_s = options.rate_per_s, .burst = options.burst };
        return @max(options.ttl_ms *| std.time.ns_per_ms, TokenBucket.refillNs(cfg));
    }

    /// Panics on an invalid `options` in every build mode: a NaN or zero
    /// rate would otherwise deny or admit everything silently in a release
    /// build (review 2026-10-24).
    pub fn init(gpa: Allocator, options: Options) Limiter {
        if (optionsError(options)) |msg| @panic(msg);
        return .{ .gpa = gpa, .options = options, .idle_ns = idleNs(options) };
    }

    pub fn deinit(l: *Limiter) void {
        var it = l.map.keyIterator();
        while (it.next()) |e| l.freeEntry(e.*);
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
        return l.allowNAt(raw_key, 1, now_ns);
    }

    /// Decide a request costing `n` tokens for `key` (x/time/rate `AllowN`:
    /// bytes, an expensive endpoint). All or nothing; `n > burst` never
    /// passes (`retry_after_ms` = `maxInt(u64)`).
    pub fn allowN(l: *Limiter, key: []const u8, n: u32) Decision {
        return l.allowNAt(key, n, l.options.clock.now());
    }

    /// `allowN` at an explicit instant.
    pub fn allowNAt(l: *Limiter, raw_key: []const u8, n: u32, now_ns: u64) Decision {
        // Only the state change runs under the lock: the key is hashed
        // before it and the report (divisions, rounding) computed after it.
        const key = l.storedKey(raw_key);
        const h = KeyContext.hash(.{}, key);
        var cfg: TokenBucket.Config = undefined;
        var allowed: bool = undefined;
        var tokens: f64 = undefined;
        {
            lockSpin(&l.lock);
            defer l.lock.unlock();
            cfg = l.config();
            // OOM → fail open (documented): decide on a fresh bucket.
            var fresh: TokenBucket = undefined;
            const b = l.bucketLockedHashed(key, h, now_ns) orelse blk: {
                fresh = .full(cfg, now_ns);
                break :blk &fresh;
            };
            allowed = b.takeNAt(cfg, now_ns, n);
            tokens = b.tokens;
        }
        return TokenBucket.decision(cfg, n, allowed, tokens);
    }

    pub const WaitError = error{
        /// `n` exceeds the burst: no wait can ever admit it.
        ExceedsBurst,
        /// Admission would need longer than the caller's `max_wait_ns`.
        WaitTooLong,
    } || std.Io.Cancelable;

    /// Block until `n` tokens for `key` are available, then take them
    /// (x/time/rate `WaitN`) — pacing one's own outgoing calls. Reserves at
    /// once and sleeps the reservation's delay on `io`; returns at once when
    /// the tokens are already there. Fails without taking anything when
    /// `n > burst` or the wait would exceed `max_wait_ns` (x/time/rate's
    /// context deadline; `maxInt(u64)` = no limit).
    ///
    /// Differs from x/time/rate in one way: a sleep cancelled through `io`
    /// returns `error.Canceled` with the tokens still taken (x/time/rate
    /// hands them back). Under-admission only: a later caller waits longer,
    /// nobody gets past the limit. The key's bucket may have been evicted and
    /// recreated meanwhile, so giving tokens back to "it" could credit a
    /// stranger.
    ///
    /// The delay is computed on `Options.clock` and slept on `io`'s awake
    /// clock; with the default monotonic clock they agree. Fail-open like
    /// `allow`: when tracking a new key fails on allocation it returns at
    /// once, unpaced.
    pub fn waitN(l: *Limiter, io: std.Io, key: []const u8, n: u32, max_wait_ns: u64) WaitError!void {
        const now_ns = l.options.clock.now();
        const r: Reservation = blk: {
            lockSpin(&l.lock);
            defer l.lock.unlock();
            const cfg = l.config();
            if (n > cfg.burst) return error.ExceedsBurst;
            const b = l.bucketLocked(key, now_ns) orelse return; // OOM → fail open
            break :blk b.reserveNAt(cfg, now_ns, n, max_wait_ns);
        };
        if (!r.ok) return error.WaitTooLong;
        const delay = r.delayNs(now_ns);
        if (delay == 0) return;
        try io.sleep(.fromNanoseconds(delay), .awake);
    }

    /// Change the sustained rate for every key (x/time/rate `SetLimit`):
    /// tokens earned so far are kept at the old rate, refill continues at
    /// the new one. Takes the lock and walks every tracked key once.
    pub fn setRate(l: *Limiter, rate_per_s: f64) void {
        l.setConfigAt(rate_per_s, null, l.options.clock.now());
    }

    /// Change the burst for every key (x/time/rate `SetBurst`): a balance
    /// above the new burst is cut to it; a raised burst fills by refill.
    pub fn setBurst(l: *Limiter, burst: u32) void {
        l.setConfigAt(null, burst, l.options.clock.now());
    }

    /// `setRate`/`setBurst` at an explicit instant; null keeps a value.
    pub fn setConfigAt(l: *Limiter, rate_per_s: ?f64, burst: ?u32, now_ns: u64) void {
        if (configError(rate_per_s, burst)) |msg| @panic(msg);
        lockSpin(&l.lock);
        defer l.lock.unlock();
        const old = l.config();
        var it = l.map.keyIterator();
        while (it.next()) |e| e.*.bucket.advanceAt(old, now_ns);
        if (rate_per_s) |r| l.options.rate_per_s = r;
        if (burst) |b| l.options.burst = b;
        l.idle_ns = idleNs(l.options);
    }

    /// The rate and burst in force (x/time/rate `Limit`/`Burst`).
    pub fn currentConfig(l: *Limiter) TokenBucket.Config {
        lockSpin(&l.lock);
        defer l.lock.unlock();
        return l.config();
    }

    /// Caller holds the lock.
    fn config(l: *const Limiter) TokenBucket.Config {
        return .{ .rate_per_s = l.options.rate_per_s, .burst = l.options.burst };
    }

    /// The key's bucket, created (full) or reset by the idle TTL as needed,
    /// marked used for the eviction hand. Null only when tracking a new key failed on
    /// allocation. Caller holds the lock.
    fn bucketLocked(l: *Limiter, raw_key: []const u8, now_ns: u64) ?*TokenBucket {
        const key = l.storedKey(raw_key);
        return l.bucketLockedHashed(key, KeyContext.hash(.{}, key), now_ns);
    }

    /// Cap the stored/looked-up key length (F3 hardening — see
    /// `Options.max_key_len`) before it ever reaches the map. `max_key_len`
    /// never changes, so this needs no lock.
    fn storedKey(l: *const Limiter, raw_key: []const u8) []const u8 {
        return raw_key[0..@min(raw_key.len, l.options.max_key_len)];
    }

    /// `bucketLocked` for a key already capped by `storedKey`, with its
    /// `KeyContext` hash `h`.
    fn bucketLockedHashed(l: *Limiter, key: []const u8, h: u64, now_ns: u64) ?*TokenBucket {
        const cfg = l.config();
        // A key may expire only once its bucket would be full anyway: a TTL
        // shorter than the refill time (5/hour with a 10 min TTL) would hand
        // an idle key a fresh burst early -- over-admission (review
        // 2026-10-24). So the effective TTL is at least `refillNs`.
        const ttl_ns = l.idle_ns;
        if (l.map.getKeyAdapted(key, HashedKey{ .h = h })) |e| {
            // Idle-expired keys start over with a full bucket (the bucket
            // has refilled to full by then -- see `ttl_ns`; this also resets
            // `updated_ns` so the entry stops looking expired). A pending
            // reservation keeps a key busy until its time to act.
            if (ttl_ns != 0 and now_ns -| e.bucket.idleSince() > ttl_ns)
                e.bucket = .full(cfg, now_ns);
            // Second chance instead of an LRU relink: a hit writes one flag
            // in the entry it already updates, not three other entries'
            // links (exact LRU cost ~20 % of a keyed decision, 2026-10-24).
            e.referenced = true;
            return &e.bucket;
        }

        // New key. First sweep idle-expired keys off the tail (releases idle
        // memory without a timer thread): an expired tail goes, a live one
        // used since the hand last passed it is rotated to the front with
        // its flag cleared, a live unused one stops the sweep. At most one
        // pass over the table. Then enforce the cap.
        if (ttl_ns != 0) {
            var budget = l.map.count();
            while (budget > 0) : (budget -= 1) {
                const e = entryOf(l.lru.last orelse break);
                if (now_ns -| e.bucket.idleSince() > ttl_ns) {
                    l.removeEntry(e);
                } else if (e.referenced) {
                    l.secondChance(e);
                } else break;
            }
        }
        if (l.map.count() >= l.options.max_keys) l.removeEntry(l.victimLocked());

        const e = l.insert(key, .full(cfg, now_ns)) catch return null; // OOM → fail open (documented)
        return &e.bucket;
    }

    /// Number of keys currently tracked (diagnostics / tests).
    pub fn keyCount(l: *Limiter) usize {
        lockSpin(&l.lock);
        defer l.lock.unlock();
        return l.map.count();
    }

    /// One allocation per key: the `Entry`, its key bytes right behind it,
    /// so a lookup's key compare and the bucket it then updates share a
    /// cache line or two instead of three separate places.
    fn insert(l: *Limiter, key: []const u8, bucket: TokenBucket) Allocator.Error!*Entry {
        const bytes = try l.gpa.alignedAlloc(u8, .of(Entry), @sizeOf(Entry) + key.len);
        errdefer l.gpa.free(bytes);
        const e: *Entry = @ptrCast(bytes.ptr);
        const key_copy = bytes[@sizeOf(Entry)..];
        @memcpy(key_copy, key);
        e.* = .{ .key = key_copy, .bucket = bucket };
        try l.map.put(l.gpa, e, {});
        l.lru.prepend(&e.node);
        return e;
    }

    /// The entry owning a list node. `Entry.bucket.updated_ns` (u64) gives
    /// `Entry` a stricter alignment than `std.DoublyLinkedList.Node` alone
    /// requires on a 32-bit target; `@fieldParentPtr` can't prove the
    /// recovered `*Entry` meets it from the node's declared type.
    /// `@alignCast` is safe because every `Entry` is allocated
    /// `Entry`-aligned (`insert`) with `node` at offset 0 — the same idiom
    /// used throughout http/ipcbus/zipstream/aaa-gate for intrusive lists.
    fn entryOf(node: *std.DoublyLinkedList.Node) *Entry {
        return @alignCast(@fieldParentPtr("node", node));
    }

    /// Clear the entry's flag and move it to the front: the hand passes it.
    fn secondChance(l: *Limiter, e: *Entry) void {
        e.referenced = false;
        l.lru.remove(&e.node);
        l.lru.prepend(&e.node);
    }

    /// The entry to evict at the cap (CLOCK / second chance): the tail
    /// unless it was used since the hand last passed it, in which case it
    /// is rotated to the front and the next one is looked at. Ends within
    /// one pass: every rotation clears a flag. Caller holds the lock; the
    /// table is not empty.
    fn victimLocked(l: *Limiter) *Entry {
        while (true) {
            const e = entryOf(l.lru.last.?);
            if (!e.referenced) return e;
            l.secondChance(e);
        }
    }

    fn freeEntry(l: *Limiter, e: *Entry) void {
        const bytes: [*]align(@alignOf(Entry)) u8 = @ptrCast(e);
        l.gpa.free(bytes[0 .. @sizeOf(Entry) + e.key.len]);
    }

    fn removeEntry(l: *Limiter, e: *Entry) void {
        const removed = l.map.remove(e);
        std.debug.assert(removed);
        l.lru.remove(&e.node);
        l.freeEntry(e);
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
    // A hand-built `router.Middleware` without `state` (no-panic sweep
    // 2026-10-28, RL-2): `.?` was UB in ReleaseFast.
    const l: *Limiter = @ptrCast(@alignCast(state orelse
        @panic("ratelimit: the middleware needs state = the Limiter (use Limiter.middleware())")));
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
    try ctx.res.setHeader("Retry-After", std.mem.print(&retry_buf, "{d}", .{retry_s}) catch unreachable);
    try ctx.res.setHeader("RateLimit-Limit", std.mem.print(&limit_buf, "{d}", .{decision.limit}) catch unreachable);
    try ctx.res.setHeader("RateLimit-Remaining", "0");
    try ctx.res.setHeader("RateLimit-Reset", std.mem.print(&reset_buf, "{d}", .{ceilDivMsToS(decision.reset_after_ms)}) catch unreachable);
    try ctx.res.setHeader("Content-Type", "text/plain");
    try ctx.res.writeAll("Too Many Requests\n");
}

fn ceilDivMsToS(ms: u64) u64 {
    return std.math.divCeil(u64, ms, std.time.ms_per_s) catch unreachable;
}

// ── key extraction ──────────────────────────────────────────────────────────

fn keyOf(l: *const Limiter, ctx: *router.Ctx, peer_buf: *[peer_key_len_max]u8) []const u8 {
    switch (l.options.key) {
        .forwarded_ip => return ipKey(clientKey(ctx.req, peer_buf), l.options.v6_key_bits, peer_buf),
        .header => |name| {
            if (ctx.req.header(name)) |v| {
                const trimmed = std.mem.trim(u8, v, " \t");
                if (trimmed.len != 0) return trimmed;
            }
            return ipKey(clientKey(ctx.req, peer_buf), l.options.v6_key_bits, peer_buf);
        },
        .forwarded_ip_trusted => |t| {
            const ip = clientIp(ctx.req, t) orelse return fallback_key;
            return ipKey(netaddr.formatIp(ip, peer_buf), l.options.v6_key_bits, peer_buf);
        },
        .custom => |k| return k.keyFor(k.ctx, ctx, peer_buf),
    }
}

/// The bucket key for a client address: parsed, IPv4-mapped unified with
/// IPv4, and an IPv6 address cut to its first `v6_bits` (so one host's
/// /64 is one bucket, not 2^64 -- review 2026-10-24), rendered canonically
/// into `buf` (`::1` and `0:0:0:0:0:0:0:1` are one key). Text that is not
/// an address (a forwarded value naming something else) stays the key
/// as it is. `text` may point into `buf`: it is parsed before `buf` is
/// written.
fn ipKey(text: []const u8, v6_bits: u8, buf: *[peer_key_len_max]u8) []const u8 {
    const ip = (netaddr.parseIp(text) orelse return text).unmap();
    const keyed: netaddr.Ip = switch (ip) {
        .v4 => ip,
        .v6 => (netaddr.Prefix{ .addr = ip, .bits = v6_bits }).masked().addr,
    };
    return netaddr.formatIp(keyed, buf);
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
        const start = if (std.mem.findScalarLast(u8, v, ',')) |i| i + 1 else 0;
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
    _ = @import("model_fuzz_test.zig");
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

const xrate_ops = @import("xrate_ops_vectors.zig");

test "TokenBucket: replays captured x/time/rate AllowN/ReserveN/CancelAt/SetLimitAt/SetBurstAt sequences" {
    // 8 seeded random sequences on one reference limiter each (see the
    // vector file): n in 0..burst+1, reservations into the future, cancels of
    // due / already-cancelled / not-ok / later-built-upon reservations, and
    // rate and burst changes mid-flight. Decisions are compared exactly; the
    // balance within a tolerance (see the AllowN trace test for why), the
    // reservation delay within 1 ns (x/time/rate truncates a float product
    // to whole nanoseconds; an ULP on either side can move it by one).
    // Negative controls 2026-10-11, each red here: (a) `cancelAt` without
    // the later-reservation correction (restore all `n`); (b) `allowNAt` not
    // recording `last_event_ns`; (c) `advanceAt` capping only when time
    // moved (a lowered burst then leaves the balance above it).
    const tokens_tolerance = 1e-9;
    var reach = @as([6]usize, @splat(0)); // allow-deny, reserve-future, cancel-restored, cancel-noop, set_limit, set_burst
    for (xrate_ops.cases) |c| {
        var cfg: TokenBucket.Config = .{ .rate_per_s = c.rate_per_s, .burst = c.burst };
        var b: TokenBucket = .full(cfg, 0);
        var res: [128]Reservation = undefined;
        try testing.expect(c.ops.len <= res.len);
        for (c.ops, 0..) |op, i| {
            const now = op.at_ms * std.time.ns_per_ms;
            const before = b.tokensAt(cfg, now);
            var ok = true;
            var delay: u64 = 0;
            switch (op.kind) {
                .allow => {
                    ok = b.allowNAt(cfg, now, op.n).allowed;
                    if (!ok) reach[0] += 1;
                },
                .reserve => {
                    res[i] = b.reserveNAt(cfg, now, op.n, std.math.maxInt(u64));
                    ok = res[i].ok;
                    delay = res[i].delayNs(now);
                    if (delay > 0) reach[1] += 1;
                },
                .cancel => if (op.ref >= 0) {
                    b.cancelAt(cfg, &res[@intCast(op.ref)], now);
                    if (b.tokensAt(cfg, now) > before) reach[2] += 1 else reach[3] += 1;
                },
                .set_limit => {
                    b.advanceAt(cfg, now);
                    cfg.rate_per_s = op.rate_per_s;
                    reach[4] += 1;
                },
                .set_burst => {
                    b.advanceAt(cfg, now);
                    cfg.burst = op.n;
                    reach[5] += 1;
                },
            }
            const got_tokens = b.tokensAt(cfg, now);
            errdefer std.debug.print(
                "\nx/time/rate op mismatch: seed {d} op {d} ({t} n={d} ref={d} at {d} ms)\n" ++
                    "  reference: ok={} delay={d} ns tokens={d}\n  ours:      ok={} delay={d} ns tokens={d}\n",
                .{ c.seed, i, op.kind, op.n, op.ref, op.at_ms, op.ok, op.delay_ns, op.tokens_after, ok, delay, got_tokens },
            );
            try testing.expectEqual(op.ok, ok);
            try testing.expect(@max(delay, op.delay_ns) - @min(delay, op.delay_ns) <= 1);
            try testing.expect(@abs(op.tokens_after - got_tokens) <= tokens_tolerance);
        }
    }
    for (reach) |r| try testing.expect(r > 0);
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
    // 0.01/s, burst 2: an empty bucket needs 200 s to refill, far past the
    // 1 s TTL -- the effective TTL is the refill time.
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

    tc.advanceMs(1500); // past the configured TTL, not the refill time
    // Negative control 2026-10-24: with the bare `ttl_ms` the drained key
    // reset to a full bucket here (a fresh burst every TTL, review M1).
    try testing.expect(!l.allow("a").allowed);
    try testing.expect(l.allow("c").allowed);
    try testing.expectEqual(@as(usize, 3), l.keyCount()); // b not swept yet

    tc.advanceMs(201 * std.time.ms_per_s); // idle past the refill time
    // Hit on an expired key: a full bucket, which refill alone gives too.
    const d = l.allow("a");
    try testing.expect(d.allowed);
    try testing.expectEqual(@as(u32, 1), d.remaining);

    // Insert of a new key sweeps the expired b and c off the LRU tail.
    try testing.expect(l.allow("d").allowed);
    try testing.expectEqual(@as(usize, 2), l.keyCount()); // a + d
}

test "Limiter: a slow limit is not reset by the idle TTL (5/hour, 10 min TTL)" {
    var tc: TestClock = .{};
    var l = Limiter.init(testing.allocator, .{
        .rate_per_s = 5.0 / 3600.0,
        .burst = 5,
        .clock = tc.clock(),
        .key = .forwarded_ip,
    });
    defer l.deinit();
    for (0..5) |_| try testing.expect(l.allow("u").allowed);
    tc.advanceMs(10 * std.time.ms_per_min + 1); // the default TTL, plus 1 ms
    // 10 min refills 0.83 tokens: refused, whether the key is hit ...
    try testing.expect(!l.allow("u").allowed);
    // ... or a new key's sweep reaches it first.
    tc.advanceMs(10 * std.time.ms_per_min + 1);
    try testing.expect(l.allow("other").allowed);
    try testing.expectEqual(@as(usize, 2), l.keyCount());
    const d = l.allow("u");
    try testing.expect(d.allowed); // 1.67 tokens by now: one passes
    try testing.expectEqual(@as(u32, 0), d.remaining);
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
    try testing.expect(std.mem.find(u8, got, "\r\n" ++ line ++ "\r\n") != null);
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

/// Answers with `clientIp` under the `TrustedProxies` in `ctx.state`.
fn hClientIp(ctx: *router.Ctx) anyerror!void {
    const t: *const TrustedProxies = @ptrCast(@alignCast(ctx.state.?));
    var buf: [peer_key_len_max]u8 = undefined;
    const ip = clientIp(ctx.req, t.*) orelse return ctx.res.writeAll("null");
    try ctx.res.writeAll(netaddr.formatIp(ip, &buf));
}

fn expectClientIp(trusted: TrustedProxies, peer: ?[]const u8, comptime headers: []const u8, want: []const u8) !void {
    var t = trusted;
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.get("/t", hClientIp);
    r.state = &t;
    const p: ?std.Io.net.IpAddress = if (peer) |s| (try netaddr.parseAddrPort(s).?.toStd()) else null;
    var out: [1024]u8 = undefined;
    const got = runWirePeer(&r, wire(headers), &out, p);
    const body = got[(std.mem.find(u8, got, "\r\n\r\n") orelse return error.NoBody) + 4 ..];
    testing.expectEqualStrings(want, body) catch |e| {
        std.debug.print("peer {?s} headers {s}\n", .{ peer, headers });
        return e;
    };
}

test "clientIp: forwarding headers count only from a trusted peer, walked right to left past trusted hops" {
    var set_v: netaddr.IpSet = blk: {
        var b: netaddr.IpSetBuilder = .empty;
        defer b.deinit(testing.allocator);
        try b.addPrefix(testing.allocator, netaddr.parsePrefix("10.0.0.0/8").?);
        break :blk try b.toSet(testing.allocator);
    };
    defer set_v.deinit(testing.allocator);
    const set: TrustedProxies = .{ .set = &set_v };

    // An untrusted peer is the client, whatever it claims.
    try expectClientIp(.none, "127.0.0.1:5000", "X-Forwarded-For: 9.9.9.9\r\n", "127.0.0.1");
    try expectClientIp(.loopback, "203.0.113.7:5000", "X-Forwarded-For: 9.9.9.9\r\nX-Real-IP: 8.8.8.8\r\n", "203.0.113.7");
    try expectClientIp(set, "192.0.2.1:5000", "X-Forwarded-For: 9.9.9.9\r\n", "192.0.2.1");
    // A trusted loopback proxy: its rightmost entry; a forged left one is ignored.
    try expectClientIp(.loopback, "127.0.0.1:5000", "X-Forwarded-For: 6.6.6.6, 203.0.113.7\r\n", "203.0.113.7");
    try expectClientIp(.loopback, "[::1]:5000", "X-Forwarded-For: 203.0.113.7\r\n", "203.0.113.7");
    try expectClientIp(.loopback, "[::ffff:127.0.0.1]:5000", "X-Forwarded-For: 203.0.113.7\r\n", "203.0.113.7");
    // Only the last header line counts (the one the nearest proxy wrote).
    try expectClientIp(.loopback, "127.0.0.1:5000", "X-Forwarded-For: 6.6.6.6\r\nX-Forwarded-For: 203.0.113.7\r\n", "203.0.113.7");
    // A chain of trusted proxies is walked past; all trusted → the leftmost.
    try expectClientIp(set, "10.0.0.1:5000", "X-Forwarded-For: 6.6.6.6, 203.0.113.7, 10.1.1.1, 10.2.2.2\r\n", "203.0.113.7");
    try expectClientIp(set, "10.0.0.1:5000", "X-Forwarded-For: 10.3.3.3, 10.2.2.2\r\n", "10.3.3.3");
    // Not an address: the hop to its right, never something further left.
    try expectClientIp(set, "10.0.0.1:5000", "X-Forwarded-For: 6.6.6.6, unknown\r\n", "10.0.0.1");
    try expectClientIp(set, "10.0.0.1:5000", "X-Forwarded-For: 6.6.6.6, garbage, 10.2.2.2\r\n", "10.2.2.2");
    // A port on an entry is dropped; empty elements are skipped; mapped → v4.
    try expectClientIp(.loopback, "127.0.0.1:5000", "X-Forwarded-For: 203.0.113.7:4711, \r\n", "203.0.113.7");
    try expectClientIp(.loopback, "127.0.0.1:5000", "X-Forwarded-For: [2001:db8::1]:443\r\n", "2001:db8::1");
    try expectClientIp(.loopback, "127.0.0.1:5000", "X-Forwarded-For: ::ffff:203.0.113.7\r\n", "203.0.113.7");
    // No XFF: X-Real-IP from a trusted peer, else the peer; an XFF of only
    // separators leaves the peer.
    try expectClientIp(.loopback, "127.0.0.1:5000", "X-Real-IP: 203.0.113.7\r\n", "203.0.113.7");
    try expectClientIp(.loopback, "127.0.0.1:5000", "X-Real-IP: nope\r\n", "127.0.0.1");
    try expectClientIp(.loopback, "127.0.0.1:5000", "X-Forwarded-For: , ,\r\n", "127.0.0.1");
    try expectClientIp(.loopback, "127.0.0.1:5000", "", "127.0.0.1");
    // Socket-free, no peer: null.
    try expectClientIp(.loopback, null, "X-Forwarded-For: 203.0.113.7\r\n", "null");
}

test "middleware: forwarded_ip_trusted keys a direct client by its peer, not by the XFF it sends" {
    var l = Limiter.init(testing.allocator, .{ .rate_per_s = 0.001, .burst = 1, .key = .{ .forwarded_ip_trusted = .loopback } });
    defer l.deinit();
    var rl = try RouterUnderLimit.init(&l);
    defer rl.deinit();
    rl.start();
    var out: [1024]u8 = undefined;
    const direct = std.Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 203, 0, 113, 7 }, .port = 5000 } };
    const proxy = std.Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 5000 } };
    // A direct client rotating forged XFF values is still one bucket.
    try expectStatus(runWirePeer(&rl.r, wire("X-Forwarded-For: 1.1.1.1\r\n"), &out, direct), "200");
    try expectStatus(runWirePeer(&rl.r, wire("X-Forwarded-For: 2.2.2.2\r\n"), &out, direct), "429");
    // Through the loopback proxy, each forwarded client has its own.
    try expectStatus(runWirePeer(&rl.r, wire("X-Forwarded-For: 1.1.1.1\r\n"), &out, proxy), "200");
    try expectStatus(runWirePeer(&rl.r, wire("X-Forwarded-For: 2.2.2.2\r\n"), &out, proxy), "200");
    try expectStatus(runWirePeer(&rl.r, wire("X-Forwarded-For: 2.2.2.2\r\n"), &out, proxy), "429");
    try testing.expectEqual(@as(u32, 3), rl.hits);
}

test "TokenBucket: reserveNAt honours max_wait; a second cancel is a no-op (deliberate x/time/rate divergence)" {
    const cfg: TokenBucket.Config = .{ .rate_per_s = 1, .burst = 3 };
    var b: TokenBucket = .full(cfg, 0);
    try testing.expect(b.allowNAt(cfg, 0, 3).allowed); // empty
    // 2 tokens owed = 2 s; a 1.5 s cap refuses and takes nothing.
    const refused = b.reserveNAt(cfg, 0, 2, 1500 * std.time.ns_per_ms);
    try testing.expect(!refused.ok);
    try testing.expectEqual(@as(f64, 0), b.tokens);
    // Exactly the wait needed is accepted.
    var r = b.reserveNAt(cfg, 0, 2, 2 * std.time.ns_per_s);
    try testing.expect(r.ok);
    try testing.expectEqual(@as(u64, 2 * std.time.ns_per_s), r.delayNs(0));
    try testing.expectEqual(@as(f64, -2), b.tokens);
    // n > burst is never ok, whatever the cap.
    try testing.expect(!b.reserveNAt(cfg, 0, 4, std.math.maxInt(u64)).ok);
    // Cancel gives the 2 back; a second cancel must not give them again
    // (x/time/rate v0.15.0 does — see xrate_ops_vectors.zig).
    b.cancelAt(cfg, &r, 0);
    try testing.expectEqual(@as(f64, 0), b.tokens);
    b.cancelAt(cfg, &r, 0);
    try testing.expectEqual(@as(f64, 0), b.tokens);
    // A denied AllowN of n > burst reports "never".
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), b.allowNAt(cfg, 0, 4).retry_after_ms);
}

test "Limiter: allowN charges n tokens per key, all or nothing" {
    var clk: TestClock = .{};
    var l = Limiter.init(testing.allocator, .{ .rate_per_s = 10, .burst = 10, .clock = clk.clock(), .key = .forwarded_ip });
    defer l.deinit();
    try testing.expectEqual(@as(u32, 4), l.allowN("a", 6).remaining);
    const d = l.allowN("a", 5); // 4 left: refused, nothing taken
    try testing.expect(!d.allowed);
    try testing.expectEqual(@as(u64, 100), d.retry_after_ms); // 1 token at 10/s
    try testing.expectEqual(@as(u32, 10), d.limit);
    try testing.expect(l.allowN("a", 4).allowed);
    try testing.expect(l.allowN("b", 10).allowed); // other key untouched
    try testing.expect(!l.allowN("c", 11).allowed); // over burst: never
}

test "Limiter: setRate keeps earned tokens, setBurst cuts the balance" {
    var clk: TestClock = .{};
    var l = Limiter.init(testing.allocator, .{ .rate_per_s = 1, .burst = 10, .clock = clk.clock(), .key = .forwarded_ip });
    defer l.deinit();
    try testing.expect(l.allowN("k", 10).allowed); // empty at t=0
    clk.advanceMs(2000); // +2 at the old rate
    l.setRate(10);
    clk.advanceMs(300); // +3 at the new rate → 5
    try testing.expectEqual(@as(u32, 0), l.allowN("k", 5).remaining);
    try testing.expect(!l.allowN("k", 1).allowed);
    clk.advanceMs(1000); // full again (10)
    l.setBurst(4); // cut to 4
    try testing.expectEqual(@as(u32, 0), l.allowN("k", 4).remaining);
    try testing.expect(!l.allowN("k", 5).allowed); // over the new burst
    try testing.expectEqual(@as(u32, 4), l.allow("k").limit);
    const cur = l.currentConfig();
    try testing.expectEqual(@as(f64, 10), cur.rate_per_s);
    try testing.expectEqual(@as(u32, 4), cur.burst);
}

test "Limiter: waitN paces, refuses over burst and over max_wait without taking tokens" {
    // Real clock and real sleeps, kept to a few milliseconds.
    var l = Limiter.init(testing.allocator, .{ .rate_per_s = 1000, .burst = 2, .key = .forwarded_ip });
    defer l.deinit();
    const io = testing.io;
    try testing.expectError(error.ExceedsBurst, l.waitN(io, "k", 3, std.math.maxInt(u64)));
    try l.waitN(io, "k", 2, 0); // full: no wait
    // Empty now; 2 tokens need 2 ms. A 0.5 ms cap refuses and takes nothing.
    try testing.expectError(error.WaitTooLong, l.waitN(io, "k", 2, 500 * std.time.ns_per_us));
    const t0 = Clock.monotonic.now();
    try l.waitN(io, "k", 2, std.math.maxInt(u64));
    const slept = Clock.monotonic.now() - t0;
    // ≥ 2 ms minus what refilled between the refusal and this call.
    try testing.expect(slept >= std.time.ns_per_ms);
}

test "Limiter: a pending reservation keeps its key from idle reset" {
    var clk: TestClock = .{};
    var l = Limiter.init(testing.allocator, .{ .rate_per_s = 0.001, .burst = 1, .ttl_ms = 1000, .clock = clk.clock(), .key = .forwarded_ip });
    defer l.deinit();
    // Take the token, then reserve two more one at a time: the last is due
    // in 2000 s, past both the TTL and the 1000 s refill time.
    try testing.expect(l.allow("k").allowed);
    {
        lockSpin(&l.lock);
        defer l.lock.unlock();
        const b = l.bucketLocked("k", clk.ns).?;
        try testing.expect(b.reserveNAt(l.config(), clk.ns, 1, std.math.maxInt(u64)).ok);
        try testing.expect(b.reserveNAt(l.config(), clk.ns, 1, std.math.maxInt(u64)).ok);
    }
    clk.advanceMs(1500 * std.time.ms_per_s); // past TTL and refill time, before the reservation is due
    // Negative control 2026-10-11: with `updated_ns` instead of
    // `idleSince()` the key reset to a full bucket here and admitted.
    try testing.expect(!l.allow("k").allowed);
}

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
    try res.setHeader("Retry-After", std.mem.print(&retry_buf, "{d}", .{1}) catch unreachable);
    try res.setHeader("RateLimit-Limit", std.mem.print(&limit_buf, "{d}", .{2}) catch unreachable);
    try res.setHeader("RateLimit-Remaining", "0");
    try res.setHeader("RateLimit-Reset", std.mem.print(&reset_buf, "{d}", .{2}) catch unreachable);
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
    try testing.expect(std.mem.find(u8, got, "#") == null);
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

test "middleware: an IPv6 client is keyed by its /64, spellings unified (review 2026-10-24)" {
    var tc: TestClock = .{};
    var l = Limiter.init(testing.allocator, .{ .rate_per_s = 0.01, .burst = 1, .clock = tc.clock(), .key = .forwarded_ip });
    defer l.deinit();
    var rl = try RouterUnderLimit.init(&l);
    defer rl.deinit();
    rl.start();
    var buf: [1024]u8 = undefined;

    try expectStatus(runWire(&rl.r, wire("X-Forwarded-For: 2001:db8:1:2::1\r\n"), &buf), "200");
    // Another address in the same /64 (rotation) is the same bucket ...
    try expectStatus(runWire(&rl.r, wire("X-Forwarded-For: 2001:db8:1:2:ffff:ffff:ffff:ffff\r\n"), &buf), "429");
    // ... so is the expanded, upper-case spelling of the first one ...
    try expectStatus(runWire(&rl.r, wire("X-Real-IP: 2001:0DB8:0001:0002:0:0:0:1\r\n"), &buf), "429");
    // ... and the next /64 is not.
    try expectStatus(runWire(&rl.r, wire("X-Forwarded-For: 2001:db8:1:3::1\r\n"), &buf), "200");
    // IPv4 stays the whole address; a v4-mapped spelling is the same client.
    try expectStatus(runWire(&rl.r, wire("X-Forwarded-For: 192.0.2.1\r\n"), &buf), "200");
    try expectStatus(runWire(&rl.r, wire("X-Forwarded-For: ::ffff:192.0.2.1\r\n"), &buf), "429");
    try expectStatus(runWire(&rl.r, wire("X-Forwarded-For: 192.0.2.2\r\n"), &buf), "200");
    // Text that is not an address is its own key, unchanged.
    try expectStatus(runWire(&rl.r, wire("X-Forwarded-For: unknown\r\n"), &buf), "200");
    try testing.expectEqual(@as(usize, 5), l.keyCount());

    // v6_key_bits = 128 keys every address apart.
    var l128 = Limiter.init(testing.allocator, .{ .rate_per_s = 0.01, .burst = 1, .clock = tc.clock(), .key = .forwarded_ip, .v6_key_bits = 128 });
    defer l128.deinit();
    var rl128 = try RouterUnderLimit.init(&l128);
    defer rl128.deinit();
    rl128.start();
    try expectStatus(runWire(&rl128.r, wire("X-Forwarded-For: 2001:db8:1:2::1\r\n"), &buf), "200");
    try expectStatus(runWire(&rl128.r, wire("X-Forwarded-For: 2001:db8:1:2::2\r\n"), &buf), "200");
    try expectStatus(runWire(&rl128.r, wire("X-Forwarded-For: 2001:db8:1:2::1\r\n"), &buf), "429");
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

fn keyByPath(_: ?*anyopaque, ctx: *router.Ctx, _: *[peer_key_len_max]u8) []const u8 {
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

test "optionsError: each refused Limiter option, and a valid one" {
    const ok: Options = .{ .rate_per_s = 1, .burst = 1, .key = .forwarded_ip };
    try testing.expect(optionsError(ok) == null);
    var o = ok;
    o.rate_per_s = 0;
    try testing.expectEqualStrings("ratelimit: rate_per_s must be > 0 and finite", optionsError(o).?);
    o = ok;
    o.rate_per_s = std.math.nan(f64);
    try testing.expect(optionsError(o) != null);
    o = ok;
    o.burst = 0;
    try testing.expectEqualStrings("ratelimit: burst must be >= 1", optionsError(o).?);
    o = ok;
    o.max_keys = 0;
    try testing.expectEqualStrings("ratelimit: max_keys must be >= 1", optionsError(o).?);
    o = ok;
    o.max_key_len = 0;
    try testing.expectEqualStrings("ratelimit: max_key_len must be >= 1", optionsError(o).?);
    o = ok;
    o.v6_key_bits = 129;
    try testing.expectEqualStrings("ratelimit: v6_key_bits must be <= 128", optionsError(o).?);
    o.v6_key_bits = 128;
    try testing.expect(optionsError(o) == null);
    // setConfigAt's checks: null keeps a value and is never refused.
    try testing.expect(configError(null, null) == null);
    try testing.expect(configError(2.5, 3) == null);
    try testing.expect(configError(-1, null) != null);
    try testing.expect(configError(null, 0) != null);
}

test "validRate: only positive finite rates (mutation survivor 2026-10-24)" {
    try testing.expect(validRate(0.001));
    try testing.expect(validRate(1e300));
    try testing.expect(!validRate(0));
    try testing.expect(!validRate(-1));
    try testing.expect(!validRate(std.math.nan(f64)));
    try testing.expect(!validRate(std.math.inf(f64)));
    try testing.expect(!validRate(-std.math.inf(f64)));
}

test "middleware: XFF with three elements keys on the rightmost, not the second (mutation survivor)" {
    var tc: TestClock = .{};
    var l = Limiter.init(testing.allocator, .{ .rate_per_s = 0.01, .burst = 1, .clock = tc.clock(), .key = .forwarded_ip });
    defer l.deinit();
    var rl = try RouterUnderLimit.init(&l);
    defer rl.deinit();
    rl.start();
    var buf: [1024]u8 = undefined;

    try expectStatus(runWire(&rl.r, wire("X-Forwarded-For: 1.1.1.1, 2.2.2.2, 3.3.3.3\r\n"), &buf), "200");
    // Same rightmost, different prefix: same bucket.
    try expectStatus(runWire(&rl.r, wire("X-Forwarded-For: 9.9.9.9, 8.8.8.8, 3.3.3.3\r\n"), &buf), "429");
    // A client whose second element equals the first request's second element
    // but whose rightmost differs is a different client.
    try expectStatus(runWire(&rl.r, wire("X-Forwarded-For: 1.1.1.1, 2.2.2.2, 4.4.4.4\r\n"), &buf), "200");
    try testing.expectEqual(@as(usize, 2), l.keyCount());
}

test "middleware: 429 Retry-After and RateLimit-Reset round UP to whole seconds (mutation survivor)" {
    var tc: TestClock = .{};
    // 0.4/s, burst 3: an empty bucket frees a token in 2.5 s and is full in 7.5 s.
    var l = Limiter.init(testing.allocator, .{ .rate_per_s = 0.4, .burst = 3, .clock = tc.clock(), .key = .forwarded_ip });
    defer l.deinit();
    var rl = try RouterUnderLimit.init(&l);
    defer rl.deinit();
    rl.start();
    var buf: [1024]u8 = undefined;

    for (0..3) |_| try expectStatus(runWire(&rl.r, wire(""), &buf), "200");
    const got = runWire(&rl.r, wire(""), &buf);
    try expectStatus(got, "429");
    try expectHeaderLine(got, "Retry-After: 3");
    try expectHeaderLine(got, "RateLimit-Limit: 3");
    try expectHeaderLine(got, "RateLimit-Reset: 8");
}

fn keyByClientKey(_: ?*anyopaque, ctx: *router.Ctx, buf: *[peer_key_len_max]u8) []const u8 {
    return clientKey(ctx.req, buf);
}

test "clientKey: a v4-mapped socket peer is the plain IPv4 text, before any ipKey step (mutation survivor)" {
    var tc: TestClock = .{};
    var l = Limiter.init(testing.allocator, .{
        .rate_per_s = 0.01,
        .burst = 1,
        .clock = tc.clock(),
        .key = .{ .custom = .{ .keyFor = keyByClientKey } },
    });
    defer l.deinit();
    var rl = try RouterUnderLimit.init(&l);
    defer rl.deinit();
    rl.start();
    var buf: [1024]u8 = undefined;

    const ip = std.Io.net.IpAddress;
    const plain: ip = ip.parseIp4("10.0.0.1", 1) catch unreachable;
    const mapped: ip = ip.parseIp6("::ffff:10.0.0.1", 2) catch unreachable;
    try expectStatus(runWirePeer(&rl.r, wire(""), &buf, plain), "200");
    try expectStatus(runWirePeer(&rl.r, wire(""), &buf, mapped), "429");
    try testing.expectEqual(@as(usize, 1), l.keyCount());
}

test "middleware: API-key header value is trimmed of surrounding blanks (mutation survivor)" {
    var tc: TestClock = .{};
    var l = Limiter.init(testing.allocator, .{ .rate_per_s = 0.01, .burst = 1, .clock = tc.clock(), .key = .{ .header = "X-Api-Key" } });
    defer l.deinit();
    var rl = try RouterUnderLimit.init(&l);
    defer rl.deinit();
    rl.start();
    var buf: [1024]u8 = undefined;

    try expectStatus(runWire(&rl.r, wire("X-Api-Key: alpha\r\n"), &buf), "200");
    try expectStatus(runWire(&rl.r, wire("X-Api-Key: \t alpha \t \r\n"), &buf), "429");
    try testing.expectEqual(@as(usize, 1), l.keyCount());
}

test "Limiter: keys sharing their first 8 bytes stay distinct (two-word key compare, mutation survivor)" {
    // 12-byte keys take the 8..16 byte fast path of `keyEql`, whose two word
    // loads overlap: only the second one tells these keys apart. With ~3000
    // of them, probe-chain fingerprint collisions are certain; a compare that
    // looked at the first word only would merge colliding keys.
    var tc: TestClock = .{};
    var l = Limiter.init(testing.allocator, .{ .rate_per_s = 1, .burst = 1, .max_keys = 4000, .ttl_ms = 0, .clock = tc.clock(), .key = .forwarded_ip });
    defer l.deinit();
    var buf: [12]u8 = undefined;
    for (0..3000) |i| {
        const k = std.mem.print(&buf, "abcdefgh{d:0>4}", .{i}) catch unreachable;
        try testing.expect(l.allow(k).allowed);
    }
    try testing.expectEqual(@as(usize, 3000), l.keyCount());
    // Every key is now empty: a second visit is denied, not a fresh bucket.
    for (0..3000) |i| {
        const k = std.mem.print(&buf, "abcdefgh{d:0>4}", .{i}) catch unreachable;
        try testing.expect(!l.allow(k).allowed);
    }
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
        return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    };
    const thread = try std.Thread.spawn(.{}, serveWrap, .{&server});
    defer thread.join();
    defer server.shutdown();

    const port = server.boundAddress().getPort();
    var client = http.Client.init(io, testing.allocator, .{});
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.mem.print(&url_buf, "http://127.0.0.1:{d}/limited", .{port});

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
