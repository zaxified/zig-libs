// SPDX-License-Identifier: MIT

//! abuseguard — IP reputation + connection-abuse defense for a directly
//! internet-facing `http.Server`.
//!
//! With no reverse proxy in front, the app IS the edge. `ratelimit` bounds
//! request *rate* per key; this module bounds *connections* and maintains
//! *IP reputation*, cutting a misbehaving client at accept time — before the
//! server spends a single allocation or read on it (a reject costs the
//! attacker only a TCP handshake and writes nothing, matching the server's
//! documented `on_connect` posture).
//!
//! Layers (each usable on its own):
//! - `Guard` — the reputation store + admission engine: per-IP and global
//!   concurrent-connection caps, a manual ban list, an auto-expiring
//!   greylist, and a decaying per-IP strike counter with fail2ban-style
//!   escalation (`record` → greylist at `ban_threshold` → ban on repeat).
//!   Bounded (`max_tracked_ips` + LRU eviction), clock-injected, internally
//!   synchronized. `admit`/`connClosed` drive it without any HTTP types.
//! - `Guard.onConnect()`/`onConnState()` — the `http.Server` Phase-2.1 hook
//!   pair: `on_connect` admits/rejects at accept, `on_conn_state` releases
//!   the per-IP slot on `.closed` (the per-IP count cannot be maintained
//!   from `on_connect` alone — this is exactly why the ConnState hook
//!   exists).
//! - `Guard.middleware()` — an optional `router.Middleware` that
//!   auto-strikes clients on 4xx/429 responses (configurable weights), so
//!   scanners and brute-forcers escalate to an accept-time ban without any
//!   app code.
//!
//! Model after (semantics adopted where the spec left a choice):
//! - **nginx `limit_conn`:** per-key concurrent-connection caps counted at
//!   admission and released at close; when the tracking zone is exhausted
//!   the request is refused (nginx answers 503 — we drop at the TCP level
//!   like every other reject, per the server's posture). Consequently the
//!   store is deliberately **fail-closed**: an untrackable connection is
//!   rejected, never admitted uncounted (contrast `ratelimit`, which fails
//!   open — a missed *rate* decision is a nuisance, an uncounted
//!   *connection* is exactly the resource being defended).
//! - **fail2ban:** `record(ip, weight)` ≈ a failregex hit; `ban_threshold`
//!   ≈ maxretry; `greylist_ttl_ms` ≈ bantime; strike decay ≈ findtime
//!   (approximated as a leaky bucket: one strike drains per
//!   `strike_decay_ms`); `ban_after_offenses` ≈ the recidive jail
//!   (repeated greylistings escalate to a permanent ban).
//!
//! Keying: the socket peer IP — the real client in a direct-internet
//! deployment. IPs are keyed in their 16-byte mapped form (`netaddr.Ip`'s
//! `as16`), which makes an IPv4-mapped IPv6 peer and its plain IPv4 form
//! one entry — one client, one budget (the `unmap` unification). The
//! middleware can optionally key on the `ratelimit` trusted-XFF chain for
//! behind-proxy deployments (`Options.middleware_key`).
//!
//! Thread-safety: internally synchronized — `on_connect` runs on the accept
//! loop, `on_conn_state`/middleware on every connection task. The lock is a
//! spinlock (`std.atomic.Mutex` + `spinLoopHint`, the std SmpAllocator
//! pattern — Zig 0.16 std has no io-less blocking mutex); critical sections
//! are a hash lookup + O(1) LRU relink (plus a bounded eviction scan only
//! when the store is at capacity).
//!
//! Scope notes:
//! - A ban/greylist affects **new admissions only**; connections already
//!   admitted keep running until they close (the guard has no handle to
//!   kill them — pair with the server's read/write timeouts).
//! - Known server edge: if `http.Server` drops an *admitted* connection
//!   before serving begins (its per-connection buffer allocation failed —
//!   OOM only), `.closed` never fires and that IP's slot leaks by one until
//!   process restart. The guard's own memory stays bounded regardless.

const std = @import("std");
const http = @import("http");
const netaddr = @import("netaddr");
const router = @import("router");
const net = std.Io.net;

pub const meta = .{
    .status = .gap,
    .platform = .posix, // default clock uses the posix clock_gettime form
    .role = .server,
    // Internally synchronized (documented spinlock around O(1) critical
    // sections); hooks race freely across the accept loop and every
    // connection task.
    .concurrency = .threadsafe,
    .model_after = "nginx limit_conn (concurrent-conn caps, zone semantics) + fail2ban (strike→ban escalation)",
    .deps = .{ "http", "netaddr", "router" },
};

const Allocator = std.mem.Allocator;

// ── clock injection ─────────────────────────────────────────────────────────

/// Monotonic time source, injected so bans/greylists/decay are deterministic
/// under test. Implementations must be non-decreasing; the absolute origin
/// is irrelevant (only differences are used).
pub const Clock = struct {
    ctx: ?*anyopaque = null,
    nowFn: *const fn (?*anyopaque) u64,

    /// The OS monotonic clock (CLOCK_MONOTONIC via the posix
    /// `clock_gettime` errno form) — the production default, and the only
    /// place in the module that touches a real clock.
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

/// How `middleware()` picks the IP to strike.
pub const MiddlewareKey = enum {
    /// The socket peer address (`Request.peerAddress`) — unforgeable, the
    /// right key when the server faces the internet directly (default).
    peer_ip,
    /// The `ratelimit` client-IP trust chain: rightmost element of the last
    /// `X-Forwarded-For` header (the one hop a client cannot forge when a
    /// compliant trusted proxy is in front), else `X-Real-IP`, else the
    /// socket peer. Values that do not parse as an IP literal fall through
    /// to the next step. Only meaningful behind a proxy that always sets
    /// the header — a direct client can otherwise strike arbitrary IPs.
    forwarded_ip,
};

pub const Options = struct {
    /// Max concurrent connections per client IP (nginx `limit_conn` shape);
    /// null = no per-IP cap. Must be ≥ 1 when set.
    max_conns_per_ip: ?u32 = 100,
    /// Max concurrent connections across all IPs (global load shedding),
    /// counted by the guard itself from its own admit/close bookkeeping —
    /// it mirrors `Server.activeConnections()` when the guard is the only
    /// admission hook. null = no global cap. Must be ≥ 1 when set.
    max_conns_total: ?u32 = null,
    /// How long an auto-greylisting rejects a client (fail2ban `bantime`).
    /// Also the default for manual `greylist` calls. Must be ≥ 1 ms.
    greylist_ttl_ms: u64 = 10 * std.time.ms_per_min,
    /// Decayed strikes at which `record` triggers an offense (fail2ban
    /// `maxretry`): the strike counter resets and the IP is greylisted —
    /// or banned once `ban_after_offenses` is reached. Must be ≥ 1.
    ban_threshold: u32 = 5,
    /// Strike decay: one strike drains per this interval (a leaky-bucket
    /// approximation of fail2ban's `findtime` — strikes older than
    /// `ban_threshold * strike_decay_ms` can never accumulate to an
    /// offense). 0 = strikes never decay.
    strike_decay_ms: u64 = 2 * std.time.ms_per_min,
    /// The offense count at which an auto-greylisting escalates to a
    /// permanent ban (fail2ban recidive shape): 2 = first offense
    /// greylists, the repeat bans. 1 = ban immediately at the first
    /// offense. 0 = never auto-ban (greylist only). Offenses are remembered
    /// until the entry is evicted or `unban` is called.
    ban_after_offenses: u32 = 2,
    /// At most this many distinct IPs tracked — the memory bound that keeps
    /// the store itself from being an exhaustion vector. Beyond it the
    /// least-recently-used evictable entry is dropped (entries with live
    /// connections are never evicted; banned entries only as a last
    /// resort). When nothing is evictable — every tracked IP has a live
    /// connection — new IPs are rejected (nginx zone-exhausted semantics),
    /// so size this ≥ any `max_conns_total`. Must be ≥ 1.
    max_tracked_ips: usize = 4096,
    /// Time source — inject a fake for deterministic tests. The store never
    /// reads a wall clock on its own.
    clock: Clock = .monotonic,
    /// `middleware()` strike weight for 4xx responses other than 429;
    /// 0 = ignore them.
    strike_4xx: u32 = 1,
    /// `middleware()` strike weight for 429 Too Many Requests (a
    /// `ratelimit` deny upstream in the chain is a strong abuse signal);
    /// 0 = ignore.
    strike_429: u32 = 2,
    /// How `middleware()` picks the IP to strike.
    middleware_key: MiddlewareKey = .peer_ip,
};

// ── the guard ───────────────────────────────────────────────────────────────

/// `admit`'s verdict — anything but `.admitted` maps to a `.reject` at the
/// server hook (which closes the socket without writing a byte).
pub const AdmitVerdict = enum {
    /// Connection admitted; the per-IP and total counters were incremented.
    /// Pair with exactly one `connClosed` when the connection ends.
    admitted,
    /// The IP is banned (manual `ban` or offense escalation).
    banned,
    /// The IP is greylisted and the TTL has not expired yet.
    greylisted,
    /// The IP is at `max_conns_per_ip` live connections.
    per_ip_cap,
    /// The guard counts `max_conns_total` live connections overall.
    total_cap,
    /// The store is at `max_tracked_ips` and nothing is evictable (or the
    /// allocator failed) — refused, nginx zone-exhausted semantics
    /// (fail-closed; see the module doc).
    store_full,
};

/// The reputation store + admission engine. Allocator-explicit, bounded,
/// clock-injected, internally synchronized — see the module doc. Do not
/// move a Guard once entries exist (the LRU list points into it).
pub const Guard = struct {
    gpa: Allocator,
    options: Options,
    lock: std.atomic.Mutex = .unlocked,
    /// Keyed by the IP's 16-byte mapped form (`netaddr.Ip.as16`), which
    /// unifies IPv4 with IPv4-mapped IPv6 — one client, one entry.
    map: std.AutoHashMapUnmanaged(Key, *Entry) = .empty,
    /// Front = most recently touched; eviction scans from the back.
    lru: std.DoublyLinkedList = .{},
    /// Live admitted connections across all IPs (the global cap's counter).
    total_conns: usize = 0,

    const Key = [16]u8;

    const Entry = struct {
        node: std.DoublyLinkedList.Node = .{},
        key: Key,
        /// Live connections from this IP (admit +1, connClosed −1).
        active_conns: u32 = 0,
        /// Decaying strike balance; decayed lazily against
        /// `strikes_updated_ns` on every touch by `record`.
        strikes: f64 = 0,
        strikes_updated_ns: u64,
        /// Monotonic instant the greylist ends; 0 = not greylisted.
        greylisted_until_ns: u64 = 0,
        /// Times this IP crossed `ban_threshold` (drives ban escalation).
        offenses: u32 = 0,
        banned: bool = false,
    };

    pub fn init(gpa: Allocator, options: Options) Guard {
        std.debug.assert(options.max_tracked_ips >= 1);
        std.debug.assert(options.ban_threshold >= 1);
        std.debug.assert(options.greylist_ttl_ms >= 1);
        if (options.max_conns_per_ip) |m| std.debug.assert(m >= 1);
        if (options.max_conns_total) |m| std.debug.assert(m >= 1);
        return .{ .gpa = gpa, .options = options };
    }

    pub fn deinit(g: *Guard) void {
        var it = g.map.valueIterator();
        while (it.next()) |e| g.gpa.destroy(e.*);
        g.map.deinit(g.gpa);
        g.* = undefined;
    }

    // ── http.Server wiring ──────────────────────────────────────────────

    /// The `http.Server.Options.on_connect` hook. Wire the pair:
    /// `.on_connect = guard.onConnect(), .on_connect_ctx = guard.onConnectCtx()`.
    pub fn onConnect(_: *const Guard) http.Server.OnConnectFn {
        return onConnectHook;
    }

    /// The context pointer that must accompany `onConnect()`.
    pub fn onConnectCtx(g: *Guard) ?*anyopaque {
        return g;
    }

    /// The `http.Server.Options.on_conn_state` hook: releases the per-IP
    /// slot on `.closed` (other states are ignored). Wire the pair:
    /// `.on_conn_state = guard.onConnState(), .on_conn_state_ctx = guard.onConnStateCtx()`.
    pub fn onConnState(_: *const Guard) http.Server.ConnStateFn {
        return onConnStateHook;
    }

    /// The context pointer that must accompany `onConnState()`.
    pub fn onConnStateCtx(g: *Guard) ?*anyopaque {
        return g;
    }

    // ── the admission engine (direct drive; no HTTP types) ──────────────

    /// Decide one incoming connection from `ip` at the injected clock's
    /// now: reject when banned / greylisted / over the per-IP cap / over
    /// the global cap / untrackable — otherwise count it and admit.
    /// Thread-safe. Every `.admitted` must be paired with one `connClosed`.
    pub fn admit(g: *Guard, ip: netaddr.Ip) AdmitVerdict {
        const now_ns = g.options.clock.now();
        lockSpin(&g.lock);
        defer g.lock.unlock();

        // Global cap first: cheapest, and shedding must not insert entries.
        if (g.options.max_conns_total) |max| {
            if (g.total_conns >= max) return .total_cap;
        }
        const e = g.getOrCreate(ip.as16(), now_ns) orelse return .store_full;
        if (e.banned) return .banned;
        if (now_ns < e.greylisted_until_ns) return .greylisted;
        e.greylisted_until_ns = 0; // lazy expiry
        if (g.options.max_conns_per_ip) |max| {
            if (e.active_conns >= max) return .per_ip_cap;
        }
        e.active_conns += 1;
        g.total_conns += 1;
        return .admitted;
    }

    /// Release the slot `admit` counted for `ip`. Unmatched calls (an IP
    /// that was never admitted) are ignored — counters never go negative.
    /// Thread-safe.
    pub fn connClosed(g: *Guard, ip: netaddr.Ip) void {
        lockSpin(&g.lock);
        defer g.lock.unlock();
        const e = g.map.get(ip.as16()) orelse return;
        if (e.active_conns == 0) return;
        e.active_conns -= 1;
        g.total_conns -|= 1;
    }

    // ── reputation ──────────────────────────────────────────────────────

    /// Accrue `weight` strikes against `ip` (an app-flagged abuse event —
    /// auth failure, malformed input, a 429 from `ratelimit`, …). Strikes
    /// decay per `strike_decay_ms`; when the decayed balance reaches
    /// `ban_threshold` it resets, the offense count rises and the IP is
    /// greylisted for `greylist_ttl_ms` — or banned outright once
    /// `ban_after_offenses` is reached. `weight` 0 is a no-op. Best-effort
    /// under memory pressure: when the IP cannot be tracked (store full of
    /// live connections / OOM) the strike is dropped. Thread-safe.
    pub fn record(g: *Guard, ip: netaddr.Ip, weight: u32) void {
        if (weight == 0) return;
        const now_ns = g.options.clock.now();
        lockSpin(&g.lock);
        defer g.lock.unlock();
        const e = g.getOrCreate(ip.as16(), now_ns) orelse return;
        e.strikes = g.decayedStrikes(e, now_ns) + @as(f64, @floatFromInt(weight));
        e.strikes_updated_ns = now_ns;
        if (e.strikes < @as(f64, @floatFromInt(g.options.ban_threshold))) return;
        // Offense: reset the balance, escalate.
        e.strikes = 0;
        e.offenses +|= 1;
        if (g.options.ban_after_offenses != 0 and e.offenses >= g.options.ban_after_offenses) {
            e.banned = true;
            e.greylisted_until_ns = 0;
        } else {
            e.greylisted_until_ns = now_ns +| (g.options.greylist_ttl_ms *| std.time.ns_per_ms);
        }
    }

    /// Manually ban `ip` (permanent until `unban`; rejects new admissions
    /// only — live connections finish on their own). Best-effort under
    /// memory pressure, like `record`. Thread-safe.
    pub fn ban(g: *Guard, ip: netaddr.Ip) void {
        const now_ns = g.options.clock.now();
        lockSpin(&g.lock);
        defer g.lock.unlock();
        const e = g.getOrCreate(ip.as16(), now_ns) orelse return;
        e.banned = true;
    }

    /// Full forgiveness: clears the ban, the greylist, all strikes and the
    /// offense history. Live-connection counts are untouched. Thread-safe.
    pub fn unban(g: *Guard, ip: netaddr.Ip) void {
        lockSpin(&g.lock);
        defer g.lock.unlock();
        const e = g.map.get(ip.as16()) orelse return;
        e.banned = false;
        e.greylisted_until_ns = 0;
        e.strikes = 0;
        e.offenses = 0;
        if (e.active_conns == 0) g.removeEntry(e); // now empty — release it
    }

    /// Manually greylist `ip` for `ttl_ms` (null = `Options.greylist_ttl_ms`),
    /// replacing any current greylist. Does not count as an offense.
    /// Best-effort under memory pressure, like `record`. Thread-safe.
    pub fn greylist(g: *Guard, ip: netaddr.Ip, ttl_ms: ?u64) void {
        const now_ns = g.options.clock.now();
        lockSpin(&g.lock);
        defer g.lock.unlock();
        const e = g.getOrCreate(ip.as16(), now_ns) orelse return;
        e.greylisted_until_ns = now_ns +| ((ttl_ms orelse g.options.greylist_ttl_ms) *| std.time.ns_per_ms);
    }

    /// Whether `ip` is currently banned. Thread-safe.
    pub fn isBanned(g: *Guard, ip: netaddr.Ip) bool {
        lockSpin(&g.lock);
        defer g.lock.unlock();
        const e = g.map.get(ip.as16()) orelse return false;
        return e.banned;
    }

    /// Whether `ip` is currently greylisted (TTL not yet expired). Thread-safe.
    pub fn isGreylisted(g: *Guard, ip: netaddr.Ip) bool {
        const now_ns = g.options.clock.now();
        lockSpin(&g.lock);
        defer g.lock.unlock();
        const e = g.map.get(ip.as16()) orelse return false;
        return now_ns < e.greylisted_until_ns;
    }

    // ── diagnostics ─────────────────────────────────────────────────────

    /// Live admitted connections from `ip`. Thread-safe.
    pub fn connCount(g: *Guard, ip: netaddr.Ip) u32 {
        lockSpin(&g.lock);
        defer g.lock.unlock();
        const e = g.map.get(ip.as16()) orelse return 0;
        return e.active_conns;
    }

    /// Live admitted connections across all IPs (the guard's own count —
    /// mirrors `Server.activeConnections()` when the guard is the only
    /// admission hook). Thread-safe.
    pub fn totalConns(g: *Guard) usize {
        lockSpin(&g.lock);
        defer g.lock.unlock();
        return g.total_conns;
    }

    /// Distinct IPs currently tracked (≤ `max_tracked_ips`). Thread-safe.
    pub fn trackedCount(g: *Guard) usize {
        lockSpin(&g.lock);
        defer g.lock.unlock();
        return g.map.count();
    }

    // ── the middleware ──────────────────────────────────────────────────

    /// A `router.Middleware` that runs the rest of the chain, then strikes
    /// the client when the response status is 4xx (`Options.strike_4xx`) or
    /// specifically 429 (`Options.strike_429`) — repeat offenders escalate
    /// to an accept-time greylist/ban with zero app code. Register it
    /// **first** (`router.use` order = outermost first) so it also observes
    /// statuses produced by inner middleware (e.g. `ratelimit`'s 429) and
    /// the router's own 404/405. Handler errors (the server's 500 path) are
    /// propagated unpunished — a 5xx is the server's fault, not abuse. The
    /// Guard must outlive the Router.
    pub fn middleware(g: *Guard) router.Middleware {
        return .{ .state = g, .run = middlewareRun };
    }

    // ── store internals (all callers hold the lock) ─────────────────────

    /// Look up `key`, refreshing its LRU position — or insert a fresh entry,
    /// first sweeping empty entries off the LRU tail and evicting at the
    /// cap. Null when nothing is evictable or the allocator failed
    /// (fail-closed; the callers document their policy).
    fn getOrCreate(g: *Guard, key: Key, now_ns: u64) ?*Entry {
        if (g.map.get(key)) |e| {
            g.lru.remove(&e.node);
            g.lru.prepend(&e.node);
            return e;
        }
        // Sweep entries whose whole state has lapsed (no live conns, no
        // ban, no offenses, greylist over, strikes decayed away) — releases
        // idle memory without a timer thread, ratelimit's tail-sweep shape.
        while (g.lru.last) |tail| {
            const e: *Entry = @fieldParentPtr("node", tail);
            if (!g.entryIsEmpty(e, now_ns)) break;
            g.removeEntry(e);
        }
        if (g.map.count() >= g.options.max_tracked_ips)
            g.removeEntry(g.findEvictable() orelse return null);
        const e = g.gpa.create(Entry) catch return null;
        e.* = .{ .key = key, .strikes_updated_ns = now_ns };
        g.map.put(g.gpa, key, e) catch {
            g.gpa.destroy(e);
            return null;
        };
        g.lru.prepend(&e.node);
        return e;
    }

    /// Least-recently-used entry that may be dropped: never one with live
    /// connections (its count would be lost and the per-IP cap corrupted);
    /// banned entries only when nothing else qualifies (under sustained
    /// cap pressure the oldest ban can be forgotten — size
    /// `max_tracked_ips` generously).
    fn findEvictable(g: *Guard) ?*Entry {
        var it = g.lru.last;
        while (it) |n| : (it = n.prev) {
            const e: *Entry = @fieldParentPtr("node", n);
            if (e.active_conns == 0 and !e.banned) return e;
        }
        it = g.lru.last;
        while (it) |n| : (it = n.prev) {
            const e: *Entry = @fieldParentPtr("node", n);
            if (e.active_conns == 0) return e;
        }
        return null;
    }

    fn entryIsEmpty(g: *const Guard, e: *const Entry, now_ns: u64) bool {
        return e.active_conns == 0 and !e.banned and e.offenses == 0 and
            now_ns >= e.greylisted_until_ns and g.decayedStrikes(e, now_ns) == 0;
    }

    /// The strike balance after lazy decay: one strike drains per
    /// `strike_decay_ms`, floored at 0.
    fn decayedStrikes(g: *const Guard, e: *const Entry, now_ns: u64) f64 {
        if (g.options.strike_decay_ms == 0) return e.strikes;
        const decay_ns: f64 = @floatFromInt(g.options.strike_decay_ms *| std.time.ns_per_ms);
        const elapsed_ns: f64 = @floatFromInt(now_ns -| e.strikes_updated_ns);
        return @max(0, e.strikes - elapsed_ns / decay_ns);
    }

    fn removeEntry(g: *Guard, e: *Entry) void {
        const removed = g.map.remove(e.key);
        std.debug.assert(removed);
        g.lru.remove(&e.node);
        g.gpa.destroy(e);
    }
};

fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

// ── the server hooks ────────────────────────────────────────────────────────

fn onConnectHook(ctx: ?*anyopaque, peer: net.IpAddress) http.Server.ConnDecision {
    const g: *Guard = @ptrCast(@alignCast(ctx.?));
    return if (g.admit(ipOf(peer)) == .admitted) .accept else .reject;
}

fn onConnStateHook(ctx: ?*anyopaque, peer: ?net.IpAddress, state: http.Server.ConnState) void {
    if (state != .closed) return;
    const p = peer orelse return; // socket-free stream: never admitted
    const g: *Guard = @ptrCast(@alignCast(ctx.?));
    g.connClosed(ipOf(p));
}

fn ipOf(peer: net.IpAddress) netaddr.Ip {
    return switch (peer) {
        .ip4 => |a| .{ .v4 = a.bytes },
        .ip6 => |a| .{ .v6 = a.bytes },
    };
}

// ── the middleware ──────────────────────────────────────────────────────────

fn middlewareRun(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    const g: *Guard = @ptrCast(@alignCast(state.?));
    try next.run(ctx); // errors → server's 500: not the client's fault
    const status = ctx.res.status;
    const weight: u32 = if (status == 429)
        g.options.strike_429
    else if (status >= 400 and status < 500)
        g.options.strike_4xx
    else
        return;
    if (weight == 0) return;
    const ip = strikeIp(g, ctx.req) orelse return; // socket-free + keyless
    g.record(ip, weight);
}

/// The IP `middleware()` strikes, per `Options.middleware_key`. The
/// `.forwarded_ip` chain mirrors `ratelimit.clientKey`'s trust policy
/// (rightmost element of the last XFF header, then X-Real-IP), except that
/// values must parse as IP literals — garbage falls through to the peer.
fn strikeIp(g: *const Guard, req: *const http.Server.Request) ?netaddr.Ip {
    switch (g.options.middleware_key) {
        .peer_ip => {},
        .forwarded_ip => {
            var xff: ?[]const u8 = null;
            var it = req.iterateHeaders();
            while (it.next()) |h| {
                if (std.ascii.eqlIgnoreCase(h.name, "x-forwarded-for")) xff = h.value;
            }
            if (xff) |v| {
                const start = if (std.mem.lastIndexOfScalar(u8, v, ',')) |i| i + 1 else 0;
                if (netaddr.parseIp(std.mem.trim(u8, v[start..], " \t"))) |ip| return ip;
            }
            if (req.header("x-real-ip")) |v| {
                if (netaddr.parseIp(std.mem.trim(u8, v, " \t"))) |ip| return ip;
            }
        },
    }
    const peer = req.peerAddress() orelse return null;
    return ipOf(peer);
}

// ── tests: helpers ──────────────────────────────────────────────────────────

const testing = std.testing;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

/// Deterministic test clock; atomic so integration tests may advance it
/// while server threads read it.
const TestClock = struct {
    ns: std.atomic.Value(u64) = .init(0),

    fn clock(t: *TestClock) Clock {
        return .{ .ctx = t, .nowFn = nowFn };
    }
    fn nowFn(ctx: ?*anyopaque) u64 {
        const t: *TestClock = @ptrCast(@alignCast(ctx.?));
        return t.ns.load(.monotonic);
    }
    fn advanceMs(t: *TestClock, ms: u64) void {
        _ = t.ns.fetchAdd(ms * std.time.ns_per_ms, .monotonic);
    }
};

fn mkIp(text: []const u8) netaddr.Ip {
    return netaddr.parseIp(text).?;
}

fn mkPeer4(text: []const u8, port: u16) net.IpAddress {
    return net.IpAddress.parseIp4(text, port) catch unreachable;
}

/// Drive the wired hook pair exactly as `http.Server` would.
fn hookConnect(g: *Guard, peer: net.IpAddress) http.Server.ConnDecision {
    return g.onConnect()(g.onConnectCtx(), peer);
}

fn hookState(g: *Guard, peer: ?net.IpAddress, state: http.Server.ConnState) void {
    g.onConnState()(g.onConnStateCtx(), peer, state);
}

// ── tests: reputation store (offline, injected clock) ───────────────────────

test "ban/unban: manual ban rejects, unban forgives and releases the entry" {
    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{ .clock = tc.clock() });
    defer g.deinit();
    const ip = mkIp("192.0.2.1");

    try testing.expect(!g.isBanned(ip));
    try testing.expectEqual(AdmitVerdict.admitted, g.admit(ip));
    g.connClosed(ip);

    g.ban(ip);
    try testing.expect(g.isBanned(ip));
    try testing.expectEqual(AdmitVerdict.banned, g.admit(ip));

    g.unban(ip);
    try testing.expect(!g.isBanned(ip));
    try testing.expectEqual(@as(usize, 0), g.trackedCount()); // empty entry released
    try testing.expectEqual(AdmitVerdict.admitted, g.admit(ip));
    g.connClosed(ip);
}

test "greylist: manual add + TTL expiry through the injected clock" {
    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{ .clock = tc.clock() });
    defer g.deinit();
    const ip = mkIp("192.0.2.2");

    g.greylist(ip, 1000);
    try testing.expect(g.isGreylisted(ip));
    try testing.expectEqual(AdmitVerdict.greylisted, g.admit(ip));

    tc.advanceMs(999);
    try testing.expectEqual(AdmitVerdict.greylisted, g.admit(ip)); // still inside the TTL

    tc.advanceMs(1); // exactly at the boundary: expired
    try testing.expect(!g.isGreylisted(ip));
    try testing.expectEqual(AdmitVerdict.admitted, g.admit(ip));
    g.connClosed(ip);

    // null TTL = Options.greylist_ttl_ms.
    g.greylist(ip, null);
    try testing.expect(g.isGreylisted(ip));
    tc.advanceMs(10 * std.time.ms_per_min);
    try testing.expect(!g.isGreylisted(ip));
}

test "record: strikes → auto-greylist at threshold → ban on repeat offense" {
    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{
        .ban_threshold = 3,
        .ban_after_offenses = 2,
        .greylist_ttl_ms = 1000,
        .strike_decay_ms = 0, // keep the arithmetic exact
        .clock = tc.clock(),
    });
    defer g.deinit();
    const ip = mkIp("192.0.2.3");

    g.record(ip, 1);
    g.record(ip, 1);
    try testing.expect(!g.isGreylisted(ip)); // 2 < 3
    g.record(ip, 1); // offense #1 → greylist, not ban
    try testing.expect(g.isGreylisted(ip));
    try testing.expect(!g.isBanned(ip));
    try testing.expectEqual(AdmitVerdict.greylisted, g.admit(ip));

    tc.advanceMs(1001); // greylist expired — the client is back
    try testing.expectEqual(AdmitVerdict.admitted, g.admit(ip));
    g.connClosed(ip);

    // The balance was reset at the offense: a fresh threshold is needed.
    g.record(ip, 2);
    try testing.expect(!g.isGreylisted(ip));
    g.record(ip, 1); // offense #2 → permanent ban (recidive)
    try testing.expect(g.isBanned(ip));
    try testing.expect(!g.isGreylisted(ip));
    try testing.expectEqual(AdmitVerdict.banned, g.admit(ip));

    // A large single weight crosses immediately on another IP.
    const flood = mkIp("192.0.2.30");
    g.record(flood, 100);
    try testing.expect(g.isGreylisted(flood));
}

test "record: ban_after_offenses=1 bans at the first crossing; 0 never bans" {
    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{
        .ban_threshold = 2,
        .ban_after_offenses = 1,
        .strike_decay_ms = 0,
        .clock = tc.clock(),
    });
    defer g.deinit();
    g.record(mkIp("192.0.2.4"), 2);
    try testing.expect(g.isBanned(mkIp("192.0.2.4")));

    var g0 = Guard.init(testing.allocator, .{
        .ban_threshold = 2,
        .ban_after_offenses = 0,
        .greylist_ttl_ms = 1000,
        .strike_decay_ms = 0,
        .clock = tc.clock(),
    });
    defer g0.deinit();
    const ip = mkIp("192.0.2.5");
    var round: usize = 0;
    while (round < 5) : (round += 1) {
        g0.record(ip, 2);
        try testing.expect(g0.isGreylisted(ip));
        try testing.expect(!g0.isBanned(ip)); // never escalates
        tc.advanceMs(1001);
    }
}

test "record: strike decay drains one strike per strike_decay_ms" {
    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{
        .ban_threshold = 3,
        .strike_decay_ms = 1000,
        .clock = tc.clock(),
    });
    defer g.deinit();
    const ip = mkIp("192.0.2.6");

    // 2 strikes fully decay over 2s: the next strike starts from 0.
    g.record(ip, 2);
    tc.advanceMs(2000);
    g.record(ip, 2); // decayed 2 → 0, +2 = 2 < 3
    try testing.expect(!g.isGreylisted(ip));

    // Partial decay is exact: 1s drains exactly one strike.
    tc.advanceMs(1000); // balance 2 → 1
    g.record(ip, 2); // 1 + 2 = 3 → offense
    try testing.expect(g.isGreylisted(ip));
}

test "per-IP isolation: strikes, greylists and counters never leak across IPs" {
    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{
        .max_conns_per_ip = 1,
        .ban_threshold = 1,
        .ban_after_offenses = 0,
        .clock = tc.clock(),
    });
    defer g.deinit();
    const alice = mkIp("10.0.0.1");
    const bob = mkIp("10.0.0.2");

    g.record(alice, 1); // alice greylisted
    try testing.expect(g.isGreylisted(alice));
    try testing.expect(!g.isGreylisted(bob));
    try testing.expectEqual(AdmitVerdict.greylisted, g.admit(alice));
    try testing.expectEqual(AdmitVerdict.admitted, g.admit(bob));

    // bob's cap is bob's alone.
    try testing.expectEqual(AdmitVerdict.per_ip_cap, g.admit(bob));
    try testing.expectEqual(@as(u32, 1), g.connCount(bob));
    try testing.expectEqual(@as(u32, 0), g.connCount(alice));
    g.connClosed(bob);
    try testing.expectEqual(@as(usize, 0), g.totalConns());
}

test "keying: IPv4-mapped IPv6 and plain IPv4 are one client, one entry" {
    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{ .max_conns_per_ip = 2, .clock = tc.clock() });
    defer g.deinit();
    const v4 = mkIp("10.0.0.1");
    const mapped = mkIp("::ffff:10.0.0.1");

    try testing.expectEqual(AdmitVerdict.admitted, g.admit(v4));
    try testing.expectEqual(AdmitVerdict.admitted, g.admit(mapped));
    try testing.expectEqual(@as(usize, 1), g.trackedCount()); // one entry
    try testing.expectEqual(AdmitVerdict.per_ip_cap, g.admit(v4)); // shared cap
    try testing.expectEqual(@as(u32, 2), g.connCount(v4));
    try testing.expectEqual(@as(u32, 2), g.connCount(mapped));

    g.ban(v4);
    try testing.expect(g.isBanned(mapped)); // one reputation
    g.connClosed(mapped);
    g.connClosed(v4);
    try testing.expectEqual(@as(usize, 0), g.totalConns());

    // A genuine IPv6 client is its own entry.
    try testing.expect(!g.isBanned(mkIp("2001:db8::1")));
}

// ── tests: admission (offline, driving the wired hook pair) ─────────────────

test "hooks: per-IP counter inc/dec via the onConnect/onConnState pair" {
    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{ .max_conns_per_ip = 2, .clock = tc.clock() });
    defer g.deinit();
    const peer_a = mkPeer4("203.0.113.7", 1111);
    const peer_a2 = mkPeer4("203.0.113.7", 2222); // same IP, new source port
    const peer_b = mkPeer4("203.0.113.8", 1111);
    const ip_a = mkIp("203.0.113.7");

    // Two connections from A (ports differ — the key is the IP alone).
    try testing.expectEqual(http.Server.ConnDecision.accept, hookConnect(&g, peer_a));
    try testing.expectEqual(http.Server.ConnDecision.accept, hookConnect(&g, peer_a2));
    try testing.expectEqual(@as(u32, 2), g.connCount(ip_a));
    try testing.expectEqual(@as(usize, 2), g.totalConns());

    // At the per-IP cap: A is rejected, B is not.
    try testing.expectEqual(http.Server.ConnDecision.reject, hookConnect(&g, peer_a));
    try testing.expectEqual(http.Server.ConnDecision.accept, hookConnect(&g, peer_b));

    // Non-closed lifecycle states never release the slot.
    hookState(&g, peer_a, .new);
    hookState(&g, peer_a, .active);
    hookState(&g, peer_a, .idle);
    try testing.expectEqual(@as(u32, 2), g.connCount(ip_a));

    // .closed releases exactly one slot → A fits again.
    hookState(&g, peer_a, .closed);
    try testing.expectEqual(@as(u32, 1), g.connCount(ip_a));
    try testing.expectEqual(http.Server.ConnDecision.accept, hookConnect(&g, peer_a));

    // A null peer (socket-free stream) is ignored; unmatched closes saturate at 0.
    hookState(&g, null, .closed);
    hookState(&g, peer_b, .closed);
    hookState(&g, peer_b, .closed); // unmatched — no underflow
    try testing.expectEqual(@as(u32, 0), g.connCount(mkIp("203.0.113.8")));
    hookState(&g, peer_a, .closed);
    hookState(&g, peer_a2, .closed);
    try testing.expectEqual(@as(usize, 0), g.totalConns());
}

test "global cap: total_cap rejections, release re-admits, no entry churn" {
    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{
        .max_conns_per_ip = null,
        .max_conns_total = 3,
        .clock = tc.clock(),
    });
    defer g.deinit();

    try testing.expectEqual(AdmitVerdict.admitted, g.admit(mkIp("10.1.0.1")));
    try testing.expectEqual(AdmitVerdict.admitted, g.admit(mkIp("10.1.0.2")));
    try testing.expectEqual(AdmitVerdict.admitted, g.admit(mkIp("10.1.0.1"))); // no per-IP cap
    try testing.expectEqual(AdmitVerdict.total_cap, g.admit(mkIp("10.1.0.3")));
    // Shedding above the cap must not have inserted an entry for .3.
    try testing.expectEqual(@as(usize, 2), g.trackedCount());

    g.connClosed(mkIp("10.1.0.2"));
    try testing.expectEqual(AdmitVerdict.admitted, g.admit(mkIp("10.1.0.3")));
    try testing.expectEqual(@as(usize, 3), g.totalConns());
    g.connClosed(mkIp("10.1.0.1"));
    g.connClosed(mkIp("10.1.0.1"));
    g.connClosed(mkIp("10.1.0.3"));
    try testing.expectEqual(@as(usize, 0), g.totalConns());
}

// ── tests: bounded store (offline) ──────────────────────────────────────────

test "bounded store: LRU eviction at max_tracked_ips" {
    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{
        .max_tracked_ips = 3,
        .ban_threshold = 100, // strikes only, no offenses
        .strike_decay_ms = 0, // strikes never decay → entries stay non-empty
        .clock = tc.clock(),
    });
    defer g.deinit();

    g.record(mkIp("10.2.0.1"), 1);
    g.record(mkIp("10.2.0.2"), 1);
    g.record(mkIp("10.2.0.3"), 1);
    try testing.expectEqual(@as(usize, 3), g.trackedCount());

    g.record(mkIp("10.2.0.1"), 1); // touch .1 → .2 becomes LRU
    g.record(mkIp("10.2.0.4"), 1); // at cap → evicts .2
    try testing.expectEqual(@as(usize, 3), g.trackedCount());

    // .1 kept its strikes (2 + 98 crosses the threshold of 100)…
    g.record(mkIp("10.2.0.1"), 98);
    try testing.expect(g.isGreylisted(mkIp("10.2.0.1")));
    // …while the evicted .2 starts from zero (the price of eviction).
    g.record(mkIp("10.2.0.2"), 98);
    try testing.expect(!g.isGreylisted(mkIp("10.2.0.2")));
}

test "bounded store: live connections are never evicted; store_full rejects; empties are swept" {
    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{
        .max_tracked_ips = 2,
        .ban_threshold = 100,
        .strike_decay_ms = 1000,
        .clock = tc.clock(),
    });
    defer g.deinit();

    // Two IPs with live connections fill the store; a third is untrackable
    // → rejected (nginx zone-exhausted semantics, fail-closed).
    try testing.expectEqual(AdmitVerdict.admitted, g.admit(mkIp("10.3.0.1")));
    try testing.expectEqual(AdmitVerdict.admitted, g.admit(mkIp("10.3.0.2")));
    try testing.expectEqual(AdmitVerdict.store_full, g.admit(mkIp("10.3.0.3")));
    try testing.expectEqual(@as(usize, 2), g.trackedCount());
    // A strike on an untrackable IP is dropped, not misattributed.
    g.record(mkIp("10.3.0.3"), 50);
    try testing.expectEqual(@as(usize, 2), g.trackedCount());

    // Releasing one slot leaves an empty entry: the next insert reclaims
    // it (tail sweep or LRU eviction, whichever reaches it first).
    g.connClosed(mkIp("10.3.0.2"));
    try testing.expectEqual(AdmitVerdict.admitted, g.admit(mkIp("10.3.0.3")));
    try testing.expectEqual(@as(usize, 2), g.trackedCount());
    try testing.expectEqual(@as(u32, 0), g.connCount(mkIp("10.3.0.2"))); // gone

    // The still-live .1 was never evicted through any of that.
    try testing.expectEqual(@as(u32, 1), g.connCount(mkIp("10.3.0.1")));
    g.connClosed(mkIp("10.3.0.1"));
    g.connClosed(mkIp("10.3.0.3"));
}

test "bounded store: banned entries are evicted last" {
    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{
        .max_tracked_ips = 2,
        .ban_threshold = 100,
        .strike_decay_ms = 0,
        .clock = tc.clock(),
    });
    defer g.deinit();

    g.ban(mkIp("10.4.0.1")); // LRU-oldest, but banned
    g.record(mkIp("10.4.0.2"), 1);
    g.record(mkIp("10.4.0.3"), 1); // at cap → evicts .2, NOT the banned .1
    try testing.expect(g.isBanned(mkIp("10.4.0.1")));
    try testing.expectEqual(@as(usize, 2), g.trackedCount());

    // With only banned entries left as candidates, the oldest ban goes
    // (documented last resort — memory boundedness wins).
    g.ban(mkIp("10.4.0.3")); // now: .1 banned, .3 banned
    g.record(mkIp("10.4.0.4"), 1); // evicts banned .1
    try testing.expect(!g.isBanned(mkIp("10.4.0.1")));
    try testing.expect(g.isBanned(mkIp("10.4.0.3")));
}

test "bounded store: expired greylists and decayed strikes sweep as empty" {
    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{
        .max_tracked_ips = 100,
        .ban_threshold = 2,
        .ban_after_offenses = 0,
        .greylist_ttl_ms = 1000,
        .strike_decay_ms = 1000,
        .clock = tc.clock(),
    });
    defer g.deinit();

    g.record(mkIp("10.5.0.1"), 1); // 1 strike, decays by t+1000
    tc.advanceMs(2000);
    // Inserting a new key sweeps the fully-lapsed .1 from the LRU tail.
    g.record(mkIp("10.5.0.2"), 1);
    try testing.expectEqual(@as(usize, 1), g.trackedCount());
}

test "guard: OOM on entry tracking fails closed" {
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var tc: TestClock = .{};
    var g = Guard.init(failing.allocator(), .{ .clock = tc.clock() });
    defer g.deinit();
    try testing.expectEqual(AdmitVerdict.store_full, g.admit(mkIp("10.6.0.1")));
    try testing.expectEqual(@as(usize, 0), g.trackedCount());
    try testing.expectEqual(@as(usize, 0), g.totalConns());
}

// ── tests: concurrency (offline) ────────────────────────────────────────────

test "race: concurrent admits from one IP admit exactly the cap" {
    const threads = 8;
    const attempts_per_thread = 100;
    const cap = 100;

    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{
        .max_conns_per_ip = cap,
        .clock = tc.clock(),
    });
    defer g.deinit();
    const ip = mkIp("198.51.100.1");

    const Worker = struct {
        fn run(guard: *Guard, target: netaddr.Ip, admitted: *std.atomic.Value(u32)) void {
            for (0..attempts_per_thread) |_| {
                if (guard.admit(target) == .admitted) _ = admitted.fetchAdd(1, .monotonic);
            }
        }
    };

    var admitted: std.atomic.Value(u32) = .init(0);
    var handles: [threads]std.Thread = undefined;
    for (&handles) |*h| h.* = try std.Thread.spawn(.{}, Worker.run, .{ &g, ip, &admitted });
    for (handles) |h| h.join();

    try testing.expectEqual(@as(u32, cap), admitted.load(.monotonic));
    try testing.expectEqual(@as(u32, cap), g.connCount(ip));
    try testing.expectEqual(@as(usize, cap), g.totalConns());
    for (0..cap) |_| g.connClosed(ip);
    try testing.expectEqual(@as(usize, 0), g.totalConns());
}

test "race: concurrent record loses no strikes (exact threshold crossing)" {
    const threads = 8;
    const strikes_per_thread = 100;

    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{
        // The ban triggers exactly at the 800th strike — any lost update
        // leaves the IP unbanned.
        .ban_threshold = threads * strikes_per_thread,
        .ban_after_offenses = 1,
        .strike_decay_ms = 0,
        .clock = tc.clock(),
    });
    defer g.deinit();
    const ip = mkIp("198.51.100.2");

    const Worker = struct {
        fn run(guard: *Guard, target: netaddr.Ip) void {
            for (0..strikes_per_thread) |_| guard.record(target, 1);
        }
    };

    var handles: [threads]std.Thread = undefined;
    for (&handles) |*h| h.* = try std.Thread.spawn(.{}, Worker.run, .{ &g, ip });
    for (handles) |h| h.join();

    try testing.expect(g.isBanned(ip));
    try testing.expectEqual(@as(usize, 1), g.trackedCount());
}

// ── tests: middleware over the socket-free server codec ─────────────────────

/// Drive a router through `http.Server.serveStream` with canned wire bytes
/// and an optional socket peer (the ratelimit test harness shape).
fn runWirePeer(r: *router.Router, bytes: []const u8, out_buf: []u8, peer: ?net.IpAddress) []const u8 {
    var in: Reader = .fixed(bytes);
    var out: Writer = .fixed(out_buf);
    var head_buf: [2048]u8 = undefined;
    var request_body_buf: [256]u8 = undefined;
    var response_body_buf: [512]u8 = undefined;
    var chunk_buf: [128]u8 = undefined;
    http.Server.serveStream(.{
        .handler = r.handler(),
        .context = r,
        .server_name = null,
        .peer = peer,
    }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    return out.buffered();
}

fn wire(comptime target: []const u8, comptime headers: []const u8) []const u8 {
    return "GET " ++ target ++ " HTTP/1.1\r\nHost: t\r\n" ++ headers ++ "Connection: close\r\n\r\n";
}

fn expectStatus(got: []const u8, comptime status: []const u8) !void {
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 " ++ status));
}

fn hOk(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll("ok");
}

fn hTooMany(ctx: *router.Ctx) anyerror!void {
    ctx.res.setStatus(429);
    try ctx.res.writeAll("slow down");
}

fn guardedRouter(g: *Guard) !router.Router {
    var r = router.Router.init(testing.allocator);
    errdefer r.deinit();
    try r.use(g.middleware());
    try r.get("/ok", hOk);
    try r.get("/toomany", hTooMany);
    return r;
}

test "middleware: 4xx responses strike the peer into a greylist; 2xx never strikes" {
    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{
        .ban_threshold = 3,
        .strike_decay_ms = 0,
        .clock = tc.clock(),
    });
    defer g.deinit();
    var r = try guardedRouter(&g);
    defer r.deinit();

    const peer = mkPeer4("203.0.113.9", 4242);
    const ip = mkIp("203.0.113.9");
    var buf: [1024]u8 = undefined;

    // 200s strike nothing, ever.
    try expectStatus(runWirePeer(&r, wire("/ok", ""), &buf, peer), "200");
    try testing.expectEqual(@as(usize, 0), g.trackedCount());

    // Three 404s (router default not_found runs behind the chain) = three
    // strikes → greylist at the threshold.
    try expectStatus(runWirePeer(&r, wire("/nope", ""), &buf, peer), "404");
    try expectStatus(runWirePeer(&r, wire("/nope", ""), &buf, peer), "404");
    try testing.expect(!g.isGreylisted(ip));
    try expectStatus(runWirePeer(&r, wire("/nope", ""), &buf, peer), "404");
    try testing.expect(g.isGreylisted(ip));
    try testing.expectEqual(AdmitVerdict.greylisted, g.admit(ip));

    // Without a peer (socket-free, no key) a 404 is not misattributed.
    try expectStatus(runWirePeer(&r, wire("/nope", ""), &buf, null), "404");
    try testing.expectEqual(@as(usize, 1), g.trackedCount());
}

test "middleware: 429 uses its own (heavier) weight" {
    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{
        .ban_threshold = 3,
        .strike_4xx = 1,
        .strike_429 = 3, // one 429 = instant offense
        .strike_decay_ms = 0,
        .clock = tc.clock(),
    });
    defer g.deinit();
    var r = try guardedRouter(&g);
    defer r.deinit();

    const peer = mkPeer4("203.0.113.10", 4242);
    var buf: [1024]u8 = undefined;
    try expectStatus(runWirePeer(&r, wire("/toomany", ""), &buf, peer), "429");
    try testing.expect(g.isGreylisted(mkIp("203.0.113.10")));
}

test "middleware: zero weights disable striking" {
    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{
        .ban_threshold = 1,
        .strike_4xx = 0,
        .strike_429 = 0,
        .clock = tc.clock(),
    });
    defer g.deinit();
    var r = try guardedRouter(&g);
    defer r.deinit();

    const peer = mkPeer4("203.0.113.11", 4242);
    var buf: [1024]u8 = undefined;
    try expectStatus(runWirePeer(&r, wire("/nope", ""), &buf, peer), "404");
    try expectStatus(runWirePeer(&r, wire("/toomany", ""), &buf, peer), "429");
    try testing.expectEqual(@as(usize, 0), g.trackedCount());
}

test "middleware: forwarded_ip keying strikes the XFF client, not the proxy peer" {
    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{
        .ban_threshold = 1,
        .ban_after_offenses = 0,
        .middleware_key = .forwarded_ip,
        .clock = tc.clock(),
    });
    defer g.deinit();
    var r = try guardedRouter(&g);
    defer r.deinit();

    const proxy = mkPeer4("10.9.0.1", 4242);
    var buf: [1024]u8 = undefined;

    // Rightmost element of the last XFF header is the trusted client.
    try expectStatus(runWirePeer(&r, wire("/nope", "X-Forwarded-For: 9.9.9.9, 198.51.100.7\r\n"), &buf, proxy), "404");
    try testing.expect(g.isGreylisted(mkIp("198.51.100.7")));
    try testing.expect(!g.isGreylisted(mkIp("9.9.9.9"))); // spoofed prefix ignored
    try testing.expect(!g.isGreylisted(mkIp("10.9.0.1"))); // proxy unpunished

    // X-Real-IP is the fallback; garbage XFF falls through to it.
    try expectStatus(runWirePeer(&r, wire("/nope", "X-Forwarded-For: not-an-ip\r\nX-Real-IP: 198.51.100.8\r\n"), &buf, proxy), "404");
    try testing.expect(g.isGreylisted(mkIp("198.51.100.8")));

    // No forwarded headers at all → the socket peer takes the strike.
    try expectStatus(runWirePeer(&r, wire("/nope", ""), &buf, proxy), "404");
    try testing.expect(g.isGreylisted(mkIp("10.9.0.1")));
}

// ── tests: in-process integration (guard + http.Server over loopback) ───────

fn serveWrap(s: *http.Server) void {
    s.serve() catch {};
}

fn sleepMs(io: std.Io, ms: u32) !void {
    const d: std.Io.Clock.Duration = .{ .raw = .fromMilliseconds(ms), .clock = .awake };
    d.sleep(io) catch return error.Canceled;
}

/// Poll the guard's total until it reaches `want` (bounded ≈ 10 s).
fn waitTotal(g: *Guard, io: std.Io, want: usize) !void {
    var tries: usize = 0;
    while (g.totalConns() != want) : (tries += 1) {
        if (tries > 1000) return error.TestTimeout;
        try sleepMs(io, 10);
    }
}

fn httpHandler(req: *http.Server.Request, rw: *http.Server.ResponseWriter) anyerror!void {
    _ = req;
    try rw.writeAll("ok");
}

/// One full close-mode exchange on a fresh connection; asserts the status.
fn expectServed(io: std.Io, addr: net.IpAddress, comptime status: []const u8) !void {
    const stream = try addr.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var rbuf: [4096]u8 = undefined;
    var wbuf: [512]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);
    try sw.interface.writeAll("GET /ok HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
    try sw.interface.flush();
    try expectResponse(&sr.interface, status);
}

/// A fresh connection the server must reject at accept: the handshake
/// completes (kernel backlog), then the socket closes with nothing written.
fn expectRejected(io: std.Io, addr: net.IpAddress) !void {
    const stream = try addr.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var rbuf: [64]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    if (sr.interface.take(1)) |_| {
        return error.TestUnexpectedResult; // the server must not serve us
    } else |err| {
        try testing.expect(err == error.EndOfStream or err == error.ReadFailed);
    }
}

/// Read one response head + body off `r`, asserting the status prefix.
fn expectResponse(r: *Reader, comptime status: []const u8) !void {
    const line = (try r.takeDelimiter('\n')) orelse return error.UnexpectedEof;
    try testing.expect(std.mem.startsWith(u8, line, "HTTP/1.1 " ++ status));
    var content_length: usize = 0;
    while (try r.takeDelimiter('\n')) |raw| {
        const l = std.mem.trimEnd(u8, raw, "\r");
        if (l.len == 0) break;
        if (std.ascii.startsWithIgnoreCase(l, "content-length:")) {
            const v = std.mem.trim(u8, l["content-length:".len..], " \t");
            content_length = try std.fmt.parseInt(usize, v, 10);
        }
    }
    _ = try r.take(content_length);
}

test "integration: per-IP cap, ban, greylist expiry and record-driven auto-ban at accept" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var tc: TestClock = .{}; // injected even here: greylist expiry needs no sleeping
    var guard = Guard.init(testing.allocator, .{
        .max_conns_per_ip = 2,
        .ban_threshold = 3,
        .ban_after_offenses = 2,
        .greylist_ttl_ms = 60_000,
        .strike_decay_ms = 0,
        .clock = tc.clock(),
    });
    defer guard.deinit();
    const loopback = mkIp("127.0.0.1");

    var server = http.Server.init(io, testing.allocator, .{
        .handler = httpHandler,
        .on_connect = guard.onConnect(),
        .on_connect_ctx = guard.onConnectCtx(),
        .on_conn_state = guard.onConnState(),
        .on_conn_state_ctx = guard.onConnStateCtx(),
    });
    defer server.deinit();
    server.bind() catch |err| {
        std.debug.print("loopback bind failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    const thread = try std.Thread.spawn(.{}, serveWrap, .{&server});
    defer thread.join();
    defer server.shutdown();
    const addr = server.boundAddress();

    // Connection 1 — keep-alive, held open for the whole test.
    const c1 = addr.connect(io, .{ .mode = .stream }) catch |err| {
        std.debug.print("loopback connect failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    var c1_open = true;
    defer if (c1_open) c1.close(io);
    var c1_rbuf: [4096]u8 = undefined;
    var c1_wbuf: [512]u8 = undefined;
    var c1r = c1.reader(io, &c1_rbuf);
    var c1w = c1.writer(io, &c1_wbuf);
    try c1w.interface.writeAll("GET /ok HTTP/1.1\r\nHost: t\r\n\r\n");
    try c1w.interface.flush();
    try expectResponse(&c1r.interface, "200");

    // Connection 2 — keep-alive, held open.
    const c2 = try addr.connect(io, .{ .mode = .stream });
    defer c2.close(io);
    var c2_rbuf: [4096]u8 = undefined;
    var c2_wbuf: [512]u8 = undefined;
    var c2r = c2.reader(io, &c2_rbuf);
    var c2w = c2.writer(io, &c2_wbuf);
    try c2w.interface.writeAll("GET /ok HTTP/1.1\r\nHost: t\r\n\r\n");
    try c2w.interface.flush();
    try expectResponse(&c2r.interface, "200");

    // Both served and still admitted: guard and server agree on the count.
    try testing.expectEqual(@as(usize, 2), guard.totalConns());
    try testing.expectEqual(@as(u32, 2), guard.connCount(loopback));
    try testing.expectEqual(@as(usize, 2), server.activeConnections());

    // Third concurrent connection from the same IP → rejected at accept.
    try expectRejected(io, addr);
    try testing.expectEqual(@as(usize, 2), guard.totalConns());
    try testing.expectEqual(@as(usize, 2), server.activeConnections());

    // Closing one held connection frees its slot (.closed → decrement)…
    c1.close(io);
    c1_open = false;
    try waitTotal(&guard, io, 1);
    try testing.expectEqual(@as(u32, 1), guard.connCount(loopback));
    // …and the next connection is admitted and served again.
    try expectServed(io, addr, "200");
    try waitTotal(&guard, io, 1); // the close-mode conn released its slot

    // Manual ban cuts new connections; unban restores them.
    guard.ban(loopback);
    try expectRejected(io, addr);
    guard.unban(loopback);
    try expectServed(io, addr, "200");
    try waitTotal(&guard, io, 1);

    // Greylist rejects until the TTL expires (clock advanced, no sleeping).
    guard.greylist(loopback, null);
    try expectRejected(io, addr);
    tc.advanceMs(60_001);
    try testing.expect(!guard.isGreylisted(loopback));
    try expectServed(io, addr, "200");
    try waitTotal(&guard, io, 1);

    // record-driven escalation, end to end: offense #1 greylists…
    guard.record(loopback, 3);
    try testing.expect(guard.isGreylisted(loopback));
    try expectRejected(io, addr);
    tc.advanceMs(60_001);
    try expectServed(io, addr, "200");
    try waitTotal(&guard, io, 1);
    // …offense #2 bans permanently.
    guard.record(loopback, 3);
    try testing.expect(guard.isBanned(loopback));
    try expectRejected(io, addr);
    tc.advanceMs(120_000);
    try expectRejected(io, addr); // a ban never expires
    try testing.expectEqual(@as(usize, 1), guard.totalConns()); // c2 still fine
}

test "integration: middleware auto-strike on real 404s escalates to accept-time rejection" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var tc: TestClock = .{};
    var guard = Guard.init(testing.allocator, .{
        .ban_threshold = 3,
        .ban_after_offenses = 0, // greylist only, so the test can recover
        .greylist_ttl_ms = 60_000,
        .strike_decay_ms = 0,
        .clock = tc.clock(),
    });
    defer guard.deinit();
    const loopback = mkIp("127.0.0.1");

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(guard.middleware());
    try r.get("/ok", hOk);

    var server = http.Server.init(io, testing.allocator, .{
        .handler = r.handler(),
        .context = &r,
        .on_connect = guard.onConnect(),
        .on_connect_ctx = guard.onConnectCtx(),
        .on_conn_state = guard.onConnState(),
        .on_conn_state_ctx = guard.onConnStateCtx(),
    });
    defer server.deinit();
    server.bind() catch |err| {
        std.debug.print("loopback bind failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    const thread = try std.Thread.spawn(.{}, serveWrap, .{&server});
    defer thread.join();
    defer server.shutdown();
    const addr = server.boundAddress();

    // Probe reachability once (skip like the sibling tests if loopback is off).
    {
        const probe = addr.connect(io, .{ .mode = .stream }) catch |err| {
            std.debug.print("loopback connect failed ({s}), skipping\n", .{@errorName(err)});
            return error.SkipZigTest;
        };
        probe.close(io);
    }
    try waitTotal(&guard, io, 0);

    // A path scanner: three 404s, each auto-striking via the middleware.
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        const stream = try addr.connect(io, .{ .mode = .stream });
        defer stream.close(io);
        var rbuf: [4096]u8 = undefined;
        var wbuf: [512]u8 = undefined;
        var sr = stream.reader(io, &rbuf);
        var sw = stream.writer(io, &wbuf);
        try sw.interface.writeAll("GET /admin/secret HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
        try sw.interface.flush();
        try expectResponse(&sr.interface, "404");
    }

    // The third strike crossed the threshold: greylisted, next connection
    // is refused before a single byte of HTTP.
    try testing.expect(guard.isGreylisted(loopback));
    try expectRejected(io, addr);

    // After the TTL (injected clock) the client is served again.
    tc.advanceMs(60_001);
    try expectServed(io, addr, "200");
}
