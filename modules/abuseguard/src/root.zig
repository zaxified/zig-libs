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
//!   That default is itself a lockout vector: N addresses each holding one
//!   idle connection under every cap fill the store, and every NEW address
//!   is refused while the holders are served (measured from qap, 2026-09-29:
//!   4096 loopback addresses; over IPv6 per /64 a free /48 is 65 536 keys).
//!   `Options.on_store_full = .admit_untracked` is the opt-out: such a
//!   connection skips the per-IP cap and reputation, but it is still
//!   COUNTED — in `total_conns` and against `max_conns_total` — so the
//!   global bound holds for it as for everyone else.
//! - **fail2ban:** `record(ip, weight)` ≈ a failregex hit; `ban_threshold`
//!   ≈ maxretry; `greylist_ttl_ms` ≈ bantime; strike decay ≈ findtime
//!   (approximated as a leaky bucket: one strike drains per
//!   `strike_decay_ms`); `ban_after_offenses` ≈ the recidive jail
//!   (repeated greylistings escalate to a permanent ban).
//!
//! Keying: the socket peer IP — the real client in a direct-internet
//! deployment. IPs are unmapped (an IPv4-mapped IPv6 peer and its plain
//! IPv4 form are one client, one budget), then masked to
//! `Options.ipv6_key_bits` (default /64: one subscriber, RFC 6177) /
//! `ipv4_key_bits` and keyed in the 16-byte `as16` form; all per-key state
//! lives on that key. `Options.allow` exempts addresses from reputation
//! (fail2ban `ignoreip`), `banPrefix` bans ranges, and `snapshot` /
//! `restore` (+ a text codec) carry bans across a restart. The
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
//! - Former server edge, now CLOSED in `http`: a connection admitted by
//!   `on_connect` but dropped before serving began reported no lifecycle
//!   state at all, so `.closed` never fired and that IP's slot leaked by
//!   one — permanently. This was documented here as an OOM-only edge, and
//!   it was not: with h2c enabled, a peer that simply sent nothing took the
//!   same exit, making the leak client-triggered at one idle socket apiece
//!   — the traffic shape this module exists to bound. `http.Server` now
//!   reports `.new`/`.closed` for a connection dropped before serving, so
//!   the pairing holds on every path. `reconcile(ip, live)` remains
//!   available to drop a phantom slot; the guard's own memory was always
//!   bounded regardless.

const std = @import("std");
const testkit = @import("testkit");
const http = @import("http");
const netaddr = @import("netaddr");
const router = @import("router");
const net = std.Io.net;

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Per-IP + global connection caps, ban/greylist, strike→ban (accept-time)",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "posix",
    .targets = .{.linux64},
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
    ///
    /// Drains in **whole** strikes, so `ban_threshold` means the same number
    /// of unit strikes whatever this is set to. Draining a fraction of a
    /// strike per nanosecond would make N strikes arriving together sum to
    /// marginally under N, and `ban_threshold = N` would silently mean N+1.
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
    /// so size this ≥ any `max_conns_total`. Must be ≥ 1. What happens
    /// past it is `on_store_full`.
    max_tracked_ips: usize = 4096,
    /// A new IP that cannot be tracked (store full of live connections, or
    /// the allocator failed): `.reject` → `.store_full` (fail-closed, the
    /// default); `.admit_untracked` → `.admitted_untracked`: no entry, so no
    /// per-IP cap, ban or greylist applies to it, but it counts in
    /// `total_conns` and `max_conns_total` still refuses it. Pick it when
    /// the lockout is worse than an uncapped address — and then set
    /// `max_conns_total`, the one bound left on those connections. `init`
    /// does not insist on it: a consumer may knowingly run without a global
    /// cap (qap's default does, and documents it), so that check belongs to
    /// the consumer's configuration validation.
    on_store_full: StoreFull = .reject,
    /// Addresses exempt from every reputation verdict (fail2ban `ignoreip`):
    /// a health checker, an office range, a peer proxy. A member is never
    /// answered `.banned` / `.greylisted` (by an entry or by `banPrefix`),
    /// `record` and the middleware's auto-strike are no-ops for it and
    /// create no entry. Resource caps still apply (`max_conns_per_ip`,
    /// `max_conns_total`, `store_full`) -- a cap is not reputation. Matched
    /// against the peer after `Ip.unmap`, so a v4 prefix covers both a plain
    /// v4 peer and its v4-mapped v6 form. A manual `ban` / `greylist` of a
    /// member is still stored (and snapshotted) but `admit` ignores it while
    /// the address stays allowlisted. Linear scan; the slice is borrowed and
    /// must outlive the Guard.
    allow: []const netaddr.Prefix = &.{},
    /// Width of the IPv6 reputation key, in bits (1..128). Every per-key
    /// state -- live-connection count, strikes, ban, greylist, offenses --
    /// belongs to the peer address masked to this width, so an attacker
    /// rotating addresses inside one /64 (one subscriber, RFC 6177) shares
    /// one budget. 128 = per single address (the pre-2026-10-04 behaviour).
    ipv6_key_bits: u8 = 64,
    /// Width of the IPv4 reputation key, in bits (1..32); see
    /// `ipv6_key_bits`. IPv4-mapped IPv6 peers are unmapped first and use
    /// this one.
    ipv4_key_bits: u8 = 32,
    /// At most this many `banPrefix` ranges (a linear scan per admission, so
    /// keep it small). Beyond it `banPrefix` fails with `TooManyPrefixBans`.
    max_prefix_bans: usize = 256,
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

/// `Options.on_store_full`.
pub const StoreFull = enum { reject, admit_untracked };

// ── the guard ───────────────────────────────────────────────────────────────

/// `admit`'s verdict — anything but `.admitted` / `.admitted_untracked`
/// maps to a `.reject` at the server hook (which closes the socket without
/// writing a byte).
pub const AdmitVerdict = enum {
    /// Connection admitted; the per-IP and total counters were incremented.
    /// Pair with exactly one `connClosed` when the connection ends.
    admitted,
    /// The IP is banned (manual `ban`, offense escalation or a `banPrefix`
    /// range).
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
    /// The store was full and `on_store_full = .admit_untracked`: admitted
    /// with no entry, counted in the total only. Pair with exactly one
    /// `connClosedUntracked` (or `connClosed`, which falls back to it).
    admitted_untracked,
};

/// The reputation store + admission engine. Allocator-explicit, bounded,
/// clock-injected, internally synchronized — see the module doc. Do not
/// move a Guard once entries exist (the LRU list points into it).
pub const Guard = struct {
    gpa: Allocator,
    options: Options,
    lock: std.atomic.Mutex = .unlocked,
    /// Keyed by the unmapped IP masked to the key width (`keyOf`) in its
    /// 16-byte mapped form (`netaddr.Ip.as16`), which unifies IPv4 with
    /// IPv4-mapped IPv6 and a v6 /64 with its subscriber — one client, one
    /// entry.
    map: std.AutoHashMapUnmanaged(Key, *Entry) = .empty,
    /// Front = most recently touched; eviction scans from the back.
    lru: std.DoublyLinkedList = .{},
    /// Live admitted connections across all IPs (the global cap's counter).
    /// Invariant: `total_conns == Σ active_conns + untracked_conns`.
    total_conns: usize = 0,
    /// Live connections admitted with no entry (`.admitted_untracked`).
    untracked_conns: usize = 0,
    /// `banPrefix` ranges: canonical (`masked`, unmapped), unique, at most
    /// `Options.max_prefix_bans`.
    prefix_bans: std.ArrayList(netaddr.Prefix) = .empty,

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
        std.debug.assert(options.ipv6_key_bits >= 1 and options.ipv6_key_bits <= 128);
        std.debug.assert(options.ipv4_key_bits >= 1 and options.ipv4_key_bits <= 32);
        return .{ .gpa = gpa, .options = options };
    }

    pub fn deinit(g: *Guard) void {
        var it = g.map.valueIterator();
        while (it.next()) |e| g.gpa.destroy(e.*);
        g.map.deinit(g.gpa);
        g.prefix_bans.deinit(g.gpa);
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
    /// now: reject when banned (entry or `banPrefix` range) / greylisted /
    /// over the per-key cap / over
    /// the global cap / untrackable (unless `on_store_full` admits it
    /// untracked) — otherwise count it and admit. Thread-safe. Every
    /// `.admitted` must be paired with one `connClosed`, every
    /// `.admitted_untracked` with one `connClosedUntracked`.
    pub fn admit(g: *Guard, ip: netaddr.Ip) AdmitVerdict {
        const now_ns = g.options.clock.now();
        lockSpin(&g.lock);
        defer g.lock.unlock();

        // Global cap first: cheapest, and shedding must not insert entries.
        if (g.options.max_conns_total) |max| {
            if (g.total_conns >= max) return .total_cap;
        }
        const allowed = g.isAllowed(ip);
        // A banned range is refused before any entry is looked up or made, so
        // a rejected peer neither churns the LRU nor, when the store is full,
        // slips in through `.admit_untracked`.
        if (!allowed and g.inPrefixBan(ip)) return .banned;
        const e = g.getOrCreate(g.keyOf(ip), now_ns) orelse switch (g.options.on_store_full) {
            .reject => return .store_full,
            .admit_untracked => {
                g.untracked_conns += 1;
                g.total_conns += 1;
                return .admitted_untracked;
            },
        };
        if (!allowed) {
            if (e.banned) return .banned;
            if (now_ns < e.greylisted_until_ns) return .greylisted;
            e.greylisted_until_ns = 0; // lazy expiry
        }
        if (g.options.max_conns_per_ip) |max| {
            if (e.active_conns >= max) return .per_ip_cap;
        }
        e.active_conns += 1;
        g.total_conns += 1;
        return .admitted;
    }

    /// Release the slot `admit` counted for `ip`. With no live slot for
    /// `ip` it releases an untracked one if any is live (the server hook
    /// knows only the peer, not which verdict admitted it); past that,
    /// unmatched calls are ignored — counters never go negative. The
    /// fallback can briefly credit the wrong side when an untracked address
    /// later gets an entry too: its untracked close takes the tracked slot,
    /// the tracked close then takes the untracked one — the totals end
    /// exact, the per-IP count ran one low in between. A caller that knows
    /// the verdict calls `connClosedUntracked` and is exact throughout.
    /// Thread-safe.
    pub fn connClosed(g: *Guard, ip: netaddr.Ip) void {
        lockSpin(&g.lock);
        defer g.lock.unlock();
        if (g.map.get(g.keyOf(ip))) |e| if (e.active_conns != 0) {
            e.active_conns -= 1;
            g.total_conns -|= 1;
            return;
        };
        g.releaseUntracked();
    }

    /// Release a connection `admit` answered `.admitted_untracked`.
    /// Unmatched calls are ignored. Thread-safe.
    pub fn connClosedUntracked(g: *Guard) void {
        lockSpin(&g.lock);
        defer g.lock.unlock();
        g.releaseUntracked();
    }

    fn releaseUntracked(g: *Guard) void {
        if (g.untracked_conns == 0) return;
        g.untracked_conns -= 1;
        g.total_conns -|= 1;
    }

    /// Force `ip`'s live-connection count to `live`, adjusting the global
    /// counter by the delta (invariant `total_conns == Σ active_conns +
    /// untracked_conns` is
    /// preserved; neither counter can go negative). This is the recovery
    /// path for the one leak `admit`/`connClosed` cannot close on their own:
    /// the documented server edge where an *admitted* connection is dropped
    /// before `.closed` fires (its per-IP slot would otherwise leak upward
    /// until restart). A supervisor that knows the true live count for `ip`
    /// — e.g. from `http.Server`'s own per-connection state — calls this to
    /// drop the phantom slots. No-op for an untracked IP. Thread-safe.
    pub fn reconcile(g: *Guard, ip: netaddr.Ip, live: u32) void {
        lockSpin(&g.lock);
        defer g.lock.unlock();
        const e = g.map.get(g.keyOf(ip)) orelse return;
        if (live < e.active_conns) {
            g.total_conns -|= e.active_conns - live;
        } else {
            g.total_conns +|= live - e.active_conns;
        }
        e.active_conns = live;
    }

    // ── reputation ──────────────────────────────────────────────────────

    /// Accrue `weight` strikes against `ip` (an app-flagged abuse event —
    /// auth failure, malformed input, a 429 from `ratelimit`, …). Strikes
    /// decay per `strike_decay_ms`; when the decayed balance reaches
    /// `ban_threshold` it resets, the offense count rises and the IP is
    /// greylisted for `greylist_ttl_ms` — or banned outright once
    /// `ban_after_offenses` is reached. `weight` 0 is a no-op, and so is any
    /// weight for an `Options.allow` member. Strikes are per key
    /// (`Options.ipv6_key_bits`). Best-effort
    /// under memory pressure: when the IP cannot be tracked (store full of
    /// live connections / OOM) the strike is dropped. Thread-safe.
    pub fn record(g: *Guard, ip: netaddr.Ip, weight: u32) void {
        if (weight == 0) return;
        const now_ns = g.options.clock.now();
        lockSpin(&g.lock);
        defer g.lock.unlock();
        if (g.isAllowed(ip)) return;
        const e = g.getOrCreate(g.keyOf(ip), now_ns) orelse return;
        const drained = g.drainedSince(e, now_ns);
        e.strikes = @max(0, e.strikes - @as(f64, @floatFromInt(drained))) +
            @as(f64, @floatFromInt(weight));
        // `record` returns above when `weight == 0`, so `weight >= 1` here
        // and `e.strikes` (prior balance minus drain, floored at 0, plus
        // `weight`) can therefore never be exactly 0. Enforced rather than
        // just asserted in prose: if a future change makes the early return
        // above stop covering `weight == 0`, this fires instead of quietly
        // reviving the dead `e.strikes == 0` branch this used to carry.
        std.debug.assert(e.strikes != 0);
        // Advance by what actually drained, not to `now`: discarding the
        // remainder would mean a client striking just inside the interval
        // never drains at all. When nothing is left to drain there is no
        // remainder worth keeping, and letting the mark lag would build up a
        // huge drain for the next strike.
        e.strikes_updated_ns = if (g.options.strike_decay_ms == 0)
            now_ns
        else
            e.strikes_updated_ns +| (drained *| (g.options.strike_decay_ms *| std.time.ns_per_ms));
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
        const e = g.getOrCreate(g.keyOf(ip), now_ns) orelse return;
        e.banned = true;
    }

    /// Full forgiveness: clears the ban, the greylist, all strikes and the
    /// offense history. Live-connection counts are untouched. Thread-safe.
    pub fn unban(g: *Guard, ip: netaddr.Ip) void {
        lockSpin(&g.lock);
        defer g.lock.unlock();
        const e = g.map.get(g.keyOf(ip)) orelse return;
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
        const e = g.getOrCreate(g.keyOf(ip), now_ns) orelse return;
        e.greylisted_until_ns = now_ns +| ((ttl_ms orelse g.options.greylist_ttl_ms) *| std.time.ns_per_ms);
    }

    /// Whether `ip` is currently banned: its key's ban or a `banPrefix`
    /// range. Reports the stored state -- an allowlisted address can read
    /// true here and still be admitted. Thread-safe.
    pub fn isBanned(g: *Guard, ip: netaddr.Ip) bool {
        lockSpin(&g.lock);
        defer g.lock.unlock();
        if (g.inPrefixBan(ip)) return true;
        const e = g.map.get(g.keyOf(ip)) orelse return false;
        return e.banned;
    }

    /// Whether `ip` is currently greylisted (TTL not yet expired). Thread-safe.
    pub fn isGreylisted(g: *Guard, ip: netaddr.Ip) bool {
        const now_ns = g.options.clock.now();
        lockSpin(&g.lock);
        defer g.lock.unlock();
        const e = g.map.get(g.keyOf(ip)) orelse return false;
        return now_ns < e.greylisted_until_ns;
    }

    // ── range bans, persistence ─────────────────────────────────────────

    /// Ban every address in `p` (permanent until `unbanPrefix`; new
    /// admissions only). Stored canonical and unmapped (`p.masked()`, a
    /// v4-mapped v6 prefix of /96 or longer becomes the v4 prefix); an equal
    /// prefix already banned is a no-op. Independent of the key width: a
    /// /48 ban covers every /64 inside it. `TooManyPrefixBans` at
    /// `Options.max_prefix_bans`. Thread-safe.
    pub fn banPrefix(g: *Guard, p: netaddr.Prefix) error{ OutOfMemory, TooManyPrefixBans }!void {
        lockSpin(&g.lock);
        defer g.lock.unlock();
        return g.banPrefixLocked(canonicalPrefix(p));
    }

    fn banPrefixLocked(g: *Guard, c: netaddr.Prefix) error{ OutOfMemory, TooManyPrefixBans }!void {
        for (g.prefix_bans.items) |q| if (q.eql(c)) return;
        if (g.prefix_bans.items.len >= g.options.max_prefix_bans) return error.TooManyPrefixBans;
        try g.prefix_bans.append(g.gpa, c);
    }

    /// Lift a `banPrefix` ban of exactly `p` (after the same canonicalising).
    /// True when one was removed. Does not touch per-key bans. Thread-safe.
    pub fn unbanPrefix(g: *Guard, p: netaddr.Prefix) bool {
        const c = canonicalPrefix(p);
        lockSpin(&g.lock);
        defer g.lock.unlock();
        for (g.prefix_bans.items, 0..) |q, i| {
            if (q.eql(c)) {
                _ = g.prefix_bans.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    /// The reputation worth keeping across a restart (fail2ban's ban DB):
    /// every banned key (as a prefix of the key width), every `banPrefix`
    /// range (marked `.range`, so it comes back as a range even when it is
    /// exactly key width), every live greylist with its remaining time rounded UP (a
    /// restored greylist is never shorter). Strikes and offense counts are
    /// NOT included. Caller owns the slice (`gpa.free`); feed it to
    /// `writeSnapshot` / `restore`. Thread-safe.
    pub fn snapshot(g: *Guard, gpa: Allocator) error{OutOfMemory}![]BanRecord {
        const now_ns = g.options.clock.now();
        lockSpin(&g.lock);
        defer g.lock.unlock();
        var out: std.ArrayList(BanRecord) = .empty;
        errdefer out.deinit(gpa);
        for (g.prefix_bans.items) |p| try out.append(gpa, .{ .prefix = p, .range = true });
        var it = g.lru.first;
        while (it) |n| : (it = n.next) {
            const e: *const Entry = @fieldParentPtr("node", n);
            const prefix = g.prefixOfKey(e.key);
            if (e.banned) try out.append(gpa, .{ .prefix = prefix });
            if (now_ns < e.greylisted_until_ns) {
                const remaining_ns = e.greylisted_until_ns - now_ns;
                const ms = remaining_ns / std.time.ns_per_ms +
                    @intFromBool(remaining_ns % std.time.ns_per_ms != 0);
                try out.append(gpa, .{ .prefix = prefix, .greylist_remaining_ms = ms });
            }
        }
        return out.toOwnedSlice(gpa);
    }

    /// Load records produced by `snapshot` / `parseSnapshotLine` into this
    /// Guard (normally a fresh one):
    ///  - a `.range` record goes to `banPrefix`, whatever its length — an
    ///    operator's range ban stays a range (never evicted, `unbanPrefix`
    ///    finds it);
    ///  - a plain ban of exactly the key width of its family becomes that
    ///    key's ban (evictable as a last resort, like any auto-ban); of any
    ///    other length — e.g. written under another key width — it goes to
    ///    `banPrefix`, which keeps it exact;
    ///  - a greylist (now + remaining) lands on the key that covers its
    ///    prefix when the prefix is at least key width (a /128 greylist
    ///    restored under /64 keys greylists the /64), and is SKIPPED when the
    ///    prefix is wider than a key — a greylist cannot cover a range, and
    ///    it would expire anyway.
    /// `InvalidRecord` only for a malformed record (a prefix longer than its
    /// family, `.range` together with a greylist). All records are validated
    /// before the first is applied; `TooManyPrefixBans` / `StoreFull` /
    /// `OutOfMemory` can still leave a prefix of the list applied, and
    /// restoring more key records than `max_tracked_ips` evicts earlier ones
    /// (the store's ordinary bound). Thread-safe; holds the guard's lock for
    /// the whole list, so admissions wait while it runs.
    pub fn restore(g: *Guard, records: []const BanRecord) error{ OutOfMemory, TooManyPrefixBans, StoreFull, InvalidRecord }!void {
        const now_ns = g.options.clock.now();
        lockSpin(&g.lock);
        defer g.lock.unlock();
        for (records) |r| {
            if (r.prefix.bits > r.prefix.width()) return error.InvalidRecord;
            if (r.range and r.greylist_remaining_ms != null) return error.InvalidRecord;
        }
        for (records) |r| {
            const c = canonicalPrefix(r.prefix);
            const key_bits = g.keyBits(c.addr);
            if (r.greylist_remaining_ms) |ms| {
                if (c.bits < key_bits) continue;
                const e = g.getOrCreate(g.keyOf(c.addr), now_ns) orelse return error.StoreFull;
                const until = now_ns +| (ms *| std.time.ns_per_ms);
                e.greylisted_until_ns = @max(e.greylisted_until_ns, until);
                continue;
            }
            if (r.range or c.bits != key_bits) {
                try g.banPrefixLocked(c);
                continue;
            }
            const e = g.getOrCreate(g.keyOf(c.addr), now_ns) orelse return error.StoreFull;
            e.banned = true;
        }
    }

    // ── diagnostics ─────────────────────────────────────────────────────

    /// Live admitted connections from `ip`. Thread-safe.
    pub fn connCount(g: *Guard, ip: netaddr.Ip) u32 {
        lockSpin(&g.lock);
        defer g.lock.unlock();
        const e = g.map.get(g.keyOf(ip)) orelse return 0;
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

    /// Live connections admitted untracked (`.admitted_untracked`), a
    /// subset of `totalConns`. Non-zero means the store is (or was) full
    /// of live addresses. Thread-safe.
    pub fn untrackedConns(g: *Guard) usize {
        lockSpin(&g.lock);
        defer g.lock.unlock();
        return g.untracked_conns;
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

    /// Key width in bits for the family of `ip` (after unmapping).
    fn keyBits(g: *const Guard, ip: netaddr.Ip) u8 {
        return switch (ip.unmap()) {
            .v4 => g.options.ipv4_key_bits,
            .v6 => g.options.ipv6_key_bits,
        };
    }

    /// The store key of `ip`: unmapped, masked to the key width, 16 bytes.
    fn keyOf(g: *const Guard, ip: netaddr.Ip) Key {
        const u = ip.unmap();
        return (netaddr.Prefix{ .addr = u, .bits = g.keyBits(u) }).masked().addr.as16();
    }

    /// Inverse of `keyOf`: the prefix a key stands for. A key in the
    /// v4-mapped range can only come from an IPv4 address (a native v6
    /// address in that range is unmapped before masking).
    fn prefixOfKey(g: *const Guard, key: Key) netaddr.Prefix {
        const v6: netaddr.Ip = .{ .v6 = key };
        if (v6.isIpv4Mapped()) return .{ .addr = v6.unmap(), .bits = g.options.ipv4_key_bits };
        return .{ .addr = v6, .bits = g.options.ipv6_key_bits };
    }

    fn isAllowed(g: *const Guard, ip: netaddr.Ip) bool {
        const u = ip.unmap();
        // Canonical like a ban prefix, so `::ffff:192.0.2.0/120` covers the
        // v4 peers it names (a raw v4-mapped prefix never matches an
        // unmapped peer).
        for (g.options.allow) |p| if (canonicalPrefix(p).contains(u)) return true;
        return false;
    }

    fn inPrefixBan(g: *const Guard, ip: netaddr.Ip) bool {
        const u = ip.unmap();
        for (g.prefix_bans.items) |p| if (p.contains(u)) return true;
        return false;
    }

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
    ///
    /// Whole strikes, not a fraction of one. `strike_decay_ms` is documented
    /// as "one strike drains per this interval", and draining continuously
    /// meant something else: three unit strikes arriving together summed to
    /// 2.99997, so `ban_threshold = 3` needed a fourth strike. That held for
    /// **any** non-zero decay, so the default configuration could never reach
    /// its own threshold in the number of strikes it names — and every
    /// threshold test in this file set `strike_decay_ms = 0` "to keep the
    /// arithmetic exact", which is precisely the region where it was wrong.
    fn decayedStrikes(g: *const Guard, e: *const Entry, now_ns: u64) f64 {
        if (g.options.strike_decay_ms == 0) return e.strikes;
        return @max(0, e.strikes - @as(f64, @floatFromInt(g.drainedSince(e, now_ns))));
    }

    /// Whole strikes that have drained since this entry's strikes were last
    /// accounted for.
    fn drainedSince(g: *const Guard, e: *const Entry, now_ns: u64) u64 {
        if (g.options.strike_decay_ms == 0) return 0;
        const decay_ns = g.options.strike_decay_ms *| std.time.ns_per_ms;
        return (now_ns -| e.strikes_updated_ns) / decay_ns;
    }

    fn removeEntry(g: *Guard, e: *Entry) void {
        const removed = g.map.remove(e.key);
        std.debug.assert(removed);
        g.lru.remove(&e.node);
        g.gpa.destroy(e);
    }
};

/// Canonical form of a ban prefix: host bits zeroed, and a v4-mapped v6
/// prefix of /96 or longer rewritten as the v4 prefix it denotes (the same
/// unification the store applies to peers).
fn canonicalPrefix(p: netaddr.Prefix) netaddr.Prefix {
    const m = p.masked();
    if (m.addr == .v6 and m.addr.isIpv4Mapped() and m.bits >= 96)
        return .{ .addr = m.addr.unmap(), .bits = m.bits - 96 };
    return m;
}

// ── persistence records ─────────────────────────────────────────────────────

/// One persisted piece of reputation (`Guard.snapshot` / `Guard.restore`).
pub const BanRecord = struct {
    prefix: netaddr.Prefix,
    /// null = a permanent ban; otherwise a greylist with this many
    /// milliseconds left.
    greylist_remaining_ms: ?u64 = null,
    /// A `banPrefix` range (not a key's own ban): `restore` puts it back
    /// as a range whatever its length. Never set together with a greylist.
    range: bool = false,
};

/// Write `records` as text, one line each: `ban <prefix>`, `range <prefix>`
/// or `greylist <prefix> <remaining_ms>`. Read back with `parseSnapshotLine`.
pub fn writeSnapshot(records: []const BanRecord, w: *std.Io.Writer) std.Io.Writer.Error!void {
    var buf: [netaddr.max_prefix_text_len]u8 = undefined;
    for (records) |r| {
        const text = netaddr.formatPrefix(r.prefix, &buf);
        if (r.greylist_remaining_ms) |ms| {
            try w.print("greylist {s} {d}\n", .{ text, ms });
        } else if (r.range) {
            try w.print("range {s}\n", .{text});
        } else {
            try w.print("ban {s}\n", .{text});
        }
    }
}

/// Parse one line of `writeSnapshot` output (without its newline). Null for
/// a blank line or a `#` comment; strict otherwise: an unknown keyword, a
/// malformed prefix, a missing or non-decimal or overflowing millisecond
/// count, or any trailing token is `InvalidRecord`.
pub fn parseSnapshotLine(line: []const u8) error{InvalidRecord}!?BanRecord {
    const t = std.mem.trim(u8, line, " \t\r");
    if (t.len == 0 or t[0] == '#') return null;
    var it = std.mem.splitScalar(u8, t, ' ');
    const word = it.next().?;
    const prefix = netaddr.parsePrefix(it.next() orelse return error.InvalidRecord) orelse
        return error.InvalidRecord;
    if (std.mem.eql(u8, word, "ban") or std.mem.eql(u8, word, "range")) {
        if (it.next() != null) return error.InvalidRecord;
        return .{ .prefix = prefix, .range = word[0] == 'r' };
    }
    if (!std.mem.eql(u8, word, "greylist")) return error.InvalidRecord;
    const ms_text = it.next() orelse return error.InvalidRecord;
    if (it.next() != null or ms_text.len == 0) return error.InvalidRecord;
    for (ms_text) |c| if (c < '0' or c > '9') return error.InvalidRecord;
    const ms = std.fmt.parseInt(u64, ms_text, 10) catch return error.InvalidRecord;
    return .{ .prefix = prefix, .greylist_remaining_ms = ms };
}

fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

// ── the server hooks ────────────────────────────────────────────────────────

fn onConnectHook(ctx: ?*anyopaque, peer: net.IpAddress) http.Server.ConnDecision {
    const g: *Guard = @ptrCast(@alignCast(ctx.?));
    return switch (g.admit(ipOf(peer))) {
        .admitted, .admitted_untracked => .accept,
        .banned, .greylisted, .per_ip_cap, .total_cap, .store_full => .reject,
    };
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

test "record: ban_threshold means that many strikes, decay on or off" {
    // The bug this pins: with a continuous drain, three unit strikes arriving
    // in the same microsecond summed to 2.99997, so a `ban_threshold` of 3
    // was not reached until the fourth. It held for any non-zero decay, which
    // is every default configuration -- and no test saw it, because every
    // other threshold test in this file disables decay "to keep the
    // arithmetic exact".
    //
    // Deliberately uses the *real* clock rather than the fake one. The fake
    // clock only moves when a test moves it, in whole milliseconds, so it
    // cannot produce the sub-interval elapsed time that caused this. A test
    // that cannot reach the state under test is not a test.
    for ([_]u64{ 0, 1000, 2 * std.time.ms_per_min }) |decay_ms| {
        var g = Guard.init(testing.allocator, .{
            .ban_threshold = 3,
            .ban_after_offenses = 0,
            .strike_decay_ms = decay_ms,
        });
        defer g.deinit();
        const ip = mkIp("192.0.2.77");

        g.record(ip, 1);
        g.record(ip, 1);
        try testing.expect(!g.isGreylisted(ip));
        g.record(ip, 1);
        try testing.expect(g.isGreylisted(ip));
    }
}

test "record: a drip just inside the decay interval still drains" {
    // The other half of the same change. Advancing the drain mark to `now`
    // rather than by what actually drained would discard the remainder, and a
    // client striking every `decay_ms - 1` would then never drain a thing.
    // Here it does: 5 strikes at 900ms apart against a 1000ms drain leave a
    // balance below the threshold rather than five.
    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{
        .ban_threshold = 5,
        .ban_after_offenses = 0,
        .strike_decay_ms = 1000,
        .clock = tc.clock(),
    });
    defer g.deinit();
    const ip = mkIp("192.0.2.78");

    for (0..5) |_| {
        g.record(ip, 1);
        tc.advanceMs(900);
    }
    // 5 strikes, 4 whole seconds of elapsed time between the first and last:
    // four of them drained, so the balance never reached 5.
    try testing.expect(!g.isGreylisted(ip));
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

test "hooks: an untracked admission is accepted at the hook, and .closed releases it" {
    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{
        .max_tracked_ips = 1,
        .on_store_full = .admit_untracked,
        .clock = tc.clock(),
    });
    defer g.deinit();
    const holder = mkPeer4("203.0.113.20", 1111);
    const late = mkPeer4("203.0.113.21", 1111);
    try testing.expectEqual(http.Server.ConnDecision.accept, hookConnect(&g, holder));
    try testing.expectEqual(http.Server.ConnDecision.accept, hookConnect(&g, late));
    try testing.expectEqual(@as(usize, 1), g.untrackedConns());
    hookState(&g, late, .closed);
    try testing.expectEqual(@as(usize, 0), g.untrackedConns());
    try testing.expectEqual(@as(usize, 1), g.totalConns());
    hookState(&g, holder, .closed);
    try testing.expectEqual(@as(usize, 0), g.totalConns());
}

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

test "reconcile: releases leaked per-IP slots and corrects the global counter" {
    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{ .max_conns_per_ip = 5, .clock = tc.clock() });
    defer g.deinit();
    const ip = mkIp("192.0.2.50");

    // Admit three; imagine two were dropped by the server before `.closed`
    // fired (the documented leak) — only one is really live.
    try testing.expectEqual(AdmitVerdict.admitted, g.admit(ip));
    try testing.expectEqual(AdmitVerdict.admitted, g.admit(ip));
    try testing.expectEqual(AdmitVerdict.admitted, g.admit(ip));
    try testing.expectEqual(@as(u32, 3), g.connCount(ip));
    try testing.expectEqual(@as(usize, 3), g.totalConns());

    // Reconcile down to the true live count: both counters follow.
    g.reconcile(ip, 1);
    try testing.expectEqual(@as(u32, 1), g.connCount(ip));
    try testing.expectEqual(@as(usize, 1), g.totalConns());

    // The one genuinely-live connection still closes cleanly to zero.
    g.connClosed(ip);
    try testing.expectEqual(@as(u32, 0), g.connCount(ip));
    try testing.expectEqual(@as(usize, 0), g.totalConns());

    // Reconciling an untracked IP is a no-op — no negative/overflowed counters.
    g.reconcile(mkIp("192.0.2.51"), 0);
    try testing.expectEqual(@as(usize, 0), g.totalConns());

    // Reconcile also corrects upward (keeps total == Σ active) without underflow.
    try testing.expectEqual(AdmitVerdict.admitted, g.admit(ip));
    g.reconcile(ip, 3);
    try testing.expectEqual(@as(u32, 3), g.connCount(ip));
    try testing.expectEqual(@as(usize, 3), g.totalConns());
    g.reconcile(ip, 0);
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

test "store full, on_store_full = .admit_untracked: admitted with no entry, still under max_conns_total" {
    // The lockout the fail-closed default allows (qap research register H5):
    // every entry holds a live connection, so a new address is untrackable.
    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{
        .max_tracked_ips = 2,
        .max_conns_total = 4,
        .on_store_full = .admit_untracked,
        .clock = tc.clock(),
    });
    defer g.deinit();

    try testing.expectEqual(AdmitVerdict.admitted, g.admit(mkIp("10.9.0.1")));
    try testing.expectEqual(AdmitVerdict.admitted, g.admit(mkIp("10.9.0.2")));
    try testing.expectEqual(AdmitVerdict.admitted_untracked, g.admit(mkIp("10.9.0.3")));
    try testing.expectEqual(AdmitVerdict.admitted_untracked, g.admit(mkIp("10.9.0.4")));
    // No entry was made for either, and both are in the total ...
    try testing.expectEqual(@as(usize, 2), g.trackedCount());
    try testing.expectEqual(@as(usize, 2), g.untrackedConns());
    try testing.expectEqual(@as(usize, 4), g.totalConns());
    // ... so the global cap refuses the next one, untracked or not.
    try testing.expectEqual(AdmitVerdict.total_cap, g.admit(mkIp("10.9.0.5")));

    // Exact release, then the fallback: `connClosed` on an address with no
    // live slot takes an untracked one (what the server hook does).
    g.connClosedUntracked();
    g.connClosed(mkIp("10.9.0.4"));
    try testing.expectEqual(@as(usize, 0), g.untrackedConns());
    try testing.expectEqual(@as(usize, 2), g.totalConns());
    // Nothing left to release: unmatched closes stay no-ops.
    g.connClosedUntracked();
    g.connClosed(mkIp("10.9.0.9"));
    try testing.expectEqual(@as(usize, 2), g.totalConns());

    g.connClosed(mkIp("10.9.0.1"));
    g.connClosed(mkIp("10.9.0.2"));
    try testing.expectEqual(@as(usize, 0), g.totalConns());
}

test "admit_untracked: an untracked address that later gets an entry -- the totals end exact" {
    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{
        .max_tracked_ips = 1,
        .on_store_full = .admit_untracked,
        .clock = tc.clock(),
    });
    defer g.deinit();

    const a = mkIp("10.9.1.1");
    const b = mkIp("10.9.1.2");
    try testing.expectEqual(AdmitVerdict.admitted, g.admit(a));
    try testing.expectEqual(AdmitVerdict.admitted_untracked, g.admit(b));
    g.connClosed(a); // a's entry empties, the next insert reclaims it
    try testing.expectEqual(AdmitVerdict.admitted, g.admit(b)); // b tracked now
    try testing.expectEqual(@as(usize, 2), g.totalConns());

    // The hook closes b's untracked connection first: it takes the tracked
    // slot (the per-IP count runs one low) ...
    g.connClosed(b);
    try testing.expectEqual(@as(u32, 0), g.connCount(b));
    // ... and the tracked close takes the untracked one: back to zero.
    g.connClosed(b);
    try testing.expectEqual(@as(usize, 0), g.untrackedConns());
    try testing.expectEqual(@as(usize, 0), g.totalConns());
}

test "the default stays fail-closed: store_full, nothing counted" {
    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{ .max_tracked_ips = 1, .clock = tc.clock() });
    defer g.deinit();
    try testing.expectEqual(AdmitVerdict.admitted, g.admit(mkIp("10.9.2.1")));
    try testing.expectEqual(AdmitVerdict.store_full, g.admit(mkIp("10.9.2.2")));
    try testing.expectEqual(@as(usize, 1), g.totalConns());
    try testing.expectEqual(@as(usize, 0), g.untrackedConns());
    // The fallback has nothing to take.
    g.connClosed(mkIp("10.9.2.2"));
    try testing.expectEqual(@as(usize, 1), g.totalConns());
    g.connClosed(mkIp("10.9.2.1"));
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
        return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    };
    const thread = try std.Thread.spawn(.{}, serveWrap, .{&server});
    defer thread.join();
    defer server.shutdown();
    const addr = server.boundAddress();

    // Connection 1 — keep-alive, held open for the whole test.
    const c1 = addr.connect(io, .{ .mode = .stream }) catch |err| {
        return testkit.loopbackSkip("loopback connect failed ({t})", .{err});
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
        return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    };
    const thread = try std.Thread.spawn(.{}, serveWrap, .{&server});
    defer thread.join();
    defer server.shutdown();
    const addr = server.boundAddress();

    // Probe reachability once (skip like the sibling tests if loopback is off).
    {
        const probe = addr.connect(io, .{ .mode = .stream }) catch |err| {
            return testkit.loopbackSkip("loopback connect failed ({t})", .{err});
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

// ── tests: allowlist, prefix keying, range bans, persistence ────────────────

fn mkPrefix(text: []const u8) netaddr.Prefix {
    return netaddr.parsePrefix(text).?;
}

test "allowlist: exempt from record/ban/greylist/prefix ban, not from the per-key cap" {
    var tc: TestClock = .{};
    const allow = [_]netaddr.Prefix{mkPrefix("192.0.2.0/24")};
    var g = Guard.init(testing.allocator, .{
        .allow = &allow,
        .max_conns_per_ip = 1,
        .ban_threshold = 1,
        .ban_after_offenses = 1,
        .clock = tc.clock(),
    });
    defer g.deinit();
    const friend = mkIp("192.0.2.77");
    const stranger = mkIp("198.51.100.1");

    g.record(friend, 100); // no-op: no strikes, no entry
    try testing.expectEqual(@as(usize, 0), g.trackedCount());
    try testing.expect(!g.isBanned(friend));
    g.record(stranger, 1);
    try testing.expect(g.isBanned(stranger)); // the same call does bite elsewhere

    // Manual state is stored but ignored while allowlisted.
    g.ban(friend);
    g.greylist(friend, null);
    try testing.expect(g.isBanned(friend));
    try g.banPrefix(mkPrefix("192.0.2.0/25"));
    try testing.expectEqual(AdmitVerdict.admitted, g.admit(friend));
    // ... but the resource cap still applies.
    try testing.expectEqual(AdmitVerdict.per_ip_cap, g.admit(friend));
    g.connClosed(friend);
    try testing.expectEqual(AdmitVerdict.banned, g.admit(stranger));

    // The v4-mapped form of a member is a member.
    try testing.expectEqual(AdmitVerdict.admitted, g.admit(mkIp("::ffff:192.0.2.77")));
    g.connClosed(friend);
}

test "allowlist: the middleware's auto-strike is a no-op for a member" {
    var tc: TestClock = .{};
    const allow = [_]netaddr.Prefix{mkPrefix("203.0.113.0/24")};
    var g = Guard.init(testing.allocator, .{ .allow = &allow, .ban_threshold = 1, .clock = tc.clock() });
    defer g.deinit();
    var r = try guardedRouter(&g);
    defer r.deinit();
    var buf: [1024]u8 = undefined;
    try expectStatus(runWirePeer(&r, wire("/nope", ""), &buf, mkPeer4("203.0.113.9", 1)), "404");
    try testing.expectEqual(@as(usize, 0), g.trackedCount());
    try expectStatus(runWirePeer(&r, wire("/nope", ""), &buf, mkPeer4("198.51.100.9", 1)), "404");
    try testing.expect(g.isGreylisted(mkIp("198.51.100.9")));
}

test "keying: two IPv6 addresses in one /64 share strikes; 128 bits separates them" {
    var tc: TestClock = .{};
    const a = mkIp("2001:db8:1:2::1");
    const b = mkIp("2001:db8:1:2:ffff::9");
    const other = mkIp("2001:db8:1:3::1");
    {
        var g = Guard.init(testing.allocator, .{
            .ban_threshold = 2,
            .ban_after_offenses = 1,
            .strike_decay_ms = 0,
            .clock = tc.clock(),
        });
        defer g.deinit();
        g.record(a, 1);
        g.record(b, 1); // second strike on the same /64 key
        try testing.expect(g.isBanned(a));
        try testing.expect(g.isBanned(b));
        try testing.expect(!g.isBanned(other)); // the next /64 is another client
        try testing.expectEqual(AdmitVerdict.banned, g.admit(b));
        try testing.expectEqual(@as(usize, 1), g.trackedCount());
        g.unban(b); // any member lifts the whole key
        try testing.expect(!g.isBanned(a));
    }
    {
        var g = Guard.init(testing.allocator, .{
            .ban_threshold = 2,
            .ban_after_offenses = 1,
            .strike_decay_ms = 0,
            .ipv6_key_bits = 128,
            .clock = tc.clock(),
        });
        defer g.deinit();
        g.record(a, 1);
        g.record(b, 1);
        try testing.expect(!g.isBanned(a));
        try testing.expect(!g.isBanned(b));
        try testing.expectEqual(@as(usize, 2), g.trackedCount());
    }
}

test "keying: the per-key connection cap is per /64 for IPv6, ipv4_key_bits = 24 groups a /24" {
    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{
        .max_conns_per_ip = 2,
        .ipv4_key_bits = 24,
        .clock = tc.clock(),
    });
    defer g.deinit();
    try testing.expectEqual(AdmitVerdict.admitted, g.admit(mkIp("2001:db8::1")));
    try testing.expectEqual(AdmitVerdict.admitted, g.admit(mkIp("2001:db8::2")));
    try testing.expectEqual(AdmitVerdict.per_ip_cap, g.admit(mkIp("2001:db8::3")));
    try testing.expectEqual(@as(u32, 2), g.connCount(mkIp("2001:db8::ffff")));
    g.reconcile(mkIp("2001:db8::9"), 1);
    try testing.expectEqual(@as(u32, 1), g.connCount(mkIp("2001:db8::1")));
    g.connClosed(mkIp("2001:db8::5"));
    try testing.expectEqual(@as(usize, 0), g.totalConns());

    try testing.expectEqual(AdmitVerdict.admitted, g.admit(mkIp("10.1.2.3")));
    try testing.expectEqual(AdmitVerdict.admitted, g.admit(mkIp("::ffff:10.1.2.200")));
    try testing.expectEqual(AdmitVerdict.per_ip_cap, g.admit(mkIp("10.1.2.99")));
    try testing.expectEqual(AdmitVerdict.admitted, g.admit(mkIp("10.1.3.1"))); // next /24
    try testing.expectEqual(@as(usize, 2), g.trackedCount());
    g.ban(mkIp("10.1.2.1"));
    try testing.expect(g.isBanned(mkIp("10.1.2.250")));
    try testing.expect(!g.isBanned(mkIp("10.1.3.250")));
}

test "banPrefix: rejects members, unbanPrefix re-admits, bound, idempotent" {
    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{ .max_prefix_bans = 2, .clock = tc.clock() });
    defer g.deinit();
    const inside = mkIp("198.51.100.200");
    const outside = mkIp("198.51.101.1");

    try g.banPrefix(mkPrefix("198.51.100.17/24")); // host bits are masked away
    try g.banPrefix(mkPrefix("198.51.100.0/24")); // equal prefix: idempotent
    try testing.expectEqual(@as(usize, 1), g.prefix_bans.items.len);
    try testing.expectEqual(AdmitVerdict.banned, g.admit(inside));
    try testing.expectEqual(AdmitVerdict.banned, g.admit(mkIp("::ffff:198.51.100.5")));
    try testing.expect(g.isBanned(inside));
    try testing.expectEqual(AdmitVerdict.admitted, g.admit(outside));
    g.connClosed(outside);
    try testing.expectEqual(@as(usize, 1), g.trackedCount()); // rejecting inserted nothing

    try g.banPrefix(mkPrefix("2001:db8::/32"));
    try testing.expectError(error.TooManyPrefixBans, g.banPrefix(mkPrefix("10.0.0.0/8")));
    try g.banPrefix(mkPrefix("2001:db8::/32")); // still idempotent at the bound
    try testing.expectEqual(AdmitVerdict.banned, g.admit(mkIp("2001:db8:ffff::1")));
    try testing.expectEqual(AdmitVerdict.admitted, g.admit(mkIp("2001:db9::1")));
    g.connClosed(mkIp("2001:db9::1"));

    try testing.expect(!g.unbanPrefix(mkPrefix("198.51.100.0/25"))); // not an exact match
    try testing.expect(g.unbanPrefix(mkPrefix("198.51.100.0/24")));
    try testing.expect(!g.unbanPrefix(mkPrefix("198.51.100.0/24")));
    try testing.expect(!g.isBanned(inside));
    try testing.expectEqual(AdmitVerdict.admitted, g.admit(inside));
    g.connClosed(inside);
    try g.banPrefix(mkPrefix("10.0.0.0/8")); // room again
}

test "banPrefix: a rejected range member does not slip in as untracked when the store is full" {
    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{
        .max_tracked_ips = 1,
        .max_conns_total = 10,
        .on_store_full = .admit_untracked,
        .clock = tc.clock(),
    });
    defer g.deinit();
    try testing.expectEqual(AdmitVerdict.admitted, g.admit(mkIp("10.0.0.1")));
    try g.banPrefix(mkPrefix("192.0.2.0/24"));
    try testing.expectEqual(AdmitVerdict.banned, g.admit(mkIp("192.0.2.1")));
    try testing.expectEqual(@as(usize, 0), g.untrackedConns());
    g.connClosed(mkIp("10.0.0.1"));
}

test "persist: snapshot -> text -> parse -> restore into a fresh Guard" {
    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{ .clock = tc.clock() });
    defer g.deinit();
    g.ban(mkIp("192.0.2.9"));
    g.ban(mkIp("2001:db8:aa:bb::1"));
    try g.banPrefix(mkPrefix("203.0.113.0/24"));
    try g.banPrefix(mkPrefix("2001:db8:ffff::/48"));
    g.greylist(mkIp("198.51.100.4"), 90_000);
    g.greylist(mkIp("198.51.100.5"), 0); // already expired: not a record
    tc.advanceMs(1500);
    tc.ns.store(tc.ns.load(.monotonic) + 300_000, .monotonic); // +0.3 ms: remaining 88 499.7 ms rounds up
    g.record(mkIp("198.51.100.6"), 1); // strikes are not persisted

    const recs = try g.snapshot(testing.allocator);
    defer testing.allocator.free(recs);
    try testing.expectEqual(@as(usize, 5), recs.len);

    var aw: Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try writeSnapshot(recs, &aw.writer);
    try testing.expect(std.mem.indexOf(u8, aw.written(), "greylist 198.51.100.4/32 88500\n") != null);
    try testing.expect(std.mem.indexOf(u8, aw.written(), "ban 192.0.2.9/32\n") != null);

    var parsed: std.ArrayList(BanRecord) = .empty;
    defer parsed.deinit(testing.allocator);
    var lines = std.mem.splitScalar(u8, aw.written(), '\n');
    while (lines.next()) |line| {
        if (try parseSnapshotLine(line)) |r| try parsed.append(testing.allocator, r);
    }
    try testing.expectEqual(recs.len, parsed.items.len);

    // The new process: a fresh Guard whose clock starts elsewhere.
    var tc2: TestClock = .{ .ns = .init(7_000_000_000) };
    var g2 = Guard.init(testing.allocator, .{ .clock = tc2.clock() });
    defer g2.deinit();
    try g2.restore(parsed.items);
    try testing.expectEqual(AdmitVerdict.banned, g2.admit(mkIp("192.0.2.9")));
    try testing.expectEqual(AdmitVerdict.banned, g2.admit(mkIp("2001:db8:aa:bb::77"))); // same /64
    try testing.expectEqual(AdmitVerdict.banned, g2.admit(mkIp("203.0.113.200")));
    try testing.expectEqual(AdmitVerdict.banned, g2.admit(mkIp("2001:db8:ffff:1::1")));
    try testing.expectEqual(AdmitVerdict.admitted, g2.admit(mkIp("198.51.100.5")));
    g2.connClosed(mkIp("198.51.100.5"));
    try testing.expectEqual(AdmitVerdict.admitted, g2.admit(mkIp("198.51.100.6")));
    g2.connClosed(mkIp("198.51.100.6"));

    // Greylist: 88 500 ms left (rounded up) -- held right up to the instant.
    const grey = mkIp("198.51.100.4");
    tc2.advanceMs(88_498);
    try testing.expectEqual(AdmitVerdict.greylisted, g2.admit(grey));
    tc2.advanceMs(1);
    try testing.expectEqual(AdmitVerdict.greylisted, g2.admit(grey)); // 1 ms left
    tc2.advanceMs(1);
    try testing.expectEqual(AdmitVerdict.admitted, g2.admit(grey));
    g2.connClosed(grey);
}

test "persist: restore across a key-width change -- greylists land on the covering key or are skipped, bans stay exact (review A2)" {
    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{ .clock = tc.clock() });
    defer g.deinit();
    // Malformed: `.range` together with a greylist. Validation precedes
    // application: the good record before it is not applied.
    try testing.expectError(error.InvalidRecord, g.restore(&.{
        .{ .prefix = mkPrefix("10.0.0.1/32") },
        .{ .prefix = mkPrefix("10.9.0.0/16"), .range = true, .greylist_remaining_ms = 5 },
    }));
    try testing.expect(!g.isBanned(mkIp("10.0.0.1")));
    try testing.expectEqual(@as(usize, 0), g.trackedCount());

    // A file written under /128 v6 keys and /24 v4 keys, restored under the
    // defaults (/64, /32). Before the fix any one of these greylists made the
    // whole restore fail with InvalidRecord -- every ban in the file lost.
    try g.restore(&.{
        .{ .prefix = mkPrefix("2001:db8:0:5::7/128"), .greylist_remaining_ms = 1000 }, // narrower: covering /64
        .{ .prefix = mkPrefix("2001:db8::/56"), .greylist_remaining_ms = 1000 }, // wider than a key: skipped
        .{ .prefix = mkPrefix("10.0.0.0/24"), .greylist_remaining_ms = 1000 }, // wider than a key: skipped
        .{ .prefix = mkPrefix("2001:db8::/56") }, // ban, other width: an exact range
        .{ .prefix = mkPrefix("::ffff:10.2.0.0/120") }, // mapped form of 10.2.0.0/24
        .{ .prefix = mkPrefix("10.3.0.4/32") }, // key width: a key ban
    });
    try testing.expect(g.isGreylisted(mkIp("2001:db8:0:5::1"))); // same /64 as ::7
    try testing.expect(!g.isGreylisted(mkIp("10.0.0.1")));
    try testing.expectEqual(@as(usize, 2), g.prefix_bans.items.len);
    try testing.expect(g.isBanned(mkIp("2001:db8:0:ff::1")));
    try testing.expect(!g.isBanned(mkIp("2001:db8:0:100::1")));
    try testing.expect(g.isBanned(mkIp("10.2.0.77")));
    try testing.expect(g.isBanned(mkIp("10.3.0.4")));
    try testing.expectEqual(@as(usize, 2), g.trackedCount()); // the /64 greylist + 10.3.0.4
}

test "persist: an operator range ban of exactly key width comes back as a range, not an evictable key ban (review A1)" {
    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{ .clock = tc.clock() });
    defer g.deinit();
    try g.banPrefix(mkPrefix("203.0.113.9/32")); // key width for v4
    const recs = try g.snapshot(testing.allocator);
    defer testing.allocator.free(recs);
    try testing.expectEqual(@as(usize, 1), recs.len);
    try testing.expect(recs[0].range);

    var buf: [128]u8 = undefined;
    var w: Writer = .fixed(&buf);
    try writeSnapshot(recs, &w);
    try testing.expectEqualStrings("range 203.0.113.9/32\n", w.buffered());
    const back = (try parseSnapshotLine(std.mem.trimEnd(u8, w.buffered(), "\n"))).?;
    try testing.expect(back.range);

    var g2 = Guard.init(testing.allocator, .{ .max_tracked_ips = 1, .clock = tc.clock() });
    defer g2.deinit();
    try g2.restore(&.{back});
    try testing.expectEqual(@as(usize, 0), g2.trackedCount()); // not an entry...
    // ...so a flood of new addresses cannot evict it,
    try testing.expectEqual(AdmitVerdict.admitted, g2.admit(mkIp("198.51.100.1")));
    g2.connClosed(mkIp("198.51.100.1"));
    try testing.expectEqual(AdmitVerdict.admitted, g2.admit(mkIp("198.51.100.2")));
    g2.connClosed(mkIp("198.51.100.2"));
    try testing.expectEqual(AdmitVerdict.banned, g2.admit(mkIp("203.0.113.9")));
    // ...and `unbanPrefix` finds it.
    try testing.expect(g2.unbanPrefix(mkPrefix("203.0.113.9/32")));
    try testing.expectEqual(AdmitVerdict.admitted, g2.admit(mkIp("203.0.113.9")));
    g2.connClosed(mkIp("203.0.113.9"));
}

test "allowlist: a v4-mapped allow prefix covers the v4 peers it names (review A3)" {
    var tc: TestClock = .{};
    const allow = [_]netaddr.Prefix{mkPrefix("::ffff:192.0.2.0/120")};
    var g = Guard.init(testing.allocator, .{ .allow = &allow, .clock = tc.clock() });
    defer g.deinit();
    g.ban(mkIp("192.0.2.7"));
    try testing.expectEqual(AdmitVerdict.admitted, g.admit(mkIp("192.0.2.7")));
    g.connClosed(mkIp("192.0.2.7"));
    g.ban(mkIp("192.0.3.7"));
    try testing.expectEqual(AdmitVerdict.banned, g.admit(mkIp("192.0.3.7")));
}

test "persist: restore bounds -- store_full and prefix-ban limit" {
    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{ .max_tracked_ips = 1, .max_prefix_bans = 1, .clock = tc.clock() });
    defer g.deinit();
    try testing.expectEqual(AdmitVerdict.admitted, g.admit(mkIp("10.0.0.1"))); // pins the only slot
    try testing.expectError(error.StoreFull, g.restore(&.{.{ .prefix = mkPrefix("10.0.0.2/32") }}));
    try testing.expectError(error.TooManyPrefixBans, g.restore(&.{
        .{ .prefix = mkPrefix("10.1.0.0/16") },
        .{ .prefix = mkPrefix("10.2.0.0/16") },
    }));
    g.connClosed(mkIp("10.0.0.1"));
}

test "persist: parseSnapshotLine accepts blanks and comments, rejects every malformed form" {
    try testing.expectEqual(@as(?BanRecord, null), try parseSnapshotLine(""));
    try testing.expectEqual(@as(?BanRecord, null), try parseSnapshotLine("   \r"));
    try testing.expectEqual(@as(?BanRecord, null), try parseSnapshotLine("# saved 2026-10-04"));

    const ban = (try parseSnapshotLine("ban 192.0.2.0/24")).?;
    try testing.expect(ban.prefix.eql(mkPrefix("192.0.2.0/24")));
    try testing.expectEqual(@as(?u64, null), ban.greylist_remaining_ms);
    try testing.expect(!ban.range);
    const range = (try parseSnapshotLine("range 192.0.2.0/24")).?;
    try testing.expect(range.range and range.greylist_remaining_ms == null);
    const grey = (try parseSnapshotLine("greylist 2001:db8::/64 18446744073709551615")).?;
    try testing.expectEqual(@as(?u64, std.math.maxInt(u64)), grey.greylist_remaining_ms);

    const bad = [_][]const u8{
        "ban", // missing prefix
        "ban 192.0.2.0", // not a prefix
        "ban 192.0.2.0/33", // bad width
        "ban 192.0.2.0/24 extra", // trailing junk
        "ban 192.0.2.0/24 5", // ms on a ban
        "range 192.0.2.0/24 5", // ms on a range
        "range", // missing prefix
        "greylist 192.0.2.1/32", // missing ms
        "greylist 192.0.2.1/32 ", // empty ms
        "greylist 192.0.2.1/32 -5",
        "greylist 192.0.2.1/32 5x",
        "greylist 192.0.2.1/32 18446744073709551616", // overflow
        "greylist 192.0.2.1/32 5 6",
        "unban 192.0.2.1/32",
        "BAN 192.0.2.1/32",
        "192.0.2.1/32",
    };
    for (bad) |line| try testing.expectError(error.InvalidRecord, parseSnapshotLine(line));
}

test "init asserts are reachable only by misuse; documented defaults hold" {
    const o: Options = .{};
    try testing.expectEqual(@as(u8, 64), o.ipv6_key_bits);
    try testing.expectEqual(@as(u8, 32), o.ipv4_key_bits);
    try testing.expectEqual(@as(usize, 256), o.max_prefix_bans);
    try testing.expectEqual(@as(usize, 0), o.allow.len);
}

// ── mutation-audit additions (2026-10-04) ───────────────────────────────────

test "persist: snapshot prefixes carry the configured key widths; a greylist ending this instant is not recorded" {
    // Kills: prefixOfKey using the other family's width (v4 <- ipv6_key_bits,
    // v6 <- ipv4_key_bits) and the snapshot `now < until` boundary (<=).
    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{ .ipv4_key_bits = 24, .ipv6_key_bits = 48, .clock = tc.clock() });
    defer g.deinit();
    g.ban(mkIp("10.1.2.3"));
    g.ban(mkIp("2001:db8:1:2::1"));
    g.greylist(mkIp("198.51.100.4"), 5);
    tc.advanceMs(5); // now == greylisted_until: expired, remaining would be 0 ms

    const recs = try g.snapshot(testing.allocator);
    defer testing.allocator.free(recs);
    try testing.expectEqual(@as(usize, 2), recs.len);
    var seen4 = false;
    var seen6 = false;
    for (recs) |r| {
        try testing.expectEqual(@as(?u64, null), r.greylist_remaining_ms);
        if (r.prefix.eql(mkPrefix("10.1.2.0/24"))) seen4 = true;
        if (r.prefix.eql(mkPrefix("2001:db8:1::/48"))) seen6 = true;
    }
    try testing.expect(seen4 and seen6);
}

test "persist: restore -- a ban longer than the key width is a range, a later shorter greylist never shortens" {
    // Kills: `c.bits != keyBits` weakened to `<` (a /128 ban would widen to the
    // whole /64 key) and `@max(old, until)` replaced by `until`.
    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{ .clock = tc.clock() });
    defer g.deinit();
    try g.restore(&.{
        .{ .prefix = mkPrefix("2001:db8::1/128") },
        .{ .prefix = mkPrefix("10.0.0.1/32"), .greylist_remaining_ms = 9000 },
        .{ .prefix = mkPrefix("10.0.0.1/32"), .greylist_remaining_ms = 1000 },
    });
    try testing.expectEqual(@as(usize, 1), g.prefix_bans.items.len);
    try testing.expect(g.isBanned(mkIp("2001:db8::1")));
    try testing.expect(!g.isBanned(mkIp("2001:db8::2"))); // not widened to the /64
    tc.advanceMs(5000);
    try testing.expect(g.isGreylisted(mkIp("10.0.0.1"))); // the 9000 ms won
}

test "banPrefix: ::ffff:0:0/96 is all of IPv4; unbanPrefix canonicalises like banPrefix" {
    // Kills: canonicalPrefix `bits >= 96` weakened to `> 96`, and unbanPrefix
    // comparing the raw (host bits set / mapped) prefix.
    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{ .clock = tc.clock() });
    defer g.deinit();
    try g.banPrefix(mkPrefix("::ffff:0:0/96"));
    try testing.expectEqual(AdmitVerdict.banned, g.admit(mkIp("203.0.113.1")));
    try testing.expect(g.unbanPrefix(mkPrefix("0.0.0.7/0")));
    try testing.expectEqual(@as(usize, 0), g.prefix_bans.items.len);

    try g.banPrefix(mkPrefix("198.51.100.0/24"));
    try testing.expect(g.unbanPrefix(mkPrefix("198.51.100.17/24"))); // host bits set
    try g.banPrefix(mkPrefix("198.51.100.0/24"));
    try testing.expect(g.unbanPrefix(mkPrefix("::ffff:198.51.100.0/120"))); // mapped form
    try testing.expectEqual(@as(usize, 0), g.prefix_bans.items.len);
}

test "persist: parseSnapshotLine rejects a sign, an unknown keyword with a valid tail" {
    // Kills: the decimal-digit loop dropped (parseInt takes "+5") and the
    // `greylist` keyword check dropped (any word with a ms count parsed).
    try testing.expectError(error.InvalidRecord, parseSnapshotLine("greylist 192.0.2.1/32 +5"));
    try testing.expectError(error.InvalidRecord, parseSnapshotLine("foo 192.0.2.1/32 5"));
}

test "init asserts: the smallest key widths (1 bit) are accepted and key one half of the space" {
    // Kills: the lower-bound asserts on ipv4_key_bits / ipv6_key_bits shifted
    // from `>= 1` to `>= 2`.
    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{ .ipv4_key_bits = 1, .ipv6_key_bits = 1, .clock = tc.clock() });
    defer g.deinit();
    g.ban(mkIp("10.0.0.1"));
    try testing.expect(g.isBanned(mkIp("100.0.0.1"))); // same 0.0.0.0/1 half
    try testing.expect(!g.isBanned(mkIp("200.0.0.1")));
    g.ban(mkIp("2001:db8::1"));
    try testing.expect(g.isBanned(mkIp("3fff::1"))); // same 0::/1 half
    try testing.expect(!g.isBanned(mkIp("fe80::1")));
}

test "record: the offense that bans also clears the greylist the first offense set" {
    // Kills: the ban branch no longer zeroing greylisted_until_ns (a banned
    // key would stay "greylisted" and be snapshotted twice).
    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{ .ban_threshold = 1, .ban_after_offenses = 2, .clock = tc.clock() });
    defer g.deinit();
    const ip = mkIp("203.0.113.50");
    g.record(ip, 1);
    try testing.expect(g.isGreylisted(ip));
    g.record(ip, 1);
    try testing.expect(g.isBanned(ip));
    try testing.expect(!g.isGreylisted(ip));
    const recs = try g.snapshot(testing.allocator);
    defer testing.allocator.free(recs);
    try testing.expectEqual(@as(usize, 1), recs.len);
}

test "record: an idle key with an offense history is not swept as empty" {
    // Kills: entryIsEmpty ignoring `offenses` (the history would vanish as
    // soon as the greylist lapsed and any new key was created).
    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{
        .ban_threshold = 1,
        .ban_after_offenses = 2,
        .greylist_ttl_ms = 1000,
        .strike_decay_ms = 0,
        .clock = tc.clock(),
    });
    defer g.deinit();
    const a = mkIp("203.0.113.60");
    g.record(a, 1); // first offense -> greylist
    tc.advanceMs(2000); // greylist over, strikes 0, no connections
    try testing.expectEqual(AdmitVerdict.admitted, g.admit(mkIp("203.0.113.61")));
    try testing.expectEqual(@as(usize, 2), g.trackedCount()); // `a` survived the tail sweep
    g.connClosed(mkIp("203.0.113.61"));
    g.record(a, 1); // second offense -> ban
    try testing.expect(g.isBanned(a));
}

fn hServerErrStatus(ctx: *router.Ctx) anyerror!void {
    ctx.res.setStatus(500);
    try ctx.res.writeAll("boom");
}

test "middleware: a 500 response is the server's fault and never strikes" {
    // Kills: the 4xx range upper bound `< 500` widened to `<= 500`.
    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{ .ban_threshold = 1, .strike_decay_ms = 0, .clock = tc.clock() });
    defer g.deinit();
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(g.middleware());
    try r.get("/boom", hServerErrStatus);
    var buf: [1024]u8 = undefined;
    try expectStatus(runWirePeer(&r, wire("/boom", ""), &buf, mkPeer4("203.0.113.70", 1)), "500");
    try testing.expectEqual(@as(usize, 0), g.trackedCount());
}
