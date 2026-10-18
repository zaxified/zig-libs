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
    /// Growth of the auto-greylist per repeat offense (fail2ban
    /// `bantime.increment` with `bantime.factor`): the n-th offense
    /// greylists for `greylist_ttl_ms * greylist_ttl_growth^(n-1)`, capped
    /// at `greylist_ttl_max_ms`. 1 = every offense greylists for
    /// `greylist_ttl_ms` (the default). With `ban_after_offenses = 0` this
    /// is fail2ban's "ever longer, never permanent" policy. Manual
    /// `greylist` calls do not grow. Must be ≥ 1.
    greylist_ttl_growth: u32 = 1,
    /// Ceiling of a grown auto-greylist (fail2ban `bantime.maxtime`); null =
    /// none (the product saturates at u64). Must be ≥ `greylist_ttl_ms`
    /// when set.
    greylist_ttl_max_ms: ?u64 = null,
    /// Dry run (nginx `limit_conn_dry_run`): every verdict and every
    /// strike is accounted as usual, but `admit` answers `.admitted` (or
    /// `.admitted_untracked` when it could not track the peer) instead of
    /// rejecting, and reports the rejection it would have made as a
    /// `.dry_run_reject` event. For rolling out caps and thresholds on live
    /// traffic before enforcing them.
    dry_run: bool = false,
    /// Called on every reputation change, after the guard's lock is
    /// released (fail2ban `actionban` / `actionunban`: push a ban into an
    /// nftables set, alert, log). See `Event`. Runs on the thread that
    /// caused the change — the accept loop for `.dry_run_reject` — so keep
    /// it short; it may call back into the Guard.
    on_event: ?EventHook = null,
};

/// `Options.on_store_full`.
pub const StoreFull = enum { reject, admit_untracked };

/// A reputation change, delivered to `Options.on_event`.
///
/// No event is sent for a greylist that simply runs out (it carries its
/// TTL, so a firewall set with element timeouts expires it on its own), for
/// `restore` (the caller holds the records it restored), or for a manual
/// `ban` / `greylist` of an `Options.allow` member (stored, never enforced).
pub const Event = struct {
    kind: Kind,
    /// The key the change applies to (`Options.ipv6_key_bits` /
    /// `ipv4_key_bits` wide), or the range for `.prefix_banned` /
    /// `.prefix_unbanned`. `::/0` for `.all_cleared`.
    prefix: netaddr.Prefix,
    /// `.greylisted`: how long the greylist lasts.
    ttl_ms: ?u64 = null,
    /// `.greylisted` / `.banned` from `record`: the key's offense count
    /// (1 = first offense); 0 for a manual call.
    offense: u32 = 0,
    /// `.dry_run_reject`: what `admit` would have answered.
    verdict: ?AdmitVerdict = null,

    pub const Kind = enum {
        /// Permanent ban of a key (offense escalation or `ban`); only on
        /// the change, not when the key was already banned.
        banned,
        /// Greylist of a key for `ttl_ms` (offense or `greylist`).
        greylisted,
        /// `unban` lifted a ban or a live greylist of the key.
        unbanned,
        /// The store evicted a banned or greylisted key to make room
        /// (`max_tracked_ips`) — the guard has forgotten it.
        evicted,
        /// `banPrefix` added a range.
        prefix_banned,
        /// `unbanPrefix` removed a range.
        prefix_unbanned,
        /// `unbanAll` cleared every ban, greylist and range.
        all_cleared,
        /// `Options.dry_run`: `admit` let in what it would have refused.
        dry_run_reject,
    };
};

/// `Options.on_event`.
pub const EventHook = struct {
    ctx: ?*anyopaque = null,
    run: *const fn (ctx: ?*anyopaque, event: Event) void,
};

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

    /// Events gathered under the lock and delivered after it is released
    /// (`deliver`), so `Options.on_event` may call back into the Guard. One
    /// operation makes at most two: an eviction plus its own change.
    const Pending = struct {
        buf: [2]Event = undefined,
        len: u8 = 0,

        fn push(p: *Pending, e: Event) void {
            std.debug.assert(p.len < p.buf.len);
            p.buf[p.len] = e;
            p.len += 1;
        }
    };

    fn deliver(g: *const Guard, pending: *const Pending) void {
        const hook = g.options.on_event orelse return;
        for (pending.buf[0..pending.len]) |e| hook.run(hook.ctx, e);
    }

    pub fn init(gpa: Allocator, options: Options) Guard {
        std.debug.assert(options.max_tracked_ips >= 1);
        std.debug.assert(options.ban_threshold >= 1);
        std.debug.assert(options.greylist_ttl_ms >= 1);
        if (options.max_conns_per_ip) |m| std.debug.assert(m >= 1);
        if (options.max_conns_total) |m| std.debug.assert(m >= 1);
        std.debug.assert(options.ipv6_key_bits >= 1 and options.ipv6_key_bits <= 128);
        std.debug.assert(options.ipv4_key_bits >= 1 and options.ipv4_key_bits <= 32);
        std.debug.assert(options.greylist_ttl_growth >= 1);
        if (options.greylist_ttl_max_ms) |m| std.debug.assert(m >= options.greylist_ttl_ms);
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
        var pending: Pending = .{};
        const verdict = verdict: {
            lockSpin(&g.lock);
            defer g.lock.unlock();
            break :verdict g.admitLocked(ip, now_ns, &pending);
        };
        g.deliver(&pending);
        return verdict;
    }

    fn admitLocked(g: *Guard, ip: netaddr.Ip, now_ns: u64, pending: *Pending) AdmitVerdict {
        const dry = g.options.dry_run;
        // The rejection `admit` would answer; in a dry run it is reported
        // and the connection admitted (and counted) anyway.
        var deny: ?AdmitVerdict = null;
        // Global cap first: cheapest, and shedding must not insert entries.
        if (g.options.max_conns_total) |max| {
            if (g.total_conns >= max) deny = .total_cap;
        }
        const allowed = g.isAllowed(ip);
        // A banned range is refused before any entry is looked up or made, so
        // a rejected peer neither churns the LRU nor, when the store is full,
        // slips in through `.admit_untracked`.
        if (deny == null and !allowed and g.inPrefixBan(ip)) deny = .banned;
        if (deny) |d| if (!dry) return d;
        const e = g.getOrCreate(g.keyOf(ip), now_ns, pending) orelse {
            if (deny == null and g.options.on_store_full == .reject) {
                if (!dry) return .store_full;
                deny = .store_full;
            }
            if (deny) |d| g.dryRunReject(ip, d, pending);
            g.untracked_conns += 1;
            g.total_conns += 1;
            return .admitted_untracked;
        };
        if (deny == null and !allowed) {
            if (e.banned) {
                deny = .banned;
            } else if (now_ns < e.greylisted_until_ns) {
                deny = .greylisted;
            } else {
                e.greylisted_until_ns = 0; // lazy expiry
            }
        }
        if (deny == null) if (g.options.max_conns_per_ip) |max| {
            if (e.active_conns >= max) deny = .per_ip_cap;
        };
        if (deny) |d| {
            if (!dry) return d;
            g.dryRunReject(ip, d, pending);
        }
        e.active_conns += 1;
        g.total_conns += 1;
        return .admitted;
    }

    fn dryRunReject(g: *const Guard, ip: netaddr.Ip, verdict: AdmitVerdict, pending: *Pending) void {
        pending.push(.{ .kind = .dry_run_reject, .prefix = g.prefixOfKey(g.keyOf(ip)), .verdict = verdict });
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
        var pending: Pending = .{};
        {
            lockSpin(&g.lock);
            defer g.lock.unlock();
            g.recordLocked(ip, weight, now_ns, &pending);
        }
        g.deliver(&pending);
    }

    fn recordLocked(g: *Guard, ip: netaddr.Ip, weight: u32, now_ns: u64, pending: *Pending) void {
        if (g.isAllowed(ip)) return;
        const e = g.getOrCreate(g.keyOf(ip), now_ns, pending) orelse return;
        const drained = g.drainedSince(e, now_ns);
        const left = e.strikes - @as(f64, @floatFromInt(drained));
        e.strikes = @max(0, left) + @as(f64, @floatFromInt(weight));
        // `record` returns above when `weight == 0`, so `weight >= 1` here
        // and `e.strikes` (prior balance minus drain, floored at 0, plus
        // `weight`) can therefore never be exactly 0. Enforced rather than
        // just asserted in prose: if a future change makes the early return
        // above stop covering `weight == 0`, this fires instead of quietly
        // reviving the dead `e.strikes == 0` branch this used to carry.
        std.debug.assert(e.strikes != 0);
        // Advance by what actually drained, not to `now`: discarding the
        // remainder would mean a client striking just inside the interval
        // never drains at all. When the old balance drained out completely
        // there is no remainder worth keeping: an empty bucket accrues no
        // drain, so the mark restarts at `now`. Until 2026-10-11 it kept the
        // sub-interval remainder there too, and a strike after a long idle
        // could drain up to one interval early.
        e.strikes_updated_ns = if (g.options.strike_decay_ms == 0 or left <= 0)
            now_ns
        else
            e.strikes_updated_ns +| (drained *| (g.options.strike_decay_ms *| std.time.ns_per_ms));
        if (e.strikes < @as(f64, @floatFromInt(g.options.ban_threshold))) return;
        // Offense: reset the balance, escalate. (The drain mark restarts at
        // the next strike: an empty balance does that above.)
        e.strikes = 0;
        e.offenses +|= 1;
        const prefix = g.prefixOfKey(e.key);
        if (g.options.ban_after_offenses != 0 and e.offenses >= g.options.ban_after_offenses) {
            e.greylisted_until_ns = 0;
            if (!e.banned) pending.push(.{ .kind = .banned, .prefix = prefix, .offense = e.offenses });
            e.banned = true;
        } else {
            const ttl_ms = g.offenseTtlMs(e.offenses);
            e.greylisted_until_ns = now_ns +| (ttl_ms *| std.time.ns_per_ms);
            pending.push(.{ .kind = .greylisted, .prefix = prefix, .ttl_ms = ttl_ms, .offense = e.offenses });
        }
    }

    /// The auto-greylist TTL of the `offense`-th offense (≥ 1):
    /// `greylist_ttl_ms * greylist_ttl_growth^(offense-1)`, saturating, capped
    /// at `greylist_ttl_max_ms`.
    fn offenseTtlMs(g: *const Guard, offense: u32) u64 {
        const cap = g.options.greylist_ttl_max_ms orelse std.math.maxInt(u64);
        var ttl = g.options.greylist_ttl_ms;
        var n: u32 = 1;
        while (n < offense and ttl < cap and g.options.greylist_ttl_growth > 1) : (n += 1)
            ttl *|= g.options.greylist_ttl_growth;
        return @min(ttl, cap);
    }

    /// Manually ban `ip` (permanent until `unban`; rejects new admissions
    /// only — live connections finish on their own). Best-effort under
    /// memory pressure, like `record`. Thread-safe.
    pub fn ban(g: *Guard, ip: netaddr.Ip) void {
        const now_ns = g.options.clock.now();
        var pending: Pending = .{};
        {
            lockSpin(&g.lock);
            defer g.lock.unlock();
            if (g.getOrCreate(g.keyOf(ip), now_ns, &pending)) |e| {
                if (!e.banned and !g.isAllowed(ip))
                    pending.push(.{ .kind = .banned, .prefix = g.prefixOfKey(e.key) });
                e.banned = true;
            }
        }
        g.deliver(&pending);
    }

    /// Full forgiveness: clears the ban, the greylist, all strikes and the
    /// offense history. Live-connection counts are untouched. Thread-safe.
    pub fn unban(g: *Guard, ip: netaddr.Ip) void {
        const now_ns = g.options.clock.now();
        var pending: Pending = .{};
        {
            lockSpin(&g.lock);
            defer g.lock.unlock();
            const e = g.map.get(g.keyOf(ip)) orelse return;
            if ((e.banned or now_ns < e.greylisted_until_ns) and !g.isAllowed(ip))
                pending.push(.{ .kind = .unbanned, .prefix = g.prefixOfKey(e.key) });
            e.banned = false;
            e.greylisted_until_ns = 0;
            e.strikes = 0;
            e.offenses = 0;
            if (e.active_conns == 0) g.removeEntry(e); // now empty — release it
        }
        g.deliver(&pending);
    }

    /// `unban` for every key at once, plus every `banPrefix` range
    /// (`fail2ban-client unban --all`). Live-connection counts are
    /// untouched. One `.all_cleared` event. Thread-safe.
    pub fn unbanAll(g: *Guard) void {
        {
            lockSpin(&g.lock);
            defer g.lock.unlock();
            g.prefix_bans.clearRetainingCapacity();
            var it = g.lru.first;
            while (it) |n| {
                it = n.next;
                const e: *Entry = @fieldParentPtr("node", n);
                e.banned = false;
                e.greylisted_until_ns = 0;
                e.strikes = 0;
                e.offenses = 0;
                if (e.active_conns == 0) g.removeEntry(e);
            }
        }
        var pending: Pending = .{};
        pending.push(.{ .kind = .all_cleared, .prefix = .{ .addr = .{ .v6 = @splat(0) }, .bits = 0 } });
        g.deliver(&pending);
    }

    /// Manually greylist `ip` for `ttl_ms` (null = `Options.greylist_ttl_ms`),
    /// replacing any current greylist. Does not count as an offense and does
    /// not grow (`greylist_ttl_growth`). Best-effort under memory pressure,
    /// like `record`. Thread-safe.
    pub fn greylist(g: *Guard, ip: netaddr.Ip, ttl_ms: ?u64) void {
        const now_ns = g.options.clock.now();
        const ms = ttl_ms orelse g.options.greylist_ttl_ms;
        var pending: Pending = .{};
        {
            lockSpin(&g.lock);
            defer g.lock.unlock();
            if (g.getOrCreate(g.keyOf(ip), now_ns, &pending)) |e| {
                e.greylisted_until_ns = now_ns +| (ms *| std.time.ns_per_ms);
                if (!g.isAllowed(ip))
                    pending.push(.{ .kind = .greylisted, .prefix = g.prefixOfKey(e.key), .ttl_ms = ms });
            }
        }
        g.deliver(&pending);
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
        const c = canonicalPrefix(p);
        const added = added: {
            lockSpin(&g.lock);
            defer g.lock.unlock();
            break :added try g.banPrefixLocked(c);
        };
        if (!added) return;
        var pending: Pending = .{};
        pending.push(.{ .kind = .prefix_banned, .prefix = c });
        g.deliver(&pending);
    }

    /// False when `c` was already banned.
    fn banPrefixLocked(g: *Guard, c: netaddr.Prefix) error{ OutOfMemory, TooManyPrefixBans }!bool {
        for (g.prefix_bans.items) |q| if (q.eql(c)) return false;
        if (g.prefix_bans.items.len >= g.options.max_prefix_bans) return error.TooManyPrefixBans;
        try g.prefix_bans.append(g.gpa, c);
        return true;
    }

    /// Lift a `banPrefix` ban of exactly `p` (after the same canonicalising).
    /// True when one was removed. Does not touch per-key bans. Thread-safe.
    pub fn unbanPrefix(g: *Guard, p: netaddr.Prefix) bool {
        const c = canonicalPrefix(p);
        const removed = removed: {
            lockSpin(&g.lock);
            defer g.lock.unlock();
            for (g.prefix_bans.items, 0..) |q, i| {
                if (q.eql(c)) {
                    _ = g.prefix_bans.orderedRemove(i);
                    break :removed true;
                }
            }
            break :removed false;
        };
        if (removed) {
            var pending: Pending = .{};
            pending.push(.{ .kind = .prefix_unbanned, .prefix = c });
            g.deliver(&pending);
        }
        return removed;
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
                const e = g.getOrCreate(g.keyOf(c.addr), now_ns, null) orelse return error.StoreFull;
                const until = now_ns +| (ms *| std.time.ns_per_ms);
                e.greylisted_until_ns = @max(e.greylisted_until_ns, until);
                continue;
            }
            if (r.range or c.bits != key_bits) {
                _ = try g.banPrefixLocked(c);
                continue;
            }
            const e = g.getOrCreate(g.keyOf(c.addr), now_ns, null) orelse return error.StoreFull;
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
    /// (fail-closed; the callers document their policy). Evicting a banned
    /// or greylisted key queues an `.evicted` event into `pending` (null:
    /// `restore`, which sends none).
    fn getOrCreate(g: *Guard, key: Key, now_ns: u64, pending: ?*Pending) ?*Entry {
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
        if (g.map.count() >= g.options.max_tracked_ips) {
            const victim = g.findEvictable() orelse return null;
            if (pending) |p| if (victim.banned or now_ns < victim.greylisted_until_ns)
                p.push(.{ .kind = .evicted, .prefix = g.prefixOfKey(victim.key) });
            g.removeEntry(victim);
        }
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

test "record: after the balance drains out, the next strike's interval starts at that strike" {
    // A strike after a long idle must hold a full `strike_decay_ms`. Until
    // 2026-10-11 the drain mark kept the idle time's sub-interval remainder
    // (here 500 ms), so this strike drained 500 ms later instead of 1000 ms
    // and the offense below was missed. Negative control: restoring the
    // remainder-keeping mark fails the last expectation.
    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{
        .ban_threshold = 3,
        .ban_after_offenses = 0,
        .strike_decay_ms = 1000,
        .clock = tc.clock(),
    });
    defer g.deinit();
    const ip = mkIp("192.0.2.79");
    g.record(ip, 1);
    tc.advanceMs(2500); // the one strike drained long ago
    g.record(ip, 1); // balance 1, its interval starts now
    tc.advanceMs(700); // < 1000 ms: nothing may drain yet
    g.record(ip, 2); // 1 + 2 = 3 → offense
    try testing.expect(g.isGreylisted(ip));
}

test "record: after an offense the next strike starts a full interval" {
    var tc: TestClock = .{};
    var g = Guard.init(testing.allocator, .{
        .ban_threshold = 2,
        .ban_after_offenses = 0,
        .greylist_ttl_ms = 100,
        .strike_decay_ms = 1000,
        .clock = tc.clock(),
    });
    defer g.deinit();
    const ip = mkIp("192.0.2.80");
    tc.advanceMs(300);
    g.record(ip, 2); // offense at 300 ms, balance reset
    tc.advanceMs(200); // greylist over
    try testing.expect(!g.isGreylisted(ip));
    g.record(ip, 1); // 500 ms
    tc.advanceMs(900); // 1400 ms: 900 ms since the strike, 1100 since the mark of the first one
    g.record(ip, 1); // nothing drained: 1 + 1 = 2 → offense
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

/// Collects `Options.on_event` deliveries; optionally calls back into the
/// Guard from inside the hook (proves the lock is released by then).
const EvLog = struct {
    evs: [8]Event = undefined,
    n: usize = 0,
    reenter: ?*Guard = null,
    reentered: usize = 0,

    fn hook(l: *EvLog) EventHook {
        return .{ .ctx = l, .run = run };
    }

    fn run(ctx: ?*anyopaque, e: Event) void {
        const l: *EvLog = @ptrCast(@alignCast(ctx.?));
        if (l.reenter) |g| {
            _ = g.isBanned(mkIp("192.0.2.1")); // would spin forever under the lock
            l.reentered += 1;
        }
        l.evs[l.n] = e;
        l.n += 1;
    }
};

test "increment: the n-th offense greylists for ttl * growth^(n-1), capped at greylist_ttl_max_ms" {
    // fail2ban bantime.increment + bantime.maxtime. Kills: growth ignored
    // (every greylist 1000 ms), the cap ignored (the 4th lasts 8000 ms), or
    // the exponent off by one (the 1st already 2000 ms).
    var tc: TestClock = .{};
    var log: EvLog = .{};
    var g = Guard.init(testing.allocator, .{
        .ban_threshold = 1,
        .ban_after_offenses = 0,
        .strike_decay_ms = 0,
        .greylist_ttl_ms = 1000,
        .greylist_ttl_growth = 2,
        .greylist_ttl_max_ms = 5000,
        .on_event = log.hook(),
        .clock = tc.clock(),
    });
    defer g.deinit();
    const ip = mkIp("203.0.113.70");
    const want = [_]u64{ 1000, 2000, 4000, 5000, 5000 };
    for (want, 1..) |ttl, offense| {
        g.record(ip, 1);
        try testing.expectEqual(offense, log.n);
        const e = log.evs[offense - 1];
        try testing.expectEqual(Event.Kind.greylisted, e.kind);
        try testing.expectEqual(@as(?u64, ttl), e.ttl_ms);
        try testing.expectEqual(@as(u32, @intCast(offense)), e.offense);
        try testing.expect(e.prefix.eql(.{ .addr = ip, .bits = 32 }));
        tc.advanceMs(ttl - 1);
        try testing.expectEqual(AdmitVerdict.greylisted, g.admit(ip));
        tc.advanceMs(1);
        try testing.expectEqual(AdmitVerdict.admitted, g.admit(ip));
        g.connClosed(ip);
    }
    // A manual greylist does not grow.
    g.greylist(ip, null);
    try testing.expectEqual(@as(?u64, 1000), log.evs[want.len].ttl_ms);
}

test "increment: growth 1 (the default) keeps every auto-greylist at greylist_ttl_ms" {
    var tc: TestClock = .{};
    var log: EvLog = .{};
    var g = Guard.init(testing.allocator, .{ .ban_threshold = 1, .ban_after_offenses = 0, .strike_decay_ms = 0, .greylist_ttl_ms = 700, .on_event = log.hook(), .clock = tc.clock() });
    defer g.deinit();
    const ip = mkIp("203.0.113.71");
    for (0..4) |_| g.record(ip, 1);
    for (log.evs[0..4]) |e| try testing.expectEqual(@as(?u64, 700), e.ttl_ms);
}

test "dry run: every rejection is admitted, counted and reported with the verdict it would have been" {
    // nginx limit_conn_dry_run. Kills: dry run still rejecting, the admitted
    // connection not counted (connCount/totalConns), or no event.
    var tc: TestClock = .{};
    var log: EvLog = .{};
    var g = Guard.init(testing.allocator, .{
        .max_conns_per_ip = 1,
        .max_conns_total = 3,
        .dry_run = true,
        .on_event = log.hook(),
        .clock = tc.clock(),
    });
    defer g.deinit();
    const a = mkIp("198.51.100.1");
    const b = mkIp("198.51.100.2");
    try testing.expectEqual(AdmitVerdict.admitted, g.admit(a));
    try testing.expectEqual(@as(usize, 0), log.n);
    try testing.expectEqual(AdmitVerdict.admitted, g.admit(a)); // over the per-IP cap
    try testing.expectEqual(@as(u32, 2), g.connCount(a));
    try testing.expectEqual(Event.Kind.dry_run_reject, log.evs[0].kind);
    try testing.expectEqual(@as(?AdmitVerdict, .per_ip_cap), log.evs[0].verdict);
    g.ban(b); // event 1: banned
    try testing.expectEqual(AdmitVerdict.admitted, g.admit(b));
    try testing.expectEqual(@as(?AdmitVerdict, .banned), log.evs[2].verdict);
    try testing.expectEqual(AdmitVerdict.admitted, g.admit(mkIp("198.51.100.3"))); // 4th > total 3
    try testing.expectEqual(@as(?AdmitVerdict, .total_cap), log.evs[3].verdict);
    try testing.expectEqual(@as(usize, 4), g.totalConns());
    // Reputation is still accounted: the ban is real, only not enforced.
    try testing.expect(g.isBanned(b));
}

test "dry run: an untrackable peer is admitted untracked and reported as store_full" {
    var tc: TestClock = .{};
    var log: EvLog = .{};
    var g = Guard.init(testing.allocator, .{ .max_tracked_ips = 1, .dry_run = true, .on_event = log.hook(), .clock = tc.clock() });
    defer g.deinit();
    try testing.expectEqual(AdmitVerdict.admitted, g.admit(mkIp("198.51.100.10")));
    try testing.expectEqual(AdmitVerdict.admitted_untracked, g.admit(mkIp("198.51.100.11")));
    try testing.expectEqual(@as(?AdmitVerdict, .store_full), log.evs[0].verdict);
    try testing.expectEqual(@as(usize, 1), g.untrackedConns());
}

test "events: delivered after the lock is released -- the hook may call back into the Guard" {
    // Kills: delivering under the spinlock (the re-entrant isBanned would
    // spin forever: this test hangs instead of passing).
    var tc: TestClock = .{};
    var log: EvLog = .{};
    var g = Guard.init(testing.allocator, .{ .ban_threshold = 1, .ban_after_offenses = 2, .strike_decay_ms = 0, .on_event = log.hook(), .clock = tc.clock() });
    defer g.deinit();
    log.reenter = &g;
    const ip = mkIp("203.0.113.80");
    g.record(ip, 1); // greylisted, offense 1
    g.record(ip, 1); // banned, offense 2
    g.ban(ip); // already banned: no event
    g.unban(ip); // unbanned
    g.greylist(ip, 5); // greylisted, manual
    try g.banPrefix(mkPrefix("203.0.113.0/24")); // prefix_banned
    try g.banPrefix(mkPrefix("203.0.113.0/24")); // already: no event
    try testing.expect(g.unbanPrefix(mkPrefix("203.0.113.0/24"))); // prefix_unbanned
    try testing.expect(!g.unbanPrefix(mkPrefix("203.0.113.0/24"))); // none
    const kinds = [_]Event.Kind{ .greylisted, .banned, .unbanned, .greylisted, .prefix_banned, .prefix_unbanned };
    try testing.expectEqual(kinds.len, log.n);
    for (kinds, log.evs[0..log.n]) |k, e| try testing.expectEqual(k, e.kind);
    try testing.expectEqual(kinds.len, log.reentered);
    try testing.expectEqual(@as(u32, 2), log.evs[1].offense);
    try testing.expectEqual(@as(u32, 0), log.evs[3].offense);
    try testing.expectEqual(@as(?u64, 5), log.evs[3].ttl_ms);
}

test "events: an allowlist member's manual ban/greylist/unban sends nothing (never enforced)" {
    var tc: TestClock = .{};
    var log: EvLog = .{};
    const allow = [_]netaddr.Prefix{mkPrefix("10.9.0.0/16")};
    var g = Guard.init(testing.allocator, .{ .allow = &allow, .on_event = log.hook(), .clock = tc.clock() });
    defer g.deinit();
    const ip = mkIp("10.9.1.1");
    g.ban(ip);
    g.greylist(ip, null);
    g.unban(ip);
    try testing.expectEqual(@as(usize, 0), log.n);
}

test "events: evicting a banned or greylisted key reports it; an expired greylist does not" {
    // Kills: no `.evicted` event (a firewall mirror would keep a ban the
    // guard forgot), or one for an entry that held no reputation.
    var tc: TestClock = .{};
    var log: EvLog = .{};
    var g = Guard.init(testing.allocator, .{ .max_tracked_ips = 1, .greylist_ttl_ms = 100, .on_event = log.hook(), .clock = tc.clock() });
    defer g.deinit();
    const a = mkIp("198.51.100.20");
    g.ban(a); // event 0
    try testing.expectEqual(AdmitVerdict.admitted, g.admit(mkIp("198.51.100.21"))); // evicts a
    try testing.expectEqual(@as(usize, 2), log.n);
    try testing.expectEqual(Event.Kind.evicted, log.evs[1].kind);
    try testing.expect(log.evs[1].prefix.eql(.{ .addr = a, .bits = 32 }));
    g.connClosed(mkIp("198.51.100.21"));
    g.greylist(mkIp("198.51.100.22"), null); // .21 held no reputation: swept, no event
    try testing.expectEqual(@as(usize, 3), log.n);
    try testing.expectEqual(Event.Kind.greylisted, log.evs[2].kind);
    tc.advanceMs(100); // the greylist is over
    g.ban(mkIp("198.51.100.23")); // .22 is empty now: swept, no event
    try testing.expectEqual(@as(usize, 4), log.n);
    try testing.expectEqual(Event.Kind.banned, log.evs[3].kind);
}

test "unbanAll: clears every key's reputation and every range, keeps live counts, one event" {
    var tc: TestClock = .{};
    var log: EvLog = .{};
    var g = Guard.init(testing.allocator, .{ .ban_threshold = 1, .strike_decay_ms = 0, .on_event = log.hook(), .clock = tc.clock() });
    defer g.deinit();
    const a = mkIp("198.51.100.30");
    const b = mkIp("198.51.100.31");
    try testing.expectEqual(AdmitVerdict.admitted, g.admit(a));
    g.record(a, 1);
    g.ban(b);
    try g.banPrefix(mkPrefix("192.0.2.0/24"));
    log.n = 0;
    g.unbanAll();
    try testing.expectEqual(@as(usize, 1), log.n);
    try testing.expectEqual(Event.Kind.all_cleared, log.evs[0].kind);
    try testing.expectEqual(@as(u8, 0), log.evs[0].prefix.bits);
    try testing.expect(!g.isGreylisted(a) and !g.isBanned(b) and !g.isBanned(mkIp("192.0.2.9")));
    try testing.expectEqual(@as(u32, 1), g.connCount(a));
    try testing.expectEqual(@as(usize, 1), g.trackedCount()); // b released, a kept (live)
    g.record(a, 1); // offense history was cleared too: a first offense again
    try testing.expectEqual(@as(u32, 1), log.evs[1].offense);
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

// ── model-fuzz: seeded random operation sequences vs a naive reference ───────
//
// The reference model below is a re-statement of the documented semantics
// (SPEC.md "Design & invariants", README) in the plainest possible form: an
// ordered array of per-key records (front = most recently touched), integer
// strike counters, absolute-nanosecond deadlines, a linear list of range bans
// and a linear allowlist test. It never calls the guard and shares no code
// with it: addresses are re-implemented as (family, 16 bytes) with a bit-loop
// mask, so keying, v4-mapped unification and prefix canonicalisation are
// checked, not borrowed. The clock is the injected TestClock, so every
// deadline, decay boundary and TTL expiry is driven to the exact nanosecond.

const AgAddr = struct {
    fam: u8, // 4 or 6
    b: [16]u8 = @splat(0),

    fn eql(x: AgAddr, y: AgAddr) bool {
        return x.fam == y.fam and std.mem.eql(u8, &x.b, &y.b);
    }
};

const AgPrefix = struct {
    a: AgAddr,
    bits: u8,

    fn eql(x: AgPrefix, y: AgPrefix) bool {
        return x.bits == y.bits and x.a.eql(y.a);
    }
};

fn agRaw(ip: netaddr.Ip) AgAddr {
    switch (ip) {
        .v4 => |b| {
            var r = AgAddr{ .fam = 4 };
            @memcpy(r.b[0..4], &b);
            return r;
        },
        .v6 => |b| return .{ .fam = 6, .b = b },
    }
}

fn agIsMapped(a: AgAddr) bool {
    if (a.fam != 6) return false;
    for (a.b[0..10]) |c| if (c != 0) return false;
    return a.b[10] == 0xff and a.b[11] == 0xff;
}

fn agUnmap(a: AgAddr) AgAddr {
    if (!agIsMapped(a)) return a;
    var r = AgAddr{ .fam = 4 };
    @memcpy(r.b[0..4], a.b[12..16]);
    return r;
}

fn agMask(a: AgAddr, bits: u8) AgAddr {
    var r = a;
    var i: usize = bits;
    while (i < 128) : (i += 1) r.b[i / 8] &= ~(@as(u8, 0x80) >> @intCast(i % 8));
    return r;
}

/// A ban / allow prefix as the docs define it: host bits zeroed; a v4-mapped
/// v6 prefix of /96 or longer is the v4 prefix it denotes.
fn agPrefixOf(p: netaddr.Prefix) AgPrefix {
    const raw = agRaw(p.addr);
    if (agIsMapped(raw) and p.bits >= 96) return .{ .a = agMask(agUnmap(raw), p.bits - 96), .bits = p.bits - 96 };
    return .{ .a = agMask(raw, p.bits), .bits = p.bits };
}

fn agHas(p: AgPrefix, a: AgAddr) bool {
    return p.a.fam == a.fam and p.a.eql(agMask(a, p.bits));
}

const AgCfg = struct {
    max_per: ?u32,
    max_total: ?u32,
    ttl_ms: u64,
    threshold: u32,
    decay_ms: u64,
    after: u32,
    max_tracked: usize,
    store_full: StoreFull,
    allow: []const netaddr.Prefix,
    v6bits: u8,
    v4bits: u8,
    max_pfx: usize,
    growth: u32,
    max_ttl_ms: ?u64,
    dry: bool,
};

const AgReach = struct {
    admitted: u64 = 0,
    banned_entry: u64 = 0,
    banned_range: u64 = 0,
    greylisted: u64 = 0,
    per_ip_cap: u64 = 0,
    total_cap: u64 = 0,
    store_full: u64 = 0,
    admitted_untracked: u64 = 0,
    allow_overrides_verdict: u64 = 0,
    grey_expired_at_boundary: u64 = 0,
    strikes_decayed: u64 = 0,
    offense_greylist: u64 = 0,
    offense_ban: u64 = 0,
    evicted: u64 = 0,
    evicted_banned_last_resort: u64 = 0,
    swept_empty: u64 = 0,
    unban_removed_entry: u64 = 0,
    too_many_prefix_bans: u64 = 0,
    unban_prefix_true: u64 = 0,
    unban_prefix_false: u64 = 0,
    close_untracked_fallback: u64 = 0,
    close_unmatched: u64 = 0,
    reconcile_applied: u64 = 0,
    snapshot_checked: u64 = 0,
    restore_roundtrip: u64 = 0,
    offense_ttl_grown: u64 = 0,
    offense_ttl_capped: u64 = 0,
    dry_run_reject: u64 = 0,
    evicted_event: u64 = 0,
    unban_all: u64 = 0,
    event_checked: u64 = 0,
};

/// An `Event` as the model predicts it (prefix in the model's own form).
const AgEv = struct {
    kind: Event.Kind,
    p: AgPrefix,
    ttl_ms: ?u64 = null,
    offense: u32 = 0,
    verdict: ?AdmitVerdict = null,

    fn of(e: Event) AgEv {
        return .{
            .kind = e.kind,
            .p = .{ .a = agRaw(e.prefix.addr), .bits = e.prefix.bits },
            .ttl_ms = e.ttl_ms,
            .offense = e.offense,
            .verdict = e.verdict,
        };
    }

    fn eql(x: AgEv, y: AgEv) bool {
        return x.kind == y.kind and x.p.eql(y.p) and x.ttl_ms == y.ttl_ms and
            x.offense == y.offense and x.verdict == y.verdict;
    }
};

/// `Options.on_event` sink for the model-fuzz: what the Guard delivered.
const AgEvSink = struct {
    evs: [4]Event = undefined,
    n: usize = 0,

    fn hook(s: *AgEvSink) EventHook {
        return .{ .ctx = s, .run = run };
    }

    fn run(ctx: ?*anyopaque, e: Event) void {
        const s: *AgEvSink = @ptrCast(@alignCast(ctx.?));
        s.evs[s.n] = e; // more than 4 per operation overflows: a failure by itself
        s.n += 1;
    }
};

const AgEntry = struct {
    key: AgAddr,
    live: u32 = 0,
    strikes: u64 = 0,
    mark: u64, // instant up to which strikes have been drained
    grey_until: u64 = 0,
    offenses: u32 = 0,
    banned: bool = false,
};

const AgModel = struct {
    cfg: AgCfg,
    reach: *AgReach,
    ents: [16]AgEntry = undefined, // [0] = most recently touched
    n: usize = 0,
    pfx: [8]AgPrefix = undefined,
    np: usize = 0,
    untracked: usize = 0,
    evs: [2]AgEv = undefined, // events of the current operation
    nev: usize = 0,

    const ms = std.time.ns_per_ms;

    fn emit(m: *AgModel, e: AgEv) void {
        m.evs[m.nev] = e;
        m.nev += 1;
    }

    fn keyPfx(m: *const AgModel, key: AgAddr) AgPrefix {
        return .{ .a = key, .bits = if (key.fam == 4) m.cfg.v4bits else m.cfg.v6bits };
    }

    /// ttl_ms * growth^(offense-1), saturating at u64, then capped.
    fn offenseTtl(m: *const AgModel, offense: u32) u64 {
        var t: u128 = m.cfg.ttl_ms;
        var k: u32 = 1;
        while (k < offense and t <= std.math.maxInt(u64)) : (k += 1) t *= m.cfg.growth;
        const sat: u64 = @intCast(@min(t, std.math.maxInt(u64)));
        return @min(sat, m.cfg.max_ttl_ms orelse std.math.maxInt(u64));
    }

    fn keyOf(m: *const AgModel, ip: netaddr.Ip) AgAddr {
        const a = agUnmap(agRaw(ip));
        return agMask(a, if (a.fam == 4) m.cfg.v4bits else m.cfg.v6bits);
    }

    fn find(m: *const AgModel, key: AgAddr) ?usize {
        for (m.ents[0..m.n], 0..) |e, i| if (e.key.eql(key)) return i;
        return null;
    }

    fn remove(m: *AgModel, i: usize) void {
        var j = i;
        while (j + 1 < m.n) : (j += 1) m.ents[j] = m.ents[j + 1];
        m.n -= 1;
    }

    fn insertFront(m: *AgModel, e: AgEntry) void {
        var j = m.n;
        while (j > 0) : (j -= 1) m.ents[j] = m.ents[j - 1];
        m.ents[0] = e;
        m.n += 1;
    }

    fn allowed(m: *const AgModel, ip: netaddr.Ip) bool {
        const a = agUnmap(agRaw(ip));
        for (m.cfg.allow) |p| if (agHas(agPrefixOf(p), a)) return true;
        return false;
    }

    fn inPfx(m: *const AgModel, ip: netaddr.Ip) bool {
        const a = agUnmap(agRaw(ip));
        for (m.pfx[0..m.np]) |p| if (agHas(p, a)) return true;
        return false;
    }

    fn drained(m: *const AgModel, e: *const AgEntry, now: u64) u64 {
        if (m.cfg.decay_ms == 0) return 0;
        return (now -| e.mark) / (m.cfg.decay_ms * ms);
    }

    fn isEmpty(m: *const AgModel, e: *const AgEntry, now: u64) bool {
        return e.live == 0 and !e.banned and e.offenses == 0 and now >= e.grey_until and
            (e.strikes -| m.drained(e, now)) == 0;
    }

    fn total(m: *const AgModel) usize {
        var t: usize = m.untracked;
        for (m.ents[0..m.n]) |e| t += e.live;
        return t;
    }

    /// Touch-or-insert; index 0 afterwards, null when nothing can make room.
    fn touch(m: *AgModel, key: AgAddr, now: u64) ?usize {
        if (m.find(key)) |i| {
            const e = m.ents[i];
            m.remove(i);
            m.insertFront(e);
            return 0;
        }
        while (m.n > 0 and m.isEmpty(&m.ents[m.n - 1], now)) {
            m.n -= 1;
            m.reach.swept_empty += 1;
        }
        if (m.n >= m.cfg.max_tracked) {
            var victim: ?usize = null;
            var i = m.n;
            while (i > 0) { // oldest first: no live connection, not banned
                i -= 1;
                if (m.ents[i].live == 0 and !m.ents[i].banned) {
                    victim = i;
                    break;
                }
            }
            if (victim == null) {
                i = m.n;
                while (i > 0) { // last resort: a banned entry without live connections
                    i -= 1;
                    if (m.ents[i].live == 0) {
                        victim = i;
                        m.reach.evicted_banned_last_resort += 1;
                        break;
                    }
                }
            }
            const v = victim orelse return null;
            if (m.ents[v].banned or now < m.ents[v].grey_until) {
                m.emit(.{ .kind = .evicted, .p = m.keyPfx(m.ents[v].key) });
                m.reach.evicted_event += 1;
            }
            m.remove(v);
            m.reach.evicted += 1;
        }
        m.insertFront(.{ .key = key, .mark = now });
        return 0;
    }

    /// `Guard.admit`: the rejection, or under `dry` the admission plus a
    /// `.dry_run_reject` event.
    fn admit(m: *AgModel, ip: netaddr.Ip, now: u64) AdmitVerdict {
        var deny: ?AdmitVerdict = null;
        if (m.cfg.max_total) |mx| if (m.total() >= mx) {
            deny = .total_cap;
        };
        const al = m.allowed(ip);
        if (deny == null and !al and m.inPfx(ip)) deny = .banned;
        if (deny != null and !m.cfg.dry) return deny.?;
        const key = m.keyOf(ip);
        const i = m.touch(key, now) orelse {
            if (deny == null and m.cfg.store_full == .reject) {
                if (!m.cfg.dry) return .store_full;
                deny = .store_full;
            }
            if (deny) |d| m.dryReject(key, d);
            m.untracked += 1;
            return .admitted_untracked;
        };
        const e = &m.ents[i];
        if (deny == null) {
            if (!al) {
                if (e.banned) {
                    deny = .banned;
                } else if (now < e.grey_until) {
                    deny = .greylisted;
                } else e.grey_until = 0;
            } else if (e.banned or now < e.grey_until or m.inPfx(ip)) {
                m.reach.allow_overrides_verdict += 1;
            }
        }
        if (deny == null) if (m.cfg.max_per) |mx| if (e.live >= mx) {
            deny = .per_ip_cap;
        };
        if (deny) |d| {
            if (!m.cfg.dry) return d;
            m.dryReject(key, d);
        }
        e.live += 1;
        return .admitted;
    }

    fn dryReject(m: *AgModel, key: AgAddr, d: AdmitVerdict) void {
        m.emit(.{ .kind = .dry_run_reject, .p = m.keyPfx(key), .verdict = d });
        m.reach.dry_run_reject += 1;
    }

    fn closed(m: *AgModel, ip: netaddr.Ip) void {
        if (m.find(m.keyOf(ip))) |i| if (m.ents[i].live != 0) {
            m.ents[i].live -= 1;
            return;
        };
        if (m.untracked > 0) {
            m.untracked -= 1;
            m.reach.close_untracked_fallback += 1;
        } else m.reach.close_unmatched += 1;
    }

    fn closedUntracked(m: *AgModel) void {
        if (m.untracked > 0) m.untracked -= 1;
    }

    fn reconcile(m: *AgModel, ip: netaddr.Ip, live: u32) void {
        const i = m.find(m.keyOf(ip)) orelse return;
        m.ents[i].live = live;
        m.reach.reconcile_applied += 1;
    }

    fn record(m: *AgModel, ip: netaddr.Ip, w: u32, now: u64) void {
        if (w == 0 or m.allowed(ip)) return;
        const i = m.touch(m.keyOf(ip), now) orelse return;
        const e = &m.ents[i];
        const dr = m.drained(e, now);
        if (dr > 0 and e.strikes > 0) m.reach.strikes_decayed += 1;
        const emptied = e.strikes <= dr;
        e.strikes = (e.strikes -| dr) + w;
        // Whole strikes drain; the undrained remainder of the interval is kept
        // while strikes are left, and an emptied balance restarts at `now`.
        e.mark = if (m.cfg.decay_ms == 0 or emptied) now else e.mark + dr * m.cfg.decay_ms * ms;
        if (e.strikes < m.cfg.threshold) return;
        e.strikes = 0;
        e.offenses += 1;
        if (m.cfg.after != 0 and e.offenses >= m.cfg.after) {
            if (!e.banned) m.emit(.{ .kind = .banned, .p = m.keyPfx(e.key), .offense = e.offenses });
            e.banned = true;
            e.grey_until = 0;
            m.reach.offense_ban += 1;
        } else {
            const ttl = m.offenseTtl(e.offenses);
            if (ttl > m.cfg.ttl_ms) m.reach.offense_ttl_grown += 1;
            if (m.cfg.max_ttl_ms != null and ttl == m.cfg.max_ttl_ms.? and ttl > m.cfg.ttl_ms) m.reach.offense_ttl_capped += 1;
            e.grey_until = now +| ttl *| ms;
            m.emit(.{ .kind = .greylisted, .p = m.keyPfx(e.key), .ttl_ms = ttl, .offense = e.offenses });
            m.reach.offense_greylist += 1;
        }
    }

    fn ban(m: *AgModel, ip: netaddr.Ip, now: u64) void {
        const i = m.touch(m.keyOf(ip), now) orelse return;
        if (!m.ents[i].banned and !m.allowed(ip)) m.emit(.{ .kind = .banned, .p = m.keyPfx(m.ents[i].key) });
        m.ents[i].banned = true;
    }

    fn unbanAll(m: *AgModel) void {
        m.np = 0;
        var i = m.n;
        while (i > 0) {
            i -= 1;
            const e = &m.ents[i];
            e.banned = false;
            e.grey_until = 0;
            e.strikes = 0;
            e.offenses = 0;
            if (e.live == 0) m.remove(i);
        }
        m.emit(.{ .kind = .all_cleared, .p = .{ .a = .{ .fam = 6 }, .bits = 0 } });
        m.reach.unban_all += 1;
    }

    fn unban(m: *AgModel, ip: netaddr.Ip, now: u64) void {
        const i = m.find(m.keyOf(ip)) orelse return;
        const e = &m.ents[i];
        if ((e.banned or now < e.grey_until) and !m.allowed(ip)) m.emit(.{ .kind = .unbanned, .p = m.keyPfx(e.key) });
        e.banned = false;
        e.grey_until = 0;
        e.strikes = 0;
        e.offenses = 0;
        if (e.live == 0) {
            m.remove(i);
            m.reach.unban_removed_entry += 1;
        }
    }

    fn greylist(m: *AgModel, ip: netaddr.Ip, ttl_ms: ?u64, now: u64) void {
        const i = m.touch(m.keyOf(ip), now) orelse return;
        const t = ttl_ms orelse m.cfg.ttl_ms;
        m.ents[i].grey_until = now + t * ms;
        if (!m.allowed(ip)) m.emit(.{ .kind = .greylisted, .p = m.keyPfx(m.ents[i].key), .ttl_ms = t });
    }

    fn banPrefix(m: *AgModel, p: netaddr.Prefix) error{TooManyPrefixBans}!void {
        const c = agPrefixOf(p);
        for (m.pfx[0..m.np]) |q| if (q.eql(c)) return;
        if (m.np >= m.cfg.max_pfx) return error.TooManyPrefixBans;
        m.pfx[m.np] = c;
        m.np += 1;
        m.emit(.{ .kind = .prefix_banned, .p = c });
    }

    fn unbanPrefix(m: *AgModel, p: netaddr.Prefix) bool {
        const c = agPrefixOf(p);
        for (m.pfx[0..m.np], 0..) |q, i| if (q.eql(c)) {
            var j = i;
            while (j + 1 < m.np) : (j += 1) m.pfx[j] = m.pfx[j + 1];
            m.np -= 1;
            m.emit(.{ .kind = .prefix_unbanned, .p = c });
            return true;
        };
        return false;
    }
};

const AgRec = struct {
    kind: u8, // 0 range, 1 ban, 2 greylist
    p: AgPrefix,
    ms: u64 = 0,

    fn less(_: void, x: AgRec, y: AgRec) bool {
        if (x.kind != y.kind) return x.kind < y.kind;
        if (x.p.a.fam != y.p.a.fam) return x.p.a.fam < y.p.a.fam;
        const c = std.mem.order(u8, &x.p.a.b, &y.p.a.b);
        if (c != .eq) return c == .lt;
        if (x.p.bits != y.p.bits) return x.p.bits < y.p.bits;
        return x.ms < y.ms;
    }

    fn eql(x: AgRec, y: AgRec) bool {
        return x.kind == y.kind and x.p.eql(y.p) and x.ms == y.ms;
    }
};

fn agRecOf(r: BanRecord) AgRec {
    return .{
        .kind = if (r.greylist_remaining_ms != null) 2 else if (r.range) 0 else 1,
        .p = .{ .a = agRaw(r.prefix.addr), .bits = r.prefix.bits },
        .ms = r.greylist_remaining_ms orelse 0,
    };
}

const ag_ips = [_][]const u8{
    "10.0.0.1",        "10.0.0.2",        "10.0.1.1",    "10.0.1.2",
    "::ffff:10.0.0.1", "::ffff:10.0.1.1", "2001:db8::1", "2001:db8::2",
    "2001:db8:0:1::1", "2001:db8:0:1::2",
};
const ag_pfx = [_][]const u8{
    "10.0.0.0/24",         "10.0.0.1/32",   "::ffff:10.0.1.0/120", "2001:db8::/32",
    "2001:db8:0:1::2/128", "2001:db8::/64", "10.0.1.0/24",
};
const ag_allow_sets = [_][]const []const u8{
    &.{},
    &.{"10.0.1.0/24"},
    &.{"2001:db8:0:1::/64"},
    &.{ "::ffff:10.0.0.0/120", "2001:db8::2/128" },
};

fn agAudit(g: *Guard, m: *const AgModel, univ: []const netaddr.Ip, now: u64) !void {
    for (univ) |ip| {
        const key = m.keyOf(ip);
        const ei = m.find(key);
        try testing.expectEqual(if (ei) |i| m.ents[i].live else 0, g.connCount(ip));
        try testing.expectEqual(m.inPfx(ip) or (if (ei) |i| m.ents[i].banned else false), g.isBanned(ip));
        try testing.expectEqual(if (ei) |i| now < m.ents[i].grey_until else false, g.isGreylisted(ip));
    }
    try testing.expectEqual(m.total(), g.totalConns());
    try testing.expectEqual(m.untracked, g.untrackedConns());
    try testing.expectEqual(m.n, g.trackedCount());
}

fn agSnapshotCheck(gpa: Allocator, g: *Guard, m: *const AgModel, univ: []const netaddr.Ip, clk: *TestClock, opts: Options, now: u64) !bool {
    var want: std.ArrayList(AgRec) = .empty;
    defer want.deinit(gpa);
    for (m.pfx[0..m.np]) |p| try want.append(gpa, .{ .kind = 0, .p = p });
    for (m.ents[0..m.n]) |e| {
        const bits = if (e.key.fam == 4) m.cfg.v4bits else m.cfg.v6bits;
        if (e.banned) try want.append(gpa, .{ .kind = 1, .p = .{ .a = e.key, .bits = bits } });
        if (now < e.grey_until) {
            const rem = e.grey_until - now;
            try want.append(gpa, .{ .kind = 2, .p = .{ .a = e.key, .bits = bits }, .ms = rem / AgModel.ms + @intFromBool(rem % AgModel.ms != 0) });
        }
    }
    const recs = try g.snapshot(gpa);
    defer gpa.free(recs);
    const got = try gpa.alloc(AgRec, recs.len);
    defer gpa.free(got);
    for (recs, got) |r, *o| o.* = agRecOf(r);
    std.mem.sort(AgRec, got, {}, AgRec.less);
    std.mem.sort(AgRec, want.items, {}, AgRec.less);
    try testing.expectEqual(want.items.len, got.len);
    for (want.items, got) |w, x| try testing.expect(w.eql(x));

    // text -> parse is the identity on the records
    var aw: Writer.Allocating = .init(gpa);
    defer aw.deinit();
    try writeSnapshot(recs, &aw.writer);
    var parsed: std.ArrayList(BanRecord) = .empty;
    defer parsed.deinit(gpa);
    var lines = std.mem.splitScalar(u8, aw.written(), '\n');
    while (lines.next()) |line| if (try parseSnapshotLine(line)) |r| try parsed.append(gpa, r);
    try testing.expectEqual(recs.len, parsed.items.len);
    for (recs, parsed.items) |a, b| {
        try testing.expect(a.prefix.eql(b.prefix));
        try testing.expectEqual(a.range, b.range);
        try testing.expectEqual(a.greylist_remaining_ms, b.greylist_remaining_ms);
    }

    // restore into a fresh guard (same options, same instant, roomy store)
    // reproduces every ban and every live greylist
    if (m.cfg.max_tracked < 16) return false;
    var g2 = Guard.init(gpa, opts);
    defer g2.deinit();
    _ = clk;
    try g2.restore(parsed.items);
    for (univ) |ip| {
        try testing.expectEqual(g.isBanned(ip), g2.isBanned(ip));
        try testing.expectEqual(g.isGreylisted(ip), g2.isGreylisted(ip));
    }
    return true;
}

fn agCase(gpa: Allocator, seed: u64, reach: *AgReach) !void {
    var prng = std.Random.DefaultPrng.init(seed);
    const rnd = prng.random();

    var univ: [ag_ips.len]netaddr.Ip = undefined;
    for (ag_ips, &univ) |t, *o| o.* = mkIp(t);
    var pfx_univ: [ag_pfx.len]netaddr.Prefix = undefined;
    for (ag_pfx, &pfx_univ) |t, *o| o.* = mkPrefix(t);
    var allow_buf: [2]netaddr.Prefix = undefined;
    const allow_text = ag_allow_sets[rnd.uintLessThan(usize, ag_allow_sets.len)];
    for (allow_text, 0..) |t, i| allow_buf[i] = mkPrefix(t);

    const per_c = [_]?u32{ null, 1, 2, 3, 100 };
    const tot_c = [_]?u32{ null, null, 2, 5 };
    const mt_c = [_]usize{ 1, 2, 3, 4, 4096 };
    const ttl_c = [_]u64{ 3, 10, 30 };
    const thr_c = [_]u32{ 1, 2, 3, 5 };
    const dec_c = [_]u64{ 0, 4, 7 };
    const after_c = [_]u32{ 0, 1, 2, 3 };
    const growth_c = [_]u32{ 1, 1, 2, 3 };
    var cfg = AgCfg{
        .max_per = per_c[rnd.uintLessThan(usize, per_c.len)],
        .max_total = tot_c[rnd.uintLessThan(usize, tot_c.len)],
        .ttl_ms = ttl_c[rnd.uintLessThan(usize, ttl_c.len)],
        .threshold = thr_c[rnd.uintLessThan(usize, thr_c.len)],
        .decay_ms = dec_c[rnd.uintLessThan(usize, dec_c.len)],
        .after = after_c[rnd.uintLessThan(usize, after_c.len)],
        .max_tracked = mt_c[rnd.uintLessThan(usize, mt_c.len)],
        .store_full = if (rnd.boolean()) .reject else .admit_untracked,
        .allow = allow_buf[0..allow_text.len],
        .v6bits = if (rnd.boolean()) 64 else 128,
        .v4bits = if (rnd.boolean()) 32 else 24,
        .max_pfx = if (rnd.boolean()) 2 else 8,
        .growth = growth_c[rnd.uintLessThan(usize, growth_c.len)],
        .max_ttl_ms = null,
        .dry = rnd.uintLessThan(u32, 4) == 0,
    };
    // A ceiling is either absent or at least the base TTL (init asserts it).
    if (rnd.boolean()) cfg.max_ttl_ms = cfg.ttl_ms * (1 + rnd.uintLessThan(u64, 5));

    var clk: TestClock = .{ .ns = .init(1_000_000_000 + rnd.uintLessThan(u64, 999_983)) };
    var sink: AgEvSink = .{};
    const opts = Options{
        .max_conns_per_ip = cfg.max_per,
        .max_conns_total = cfg.max_total,
        .greylist_ttl_ms = cfg.ttl_ms,
        .ban_threshold = cfg.threshold,
        .strike_decay_ms = cfg.decay_ms,
        .ban_after_offenses = cfg.after,
        .max_tracked_ips = cfg.max_tracked,
        .on_store_full = cfg.store_full,
        .allow = cfg.allow,
        .ipv6_key_bits = cfg.v6bits,
        .ipv4_key_bits = cfg.v4bits,
        .max_prefix_bans = cfg.max_pfx,
        .clock = clk.clock(),
        .greylist_ttl_growth = cfg.growth,
        .greylist_ttl_max_ms = cfg.max_ttl_ms,
        .dry_run = cfg.dry,
        .on_event = sink.hook(),
    };
    var g = Guard.init(gpa, opts);
    defer g.deinit();
    var m = AgModel{ .cfg = cfg, .reach = reach };
    var owed: [ag_ips.len]u32 = @splat(0);
    var owed_untracked: u32 = 0;

    const steps = 100 + rnd.uintLessThan(usize, 250);
    var step: usize = 0;
    var op: []const u8 = "";
    errdefer std.debug.print("abuseguard model-fuzz FAILED: seed={d} step={d} op={s}\n", .{ seed, step, op });
    while (step < steps) : (step += 1) {
        const now = clk.ns.load(.monotonic);
        const k = rnd.uintLessThan(usize, ag_ips.len);
        const ip = univ[k];
        const roll = rnd.uintLessThan(u32, 100);
        if (roll < 34) {
            op = "admit";
            const want = m.admit(ip, now);
            const got = g.admit(ip);
            try testing.expectEqual(want, got);
            switch (got) {
                .admitted => {
                    owed[k] += 1;
                    reach.admitted += 1;
                },
                .admitted_untracked => {
                    owed_untracked += 1;
                    reach.admitted_untracked += 1;
                },
                .banned => if (m.inPfx(ip)) {
                    reach.banned_range += 1;
                } else {
                    reach.banned_entry += 1;
                },
                .greylisted => reach.greylisted += 1,
                .per_ip_cap => reach.per_ip_cap += 1,
                .total_cap => reach.total_cap += 1,
                .store_full => reach.store_full += 1,
            }
        } else if (roll < 52) {
            op = "connClosed";
            // mostly pair a held slot, sometimes close something nobody holds
            var kk = k;
            if (rnd.uintLessThan(u32, 10) != 0) for (owed, 0..) |o, i| if (o > 0) {
                kk = i;
                break;
            };
            if (owed[kk] > 0) owed[kk] -= 1;
            m.closed(univ[kk]);
            g.connClosed(univ[kk]);
        } else if (roll < 56) {
            op = "connClosedUntracked";
            if (owed_untracked > 0) owed_untracked -= 1;
            m.closedUntracked();
            g.connClosedUntracked();
        } else if (roll < 68) {
            op = "record";
            const wts = [_]u32{ 0, 1, 1, 2, 3 };
            const w = wts[rnd.uintLessThan(usize, wts.len)];
            m.record(ip, w, now);
            g.record(ip, w);
        } else if (roll < 72) {
            op = "ban";
            m.ban(ip, now);
            g.ban(ip);
        } else if (roll < 75) {
            op = "unban";
            m.unban(ip, now);
            g.unban(ip);
        } else if (roll < 79) {
            op = "greylist";
            const ttl: ?u64 = switch (rnd.uintLessThan(u32, 4)) {
                0 => null,
                1 => 0,
                2 => 1 + rnd.uintLessThan(u64, 4),
                else => cfg.ttl_ms,
            };
            m.greylist(ip, ttl, now);
            g.greylist(ip, ttl);
        } else if (roll < 82) {
            op = "banPrefix";
            const p = pfx_univ[rnd.uintLessThan(usize, pfx_univ.len)];
            const want = m.banPrefix(p);
            if (g.banPrefix(p)) |_| {
                try want;
            } else |err| {
                try testing.expectError(error.TooManyPrefixBans, want);
                try testing.expectEqual(error.TooManyPrefixBans, err);
                reach.too_many_prefix_bans += 1;
            }
        } else if (roll < 85) {
            op = "unbanPrefix";
            const p = pfx_univ[rnd.uintLessThan(usize, pfx_univ.len)];
            const want = m.unbanPrefix(p);
            try testing.expectEqual(want, g.unbanPrefix(p));
            if (want) reach.unban_prefix_true += 1 else reach.unban_prefix_false += 1;
        } else if (roll < 86) {
            op = "unbanAll";
            m.unbanAll();
            g.unbanAll();
        } else if (roll < 88) {
            op = "reconcile";
            const live = rnd.uintLessThan(u32, 4);
            m.reconcile(ip, live);
            g.reconcile(ip, live);
        } else if (roll < 96) {
            op = "advance";
            const dn = cfg.decay_ms * AgModel.ms;
            const tn = cfg.ttl_ms * AgModel.ms;
            var adv: u64 = switch (rnd.uintLessThan(u32, 8)) {
                0 => 0,
                1 => 1,
                2 => AgModel.ms,
                3 => if (dn > 0) dn - 1 + rnd.uintLessThan(u64, 3) else tn,
                4 => tn - 1 + rnd.uintLessThan(u64, 3),
                5 => rnd.uintLessThan(u64, 3 * tn),
                else => 0,
            };
            // aim exactly at (or one ns around) a live deadline or a drain boundary
            if (adv == 0 and m.n > 0) {
                const e = m.ents[rnd.uintLessThan(usize, m.n)];
                const edge: u64 = if (now < e.grey_until and rnd.boolean())
                    e.grey_until
                else if (dn > 0 and e.strikes > 0)
                    e.mark + dn * (1 + rnd.uintLessThan(u64, 3))
                else
                    0;
                if (edge > now) {
                    adv = edge - now - rnd.uintLessThan(u64, 2);
                    if (edge == e.grey_until) reach.grey_expired_at_boundary += 1;
                }
            }
            _ = clk.ns.fetchAdd(adv, .monotonic);
        } else {
            op = "snapshot";
            reach.snapshot_checked += 1;
            if (try agSnapshotCheck(gpa, &g, &m, &univ, &clk, opts, now)) reach.restore_roundtrip += 1;
        }
        try testing.expectEqual(m.nev, sink.n);
        for (m.evs[0..m.nev], sink.evs[0..sink.n]) |want, got| try testing.expect(want.eql(AgEv.of(got)));
        if (m.nev > 0) reach.event_checked += 1;
        m.nev = 0;
        sink.n = 0;
        try agAudit(&g, &m, &univ, clk.ns.load(.monotonic));
    }
}

test "model-fuzz: Guard == naive per-key reference model (300 seeds, injected clock)" {
    const gpa = testing.allocator;
    var reach = AgReach{};
    var seed: u64 = 0;
    while (seed < 300) : (seed += 1) try agCase(gpa, 0xAB05_E6A2_D000 + seed, &reach);
    errdefer std.debug.print("abuseguard model-fuzz reach: {any}\n", .{reach});
    inline for (std.meta.fields(AgReach)) |f| {
        if (@field(reach, f.name) == 0) {
            std.debug.print("abuseguard model-fuzz: reach class never hit: {s}\n", .{f.name});
            return error.ReachClassMissed;
        }
    }
}
