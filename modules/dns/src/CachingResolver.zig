// SPDX-License-Identifier: MIT

//! An answer cache over the high-level lookups of `Resolver` — what c-ares
//! (on by default since 1.31), hickory (`CachingClient`, `ResolverOpts`
//! cache_size and TTL clamps), unbound and systemd-resolved ship, and what
//! every long-running consumer otherwise rebuilds by hand (clamps, serve-stale,
//! failure backoff).
//!
//! ```zig
//! var cache = try dns.CachingResolver.init(gpa, io, .{}, .{ .stale_s = 3600 });
//! defer cache.deinit();
//! var ans = try cache.lookupIp("example.com");
//! defer ans.deinit();                     // ans.lookup is the caller's own copy
//! // ans.source: .network / .cache / .stale; ans.lookup.ttl_s = seconds left
//! ```
//!
//! Policy (every default's source is in SPEC.md § "Caching (CachingResolver)"):
//!
//!  - Key = (lookup kind, name ASCII-lowercased); a trailing root dot stays
//!    part of the key (the Resolver treats a rooted name differently: no
//!    search list). `reverse` keys by the address, `lookupSrv` by all three
//!    arguments.
//!  - Only answers that came from DNS are cached (`canonical != null`). IP
//!    literals, /etc/hosts entries and `.onion`/`.invalid` names pass through
//!    uncached (`source = .network`): the hosts file can change. Literals and
//!    `.onion`/`.invalid` names are answered before any accounting (no budget
//!    token, no pool slot, no `network_lookups`); an /etc/hosts hit is found
//!    out only by asking, so it is refunded afterwards (token and
//!    `network_lookups` given back). A cached `canonical` keeps the letter
//!    case of the caller that filled the entry; a rooted and an unrooted name
//!    are separate entries.
//!  - Positive answers keep `clamp(ttl_s, min_ttl_s, max_ttl_s)`, negative
//!    ones (NXDOMAIN, NODATA; RFC 2308) `clamp(ttl_s, negative_min_ttl_s,
//!    negative_max_ttl_s)`. An answer without a TTL (an empty one without
//!    SOA) keeps `no_ttl_s` as it is, unclamped; 0 = not stored. `lookupIp`
//!    answers marked `partial` are kept at most `partial_ttl_s`.
//!  - Upstream failures (`Timeout`, `ServerFailed`, `NetworkFailed`,
//!    `MalformedResponse`, `DohFailed`, `TlsFailed`) serve an expired entry
//!    still inside `stale_s` (RFC 8767; off by default) and arm a per-key
//!    exponential backoff during which the key is not asked again. The
//!    backoff is per key (a network outage arms every key that was asked);
//!    `MalformedResponse`, which includes an RFC 5452 mismatch, arms it too.
//!    `resetFailures` clears it for a caller that knows the network is back.
//!    A failure of a concurrent miss never arms backoff on an entry that
//!    holds a fresh answer: that answer is served. Evicting an entry drops its
//!    backoff state. `forget`/`forgetReverse`/`forgetSrv` drop one key (answer
//!    and backoff) so its next lookup asks the network; `clear` drops all.
//!  - The serve-stale window counts from EXPIRY (RFC 8767), not from the last
//!    good answer: a key stays servable for `ttl + stale_s` seconds after it was
//!    stored. A caller who wants "keep the last answer N seconds" sets `stale_s`
//!    to N minus the TTL it saw, or simply to N as an upper bound (the answer is
//!    then kept a little longer than N). A stale answer says why in
//!    `Answer.stale_reason`. Negative answers (NXDOMAIN, NODATA) live for the SOA
//!    TTL (RFC 2308), clamped by the `negative_*` options; they get no
//!    doubling backoff (that is only for upstream failures).
//!  - Thread-safe: one `std.Io.Mutex` guards the table and is never held
//!    across a network lookup. The cache owns its `Resolver`s (a `Resolver` is
//!    single-owner): it creates them lazily from the `Resolver.Options` given
//!    to `init`, at most `Options.max_concurrent_lookups` of them, and a miss
//!    takes a free one for the duration of its lookup (waiting, cancelable,
//!    when all are busy). One slow name therefore never blocks a miss on
//!    another. Concurrent misses on the SAME key are coalesced (hickory, unbound):
//!    the first asks the network, the others wait for it (cancelable) and then
//!    read the table it filled — its answer as `.cache`, or its failure through
//!    the usual backoff / serve-stale rules; an outcome that left nothing in the
//!    table (a canceled lead, a non-cacheable answer, a local error) makes each
//!    of them ask itself, in parallel, as without coalescing. `Stats.coalesced`
//!    counts the waits. An answer expires TTL seconds after the moment
//!    the lookup was sent, not after it returned. `lookupIp` order is RFC 6724
//!    as of the lookup time; a hit is re-sorted on the way out (see
//!    `Options.resort_ip_hits`), so a route change shows in the order.
//!  - Memory: everything is under `gpa` (which must be thread-safe: pool
//!    threads allocate concurrently), the table owns clones; an
//!    allocation failure while storing returns the answer uncached.

const std = @import("std");
const builtin = @import("builtin");
const testkit = @import("testkit");
const netaddr = @import("netaddr");
const message = @import("message.zig");
const config = @import("config.zig");
const Resolver = @import("Resolver.zig");
const net = std.Io.net;

const CachingResolver = @This();

gpa: std.mem.Allocator,
io: std.Io,
resolver_options: Resolver.Options,
options: Options,
/// Guards everything from `map` on; never held across a Resolver call.
mutex: std.Io.Mutex = .init,
/// Resolver pool: the free list and creation count, with the condition a miss
/// waits on when `max_concurrent_lookups` Resolvers are all busy.
pool_mutex: std.Io.Mutex = .init,
pool_cond: std.Io.Condition = .init,
free: ?*Slot = null,
all: ?*Slot = null,
created: u16 = 0,
pool_waiters: u32 = 0,
map: std.StringHashMapUnmanaged(*Entry) = .empty,
/// Most / least recently used end of the intrusive list.
head: ?*Entry = null,
tail: ?*Entry = null,
tokens: u32 = 0,
refill_s: u64 = 0,
hits: u64 = 0,
misses: u64 = 0,
stale_served: u64 = 0,
evictions: u64 = 0,
network_lookups: u64 = 0,
budget_refused: u64 = 0,
coalesced: u64 = 0,
prefetches: u64 = 0,
/// Keys with a network lookup in flight (request coalescing), under `mutex`.
inflight: std.StringHashMapUnmanaged(*Flight) = .empty,
/// Misses parked behind an in-flight lookup of their key (a test observable).
flight_waiters: u32 = 0,

/// One network lookup in flight for a key; later misses of that key wait on
/// `cond` (with `mutex`) until the leader sets `done`. Freed by whoever leaves
/// last: the leader when nobody waits, else the last waiter.
const Flight = struct {
    key: []u8,
    cond: std.Io.Condition = .init,
    done: bool = false,
    waiters: u32 = 0,
};

/// The clock seam: seconds on a monotonic scale (only differences matter).
pub const Clock = struct {
    context: ?*anyopaque = null,
    nowFn: *const fn (context: ?*anyopaque) u64,
};

/// A token bucket over network lookups: `burst` at once, `per_s` refilled
/// every second.
pub const Budget = struct { per_s: u32, burst: u32 };

pub const Options = struct {
    /// Table bound; at capacity expired entries go first, then the least
    /// recently used one.
    max_entries: u32 = 4096,
    /// Positive clamp (hickory `positive_min_ttl` / `positive_max_ttl`).
    min_ttl_s: u32 = 0,
    max_ttl_s: u32 = 86_400,
    /// Negative clamp: RFC 2308 §5 allows up to 3 h, c-ares caps at 1 h.
    negative_min_ttl_s: u32 = 0,
    negative_max_ttl_s: u32 = 3600,
    /// An answer whose DNS reply carried no TTL (an empty one without SOA):
    /// kept this long, unclamped; 0 = not cached.
    no_ttl_s: u32 = 0,
    /// `lookupIp` answers with `partial` (one family failed) are kept at most
    /// this long.
    partial_ttl_s: u32 = 30,
    /// RFC 8767 serve-stale window after expiry; 0 = off.
    stale_s: u32 = 0,
    /// RFC 8767 §4: the TTL reported on a stale answer, and the failure
    /// recheck interval for a key served stale.
    stale_answer_ttl_s: u32 = 30,
    /// Per-key backoff after an upstream failure: `min`, doubling, up to
    /// `max`; reset by a success.
    failure_backoff_min_s: u32 = 1,
    failure_backoff_max_s: u32 = 300,
    /// Optional cap on network lookups; a miss over budget is served stale if
    /// possible, else `error.BudgetExceeded`.
    max_network_lookups: ?Budget = null,
    /// Test seam; default = the `Io` awake clock.
    clock: ?Clock = null,
    /// Most `Resolver`s (hence network lookups) in flight at once; created on
    /// demand. A miss beyond that waits for one to be returned. 0 is invalid.
    max_concurrent_lookups: u16 = 8,
    /// Re-order the items of a `lookupIp` hit (`.cache` or `.stale`) with RFC
    /// 6724 destination selection as of NOW, so a hit served after the host's
    /// routes changed does not keep the order of the lookup that filled the
    /// entry. Cost: one route query (a UDP connect, no packet sent) per item
    /// per hit, on the caller's clone after the table mutex is released. `false`
    /// keeps the stored order (that of the filling lookup). A `.network` answer
    /// is sorted by the Resolver itself and is never re-sorted here.
    resort_ip_hits: bool = true,
    /// Source-address probe used by `resort_ip_hits`; a test seam. Null
    /// result = unreachable. Default `netaddr.systemSource` (Linux; elsewhere
    /// a probe that finds no route, i.e. no re-sorting).
    sort_source: *const fn (netaddr.Ip) ?netaddr.Ip = defaultSortSource,
    /// Prefetch (unbound `prefetch`): a hit on an entry with less than this
    /// percentage of its stored TTL left is served from the table and marks
    /// the key due for a refresh, once; `refreshDue` performs the refreshes.
    /// 0 = off (the default), at most 99. No background task: the caller drives
    /// `refreshDue`, e.g. from a timer task on its `Io`.
    prefetch_pct: u8 = 0,
};

fn noSource(_: netaddr.Ip) ?netaddr.Ip {
    return null;
}

const defaultSortSource: *const fn (netaddr.Ip) ?netaddr.Ip =
    if (builtin.os.tag == .linux) &netaddr.systemSource else &noSource;

/// One pooled Resolver (heap-pinned: a Resolver must not move once used).
const Slot = struct {
    resolver: Resolver,
    next_free: ?*Slot = null,
    next_all: ?*Slot = null,
};

pub const Error = Resolver.Error || error{BudgetExceeded};

pub const Source = enum {
    /// Asked the network just now (or a local answer that is never cached).
    network,
    /// Served from the table within its TTL.
    cache,
    /// Served from the table after expiry, inside `stale_s`, because the
    /// network failed, is backed off or is over budget.
    stale,
};

pub fn Answer(comptime T: type) type {
    return struct {
        /// The caller's own copy (free with `deinit`). `ttl_s` is what is
        /// left of the cache TTL: for `.network` the clamped TTL it was stored
        /// with, for `.cache` that minus its age, for `.stale`
        /// `Options.stale_answer_ttl_s`. Literals and hosts answers keep null.
        lookup: Resolver.Lookup(T),
        source: Source,
        /// Set on `.stale`: the error that made the cache serve the expired
        /// answer instead of asking the network: the upstream failure just
        /// seen, the error the key's backoff is holding, or
        /// `error.BudgetExceeded`. Null for `.network` and `.cache`.
        stale_reason: ?Error = null,

        pub fn deinit(a: *@This()) void {
            a.lookup.deinit();
            a.* = undefined;
        }
    };
}

pub const Stats = struct {
    entries: usize,
    hits: u64,
    misses: u64,
    stale_served: u64,
    evictions: u64,
    network_lookups: u64,
    budget_refused: u64,
    /// Misses that waited for a concurrent lookup of the same key instead of
    /// asking the network themselves (request coalescing); a wait that was
    /// canceled counts too. A wait whose lead left nothing in the table
    /// (canceled, not cacheable, a local error) is followed by a network lookup
    /// of its own, uncoalesced and in parallel with the other waiters', and
    /// counts in both.
    coalesced: u64,
    /// Refreshes `refreshDue` attempted (a network lookup, a wait for one, or a
    /// refresh the key's backoff or the budget refused).
    prefetches: u64,
};

const Kind = enum(u8) { ip, reverse, mx, ns, txt, cname, srv };

/// Longest key: kind + two length-prefixed SRV labels + a name.
const key_buf_len = 2 * 256 + 1 + message.max_name_text_len + 16;

const Payload = union(enum) {
    ip: Resolver.Lookup(netaddr.Ip),
    str: Resolver.Lookup([]const u8),
    mx: Resolver.Lookup(Resolver.Mx),
    srv: Resolver.Lookup(Resolver.Srv),

    fn deinit(p: *Payload) void {
        switch (p.*) {
            inline else => |*l| l.deinit(),
        }
    }

    fn of(comptime T: type, p: *Payload) *Resolver.Lookup(T) {
        return switch (T) {
            netaddr.Ip => &p.ip,
            []const u8 => &p.str,
            Resolver.Mx => &p.mx,
            Resolver.Srv => &p.srv,
            else => @compileError("CachingResolver: no payload slot for " ++ @typeName(T)),
        };
    }

    fn from(comptime T: type, lk: Resolver.Lookup(T)) Payload {
        return switch (T) {
            netaddr.Ip => .{ .ip = lk },
            []const u8 => .{ .str = lk },
            Resolver.Mx => .{ .mx = lk },
            Resolver.Srv => .{ .srv = lk },
            else => @compileError("CachingResolver: no payload slot for " ++ @typeName(T)),
        };
    }
};

const Entry = struct {
    /// Owned; also the map key.
    key: []u8,
    prev: ?*Entry = null,
    next: ?*Entry = null,
    /// Null for a key that only carries failure state.
    payload: ?Payload = null,
    /// The TTL it was stored with, and the absolute second it expires.
    stored_ttl: u32 = 0,
    expires_s: u64 = 0,
    /// Consecutive upstream failures; while `now < retry_at_s` the key is not asked.
    fail_count: u8 = 0,
    retry_at_s: u64 = 0,
    last_err: Resolver.Error = error.Timeout,
    /// Marked by a hit late in the TTL (`Options.prefetch_pct`); cleared by
    /// `refreshDue` taking it and by a new answer being stored.
    prefetch_due: bool = false,
};

/// `error.InvalidOptions`: `max_entries` 0, `min_ttl_s` > `max_ttl_s`,
/// `negative_min_ttl_s` > `negative_max_ttl_s`, a zero or inverted backoff,
/// a budget with `per_s` or `burst` 0, `max_concurrent_lookups` 0,
/// `prefetch_pct` over 99. The slices
/// inside `resolver_options` (servers, paths, EDNS options) must outlive the
/// cache. `gpa` must be thread-safe: concurrent lookups allocate from several
/// threads at once (use `std.heap.smp_allocator` or the like, not an unlocked
/// arena or a single-threaded allocator).
pub fn init(gpa: std.mem.Allocator, io: std.Io, resolver_options: Resolver.Options, options: Options) error{InvalidOptions}!CachingResolver {
    const o = options;
    if (o.max_entries == 0) return error.InvalidOptions;
    if (o.min_ttl_s > o.max_ttl_s or o.negative_min_ttl_s > o.negative_max_ttl_s) return error.InvalidOptions;
    if (o.failure_backoff_min_s == 0 or o.failure_backoff_min_s > o.failure_backoff_max_s) return error.InvalidOptions;
    if (o.max_network_lookups) |b| if (b.per_s == 0 or b.burst == 0) return error.InvalidOptions;
    if (o.max_concurrent_lookups == 0) return error.InvalidOptions;
    if (o.prefetch_pct > 99) return error.InvalidOptions;
    var c: CachingResolver = .{ .gpa = gpa, .io = io, .resolver_options = resolver_options, .options = o };
    if (o.max_network_lookups) |b| c.tokens = b.burst;
    c.refill_s = c.now();
    return c;
}

/// Frees every entry and Resolver. No lookup may be running.
pub fn deinit(c: *CachingResolver) void {
    while (c.all) |slot| {
        c.all = slot.next_all;
        slot.resolver.deinit();
        c.gpa.destroy(slot);
    }
    c.removeAll();
    c.map.deinit(c.gpa);
    std.debug.assert(c.inflight.count() == 0); // "no lookup may be running"
    c.inflight.deinit(c.gpa);
    c.* = undefined;
}

/// Drops every entry whose TTL and stale window are over and whose failure
/// backoff has elapsed.
pub fn prune(c: *CachingResolver) void {
    c.mutex.lockUncancelable(c.io);
    defer c.mutex.unlock(c.io);
    const t = c.now();
    var it = c.tail;
    while (it) |e| {
        it = e.prev;
        if (c.dead(e, t)) {
            c.removeEntry(e);
        } else if (e.payload != null and !c.staleUsable(e, t) and t >= e.expires_s) {
            dropPayload(e);
        }
    }
}

/// Clears every key's failure backoff and keeps the answers: for a caller that
/// knows the network came back (a link-up event), so keys are asked again at
/// once instead of at the end of their backoff. Entries that carried nothing
/// but failure state are removed.
pub fn resetFailures(c: *CachingResolver) void {
    c.mutex.lockUncancelable(c.io);
    defer c.mutex.unlock(c.io);
    var it = c.tail;
    while (it) |e| {
        it = e.prev;
        if (e.payload == null) {
            c.removeEntry(e);
        } else {
            e.fail_count = 0;
            e.retry_at_s = 0;
        }
    }
}

/// The lookup kinds keyed by a single name (`reverse` and `lookupSrv` have
/// their own `forget*`).
pub const NameKind = enum { ip, mx, ns, txt, cname };

/// Drops the entry of one key (answer and failure backoff) so its next lookup
/// goes to the network, without touching any other key: for a caller that
/// knows one name's answer is wrong now. No-op when the key is absent. A
/// lookup of the same key already in flight may still store its answer
/// afterwards.
pub fn forget(c: *CachingResolver, kind: NameKind, name: []const u8) void {
    var buf: [key_buf_len]u8 = undefined;
    const k: Kind = switch (kind) {
        .ip => .ip,
        .mx => .mx,
        .ns => .ns,
        .txt => .txt,
        .cname => .cname,
    };
    c.forgetKey(nameKey(&buf, k, name));
}

/// `forget` for `reverse(ip)`.
pub fn forgetReverse(c: *CachingResolver, ip: netaddr.Ip) void {
    var buf: [key_buf_len]u8 = undefined;
    c.forgetKey(reverseKey(&buf, ip));
}

/// `forget` for `lookupSrv(service, proto, name)`.
pub fn forgetSrv(c: *CachingResolver, service: []const u8, proto: []const u8, name: []const u8) void {
    var buf: [key_buf_len]u8 = undefined;
    c.forgetKey(srvKey(&buf, service, proto, name));
}

fn forgetKey(c: *CachingResolver, key: ?[]const u8) void {
    const k = key orelse return; // too long to ever have been cached
    c.mutex.lockUncancelable(c.io);
    defer c.mutex.unlock(c.io);
    if (c.map.get(k)) |e| c.removeEntry(e);
}

/// Drops every entry (answers and failure state alike).
pub fn clear(c: *CachingResolver) void {
    c.mutex.lockUncancelable(c.io);
    defer c.mutex.unlock(c.io);
    c.removeAll();
}

pub fn stats(c: *CachingResolver) Stats {
    c.mutex.lockUncancelable(c.io);
    defer c.mutex.unlock(c.io);
    return .{
        .entries = c.map.count(),
        .hits = c.hits,
        .misses = c.misses,
        .stale_served = c.stale_served,
        .evictions = c.evictions,
        .network_lookups = c.network_lookups,
        .budget_refused = c.budget_refused,
        .coalesced = c.coalesced,
        .prefetches = c.prefetches,
    };
}

// ── lookups ─────────────────────────────────────────────────────────────────

pub fn lookupIp(c: *CachingResolver, name: []const u8) Error!Answer(netaddr.Ip) {
    var buf: [key_buf_len]u8 = undefined;
    return c.run(netaddr.Ip, nameKey(&buf, .ip, name), netaddr.parseIp(name) != null or config.isDnsAvoided(name), name, callIp);
}

pub fn reverse(c: *CachingResolver, ip: netaddr.Ip) Error!Answer([]const u8) {
    var buf: [key_buf_len]u8 = undefined;
    return c.run([]const u8, reverseKey(&buf, ip), false, ip, callReverse);
}

fn reverseKey(buf: *[key_buf_len]u8, ip: netaddr.Ip) []const u8 {
    buf[0] = @backingInt(Kind.reverse);
    return switch (ip) {
        .v4 => |b| blk: {
            buf[1] = 4;
            @memcpy(buf[2..6], &b);
            break :blk buf[0..6];
        },
        .v6 => |b| blk: {
            buf[1] = 6;
            @memcpy(buf[2..18], &b);
            break :blk buf[0..18];
        },
    };
}

pub fn lookupMx(c: *CachingResolver, name: []const u8) Error!Answer(Resolver.Mx) {
    var buf: [key_buf_len]u8 = undefined;
    return c.run(Resolver.Mx, nameKey(&buf, .mx, name), config.isDnsAvoided(name), name, callMx);
}

pub fn lookupNs(c: *CachingResolver, name: []const u8) Error!Answer([]const u8) {
    var buf: [key_buf_len]u8 = undefined;
    return c.run([]const u8, nameKey(&buf, .ns, name), config.isDnsAvoided(name), name, callNs);
}

pub fn lookupTxt(c: *CachingResolver, name: []const u8) Error!Answer([]const u8) {
    var buf: [key_buf_len]u8 = undefined;
    return c.run([]const u8, nameKey(&buf, .txt, name), config.isDnsAvoided(name), name, callTxt);
}

pub fn lookupCname(c: *CachingResolver, name: []const u8) Error!Answer([]const u8) {
    var buf: [key_buf_len]u8 = undefined;
    return c.run([]const u8, nameKey(&buf, .cname, name), config.isDnsAvoided(name), name, callCname);
}

pub fn lookupSrv(c: *CachingResolver, service: []const u8, proto: []const u8, name: []const u8) Error!Answer(Resolver.Srv) {
    var buf: [key_buf_len]u8 = undefined;
    const key = srvKey(&buf, service, proto, name);
    return c.run(Resolver.Srv, key, config.isDnsAvoided(name), SrvArgs{ .service = service, .proto = proto, .name = name }, callSrv);
}

const SrvArgs = struct { service: []const u8, proto: []const u8, name: []const u8 };

/// Refreshes up to `max` keys that `Options.prefetch_pct` marked due, newest
/// use first, each through the normal miss path (so concurrent lookups of the
/// key wait for it, and the budget and backoff apply); returns how many it
/// ran. A refresh that fails keeps the old answer (and arms the backoff as any
/// failure does). The refreshed entry's `canonical` is the key's ASCII
/// lower-case form. Blocking: call it from a task of its own (for example a
/// timer loop on the cache's `Io`) so a lookup never waits behind it.
/// Cancelable: `error.Canceled` stops it between or inside refreshes.
pub fn refreshDue(c: *CachingResolver, max: usize) error{Canceled}!usize {
    var done: usize = 0;
    while (done < max) {
        var buf: [key_buf_len]u8 = undefined;
        const k = c.takeDue(&buf) orelse break;
        done += 1;
        c.mutex.lockUncancelable(c.io);
        c.prefetches += 1;
        c.mutex.unlock(c.io);
        c.refreshKey(k) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => {}, // kept: the old answer, the backoff
        };
    }
    return done;
}

/// The most recently used due key, copied into `buf`, its mark cleared.
fn takeDue(c: *CachingResolver, buf: *[key_buf_len]u8) ?[]const u8 {
    c.mutex.lockUncancelable(c.io);
    defer c.mutex.unlock(c.io);
    var it = c.head;
    while (it) |e| : (it = e.next) {
        if (!e.prefetch_due) continue;
        e.prefetch_due = false;
        @memcpy(buf[0..e.key.len], e.key);
        return buf[0..e.key.len];
    }
    return null;
}

fn refreshKey(c: *CachingResolver, k: []const u8) Error!void {
    const kind: Kind = std.enums.fromInt(Kind, k[0]) orelse return;
    const body = k[1..];
    switch (kind) {
        .ip => try settle(c.runLocked(netaddr.Ip, k, false, true, body, callIp)),
        .mx => try settle(c.runLocked(Resolver.Mx, k, false, true, body, callMx)),
        .ns => try settle(c.runLocked([]const u8, k, false, true, body, callNs)),
        .txt => try settle(c.runLocked([]const u8, k, false, true, body, callTxt)),
        .cname => try settle(c.runLocked([]const u8, k, false, true, body, callCname)),
        .reverse => {
            const ip: netaddr.Ip = switch (body[0]) {
                4 => .{ .v4 = body[1..5].* },
                else => .{ .v6 = body[1..17].* },
            };
            try settle(c.runLocked([]const u8, k, false, true, ip, callReverse));
        },
        .srv => {
            const sl = body[0];
            const service = body[1..][0..sl];
            const pl = body[1 + sl];
            const proto = body[2 + sl ..][0..pl];
            const name = body[2 + sl + pl ..];
            try settle(c.runLocked(Resolver.Srv, k, false, true, SrvArgs{ .service = service, .proto = proto, .name = name }, callSrv));
        },
    }
}

/// A refresh's answer is not wanted (the table has it); only cancelation stops `refreshDue`.
fn settle(r: anytype) error{Canceled}!void {
    if (r) |ans| {
        var a = ans;
        a.deinit();
    } else |err| if (err == error.Canceled) return error.Canceled;
}

/// One `lookupIp` result of `lookupIpMany`: the caller's own answer (free with
/// `deinit`) or the lookup's error.
pub const IpResult = Error!Answer(netaddr.Ip);

/// `lookupIp` for every name at once: the lookups run concurrently on the
/// cache's `Io` (a `std.Io.Group`; the network side is bounded by
/// `max_concurrent_lookups`, the rest wait for a pooled Resolver, and misses
/// of one key coalesce; hits are served at once), `results[i]` for `names[i]`. Every result is
/// set when this returns, also on `error.Canceled` (a lookup that was cut short
/// holds `error.Canceled`); the caller frees each answer.
/// `error.LengthMismatch`: `results.len != names.len` (nothing was looked up).
/// The c-ares / hickory "many queries in flight" use; a single lookup can be
/// made concurrent the same way with `io.async(CachingResolver.lookupIp, ...)`.
pub fn lookupIpMany(c: *CachingResolver, names: []const []const u8, results: []IpResult) error{ Canceled, LengthMismatch }!void {
    if (names.len != results.len) return error.LengthMismatch;
    for (results) |*r| r.* = error.Canceled;
    var g: std.Io.Group = .init;
    for (names, results) |n, *r| g.async(c.io, manyOne, .{ c, n, r });
    try g.await(c.io);
}

fn manyOne(c: *CachingResolver, name: []const u8, out: *IpResult) void {
    out.* = c.lookupIp(name);
}

fn dropAnswer(r: anytype) void {
    if (r) |ans| {
        var a = ans;
        a.deinit();
    } else |_| {}
}

fn callIp(r: *Resolver, name: []const u8) Resolver.Error!Resolver.Lookup(netaddr.Ip) {
    return r.lookupIp(name);
}
fn callReverse(r: *Resolver, ip: netaddr.Ip) Resolver.Error!Resolver.Lookup([]const u8) {
    return r.reverse(ip);
}
fn callMx(r: *Resolver, name: []const u8) Resolver.Error!Resolver.Lookup(Resolver.Mx) {
    return r.lookupMx(name);
}
fn callNs(r: *Resolver, name: []const u8) Resolver.Error!Resolver.Lookup([]const u8) {
    return r.lookupNs(name);
}
fn callTxt(r: *Resolver, name: []const u8) Resolver.Error!Resolver.Lookup([]const u8) {
    return r.lookupTxt(name);
}
fn callCname(r: *Resolver, name: []const u8) Resolver.Error!Resolver.Lookup([]const u8) {
    return r.lookupCname(name);
}
fn callSrv(r: *Resolver, a: SrvArgs) Resolver.Error!Resolver.Lookup(Resolver.Srv) {
    return r.lookupSrv(a.service, a.proto, a.name);
}

/// Kind byte + the name with ASCII case folded (RFC 4343); null when it does
/// not fit (the Resolver then answers with its own error, nothing is cached).
fn nameKey(buf: *[key_buf_len]u8, kind: Kind, name: []const u8) ?[]const u8 {
    if (name.len + 1 > buf.len) return null;
    buf[0] = @backingInt(kind);
    for (name, buf[1..][0..name.len]) |ch, *o| o.* = std.ascii.toLower(ch);
    return buf[0 .. 1 + name.len];
}

fn srvKey(buf: *[key_buf_len]u8, service: []const u8, proto: []const u8, name: []const u8) ?[]const u8 {
    if (service.len > 255 or proto.len > 255) return null;
    if (3 + service.len + proto.len + name.len > buf.len) return null;
    var n: usize = 0;
    buf[n] = @backingInt(Kind.srv);
    n += 1;
    for ([_][]const u8{ service, proto }) |part| {
        buf[n] = @intCast(part.len);
        n += 1;
        for (part, buf[n..][0..part.len]) |ch, *o| o.* = std.ascii.toLower(ch);
        n += part.len;
    }
    for (name, buf[n..][0..name.len]) |ch, *o| o.* = std.ascii.toLower(ch);
    return buf[0 .. n + name.len];
}

// ── the cache logic ─────────────────────────────────────────────────────────

fn run(
    c: *CachingResolver,
    comptime T: type,
    key: ?[]const u8,
    /// An IP literal or a DNS-avoided name: answered before any accounting.
    local: bool,
    ctx: anytype,
    comptime call: fn (*Resolver, @TypeOf(ctx)) Resolver.Error!Resolver.Lookup(T),
) Error!Answer(T) {
    const ans = try c.runLocked(T, key, local, false, ctx, call);
    // The table mutex is released by now: the clone is the caller's own, so
    // sorting it (route queries) never holds the table.
    if (T == netaddr.Ip and c.options.resort_ip_hits and ans.source != .network) {
        const items: []netaddr.Ip = @constCast(ans.lookup.items); // the clone's arena memory
        netaddr.sortDestinations(items, c.options.sort_source) catch {}; // too many candidates: order kept
    }
    return ans;
}

fn runLocked(
    c: *CachingResolver,
    comptime T: type,
    key: ?[]const u8,
    local: bool,
    /// A `refreshDue` refresh: a fresh entry is no hit, and the miss is not counted.
    refresh: bool,
    ctx: anytype,
    comptime call: fn (*Resolver, @TypeOf(ctx)) Resolver.Error!Resolver.Lookup(T),
) Error!Answer(T) {
    const io = c.io;
    if (local) return c.bypassLocal(T, ctx, call);
    const k = key orelse return c.bypass(T, ctx, call);

    c.mutex.lockUncancelable(io);
    var held = true;
    defer if (held) c.mutex.unlock(io);

    var counted = refresh;
    var force = refresh;
    // Set once this miss has waited for a lead: if the table still has nothing for it, it asks the network
    // itself, uncoalesced, instead of queueing behind the next waiter's lookup (which would serialise them).
    var waited = false;
    while (true) {
        const t0 = c.now();
        var entry: ?*Entry = c.map.get(k);
        if (entry) |e| {
            c.touch(e);
            if (e.payload != null and t0 < e.expires_s and !force) {
                const left = e.expires_s - t0;
                const ans = try c.answerFrom(T, e, .cache, @min(left, e.stored_ttl));
                if (!counted) c.hits += 1;
                const pct = c.options.prefetch_pct;
                if (pct != 0 and !e.prefetch_due and @as(u64, left) * 100 < @as(u64, pct) * e.stored_ttl) e.prefetch_due = true;
                return ans;
            }
            if (e.payload != null and !c.staleUsable(e, t0)) {
                dropPayload(e);
                if (e.fail_count == 0) {
                    c.removeEntry(e);
                    entry = null;
                }
            }
        }
        if (!counted) c.misses += 1;
        counted = true;
        const stale_entry: ?*Entry = if (entry) |e| (if (c.staleUsable(e, t0)) e else null) else null;
        if (entry) |e| {
            if (e.fail_count > 0 and t0 < e.retry_at_s) {
                if (refresh) return e.last_err; // nobody reads a refresh's answer: no stale clone, no stale count
                if (stale_entry) |s| return c.staleAnswer(T, s, e.last_err);
                return e.last_err;
            }
        }
        // Another task is asking the network for this key: wait for it, then read the table again.
        if (!waited) if (c.inflight.get(k)) |f| {
            c.coalesced += 1;
            f.waiters += 1;
            c.flight_waiters += 1;
            var wait_err: ?std.Io.Cancelable = null;
            while (!f.done) f.cond.wait(io, &c.mutex) catch |err| {
                wait_err = err;
                break;
            };
            f.waiters -= 1;
            c.flight_waiters -= 1;
            if (f.done and f.waiters == 0) c.destroyFlight(f);
            if (wait_err) |err| return err;
            force = false; // what the lead stored is the refresh
            waited = true;
            continue;
        };
        if (c.options.max_network_lookups) |b| {
            if (!c.takeToken(b, t0)) {
                c.budget_refused += 1;
                if (refresh) return error.BudgetExceeded;
                if (stale_entry) |s| return c.staleAnswer(T, s, error.BudgetExceeded);
                return error.BudgetExceeded;
            }
        }
        break;
    }
    c.network_lookups += 1;
    // Lead the lookup; without memory for the record it simply goes uncoalesced.
    const flight: ?*Flight = if (waited) null else c.startFlight(k);
    defer if (flight) |f| c.endFlight(f); // `mutex` is held again on every return below
    c.mutex.unlock(io);
    held = false;

    const slot = c.acquire() catch |err| {
        // Never reached the network: give the token and the count back.
        c.mutex.lockUncancelable(io);
        held = true;
        c.refundLocked();
        return err;
    };
    // The TTL runs from the moment the query is sent: an answer never outlives
    // its TTL by the lookup's duration.
    const t_call = c.now();
    const res = call(&slot.resolver, ctx);
    c.release(slot);

    c.mutex.lockUncancelable(io);
    held = true;
    const t1 = c.now();
    var lk = res catch |err| return c.failed(T, k, err, t1, refresh);
    return c.succeeded(T, k, &lk, t_call);
}

/// Registers this miss as the key's network lookup. Called with `mutex` held.
fn startFlight(c: *CachingResolver, k: []const u8) ?*Flight {
    const f = c.gpa.create(Flight) catch return null;
    const key = c.gpa.dupe(u8, k) catch {
        c.gpa.destroy(f);
        return null;
    };
    f.* = .{ .key = key };
    c.inflight.put(c.gpa, key, f) catch {
        c.gpa.free(key);
        c.gpa.destroy(f);
        return null;
    };
    return f;
}

/// The leader's outcome is in the table: wake the waiters. Called with `mutex` held.
fn endFlight(c: *CachingResolver, f: *Flight) void {
    _ = c.inflight.remove(f.key);
    f.done = true;
    if (f.waiters == 0) {
        c.destroyFlight(f);
    } else {
        f.cond.broadcast(c.io);
    }
}

fn destroyFlight(c: *CachingResolver, f: *Flight) void {
    c.gpa.free(f.key);
    c.gpa.destroy(f);
}

/// Gives back what a lookup took that turned out not to reach the network.
/// Called with `mutex` held.
fn refundLocked(c: *CachingResolver) void {
    c.network_lookups -|= 1;
    if (c.options.max_network_lookups) |b| c.tokens = @min(b.burst, c.tokens +| 1);
}

/// An IP literal or a DNS-avoided name: no budget token, no pool slot, no
/// statistic. A throwaway Resolver, so it never waits behind a slow lookup.
fn bypassLocal(
    c: *CachingResolver,
    comptime T: type,
    ctx: anytype,
    comptime call: fn (*Resolver, @TypeOf(ctx)) Resolver.Error!Resolver.Lookup(T),
) Error!Answer(T) {
    var r = Resolver.init(c.io, c.gpa, c.resolver_options);
    defer r.deinit();
    return .{ .lookup = try call(&r, ctx), .source = .network };
}

/// A key that does not fit the key buffer: straight to the resolver.
fn bypass(
    c: *CachingResolver,
    comptime T: type,
    ctx: anytype,
    comptime call: fn (*Resolver, @TypeOf(ctx)) Resolver.Error!Resolver.Lookup(T),
) Error!Answer(T) {
    // Counted only once a Resolver is held: a failed `acquire` (Canceled,
    // OutOfMemory) sent nothing (review F5, here as in the cached path).
    // Like the cached path, an answer that did not come from DNS
    // (`canonical == null`: /etc/hosts, a name the Resolver refused locally)
    // is not a network lookup. No budget token is taken here to give back.
    const slot = try c.acquire();
    defer c.release(slot);
    const lk = try call(&slot.resolver, ctx);
    if (lk.canonical != null) {
        c.mutex.lockUncancelable(c.io);
        c.network_lookups += 1;
        c.mutex.unlock(c.io);
    }
    return .{ .lookup = lk, .source = .network };
}

/// A free pooled Resolver, a new one while fewer than `max_concurrent_lookups`
/// exist, else wait (cancelable) for one to come back. `mutex` must not be held.
fn acquire(c: *CachingResolver) Error!*Slot {
    const io = c.io;
    try c.pool_mutex.lock(io);
    while (true) {
        if (c.free) |s| {
            c.free = s.next_free;
            s.next_free = null;
            c.pool_mutex.unlock(io);
            return s;
        }
        if (c.created < c.options.max_concurrent_lookups) {
            c.created += 1; // reserved; the allocation happens outside the lock
            c.pool_mutex.unlock(io);
            const s = c.gpa.create(Slot) catch {
                c.pool_mutex.lockUncancelable(io);
                c.created -= 1;
                c.pool_cond.signal(io);
                c.pool_mutex.unlock(io);
                return error.OutOfMemory;
            };
            s.* = .{ .resolver = Resolver.init(io, c.gpa, c.resolver_options) };
            c.pool_mutex.lockUncancelable(io);
            s.next_all = c.all;
            c.all = s;
            c.pool_mutex.unlock(io);
            return s;
        }
        c.pool_waiters += 1;
        c.pool_cond.wait(io, &c.pool_mutex) catch |err| {
            c.pool_waiters -= 1;
            c.pool_mutex.unlock(io); // `wait` returns with the mutex held
            return err;
        };
        c.pool_waiters -= 1;
    }
}

fn release(c: *CachingResolver, s: *Slot) void {
    c.pool_mutex.lockUncancelable(c.io);
    s.next_free = c.free;
    c.free = s;
    c.pool_cond.signal(c.io);
    c.pool_mutex.unlock(c.io);
}

/// Called with `mutex` held. An upstream failure arms the key's backoff and
/// serves what is still allowed to be served.
fn failed(c: *CachingResolver, comptime T: type, k: []const u8, err: Resolver.Error, t: u64, refresh: bool) Error!Answer(T) {
    if (isLocalRefusal(err)) {
        // Refused before anything was sent: not a network lookup, and the
        // budget token goes back (the `bypass` path never counted these).
        c.refundLocked();
        return err;
    }
    if (!isUpstreamFailure(err)) return err;
    if (refresh) {
        // A prefetch refresh failed: the old answer stays (fresh hits ignore the failure state), but the key's
        // backoff is armed, so the next refresh of a dead upstream waits for it instead of retrying at once.
        const e = c.map.get(k) orelse return err;
        e.fail_count +|= 1;
        e.last_err = err;
        e.retry_at_s = t +| c.backoffDelay(e.fail_count);
        return err;
    }
    // A concurrent miss of the same key may have stored a fresh answer while
    // this lookup was failing: serve it, and leave the failure state alone.
    if (c.map.get(k)) |cur| {
        if (cur.payload != null and t < cur.expires_s) {
            c.touch(cur);
            return c.answerFrom(T, cur, .cache, @min(cur.expires_s -| t, cur.stored_ttl));
        }
    }
    const e = c.failureEntry(k) orelse return err;
    e.fail_count +|= 1;
    e.last_err = err;
    var delay = c.backoffDelay(e.fail_count);
    const stale_ok = c.staleUsable(e, t);
    if (stale_ok) delay = @max(delay, c.options.stale_answer_ttl_s);
    e.retry_at_s = t +| delay;
    if (stale_ok) return c.staleAnswer(T, e, err);
    return err;
}

/// Called with `mutex` held. Applies the TTL policy and keeps a clone.
fn succeeded(c: *CachingResolver, comptime T: type, k: []const u8, lk: *Resolver.Lookup(T), t: u64) Answer(T) {
    if (lk.canonical == null) {
        // /etc/hosts (literals never get here): never cached, and it did not
        // use the network.
        c.refundLocked();
        return .{ .lookup = lk.*, .source = .network };
    }
    const ttl = c.effectiveTtl(lk.status, lk.ttl_s, lk.partial);
    lk.ttl_s = ttl;
    if (ttl == 0) {
        if (c.map.get(k)) |e| c.removeEntry(e); // supersedes whatever was there
    } else {
        c.store(T, k, lk, t, ttl);
    }
    return .{ .lookup = lk.*, .source = .network };
}

fn store(c: *CachingResolver, comptime T: type, k: []const u8, lk: *const Resolver.Lookup(T), t: u64, ttl: u32) void {
    var copy = lk.clone(c.gpa) catch return; // OOM: the answer is still returned, just not cached
    const e = c.map.get(k) orelse c.insertEntry(k) catch {
        copy.deinit();
        return;
    };
    c.touch(e);
    if (e.payload) |*p| p.deinit();
    e.payload = Payload.from(T, copy);
    e.stored_ttl = ttl;
    e.expires_s = t +| ttl;
    e.fail_count = 0;
    e.retry_at_s = 0;
    e.prefetch_due = false;
}

fn answerFrom(c: *CachingResolver, comptime T: type, e: *Entry, source: Source, ttl: u32) error{OutOfMemory}!Answer(T) {
    var lk = try Payload.of(T, &e.payload.?).clone(c.gpa);
    lk.ttl_s = ttl;
    return .{ .lookup = lk, .source = source };
}

fn staleAnswer(c: *CachingResolver, comptime T: type, e: *Entry, reason: Error) error{OutOfMemory}!Answer(T) {
    var a = try c.answerFrom(T, e, .stale, c.options.stale_answer_ttl_s);
    a.stale_reason = reason;
    c.stale_served += 1;
    return a;
}

/// Errors the Resolver returns before sending a query: the name or the
/// options cannot become one. OutOfMemory and Canceled are not here: either
/// can come after a query went out.
fn isLocalRefusal(err: Resolver.Error) bool {
    return switch (err) {
        error.NameTooLong, error.BadName, error.RequestTooLarge, error.InvalidOptions, error.NoDotSupport, error.NoDohEndpoint => true,
        else => false,
    };
}

fn isUpstreamFailure(err: Resolver.Error) bool {
    return switch (err) {
        error.Timeout, error.ServerFailed, error.NetworkFailed, error.MalformedResponse, error.DohFailed, error.TlsFailed => true,
        else => false,
    };
}

fn effectiveTtl(c: *const CachingResolver, status: Resolver.Status, ttl: ?u32, partial: bool) u32 {
    const o = c.options;
    var t: u32 = if (ttl) |v| switch (status) {
        .found => @max(o.min_ttl_s, @min(v, o.max_ttl_s)),
        .nxdomain, .nodata => @max(o.negative_min_ttl_s, @min(v, o.negative_max_ttl_s)),
    } else o.no_ttl_s;
    if (partial) t = @min(t, o.partial_ttl_s);
    return t;
}

fn backoffDelay(c: *const CachingResolver, fails: u8) u32 {
    const shift: u6 = @intCast(@min(@as(u8, 31), fails -| 1));
    const d: u64 = @as(u64, c.options.failure_backoff_min_s) << shift;
    return @intCast(@min(d, c.options.failure_backoff_max_s));
}

/// Expired, but inside the serve-stale window.
fn staleUsable(c: *const CachingResolver, e: *const Entry, t: u64) bool {
    return e.payload != null and t < e.expires_s +| c.options.stale_s;
}

/// Nothing left worth keeping: no servable answer and no active backoff.
fn dead(c: *const CachingResolver, e: *const Entry, t: u64) bool {
    return !c.staleUsable(e, t) and t >= e.expires_s and (e.fail_count == 0 or t >= e.retry_at_s);
}

fn takeToken(c: *CachingResolver, b: Budget, t: u64) bool {
    if (t < c.refill_s) {
        c.refill_s = t; // the clock went backwards: re-anchor, no refill
    } else {
        const add = (t - c.refill_s) *| b.per_s;
        c.tokens = @intCast(@min(@as(u64, b.burst), @as(u64, c.tokens) +| add));
        c.refill_s = t;
    }
    if (c.tokens == 0) return false;
    c.tokens -= 1;
    return true;
}

fn now(c: *CachingResolver) u64 {
    if (c.options.clock) |ck| return ck.nowFn(ck.context);
    const s = std.Io.Clock.awake.now(c.io).toSeconds();
    return if (s < 0) 0 else @intCast(s);
}

// ── table plumbing (all with `mutex` held) ──────────────────────────────────

fn failureEntry(c: *CachingResolver, k: []const u8) ?*Entry {
    if (c.map.get(k)) |e| return e;
    return c.insertEntry(k) catch null;
}

fn insertEntry(c: *CachingResolver, k: []const u8) error{OutOfMemory}!*Entry {
    c.makeRoom();
    const e = try c.gpa.create(Entry);
    errdefer c.gpa.destroy(e);
    const key = try c.gpa.dupe(u8, k);
    errdefer c.gpa.free(key);
    e.* = .{ .key = key };
    try c.map.put(c.gpa, key, e);
    c.pushFront(e);
    return e;
}

/// At capacity: an expired entry among the 16 least recently used goes first
/// (not an eviction), else the least recently used one.
fn makeRoom(c: *CachingResolver) void {
    if (c.map.count() < c.options.max_entries) return;
    const t = c.now();
    var it = c.tail;
    var scanned: usize = 0;
    while (it) |e| : (scanned += 1) {
        if (scanned >= 16) break;
        if (c.dead(e, t)) {
            c.removeEntry(e);
            return;
        }
        it = e.prev;
    }
    if (c.tail) |victim| {
        c.removeEntry(victim);
        c.evictions += 1;
    }
}

fn dropPayload(e: *Entry) void {
    if (e.payload) |*p| p.deinit();
    e.payload = null;
    e.stored_ttl = 0;
}

fn removeEntry(c: *CachingResolver, e: *Entry) void {
    c.unlink(e);
    _ = c.map.remove(e.key);
    if (e.payload) |*p| p.deinit();
    c.gpa.free(e.key);
    c.gpa.destroy(e);
}

fn removeAll(c: *CachingResolver) void {
    while (c.tail) |e| c.removeEntry(e);
}

fn unlink(c: *CachingResolver, e: *Entry) void {
    if (e.prev) |p| p.next = e.next else c.head = e.next;
    if (e.next) |n| n.prev = e.prev else c.tail = e.prev;
    e.prev = null;
    e.next = null;
}

fn pushFront(c: *CachingResolver, e: *Entry) void {
    e.prev = null;
    e.next = c.head;
    if (c.head) |h| h.prev = e else c.tail = e;
    c.head = e;
}

fn touch(c: *CachingResolver, e: *Entry) void {
    if (c.head == e) return;
    c.unlink(e);
    c.pushFront(e);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

const Mode = enum(u8) { answer, nxdomain_soa, nodata_soa, nxdomain_nosoa, servfail, silent };

fn putName(w: *std.Io.Writer, name: []const u8) !void {
    var it = std.mem.splitScalar(u8, name, '.');
    while (it.next()) |label| {
        if (label.len == 0) continue;
        try w.writeByte(@intCast(label.len));
        try w.writeAll(label);
    }
    try w.writeByte(0);
}

/// A resource record; `owner` null = a pointer to the question name.
fn putRr(w: *std.Io.Writer, owner: ?[]const u8, ty: u16, ttl: u32, rdata: []const u8) !void {
    if (owner) |o| try putName(w, o) else try w.writeAll("\xc0\x0c");
    try w.writeInt(u16, ty, .big);
    try w.writeInt(u16, 1, .big);
    try w.writeInt(u32, ttl, .big);
    try w.writeInt(u16, @intCast(rdata.len), .big);
    try w.writeAll(rdata);
}

/// A loopback UDP server the tests steer: it counts every datagram it
/// receives (before replying), and answers the common types with `ttl`.
const Stub = struct {
    io: std.Io,
    sock: net.Socket,
    stop: std.atomic.Value(bool) = .init(false),
    queries: std.atomic.Value(u32) = .init(0),
    mode: std.atomic.Value(Mode) = .init(.answer),
    ttl: std.atomic.Value(u32) = .init(60),
    drop_aaaa: std.atomic.Value(bool) = .init(false),
    /// The answer to a name starting with "slow" is held back until
    /// `release_slow` is set: `stashed` says it is being held.
    stashed: std.atomic.Value(bool) = .init(false),
    release_slow: std.atomic.Value(bool) = .init(false),
    /// Queries asked for exactly `_sip._tcp.example.com` (the wire name, case-blind).
    sip_queries: std.atomic.Value(u32) = .init(0),
    /// When set, the clock advances by `bump_by` as the answer is sent.
    bump_clock: ?*TestClock = null,
    bump_by: std.atomic.Value(u32) = .init(0),
    pending: [1024]u8 = undefined,
    pending_len: usize = 0,
    pending_to: net.IpAddress = undefined,

    fn run(st: *Stub) void {
        var rbuf: [message.max_query_len]u8 = undefined;
        while (!st.stop.load(.acquire)) {
            if (st.stashed.load(.acquire) and st.release_slow.load(.acquire)) {
                st.sock.send(st.io, &st.pending_to, st.pending[0..st.pending_len]) catch return;
                st.stashed.store(false, .release);
            }
            const t: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(20), .clock = .awake } };
            const incoming = st.sock.receiveTimeout(st.io, &rbuf, t.toDeadline(st.io)) catch |err| switch (err) {
                error.Timeout => continue,
                else => return,
            };
            st.serve(incoming) catch return;
        }
    }

    fn serve(st: *Stub, in: net.IncomingMessage) !void {
        const q = in.data;
        _ = st.queries.fetchAdd(1, .acq_rel);
        const mode = st.mode.load(.acquire);
        if (mode == .silent or q.len < 17) return;
        var i: usize = 12;
        while (i < q.len and q[i] != 0) i += @as(usize, q[i]) + 1;
        if (i + 5 > q.len) return;
        const qtype = std.mem.readInt(u16, q[i + 1 ..][0..2], .big);
        if (qtype == 28 and st.drop_aaaa.load(.acquire)) return;
        if (std.ascii.eqlIgnoreCase(q[12 .. i + 1], "\x04_sip\x04_tcp\x07example\x03com\x00")) _ = st.sip_queries.fetchAdd(1, .acq_rel);
        const ttl = st.ttl.load(.acquire);
        const alias = q.len > 18 and std.ascii.eqlIgnoreCase(q[13..][0..@min(@as(usize, q[12]), 5)], "alias");

        var rd: [300]u8 = undefined;
        var rw: std.Io.Writer = .fixed(&rd);
        var an: [600]u8 = undefined;
        var aw: std.Io.Writer = .fixed(&an);
        var ancount: u16 = 0;
        if (mode == .answer) {
            if (alias and qtype == 1) {
                try putName(&rw, "real.example.com");
                try putRr(&aw, null, 5, ttl, rw.buffered());
                rw = .fixed(&rd);
                try putRr(&aw, "real.example.com", 1, ttl, &.{ 192, 0, 2, 7 });
                ancount = 2;
            } else {
                switch (qtype) {
                    1 => try rw.writeAll(&.{ 192, 0, 2, 1 }),
                    28 => try rw.writeAll(&.{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }),
                    12 => try putName(&rw, "host.example.com"),
                    15 => {
                        try rw.writeInt(u16, 10, .big);
                        try putName(&rw, "mail.example.com");
                    },
                    2 => try putName(&rw, "ns1.example.com"),
                    16 => {
                        try rw.writeByte(11);
                        try rw.writeAll("v=spf1 -all");
                    },
                    33 => {
                        try rw.writeInt(u16, 1, .big);
                        try rw.writeInt(u16, 2, .big);
                        try rw.writeInt(u16, 5060, .big);
                        try putName(&rw, "sip.example.com");
                    },
                    else => {},
                }
                if (rw.buffered().len > 0) {
                    try putRr(&aw, null, qtype, ttl, rw.buffered());
                    ancount = 1;
                }
            }
        }
        var soa: [200]u8 = undefined;
        var sw: std.Io.Writer = .fixed(&soa);
        var nscount: u16 = 0;
        if (mode == .nxdomain_soa or mode == .nodata_soa) {
            var sd: [150]u8 = undefined;
            var sdw: std.Io.Writer = .fixed(&sd);
            try putName(&sdw, "ns1.example.com");
            try putName(&sdw, "hostmaster.example.com");
            for ([_]u32{ 1, 3600, 600, 86400, ttl }) |v| try sdw.writeInt(u32, v, .big);
            try putRr(&sw, "example.com", 6, ttl, sdw.buffered());
            nscount = 1;
        }

        var out: [1024]u8 = undefined;
        var w: std.Io.Writer = .fixed(&out);
        try w.writeAll(q[0..2]);
        const flags: u16 = switch (mode) {
            .nxdomain_soa, .nxdomain_nosoa => 0x8183,
            .servfail => 0x8182,
            else => 0x8180,
        };
        try w.writeInt(u16, flags, .big);
        try w.writeInt(u16, 1, .big);
        try w.writeInt(u16, ancount, .big);
        try w.writeInt(u16, nscount, .big);
        try w.writeInt(u16, 0, .big);
        try w.writeAll(q[12 .. i + 5]);
        try w.writeAll(aw.buffered());
        try w.writeAll(sw.buffered());
        if (q[12] == 4 and std.ascii.eqlIgnoreCase(q[13..17], "slow")) {
            @memcpy(st.pending[0..w.buffered().len], w.buffered());
            st.pending_len = w.buffered().len;
            st.pending_to = in.from;
            st.stashed.store(true, .release);
            return;
        }
        if (st.bump_clock) |ck| ck.add(st.bump_by.load(.acquire));
        try st.sock.send(st.io, &in.from, w.buffered());
    }
};

const TestClock = struct {
    now: u64 = 1000,

    /// 64-bit atomics where the target has them. A 32-bit target without
    /// them (mips32) only COMPILES these tests (`check-portable` runs no
    /// binary), so a plain access there is never executed.
    const atomic64 = @bitSizeOf(usize) >= 64;

    fn read(ctx: ?*anyopaque) u64 {
        const s: *TestClock = @ptrCast(@alignCast(ctx.?));
        return if (atomic64) @atomicLoad(u64, &s.now, .monotonic) else s.now;
    }

    fn add(s: *TestClock, by: u64) void {
        if (atomic64) _ = @atomicRmw(u64, &s.now, .Add, by, .monotonic) else s.now += by;
    }

    fn clock(s: *TestClock) Clock {
        return .{ .context = s, .nowFn = read };
    }
};

const loopback_servers = [_]netaddr.Ip{.{ .v4 = .{ 127, 0, 0, 1 } }};

/// Pinned on the test's stack (the `Io` points into it).
const Harness = struct {
    threaded: std.Io.Threaded = undefined,
    io: std.Io = undefined,
    stub: Stub = undefined,
    fut: std.Io.Future(void) = undefined,
    ropts: Resolver.Options = undefined,
    clock: TestClock = .{},
    timeout_ms: u32 = 150,

    fn start(h: *Harness, family: Resolver.Family) !void {
        h.threaded = .init(testing.allocator, .{});
        h.io = h.threaded.io();
        const addr: net.IpAddress = .{ .ip4 = .loopback(0) };
        const sock = addr.bind(h.io, .{ .mode = .dgram }) catch |err| {
            h.threaded.deinit();
            return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
        };
        h.stub = .{ .io = h.io, .sock = sock };
        h.fut = h.io.concurrent(Stub.run, .{&h.stub}) catch |err| {
            sock.close(h.io);
            h.threaded.deinit();
            return err;
        };
        h.ropts = .{
            .servers = &loopback_servers,
            .port = sock.address.getPort(),
            .timeout_ms = h.timeout_ms,
            .attempts = 1,
            .use_hosts = false,
            .use_search = false,
            .family = family,
            .parallel_families = false,
        };
    }

    fn stop(h: *Harness) void {
        h.stub.stop.store(true, .release);
        h.fut.await(h.io);
        h.stub.sock.close(h.io);
        h.threaded.deinit();
    }

    fn cache(h: *Harness, options: Options) !CachingResolver {
        var o = options;
        o.clock = h.clock.clock();
        return CachingResolver.init(testing.allocator, h.io, h.ropts, o);
    }

    fn queries(h: *Harness) u32 {
        return h.stub.queries.load(.acquire);
    }
};

fn expectIp(a: *const Answer(netaddr.Ip), source: Source, ttl: ?u32) !void {
    try testing.expectEqual(source, a.source);
    try testing.expectEqual(ttl, a.lookup.ttl_s);
}

test "hit within the TTL answers without a query and ages ttl_s; expiry asks again" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    h.stub.ttl.store(60, .release);
    var c = try h.cache(.{});
    defer c.deinit();

    var a1 = try c.lookupIp("host.example.com");
    defer a1.deinit();
    try expectIp(&a1, .network, 60);
    try testing.expectEqual(@as(usize, 1), a1.lookup.items.len);
    try testing.expectEqual(@as(u32, 1), h.queries());

    h.clock.now += 10;
    var a2 = try c.lookupIp("host.example.com");
    defer a2.deinit();
    try expectIp(&a2, .cache, 50);
    try testing.expectEqual(@as(usize, 1), a2.lookup.items.len);
    try testing.expectEqualStrings("host.example.com", a2.lookup.canonical.?);
    try testing.expectEqual(@as(u32, 1), h.queries());

    h.clock.now += 49; // 59 s old: still inside
    var a3 = try c.lookupIp("host.example.com");
    defer a3.deinit();
    try expectIp(&a3, .cache, 1);

    h.clock.now += 1; // 60 s: expired
    var a4 = try c.lookupIp("host.example.com");
    defer a4.deinit();
    try expectIp(&a4, .network, 60);
    try testing.expectEqual(@as(u32, 2), h.queries());

    const s = c.stats();
    try testing.expectEqual(@as(u64, 2), s.hits);
    try testing.expectEqual(@as(u64, 2), s.misses);
    try testing.expectEqual(@as(u64, 2), s.network_lookups);
    try testing.expectEqual(@as(usize, 1), s.entries);
}

test "positive max and min clamp" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .min_ttl_s = 100, .max_ttl_s = 300 });
    defer c.deinit();

    h.stub.ttl.store(3600, .release);
    var big = try c.lookupIp("big.example.com");
    defer big.deinit();
    try expectIp(&big, .network, 300);
    h.clock.now += 299;
    var big2 = try c.lookupIp("big.example.com");
    defer big2.deinit();
    try expectIp(&big2, .cache, 1);
    h.clock.now += 1;
    var big3 = try c.lookupIp("big.example.com");
    defer big3.deinit();
    try expectIp(&big3, .network, 300);

    h.stub.ttl.store(5, .release);
    var small = try c.lookupIp("small.example.com");
    defer small.deinit();
    try expectIp(&small, .network, 100);
    h.clock.now += 50;
    var small2 = try c.lookupIp("small.example.com");
    defer small2.deinit();
    try expectIp(&small2, .cache, 50);
}

test "negative caching: NXDOMAIN and NODATA, with their clamps" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .negative_min_ttl_s = 20, .negative_max_ttl_s = 60 });
    defer c.deinit();

    h.stub.mode.store(.nxdomain_soa, .release);
    h.stub.ttl.store(3600, .release);
    var nx = try c.lookupIp("gone.example.com");
    defer nx.deinit();
    try testing.expectEqual(Resolver.Status.nxdomain, nx.lookup.status);
    try expectIp(&nx, .network, 60); // capped
    h.clock.now += 30;
    var nx2 = try c.lookupIp("gone.example.com");
    defer nx2.deinit();
    try testing.expectEqual(Resolver.Status.nxdomain, nx2.lookup.status);
    try expectIp(&nx2, .cache, 30);
    try testing.expectEqual(@as(u32, 1), h.queries());
    h.clock.now += 30;
    var nx3 = try c.lookupIp("gone.example.com");
    defer nx3.deinit();
    try expectIp(&nx3, .network, 60);
    try testing.expectEqual(@as(u32, 2), h.queries());

    h.stub.mode.store(.nodata_soa, .release);
    h.stub.ttl.store(5, .release);
    var nd = try c.lookupIp("empty.example.com");
    defer nd.deinit();
    try testing.expectEqual(Resolver.Status.nodata, nd.lookup.status);
    try expectIp(&nd, .network, 20); // raised to the minimum
    h.clock.now += 19;
    var nd2 = try c.lookupIp("empty.example.com");
    defer nd2.deinit();
    try expectIp(&nd2, .cache, 1);
    try testing.expectEqual(@as(u32, 3), h.queries());
}

test "a negative answer without SOA is not cached unless no_ttl_s says so" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    h.stub.mode.store(.nxdomain_nosoa, .release);

    var c = try h.cache(.{});
    defer c.deinit();
    var a1 = try c.lookupIp("nosoa.example.com");
    defer a1.deinit();
    try testing.expectEqual(Resolver.Status.nxdomain, a1.lookup.status);
    var a2 = try c.lookupIp("nosoa.example.com");
    defer a2.deinit();
    try expectIp(&a2, .network, 0);
    try testing.expectEqual(@as(u32, 2), h.queries());
    try testing.expectEqual(@as(usize, 0), c.stats().entries);

    var c2 = try h.cache(.{ .no_ttl_s = 45, .negative_min_ttl_s = 1000 }); // no_ttl_s is not clamped
    defer c2.deinit();
    var b1 = try c2.lookupIp("nosoa.example.com");
    defer b1.deinit();
    try expectIp(&b1, .network, 45);
    h.clock.now += 40;
    var b2 = try c2.lookupIp("nosoa.example.com");
    defer b2.deinit();
    try expectIp(&b2, .cache, 5);
    try testing.expectEqual(@as(u32, 3), h.queries());
}

test "a partial lookupIp answer is kept at most partial_ttl_s" {
    var h: Harness = .{};
    try h.start(.any);
    defer h.stop();
    h.stub.drop_aaaa.store(true, .release); // AAAA times out, A answers
    h.stub.ttl.store(600, .release);
    var c = try h.cache(.{ .partial_ttl_s = 30 });
    defer c.deinit();

    var a1 = try c.lookupIp("dual.example.com");
    defer a1.deinit();
    try testing.expect(a1.lookup.partial);
    try expectIp(&a1, .network, 30);
    try testing.expectEqual(@as(u32, 2), h.queries());
    h.clock.now += 10;
    var a2 = try c.lookupIp("dual.example.com");
    defer a2.deinit();
    try expectIp(&a2, .cache, 20);
    try testing.expect(a2.lookup.partial);
    try testing.expectEqual(@as(u32, 2), h.queries());
    h.clock.now += 20;
    var a3 = try c.lookupIp("dual.example.com");
    defer a3.deinit();
    try expectIp(&a3, .network, 30);
    try testing.expectEqual(@as(u32, 4), h.queries());
}

test "literals and DNS-free names pass through uncached" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{});
    defer c.deinit();

    for (0..2) |_| {
        var lit = try c.lookupIp("192.0.2.9");
        defer lit.deinit();
        try testing.expectEqual(Source.network, lit.source);
        try testing.expectEqual(@as(?[]const u8, null), lit.lookup.canonical);
        try testing.expectEqual(@as(?u32, null), lit.lookup.ttl_s);
        try testing.expectEqual(@as(usize, 1), lit.lookup.items.len);
        var onion = try c.lookupIp("x.onion"); // RFC 7686: never asked, canonical null
        defer onion.deinit();
        try testing.expectEqual(Source.network, onion.source);
        try testing.expectEqual(Resolver.Status.nxdomain, onion.lookup.status);
    }
    try testing.expectEqual(@as(u32, 0), h.queries());
    const s = c.stats();
    try testing.expectEqual(@as(usize, 0), s.entries);
    try testing.expectEqual(@as(u64, 0), s.hits);
}

test "keys are case-insensitive; a rooted name is a different key" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{});
    defer c.deinit();

    var a1 = try c.lookupIp("WWW.Example.COM");
    defer a1.deinit();
    try testing.expectEqual(Source.network, a1.source);
    var a2 = try c.lookupIp("www.example.com");
    defer a2.deinit();
    try testing.expectEqual(Source.cache, a2.source);
    try testing.expectEqual(@as(u32, 1), h.queries());

    var r1 = try c.lookupIp("rooted.example.com.");
    defer r1.deinit();
    var r2 = try c.lookupIp("rooted.example.com");
    defer r2.deinit();
    try testing.expectEqual(Source.network, r1.source);
    try testing.expectEqual(Source.network, r2.source);
    try testing.expectEqual(@as(u32, 3), h.queries());
    try testing.expectEqual(@as(usize, 3), c.stats().entries);
}

test "serve-stale on SERVFAIL inside the window, with the RFC 8767 failure recheck" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .stale_s = 100, .stale_answer_ttl_s = 30 });
    defer c.deinit();

    var prime = try c.lookupIp("stale.example.com");
    defer prime.deinit();
    try testing.expectEqual(@as(u32, 1), h.queries());
    h.stub.mode.store(.servfail, .release);

    h.clock.now += 61; // expired, inside the stale window
    var s1 = try c.lookupIp("stale.example.com");
    defer s1.deinit();
    try expectIp(&s1, .stale, 30);
    try testing.expectEqual(@as(usize, 1), s1.lookup.items.len);
    try testing.expectEqual(@as(u32, 2), h.queries());

    h.clock.now += 29; // inside the recheck interval: no query
    var s2 = try c.lookupIp("stale.example.com");
    defer s2.deinit();
    try expectIp(&s2, .stale, 30);
    try testing.expectEqual(@as(u32, 2), h.queries());

    h.clock.now += 1; // 30 s after the failure: asked again, fails again
    var s3 = try c.lookupIp("stale.example.com");
    defer s3.deinit();
    try expectIp(&s3, .stale, 30);
    try testing.expectEqual(@as(u32, 3), h.queries());
    try testing.expectEqual(@as(u64, 3), c.stats().stale_served);

    h.stub.mode.store(.answer, .release); // the upstream recovers
    h.clock.now += 30;
    var ok = try c.lookupIp("stale.example.com");
    defer ok.deinit();
    try expectIp(&ok, .network, 60);

    h.stub.mode.store(.servfail, .release); // past the window there is nothing to serve
    h.clock.now += 60 + 100;
    try testing.expectError(error.ServerFailed, c.lookupIp("stale.example.com"));
}

test "serve-stale on a timeout; the failure is armed for the recheck interval" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .stale_s = 100 });
    defer c.deinit();
    var prime = try c.lookupIp("quiet.example.com");
    defer prime.deinit();
    h.stub.mode.store(.silent, .release);
    h.clock.now += 70;
    var s1 = try c.lookupIp("quiet.example.com");
    defer s1.deinit();
    try expectIp(&s1, .stale, 30);
    try testing.expectEqual(@as(u32, 2), h.queries());
    // A name never seen has nothing stale: the plain error, then backoff.
    try testing.expectError(error.Timeout, c.lookupIp("never.example.com"));
    try testing.expectError(error.Timeout, c.lookupIp("never.example.com"));
    try testing.expectEqual(@as(u32, 3), h.queries());
}

test "stale is off by default" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{});
    defer c.deinit();
    var prime = try c.lookupIp("off.example.com");
    defer prime.deinit();
    h.stub.mode.store(.servfail, .release);
    h.clock.now += 61;
    try testing.expectError(error.ServerFailed, c.lookupIp("off.example.com"));
    try testing.expectEqual(@as(u64, 0), c.stats().stale_served);
}

test "failure backoff doubles up to the maximum and resets on success" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .failure_backoff_min_s = 1, .failure_backoff_max_s = 4 });
    defer c.deinit();
    h.stub.mode.store(.servfail, .release);

    // failure 1 at +0 arms 1 s; failure 2 at +1 arms 2 s; 3 at +3 arms 4 s; 4 at +7 arms 4 s (the cap).
    const name = "down.example.com";
    const steps = [_]struct { at: u64, queries: u32 }{
        .{ .at = 0, .queries = 1 },
        .{ .at = 0, .queries = 1 }, // armed: the last error, no query
        .{ .at = 1, .queries = 2 },
        .{ .at = 2, .queries = 2 },
        .{ .at = 3, .queries = 3 },
        .{ .at = 6, .queries = 3 },
        .{ .at = 7, .queries = 4 },
        .{ .at = 10, .queries = 4 }, // doubling would have armed 8 s; the cap armed 4 s
        .{ .at = 11, .queries = 5 },
    };
    const base = h.clock.now;
    for (steps) |st| {
        h.clock.now = base + st.at;
        try testing.expectError(error.ServerFailed, c.lookupIp(name));
        try testing.expectEqual(st.queries, h.queries());
    }

    h.stub.mode.store(.answer, .release); // success resets the count
    h.clock.now = base + 15;
    var ok = try c.lookupIp(name);
    defer ok.deinit();
    try expectIp(&ok, .network, 60);
    h.stub.mode.store(.servfail, .release);
    h.clock.now = base + 15 + 60;
    const q = h.queries();
    try testing.expectError(error.ServerFailed, c.lookupIp(name)); // delay is 1 again, not 8
    try testing.expectEqual(q + 1, h.queries());
    h.clock.now += 1;
    try testing.expectError(error.ServerFailed, c.lookupIp(name));
    try testing.expectEqual(q + 2, h.queries());
}

test "errors that are not upstream failures pass through and arm nothing" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{});
    defer c.deinit();
    var long_name: [300]u8 = undefined;
    @memset(&long_name, 'a');
    var huge_name: [key_buf_len + 100]u8 = undefined; // does not fit the key buffer: bypasses the table
    @memset(&huge_name, 'b');
    for ([_][]const u8{ "a..b.example.com", &long_name, &huge_name }) |bad| {
        for (0..2) |_| {
            // A name too long for the Resolver's candidate buffer yields no
            // candidate: an empty NXDOMAIN answer without `canonical`, which
            // is never cached. The others are the codec's own error.
            if (c.lookupIp(bad)) |ok| {
                var x = ok;
                defer x.deinit();
                try testing.expectEqual(@as(?[]const u8, null), x.lookup.canonical);
                try testing.expectEqual(Source.network, x.source);
            } else |err| try testing.expect(err == error.BadName or err == error.NameTooLong);
        }
    }
    try testing.expectEqual(@as(usize, 0), c.stats().entries);
    try testing.expectEqual(@as(u32, 0), h.queries());
    // Nothing was sent, so nothing counts as a network lookup.
    try testing.expectEqual(@as(u64, 0), c.stats().network_lookups);
}

test "a local refusal takes no budget token" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .max_network_lookups = .{ .per_s = 1, .burst = 1 } });
    defer c.deinit();
    for (0..3) |_| try testing.expectError(error.BadName, c.lookupIp("a..b.example.com"));
    try testing.expectEqual(@as(u64, 0), c.stats().budget_refused);
    // The one token of the burst is still there for a real lookup.
    var ok = try c.lookupIp("a.example.com");
    defer ok.deinit();
    try testing.expectEqual(Source.network, ok.source);
    try testing.expectEqual(@as(u64, 1), c.stats().network_lookups);
    try testing.expectEqual(@as(u64, 0), c.stats().budget_refused);
}

test "network budget: refusal, refill, and stale under budget" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .max_network_lookups = .{ .per_s = 1, .burst = 2 }, .stale_s = 1000 });
    defer c.deinit();

    var a = try c.lookupIp("a.example.com");
    defer a.deinit();
    var b = try c.lookupIp("b.example.com");
    defer b.deinit();
    try testing.expectError(error.BudgetExceeded, c.lookupIp("c.example.com"));
    try testing.expectEqual(@as(u32, 2), h.queries());
    try testing.expectEqual(@as(u64, 1), c.stats().budget_refused);
    var hit = try c.lookupIp("a.example.com"); // a hit costs no token
    defer hit.deinit();
    try testing.expectEqual(Source.cache, hit.source);

    h.clock.now += 1; // one token back
    var cc = try c.lookupIp("c.example.com");
    defer cc.deinit();
    try testing.expectEqual(Source.network, cc.source);

    // a and b are long expired (stale window open); the refilled burst of 2
    // goes to d and e, so a is refused at the network and served stale.
    h.clock.now += 61;
    var d = try c.lookupIp("d.example.com");
    defer d.deinit();
    var e = try c.lookupIp("e.example.com");
    defer e.deinit();
    var stale = try c.lookupIp("a.example.com");
    defer stale.deinit();
    try expectIp(&stale, .stale, 30);
    try testing.expectEqual(@as(u64, 2), c.stats().budget_refused);
}

test "LRU eviction at max_entries, and prune" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .max_entries = 2 });
    defer c.deinit();

    var a = try c.lookupIp("a.example.com");
    defer a.deinit();
    var b = try c.lookupIp("b.example.com");
    defer b.deinit();
    var a2 = try c.lookupIp("a.example.com"); // a is now the most recently used
    defer a2.deinit();
    try testing.expectEqual(Source.cache, a2.source);
    var cc = try c.lookupIp("c.example.com"); // evicts b
    defer cc.deinit();
    try testing.expectEqual(@as(u64, 1), c.stats().evictions);
    try testing.expectEqual(@as(usize, 2), c.stats().entries);
    var a3 = try c.lookupIp("a.example.com");
    defer a3.deinit();
    try testing.expectEqual(Source.cache, a3.source);
    var b2 = try c.lookupIp("b.example.com");
    defer b2.deinit();
    try testing.expectEqual(Source.network, b2.source);

    h.clock.now += 70; // a and b expired
    c.prune();
    try testing.expectEqual(@as(usize, 0), c.stats().entries);
    var again = try c.lookupIp("a.example.com");
    defer again.deinit();
    c.clear();
    try testing.expectEqual(@as(usize, 0), c.stats().entries);
}

test "at capacity an expired entry goes before a fresh one is evicted" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .max_entries = 2 });
    defer c.deinit();
    h.stub.ttl.store(10, .release);
    var a = try c.lookupIp("a.example.com");
    defer a.deinit();
    h.stub.ttl.store(600, .release);
    var b = try c.lookupIp("b.example.com");
    defer b.deinit();
    var a2 = try c.lookupIp("a.example.com"); // a is the most recently used, b the oldest
    defer a2.deinit();
    h.clock.now += 20; // a expired, b fresh
    var cc = try c.lookupIp("c.example.com");
    defer cc.deinit();
    try testing.expectEqual(@as(u64, 0), c.stats().evictions);
    try testing.expectEqual(@as(usize, 2), c.stats().entries); // the expired one was removed, not left beside the new one
    var b2 = try c.lookupIp("b.example.com");
    defer b2.deinit();
    try testing.expectEqual(Source.cache, b2.source);
}

test "prune keeps entries inside the stale window" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .stale_s = 100 });
    defer c.deinit();
    var a = try c.lookupIp("a.example.com");
    defer a.deinit();
    h.clock.now += 100; // 40 s into the window
    c.prune();
    try testing.expectEqual(@as(usize, 1), c.stats().entries);
    h.clock.now += 61;
    c.prune();
    try testing.expectEqual(@as(usize, 0), c.stats().entries);
}

test "InvalidOptions" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const bad = [_]Options{
        .{ .max_entries = 0 },
        .{ .min_ttl_s = 10, .max_ttl_s = 5 },
        .{ .negative_min_ttl_s = 10, .negative_max_ttl_s = 5 },
        .{ .failure_backoff_min_s = 0 },
        .{ .failure_backoff_min_s = 10, .failure_backoff_max_s = 5 },
        .{ .max_network_lookups = .{ .per_s = 0, .burst = 1 } },
        .{ .max_network_lookups = .{ .per_s = 1, .burst = 0 } },
        .{ .max_concurrent_lookups = 0 },
    };
    for (bad) |o| try testing.expectError(error.InvalidOptions, CachingResolver.init(testing.allocator, threaded.io(), .{}, o));
    var ok = try CachingResolver.init(testing.allocator, threaded.io(), .{}, .{});
    ok.deinit();
}

test "a clock that goes backwards neither underflows nor inflates ttl_s" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .max_network_lookups = .{ .per_s = 1, .burst = 1 } });
    defer c.deinit();
    var a = try c.lookupIp("a.example.com");
    defer a.deinit();
    h.clock.now = 10; // far back
    var a2 = try c.lookupIp("a.example.com");
    defer a2.deinit();
    try expectIp(&a2, .cache, 60); // never more than the stored TTL
    try testing.expectError(error.BudgetExceeded, c.lookupIp("b.example.com"));
    h.clock.now = 11;
    var b = try c.lookupIp("b.example.com");
    defer b.deinit();
}

test "an allocation failure while storing returns the answer uncached" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    // Measure the allocations of one uncached-then-stored lookup, then fail
    // the last of them (inside the store) on an identical run.
    var counting = std.testing.FailingAllocator.init(testing.allocator, .{});
    var total: usize = 0;
    {
        var c = try CachingResolver.init(counting.allocator(), h.io, h.ropts, .{ .clock = h.clock.clock() });
        defer c.deinit();
        var a = try c.lookupIp("oom.example.com");
        a.deinit();
        try testing.expectEqual(@as(usize, 1), c.stats().entries);
        total = counting.alloc_index;
    }
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = total - 1 });
    var c = try CachingResolver.init(failing.allocator(), h.io, h.ropts, .{ .clock = h.clock.clock() });
    defer c.deinit();
    var a = try c.lookupIp("oom.example.com");
    defer a.deinit();
    try testing.expectEqual(Source.network, a.source);
    try testing.expectEqual(@as(usize, 1), a.lookup.items.len);
    try testing.expectEqual(@as(usize, 0), c.stats().entries);
}

test "every lookup kind: network once, then cache" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{});
    defer c.deinit();
    var q: u32 = 0;

    {
        var a = try c.reverse(.{ .v4 = .{ 192, 0, 2, 1 } });
        defer a.deinit();
        try testing.expectEqual(Source.network, a.source);
        try testing.expectEqualStrings("host.example.com", a.lookup.items[0]);
        var b = try c.reverse(.{ .v4 = .{ 192, 0, 2, 1 } });
        defer b.deinit();
        try testing.expectEqual(Source.cache, b.source);
        try testing.expectEqualStrings("host.example.com", b.lookup.items[0]);
        var other = try c.reverse(.{ .v4 = .{ 192, 0, 2, 2 } }); // another address: another key
        defer other.deinit();
        try testing.expectEqual(Source.network, other.source);
        var v6 = try c.reverse(.{ .v6 = .{ 0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } });
        defer v6.deinit();
        try testing.expectEqual(Source.network, v6.source);
        q += 3;
        try testing.expectEqual(q, h.queries());
    }
    {
        var a = try c.lookupMx("example.com");
        defer a.deinit();
        var b = try c.lookupMx("EXAMPLE.com");
        defer b.deinit();
        try testing.expectEqual(Source.network, a.source);
        try testing.expectEqual(Source.cache, b.source);
        try testing.expectEqual(@as(u16, 10), b.lookup.items[0].preference);
        try testing.expectEqualStrings("mail.example.com", b.lookup.items[0].host);
        q += 1;
        try testing.expectEqual(q, h.queries());
    }
    {
        var a = try c.lookupNs("example.com"); // same name as the MX key: a different kind
        defer a.deinit();
        var b = try c.lookupNs("example.com");
        defer b.deinit();
        try testing.expectEqual(Source.network, a.source);
        try testing.expectEqual(Source.cache, b.source);
        try testing.expectEqualStrings("ns1.example.com", b.lookup.items[0]);
        q += 1;
        try testing.expectEqual(q, h.queries());
    }
    {
        var a = try c.lookupTxt("example.com");
        defer a.deinit();
        var b = try c.lookupTxt("example.com");
        defer b.deinit();
        try testing.expectEqual(Source.network, a.source);
        try testing.expectEqual(Source.cache, b.source);
        try testing.expectEqualStrings("v=spf1 -all", b.lookup.items[0]);
        q += 1;
        try testing.expectEqual(q, h.queries());
    }
    {
        var a = try c.lookupCname("alias.example.com");
        defer a.deinit();
        var b = try c.lookupCname("alias.example.com");
        defer b.deinit();
        try testing.expectEqual(Source.network, a.source);
        try testing.expectEqual(Source.cache, b.source);
        try testing.expectEqualStrings("real.example.com", b.lookup.canonical.?);
        try testing.expectEqualStrings("real.example.com", b.lookup.items[0]);
        q += 1;
        try testing.expectEqual(q, h.queries());
    }
    {
        var a = try c.lookupSrv("sip", "tcp", "example.com");
        defer a.deinit();
        var b = try c.lookupSrv("SIP", "tcp", "example.com");
        defer b.deinit();
        try testing.expectEqual(Source.network, a.source);
        try testing.expectEqual(Source.cache, b.source);
        try testing.expectEqual(@as(u16, 5060), b.lookup.items[0].port);
        try testing.expectEqualStrings("sip.example.com", b.lookup.items[0].target);
        var d = try c.lookupSrv("sip", "udp", "example.com");
        defer d.deinit();
        try testing.expectEqual(Source.network, d.source);
        q += 2;
        try testing.expectEqual(q, h.queries());
    }
}

const Worker = struct {
    c: *CachingResolver,
    iterations: usize,
    failures: std.atomic.Value(u32) = .init(0),

    fn run(w: *Worker) void {
        const names = [_][]const u8{ "t1.example.com", "t2.example.com", "t3.example.com" };
        for (0..w.iterations) |i| {
            var a = w.c.lookupIp(names[i % names.len]) catch {
                _ = w.failures.fetchAdd(1, .acq_rel);
                continue;
            };
            if (a.lookup.items.len != 1) _ = w.failures.fetchAdd(1, .acq_rel);
            a.deinit();
        }
    }
};

test "four threads share one cache: no leak, consistent stats" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{});
    defer c.deinit();

    const iterations = 12;
    var workers: [4]Worker = undefined;
    var futs: [4]std.Io.Future(void) = undefined;
    var started: usize = 0;
    defer for (futs[0..started]) |*f| f.await(h.io);
    for (&workers, &futs) |*w, *f| {
        w.* = .{ .c = &c, .iterations = iterations };
        f.* = try h.io.concurrent(Worker.run, .{w});
        started += 1;
    }
    for (futs[0..started]) |*f| f.await(h.io);
    started = 0;

    var failures: u32 = 0;
    for (&workers) |*w| failures += w.failures.load(.acquire);
    try testing.expectEqual(@as(u32, 0), failures);
    const s = c.stats();
    try testing.expectEqual(@as(u64, 4 * iterations), s.hits + s.misses);
    // Every miss either asked the network or waited for the lookup of its key (coalescing), so with
    // cacheable answers each of the three names is asked exactly once, however the threads interleave.
    try testing.expectEqual(s.misses, s.network_lookups + s.coalesced);
    try testing.expectEqual(@as(u64, 3), s.network_lookups);
    try testing.expectEqual(@as(u64, h.queries()), s.network_lookups);
    try testing.expectEqual(@as(usize, 3), s.entries);
}

/// Runs one lookup on its own task and reports when it is done.
const NamedLookup = struct {
    c: *CachingResolver,
    name: []const u8,
    started: std.atomic.Value(bool) = .init(false),
    done: std.atomic.Value(bool) = .init(false),
    ok: std.atomic.Value(bool) = .init(false),

    fn run(w: *NamedLookup) void {
        w.started.store(true, .release);
        if (w.c.lookupIp(w.name)) |ans| {
            var a = ans;
            w.ok.store(a.lookup.items.len == 1, .release);
            a.deinit();
        } else |_| {}
        w.done.store(true, .release);
    }
};

/// Bounded wait for a flag another task sets (a test, not a library, spins).
fn waitFor(io: std.Io, flag: *const std.atomic.Value(bool)) !void {
    for (0..5000) |_| {
        if (flag.load(.acquire)) return;
        try io.sleep(.fromMilliseconds(2), .awake);
    }
    return error.TestTimeout;
}

fn waitForWaiters(c: *CachingResolver, n: u32) !void {
    for (0..5000) |_| {
        c.pool_mutex.lockUncancelable(c.io);
        const w = c.pool_waiters;
        c.pool_mutex.unlock(c.io);
        if (w >= n) return;
        try c.io.sleep(.fromMilliseconds(2), .awake);
    }
    return error.TestTimeout;
}

test "a slow name does not block a miss on another name" {
    var h: Harness = .{ .timeout_ms = 10_000 };
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .max_concurrent_lookups = 2 });
    defer c.deinit();

    var slow: NamedLookup = .{ .c = &c, .name = "slow.example.com" };
    var fut = try h.io.concurrent(NamedLookup.run, .{&slow});
    defer fut.await(h.io);
    errdefer h.stub.release_slow.store(true, .release);
    try waitFor(h.io, &h.stub.stashed); // the stub holds the slow name's answer

    var fast = try c.lookupIp("fast.example.com"); // answered at once
    defer fast.deinit();
    try testing.expectEqual(Source.network, fast.source);
    try testing.expect(!slow.done.load(.acquire)); // the slow one cannot have finished: its answer is still held

    h.stub.release_slow.store(true, .release);
    try waitFor(h.io, &slow.done);
    try testing.expect(slow.ok.load(.acquire));
    try testing.expectEqual(@as(u32, 2), h.queries());
}

test "with max_concurrent_lookups = 1 the second miss waits for the first" {
    var h: Harness = .{ .timeout_ms = 10_000 };
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .max_concurrent_lookups = 1 });
    defer c.deinit();

    var slow: NamedLookup = .{ .c = &c, .name = "slow.example.com" };
    var f1 = try h.io.concurrent(NamedLookup.run, .{&slow});
    defer f1.await(h.io);
    errdefer h.stub.release_slow.store(true, .release);
    try waitFor(h.io, &h.stub.stashed);

    var fast: NamedLookup = .{ .c = &c, .name = "fast.example.com" };
    var f2 = try h.io.concurrent(NamedLookup.run, .{&fast});
    defer f2.await(h.io);
    try waitForWaiters(&c, 1); // the second is parked in the pool
    try testing.expect(!fast.done.load(.acquire));
    try testing.expectEqual(@as(u32, 1), h.queries()); // and has sent nothing

    h.stub.release_slow.store(true, .release);
    try waitFor(h.io, &slow.done);
    try waitFor(h.io, &fast.done);
    try testing.expect(slow.ok.load(.acquire) and fast.ok.load(.acquire));
    try testing.expectEqual(@as(u32, 2), h.queries());
    try testing.expectEqual(@as(u32, 0), c.pool_waiters); // the parked miss was counted out again
}

// ── request coalescing ──

fn waitForFlightWaiters(c: *CachingResolver, n: u32) !void {
    for (0..5000) |_| {
        c.mutex.lockUncancelable(c.io);
        const w = c.flight_waiters;
        c.mutex.unlock(c.io);
        if (w >= n) return;
        try c.io.sleep(.fromMilliseconds(2), .awake);
    }
    return error.TestTimeout;
}

fn inflightCount(c: *CachingResolver) usize {
    c.mutex.lockUncancelable(c.io);
    defer c.mutex.unlock(c.io);
    return c.inflight.count();
}

test "concurrent misses on one key share one network lookup (request coalescing)" {
    var h: Harness = .{ .timeout_ms = 10_000 };
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .max_concurrent_lookups = 4 });
    defer c.deinit();

    var ws: [4]NamedLookup = undefined;
    var fs: [4]std.Io.Future(void) = undefined;
    var started: usize = 0;
    defer for (fs[0..started]) |*f| f.await(h.io);
    errdefer h.stub.release_slow.store(true, .release);
    for (&ws, &fs, 0..) |*w, *f, i| {
        w.* = .{ .c = &c, .name = "slow.example.com" };
        f.* = try h.io.concurrent(NamedLookup.run, .{w});
        started += 1;
        if (i == 0) try waitFor(h.io, &h.stub.stashed); // the lead's answer is held
    }
    try waitForFlightWaiters(&c, 3); // the other three wait for it
    try testing.expectEqual(@as(u32, 1), h.queries()); // and sent nothing

    h.stub.release_slow.store(true, .release);
    for (&ws) |*w| try waitFor(h.io, &w.done);
    for (&ws) |*w| try testing.expect(w.ok.load(.acquire));
    const st = c.stats();
    try testing.expectEqual(@as(u64, 1), st.network_lookups);
    try testing.expectEqual(@as(u64, 3), st.coalesced);
    try testing.expectEqual(@as(u64, 4), st.misses);
    try testing.expectEqual(@as(u64, 0), st.hits);
    try testing.expectEqual(@as(u32, 1), h.queries());
    try testing.expectEqual(@as(u32, 0), c.flight_waiters);
    try testing.expectEqual(@as(usize, 0), inflightCount(&c));
}

test "coalesced misses share the lead's upstream failure: one lookup, no retry storm" {
    var h: Harness = .{ .timeout_ms = 10_000 };
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .max_concurrent_lookups = 4 });
    defer c.deinit();
    h.stub.mode.store(.servfail, .release); // the held answer is a SERVFAIL

    var ws: [3]NamedLookup = undefined;
    var fs: [3]std.Io.Future(void) = undefined;
    var started: usize = 0;
    defer for (fs[0..started]) |*f| f.await(h.io);
    errdefer h.stub.release_slow.store(true, .release);
    for (&ws, &fs, 0..) |*w, *f, i| {
        w.* = .{ .c = &c, .name = "slow.example.com" };
        f.* = try h.io.concurrent(NamedLookup.run, .{w});
        started += 1;
        if (i == 0) try waitFor(h.io, &h.stub.stashed);
    }
    try waitForFlightWaiters(&c, 2);
    h.stub.release_slow.store(true, .release);
    for (&ws) |*w| try waitFor(h.io, &w.done);
    for (&ws) |*w| try testing.expect(!w.ok.load(.acquire)); // all three see the failure
    const st = c.stats();
    try testing.expectEqual(@as(u64, 1), st.network_lookups); // the waiters read the lead's backoff, not the network
    try testing.expectEqual(@as(u64, 2), st.coalesced);
    try testing.expectEqual(@as(usize, 0), inflightCount(&c));
}

test "a miss waiting for its key's lookup can be cancelled; the lead still finishes" {
    var h: Harness = .{ .timeout_ms = 10_000 };
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .max_concurrent_lookups = 4 });
    defer c.deinit();

    var lead: NamedLookup = .{ .c = &c, .name = "slow.example.com" };
    var f1 = try h.io.concurrent(NamedLookup.run, .{&lead});
    defer f1.await(h.io);
    errdefer h.stub.release_slow.store(true, .release);
    try waitFor(h.io, &h.stub.stashed);

    var waiter: NamedLookup = .{ .c = &c, .name = "SLOW.example.com" }; // same key: case folded
    var f2 = try h.io.concurrent(NamedLookup.run, .{&waiter});
    var f2_over = false;
    defer if (!f2_over) f2.cancel(h.io);
    try waitForFlightWaiters(&c, 1);
    f2.cancel(h.io);
    f2_over = true;
    try testing.expect(!waiter.ok.load(.acquire));
    try testing.expectEqual(@as(u32, 0), c.flight_waiters);

    h.stub.release_slow.store(true, .release);
    try waitFor(h.io, &lead.done);
    try testing.expect(lead.ok.load(.acquire));
    try testing.expectEqual(@as(usize, 0), inflightCount(&c));
    try testing.expectEqual(@as(u64, 1), c.stats().network_lookups);
}

test "a cancelled lead does not strand its waiters: one of them asks in turn" {
    var h: Harness = .{ .timeout_ms = 10_000 };
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .max_concurrent_lookups = 4 });
    defer c.deinit();

    var lead: NamedLookup = .{ .c = &c, .name = "slow.example.com" };
    var f1 = try h.io.concurrent(NamedLookup.run, .{&lead});
    var f1_over = false;
    defer if (!f1_over) f1.cancel(h.io);
    errdefer h.stub.release_slow.store(true, .release);
    try waitFor(h.io, &h.stub.stashed);

    var waiter: NamedLookup = .{ .c = &c, .name = "slow.example.com" };
    var f2 = try h.io.concurrent(NamedLookup.run, .{&waiter});
    defer f2.await(h.io);
    try waitForFlightWaiters(&c, 1);
    f1.cancel(h.io); // the lead gives up while its answer is held
    f1_over = true;
    try testing.expect(!lead.ok.load(.acquire));

    // The waiter wakes to an empty table and asks itself: a second query reaches the stub.
    for (0..5000) |_| {
        if (h.queries() >= 2) break;
        try h.io.sleep(.fromMilliseconds(2), .awake);
    } else return error.TestTimeout;
    h.stub.release_slow.store(true, .release);
    try waitFor(h.io, &waiter.done);
    try testing.expect(waiter.ok.load(.acquire));
    const st = c.stats();
    try testing.expectEqual(@as(u64, 2), st.network_lookups);
    try testing.expectEqual(@as(u64, 1), st.coalesced);
    try testing.expectEqual(@as(usize, 0), inflightCount(&c));
}

// ── prefetch and many lookups ──

test "prefetch is off by default: a hit late in the TTL marks nothing" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{});
    defer c.deinit();
    dropAnswer(c.lookupIp("pf.example.com"));
    h.clock.add(59); // 1 s of 60 left
    dropAnswer(c.lookupIp("pf.example.com"));
    try testing.expectEqual(@as(usize, 0), try c.refreshDue(10));
    try testing.expectEqual(@as(u32, 1), h.queries());
    try testing.expectEqual(@as(u64, 0), c.stats().prefetches);
}

test "prefetch: a hit in the last prefetch_pct of the TTL marks the key once; refreshDue renews it" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .prefetch_pct = 20 });
    defer c.deinit();
    dropAnswer(c.lookupIp("pf.example.com")); // stored for 60 s
    h.clock.add(40); // 20 s left = 33 %: not yet
    dropAnswer(c.lookupIp("pf.example.com"));
    try testing.expectEqual(@as(usize, 0), try c.refreshDue(10));
    h.clock.add(10); // 10 s left = 16 %: due
    var hit = try c.lookupIp("pf.example.com");
    try testing.expectEqual(Source.cache, hit.source); // served from the table all the same
    hit.deinit();
    dropAnswer(c.lookupIp("pf.example.com")); // a second late hit does not mark it twice
    try testing.expectEqual(@as(u32, 1), h.queries());
    try testing.expectEqual(@as(usize, 1), try c.refreshDue(10));
    try testing.expectEqual(@as(u32, 2), h.queries());
    try testing.expectEqual(@as(usize, 0), try c.refreshDue(10)); // taken
    h.clock.add(30); // past the old expiry (60 s), inside the renewed one
    var after = try c.lookupIp("pf.example.com");
    defer after.deinit();
    try testing.expectEqual(Source.cache, after.source);
    try testing.expectEqual(@as(u32, 2), h.queries());
    const st = c.stats();
    try testing.expectEqual(@as(u64, 1), st.prefetches);
    try testing.expectEqual(@as(u64, 1), st.misses); // the refresh is no miss
}

test "a failed prefetch refresh keeps the old answer and arms the key's backoff (no retry storm)" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .prefetch_pct = 20 });
    defer c.deinit();
    dropAnswer(c.lookupIp("pf.example.com")); // stored for 60 s
    h.clock.add(50);
    dropAnswer(c.lookupIp("pf.example.com")); // marks it due
    h.stub.mode.store(.servfail, .release);
    try testing.expectEqual(@as(usize, 1), try c.refreshDue(10));
    const sent = h.queries();
    try testing.expect(sent >= 2);
    var hit = try c.lookupIp("pf.example.com"); // the old answer is still served, and marks it again
    try testing.expectEqual(Source.cache, hit.source);
    hit.deinit();
    try testing.expectEqual(@as(usize, 1), try c.refreshDue(10)); // attempted ...
    try testing.expectEqual(sent, h.queries()); // ... but held by the backoff: nothing sent
    const st = c.stats();
    try testing.expectEqual(@as(u64, 0), st.stale_served);
    try testing.expectEqual(@as(u64, 2), st.prefetches);
}

test "prefetch_pct over 99 is refused" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    try testing.expectError(error.InvalidOptions, h.cache(.{ .prefetch_pct = 100 }));
}

test "lookupIpMany: one result per name, successes and failures, in order" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .max_concurrent_lookups = 2 });
    defer c.deinit();
    const long_label: [64]u8 = @splat('a'); // over 63 bytes: refused locally
    const names = [_][]const u8{ "m1.example.com", "m2.example.com", long_label ++ ".example.com", "m1.example.com", "192.0.2.7" };
    var results: [names.len]IpResult = undefined;
    try c.lookupIpMany(&names, &results);
    defer for (&results) |*r| dropAnswer(r.*);
    for ([_]usize{ 0, 1, 3, 4 }) |i| {
        const a = try results[i];
        try testing.expectEqual(@as(usize, 1), a.lookup.items.len);
    }
    try testing.expect(std.meta.isError(results[2]));
    try testing.expectEqual(@as(u32, 2), h.queries()); // m1 once (cached or coalesced), m2 once; the bad name sent nothing
    var short: [1]IpResult = undefined;
    try testing.expectError(error.LengthMismatch, c.lookupIpMany(&names, &short));
}

const ManyRun = struct {
    c: *CachingResolver,
    names: []const []const u8,
    results: []IpResult,
    err: ?anyerror = null,
    fn run(m: *ManyRun) void {
        m.c.lookupIpMany(m.names, m.results) catch |e| {
            m.err = e;
        };
    }
};

test "lookupIpMany can be cancelled: every result is set, the cut-short one to error.Canceled" {
    var h: Harness = .{ .timeout_ms = 10_000 };
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .max_concurrent_lookups = 4 });
    defer c.deinit();
    const names = [_][]const u8{ "fast.example.com", "slow.example.com" };
    var results: [names.len]IpResult = undefined;
    var m: ManyRun = .{ .c = &c, .names = &names, .results = &results };
    var f = try h.io.concurrent(ManyRun.run, .{&m});
    var over = false;
    defer if (!over) f.cancel(h.io);
    errdefer h.stub.release_slow.store(true, .release);
    try waitFor(h.io, &h.stub.stashed);
    f.cancel(h.io);
    over = true;
    defer for (&results) |*r| dropAnswer(r.*);
    try testing.expectError(error.Canceled, results[1]);
    if (results[0]) |a| try testing.expectEqual(@as(usize, 1), a.lookup.items.len) else |e| try testing.expectEqual(error.Canceled, e);
    try testing.expectEqual(@as(usize, 0), inflightCount(&c));
}

// ── delta mutation audit 2026-11-15: tests the first schemata run asked for ──

fn freeCount(c: *CachingResolver) usize {
    c.pool_mutex.lockUncancelable(c.io);
    defer c.pool_mutex.unlock(c.io);
    var n: usize = 0;
    var it = c.free;
    while (it) |s| : (it = s.next_free) n += 1;
    return n;
}

fn waitUntilClear(io: std.Io, flag: *const std.atomic.Value(bool)) !void {
    for (0..5000) |_| {
        if (!flag.load(.acquire)) return;
        try io.sleep(.fromMilliseconds(2), .awake);
    }
    return error.TestTimeout;
}

test "options whose min equals max are valid" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const ok = [_]Options{
        .{ .min_ttl_s = 5, .max_ttl_s = 5 },
        .{ .negative_min_ttl_s = 5, .negative_max_ttl_s = 5 },
        .{ .failure_backoff_min_s = 5, .failure_backoff_max_s = 5 },
    };
    for (ok) |o| {
        var c = try CachingResolver.init(testing.allocator, threaded.io(), .{}, o);
        c.deinit();
    }
}

test "isUpstreamFailure names exactly the six upstream failures" {
    const upstream = [_]Resolver.Error{ error.Timeout, error.ServerFailed, error.NetworkFailed, error.MalformedResponse, error.DohFailed, error.TlsFailed };
    for (upstream) |e| try testing.expect(isUpstreamFailure(e));
    const local = [_]Resolver.Error{ error.BadName, error.NameTooLong, error.OutOfMemory, error.Canceled };
    for (local) |e| try testing.expect(!isUpstreamFailure(e));
}

test "backoffDelay doubles from min, stops at max, and a saturated fail count cannot wrap" {
    var c: CachingResolver = undefined;
    c.options = .{ .failure_backoff_min_s = 2, .failure_backoff_max_s = 300 };
    const want = [_]u32{ 2, 4, 8, 16, 32, 64, 128, 256, 300 };
    for (want, 1..) |w, fails| try testing.expectEqual(w, c.backoffDelay(@intCast(fails)));
    for ([_]u8{ 33, 64, 65, 100, 255 }) |fails| try testing.expectEqual(@as(u32, 300), c.backoffDelay(fails));
}

test "prune inside the stale window keeps the payload servable" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .stale_s = 100 });
    defer c.deinit();
    var a = try c.lookupIp("a.example.com");
    defer a.deinit();
    h.clock.now += 100; // 40 s into the window
    c.prune();
    h.stub.mode.store(.servfail, .release);
    var s = try c.lookupIp("a.example.com");
    defer s.deinit();
    try expectIp(&s, .stale, 30);
}

test "prune keeps failure state until the backoff has elapsed, not a second longer" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .failure_backoff_min_s = 10, .failure_backoff_max_s = 10 });
    defer c.deinit();
    h.stub.mode.store(.servfail, .release);
    const base = h.clock.now;
    try testing.expectError(error.ServerFailed, c.lookupIp("down.example.com")); // arms until base + 10
    h.clock.now = base + 9;
    c.prune();
    try testing.expectEqual(@as(usize, 1), c.stats().entries);
    try testing.expectError(error.ServerFailed, c.lookupIp("down.example.com"));
    try testing.expectEqual(@as(u32, 1), h.queries()); // still backed off, nothing asked
    h.clock.now = base + 10;
    c.prune();
    try testing.expectEqual(@as(usize, 0), c.stats().entries);
}

test "a payload past the stale window is freed at once, a live backoff is kept" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var fa = std.testing.FailingAllocator.init(testing.allocator, .{});
    var c = try CachingResolver.init(fa.allocator(), h.io, h.ropts, .{ .stale_s = 10, .clock = h.clock.clock() });
    defer c.deinit();
    const base = h.clock.now;
    dropAnswer(c.lookupIp("a.example.com"));
    dropAnswer(c.lookupIp("b.example.com"));
    h.stub.mode.store(.servfail, .release);
    h.clock.now = base + 61; // expired, inside the window: stale, failure armed until base + 91
    for ([_][]const u8{ "a.example.com", "b.example.com" }) |n| {
        var s = try c.lookupIp(n);
        s.deinit();
    }
    const q = h.queries();
    h.clock.now = base + 75; // past the window, backoff still armed

    var live = fa.allocated_bytes - fa.freed_bytes;
    try testing.expectError(error.ServerFailed, c.lookupIp("b.example.com")); // the lookup path frees b
    try testing.expectEqual(q, h.queries()); // and keeps the backoff: nothing asked
    try testing.expect(fa.allocated_bytes - fa.freed_bytes < live);

    live = fa.allocated_bytes - fa.freed_bytes;
    c.prune(); // the prune path frees a
    try testing.expect(fa.allocated_bytes - fa.freed_bytes < live);
    try testing.expectEqual(@as(usize, 2), c.stats().entries); // both still carry failure state

    // The clock steps back before the old expiry: the dropped payload is not served.
    h.clock.now = base + 50;
    try testing.expectError(error.ServerFailed, c.lookupIp("a.example.com"));
    try testing.expectEqual(q, h.queries());
}

test "an expired entry is removed even when the budget then refuses the lookup" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    h.stub.ttl.store(1, .release);
    var c = try h.cache(.{ .max_network_lookups = .{ .per_s = 1, .burst = 1 } });
    defer c.deinit();
    dropAnswer(c.lookupIp("a.example.com"));
    h.clock.now += 1; // a expired, one token back
    dropAnswer(c.lookupIp("b.example.com"));
    try testing.expectError(error.BudgetExceeded, c.lookupIp("a.example.com"));
    try testing.expectEqual(@as(usize, 1), c.stats().entries); // only b
}

test "a failure entry without a payload is never served stale" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .stale_s = 1_000_000 }); // wider than the clock value: 0 + stale_s > now
    defer c.deinit();
    h.stub.mode.store(.servfail, .release);
    try testing.expectError(error.ServerFailed, c.lookupIp("never.example.com"));
    try testing.expectEqual(@as(u64, 0), c.stats().stale_served);
}

test "a fresh answer without a TTL supersedes the expired one, which is then not served stale" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .stale_s = 1000 });
    defer c.deinit();
    dropAnswer(c.lookupIp("a.example.com"));
    h.clock.now += 61;
    h.stub.mode.store(.nxdomain_nosoa, .release);
    var nx = try c.lookupIp("a.example.com");
    defer nx.deinit();
    try testing.expectEqual(Resolver.Status.nxdomain, nx.lookup.status);
    h.stub.mode.store(.servfail, .release);
    try testing.expectError(error.ServerFailed, c.lookupIp("a.example.com"));
}

test "a partial answer with a TTL under partial_ttl_s keeps the smaller one" {
    var h: Harness = .{};
    try h.start(.any);
    defer h.stop();
    h.stub.drop_aaaa.store(true, .release);
    h.stub.ttl.store(10, .release);
    var c = try h.cache(.{ .partial_ttl_s = 30 });
    defer c.deinit();
    var a = try c.lookupIp("dual.example.com");
    defer a.deinit();
    try testing.expect(a.lookup.partial);
    try expectIp(&a, .network, 10);
}

test "the token bucket refills per_s tokens a second up to the burst" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .max_network_lookups = .{ .per_s = 3, .burst = 6 } });
    defer c.deinit();
    var buf: [32]u8 = undefined;
    for (0..6) |i| dropAnswer(c.lookupIp(try std.fmt.bufPrint(&buf, "n{d}.example.com", .{i})));
    try testing.expectError(error.BudgetExceeded, c.lookupIp("n6.example.com"));
    h.clock.now += 2; // 2 s x 3 per second = the whole burst again
    for (6..12) |i| dropAnswer(c.lookupIp(try std.fmt.bufPrint(&buf, "n{d}.example.com", .{i})));
    try testing.expectError(error.BudgetExceeded, c.lookupIp("n12.example.com"));
    try testing.expectEqual(@as(u64, 2), c.stats().budget_refused);
}

test "a clock at the end of u64 saturates instead of overflowing" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .failure_backoff_min_s = 100, .failure_backoff_max_s = 100 });
    defer c.deinit();
    h.clock.now = std.math.maxInt(u64) - 5;
    dropAnswer(c.lookupIp("late.example.com")); // stored with 60 s: the expiry saturates
    var a = try c.lookupIp("late.example.com");
    defer a.deinit();
    try expectIp(&a, .cache, 5);
    h.stub.mode.store(.servfail, .release);
    try testing.expectError(error.ServerFailed, c.lookupIp("down.example.com")); // retry_at saturates
}

test "scanning for an expired entry at capacity looks at the 16 least recently used" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var evictions: [2]u64 = undefined;
    for ([_]usize{ 15, 16 }, 0..) |k, slot| {
        var c = try h.cache(.{ .max_entries = 20 });
        defer c.deinit();
        var buf: [32]u8 = undefined;
        for (0..20) |i| {
            h.stub.ttl.store(if (i == k) 10 else 600, .release);
            dropAnswer(c.lookupIp(try std.fmt.bufPrint(&buf, "n{d}.example.com", .{i})));
        }
        h.clock.now += 20; // only entry k has expired; entry i is i places from the LRU end
        h.stub.ttl.store(600, .release);
        dropAnswer(c.lookupIp("new.example.com"));
        try testing.expectEqual(@as(usize, 20), c.stats().entries);
        evictions[slot] = c.stats().evictions;
    }
    try testing.expectEqual(@as(u64, 0), evictions[0]); // the 16th from the end is found
    try testing.expectEqual(@as(u64, 1), evictions[1]); // the 17th is not looked at: the LRU one goes
}

test "keys keep kinds, addresses, names and SRV parts apart" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{});
    defer c.deinit();

    // reverse key = {reverse, 4, 1, 2, 3, 4}: no name key may equal it.
    dropAnswer(c.reverse(.{ .v4 = .{ 1, 2, 3, 4 } }));
    dropAnswer(c.lookupIp("\x04\x01\x02\x03\x04"));
    try testing.expectEqual(@as(u64, 0), c.stats().hits);

    // two IPv6 addresses that differ only in the last byte
    const x: netaddr.Ip = .{ .v6 = .{ 0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } };
    var y = x;
    y.v6[15] = 2;
    dropAnswer(c.reverse(x));
    var ry = try c.reverse(y);
    defer ry.deinit();
    try testing.expectEqual(Source.network, ry.source);

    // names that differ only in the last character
    dropAnswer(c.lookupIp("ending.example.com"));
    var n2 = try c.lookupIp("ending.example.con");
    defer n2.deinit();
    try testing.expectEqual(Source.network, n2.source);

    // SRV: the name is part of the key, case-folded; the part boundaries are too
    dropAnswer(c.lookupSrv("sip", "tcp", "One.Example.com"));
    var s1 = try c.lookupSrv("sip", "tcp", "one.example.COM");
    defer s1.deinit();
    try testing.expectEqual(Source.cache, s1.source);
    var s2 = try c.lookupSrv("sip", "tcp", "two.example.com");
    defer s2.deinit();
    try testing.expectEqual(Source.network, s2.source);
    dropAnswer(c.lookupSrv("ab", "c", "x.example.com"));
    var s3 = try c.lookupSrv("a", "bc", "x.example.com");
    defer s3.deinit();
    try testing.expectEqual(Source.network, s3.source);
    // the kind of an SRV key: {len("ab"), "ab", len("tcp"), "tcp", name} equals the MX key of this name unless a kind byte leads
    dropAnswer(c.lookupSrv("ab", "tcp", "example.com"));
    const hits = c.stats().hits;
    dropAnswer(c.lookupMx("ab\x03tcpexample.com"));
    try testing.expectEqual(hits, c.stats().hits);
    // an undefined length byte (0xaa in a safe build) must not stand in for the real one
    dropAnswer(c.lookupSrv("a\xaa", "b", "y.example.com"));
    const hits2 = c.stats().hits;
    dropAnswer(c.lookupSrv("a", "\xaab", "y.example.com"));
    try testing.expectEqual(hits2, c.stats().hits);
}

test "key length limits: the last name that fits is cached, the next bypasses the table" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{});
    defer c.deinit();

    var big: [key_buf_len]u8 = undefined;
    @memset(&big, 'a');
    var m = c.stats().misses;
    dropAnswer(c.lookupIp(big[0 .. key_buf_len - 1])); // kind + name fills the buffer exactly
    try testing.expectEqual(m + 1, c.stats().misses);
    m = c.stats().misses;
    dropAnswer(c.lookupIp(big[0..key_buf_len])); // one byte too long: straight to the resolver
    try testing.expectEqual(m, c.stats().misses);
    // neither name is valid DNS (over 253 bytes): nothing went to the network
    try testing.expectEqual(@as(u64, 0), c.stats().network_lookups);
    try testing.expect(c.free != null); // the bypass returned its Resolver

    var svc: [256]u8 = undefined;
    @memset(&svc, 'a');
    m = c.stats().misses;
    dropAnswer(c.lookupSrv(svc[0..255], "tcp", "example.com")); // 255 is the longest part
    try testing.expectEqual(m + 1, c.stats().misses);
    dropAnswer(c.lookupSrv("sip", svc[0..255], "example.com"));
    try testing.expectEqual(m + 2, c.stats().misses);
    dropAnswer(c.lookupSrv(svc[0..256], "tcp", "example.com")); // 256 does not fit a length byte
    dropAnswer(c.lookupSrv("sip", svc[0..256], "example.com"));
    try testing.expectEqual(m + 2, c.stats().misses);
    // 3 + 255 + 255 + 269 = key_buf_len: fits; one more does not
    m = c.stats().misses;
    dropAnswer(c.lookupSrv(svc[0..255], svc[0..255], big[0..269]));
    try testing.expectEqual(m + 1, c.stats().misses);
    dropAnswer(c.lookupSrv(svc[0..255], svc[0..255], big[0..270]));
    try testing.expectEqual(m + 1, c.stats().misses);
}

test "an allocation failure creating a Resolver leaves the pool as it was" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var c = try CachingResolver.init(failing.allocator(), h.io, h.ropts, .{ .clock = h.clock.clock() });
    defer c.deinit();
    try testing.expectError(error.OutOfMemory, c.lookupIp("oom.example.com"));
    try testing.expectEqual(@as(u16, 0), c.created);
    try testing.expect(c.free == null and c.all == null);
    // the table mutex was released (stats takes it) and the miss was counted
    try testing.expectEqual(@as(u64, 1), c.stats().misses);
    var huge: [key_buf_len + 100]u8 = undefined;
    @memset(&huge, 'b');
    try testing.expectError(error.OutOfMemory, c.lookupIp(&huge)); // the bypass path too
    try testing.expectEqual(@as(u16, 0), c.created);
    // neither lookup got a Resolver, so neither counts as a network lookup
    try testing.expectEqual(@as(u64, 0), c.stats().network_lookups);
}

test "an allocation failure while arming a failure entry still returns the upstream error" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    h.stub.mode.store(.servfail, .release);
    var total: usize = 0;
    {
        var counting = std.testing.FailingAllocator.init(testing.allocator, .{});
        var c = try CachingResolver.init(counting.allocator(), h.io, h.ropts, .{ .clock = h.clock.clock() });
        defer c.deinit();
        try testing.expectError(error.ServerFailed, c.lookupIp("down.example.com"));
        try testing.expectEqual(@as(usize, 1), c.stats().entries);
        total = counting.alloc_index;
    }
    // Fail every allocation in turn. Most positions fall inside the Resolver (an
    // OutOfMemory from it); the entry, its key and the table slot are three
    // positions where the answer is still the upstream error, with nothing armed.
    var armed_ok: usize = 0;
    for (0..total) |k| {
        var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = k });
        var c = try CachingResolver.init(failing.allocator(), h.io, h.ropts, .{ .clock = h.clock.clock() });
        defer c.deinit();
        if (c.lookupIp("down.example.com")) |ans| {
            var x = ans;
            x.deinit();
            return error.TestUnexpectedResult;
        } else |err| switch (err) {
            error.OutOfMemory => {},
            error.ServerFailed => {
                try testing.expectEqual(@as(usize, 0), c.stats().entries);
                armed_ok += 1;
            },
            else => return err,
        }
    }
    try testing.expect(armed_ok >= 3);
}

/// Fails its first allocation, but only once another task is parked in the
/// Resolver pool waiting for that very allocation's reservation.
const GateAllocator = struct {
    child: std.mem.Allocator,
    c: *CachingResolver,
    armed: std.atomic.Value(bool) = .init(true),

    fn allocator(g: *GateAllocator) std.mem.Allocator {
        return .{ .ptr = g, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(ctx: *anyopaque, len: usize, a: std.mem.Alignment, ra: usize) ?[*]u8 {
        const g: *GateAllocator = @ptrCast(@alignCast(ctx));
        // Only the pooled Resolver's allocation is failed (other allocations, e.g. the coalescing
        // record taken under the table mutex, pass): that is the path this gate is for.
        if (len == @sizeOf(Slot) and g.armed.swap(false, .acq_rel)) {
            for (0..5000) |_| {
                g.c.pool_mutex.lockUncancelable(g.c.io);
                const w = g.c.pool_waiters;
                g.c.pool_mutex.unlock(g.c.io);
                if (w >= 1) break;
                g.c.io.sleep(.fromMilliseconds(2), .awake) catch {};
            }
            return null;
        }
        return g.child.rawAlloc(len, a, ra);
    }
    fn resize(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, n: usize, ra: usize) bool {
        const g: *GateAllocator = @ptrCast(@alignCast(ctx));
        return g.child.rawResize(m, a, n, ra);
    }
    fn remap(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, n: usize, ra: usize) ?[*]u8 {
        const g: *GateAllocator = @ptrCast(@alignCast(ctx));
        return g.child.rawRemap(m, a, n, ra);
    }
    fn free(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, ra: usize) void {
        const g: *GateAllocator = @ptrCast(@alignCast(ctx));
        g.child.rawFree(m, a, ra);
    }
};

test "a failed Resolver allocation hands its reservation to the miss that is waiting for it" {
    var h: Harness = .{ .timeout_ms = 10_000 };
    try h.start(.v4);
    defer h.stop();
    var gate: GateAllocator = .{ .child = testing.allocator, .c = undefined };
    var c = try CachingResolver.init(gate.allocator(), h.io, h.ropts, .{ .max_concurrent_lookups = 1, .clock = h.clock.clock() });
    defer c.deinit();
    gate.c = &c;

    var l1: NamedLookup = .{ .c = &c, .name = "one.example.com" };
    var l2: NamedLookup = .{ .c = &c, .name = "two.example.com" };
    var f1 = try h.io.concurrent(NamedLookup.run, .{&l1});
    defer f1.await(h.io);
    var f2 = try h.io.concurrent(NamedLookup.run, .{&l2});
    defer f2.await(h.io);
    try waitFor(h.io, &l1.done);
    try waitFor(h.io, &l2.done);
    // One of them lost the allocation; the other was woken, created the Resolver and answered.
    try testing.expect(l1.ok.load(.acquire) != l2.ok.load(.acquire));
    try testing.expectEqual(@as(u16, 1), c.created);
}

test "the Resolver pool: a popped slot leaves the list, a pushed one keeps the chain, slots are reused" {
    var h: Harness = .{ .timeout_ms = 10_000 };
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .max_concurrent_lookups = 2 });
    defer c.deinit();

    dropAnswer(c.lookupIp("seq.example.com"));
    try testing.expectEqual(@as(u16, 1), c.created);
    try testing.expectEqual(@as(usize, 1), freeCount(&c));

    for (0..2) |round| {
        var slow: NamedLookup = .{ .c = &c, .name = "slow.example.com" };
        var f = try h.io.concurrent(NamedLookup.run, .{&slow});
        defer f.await(h.io);
        errdefer h.stub.release_slow.store(true, .release);
        try waitFor(h.io, &h.stub.stashed);
        try testing.expectEqual(round, freeCount(&c)); // the slow miss popped one: none left in round 0, one in round 1
        var fast_name: [24]u8 = undefined;
        dropAnswer(c.lookupIp(try std.fmt.bufPrint(&fast_name, "fast{d}.example.com", .{round}))); // takes or creates the second
        try testing.expectEqual(@as(u16, 2), c.created);
        try testing.expectEqual(@as(usize, 1), freeCount(&c));
        h.stub.release_slow.store(true, .release);
        try waitFor(h.io, &slow.done);
        try waitUntilClear(h.io, &h.stub.stashed);
        h.stub.release_slow.store(false, .release);
        try testing.expectEqual(@as(usize, 2), freeCount(&c)); // the chain survived the push
        c.clear(); // the slow name is a miss again in the next round
    }
}

test "a miss parked in the pool can be cancelled and leaves the pool consistent" {
    var h: Harness = .{ .timeout_ms = 10_000 };
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .max_concurrent_lookups = 1 });
    defer c.deinit();

    var slow: NamedLookup = .{ .c = &c, .name = "slow.example.com" };
    var f1 = try h.io.concurrent(NamedLookup.run, .{&slow});
    defer f1.await(h.io);
    errdefer h.stub.release_slow.store(true, .release);
    try waitFor(h.io, &h.stub.stashed);

    var parked: NamedLookup = .{ .c = &c, .name = "parked.example.com" };
    var f2 = try h.io.concurrent(NamedLookup.run, .{&parked});
    var f2_over = false;
    defer if (!f2_over) f2.cancel(h.io);
    try waitForWaiters(&c, 1);
    f2.cancel(h.io);
    f2_over = true;
    c.pool_mutex.lockUncancelable(c.io); // not left locked by the cancel path
    const waiters = c.pool_waiters;
    c.pool_mutex.unlock(c.io);
    try testing.expectEqual(@as(u32, 0), waiters);
    try testing.expect(!parked.ok.load(.acquire));

    h.stub.release_slow.store(true, .release);
    try waitFor(h.io, &slow.done);
    try testing.expect(slow.ok.load(.acquire));
    dropAnswer(c.lookupIp("after.example.com")); // the pool still works
}

test "the expiry is measured from before the network call (an answer never outlives its TTL)" {
    var h: Harness = .{ .timeout_ms = 10_000 };
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .max_concurrent_lookups = 2, .failure_backoff_min_s = 5, .failure_backoff_max_s = 5 });
    defer c.deinit();

    {
        var slow: NamedLookup = .{ .c = &c, .name = "slow.a.example.com" };
        var f = try h.io.concurrent(NamedLookup.run, .{&slow});
        defer f.await(h.io);
        errdefer h.stub.release_slow.store(true, .release);
        try waitFor(h.io, &h.stub.stashed);
        h.clock.now += 30; // the answer takes 30 s to arrive
        h.stub.release_slow.store(true, .release);
        try waitFor(h.io, &slow.done);
        try waitUntilClear(h.io, &h.stub.stashed);
        h.stub.release_slow.store(false, .release);
        const e = c.map.get("\x00slow.a.example.com").?;
        // the TTL counts from before the call: the 30 s it took are already spent
        try testing.expectEqual(h.clock.now - 30 + 60, e.expires_s);
    }
    h.stub.mode.store(.servfail, .release);
    {
        var slow: NamedLookup = .{ .c = &c, .name = "slow.b.example.com" };
        var f = try h.io.concurrent(NamedLookup.run, .{&slow});
        defer f.await(h.io);
        errdefer h.stub.release_slow.store(true, .release);
        try waitFor(h.io, &h.stub.stashed);
        h.clock.now += 30;
        h.stub.release_slow.store(true, .release);
        try waitFor(h.io, &slow.done);
        try waitUntilClear(h.io, &h.stub.stashed);
        h.stub.release_slow.store(false, .release);
        const e = c.map.get("\x00slow.b.example.com").?;
        try testing.expectEqual(h.clock.now + 5, e.retry_at_s);
    }
}

test "a refreshed answer becomes the most recently used even if another lookup finished meanwhile" {
    var h: Harness = .{ .timeout_ms = 10_000 };
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .max_entries = 2, .max_concurrent_lookups = 2, .stale_s = 100 }); // the expired entry stays in the table
    defer c.deinit();

    h.stub.ttl.store(5, .release);
    h.stub.release_slow.store(true, .release);
    dropAnswer(c.lookupIp("slow.b.example.com")); // b, soon expired
    try waitUntilClear(h.io, &h.stub.stashed);
    h.stub.release_slow.store(false, .release);
    h.stub.ttl.store(600, .release);
    h.clock.now += 10;

    var slow: NamedLookup = .{ .c = &c, .name = "slow.b.example.com" };
    var f = try h.io.concurrent(NamedLookup.run, .{&slow});
    defer f.await(h.io);
    errdefer h.stub.release_slow.store(true, .release);
    try waitFor(h.io, &h.stub.stashed); // b's refresh is under way (b is the most recently used)
    dropAnswer(c.lookupIp("c.example.com")); // c finishes first: c is now the most recently used
    h.stub.release_slow.store(true, .release);
    try waitFor(h.io, &slow.done); // b's answer is stored: b must move in front of c
    dropAnswer(c.lookupIp("d.example.com")); // evicts the least recently used, which is c
    try testing.expectEqual(@as(u64, 1), c.stats().evictions);
    var again = try c.lookupIp("slow.b.example.com");
    defer again.deinit();
    try testing.expectEqual(Source.cache, again.source);
}

test "every pooled Resolver is deinitialised with the cache" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [256]u8 = undefined;
    const conf_path = try std.mem.print(&path_buf, ".zig-cache/tmp/{s}/resolv.conf", .{&tmp.sub_path});
    try std.Io.Dir.cwd().writeFile(h.io, .{ .sub_path = conf_path, .data = "search example.com\n" });
    h.ropts.use_search = true; // the Resolver now keeps the resolv.conf text, freed by its deinit
    h.ropts.resolv_conf_path = conf_path;
    var c = try h.cache(.{});
    defer c.deinit();
    dropAnswer(c.lookupIp("host.example.com"));
    try testing.expectEqual(@as(u16, 1), c.created);
}

test "F1: literals, DNS-avoided names and hosts hits spend no budget, slot or network stat" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [256]u8 = undefined;
    const hosts_path = try std.mem.print(&path_buf, ".zig-cache/tmp/{s}/hosts", .{&tmp.sub_path});
    try std.Io.Dir.cwd().writeFile(h.io, .{ .sub_path = hosts_path, .data = "192.0.2.1 gw.example.com gw\n" });
    h.ropts.use_hosts = true;
    h.ropts.hosts_path = hosts_path;
    var c = try h.cache(.{ .max_network_lookups = .{ .per_s = 1, .burst = 1 } });
    defer c.deinit();

    for (0..2) |_| {
        var lit = try c.lookupIp("192.0.2.9");
        defer lit.deinit();
        var lit6 = try c.lookupIp("2001:db8::1");
        defer lit6.deinit();
        var onion = try c.lookupIp("x.onion");
        defer onion.deinit();
        var gw = try c.lookupIp("gw.example.com"); // /etc/hosts
        defer gw.deinit();
        try testing.expectEqual(@as(usize, 1), gw.lookup.items.len);
        try testing.expectEqual(@as(?[]const u8, null), gw.lookup.canonical);
    }
    try testing.expectEqual(@as(u32, 0), h.queries());
    const s = c.stats();
    try testing.expectEqual(@as(u64, 0), s.network_lookups);
    try testing.expectEqual(@as(u64, 0), s.budget_refused);
    try testing.expectEqual(@as(usize, 0), s.entries);
    try testing.expect(c.created <= 1); // only the hosts name needs a pooled Resolver
    // The single token is still there for a real lookup.
    var real = try c.lookupIp("real.example.com");
    defer real.deinit();
    try testing.expectEqual(@as(u64, 1), c.stats().network_lookups);
}

test "F3: the TTL runs from the moment the query was sent" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    h.stub.ttl.store(60, .release);
    h.stub.bump_clock = &h.clock;
    h.stub.bump_by.store(5, .release); // the lookup "takes" 5 s
    var c = try h.cache(.{});
    defer c.deinit();
    var a = try c.lookupIp("slowish.example.com");
    defer a.deinit();
    h.stub.bump_by.store(0, .release);
    // The query left at 1000: the answer expires at 1060, not 1065.
    h.clock.now = 1059;
    var hit = try c.lookupIp("slowish.example.com");
    defer hit.deinit();
    try testing.expectEqual(Source.cache, hit.source);
    h.clock.now = 1060;
    var again = try c.lookupIp("slowish.example.com");
    defer again.deinit();
    try testing.expectEqual(Source.network, again.source);
}

test "F4: a failure never arms backoff on an entry that holds a fresh answer" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{});
    defer c.deinit();
    var a = try c.lookupIp("host.example.com");
    defer a.deinit();
    // Another miss of the same key failed after the first one stored its answer.
    var kbuf: [key_buf_len]u8 = undefined;
    const k = nameKey(&kbuf, .ip, "host.example.com").?;
    c.mutex.lockUncancelable(c.io);
    var served = try c.failed(netaddr.Ip, k, error.Timeout, c.now(), false);
    c.mutex.unlock(c.io);
    defer served.deinit();
    try testing.expectEqual(Source.cache, served.source);
    try testing.expectEqual(@as(usize, 1), served.lookup.items.len);
    try testing.expectEqual(@as(u8, 0), c.map.get(k).?.fail_count);
    var hit = try c.lookupIp("host.example.com");
    defer hit.deinit();
    try testing.expectEqual(Source.cache, hit.source);
    try testing.expectEqual(@as(u32, 1), h.queries());
}

test "F5: a cancel while waiting for a pool slot gives the budget token back" {
    var h: Harness = .{ .timeout_ms = 10_000 };
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .max_concurrent_lookups = 1, .max_network_lookups = .{ .per_s = 1, .burst = 2 } });
    defer c.deinit();

    var slow: NamedLookup = .{ .c = &c, .name = "slow.example.com" };
    var f1 = try h.io.concurrent(NamedLookup.run, .{&slow});
    defer f1.await(h.io);
    errdefer h.stub.release_slow.store(true, .release);
    try waitFor(h.io, &h.stub.stashed);

    var fast: NamedLookup = .{ .c = &c, .name = "fast.example.com" };
    var f2 = try h.io.concurrent(NamedLookup.run, .{&fast});
    var f2_live = true;
    defer if (f2_live) f2.cancel(h.io);
    try waitForWaiters(&c, 1); // it holds a token and waits for the slot
    f2.cancel(h.io);
    f2_live = false;
    try testing.expect(!fast.ok.load(.acquire));
    try testing.expectEqual(@as(u64, 1), c.stats().network_lookups); // the slow one only

    h.stub.release_slow.store(true, .release);
    try waitFor(h.io, &slow.done);
    var third = try c.lookupIp("third.example.com"); // needs the refunded token
    defer third.deinit();
    try testing.expectEqual(@as(u64, 2), c.stats().network_lookups);
}

test "F6: resetFailures clears every backoff and keeps the answers" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .failure_backoff_min_s = 100, .failure_backoff_max_s = 100 });
    defer c.deinit();
    var kept = try c.lookupIp("kept.example.com");
    defer kept.deinit();
    h.stub.mode.store(.servfail, .release);
    try testing.expectError(error.ServerFailed, c.lookupIp("down.example.com"));
    try testing.expectError(error.ServerFailed, c.lookupIp("down.example.com")); // backed off: no query
    try testing.expectEqual(@as(u32, 2), h.queries());
    h.stub.mode.store(.answer, .release);
    try testing.expectError(error.ServerFailed, c.lookupIp("down.example.com")); // still armed
    try testing.expectEqual(@as(u32, 2), h.queries());

    c.resetFailures();
    var up = try c.lookupIp("down.example.com");
    defer up.deinit();
    try testing.expectEqual(Source.network, up.source);
    try testing.expectEqual(@as(u32, 3), h.queries());
    var hit = try c.lookupIp("kept.example.com");
    defer hit.deinit();
    try testing.expectEqual(Source.cache, hit.source);
}

test "every lookup kind answers a literal or a DNS-avoided name before the table, the budget and the pool" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .max_network_lookups = .{ .per_s = 1, .burst = 1 } });
    defer c.deinit();
    dropAnswer(c.lookupIp("real.example.com")); // spends the only token
    const before = c.stats();
    try testing.expectEqual(@as(u64, 1), before.misses);
    try testing.expectEqual(@as(u64, 1), before.network_lookups);

    // The budget is empty: anything that took a token would be BudgetExceeded.
    for ([_][]const u8{ "192.0.2.9", "2001:db8::1", "x.onion", "x.invalid" }) |n| {
        var a = try c.lookupIp(n);
        a.deinit();
    }
    try testing.expectError(error.BadName, c.lookupMx("x.onion"));
    try testing.expectError(error.BadName, c.lookupNs("x.onion"));
    try testing.expectError(error.BadName, c.lookupTxt("x.onion"));
    try testing.expectError(error.BadName, c.lookupCname("x.invalid"));
    try testing.expectError(error.BadName, c.lookupSrv("ldap", "tcp", "x.onion"));

    const s = c.stats();
    try testing.expectEqual(before.misses, s.misses);
    try testing.expectEqual(before.network_lookups, s.network_lookups);
    try testing.expectEqual(@as(u64, 0), s.budget_refused);
    try testing.expectEqual(@as(usize, 1), s.entries);
    try testing.expectEqual(@as(u32, 1), h.queries());
}

test "the TTL runs from the moment the query was sent, also after waiting for a pool slot" {
    var h: Harness = .{ .timeout_ms = 10_000 };
    try h.start(.v4);
    defer h.stop();
    h.stub.ttl.store(60, .release);
    var c = try h.cache(.{ .max_concurrent_lookups = 1 });
    defer c.deinit();

    var slow: NamedLookup = .{ .c = &c, .name = "slow.example.com" };
    var f1 = try h.io.concurrent(NamedLookup.run, .{&slow});
    defer f1.await(h.io);
    errdefer h.stub.release_slow.store(true, .release);
    try waitFor(h.io, &h.stub.stashed);

    var fast: NamedLookup = .{ .c = &c, .name = "fast.example.com" };
    var f2 = try h.io.concurrent(NamedLookup.run, .{&fast});
    defer f2.await(h.io);
    try waitForWaiters(&c, 1); // fast read the clock (t0) and now waits for the only slot
    const t_wait = h.clock.now;
    h.clock.now += 40; // 40 s pass before its query can be sent
    h.stub.release_slow.store(true, .release);
    try waitFor(h.io, &fast.done);
    try waitFor(h.io, &slow.done);
    const e = c.map.get("\x00fast.example.com").?;
    try testing.expectEqual(t_wait + 40 + 60, e.expires_s); // from the send, not from the first read
}

test "refundLocked gives back one count and one token, never above the burst" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .max_network_lookups = .{ .per_s = 1, .burst = 3 } });
    defer c.deinit();
    c.mutex.lockUncancelable(c.io);
    defer c.mutex.unlock(c.io);
    c.network_lookups = 5;
    c.tokens = 1;
    c.refundLocked();
    try testing.expectEqual(@as(u64, 4), c.network_lookups);
    try testing.expectEqual(@as(u32, 2), c.tokens);
    c.tokens = 3; // a full bucket stays full
    c.refundLocked();
    try testing.expectEqual(@as(u64, 3), c.network_lookups);
    try testing.expectEqual(@as(u32, 3), c.tokens);
    c.network_lookups = 0; // the count saturates at zero
    c.tokens = 0;
    c.refundLocked();
    try testing.expectEqual(@as(u64, 0), c.network_lookups);
    try testing.expectEqual(@as(u32, 1), c.tokens);
}

test "the direct bypass counts a lookup that reached DNS and not one that did not" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{});
    defer c.deinit();
    var a = try c.bypass(netaddr.Ip, @as([]const u8, "host.example.com"), callIp);
    a.deinit();
    try testing.expectEqual(@as(u64, 1), c.stats().network_lookups);
    var lit = try c.bypass(netaddr.Ip, @as([]const u8, "192.0.2.9"), callIp); // canonical == null: nothing was asked
    lit.deinit();
    try testing.expectEqual(@as(u64, 1), c.stats().network_lookups);
    try testing.expectEqual(@as(u32, 1), h.queries());
}

test "a fresh answer served by a failure is aged, capped at its stored TTL and becomes the most recently used" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    h.stub.ttl.store(60, .release);
    var c = try h.cache(.{ .max_entries = 2 });
    defer c.deinit();
    dropAnswer(c.lookupIp("a.example.com")); // stored at 1000, expires 1060
    dropAnswer(c.lookupIp("b.example.com")); // b is now the most recently used
    h.clock.now += 10;
    var kbuf: [key_buf_len]u8 = undefined;
    const ka = nameKey(&kbuf, .ip, "a.example.com").?;

    c.mutex.lockUncancelable(c.io);
    var aged = try c.failed(netaddr.Ip, ka, error.Timeout, c.now(), false);
    // an earlier `t` would give 70 s left: the stored TTL (60) is the ceiling
    var capped = try c.failed(netaddr.Ip, ka, error.Timeout, c.now() - 20, false);
    c.mutex.unlock(c.io);
    defer aged.deinit();
    defer capped.deinit();
    try testing.expectEqual(@as(?u32, 50), aged.lookup.ttl_s);
    try testing.expectEqual(@as(?u32, 60), capped.lookup.ttl_s);

    dropAnswer(c.lookupIp("c.example.com")); // evicts the least recently used: b, because a was touched
    var kb: [key_buf_len]u8 = undefined;
    try testing.expect(c.map.get(nameKey(&kb, .ip, "b.example.com").?) == null);
    try testing.expect(c.map.get(ka) != null);
}

test "resetFailures reaches every entry and clears the counters of the answers it keeps" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .stale_s = 1000, .failure_backoff_min_s = 100, .failure_backoff_max_s = 100 });
    defer c.deinit();
    h.stub.mode.store(.servfail, .release);
    try testing.expectError(error.ServerFailed, c.lookupIp("down1.example.com"));
    try testing.expectError(error.ServerFailed, c.lookupIp("down2.example.com"));
    h.stub.mode.store(.answer, .release);
    dropAnswer(c.lookupIp("kept.example.com")); // stored at 1000, expires 1060
    h.clock.now += 100; // expired, inside the stale window
    h.stub.mode.store(.servfail, .release);
    var st = try c.lookupIp("kept.example.com"); // served stale: arms the key's failure state
    st.deinit();
    try testing.expectEqual(@as(u64, 1), c.stats().stale_served);
    h.stub.mode.store(.answer, .release);
    dropAnswer(c.lookupIp("ok.example.com")); // the most recently used entry carries no failure
    var kbuf: [key_buf_len]u8 = undefined;
    const kk = nameKey(&kbuf, .ip, "kept.example.com").?;
    try testing.expect(c.map.get(kk).?.fail_count > 0);
    try testing.expect(c.map.get(kk).?.retry_at_s > 0);

    c.resetFailures();
    const e = c.map.get(kk).?;
    try testing.expect(e.payload != null);
    try testing.expectEqual(@as(u8, 0), e.fail_count);
    try testing.expectEqual(@as(u64, 0), e.retry_at_s);
    try testing.expectEqual(@as(usize, 2), c.stats().entries); // down1 and down2 are gone
}

test "forget drops one key: the next lookup asks the network, the others stay cached" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{});
    defer c.deinit();

    var a = try c.lookupIp("a.example.com");
    defer a.deinit();
    var b = try c.lookupIp("b.example.com");
    defer b.deinit();
    var m = try c.lookupMx("a.example.com");
    defer m.deinit();
    var r = try c.reverse(.{ .v4 = .{ 192, 0, 2, 1 } });
    defer r.deinit();
    var s = try c.lookupSrv("sip", "tcp", "a.example.com");
    defer s.deinit();
    try testing.expectEqual(@as(u32, 5), h.queries());

    c.forget(.ip, "A.Example.COM"); // keyed like a lookup: case folded
    var a2 = try c.lookupIp("a.example.com");
    defer a2.deinit();
    try testing.expectEqual(Source.network, a2.source);
    try testing.expectEqual(@as(u32, 6), h.queries());
    var b2 = try c.lookupIp("b.example.com");
    defer b2.deinit();
    try testing.expectEqual(Source.cache, b2.source);
    var m2 = try c.lookupMx("a.example.com"); // another kind of the same name
    defer m2.deinit();
    try testing.expectEqual(Source.cache, m2.source);

    c.forgetReverse(.{ .v4 = .{ 192, 0, 2, 1 } });
    var r2 = try c.reverse(.{ .v4 = .{ 192, 0, 2, 1 } });
    defer r2.deinit();
    try testing.expectEqual(Source.network, r2.source);
    c.forgetSrv("sip", "tcp", "a.example.com");
    var s2 = try c.lookupSrv("sip", "tcp", "a.example.com");
    defer s2.deinit();
    try testing.expectEqual(Source.network, s2.source);
    try testing.expectEqual(@as(u32, 8), h.queries());
}

test "forget of an absent key is a no-op" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{});
    defer c.deinit();
    var a = try c.lookupIp("a.example.com");
    defer a.deinit();
    c.forget(.ip, "never.example.com");
    c.forget(.txt, "a.example.com");
    c.forgetReverse(.{ .v6 = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } });
    c.forgetSrv("x", "udp", "a.example.com");
    const long: [key_buf_len]u8 = @splat('a'); // longer than any key the cache can build
    c.forget(.ip, &long); // too long for a key: nothing could have been cached
    const long_service: [256]u8 = @splat('s');
    c.forgetSrv(&long_service, "udp", "a.example.com");
    try testing.expectEqual(@as(usize, 1), c.stats().entries);
    var a2 = try c.lookupIp("a.example.com");
    defer a2.deinit();
    try testing.expectEqual(Source.cache, a2.source);
}

test "forget during backoff clears it: the key is asked again at once" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .failure_backoff_min_s = 100, .failure_backoff_max_s = 100 });
    defer c.deinit();
    h.stub.mode.store(.servfail, .release);
    try testing.expectError(error.ServerFailed, c.lookupIp("down.example.com"));
    try testing.expectError(error.ServerFailed, c.lookupIp("down.example.com")); // held by the backoff
    try testing.expectEqual(@as(u32, 1), h.queries());

    h.stub.mode.store(.answer, .release);
    c.forget(.ip, "down.example.com");
    try testing.expectEqual(@as(usize, 0), c.stats().entries);
    var ok = try c.lookupIp("down.example.com");
    defer ok.deinit();
    try testing.expectEqual(Source.network, ok.source);
    try testing.expectEqual(@as(u32, 2), h.queries());
}

test "stale_reason: the upstream failure, the backoff's error, the budget" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .stale_s = 1000, .stale_answer_ttl_s = 30, .max_network_lookups = .{ .per_s = 1, .burst = 2 } });
    defer c.deinit();
    var prime = try c.lookupIp("s.example.com"); // token 1
    defer prime.deinit();
    try testing.expectEqual(@as(?Error, null), prime.stale_reason);
    var hit = try c.lookupIp("s.example.com");
    defer hit.deinit();
    try testing.expectEqual(@as(?Error, null), hit.stale_reason);

    h.stub.mode.store(.servfail, .release);
    h.clock.now += 61;
    var s1 = try c.lookupIp("s.example.com"); // token 2 (plus 61 s refill, capped at 2): the upstream says no
    defer s1.deinit();
    try expectIp(&s1, .stale, 30);
    try testing.expectEqual(@as(?Error, error.ServerFailed), s1.stale_reason);

    var s2 = try c.lookupIp("s.example.com"); // inside the recheck: the backoff holds the error
    defer s2.deinit();
    try expectIp(&s2, .stale, 30);
    try testing.expectEqual(@as(?Error, error.ServerFailed), s2.stale_reason);
    try testing.expectEqual(@as(u32, 2), h.queries());

    // Budget: the recheck is over and no token is left.
    h.clock.now += 30;
    c.tokens = 0;
    c.refill_s = c.now();
    var s3 = try c.lookupIp("s.example.com");
    defer s3.deinit();
    try expectIp(&s3, .stale, 30);
    try testing.expectEqual(@as(?Error, error.BudgetExceeded), s3.stale_reason);
}

var probe_calls: u32 = 0;
var probe_v6_reachable: bool = false;

fn probeSource(dst: netaddr.Ip) ?netaddr.Ip {
    probe_calls += 1;
    return switch (dst) {
        .v4 => if (probe_v6_reachable) null else dst,
        .v6 => if (probe_v6_reachable) dst else null,
    };
}

test "a changed route source reorders a cache hit; resort_ip_hits = false keeps the stored order" {
    var h: Harness = .{};
    try h.start(.any);
    defer h.stop();
    var c = try h.cache(.{ .sort_source = probeSource });
    defer c.deinit();
    var a = try c.lookupIp("dual.example.com");
    defer a.deinit();
    try testing.expectEqual(@as(usize, 2), a.lookup.items.len);

    probe_v6_reachable = false;
    var h1 = try c.lookupIp("dual.example.com");
    defer h1.deinit();
    try testing.expectEqual(Source.cache, h1.source);
    try testing.expect(h1.lookup.items[0] == .v4);

    probe_v6_reachable = true; // the host's routes changed
    var h2 = try c.lookupIp("dual.example.com");
    defer h2.deinit();
    try testing.expectEqual(Source.cache, h2.source);
    try testing.expect(h2.lookup.items[0] == .v6);

    // The stored copy is untouched by either re-sort: the option off serves it as stored.
    c.options.resort_ip_hits = false;
    probe_calls = 0;
    var h3 = try c.lookupIp("dual.example.com");
    defer h3.deinit();
    try testing.expectEqual(@as(u32, 0), probe_calls);
}

test "forget drops exactly the asked kind of a name: all five name kinds" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{});
    defer c.deinit();
    const name = "alias.example.com";
    const kinds = [_]NameKind{ .ip, .mx, .ns, .txt, .cname };
    for (kinds) |kind| {
        // Everything cached, then one kind forgotten: only that one goes to the network.
        inline for (kinds) |k2| try testing.expect(try lookupKind(&c, k2, name) != null);
        c.forget(kind, name);
        for (kinds) |k2| {
            const src = try lookupKind(&c, k2, name);
            try testing.expectEqual(if (k2 == kind) Source.network else Source.cache, src.?);
        }
    }
}

fn lookupKind(c: *CachingResolver, kind: NameKind, name: []const u8) Error!?Source {
    switch (kind) {
        .ip => {
            var a = try c.lookupIp(name);
            defer a.deinit();
            return a.source;
        },
        .mx => {
            var a = try c.lookupMx(name);
            defer a.deinit();
            return a.source;
        },
        .ns => {
            var a = try c.lookupNs(name);
            defer a.deinit();
            return a.source;
        },
        .txt => {
            var a = try c.lookupTxt(name);
            defer a.deinit();
            return a.source;
        },
        .cname => {
            var a = try c.lookupCname(name);
            defer a.deinit();
            return a.source;
        },
    }
}

test "a stale IP answer is re-sorted like a cache hit; a network answer is left to the Resolver" {
    var h: Harness = .{};
    try h.start(.any);
    defer h.stop();
    var c = try h.cache(.{ .sort_source = probeSource, .stale_s = 1000, .stale_answer_ttl_s = 30 });
    defer c.deinit();
    probe_calls = 0;
    probe_v6_reachable = false;
    var a = try c.lookupIp("dual.example.com");
    defer a.deinit();
    try testing.expectEqual(Source.network, a.source);
    try testing.expectEqual(@as(u32, 0), probe_calls); // the cache layer never re-sorts a network answer

    h.stub.mode.store(.servfail, .release);
    h.clock.now += 61;
    var s1 = try c.lookupIp("dual.example.com"); // the upstream fails: stale
    defer s1.deinit();
    try testing.expectEqual(Source.stale, s1.source);
    try testing.expect(s1.lookup.items[0] == .v4);

    probe_v6_reachable = true;
    var s2 = try c.lookupIp("dual.example.com"); // the backoff holds: stale again, routes changed
    defer s2.deinit();
    try testing.expectEqual(Source.stale, s2.source);
    try testing.expect(s2.lookup.items[0] == .v6);
}

test "a hit of more than max_sort_candidates addresses keeps its order, and the default source is the system probe" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .sort_source = probeSource });
    defer c.deinit();
    comptime std.debug.assert(@TypeOf((Options{}).sort_source) == *const fn (netaddr.Ip) ?netaddr.Ip);
    if (comptime builtin.os.tag == .linux) try testing.expect((Options{}).sort_source == &netaddr.systemSource);

    var many: [netaddr.max_sort_candidates + 1]netaddr.Ip = undefined;
    for (&many, 0..) |*ip, i| ip.* = .{ .v4 = .{ 198, 51, 100, @intCast(200 - i) } };
    const src: Resolver.Lookup(netaddr.Ip) = .{ .arena = undefined, .items = &many, .status = .found, .ttl_s = 60, .canonical = null, .authenticated = false, .partial = false };
    var buf: [key_buf_len]u8 = undefined;
    c.store(netaddr.Ip, nameKey(&buf, .ip, "many.example.com").?, &src, c.now(), 60);

    probe_calls = 0;
    var hit = try c.lookupIp("many.example.com");
    defer hit.deinit();
    try testing.expectEqual(Source.cache, hit.source);
    try testing.expectEqual(many.len, hit.lookup.items.len);
    try testing.expectEqualSlices(netaddr.Ip, &many, hit.lookup.items); // unsorted: too many candidates
    try testing.expectEqual(@as(u32, 0), probe_calls);
}

// ── delta mutation audit 2026-11-16 (coalescing, prefetch, lookupIpMany): tests the first schemata run asked for ──

fn expectSource(r: anytype, want: Source) !void {
    var a = try r;
    defer a.deinit();
    try testing.expectEqual(want, a.source);
}

fn dueFlag(c: *CachingResolver, kind: Kind, name: []const u8) bool {
    var buf: [key_buf_len]u8 = undefined;
    const k = nameKey(&buf, kind, name).?;
    c.mutex.lockUncancelable(c.io);
    defer c.mutex.unlock(c.io);
    return c.map.get(k).?.prefetch_due;
}

test "refreshDue renews every kind of key: each key survives the round trip through its own bytes" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .prefetch_pct = 50 });
    defer c.deinit();
    const v4: netaddr.Ip = .{ .v4 = .{ 192, 0, 2, 1 } };
    const v6: netaddr.Ip = .{ .v6 = .{ 0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } };
    for (0..2) |round| {
        // Round 0 stores eight answers (60 s); after 40 s round 1 hits them late in the TTL and marks them.
        dropAnswer(c.lookupIp("pk.example.com"));
        dropAnswer(c.reverse(v4));
        dropAnswer(c.reverse(v6));
        dropAnswer(c.lookupMx("example.com"));
        dropAnswer(c.lookupNs("example.com"));
        dropAnswer(c.lookupTxt("example.com"));
        dropAnswer(c.lookupCname("alias.example.com"));
        dropAnswer(c.lookupSrv("sip", "tcp", "example.com"));
        if (round == 0) h.clock.add(40);
    }
    try testing.expectEqual(@as(u32, 8), h.queries());
    try testing.expectEqual(@as(usize, 8), try c.refreshDue(100));
    try testing.expectEqual(@as(u32, 16), h.queries()); // one network lookup per key
    try testing.expectEqual(@as(u32, 2), h.stub.sip_queries.load(.acquire)); // the SRV refresh asked for the same name again
    try testing.expectEqual(@as(usize, 0), try c.refreshDue(100));
    h.clock.add(30); // 70 s after the first answers: past their TTL, inside the renewed one
    try expectSource(c.lookupIp("pk.example.com"), .cache);
    try expectSource(c.reverse(v4), .cache);
    try expectSource(c.reverse(v6), .cache);
    try expectSource(c.lookupMx("example.com"), .cache);
    try expectSource(c.lookupNs("example.com"), .cache);
    try expectSource(c.lookupTxt("example.com"), .cache);
    try expectSource(c.lookupCname("alias.example.com"), .cache);
    try expectSource(c.lookupSrv("sip", "tcp", "example.com"), .cache);
    try testing.expectEqual(@as(u32, 16), h.queries());
    const st = c.stats();
    try testing.expectEqual(@as(u64, 8), st.prefetches);
    try testing.expectEqual(@as(u64, 8), st.misses); // the refreshes are no misses
}

test "refreshDue takes at most max keys, the most recently used first, each key once" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .prefetch_pct = 50 });
    defer c.deinit();
    dropAnswer(c.lookupIp("old.example.com"));
    dropAnswer(c.lookupIp("new.example.com"));
    h.clock.add(40);
    dropAnswer(c.lookupIp("old.example.com")); // marks both, the newer use last
    dropAnswer(c.lookupIp("new.example.com"));
    try testing.expect(dueFlag(&c, .ip, "old.example.com") and dueFlag(&c, .ip, "new.example.com"));
    try testing.expectEqual(@as(usize, 0), try c.refreshDue(0));
    try testing.expectEqual(@as(usize, 1), try c.refreshDue(1));
    try testing.expect(dueFlag(&c, .ip, "old.example.com")); // the newer use went first
    try testing.expect(!dueFlag(&c, .ip, "new.example.com"));
    try testing.expectEqual(@as(u32, 3), h.queries());
    try testing.expectEqual(@as(usize, 1), try c.refreshDue(1)); // the older one is still found behind the newer
    try testing.expect(!dueFlag(&c, .ip, "old.example.com"));
    try testing.expectEqual(@as(usize, 0), try c.refreshDue(1));
    try testing.expectEqual(@as(u32, 4), h.queries());
}

const RefreshRun = struct {
    c: *CachingResolver,
    res: ?(error{Canceled}!usize) = null,
    done: std.atomic.Value(bool) = .init(false),
    fn run(r: *RefreshRun) void {
        r.res = r.c.refreshDue(10);
        r.done.store(true, .release);
    }
};

test "refreshDue can be cancelled: the cancel stops it instead of being counted as a failed refresh" {
    var h: Harness = .{ .timeout_ms = 10_000 };
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .prefetch_pct = 50 });
    defer c.deinit();
    var first: NamedLookup = .{ .c = &c, .name = "slow.example.com" };
    var f1 = try h.io.concurrent(NamedLookup.run, .{&first});
    defer f1.await(h.io);
    errdefer h.stub.release_slow.store(true, .release);
    try waitFor(h.io, &h.stub.stashed);
    h.stub.release_slow.store(true, .release);
    try waitFor(h.io, &first.done);
    try testing.expect(first.ok.load(.acquire));
    h.stub.release_slow.store(false, .release);
    h.clock.add(40);
    try expectSource(c.lookupIp("slow.example.com"), .cache); // late in the TTL: marked

    var r: RefreshRun = .{ .c = &c };
    var f2 = try h.io.concurrent(RefreshRun.run, .{&r});
    var f2_over = false;
    defer if (!f2_over) f2.cancel(h.io);
    for (0..5000) |_| {
        if (h.queries() >= 2) break;
        try h.io.sleep(.fromMilliseconds(2), .awake);
    } else return error.TestTimeout;
    f2.cancel(h.io); // the refresh's answer is held
    f2_over = true;
    try testing.expectError(error.Canceled, r.res.?);
    try testing.expectEqual(@as(usize, 0), inflightCount(&c));
    h.stub.release_slow.store(true, .release);
}

test "the prefetch mark: strictly less than prefetch_pct of the stored TTL left, exactly (20 % and 99 % of 60 s)" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .prefetch_pct = 20 });
    defer c.deinit();
    dropAnswer(c.lookupIp("edge.example.com")); // stored for 60 s
    h.clock.add(48); // 12 s left: 12 * 100 is not below 20 * 60
    dropAnswer(c.lookupIp("edge.example.com"));
    try testing.expect(!dueFlag(&c, .ip, "edge.example.com"));
    h.clock.add(1); // 11 s left
    dropAnswer(c.lookupIp("edge.example.com"));
    try testing.expect(dueFlag(&c, .ip, "edge.example.com"));

    var c99 = try h.cache(.{ .prefetch_pct = 99 });
    defer c99.deinit();
    dropAnswer(c99.lookupIp("edge.example.com")); // stored for 60 s
    dropAnswer(c99.lookupIp("edge.example.com")); // 60 s left: 6000 is not below 99 * 60
    try testing.expect(!dueFlag(&c99, .ip, "edge.example.com"));
    h.clock.add(1); // 59 s left: 5900 is below 5940, and 59 * 101 is not
    dropAnswer(c99.lookupIp("edge.example.com"));
    try testing.expect(dueFlag(&c99, .ip, "edge.example.com"));
}

fn waitForQueries(h: *Harness, n: u32) !void {
    for (0..5000) |_| {
        if (h.queries() >= n) return;
        try h.io.sleep(.fromMilliseconds(2), .awake);
    }
    return error.TestTimeout;
}

/// Stores `slow.example.com` (the stub holds the answer until released), leaving the stub holding nothing.
fn primeSlow(h: *Harness, c: *CachingResolver) !void {
    var prime: NamedLookup = .{ .c = c, .name = "slow.example.com" };
    var f = try h.io.concurrent(NamedLookup.run, .{&prime});
    defer f.await(h.io);
    errdefer h.stub.release_slow.store(true, .release);
    try waitFor(h.io, &h.stub.stashed);
    h.stub.release_slow.store(true, .release);
    try waitFor(h.io, &prime.done);
    try testing.expect(prime.ok.load(.acquire));
    h.stub.release_slow.store(false, .release);
}

test "a refresh the budget refuses keeps the answer and serves nothing stale" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .prefetch_pct = 50, .stale_s = 300, .max_network_lookups = .{ .per_s = 1, .burst = 1 } });
    defer c.deinit();
    dropAnswer(c.lookupIp("bg.example.com")); // spends the token
    h.clock.add(40);
    dropAnswer(c.lookupIp("bg.example.com")); // late in the TTL: marked
    h.clock.add(25); // expired, inside the stale window; the bucket is full again
    dropAnswer(c.lookupIp("other.example.com")); // spends the token
    try testing.expectEqual(@as(usize, 1), try c.refreshDue(1));
    const st = c.stats();
    try testing.expectEqual(@as(u64, 1), st.budget_refused);
    try testing.expectEqual(@as(u64, 0), st.stale_served); // nobody reads a refresh's answer
    try testing.expectEqual(@as(u64, 2), st.network_lookups);
}

test "a new answer clears the prefetch mark an expired one carried" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .prefetch_pct = 50, .stale_s = 300 });
    defer c.deinit();
    dropAnswer(c.lookupIp("mk.example.com"));
    h.clock.add(40);
    dropAnswer(c.lookupIp("mk.example.com"));
    try testing.expect(dueFlag(&c, .ip, "mk.example.com"));
    h.clock.add(25); // expired, inside the stale window: the entry stays
    try expectSource(c.lookupIp("mk.example.com"), .network);
    try testing.expect(!dueFlag(&c, .ip, "mk.example.com"));
    try testing.expectEqual(@as(usize, 0), try c.refreshDue(10));
    try testing.expectEqual(@as(u32, 2), h.queries());
}

test "a failed refresh remembers its error: the next lookup inside the backoff gets it" {
    var h: Harness = .{};
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .prefetch_pct = 20, .failure_backoff_min_s = 100, .failure_backoff_max_s = 300 });
    defer c.deinit();
    dropAnswer(c.lookupIp("le.example.com"));
    h.clock.add(50);
    dropAnswer(c.lookupIp("le.example.com")); // marked
    h.stub.mode.store(.servfail, .release);
    try testing.expectEqual(@as(usize, 1), try c.refreshDue(1));
    const sent = h.queries();
    h.clock.add(11); // expired (61 s), 11 s into the 100 s backoff
    try testing.expectError(error.ServerFailed, c.lookupIp("le.example.com"));
    try testing.expectEqual(sent, h.queries());
}

test "a failed refresh of a key forgotten meanwhile leaves no failure entry behind" {
    var h: Harness = .{ .timeout_ms = 10_000 };
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .prefetch_pct = 50 });
    defer c.deinit();
    try primeSlow(&h, &c);
    h.clock.add(40);
    try expectSource(c.lookupIp("slow.example.com"), .cache); // marked
    h.stub.mode.store(.servfail, .release);
    var r: RefreshRun = .{ .c = &c };
    var f = try h.io.concurrent(RefreshRun.run, .{&r});
    defer f.await(h.io);
    errdefer h.stub.release_slow.store(true, .release);
    try waitFor(h.io, &h.stub.stashed); // the refresh's SERVFAIL is held
    c.forget(.ip, "slow.example.com");
    h.stub.release_slow.store(true, .release);
    try waitFor(h.io, &r.done);
    try testing.expectEqual(@as(usize, 1), try r.res.?);
    try testing.expectEqual(@as(usize, 0), c.stats().entries);
}

test "a refresh parked behind a user lookup of its key reads what that lookup stored" {
    var h: Harness = .{ .timeout_ms = 10_000 };
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .prefetch_pct = 50, .stale_s = 300 });
    defer c.deinit();
    try primeSlow(&h, &c);
    h.clock.add(40);
    try expectSource(c.lookupIp("slow.example.com"), .cache); // marked
    h.clock.add(25); // expired, inside the stale window: the mark stays with the entry

    var user: NamedLookup = .{ .c = &c, .name = "slow.example.com" };
    var f1 = try h.io.concurrent(NamedLookup.run, .{&user});
    defer f1.await(h.io);
    errdefer h.stub.release_slow.store(true, .release);
    try waitFor(h.io, &h.stub.stashed); // the user's miss is in flight, its answer held
    var r: RefreshRun = .{ .c = &c };
    var f2 = try h.io.concurrent(RefreshRun.run, .{&r});
    defer f2.await(h.io);
    try waitForFlightWaiters(&c, 1);
    h.stub.release_slow.store(true, .release);
    try waitFor(h.io, &user.done);
    try waitFor(h.io, &r.done);
    try testing.expectEqual(@as(usize, 1), try r.res.?);
    try testing.expectEqual(@as(u32, 2), h.queries()); // the prime and the user's lookup: the refresh asked nobody
    try testing.expectEqual(@as(u64, 2), c.stats().network_lookups);
}

test "waiters of a cancelled lead ask the network themselves, and a newcomer is not parked behind them" {
    var h: Harness = .{ .timeout_ms = 10_000 };
    try h.start(.v4);
    defer h.stop();
    var c = try h.cache(.{ .max_concurrent_lookups = 8 });
    defer c.deinit();
    var lead: NamedLookup = .{ .c = &c, .name = "slow.example.com" };
    var f1 = try h.io.concurrent(NamedLookup.run, .{&lead});
    var f1_over = false;
    defer if (!f1_over) f1.cancel(h.io);
    errdefer h.stub.release_slow.store(true, .release);
    try waitFor(h.io, &h.stub.stashed);

    var w1: NamedLookup = .{ .c = &c, .name = "slow.example.com" };
    var w2: NamedLookup = .{ .c = &c, .name = "slow.example.com" };
    var f2 = try h.io.concurrent(NamedLookup.run, .{&w1});
    defer f2.cancel(h.io);
    var f3 = try h.io.concurrent(NamedLookup.run, .{&w2});
    defer f3.cancel(h.io);
    try waitForFlightWaiters(&c, 2);
    f1.cancel(h.io); // the lead gives up
    f1_over = true;
    try waitForQueries(&h, 3); // both waiters ask at once; neither queues behind the other

    var late: NamedLookup = .{ .c = &c, .name = "slow.example.com" };
    var f4 = try h.io.concurrent(NamedLookup.run, .{&late});
    defer f4.cancel(h.io);
    try waitForQueries(&h, 4); // an uncoalesced lookup is no flight to park behind
    try testing.expectEqual(@as(u32, 0), c.flight_waiters);
}
