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
//!    uncached (`source = .network`): the hosts file can change.
//!  - Positive answers keep `clamp(ttl_s, min_ttl_s, max_ttl_s)`, negative
//!    ones (NXDOMAIN, NODATA; RFC 2308) `clamp(ttl_s, negative_min_ttl_s,
//!    negative_max_ttl_s)`. An answer without a TTL (an empty one without
//!    SOA) keeps `no_ttl_s` as it is, unclamped; 0 = not stored. `lookupIp`
//!    answers marked `partial` are kept at most `partial_ttl_s`.
//!  - Upstream failures (`Timeout`, `ServerFailed`, `NetworkFailed`,
//!    `MalformedResponse`, `DohFailed`, `TlsFailed`) serve an expired entry
//!    still inside `stale_s` (RFC 8767; off by default) and arm a per-key
//!    exponential backoff during which the key is not asked again.
//!  - Thread-safe: one `std.Io.Mutex` guards the table and is never held
//!    across a network lookup. The cache owns its `Resolver`s (a `Resolver` is
//!    single-owner): it creates them lazily from the `Resolver.Options` given
//!    to `init`, at most `Options.max_concurrent_lookups` of them, and a miss
//!    takes a free one for the duration of its lookup (waiting, cancelable,
//!    when all are busy). One slow name therefore never blocks a miss on
//!    another. Two concurrent misses on the SAME key may both query (no
//!    request coalescing yet).
//!  - Memory: everything is under `gpa`, the table owns clones; an
//!    allocation failure while storing returns the answer uncached.

const std = @import("std");
const testkit = @import("testkit");
const netaddr = @import("netaddr");
const message = @import("message.zig");
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
};

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
};

/// `error.InvalidOptions`: `max_entries` 0, `min_ttl_s` > `max_ttl_s`,
/// `negative_min_ttl_s` > `negative_max_ttl_s`, a zero or inverted backoff,
/// a budget with `per_s` or `burst` 0, `max_concurrent_lookups` 0. The slices
/// inside `resolver_options` (servers, paths, EDNS options) must outlive the
/// cache.
pub fn init(gpa: std.mem.Allocator, io: std.Io, resolver_options: Resolver.Options, options: Options) error{InvalidOptions}!CachingResolver {
    const o = options;
    if (o.max_entries == 0) return error.InvalidOptions;
    if (o.min_ttl_s > o.max_ttl_s or o.negative_min_ttl_s > o.negative_max_ttl_s) return error.InvalidOptions;
    if (o.failure_backoff_min_s == 0 or o.failure_backoff_min_s > o.failure_backoff_max_s) return error.InvalidOptions;
    if (o.max_network_lookups) |b| if (b.per_s == 0 or b.burst == 0) return error.InvalidOptions;
    if (o.max_concurrent_lookups == 0) return error.InvalidOptions;
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
    };
}

// ── lookups ─────────────────────────────────────────────────────────────────

pub fn lookupIp(c: *CachingResolver, name: []const u8) Error!Answer(netaddr.Ip) {
    var buf: [key_buf_len]u8 = undefined;
    return c.run(netaddr.Ip, nameKey(&buf, .ip, name), name, callIp);
}

pub fn reverse(c: *CachingResolver, ip: netaddr.Ip) Error!Answer([]const u8) {
    var buf: [key_buf_len]u8 = undefined;
    buf[0] = @backingInt(Kind.reverse);
    const key: []const u8 = switch (ip) {
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
    return c.run([]const u8, key, ip, callReverse);
}

pub fn lookupMx(c: *CachingResolver, name: []const u8) Error!Answer(Resolver.Mx) {
    var buf: [key_buf_len]u8 = undefined;
    return c.run(Resolver.Mx, nameKey(&buf, .mx, name), name, callMx);
}

pub fn lookupNs(c: *CachingResolver, name: []const u8) Error!Answer([]const u8) {
    var buf: [key_buf_len]u8 = undefined;
    return c.run([]const u8, nameKey(&buf, .ns, name), name, callNs);
}

pub fn lookupTxt(c: *CachingResolver, name: []const u8) Error!Answer([]const u8) {
    var buf: [key_buf_len]u8 = undefined;
    return c.run([]const u8, nameKey(&buf, .txt, name), name, callTxt);
}

pub fn lookupCname(c: *CachingResolver, name: []const u8) Error!Answer([]const u8) {
    var buf: [key_buf_len]u8 = undefined;
    return c.run([]const u8, nameKey(&buf, .cname, name), name, callCname);
}

pub fn lookupSrv(c: *CachingResolver, service: []const u8, proto: []const u8, name: []const u8) Error!Answer(Resolver.Srv) {
    var buf: [key_buf_len]u8 = undefined;
    const key = srvKey(&buf, service, proto, name);
    return c.run(Resolver.Srv, key, SrvArgs{ .service = service, .proto = proto, .name = name }, callSrv);
}

const SrvArgs = struct { service: []const u8, proto: []const u8, name: []const u8 };

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
    ctx: anytype,
    comptime call: fn (*Resolver, @TypeOf(ctx)) Resolver.Error!Resolver.Lookup(T),
) Error!Answer(T) {
    const io = c.io;
    const k = key orelse return c.bypass(T, ctx, call);

    c.mutex.lockUncancelable(io);
    var held = true;
    defer if (held) c.mutex.unlock(io);

    const t0 = c.now();
    var entry: ?*Entry = c.map.get(k);
    if (entry) |e| {
        c.touch(e);
        if (e.payload != null and t0 < e.expires_s) {
            const ans = try c.answerFrom(T, e, .cache, @min(e.expires_s -| t0, e.stored_ttl));
            c.hits += 1;
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
    c.misses += 1;
    const stale_entry: ?*Entry = if (entry) |e| (if (c.staleUsable(e, t0)) e else null) else null;
    if (entry) |e| {
        if (e.fail_count > 0 and t0 < e.retry_at_s) {
            if (stale_entry) |s| return c.staleAnswer(T, s);
            return e.last_err;
        }
    }
    if (c.options.max_network_lookups) |b| {
        if (!c.takeToken(b, t0)) {
            c.budget_refused += 1;
            if (stale_entry) |s| return c.staleAnswer(T, s);
            return error.BudgetExceeded;
        }
    }
    c.network_lookups += 1;
    c.mutex.unlock(io);
    held = false;

    const slot = try c.acquire();
    const res = call(&slot.resolver, ctx);
    c.release(slot);

    c.mutex.lockUncancelable(io);
    held = true;
    const t1 = c.now();
    var lk = res catch |err| return c.failed(T, k, err, t1);
    return c.succeeded(T, k, &lk, t1);
}

/// A key that does not fit the key buffer: straight to the resolver.
fn bypass(
    c: *CachingResolver,
    comptime T: type,
    ctx: anytype,
    comptime call: fn (*Resolver, @TypeOf(ctx)) Resolver.Error!Resolver.Lookup(T),
) Error!Answer(T) {
    c.mutex.lockUncancelable(c.io);
    c.network_lookups += 1;
    c.mutex.unlock(c.io);
    const slot = try c.acquire();
    defer c.release(slot);
    return .{ .lookup = try call(&slot.resolver, ctx), .source = .network };
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
fn failed(c: *CachingResolver, comptime T: type, k: []const u8, err: Resolver.Error, t: u64) Error!Answer(T) {
    if (!isUpstreamFailure(err)) return err;
    const e = c.failureEntry(k) orelse return err;
    e.fail_count +|= 1;
    e.last_err = err;
    var delay = c.backoffDelay(e.fail_count);
    const stale_ok = c.staleUsable(e, t);
    if (stale_ok) delay = @max(delay, c.options.stale_answer_ttl_s);
    e.retry_at_s = t +| delay;
    if (stale_ok) return c.staleAnswer(T, e);
    return err;
}

/// Called with `mutex` held. Applies the TTL policy and keeps a clone.
fn succeeded(c: *CachingResolver, comptime T: type, k: []const u8, lk: *Resolver.Lookup(T), t: u64) Answer(T) {
    if (lk.canonical == null) return .{ .lookup = lk.*, .source = .network }; // literal / hosts: never cached
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
}

fn answerFrom(c: *CachingResolver, comptime T: type, e: *Entry, source: Source, ttl: u32) error{OutOfMemory}!Answer(T) {
    var lk = try Payload.of(T, &e.payload.?).clone(c.gpa);
    lk.ttl_s = ttl;
    return .{ .lookup = lk, .source = source };
}

fn staleAnswer(c: *CachingResolver, comptime T: type, e: *Entry) error{OutOfMemory}!Answer(T) {
    const a = try c.answerFrom(T, e, .stale, c.options.stale_answer_ttl_s);
    c.stale_served += 1;
    return a;
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
        try st.sock.send(st.io, &in.from, w.buffered());
    }
};

const TestClock = struct {
    now: u64 = 1000,

    fn read(ctx: ?*anyopaque) u64 {
        const s: *TestClock = @ptrCast(@alignCast(ctx.?));
        return s.now;
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
    try testing.expectEqual(s.misses, s.network_lookups);
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
}
