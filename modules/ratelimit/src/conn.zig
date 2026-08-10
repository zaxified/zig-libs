// SPDX-License-Identifier: MIT

//! Connection-establishment rate limiting, keyed by *user* rather than by
//! address — the `http.Server.Options.on_connect` half of this module.
//!
//! `Limiter` (root.zig) limits **requests**, after a connection exists and
//! its headers are parsed. This limits **new connections**, on the accept
//! loop, before a byte is read: the only place a connection can be refused
//! at TCP cost only (`ConnDecision.reject` closes the socket and writes
//! nothing — no 429, no response bytes spent on an abuser).
//!
//! ## Identity: a user is a list of CIDR prefixes
//!
//! There is no mTLS and no JWT this early — the peer address is all the
//! server has. A **user** is therefore a configured set of prefixes
//! (`User.prefixes`, v4 and v6), and every address inside them shares **one**
//! token bucket. Prefixes, not single addresses: a real customer arrives from
//! a range, and "4 new connections per second per user" keyed per address
//! would really be "4 per second per address" — the limit would mean nothing
//! to anyone with a /24.
//!
//! Matching is first-match-wins over `Options.users` in configuration order,
//! so deliberately overlapping entries (a specific prefix listed before the
//! range that encloses it) resolve predictably. Peer addresses are `unmap`ped
//! first, so a dual-stack listener handing out `::ffff:192.0.2.7` matches a
//! `192.0.2.0/24` prefix.
//!
//! ## Unlisted addresses have a defined default — per address, not shared
//!
//! Traffic from outside every configured prefix gets `Options.rate_per_s` /
//! `Options.burst` **per address** (v4) or per `unlisted_v6_bits` prefix
//! (v6, default /64 — see below). One shared default bucket would let a
//! single stranger starve every other stranger, which is a denial of service
//! wearing a rate limiter's clothes. Unlisted traffic is never "unlimited"
//! and never "denied" by default: it is limited, at the stated numbers.
//!
//! ## The keyed table is itself a DoS surface
//!
//! Any per-address table is attackable by address rotation, and IPv6 makes
//! that free: a /64 is one host's *normal* allocation and holds 2^64
//! addresses. Two mechanisms bound it, and it is worth being precise about
//! what each one buys:
//!
//! 1. **Unlisted v6 addresses are keyed by their /64**
//!    (`unlisted_v6_bits`), not by the full 128 bits. Rotating inside one
//!    /64 — the free, unlimited case — collapses to a single bucket and
//!    buys the attacker nothing at all.
//! 2. **The unlisted table is bounded** (`max_unlisted_keys`, LRU + idle
//!    TTL, inherited from `Limiter`). An attacker holding a /48 still has
//!    2^16 distinct /64s and can churn the table.
//!
//! **What the attacker gets, stated plainly:** churning the unlisted table
//! evicts *other unlisted* keys, and an evicted key restarts with a full
//! bucket — so a flood can hand other strangers up to `burst` extra
//! connections, and can reset its own limit at the price of also resetting
//! everyone else's. What it cannot do is touch a **configured user**:
//! listed users' buckets live in a fixed array allocated at `init`, are
//! never stored in the evictable table, and are therefore unreachable by any
//! amount of address rotation. That is the property the whole design is for
//! — the customers you named cannot have their limit reset, or their memory
//! consumed, by a stranger with an IPv6 range.

const std = @import("std");
const rl = @import("root.zig");
const http = @import("http");
const netaddr = @import("netaddr");

const Allocator = std.mem.Allocator;
const TokenBucket = rl.TokenBucket;
const Decision = rl.Decision;
const Clock = rl.Clock;

/// Owner's ruling (2026-08-10): max 4 new connections per second per user.
pub const default_conn_rate_per_s: f64 = 4;
/// Burst allowance. A browser opening several tabs, or an h2 client racing
/// happy-eyeballs sockets, legitimately establishes a handful of connections
/// at once; without a burst the limit would refuse ordinary clients.
pub const default_conn_burst: u32 = 8;

/// One configured user: a name (for diagnostics only — matching never reads
/// it) and the CIDR prefixes that identify it. Both slices are borrowed:
/// they must outlive the `ConnectionLimiter`.
pub const User = struct {
    name: []const u8,
    /// The user's addresses, v4 and/or v6, in CIDR form. Every address in
    /// any of them shares this user's single bucket. Must be non-empty (a
    /// user no address can match is a configuration mistake, not a policy).
    prefixes: []const netaddr.Prefix,
    /// Per-user rate override; null = `Options.rate_per_s`.
    rate_per_s: ?f64 = null,
    /// Per-user burst override; null = `Options.burst`.
    burst: ?u32 = null,
};

pub const Options = struct {
    /// Configured users, matched first-match-wins in this order.
    users: []const User = &.{},
    /// Default sustained rate — for users without an override and for every
    /// unlisted address. Must be > 0 and finite.
    rate_per_s: f64 = default_conn_rate_per_s,
    /// Default burst, same audience as `rate_per_s`. Must be ≥ 1.
    burst: u32 = default_conn_burst,
    /// Prefix length an unlisted **IPv4** address is keyed by. /32 (one
    /// bucket per address) is the honest default: v4 addresses are scarce
    /// enough that rotation is not free, and coarser keying would merge
    /// unrelated customers behind one ISP.
    unlisted_v4_bits: u8 = 32,
    /// Prefix length an unlisted **IPv6** address is keyed by. /64 by
    /// default: that is the standard single-site/single-host allocation, so
    /// rotating within it is one host talking to us and must not buy a fresh
    /// bucket. Setting this to 128 restores per-address keying and hands
    /// anyone with a /64 an unlimited supply of buckets — do not.
    unlisted_v6_bits: u8 = 64,
    /// Memory bound on the unlisted table; beyond it the least-recently-used
    /// key is evicted (see the type doc for what that buys an attacker).
    /// Configured users are *not* stored here and are unaffected.
    max_unlisted_keys: usize = 4096,
    /// Idle expiry for unlisted keys (0 disables); memory stays bounded by
    /// `max_unlisted_keys` either way.
    unlisted_ttl_ms: u64 = 10 * std.time.ms_per_min,
    /// Time source — inject a fake for deterministic tests. A rate-limit
    /// test that sleeps on the wall clock is flaky by construction.
    clock: Clock = .monotonic,
};

/// Per-user connection-establishment limiter for
/// `http.Server.Options.on_connect`.
///
/// Thread-safety: internally synchronized, like `Limiter` (spinlock around
/// an O(1) critical section; Zig 0.16 std has no io-less blocking mutex).
/// The hook runs inline on the accept loop — with `Options.accept_threads`
/// > 1 there are several accept loops and they race.
///
/// Cost per connection: a linear scan over the configured prefixes (a
/// handful of masked compares) plus, for unlisted peers, one hash lookup.
/// Deliberately not an LPM trie: this runs once per *connection*, next to a
/// TCP handshake, and configuration is a hand-written user list.
pub const ConnectionLimiter = struct {
    gpa: Allocator,
    options: Options,
    lock: std.atomic.Mutex = .unlocked,
    /// One bucket per configured user, parallel to `options.users`.
    /// **Fixed-size, allocated once, never evicted** — this is what makes a
    /// configured user immune to table-flooding (see the module doc).
    user_buckets: []TokenBucket,
    /// Unlisted peers only: the bounded LRU store.
    unlisted: rl.Limiter,

    /// Key encoding for the unlisted table: one family tag byte + up to 16
    /// masked address bytes.
    const key_len_max = 17;

    pub fn init(gpa: Allocator, options: Options) Allocator.Error!ConnectionLimiter {
        std.debug.assert(options.rate_per_s > 0 and std.math.isFinite(options.rate_per_s));
        std.debug.assert(options.burst >= 1);
        std.debug.assert(options.unlisted_v4_bits <= 32);
        std.debug.assert(options.unlisted_v6_bits <= 128);
        for (options.users) |u| {
            std.debug.assert(u.prefixes.len >= 1);
            std.debug.assert(u.rate_per_s == null or (u.rate_per_s.? > 0 and std.math.isFinite(u.rate_per_s.?)));
            std.debug.assert(u.burst == null or u.burst.? >= 1);
        }

        const buckets = try gpa.alloc(TokenBucket, options.users.len);
        const now = options.clock.now();
        for (buckets, options.users) |*b, u| b.* = .full(userCfg(options, u), now);

        return .{
            .gpa = gpa,
            .options = options,
            .user_buckets = buckets,
            .unlisted = .init(gpa, .{
                .rate_per_s = options.rate_per_s,
                .burst = options.burst,
                .max_keys = options.max_unlisted_keys,
                .max_key_len = key_len_max,
                .ttl_ms = options.unlisted_ttl_ms,
                .clock = options.clock,
                // Never used: this Limiter is driven only through
                // `allowAt` with a key we build from the peer address.
                // There is no request here — the whole point is that the
                // decision happens before one exists — so any request-shaped
                // key source would be a lie. Reaching it means someone
                // wired this inner Limiter up as router middleware.
                .key = .{ .custom = .{ .keyFor = unusedKeyFor } },
            }),
        };
    }

    pub fn deinit(cl: *ConnectionLimiter) void {
        cl.unlisted.deinit();
        cl.gpa.free(cl.user_buckets);
        cl.* = undefined;
    }

    /// Decide one new connection from `peer`, at the injected clock's now.
    /// Thread-safe; never fails (the unlisted path inherits `Limiter`'s
    /// documented fail-open on allocator exhaustion).
    pub fn allowPeer(cl: *ConnectionLimiter, peer: netaddr.Ip) Decision {
        return cl.allowPeerAt(peer, cl.options.clock.now());
    }

    /// `allowPeer` at an explicit instant — the deterministic-test entry
    /// point. `now_ns` must be non-decreasing across calls.
    pub fn allowPeerAt(cl: *ConnectionLimiter, peer: netaddr.Ip, now_ns: u64) Decision {
        const ip = peer.unmap();
        if (cl.userIndex(ip)) |i| {
            const cfg = userCfg(cl.options, cl.options.users[i]);
            lockSpin(&cl.lock);
            defer cl.lock.unlock();
            return cl.user_buckets[i].allowAt(cfg, now_ns);
        }
        var buf: [key_len_max]u8 = undefined;
        return cl.unlisted.allowAt(cl.unlistedKey(ip, &buf), now_ns);
    }

    /// The `http.Server.OnConnectFn` form: pass this as
    /// `Options.on_connect` with `Options.on_connect_ctx = &limiter`.
    /// Rejection closes the socket without a byte written or a task spawned.
    pub fn onConnect(ctx: ?*anyopaque, peer: std.Io.net.IpAddress) http.Server.ConnDecision {
        const cl: *ConnectionLimiter = @ptrCast(@alignCast(ctx.?));
        const ip: netaddr.Ip = switch (peer) {
            .ip4 => |a| .{ .v4 = a.bytes },
            .ip6 => |a| .{ .v6 = a.bytes },
        };
        return if (cl.allowPeer(ip).allowed) .accept else .reject;
    }

    /// Index of the configured user owning `ip` (first match wins), or null
    /// when the address is unlisted. `ip` should already be `unmap`ped.
    pub fn userIndex(cl: *const ConnectionLimiter, ip: netaddr.Ip) ?usize {
        for (cl.options.users, 0..) |u, i| {
            for (u.prefixes) |p| if (p.contains(ip)) return i;
        }
        return null;
    }

    /// Distinct unlisted keys currently tracked (diagnostics / tests).
    /// Configured users are never counted — they are not in this table.
    pub fn unlistedKeyCount(cl: *ConnectionLimiter) usize {
        return cl.unlisted.keyCount();
    }

    /// Family tag + the address masked to the configured unlisted prefix
    /// length. Binary, not text: cheaper on the accept path and free of any
    /// question about two spellings of one address.
    fn unlistedKey(cl: *const ConnectionLimiter, ip: netaddr.Ip, buf: *[key_len_max]u8) []const u8 {
        const bits = switch (ip) {
            .v4 => cl.options.unlisted_v4_bits,
            .v6 => cl.options.unlisted_v6_bits,
        };
        const masked = (netaddr.Prefix{ .addr = ip, .bits = bits }).masked().addr;
        switch (masked) {
            .v4 => |q| {
                buf[0] = 4;
                @memcpy(buf[1..5], &q);
                return buf[0..5];
            },
            .v6 => |b| {
                buf[0] = 6;
                @memcpy(buf[1..17], &b);
                return buf[0..17];
            },
        }
    }
};

fn userCfg(options: Options, u: User) TokenBucket.Config {
    return .{
        .rate_per_s = u.rate_per_s orelse options.rate_per_s,
        .burst = u.burst orelse options.burst,
    };
}

fn unusedKeyFor(_: ?*anyopaque, _: *@import("router").Ctx) []const u8 {
    @panic("ConnectionLimiter's inner Limiter is connection-keyed; it is not router middleware");
}

fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

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

fn pfx(text: []const u8) netaddr.Prefix {
    return netaddr.parsePrefix(text).?;
}

fn addr(text: []const u8) netaddr.Ip {
    return netaddr.parseIp(text).?;
}

test "ConnectionLimiter: two addresses of one user share one bucket" {
    var tc: TestClock = .{};
    // 4/s with burst 4 so the fifth connection of a second is the one that
    // must be refused — the owner's rule, minus the burst headroom.
    const users = [_]User{.{
        .name = "acme",
        .prefixes = &.{ pfx("192.0.2.0/24"), pfx("2001:db8:1::/48") },
        .rate_per_s = 4,
        .burst = 4,
    }};
    var cl = try ConnectionLimiter.init(testing.allocator, .{
        .users = &users,
        .rate_per_s = 1,
        .burst = 1,
        .clock = tc.clock(),
    });
    defer cl.deinit();

    // Four connections spread over two different addresses inside the two
    // different prefixes — one v4, one v6.
    try testing.expect(cl.allowPeer(addr("192.0.2.7")).allowed);
    try testing.expect(cl.allowPeer(addr("2001:db8:1::5")).allowed);
    try testing.expect(cl.allowPeer(addr("192.0.2.200")).allowed);
    try testing.expect(cl.allowPeer(addr("2001:db8:1:2::9")).allowed);

    // The fifth is refused no matter which of the user's addresses it comes
    // from: one user, one bucket.
    try testing.expect(!cl.allowPeer(addr("192.0.2.7")).allowed);
    try testing.expect(!cl.allowPeer(addr("2001:db8:1::5")).allowed);
    try testing.expect(!cl.allowPeer(addr("192.0.2.99")).allowed); // never seen before

    // Nothing about the user landed in the evictable table.
    try testing.expectEqual(@as(usize, 0), cl.unlistedKeyCount());

    // One second later the bucket has refilled to its whole burst.
    tc.advanceMs(1000);
    for (0..4) |_| try testing.expect(cl.allowPeer(addr("192.0.2.7")).allowed);
    try testing.expect(!cl.allowPeer(addr("2001:db8:1::5")).allowed);

    // A dual-stack listener hands out `::ffff:a.b.c.d` for a v4 peer, and
    // that spelling must reach the SAME bucket as the plain form.
    //
    // `.allowed` cannot test this: a fresh bucket allows a stranger too, so
    // an assertion of the form `expect(allowPeer(mapped).allowed)` passes
    // whether the address matched the user or fell through to the unlisted
    // default. Only **bucket identity** distinguishes them — drain the user
    // over one spelling, then present the other and require a refusal.
    tc.advanceMs(1000); // the burst is back
    for (0..4) |_| try testing.expect(cl.allowPeer(addr("192.0.2.7")).allowed);
    try testing.expect(!cl.allowPeer(addr("::ffff:192.0.2.7")).allowed);

    // …and the same in the other direction: the mapped spelling spends the
    // user's tokens, not a stranger's.
    tc.advanceMs(1000);
    for (0..4) |_| try testing.expect(cl.allowPeer(addr("::ffff:192.0.2.7")).allowed);
    try testing.expect(!cl.allowPeer(addr("192.0.2.7")).allowed);

    // Second detector for the same bug: a mapped peer that failed to match
    // would have been keyed into the evictable table, which is exactly the
    // demotion that makes a configured customer flushable again.
    try testing.expectEqual(@as(usize, 0), cl.unlistedKeyCount());
}

test "ConnectionLimiter: a per-user override really overrides" {
    var tc: TestClock = .{};
    const users = [_]User{
        // No override → the default numbers below.
        .{ .name = "small", .prefixes = &.{pfx("192.0.2.0/24")} },
        // Override → its own, higher allowance.
        .{ .name = "big", .prefixes = &.{pfx("198.51.100.0/24")}, .rate_per_s = 100, .burst = 20 },
    };
    var cl = try ConnectionLimiter.init(testing.allocator, .{
        .users = &users,
        .rate_per_s = 4,
        .burst = 4,
        .clock = tc.clock(),
    });
    defer cl.deinit();

    // The overridden user gets 20 at one instant…
    for (0..20) |_| try testing.expect(cl.allowPeer(addr("198.51.100.1")).allowed);
    try testing.expect(!cl.allowPeer(addr("198.51.100.2")).allowed);

    // …while the default user still gets exactly 4, at the same instant.
    for (0..4) |_| try testing.expect(cl.allowPeer(addr("192.0.2.1")).allowed);
    try testing.expect(!cl.allowPeer(addr("192.0.2.2")).allowed);

    // And the rates differ too: in 250 ms the 100/s user refills its whole
    // 20-token burst while the 4/s user gets back exactly one token.
    tc.advanceMs(250);
    for (0..20) |_| try testing.expect(cl.allowPeer(addr("198.51.100.1")).allowed);
    try testing.expect(cl.allowPeer(addr("192.0.2.1")).allowed);
    try testing.expect(!cl.allowPeer(addr("192.0.2.1")).allowed);
}

test "ConnectionLimiter: unlisted addresses get the default, one bucket each" {
    var tc: TestClock = .{};
    var cl = try ConnectionLimiter.init(testing.allocator, .{
        .rate_per_s = 4,
        .burst = 4,
        .clock = tc.clock(),
    });
    defer cl.deinit();

    // Unlisted is neither "unlimited" nor "denied": it is the default limit.
    for (0..4) |_| try testing.expect(cl.allowPeer(addr("203.0.113.1")).allowed);
    try testing.expect(!cl.allowPeer(addr("203.0.113.1")).allowed);

    // A second stranger is untouched by the first one's exhaustion — the
    // default is per address, not one shared bucket.
    for (0..4) |_| try testing.expect(cl.allowPeer(addr("203.0.113.2")).allowed);
    try testing.expect(!cl.allowPeer(addr("203.0.113.2")).allowed);
    try testing.expectEqual(@as(usize, 2), cl.unlistedKeyCount());
}

test "ConnectionLimiter: rotating inside one /64 is a single unlisted bucket" {
    var tc: TestClock = .{};
    var cl = try ConnectionLimiter.init(testing.allocator, .{
        .rate_per_s = 4,
        .burst = 4,
        .clock = tc.clock(),
    });
    defer cl.deinit();

    // 2^64 addresses are free to an attacker with one /64; keying by /64
    // makes all of them one bucket.
    var allowed: usize = 0;
    for (0..64) |i| {
        var a: [16]u8 = undefined;
        @memcpy(a[0..8], &[_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0 });
        std.mem.writeInt(u64, a[8..16], @intCast(i + 1), .big);
        if (cl.allowPeerAt(.{ .v6 = a }, tc.ns).allowed) allowed += 1;
    }
    try testing.expectEqual(@as(usize, 4), allowed); // the burst, and no more
    try testing.expectEqual(@as(usize, 1), cl.unlistedKeyCount());
}

test "ConnectionLimiter: IPv6 rotation cannot grow the table or evict a user" {
    var tc: TestClock = .{};
    // Refill is negligible over the whole test, so anything that passes
    // later can only come from a bucket that was reset, never from refill.
    const users = [_]User{.{ .name = "acme", .prefixes = &.{pfx("2001:db8:cafe::/48")} }};
    const max_keys = 64;
    var cl = try ConnectionLimiter.init(testing.allocator, .{
        .users = &users,
        .rate_per_s = 0.001,
        .burst = 4,
        .max_unlisted_keys = max_keys,
        .unlisted_ttl_ms = 0, // isolate the cap from the TTL sweep
        .clock = tc.clock(),
    });
    defer cl.deinit();

    // The legitimate user spends its burst and is now at zero.
    for (0..4) |_| try testing.expect(cl.allowPeer(addr("2001:db8:cafe::1")).allowed);
    try testing.expect(!cl.allowPeer(addr("2001:db8:cafe::1")).allowed);

    // The flood: 4096 distinct /64s out of an attacker-held /48 that does
    // not overlap the user's. Every one of them is a brand-new key.
    for (0..4096) |i| {
        var a: [16]u8 = undefined;
        @memcpy(a[0..6], &[_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0xbe, 0xef });
        std.mem.writeInt(u16, a[6..8], @intCast(i), .big);
        std.mem.writeInt(u64, a[8..16], 1, .big);
        _ = cl.allowPeerAt(.{ .v6 = a }, tc.ns);
    }

    // The table stayed bounded — the attacker bought memory in the table,
    // not memory in the process.
    try testing.expect(cl.unlistedKeyCount() <= max_keys);

    // …and the configured user's bucket survived the flood untouched: still
    // drained, because it never lived in the evictable table at all. This is
    // the assertion the whole design exists for.
    try testing.expect(!cl.allowPeer(addr("2001:db8:cafe::1")).allowed);
    try testing.expect(!cl.allowPeer(addr("2001:db8:cafe:99::7")).allowed);
    try testing.expectEqual(@as(?usize, 0), cl.userIndex(addr("2001:db8:cafe::1")));
}

test "ConnectionLimiter: first configured match wins on overlapping prefixes" {
    var tc: TestClock = .{};
    const users = [_]User{
        .{ .name = "vip", .prefixes = &.{pfx("192.0.2.128/25")}, .burst = 10 },
        .{ .name = "rest", .prefixes = &.{pfx("192.0.2.0/24")}, .burst = 1 },
    };
    var cl = try ConnectionLimiter.init(testing.allocator, .{
        .users = &users,
        .rate_per_s = 0.001,
        .burst = 1,
        .clock = tc.clock(),
    });
    defer cl.deinit();

    try testing.expectEqual(@as(?usize, 0), cl.userIndex(addr("192.0.2.200")));
    try testing.expectEqual(@as(?usize, 1), cl.userIndex(addr("192.0.2.5")));
    for (0..10) |_| try testing.expect(cl.allowPeer(addr("192.0.2.200")).allowed);
    try testing.expect(cl.allowPeer(addr("192.0.2.5")).allowed);
    try testing.expect(!cl.allowPeer(addr("192.0.2.5")).allowed);
}

test "ConnectionLimiter: the on_connect hook rejects past the limit" {
    var tc: TestClock = .{};
    const users = [_]User{.{ .name = "acme", .prefixes = &.{pfx("127.0.0.0/8")}, .burst = 2, .rate_per_s = 0.001 }};
    var cl = try ConnectionLimiter.init(testing.allocator, .{
        .users = &users,
        .clock = tc.clock(),
    });
    defer cl.deinit();

    // Exactly the shape `http.Server` calls on its accept loop: an
    // `std.Io.net.IpAddress` in, a `ConnDecision` out — no request, no read.
    const peer: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 40000 } };
    const peer2: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 9 }, .port = 40001 } };
    try testing.expectEqual(http.Server.ConnDecision.accept, ConnectionLimiter.onConnect(&cl, peer));
    try testing.expectEqual(http.Server.ConnDecision.accept, ConnectionLimiter.onConnect(&cl, peer2));
    try testing.expectEqual(http.Server.ConnDecision.reject, ConnectionLimiter.onConnect(&cl, peer));

    // The hook is assignable to the published seam without a shim.
    const hook: http.Server.OnConnectFn = ConnectionLimiter.onConnect;
    try testing.expectEqual(http.Server.ConnDecision.reject, hook(&cl, peer2));
}

/// `std.Io.net` peers as a dual-stack listener produces them.
fn peer4(q: [4]u8, port: u16) std.Io.net.IpAddress {
    return .{ .ip4 = .{ .bytes = q, .port = port } };
}
fn peer6(b: [16]u8, port: u16) std.Io.net.IpAddress {
    return .{ .ip6 = .{ .bytes = b, .port = port } };
}
/// The `::ffff:a.b.c.d` form the kernel hands a dual-stack listener for a
/// v4 peer — spelled out here rather than parsed, because this is the exact
/// byte pattern the hook has to cope with.
fn mapped(q: [4]u8) [16]u8 {
    return [_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff } ++ q;
}

test "ConnectionLimiter: the hook itself resolves a v4-mapped peer to the user" {
    var tc: TestClock = .{};
    // The user's override (burst 6) is deliberately larger than what an
    // unlisted stranger gets (burst 2), so a mapped peer that fails to match
    // is refused three connections early — the override silently not
    // applying is the operational symptom of the bug.
    const users = [_]User{.{
        .name = "acme",
        .prefixes = &.{pfx("192.0.2.0/24")},
        .rate_per_s = 0.001, // no refill anywhere in this test
        .burst = 6,
    }};
    var cl = try ConnectionLimiter.init(testing.allocator, .{
        .users = &users,
        .rate_per_s = 0.001,
        .burst = 2,
        .clock = tc.clock(),
    });
    defer cl.deinit();

    const plain = peer4(.{ 192, 0, 2, 7 }, 40000);
    const as_mapped = peer6(mapped(.{ 192, 0, 2, 7 }), 40001);
    const other_mapped = peer6(mapped(.{ 192, 0, 2, 200 }), 40002);

    // Six accepts — the user's override — spread across both spellings and
    // two different addresses of the prefix. Past the third, an unmatched
    // mapped peer would already be out of its unlisted burst of 2.
    try testing.expectEqual(http.Server.ConnDecision.accept, ConnectionLimiter.onConnect(&cl, as_mapped));
    try testing.expectEqual(http.Server.ConnDecision.accept, ConnectionLimiter.onConnect(&cl, other_mapped));
    try testing.expectEqual(http.Server.ConnDecision.accept, ConnectionLimiter.onConnect(&cl, as_mapped));
    try testing.expectEqual(http.Server.ConnDecision.accept, ConnectionLimiter.onConnect(&cl, plain));
    try testing.expectEqual(http.Server.ConnDecision.accept, ConnectionLimiter.onConnect(&cl, as_mapped));
    try testing.expectEqual(http.Server.ConnDecision.accept, ConnectionLimiter.onConnect(&cl, other_mapped));

    // Seventh: one bucket, drained — from either spelling.
    try testing.expectEqual(http.Server.ConnDecision.reject, ConnectionLimiter.onConnect(&cl, as_mapped));
    try testing.expectEqual(http.Server.ConnDecision.reject, ConnectionLimiter.onConnect(&cl, plain));

    // And the customer never entered the evictable table by either spelling.
    try testing.expectEqual(@as(usize, 0), cl.unlistedKeyCount());
}

test "ConnectionLimiter: unmapping never merges two distinct peers" {
    var tc: TestClock = .{};
    // A user configured with a v6 prefix. `Prefix.contains` is family-strict
    // and unmapping only rewrites `::ffff:a.b.c.d` → `a.b.c.d`, so a v4
    // peer can never be pulled into a v6 customer's bucket.
    const users = [_]User{.{ .name = "acme", .prefixes = &.{pfx("2001:db8:1::/48")}, .rate_per_s = 0.001, .burst = 2 }};
    var cl = try ConnectionLimiter.init(testing.allocator, .{
        .users = &users,
        .rate_per_s = 0.001,
        .burst = 2,
        .clock = tc.clock(),
    });
    defer cl.deinit();

    try testing.expectEqual(@as(?usize, null), cl.userIndex(addr("::ffff:192.0.2.7").unmap()));
    try testing.expectEqual(@as(?usize, null), cl.userIndex(addr("192.0.2.7")));
    try testing.expectEqual(@as(?usize, 0), cl.userIndex(addr("2001:db8:1::5")));

    // Drain the v6 user; an unrelated v4 peer, mapped or not, is untouched
    // by that — no collision in the matching direction.
    for (0..2) |_| try testing.expect(cl.allowPeer(addr("2001:db8:1::5")).allowed);
    try testing.expect(!cl.allowPeer(addr("2001:db8:1::5")).allowed);
    try testing.expect(cl.allowPeer(addr("::ffff:192.0.2.7")).allowed);

    // Nor in the keying direction: unmap is injective apart from the one
    // identity it exists to assert (a host's two spellings), so two
    // *different* addresses keep two buckets. `::ffff:192.0.2.8` is a
    // distinct host from `::ffff:192.0.2.7` and gets its own.
    try testing.expect(cl.allowPeer(addr("::ffff:192.0.2.8")).allowed);
    try testing.expect(cl.allowPeer(addr("::ffff:192.0.2.8")).allowed);
    try testing.expect(!cl.allowPeer(addr("::ffff:192.0.2.8")).allowed);
    try testing.expect(cl.allowPeer(addr("192.0.2.7")).allowed); // 7 had 1 left
    try testing.expect(!cl.allowPeer(addr("::ffff:192.0.2.7")).allowed); // …now drained
    try testing.expectEqual(@as(usize, 2), cl.unlistedKeyCount()); // .7 and .8, not 4

    // The one consequence operators must know: a v4 customer has to be
    // spelled in v4 CIDR. `::ffff:0:0/96` — the v6 spelling of the whole v4
    // space — matches nothing, because peers are unmapped before matching.
    const v6_spelled = [_]User{.{ .name = "wrong", .prefixes = &.{pfx("::ffff:0:0/96")}, .burst = 2 }};
    var cl2 = try ConnectionLimiter.init(testing.allocator, .{ .users = &v6_spelled, .clock = tc.clock() });
    defer cl2.deinit();
    try testing.expectEqual(@as(?usize, null), cl2.userIndex(addr("::ffff:192.0.2.7").unmap()));
}

test "ConnectionLimiter: concurrent accepts admit exactly the user's burst" {
    const threads = 8;
    const attempts_per_thread = 100;
    const burst = 100;

    var tc: TestClock = .{}; // frozen clock → zero refill during the race
    const users = [_]User{.{
        .name = "acme",
        .prefixes = &.{pfx("192.0.2.0/24")},
        .rate_per_s = 0.000001,
        .burst = burst,
    }};
    var cl = try ConnectionLimiter.init(testing.allocator, .{ .users = &users, .clock = tc.clock() });
    defer cl.deinit();

    const Worker = struct {
        fn run(c: *ConnectionLimiter, allowed: *std.atomic.Value(u32)) void {
            for (0..attempts_per_thread) |i| {
                // Different addresses of the same user from every thread —
                // the shared bucket is what must not over-admit.
                const a: netaddr.Ip = .{ .v4 = .{ 192, 0, 2, @intCast(i % 256) } };
                if (c.allowPeer(a).allowed) _ = allowed.fetchAdd(1, .monotonic);
            }
        }
    };

    var allowed: std.atomic.Value(u32) = .init(0);
    var handles: [threads]std.Thread = undefined;
    for (&handles) |*h| h.* = try std.Thread.spawn(.{}, Worker.run, .{ &cl, &allowed });
    for (handles) |h| h.join();

    try testing.expectEqual(@as(u32, burst), allowed.load(.monotonic));
    try testing.expectEqual(@as(usize, 0), cl.unlistedKeyCount());
}

// The shipped defaults are the owner's ruling of 2026-08-10, not a suggestion:
// max 4 new connections per second per user, with a burst of 8 so a browser
// opening several tabs is not refused. Every other test here configures its
// own rate, so without this one the *values* are unpinned — the mechanism
// would keep working at any number and a silent change would ship green.
test "the shipped connection defaults are the values the owner ruled" {
    try testing.expectEqual(@as(f64, 4), default_conn_rate_per_s);
    try testing.expectEqual(@as(u32, 8), default_conn_burst);

    // And they are what an unconfigured limiter actually hands out, not just
    // what the constants say: a fresh peer gets exactly `burst` connections.
    var cl = try ConnectionLimiter.init(testing.allocator, .{ .users = &.{} });
    defer cl.deinit();
    const peer = addr("198.51.100.9");
    for (0..default_conn_burst) |_| try testing.expect(cl.allowPeer(peer).allowed);
    try testing.expect(!cl.allowPeer(peer).allowed);
}
