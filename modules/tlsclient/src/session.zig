// SPDX-License-Identifier: MIT

//! zig-libs tlsclient: the client-side TLS 1.3 session cache (Go
//! `ClientSessionCache` / `NewLRUClientSessionCache`).
//!
//! One entry per server name, least recently stored replaced first. An entry
//! is reserved when a full handshake completes -- the resumption master
//! secret and the server's certificate chain go in then, while the chain's
//! bytes still exist -- and becomes usable when a NewSessionTicket arrives
//! (the ticket and the PSK derived from it). A resumed handshake keeps its
//! entry, chain included, so the session view still shows the certificates
//! (as Go's does).
//!
//! The entries live in caller storage and hold secrets (resumption secret,
//! PSK): the caller owns their lifetime and wiping (`deinit` zeroes them).
//! Thread safety: give `lock` when clients on several threads share a cache;
//! each access holds it briefly.

const std = @import("std");
const tls = std.crypto.tls;
const mem = std.mem;

/// Longest ticket kept (RFC 8446 allows 2^16 - 1; real ones are a few
/// hundred bytes). A longer one is not cached.
pub const max_ticket_len = 2048;
/// Most certificate bytes kept per entry; a longer chain is not cached.
pub const max_chain_bytes = 16 * 1024;
pub const max_chain_len = 10;
/// RFC 8446 §4.6.1: servers MUST NOT give a lifetime over seven days.
pub const max_lifetime_s = 7 * 24 * 3600;
pub const max_key_len = 255;

pub const HashKind = enum { sha256, sha384, sha512 };

pub const ClientSession = struct {
    key_buf: [max_key_len]u8 = undefined,
    key_len: u8 = 0,
    /// 0: free. Assigned at `reserve`, so a client holding an entry can tell
    /// whether another connection has taken it since.
    generation: u64 = 0,
    /// A ticket is present and the PSK derived.
    usable: bool = false,
    hash: HashKind = .sha256,
    resumption_secret: [64]u8 = undefined,
    psk: [64]u8 = undefined,
    ticket_buf: [max_ticket_len]u8 = undefined,
    ticket_len: u16 = 0,
    ticket_age_add: u32 = 0,
    ticket_lifetime_s: u32 = 0,
    /// When the ticket arrived (milliseconds of the wall clock).
    received_ms: i64 = 0,
    /// The leaf's notAfter (seconds); a session past it is not resumed.
    leaf_not_after_s: i64 = std.math.maxInt(i64),
    chain_buf: [max_chain_bytes]u8 = undefined,
    chain_lens: [max_chain_len]u16 = undefined,
    chain_count: u8 = 0,

    pub fn key(s: *const ClientSession) []const u8 {
        return s.key_buf[0..s.key_len];
    }

    pub fn ticket(s: *const ClientSession) []const u8 {
        return s.ticket_buf[0..s.ticket_len];
    }

    pub fn hashLen(s: *const ClientSession) usize {
        return switch (s.hash) {
            .sha256 => 32,
            .sha384 => 48,
            .sha512 => 64,
        };
    }

    /// The certificates kept, leaf first, as slices into the entry.
    pub fn chain(s: *const ClientSession, out: *[max_chain_len][]const u8) []const []const u8 {
        var off: usize = 0;
        for (0..s.chain_count) |i| {
            out[i] = s.chain_buf[off..][0..s.chain_lens[i]];
            off += s.chain_lens[i];
        }
        return out[0..s.chain_count];
    }

    /// Store `certs` (false: too large, nothing kept).
    pub fn setChain(s: *ClientSession, certs: []const []const u8) bool {
        s.chain_count = 0;
        if (certs.len > max_chain_len) return false;
        var off: usize = 0;
        for (certs) |c| {
            if (c.len > max_chain_bytes - off) return false;
            off += c.len;
        }
        off = 0;
        for (certs, 0..) |c, i| {
            @memcpy(s.chain_buf[off..][0..c.len], c);
            s.chain_lens[i] = @intCast(c.len);
            off += c.len;
        }
        s.chain_count = @intCast(certs.len);
        return true;
    }

    /// Whether the ticket may be offered at `now_ms` (lifetime, leaf expiry).
    pub fn fresh(s: *const ClientSession, now_ms: i64) bool {
        if (!s.usable) return false;
        const age_ms = now_ms - s.received_ms;
        if (age_ms < 0 or age_ms >= @as(i64, s.ticket_lifetime_s) * 1000) return false;
        return @divFloor(now_ms, 1000) < s.leaf_not_after_s;
    }
};

pub const SessionCache = struct {
    entries: []ClientSession,
    next_generation: u64 = 1,
    lock: ?Lock = null,

    pub const Lock = struct {
        io: std.Io,
        mutex: *std.Io.Mutex,
    };

    /// A cache over `entries` (its capacity); `lock` for shared use.
    pub fn init(entries: []ClientSession, lock: ?Lock) SessionCache {
        for (entries) |*e| e.* = .{};
        return .{ .entries = entries, .lock = lock };
    }

    /// Zero every entry (secrets included).
    pub fn deinit(c: *SessionCache) void {
        for (c.entries) |*e| std.crypto.secureZero(u8, mem.asBytes(e));
    }

    pub fn acquire(c: *SessionCache) void {
        if (c.lock) |l| l.mutex.lockUncancelable(l.io);
    }

    pub fn release(c: *SessionCache) void {
        if (c.lock) |l| l.mutex.unlock(l.io);
    }

    /// secret-api-ok: compares only the cache key (the server name + port, public); the session secrets are not read.
    /// The entry for `key`, if any (caller holds the lock).
    pub fn find(c: *SessionCache, k: []const u8) ?*ClientSession {
        for (c.entries) |*e| {
            if (e.generation != 0 and mem.eql(u8, e.key(), k)) return e;
        }
        return null;
    }

    /// secret-api-ok: picks a slot by the public cache key and generation counters; no session secret is read or copied.
    /// The entry `key` is stored in from now on: its own, else a free one,
    /// else the oldest. Gets a new generation (caller holds the lock).
    pub fn reserve(c: *SessionCache, k: []const u8) ?*ClientSession {
        if (k.len == 0 or k.len > max_key_len or c.entries.len == 0) return null;
        const e = c.find(k) orelse blk: {
            var oldest: *ClientSession = &c.entries[0];
            for (c.entries) |*x| {
                if (x.generation == 0) break :blk x;
                if (x.generation < oldest.generation) oldest = x;
            }
            break :blk oldest;
        };
        if (e.generation == 0 or !mem.eql(u8, e.key(), k)) {
            std.crypto.secureZero(u8, mem.asBytes(e));
            e.* = .{};
            @memcpy(e.key_buf[0..k.len], k);
            e.key_len = @intCast(k.len);
        }
        e.generation = c.next_generation;
        c.next_generation += 1;
        return e;
    }
};

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "SessionCache: one entry per key, the oldest replaced, generations move" {
    var storage: [2]ClientSession = undefined;
    var c: SessionCache = .init(&storage, null);
    defer c.deinit();
    const a = c.reserve("a.test").?;
    const ga = a.generation;
    const b = c.reserve("b.test").?;
    try testing.expect(a != b);
    try testing.expectEqual(a, c.reserve("a.test").?); // same key, same entry
    try testing.expect(a.generation > ga);
    // A third key replaces the oldest (b, reserved before a's second time).
    const x = c.reserve("c.test").?;
    try testing.expectEqual(b, x);
    try testing.expectEqualStrings("c.test", x.key());
    try testing.expect(c.find("b.test") == null);
    try testing.expect(c.reserve("") == null);
}

test "ClientSession: fresh within the lifetime and before the leaf expires; chain round-trips" {
    var s: ClientSession = .{ .usable = true, .ticket_lifetime_s = 10, .received_ms = 1_000_000 };
    try testing.expect(s.fresh(1_000_000));
    try testing.expect(s.fresh(1_009_999));
    try testing.expect(!s.fresh(1_010_000));
    try testing.expect(!s.fresh(999_999)); // clock went back
    s.leaf_not_after_s = 1_005;
    try testing.expect(!s.fresh(1_005_000));
    try testing.expect(s.setChain(&.{ "leaf", "inter" }));
    var out: [max_chain_len][]const u8 = undefined;
    const ch = s.chain(&out);
    try testing.expectEqual(@as(usize, 2), ch.len);
    try testing.expectEqualStrings("inter", ch[1]);
    const big = @as([max_chain_bytes + 1]u8, @splat(0));
    try testing.expect(!s.setChain(&.{&big}));
    try testing.expectEqual(@as(u8, 0), s.chain_count);
}
