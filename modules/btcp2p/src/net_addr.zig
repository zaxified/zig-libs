// SPDX-License-Identifier: MIT
//! The `net_addr` structure (Bitcoin Developer Reference / wiki
//! "Network address"): the peer-address format shared by `version`'s
//! `addr_recv`/`addr_from` fields (no leading timestamp -- "Network
//! addresses are not prefixed with a timestamp in the version message")
//! and `addr`'s address list (each entry timestamp-prefixed, see
//! `TimedNetAddr` below).

const std = @import("std");
const message = @import("message.zig");
const Reader = message.Reader;
const Writer = message.Writer;
const Allocator = std.mem.Allocator;

/// The 12-byte prefix that maps an IPv4 address into the 16-byte
/// IPv4-in-IPv6 slot every `net_addr` carries (wiki: "12 bytes 00 00 00
/// 00 00 00 00 00 00 00 FF FF, followed by the 4 bytes of the IPv4
/// address").
const IPV4_MAPPED_PREFIX = [12]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

/// One peer's address + the services it advertises. `ip` is always the
/// 16-byte wire form (IPv4-mapped IPv6 for an IPv4 peer, or a real IPv6
/// address); use `ipv4`/`fromIpv4` to bridge to/from a plain 4-byte IPv4
/// address.
pub const NetAddr = struct {
    services: u64,
    ip: [16]u8,
    /// Host-order port number. The wire encodes this big-endian
    /// ("network byte order" per spec) -- `decode`/`encode` handle the
    /// byte-order flip; callers never see wire-order bytes.
    port: u16,

    pub fn decode(r: *Reader) message.ReadError!NetAddr {
        const services = try r.u64le();
        const ip = try r.takeArray(16);
        const port = try r.u16be();
        return .{ .services = services, .ip = ip, .port = port };
    }

    pub fn encode(self: NetAddr, w: *Writer, allocator: Allocator) Allocator.Error!void {
        try w.putU64le(allocator, self.services);
        try w.putBytes(allocator, &self.ip);
        try w.putU16be(allocator, self.port);
    }

    /// The plain 4-byte IPv4 address, if `ip` is IPv4-mapped -- `null`
    /// for a real IPv6 address.
    pub fn ipv4(self: NetAddr) ?[4]u8 {
        if (!std.mem.eql(u8, self.ip[0..12], &IPV4_MAPPED_PREFIX)) return null;
        return self.ip[12..16].*;
    }

    /// Builds the 16-byte IPv4-mapped-IPv6 wire form from a plain 4-byte
    /// IPv4 address.
    pub fn fromIpv4(addr: [4]u8) [16]u8 {
        var ip: [16]u8 = undefined;
        @memcpy(ip[0..12], &IPV4_MAPPED_PREFIX);
        @memcpy(ip[12..16], &addr);
        return ip;
    }
};

/// `addr`-message entry: a `net_addr` with the timestamp prefix that
/// message adds (wiki: "Starting version 31402, addresses are prefixed
/// with a timestamp").
pub const TimedNetAddr = struct {
    /// Seconds-since-epoch this address was last seen active.
    time: u32,
    addr: NetAddr,

    pub fn decode(r: *Reader) message.ReadError!TimedNetAddr {
        const time = try r.u32le();
        const addr = try NetAddr.decode(r);
        return .{ .time = time, .addr = addr };
    }

    pub fn encode(self: TimedNetAddr, w: *Writer, allocator: Allocator) Allocator.Error!void {
        try w.putU32le(allocator, self.time);
        try self.addr.encode(w, allocator);
    }
};

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

/// `testkit.fuzz`, for the corpus at the bottom of this file. A corpus entry
/// is not the frame: `Smith.slice` reads a little-endian `u32` length first,
/// so a raw frame would arrive minus its own first four octets.
/// `testkit/src/fuzz.zig` carries the other two hazards.
const testkit = @import("testkit");
const seed = testkit.fuzz.seed;
const seedHex = testkit.fuzz.seedHex;

// ── externally anchored: wiki's "Hexdump example of Network address
// structure" ──────────────────────────────────────────────────────────

/// The wiki's "Hexdump example of Network address structure". Container-level
/// so the fuzz corpus below seeds the SAME octets this test anchors, rather
/// than a re-transcription of them.
const wiki_net_addr = [_]u8{
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // services = 1 (NODE_NETWORK)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x0a, 0x00, 0x00, 0x01, // ::ffff:10.0.0.1
    0x20, 0x8d, // port 8333
};

test "external: NetAddr decodes the wiki's own worked example byte-exact" {
    const bytes = wiki_net_addr;
    var r: Reader = .{ .bytes = &bytes };
    const addr = try NetAddr.decode(&r);
    try testing.expectEqual(@as(u64, 1), addr.services);
    try testing.expectEqual(@as(u16, 8333), addr.port);
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 1 }, &addr.ipv4().?);
    try testing.expectEqual(@as(usize, 0), r.remaining());
}

test "NetAddr: encode -> decode round-trip preserves services/ip/port" {
    const allocator = testing.allocator;
    const addr: NetAddr = .{ .services = 9, .ip = NetAddr.fromIpv4(.{ 203, 0, 113, 42 }), .port = 18333 };
    var w: Writer = .{};
    defer w.deinit(allocator);
    try addr.encode(&w, allocator);

    var r: Reader = .{ .bytes = w.list.items };
    const decoded = try NetAddr.decode(&r);
    try testing.expectEqual(addr.services, decoded.services);
    try testing.expectEqual(addr.port, decoded.port);
    try testing.expectEqualSlices(u8, &.{ 203, 0, 113, 42 }, &decoded.ipv4().?);
}

test "NetAddr: ipv4() is null for a real (non-mapped) IPv6 address" {
    const ip: [16]u8 = @splat(0xab);
    const addr: NetAddr = .{ .services = 0, .ip = ip, .port = 0 };
    try testing.expectEqual(@as(?[4]u8, null), addr.ipv4());
}

test "TimedNetAddr: encode -> decode round-trip, matches wiki's addr-message worked example" {
    // wiki's "addr" example entry: time=0x4D1015E2 (LE on wire), services=1,
    // ip=::ffff:10.0.0.1, port=8333.
    const bytes = [_]u8{
        0xe2, 0x15, 0x10, 0x4d, // time
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // services
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff, 0x0a, 0x00, 0x00, 0x01,
        0x20, 0x8d,
    };
    var r: Reader = .{ .bytes = &bytes };
    const t = try TimedNetAddr.decode(&r);
    try testing.expectEqual(@as(u32, 0x4d1015e2), t.time);
    try testing.expectEqual(@as(u64, 1), t.addr.services);
    try testing.expectEqual(@as(u16, 8333), t.addr.port);

    const allocator = testing.allocator;
    var w: Writer = .{};
    defer w.deinit(allocator);
    try t.encode(&w, allocator);
    try testing.expectEqualSlices(u8, &bytes, w.list.items);
}

test "hostile: NetAddr.decode on a truncated buffer fails closed" {
    const bytes = [_]u8{ 0, 0, 0 };
    var r: Reader = .{ .bytes = &bytes };
    try testing.expectError(error.Truncated, NetAddr.decode(&r));
}

/// `net_addr` structures, in the format `Smith.slice` reads (see
/// `testkit.fuzz`). The wiki's worked example, a real (non-mapped) IPv6 peer,
/// and the boundary either side of the fixed 26-octet width.
///
/// `NetAddr.decode` is pure fixed-width reads, so the only thing that decides
/// accept-vs-`Truncated` is the length — and with the collapsing draw the
/// length was always 0, i.e. the harness only ever proved that a 0-octet
/// buffer is refused.
const decode_seeds = [_][]const u8{
    seed(&wiki_net_addr), // the wiki's ::ffff:10.0.0.1 port 8333
    seedHex("00" ** 26), // the all-zero net_addr a `version` message carries
    seedHex("ab" ** 26), // a real IPv6 address (ipv4() is null for it)
    seedHex("ff" ** 30), // 4 octets of trailing junk after a full net_addr
    seedHex("00" ** 25), // Truncated: one octet short of the fixed width
    seedHex("000000"), // Truncated: the 3-octet buffer from the hostile test
};

test "fuzz: NetAddr.decode never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzNetAddrDecode, .{ .corpus = &decode_seeds });
}

fn fuzzNetAddrDecode(_: void, smith: *std.testing.Smith) !void {
    var buf: [64]u8 = undefined;
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
    // length. `bytes` takes `@min(buf.len, in.len)` octets and the ranged draw
    // then finds fewer than the eight it needs and returns the range MINIMUM,
    // so `len` was 0 for every seed and `NetAddr.decode` saw `buf[0..0]` every
    // single time, with the seed sitting unread in `buf`.
    const len: usize = smith.slice(&buf);
    var r: Reader = .{ .bytes = buf[0..len] };
    _ = NetAddr.decode(&r) catch return;
}

test "corpus: every net_addr seed reaches the decoder, and the accepted count is pinned" {
    // ⭐ The measurement, executable rather than written in a comment. Two
    // things it holds that no other test does: a seed longer than the harness's
    // buffer reads back EMPTY (`Smith.slice` falls back to the range minimum),
    // which is silent everywhere else; and a corpus where nothing is accepted
    // is a corpus that only exercises the refusal path. Acceptance is not
    // reach, so this pins the number rather than asserting it is > 0.
    var nonempty: usize = 0;
    var accepted: usize = 0;
    for (decode_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [64]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        var r: Reader = .{ .bytes = buf[0..len] };
        if (NetAddr.decode(&r)) |_| {
            accepted += 1;
        } else |_| {}
    }
    try testing.expectEqual(decode_seeds.len, nonempty);
    // Measured 2026-09-07: 0 of 6 seeds non-empty and 0 accepted before the
    // draw was fixed, 6 of 6 non-empty and 4 accepted after.
    try testing.expectEqual(@as(usize, 4), accepted);
}
