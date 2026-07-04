// SPDX-License-Identifier: MIT

//! ICMP echo packet construction and parsing for IPv4 and IPv6.
//!
//! All multi-byte header fields are written and read in network byte order.
//! The IPv6 checksum is left at zero: the kernel fills it in for both
//! SOCK_DGRAM and SOCK_RAW ICMPv6 sockets (it needs the pseudo-header
//! addresses, which only the kernel knows for sure).
//!
//! Parsing is bounds-checked and never panics on short or garbage input —
//! unrecognized packets come back as `.ignored`.

const std = @import("std");

/// Length of the ICMP echo header (type, code, checksum, id, seq).
pub const echo_header_len = 8;

pub const v4 = struct {
    pub const echo_reply: u8 = 0;
    pub const dest_unreachable: u8 = 3;
    pub const source_quench: u8 = 4;
    pub const redirect: u8 = 5;
    pub const echo_request: u8 = 8;
    pub const time_exceeded: u8 = 11;
    pub const param_problem: u8 = 12;
    pub const timestamp_request: u8 = 13;
    pub const timestamp_reply: u8 = 14;
};

/// ICMP Timestamp payload (RFC 792): milliseconds since midnight UT.
pub const TsData = struct {
    originate_ms: u32,
    receive_ms: u32,
    transmit_ms: u32,
};

/// Total length of an ICMP timestamp message (header + 3 timestamps).
pub const timestamp_msg_len = echo_header_len + 12;

pub const v6 = struct {
    pub const dest_unreachable: u8 = 1;
    pub const packet_too_big: u8 = 2;
    pub const time_exceeded: u8 = 3;
    pub const param_problem: u8 = 4;
    pub const echo_request: u8 = 128;
    pub const echo_reply: u8 = 129;
};

pub const Family = enum { v4, v6 };

/// RFC 1071 internet checksum over `data`, returned in host byte order.
/// Store the result big-endian into the packet.
pub fn checksum(data: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < data.len) : (i += 2) {
        sum += (@as(u32, data[i]) << 8) | data[i + 1];
    }
    if (i < data.len) sum += @as(u32, data[i]) << 8;
    while (sum >> 16 != 0) sum = (sum & 0xffff) + (sum >> 16);
    return @intCast(~sum & 0xffff);
}

/// Fill `buf` with an ICMP echo request. `buf.len` must be
/// `echo_header_len + payload_size`; payload bytes beyond the header are
/// expected to be pre-filled (pattern or zeroes) by the caller.
pub fn writeEchoRequest(family: Family, buf: []u8, ident: u16, seq: u16) void {
    std.debug.assert(buf.len >= echo_header_len);
    buf[0] = switch (family) {
        .v4 => v4.echo_request,
        .v6 => v6.echo_request,
    };
    buf[1] = 0; // code
    buf[2] = 0; // checksum (filled below for v4)
    buf[3] = 0;
    std.mem.writeInt(u16, buf[4..6], ident, .big);
    std.mem.writeInt(u16, buf[6..8], seq, .big);
    if (family == .v4) {
        const sum = checksum(buf);
        std.mem.writeInt(u16, buf[2..4], sum, .big);
    }
}

/// Fill `buf` (>= timestamp_msg_len) with an ICMP timestamp request
/// (fping --icmp-timestamp; IPv4 only).
pub fn writeTimestampRequest(buf: []u8, ident: u16, seq: u16, originate_ms: u32) void {
    std.debug.assert(buf.len >= timestamp_msg_len);
    buf[0] = v4.timestamp_request;
    buf[1] = 0;
    buf[2] = 0;
    buf[3] = 0;
    std.mem.writeInt(u16, buf[4..6], ident, .big);
    std.mem.writeInt(u16, buf[6..8], seq, .big);
    std.mem.writeInt(u32, buf[8..12], originate_ms, .big);
    std.mem.writeInt(u32, buf[12..16], 0, .big);
    std.mem.writeInt(u32, buf[16..20], 0, .big);
    const sum = checksum(buf[0..timestamp_msg_len]);
    std.mem.writeInt(u16, buf[2..4], sum, .big);
}

pub const ErrorKind = enum {
    dest_unreachable,
    time_exceeded,
    packet_too_big,
    redirect,
    param_problem,
    other,
};

pub const Reply = union(enum) {
    /// Echo or timestamp reply addressed to us (id/seq in host byte order).
    /// `ts` is set for ICMP timestamp replies.
    echo_reply: struct { ident: u16, seq: u16, ts: ?TsData = null },
    /// ICMP error quoting an echo/timestamp request of ours.
    icmp_error: struct { kind: ErrorKind, code: u8, orig_ident: u16, orig_seq: u16 },
    /// Anything else (not ours, malformed, uninteresting type).
    ignored,
};

/// Parse a packet read from an IPv4 ICMP socket. `strip_ip_header` must be
/// true for SOCK_RAW sockets, where the kernel prepends the IP header.
pub fn parseV4(packet: []const u8, strip_ip_header: bool) Reply {
    var buf = packet;
    if (strip_ip_header) {
        if (buf.len < 20) return .ignored;
        const ihl: usize = @as(usize, buf[0] & 0x0f) * 4;
        if (ihl < 20 or buf.len < ihl) return .ignored;
        buf = buf[ihl..];
    }
    if (buf.len < echo_header_len) return .ignored;

    switch (buf[0]) {
        v4.echo_reply => return .{ .echo_reply = .{
            .ident = std.mem.readInt(u16, buf[4..6], .big),
            .seq = std.mem.readInt(u16, buf[6..8], .big),
        } },
        v4.timestamp_reply => {
            if (buf.len < timestamp_msg_len) return .ignored;
            return .{ .echo_reply = .{
                .ident = std.mem.readInt(u16, buf[4..6], .big),
                .seq = std.mem.readInt(u16, buf[6..8], .big),
                .ts = .{
                    .originate_ms = std.mem.readInt(u32, buf[8..12], .big),
                    .receive_ms = std.mem.readInt(u32, buf[12..16], .big),
                    .transmit_ms = std.mem.readInt(u32, buf[16..20], .big),
                },
            } };
        },
        v4.dest_unreachable, v4.source_quench, v4.redirect, v4.time_exceeded, v4.param_problem => {
            // The error quotes the original IP header + >= 8 bytes of payload.
            const quoted = buf[echo_header_len..];
            if (quoted.len < 20) return .ignored;
            const qihl: usize = @as(usize, quoted[0] & 0x0f) * 4;
            if (qihl < 20 or quoted.len < qihl + echo_header_len) return .ignored;
            const orig = quoted[qihl..];
            if (orig[0] != v4.echo_request and orig[0] != v4.timestamp_request) return .ignored;
            return .{ .icmp_error = .{
                .kind = switch (buf[0]) {
                    v4.dest_unreachable => .dest_unreachable,
                    v4.time_exceeded => .time_exceeded,
                    v4.redirect => .redirect,
                    v4.param_problem => .param_problem,
                    else => .other,
                },
                .code = buf[1],
                .orig_ident = std.mem.readInt(u16, orig[4..6], .big),
                .orig_seq = std.mem.readInt(u16, orig[6..8], .big),
            } };
        },
        else => return .ignored,
    }
}

/// Parse a packet read from an IPv6 ICMP socket. ICMPv6 sockets never
/// deliver the IPv6 header.
pub fn parseV6(packet: []const u8) Reply {
    const buf = packet;
    if (buf.len < echo_header_len) return .ignored;

    switch (buf[0]) {
        v6.echo_reply => return .{ .echo_reply = .{
            .ident = std.mem.readInt(u16, buf[4..6], .big),
            .seq = std.mem.readInt(u16, buf[6..8], .big),
        } },
        v6.dest_unreachable, v6.packet_too_big, v6.time_exceeded, v6.param_problem => {
            // The error quotes the original IPv6 header (40 bytes) + payload.
            const quoted = buf[echo_header_len..];
            if (quoted.len < 40 + echo_header_len) return .ignored;
            if (quoted[6] != 58) return .ignored; // next header must be ICMPv6
            const orig = quoted[40..];
            if (orig[0] != v6.echo_request) return .ignored;
            return .{ .icmp_error = .{
                .kind = switch (buf[0]) {
                    v6.dest_unreachable => .dest_unreachable,
                    v6.packet_too_big => .packet_too_big,
                    v6.time_exceeded => .time_exceeded,
                    v6.param_problem => .param_problem,
                    else => .other,
                },
                .code = buf[1],
                .orig_ident = std.mem.readInt(u16, orig[4..6], .big),
                .orig_seq = std.mem.readInt(u16, orig[6..8], .big),
            } };
        },
        else => return .ignored,
    }
}

// ── tests ───────────────────────────────────────────────────────────────────

test "checksum of RFC 1071 example" {
    // Example from RFC 1071: bytes 00 01 f2 03 f4 f5 f6 f7 -> sum ddf2 -> cksum 220d
    const data = [_]u8{ 0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7 };
    try std.testing.expectEqual(@as(u16, 0x220d), checksum(&data));
}

test "checksum odd length" {
    const data = [_]u8{ 0xff, 0xff, 0x01 };
    // sum = 0xffff + 0x0100 = 0x100ff -> fold -> 0x0100; ~0x0100 = 0xfeff
    try std.testing.expectEqual(@as(u16, 0xfeff), checksum(&data));
}

test "golden: v4 echo request wire bytes" {
    var buf: [echo_header_len + 4]u8 = @splat(0);
    writeEchoRequest(.v4, &buf, 0x1234, 7);
    // type=8 code=0; checksum = ~(0x0800 + 0x1234 + 0x0007) = 0xe5c4.
    const expected = [_]u8{ 0x08, 0x00, 0xe5, 0xc4, 0x12, 0x34, 0x00, 0x07, 0, 0, 0, 0 };
    try std.testing.expectEqualSlices(u8, &expected, &buf);
}

test "golden: v6 echo request wire bytes (checksum kernel-filled)" {
    var buf: [echo_header_len]u8 = @splat(0);
    writeEchoRequest(.v6, &buf, 0xbeef, 513);
    const expected = [_]u8{ 128, 0x00, 0x00, 0x00, 0xbe, 0xef, 0x02, 0x01 };
    try std.testing.expectEqualSlices(u8, &expected, &buf);
}

test "echo request round-trip v4 dgram" {
    var buf: [echo_header_len + 8]u8 = @splat(0);
    writeEchoRequest(.v4, &buf, 0xabcd, 42);
    // Packet checksum must verify (sum over whole packet == 0).
    try std.testing.expectEqual(@as(u16, 0), checksum(&buf));
    // A reply differs only in type; emulate kernel echo by flipping type.
    var reply = buf;
    reply[0] = v4.echo_reply;
    const parsed = parseV4(&reply, false);
    try std.testing.expectEqual(@as(u16, 0xabcd), parsed.echo_reply.ident);
    try std.testing.expectEqual(@as(u16, 42), parsed.echo_reply.seq);
}

test "echo request round-trip v6" {
    var buf: [echo_header_len + 16]u8 = @splat(0xa5);
    writeEchoRequest(.v6, &buf, 0x00ff, 65535);
    var reply = buf;
    reply[0] = v6.echo_reply;
    const parsed = parseV6(&reply);
    try std.testing.expectEqual(@as(u16, 0x00ff), parsed.echo_reply.ident);
    try std.testing.expectEqual(@as(u16, 65535), parsed.echo_reply.seq);
}

test "echo reply v4 with raw IP header" {
    var pkt: [20 + echo_header_len]u8 = @splat(0);
    pkt[0] = 0x45; // IPv4, ihl=5
    pkt[20] = v4.echo_reply;
    std.mem.writeInt(u16, pkt[24..26], 7, .big);
    std.mem.writeInt(u16, pkt[26..28], 9, .big);
    const parsed = parseV4(&pkt, true);
    try std.testing.expectEqual(@as(u16, 7), parsed.echo_reply.ident);
    try std.testing.expectEqual(@as(u16, 9), parsed.echo_reply.seq);
}

test "icmp v4 dest unreachable quoting our echo" {
    var pkt: [echo_header_len + 20 + echo_header_len]u8 = @splat(0);
    pkt[0] = v4.dest_unreachable;
    pkt[1] = 1; // host unreachable
    pkt[8] = 0x45; // quoted IP header
    const orig = pkt[8 + 20 ..];
    orig[0] = v4.echo_request;
    std.mem.writeInt(u16, orig[4..6], 0x1234, .big);
    std.mem.writeInt(u16, orig[6..8], 77, .big);
    const parsed = parseV4(&pkt, false);
    try std.testing.expectEqual(ErrorKind.dest_unreachable, parsed.icmp_error.kind);
    try std.testing.expectEqual(@as(u16, 0x1234), parsed.icmp_error.orig_ident);
    try std.testing.expectEqual(@as(u16, 77), parsed.icmp_error.orig_seq);
}

test "echo reply v6" {
    var pkt: [echo_header_len]u8 = @splat(0);
    pkt[0] = v6.echo_reply;
    std.mem.writeInt(u16, pkt[4..6], 3, .big);
    std.mem.writeInt(u16, pkt[6..8], 4, .big);
    const parsed = parseV6(&pkt);
    try std.testing.expectEqual(@as(u16, 3), parsed.echo_reply.ident);
    try std.testing.expectEqual(@as(u16, 4), parsed.echo_reply.seq);
}

test "short and foreign packets are ignored" {
    try std.testing.expectEqual(Reply.ignored, parseV4(&.{ 1, 2, 3 }, false));
    try std.testing.expectEqual(Reply.ignored, parseV6(&.{}));
    var pkt: [echo_header_len]u8 = @splat(0);
    pkt[0] = 99;
    try std.testing.expectEqual(Reply.ignored, parseV4(&pkt, false));
    // Truncated error quotes must be ignored, not sliced out of bounds.
    var err4: [echo_header_len + 10]u8 = @splat(0);
    err4[0] = v4.time_exceeded;
    err4[8] = 0x45;
    try std.testing.expectEqual(Reply.ignored, parseV4(&err4, false));
    var err6: [echo_header_len + 12]u8 = @splat(0);
    err6[0] = v6.time_exceeded;
    try std.testing.expectEqual(Reply.ignored, parseV6(&err6));
}

test "comptime checksum" {
    // Zig-only: the wire checksum is evaluated at compile time, so this
    // "test" cannot even build if the algorithm regresses.
    comptime {
        const data = [_]u8{ 0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7 };
        std.debug.assert(checksum(&data) == 0x220d);
        var pkt: [echo_header_len + 4]u8 = @splat(0);
        writeEchoRequest(.v4, &pkt, 0x1234, 7);
        std.debug.assert(checksum(&pkt) == 0); // packet must verify
    }
}

test "checksum property: inserting the checksum makes packets verify" {
    // Property test over random payloads — fping's C tree has no unit
    // tests at all (only a Perl end-to-end suite).
    var prng: std.Random.DefaultPrng = .init(0xdecafbad);
    const random = prng.random();
    var pkt: [echo_header_len + 56]u8 = undefined;
    for (0..1000) |_| {
        random.bytes(&pkt);
        writeEchoRequest(.v4, &pkt, random.int(u16), random.int(u16));
        try std.testing.expectEqual(@as(u16, 0), checksum(&pkt));
    }
}

test "fuzz: parsers never crash on arbitrary packets" {
    // Fuzzing is built into the Zig toolchain (`zig build test --fuzz`);
    // under a plain `zig build test` this runs as a smoke test. The
    // parsers handle untrusted bytes straight from the network, and safe
    // build modes turn any out-of-bounds access into a caught panic.
    try std.testing.fuzz({}, fuzzParsers, .{});
}

fn fuzzParsers(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    _ = parseV4(buf[0..len], false);
    _ = parseV4(buf[0..len], true);
    _ = parseV6(buf[0..len]);
}
