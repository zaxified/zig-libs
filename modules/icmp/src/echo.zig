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

test "icmp v4 error kinds map correctly for every quoted-error type" {
    // Each v4 error type must map to its OWN ErrorKind, not just "some
    // non-dest_unreachable value" — a mutation that permutes the switch
    // arms (e.g. swaps time_exceeded/redirect) must be caught here.
    const cases = [_]struct { wire: u8, kind: ErrorKind }{
        .{ .wire = v4.dest_unreachable, .kind = .dest_unreachable },
        .{ .wire = v4.time_exceeded, .kind = .time_exceeded },
        .{ .wire = v4.redirect, .kind = .redirect },
        .{ .wire = v4.param_problem, .kind = .param_problem },
        .{ .wire = v4.source_quench, .kind = .other },
    };
    for (cases) |c| {
        var pkt: [echo_header_len + 20 + echo_header_len]u8 = @splat(0);
        pkt[0] = c.wire;
        pkt[8] = 0x45; // quoted IP header, ihl=5
        const orig = pkt[8 + 20 ..];
        orig[0] = v4.echo_request;
        std.mem.writeInt(u16, orig[4..6], 0x1234, .big);
        std.mem.writeInt(u16, orig[6..8], 77, .big);
        const parsed = parseV4(&pkt, false);
        try std.testing.expectEqual(c.kind, parsed.icmp_error.kind);
    }
}

test "icmp v4 error quoting a timestamp request is accepted" {
    // parseV4 explicitly accepts a quoted timestamp_request as "ours", not
    // just echo_request — the accessor `orig[0] != echo_request and
    // orig[0] != timestamp_request` must reject anything else.
    var pkt: [echo_header_len + 20 + echo_header_len]u8 = @splat(0);
    pkt[0] = v4.time_exceeded;
    pkt[8] = 0x45;
    const orig = pkt[8 + 20 ..];
    orig[0] = v4.timestamp_request;
    std.mem.writeInt(u16, orig[4..6], 0x55, .big);
    std.mem.writeInt(u16, orig[6..8], 66, .big);
    const parsed = parseV4(&pkt, false);
    try std.testing.expectEqual(ErrorKind.time_exceeded, parsed.icmp_error.kind);
    try std.testing.expectEqual(@as(u16, 0x55), parsed.icmp_error.orig_ident);
    try std.testing.expectEqual(@as(u16, 66), parsed.icmp_error.orig_seq);

    // A quoted type that is neither echo_request nor timestamp_request
    // must be ignored, not accepted as "close enough".
    orig[0] = v4.echo_reply;
    try std.testing.expectEqual(Reply.ignored, parseV4(&pkt, false));
}

test "icmp v4 quoted-header boundary is exact at qihl + echo_header_len" {
    // The binding constraint on the quoted region is
    // `quoted.len < qihl + echo_header_len`, not the earlier `quoted.len <
    // 20` sanity check (which a fixed 20-byte IHL quote always also
    // satisfies or fails together with the second check — a mutation there
    // alone is unobservable). Pin the real edge: with qihl=20, exactly 27
    // bytes of quote (one short of the required 28) must be rejected, and
    // exactly 28 must be accepted.
    var pkt27: [echo_header_len + 27]u8 = @splat(0);
    pkt27[0] = v4.time_exceeded;
    pkt27[8] = 0x45; // ihl=5 -> qihl=20; only 7 bytes follow, need 8
    pkt27[28] = v4.echo_request; // quoted[20] = orig[0], so it isn't the reason for rejection
    try std.testing.expectEqual(Reply.ignored, parseV4(&pkt27, false));

    var pkt28: [echo_header_len + 28]u8 = @splat(0);
    pkt28[0] = v4.time_exceeded;
    pkt28[8] = 0x45;
    const orig = pkt28[8 + 20 ..];
    orig[0] = v4.echo_request;
    const parsed = parseV4(&pkt28, false);
    try std.testing.expectEqual(ErrorKind.time_exceeded, parsed.icmp_error.kind);
}

test "icmp v6 error kinds map correctly for every quoted-error type" {
    const cases = [_]struct { wire: u8, kind: ErrorKind }{
        .{ .wire = v6.dest_unreachable, .kind = .dest_unreachable },
        .{ .wire = v6.packet_too_big, .kind = .packet_too_big },
        .{ .wire = v6.time_exceeded, .kind = .time_exceeded },
        .{ .wire = v6.param_problem, .kind = .param_problem },
    };
    for (cases) |c| {
        var pkt: [echo_header_len + 40 + echo_header_len]u8 = @splat(0);
        pkt[0] = c.wire;
        const quoted = pkt[echo_header_len..];
        quoted[6] = 58; // next header = ICMPv6
        const orig = quoted[40..];
        orig[0] = v6.echo_request;
        std.mem.writeInt(u16, orig[4..6], 0xbeef, .big);
        std.mem.writeInt(u16, orig[6..8], 9, .big);
        const parsed = parseV6(&pkt);
        try std.testing.expectEqual(c.kind, parsed.icmp_error.kind);
        try std.testing.expectEqual(@as(u16, 0xbeef), parsed.icmp_error.orig_ident);
        try std.testing.expectEqual(@as(u16, 9), parsed.icmp_error.orig_seq);
    }
}

test "icmp v6 error rejects wrong next-header and wrong quoted type" {
    var pkt: [echo_header_len + 40 + echo_header_len]u8 = @splat(0);
    pkt[0] = v6.time_exceeded;
    const quoted = pkt[echo_header_len..];
    const orig = quoted[40..];
    orig[0] = v6.echo_request;

    // next header != 58 (not ICMPv6) must be ignored.
    quoted[6] = 6; // TCP
    try std.testing.expectEqual(Reply.ignored, parseV6(&pkt));

    // Fix next header, but quote something other than echo_request.
    quoted[6] = 58;
    orig[0] = v6.echo_reply;
    try std.testing.expectEqual(Reply.ignored, parseV6(&pkt));
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

// ── real-capture goldens (loopback, tcpdump, 2026-08-01) ────────────────────
//
// Every fixture above this point is hand-computed from RFC 792/4443 — never
// checked against a real kernel. These are captured from an actual Linux
// network stack instead: `tcpdump -i lo` inside a throwaway, unprivileged
// `unshare --user --net` namespace (CAP_NET_RAW exists only inside that
// disposable namespace; nothing on the host was changed — no setcap, no
// persistent interface/firewall edits). Traffic generators: `ping` (echo
// request/reply, both families), a UDP datagram to a closed loopback port
// (kernel-generated dest-unreachable/port-unreachable), and a short Python
// script sending a hand-built ICMP timestamp request over an
// `AF_INET/SOCK_RAW` socket — self-verifying, since the kernel only replies
// if the request's checksum is valid. This anchors the wire layout and the
// kernel's own checksum arithmetic independently of this module's own
// `checksum()`.
//
// Not reachable from this sandbox — documented, not silently dropped:
//   - v4 source_quench: deprecated (RFC 6633); no reachable Linux path still
//     emits it.
//   - v4 redirect, v4/v6 param_problem: need either a real multi-router LAN
//     topology (redirect) or a deliberately malformed IP option/extension
//     header accepted far enough to be diagnosed (param_problem) — nothing
//     this sandbox can produce offline and reproducibly.
//   - v4/v6 time_exceeded: only ever generated by a *forwarding* router
//     decrementing TTL/hop-limit; loopback delivery never enters the
//     forwarding path, and capturing on a real routed interface would need
//     CAP_NET_RAW on the host itself (out of scope — see module task notes).
//   - v6 packet_too_big: needs a real path-MTU condition; loopback MTU is
//     64 KiB and nothing here fragments.

const v4_echo_req_icmp = [_]u8{
    0x08, 0x00, 0x65, 0xd8, 0x95, 0x55, 0x00, 0x01, 0xdb, 0xde, 0x6d, 0x6a, 0x00, 0x00, 0x00, 0x00,
    0xf2, 0xb4, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
};
const v4_echo_reply_icmp = [_]u8{
    0x00, 0x00, 0x6d, 0xd8, 0x95, 0x55, 0x00, 0x01, 0xdb, 0xde, 0x6d, 0x6a, 0x00, 0x00, 0x00, 0x00,
    0xf2, 0xb4, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
};
// The IPv4 header the reply above actually rode in on — pins the SOCK_RAW
// delivery path (`strip_ip_header = true`), 20 bytes, no options.
const v4_echo_reply_ip = [_]u8{
    0x45, 0x00, 0x00, 0x54, 0xa9, 0xe1, 0x00, 0x00, 0x40, 0x01, 0xd2, 0xc5, 0x7f, 0x00, 0x00, 0x01,
    0x7f, 0x00, 0x00, 0x01,
};
// A real kernel-generated ICMP port-unreachable (sent in response to a UDP
// datagram to a closed loopback port), quoting that UDP datagram.
const v4_dest_unreach_icmp = [_]u8{
    0x03, 0x03, 0x3d, 0x3a, 0x00, 0x00, 0x00, 0x00, 0x45, 0x00, 0x00, 0x21, 0x87, 0x57, 0x40, 0x00,
    0x40, 0x11, 0xb5, 0x72, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0xe1, 0x82, 0x9c, 0x3f,
    0x00, 0x0d, 0xfe, 0x20, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
};
const v4_ts_req_icmp = [_]u8{
    0x0d, 0x00, 0xaf, 0x6e, 0x13, 0x57, 0x00, 0x01, 0x00, 0x00, 0x30, 0x39, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
};
const v4_ts_reply_icmp = [_]u8{
    0x0e, 0x00, 0x46, 0x47, 0x13, 0x57, 0x00, 0x01, 0x00, 0x00, 0x30, 0x39, 0x02, 0x8f, 0xb1, 0x84,
    0x02, 0x8f, 0xb1, 0x84,
};
const v6_echo_req_icmp = [_]u8{
    0x80, 0x00, 0x4e, 0x52, 0x95, 0x5a, 0x00, 0x01, 0xdb, 0xde, 0x6d, 0x6a, 0x00, 0x00, 0x00, 0x00,
    0x87, 0xb9, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
};
const v6_echo_reply_icmp = [_]u8{
    0x81, 0x00, 0x4d, 0x52, 0x95, 0x5a, 0x00, 0x01, 0xdb, 0xde, 0x6d, 0x6a, 0x00, 0x00, 0x00, 0x00,
    0x87, 0xb9, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
};
// A real kernel-generated ICMPv6 dest-unreachable (port unreachable), quoting
// the UDP datagram it complains about — next-header 17 (UDP), not 58.
const v6_dest_unreach_icmp = [_]u8{
    0x01, 0x04, 0xff, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x60, 0x02, 0xd2, 0x83, 0x00, 0x0e, 0x11, 0x40,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0xda, 0xc5, 0x9c, 0x3f, 0x00, 0x0e, 0x00, 0x21, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x36,
};

test "golden: real capture — v4 echo request/reply over loopback verify" {
    // The checksum here is the kernel's, not ours — `checksum()` just has to
    // agree that it's zero.
    try std.testing.expectEqual(@as(u16, 0), checksum(&v4_echo_req_icmp));
    try std.testing.expectEqual(@as(u16, 0), checksum(&v4_echo_reply_icmp));
    const parsed = parseV4(&v4_echo_reply_icmp, false);
    try std.testing.expectEqual(@as(u16, 0x9555), parsed.echo_reply.ident);
    try std.testing.expectEqual(@as(u16, 1), parsed.echo_reply.seq);
}

test "golden: real capture — v4 echo reply with real IP header (SOCK_RAW path)" {
    var full: [v4_echo_reply_ip.len + v4_echo_reply_icmp.len]u8 = undefined;
    @memcpy(full[0..v4_echo_reply_ip.len], &v4_echo_reply_ip);
    @memcpy(full[v4_echo_reply_ip.len..], &v4_echo_reply_icmp);
    const parsed = parseV4(&full, true);
    try std.testing.expectEqual(@as(u16, 0x9555), parsed.echo_reply.ident);
    try std.testing.expectEqual(@as(u16, 1), parsed.echo_reply.seq);
}

test "golden: real capture — v4 ICMP timestamp request/reply over loopback" {
    try std.testing.expectEqual(@as(u16, 0), checksum(&v4_ts_req_icmp));
    try std.testing.expectEqual(@as(u16, 0), checksum(&v4_ts_reply_icmp));
    const parsed = parseV4(&v4_ts_reply_icmp, false);
    try std.testing.expectEqual(@as(u16, 0x1357), parsed.echo_reply.ident);
    try std.testing.expectEqual(@as(u16, 1), parsed.echo_reply.seq);
    const ts = parsed.echo_reply.ts.?;
    try std.testing.expectEqual(@as(u32, 12345), ts.originate_ms); // our own request's payload
    try std.testing.expectEqual(@as(u32, 0x028fb184), ts.receive_ms); // kernel-filled
    try std.testing.expectEqual(@as(u32, 0x028fb184), ts.transmit_ms); // kernel-filled
}

test "golden: real capture — v4 dest-unreachable quoting a UDP datagram is ignored" {
    // A genuine kernel-generated ICMP port-unreachable quotes the *UDP*
    // datagram it's complaining about, not one of our ICMP requests.
    // `orig[0]` is the quoted UDP header's high source-port byte here — it
    // must never be confused with echo_request/timestamp_request.
    try std.testing.expectEqual(Reply.ignored, parseV4(&v4_dest_unreach_icmp, false));
}

test "golden: real capture — v6 echo request wire bytes (type/code/id/seq)" {
    try std.testing.expectEqual(@as(u8, v6.echo_request), v6_echo_req_icmp[0]);
    try std.testing.expectEqual(@as(u8, 0), v6_echo_req_icmp[1]);
    try std.testing.expectEqual(@as(u16, 0x955a), std.mem.readInt(u16, v6_echo_req_icmp[4..6], .big));
    try std.testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, v6_echo_req_icmp[6..8], .big));
}

test "golden: real capture — v6 echo reply over loopback" {
    // The reply's checksum is real (kernel-computed over the IPv6
    // pseudo-header, per the module doc comment this library never
    // recomputes) — parseV6 just has to decode id/seq correctly.
    const parsed = parseV6(&v6_echo_reply_icmp);
    try std.testing.expectEqual(@as(u16, 0x955a), parsed.echo_reply.ident);
    try std.testing.expectEqual(@as(u16, 1), parsed.echo_reply.seq);
}

test "golden: real capture — v6 dest-unreachable quoting a UDP datagram is ignored" {
    // Same shape as the v4 case above, but the rejection reason is the
    // quoted next-header (17/UDP, not 58/ICMPv6) rather than the quoted type.
    try std.testing.expectEqual(Reply.ignored, parseV6(&v6_dest_unreach_icmp));
}

test "golden: real-capture fixture count + size canary — 8 real loopback captures" {
    // Pins fixture shapes so a future re-capture silently changing sizes
    // (e.g. a kernel start sending ping payload padding differently) doesn't
    // slip by unnoticed.
    try std.testing.expectEqual(@as(usize, 64), v4_echo_req_icmp.len);
    try std.testing.expectEqual(@as(usize, 64), v4_echo_reply_icmp.len);
    try std.testing.expectEqual(@as(usize, 20), v4_echo_reply_ip.len);
    try std.testing.expectEqual(@as(usize, 41), v4_dest_unreach_icmp.len);
    try std.testing.expectEqual(@as(usize, 20), v4_ts_req_icmp.len);
    try std.testing.expectEqual(@as(usize, 20), v4_ts_reply_icmp.len);
    try std.testing.expectEqual(@as(usize, 64), v6_echo_req_icmp.len);
    try std.testing.expectEqual(@as(usize, 64), v6_echo_reply_icmp.len);
    try std.testing.expectEqual(@as(usize, 62), v6_dest_unreach_icmp.len);
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
