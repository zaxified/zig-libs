// SPDX-License-Identifier: MIT

//! echo — the ICMP (RFC 792) and ICMPv6 (RFC 4443 §4) Echo Request / Echo
//! Reply decoder that feeds `Estimator.observeEcho`.
//!
//! An Echo message is 8 octets of header and an opaque payload:
//!
//!     0      1      2      3      4      5      6      7
//!     type   code   checksum      identifier    sequence      payload…
//!
//! ICMPv4 uses type 8 (request) / 0 (reply); ICMPv6 uses 128 / 129. Code is 0
//! for both. RFC 792: "the identifier and sequence number may be used by the
//! echo sender to aid in matching the replies with the echo requests", and
//! the replier copies both (and the payload) back unchanged — which is exactly
//! what a passive observer needs: the pair (identifier, sequence) seen on a
//! request going one way is the pair a reply carries the other way. `key`
//! packs it into the 32-bit value the shared `TsTable` stores.
//!
//! Two entry points:
//!   - `parseIcmpEcho(family, icmp_message)` — the message starting at the
//!     ICMP type octet, for a caller that already walked the IP header.
//!   - `parseIpEcho(ip_packet)` — a whole IPv4 or IPv6 packet (version from
//!     its first nibble). Walks the IPv4 header (IHL, total length, first
//!     fragment only) or the IPv6 extension-header chain (Hop-by-Hop, Routing,
//!     Destination Options, Fragment, AH; at most `max_ipv6_extension_headers`)
//!     and also returns the source and destination addresses, so the caller can
//!     demultiplex by address pair and pick a `Direction` (`IpEcho.direction`).
//!
//! **Checksums are not verified.** IPv4 and ICMPv6 checksums need the full
//! message (the capture may be snaplen-truncated) and, for ICMPv6, the IPv6
//! pseudo-header; a passive observer measures what the endpoints accepted, and
//! the endpoints check them. A corrupted packet that reaches the estimator can
//! at worst cause one wrong sample or one missed sample, never memory growth.
//!
//! Hostile-input contract: every input is untrusted wire bytes. Neither entry
//! point reads past its slice or panics. "Well formed, but not an echo" is
//! `null` (a TCP segment, an ICMP Destination Unreachable, a non-first
//! fragment, ESP); "cannot be what it claims" is a typed `ParseError`.

const std = @import("std");

/// Which ICMP the message belongs to: ICMPv4 inside IPv4 or ICMPv6 inside IPv6.
pub const Family = enum { v4, v6 };

pub const Kind = enum { request, reply };

/// One decoded Echo Request or Echo Reply header.
pub const IcmpEcho = struct {
    family: Family,
    kind: Kind,
    identifier: u16,
    sequence: u16,

    /// The 32-bit value the matching table stores: `identifier << 16 |
    /// sequence`. Matching is exact equality, so a sequence number that wraps
    /// from 65535 to 0 is simply a different key — no ordering is assumed.
    pub fn key(self: IcmpEcho) u32 {
        return @as(u32, self.identifier) << 16 | self.sequence;
    }
};

pub const IpAddr = union(Family) {
    v4: [4]u8,
    v6: [16]u8,

    fn bytes(self: *const IpAddr) []const u8 {
        return switch (self.*) {
            .v4 => |*a| a,
            .v6 => |*a| a,
        };
    }
};

/// An echo message together with the addresses of the packet that carried it.
pub const IpEcho = struct {
    src: IpAddr,
    dst: IpAddr,
    echo: IcmpEcho,

    /// A `Direction` that is consistent across both directions of one address
    /// pair, for a caller that keys one `Estimator` per unordered pair
    /// {src, dst}: `a_to_b` when `src` sorts below `dst` (octet-wise), `b_to_a`
    /// when above. When `src == dst` (a host pinging its own address — there
    /// is only one host, so requests can only be answered by it) requests are
    /// `a_to_b` and replies `b_to_a`.
    pub fn direction(self: IpEcho) Direction {
        return switch (std.mem.order(u8, self.src.bytes(), self.dst.bytes())) {
            .lt => .a_to_b,
            .gt => .b_to_a,
            .eq => switch (self.echo.kind) {
                .request => .a_to_b,
                .reply => .b_to_a,
            },
        };
    }
};

const Direction = @import("root.zig").Direction;

pub const ParseError = error{
    /// The bytes end before a header that the packet says is there is complete.
    Truncated,
    /// The first nibble is neither 4 nor 6.
    UnknownIpVersion,
    /// IPv4 IHL below 5, or a total length shorter than the header.
    BadHeaderLength,
    /// The ICMP type is an echo type but the code is not 0.
    BadCode,
    /// More IPv6 extension headers than `max_ipv6_extension_headers`.
    TooManyExtensionHeaders,
};

/// Cap on the IPv6 extension-header walk. RFC 8200 §4.1 recommends each
/// appear at most once (Destination Options at most twice) — six is the
/// longest legitimate chain; eight leaves room without letting a packet of
/// chained headers make the walk long.
pub const max_ipv6_extension_headers = 8;

/// Decode an ICMP message (starting at its type octet). `null` when it is not
/// an Echo Request or Echo Reply of `family`.
pub fn parseIcmpEcho(family: Family, msg: []const u8) ParseError!?IcmpEcho {
    if (msg.len < 1) return error.Truncated;
    const kind: Kind = switch (family) {
        .v4 => switch (msg[0]) {
            8 => .request,
            0 => .reply,
            else => return null,
        },
        .v6 => switch (msg[0]) {
            128 => .request,
            129 => .reply,
            else => return null,
        },
    };
    if (msg.len < 8) return error.Truncated;
    if (msg[1] != 0) return error.BadCode;
    return .{
        .family = family,
        .kind = kind,
        .identifier = std.mem.readInt(u16, msg[4..6], .big),
        .sequence = std.mem.readInt(u16, msg[6..8], .big),
    };
}

/// Decode a whole IPv4 or IPv6 packet (no link-layer header). `null` when it
/// is well formed but does not carry an ICMP / ICMPv6 Echo header (another
/// protocol, another ICMP type, a non-first fragment, ESP, No Next Header).
pub fn parseIpEcho(packet: []const u8) ParseError!?IpEcho {
    if (packet.len < 1) return error.Truncated;
    return switch (packet[0] >> 4) {
        4 => parseIpv4(packet),
        6 => parseIpv6(packet),
        else => error.UnknownIpVersion,
    };
}

fn parseIpv4(p: []const u8) ParseError!?IpEcho {
    if (p.len < 20) return error.Truncated;
    const hlen: usize = @as(usize, p[0] & 0x0f) * 4;
    if (hlen < 20) return error.BadHeaderLength;
    const total: usize = std.mem.readInt(u16, p[2..4], .big);
    if (total < hlen) return error.BadHeaderLength;
    if (p.len < hlen) return error.Truncated;
    const frag_offset = std.mem.readInt(u16, p[6..8], .big) & 0x1fff;
    if (frag_offset != 0) return null; // only the first fragment carries the ICMP header
    if (p[9] != 1) return null; // not ICMP
    // A capture may be cut short of `total` (snaplen); the echo header is all
    // that is needed. Bytes past `total` are link-layer padding, not ICMP.
    const end = @min(total, p.len);
    const echo = try parseIcmpEcho(.v4, p[hlen..end]) orelse return null;
    return .{ .src = .{ .v4 = p[12..16].* }, .dst = .{ .v4 = p[16..20].* }, .echo = echo };
}

fn parseIpv6(p: []const u8) ParseError!?IpEcho {
    if (p.len < 40) return error.Truncated;
    const plen: usize = std.mem.readInt(u16, p[4..6], .big);
    // Payload length 0 is a jumbogram (RFC 2675): take what was captured.
    const end = if (plen == 0) p.len else @min(40 + plen, p.len);
    var next = p[6];
    var off: usize = 40;
    var walked: usize = 0;
    while (true) {
        switch (next) {
            58 => break, // ICMPv6
            0, 43, 60, 44, 51 => {
                if (walked == max_ipv6_extension_headers) return error.TooManyExtensionHeaders;
                walked += 1;
                if (end < off + 2) return error.Truncated;
                const ext_len: usize = switch (next) {
                    44 => 8, // Fragment: fixed size
                    51 => (@as(usize, p[off + 1]) + 2) * 4, // AH: 32-bit words, minus 2
                    else => (@as(usize, p[off + 1]) + 1) * 8, // 8-octet units, minus the first
                };
                if (end < off + ext_len) return error.Truncated;
                if (next == 44) {
                    const frag_offset = std.mem.readInt(u16, p[off + 2 ..][0..2], .big) >> 3;
                    if (frag_offset != 0) return null;
                }
                next = p[off];
                off += ext_len;
            },
            else => return null, // TCP, UDP, ESP, No Next Header, …
        }
    }
    const echo = try parseIcmpEcho(.v6, p[off..end]) orelse return null;
    return .{ .src = .{ .v6 = p[8..24].* }, .dst = .{ .v6 = p[24..40].* }, .echo = echo };
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "parseIcmpEcho: v4 request and reply, v6 request and reply" {
    const req4 = [_]u8{ 8, 0, 0xaa, 0xbb, 0x12, 0x34, 0x00, 0x07 };
    const e = (try parseIcmpEcho(.v4, &req4)).?;
    try testing.expectEqual(Kind.request, e.kind);
    try testing.expectEqual(@as(u16, 0x1234), e.identifier);
    try testing.expectEqual(@as(u16, 7), e.sequence);
    try testing.expectEqual(@as(u32, 0x1234_0007), e.key());

    const rep4 = [_]u8{ 0, 0, 0, 0, 0x12, 0x34, 0x00, 0x07 };
    try testing.expectEqual(Kind.reply, (try parseIcmpEcho(.v4, &rep4)).?.kind);
    const req6 = [_]u8{ 128, 0, 0, 0, 0, 1, 0xff, 0xff };
    const e6 = (try parseIcmpEcho(.v6, &req6)).?;
    try testing.expectEqual(Kind.request, e6.kind);
    try testing.expectEqual(Family.v6, e6.family);
    try testing.expectEqual(@as(u16, 0xffff), e6.sequence);
    const rep6 = [_]u8{ 129, 0, 0, 0, 0, 1, 0xff, 0xff };
    try testing.expectEqual(Kind.reply, (try parseIcmpEcho(.v6, &rep6)).?.kind);
}

test "parseIcmpEcho: the other family's echo types are not echoes" {
    // 128/129 inside IPv4 and 8/0 inside IPv6 are other messages entirely.
    try testing.expectEqual(@as(?IcmpEcho, null), try parseIcmpEcho(.v4, &[_]u8{ 128, 0, 0, 0, 0, 1, 0, 1 }));
    try testing.expectEqual(@as(?IcmpEcho, null), try parseIcmpEcho(.v6, &[_]u8{ 8, 0, 0, 0, 0, 1, 0, 1 }));
    // Destination Unreachable (3) and ICMPv6 Packet Too Big (2): not echoes,
    // even when shorter than an echo header.
    try testing.expectEqual(@as(?IcmpEcho, null), try parseIcmpEcho(.v4, &[_]u8{3}));
    try testing.expectEqual(@as(?IcmpEcho, null), try parseIcmpEcho(.v6, &[_]u8{ 2, 0 }));
}

test "parseIcmpEcho: truncated echo headers and non-zero codes fail closed" {
    try testing.expectError(error.Truncated, parseIcmpEcho(.v4, &[_]u8{}));
    try testing.expectError(error.Truncated, parseIcmpEcho(.v4, &[_]u8{ 8, 0, 0, 0, 0, 1, 0 }));
    try testing.expectError(error.Truncated, parseIcmpEcho(.v6, &[_]u8{129}));
    try testing.expectError(error.BadCode, parseIcmpEcho(.v4, &[_]u8{ 0, 1, 0, 0, 0, 1, 0, 1 }));
}

fn ipv4Echo(buf: *[28]u8, ihl_words: u8, total: u16, flags_frag: u16, proto: u8, icmp: [8]u8) []u8 {
    buf.* = [_]u8{0} ** 28;
    buf[0] = 0x40 | ihl_words;
    std.mem.writeInt(u16, buf[2..4], total, .big);
    std.mem.writeInt(u16, buf[6..8], flags_frag, .big);
    buf[8] = 64;
    buf[9] = proto;
    buf[12..16].* = .{ 10, 0, 0, 1 };
    buf[16..20].* = .{ 10, 0, 0, 2 };
    buf[20..28].* = icmp;
    return buf;
}

test "parseIpEcho: IPv4 header walk — addresses, first fragment only, protocol, lengths" {
    var b: [28]u8 = undefined;
    const icmp = [_]u8{ 8, 0, 0, 0, 0, 9, 0, 3 };

    const ok = (try parseIpEcho(ipv4Echo(&b, 5, 28, 0x4000, 1, icmp))).?; // DF set
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 1 }, &ok.src.v4);
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 2 }, &ok.dst.v4);
    try testing.expectEqual(@as(u16, 9), ok.echo.identifier);
    // First fragment of a fragmented echo (MF set, offset 0): header is here.
    try testing.expect((try parseIpEcho(ipv4Echo(&b, 5, 28, 0x2000, 1, icmp))) != null);
    // A later fragment: its first octets are payload, not an ICMP header.
    try testing.expectEqual(@as(?IpEcho, null), try parseIpEcho(ipv4Echo(&b, 5, 28, 0x0001, 1, icmp)));
    // TCP with bytes that would read as an echo request: not ICMP.
    try testing.expectEqual(@as(?IpEcho, null), try parseIpEcho(ipv4Echo(&b, 5, 28, 0, 6, icmp)));
    // IHL 4 and a total length below the header are impossible.
    try testing.expectError(error.BadHeaderLength, parseIpEcho(ipv4Echo(&b, 4, 28, 0, 1, icmp)));
    try testing.expectError(error.BadHeaderLength, parseIpEcho(ipv4Echo(&b, 5, 19, 0, 1, icmp)));
    // IHL 7 claims options past the end of a 28-octet capture.
    try testing.expectError(error.Truncated, parseIpEcho(ipv4Echo(&b, 7, 28, 0, 1, icmp)));
    // A total length that stops inside the echo header.
    try testing.expectError(error.Truncated, parseIpEcho(ipv4Echo(&b, 5, 27, 0, 1, icmp)));
    // A capture cut short of the total length still decodes from the header.
    try testing.expect((try parseIpEcho(ipv4Echo(&b, 5, 84, 0, 1, icmp))) != null);
    try testing.expectError(error.Truncated, parseIpEcho(b[0..19]));
    try testing.expectError(error.Truncated, parseIpEcho(&[_]u8{}));
    try testing.expectError(error.UnknownIpVersion, parseIpEcho(&[_]u8{0x50}));
}

fn ipv6Base(buf: []u8, plen: u16, next: u8) void {
    @memset(buf, 0);
    buf[0] = 0x60;
    std.mem.writeInt(u16, buf[4..6], plen, .big);
    buf[6] = next;
    buf[7] = 64;
    buf[8] = 0xfd;
    buf[23] = 1; // fd00::1
    buf[24] = 0xfd;
    buf[39] = 2; // fd00::2
}

test "parseIpEcho: IPv6 extension-header walk — HbH, Fragment, AH, ESP, cap" {
    var b: [128]u8 = undefined;
    const icmp = [_]u8{ 129, 0, 0, 0, 0xbe, 0xef, 0, 1 };

    // Bare ICMPv6.
    ipv6Base(&b, 8, 58);
    b[40..48].* = icmp;
    const bare = (try parseIpEcho(b[0..48])).?;
    try testing.expectEqual(Kind.reply, bare.echo.kind);
    try testing.expectEqual(@as(u8, 2), bare.dst.v6[15]);

    // Hop-by-Hop (8 octets) -> Fragment (offset 0) -> ICMPv6.
    ipv6Base(&b, 24, 0);
    b[40] = 44; // HbH next = Fragment
    b[41] = 0; // (0+1)*8 = 8 octets
    b[48] = 58; // Fragment next = ICMPv6
    b[50..52].* = .{ 0x00, 0x01 }; // offset 0, M flag
    b[56..64].* = icmp;
    try testing.expectEqual(@as(u16, 0xbeef), (try parseIpEcho(b[0..64])).?.echo.identifier);
    // The same, as a non-first fragment.
    b[50..52].* = .{ 0x00, 0x08 }; // offset 1
    try testing.expectEqual(@as(?IpEcho, null), try parseIpEcho(b[0..64]));

    // AH: length in 32-bit words minus 2 — payload len 1 means 12 octets.
    ipv6Base(&b, 20, 51);
    b[40] = 58;
    b[41] = 1;
    b[52..60].* = icmp;
    try testing.expect((try parseIpEcho(b[0..60])) != null);

    // ESP (50) and No Next Header (59): nothing to see.
    ipv6Base(&b, 8, 50);
    try testing.expectEqual(@as(?IpEcho, null), try parseIpEcho(b[0..48]));
    ipv6Base(&b, 0, 59);
    try testing.expectEqual(@as(?IpEcho, null), try parseIpEcho(b[0..40]));

    // An extension header whose length runs past the payload length.
    ipv6Base(&b, 8, 60);
    b[41] = 1; // 16 octets, payload is 8
    try testing.expectError(error.Truncated, parseIpEcho(b[0..48]));

    // Nine chained Destination Options headers: over the cap.
    ipv6Base(&b, 80, 60);
    for (0..10) |i| {
        b[40 + 8 * i] = 60;
        b[41 + 8 * i] = 0;
    }
    try testing.expectError(error.TooManyExtensionHeaders, parseIpEcho(b[0..120]));

    try testing.expectError(error.Truncated, parseIpEcho(b[0..39]));
}

test "IpEcho.direction: ordered by address, and by kind for a self-ping" {
    const req: IcmpEcho = .{ .family = .v4, .kind = .request, .identifier = 1, .sequence = 1 };
    var rep = req;
    rep.kind = .reply;
    const lo: IpAddr = .{ .v4 = .{ 10, 0, 0, 1 } };
    const hi: IpAddr = .{ .v4 = .{ 10, 0, 0, 2 } };
    try testing.expectEqual(Direction.a_to_b, (IpEcho{ .src = lo, .dst = hi, .echo = req }).direction());
    try testing.expectEqual(Direction.b_to_a, (IpEcho{ .src = hi, .dst = lo, .echo = rep }).direction());
    // The other host pinging back uses the same labels for the same paths.
    try testing.expectEqual(Direction.b_to_a, (IpEcho{ .src = hi, .dst = lo, .echo = req }).direction());
    try testing.expectEqual(Direction.a_to_b, (IpEcho{ .src = lo, .dst = lo, .echo = req }).direction());
    try testing.expectEqual(Direction.b_to_a, (IpEcho{ .src = lo, .dst = lo, .echo = rep }).direction());
}

test "parseIpEcho: hostile random packets of every length never panic or read OOB" {
    var state: u64 = 0x9E3779B97F4A7C15;
    var buf: [96]u8 = undefined;
    var trials: usize = 0;
    while (trials < 20_000) : (trials += 1) {
        for (&buf) |*x| {
            state = state *% 6364136223846793005 +% 1442695040888963407;
            x.* = @truncate(state >> 33);
        }
        // Make the version nibble 4 or 6 most of the time so the walk runs.
        buf[0] = (buf[0] & 0x0f) | (if (buf[1] & 1 == 0) @as(u8, 0x40) else 0x60);
        const len = trials % (buf.len + 1);
        _ = parseIpEcho(buf[0..len]) catch {};
    }
}

// ── check-fuzz coverage: a `testing.fuzz` harness on `parseIpEcho` ──────────

const fuzzseed = @import("testkit").fuzz;

/// Seeds are whole IP packets, verbatim (one byte-first `smith.slice` draw is
/// the packet): two real loopback frames from `echo_golden.zig` (the 14-octet
/// link header removed) and hand-built shapes for the branches they miss.
const fuzz_corpus = [_][]const u8{
    // ⭐ ping 127.0.0.1 -> 127.0.0.2, echo request id 7749 seq 1 (first 28 octets)
    fuzzseed.seedHex("450000543afc4000400101aa7f0000017f0000020800" ++ "6e441e450001"),
    // ⭐ the reply to it
    fuzzseed.seedHex("45000054a8d000004001d3d57f0000027f000001" ++ "00007644" ++ "1e450001"),
    fuzzseed.seedHex("4500001c000000004006000000000000000000000800000000010001"), // TCP, not ICMP
    fuzzseed.seedHex("4500001c000020014001000000000000000000000800000000010001"), // non-first fragment
    fuzzseed.seedHex("4f00001c"), // IHL 15, truncated
    fuzzseed.seedHex("6000000000083a40" ++ "00" ** 32 ++ "8100000000010001"), // bare ICMPv6 reply
    fuzzseed.seedHex("6000000000100040" ++ "00" ** 32 ++ "3a00000000000000" ++ "8000000000010001"), // HbH then request
    fuzzseed.seedHex("60000000002c3c40" ++ "00" ** 32 ++ ("3c00000000000000" ** 5)), // DestOpts chain
    fuzzseed.seedHex("6000000000203340" ++ "00" ** 32 ++ "3aff"), // AH claiming 1028 octets
    fuzzseed.seedHex("7000"), // version 7
};

test "fuzz: parseIpEcho never panics or reads OOB on arbitrary packets" {
    try std.testing.fuzz({}, fuzzParseIpEcho, .{ .corpus = &fuzz_corpus });
}

fn fuzzParseIpEcho(_: void, smith: *std.testing.Smith) !void {
    var raw: [128]u8 = undefined;
    const n: usize = smith.slice(&raw);
    _ = parseIpEcho(raw[0..n]) catch {};
}

test "corpus: every seed reaches the walk, and the outcomes are pinned" {
    var echoes: usize = 0;
    var nulls: usize = 0;
    var errors: usize = 0;
    for (fuzz_corpus) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var raw: [128]u8 = undefined;
        const n: usize = smith.slice(&raw);
        try testing.expect(n > 0);
        if (parseIpEcho(raw[0..n])) |r| {
            if (r != null) echoes += 1 else nulls += 1;
        } else |_| errors += 1;
    }
    try testing.expectEqual(@as(usize, 4), echoes);
    try testing.expectEqual(@as(usize, 2), nulls);
    try testing.expectEqual(@as(usize, 4), errors);
}
