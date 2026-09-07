// SPDX-License-Identifier: MIT

//! ARP (RFC 826) packet codec.
//!
//! Two layers:
//!
//! - `Packet` — the generic ARP packet with variable hardware/protocol
//!   address lengths; parses by slicing into the caller's buffer
//!   (allocation-free).
//! - `EthIpv4` — the common Ethernet+IPv4 case as a fully typed value
//!   (`Mac` + `[4]u8` addresses) with request/reply/gratuitous
//!   constructors and a fixed 28-byte encoding.
//!
//! Gratuitous ARP (sender protocol address == target protocol address,
//! announcing/defending an address) and ARP probes (sender protocol
//! address all-zero, RFC 5227) are recognized via predicates.
//!
//! Provenance: clean-room from RFC 826 (with RFC 5227 for the
//! probe/announce conventions).

const std = @import("std");
const netaddr = @import("netaddr");
// Test-only (`build.zig`'s `test_deps`, never `deps`): the fuzz corpus seed
// helpers, in the format `std.testing.Smith` actually reads.
const testkit = @import("testkit");
const Mac = @import("mac.zig").Mac;

pub const ParseError = error{
    /// Buffer shorter than the fixed 8-byte ARP header.
    Truncated,
    /// Buffer shorter than header + 2*(hlen+plen) address block.
    TruncatedAddresses,
    /// `EthIpv4.parse` only: htype/ptype/hlen/plen are not Ethernet+IPv4.
    NotEthernetIpv4,
};

/// ARP hardware types (IANA "arp-parameters"); only Ethernet matters here.
pub const htype_ethernet: u16 = 1;
/// EtherType for IPv4, used as the ARP protocol type.
pub const ptype_ipv4: u16 = 0x0800;

pub const Operation = enum(u16) {
    request = 1,
    reply = 2,
    _,
};

/// Generic ARP packet — address fields are slices into the parsed buffer
/// (or caller-provided slices when building).
pub const Packet = struct {
    htype: u16,
    ptype: u16,
    oper: Operation,
    /// Sender hardware address (`hlen` bytes).
    sha: []const u8,
    /// Sender protocol address (`plen` bytes).
    spa: []const u8,
    /// Target hardware address (`hlen` bytes).
    tha: []const u8,
    /// Target protocol address (`plen` bytes).
    tpa: []const u8,

    /// Fixed header size before the four address fields.
    pub const header_len = 8;

    /// Parses one ARP packet from `bytes` (trailing bytes ignored — Ethernet
    /// pads short frames). Slices point into `bytes`.
    pub fn parse(bytes: []const u8) ParseError!Packet {
        if (bytes.len < header_len) return ParseError.Truncated;
        const hlen: usize = bytes[4];
        const plen: usize = bytes[5];
        const need = header_len + 2 * (hlen + plen);
        if (bytes.len < need) return ParseError.TruncatedAddresses;
        var pos: usize = header_len;
        const sha = bytes[pos..][0..hlen];
        pos += hlen;
        const spa = bytes[pos..][0..plen];
        pos += plen;
        const tha = bytes[pos..][0..hlen];
        pos += hlen;
        const tpa = bytes[pos..][0..plen];
        return .{
            .htype = std.mem.readInt(u16, bytes[0..2], .big),
            .ptype = std.mem.readInt(u16, bytes[2..4], .big),
            .oper = @enumFromInt(std.mem.readInt(u16, bytes[6..8], .big)),
            .sha = sha,
            .spa = spa,
            .tha = tha,
            .tpa = tpa,
        };
    }

    /// Encoded size of this packet.
    pub fn encodedLen(p: *const Packet) usize {
        return header_len + 2 * (p.sha.len + p.spa.len);
    }

    /// Encodes into `buf`; returns the written slice. `sha`/`tha` must have
    /// equal length (hlen), likewise `spa`/`tpa` (plen), each <= 255.
    pub fn encode(p: *const Packet, buf: []u8) error{BufferTooSmall}![]const u8 {
        std.debug.assert(p.sha.len == p.tha.len and p.sha.len <= 255);
        std.debug.assert(p.spa.len == p.tpa.len and p.spa.len <= 255);
        const need = p.encodedLen();
        if (buf.len < need) return error.BufferTooSmall;
        std.mem.writeInt(u16, buf[0..2], p.htype, .big);
        std.mem.writeInt(u16, buf[2..4], p.ptype, .big);
        buf[4] = @intCast(p.sha.len);
        buf[5] = @intCast(p.spa.len);
        std.mem.writeInt(u16, buf[6..8], @intFromEnum(p.oper), .big);
        var pos: usize = header_len;
        for ([_][]const u8{ p.sha, p.spa, p.tha, p.tpa }) |field| {
            @memcpy(buf[pos..][0..field.len], field);
            pos += field.len;
        }
        return buf[0..need];
    }
};

/// The Ethernet+IPv4 ARP packet as a typed value — the case every
/// discovery/scan workload actually sees.
pub const EthIpv4 = struct {
    oper: Operation,
    sender_mac: Mac,
    sender_ip: [4]u8,
    target_mac: Mac,
    target_ip: [4]u8,

    /// Wire size: 8-byte header + 2*(6+4) addresses.
    pub const wire_len = 28;

    /// An ARP request: "who has `target_ip`? tell `sender_ip`". Target MAC
    /// is zero (unknown).
    pub fn request(sender_mac: Mac, sender_ip: [4]u8, target_ip: [4]u8) EthIpv4 {
        return .{
            .oper = .request,
            .sender_mac = sender_mac,
            .sender_ip = sender_ip,
            .target_mac = .zero,
            .target_ip = target_ip,
        };
    }

    /// An ARP reply: "`sender_ip` is at `sender_mac`", addressed to the
    /// original requester.
    pub fn reply(sender_mac: Mac, sender_ip: [4]u8, target_mac: Mac, target_ip: [4]u8) EthIpv4 {
        return .{
            .oper = .reply,
            .sender_mac = sender_mac,
            .sender_ip = sender_ip,
            .target_mac = target_mac,
            .target_ip = target_ip,
        };
    }

    /// A gratuitous ARP announcement for `ip`: request with sender IP ==
    /// target IP, zero target MAC (RFC 5227 "ARP Announcement").
    pub fn gratuitous(mac: Mac, ip: [4]u8) EthIpv4 {
        return .{
            .oper = .request,
            .sender_mac = mac,
            .sender_ip = ip,
            .target_mac = .zero,
            .target_ip = ip,
        };
    }

    /// Gratuitous ARP: sender and target protocol addresses match
    /// (announcement/defence; sent as request or reply).
    pub fn isGratuitous(p: *const EthIpv4) bool {
        return std.mem.eql(u8, &p.sender_ip, &p.target_ip);
    }

    /// RFC 5227 ARP probe: request with an all-zero sender IP.
    pub fn isProbe(p: *const EthIpv4) bool {
        return p.oper == .request and std.mem.allEqual(u8, &p.sender_ip, 0);
    }

    pub fn senderIp(p: *const EthIpv4) netaddr.Ip {
        return .{ .v4 = p.sender_ip };
    }

    pub fn targetIp(p: *const EthIpv4) netaddr.Ip {
        return .{ .v4 = p.target_ip };
    }

    /// Parses an Ethernet+IPv4 ARP packet; anything else (other hardware or
    /// protocol types) is `NotEthernetIpv4` — fall back to `Packet.parse`.
    pub fn parse(bytes: []const u8) ParseError!EthIpv4 {
        const p = try Packet.parse(bytes);
        if (p.htype != htype_ethernet or p.ptype != ptype_ipv4 or
            p.sha.len != 6 or p.spa.len != 4)
            return ParseError.NotEthernetIpv4;
        return .{
            .oper = p.oper,
            .sender_mac = .{ .octets = p.sha[0..6].* },
            .sender_ip = p.spa[0..4].*,
            .target_mac = .{ .octets = p.tha[0..6].* },
            .target_ip = p.tpa[0..4].*,
        };
    }

    /// Encodes to the fixed 28-byte wire form.
    pub fn encode(p: *const EthIpv4) [wire_len]u8 {
        var buf: [wire_len]u8 = undefined;
        std.mem.writeInt(u16, buf[0..2], htype_ethernet, .big);
        std.mem.writeInt(u16, buf[2..4], ptype_ipv4, .big);
        buf[4] = 6;
        buf[5] = 4;
        std.mem.writeInt(u16, buf[6..8], @intFromEnum(p.oper), .big);
        buf[8..14].* = p.sender_mac.octets;
        buf[14..18].* = p.sender_ip;
        buf[18..24].* = p.target_mac.octets;
        buf[24..28].* = p.target_ip;
        return buf;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

// Golden Ethernet/IPv4 ARP request, transcribed field-by-field from the
// RFC 826 packet format: who-has 192.168.1.1, tell 192.168.1.100
// (sender 00:1b:21:3c:9d:f8).
const kat_request = [_]u8{
    0x00, 0x01, // htype: Ethernet
    0x08, 0x00, // ptype: IPv4
    0x06, 0x04, // hlen, plen
    0x00, 0x01, // oper: request
    0x00, 0x1b, 0x21, 0x3c, 0x9d, 0xf8, // sender MAC
    0xc0, 0xa8, 0x01, 0x64, // sender IP 192.168.1.100
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // target MAC (unknown)
    0xc0, 0xa8, 0x01, 0x01, // target IP 192.168.1.1
};

// Matching reply: 192.168.1.1 is-at a4:5e:60:d4:2b:11.
const kat_reply = [_]u8{
    0x00, 0x01,
    0x08, 0x00,
    0x06, 0x04,
    0x00, 0x02, // oper: reply
    0xa4, 0x5e, 0x60, 0xd4, 0x2b, 0x11, // sender MAC
    0xc0, 0xa8, 0x01, 0x01, // sender IP 192.168.1.1
    0x00, 0x1b, 0x21, 0x3c, 0x9d, 0xf8, // target MAC
    0xc0, 0xa8, 0x01, 0x64, // target IP 192.168.1.100
};

test "ARP KAT: parse request" {
    const p = try EthIpv4.parse(&kat_request);
    try testing.expectEqual(Operation.request, p.oper);
    try testing.expect(p.sender_mac.eql(Mac.parse("00:1b:21:3c:9d:f8").?));
    try testing.expectEqualSlices(u8, &.{ 192, 168, 1, 100 }, &p.sender_ip);
    try testing.expect(p.target_mac.isZero());
    try testing.expectEqualSlices(u8, &.{ 192, 168, 1, 1 }, &p.target_ip);
    try testing.expect(!p.isGratuitous());
    try testing.expect(!p.isProbe());

    // netaddr bridge.
    var ipbuf: [netaddr.max_ip_text_len]u8 = undefined;
    try testing.expectEqualStrings("192.168.1.100", netaddr.formatIp(p.senderIp(), &ipbuf));
}

test "ARP KAT: parse reply + round-trip both" {
    const r = try EthIpv4.parse(&kat_reply);
    try testing.expectEqual(Operation.reply, r.oper);
    try testing.expect(r.sender_mac.eql(Mac.parse("a4:5e:60:d4:2b:11").?));
    try testing.expectEqualSlices(u8, &.{ 192, 168, 1, 1 }, &r.sender_ip);
    try testing.expectEqualSlices(u8, &.{ 192, 168, 1, 100 }, &r.target_ip);

    // Round-trip: encode(parse(x)) == x.
    const req = try EthIpv4.parse(&kat_request);
    try testing.expectEqualSlices(u8, &kat_request, &req.encode());
    try testing.expectEqualSlices(u8, &kat_reply, &r.encode());

    // Constructor equivalence.
    const built = EthIpv4.request(
        Mac.parse("00:1b:21:3c:9d:f8").?,
        .{ 192, 168, 1, 100 },
        .{ 192, 168, 1, 1 },
    );
    try testing.expectEqualSlices(u8, &kat_request, &built.encode());
}

test "ARP: gratuitous + probe recognition" {
    const g = EthIpv4.gratuitous(Mac.parse("a4:5e:60:d4:2b:11").?, .{ 10, 0, 0, 7 });
    const parsed = try EthIpv4.parse(&g.encode());
    try testing.expect(parsed.isGratuitous());
    try testing.expect(!parsed.isProbe());
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 7 }, &parsed.sender_ip);

    const probe = EthIpv4.request(Mac.parse("a4:5e:60:d4:2b:11").?, .{ 0, 0, 0, 0 }, .{ 10, 0, 0, 7 });
    try testing.expect((try EthIpv4.parse(&probe.encode())).isProbe());

    // A zero sender IP alone is not enough: RFC 5227's probe is specifically
    // a *request*. A reply carrying an all-zero sender IP is malformed/
    // unusual, not a probe.
    const reply_zero_sender = EthIpv4.reply(
        Mac.parse("a4:5e:60:d4:2b:11").?,
        .{ 0, 0, 0, 0 },
        Mac.parse("00:1b:21:3c:9d:f8").?,
        .{ 10, 0, 0, 7 },
    );
    try testing.expect(!(try EthIpv4.parse(&reply_zero_sender.encode())).isProbe());
}

test "ARP: generic Packet parse + encode round-trip" {
    const p = try Packet.parse(&kat_request);
    try testing.expectEqual(htype_ethernet, p.htype);
    try testing.expectEqual(ptype_ipv4, p.ptype);
    try testing.expectEqual(Operation.request, p.oper);
    try testing.expectEqual(@as(usize, 6), p.sha.len);
    try testing.expectEqual(@as(usize, 4), p.spa.len);

    var buf: [64]u8 = undefined;
    const out = try p.encode(&buf);
    try testing.expectEqualSlices(u8, &kat_request, out);
}

test "ARP: trailing Ethernet padding is ignored" {
    const padded = kat_request ++ [_]u8{0} ** 18; // 46-byte min payload pad
    const p = try EthIpv4.parse(&padded);
    try testing.expectEqual(Operation.request, p.oper);
}

test "ARP malformed: short packets are typed errors" {
    try testing.expectError(ParseError.Truncated, Packet.parse(&.{}));
    try testing.expectError(ParseError.Truncated, Packet.parse(kat_request[0..7]));
    try testing.expectError(ParseError.TruncatedAddresses, Packet.parse(kat_request[0..27]));
    try testing.expectError(ParseError.TruncatedAddresses, EthIpv4.parse(kat_request[0..20]));

    // hlen/plen claiming more than the buffer holds.
    var evil = kat_request;
    evil[4] = 0xff;
    try testing.expectError(ParseError.TruncatedAddresses, Packet.parse(&evil));

    // Non-Ethernet htype refused by the typed parser.
    var other = kat_request;
    other[1] = 6; // IEEE 802
    try testing.expectError(ParseError.NotEthernetIpv4, EthIpv4.parse(&other));
}

test "ARP garbage sweep: no panics on random input" {
    var prng = std.Random.DefaultPrng.init(0x41525021); // "ARP!"
    const random = prng.random();
    var buf: [64]u8 = undefined;
    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        const len = random.uintAtMost(usize, buf.len);
        random.bytes(buf[0..len]);
        _ = Packet.parse(buf[0..len]) catch {};
        _ = EthIpv4.parse(buf[0..len]) catch {};
    }
}

// ── fuzz: ARP frame parse off the wire, never panics ────────────────────────
//
// `Packet.parse`/`EthIpv4.parse` run on raw Ethernet frames arriving on a
// LAN segment — no authentication of any kind at this layer. The manual
// PRNG sweep above predates the `Smith` harness convention this collection
// standardises on; this drives the same boundary through `std.testing.fuzz`.

/// ARP packets for `fuzzArpParse`, in the format `Smith.slice` reads (see
/// `testkit.fuzz`): a little-endian u32 length, then the frame.
///
/// ⭐ Hex, not built at run time: every field in an ARP packet is big-endian
/// or a raw octet string, so these bytes are the same on every host — unlike
/// the netlink families in this collection, where a hex corpus would silently
/// be a little-endian one.
const arp_seeds = [_][]const u8{
    // Request: who has 192.168.1.1, tell 192.168.1.100 (00:1b:21:3c:9d:f8).
    testkit.fuzz.seedHex("0001080006040001" ++ "001b213c9df8" ++ "c0a80164" ++ "000000000000" ++ "c0a80101"),
    // Reply: 192.168.1.1 is at a4:5e:60:d4:2b:11.
    testkit.fuzz.seedHex("0001080006040002" ++ "a45e60d42b11" ++ "c0a80101" ++ "001b213c9df8" ++ "c0a80164"),
    // Gratuitous: sender and target protocol addresses equal.
    testkit.fuzz.seedHex("0001080006040001" ++ "001b213c9df8" ++ "c0a80164" ++ "000000000000" ++ "c0a80164"),
    // Probe: sender protocol address all zero (RFC 5227).
    testkit.fuzz.seedHex("0001080006040001" ++ "001b213c9df8" ++ "00000000" ++ "000000000000" ++ "c0a801c8"),
    // The same request padded to Ethernet's 46-octet minimum payload — the
    // trailing octets must be ignored, not parsed.
    testkit.fuzz.seedHex("0001080006040001" ++ "001b213c9df8" ++ "c0a80164" ++ "000000000000" ++ "c0a80101" ++ "00" ** 18),

    // ── generic `Packet`, refused by `EthIpv4` ─────────────────────────────
    // htype 6 (IEEE 802) instead of 1.
    testkit.fuzz.seedHex("0006080006040001" ++ "001b213c9df8" ++ "c0a80164" ++ "000000000000" ++ "c0a80101"),
    // ptype 0x86dd (IPv6) instead of 0x0800.
    testkit.fuzz.seedHex("000186dd06040001" ++ "001b213c9df8" ++ "c0a80164" ++ "000000000000" ++ "c0a80101"),
    // hlen 14 / plen 8: a legal generic ARP whose address fields are 44
    // octets, so `Packet` slices four of them and `EthIpv4` says no.
    testkit.fuzz.seedHex("0001080e0e080001" ++ "aa" ** 14 ++ "bb" ** 8 ++ "cc" ** 14 ++ "dd" ** 8),

    // ── the refusals ───────────────────────────────────────────────────────
    // Nothing at all, and one octet short of the fixed header.
    testkit.fuzz.seed(""),
    testkit.fuzz.seedHex("00010800060400"),
    // The header is complete and hlen/plen are 0xff, so the four address
    // fields would need 1020 octets. `need` must be computed before the
    // slicing, not during it.
    testkit.fuzz.seedHex("00010800ffff0001" ++ "00" ** 8),
    // hlen/plen declaring exactly one octet more than the frame carries.
    testkit.fuzz.seedHex("0001080006040001" ++ "001b213c9df8" ++ "c0a80164" ++ "000000000000" ++ "c0a801"),
};

test "fuzz: ARP parse never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzArpParse, .{ .corpus = &arp_seeds });
}

fn fuzzArpParse(_: void, smith: *std.testing.Smith) !void {
    // 128, not 64: the hlen 14 / plen 8 seed is 52 octets and a generic ARP
    // packet may legally be far larger. A seed longer than the buffer is not
    // a big seed — `Smith.slice` reads it back as the EMPTY one.
    var buf: [128]u8 = undefined;
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
    // length. `bytes` takes `@min(buf.len, in.len)` octets and the ranged draw
    // then finds fewer than the eight it needs and returns the range MINIMUM,
    // so `len` was 0 for every seed and both parsers were handed an EMPTY
    // slice with the frame sitting unread in `buf`.
    //
    // ⛔ Measured 2026-09-07 over the corpus above: **0 of 12 seeds non-empty,
    // 0 packets parsed and 0 address octets sliced before; 11 of 12 non-empty
    // (one seed IS the empty frame), 8 packets, 5 of them Ethernet+IPv4, and
    // 184 address octets sliced, after.**
    const len: usize = smith.slice(&buf);
    _ = Packet.parse(buf[0..len]) catch {};
    _ = EthIpv4.parse(buf[0..len]) catch {};
}

test "corpus: every ARP seed reaches the parsers, and the sliced counts are pinned" {
    // ⭐ The measurement, executable rather than written in a comment, over the
    // SAME corpus the harness gets. `nonempty` is the reach claim and the only
    // check that catches a seed grown past the harness's buffer, which
    // `Smith.slice` reads back as the EMPTY one, silently.
    //
    // `octets` is the second number: it is the total length of the four
    // address fields `Packet.parse` sliced out, so it counts the arithmetic
    // that decides where those slices start and end — the only part of this
    // parser that can be wrong. A packet count alone would not move if
    // `hlen`/`plen` were misread.
    var nonempty: usize = 0;
    var packets: usize = 0;
    var eth: usize = 0;
    var octets: usize = 0;
    for (arp_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [128]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        if (Packet.parse(buf[0..len])) |p| {
            packets += 1;
            octets += p.sha.len + p.spa.len + p.tha.len + p.tpa.len;
        } else |_| {}
        if (EthIpv4.parse(buf[0..len])) |_| eth += 1 else |_| {}
    }
    try testing.expectEqual(arp_seeds.len - 1, nonempty); // one seed IS the empty frame
    try testing.expectEqual(@as(usize, 8), packets);
    try testing.expectEqual(@as(usize, 5), eth);
    try testing.expectEqual(@as(usize, 184), octets);
}
