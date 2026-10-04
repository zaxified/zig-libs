// SPDX-License-Identifier: MIT
//! IPv6 Neighbor Discovery (RFC 4861) — the IPv6 counterpart of `arp`: router
//! solicitation/advertisement, neighbor solicitation/advertisement and
//! redirect messages, their options, the ICMPv6 checksum (RFC 4443 §2.3), and
//! builders for the two messages a scanner sends (NS, RS). Allocation-free;
//! every slice points into the parsed buffer.
//!
//! Input is the ICMPv6 message (type, code, checksum, body) — what follows the
//! IPv6 header. Like the rest of this module it is a codec: it does not check
//! the hop limit of 255 RFC 4861 §7.1.1 requires of a received ND message
//! (that is in the IPv6 header) and does not verify the checksum on parse
//! (`checksum` does, given the addresses).
//!
//! Anchored against tcpdump 4.99.6: the four messages in the tests were built
//! for this module and decoded by `tcpdump -vvv` ("icmp6 sum ok" on each);
//! every expected value is what tcpdump printed.

const std = @import("std");
const Mac = @import("mac.zig").Mac;

pub const ParseError = error{
    /// Shorter than the fixed part of its message type.
    Truncated,
    /// Not an ND message type (133-137), or a non-zero code.
    NotNeighborDiscovery,
    /// An option with length 0 or running past the message (RFC 4861 §4.6:
    /// "nodes MUST silently discard an ND packet that contains an option with
    /// length zero").
    BadOption,
};

pub const BuildError = error{BufferTooSmall};

pub const Type = enum(u8) {
    router_solicitation = 133,
    router_advertisement = 134,
    neighbor_solicitation = 135,
    neighbor_advertisement = 136,
    redirect = 137,
};

pub const OptionType = struct {
    pub const source_link_addr: u8 = 1;
    pub const target_link_addr: u8 = 2;
    pub const prefix_info: u8 = 3;
    pub const redirected_header: u8 = 4;
    pub const mtu: u8 = 5;
    /// RFC 8106 Recursive DNS Server.
    pub const rdnss: u8 = 25;
};

pub const RouterAdvertisement = struct {
    cur_hop_limit: u8,
    /// M: addresses via DHCPv6.
    managed: bool,
    /// O: other configuration via DHCPv6.
    other: bool,
    /// Default router preference (RFC 4191): 0 medium, 1 high, 3 low.
    preference: u2,
    router_lifetime_s: u16,
    reachable_ms: u32,
    retrans_ms: u32,
};

pub const NeighborAdvertisement = struct {
    router: bool,
    solicited: bool,
    override: bool,
    target: [16]u8,
};

pub const Body = union(Type) {
    router_solicitation,
    router_advertisement: RouterAdvertisement,
    neighbor_solicitation: struct { target: [16]u8 },
    neighbor_advertisement: NeighborAdvertisement,
    redirect: struct { target: [16]u8, destination: [16]u8 },
};

pub const Message = struct {
    body: Body,
    /// The checksum as received (verify it with `checksum`).
    checksum: u16,
    /// The options area, for re-iteration.
    options_raw: []const u8,

    pub fn parse(icmp: []const u8) ParseError!Message {
        if (icmp.len < 4) return ParseError.Truncated;
        if (icmp[1] != 0) return ParseError.NotNeighborDiscovery;
        if (icmp[0] < 133 or icmp[0] > 137) return ParseError.NotNeighborDiscovery;
        const t: Type = @enumFromInt(icmp[0]);
        const fixed: usize = switch (t) {
            .router_solicitation => 8,
            .router_advertisement => 16,
            .neighbor_solicitation, .neighbor_advertisement => 24,
            .redirect => 40,
        };
        if (icmp.len < fixed) return ParseError.Truncated;
        const body: Body = switch (t) {
            .router_solicitation => .router_solicitation,
            .router_advertisement => .{ .router_advertisement = .{
                .cur_hop_limit = icmp[4],
                .managed = icmp[5] & 0x80 != 0,
                .other = icmp[5] & 0x40 != 0,
                .preference = @intCast((icmp[5] >> 3) & 0x3),
                .router_lifetime_s = std.mem.readInt(u16, icmp[6..8], .big),
                .reachable_ms = std.mem.readInt(u32, icmp[8..12], .big),
                .retrans_ms = std.mem.readInt(u32, icmp[12..16], .big),
            } },
            .neighbor_solicitation => .{ .neighbor_solicitation = .{ .target = icmp[8..24].* } },
            .neighbor_advertisement => .{ .neighbor_advertisement = .{
                .router = icmp[4] & 0x80 != 0,
                .solicited = icmp[4] & 0x40 != 0,
                .override = icmp[4] & 0x20 != 0,
                .target = icmp[8..24].*,
            } },
            .redirect => .{ .redirect = .{ .target = icmp[8..24].*, .destination = icmp[24..40].* } },
        };
        const m: Message = .{
            .body = body,
            .checksum = std.mem.readInt(u16, icmp[2..4], .big),
            .options_raw = icmp[fixed..],
        };
        // Validate the option framing once, so the accessors cannot fail.
        var it = m.options();
        while (try it.next()) |_| {}
        return m;
    }

    pub fn options(m: *const Message) OptionIterator {
        return .{ .buf = m.options_raw };
    }

    /// The Source (`which = source_link_addr`) or Target Link-Layer Address
    /// option, as a MAC when it is 6 bytes (Ethernet).
    pub fn linkAddr(m: *const Message, which: u8) ?Mac {
        var it = m.options();
        while (it.next() catch null) |o| {
            if (o.type == which and o.data.len >= 6) return .{ .octets = o.data[0..6].* };
        }
        return null;
    }

    pub fn mtu(m: *const Message) ?u32 {
        var it = m.options();
        while (it.next() catch null) |o| {
            if (o.type == OptionType.mtu and o.data.len >= 6) return std.mem.readInt(u32, o.data[2..6], .big);
        }
        return null;
    }
};

pub const RawOption = struct {
    type: u8,
    /// The option body after its 2-byte header (length × 8 − 2 bytes).
    data: []const u8,
};

pub const OptionIterator = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn next(it: *OptionIterator) ParseError!?RawOption {
        if (it.pos == it.buf.len) return null;
        if (it.buf.len - it.pos < 2) return ParseError.BadOption;
        const units: usize = it.buf[it.pos + 1];
        if (units == 0 or it.buf.len - it.pos < units * 8) return ParseError.BadOption;
        const o: RawOption = .{ .type = it.buf[it.pos], .data = it.buf[it.pos + 2 .. it.pos + units * 8] };
        it.pos += units * 8;
        return o;
    }
};

/// Prefix Information option (type 3, RFC 4861 §4.6.2).
pub const PrefixInfo = struct {
    prefix_len: u8,
    on_link: bool,
    autonomous: bool,
    valid_s: u32,
    preferred_s: u32,
    prefix: [16]u8,

    /// `o` must be a type-3 option; null when it is too short.
    pub fn parse(o: RawOption) ?PrefixInfo {
        if (o.type != OptionType.prefix_info or o.data.len < 30) return null;
        return .{
            .prefix_len = o.data[0],
            .on_link = o.data[1] & 0x80 != 0,
            .autonomous = o.data[1] & 0x40 != 0,
            .valid_s = std.mem.readInt(u32, o.data[2..6], .big),
            .preferred_s = std.mem.readInt(u32, o.data[6..10], .big),
            .prefix = o.data[14..30].*,
        };
    }
};

/// Recursive DNS Server option (type 25, RFC 8106 §5.1): a lifetime and one
/// or more 16-byte addresses.
pub const Rdnss = struct {
    lifetime_s: u32,
    addrs: []const u8,

    pub fn parse(o: RawOption) ?Rdnss {
        if (o.type != OptionType.rdnss or o.data.len < 6 + 16) return null;
        const n = (o.data.len - 6) / 16;
        return .{ .lifetime_s = std.mem.readInt(u32, o.data[2..6], .big), .addrs = o.data[6..][0 .. n * 16] };
    }

    pub fn count(r: Rdnss) usize {
        return r.addrs.len / 16;
    }

    pub fn at(r: Rdnss, i: usize) [16]u8 {
        return r.addrs[i * 16 ..][0..16].*;
    }
};

/// The ICMPv6 checksum over the IPv6 pseudo-header (RFC 8200 §8.1) and
/// `icmp` as given. To fill in a message, zero its checksum field, compute,
/// and store the result; to verify a received one, compute over it as is —
/// the result is 0 when it is intact.
pub fn checksum(src: [16]u8, dst: [16]u8, icmp: []const u8) u16 {
    var sum: u64 = 0;
    for ([_][]const u8{ &src, &dst }) |a| sum += sumWords(a);
    sum += @as(u64, @intCast(icmp.len >> 16)) + (icmp.len & 0xffff); // upper-layer length (32-bit)
    sum += 58; // next header = ICMPv6
    sum += sumWords(icmp);
    while (sum >> 16 != 0) sum = (sum & 0xffff) + (sum >> 16);
    return ~@as(u16, @intCast(sum));
}

fn sumWords(b: []const u8) u64 {
    var s: u64 = 0;
    var i: usize = 0;
    while (i + 1 < b.len) : (i += 2) s += std.mem.readInt(u16, b[i..][0..2], .big);
    if (i < b.len) s += @as(u64, b[i]) << 8;
    return s;
}

/// The solicited-node multicast address of `target` (RFC 4291 §2.7.1):
/// ff02::1:ffXX:XXXX from its low 24 bits — where an NS for it is sent.
pub fn solicitedNode(target: [16]u8) [16]u8 {
    var a: [16]u8 = .{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0, 0, 0 };
    a[13..16].* = target[13..16].*;
    return a;
}

/// The Ethernet multicast MAC an IPv6 multicast address maps to
/// (RFC 2464 §7): 33:33 + its low 32 bits.
pub fn multicastMac(group: [16]u8) Mac {
    return .{ .octets = .{ 0x33, 0x33, group[12], group[13], group[14], group[15] } };
}

/// A Neighbor Solicitation for `target` from `src` (with a Source Link-Layer
/// Address option, as RFC 4861 §4.3 requires unless `src` is unspecified),
/// checksummed for `dst` — normally `solicitedNode(target)`. 32 bytes.
pub fn buildNeighborSolicitation(out: []u8, src: [16]u8, dst: [16]u8, target: [16]u8, src_mac: Mac) BuildError![]const u8 {
    if (out.len < 32) return BuildError.BufferTooSmall;
    @memset(out[0..8], 0);
    out[0] = @intFromEnum(Type.neighbor_solicitation);
    out[8..24].* = target;
    out[24] = OptionType.source_link_addr;
    out[25] = 1;
    out[26..32].* = src_mac.octets;
    std.mem.writeInt(u16, out[2..4], checksum(src, dst, out[0..32]), .big);
    return out[0..32];
}

/// A Router Solicitation with a Source Link-Layer Address option, for
/// ff02::2 (all routers). 16 bytes.
pub fn buildRouterSolicitation(out: []u8, src: [16]u8, dst: [16]u8, src_mac: Mac) BuildError![]const u8 {
    if (out.len < 16) return BuildError.BufferTooSmall;
    @memset(out[0..8], 0);
    out[0] = @intFromEnum(Type.router_solicitation);
    out[8] = OptionType.source_link_addr;
    out[9] = 1;
    out[10..16].* = src_mac.octets;
    std.mem.writeInt(u16, out[2..4], checksum(src, dst, out[0..16]), .big);
    return out[0..16];
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    @setEvalBranchQuota(10000);
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

const ll1 = hex("fe800000000000000211223344556677"); // fe80::211:2233:4455:6677
const ll2 = hex("fe80000000000000020000fffe000001"); // fe80::200:ff:fe00:1
const all_nodes = hex("ff020000000000000000000000000001");
const all_routers = hex("ff020000000000000000000000000002");
const target5 = hex("20010db8000000000000000000000005"); // 2001:db8::5
const mac1: Mac = .{ .octets = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 } };
const mac2: Mac = .{ .octets = .{ 0x02, 0, 0, 0, 0, 1 } };

const ns_msg = hex("870017b10000000020010db80000000000000000000000050101001122334455");
const na_msg = hex("880098d0e000000020010db80000000000000000000000050201020000000001");
const ra_msg = hex("8600678040c0070800007530000003e8010102000000000105010000000005dc030440c000015180000038400000000020010db8000100000000000000000000190300000000025820010db8000000000000000000000053");
const rs_msg = hex("85004684000000000101001122334455");

test "NS/NA/RA/RS decode to what tcpdump printed, and their checksums verify" {
    // fe80::211:2233:4455:6677 > ff02::1:ff00:5: "[icmp6 sum ok] neighbor
    // solicitation, who has 2001:db8::5", "source link-address option (1):
    // 00:11:22:33:44:55"
    const ns = try Message.parse(&ns_msg);
    try testing.expectEqualSlices(u8, &target5, &ns.body.neighbor_solicitation.target);
    try testing.expectEqual(mac1, ns.linkAddr(OptionType.source_link_addr).?);
    try testing.expectEqual(@as(u16, 0), checksum(ll1, solicitedNode(target5), &ns_msg));
    // "neighbor advertisement, tgt is 2001:db8::5, Flags [router, solicited,
    // override]", "destination link-address option (2): 02:00:00:00:00:01"
    const na = try Message.parse(&na_msg);
    const a = na.body.neighbor_advertisement;
    try testing.expect(a.router and a.solicited and a.override);
    try testing.expectEqualSlices(u8, &target5, &a.target);
    try testing.expectEqual(mac2, na.linkAddr(OptionType.target_link_addr).?);
    try testing.expectEqual(@as(u16, 0), checksum(ll2, ll1, &na_msg));
    // "hop limit 64, Flags [managed, other stateful], pref medium, router
    // lifetime 1800s, reachable time 30000ms, retrans timer 1000ms",
    // "mtu option (5): 1500", "prefix info option (3): 2001:db8:1::/64,
    // Flags [onlink, auto], valid time 86400s, pref. time 14400s",
    // "rdnss option (25): lifetime 600s, addr: 2001:db8::53"
    const ra = try Message.parse(&ra_msg);
    const r = ra.body.router_advertisement;
    try testing.expectEqual(@as(u8, 64), r.cur_hop_limit);
    try testing.expect(r.managed and r.other);
    try testing.expectEqual(@as(u2, 0), r.preference);
    try testing.expectEqual(@as(u16, 1800), r.router_lifetime_s);
    try testing.expectEqual(@as(u32, 30000), r.reachable_ms);
    try testing.expectEqual(@as(u32, 1000), r.retrans_ms);
    try testing.expectEqual(mac2, ra.linkAddr(OptionType.source_link_addr).?);
    try testing.expectEqual(@as(?u32, 1500), ra.mtu());
    var it = ra.options();
    var saw_prefix = false;
    var saw_dns = false;
    while (try it.next()) |o| {
        if (PrefixInfo.parse(o)) |p| {
            try testing.expectEqual(@as(u8, 64), p.prefix_len);
            try testing.expect(p.on_link and p.autonomous);
            try testing.expectEqual(@as(u32, 86400), p.valid_s);
            try testing.expectEqual(@as(u32, 14400), p.preferred_s);
            try testing.expectEqualSlices(u8, &hex("20010db8000100000000000000000000"), &p.prefix);
            saw_prefix = true;
        }
        if (Rdnss.parse(o)) |d| {
            try testing.expectEqual(@as(u32, 600), d.lifetime_s);
            try testing.expectEqual(@as(usize, 1), d.count());
            try testing.expectEqualSlices(u8, &hex("20010db8000000000000000000000053"), &d.at(0));
            saw_dns = true;
        }
    }
    try testing.expect(saw_prefix and saw_dns);
    try testing.expectEqual(@as(u16, 0), checksum(ll2, all_nodes, &ra_msg));
    // "router solicitation", "source link-address option (1): 00:11:22:33:44:55"
    const rs = try Message.parse(&rs_msg);
    try testing.expect(rs.body == .router_solicitation);
    try testing.expectEqual(mac1, rs.linkAddr(OptionType.source_link_addr).?);
    try testing.expectEqual(@as(u16, 0), checksum(ll1, all_routers, &rs_msg));
    // One flipped bit anywhere breaks the checksum.
    var bad = ns_msg;
    bad[20] ^= 1;
    try testing.expect(checksum(ll1, solicitedNode(target5), &bad) != 0);
}

test "builders reproduce the tcpdump-verified NS and RS byte for byte" {
    var buf: [32]u8 = undefined;
    try testing.expectEqualSlices(u8, &ns_msg, try buildNeighborSolicitation(&buf, ll1, solicitedNode(target5), target5, mac1));
    try testing.expectEqualSlices(u8, &rs_msg, try buildRouterSolicitation(&buf, ll1, all_routers, mac1));
    try testing.expectError(error.BufferTooSmall, buildNeighborSolicitation(buf[0..31], ll1, ll1, target5, mac1));
    try testing.expectError(error.BufferTooSmall, buildRouterSolicitation(buf[0..15], ll1, ll1, mac1));
}

test "solicited-node address and its multicast MAC" {
    // RFC 4291 §2.7.1: ff02:0:0:0:0:1:ff00::/104 + the low 24 bits; tcpdump
    // printed the NS above as going to ff02::1:ff00:5. RFC 2464 §7: 33:33 +
    // the low 32 bits.
    try testing.expectEqualSlices(u8, &hex("ff0200000000000000000001ff000005"), &solicitedNode(target5));
    try testing.expectEqual(Mac{ .octets = .{ 0x33, 0x33, 0xff, 0, 0, 5 } }, multicastMac(solicitedNode(target5)));
}

test "malformed ND messages are refused" {
    try testing.expectError(error.Truncated, Message.parse(&.{ 135, 0, 0 }));
    try testing.expectError(error.Truncated, Message.parse(ns_msg[0..23]));
    try testing.expectError(error.NotNeighborDiscovery, Message.parse(&.{ 128, 0, 0, 0, 0, 0, 0, 0 })); // echo request
    try testing.expectError(error.NotNeighborDiscovery, Message.parse(&.{ 133, 1, 0, 0, 0, 0, 0, 0 })); // code 1
    // An option of length 0 (RFC 4861 §4.6: discard) and one past the end.
    var zero = rs_msg;
    zero[9] = 0;
    try testing.expectError(error.BadOption, Message.parse(&zero));
    var long = rs_msg;
    long[9] = 2;
    try testing.expectError(error.BadOption, Message.parse(&long));
    try testing.expectError(error.BadOption, Message.parse(rs_msg[0..9]));
    // RFC 4191 §2.2: Prf is bits 4-3 of the RA flags byte; 0b01 = high.
    var high = ra_msg;
    high[5] = 0xc8;
    try testing.expectEqual(@as(u2, 1), (try Message.parse(&high)).body.router_advertisement.preference);
    high[5] = 0x18; // 0b11 = low, and neither M nor O
    const low = (try Message.parse(&high)).body.router_advertisement;
    try testing.expectEqual(@as(u2, 3), low.preference);
    try testing.expect(!low.managed and !low.other);
    // A redirect: target + destination, no options.
    var redirect: [40]u8 = @splat(0);
    redirect[0] = 137;
    redirect[8] = 0xfe;
    redirect[24] = 0x20;
    const m = try Message.parse(&redirect);
    try testing.expectEqual(@as(u8, 0xfe), m.body.redirect.target[0]);
    try testing.expectEqual(@as(u8, 0x20), m.body.redirect.destination[0]);
    try testing.expect(m.linkAddr(OptionType.target_link_addr) == null);
    try testing.expect(m.mtu() == null);
    // Short prefix / RDNSS options are not decoded.
    try testing.expect(PrefixInfo.parse(.{ .type = 3, .data = &([_]u8{0} ** 29) }) == null);
    try testing.expect(Rdnss.parse(.{ .type = 25, .data = &([_]u8{0} ** 21) }) == null);
    try testing.expect(Rdnss.parse(.{ .type = 3, .data = &([_]u8{0} ** 22) }) == null);
}

test "checksum: odd-length input pads the last byte, as RFC 1071 sums" {
    const zero16: [16]u8 = @splat(0);
    // Pseudo-header for ::→:: with length 1 and next header 58, plus the
    // single byte 0x01 padded to 0x0100: 1 + 58 + 0x0100 = 0x013b → ~ = 0xfec4.
    try testing.expectEqual(@as(u16, 0xfec4), checksum(zero16, zero16, &.{0x01}));
}
