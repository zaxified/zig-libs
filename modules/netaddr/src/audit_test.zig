// SPDX-License-Identifier: MIT

//! Tests added by the 2026-10-25 grade-1 audit (mutant schemata over the
//! non-test source). Each test names what a mutant of the source would have
//! changed; they pin boundaries the earlier tables and oracles never reached.

const std = @import("std");
const testing = std.testing;
const na = @import("root.zig");

const Ip = na.Ip;
const Prefix = na.Prefix;
const IpRange = na.IpRange;

fn ip(text: []const u8) Ip {
    return na.parseIp(text).?;
}

fn pfx(text: []const u8) Prefix {
    return na.parsePrefix(text).?;
}

fn rng(from: []const u8, to: []const u8) IpRange {
    return .{ .from = ip(from), .to = ip(to) };
}

const gpa = testing.allocator;

fn setOf(items: []const IpRange) !na.IpSet {
    var b: na.IpSetBuilder = .empty;
    defer b.deinit(gpa);
    for (items) |r| try b.addRange(gpa, r);
    return b.toSet(gpa);
}

test "audit: Ip predicates at the edges of their ranges" {
    // isLoopback checks all 15 leading bytes, not 14.
    try testing.expect(!ip("::101").isLoopback());
    try testing.expect(ip("::1").isLoopback());
    // isUniqueLocal is v6 only.
    try testing.expect(!ip("10.0.0.1").isUniqueLocal());
    try testing.expect(!ip("252.0.0.1").isUniqueLocal());
    // isLinkLocalMulticast v4 is 224.0.0.0/24 only: each of the three octets.
    try testing.expect(ip("224.0.0.9").isLinkLocalMulticast());
    try testing.expect(!ip("224.1.0.9").isLinkLocalMulticast());
    try testing.expect(!ip("224.0.1.9").isLinkLocalMulticast());
    try testing.expect(!ip("225.0.0.9").isLinkLocalMulticast());
    // lessThan is strict.
    try testing.expect(!Ip.lessThan({}, ip("1.2.3.4"), ip("1.2.3.4")));
    try testing.expect(Ip.lessThan({}, ip("1.2.3.4"), ip("1.2.3.5")));
}

test "audit: parsers refuse bytes next to the digit range and over-deep dotted tails" {
    // ':' is '9' + 1 and '/' is '0' - 1: neither is a digit anywhere.
    try testing.expect(na.parseIp4("1:.2.3.4") == null);
    try testing.expect(na.parseIp4("1.:.3.4") == null);
    try testing.expect(na.parseIp("1:2.3.4.5") == null);
    try testing.expect(na.parseIp("12:3.4.5.6") == null);
    try testing.expect(na.parsePrefix("10.0.0.0/:") == null);
    try testing.expect(na.parsePrefix("10.0.0.0/2:") == null);
    try testing.expect(na.parsePrefix("10.0.0.0/;") == null);
    try testing.expect(na.parseHostPort("h:8:") == null);
    // A dotted tail needs two free group positions: seven groups plus `::` has one.
    try testing.expect(na.parseIp6("1:2:3:4:5:6:7::1.2.3.4") == null);
    try testing.expect(na.parseIp6("1:2:3:4:5::1.2.3.4") != null);
    // Brackets must be on both ends of an AddrPort host.
    try testing.expect(na.parseAddrPort("a::1]:80") == null);
    try testing.expect(na.parseAddrPort("[::1:80") == null);
    try testing.expect(na.parseAddrPort("[::1]:80") != null);
    // parseHostPort ends the host at the FIRST ']'.
    try testing.expect(na.parseHostPort("[a]b]:80") == null);
    try testing.expect(na.parseHostPort("[a]:80") != null);
}

test "audit: Zone, ZonedIp, AddrPort equality and formatting of hand-built values" {
    const a = na.Zone.fromSlice("a").?;
    const b = na.Zone.fromSlice("b").?;
    try testing.expect(!a.eql(b));
    try testing.expect(a.eql(a));

    const v4: Ip = ip("1.2.3.4");
    const v6: Ip = ip("2001:db8::1");
    const x: na.AddrPort = .{ .ip = v4, .port = 80 };
    try testing.expect(!x.eql(.{ .ip = v4, .port = 81 }));
    try testing.expect(!x.eql(.{ .ip = ip("1.2.3.5"), .port = 80 }));
    try testing.expect(!(na.AddrPort{ .ip = v6, .port = 80, .zone = a }).eql(.{ .ip = v6, .port = 80, .zone = b }));
    try testing.expect(x.eql(.{ .ip = v4, .port = 80 }));

    // A hand-built v4 value with a zone prints without it.
    var buf: [na.max_zoned_ip_text_len]u8 = undefined;
    try testing.expectEqualStrings("1.2.3.4", na.formatIpZoned(.{ .ip = v4, .zone = a }, &buf));
    try testing.expectEqualStrings("2001:db8::1%a", na.formatIpZoned(.{ .ip = v6, .zone = a }, &buf));
}

test "audit: std conversion keeps ports, adds no zone, ignores a zone on v4, refuses '_'" {
    const v6 = try std.Io.net.IpAddress.parse("2001:db8::1", 443);
    try testing.expectEqual(@as(u16, 443), na.AddrPort.fromStd(v6).port);
    try testing.expect(na.AddrPort.fromStd(v6).zone.isNone());
    try testing.expectEqual(@as(u16, 443), na.Ip.toStd(ip("2001:db8::1"), 443).ip6.port);
    try testing.expectEqual(@as(u16, 8), na.Ip.toStd(ip("1.2.3.4"), 8).ip4.port);

    // A hand-built v4 value that carries a numeric zone converts as plain v4.
    const odd: na.AddrPort = .{ .ip = ip("1.2.3.4"), .port = 9, .zone = na.Zone.fromSlice("3").? };
    const back = try odd.toStd();
    try testing.expect(back == .ip4);
    try testing.expectEqual(@as(u16, 9), back.ip4.port);

    // std.fmt.parseInt skips '_': the digit test must refuse it before.
    var ap = na.parseAddrPort("[fe80::1]:53").?;
    ap.zone = na.Zone.fromSlice("1_0").?;
    try testing.expectError(error.ZoneNotNumeric, ap.toStd());
}

test "audit: Prefix operations with a hand-built length past the family width" {
    const wide: Prefix = .{ .addr = ip("192.0.2.1"), .bits = 200 };
    // range/lastAddr clamp the host mask too.
    const r = wide.range();
    try testing.expect(r.from.eql(ip("192.0.2.1")) and r.to.eql(ip("192.0.2.1")));
    try testing.expect(wide.lastAddr().eql(ip("192.0.2.1")));
    // containsPrefix: the /200 container still holds the /32 it clamps to.
    try testing.expect(wide.containsPrefix(pfx("192.0.2.1/32")));
    // supernet cannot grow past the clamped length.
    try testing.expect(wide.supernet(100) == null);
    try testing.expect(wide.supernet(32) != null);
    // compareLengthFirst clamps both sides.
    try testing.expectEqual(std.math.Order.eq, wide.compareLengthFirst(pfx("192.0.2.1/32")));
    try testing.expectEqual(std.math.Order.eq, pfx("192.0.2.1/32").compareLengthFirst(wide));
    // eql is field-wise: bits and address both count.
    try testing.expect(!pfx("10.0.0.0/8").eql(pfx("10.0.0.0/9")));
    try testing.expect(!pfx("10.0.0.0/8").eql(pfx("11.0.0.0/8")));
}

test "audit: supernet to the same length, v6 first/last host, v6 prefix of length <= 30" {
    try testing.expect(pfx("10.1.2.0/24").supernet(24).?.eql(pfx("10.1.2.0/24")));
    try testing.expect(pfx("10.1.2.0/24").supernet(23).?.eql(pfx("10.1.2.0/23")));
    // The /30 reservation is v4 only, also for v6 lengths <= 30.
    const p = pfx("2000::/16");
    try testing.expect(p.firstHost().eql(ip("2000::")));
    try testing.expect(p.lastHost().eql(ip("2000:ffff:ffff:ffff:ffff:ffff:ffff:ffff")));
    const z = pfx("::/0");
    try testing.expect(z.firstHost().eql(ip("::")));
    try testing.expect(z.lastHost().eql(ip("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")));
}

test "audit: IpRange.eql compares both ends" {
    const a = rng("10.0.0.1", "10.0.0.5");
    try testing.expect(!a.eql(rng("10.0.0.2", "10.0.0.5")));
    try testing.expect(!a.eql(rng("10.0.0.1", "10.0.0.6")));
    try testing.expect(a.eql(rng("10.0.0.1", "10.0.0.5")));
}

test "audit: mergePrefixes never joins the v4 and the v6 family" {
    // v6 numbers 0 and 2^32 touch the v4 space numerically: ::/128 lies
    // inside 0.0.0.0/8 as an integer, ::1:0:0/128 follows 255.255.255.255.
    const sets = [_][]const Prefix{
        &.{ pfx("10.0.0.0/8"), pfx("::1/128") },
        &.{ pfx("255.255.255.255/32"), pfx("::1:0:0/128") },
    };
    for (sets) |in| {
        const out = try na.mergePrefixes(gpa, in);
        defer gpa.free(out);
        try testing.expectEqual(@as(usize, 2), out.len);
        try testing.expect(out[0].addr == .v4 and out[1].addr == .v6);
    }
}

test "audit: IpSet queries are family-aware and strict about empty and invalid input" {
    var one = try setOf(&.{rng("0.0.0.1", "0.0.0.5")});
    defer one.deinit(gpa);
    try testing.expect(!one.isEmpty());
    try testing.expectEqual(@as(usize, 1), one.rangeCount());
    try testing.expect(IpSet_empty().isEmpty());

    var v6 = try setOf(&.{rng("::1", "::5")});
    defer v6.deinit(gpa);
    // The same integers in the other family: no containment, overlap or equality.
    try testing.expect(!v6.containsRange(rng("0.0.0.1", "0.0.0.2")));
    try testing.expect(!v6.overlapsRange(rng("0.0.0.1", "0.0.0.2")));
    try testing.expect(!one.overlaps(v6));
    try testing.expect(!v6.overlaps(one));
    try testing.expect(!one.eql(v6));
    try testing.expect(one.eql(one));

    // A malformed range (from > to) overlaps nothing, whatever the set holds.
    var net = try setOf(&.{rng("10.0.0.0", "10.0.0.255")});
    defer net.deinit(gpa);
    try testing.expect(!net.overlapsRange(rng("10.0.0.9", "10.0.0.1")));
    try testing.expect(!net.containsRange(rng("10.0.0.9", "10.0.0.1")));

    // eql looks at both ends of a span.
    var a = try setOf(&.{rng("10.0.0.0", "10.0.0.255")});
    defer a.deinit(gpa);
    var b = try setOf(&.{rng("10.0.0.5", "10.0.0.255")});
    defer b.deinit(gpa);
    var c = try setOf(&.{rng("10.0.0.0", "10.0.0.254")});
    defer c.deinit(gpa);
    try testing.expect(!a.eql(b));
    try testing.expect(!a.eql(c));
}

fn IpSet_empty() na.IpSet {
    return na.IpSet.empty;
}

test "audit: IpSetBuilder keeps removal order, normal flag and clone state" {
    // clone of a builder that was never normalised is normalised when read.
    {
        var b: na.IpSetBuilder = .empty;
        defer b.deinit(gpa);
        try b.addPrefix(gpa, pfx("20.0.0.0/24"));
        try b.addPrefix(gpa, pfx("10.0.0.0/24"));
        var c = try b.clone(gpa);
        defer c.deinit(gpa);
        var s = try c.toSet(gpa);
        defer s.deinit(gpa);
        try testing.expectEqual(@as(usize, 2), s.rangeCount());
        try testing.expect(s.rangeAt(0).from.eql(ip("10.0.0.0")));
    }
    // clone keeps the pending removals.
    {
        var b: na.IpSetBuilder = .empty;
        defer b.deinit(gpa);
        try b.addPrefix(gpa, pfx("10.0.0.0/24"));
        try b.removePrefix(gpa, pfx("10.0.0.0/25"));
        var c = try b.clone(gpa);
        defer c.deinit(gpa);
        var s = try c.toSet(gpa);
        defer s.deinit(gpa);
        try testing.expect(!s.contains(ip("10.0.0.1")));
        try testing.expect(s.contains(ip("10.0.0.200")));
    }
    // addSet applies earlier removals first: a removal never reaches later adds.
    {
        var other = try setOf(&.{rng("10.0.0.0", "10.0.0.255")});
        defer other.deinit(gpa);
        var b: na.IpSetBuilder = .empty;
        defer b.deinit(gpa);
        try b.addPrefix(gpa, pfx("10.0.0.0/24"));
        try b.removePrefix(gpa, pfx("10.0.0.0/24"));
        try b.addSet(gpa, other);
        var s = try b.toSet(gpa);
        defer s.deinit(gpa);
        try testing.expect(s.contains(ip("10.0.0.7")));
    }
    // addSet after a read marks the builder unsorted again.
    {
        var other = try setOf(&.{rng("10.0.0.0", "10.0.0.255")});
        defer other.deinit(gpa);
        var b: na.IpSetBuilder = .empty;
        defer b.deinit(gpa);
        try b.addPrefix(gpa, pfx("20.0.0.0/24"));
        var first = try b.toSet(gpa);
        first.deinit(gpa);
        try b.addSet(gpa, other);
        var s = try b.toSet(gpa);
        defer s.deinit(gpa);
        try testing.expect(s.rangeAt(0).from.eql(ip("10.0.0.0")));
        try testing.expect(s.contains(ip("10.0.0.9")) and s.contains(ip("20.0.0.9")));
    }
    // addSet of an empty set on a fresh builder (an empty list is normalised).
    {
        var b: na.IpSetBuilder = .empty;
        defer b.deinit(gpa);
        try b.addSet(gpa, na.IpSet.empty);
        var s = try b.toSet(gpa);
        defer s.deinit(gpa);
        try testing.expect(s.isEmpty());
    }
    // intersect pairs spans of one family only.
    {
        var v4 = try setOf(&.{rng("0.0.0.1", "0.0.0.5")});
        defer v4.deinit(gpa);
        var v6 = try setOf(&.{rng("::2", "::3")});
        defer v6.deinit(gpa);
        var b: na.IpSetBuilder = .empty;
        defer b.deinit(gpa);
        try b.addSet(gpa, v4);
        try b.intersect(gpa, v6);
        var s = try b.toSet(gpa);
        defer s.deinit(gpa);
        try testing.expect(s.isEmpty());
    }
}

fn countingSource(_: Ip) ?Ip {
    probes += 1;
    return null;
}
var probes: usize = 0;

test "audit: RFC 6724 corners - unusable pairs, policy row edges, selection ties" {
    // Two unusable destinations still go through rules 2..9 with an all-zero
    // pseudo source: scope 0 (an unnamed multicast scope) and label 0 (::1) match it.
    {
        var d = [_]Ip{ ip("::1"), ip("ff00::1") };
        var s = [_]?Ip{ null, null };
        try na.sortDestinationsWithSources(&d, &s);
        try testing.expect(d[0].eql(ip("ff00::1")));
    }
    {
        var d = [_]Ip{ ip("2001:db8::1"), ip("::1") };
        var s = [_]?Ip{ null, null };
        try na.sortDestinationsWithSources(&d, &s);
        try testing.expect(d[0].eql(ip("::1")));
    }
    // sortDestinations probes nothing for fewer than two candidates.
    {
        probes = 0;
        var one = [_]Ip{ip("::1")};
        try na.sortDestinations(&one, &countingSource);
        try testing.expectEqual(@as(usize, 0), probes);
        var two = [_]Ip{ ip("::1"), ip("::2") };
        try na.sortDestinations(&two, &countingSource);
        try testing.expectEqual(@as(usize, 2), probes);
    }
    // One address just outside each policy row that a longer prefix would swallow.
    const Row = struct { text: []const u8, prec: u8, label: u8 };
    const rows = [_]Row{
        .{ .text = "2003::1", .prec = 40, .label = 1 }, // 2002::/16 is not /15
        .{ .text = "2002:ffff::1", .prec = 30, .label = 2 },
        .{ .text = "fee0::1", .prec = 1, .label = 11 }, // fec0::/10 reaches feff
        .{ .text = "3ffe:8000::1", .prec = 1, .label = 12 }, // 3ffe::/16 is not /17
        .{ .text = "2001:1::1", .prec = 40, .label = 1 }, // Teredo is 2001::/32
        .{ .text = "2001::1", .prec = 5, .label = 5 },
        .{ .text = "::fffe:0:1", .prec = 40, .label = 1 }, // ::ffff:0:0/96 is not /95
        .{ .text = "::", .prec = 1, .label = 3 }, // ::1/128 is not /127
        .{ .text = "::1", .prec = 50, .label = 0 },
        .{ .text = "fc00::1", .prec = 3, .label = 13 },
        .{ .text = "fe00::1", .prec = 40, .label = 1 }, // fc00::/7 ends at fdff
    };
    for (rows) |r| {
        const p = na.policyOf(ip(r.text));
        errdefer std.debug.print("  row {s}\n", .{r.text});
        try testing.expectEqual(r.prec, p.precedence);
        try testing.expectEqual(r.label, p.label);
    }
    // Scope of fe80-febf is link-local, of fec0-feff site-local, of ::ffff:mapped global.
    try testing.expectEqual(na.Scope.site_local, na.scopeOf(ip("feff::1")));
    try testing.expectEqual(na.Scope.link_local, na.scopeOf(ip("febf::1")));

    // selectSource works on the family the destination ends up in once unmapped.
    {
        const cands = [_]Ip{ ip("2001:db8::5"), ip("192.0.2.9") };
        try testing.expectEqual(@as(?usize, 1), na.selectSource(&cands, ip("::ffff:192.0.2.1")));
        const mapped = [_]Ip{ip("::ffff:192.0.2.9")};
        try testing.expectEqual(@as(?usize, 0), na.selectSource(&mapped, ip("192.0.2.1")));
    }
    // Equal candidates: the first one wins.
    {
        const cands = [_]Ip{ ip("2001:db9::1"), ip("2001:db9::2") };
        try testing.expectEqual(@as(?usize, 0), na.selectSource(&cands, ip("2001:db8::1")));
    }
}

// ── no-panic sweep 2026-10-28 ───────────────────────────────────────────────

/// Three 64-address regions the builder model covers: low v4, the top of v4
/// and the top of v6 (where `to + 1` would overflow).
const sweep_regions = [_]struct { fam: std.meta.Tag(Ip), base: u128 }{
    .{ .fam = .v4, .base = 0x0A00_0000 },
    .{ .fam = .v4, .base = std.math.maxInt(u32) - 63 },
    .{ .fam = .v6, .base = std.math.maxInt(u128) - 63 },
};

fn sweepIp(region: usize, off: u128) Ip {
    const r = sweep_regions[region];
    const v = r.base + off;
    return switch (r.fam) {
        .v4 => blk: {
            var b: [4]u8 = undefined;
            std.mem.writeInt(u32, &b, @intCast(v), .big);
            break :blk .{ .v4 = b };
        },
        .v6 => blk: {
            var b: [16]u8 = undefined;
            std.mem.writeInt(u128, &b, v, .big);
            break :blk .{ .v6 = b };
        },
    };
}

test "no-panic sweep N-4: any interleaving of adds and removes matches a per-address model" {
    for (0..300) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        const rand = prng.random();
        var model: [3]u64 = @splat(0);
        var b: na.IpSetBuilder = .empty;
        defer b.deinit(gpa);
        const n_ops = rand.uintLessThan(usize, 48);
        for (0..n_ops) |_| {
            const region = rand.uintLessThan(usize, 3);
            const lo = rand.uintLessThan(u7, 64);
            const hi = lo + rand.uintLessThan(u7, 64 - lo);
            const mask: u64 = (if (hi == 63) ~@as(u64, 0) else (@as(u64, 1) << @intCast(hi + 1)) - 1) &
                ~((@as(u64, 1) << @intCast(lo)) - 1);
            const add = rand.boolean();
            const r: IpRange = .{ .from = sweepIp(region, lo), .to = sweepIp(region, hi) };
            var effect = mask;
            switch (rand.uintLessThan(u8, 4)) {
                0 => if (add) try b.addRange(gpa, r) else try b.removeRange(gpa, r),
                1 => {
                    effect = @as(u64, 1) << @intCast(lo);
                    if (add) try b.add(gpa, r.from) else try b.remove(gpa, r.from);
                },
                2 => {
                    var s = try setOf(&.{r});
                    defer s.deinit(gpa);
                    if (add) try b.addSet(gpa, s) else try b.removeSet(gpa, s);
                },
                else => {
                    // A mid-way read resolves everything pending so far.
                    var s = try b.toSet(gpa);
                    s.deinit(gpa);
                    continue;
                },
            }
            if (add) model[region] |= effect else model[region] &= ~effect;
        }
        var s = try b.toSet(gpa);
        defer s.deinit(gpa);
        for (0..3) |region| for (0..64) |off| {
            const want = model[region] >> @intCast(off) & 1 == 1;
            try testing.expectEqual(want, s.contains(sweepIp(region, off)));
        };
        // Normalised: sorted, disjoint, never adjacent within a family.
        var i: usize = 1;
        while (i < s.rangeCount()) : (i += 1) {
            const prev = s.rangeAt(i - 1);
            const cur = s.rangeAt(i);
            if (std.meta.activeTag(prev.to) != std.meta.activeTag(cur.from)) continue;
            const next_after_prev = prev.to.next() orelse return error.TestUnexpectedResult;
            try testing.expect(next_after_prev.compare(cur.from) == .lt);
        }
    }
}

fn tenNet(i: usize) Ip {
    return .{ .v4 = .{ 10, 0, 0, @intCast(i) } };
}

test "no-panic sweep N-1: a hand-set Zone.len past max_zone_len reads as the whole buffer" {
    var z: na.Zone = .{ .len = 200 };
    @memset(&z.buf, 'z');
    try testing.expectEqual(@as(usize, na.max_zone_len), z.slice().len);
    z.len = na.max_zone_len;
    try testing.expectEqual(@as(usize, na.max_zone_len), z.slice().len);
}

test "no-panic sweep N-3: a hand-built AddrIterator with cur past last ends after one address" {
    var it: na.AddrIterator = .{ .family = .v4, .cur = 10, .last = 5 };
    try testing.expect(it.next() != null);
    try testing.expectEqual(@as(?Ip, null), it.next());
    // At the top of the width a `cur` equal to `last` ends too, without overflowing.
    var top: na.AddrIterator = .{ .family = .v6, .cur = std.math.maxInt(u128), .last = std.math.maxInt(u128) };
    try testing.expect(top.next() != null);
    try testing.expectEqual(@as(?Ip, null), top.next());
}

test "no-panic sweep N-4: clone in logging mode carries the pending log" {
    var b: na.IpSetBuilder = .empty;
    defer b.deinit(gpa);
    try b.addRange(gpa, rng("10.0.0.0", "10.0.0.9"));
    try b.removeRange(gpa, rng("10.0.0.2", "10.0.0.5"));
    try b.addRange(gpa, rng("10.0.0.3", "10.0.0.3")); // logged
    try b.removeRange(gpa, rng("10.0.0.8", "10.0.0.9")); // logged
    var c = try b.clone(gpa);
    defer c.deinit(gpa);
    var sb = try b.toSet(gpa);
    defer sb.deinit(gpa);
    var sc = try c.toSet(gpa);
    defer sc.deinit(gpa);
    const want = [_]bool{ true, true, false, true, false, false, true, true, false, false };
    for (want, 0..) |w, i| {
        const a = tenNet(i);
        try testing.expectEqual(w, sb.contains(a));
        try testing.expectEqual(w, sc.contains(a));
    }
}

test "no-panic sweep N-4: a flush that fails inside the log sweep leaves the log in force" {
    // After the OOM the removals are applied and cleared but the log is not:
    // an add made now still has to go behind the logged removals.
    var j: usize = 0;
    var failed_any = false;
    while (j < 40) : (j += 1) {
        var b: na.IpSetBuilder = .empty;
        defer b.deinit(gpa);
        try b.addRange(gpa, rng("10.0.0.0", "10.0.0.9"));
        try b.removeRange(gpa, rng("10.0.0.2", "10.0.0.3"));
        try b.addRange(gpa, rng("10.0.0.2", "10.0.0.2")); // logged
        try b.removeRange(gpa, rng("10.0.0.5", "10.0.0.6")); // logged
        var fa = testing.FailingAllocator.init(gpa, .{ .fail_index = j });
        var finished = false;
        if (b.toSet(fa.allocator())) |first| {
            var s = first;
            s.deinit(fa.allocator());
            finished = true;
        } else |err| {
            try testing.expectEqual(error.OutOfMemory, err);
            failed_any = true;
        }
        if (finished) break;
        try b.add(gpa, ip("10.0.0.5"));
        var s = try b.toSet(gpa);
        defer s.deinit(gpa);
        // 0-9, minus 2-3, plus 2, minus 5-6, plus 5.
        const want = [_]bool{ true, true, true, false, true, true, false, true, true, true, false };
        for (want, 0..) |w, i| {
            errdefer std.debug.print("  fail_index {d}, offset {d}\n", .{ j, i });
            try testing.expectEqual(w, s.contains(tenNet(i)));
        }
    }
    try testing.expect(failed_any);
}

test "no-panic sweep N-4: the log sweep keeps families apart where one ends at the other's start position" {
    // v4 255.255.255.255 ends at position 2^32, exactly where the v6 span
    // ::1:0:0 starts: neither the event grouping nor the adjacent merge may
    // cross the family border.
    var b: na.IpSetBuilder = .empty;
    defer b.deinit(gpa);
    try b.addRange(gpa, rng("255.255.255.254", "255.255.255.255"));
    try b.addRange(gpa, rng("::1:0:0", "::1:0:3"));
    try b.removeRange(gpa, rng("255.255.255.254", "255.255.255.254"));
    try b.addRange(gpa, rng("::1:0:2", "::1:0:9")); // logged
    var s = try b.toSet(gpa);
    defer s.deinit(gpa);
    try testing.expectEqual(@as(usize, 2), s.rangeCount());
    const r0 = s.rangeAt(0);
    try testing.expect(r0.from.eql(ip("255.255.255.255")) and r0.to.eql(ip("255.255.255.255")));
    const r1 = s.rangeAt(1);
    try testing.expect(r1.from.eql(ip("::1:0:0")) and r1.to.eql(ip("::1:0:9")));
    try testing.expect(!s.contains(ip("255.255.255.254")));
    try testing.expect(!s.contains(ip("::ffff:ffff"))); // the address before ::1:0:0
}
