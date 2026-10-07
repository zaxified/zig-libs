// SPDX-License-Identifier: MIT

//! Unit tests for the Go `netip` / netipx parity surface: ordering,
//! next/prev, the remaining classification predicates, zones, `AddrPort`,
//! `IpRange` and `IpSet`. Behaviour is pinned against Go by the replay in
//! `netip_oracle_test.zig`; these tests carry the edges by name and the
//! set algebra against a brute-force model.

const std = @import("std");
const testing = std.testing;
const na = @import("root.zig");

fn ip(text: []const u8) na.Ip {
    return na.parseIp(text).?;
}

fn pfx(text: []const u8) na.Prefix {
    return na.parsePrefix(text).?;
}

test "Ip.compare: v4 before v6, then numeric; lessThan sorts" {
    try testing.expectEqual(std.math.Order.lt, ip("255.255.255.255").compare(ip("::")));
    try testing.expectEqual(std.math.Order.gt, ip("::ffff:1.2.3.4").compare(ip("1.2.3.4")));
    try testing.expectEqual(std.math.Order.lt, ip("1.2.3.4").compare(ip("1.2.3.5")));
    try testing.expectEqual(std.math.Order.eq, ip("2001:db8::1").compare(ip("2001:db8::1")));
    try testing.expectEqual(std.math.Order.lt, ip("2001:db8::1").compare(ip("2001:db8::1:0")));

    var list = [_]na.Ip{ ip("::1"), ip("10.0.0.2"), ip("::"), ip("10.0.0.1") };
    std.sort.pdq(na.Ip, &list, {}, na.Ip.lessThan);
    try testing.expect(list[0].eql(ip("10.0.0.1")));
    try testing.expect(list[1].eql(ip("10.0.0.2")));
    try testing.expect(list[2].eql(ip("::")));
    try testing.expect(list[3].eql(ip("::1")));
}

test "Ip.next/prev stay in the family and stop at its ends" {
    try testing.expect(ip("1.2.3.255").next().?.eql(ip("1.2.4.0")));
    try testing.expect(ip("1.2.4.0").prev().?.eql(ip("1.2.3.255")));
    try testing.expect(ip("255.255.255.255").next() == null);
    try testing.expect(ip("0.0.0.0").prev() == null);
    try testing.expect(ip("::").prev() == null);
    try testing.expect(ip("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").next() == null);
    // No family crossing: the mapped block's end is followed by plain v6.
    try testing.expect(ip("::ffff:255.255.255.255").next().?.eql(ip("::1:0:0:0")));
    try testing.expect(ip("::1:0:0:0").prev().?.eql(ip("::ffff:255.255.255.255")));
}

test "isGlobalUnicast / isLinkLocalMulticast / isInterfaceLocalMulticast" {
    const Row = struct { []const u8, bool, bool, bool };
    const rows = [_]Row{
        .{ "8.8.8.8", true, false, false },
        .{ "10.0.0.1", true, false, false }, // private still counts
        .{ "fc00::1", true, false, false },
        .{ "::ffff:1.2.3.4", true, false, false },
        .{ "255.255.255.255", false, false, false },
        .{ "::ffff:255.255.255.255", false, false, false },
        .{ "0.0.0.0", false, false, false },
        .{ "::", false, false, false },
        .{ "127.0.0.1", false, false, false },
        .{ "::1", false, false, false },
        .{ "169.254.1.1", false, false, false },
        .{ "fe80::1", false, false, false },
        .{ "224.0.0.5", false, true, false },
        .{ "::ffff:224.0.0.1", false, true, false },
        .{ "224.0.1.5", false, false, false },
        .{ "ff02::1", false, true, false },
        .{ "ff12::1", false, true, false },
        .{ "ff01::1", false, false, true },
        .{ "ff11::1", false, false, true },
        .{ "ff05::1", false, false, false },
    };
    for (rows) |r| {
        const a = ip(r[0]);
        errdefer std.debug.print("row {s}\n", .{r[0]});
        try testing.expectEqual(r[1], a.isGlobalUnicast());
        try testing.expectEqual(r[2], a.isLinkLocalMulticast());
        try testing.expectEqual(r[3], a.isInterfaceLocalMulticast());
    }
}

test "bitLen, prefix, asSlice/fromSlice, constants" {
    try testing.expectEqual(@as(u8, 32), ip("1.2.3.4").bitLen());
    try testing.expectEqual(@as(u8, 128), ip("::1").bitLen());
    try testing.expect(ip("1.2.3.4").prefix(24).?.eql(pfx("1.2.3.0/24")));
    try testing.expect(ip("1.2.3.4").prefix(33) == null);
    try testing.expect(ip("2001:db8::1").prefix(0).?.eql(pfx("::/0")));

    const a = ip("1.2.3.4");
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, a.asSlice());
    try testing.expect(na.Ip.fromSlice(a.asSlice()).?.eql(a));
    const b = ip("::ffff:1.2.3.4");
    try testing.expectEqual(@as(usize, 16), b.asSlice().len);
    try testing.expect(na.Ip.fromSlice(b.asSlice()).?.eql(b)); // not unmapped
    try testing.expect(na.Ip.fromSlice(&.{ 1, 2, 3 }) == null);

    try testing.expect(na.Ip.ipv4_unspecified.eql(ip("0.0.0.0")));
    try testing.expect(na.Ip.ipv4_broadcast.eql(ip("255.255.255.255")));
    try testing.expect(na.Ip.ipv6_unspecified.eql(ip("::")));
    try testing.expect(na.Ip.ipv6_loopback.eql(ip("::1")));
    try testing.expect(na.Ip.ipv6_link_local_all_nodes.eql(ip("ff02::1")));
    try testing.expect(na.Ip.ipv6_link_local_all_routers.eql(ip("ff02::2")));
}

test "formatIpExpanded" {
    var buf: [na.max_ip_expanded_text_len]u8 = undefined;
    try testing.expectEqualStrings("2001:0db8:0000:0000:0000:0000:0000:0001", na.formatIpExpanded(ip("2001:db8::1"), &buf));
    try testing.expectEqualStrings("0000:0000:0000:0000:0000:ffff:0102:0304", na.formatIpExpanded(ip("::ffff:1.2.3.4"), &buf));
    try testing.expectEqualStrings("1.2.3.4", na.formatIpExpanded(ip("1.2.3.4"), &buf));
}

test "{f} formatting of Ip, Prefix, ZonedIp, AddrPort, IpRange" {
    var buf: [256]u8 = undefined;
    const s = try std.fmt.bufPrint(&buf, "{f} {f} {f} {f} {f}", .{
        ip("2001:db8::1"),
        pfx("10.0.0.0/8"),
        na.parseIpZoned("fe80::1%eth0").?,
        na.parseAddrPort("[fe80::1%eth0]:443").?,
        na.parseIpRange("1.2.3.4-1.2.3.9").?,
    });
    try testing.expectEqualStrings("2001:db8::1 10.0.0.0/8 fe80::1%eth0 [fe80::1%eth0]:443 1.2.3.4-1.2.3.9", s);
}

test "parseIpZoned: Go netip zone rules" {
    const z = na.parseIpZoned("fe80::1%eth0").?;
    try testing.expect(z.ip.eql(ip("fe80::1")));
    try testing.expectEqualStrings("eth0", z.zone.slice());
    // Any bytes after the first '%' are the zone.
    try testing.expectEqualStrings("a%b", na.parseIpZoned("fe80::1%a%b").?.zone.slice());
    try testing.expectEqualStrings("]", na.parseIpZoned("fe80::1%]").?.zone.slice());
    try testing.expectEqualStrings("x", na.parseIpZoned("::ffff:1.2.3.4%x").?.zone.slice());
    // No zone is fine; an empty one, a v4 one, or an over-long one is not.
    try testing.expect(na.parseIpZoned("1.2.3.4").?.zone.isNone());
    try testing.expect(na.parseIpZoned("fe80::1%") == null);
    try testing.expect(na.parseIpZoned("1.2.3.4%eth0") == null);
    try testing.expect(na.parseIpZoned("fe80::1%" ++ "z" ** na.max_zone_len) != null);
    try testing.expect(na.parseIpZoned("fe80::1%" ++ "z" ** (na.max_zone_len + 1)) == null);

    var buf: [na.max_zoned_ip_text_len]u8 = undefined;
    try testing.expectEqualStrings("fe80::1%eth0", na.formatIpZoned(z, &buf));
    const longest = na.parseIpZoned("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255%" ++ "z" ** na.max_zone_len).?;
    try testing.expectEqual(@as(usize, 39 + 1 + na.max_zone_len), na.formatIpZoned(longest, &buf).len);
}

test "ZonedIp: init drops a v4 zone, compare orders by zone last" {
    const v4 = na.ZonedIp.init(ip("1.2.3.4"), "eth0").?;
    try testing.expect(v4.zone.isNone());
    const a = na.ZonedIp.init(ip("fe80::1"), "").?;
    const b = na.ZonedIp.init(ip("fe80::1"), "a").?;
    try testing.expectEqual(std.math.Order.lt, a.compare(b));
    try testing.expectEqual(std.math.Order.gt, b.compare(a));
    try testing.expect(!a.eql(b));
    try testing.expect(b.eql(na.parseIpZoned("fe80::1%a").?));
    try testing.expect(na.ZonedIp.init(ip("fe80::1"), "z" ** (na.max_zone_len + 1)) == null);
    try testing.expect(na.Zone.fromSlice("eth0").?.eql(na.parseIpZoned("::1%eth0").?.zone));
    try testing.expectEqual(std.math.Order.lt, na.Zone.none.order(na.Zone.fromSlice("0").?));
}

test "parseAddrPort / formatAddrPort" {
    const Row = struct { []const u8, ?[]const u8 };
    const rows = [_]Row{
        .{ "1.2.3.4:80", "1.2.3.4:80" },
        .{ "[::1]:80", "[::1]:80" },
        .{ "[fe80::1%eth0]:80", "[fe80::1%eth0]:80" },
        .{ "[::ffff:1.2.3.4]:1", "[::ffff:1.2.3.4]:1" },
        .{ "[fe80::1%]]:80", "[fe80::1%]]:80" },
        .{ "0.0.0.0:0", "0.0.0.0:0" },
        .{ "[::]:65535", "[::]:65535" },
        .{ "1.2.3.4:080", null }, // leading zero: this module's port rule
        .{ "1.2.3.4:+80", null },
        .{ "[1.2.3.4]:80", null }, // brackets only around IPv6
        .{ "::1:80", null }, // IPv6 needs brackets
        .{ "1.2.3.4:", null },
        .{ "1.2.3.4", null },
        .{ "1.2.3.4:65536", null },
        .{ "[::1]80", null },
        .{ "[::1%]:80", null },
        .{ "example.com:80", null }, // numeric only
        .{ "[]:80", null },
        .{ "", null },
    };
    var buf: [na.max_addr_port_text_len]u8 = undefined;
    for (rows) |r| {
        errdefer std.debug.print("row {s}\n", .{r[0]});
        if (r[1]) |want| {
            try testing.expectEqualStrings(want, na.formatAddrPort(na.parseAddrPort(r[0]).?, &buf));
        } else try testing.expect(na.parseAddrPort(r[0]) == null);
    }
}

test "AddrPort.compare: address, zone, then port; eql" {
    const a = na.parseAddrPort("1.2.3.4:90").?;
    const b = na.parseAddrPort("1.2.3.5:80").?;
    const c = na.parseAddrPort("[::1]:1").?;
    const d = na.parseAddrPort("[::1%a]:1").?;
    try testing.expectEqual(std.math.Order.lt, a.compare(b));
    try testing.expectEqual(std.math.Order.lt, b.compare(c));
    try testing.expectEqual(std.math.Order.lt, c.compare(d));
    try testing.expectEqual(std.math.Order.lt, a.compare(na.parseAddrPort("1.2.3.4:91").?));
    try testing.expect(a.eql(na.parseAddrPort("1.2.3.4:90").?));
    try testing.expect(!c.eql(d));
}

test "std.Io.net.IpAddress round trips" {
    const v4 = try std.Io.net.IpAddress.parse("192.0.2.1", 8080);
    const ap4 = na.AddrPort.fromStd(v4);
    try testing.expect(ap4.eql(na.parseAddrPort("192.0.2.1:8080").?));
    try testing.expect((try ap4.toStd()).eql(&v4));
    try testing.expect(na.Ip.fromStd(v4).eql(ip("192.0.2.1")));
    try testing.expect(na.Ip.toStd(ip("192.0.2.1"), 8080).eql(&v4));

    var v6 = try std.Io.net.IpAddress.parse("fe80::1", 53);
    v6.ip6.interface = .{ .index = 7 };
    const ap6 = na.AddrPort.fromStd(v6);
    try testing.expectEqualStrings("7", ap6.zone.slice());
    const back = try ap6.toStd();
    try testing.expectEqual(@as(u32, 7), back.ip6.interface.index);
    try testing.expectEqualSlices(u8, &v6.ip6.bytes, &back.ip6.bytes);
    try testing.expectError(error.ZoneNotNumeric, na.parseAddrPort("[fe80::1%eth0]:53").?.toStd());
    // Only the canonical decimal form fromStd writes maps to an index.
    for ([_][]const u8{ "0", "+5", "007", "-1", "4294967296" }) |zone| {
        var ap = na.parseAddrPort("[fe80::1]:53").?;
        ap.zone = na.Zone.fromSlice(zone).?;
        try testing.expectError(error.ZoneNotNumeric, ap.toStd());
    }
    var max = na.parseAddrPort("[fe80::1%4294967295]:53").?;
    try testing.expectEqual(@as(u32, 4294967295), (try max.toStd()).ip6.interface.index);
    max = na.AddrPort.fromStd(try max.toStd());
    try testing.expectEqualStrings("4294967295", max.zone.slice());
    try testing.expect(na.Ip.fromStd(v6).eql(ip("fe80::1")));
}

test "Prefix.compare (netip) and compareLengthFirst (netipx), lastAddr" {
    const O = std.math.Order;
    try testing.expectEqual(O.gt, pfx("1.2.3.4/24").compare(pfx("1.2.3.0/24"))); // unmasked last
    try testing.expectEqual(O.lt, pfx("10.0.0.0/8").compare(pfx("10.0.0.0/16"))); // same net: shorter first
    try testing.expectEqual(O.lt, pfx("9.0.0.0/32").compare(pfx("10.0.0.0/8"))); // masked address first
    try testing.expectEqual(O.lt, pfx("255.0.0.0/8").compare(pfx("::/0")));
    try testing.expectEqual(O.eq, pfx("::1/128").compare(pfx("::1/128")));

    try testing.expectEqual(O.gt, pfx("9.0.0.0/32").compareLengthFirst(pfx("10.0.0.0/8")));
    try testing.expectEqual(O.lt, pfx("10.0.0.0/8").compareLengthFirst(pfx("9.0.0.0/32")));
    try testing.expectEqual(O.lt, pfx("1.0.0.0/8").compareLengthFirst(pfx("2.0.0.0/8")));
    try testing.expectEqual(O.lt, pfx("255.0.0.0/32").compareLengthFirst(pfx("::/0")));

    try testing.expect(pfx("10.1.2.3/8").lastAddr().eql(ip("10.255.255.255")));
    try testing.expect(pfx("2001:db8::/127").lastAddr().eql(ip("2001:db8::1")));
}

test "parsePrefixOrAddr keeps the address as written" {
    try testing.expect(na.parsePrefixOrAddr("192.0.2.1").?.ip.eql(ip("192.0.2.1")));
    try testing.expect(na.parsePrefixOrAddr("192.0.2.1/24").?.ip.eql(ip("192.0.2.1")));
    try testing.expect(na.parsePrefixOrAddr("2001:db8::68/96").?.ip.eql(ip("2001:db8::68")));
    try testing.expectEqualStrings("eth0", na.parsePrefixOrAddr("fe80::1%eth0").?.zone.slice());
    try testing.expect(na.parsePrefixOrAddr("fe80::1%eth0/64") == null);
    try testing.expect(na.parsePrefixOrAddr("192.0.2.1/33") == null);
    try testing.expect(na.parsePrefixOrAddr("x") == null);
}

test "IpRange: parse, format, validity, contains, overlaps, toPrefix, prefixes" {
    const r = na.parseIpRange("1.2.3.4-1.2.3.10").?;
    var buf: [na.max_ip_range_text_len]u8 = undefined;
    try testing.expectEqualStrings("1.2.3.4-1.2.3.10", na.formatIpRange(r, &buf));
    try testing.expect(na.parseIpRange("1.2.3.4-1.2.3.4") != null);
    try testing.expect(na.parseIpRange("1.2.3.5-1.2.3.4") == null);
    try testing.expect(na.parseIpRange("1.2.3.4-::1") == null);
    try testing.expect(na.parseIpRange("1.2.3.4 - 1.2.3.5") == null);
    try testing.expect(na.parseIpRange("1.2.3.4") == null);
    // A zone is accepted and dropped, as in netipx.
    try testing.expect(na.parseIpRange("fe80::1%a-fe80::2%a").?.eql(.{ .from = ip("fe80::1"), .to = ip("fe80::2") }));
    const longest: na.IpRange = .{ .from = ip("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.254"), .to = ip("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255") };
    try testing.expectEqual(@as(usize, 79), na.formatIpRange(longest, &buf).len);

    const bad: na.IpRange = .{ .from = ip("1.2.3.5"), .to = ip("1.2.3.4") };
    const mixed: na.IpRange = .{ .from = ip("1.2.3.4"), .to = ip("::1") };
    try testing.expect(r.isValid() and !bad.isValid() and !mixed.isValid());

    try testing.expect(r.contains(ip("1.2.3.4")) and r.contains(ip("1.2.3.10")));
    try testing.expect(!r.contains(ip("1.2.3.11")) and !r.contains(ip("::ffff:1.2.3.5")));
    try testing.expect(!bad.contains(ip("1.2.3.4")));

    // Touching in one address counts, from either side.
    try testing.expect(r.overlaps(na.parseIpRange("1.2.3.10-1.2.3.20").?));
    try testing.expect(na.parseIpRange("1.2.3.10-1.2.3.20").?.overlaps(r));
    try testing.expect(na.parseIpRange("1.2.3.0-1.2.3.4").?.overlaps(r));
    try testing.expect(!r.overlaps(na.parseIpRange("1.2.3.11-1.2.3.20").?));
    try testing.expect(!r.overlaps(bad) and !bad.overlaps(r));
    try testing.expect(!r.overlaps(na.parseIpRange("::-::ffff:ffff:ffff").?));

    try testing.expect(r.toPrefix() == null);
    try testing.expect(na.parseIpRange("1.2.3.0-1.2.3.255").?.toPrefix().?.eql(pfx("1.2.3.0/24")));
    try testing.expect(na.parseIpRange("1.2.3.4-1.2.3.4").?.toPrefix().?.eql(pfx("1.2.3.4/32")));
    try testing.expect(na.parseIpRange("0.0.0.0-255.255.255.255").?.toPrefix().?.eql(pfx("0.0.0.0/0")));
    try testing.expect(na.parseIpRange("::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").?.toPrefix().?.eql(pfx("::/0")));
    try testing.expect(na.parseIpRange("1.2.3.1-1.2.3.2").?.toPrefix() == null);
    try testing.expect(bad.toPrefix() == null);

    const ps = try r.prefixes(testing.allocator);
    defer testing.allocator.free(ps);
    try testing.expectEqual(@as(usize, 3), ps.len); // .4/30 .8/31 .10/32
    try testing.expectError(error.InvalidRange, bad.prefixes(testing.allocator));
}

// ── IpSet ───────────────────────────────────────────────────────────────────

fn buildSet(gpa: std.mem.Allocator, prefixes: []const []const u8) !na.IpSet {
    var b: na.IpSetBuilder = .empty;
    defer b.deinit(gpa);
    for (prefixes) |p| try b.addPrefix(gpa, pfx(p));
    return b.toSet(gpa);
}

fn expectPrefixes(s: na.IpSet, want: []const []const u8) !void {
    const got = try s.prefixes(testing.allocator);
    defer testing.allocator.free(got);
    errdefer for (got) |p| std.debug.print("  got {f}\n", .{p});
    try testing.expectEqual(want.len, got.len);
    for (want, got) |w, g| try testing.expect(g.eql(pfx(w)));
}

test "IpSetBuilder: adds merge, removes apply in call order" {
    const gpa = testing.allocator;
    var b: na.IpSetBuilder = .empty;
    defer b.deinit(gpa);
    try b.addPrefix(gpa, pfx("10.0.0.0/25"));
    try b.addPrefix(gpa, pfx("10.0.0.128/25")); // adjacent: merges to /24
    try b.add(gpa, ip("10.0.1.0"));
    try b.addRange(gpa, .{ .from = ip("10.0.1.1"), .to = ip("10.0.1.255") });
    try b.addPrefix(gpa, pfx("2001:db8::/32"));
    try b.remove(gpa, ip("10.0.0.7"));
    try b.add(gpa, ip("10.0.0.7")); // added after the removal: present again
    try b.removePrefix(gpa, pfx("2001:db8:8000::/33"));
    try b.removeRange(gpa, .{ .from = ip("10.0.1.128"), .to = ip("10.0.1.255") });
    try testing.expectError(error.InvalidRange, b.addRange(gpa, .{ .from = ip("1.0.0.2"), .to = ip("1.0.0.1") }));
    try testing.expectError(error.InvalidRange, b.removeRange(gpa, .{ .from = ip("1.0.0.1"), .to = ip("::1") }));

    var s = try b.toSet(gpa);
    defer s.deinit(gpa);
    try expectPrefixes(s, &.{ "10.0.0.0/24", "10.0.1.0/25", "2001:db8::/33" });
    try testing.expectEqual(@as(usize, 2), s.rangeCount());
    try testing.expect(s.rangeAt(0).eql(na.parseIpRange("10.0.0.0-10.0.1.127").?));

    const rs = try s.ranges(gpa);
    defer gpa.free(rs);
    try testing.expectEqual(@as(usize, 2), rs.len);
    try testing.expect(rs[1].eql(na.parseIpRange("2001:db8::-2001:db8:7fff:ffff:ffff:ffff:ffff:ffff").?));

    // Still usable after toSet.
    try b.add(gpa, ip("192.0.2.1"));
    var s2 = try b.toSet(gpa);
    defer s2.deinit(gpa);
    try testing.expect(s2.contains(ip("192.0.2.1")) and !s.contains(ip("192.0.2.1")));
}

test "IpSet queries: contains, ranges, prefixes, overlaps, eql" {
    const gpa = testing.allocator;
    var s = try buildSet(gpa, &.{ "10.0.0.0/8", "192.168.0.0/24", "192.168.1.0/30", "2001:db8::/32" });
    defer s.deinit(gpa);

    try testing.expect(s.contains(ip("10.255.255.255")));
    try testing.expect(!s.contains(ip("11.0.0.0")));
    try testing.expect(!s.contains(ip("::ffff:10.0.0.1"))); // strict family
    try testing.expect(s.contains(ip("192.168.1.3")) and !s.contains(ip("192.168.1.4")));
    try testing.expect(s.contains(ip("2001:db8:ffff::1")) and !s.contains(ip("2001:db9::")));

    try testing.expect(s.containsPrefix(pfx("10.20.0.0/16")));
    try testing.expect(s.containsRange(na.parseIpRange("192.168.0.200-192.168.1.3").?)); // merged span
    try testing.expect(!s.containsRange(na.parseIpRange("192.168.0.200-192.168.1.4").?));
    try testing.expect(!s.containsPrefix(pfx("8.0.0.0/6")));
    try testing.expect(!s.containsRange(.{ .from = ip("10.0.0.2"), .to = ip("10.0.0.1") }));

    try testing.expect(s.overlapsPrefix(pfx("8.0.0.0/6")));
    try testing.expect(!s.overlapsPrefix(pfx("11.0.0.0/8")));
    try testing.expect(s.overlapsRange(na.parseIpRange("192.168.1.3-192.168.9.0").?));
    try testing.expect(!s.overlapsRange(na.parseIpRange("192.168.1.4-192.168.9.0").?));
    try testing.expect(!s.overlapsRange(.{ .from = ip("10.0.0.1"), .to = ip("::1") }));

    var t = try buildSet(gpa, &.{ "192.168.1.3/32", "2001:db9::/32" });
    defer t.deinit(gpa);
    var u = try buildSet(gpa, &.{ "192.168.1.4/32", "2001:db9::/32" });
    defer u.deinit(gpa);
    try testing.expect(s.overlaps(t) and t.overlaps(s));
    try testing.expect(!s.overlaps(u) and !u.overlaps(s));
    try testing.expect(!s.overlaps(na.IpSet.empty));

    var same = try buildSet(gpa, &.{ "2001:db8::/33", "2001:db8:8000::/33", "192.168.1.0/30", "192.168.0.0/24", "10.0.0.0/8" });
    defer same.deinit(gpa);
    try testing.expect(s.eql(same) and !s.eql(t));
    try testing.expect(na.IpSet.empty.isEmpty() and !s.isEmpty());
}

test "IpSetBuilder: complement, intersect, addSet, removeSet, clone" {
    const gpa = testing.allocator;
    var b: na.IpSetBuilder = .empty;
    defer b.deinit(gpa);
    try b.complement(gpa);
    var all = try b.toSet(gpa);
    defer all.deinit(gpa);
    try expectPrefixes(all, &.{ "0.0.0.0/0", "::/0" });

    var c = try b.clone(gpa);
    defer c.deinit(gpa);
    try c.removePrefix(gpa, pfx("128.0.0.0/1"));
    try c.removePrefix(gpa, pfx("::/1"));
    try c.complement(gpa);
    var half = try c.toSet(gpa);
    defer half.deinit(gpa);
    try expectPrefixes(half, &.{ "128.0.0.0/1", "::/1" });

    var x = try buildSet(gpa, &.{ "10.0.0.0/8", "2001:db8::/32" });
    defer x.deinit(gpa);
    var y = try buildSet(gpa, &.{ "10.1.0.0/16", "10.3.0.0/16", "2001:db8:1::/48", "172.16.0.0/12" });
    defer y.deinit(gpa);

    var i: na.IpSetBuilder = .empty;
    defer i.deinit(gpa);
    try i.addSet(gpa, x);
    try i.intersect(gpa, y);
    var xy = try i.toSet(gpa);
    defer xy.deinit(gpa);
    try expectPrefixes(xy, &.{ "10.1.0.0/16", "10.3.0.0/16", "2001:db8:1::/48" });

    var d: na.IpSetBuilder = .empty;
    defer d.deinit(gpa);
    try d.addSet(gpa, x);
    try d.removeSet(gpa, y);
    try d.addSet(gpa, na.IpSet.empty);
    var x_minus_y = try d.toSet(gpa);
    defer x_minus_y.deinit(gpa);
    try testing.expect(!x_minus_y.overlaps(y));
    try testing.expect(x_minus_y.contains(ip("10.2.0.0")) and !x_minus_y.contains(ip("10.3.255.255")));
}

test "IpSet.removeFreePrefix: tightest fit, first on a tie, rest without it" {
    const gpa = testing.allocator;
    var s = try buildSet(gpa, &.{ "10.0.0.0/8", "192.168.0.0/24", "192.168.1.0/30", "2001:db8::/32" });
    defer s.deinit(gpa);

    const Row = struct { u8, ?[]const u8 };
    const rows = [_]Row{
        .{ 30, "192.168.1.0/30" }, .{ 24, "192.168.0.0/24" }, .{ 8, "10.0.0.0/8" },
        .{ 32, "2001:db8::/32" },  .{ 64, "2001:db8::/64" },  .{ 7, null },
        .{ 0, null },              .{ 129, null },            .{ 255, null },
    };
    for (rows) |r| {
        errdefer std.debug.print("bits {d}\n", .{r[0]});
        var got = try s.removeFreePrefix(gpa, r[0]);
        if (r[1]) |want| {
            defer got.?.rest.deinit(gpa);
            try testing.expect(got.?.prefix.eql(pfx(want)));
            try testing.expect(!got.?.rest.overlapsPrefix(got.?.prefix));
            // rest ∪ prefix == s
            var b: na.IpSetBuilder = .empty;
            defer b.deinit(gpa);
            try b.addSet(gpa, got.?.rest);
            try b.addPrefix(gpa, got.?.prefix);
            var back = try b.toSet(gpa);
            defer back.deinit(gpa);
            try testing.expect(back.eql(s));
        } else try testing.expect(got == null);
    }

    var tie = try buildSet(gpa, &.{ "10.0.2.0/24", "10.0.0.0/24", "2001:db8::/24" });
    defer tie.deinit(gpa);
    var got = (try tie.removeFreePrefix(gpa, 24)).?;
    defer got.rest.deinit(gpa);
    try testing.expect(got.prefix.eql(pfx("10.0.0.0/24")));
    try testing.expect(na.IpSet.empty.removeFreePrefix(gpa, 0) catch unreachable == null);
}

test "IpSet algebra against a brute-force model over a 6-bit space" {
    // Every operation over sets of addresses within 10.0.0.0/26, checked
    // address by address against a u64 bitmap, for random add/remove/
    // complement/intersect sequences. Complement spills outside the window,
    // so membership is only compared inside it, and complement is done
    // relative to the window (complement, then intersect with the window).
    const gpa = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6e65_7469_70);
    const rnd = prng.random();
    const base: u32 = 0x0a00_0000;
    const window = pfx("10.0.0.0/26");
    var wset = try buildSet(gpa, &.{"10.0.0.0/26"});
    defer wset.deinit(gpa);

    for (0..400) |_| {
        var b: na.IpSetBuilder = .empty;
        defer b.deinit(gpa);
        var model: u64 = 0;
        for (0..rnd.intRangeAtMost(usize, 1, 12)) |_| {
            const lo = rnd.uintLessThan(u32, 64);
            const hi = rnd.intRangeAtMost(u32, lo, 63);
            const span: u64 = (if (hi - lo == 63) ~@as(u64, 0) else ((@as(u64, 1) << @intCast(hi - lo + 1)) - 1)) << @intCast(lo);
            var lo_b: [4]u8 = undefined;
            var hi_b: [4]u8 = undefined;
            std.mem.writeInt(u32, &lo_b, base + lo, .big);
            std.mem.writeInt(u32, &hi_b, base + hi, .big);
            const r: na.IpRange = .{ .from = .{ .v4 = lo_b }, .to = .{ .v4 = hi_b } };
            switch (rnd.uintLessThan(u8, 5)) {
                0, 1 => {
                    try b.addRange(gpa, r);
                    model |= span;
                },
                2 => {
                    try b.removeRange(gpa, r);
                    model &= ~span;
                },
                3 => {
                    try b.complement(gpa);
                    try b.intersect(gpa, wset);
                    model = ~model;
                },
                else => {
                    var other: na.IpSetBuilder = .empty;
                    defer other.deinit(gpa);
                    try other.addRange(gpa, r);
                    var os = try other.toSet(gpa);
                    defer os.deinit(gpa);
                    try b.intersect(gpa, os);
                    model &= span;
                },
            }
        }
        var s = try b.toSet(gpa);
        defer s.deinit(gpa);
        var it = window.addresses();
        var k: u6 = 0;
        while (it.next()) |a| : (k +%= 1) {
            try testing.expectEqual((model >> k) & 1 == 1, s.contains(a));
        }
        // Normal form: spans are disjoint, non-adjacent and sorted.
        for (1..@max(1, s.rangeCount())) |i| {
            const prev_to = s.rangeAt(i - 1).to;
            try testing.expect(prev_to.next().?.compare(s.rangeAt(i).from) == .lt);
        }
        // prefixes() covers exactly the set.
        const ps = try s.prefixes(gpa);
        defer gpa.free(ps);
        var total: u128 = 0;
        for (ps) |p| {
            try testing.expect(s.containsPrefix(p));
            total += p.hostCount();
        }
        try testing.expectEqual(@as(u128, @popCount(model)), total);
    }
}
