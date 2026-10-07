// SPDX-License-Identifier: MIT

//! Replays `netip_vectors.zig`: Go net/netip + go4.org/netipx answers to
//! this module's own cases (`tools/go_netip_oracle`), against the
//! Go-parity surface — zoned parse/format, the predicates, Compare,
//! Next/Prev, AddrPort, Prefix ordering, IPRange and IPSet. No Go at test
//! time.
//!
//! Listed divergences, each counted and pinned so a drift either way shows:
//!  - a zone longer than `max_zone_len` (Go: any length; here refused);
//!  - a port with a leading zero (`1.2.3.4:080`; Go takes it, this module's
//!    `parsePort` does not — the F8 decision);
//!  - `IsPrivate` on `fc00::/7` (Go: private; here `isUniqueLocal`'s job).

const std = @import("std");
const testing = std.testing;
const na = @import("root.zig");
const v = @import("netip_vectors.zig");

fn order(o: std.math.Order) i8 {
    return switch (o) {
        .lt => -1,
        .eq => 0,
        .gt => 1,
    };
}

/// A Go-printed zoned address (it has always parsed).
fn zoned(text: []const u8) na.ZonedIp {
    return na.parseIpZoned(text) orelse std.debug.panic("vector address {s} does not parse", .{text});
}

fn prefix(text: []const u8) na.Prefix {
    return na.parsePrefix(text) orelse std.debug.panic("vector prefix {s} does not parse", .{text});
}

fn range(text: []const u8) na.IpRange {
    return na.parseIpRange(text) orelse std.debug.panic("vector range {s} does not parse", .{text});
}

/// "from-to" as written, valid or not (a range pair may be malformed).
fn rawRange(text: []const u8) na.IpRange {
    const dash = std.mem.indexOfScalar(u8, text, '-').?;
    return .{ .from = zoned(text[0..dash]).ip, .to = zoned(text[dash + 1 ..]).ip };
}

/// Text of `ip` with `zone` appended the way Go prints a zoned address.
fn withZone(buf: []u8, ip_text: []const u8, zone: na.Zone) []const u8 {
    if (zone.isNone()) return ip_text;
    return std.fmt.bufPrint(buf, "{s}%{s}", .{ ip_text, zone.slice() }) catch unreachable;
}

test "netip oracle: ParseAddr, String, StringExpanded, predicates, Next/Prev" {
    var long_zone: usize = 0;
    var private_v6: usize = 0;
    for (v.addrs) |c| {
        errdefer std.debug.print("addr {s}\n", .{c.text});
        const got = na.parseIpZoned(c.text);
        if (!c.ok) {
            try testing.expect(got == null);
            continue;
        }
        const z = got orelse {
            // Go takes any zone length; ours is capped.
            const pct = std.mem.indexOfScalar(u8, c.text, '%').?;
            try testing.expect(c.text.len - pct - 1 > na.max_zone_len);
            long_zone += 1;
            continue;
        };
        var buf: [na.max_zoned_ip_text_len]u8 = undefined;
        var buf2: [na.max_zoned_ip_text_len + 1]u8 = undefined;
        try testing.expectEqualStrings(c.str, na.formatIpZoned(z, &buf));
        var ebuf: [na.max_ip_expanded_text_len]u8 = undefined;
        try testing.expectEqualStrings(c.expanded, withZone(&buf2, na.formatIpExpanded(z.ip, &ebuf), z.zone));
        try testing.expectEqualStrings(c.zone, z.zone.slice());
        try testing.expectEqual(c.bits, z.ip.bitLen());

        const ip = z.ip;
        try testing.expectEqual(c.flags.global_unicast, ip.isGlobalUnicast());
        try testing.expectEqual(c.flags.link_local_multicast, ip.isLinkLocalMulticast());
        try testing.expectEqual(c.flags.interface_local_multicast, ip.isInterfaceLocalMulticast());
        try testing.expectEqual(c.flags.loopback, ip.isLoopback());
        try testing.expectEqual(c.flags.multicast, ip.isMulticast());
        try testing.expectEqual(c.flags.link_local_unicast, ip.isLinkLocalUnicast());
        try testing.expectEqual(c.flags.unspecified, ip.isUnspecified());
        try testing.expectEqual(c.flags.is4in6, ip.isIpv4Mapped());
        if (c.flags.private != ip.isPrivate()) {
            // Go's IsPrivate also covers fc00::/7, our isUniqueLocal.
            try testing.expect(c.flags.private and ip.isUniqueLocal());
            private_v6 += 1;
        }

        var nbuf: [na.max_ip_text_len]u8 = undefined;
        if (ip.next()) |n| {
            try testing.expectEqualStrings(c.next, withZone(&buf2, na.formatIp(n, &nbuf), z.zone));
        } else try testing.expectEqualStrings("", c.next);
        if (ip.prev()) |p| {
            try testing.expectEqualStrings(c.prev, withZone(&buf2, na.formatIp(p, &nbuf), z.zone));
        } else try testing.expectEqualStrings("", c.prev);
    }
    try testing.expectEqual(@as(usize, 1), long_zone);
    try testing.expect(private_v6 > 0);
}

test "netip oracle: Addr.Compare" {
    for (v.addr_compare) |c| {
        errdefer std.debug.print("compare {s} {s}\n", .{ c.a, c.b });
        try testing.expectEqual(c.order, order(zoned(c.a).compare(zoned(c.b))));
        // Zone-less order agrees whenever the zones do not decide it.
        const o = zoned(c.a).ip.compare(zoned(c.b).ip);
        if (o != .eq) try testing.expectEqual(c.order, order(o));
    }
}

test "netip oracle: ParseAddrPort, String, Compare" {
    var leading_zero: usize = 0;
    for (v.addr_ports) |c| {
        errdefer std.debug.print("addrport {s}\n", .{c.text});
        const got = na.parseAddrPort(c.text);
        if (!c.ok) {
            try testing.expect(got == null);
            continue;
        }
        const ap = got orelse {
            // Go's port parser takes leading zeros; this module's does not.
            const colon = std.mem.lastIndexOfScalar(u8, c.text, ':').?;
            const port = c.text[colon + 1 ..];
            try testing.expect(port.len > 1 and port[0] == '0');
            leading_zero += 1;
            continue;
        };
        var buf: [na.max_addr_port_text_len]u8 = undefined;
        try testing.expectEqualStrings(c.str, na.formatAddrPort(ap, &buf));
    }
    try testing.expectEqual(@as(usize, 2), leading_zero);

    for (v.addr_port_compare) |c| {
        errdefer std.debug.print("compare {s} {s}\n", .{ c.a, c.b });
        try testing.expectEqual(c.order, order(na.parseAddrPort(c.a).?.compare(na.parseAddrPort(c.b).?)));
    }
}

test "netip oracle: Prefix.Compare, ComparePrefix, Addr.Prefix, PrefixLastIP, ParsePrefixOrAddr" {
    for (v.prefix_compare) |c| {
        errdefer std.debug.print("compare {s} {s}\n", .{ c.a, c.b });
        try testing.expectEqual(c.netip, order(prefix(c.a).compare(prefix(c.b))));
        try testing.expectEqual(c.netipx, order(prefix(c.a).compareLengthFirst(prefix(c.b))));
    }
    for (v.addr_prefix) |c| {
        errdefer std.debug.print("prefix {s}/{d}\n", .{ c.addr, c.bits });
        const got = zoned(c.addr).ip.prefix(c.bits);
        if (c.prefix.len == 0) {
            try testing.expect(got == null);
            continue;
        }
        var buf: [na.max_prefix_text_len]u8 = undefined;
        try testing.expectEqualStrings(c.prefix, na.formatPrefix(got.?, &buf));
        var lbuf: [na.max_ip_text_len]u8 = undefined;
        try testing.expectEqualStrings(c.last, na.formatIp(got.?.lastAddr(), &lbuf));
    }
    for (v.prefix_or_addr) |c| {
        errdefer std.debug.print("prefix-or-addr {s}\n", .{c.text});
        const got = na.parsePrefixOrAddr(c.text);
        if (!c.ok) {
            try testing.expect(got == null);
            continue;
        }
        var buf: [na.max_zoned_ip_text_len]u8 = undefined;
        try testing.expectEqualStrings(c.str, na.formatIpZoned(got.?, &buf));
    }
}

test "netip oracle: ParseIPRange, String, Prefix, Prefixes, Overlaps, Contains" {
    const gpa = testing.allocator;
    for (v.ranges) |c| {
        errdefer std.debug.print("range {s}\n", .{c.text});
        const got = na.parseIpRange(c.text);
        if (!c.ok) {
            try testing.expect(got == null);
            continue;
        }
        const r = got.?;
        var buf: [na.max_ip_range_text_len]u8 = undefined;
        try testing.expectEqualStrings(c.str, na.formatIpRange(r, &buf));
        var pbuf: [na.max_prefix_text_len]u8 = undefined;
        if (r.toPrefix()) |p| {
            try testing.expectEqualStrings(c.prefix, na.formatPrefix(p, &pbuf));
        } else try testing.expectEqualStrings("", c.prefix);
        const ps = try r.prefixes(gpa);
        defer gpa.free(ps);
        try testing.expectEqual(c.prefixes.len, ps.len);
        for (c.prefixes, ps) |want, p| try testing.expectEqualStrings(want, na.formatPrefix(p, &pbuf));
    }
    for (v.range_pairs) |c| {
        errdefer std.debug.print("pair {s} {s} {s}\n", .{ c.a, c.b, c.addr });
        const a = rawRange(c.a);
        try testing.expectEqual(c.overlaps, a.overlaps(rawRange(c.b)));
        try testing.expectEqual(c.contains, a.contains(zoned(c.addr).ip));
    }
}

fn build(gpa: std.mem.Allocator, ops: []const v.Op) !na.IpSet {
    var b: na.IpSetBuilder = .empty;
    defer b.deinit(gpa);
    for (ops) |o| switch (o.kind) {
        .add => try b.add(gpa, zoned(o.arg).ip),
        .add_prefix => try b.addPrefix(gpa, prefix(o.arg)),
        .add_range => try b.addRange(gpa, range(o.arg)),
        .remove => try b.remove(gpa, zoned(o.arg).ip),
        .remove_prefix => try b.removePrefix(gpa, prefix(o.arg)),
        .remove_range => try b.removeRange(gpa, range(o.arg)),
        .complement => try b.complement(gpa),
        .intersect => {
            var ib: na.IpSetBuilder = .empty;
            defer ib.deinit(gpa);
            var it = std.mem.splitScalar(u8, o.arg, ',');
            while (it.next()) |p| try ib.addPrefix(gpa, prefix(p));
            var other = try ib.toSet(gpa);
            defer other.deinit(gpa);
            try b.intersect(gpa, other);
        },
    };
    return b.toSet(gpa);
}

/// Brute force: does any maximal v6 range of `s` hold an aligned block of
/// `bits` length?
fn anyV6PrefixOfLength(s: na.IpSet, bits: u8) bool {
    for (0..s.rangeCount()) |i| {
        const r = s.rangeAt(i);
        if (r.from != .v6) continue;
        const from = std.mem.readInt(u128, &r.from.v6, .big);
        const to = std.mem.readInt(u128, &r.to.v6, .big);
        if (bits == 0) {
            if (from == 0 and to == std.math.maxInt(u128)) return true;
            continue;
        }
        const size: u128 = @as(u128, 1) << @intCast(128 - @as(u16, bits));
        const first = (from +% (size - 1)) & ~(size - 1);
        if (first >= from and first <= to and to - first >= size - 1) return true;
    }
    return false;
}

fn expectRanges(s: na.IpSet, want: []const []const u8) !void {
    try testing.expectEqual(want.len, s.rangeCount());
    var buf: [na.max_ip_range_text_len]u8 = undefined;
    for (want, 0..) |w, i| try testing.expectEqualStrings(w, na.formatIpRange(s.rangeAt(i), &buf));
}

test "netip oracle: IPSetBuilder ops, Prefixes, Ranges, probes, RemoveFreePrefix, Overlaps, Equal" {
    const gpa = testing.allocator;
    var sets: [v.sets.len]na.IpSet = undefined;
    var built: usize = 0;
    var invalid_free: usize = 0;
    defer for (sets[0..built]) |*s| s.deinit(gpa);

    for (v.sets, 0..) |c, ci| {
        errdefer std.debug.print("set case {d}\n", .{ci});
        sets[ci] = try build(gpa, c.ops);
        built += 1;
        const s = sets[ci];

        const ps = try s.prefixes(gpa);
        defer gpa.free(ps);
        var pbuf: [na.max_prefix_text_len]u8 = undefined;
        try testing.expectEqual(c.prefixes.len, ps.len);
        for (c.prefixes, ps) |want, p| try testing.expectEqualStrings(want, na.formatPrefix(p, &pbuf));
        try expectRanges(s, c.ranges);

        for (c.probes) |p| {
            errdefer std.debug.print("probe {t} {s}\n", .{ p.kind, p.arg });
            const yes = switch (p.kind) {
                .contains => s.contains(zoned(p.arg).ip),
                .contains_prefix => s.containsPrefix(prefix(p.arg)),
                .contains_range => s.containsRange(range(p.arg)),
                .overlaps_prefix => s.overlapsPrefix(prefix(p.arg)),
                .overlaps_range => s.overlapsRange(range(p.arg)),
            };
            try testing.expectEqual(p.yes, yes);
        }

        for (c.free) |f| {
            errdefer std.debug.print("removeFreePrefix {d}\n", .{f.bits});
            var got = try s.removeFreePrefix(gpa, f.bits);
            if (f.prefix.len == 0) {
                try testing.expect(got == null);
                continue;
            }
            if (std.mem.eql(u8, f.prefix, "invalid Prefix")) {
                // netipx picked a v4 prefix for a length only v6 can have.
                // Here the tightest fit among the families that can hold
                // `bits` is taken, and the contract is checked instead.
                try testing.expect(f.bits > 32);
                invalid_free += 1;
                if (got) |*g| {
                    defer g.rest.deinit(gpa);
                    try testing.expect(g.prefix.addr == .v6 and g.prefix.bits == f.bits);
                    try testing.expect(s.containsPrefix(g.prefix));
                    var b: na.IpSetBuilder = .empty;
                    defer b.deinit(gpa);
                    try b.addSet(gpa, s);
                    try b.removePrefix(gpa, g.prefix);
                    var want = try b.toSet(gpa);
                    defer want.deinit(gpa);
                    try testing.expect(g.rest.eql(want));
                } else try testing.expect(!anyV6PrefixOfLength(s, f.bits));
                continue;
            }
            defer got.?.rest.deinit(gpa);
            try testing.expectEqualStrings(f.prefix, na.formatPrefix(got.?.prefix, &pbuf));
            try expectRanges(got.?.rest, f.rest);
        }
    }
    // Counted, so a netipx that fixes this (or a module that starts
    // agreeing with it) shows up as drift rather than passing silently.
    try testing.expectEqual(@as(usize, 227), invalid_free);
    for (v.set_pairs) |p| {
        errdefer std.debug.print("pair {d} {d}\n", .{ p.a, p.b });
        try testing.expectEqual(p.overlaps, sets[p.a].overlaps(sets[p.b]));
        try testing.expectEqual(p.equal, sets[p.a].eql(sets[p.b]));
    }
}
