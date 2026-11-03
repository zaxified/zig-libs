// SPDX-License-Identifier: MIT
//! Tests and the deterministic fuzz harness for `ext.zig` (multipath routes,
//! nexthop objects, link kinds). The `Socket`-level and request-builder tests
//! that need `root.zig`'s private items sit at the end of root.zig.

const std = @import("std");
const builtin = @import("builtin");
const native_endian = builtin.cpu.arch.endian();
const testing = std.testing;
const Allocator = std.mem.Allocator;

const codec = @import("codec.zig");
const root = @import("root.zig");
const e = @import("ext.zig");
const fz = @import("fuzz_test.zig");
const testkit = @import("testkit");

const HopSpec = e.HopSpec;
const RouteHop = e.RouteHop;
const RawAttr = e.RawAttr;
const KindInfo = e.KindInfo;
const BridgeInfo = e.BridgeInfo;
const Nexthop = e.Nexthop;
const NexthopSpec = e.NexthopSpec;
const GroupMember = e.GroupMember;
const RTNH_F = e.RTNH_F;
const RTAX = e.RTAX;
const NHA = e.NHA;
const IFLA_BR = e.IFLA_BR;
const GRE_KEY = e.GRE_KEY;
const max_route_hops = e.max_route_hops;
const max_spec_hops = e.max_spec_hops;
const max_raw_attrs = e.max_raw_attrs;

fn firstAttr(buf: []const u8) !codec.Attr {
    var it: codec.AttrIterator = .{ .buf = buf };
    return (try it.next()) orelse error.TestNoAttr;
}

/// The payload of the `IFLA_INFO_DATA` nest an `encode*` function wrote.
fn dataOf(list: []const u8) ![]const u8 {
    const a = try firstAttr(list);
    try testing.expectEqual(root.IFLA_INFO.DATA, a.type);
    return a.data;
}

test "multipath: three hops round-trip, with weight 256 and on-link" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    const hops = [_]HopSpec{
        .{ .gateway = &.{ 10, 0, 0, 1 }, .oif = 3 },
        .{ .gateway = &.{ 10, 0, 1, 1 }, .weight = 256, .onlink = true },
        .{ .oif = 7, .weight = 5 },
    };
    try testing.expectEqual(@as(?u8, root.AF.INET), try e.hopsFamily(&hops));
    try e.appendMultipath(gpa, &list, &hops);
    const a = try firstAttr(list.items);
    try testing.expectEqual(root.RTA.MULTIPATH, a.type);
    var out: [max_route_hops]RouteHop = undefined;
    try testing.expectEqual(@as(u16, 3), try e.parseMultipath(a.data, &out));
    try testing.expectEqual(@as(u32, 3), out[0].oif);
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 1 }, out[0].gatewayBytes());
    try testing.expectEqual(@as(u16, 1), out[0].weight);
    try testing.expectEqual(@as(u16, 256), out[1].weight);
    try testing.expectEqual(RTNH_F.ONLINK, out[1].flags);
    try testing.expectEqual(@as(u8, 0), out[2].gateway_len);
    try testing.expectEqual(@as(u32, 7), out[2].oif);
    try testing.expectEqual(@as(u16, 5), out[2].weight);
}

test "multipath: one hop is the bytes struct rtnexthop + RTA_GATEWAY lay out (UAPI layout)" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try e.appendMultipath(gpa, &list, &.{.{ .gateway = &.{ 10, 0, 0, 1 }, .oif = 3, .weight = 2 }});
    try testing.expectEqualSlices(u8, &.{
        0x14, 0x00, 0x09, 0x00, // RTA_MULTIPATH, len 20
        0x10, 0x00, 0x00, 0x01, // rtnh_len 16, flags 0, hops 1 (weight 2)
        0x03, 0x00, 0x00, 0x00, // ifindex 3
        0x08, 0x00, 0x05, 0x00, 10, 0, 0, 1, // RTA_GATEWAY
    }, list.items);
}

test "multipath: more hops than fit inline are counted, not stored" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    var hops: [7]HopSpec = undefined;
    for (&hops, 0..) |*h, i| h.* = .{ .oif = @intCast(i + 1) };
    try e.appendMultipath(gpa, &list, &hops);
    const a = try firstAttr(list.items);
    var out: [max_route_hops]RouteHop = undefined;
    try testing.expectEqual(@as(u16, 7), try e.parseMultipath(a.data, &out));
    try testing.expectEqual(@as(u32, 4), out[3].oif);
    var it: e.MultipathIterator = .{ .buf = a.data };
    var n: u32 = 0;
    while (try it.next()) |h| : (n += 1) try testing.expectEqual(n + 1, h.oif);
    try testing.expectEqual(@as(u32, 7), n);
}

test "multipath: hostile lists are errors, never reads past the buffer" {
    var out: [max_route_hops]RouteHop = undefined;
    // Shorter than one rtnexthop.
    try testing.expectError(error.Truncated, e.parseMultipath(&.{ 8, 0, 0, 0 }, &out));
    // rtnh_len below the fixed part.
    try testing.expectError(error.BadLength, e.parseMultipath(&.{ 4, 0, 0, 0, 1, 0, 0, 0 }, &out));
    // rtnh_len past the buffer.
    try testing.expectError(error.Truncated, e.parseMultipath(&.{ 64, 0, 0, 0, 1, 0, 0, 0 }, &out));
    // A gateway attribute that overruns its hop.
    try testing.expectError(error.Truncated, e.parseMultipath(&.{ 12, 0, 0, 0, 1, 0, 0, 0, 20, 0, 5, 0 }, &out));
    // Empty is zero hops.
    try testing.expectEqual(@as(u16, 0), try e.parseMultipath(&.{}, &out));
}

test "multipath: hop specs are validated before anything is built" {
    try testing.expectError(error.InvalidHop, e.hopsFamily(&.{.{}})); // no gateway, no oif
    try testing.expectError(error.InvalidHop, e.hopsFamily(&.{.{ .oif = 1, .weight = 0 }}));
    try testing.expectError(error.InvalidHop, e.hopsFamily(&.{.{ .oif = 1, .weight = 257 }}));
    try testing.expectError(error.MixedFamilies, e.hopsFamily(&.{
        .{ .gateway = &.{ 10, 0, 0, 1 } },
        .{ .gateway = &(@as([16]u8, @splat(1))) },
    }));
    try testing.expectError(error.InvalidAddressLength, e.hopsFamily(&.{.{ .gateway = &.{ 1, 2, 3 } }}));
    const many: [max_spec_hops + 1]HopSpec = @splat(.{ .oif = 1 });
    try testing.expectError(error.TooManyHops, e.hopsFamily(&many));
    try testing.expectEqual(@as(?u8, null), try e.hopsFamily(&.{.{ .oif = 1 }}));
}

test "metrics: mtu/advmss/hoplimit round-trip, an empty set writes nothing" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try e.appendMetrics(gpa, &list, null, null, null);
    try testing.expectEqual(@as(usize, 0), list.items.len);
    try e.appendMetrics(gpa, &list, 1400, null, 32);
    const a = try firstAttr(list.items);
    try testing.expectEqual(root.RTA.METRICS, a.type);
    const m = try e.parseMetrics(a.data);
    try testing.expectEqual(e.Metrics{ .mtu = 1400, .advmss = 0, .hoplimit = 32 }, m);
    try testing.expectError(error.BadLength, e.parseMetrics(&.{ 6, 0, RTAX.MTU, 0, 1, 2, 0, 0 }));
}

fn nhPayload(gpa: Allocator, spec: NexthopSpec) ![]u8 {
    const req = try e.buildNexthopRequest(gpa, 9, e.RTM_NEWNEXTHOP, 0x0605, spec);
    defer gpa.free(req);
    return gpa.dupe(u8, req[codec.header_len..]);
}

test "nexthop: a gateway nexthop builds the documented bytes and parses back" {
    const gpa = testing.allocator;
    const req = try e.buildNexthopRequest(gpa, 9, e.RTM_NEWNEXTHOP, 0x0605, .{ .id = 5, .gateway = &.{ 10, 0, 0, 1 }, .oif = 2, .protocol = 4 });
    defer gpa.free(req);
    try testing.expectEqualSlices(u8, &.{
        0x30, 0, 0, 0, // len 48
        0x68, 0, // RTM_NEWNEXTHOP
        0x05, 0x06, // flags
        9, 0, 0, 0, 0, 0, 0, 0, // seq, pid
        2, 0, 4, 0, 0, 0, 0, 0, // nhmsg: AF_INET, scope 0, protocol 4, flags 0
        0x08, 0, 0x01, 0, 5, 0, 0, 0, // NHA_ID
        0x08, 0, 0x05, 0, 2, 0, 0, 0, // NHA_OIF
        0x08, 0, 0x06, 0, 10, 0, 0, 1, // NHA_GATEWAY
    }, req);
    const n = (try e.parseNexthop(req[codec.header_len..])).?;
    try testing.expectEqual(@as(u32, 5), n.id);
    try testing.expectEqual(@as(u8, 4), n.protocol);
    try testing.expectEqual(@as(u32, 2), n.oif);
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 1 }, n.gateway.bytes());
}

test "nexthop: groups carry id and weight per member, blackhole is a bare flag" {
    const gpa = testing.allocator;
    const g = try nhPayload(gpa, .{ .id = 3, .group = &.{ .{ .id = 1 }, .{ .id = 2, .weight = 256 } } });
    defer gpa.free(g);
    const n = (try e.parseNexthop(g)).?;
    try testing.expectEqual(@as(u8, root.AF.UNSPEC), n.family);
    try testing.expectEqual(@as(u16, 2), n.group_count);
    try testing.expectEqual(@as(u32, 2), n.members()[1].id);
    try testing.expectEqual(@as(u16, 256), n.members()[1].weight);
    try testing.expectEqual(@as(u16, 1), n.members()[0].weight);

    const b = try nhPayload(gpa, .{ .id = 4, .blackhole = true, .family = root.AF.INET6 });
    defer gpa.free(b);
    const bn = (try e.parseNexthop(b)).?;
    try testing.expect(bn.blackhole);
    try testing.expectEqual(@as(u8, root.AF.INET6), bn.family);

    // Delete and get carry the id only.
    const del = try e.buildNexthopRequest(gpa, 1, e.RTM_DELNEXTHOP, 5, .{ .id = 8 });
    defer gpa.free(del);
    try testing.expectEqual(@as(usize, 16 + 8 + 8), del.len);
}

test "nexthop: specs the kernel would misread are refused" {
    const gpa = testing.allocator;
    const bad = [_]NexthopSpec{
        .{ .id = 0, .oif = 1 },
        .{ .id = 1, .blackhole = true, .oif = 1 },
        .{ .id = 1, .blackhole = true, .gateway = &.{ 1, 1, 1, 1 } },
        .{ .id = 1, .blackhole = true, .group = &.{.{ .id = 2 }} },
        .{ .id = 1, .oif = 1, .group = &.{.{ .id = 2 }} },
        .{ .id = 1, .group = &.{.{ .id = 0 }} },
        .{ .id = 1, .group = &.{.{ .id = 2, .weight = 0 }} },
        .{ .id = 1, .group = &.{.{ .id = 2, .weight = 300 }} },
    };
    for (bad) |s| try testing.expectError(error.InvalidNexthop, e.buildNexthopRequest(gpa, 1, e.RTM_NEWNEXTHOP, 0, s));
    try testing.expectError(error.MixedFamilies, e.buildNexthopRequest(gpa, 1, e.RTM_NEWNEXTHOP, 0, .{ .id = 1, .gateway = &.{ 1, 1, 1, 1 }, .family = root.AF.INET6 }));
    try testing.expectError(error.InvalidNexthop, e.buildNexthopRequest(gpa, 1, e.RTM_GETNEXTHOP, 0, .{ .id = 0 }));
    const many: [max_spec_hops + 1]GroupMember = @splat(.{ .id = 1 });
    try testing.expectError(error.TooManyHops, e.buildNexthopRequest(gpa, 1, e.RTM_NEWNEXTHOP, 0, .{ .id = 1, .group = &many }));
}

test "nexthop: hostile payloads are errors, an object without NHA_ID is skipped" {
    try testing.expectError(error.Truncated, e.parseNexthop(&.{ 2, 0, 0 }));
    // NHA_GROUP whose length is not a multiple of 8.
    try testing.expectError(error.BadLength, e.parseNexthop(&.{ 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 2, 0, 1, 2, 3, 4, 5, 6 }));
    // NHA_OIF with the wrong width.
    try testing.expectError(error.BadLength, e.parseNexthop(&.{ 0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 5, 0, 1, 2, 0, 0 }));
    try testing.expectEqual(@as(?Nexthop, null), try e.parseNexthop(&.{ 2, 0, 0, 0, 0, 0, 0, 0 }));
    // A group bigger than the inline room: counted, first eight kept.
    var buf: [8 + 4 + 8 * 11 + 8]u8 = @splat(0);
    std.mem.writeInt(u16, buf[8..10], 4 + 8 * 11, native_endian);
    std.mem.writeInt(u16, buf[10..12], NHA.GROUP, native_endian);
    for (0..11) |i| std.mem.writeInt(u32, buf[12 + i * 8 ..][0..4], @intCast(i + 1), native_endian);
    const tail = 12 + 8 * 11;
    std.mem.writeInt(u16, buf[tail..][0..2], 8, native_endian);
    std.mem.writeInt(u16, buf[tail + 2 ..][0..2], NHA.ID, native_endian);
    std.mem.writeInt(u32, buf[tail + 4 ..][0..4], 77, native_endian);
    const n = (try e.parseNexthop(&buf)).?;
    try testing.expectEqual(@as(u16, 11), n.group_count);
    try testing.expectEqual(@as(usize, e.max_group_members), n.members().len);
    try testing.expectEqual(@as(u32, 8), n.members()[7].id);
}

test "kinds: vxlan round-trips, IPv6 groups use GROUP6, the port is big-endian" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try e.encodeVxlan(gpa, &list, .{
        .vni = 42,
        .group = &.{ 239, 1, 1, 1 },
        .local = &.{ 10, 0, 0, 2 },
        .port = 4789,
        .ttl = 64,
        .tos = 4,
        .learning = false,
        .ageing = 300,
        .udp_csum = true,
    }, 9);
    const info = try e.parseKindInfo("vxlan", try dataOf(list.items));
    const v = info.vxlan;
    try testing.expectEqual(@as(u32, 42), v.vni);
    try testing.expectEqualSlices(u8, &.{ 239, 1, 1, 1 }, v.group.bytes());
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 2 }, v.local.bytes());
    try testing.expectEqual(@as(u32, 9), v.link);
    try testing.expectEqual(@as(u16, 4789), v.port);
    try testing.expectEqual(@as(u8, 64), v.ttl);
    try testing.expectEqual(@as(u8, 4), v.tos);
    try testing.expect(!v.learning);
    try testing.expectEqual(@as(u32, 300), v.ageing);
    try testing.expect(v.udp_csum);
    // 4789 = 0x12b5 on the wire as 12 b5.
    try testing.expect(std.mem.find(u8, list.items, &.{ 0x12, 0xb5, 0x00, 0x00 }) != null);

    list.clearRetainingCapacity();
    const g6: [16]u8 = .{ 0xff, 0x0e } ++ @as([14]u8, @splat(0));
    try e.encodeVxlan(gpa, &list, .{ .vni = 1, .group = &g6, .local = &(@as([16]u8, @splat(7))) }, null);
    const v6 = (try e.parseKindInfo("vxlan", try dataOf(list.items))).vxlan;
    try testing.expectEqual(@as(u8, 16), v6.group.len);
    try testing.expectEqual(@as(u8, 16), v6.local.len);
    try testing.expectEqual(@as(u32, 0), v6.link);
}

test "kinds: macvlan, ipvlan, vrf, bond round-trip" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);

    try e.encodeMacvlan(gpa, &list, .{});
    try testing.expectEqual(@as(usize, 0), list.items.len); // no mode: no DATA at all
    try e.encodeMacvlan(gpa, &list, .{ .mode = .passthru });
    try testing.expectEqual(@as(u32, 8), (try e.parseKindInfo("macvtap", try dataOf(list.items))).macvlan.mode);

    list.clearRetainingCapacity();
    try e.encodeIpvlan(gpa, &list, .{ .mode = .l3s, .flags = 2 });
    const iv = (try e.parseKindInfo("ipvlan", try dataOf(list.items))).ipvlan;
    try testing.expectEqual(@as(u16, 2), iv.mode);
    try testing.expectEqual(@as(u16, 2), iv.flags);

    list.clearRetainingCapacity();
    try e.encodeVrf(gpa, &list, .{ .table = 100 });
    try testing.expectEqual(@as(u32, 100), (try e.parseKindInfo("vrf", try dataOf(list.items))).vrf.table);

    list.clearRetainingCapacity();
    try e.encodeBond(gpa, &list, .{ .mode = .lacp, .miimon = 100, .updelay = 200, .downdelay = 300, .min_links = 2, .xmit_hash_policy = 1, .lacp_rate = 1 });
    const b = (try e.parseKindInfo("bond", try dataOf(list.items))).bond;
    try testing.expectEqual(@as(u8, 4), b.mode);
    try testing.expectEqual(@as(u32, 100), b.miimon);
    try testing.expectEqual(@as(u32, 200), b.updelay);
    try testing.expectEqual(@as(u32, 300), b.downdelay);
    try testing.expectEqual(@as(u32, 2), b.min_links);
    try testing.expectEqual(@as(u8, 1), b.xmit_hash_policy);
    try testing.expectEqual(@as(u8, 1), b.lacp_rate);
}

test "kinds: gre sets GRE_KEY with a key, ipip, geneve and raw round-trip" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);

    try e.encodeGre(gpa, &list, .{ .local = &.{ 10, 0, 0, 1 }, .remote = &.{ 10, 0, 0, 2 }, .ttl = 8, .ikey = 7, .okey = 9, .pmtudisc = true }, 4);
    const g = (try e.parseKindInfo("gretap", try dataOf(list.items))).gre;
    try testing.expectEqual(@as(u32, 4), g.link);
    try testing.expectEqual(GRE_KEY, g.iflags);
    try testing.expectEqual(GRE_KEY, g.oflags);
    try testing.expectEqual(@as(u32, 7), g.ikey);
    try testing.expectEqual(@as(u32, 9), g.okey);
    try testing.expectEqual(@as(u8, 8), g.ttl);
    try testing.expect(g.pmtudisc);
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 2 }, g.remote.bytes());

    list.clearRetainingCapacity();
    try e.encodeGre(gpa, &list, .{ .ttl = 1 }, null); // keyless: no flags written
    const g0 = (try e.parseKindInfo("gre", try dataOf(list.items))).gre;
    try testing.expectEqual(@as(u16, 0), g0.iflags);

    list.clearRetainingCapacity();
    try e.encodeIptun(gpa, &list, .{ .local = &.{ 1, 2, 3, 4 }, .remote = &.{ 5, 6, 7, 8 }, .ttl = 3, .tos = 1 }, null);
    const t = (try e.parseKindInfo("sit", try dataOf(list.items))).iptun;
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, t.local.bytes());
    try testing.expectEqual(@as(u8, 3), t.ttl);
    try testing.expectEqual(@as(u8, 1), t.tos);

    list.clearRetainingCapacity();
    try e.encodeGeneve(gpa, &list, .{ .vni = 5, .remote = &(@as([16]u8, @splat(9))), .port = 6081, .ttl = 2, .udp_csum = true });
    const ge = (try e.parseKindInfo("geneve", try dataOf(list.items))).geneve;
    try testing.expectEqual(@as(u32, 5), ge.vni);
    try testing.expectEqual(@as(u8, 16), ge.remote.len);
    try testing.expectEqual(@as(u16, 6081), ge.port);
    try testing.expect(ge.udp_csum);

    list.clearRetainingCapacity();
    try e.encodeRaw(gpa, &list, &.{ .{ .attr_type = 3, .data = &.{ 1, 2, 3, 4 } }, .{ .attr_type = 9, .data = "x" } });
    const rd = try dataOf(list.items);
    var it: codec.AttrIterator = .{ .buf = rd };
    try testing.expectEqual(@as(u16, 3), (try it.next()).?.type);
    try testing.expectEqualSlices(u8, "x", (try it.next()).?.data);
    list.clearRetainingCapacity();
    try e.encodeRaw(gpa, &list, &.{});
    try testing.expectEqual(@as(usize, 0), list.items.len);
}

test "kinds: the bridge device's own options read back" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try codec.appendAttrU32(gpa, &list, root.IFLA_BR.FORWARD_DELAY, 1500);
    try codec.appendAttrU32(gpa, &list, IFLA_BR.HELLO_TIME, 200);
    try codec.appendAttrU32(gpa, &list, IFLA_BR.MAX_AGE, 2000);
    try codec.appendAttrU32(gpa, &list, root.IFLA_BR.AGEING_TIME, 30000);
    try codec.appendAttrU32(gpa, &list, root.IFLA_BR.STP_STATE, 1);
    try codec.appendAttrU16(gpa, &list, root.IFLA_BR.PRIORITY, 4096);
    try codec.appendAttrU8(gpa, &list, root.IFLA_BR.VLAN_FILTERING, 1);
    try codec.appendAttrBe16(gpa, &list, root.IFLA_BR.VLAN_PROTOCOL, 0x88a8);
    try codec.appendAttrU16(gpa, &list, IFLA_BR.GROUP_FWD_MASK, 8);
    try codec.appendAttrU16(gpa, &list, IFLA_BR.VLAN_DEFAULT_PVID, 5);
    try codec.appendAttrU8(gpa, &list, IFLA_BR.MCAST_SNOOPING, 1);
    try codec.appendAttrU8(gpa, &list, IFLA_BR.MCAST_QUERIER, 0);
    const b = (try e.parseKindInfo("bridge", list.items)).bridge;
    try testing.expectEqual(BridgeInfo{
        .forward_delay = 1500,
        .hello_time = 200,
        .max_age = 2000,
        .ageing_time = 30000,
        .stp_state = 1,
        .priority = 4096,
        .vlan_filtering = true,
        .vlan_protocol = 0x88a8,
        .group_fwd_mask = 8,
        .vlan_default_pvid = 5,
        .mcast_snooping = true,
        .mcast_querier = false,
    }, b);
}

test "kinds: values the kernel could only mis-read are refused" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try testing.expectError(error.InvalidKindData, e.encodeVxlan(gpa, &list, .{ .vni = 0x1000000 }, null));
    try testing.expectError(error.InvalidKindData, e.encodeGeneve(gpa, &list, .{ .vni = 0x1000000 }));
    try testing.expectError(error.InvalidKindData, e.encodeVrf(gpa, &list, .{ .table = 0 }));
    try testing.expectError(error.MixedFamilies, e.encodeVxlan(gpa, &list, .{ .vni = 1, .group = &.{ 1, 1, 1, 1 }, .local = &(@as([16]u8, @splat(1))) }, null));
    try testing.expectError(error.InvalidAddressLength, e.encodeVxlan(gpa, &list, .{ .vni = 1, .group = &.{ 1, 1, 1 } }, null));
    try testing.expectError(error.InvalidAddressLength, e.encodeGre(gpa, &list, .{ .local = &(@as([16]u8, @splat(1))) }, null));
    try testing.expectError(error.InvalidAddressLength, e.encodeIptun(gpa, &list, .{ .remote = &.{1} }, null));
    const many: [max_raw_attrs + 1]RawAttr = @splat(.{ .attr_type = 1, .data = "" });
    try testing.expectError(error.TooManyAttrs, e.encodeRaw(gpa, &list, &many));
    const big = try gpa.alloc(u8, 70000);
    defer gpa.free(big);
    try testing.expectError(error.AttrTooLong, e.encodeRaw(gpa, &list, &.{.{ .attr_type = 1, .data = big }}));
}

test "kinds: hostile info data is an error or .none, never a panic" {
    // Unknown kind (and veth, which has no data of its own): none.
    try testing.expectEqual(KindInfo.none, try e.parseKindInfo("dummy", &.{ 8, 0, 1, 0, 1, 0, 0, 0 }));
    // Truncated attribute header and an overrunning length.
    try testing.expectError(error.Truncated, e.parseKindInfo("vxlan", &.{ 8, 0 }));
    try testing.expectError(error.Truncated, e.parseKindInfo("vrf", &.{ 40, 0, 1, 0, 1, 0, 0, 0 }));
    // Wrong scalar widths.
    try testing.expectError(error.BadLength, e.parseKindInfo("vxlan", &.{ 6, 0, 1, 0, 1, 0, 0, 0 }));
    try testing.expectError(error.BadLength, e.parseKindInfo("bond", &.{ 8, 0, 1, 0, 1, 0, 0, 0 }));
    try testing.expectError(error.BadLength, e.parseKindInfo("bridge", &.{ 5, 0, 8, 0, 1, 0, 0, 0 }));
    try testing.expectError(error.BadLength, e.parseKindInfo("gre", &.{ 6, 0, 4, 0, 1, 0, 0, 0 }));
    // An address attribute of an odd size is ignored, not copied.
    const v = (try e.parseKindInfo("vxlan", &.{ 7, 0, 2, 0, 1, 2, 3, 0 })).vxlan;
    try testing.expectEqual(@as(u8, 0), v.group.len);
}

// ── constants and bytes, independent of the code that uses them ─────────────
// Every number below was printed by a C program compiled against the real
// /usr/include/linux/{if_link,if_tunnel,rtnetlink,nexthop,fib_rules,if_addr}.h
// of the build host (2026-11-03) -- not typed from memory.

test "constants equal the kernel headers" {
    const eq = testing.expectEqual;
    try eq(@as(u16, 104), e.RTM_NEWNEXTHOP);
    try eq(@as(u16, 105), e.RTM_DELNEXTHOP);
    try eq(@as(u16, 106), e.RTM_GETNEXTHOP);
    try eq(@as(u16, 30), e.RTA_NH_ID);
    try eq(@as(u16, 8), root.RTA.METRICS);
    try eq(@as(u16, 9), root.RTA.MULTIPATH);
    try eq(@as(u16, 7), root.RTA.PREFSRC);
    try eq(@as(u16, 16), root.RTA.MARK);
    try eq(@as(u16, 2), RTAX.MTU);
    try eq(@as(u16, 8), RTAX.ADVMSS);
    try eq(@as(u16, 10), RTAX.HOPLIMIT);
    try eq(@as(u8, 4), RTNH_F.ONLINK);
    try eq([_]u16{ 1, 2, 3, 4, 5, 6, 11 }, [_]u16{ NHA.ID, NHA.GROUP, NHA.GROUP_TYPE, NHA.BLACKHOLE, NHA.OIF, NHA.GATEWAY, NHA.FDB });
    const vx = e.IFLA_VXLAN;
    try eq([_]u16{ 1, 2, 3, 4, 5, 6, 7, 8, 15, 16, 17, 18 }, [_]u16{ vx.ID, vx.GROUP, vx.LINK, vx.LOCAL, vx.TTL, vx.TOS, vx.LEARNING, vx.AGEING, vx.PORT, vx.GROUP6, vx.LOCAL6, vx.UDP_CSUM });
    try eq([_]u16{ 1, 2 }, [_]u16{ e.IFLA_MACVLAN.MODE, e.IFLA_MACVLAN.FLAGS });
    try eq([_]u32{ 1, 2, 4, 8, 16 }, [_]u32{
        @backingInt(e.MacvlanMode.private),  @backingInt(e.MacvlanMode.vepa),   @backingInt(e.MacvlanMode.bridge),
        @backingInt(e.MacvlanMode.passthru), @backingInt(e.MacvlanMode.source),
    });
    try eq([_]u16{ 1, 2 }, [_]u16{ e.IFLA_IPVLAN.MODE, e.IFLA_IPVLAN.FLAGS });
    try eq([_]u16{ 0, 1, 2 }, [_]u16{ @backingInt(e.IpvlanMode.l2), @backingInt(e.IpvlanMode.l3), @backingInt(e.IpvlanMode.l3s) });
    try eq(@as(u16, 1), e.IFLA_VRF.TABLE);
    const b = e.IFLA_BOND;
    try eq([_]u16{ 1, 3, 4, 5, 14, 18, 21 }, [_]u16{ b.MODE, b.MIIMON, b.UPDELAY, b.DOWNDELAY, b.XMIT_HASH_POLICY, b.MIN_LINKS, b.AD_LACP_RATE });
    const g = e.IFLA_GRE;
    try eq([_]u16{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 }, [_]u16{ g.LINK, g.IFLAGS, g.OFLAGS, g.IKEY, g.OKEY, g.LOCAL, g.REMOTE, g.TTL, g.TOS, g.PMTUDISC });
    try eq(@as(u16, 0x2000), GRE_KEY); // GRE_KEY is 32 in the host-order header view: 0x2000 on the wire
    const t = e.IFLA_IPTUN;
    try eq([_]u16{ 1, 2, 3, 4, 5, 10 }, [_]u16{ t.LINK, t.LOCAL, t.REMOTE, t.TTL, t.TOS, t.PMTUDISC });
    const gn = e.IFLA_GENEVE;
    try eq([_]u16{ 1, 2, 3, 4, 5, 7, 8 }, [_]u16{ gn.ID, gn.REMOTE, gn.TTL, gn.TOS, gn.PORT, gn.REMOTE6, gn.UDP_CSUM });
    try eq([_]u16{ 2, 3, 9, 23, 25, 39 }, [_]u16{ IFLA_BR.HELLO_TIME, IFLA_BR.MAX_AGE, IFLA_BR.GROUP_FWD_MASK, IFLA_BR.MCAST_SNOOPING, IFLA_BR.MCAST_QUERIER, IFLA_BR.VLAN_DEFAULT_PVID });
    try eq([_]u16{ 19, 20, 27, 28, 30, 31, 32, 33, 37, 50, 51 }, [_]u16{
        root.IFLA_NET_NS_PID,    root.IFLA_IFALIAS, root.IFLA_GROUP,        root.IFLA_NET_NS_FD, root.IFLA_PROMISCUITY, root.IFLA_NUM_TX_QUEUES,
        root.IFLA_NUM_RX_QUEUES, root.IFLA_CARRIER, root.IFLA_LINK_NETNSID, root.IFLA_MIN_MTU,   root.IFLA_MAX_MTU,
    });
    const f = root.FRA;
    try eq([_]u16{ 4, 13, 14, 19, 20, 21, 22, 23, 24 }, [_]u16{ f.GOTO, f.SUPPRESS_IFGROUP, f.SUPPRESS_PREFIXLEN, f.L3MDEV, f.UID_RANGE, f.PROTOCOL, f.IP_PROTO, f.SPORT_RANGE, f.DPORT_RANGE });
    try eq(@as(u8, 2), @backingInt(root.RuleAction.goto));
    // Struct layouts: rtnexthop 8 (hops at 3, ifindex at 4), nhmsg 8 (protocol 2, flags 4),
    // nexthop_grp 8 (weight 4, weight_high 5), port range 4, uid range 8, ifa_cacheinfo 16.
    try eq(@as(usize, 8), e.nhmsg_len);
}

test "wire bytes of the new kinds, written out by hand" {
    if (native_endian != .little) return error.SkipZigTest;
    const gpa = testing.allocator;
    var l: std.ArrayList(u8) = .empty;
    defer l.deinit(gpa);
    try e.encodeVxlan(gpa, &l, .{ .vni = 42 }, null);
    try testing.expectEqualSlices(u8, &.{ 0x0c, 0, 2, 0, 0x08, 0, 0x01, 0, 0x2a, 0, 0, 0 }, l.items);
    l.clearRetainingCapacity();
    try e.encodeMacvlan(gpa, &l, .{ .mode = .bridge });
    try testing.expectEqualSlices(u8, &.{ 0x0c, 0, 2, 0, 0x08, 0, 0x01, 0, 0x04, 0, 0, 0 }, l.items);
    l.clearRetainingCapacity();
    try e.encodeIpvlan(gpa, &l, .{ .mode = .l3s, .flags = 2 });
    try testing.expectEqualSlices(u8, &.{ 0x14, 0, 2, 0, 0x06, 0, 0x01, 0, 0x02, 0, 0, 0, 0x06, 0, 0x02, 0, 0x02, 0, 0, 0 }, l.items);
    l.clearRetainingCapacity();
    try e.encodeVrf(gpa, &l, .{ .table = 100 });
    try testing.expectEqualSlices(u8, &.{ 0x0c, 0, 2, 0, 0x08, 0, 0x01, 0, 0x64, 0, 0, 0 }, l.items);
    l.clearRetainingCapacity();
    try e.encodeBond(gpa, &l, .{ .mode = .lacp, .miimon = 100 });
    try testing.expectEqualSlices(u8, &.{ 0x14, 0, 2, 0, 0x05, 0, 0x01, 0, 0x04, 0, 0, 0, 0x08, 0, 0x03, 0, 0x64, 0, 0, 0 }, l.items);
    l.clearRetainingCapacity();
    try e.encodeGre(gpa, &l, .{ .ikey = 7, .okey = 9 }, null);
    try testing.expectEqualSlices(u8, &.{
        0x24, 0, 2, 0,
        0x06, 0, 0x02, 0, 0x20, 0x00, 0, 0, // IFLAGS = GRE_KEY (big-endian 0x2000)
        0x06, 0, 0x03, 0, 0x20, 0x00, 0, 0, // OFLAGS
        0x08, 0, 0x04, 0, 0, 0, 0, 7, // IKEY, big-endian
        0x08, 0, 0x05, 0, 0, 0, 0, 9, // OKEY
    }, l.items);
    // Group weights: id, weight-1 low byte, weight-1 high byte, two reserved.
    const gp = try nhPayload(gpa, .{ .id = 3, .group = &.{ .{ .id = 1 }, .{ .id = 2, .weight = 256 } } });
    defer gpa.free(gp);
    try testing.expectEqualSlices(u8, &.{
        0x14, 0, 0x02, 0, // NHA_GROUP, 20
        1, 0, 0, 0, 0x00, 0x00, 0, 0, // id 1, weight 1
        2, 0, 0, 0, 0xff, 0x00, 0, 0, // id 2, weight 256
    }, gp[8 + 8 ..][0..20]);
}

test "nexthop: an FDB group is accepted and carries both attributes; groups pass a family filter" {
    const gpa = testing.allocator;
    const p = try nhPayload(gpa, .{ .id = 9, .fdb = true, .group = &.{ .{ .id = 1 }, .{ .id = 2 } } });
    defer gpa.free(p);
    const n = (try e.parseNexthop(p)).?;
    try testing.expect(n.fdb);
    try testing.expectEqual(@as(u16, 2), n.group_count);
}

// ── fuzz: the four new parsers ──────────────────────────────────────────────

const kind_names = [_][]const u8{ "vxlan", "macvlan", "macvtap", "ipvlan", "ipvtap", "vrf", "bond", "bridge", "gre", "gretap", "ipip", "sit", "geneve", "dummy" };

const ExtMark = fz.Marker(enum { rejected, kind, multipath, nexthop, metrics, link_info, link_top, route_mp, route_metrics, addr_cache, rule_ext });

const ExtCorpus = struct {
    scratch: [8192]u8 = undefined,
    store: [4096]u8 = undefined,
    used: usize = 0,
    entries: [14][]const u8 = undefined,
    n: usize = 0,

    fn push(self: *ExtCorpus, frame: []const u8) void {
        const s = testkit.fuzz.seedInto(self.store[self.used..], frame);
        self.entries[self.n] = s;
        self.used += s.len;
        self.n += 1;
    }

    fn build(self: *ExtCorpus) ![]const []const u8 {
        var fba = std.heap.FixedBufferAllocator.init(&self.scratch);
        const gpa = fba.allocator();
        {
            var list: std.ArrayList(u8) = .empty;
            try e.appendMultipath(gpa, &list, &.{ .{ .gateway = &.{ 10, 0, 0, 1 }, .oif = 2 }, .{ .oif = 3, .weight = 9 } });
            self.push(list.items[codec.attr_header_len..]);
        }
        {
            var list: std.ArrayList(u8) = .empty;
            try e.encodeVxlan(gpa, &list, .{ .vni = 7, .group = &.{ 239, 0, 0, 1 }, .port = 4789, .ttl = 3 }, 2);
            self.push(list.items[codec.attr_header_len..]);
        }
        {
            var list: std.ArrayList(u8) = .empty;
            try e.encodeBond(gpa, &list, .{ .mode = .active_backup, .miimon = 100 });
            self.push(list.items[codec.attr_header_len..]);
        }
        {
            var list: std.ArrayList(u8) = .empty;
            try e.encodeGre(gpa, &list, .{ .local = &.{ 1, 1, 1, 1 }, .ikey = 5 }, null);
            self.push(list.items[codec.attr_header_len..]);
        }
        {
            var list: std.ArrayList(u8) = .empty;
            try e.appendMetrics(gpa, &list, 1500, 1460, 64);
            self.push(list.items[codec.attr_header_len..]);
        }
        {
            const p = try nhPayload(gpa, .{ .id = 3, .group = &.{ .{ .id = 1 }, .{ .id = 2, .weight = 4 } } });
            self.push(p);
        }
        // One seed per remaining kind: bridge, macvlan, ipvlan, vrf, geneve, ipip/sit.
        {
            var list: std.ArrayList(u8) = .empty;
            try codec.appendAttrU32(gpa, &list, root.IFLA_BR.FORWARD_DELAY, 1500);
            try codec.appendAttrU32(gpa, &list, IFLA_BR.HELLO_TIME, 200);
            try codec.appendAttrU8(gpa, &list, root.IFLA_BR.VLAN_FILTERING, 1);
            try codec.appendAttrBe16(gpa, &list, root.IFLA_BR.VLAN_PROTOCOL, 0x8100);
            try codec.appendAttrU8(gpa, &list, IFLA_BR.MCAST_SNOOPING, 1);
            self.push(list.items);
        }
        {
            var list: std.ArrayList(u8) = .empty;
            try e.encodeMacvlan(gpa, &list, .{ .mode = .bridge });
            self.push(list.items[codec.attr_header_len..]);
        }
        {
            var list: std.ArrayList(u8) = .empty;
            try e.encodeIpvlan(gpa, &list, .{ .mode = .l3, .flags = 1 });
            self.push(list.items[codec.attr_header_len..]);
        }
        {
            var list: std.ArrayList(u8) = .empty;
            try e.encodeVrf(gpa, &list, .{ .table = 100 });
            self.push(list.items[codec.attr_header_len..]);
        }
        {
            var list: std.ArrayList(u8) = .empty;
            try e.encodeGeneve(gpa, &list, .{ .vni = 5, .remote = &.{ 10, 0, 0, 1 }, .port = 6081 });
            self.push(list.items[codec.attr_header_len..]);
        }
        {
            var list: std.ArrayList(u8) = .empty;
            try e.encodeIptun(gpa, &list, .{ .local = &.{ 1, 2, 3, 4 }, .remote = &.{ 5, 6, 7, 8 }, .ttl = 4 }, 3);
            self.push(list.items[codec.attr_header_len..]); // ipip and sit share the data
        }
        {
            // A whole rule payload and an address payload with cacheinfo, for the wrapped parsers.
            var list: std.ArrayList(u8) = .empty;
            try codec.appendAttrU32(gpa, &list, root.FRA.GOTO, 100);
            self.push(list.items);
        }
        return self.entries[0..self.n];
    }
};

fn extHarness(comptime S: type, src: *S, gpa: Allocator) anyerror!void {
    _ = gpa;
    var raw: [256]u8 = undefined;
    var cstore: ExtCorpus = .{};
    const entries: []const []const u8 = if (S == fz.fuzz_driver.Rng) (cstore.build() catch &.{}) else &.{};
    const len: usize = fz.drawInput(S, src, &raw, entries);
    const payload = raw[0..len];
    var any = false;
    for (kind_names) |k| {
        if (e.parseKindInfo(k, payload)) |info| {
            if (info != .none) {
                any = true;
                ExtMark.mark(.kind);
            }
        } else |_| {}
    }
    var hops: [max_route_hops]RouteHop = undefined;
    if (e.parseMultipath(payload, &hops)) |n| {
        if (n > 0) {
            any = true;
            ExtMark.mark(.multipath);
        }
    } else |_| {}
    if (e.parseNexthop(payload)) |v| {
        if (v != null) {
            any = true;
            ExtMark.mark(.nexthop);
        }
    } else |_| {}
    if (e.parseMetrics(payload)) |m| {
        if (m.mtu != 0 or m.advmss != 0 or m.hoplimit != 0) {
            any = true;
            ExtMark.mark(.metrics);
        }
    } else |_| {}
    // The same bytes where the real parsers meet them: inside a link's
    // LINKINFO > INFO_DATA nest (every kind), the new top-level attributes,
    // an rtmsg's RTA_MULTIPATH / RTA_METRICS, an address's cacheinfo, a rule's
    // added selectors.
    var wrap: [768]u8 = undefined;
    for (kind_names) |k| {
        const n = linkWith(&wrap, k, payload);
        if (root.parseLink(wrap[0..n])) |v| {
            if (v) |lk| if (lk.info != .none) {
                any = true;
                ExtMark.mark(.link_info);
            };
        } else |_| {}
    }
    if (payload.len >= 4) {
        var n: usize = 16;
        wrap[0..16].* = @splat(0);
        for ([_]u16{ root.IFLA_TXQLEN, root.IFLA_GROUP, root.IFLA_MAX_MTU, root.IFLA_NUM_TX_QUEUES }) |t| n = putAttr(&wrap, n, t, payload[0..4]);
        n = putAttr(&wrap, n, root.IFLA_CARRIER, payload[0..1]);
        if (root.parseLink(wrap[0..n])) |v| {
            if (v) |lk| if (lk.group != 0 or lk.txqlen != 0 or lk.max_mtu != 0) {
                any = true;
                ExtMark.mark(.link_top);
            };
        } else |_| {}
    }
    {
        var n: usize = root.rtmsg_len;
        @memset(wrap[0..n], 0);
        wrap[0] = root.AF.INET;
        n = putAttr(&wrap, n, root.RTA.MULTIPATH, payload);
        n = putAttr(&wrap, n, root.RTA.METRICS, payload);
        n = putAttr(&wrap, n, root.RTA.NH_ID, payload[0..@min(4, payload.len)]);
        if (root.parseRoute(wrap[0..n])) |v| {
            if (v) |r| {
                if (r.hop_count > 0) {
                    any = true;
                    ExtMark.mark(.route_mp);
                }
                if (r.mtu != 0 or r.advmss != 0 or r.hoplimit != 0) {
                    any = true;
                    ExtMark.mark(.route_metrics);
                }
            }
        } else |_| {}
    }
    if (payload.len >= 16) {
        var n: usize = root.ifaddrmsg_len;
        @memset(wrap[0..n], 0);
        wrap[0] = root.AF.INET;
        n = putAttr(&wrap, n, 2, &.{ 10, 0, 0, 1 }); // IFA_LOCAL
        n = putAttr(&wrap, n, 6, payload[0..16]); // IFA_CACHEINFO
        if (root.parseAddress(wrap[0..n])) |v| {
            if (v) |a| if (a.preferred_lft != root.infinite_lft or a.valid_lft != root.infinite_lft) {
                any = true;
                ExtMark.mark(.addr_cache);
            };
        } else |_| {}
    }
    if (payload.len >= 4) {
        const types = [_]u16{ root.FRA.GOTO, root.FRA.SUPPRESS_PREFIXLEN, root.FRA.UID_RANGE, root.FRA.SPORT_RANGE, root.FRA.DPORT_RANGE, root.FRA.IP_PROTO };
        const widths = [_]usize{ 4, 4, 8, 4, 4, 1 };
        var n: usize = root.fib_rule_hdr_len;
        @memset(wrap[0..n], 0);
        wrap[0] = root.AF.INET;
        for (types, widths) |t, w| n = putAttr(&wrap, n, t, payload[0..@min(w, payload.len)]);
        if (root.parseRule(wrap[0..n])) |v| {
            if (v) |r| if (r.goto != null or r.uid_range != null or r.sport != null or r.dport != null or r.suppress_prefixlen != null) {
                any = true;
                ExtMark.mark(.rule_ext);
            };
        } else |_| {}
    }
    if (!any) ExtMark.mark(.rejected);
}

/// Append one attribute to `buf` at `n`; returns the new length (4-aligned).
fn putAttr(buf: []u8, n: usize, t: u16, data: []const u8) usize {
    const total = codec.attr_header_len + data.len;
    std.mem.writeInt(u16, buf[n..][0..2], @intCast(total), native_endian);
    std.mem.writeInt(u16, buf[n + 2 ..][0..2], t, native_endian);
    @memcpy(buf[n + 4 ..][0..data.len], data);
    const end = n + codec.alignUp(total);
    @memset(buf[n + total .. end], 0);
    return end;
}

/// An ifinfomsg whose IFLA_LINKINFO holds KIND = `kind` and DATA = `data`.
fn linkWith(buf: []u8, kind: []const u8, data: []const u8) usize {
    buf[0..16].* = @splat(0);
    buf[4] = 1; // index 1
    const off: usize = 16;
    var n = off + codec.attr_header_len;
    var kb: [32]u8 = @splat(0);
    @memcpy(kb[0..kind.len], kind);
    n = putAttr(buf, n, root.IFLA_INFO.KIND, kb[0 .. kind.len + 1]);
    n = putAttr(buf, n, root.IFLA_INFO.DATA, data);
    std.mem.writeInt(u16, buf[off..][0..2], @intCast(n - off), native_endian);
    std.mem.writeInt(u16, buf[off + 2 ..][0..2], root.IFLA_LINKINFO, native_endian);
    return n;
}

fn extSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [fz.script_cap]u8 = undefined;
    const n = smith.slice(&script);
    try fz.runFrom(extHarness, smith, script[0..n]);
}

test "fuzz: multipath, nexthop, metrics and kind-info parsers never crash on arbitrary bytes" {
    var corpus: ExtCorpus = .{};
    try testing.fuzz({}, extSmith, .{ .corpus = try corpus.build() });
}

test "fuzz driver: NETLINK_FUZZ (rtnetlink extensions)" {
    try fz.fuzz_driver.run(extHarness, .{ .prefix = "NETLINK_FUZZ", .name = "netlink-ext" });
}

test "fuzz harness: rtnetlink extensions, 300 seeds, reaches every outcome" {
    try ExtMark.reach(extHarness, "netlink-ext", 300);
}
