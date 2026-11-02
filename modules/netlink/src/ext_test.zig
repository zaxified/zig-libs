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

// ── fuzz: the four new parsers ──────────────────────────────────────────────

const kind_names = [_][]const u8{ "vxlan", "macvlan", "ipvlan", "vrf", "bond", "bridge", "gre", "ipip", "geneve", "dummy" };

const ExtMark = fz.Marker(enum { rejected, kind, multipath, nexthop, metrics });

const ExtCorpus = struct {
    scratch: [4096]u8 = undefined,
    store: [2048]u8 = undefined,
    used: usize = 0,
    entries: [6][]const u8 = undefined,
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
    if (!any) ExtMark.mark(.rejected);
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
