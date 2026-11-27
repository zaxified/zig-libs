// SPDX-License-Identifier: MIT
//! Killing tests of the 2026-11-25 delta mutation run (LLDP org TLV adders and decoders, DHCPv4
//! RFC 3396 helpers, DHCPv6 vendorOpts).
const std = @import("std");
const testing = std.testing;
const lldp = @import("lldp.zig");
const dhcp = @import("dhcp.zig");
const dhcp6 = @import("dhcp6.zig");

/// The org TLV a fresh builder wrote (`b.pos` bytes: 2 header bytes, then the value).
fn org(buf: []const u8, end: usize) !lldp.OrgSpecific {
    return lldp.OrgSpecific.parse(buf[2..end]);
}

fn hexb(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "mutation 2026-11-25: EVB decodes subtype 0 only, Cisco PoE needs a byte and roundtrips through its adder" {
    var buf: [64]u8 = undefined;
    var b = lldp.Builder.init(&buf);
    try b.addOrgSpecific(lldp.oui_ieee_8021qbg, 1, &hexb("00c3008300200010" ++ "11"));
    try testing.expect((try org(&buf, b.pos)).decode() == null);
    b = lldp.Builder.init(&buf);
    try b.addOrgSpecific(lldp.oui_cisco, 1, &.{});
    try testing.expect((try org(&buf, b.pos)).decode() == null);
    b = lldp.Builder.init(&buf);
    const poe: lldp.CiscoPoe = .{ .pse_four_wire = false, .pd_spare_pair_shared = true, .pd_request_spare_pair = false, .pse_spare_pair_on = true };
    try b.addCiscoPoe(poe);
    try testing.expectEqualDeep(lldp.OrgValue{ .cisco_poe = poe }, (try org(&buf, b.pos)).decode().?);
}

test "mutation 2026-11-25: Profinet PTCP status keeps each period word and flag apart" {
    var buf: [128]u8 = undefined;
    const base: lldp.ProfinetPtcpStatus = .{
        .master_address = @splat(1),
        .subdomain_uuid = @splat(2),
        .ir_data_uuid = @splat(3),
        .period_valid = false,
        .period_length = 0x40000000,
        .red_period_valid = true,
        .red_period_begin = 0x7fffffff,
        .orange_period_valid = true,
        .orange_period_begin = 5,
        .green_period_valid = false,
        .green_period_begin = 7,
    };
    var b = lldp.Builder.init(&buf);
    try b.addProfinetPtcpStatus(base);
    try testing.expectEqualDeep(lldp.OrgValue{ .profinet_ptcp_status = base }, (try org(&buf, b.pos)).decode().?);
    var two = base;
    two.period_valid = true;
    two.period_length = 1;
    two.red_period_valid = false;
    two.orange_period_valid = false;
    two.green_period_valid = false;
    two.green_period_begin = 0x7fffffff;
    b = lldp.Builder.init(&buf);
    try b.addProfinetPtcpStatus(two);
    try testing.expectEqualDeep(lldp.OrgValue{ .profinet_ptcp_status = two }, (try org(&buf, b.pos)).decode().?);
}

test "mutation 2026-11-25: DCBX ETS max_tcs uses three bits, the CBS flag round-trips, EVB needs nine bytes" {
    var info: [21]u8 = @splat(0);
    info[0] = 0x07;
    try testing.expectEqual(@as(u3, 7), lldp.EtsConfig.parse(&info).?.max_tcs);
    var buf: [64]u8 = undefined;
    var b = lldp.Builder.init(&buf);
    const e: lldp.EtsConfig = .{ .willing = false, .cbs = true, .max_tcs = 5, .priority_to_tc = @splat(3), .tc_bandwidth = @splat(12), .tsa = @splat(2) };
    try b.addEtsConfig(e);
    try testing.expectEqualDeep(lldp.OrgValue{ .ets_config = e }, (try org(&buf, b.pos)).decode().?);
    const eight: [8]u8 = @splat(0);
    try testing.expect(lldp.Evb.parse(&eight) == null);
}

test "mutation 2026-11-25: addMedCoordinate accepts the exact latitude and longitude limits, addMedCivic the exact edges" {
    var buf: [600]u8 = undefined;
    const lat_limit: i34 = 90 << 25;
    const lon_limit: i34 = 180 << 25;
    const edges = [_][2]i34{ .{ lat_limit, lon_limit }, .{ -lat_limit, -lon_limit } };
    for (edges) |e| {
        var b = lldp.Builder.init(&buf);
        try b.addMedCoordinate(.{ .lat_resolution = 34, .lat = e[0], .lon_resolution = 34, .lon = e[1], .altitude_type = 0, .alt_resolution = 0, .alt = 0, .datum = 1 });
    }
    var b = lldp.Builder.init(&buf);
    try testing.expectError(lldp.BuildError.InvalidValue, b.addMedCoordinate(.{ .lat_resolution = 34, .lat = lat_limit + 1, .lon_resolution = 34, .lon = 0, .altitude_type = 0, .alt_resolution = 0, .alt = 0, .datum = 1 }));
    try testing.expectError(lldp.BuildError.InvalidValue, b.addMedCoordinate(.{ .lat_resolution = 34, .lat = -lat_limit - 1, .lon_resolution = 34, .lon = 0, .altitude_type = 0, .alt_resolution = 0, .alt = 0, .datum = 1 }));
    try testing.expectError(lldp.BuildError.InvalidValue, b.addMedCoordinate(.{ .lat_resolution = 34, .lat = 0, .lon_resolution = 34, .lon = lon_limit + 1, .altitude_type = 0, .alt_resolution = 0, .alt = 0, .datum = 1 }));
    try testing.expectError(lldp.BuildError.InvalidValue, b.addMedCoordinate(.{ .lat_resolution = 34, .lat = 0, .lon_resolution = 34, .lon = -lon_limit - 1, .altitude_type = 0, .alt_resolution = 0, .alt = 0, .datum = 1 }));
    // country letters A..Z inclusive
    b = lldp.Builder.init(&buf);
    try b.addMedCivic(0, "AZ".*, &.{});
    try b.addMedCivic(0, "ZA".*, &.{});
    // an element that makes the LCI exactly 256 bytes long is the last one that fits
    const value: [250]u8 = @splat('x');
    b = lldp.Builder.init(&buf);
    try b.addMedCivic(2, "CZ".*, &.{.{ .ca_type = 6, .value = &value }});
    b = lldp.Builder.init(&buf);
    try testing.expectError(lldp.BuildError.InvalidValue, b.addMedCivic(2, "CZ".*, &.{.{ .ca_type = 6, .value = value[0..] ++ "x" }}));
}

test "mutation 2026-11-25: DHCPv4 isFragmented, concatOption and addLongOption at their exact bounds" {
    var buf: [1100]u8 = undefined;
    // one valid instance of 119 followed by a truncated option: one instance is not fragmented
    var b = try dhcp.Builder.init(&buf, .{ .op = .boot_reply, .xid = 1 });
    try b.addOption(119, "abc");
    try b.addOption(119, "");
    const len = (try b.finish(.{})).len;
    const m = try dhcp.Message.parse(buf[0..len]);
    var out3: [3]u8 = undefined;
    try testing.expectEqualStrings("abc", (try m.concatOption(119, &out3)).?);
    // one valid instance in the options field, then a truncated option in the overloaded `file` field
    b = try dhcp.Builder.init(&buf, .{ .op = .boot_reply, .xid = 2 });
    try b.addOption(119, "abc");
    try b.addOption(@backingInt(dhcp.OptionCode.option_overload), &.{1});
    const one_len = (try b.finish(.{})).len;
    buf[234..236].* = .{ 119, 9 };
    const trunc = try dhcp.Message.parse(buf[0..one_len]);
    try testing.expect(!trunc.isFragmented(119));
    // a long option fills the buffer exactly and fails atomically one byte short
    const probe = try dhcp.Builder.init(&buf, .{ .op = .boot_reply, .xid = 3 });
    const start = probe.pos;
    const data: [510]u8 = @splat(7);
    var exact: [2000]u8 = undefined;
    var fit = try dhcp.Builder.init(exact[0 .. start + 510 + 4], .{ .op = .boot_reply, .xid = 3 });
    try fit.addLongOption(119, &data);
    var tight = try dhcp.Builder.init(exact[0 .. start + 510 + 3], .{ .op = .boot_reply, .xid = 3 });
    const before = tight.pos;
    try testing.expectError(dhcp.BuildError.BufferTooSmall, tight.addLongOption(119, &data));
    try testing.expectEqual(before, tight.pos);
}

test "mutation 2026-11-25: DHCPv6 vendorOpts skips other options and is terminal after a short vendor option" {
    const hp = struct {
        fn f(comptime s: []const u8) *const [s.len / 2]u8 {
            const v = comptime hexb(s);
            return &v;
        }
    }.f;
    const m = try dhcp6.Message.parse(hp("01000000" ++ "00010004aabbccdd" ++ "00110004" ++ "00000137"));
    var it = m.vendorOpts();
    try testing.expectEqual(@as(u32, 311), (try it.next()).?.enterprise);
    try testing.expect((try it.next()) == null);
    const bad = try dhcp6.Message.parse(hp("01000000" ++ "00110003" ++ "000001" ++ "00110004" ++ "00000137"));
    var bit = bad.vendorOpts();
    try testing.expectError(error.BadOptionLength, bit.next());
    try testing.expect((try bit.next()) == null);
}
