// SPDX-License-Identifier: MIT

//! Tests added by the 2026-11-15 strict mutation re-audit: each pins a boundary,
//! an arm or an optional field that the 2026-10-04 run (and the tests then in
//! the module) did not observe. See SPEC.md § Mutation (2026-11-15).

const std = @import("std");
const testing = std.testing;
const caps = @import("caps.zig");
const codec = @import("netlink").codec;
const config = @import("config.zig");
const connect = @import("connect.zig");
const ie = @import("ie.zig");
const iface = @import("iface.zig");
const modes = @import("modes.zig");
const scan = @import("scan.zig");
const station = @import("station.zig");
const uapi = @import("uapi.zig");

const gpa = testing.allocator;

// ── capability decoders ─────────────────────────────────────────────────────

test "HT rxMcs covers MCS 0 to 76 and nothing past it" {
    var h: caps.HtCaps = .{};
    h.mcs_set = @splat(0xff);
    try testing.expect(h.rxMcs(0));
    try testing.expect(h.rxMcs(76));
    try testing.expect(!h.rxMcs(77));
}

test "VHT stream counts run 1 to 8; 0 and 9 are not stream counts" {
    var v: caps.VhtCaps = .{};
    v.mcs_set = @splat(0); // every stream: MCS 0-7
    try testing.expectEqual(@as(u8, 8), v.rxStreams());
    try testing.expectEqual(@as(?u8, 7), v.rxMaxMcs(8));
    try testing.expectEqual(@as(?u8, 7), v.rxMaxMcs(1));
    try testing.expectEqual(@as(?u8, null), v.rxMaxMcs(0));
    try testing.expectEqual(@as(?u8, null), v.rxMaxMcs(9));
    try testing.expectEqual(@as(?u8, null), v.txMaxMcs(9));
}

// ── information elements ────────────────────────────────────────────────────

test "ie: an extension element with a one-byte body has its id and an empty body" {
    var it: ie.Iterator = .{ .buf = &.{ 255, 1, 35 } };
    const e = (try it.next()).?;
    try testing.expectEqual(@as(?u8, 35), e.ext_id);
    try testing.expectEqual(@as(usize, 0), e.body.len);
}

test "ie.find / findExtension / findVendor pick the element they name and nothing else" {
    const ies = [_]u8{ 5, 1, 0xaa, 7, 1, 0xbb };
    try testing.expectEqualSlices(u8, &.{0xbb}, ie.find(&ies, 7).?);
    try testing.expectEqualSlices(u8, &.{0xaa}, ie.find(&ies, 5).?);
    // an extension element is not found by its outer id
    try testing.expect(ie.find(&.{ 255, 2, 35, 1 }, 255) == null);

    const exts = [_]u8{ 255, 2, 35, 0x11, 255, 2, 36, 0x22 };
    try testing.expectEqualSlices(u8, &.{0x22}, ie.findExtension(&exts, 36).?);
    try testing.expectEqualSlices(u8, &.{0x11}, ie.findExtension(&exts, 35).?);

    const oui: [3]u8 = .{ 0x00, 0x50, 0xf2 };
    // not a vendor element, though its body looks like one
    try testing.expect(ie.findVendor(&.{ 1, 5, 0x00, 0x50, 0xf2, 1, 0xaa }, oui, 1) == null);
    // a vendor element with exactly OUI + type has an empty payload, not "absent"
    try testing.expectEqual(@as(usize, 0), ie.findVendor(&.{ 221, 4, 0x00, 0x50, 0xf2, 1 }, oui, 1).?.len);
    // a vendor element too short to carry an OUI is skipped, not read past its end
    try testing.expect(ie.findVendor(&.{ 221, 2, 0x00, 0x50 }, oui, 1) == null);
}

test "parseRsn: every optional tail may be missing; the element ends where it ends" {
    const ccmp = [_]u8{ 0x00, 0x0f, 0xac, 0x04 };
    const psk = [_]u8{ 0x00, 0x0f, 0xac, 0x02 };
    var only_pairwise: [2 + 4 + 2 + 4]u8 = undefined;
    @memcpy(only_pairwise[0..2], &[_]u8{ 1, 0 });
    @memcpy(only_pairwise[2..6], &ccmp);
    @memcpy(only_pairwise[6..8], &[_]u8{ 1, 0 });
    @memcpy(only_pairwise[8..12], &ccmp);
    const r1 = try ie.parseRsn(&only_pairwise);
    try testing.expectEqual(@as(?u16, null), r1.capabilities);

    var with_akm: [only_pairwise.len + 2 + 4]u8 = undefined;
    @memcpy(with_akm[0..only_pairwise.len], &only_pairwise);
    @memcpy(with_akm[only_pairwise.len..][0..2], &[_]u8{ 1, 0 });
    @memcpy(with_akm[only_pairwise.len + 2 ..][0..4], &psk);
    const r2 = try ie.parseRsn(&with_akm);
    try testing.expect(r2.offersPsk());
    try testing.expectEqual(@as(?u16, null), r2.capabilities);
}

fn elem(list: *std.ArrayList(u8), id: u8, body: []const u8) !void {
    try list.append(gpa, id);
    try list.append(gpa, @intCast(body.len));
    try list.appendSlice(gpa, body);
}

test "summarize: the first of a repeated element wins, short bodies are skipped, HE needs its extension id" {
    var l: std.ArrayList(u8) = .empty;
    defer l.deinit(gpa);
    try elem(&l, ie.EID.EXTENDED_SUPPORTED_RATES, &.{ 1, 2 });
    try elem(&l, ie.EID.EXTENDED_SUPPORTED_RATES, &.{3});
    try elem(&l, ie.EID.DS_PARAMS, &.{6});
    try elem(&l, ie.EID.DS_PARAMS, &.{7});
    try elem(&l, ie.EID.ERP, &.{});
    try elem(&l, ie.EID.ERP, &.{0x05});
    try elem(&l, ie.EID.ERP, &.{0x09});
    try elem(&l, ie.EID.COUNTRY, &.{ 'U', 'S' });
    try elem(&l, ie.EID.COUNTRY, &.{ 'C', 'Z', ' ' });
    try elem(&l, ie.EID.COUNTRY, &.{ 'D', 'E', ' ' });
    var s = ie.summarize(l.items);
    try testing.expectEqualSlices(u8, &.{ 1, 2 }, s.extended_rates);
    try testing.expectEqual(@as(?u8, 6), s.ds_channel);
    try testing.expectEqual(@as(?u8, 5), s.erp);
    try testing.expectEqualStrings("CZ ", s.country.?);
    try testing.expect(!s.he);

    var h: std.ArrayList(u8) = .empty;
    defer h.deinit(gpa);
    try elem(&h, ie.EID.EXTENSION, &.{ie.EXT_EID.HE_CAPABILITY});
    s = ie.summarize(h.items);
    try testing.expect(s.he);
    var o: std.ArrayList(u8) = .empty;
    defer o.deinit(gpa);
    try elem(&o, ie.EID.EXTENSION, &.{ie.EXT_EID.HE_CAPABILITY +% 1});
    try testing.expect(!ie.summarize(o.items).he);

    // a WPA1 vendor element too short to parse flags the walk as truncated
    var w: std.ArrayList(u8) = .empty;
    defer w.deinit(gpa);
    try elem(&w, ie.EID.VENDOR_SPECIFIC, &.{ 0x00, 0x50, 0xf2, 0x01, 0xff });
    try testing.expect(ie.summarize(w.items).truncated);
}

// ── interface / station parsing ─────────────────────────────────────────────

test "iface.parse: a name of IFNAMSIZ-1 fits, IFNAMSIZ does not; an SSID of 32 fits, 33 does not" {
    var m: std.ArrayList(u8) = .empty;
    defer m.deinit(gpa);
    try codec.appendAttrString(gpa, &m, uapi.ATTR.IFNAME, "012345678901234");
    _ = try iface.parse(m.items);
    var bad: std.ArrayList(u8) = .empty;
    defer bad.deinit(gpa);
    try codec.appendAttrString(gpa, &bad, uapi.ATTR.IFNAME, "0123456789012345");
    try testing.expectError(error.BadLength, iface.parse(bad.items));

    var ok: std.ArrayList(u8) = .empty;
    defer ok.deinit(gpa);
    try codec.appendAttr(gpa, &ok, uapi.ATTR.SSID, &@as([32]u8, @splat('a')));
    _ = try iface.parse(ok.items);
    var over: std.ArrayList(u8) = .empty;
    defer over.deinit(gpa);
    try codec.appendAttr(gpa, &over, uapi.ATTR.SSID, &@as([33]u8, @splat('a')));
    try testing.expectError(error.BadLength, iface.parse(over.items));
}

test "station: 32-bit counters fill an absent 64-bit twin and never overwrite a present one" {
    var m: std.ArrayList(u8) = .empty;
    defer m.deinit(gpa);
    const n = try codec.nestBegin(gpa, &m, uapi.ATTR.STA_INFO);
    try codec.appendAttrU32(gpa, &m, uapi.STA_INFO.RX_BYTES, 1234);
    try codec.appendAttrU64(gpa, &m, uapi.STA_INFO.TX_BYTES64, 5_000_000_000);
    try codec.appendAttrU32(gpa, &m, uapi.STA_INFO.TX_BYTES, 77);
    try codec.nestEnd(&m, n);
    const s = try station.parse(m.items);
    try testing.expectEqual(@as(?u64, 1234), s.rx_bytes);
    try testing.expectEqual(@as(?u64, 5_000_000_000), s.tx_bytes);

    var m2: std.ArrayList(u8) = .empty;
    defer m2.deinit(gpa);
    const n2 = try codec.nestBegin(gpa, &m2, uapi.ATTR.STA_INFO);
    try codec.appendAttrU32(gpa, &m2, uapi.STA_INFO.TX_BYTES, 77);
    try codec.nestEnd(&m2, n2);
    try testing.expectEqual(@as(?u64, 77), (try station.parse(m2.items)).tx_bytes);
}

// ── request builders ────────────────────────────────────────────────────────

test "channel: the primary sits at an odd multiple of 10 MHz strictly inside the width" {
    const tgt: config.Target = .{ .ifindex = 3 };
    const ok40 = try config.buildSetChannel(gpa, 20, 1, tgt, .{ .freq_mhz = 5180, .width = .@"40", .center1_mhz = 5190 });
    gpa.free(ok40);
    try testing.expectError(error.InvalidRequest, config.buildSetChannel(gpa, 20, 1, tgt, .{ .freq_mhz = 5180, .width = .@"40", .center1_mhz = 5210 }));
    const ok80 = try config.buildSetChannel(gpa, 20, 1, tgt, .{ .freq_mhz = 5180, .width = .@"80", .center1_mhz = 5210 });
    gpa.free(ok80);
    try testing.expectError(error.InvalidRequest, config.buildSetChannel(gpa, 20, 1, tgt, .{ .freq_mhz = 5180, .width = .@"80", .center1_mhz = 5230 }));
}

test "new interface names are 1 to 15 bytes; set-interface needs a type or an option" {
    const ok = try config.buildNewInterfaceWith(gpa, 20, 1, 0, "012345678901234", .station, .{});
    gpa.free(ok);
    try testing.expectError(error.InvalidRequest, config.buildNewInterfaceWith(gpa, 20, 1, 0, "0123456789012345", .station, .{}));
    try testing.expectError(error.InvalidRequest, config.buildNewInterfaceWith(gpa, 20, 1, 0, "", .station, .{}));

    try testing.expectError(error.InvalidRequest, config.buildSetInterface(gpa, 20, 1, 3, null, .{}));
    const a = try config.buildSetInterface(gpa, 20, 1, 3, .station, .{});
    gpa.free(a);
    const b = try config.buildSetInterface(gpa, 20, 1, 3, null, .{ .monitor = .{ .fcsfail = true } });
    gpa.free(b);
    const c = try config.buildSetInterface(gpa, 20, 1, 3, null, .{ .four_addr = true });
    gpa.free(c);
}

test "passphrase characters run 0x20 to 0x7e; SSIDs and WEP key indices have their last valid value" {
    var out: [uapi.pmk_len]u8 = undefined;
    try connect.pmkFromPassphrase(&out, "pass word~", "net");
    try testing.expectError(error.InvalidPassphrase, connect.pmkFromPassphrase(&out, "pass\x1fword", "net"));
    try testing.expectError(error.InvalidPassphrase, connect.pmkFromPassphrase(&out, "pass\x7fword", "net"));
    try connect.pmkFromPassphrase(&out, "password", &@as([32]u8, @splat('s')));
    try testing.expectError(error.InvalidRequest, connect.pmkFromPassphrase(&out, "password", &@as([33]u8, @splat('s'))));

    const ssid32: [32]u8 = @splat('s');
    const ssid33: [33]u8 = @splat('s');
    const okc = try connect.buildConnect(gpa, 20, 1, connect.ConnectOptions.open(3, &ssid32));
    gpa.free(okc);
    try testing.expectError(error.InvalidRequest, connect.buildConnect(gpa, 20, 1, connect.ConnectOptions.open(3, &ssid33)));

    const key5 = [_]u8{ 1, 2, 3, 4, 5 };
    var opts = connect.ConnectOptions.open(3, "x");
    opts.wep_keys = &.{.{ .index = 3, .data = &key5 }};
    const okw = try connect.buildConnect(gpa, 20, 1, opts);
    gpa.free(okw);
    opts.wep_keys = &.{.{ .index = 4, .data = &key5 }};
    try testing.expectError(error.InvalidRequest, connect.buildConnect(gpa, 20, 1, opts));
}

fn hasAttr(bytes: []const u8, attr_type: u16) !bool {
    var it: codec.MessageIterator = .{ .buf = bytes };
    const m = (try it.next()).?;
    var ai = try m.attrs(4);
    while (try ai.next()) |a| if (a.type == attr_type) return true;
    return false;
}

test "connect: PREV_BSSID is sent exactly when set" {
    var opts = connect.ConnectOptions.open(3, "x");
    const without = try connect.buildConnect(gpa, 20, 1, opts);
    defer gpa.free(without);
    try testing.expect(!try hasAttr(without, uapi.ATTR.PREV_BSSID));
    opts.prev_bssid = .{ 1, 2, 3, 4, 5, 6 };
    const with = try connect.buildConnect(gpa, 20, 1, opts);
    defer gpa.free(with);
    try testing.expect(try hasAttr(with, uapi.ATTR.PREV_BSSID));
}

test "IBSS and mesh identifiers: 32 bytes fit, 33 do not" {
    const ch: config.Channel = .{ .freq_mhz = 2412 };
    const id32: [32]u8 = @splat('m');
    const id33: [33]u8 = @splat('m');
    const a = try modes.buildJoinIbss(gpa, 20, 1, .{ .ifindex = 3, .ssid = &id32, .channel = ch });
    gpa.free(a);
    try testing.expectError(error.InvalidRequest, modes.buildJoinIbss(gpa, 20, 1, .{ .ifindex = 3, .ssid = &id33, .channel = ch }));
    const b = try modes.buildJoinMesh(gpa, 20, 1, .{ .ifindex = 3, .mesh_id = &id32, .channel = ch });
    gpa.free(b);
    try testing.expectError(error.InvalidRequest, modes.buildJoinMesh(gpa, 20, 1, .{ .ifindex = 3, .mesh_id = &id33, .channel = ch }));
}

test "scan requests: SSID length 32 and the radio's SSID cap are inclusive limits" {
    const id32: []const u8 = &@as([32]u8, @splat('s'));
    const id33: []const u8 = &@as([33]u8, @splat('s'));
    const a = try scan.buildTriggerScan(gpa, 20, 1, .{ .ifindex = 3, .ssids = &.{id32} });
    gpa.free(a);
    try testing.expectError(error.InvalidRequest, scan.buildTriggerScan(gpa, 20, 1, .{ .ifindex = 3, .ssids = &.{id33} }));
    const two = try scan.buildTriggerScan(gpa, 20, 1, .{ .ifindex = 3, .ssids = &.{ "a", "b" }, .max_num_ssids = 2 });
    gpa.free(two);
    try testing.expectError(error.InvalidRequest, scan.buildTriggerScan(gpa, 20, 1, .{ .ifindex = 3, .ssids = &.{ "a", "b", "c" }, .max_num_ssids = 2 }));

    const s = try scan.buildStartSchedScan(gpa, 20, 1, .{ .ifindex = 3, .interval_ms = 1000, .ssids = &.{id32}, .match_ssids = &.{id32} });
    gpa.free(s);
    try testing.expectError(error.InvalidRequest, scan.buildStartSchedScan(gpa, 20, 1, .{ .ifindex = 3, .interval_ms = 1000, .ssids = &.{id33} }));
    try testing.expectError(error.InvalidRequest, scan.buildStartSchedScan(gpa, 20, 1, .{ .ifindex = 3, .interval_ms = 1000, .match_ssids = &.{id33} }));
    const two2 = try scan.buildStartSchedScan(gpa, 20, 1, .{ .ifindex = 3, .interval_ms = 1000, .ssids = &.{ "a", "b" }, .max_num_ssids = 2 });
    gpa.free(two2);
    try testing.expectError(error.InvalidRequest, scan.buildStartSchedScan(gpa, 20, 1, .{ .ifindex = 3, .interval_ms = 1000, .ssids = &.{ "a", "b", "c" }, .max_num_ssids = 2 }));
}
