// SPDX-License-Identifier: MIT
//! `NL80211_CMD_GET_STATION` decoding — per-peer link statistics from the
//! nested `NL80211_ATTR_STA_INFO`, including the doubly-nested
//! `NL80211_RATE_INFO_*` bitrate descriptions.
//!
//! On a managed (client) interface the station dump has exactly one entry: the
//! AP. On an AP or mesh interface it has one per associated peer.
//!
//! Two things here are easy to get wrong and are handled explicitly:
//!
//! * **32-bit counters were superseded by 64-bit ones.** The kernel sends both
//!   `RX_BYTES` (u32, wrapping) and `RX_BYTES64` (u64) when it can. This
//!   decoder prefers the 64-bit attribute and falls back to the 32-bit one, so
//!   a caller never silently reads a wrapped byte count.
//! * **Bitrate is not one field.** `RATE_INFO_BITRATE` is a u16 in 100 kbit/s
//!   units and saturates at 6553.5 Mbit/s; `RATE_INFO_BITRATE32` is the u32
//!   replacement. `RateInfo.kilobitsPerSecond` prefers the 32-bit one.
//!
//! Decoding one station allocates nothing; only the list a dump returns is
//! allocated.

const std = @import("std");
const netlink = @import("netlink");
const codec = netlink.codec;
const genl = @import("genetlink");
const uapi = @import("uapi.zig");

pub const Error = codec.Error;

/// Build a `NL80211_CMD_GET_STATION` request: a dump of every peer when `mac`
/// is null (`iw dev <dev> station dump`), or one peer otherwise (what
/// `iw dev <dev> link` sends after learning the BSSID).
pub fn buildGetStation(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    ifindex: u32,
    mac: ?uapi.Mac,
) std.mem.Allocator.Error![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    var flags = codec.NLM_F_REQUEST | codec.NLM_F_ACK;
    if (mac == null) flags |= codec.NLM_F_DUMP;
    const hdr = try codec.appendHeader(gpa, &list, family_id, flags, seq, 0);
    try genl.appendHeader(gpa, &list, uapi.CMD.GET_STATION, uapi.family_version);
    try codec.appendAttrU32(gpa, &list, uapi.ATTR.IFINDEX, ifindex);
    if (mac) |m| codec.appendAttr(gpa, &list, uapi.ATTR.MAC, &m) catch |e| switch (e) {
        error.AttrTooLong => unreachable, // 6 bytes
        error.OutOfMemory => return error.OutOfMemory,
    };
    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

/// Modulation width reported inside a `RATE_INFO` nest. The kernel encodes it
/// as a set of flag attributes rather than a number.
pub const RateWidth = enum {
    /// No width flag present — 20 MHz (or a legacy rate).
    default_20,
    mhz_5,
    mhz_10,
    mhz_40,
    mhz_80,
    mhz_80p80,
    mhz_160,
    mhz_320,

    pub fn megahertz(w: RateWidth) u16 {
        return switch (w) {
            .default_20 => 20,
            .mhz_5 => 5,
            .mhz_10 => 10,
            .mhz_40 => 40,
            .mhz_80, .mhz_80p80 => 80,
            .mhz_160 => 160,
            .mhz_320 => 320,
        };
    }
};

/// A decoded `NL80211_ATTR_STA_INFO` → `TX_BITRATE`/`RX_BITRATE` nest.
pub const RateInfo = struct {
    /// `RATE_INFO_BITRATE`, 100 kbit/s units, saturating.
    bitrate_100kbps: ?u16 = null,
    /// `RATE_INFO_BITRATE32`, 100 kbit/s units, non-saturating.
    bitrate32_100kbps: ?u32 = null,
    /// HT MCS index.
    mcs: ?u8 = null,
    vht_mcs: ?u8 = null,
    vht_nss: ?u8 = null,
    he_mcs: ?u8 = null,
    he_nss: ?u8 = null,
    he_gi: ?u8 = null,
    eht_mcs: ?u8 = null,
    eht_nss: ?u8 = null,
    short_gi: bool = false,
    width: RateWidth = .default_20,

    /// The link rate in kbit/s, preferring the non-saturating 32-bit field.
    pub fn kilobitsPerSecond(r: RateInfo) ?u32 {
        // `b * 100` overflows `u32` for `b >= 42_949_673`; the kernel does not
        // bound `BITRATE32`, so hostile or corrupted wire data can hit it.
        // Saturate rather than wrap or panic: a link rate over ~4.3 Tbit/s is
        // never real, so clamping to `maxInt(u32)` kbit/s preserves "absurdly
        // fast" without aborting the process on decoded wire data.
        if (r.bitrate32_100kbps) |b| return b *| 100;
        if (r.bitrate_100kbps) |b| return @as(u32, b) *| 100;
        return null;
    }
};

/// Decode one `RATE_INFO` nest.
pub fn parseRateInfo(nest: []const u8) Error!RateInfo {
    var r: RateInfo = .{};
    var it: codec.AttrIterator = .{ .buf = nest };
    while (try it.next()) |a| switch (a.type) {
        uapi.RATE_INFO.BITRATE => r.bitrate_100kbps = try a.asU16(),
        uapi.RATE_INFO.BITRATE32 => r.bitrate32_100kbps = try a.asU32(),
        uapi.RATE_INFO.MCS => r.mcs = try a.asU8(),
        uapi.RATE_INFO.VHT_MCS => r.vht_mcs = try a.asU8(),
        uapi.RATE_INFO.VHT_NSS => r.vht_nss = try a.asU8(),
        uapi.RATE_INFO.HE_MCS => r.he_mcs = try a.asU8(),
        uapi.RATE_INFO.HE_NSS => r.he_nss = try a.asU8(),
        uapi.RATE_INFO.HE_GI => r.he_gi = try a.asU8(),
        uapi.RATE_INFO.EHT_MCS => r.eht_mcs = try a.asU8(),
        uapi.RATE_INFO.EHT_NSS => r.eht_nss = try a.asU8(),
        uapi.RATE_INFO.SHORT_GI => r.short_gi = true,
        uapi.RATE_INFO.@"5_MHZ_WIDTH" => r.width = .mhz_5,
        uapi.RATE_INFO.@"10_MHZ_WIDTH" => r.width = .mhz_10,
        uapi.RATE_INFO.@"40_MHZ_WIDTH" => r.width = .mhz_40,
        uapi.RATE_INFO.@"80_MHZ_WIDTH" => r.width = .mhz_80,
        uapi.RATE_INFO.@"80P80_MHZ_WIDTH" => r.width = .mhz_80p80,
        uapi.RATE_INFO.@"160_MHZ_WIDTH" => r.width = .mhz_160,
        uapi.RATE_INFO.@"320_MHZ_WIDTH" => r.width = .mhz_320,
        else => {},
    };
    return r;
}

/// One peer's link statistics.
pub const Station = struct {
    ifindex: ?u32 = null,
    mac: ?uapi.Mac = null,
    generation: ?u32 = null,

    rx_bytes: ?u64 = null,
    tx_bytes: ?u64 = null,
    rx_packets: ?u32 = null,
    tx_packets: ?u32 = null,
    tx_retries: ?u32 = null,
    tx_failed: ?u32 = null,
    rx_drop_misc: ?u64 = null,
    beacon_loss: ?u32 = null,
    beacon_rx: ?u64 = null,

    /// Last measured signal, dBm.
    signal_dbm: ?i8 = null,
    /// Running average signal, dBm.
    signal_avg_dbm: ?i8 = null,
    beacon_signal_avg_dbm: ?i8 = null,

    tx_bitrate: ?RateInfo = null,
    rx_bitrate: ?RateInfo = null,

    /// Seconds since association.
    connected_time_s: ?u32 = null,
    /// Milliseconds since the last frame from this peer.
    inactive_time_ms: ?u32 = null,
    /// The driver's estimate of usable throughput, kbit/s.
    expected_throughput_kbps: ?u32 = null,
    rx_duration_us: ?u64 = null,
    tx_duration_us: ?u64 = null,

    /// Signal in dBm, preferring the average when a spot value is missing.
    pub fn bestSignalDbm(s: Station) ?i8 {
        return s.signal_dbm orelse s.signal_avg_dbm;
    }
};

/// Decode one `NL80211_CMD_NEW_STATION` message's attribute bytes.
pub fn parse(attr_bytes: []const u8) Error!Station {
    var out: Station = .{};
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.ATTR.IFINDEX => out.ifindex = try a.asU32(),
        uapi.ATTR.GENERATION => out.generation = try a.asU32(),
        uapi.ATTR.MAC => {
            if (a.data.len != 6) return error.BadLength;
            out.mac = a.data[0..6].*;
        },
        uapi.ATTR.STA_INFO => try parseStaInfo(a.data, &out),
        else => {},
    };
    return out;
}

fn parseStaInfo(nest: []const u8, out: *Station) Error!void {
    var it: codec.AttrIterator = .{ .buf = nest };
    while (try it.next()) |a| switch (a.type) {
        // 32-bit counters: only used when the 64-bit twin is absent, so a
        // wrapped value never overwrites a good one.
        uapi.STA_INFO.RX_BYTES => if (out.rx_bytes == null) {
            out.rx_bytes = try a.asU32();
        },
        uapi.STA_INFO.TX_BYTES => if (out.tx_bytes == null) {
            out.tx_bytes = try a.asU32();
        },
        uapi.STA_INFO.RX_BYTES64 => out.rx_bytes = try asU64(a),
        uapi.STA_INFO.TX_BYTES64 => out.tx_bytes = try asU64(a),
        uapi.STA_INFO.RX_PACKETS => out.rx_packets = try a.asU32(),
        uapi.STA_INFO.TX_PACKETS => out.tx_packets = try a.asU32(),
        uapi.STA_INFO.TX_RETRIES => out.tx_retries = try a.asU32(),
        uapi.STA_INFO.TX_FAILED => out.tx_failed = try a.asU32(),
        uapi.STA_INFO.RX_DROP_MISC => out.rx_drop_misc = try asU64(a),
        uapi.STA_INFO.BEACON_LOSS => out.beacon_loss = try a.asU32(),
        uapi.STA_INFO.BEACON_RX => out.beacon_rx = try asU64(a),
        uapi.STA_INFO.SIGNAL => out.signal_dbm = try asI8(a),
        uapi.STA_INFO.SIGNAL_AVG => out.signal_avg_dbm = try asI8(a),
        uapi.STA_INFO.BEACON_SIGNAL_AVG => out.beacon_signal_avg_dbm = try asI8(a),
        uapi.STA_INFO.TX_BITRATE => out.tx_bitrate = try parseRateInfo(a.data),
        uapi.STA_INFO.RX_BITRATE => out.rx_bitrate = try parseRateInfo(a.data),
        uapi.STA_INFO.CONNECTED_TIME => out.connected_time_s = try a.asU32(),
        uapi.STA_INFO.INACTIVE_TIME => out.inactive_time_ms = try a.asU32(),
        uapi.STA_INFO.EXPECTED_THROUGHPUT => out.expected_throughput_kbps = try a.asU32(),
        uapi.STA_INFO.RX_DURATION => out.rx_duration_us = try asU64(a),
        uapi.STA_INFO.TX_DURATION => out.tx_duration_us = try asU64(a),
        else => {},
    };
}

fn asU64(a: codec.Attr) Error!u64 {
    if (a.data.len != 8) return error.BadLength;
    return std.mem.readInt(u64, a.data[0..8], .little);
}

/// The kernel writes signal strengths as a single signed byte (`s8`).
fn asI8(a: codec.Attr) Error!i8 {
    if (a.data.len != 1) return error.BadLength;
    return @bitCast(a.data[0]);
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

fn wrapNest(gpa: std.mem.Allocator, list: *std.ArrayList(u8), t: u16, inner: []const u8) !void {
    const off = try codec.nestBegin(gpa, list, t);
    try list.appendSlice(gpa, inner);
    codec.nestEnd(list, off);
}

test "parseRateInfo: VHT-MCS 2, NSS 1, 80 MHz, short GI (the captured shape)" {
    // The bytes the kernel sent for this machine's rx bitrate, with the
    // attribute order preserved.
    const raw = [_]u8{
        0x08, 0x00, 0x05, 0x00, 0xd0, 0x03, 0x00, 0x00, // BITRATE32 = 976
        0x06, 0x00, 0x01, 0x00, 0xd0, 0x03, 0x00, 0x00, // BITRATE = 976
        0x04, 0x00, 0x08, 0x00, // 80 MHz width (flag)
        0x05, 0x00, 0x06, 0x00, 0x02, 0x00, 0x00, 0x00, // VHT_MCS = 2
        0x05, 0x00, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, // VHT_NSS = 1
        0x04, 0x00, 0x04, 0x00, // SHORT_GI (flag)
    };
    const r = try parseRateInfo(&raw);
    try testing.expectEqual(@as(?u32, 97_600), r.kilobitsPerSecond()); // 97.6 Mbit/s
    try testing.expectEqual(@as(?u8, 2), r.vht_mcs);
    try testing.expectEqual(@as(?u8, 1), r.vht_nss);
    try testing.expect(r.short_gi);
    try testing.expectEqual(RateWidth.mhz_80, r.width);
    try testing.expectEqual(@as(u16, 80), r.width.megahertz());
}

test "parseRateInfo prefers BITRATE32 over the saturating u16" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    const gpa = testing.allocator;
    // u16 saturated at 65535 (6553.5 Mbit/s), u32 says 120000 (12 Gbit/s).
    try codec.appendAttrU16(gpa, &buf, uapi.RATE_INFO.BITRATE, 65535);
    try codec.appendAttrU32(gpa, &buf, uapi.RATE_INFO.BITRATE32, 120_000);
    const r = try parseRateInfo(buf.items);
    try testing.expectEqual(@as(?u32, 12_000_000), r.kilobitsPerSecond());
}

test "parse: 64-bit counters win over the 32-bit ones regardless of order" {
    const gpa = testing.allocator;
    for ([_]bool{ false, true }) |wide_first| {
        var info: std.ArrayList(u8) = .empty;
        defer info.deinit(gpa);
        if (wide_first) {
            try codec.appendAttr(gpa, &info, uapi.STA_INFO.RX_BYTES64, &.{ 0x32, 0xe0, 0x84, 0xe5, 0x07, 0, 0, 0 });
            try codec.appendAttrU32(gpa, &info, uapi.STA_INFO.RX_BYTES, 0xe584_e032);
        } else {
            try codec.appendAttrU32(gpa, &info, uapi.STA_INFO.RX_BYTES, 0xe584_e032);
            try codec.appendAttr(gpa, &info, uapi.STA_INFO.RX_BYTES64, &.{ 0x32, 0xe0, 0x84, 0xe5, 0x07, 0, 0, 0 });
        }
        var msg: std.ArrayList(u8) = .empty;
        defer msg.deinit(gpa);
        try wrapNest(gpa, &msg, uapi.ATTR.STA_INFO, info.items);

        const s = try parse(msg.items);
        try testing.expectEqual(@as(?u64, 33_915_461_682), s.rx_bytes);
    }
}

test "parse: signal strengths are signed bytes" {
    const gpa = testing.allocator;
    var info: std.ArrayList(u8) = .empty;
    defer info.deinit(gpa);
    try codec.appendAttrU8(gpa, &info, uapi.STA_INFO.SIGNAL, 0xaf); // -81
    try codec.appendAttrU8(gpa, &info, uapi.STA_INFO.SIGNAL_AVG, 0xb0); // -80
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(gpa);
    try wrapNest(gpa, &msg, uapi.ATTR.STA_INFO, info.items);

    const s = try parse(msg.items);
    try testing.expectEqual(@as(?i8, -81), s.signal_dbm);
    try testing.expectEqual(@as(?i8, -80), s.signal_avg_dbm);
    try testing.expectEqual(@as(?i8, -81), s.bestSignalDbm());
}

test "parse: malformed nests yield typed errors" {
    const gpa = testing.allocator;
    // STA_INFO whose inner TLV is truncated.
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(gpa);
    try wrapNest(gpa, &msg, uapi.ATTR.STA_INFO, &.{ 0x40, 0x00, 0x02, 0x00, 0x01 });
    try testing.expectError(error.Truncated, parse(msg.items));

    // RX_BYTES64 with the wrong width.
    var msg2: std.ArrayList(u8) = .empty;
    defer msg2.deinit(gpa);
    var info: std.ArrayList(u8) = .empty;
    defer info.deinit(gpa);
    try codec.appendAttrU32(gpa, &info, uapi.STA_INFO.RX_BYTES64, 7);
    try wrapNest(gpa, &msg2, uapi.ATTR.STA_INFO, info.items);
    try testing.expectError(error.BadLength, parse(msg2.items));

    // A nested rate-info attribute that lies about its length.
    var msg3: std.ArrayList(u8) = .empty;
    defer msg3.deinit(gpa);
    var info3: std.ArrayList(u8) = .empty;
    defer info3.deinit(gpa);
    try codec.appendAttr(gpa, &info3, uapi.STA_INFO.TX_BITRATE, &.{ 0xff, 0x00, 0x01, 0x00 });
    try wrapNest(gpa, &msg3, uapi.ATTR.STA_INFO, info3.items);
    try testing.expectError(error.Truncated, parse(msg3.items));
}

test "parse: an empty station is valid (all fields absent)" {
    const s = try parse(&.{});
    try testing.expectEqual(@as(?u64, null), s.rx_bytes);
    try testing.expectEqual(@as(?i8, null), s.bestSignalDbm());
    try testing.expectEqual(@as(?RateInfo, null), s.tx_bitrate);
}

test "fuzz: station parse never crashes" {
    try testing.fuzz({}, fuzzParse, .{});
}

fn fuzzParse(_: void, smith: *std.testing.Smith) !void {
    var raw: [512]u8 = undefined;
    smith.bytes(&raw);
    const len = smith.valueRangeAtMost(u16, 0, raw.len);
    // Also exercise the accessors, not just the parse — `kilobitsPerSecond`
    // (P-18) is where the previous integer-overflow panic lived, and a
    // fuzz harness that only calls `parse`/`parseRateInfo` walks right past
    // it, per the finding.
    if (parse(raw[0..len])) |s| {
        std.mem.doNotOptimizeAway(&s);
        if (s.tx_bitrate) |r| std.mem.doNotOptimizeAway(r.kilobitsPerSecond());
        if (s.rx_bitrate) |r| std.mem.doNotOptimizeAway(r.kilobitsPerSecond());
    } else |_| {}
    if (parseRateInfo(raw[0..len])) |r| {
        std.mem.doNotOptimizeAway(&r);
        std.mem.doNotOptimizeAway(r.kilobitsPerSecond());
    } else |_| {}
}

// P-18: `BITRATE32 >= 42_949_673` made `b * 100` overflow a `u32` and abort
// the process (Debug/ReleaseSafe) or wrap silently (ReleaseFast). This is
// decoded wire data with no kernel-side range check, so it is attacker/
// corruption-reachable. Same defect class as W2-01 (CRIT), differing only
// in exposure.
test "kilobitsPerSecond saturates instead of overflowing on a hostile BITRATE32" {
    const r: RateInfo = .{ .bitrate32_100kbps = 42_949_673 };
    try testing.expectEqual(@as(?u32, std.math.maxInt(u32)), r.kilobitsPerSecond());

    // One below the threshold still overflows the naive `* 100`, so pin it
    // too: `42_949_672 * 100 == 4_294_967_200`, which fits `u32`
    // (`maxInt(u32) == 4_294_967_295`) — the true boundary.
    const r2: RateInfo = .{ .bitrate32_100kbps = 42_949_672 };
    try testing.expectEqual(@as(?u32, 4_294_967_200), r2.kilobitsPerSecond());
}
