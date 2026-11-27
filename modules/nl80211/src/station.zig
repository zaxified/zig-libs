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
// Test-only (`build.zig`'s `test_deps`, never `deps`): the fuzz corpus seed
// helpers, in the format `std.testing.Smith` actually reads.
const testkit = @import("testkit");

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

/// Radio chains the per-chain signal arrays keep (the kernel's
/// `IEEE80211_MAX_CHAINS` is 4).
pub const max_chains = 8;

/// `STA_INFO.BSS_PARAM`: the flags and timing of the BSS a station is part of.
pub const BssParam = struct {
    cts_protection: bool = false,
    short_preamble: bool = false,
    short_slot_time: bool = false,
    dtim_period: u8 = 0,
    beacon_interval_tu: u16 = 0,
};

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

    /// Per-chain signal, dBm, in chain order (`STA_INFO.CHAIN_SIGNAL`); read
    /// through `chainSignals`. Chains past `max_chains` are dropped.
    chain_signal_buf: [max_chains]i8 = @splat(0),
    n_chain_signal: u8 = 0,
    chain_signal_avg_buf: [max_chains]i8 = @splat(0),
    n_chain_signal_avg: u8 = 0,
    /// The AP's basic parameters as the station sees them (`STA_INFO.BSS_PARAM`).
    bss_param: ?BssParam = null,
    /// Multi-link operation: the link this entry describes and the peer MLD's
    /// address (top-level attributes of the station message).
    mlo_link_id: ?u8 = null,
    mld_addr: ?uapi.Mac = null,

    /// Per-chain signal, dBm.
    pub fn chainSignals(s: *const Station) []const i8 {
        return s.chain_signal_buf[0..s.n_chain_signal];
    }

    /// Per-chain running average, dBm.
    pub fn chainSignalsAvg(s: *const Station) []const i8 {
        return s.chain_signal_avg_buf[0..s.n_chain_signal_avg];
    }

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
        uapi.ATTR.MLO_LINK_ID => out.mlo_link_id = try a.asU8(),
        uapi.ATTR.MLD_ADDR => {
            if (a.data.len != 6) return error.BadLength;
            out.mld_addr = a.data[0..6].*;
        },
        else => {},
    };
    return out;
}

/// Per-TID counters of one peer (`STA_INFO.TID_STATS`), including the
/// driver's per-TID transmit queue (`txq`). Every field is null when the
/// driver does not report it.
pub const TidStats = struct {
    /// The traffic identifier, 0..16 (16 is the non-QoS / management slot).
    tid: u8 = 0,
    rx_msdu: ?u64 = null,
    tx_msdu: ?u64 = null,
    tx_msdu_retries: ?u64 = null,
    tx_msdu_failed: ?u64 = null,
    txq: ?TxqStats = null,
};

/// `TID_STATS.TXQ_STATS`: the intermediate transmit queue of one TID.
pub const TxqStats = struct {
    backlog_bytes: ?u32 = null,
    backlog_packets: ?u32 = null,
    flows: ?u32 = null,
    drops: ?u32 = null,
    ecn_marks: ?u32 = null,
    overlimit: ?u32 = null,
    overmemory: ?u32 = null,
    collisions: ?u32 = null,
    tx_bytes: ?u32 = null,
    tx_packets: ?u32 = null,
    max_flows: ?u32 = null,
};

/// Most TIDs one peer reports: 0..15 plus the management slot.
pub const max_tids = 17;

/// Decode `STA_INFO.TID_STATS` of one station message into `out`, in the order
/// the kernel sent them, and return how many entries it holds. Kept apart from
/// `parse` because a full table is ~3 KiB a peer and most callers never ask for
/// it; more entries than `out` holds are dropped. Entries whose TID is out of
/// range are skipped.
pub fn parseTidStats(attr_bytes: []const u8, out: []TidStats) Error!usize {
    var n: usize = 0;
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| {
        if (a.type != uapi.ATTR.STA_INFO) continue;
        var inner: codec.AttrIterator = .{ .buf = a.data };
        while (try inner.next()) |s| {
            if (s.type != uapi.STA_INFO.TID_STATS) continue;
            var tids: codec.AttrIterator = .{ .buf = s.data };
            while (try tids.next()) |t| {
                // The nest's type is the TID plus one.
                if (t.type == 0 or t.type > max_tids) continue;
                if (n >= out.len) return n;
                out[n] = try parseOneTid(@intCast(t.type - 1), t.data);
                n += 1;
            }
        }
    }
    return n;
}

fn parseOneTid(tid: u8, nest: []const u8) Error!TidStats {
    var r: TidStats = .{ .tid = tid };
    var it: codec.AttrIterator = .{ .buf = nest };
    while (try it.next()) |a| switch (a.type) {
        uapi.TID_STATS.RX_MSDU => r.rx_msdu = try asU64(a),
        uapi.TID_STATS.TX_MSDU => r.tx_msdu = try asU64(a),
        uapi.TID_STATS.TX_MSDU_RETRIES => r.tx_msdu_retries = try asU64(a),
        uapi.TID_STATS.TX_MSDU_FAILED => r.tx_msdu_failed = try asU64(a),
        uapi.TID_STATS.TXQ_STATS => r.txq = try parseTxq(a.data),
        else => {},
    };
    return r;
}

fn parseTxq(nest: []const u8) Error!TxqStats {
    var q: TxqStats = .{};
    var it: codec.AttrIterator = .{ .buf = nest };
    while (try it.next()) |a| switch (a.type) {
        uapi.TXQ_STATS.BACKLOG_BYTES => q.backlog_bytes = try a.asU32(),
        uapi.TXQ_STATS.BACKLOG_PACKETS => q.backlog_packets = try a.asU32(),
        uapi.TXQ_STATS.FLOWS => q.flows = try a.asU32(),
        uapi.TXQ_STATS.DROPS => q.drops = try a.asU32(),
        uapi.TXQ_STATS.ECN_MARKS => q.ecn_marks = try a.asU32(),
        uapi.TXQ_STATS.OVERLIMIT => q.overlimit = try a.asU32(),
        uapi.TXQ_STATS.OVERMEMORY => q.overmemory = try a.asU32(),
        uapi.TXQ_STATS.COLLISIONS => q.collisions = try a.asU32(),
        uapi.TXQ_STATS.TX_BYTES => q.tx_bytes = try a.asU32(),
        uapi.TXQ_STATS.TX_PACKETS => q.tx_packets = try a.asU32(),
        uapi.TXQ_STATS.MAX_FLOWS => q.max_flows = try a.asU32(),
        else => {},
    };
    return q;
}

fn parseChains(nest: []const u8, buf: *[max_chains]i8, n: *u8) Error!void {
    var it: codec.AttrIterator = .{ .buf = nest };
    var count: u8 = 0;
    while (try it.next()) |a| {
        const v = try asI8(a);
        if (count < max_chains) {
            buf[count] = v;
            count += 1;
        }
    }
    n.* = count;
}

fn parseBssParam(nest: []const u8) Error!BssParam {
    var p: BssParam = .{};
    var it: codec.AttrIterator = .{ .buf = nest };
    while (try it.next()) |a| switch (a.type) {
        uapi.STA_BSS_PARAM.CTS_PROT => p.cts_protection = true,
        uapi.STA_BSS_PARAM.SHORT_PREAMBLE => p.short_preamble = true,
        uapi.STA_BSS_PARAM.SHORT_SLOT_TIME => p.short_slot_time = true,
        uapi.STA_BSS_PARAM.DTIM_PERIOD => p.dtim_period = try a.asU8(),
        uapi.STA_BSS_PARAM.BEACON_INTERVAL => p.beacon_interval_tu = try a.asU16(),
        else => {},
    };
    return p;
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
        uapi.STA_INFO.CHAIN_SIGNAL => try parseChains(a.data, &out.chain_signal_buf, &out.n_chain_signal),
        uapi.STA_INFO.CHAIN_SIGNAL_AVG => try parseChains(a.data, &out.chain_signal_avg_buf, &out.n_chain_signal_avg),
        uapi.STA_INFO.BSS_PARAM => out.bss_param = try parseBssParam(a.data),
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
    codec.nestEnd(list, off) catch return error.InvalidRequest;
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

/// GET_STATION reply attribute lists and bare RATE_INFO nests for `fuzzParse`, in the format `Smith.slice` reads (see
/// `testkit.fuzz`): a little-endian u32 length, then the frame.
///
/// ⭐ Built at run time by `codec`'s own encoders, the way the value tests
/// above build theirs, rather than quoted as hex: an nl80211 attribute is a
/// netlink TLV, whose length and scalars are HOST byte order, so a hex corpus
/// would be a little-endian one and the counts pinned below would be false on
/// a big-endian target instead of failing there.
const Corpus = struct {
    scratch: [8192]u8 = undefined,
    store: [8192]u8 = undefined,
    used: usize = 0,
    entries: [10][]const u8 = undefined,
    n: usize = 0,

    fn push(self: *Corpus, frame: []const u8) void {
        const sd = testkit.fuzz.seedInto(self.store[self.used..], frame);
        self.entries[self.n] = sd;
        self.used += sd.len;
        self.n += 1;
    }

    fn build(self: *Corpus) ![]const []const u8 {
        var fba = std.heap.FixedBufferAllocator.init(&self.scratch);
        const gpa = fba.allocator();

        // The captured VHT rate-info nest, fed bare: `parseRateInfo` takes a
        // nest body, so this seed is what reaches its half of the harness.
        const vht_rate = [_]u8{
            0x08, 0x00, 0x05, 0x00, 0xd0, 0x03, 0x00, 0x00, // BITRATE32 = 976
            0x06, 0x00, 0x01, 0x00, 0xd0, 0x03, 0x00, 0x00, // BITRATE = 976
            0x04, 0x00, 0x08, 0x00, // 80 MHz (flag)
            0x05, 0x00, 0x06, 0x00, 0x02, 0x00, 0x00, 0x00, // VHT_MCS = 2
            0x05, 0x00, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, // VHT_NSS = 1
            0x04, 0x00, 0x04, 0x00, // SHORT_GI (flag)
        };
        self.push(&vht_rate);

        // P-18: BITRATE32 large enough that `b * 100` overflows a u32. This is
        // the seed the accessor call in the harness exists for.
        var overflow: std.ArrayList(u8) = .empty;
        try codec.appendAttrU32(gpa, &overflow, uapi.RATE_INFO.BITRATE32, 42_949_673);
        self.push(overflow.items);

        // A whole station: 64-bit counters, signed signal bytes, and both
        // bitrate nests, so the accessors run on a station rather than on a
        // bare nest.
        var full: std.ArrayList(u8) = .empty;
        {
            var info: std.ArrayList(u8) = .empty;
            try codec.appendAttr(gpa, &info, uapi.STA_INFO.RX_BYTES64, &.{ 0x32, 0xe0, 0x84, 0xe5, 0x07, 0, 0, 0 });
            try codec.appendAttrU32(gpa, &info, uapi.STA_INFO.RX_BYTES, 0xe584_e032);
            try codec.appendAttrU8(gpa, &info, uapi.STA_INFO.SIGNAL, 0xaf); // -81
            try codec.appendAttrU8(gpa, &info, uapi.STA_INFO.SIGNAL_AVG, 0xb0); // -80
            try codec.appendAttr(gpa, &info, uapi.STA_INFO.TX_BITRATE, &vht_rate);
            try codec.appendAttr(gpa, &info, uapi.STA_INFO.RX_BITRATE, &vht_rate);
            try wrapNest(gpa, &full, uapi.ATTR.STA_INFO, info.items);
        }
        self.push(full.items);

        // An empty STA_INFO nest: a legal station with every field absent.
        var empty_nest: std.ArrayList(u8) = .empty;
        try wrapNest(gpa, &empty_nest, uapi.ATTR.STA_INFO, &.{});
        self.push(empty_nest.items);

        // ── the refusals ───────────────────────────────────────────────────
        // A STA_INFO whose inner TLV is truncated.
        var truncated: std.ArrayList(u8) = .empty;
        try wrapNest(gpa, &truncated, uapi.ATTR.STA_INFO, &.{ 0x40, 0x00, 0x02, 0x00, 0x01 });
        self.push(truncated.items);
        // RX_BYTES64 four octets wide.
        var narrow: std.ArrayList(u8) = .empty;
        {
            var info: std.ArrayList(u8) = .empty;
            try codec.appendAttrU32(gpa, &info, uapi.STA_INFO.RX_BYTES64, 7);
            try wrapNest(gpa, &narrow, uapi.ATTR.STA_INFO, info.items);
        }
        self.push(narrow.items);
        // A TX_BITRATE nest that lies about its own length.
        var lying: std.ArrayList(u8) = .empty;
        {
            var info: std.ArrayList(u8) = .empty;
            try codec.appendAttr(gpa, &info, uapi.STA_INFO.TX_BITRATE, &.{ 0xff, 0x00, 0x01, 0x00 });
            try wrapNest(gpa, &lying, uapi.ATTR.STA_INFO, info.items);
        }
        self.push(lying.items);

        return self.entries[0..self.n];
    }
};

const fz = @import("fuzz_test.zig");
const StationMark = fz.Marker(enum { rejected, parsed, bitrate, rate_info });

test "fuzz: station parse never crashes" {
    var corpus: Corpus = .{};
    try testing.fuzz({}, fuzzParseSmith, .{ .corpus = try corpus.build() });
}

test "fuzz driver: NL80211_FUZZ (station parse)" {
    try fz.fuzz_driver.run(fuzzParse, .{ .prefix = "NL80211_FUZZ", .name = "nl80211-station" });
}

test "fuzz harness: station parse, 300 seeds, reaches every outcome" {
    try StationMark.reach(fuzzParse, "nl80211-station", 300);
}

fn fuzzParseSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [fz.script_cap]u8 = undefined;
    const n = smith.slice(&script);
    try fz.runFrom(fuzzParse, smith, script[0..n]);
}

fn fuzzParse(comptime S: type, smith: *S, gpa: std.mem.Allocator) anyerror!void {
    var raw: [512]u8 = undefined;
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
    // length. `bytes` takes `@min(raw.len, in.len)` octets and the ranged draw
    // then finds fewer than the eight it needs and returns the range MINIMUM,
    // so `len` was 0 for every seed and both `parse` and `parseRateInfo` were handed an empty attribute list, with
    // the reply sitting unread in `raw`.
    //
    // ⛔ And it looked HEALTHIER that way: a station with no
    // attributes at all is a legal reply — the test above says so in as many
    // words — so both parsers succeeded on the empty slice every round.
    // Measured 2026-09-07 over the corpus above: **0 of 7 seeds non-empty, 7
    // of 7 "parsed" and 0 bitrates reached before; 7 of 7 non-empty, 3 parsed
    // and 3 bitrates after.** The bitrate count is the one that matters:
    // `kilobitsPerSecond` is where the P-18 overflow panic lived, and the
    // collapsed harness could not reach it at all.
    var cstore: Corpus = .{};
    const entries: []const []const u8 = if (S == fz.fuzz_driver.Rng) (cstore.build() catch &.{}) else &.{};
    const len: usize = fz.drawInput(S, smith, &raw, entries);
    _ = gpa;
    // Also exercise the accessors, not just the parse — `kilobitsPerSecond`
    // (P-18) is where the previous integer-overflow panic lived, and a
    // fuzz harness that only calls `parse`/`parseRateInfo` walks right past
    // it, per the finding.
    if (parse(raw[0..len])) |s| {
        StationMark.mark(.parsed);
        std.mem.doNotOptimizeAway(&s);
        if (s.tx_bitrate) |r| std.mem.doNotOptimizeAway(r.kilobitsPerSecond());
        if (s.rx_bitrate) |r| std.mem.doNotOptimizeAway(r.kilobitsPerSecond());
        if (s.tx_bitrate != null or s.rx_bitrate != null) StationMark.mark(.bitrate);
    } else |_| StationMark.mark(.rejected);
    if (parseRateInfo(raw[0..len])) |r| {
        StationMark.mark(.rate_info);
        std.mem.doNotOptimizeAway(&r);
        std.mem.doNotOptimizeAway(r.kilobitsPerSecond());
    } else |_| {}
}

test "corpus: every station seed reaches the parsers, and the counts are pinned" {
    // ⭐ The measurement, executable rather than written in a comment, over the
    // SAME corpus the harness gets. `nonempty` is the reach claim and the only
    // check that catches a seed grown past the harness's buffer, which
    // `Smith.slice` reads back as the EMPTY one, silently. The second number
    // is what the first cannot say: an empty attribute list is a legal reply
    // here, so "parsed" alone counts a harness that walks nothing as a
    // success.
    //
    // `bitrates` is that second number here, and it is pinned because it is
    // the only thing that says `kilobitsPerSecond` — the accessor P-18 was
    // about — was executed on decoded wire data at all.
    var corpus: Corpus = .{};
    const entries = try corpus.build();
    var nonempty: usize = 0;
    var parsed: usize = 0;
    var bitrates: usize = 0;
    for (entries) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var raw: [512]u8 = undefined;
        const len: usize = smith.slice(&raw);
        if (len != 0) nonempty += 1;
        if (parse(raw[0..len])) |s| {
            parsed += 1;
            if (s.tx_bitrate) |r| {
                if (r.kilobitsPerSecond() != null) bitrates += 1;
            }
        } else |_| {}
        if (parseRateInfo(raw[0..len])) |r| {
            if (r.kilobitsPerSecond() != null) bitrates += 1;
        } else |_| {}
    }
    try testing.expectEqual(entries.len, nonempty);
    try testing.expectEqual(@as(usize, 3), parsed);
    try testing.expectEqual(@as(usize, 3), bitrates);
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

// ── chain signal, BSS parameters, TID statistics, multi-link ────────────────

fn nestOf(gpa: std.mem.Allocator, list: *std.ArrayList(u8), t: u16) !usize {
    return codec.nestBegin(gpa, list, t);
}

test "parse: per-chain signal and its average keep the chain order and drop past max_chains" {
    const gpa = testing.allocator;
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(gpa);
    const sta = try nestOf(gpa, &msg, uapi.ATTR.STA_INFO);
    const chains = try nestOf(gpa, &msg, uapi.STA_INFO.CHAIN_SIGNAL);
    for ([_]i8{ -50, -61, -72 }, 1..) |v, i| try codec.appendAttrU8(gpa, &msg, @intCast(i), @bitCast(v));
    try codec.nestEnd(&msg, chains);
    const avg = try nestOf(gpa, &msg, uapi.STA_INFO.CHAIN_SIGNAL_AVG);
    for (0..max_chains + 3) |i| try codec.appendAttrU8(gpa, &msg, @intCast(i + 1), @bitCast(@as(i8, -40)));
    try codec.nestEnd(&msg, avg);
    try codec.nestEnd(&msg, sta);

    const s = try parse(msg.items);
    try testing.expectEqualSlices(i8, &.{ -50, -61, -72 }, s.chainSignals());
    try testing.expectEqual(@as(usize, max_chains), s.chainSignalsAvg().len);
    // A chain value that is not one octet is a malformed message.
    var bad: std.ArrayList(u8) = .empty;
    defer bad.deinit(gpa);
    const sta2 = try nestOf(gpa, &bad, uapi.ATTR.STA_INFO);
    const c2 = try nestOf(gpa, &bad, uapi.STA_INFO.CHAIN_SIGNAL);
    try codec.appendAttrU32(gpa, &bad, 1, 7);
    try codec.nestEnd(&bad, c2);
    try codec.nestEnd(&bad, sta2);
    try testing.expectError(error.BadLength, parse(bad.items));
}

test "parse: BSS_PARAM flags, DTIM period and beacon interval" {
    const gpa = testing.allocator;
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(gpa);
    const sta = try nestOf(gpa, &msg, uapi.ATTR.STA_INFO);
    const p = try nestOf(gpa, &msg, uapi.STA_INFO.BSS_PARAM);
    try codec.appendAttr(gpa, &msg, uapi.STA_BSS_PARAM.SHORT_PREAMBLE, &.{});
    try codec.appendAttr(gpa, &msg, uapi.STA_BSS_PARAM.SHORT_SLOT_TIME, &.{});
    try codec.appendAttrU8(gpa, &msg, uapi.STA_BSS_PARAM.DTIM_PERIOD, 3);
    try codec.appendAttrU16(gpa, &msg, uapi.STA_BSS_PARAM.BEACON_INTERVAL, 100);
    try codec.nestEnd(&msg, p);
    try codec.nestEnd(&msg, sta);
    const s = try parse(msg.items);
    const b = s.bss_param.?;
    try testing.expect(!b.cts_protection and b.short_preamble and b.short_slot_time);
    try testing.expectEqual(@as(u8, 3), b.dtim_period);
    try testing.expectEqual(@as(u16, 100), b.beacon_interval_tu);
    try testing.expect((try parse(&.{})).bss_param == null);
}

test "parseTidStats: TID = nest type - 1, counters and the transmit queue" {
    const gpa = testing.allocator;
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(gpa);
    const sta = try nestOf(gpa, &msg, uapi.ATTR.STA_INFO);
    const tids = try nestOf(gpa, &msg, uapi.STA_INFO.TID_STATS);
    // TID 0 and TID 5, and a type that is not a TID (0) and one past the table.
    for ([_]u16{ 1, 6, 0, max_tids + 1 }) |t| {
        const one = try nestOf(gpa, &msg, t);
        try codec.appendAttrU64(gpa, &msg, uapi.TID_STATS.RX_MSDU, 1000 + t);
        try codec.appendAttrU64(gpa, &msg, uapi.TID_STATS.TX_MSDU_FAILED, 3);
        const q = try nestOf(gpa, &msg, uapi.TID_STATS.TXQ_STATS);
        try codec.appendAttrU32(gpa, &msg, uapi.TXQ_STATS.BACKLOG_BYTES, 1500);
        try codec.appendAttrU32(gpa, &msg, uapi.TXQ_STATS.DROPS, 2);
        try codec.appendAttrU32(gpa, &msg, uapi.TXQ_STATS.MAX_FLOWS, 4096);
        try codec.nestEnd(&msg, q);
        try codec.nestEnd(&msg, one);
    }
    try codec.nestEnd(&msg, tids);
    try codec.nestEnd(&msg, sta);

    var out: [max_tids]TidStats = undefined;
    const n = try parseTidStats(msg.items, &out);
    try testing.expectEqual(@as(usize, 2), n);
    try testing.expectEqual(@as(u8, 0), out[0].tid);
    try testing.expectEqual(@as(?u64, 1001), out[0].rx_msdu);
    try testing.expectEqual(@as(u8, 5), out[1].tid);
    try testing.expectEqual(@as(?u64, 1006), out[1].rx_msdu);
    try testing.expectEqual(@as(?u64, 3), out[1].tx_msdu_failed);
    try testing.expectEqual(@as(?u64, null), out[1].tx_msdu);
    try testing.expectEqual(@as(?u32, 1500), out[1].txq.?.backlog_bytes);
    try testing.expectEqual(@as(?u32, 2), out[1].txq.?.drops);
    try testing.expectEqual(@as(?u32, 4096), out[1].txq.?.max_flows);
    try testing.expectEqual(@as(?u32, null), out[1].txq.?.flows);
    // A short output keeps what fits.
    var one: [1]TidStats = undefined;
    try testing.expectEqual(@as(usize, 1), try parseTidStats(msg.items, &one));
    // None reported: zero entries, no error.
    try testing.expectEqual(@as(usize, 0), try parseTidStats(&.{}, &out));
}

test "parse: multi-link attributes of a station message" {
    const gpa = testing.allocator;
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(gpa);
    try codec.appendAttrU8(gpa, &msg, uapi.ATTR.MLO_LINK_ID, 2);
    try codec.appendAttr(gpa, &msg, uapi.ATTR.MLD_ADDR, &.{ 2, 0, 0, 1, 2, 3 });
    const s = try parse(msg.items);
    try testing.expectEqual(@as(?u8, 2), s.mlo_link_id);
    try testing.expectEqualSlices(u8, &.{ 2, 0, 0, 1, 2, 3 }, &s.mld_addr.?);
    var bad: std.ArrayList(u8) = .empty;
    defer bad.deinit(gpa);
    try codec.appendAttr(gpa, &bad, uapi.ATTR.MLD_ADDR, &.{ 1, 2, 3 });
    try testing.expectError(error.BadLength, parse(bad.items));
}

test "mutation 2026-11-25: parseTidStats reads every counter of TID 16 and ignores nests that are not the station's TID_STATS" {
    const gpa = testing.allocator;
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(gpa);
    // A top-level attribute that is not STA_INFO, holding a perfectly good TID_STATS nest.
    const decoy = try nestOf(gpa, &msg, uapi.ATTR.IFINDEX);
    const d_tids = try nestOf(gpa, &msg, uapi.STA_INFO.TID_STATS);
    const d_one = try nestOf(gpa, &msg, 2);
    try codec.appendAttrU64(gpa, &msg, uapi.TID_STATS.RX_MSDU, 7);
    try codec.nestEnd(&msg, d_one);
    try codec.nestEnd(&msg, d_tids);
    try codec.nestEnd(&msg, decoy);

    const sta = try nestOf(gpa, &msg, uapi.ATTR.STA_INFO);
    // Inside STA_INFO, an attribute that is not TID_STATS, holding a good TID nest.
    const inner = try nestOf(gpa, &msg, uapi.STA_INFO.SIGNAL);
    const i_one = try nestOf(gpa, &msg, 2);
    try codec.appendAttrU64(gpa, &msg, uapi.TID_STATS.RX_MSDU, 8);
    try codec.nestEnd(&msg, i_one);
    try codec.nestEnd(&msg, inner);
    const tids = try nestOf(gpa, &msg, uapi.STA_INFO.TID_STATS);
    const one = try nestOf(gpa, &msg, max_tids); // TID 16, the last one
    try codec.appendAttrU64(gpa, &msg, uapi.TID_STATS.RX_MSDU, 11);
    try codec.appendAttrU64(gpa, &msg, uapi.TID_STATS.TX_MSDU, 12);
    try codec.appendAttrU64(gpa, &msg, uapi.TID_STATS.TX_MSDU_RETRIES, 13);
    try codec.appendAttrU64(gpa, &msg, uapi.TID_STATS.TX_MSDU_FAILED, 14);
    const q = try nestOf(gpa, &msg, uapi.TID_STATS.TXQ_STATS);
    const fields = [_]u16{
        uapi.TXQ_STATS.BACKLOG_BYTES, uapi.TXQ_STATS.BACKLOG_PACKETS, uapi.TXQ_STATS.FLOWS,      uapi.TXQ_STATS.DROPS,
        uapi.TXQ_STATS.ECN_MARKS,     uapi.TXQ_STATS.OVERLIMIT,       uapi.TXQ_STATS.OVERMEMORY, uapi.TXQ_STATS.COLLISIONS,
        uapi.TXQ_STATS.TX_BYTES,      uapi.TXQ_STATS.TX_PACKETS,      uapi.TXQ_STATS.MAX_FLOWS,
    };
    for (fields, 0..) |f, i| try codec.appendAttrU32(gpa, &msg, f, @intCast(100 + i));
    try codec.nestEnd(&msg, q);
    try codec.nestEnd(&msg, one);
    try codec.nestEnd(&msg, tids);
    try codec.nestEnd(&msg, sta);

    var out: [max_tids]TidStats = undefined;
    const n = try parseTidStats(msg.items, &out);
    try testing.expectEqual(@as(usize, 1), n);
    const t = out[0];
    try testing.expectEqual(@as(u8, 16), t.tid);
    try testing.expectEqual(@as(?u64, 11), t.rx_msdu);
    try testing.expectEqual(@as(?u64, 12), t.tx_msdu);
    try testing.expectEqual(@as(?u64, 13), t.tx_msdu_retries);
    try testing.expectEqual(@as(?u64, 14), t.tx_msdu_failed);
    const x = t.txq.?;
    try testing.expectEqual(@as(?u32, 100), x.backlog_bytes);
    try testing.expectEqual(@as(?u32, 101), x.backlog_packets);
    try testing.expectEqual(@as(?u32, 102), x.flows);
    try testing.expectEqual(@as(?u32, 103), x.drops);
    try testing.expectEqual(@as(?u32, 104), x.ecn_marks);
    try testing.expectEqual(@as(?u32, 105), x.overlimit);
    try testing.expectEqual(@as(?u32, 106), x.overmemory);
    try testing.expectEqual(@as(?u32, 107), x.collisions);
    try testing.expectEqual(@as(?u32, 108), x.tx_bytes);
    try testing.expectEqual(@as(?u32, 109), x.tx_packets);
    try testing.expectEqual(@as(?u32, 110), x.max_flows);
}

test "mutation 2026-11-25: BSS_PARAM CTS protection" {
    const gpa = testing.allocator;
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(gpa);
    const sta = try nestOf(gpa, &msg, uapi.ATTR.STA_INFO);
    const p = try nestOf(gpa, &msg, uapi.STA_INFO.BSS_PARAM);
    try codec.appendAttr(gpa, &msg, uapi.STA_BSS_PARAM.CTS_PROT, &.{});
    try codec.nestEnd(&msg, p);
    try codec.nestEnd(&msg, sta);
    const b = (try parse(msg.items)).bss_param.?;
    try testing.expect(b.cts_protection and !b.short_preamble and !b.short_slot_time);
}
