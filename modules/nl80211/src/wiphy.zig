// SPDX-License-Identifier: MIT
//! `NL80211_CMD_GET_WIPHY` decoding — per-radio capabilities.
//!
//! ## Why this needs a *merging* parser
//!
//! A wiphy's capability blob is far larger than one netlink message. Since
//! Linux 3.10 the kernel therefore answers a dump that carries
//! `NL80211_ATTR_SPLIT_WIPHY_DUMP` by **splitting one wiphy across many
//! `NL80211_CMD_NEW_WIPHY` messages**, each repeating only `ATTR.WIPHY` (the
//! index) and `ATTR.WIPHY_NAME` and adding a slice of the rest. A dump of a
//! single radio on the development machine arrived as **59 messages**, with the
//! frequency list dribbled out one channel per message.
//!
//! So the unit of decoding is not "message → Wiphy". It is: feed every message
//! into a `Parser`, which keys accumulating state by wiphy index and merges;
//! `finish()` then yields the completed radios. Feeding a *non*-split dump
//! through the same parser works unchanged — it is just the degenerate case of
//! one message per wiphy.
//!
//! Merging rules, all of them driven by what the kernel actually sends:
//!
//! * Scalars (name, `MAX_NUM_SCAN_SSIDS`, …) are **last-writer-wins**; the
//!   kernel repeats identical values, never conflicting ones.
//! * Bands are keyed by their nested attribute index and merged in place.
//! * Frequencies are keyed by *their* index inside the band, so a channel that
//!   appears twice is updated rather than duplicated.
//! * Lists that arrive whole (ciphers, iftypes, supported commands) replace
//!   rather than append, because the kernel emits each exactly once.

const std = @import("std");
const netlink = @import("netlink");
const codec = netlink.codec;
const genl = @import("genetlink");
const uapi = @import("uapi.zig");

pub const Error = codec.Error || error{OutOfMemory};

/// Build a `NL80211_CMD_GET_WIPHY` dump request. With `split` (what `iw list`
/// sends) the kernel spreads each radio over many messages instead of
/// truncating it to one — see the file header.
pub fn buildGetWiphy(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    split: bool,
) std.mem.Allocator.Error![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(
        gpa,
        &list,
        family_id,
        codec.NLM_F_REQUEST | codec.NLM_F_ACK | codec.NLM_F_DUMP,
        seq,
        0,
    );
    try genl.appendHeader(gpa, &list, uapi.CMD.GET_WIPHY, uapi.family_version);
    if (split) codec.appendAttr(gpa, &list, uapi.ATTR.SPLIT_WIPHY_DUMP, &.{}) catch |e| switch (e) {
        error.AttrTooLong => unreachable, // zero-length flag
        error.OutOfMemory => return error.OutOfMemory,
    };
    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

/// `NL80211_WIPHY_NAME` ceiling in the kernel's policy, including no NUL.
pub const max_wiphy_name = 64;

/// One channel a radio can operate on.
pub const Frequency = struct {
    /// Index of this entry inside `NL80211_BAND_ATTR_FREQS` — the merge key.
    index: u32,
    freq_mhz: u32 = 0,
    /// Kilohertz offset from `freq_mhz` (6 GHz / S1G channels).
    offset_khz: u32 = 0,
    /// Maximum transmit power in mBm (100 · dBm).
    max_tx_power_mbm: ?u32 = null,
    /// The channel is administratively unusable in the current regdomain.
    disabled: bool = false,
    /// "No initiating radiation": passive scan only, no beaconing.
    no_ir: bool = false,
    /// Radar detection (DFS) is required here.
    radar: bool = false,
    indoor_only: bool = false,
    no_ht40_minus: bool = false,
    no_ht40_plus: bool = false,
    no_80mhz: bool = false,
    no_160mhz: bool = false,
    no_20mhz: bool = false,
    no_10mhz: bool = false,

    /// True when the channel may be actively scanned / used to transmit.
    pub fn usable(f: Frequency) bool {
        return !f.disabled;
    }
};

/// One frequency band of a radio (index 0 = 2.4 GHz, 1 = 5 GHz, 2 = 60 GHz,
/// 3 = 6 GHz, 4 = S1G — the kernel's `enum nl80211_band`).
pub const Band = struct {
    /// The nested attribute index, i.e. the `nl80211_band` value.
    index: u32,
    freqs: []Frequency = &.{},
    /// Legacy bitrates in 100 kbit/s units.
    rates: []u32 = &.{},
    /// A HT capabilities field was advertised for this band.
    ht: bool = false,
    /// A VHT capabilities field was advertised for this band.
    vht: bool = false,
};

/// A physical radio and the capability subset this module decodes.
pub const Wiphy = struct {
    index: u32,
    bands: []Band = &.{},
    /// Cipher suites the radio supports, as `0x000FACxx` selectors.
    ciphers: []u32 = &.{},
    /// nl80211 command ids the radio supports (`NL80211_ATTR_SUPPORTED_COMMANDS`).
    commands: []u32 = &.{},
    /// Bit `n` set = `@as(Iftype, @enumFromInt(n))` is supported.
    iftypes: u32 = 0,
    /// Iftypes the radio can create purely in software.
    software_iftypes: u32 = 0,
    /// How many SSIDs one `TRIGGER_SCAN` may carry. Exceeding it is EINVAL.
    max_num_scan_ssids: ?u8 = null,
    max_num_sched_scan_ssids: ?u8 = null,
    /// Bytes of extra IEs a scan request may carry.
    max_scan_ie_len: ?u16 = null,
    feature_flags: ?u32 = null,
    /// The radio's permanent MAC address.
    mac: ?uapi.Mac = null,
    generation: ?u32 = null,

    name_buf: [max_wiphy_name]u8 = @splat(0),
    name_len: u8 = 0,

    /// The radio name (`phy0`).
    pub fn name(w: *const Wiphy) []const u8 {
        return w.name_buf[0..w.name_len];
    }

    pub fn supportsIftype(w: *const Wiphy, t: uapi.Iftype) bool {
        const n = @intFromEnum(t);
        if (n >= 32) return false;
        return w.iftypes & (@as(u32, 1) << @intCast(n)) != 0;
    }

    pub fn supportsCipher(w: *const Wiphy, suite: u32) bool {
        return std.mem.indexOfScalar(u32, w.ciphers, suite) != null;
    }

    /// Is `cmd` in `NL80211_ATTR_SUPPORTED_COMMANDS`?
    ///
    /// **This is "advertised", not "possible".** The kernel publishes a
    /// partial list — chiefly the MLME commands a driver opted into — and a
    /// radio that scans perfectly well does not necessarily list
    /// `TRIGGER_SCAN` (the development machine's does not; `goldens.zig` pins
    /// that). Infer scan capability from `max_num_scan_ssids` instead.
    pub fn supportsCommand(w: *const Wiphy, cmd: u8) bool {
        return std.mem.indexOfScalar(u32, w.commands, cmd) != null;
    }

    /// The band whose `index` equals `n`, or null.
    pub fn band(w: *const Wiphy, n: u32) ?*const Band {
        for (w.bands) |*b| if (b.index == n) return b;
        return null;
    }

    /// Look a channel up across every band.
    pub fn frequency(w: *const Wiphy, mhz: u32) ?*const Frequency {
        for (w.bands) |*b| for (b.freqs) |*f| {
            if (f.freq_mhz == mhz) return f;
        };
        return null;
    }

    /// Total number of channels across every band.
    pub fn channelCount(w: *const Wiphy) usize {
        var n: usize = 0;
        for (w.bands) |b| n += b.freqs.len;
        return n;
    }

    pub fn deinit(w: *Wiphy, gpa: std.mem.Allocator) void {
        for (w.bands) |*b| {
            gpa.free(b.freqs);
            gpa.free(b.rates);
        }
        gpa.free(w.bands);
        gpa.free(w.ciphers);
        gpa.free(w.commands);
        w.* = undefined;
    }
};

/// Free a list returned by `Parser.finish`.
pub fn freeAll(gpa: std.mem.Allocator, list: []Wiphy) void {
    for (list) |*w| w.deinit(gpa);
    gpa.free(list);
}

// ── the merging parser ─────────────────────────────────────────────────────

const BandBuilder = struct {
    index: u32,
    freqs: std.ArrayList(Frequency) = .empty,
    rates: std.ArrayList(u32) = .empty,
    ht: bool = false,
    vht: bool = false,
};

const WiphyBuilder = struct {
    w: Wiphy,
    bands: std.ArrayList(BandBuilder) = .empty,
    ciphers: std.ArrayList(u32) = .empty,
    commands: std.ArrayList(u32) = .empty,
};

/// Accumulates a (possibly split) `GET_WIPHY` dump. Feed every
/// `NL80211_CMD_NEW_WIPHY` message's attribute bytes, then `finish`.
pub const Parser = struct {
    gpa: std.mem.Allocator,
    builders: std.ArrayList(WiphyBuilder) = .empty,

    pub fn init(gpa: std.mem.Allocator) Parser {
        return .{ .gpa = gpa };
    }

    pub fn deinit(p: *Parser) void {
        for (p.builders.items) |*b| {
            for (b.bands.items) |*bb| {
                bb.freqs.deinit(p.gpa);
                bb.rates.deinit(p.gpa);
            }
            b.bands.deinit(p.gpa);
            b.ciphers.deinit(p.gpa);
            b.commands.deinit(p.gpa);
        }
        p.builders.deinit(p.gpa);
        p.* = undefined;
    }

    /// Feed one message's attribute bytes (the genl payload past the
    /// `genlmsghdr`). Messages may arrive in any order and interleave radios.
    pub fn feed(p: *Parser, attr_bytes: []const u8) Error!void {
        // The wiphy index identifies which radio this fragment belongs to. A
        // message without one cannot be attributed and is dropped rather than
        // merged into the wrong radio.
        const idx = (try findWiphyIndex(attr_bytes)) orelse return;
        const b = try p.builderFor(idx);

        var it: codec.AttrIterator = .{ .buf = attr_bytes };
        while (try it.next()) |a| switch (a.type) {
            uapi.ATTR.WIPHY_NAME => {
                const s = a.asString();
                if (s.len > max_wiphy_name) return error.BadLength;
                @memcpy(b.w.name_buf[0..s.len], s);
                b.w.name_len = @intCast(s.len);
            },
            uapi.ATTR.GENERATION => b.w.generation = try a.asU32(),
            uapi.ATTR.MAX_NUM_SCAN_SSIDS => b.w.max_num_scan_ssids = try a.asU8(),
            uapi.ATTR.MAX_NUM_SCHED_SCAN_SSIDS => b.w.max_num_sched_scan_ssids = try a.asU8(),
            uapi.ATTR.MAX_SCAN_IE_LEN => b.w.max_scan_ie_len = try a.asU16(),
            uapi.ATTR.FEATURE_FLAGS => b.w.feature_flags = try a.asU32(),
            uapi.ATTR.MAC => {
                if (a.data.len != 6) return error.BadLength;
                b.w.mac = a.data[0..6].*;
            },
            uapi.ATTR.CIPHER_SUITES => {
                // A flat array of u32s, not a nest.
                if (a.data.len % 4 != 0) return error.BadLength;
                b.ciphers.clearRetainingCapacity();
                var off: usize = 0;
                while (off < a.data.len) : (off += 4)
                    try b.ciphers.append(p.gpa, std.mem.readInt(u32, a.data[off..][0..4], .little));
            },
            uapi.ATTR.SUPPORTED_IFTYPES => b.w.iftypes = try flagSetToBits(a.data),
            uapi.ATTR.SOFTWARE_IFTYPES => b.w.software_iftypes = try flagSetToBits(a.data),
            uapi.ATTR.SUPPORTED_COMMANDS => {
                b.commands.clearRetainingCapacity();
                var inner: codec.AttrIterator = .{ .buf = a.data };
                while (try inner.next()) |c| try b.commands.append(p.gpa, try c.asU32());
            },
            uapi.ATTR.WIPHY_BANDS => try p.feedBands(b, a.data),
            else => {},
        };
    }

    /// Complete every accumulated radio. The parser is left empty and may be
    /// reused; the caller owns the result (`freeAll`).
    pub fn finish(p: *Parser) Error![]Wiphy {
        var out: std.ArrayList(Wiphy) = .empty;
        errdefer {
            for (out.items) |*w| w.deinit(p.gpa);
            out.deinit(p.gpa);
        }
        for (p.builders.items) |*b| {
            // `toOwnedSlice` empties the builder's list, so nothing is owned
            // twice even if a later allocation in this loop fails: whatever
            // has already moved is freed by the errdefer above, and whatever
            // has not is still owned (and freed) by `Parser.deinit`.
            var bands: std.ArrayList(Band) = .empty;
            errdefer {
                for (bands.items) |*x| {
                    p.gpa.free(x.freqs);
                    p.gpa.free(x.rates);
                }
                bands.deinit(p.gpa);
            }
            for (b.bands.items) |*bb| {
                const freqs = try bb.freqs.toOwnedSlice(p.gpa);
                errdefer p.gpa.free(freqs);
                const rates = try bb.rates.toOwnedSlice(p.gpa);
                errdefer p.gpa.free(rates);
                try bands.append(p.gpa, .{
                    .index = bb.index,
                    .freqs = freqs,
                    .rates = rates,
                    .ht = bb.ht,
                    .vht = bb.vht,
                });
            }
            var w = b.w;
            w.bands = try bands.toOwnedSlice(p.gpa);
            {
                errdefer w.deinit(p.gpa);
                try out.append(p.gpa, w);
            }
            const slot = &out.items[out.items.len - 1];
            slot.ciphers = try b.ciphers.toOwnedSlice(p.gpa);
            slot.commands = try b.commands.toOwnedSlice(p.gpa);
        }
        // Ownership has moved into `out`; drop the (now empty) builders.
        for (p.builders.items) |*b| {
            for (b.bands.items) |*bb| {
                bb.freqs.deinit(p.gpa);
                bb.rates.deinit(p.gpa);
            }
            b.bands.deinit(p.gpa);
            b.ciphers.deinit(p.gpa);
            b.commands.deinit(p.gpa);
        }
        p.builders.clearRetainingCapacity();
        return out.toOwnedSlice(p.gpa);
    }

    fn builderFor(p: *Parser, idx: u32) Error!*WiphyBuilder {
        for (p.builders.items) |*b| if (b.w.index == idx) return b;
        try p.builders.append(p.gpa, .{ .w = .{ .index = idx } });
        return &p.builders.items[p.builders.items.len - 1];
    }

    fn feedBands(p: *Parser, b: *WiphyBuilder, nest: []const u8) Error!void {
        var it: codec.AttrIterator = .{ .buf = nest };
        while (try it.next()) |band_attr| {
            const bb = try bandBuilderFor(p.gpa, b, band_attr.type);
            var inner: codec.AttrIterator = .{ .buf = band_attr.data };
            while (try inner.next()) |a| switch (a.type) {
                uapi.BAND_ATTR.FREQS => try feedFreqs(p.gpa, bb, a.data),
                uapi.BAND_ATTR.RATES => {
                    bb.rates.clearRetainingCapacity();
                    var rit: codec.AttrIterator = .{ .buf = a.data };
                    while (try rit.next()) |r| {
                        var sub: codec.AttrIterator = .{ .buf = r.data };
                        while (try sub.next()) |x| {
                            if (x.type == uapi.BITRATE_ATTR.RATE)
                                try bb.rates.append(p.gpa, try x.asU32());
                        }
                    }
                },
                uapi.BAND_ATTR.HT_CAPA, uapi.BAND_ATTR.HT_MCS_SET => bb.ht = true,
                uapi.BAND_ATTR.VHT_CAPA, uapi.BAND_ATTR.VHT_MCS_SET => bb.vht = true,
                else => {},
            };
        }
    }
};

fn bandBuilderFor(gpa: std.mem.Allocator, b: *WiphyBuilder, index: u32) Error!*BandBuilder {
    for (b.bands.items) |*bb| if (bb.index == index) return bb;
    try b.bands.append(gpa, .{ .index = index });
    return &b.bands.items[b.bands.items.len - 1];
}

fn feedFreqs(gpa: std.mem.Allocator, bb: *BandBuilder, nest: []const u8) Error!void {
    var it: codec.AttrIterator = .{ .buf = nest };
    while (try it.next()) |entry| {
        const f = try freqFor(gpa, bb, entry.type);
        var inner: codec.AttrIterator = .{ .buf = entry.data };
        while (try inner.next()) |a| switch (a.type) {
            uapi.FREQUENCY_ATTR.FREQ => f.freq_mhz = try a.asU32(),
            uapi.FREQUENCY_ATTR.OFFSET => f.offset_khz = try a.asU32(),
            uapi.FREQUENCY_ATTR.MAX_TX_POWER => f.max_tx_power_mbm = try a.asU32(),
            uapi.FREQUENCY_ATTR.DISABLED => f.disabled = true,
            uapi.FREQUENCY_ATTR.NO_IR => f.no_ir = true,
            uapi.FREQUENCY_ATTR.RADAR => f.radar = true,
            uapi.FREQUENCY_ATTR.INDOOR_ONLY => f.indoor_only = true,
            uapi.FREQUENCY_ATTR.NO_HT40_MINUS => f.no_ht40_minus = true,
            uapi.FREQUENCY_ATTR.NO_HT40_PLUS => f.no_ht40_plus = true,
            uapi.FREQUENCY_ATTR.NO_80MHZ => f.no_80mhz = true,
            uapi.FREQUENCY_ATTR.NO_160MHZ => f.no_160mhz = true,
            uapi.FREQUENCY_ATTR.NO_20MHZ => f.no_20mhz = true,
            uapi.FREQUENCY_ATTR.NO_10MHZ => f.no_10mhz = true,
            else => {},
        };
    }
}

fn freqFor(gpa: std.mem.Allocator, bb: *BandBuilder, index: u32) Error!*Frequency {
    for (bb.freqs.items) |*f| if (f.index == index) return f;
    try bb.freqs.append(gpa, .{ .index = index });
    return &bb.freqs.items[bb.freqs.items.len - 1];
}

/// `NL80211_ATTR_WIPHY` of a message, or null when it carries none.
fn findWiphyIndex(attr_bytes: []const u8) codec.Error!?u32 {
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| {
        if (a.type == uapi.ATTR.WIPHY) return try a.asU32();
    }
    return null;
}

/// A nest of zero-length flag attributes whose *types* are the set members
/// (how nl80211 encodes `SUPPORTED_IFTYPES`) → a bitmask.
fn flagSetToBits(nest: []const u8) codec.Error!u32 {
    var bits: u32 = 0;
    var it: codec.AttrIterator = .{ .buf = nest };
    while (try it.next()) |a| {
        if (a.type < 32) bits |= @as(u32, 1) << @intCast(a.type);
    }
    return bits;
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

fn openNest(gpa: std.mem.Allocator, l: *std.ArrayList(u8), t: u16) !usize {
    return codec.nestBegin(gpa, l, t);
}

test "split dump: one radio spread over several messages is merged into one" {
    const gpa = testing.allocator;
    var p: Parser = .init(gpa);
    defer p.deinit();

    // Message 1: identity + scan limits.
    {
        var m: std.ArrayList(u8) = .empty;
        defer m.deinit(gpa);
        try codec.appendAttrU32(gpa, &m, uapi.ATTR.WIPHY, 0);
        try codec.appendAttrString(gpa, &m, uapi.ATTR.WIPHY_NAME, "phy0");
        try codec.appendAttrU8(gpa, &m, uapi.ATTR.MAX_NUM_SCAN_SSIDS, 20);
        try codec.appendAttrU16(gpa, &m, uapi.ATTR.MAX_SCAN_IE_LEN, 413);
        try p.feed(m.items);
    }
    // Message 2: ciphers + iftypes (identity repeated, as the kernel does).
    {
        var m: std.ArrayList(u8) = .empty;
        defer m.deinit(gpa);
        try codec.appendAttrU32(gpa, &m, uapi.ATTR.WIPHY, 0);
        try codec.appendAttrString(gpa, &m, uapi.ATTR.WIPHY_NAME, "phy0");
        try codec.appendAttr(gpa, &m, uapi.ATTR.CIPHER_SUITES, &.{
            0x01, 0xac, 0x0f, 0x00, // WEP40
            0x04, 0xac, 0x0f, 0x00, // CCMP
        });
        const off = try openNest(gpa, &m, uapi.ATTR.SUPPORTED_IFTYPES);
        try codec.appendAttr(gpa, &m, @intFromEnum(uapi.Iftype.station), &.{});
        try codec.appendAttr(gpa, &m, @intFromEnum(uapi.Iftype.ap), &.{});
        codec.nestEnd(&m, off);
        try p.feed(m.items);
    }
    // Messages 3 and 4: one channel each, same band — the split-dump shape.
    for ([_]struct { idx: u16, mhz: u32 }{ .{ .idx = 0, .mhz = 2412 }, .{ .idx = 1, .mhz = 2417 } }) |ch| {
        var m: std.ArrayList(u8) = .empty;
        defer m.deinit(gpa);
        try codec.appendAttrU32(gpa, &m, uapi.ATTR.WIPHY, 0);
        const bands = try openNest(gpa, &m, uapi.ATTR.WIPHY_BANDS);
        const band0 = try openNest(gpa, &m, 0);
        const freqs = try openNest(gpa, &m, uapi.BAND_ATTR.FREQS);
        const entry = try openNest(gpa, &m, ch.idx);
        try codec.appendAttrU32(gpa, &m, uapi.FREQUENCY_ATTR.FREQ, ch.mhz);
        try codec.appendAttrU32(gpa, &m, uapi.FREQUENCY_ATTR.MAX_TX_POWER, 2000);
        codec.nestEnd(&m, entry);
        codec.nestEnd(&m, freqs);
        codec.nestEnd(&m, band0);
        codec.nestEnd(&m, bands);
        try p.feed(m.items);
    }

    const list = try p.finish();
    defer freeAll(gpa, list);
    try testing.expectEqual(@as(usize, 1), list.len);
    const w = &list[0];
    try testing.expectEqualStrings("phy0", w.name());
    try testing.expectEqual(@as(?u8, 20), w.max_num_scan_ssids);
    try testing.expectEqual(@as(?u16, 413), w.max_scan_ie_len);
    try testing.expect(w.supportsCipher(uapi.CIPHER.CCMP));
    try testing.expect(!w.supportsCipher(uapi.CIPHER.GCMP));
    try testing.expect(w.supportsIftype(.station));
    try testing.expect(w.supportsIftype(.ap));
    try testing.expect(!w.supportsIftype(.mesh_point));
    try testing.expectEqual(@as(usize, 1), w.bands.len);
    try testing.expectEqual(@as(usize, 2), w.channelCount());
    try testing.expectEqual(@as(u32, 2412), w.frequency(2412).?.freq_mhz);
    try testing.expectEqual(@as(?u32, 2000), w.frequency(2417).?.max_tx_power_mbm);
    try testing.expectEqual(@as(?*const Frequency, null), w.frequency(5180));
}

test "two radios interleaved in one dump stay separate" {
    const gpa = testing.allocator;
    var p: Parser = .init(gpa);
    defer p.deinit();
    for ([_]struct { idx: u32, nm: []const u8 }{
        .{ .idx = 0, .nm = "phy0" },
        .{ .idx = 1, .nm = "phy1" },
        .{ .idx = 0, .nm = "phy0" },
        .{ .idx = 1, .nm = "phy1" },
    }) |m| {
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(gpa);
        try codec.appendAttrU32(gpa, &buf, uapi.ATTR.WIPHY, m.idx);
        try codec.appendAttrString(gpa, &buf, uapi.ATTR.WIPHY_NAME, m.nm);
        try p.feed(buf.items);
    }
    const list = try p.finish();
    defer freeAll(gpa, list);
    try testing.expectEqual(@as(usize, 2), list.len);
    try testing.expectEqualStrings("phy0", list[0].name());
    try testing.expectEqualStrings("phy1", list[1].name());
}

test "a message with no wiphy index is dropped, not misattributed" {
    const gpa = testing.allocator;
    var p: Parser = .init(gpa);
    defer p.deinit();
    var m: std.ArrayList(u8) = .empty;
    defer m.deinit(gpa);
    try codec.appendAttrString(gpa, &m, uapi.ATTR.WIPHY_NAME, "orphan");
    try p.feed(m.items);
    const list = try p.finish();
    defer freeAll(gpa, list);
    try testing.expectEqual(@as(usize, 0), list.len);
}

test "the same channel index arriving twice updates, never duplicates" {
    const gpa = testing.allocator;
    var p: Parser = .init(gpa);
    defer p.deinit();
    for ([_]bool{ false, true }) |second| {
        var m: std.ArrayList(u8) = .empty;
        defer m.deinit(gpa);
        try codec.appendAttrU32(gpa, &m, uapi.ATTR.WIPHY, 0);
        const bands = try openNest(gpa, &m, uapi.ATTR.WIPHY_BANDS);
        const band0 = try openNest(gpa, &m, 0);
        const freqs = try openNest(gpa, &m, uapi.BAND_ATTR.FREQS);
        const entry = try openNest(gpa, &m, 0);
        try codec.appendAttrU32(gpa, &m, uapi.FREQUENCY_ATTR.FREQ, 5500);
        if (second) try codec.appendAttr(gpa, &m, uapi.FREQUENCY_ATTR.RADAR, &.{});
        codec.nestEnd(&m, entry);
        codec.nestEnd(&m, freqs);
        codec.nestEnd(&m, band0);
        codec.nestEnd(&m, bands);
        try p.feed(m.items);
    }
    const list = try p.finish();
    defer freeAll(gpa, list);
    try testing.expectEqual(@as(usize, 1), list[0].bands.len);
    try testing.expectEqual(@as(usize, 1), list[0].bands[0].freqs.len);
    try testing.expect(list[0].bands[0].freqs[0].radar);
}

test "malformed wiphy attributes yield typed errors" {
    const gpa = testing.allocator;
    var p: Parser = .init(gpa);
    defer p.deinit();
    // CIPHER_SUITES whose length is not a multiple of 4.
    var m: std.ArrayList(u8) = .empty;
    defer m.deinit(gpa);
    try codec.appendAttrU32(gpa, &m, uapi.ATTR.WIPHY, 0);
    try codec.appendAttr(gpa, &m, uapi.ATTR.CIPHER_SUITES, &.{ 1, 2, 3 });
    try testing.expectError(error.BadLength, p.feed(m.items));

    // A truncated top-level TLV.
    try testing.expectError(error.Truncated, p.feed(&.{ 0x40, 0x00, 0x01 }));
}

test "finish on an empty parser returns an empty list" {
    const gpa = testing.allocator;
    var p: Parser = .init(gpa);
    defer p.deinit();
    const list = try p.finish();
    defer freeAll(gpa, list);
    try testing.expectEqual(@as(usize, 0), list.len);
}

test "fuzz: the wiphy parser never crashes and never leaks" {
    try testing.fuzz({}, fuzzFeed, .{});
}

fn fuzzFeed(_: void, smith: *std.testing.Smith) !void {
    var raw: [512]u8 = undefined;
    smith.bytes(&raw);
    const len = smith.valueRangeAtMost(u16, 0, raw.len);
    var p: Parser = .init(testing.allocator);
    defer p.deinit();
    p.feed(raw[0..len]) catch return;
    const list = p.finish() catch return;
    freeAll(testing.allocator, list);
}
