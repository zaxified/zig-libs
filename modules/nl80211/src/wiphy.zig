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
const capdefs = @import("caps.zig");
// Test-only (`build.zig`'s `test_deps`, never `deps`): the fuzz corpus seed
// helpers, in the format `std.testing.Smith` actually reads.
const testkit = @import("testkit");

pub const Error = codec.Error || error{
    OutOfMemory,
    /// A valid reply that declares more radios, bands or channels than
    /// `max_wiphys` / `max_bands` / `max_channels_per_band`. Not a malformed
    /// reply: the parser refuses to grow (and to scan) without bound.
    TooManyEntries,
};

/// Parser ceilings (sweep NL-1). The merge keys are looked up linearly (radios,
/// bands) or through a hash map (channels), and everything accumulates across
/// the messages of a split dump, so without them a dump of tiny messages grows
/// the state and the work per message without bound. Real hardware: a handful
/// of radios, at most 6 bands, ~230 channels in the largest (6 GHz) band.
pub const max_wiphys = 256;
pub const max_bands = 16;
pub const max_channels_per_band = 1024;
/// Aggregate over all radios and bands of one parse: the three ceilings above
/// multiply (256 x 16 x 1024 = 4 M entries, ~190 MiB), this one does not.
/// Real hardware: ~300 channels per radio, at most 8 radios.
pub const max_total_channels = 16384;
/// Bytes of the extended-feature bitmap kept (the kernel defines ~80 bits
/// today; this holds 256). A longer bitmap is `TooManyEntries`.
pub const max_ext_feature_bytes = 32;

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
    /// Decoded HT capability fields (see `capdefs.HtCaps`), when advertised.
    ht_caps: ?capdefs.HtCaps = null,
    /// Decoded VHT capability fields (see `capdefs.VhtCaps`), when advertised.
    vht_caps: ?capdefs.VhtCaps = null,
    he_buf: [capdefs.max_he_sets]capdefs.HeCaps = @splat(.{}),
    n_he: u8 = 0,

    /// HE capability sets of this band, one per interface-type group.
    pub fn heSets(b: *const Band) []const capdefs.HeCaps {
        return b.he_buf[0..b.n_he];
    }
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

    /// Interface combinations the radio can run (`iw list`'s "valid interface
    /// combinations"); read them through `ifaceCombinations`.
    comb_buf: [capdefs.max_iface_combinations]capdefs.IfaceCombination = @splat(.{}),
    n_combinations: u8 = 0,
    /// The `NL80211_ATTR_EXT_FEATURES` bitmap; test with `hasExtFeature`.
    ext_features_buf: [max_ext_feature_bytes]u8 = @splat(0),
    ext_features_len: u8 = 0,

    name_buf: [max_wiphy_name]u8 = @splat(0),
    name_len: u8 = 0,

    /// The radio name (`phy0`).
    pub fn name(w: *const Wiphy) []const u8 {
        return w.name_buf[0..w.name_len];
    }

    pub fn ifaceCombinations(w: *const Wiphy) []const capdefs.IfaceCombination {
        return w.comb_buf[0..w.n_combinations];
    }

    /// Is extended feature `bit` (an `uapi.EXT_FEATURE` value) advertised?
    pub fn hasExtFeature(w: *const Wiphy, bit: u16) bool {
        return capdefs.hasBit(w.ext_features_buf[0..w.ext_features_len], bit);
    }

    pub fn supportsIftype(w: *const Wiphy, t: uapi.Iftype) bool {
        const n = @backingInt(t);
        if (n >= 32) return false;
        return w.iftypes & (@as(u32, 1) << @intCast(n)) != 0;
    }

    pub fn supportsCipher(w: *const Wiphy, suite: u32) bool {
        return std.mem.findScalar(u32, w.ciphers, suite) != null;
    }

    /// Is `cmd` in `NL80211_ATTR_SUPPORTED_COMMANDS`?
    ///
    /// **This is "advertised", not "possible".** The kernel publishes a
    /// partial list — chiefly the MLME commands a driver opted into — and a
    /// radio that scans perfectly well does not necessarily list
    /// `TRIGGER_SCAN` (the development machine's does not; `goldens.zig` pins
    /// that). Infer scan capability from `max_num_scan_ssids` instead.
    pub fn supportsCommand(w: *const Wiphy, cmd: u8) bool {
        return std.mem.findScalar(u32, w.commands, cmd) != null;
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
    /// `Frequency.index` -> position in `freqs`.
    freq_pos: std.AutoHashMapUnmanaged(u32, u32) = .empty,
    rates: std.ArrayList(u32) = .empty,
    ht: bool = false,
    vht: bool = false,
    ht_caps: ?capdefs.HtCaps = null,
    vht_caps: ?capdefs.VhtCaps = null,
    he_buf: [capdefs.max_he_sets]capdefs.HeCaps = @splat(.{}),
    n_he: u8 = 0,
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
    /// Channels held across all radios and bands (`max_total_channels`).
    n_channels: u32 = 0,

    pub fn init(gpa: std.mem.Allocator) Parser {
        return .{ .gpa = gpa };
    }

    pub fn deinit(p: *Parser) void {
        for (p.builders.items) |*b| {
            for (b.bands.items) |*bb| {
                bb.freqs.deinit(p.gpa);
                bb.freq_pos.deinit(p.gpa);
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
            uapi.ATTR.EXT_FEATURES => {
                if (a.data.len > max_ext_feature_bytes) return error.TooManyEntries;
                @memcpy(b.w.ext_features_buf[0..a.data.len], a.data);
                b.w.ext_features_len = @intCast(a.data.len);
            },
            uapi.ATTR.INTERFACE_COMBINATIONS => try feedCombinations(&b.w, a.data),
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
                    .ht_caps = bb.ht_caps,
                    .vht_caps = bb.vht_caps,
                    .he_buf = bb.he_buf,
                    .n_he = bb.n_he,
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
                bb.freq_pos.deinit(p.gpa);
                bb.rates.deinit(p.gpa);
            }
            b.bands.deinit(p.gpa);
            b.ciphers.deinit(p.gpa);
            b.commands.deinit(p.gpa);
        }
        p.builders.clearRetainingCapacity();
        p.n_channels = 0;
        return out.toOwnedSlice(p.gpa);
    }

    fn builderFor(p: *Parser, idx: u32) Error!*WiphyBuilder {
        for (p.builders.items) |*b| if (b.w.index == idx) return b;
        if (p.builders.items.len >= max_wiphys) return error.TooManyEntries;
        try p.builders.append(p.gpa, .{ .w = .{ .index = idx } });
        return &p.builders.items[p.builders.items.len - 1];
    }

    fn feedBands(p: *Parser, b: *WiphyBuilder, nest: []const u8) Error!void {
        var it: codec.AttrIterator = .{ .buf = nest };
        while (try it.next()) |band_attr| {
            const bb = try bandBuilderFor(p.gpa, b, band_attr.type);
            var inner: codec.AttrIterator = .{ .buf = band_attr.data };
            while (try inner.next()) |a| switch (a.type) {
                uapi.BAND_ATTR.FREQS => try feedFreqs(p.gpa, bb, a.data, &p.n_channels),
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
                uapi.BAND_ATTR.HT_CAPA => {
                    bb.ht = true;
                    if (bb.ht_caps == null) bb.ht_caps = .{};
                    bb.ht_caps.?.capa = try a.asU16();
                },
                uapi.BAND_ATTR.HT_MCS_SET => {
                    bb.ht = true;
                    if (a.data.len != 16) return error.BadLength;
                    if (bb.ht_caps == null) bb.ht_caps = .{};
                    bb.ht_caps.?.mcs_set = a.data[0..16].*;
                },
                uapi.BAND_ATTR.HT_AMPDU_FACTOR => {
                    if (bb.ht_caps == null) bb.ht_caps = .{};
                    bb.ht_caps.?.ampdu_factor = try a.asU8();
                },
                uapi.BAND_ATTR.HT_AMPDU_DENSITY => {
                    if (bb.ht_caps == null) bb.ht_caps = .{};
                    bb.ht_caps.?.ampdu_density = try a.asU8();
                },
                uapi.BAND_ATTR.VHT_CAPA => {
                    bb.vht = true;
                    if (bb.vht_caps == null) bb.vht_caps = .{};
                    bb.vht_caps.?.capa = try a.asU32();
                },
                uapi.BAND_ATTR.VHT_MCS_SET => {
                    bb.vht = true;
                    if (a.data.len != 8) return error.BadLength;
                    if (bb.vht_caps == null) bb.vht_caps = .{};
                    bb.vht_caps.?.mcs_set = a.data[0..8].*;
                },
                uapi.BAND_ATTR.IFTYPE_DATA => try feedHeSets(bb, a.data),
                else => {},
            };
        }
    }
};

/// `NL80211_BAND_ATTR_IFTYPE_DATA`: one entry per interface-type group, each
/// keyed by its nest index so a split dump merges instead of duplicating.
fn feedHeSets(bb: *BandBuilder, nest: []const u8) Error!void {
    var it: codec.AttrIterator = .{ .buf = nest };
    while (try it.next()) |entry| {
        var slot: ?*capdefs.HeCaps = null;
        for (bb.he_buf[0..bb.n_he]) |*h| {
            if (h.index == entry.type) slot = h;
        }
        const h = slot orelse blk: {
            if (bb.n_he >= capdefs.max_he_sets) return error.TooManyEntries;
            bb.he_buf[bb.n_he] = .{ .index = entry.type };
            bb.n_he += 1;
            break :blk &bb.he_buf[bb.n_he - 1];
        };
        var inner: codec.AttrIterator = .{ .buf = entry.data };
        while (try inner.next()) |a| switch (a.type) {
            uapi.BAND_IFTYPE_ATTR.IFTYPES => h.iftypes = try flagSetToBits(a.data),
            uapi.BAND_IFTYPE_ATTR.HE_CAP_MAC => {
                if (a.data.len != 6) return error.BadLength;
                h.mac = a.data[0..6].*;
            },
            uapi.BAND_IFTYPE_ATTR.HE_CAP_PHY => {
                if (a.data.len != 11) return error.BadLength;
                h.phy = a.data[0..11].*;
            },
            uapi.BAND_IFTYPE_ATTR.HE_CAP_MCS_SET => {
                if (a.data.len != 4 and a.data.len != 8 and a.data.len != 12) return error.BadLength;
                h.mcs_set = @splat(0);
                @memcpy(h.mcs_set[0..a.data.len], a.data);
                h.mcs_len = @intCast(a.data.len);
            },
            else => {},
        };
    }
}

/// `NL80211_ATTR_INTERFACE_COMBINATIONS`: the whole list arrives in one
/// attribute, so it replaces what an earlier message left.
fn feedCombinations(w: *Wiphy, nest: []const u8) Error!void {
    w.n_combinations = 0;
    var it: codec.AttrIterator = .{ .buf = nest };
    while (try it.next()) |entry| {
        if (w.n_combinations >= capdefs.max_iface_combinations) return error.TooManyEntries;
        var c: capdefs.IfaceCombination = .{};
        var inner: codec.AttrIterator = .{ .buf = entry.data };
        while (try inner.next()) |a| switch (a.type) {
            uapi.IFACE_COMB.LIMITS => {
                var lim_it: codec.AttrIterator = .{ .buf = a.data };
                while (try lim_it.next()) |lim| {
                    if (c.n_limits >= capdefs.max_iface_limits) return error.TooManyEntries;
                    var l: capdefs.IfaceLimit = .{};
                    var f: codec.AttrIterator = .{ .buf = lim.data };
                    while (try f.next()) |x| switch (x.type) {
                        uapi.IFACE_LIMIT.MAX => l.max = try x.asU32(),
                        uapi.IFACE_LIMIT.TYPES => l.types = try flagSetToBits(x.data),
                        else => {},
                    };
                    c.limits_buf[c.n_limits] = l;
                    c.n_limits += 1;
                }
            },
            uapi.IFACE_COMB.MAXNUM => c.max_total = try a.asU32(),
            uapi.IFACE_COMB.NUM_CHANNELS => c.num_channels = try a.asU32(),
            uapi.IFACE_COMB.STA_AP_BI_MATCH => c.sta_ap_bi_match = true,
            uapi.IFACE_COMB.RADAR_DETECT_WIDTHS => c.radar_detect_widths = try a.asU32(),
            uapi.IFACE_COMB.RADAR_DETECT_REGIONS => c.radar_detect_regions = try a.asU32(),
            else => {},
        };
        w.comb_buf[w.n_combinations] = c;
        w.n_combinations += 1;
    }
}

fn bandBuilderFor(gpa: std.mem.Allocator, b: *WiphyBuilder, index: u32) Error!*BandBuilder {
    for (b.bands.items) |*bb| if (bb.index == index) return bb;
    if (b.bands.items.len >= max_bands) return error.TooManyEntries;
    try b.bands.append(gpa, .{ .index = index });
    return &b.bands.items[b.bands.items.len - 1];
}

fn feedFreqs(gpa: std.mem.Allocator, bb: *BandBuilder, nest: []const u8, total: *u32) Error!void {
    var it: codec.AttrIterator = .{ .buf = nest };
    while (try it.next()) |entry| {
        const f = try freqFor(gpa, bb, entry.type, total);
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

fn freqFor(gpa: std.mem.Allocator, bb: *BandBuilder, index: u32, total: *u32) Error!*Frequency {
    if (bb.freq_pos.get(index)) |pos| return &bb.freqs.items[pos];
    if (bb.freqs.items.len >= max_channels_per_band) return error.TooManyEntries;
    if (total.* >= max_total_channels) return error.TooManyEntries;
    const pos: u32 = @intCast(bb.freqs.items.len); // < max_channels_per_band
    try bb.freq_pos.put(gpa, index, pos);
    errdefer _ = bb.freq_pos.remove(index);
    try bb.freqs.append(gpa, .{ .index = index });
    total.* += 1;
    return &bb.freqs.items[pos];
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
        try codec.appendAttr(gpa, &m, @backingInt(uapi.Iftype.station), &.{});
        try codec.appendAttr(gpa, &m, @backingInt(uapi.Iftype.ap), &.{});
        codec.nestEnd(&m, off) catch return error.InvalidRequest;
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
        codec.nestEnd(&m, entry) catch return error.InvalidRequest;
        codec.nestEnd(&m, freqs) catch return error.InvalidRequest;
        codec.nestEnd(&m, band0) catch return error.InvalidRequest;
        codec.nestEnd(&m, bands) catch return error.InvalidRequest;
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
        codec.nestEnd(&m, entry) catch return error.InvalidRequest;
        codec.nestEnd(&m, freqs) catch return error.InvalidRequest;
        codec.nestEnd(&m, band0) catch return error.InvalidRequest;
        codec.nestEnd(&m, bands) catch return error.InvalidRequest;
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

/// GET_WIPHY split-dump messages for `fuzzFeed`, in the format `Smith.slice` reads (see
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
    entries: [8][]const u8 = undefined,
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

        // Identity plus scan limits: the first message of a split dump.
        var identity: std.ArrayList(u8) = .empty;
        try codec.appendAttrU32(gpa, &identity, uapi.ATTR.WIPHY, 0);
        try codec.appendAttrString(gpa, &identity, uapi.ATTR.WIPHY_NAME, "phy0");
        try codec.appendAttrU8(gpa, &identity, uapi.ATTR.MAX_NUM_SCAN_SSIDS, 20);
        try codec.appendAttrU16(gpa, &identity, uapi.ATTR.MAX_SCAN_IE_LEN, 413);
        self.push(identity.items);

        // Ciphers and supported iftypes.
        var caps: std.ArrayList(u8) = .empty;
        try codec.appendAttrU32(gpa, &caps, uapi.ATTR.WIPHY, 0);
        try codec.appendAttrString(gpa, &caps, uapi.ATTR.WIPHY_NAME, "phy0");
        try codec.appendAttr(gpa, &caps, uapi.ATTR.CIPHER_SUITES, &.{
            0x01, 0xac, 0x0f, 0x00, // WEP40
            0x04, 0xac, 0x0f, 0x00, // CCMP
        });
        {
            const off = try codec.nestBegin(gpa, &caps, uapi.ATTR.SUPPORTED_IFTYPES);
            try codec.appendAttr(gpa, &caps, @backingInt(uapi.Iftype.station), &.{});
            try codec.appendAttr(gpa, &caps, @backingInt(uapi.Iftype.ap), &.{});
            try codec.nestEnd(&caps, off);
        }
        self.push(caps.items);

        // One band with two channels — the nest-inside-nest-inside-nest shape
        // that is the whole reason this parser exists.
        var band: std.ArrayList(u8) = .empty;
        try codec.appendAttrU32(gpa, &band, uapi.ATTR.WIPHY, 0);
        {
            const bands = try codec.nestBegin(gpa, &band, uapi.ATTR.WIPHY_BANDS);
            const band0 = try codec.nestBegin(gpa, &band, 0);
            const freqs = try codec.nestBegin(gpa, &band, uapi.BAND_ATTR.FREQS);
            for ([_]struct { idx: u16, mhz: u32 }{
                .{ .idx = 0, .mhz = 2412 },
                .{ .idx = 1, .mhz = 2417 },
            }) |ch| {
                const entry = try codec.nestBegin(gpa, &band, ch.idx);
                try codec.appendAttrU32(gpa, &band, uapi.FREQUENCY_ATTR.FREQ, ch.mhz);
                try codec.appendAttrU32(gpa, &band, uapi.FREQUENCY_ATTR.MAX_TX_POWER, 2000);
                try codec.nestEnd(&band, entry);
            }
            try codec.nestEnd(&band, freqs);
            try codec.nestEnd(&band, band0);
            try codec.nestEnd(&band, bands);
        }
        self.push(band.items);

        // ── the shapes the merge rules exist for ───────────────────────────
        // A message with no wiphy index at all: dropped, not misattributed.
        var anonymous: std.ArrayList(u8) = .empty;
        try codec.appendAttrString(gpa, &anonymous, uapi.ATTR.WIPHY_NAME, "phyX");
        self.push(anonymous.items);
        // A second radio.
        var phy1: std.ArrayList(u8) = .empty;
        try codec.appendAttrU32(gpa, &phy1, uapi.ATTR.WIPHY, 1);
        try codec.appendAttrString(gpa, &phy1, uapi.ATTR.WIPHY_NAME, "phy1");
        self.push(phy1.items);
        // A TLV header declaring 0x40 octets over a 2-octet buffer, and a
        // WIPHY index that is not four octets wide.
        self.push(&[_]u8{ 0x40, 0x00 });
        var narrow: std.ArrayList(u8) = .empty;
        try codec.appendAttrU16(gpa, &narrow, uapi.ATTR.WIPHY, 0);
        self.push(narrow.items);

        return self.entries[0..self.n];
    }
};

const fz = @import("fuzz_test.zig");
const WiphyMark = fz.Marker(enum { rejected, wiphys });

test "fuzz: the wiphy parser never crashes and never leaks" {
    var corpus: Corpus = .{};
    try testing.fuzz({}, fuzzFeedSmith, .{ .corpus = try corpus.build() });
}

test "fuzz driver: NL80211_FUZZ (wiphy parser)" {
    try fz.fuzz_driver.run(fuzzFeed, .{ .prefix = "NL80211_FUZZ", .name = "nl80211-wiphy" });
}

test "fuzz harness: wiphy parser, 300 seeds, reaches every outcome" {
    try WiphyMark.reach(fuzzFeed, "nl80211-wiphy", 300);
}

fn fuzzFeedSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [fz.script_cap]u8 = undefined;
    const n = smith.slice(&script);
    try fz.runFrom(fuzzFeed, smith, script[0..n]);
}

fn fuzzFeed(comptime S: type, smith: *S, gpa: std.mem.Allocator) anyerror!void {
    var raw: [512]u8 = undefined;
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
    // length. `bytes` takes `@min(raw.len, in.len)` octets and the ranged draw
    // then finds fewer than the eight it needs and returns the range MINIMUM,
    // so `len` was 0 for every seed and `Parser.feed` was handed an empty attribute list, with
    // the reply sitting unread in `raw`.
    //
    // ⛔ And it looked HEALTHIER that way: feeding an empty
    // message is legal and `finish()` then returns an empty list, so the
    // harness completed cleanly every round. Measured 2026-09-07 over the
    // corpus above: **0 of 7 seeds non-empty and 0 wiphys produced before; 7
    // of 7 non-empty and 4 wiphys after.** The wiphy count is the number that
    // says a message was ever attributed to a radio.
    var cstore: Corpus = .{};
    const entries: []const []const u8 = if (S == fz.fuzz_driver.Rng) (cstore.build() catch &.{}) else &.{};
    const len: usize = fz.drawInput(S, smith, &raw, entries);
    var p: Parser = .init(gpa);
    defer p.deinit();
    p.feed(raw[0..len]) catch return WiphyMark.mark(.rejected);
    const list = p.finish() catch return WiphyMark.mark(.rejected);
    if (list.len != 0) WiphyMark.mark(.wiphys);
    freeAll(gpa, list);
}

test "corpus: every wiphy seed reaches the parser, and the counts are pinned" {
    // ⭐ The measurement, executable rather than written in a comment, over the
    // SAME corpus the harness gets. `nonempty` is the reach claim and the only
    // check that catches a seed grown past the harness's buffer, which
    // `Smith.slice` reads back as the EMPTY one, silently. The second number
    // is what the first cannot say: an empty attribute list is a legal reply
    // here, so "parsed" alone counts a harness that walks nothing as a
    // success.
    //
    // ⚠ One seed is one message and one `Parser`, which is what the harness
    // does — the merge of a radio split across several messages is covered by
    // the value tests above, not here.
    var corpus: Corpus = .{};
    const entries = try corpus.build();
    var nonempty: usize = 0;
    var fed: usize = 0;
    var wiphys: usize = 0;
    for (entries) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var raw: [512]u8 = undefined;
        const len: usize = smith.slice(&raw);
        if (len != 0) nonempty += 1;
        var p: Parser = .init(testing.allocator);
        defer p.deinit();
        p.feed(raw[0..len]) catch continue;
        fed += 1;
        const list = p.finish() catch continue;
        wiphys += list.len;
        freeAll(testing.allocator, list);
    }
    try testing.expectEqual(entries.len, nonempty);
    try testing.expectEqual(@as(usize, 5), fed);
    try testing.expectEqual(@as(usize, 4), wiphys);
}

fn heEntry(gpa: std.mem.Allocator, m: *std.ArrayList(u8), idx: u16, iftype: uapi.Iftype, mac: []const u8, phy: []const u8, mcs: []const u8) !void {
    const e = try codec.nestBegin(gpa, m, idx);
    const it = try codec.nestBegin(gpa, m, uapi.BAND_IFTYPE_ATTR.IFTYPES);
    try codec.appendAttr(gpa, m, @intCast(@backingInt(iftype)), &.{});
    try codec.nestEnd(m, it);
    try codec.appendAttr(gpa, m, uapi.BAND_IFTYPE_ATTR.HE_CAP_MAC, mac);
    try codec.appendAttr(gpa, m, uapi.BAND_IFTYPE_ATTR.HE_CAP_PHY, phy);
    try codec.appendAttr(gpa, m, uapi.BAND_IFTYPE_ATTR.HE_CAP_MCS_SET, mcs);
    try codec.nestEnd(m, e);
}

fn heMessage(gpa: std.mem.Allocator, m: *std.ArrayList(u8), entries: []const struct { u16, uapi.Iftype, []const u8 }) !void {
    try codec.appendAttrU32(gpa, m, uapi.ATTR.WIPHY, 0);
    const bands = try codec.nestBegin(gpa, m, uapi.ATTR.WIPHY_BANDS);
    const band = try codec.nestBegin(gpa, m, 1);
    const data = try codec.nestBegin(gpa, m, uapi.BAND_ATTR.IFTYPE_DATA);
    const mac: [6]u8 = .{ 1, 2, 3, 4, 5, 6 };
    const phy: [11]u8 = .{ 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20 };
    for (entries) |e| try heEntry(gpa, m, e[0], e[1], &mac, &phy, e[2]);
    try codec.nestEnd(m, data);
    try codec.nestEnd(m, band);
    try codec.nestEnd(m, bands);
}

test "HE capabilities: one set per interface-type group, merged by nest index across messages" {
    const gpa = testing.allocator;
    var p: Parser = .init(gpa);
    defer p.deinit();
    const mcs4 = [_]u8{ 0xfa, 0xff, 0xfa, 0xff };
    const mcs8 = [_]u8{ 0xfa, 0xff, 0xfa, 0xff, 0xfa, 0xff, 0xfa, 0xff };
    {
        var m: std.ArrayList(u8) = .empty;
        defer m.deinit(gpa);
        try heMessage(gpa, &m, &.{ .{ 0, .station, &mcs8 }, .{ 1, .ap, &mcs4 } });
        try p.feed(m.items);
    }
    {
        // The same entry 0 again (a split dump repeating it): updated, not duplicated.
        var m: std.ArrayList(u8) = .empty;
        defer m.deinit(gpa);
        try heMessage(gpa, &m, &.{.{ 0, .station, &mcs4 }});
        try p.feed(m.items);
    }
    const list = try p.finish();
    defer freeAll(gpa, list);
    const sets = list[0].band(1).?.heSets();
    try testing.expectEqual(@as(usize, 2), sets.len);
    try testing.expectEqual(@as(u32, 0), sets[0].index);
    try testing.expect(sets[0].supportsIftype(@backingInt(uapi.Iftype.station)));
    try testing.expect(!sets[0].supportsIftype(@backingInt(uapi.Iftype.ap)));
    try testing.expectEqual(@as(u8, 4), sets[0].mcs_len); // the second message won
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5, 6 }, &sets[0].mac);
    try testing.expectEqual(@as(u8, 20), sets[0].phy[10]);
    try testing.expect(sets[1].supportsIftype(@backingInt(uapi.Iftype.ap)));
}

test "HE capabilities: odd field widths are BadLength, too many sets TooManyEntries" {
    const gpa = testing.allocator;
    {
        var p: Parser = .init(gpa);
        defer p.deinit();
        var m: std.ArrayList(u8) = .empty;
        defer m.deinit(gpa);
        const bad = [_]u8{ 1, 2, 3 };
        try heMessage(gpa, &m, &.{.{ 0, .station, &bad }});
        try testing.expectError(error.BadLength, p.feed(m.items));
    }
    {
        var p: Parser = .init(gpa);
        defer p.deinit();
        var m: std.ArrayList(u8) = .empty;
        defer m.deinit(gpa);
        const mcs4 = [_]u8{ 0, 0, 0, 0 };
        var entries: [capdefs.max_he_sets + 1]struct { u16, uapi.Iftype, []const u8 } = undefined;
        for (&entries, 0..) |*e, i| e.* = .{ @intCast(i), .station, &mcs4 };
        try heMessage(gpa, &m, &entries);
        try testing.expectError(error.TooManyEntries, p.feed(m.items));
    }
}

test "interface combinations and extended features: ceilings and replacement" {
    const gpa = testing.allocator;
    var p: Parser = .init(gpa);
    defer p.deinit();
    // 33 combinations: one over the ceiling.
    var m: std.ArrayList(u8) = .empty;
    defer m.deinit(gpa);
    try codec.appendAttrU32(gpa, &m, uapi.ATTR.WIPHY, 0);
    const nest = try codec.nestBegin(gpa, &m, uapi.ATTR.INTERFACE_COMBINATIONS);
    var i: u16 = 0;
    while (i <= capdefs.max_iface_combinations) : (i += 1) {
        const c = try codec.nestBegin(gpa, &m, i);
        try codec.appendAttrU32(gpa, &m, uapi.IFACE_COMB.MAXNUM, 1);
        try codec.nestEnd(&m, c);
    }
    try codec.nestEnd(&m, nest);
    try testing.expectError(error.TooManyEntries, p.feed(m.items));

    // An over-long extended-feature bitmap (a parser that failed is dropped by
    // real callers; this one is reused only to reach the next case).
    var m2: std.ArrayList(u8) = .empty;
    defer m2.deinit(gpa);
    try codec.appendAttrU32(gpa, &m2, uapi.ATTR.WIPHY, 0);
    const long: [max_ext_feature_bytes + 1]u8 = @splat(0xff);
    try codec.appendAttr(gpa, &m2, uapi.ATTR.EXT_FEATURES, &long);
    try testing.expectError(error.TooManyEntries, p.feed(m2.items));

    // A short one: bits past its end read as false, not as a panic.
    var m3: std.ArrayList(u8) = .empty;
    defer m3.deinit(gpa);
    try codec.appendAttrU32(gpa, &m3, uapi.ATTR.WIPHY, 0);
    try codec.appendAttr(gpa, &m3, uapi.ATTR.EXT_FEATURES, &.{0x01});
    try p.feed(m3.items);
    const list = try p.finish();
    defer freeAll(gpa, list);
    try testing.expect(list[0].hasExtFeature(0));
    try testing.expect(!list[0].hasExtFeature(1));
    try testing.expect(!list[0].hasExtFeature(8));
}
