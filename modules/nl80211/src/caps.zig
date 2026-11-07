// SPDX-License-Identifier: MIT
//! Radio capability fields a `GET_WIPHY` band carries beyond its channel list:
//! HT (802.11n) and VHT (802.11ac) capability words with named accessors, HE
//! (802.11ax) capability bytes, interface combinations and the extended
//! feature bitmap.
//!
//! The bit positions are IEEE 802.11-2020 §9.4.2.55 (HT Capabilities element)
//! and §9.4.2.157 (VHT Capabilities element) — the kernel hands the raw
//! capability words through unchanged (`NL80211_BAND_ATTR_HT_CAPA`,
//! `_VHT_CAPA`, …). The HT and VHT accessors are checked against the real
//! iwlwifi radio in `goldens.zig`; HE carries the raw `HE MAC` / `HE PHY`
//! capability bytes without per-bit accessors (this host has no HE radio to
//! anchor them against, so none are guessed).

const std = @import("std");

/// `NL80211_BAND_ATTR_HT_CAPA` + `_HT_AMPDU_FACTOR` + `_HT_AMPDU_DENSITY` +
/// `_HT_MCS_SET` of one band.
pub const HtCaps = struct {
    /// HT Capabilities Info field.
    capa: u16 = 0,
    /// A-MPDU parameters: max length exponent (the length is
    /// `2^(13 + factor) - 1` bytes, factor 0 to 3).
    ampdu_factor: u8 = 0,
    /// Minimum MPDU start spacing code (0 none, 1 = 1/4 us … 7 = 16 us).
    ampdu_density: u8 = 0,
    /// Supported MCS set, 16 bytes: bytes 0 to 9 are the RX MCS bitmask
    /// (MCS 0 to 76), bytes 10 to 11 the highest supported RX rate in Mbit/s
    /// (10 bits), byte 12 the TX parameters.
    mcs_set: [16]u8 = @splat(0),

    pub fn ldpcRx(h: HtCaps) bool {
        return h.capa & 0x0001 != 0;
    }
    /// 20 and 40 MHz operation (otherwise 20 MHz only).
    pub fn cw40(h: HtCaps) bool {
        return h.capa & 0x0002 != 0;
    }
    /// Spatial multiplexing power save: 0 static, 1 dynamic, 3 disabled.
    pub fn smPowerSave(h: HtCaps) u2 {
        return @truncate(h.capa >> 2);
    }
    pub fn greenfield(h: HtCaps) bool {
        return h.capa & 0x0010 != 0;
    }
    pub fn sgi20(h: HtCaps) bool {
        return h.capa & 0x0020 != 0;
    }
    pub fn sgi40(h: HtCaps) bool {
        return h.capa & 0x0040 != 0;
    }
    pub fn txStbc(h: HtCaps) bool {
        return h.capa & 0x0080 != 0;
    }
    /// Number of spatial streams the radio can receive with STBC (0 to 3).
    pub fn rxStbcStreams(h: HtCaps) u2 {
        return @truncate(h.capa >> 8);
    }
    pub fn delayedBlockAck(h: HtCaps) bool {
        return h.capa & 0x0400 != 0;
    }
    /// Maximum A-MSDU length: 7935 bytes when true, else 3839.
    pub fn amsdu7935(h: HtCaps) bool {
        return h.capa & 0x0800 != 0;
    }
    pub fn dsssCck40(h: HtCaps) bool {
        return h.capa & 0x1000 != 0;
    }
    pub fn intolerant40(h: HtCaps) bool {
        return h.capa & 0x4000 != 0;
    }
    /// Maximum A-MPDU length in bytes.
    pub fn maxAmpduLen(h: HtCaps) u32 {
        return (@as(u32, 1) << @intCast(13 + @as(u32, h.ampdu_factor & 3))) - 1;
    }
    /// Spatial streams the RX MCS bitmask supports (1 to 4), 0 when none.
    pub fn rxStreams(h: HtCaps) u8 {
        var n: u8 = 0;
        for (h.mcs_set[0..4], 1..) |b, i| {
            if (b != 0) n = @intCast(i);
        }
        return n;
    }
    /// Is MCS `n` (0 to 76) in the RX bitmask?
    pub fn rxMcs(h: HtCaps, n: u8) bool {
        if (n > 76) return false;
        return h.mcs_set[n / 8] >> @intCast(n % 8) & 1 != 0;
    }
    /// Highest supported RX data rate, Mbit/s (0 = not stated).
    pub fn rxHighestMbps(h: HtCaps) u16 {
        return std.mem.readInt(u16, h.mcs_set[10..12], .little) & 0x03ff;
    }
    /// Is the TX MCS set defined (byte 12 bit 0)?
    pub fn txMcsDefined(h: HtCaps) bool {
        return h.mcs_set[12] & 0x01 != 0;
    }
    /// Maximum TX spatial streams (1 to 4) when `txMcsDefined` and the TX set
    /// differs from the RX set; 0 otherwise.
    pub fn txMaxStreams(h: HtCaps) u8 {
        const b = h.mcs_set[12];
        if (b & 0x01 == 0 or b & 0x02 != 0) return 0;
        return @as(u8, (b >> 2) & 3) + 1;
    }
};

/// `NL80211_BAND_ATTR_VHT_CAPA` + `_VHT_MCS_SET` of one band.
pub const VhtCaps = struct {
    /// VHT Capabilities Info field.
    capa: u32 = 0,
    /// Supported VHT-MCS and NSS set, 8 bytes: RX MCS map (u16), RX highest
    /// rate (u16), TX MCS map (u16), TX highest rate (u16), little-endian.
    mcs_set: [8]u8 = @splat(0),

    /// Maximum MPDU length: 3895, 7991 or 11454 bytes (0 for the reserved code).
    pub fn maxMpduLen(v: VhtCaps) u32 {
        return switch (v.capa & 3) {
            0 => 3895,
            1 => 7991,
            2 => 11454,
            else => 0,
        };
    }
    /// Supported channel width set: 0 = 80 MHz only, 1 = also 160 MHz,
    /// 2 = also 160 and 80+80 MHz.
    pub fn chanWidthSet(v: VhtCaps) u2 {
        return @truncate(v.capa >> 2);
    }
    pub fn ldpcRx(v: VhtCaps) bool {
        return v.capa & (1 << 4) != 0;
    }
    pub fn sgi80(v: VhtCaps) bool {
        return v.capa & (1 << 5) != 0;
    }
    pub fn sgi160(v: VhtCaps) bool {
        return v.capa & (1 << 6) != 0;
    }
    pub fn txStbc(v: VhtCaps) bool {
        return v.capa & (1 << 7) != 0;
    }
    pub fn rxStbcStreams(v: VhtCaps) u3 {
        return @truncate(v.capa >> 8);
    }
    pub fn suBeamformer(v: VhtCaps) bool {
        return v.capa & (1 << 11) != 0;
    }
    pub fn suBeamformee(v: VhtCaps) bool {
        return v.capa & (1 << 12) != 0;
    }
    /// Beamformee STS capability (the field value; the radio supports that
    /// many plus one space-time streams).
    pub fn beamformeeSts(v: VhtCaps) u3 {
        return @truncate(v.capa >> 13);
    }
    pub fn muBeamformer(v: VhtCaps) bool {
        return v.capa & (1 << 19) != 0;
    }
    pub fn muBeamformee(v: VhtCaps) bool {
        return v.capa & (1 << 20) != 0;
    }
    /// Maximum A-MPDU length in bytes: `2^(13 + exponent) - 1`.
    pub fn maxAmpduLen(v: VhtCaps) u32 {
        const exp: u5 = @intCast(13 + ((v.capa >> 23) & 7));
        return (@as(u32, 1) << exp) - 1;
    }

    pub fn rxMcsMap(v: VhtCaps) u16 {
        return std.mem.readInt(u16, v.mcs_set[0..2], .little);
    }
    pub fn txMcsMap(v: VhtCaps) u16 {
        return std.mem.readInt(u16, v.mcs_set[4..6], .little);
    }
    /// Highest VHT-MCS (7, 8 or 9) the RX map allows for `nss` (1 to 8), or
    /// null when that stream count is not supported.
    pub fn rxMaxMcs(v: VhtCaps, nss: u8) ?u8 {
        return mapMcs(v.rxMcsMap(), nss);
    }
    pub fn txMaxMcs(v: VhtCaps, nss: u8) ?u8 {
        return mapMcs(v.txMcsMap(), nss);
    }
    /// Highest stream count with any MCS in the RX map (0 when none).
    pub fn rxStreams(v: VhtCaps) u8 {
        var n: u8 = 0;
        var i: u8 = 1;
        while (i <= 8) : (i += 1) {
            if (v.rxMaxMcs(i) != null) n = i;
        }
        return n;
    }
};

fn mapMcs(map: u16, nss: u8) ?u8 {
    if (nss < 1 or nss > 8) return null;
    const code: u2 = @truncate(map >> @intCast(2 * (nss - 1)));
    return switch (code) {
        0 => 7,
        1 => 8,
        2 => 9,
        3 => null,
    };
}

/// Most HE capability sets one band carries (one per interface-type group the
/// driver distinguishes; real radios advertise two to four).
pub const max_he_sets = 8;

/// One `NL80211_BAND_ATTR_IFTYPE_DATA` entry: the HE capabilities for a set of
/// interface types. The byte arrays are the HE MAC and PHY capability fields
/// of the HE Capabilities element (IEEE 802.11ax-2021 §9.4.2.248), unchanged.
pub const HeCaps = struct {
    /// Index of the entry in the kernel's nest — the merge key of a split dump.
    index: u32 = 0,
    /// Bit `n` set = `Iftype` number `n` uses these capabilities.
    iftypes: u32 = 0,
    mac: [6]u8 = @splat(0),
    phy: [11]u8 = @splat(0),
    /// Supported HE-MCS and NSS set: 4 bytes (up to 80 MHz), 8 (160 MHz) or
    /// 12 (80+80 MHz); `mcs_len` says which.
    mcs_set: [12]u8 = @splat(0),
    mcs_len: u8 = 0,

    pub fn supportsIftype(h: *const HeCaps, n: u5) bool {
        return h.iftypes & (@as(u32, 1) << n) != 0;
    }
};

/// Most limits one interface combination carries.
pub const max_iface_limits = 8;
/// Most interface combinations a radio reports (real radios: 2 to 10).
pub const max_iface_combinations = 32;

/// `NL80211_IFACE_LIMIT_*`: at most `max` interfaces whose type is in `types`.
pub const IfaceLimit = struct {
    max: u32 = 0,
    /// Bit `n` set = `Iftype` number `n` counts against this limit.
    types: u32 = 0,
};

/// One `NL80211_ATTR_INTERFACE_COMBINATIONS` entry: a set of interface counts
/// the radio can run at once (`iw list`'s "valid interface combinations").
pub const IfaceCombination = struct {
    limits_buf: [max_iface_limits]IfaceLimit = @splat(.{}),
    n_limits: u8 = 0,
    /// Interfaces in total.
    max_total: u32 = 0,
    /// Distinct channels the interfaces may occupy.
    num_channels: u32 = 0,
    /// All beaconing interfaces must share a beacon interval.
    sta_ap_bi_match: bool = false,
    /// Bit `n` set = radar detection works on `ChanWidth` number `n`.
    radar_detect_widths: u32 = 0,
    radar_detect_regions: u32 = 0,

    pub fn limits(c: *const IfaceCombination) []const IfaceLimit {
        return c.limits_buf[0..c.n_limits];
    }
};

/// Test bit `bit` (an `uapi.EXT_FEATURE` value) of an `EXT_FEATURES` byte
/// bitmap.
pub fn hasBit(bitmap: []const u8, bit: u16) bool {
    const byte = bit / 8;
    if (byte >= bitmap.len) return false;
    return bitmap[byte] >> @intCast(bit % 8) & 1 != 0;
}
