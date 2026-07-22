// SPDX-License-Identifier: MIT
//! nl80211 kernel UAPI constants — commands, top-level attributes, the nested
//! attribute spaces this module decodes, and the IEEE 802.11 cipher/AKM suite
//! selectors used by `CONNECT`.
//!
//! Clean-room from `linux/nl80211.h` (GPL-2.0 WITH Linux-syscall-note): the
//! numeric values are the kernel's OS ABI, not copyrightable interface code.
//! Only the subset this module actually encodes or decodes is transcribed —
//! nl80211 has 100+ commands and 350+ attributes and transcribing all of them
//! would be a maintenance liability with no consumer. The `raw` escape hatch in
//! `client.zig` covers everything not listed here.
//!
//! Every value below is asserted against the values `iw` put on the wire (see
//! `goldens.zig`) or read straight out of the header; the test at the bottom of
//! this file pins the ones that matter so a typo cannot ship silently.

const std = @import("std");

/// The genetlink family name. Its message-type id is **dynamic** and must be
/// resolved through nlctrl at runtime — never hardcode it (on the machine this
/// module was developed on it happened to be 41, on the next boot it may not
/// be).
pub const family_name = "nl80211";

/// The genl version this module speaks (`genlmsghdr.version`). nl80211 ignores
/// it on requests; `iw` sends 0 for family commands and 1 for nlctrl.
pub const family_version: u8 = 0;

// ── commands (enum nl80211_commands) ────────────────────────────────────────

pub const CMD = struct {
    pub const GET_WIPHY: u8 = 1;
    pub const NEW_WIPHY: u8 = 3;
    pub const GET_INTERFACE: u8 = 5;
    pub const NEW_INTERFACE: u8 = 7;
    pub const GET_STATION: u8 = 17;
    pub const NEW_STATION: u8 = 19;
    pub const REQ_SET_REG: u8 = 27;
    pub const GET_REG: u8 = 31;
    pub const GET_SCAN: u8 = 32;
    pub const TRIGGER_SCAN: u8 = 33;
    pub const NEW_SCAN_RESULTS: u8 = 34;
    pub const SCAN_ABORTED: u8 = 35;
    pub const REG_CHANGE: u8 = 36;
    pub const AUTHENTICATE: u8 = 37;
    pub const ASSOCIATE: u8 = 38;
    pub const DEAUTHENTICATE: u8 = 39;
    pub const DISASSOCIATE: u8 = 40;
    pub const CONNECT: u8 = 46;
    pub const ROAM: u8 = 47;
    pub const DISCONNECT: u8 = 48;
    pub const GET_SURVEY: u8 = 50;
    pub const NEW_SURVEY_RESULTS: u8 = 51;
    pub const GET_PROTOCOL_FEATURES: u8 = 95;
    pub const WIPHY_REG_CHANGE: u8 = 113;
};

// ── top-level attributes (enum nl80211_attrs) ──────────────────────────────

pub const ATTR = struct {
    pub const WIPHY: u16 = 1;
    pub const WIPHY_NAME: u16 = 2;
    pub const IFINDEX: u16 = 3;
    pub const IFNAME: u16 = 4;
    pub const IFTYPE: u16 = 5;
    pub const MAC: u16 = 6;
    pub const STA_INFO: u16 = 21;
    pub const WIPHY_BANDS: u16 = 22;
    pub const SUPPORTED_IFTYPES: u16 = 32;
    pub const REG_ALPHA2: u16 = 33;
    pub const REG_RULES: u16 = 34;
    pub const WIPHY_FREQ: u16 = 38;
    pub const IE: u16 = 42;
    pub const MAX_NUM_SCAN_SSIDS: u16 = 43;
    pub const SCAN_FREQUENCIES: u16 = 44;
    pub const SCAN_SSIDS: u16 = 45;
    pub const GENERATION: u16 = 46;
    pub const BSS: u16 = 47;
    pub const REG_INITIATOR: u16 = 48;
    pub const REG_TYPE: u16 = 49;
    pub const SUPPORTED_COMMANDS: u16 = 50;
    pub const SSID: u16 = 52;
    pub const AUTH_TYPE: u16 = 53;
    pub const REASON_CODE: u16 = 54;
    pub const MAX_SCAN_IE_LEN: u16 = 56;
    pub const CIPHER_SUITES: u16 = 57;
    pub const USE_MFP: u16 = 66;
    pub const CONTROL_PORT: u16 = 68;
    pub const PRIVACY: u16 = 70;
    pub const STATUS_CODE: u16 = 72;
    pub const CIPHER_SUITES_PAIRWISE: u16 = 73;
    pub const CIPHER_SUITE_GROUP: u16 = 74;
    pub const WPA_VERSIONS: u16 = 75;
    pub const AKM_SUITES: u16 = 76;
    pub const PREV_BSSID: u16 = 79;
    pub const KEYS: u16 = 81;
    pub const @"4ADDR": u16 = 83;
    pub const WIPHY_TX_POWER_LEVEL: u16 = 98;
    pub const SOFTWARE_IFTYPES: u16 = 121;
    pub const MAX_NUM_SCHED_SCAN_SSIDS: u16 = 123;
    pub const MAX_SCHED_SCAN_IE_LEN: u16 = 124;
    pub const FEATURE_FLAGS: u16 = 143;
    pub const DFS_REGION: u16 = 146;
    pub const WDEV: u16 = 153;
    pub const SCAN_FLAGS: u16 = 158;
    pub const CHANNEL_WIDTH: u16 = 159;
    pub const CENTER_FREQ1: u16 = 160;
    pub const CENTER_FREQ2: u16 = 161;
    pub const SPLIT_WIPHY_DUMP: u16 = 174;
    pub const SOCKET_OWNER: u16 = 204;
    pub const PMK: u16 = 254;
    pub const WANT_1X_4WAY_HS: u16 = 257;
    pub const SAE_PASSWORD: u16 = 277;
};

// ── nested attribute spaces ────────────────────────────────────────────────

/// enum nl80211_bss — inside `ATTR.BSS`.
pub const BSS = struct {
    pub const BSSID: u16 = 1;
    pub const FREQUENCY: u16 = 2;
    pub const TSF: u16 = 3;
    pub const BEACON_INTERVAL: u16 = 4;
    pub const CAPABILITY: u16 = 5;
    pub const INFORMATION_ELEMENTS: u16 = 6;
    pub const SIGNAL_MBM: u16 = 7;
    pub const SIGNAL_UNSPEC: u16 = 8;
    pub const STATUS: u16 = 9;
    pub const SEEN_MS_AGO: u16 = 10;
    pub const BEACON_IES: u16 = 11;
    pub const CHAN_WIDTH: u16 = 12;
    pub const BEACON_TSF: u16 = 13;
    pub const PRESP_DATA: u16 = 14;
    pub const LAST_SEEN_BOOTTIME: u16 = 15;
    pub const PAD: u16 = 16;
    pub const PARENT_TSF: u16 = 17;
    pub const PARENT_BSSID: u16 = 18;
    pub const CHAIN_SIGNAL: u16 = 19;
    pub const FREQUENCY_OFFSET: u16 = 20;
    pub const MLO_LINK_ID: u16 = 21;
    pub const MLD_ADDR: u16 = 22;
    pub const USE_FOR: u16 = 23;
};

/// enum nl80211_bss_status — the value of `BSS.STATUS`.
pub const BssStatus = enum(u32) {
    authenticated = 0,
    associated = 1,
    ibss_joined = 2,
    _,
};

/// enum nl80211_sta_info — inside `ATTR.STA_INFO`.
pub const STA_INFO = struct {
    pub const INACTIVE_TIME: u16 = 1;
    pub const RX_BYTES: u16 = 2;
    pub const TX_BYTES: u16 = 3;
    pub const SIGNAL: u16 = 7;
    pub const TX_BITRATE: u16 = 8;
    pub const RX_PACKETS: u16 = 9;
    pub const TX_PACKETS: u16 = 10;
    pub const TX_RETRIES: u16 = 11;
    pub const TX_FAILED: u16 = 12;
    pub const SIGNAL_AVG: u16 = 13;
    pub const RX_BITRATE: u16 = 14;
    pub const BSS_PARAM: u16 = 15;
    pub const CONNECTED_TIME: u16 = 16;
    pub const STA_FLAGS: u16 = 17;
    pub const BEACON_LOSS: u16 = 18;
    pub const RX_BYTES64: u16 = 23;
    pub const TX_BYTES64: u16 = 24;
    pub const CHAIN_SIGNAL: u16 = 25;
    pub const CHAIN_SIGNAL_AVG: u16 = 26;
    pub const EXPECTED_THROUGHPUT: u16 = 27;
    pub const RX_DROP_MISC: u16 = 28;
    pub const BEACON_RX: u16 = 29;
    pub const BEACON_SIGNAL_AVG: u16 = 30;
    pub const TID_STATS: u16 = 31;
    pub const RX_DURATION: u16 = 32;
    pub const PAD: u16 = 33;
    pub const ACK_SIGNAL: u16 = 34;
    pub const ACK_SIGNAL_AVG: u16 = 35;
    pub const RX_MPDUS: u16 = 36;
    pub const FCS_ERROR_COUNT: u16 = 37;
    pub const TX_DURATION: u16 = 39;
    pub const ASSOC_AT_BOOTTIME: u16 = 42;
};

/// enum nl80211_rate_info — inside `STA_INFO.TX_BITRATE` / `RX_BITRATE`.
pub const RATE_INFO = struct {
    pub const BITRATE: u16 = 1;
    pub const MCS: u16 = 2;
    pub const @"40_MHZ_WIDTH": u16 = 3;
    pub const SHORT_GI: u16 = 4;
    pub const BITRATE32: u16 = 5;
    pub const VHT_MCS: u16 = 6;
    pub const VHT_NSS: u16 = 7;
    pub const @"80_MHZ_WIDTH": u16 = 8;
    pub const @"80P80_MHZ_WIDTH": u16 = 9;
    pub const @"160_MHZ_WIDTH": u16 = 10;
    pub const @"10_MHZ_WIDTH": u16 = 11;
    pub const @"5_MHZ_WIDTH": u16 = 12;
    pub const HE_MCS: u16 = 13;
    pub const HE_NSS: u16 = 14;
    pub const HE_GI: u16 = 15;
    pub const HE_DCM: u16 = 16;
    pub const HE_RU_ALLOC: u16 = 17;
    pub const @"320_MHZ_WIDTH": u16 = 18;
    pub const EHT_MCS: u16 = 19;
    pub const EHT_NSS: u16 = 20;
};

/// enum nl80211_band_attr — inside one band of `ATTR.WIPHY_BANDS`.
pub const BAND_ATTR = struct {
    pub const FREQS: u16 = 1;
    pub const RATES: u16 = 2;
    pub const HT_MCS_SET: u16 = 3;
    pub const HT_CAPA: u16 = 4;
    pub const VHT_MCS_SET: u16 = 7;
    pub const VHT_CAPA: u16 = 8;
    pub const IFTYPE_DATA: u16 = 9;
};

/// enum nl80211_frequency_attr — inside one entry of `BAND_ATTR.FREQS`.
pub const FREQUENCY_ATTR = struct {
    pub const FREQ: u16 = 1;
    pub const DISABLED: u16 = 2;
    pub const NO_IR: u16 = 3;
    pub const RADAR: u16 = 5;
    pub const MAX_TX_POWER: u16 = 6;
    pub const DFS_STATE: u16 = 7;
    pub const NO_HT40_MINUS: u16 = 9;
    pub const NO_HT40_PLUS: u16 = 10;
    pub const NO_80MHZ: u16 = 11;
    pub const NO_160MHZ: u16 = 12;
    pub const INDOOR_ONLY: u16 = 14;
    pub const IR_CONCURRENT: u16 = 15;
    pub const NO_20MHZ: u16 = 16;
    pub const NO_10MHZ: u16 = 17;
    pub const WMM: u16 = 18;
    pub const OFFSET: u16 = 20;
};

/// enum nl80211_bitrate_attr — inside one entry of `BAND_ATTR.RATES`.
pub const BITRATE_ATTR = struct {
    pub const RATE: u16 = 1;
    pub const @"2GHZ_SHORTPREAMBLE": u16 = 2;
};

/// enum nl80211_reg_rule_attr — inside one entry of `ATTR.REG_RULES`.
pub const REG_RULE_ATTR = struct {
    pub const REG_RULE_FLAGS: u16 = 1;
    pub const FREQ_RANGE_START: u16 = 2;
    pub const FREQ_RANGE_END: u16 = 3;
    pub const FREQ_RANGE_MAX_BW: u16 = 4;
    pub const POWER_RULE_MAX_ANT_GAIN: u16 = 5;
    pub const POWER_RULE_MAX_EIRP: u16 = 6;
    pub const DFS_CAC_TIME: u16 = 7;
    pub const POWER_RULE_PSD: u16 = 8;
};

/// enum nl80211_key_attributes — inside one entry of `ATTR.KEYS`.
pub const KEY = struct {
    pub const DATA: u16 = 1;
    pub const IDX: u16 = 2;
    pub const CIPHER: u16 = 3;
    pub const SEQ: u16 = 4;
    pub const DEFAULT: u16 = 5;
    pub const DEFAULT_MGMT: u16 = 6;
    pub const TYPE: u16 = 7;
};

/// nlctrl `CTRL_ATTR_MCAST_GRP_*` — inside one entry of
/// `CTRL_ATTR_MCAST_GROUPS`. Needed here because the sibling `genetlink`
/// module deliberately stops at family-id resolution (see its README's
/// "Out of scope" note); nl80211 is the first family that needs groups.
pub const CTRL_ATTR = struct {
    pub const FAMILY_ID: u16 = 1;
    pub const FAMILY_NAME: u16 = 2;
    pub const MCAST_GROUPS: u16 = 7;
};

pub const CTRL_ATTR_MCAST_GRP = struct {
    pub const NAME: u16 = 1;
    pub const ID: u16 = 2;
};

/// The nl80211 multicast group names (kernel `nl80211_mcgrps`). Ids are
/// dynamic — resolve them, do not assume.
pub const mcast_group = struct {
    pub const config = "config";
    pub const scan = "scan";
    pub const regulatory = "regulatory";
    pub const mlme = "mlme";
    pub const vendor = "vendor";
    pub const nan = "nan";
};

// ── enums ──────────────────────────────────────────────────────────────────

/// enum nl80211_iftype.
pub const Iftype = enum(u32) {
    unspecified = 0,
    adhoc = 1,
    station = 2,
    ap = 3,
    ap_vlan = 4,
    wds = 5,
    monitor = 6,
    mesh_point = 7,
    p2p_client = 8,
    p2p_go = 9,
    p2p_device = 10,
    ocb = 11,
    nan = 12,
    _,
};

/// enum nl80211_auth_type. `automatic` is nl80211's "let the driver pick"
/// sentinel (`NL80211_AUTHTYPE_MAX + 1`), which `CONNECT` accepts.
pub const AuthType = enum(u32) {
    open_system = 0,
    shared_key = 1,
    ft = 2,
    network_eap = 3,
    sae = 4,
    fils_sk = 5,
    fils_sk_pfs = 6,
    fils_pk = 7,
    automatic = 9,
    _,
};

/// enum nl80211_chan_width.
pub const ChanWidth = enum(u32) {
    @"20_noht" = 0,
    @"20" = 1,
    @"40" = 2,
    @"80" = 3,
    @"80p80" = 4,
    @"160" = 5,
    @"5" = 6,
    @"10" = 7,
    @"1" = 8,
    @"2" = 9,
    @"4" = 10,
    @"8" = 11,
    @"16" = 12,
    @"320" = 13,
    _,

    /// Channel bandwidth in MHz, or null for the widths that are not a plain
    /// contiguous bandwidth (`80p80`) or are not known to this table.
    pub fn megahertz(w: ChanWidth) ?u16 {
        return switch (w) {
            .@"20_noht", .@"20" => 20,
            .@"40" => 40,
            .@"80" => 80,
            .@"160" => 160,
            .@"5" => 5,
            .@"10" => 10,
            .@"1" => 1,
            .@"2" => 2,
            .@"4" => 4,
            .@"8" => 8,
            .@"16" => 16,
            .@"320" => 320,
            else => null,
        };
    }
};

/// enum nl80211_reg_type — how the reported regulatory domain was derived.
pub const RegType = enum(u32) {
    country = 0,
    world = 1,
    custom_world = 2,
    intersection = 3,
    _,
};

/// enum nl80211_dfs_regions.
pub const DfsRegion = enum(u32) {
    unset = 0,
    fcc = 1,
    etsi = 2,
    jp = 3,
    _,
};

/// enum nl80211_mfp — management frame protection policy for `CONNECT`.
pub const Mfp = enum(u32) {
    no = 0,
    required = 1,
    optional = 2,
    _,
};

/// `NL80211_ATTR_WPA_VERSIONS` bits.
pub const WPA_VERSION = struct {
    pub const @"1": u32 = 1 << 0;
    pub const @"2": u32 = 1 << 1;
    pub const @"3": u32 = 1 << 2;
};

/// `NL80211_ATTR_SCAN_FLAGS` bits (enum nl80211_scan_flags).
pub const SCAN_FLAG = struct {
    pub const LOW_PRIORITY: u32 = 1 << 0;
    pub const FLUSH: u32 = 1 << 1;
    pub const AP: u32 = 1 << 2;
    pub const RANDOM_ADDR: u32 = 1 << 3;
    pub const FILS_MAX_CHANNEL_TIME: u32 = 1 << 4;
    pub const ACCEPT_BCAST_PROBE_RESP: u32 = 1 << 5;
    pub const OCE_PROBE_REQ_HIGH_TX_RATE: u32 = 1 << 6;
    pub const OCE_PROBE_REQ_DEFERRAL_SUPPRESSION: u32 = 1 << 7;
    pub const LOW_SPAN: u32 = 1 << 8;
    pub const LOW_POWER: u32 = 1 << 9;
    pub const HIGH_ACCURACY: u32 = 1 << 10;
    pub const RANDOM_SN: u32 = 1 << 11;
    pub const MIN_PREQ_CONTENT: u32 = 1 << 12;
    pub const FREQ_KHZ: u32 = 1 << 13;
    pub const COLOCATED_6GHZ: u32 = 1 << 14;
};

/// `NL80211_RRF_*` regulatory-rule flag bits.
pub const RRF = struct {
    pub const NO_OFDM: u32 = 1 << 0;
    pub const NO_CCK: u32 = 1 << 1;
    pub const NO_INDOOR: u32 = 1 << 2;
    pub const NO_OUTDOOR: u32 = 1 << 3;
    pub const DFS: u32 = 1 << 4;
    pub const PTP_ONLY: u32 = 1 << 5;
    pub const PTMP_ONLY: u32 = 1 << 6;
    pub const NO_IR: u32 = 1 << 7;
    pub const AUTO_BW: u32 = 1 << 11;
    pub const IR_CONCURRENT: u32 = 1 << 12;
    pub const NO_HT40MINUS: u32 = 1 << 13;
    pub const NO_HT40PLUS: u32 = 1 << 14;
    pub const NO_80MHZ: u32 = 1 << 15;
    pub const NO_160MHZ: u32 = 1 << 16;
    pub const NO_HE: u32 = 1 << 17;
    pub const NO_320MHZ: u32 = 1 << 18;
    pub const NO_EHT: u32 = 1 << 19;
    pub const PSD: u32 = 1 << 20;
};

// ── IEEE 802.11 cipher / AKM suite selectors ───────────────────────────────
//
// A suite selector is OUI ‖ type. nl80211 carries it as a host-order u32, so
// 00-0F-AC:4 (CCMP-128) is 0x000FAC04; the same selector inside an RSN
// information element is the same number read big-endian off the wire. Both
// paths therefore compare against the constants below.

/// The 00-0F-AC ("IEEE 802.11") suite OUI, pre-shifted.
pub const oui_ieee80211: u32 = 0x000F_AC00;

/// `WLAN_CIPHER_SUITE_*`.
pub const CIPHER = struct {
    pub const USE_GROUP: u32 = oui_ieee80211 | 0x00;
    pub const WEP40: u32 = oui_ieee80211 | 0x01;
    pub const TKIP: u32 = oui_ieee80211 | 0x02;
    pub const CCMP: u32 = oui_ieee80211 | 0x04;
    pub const WEP104: u32 = oui_ieee80211 | 0x05;
    pub const AES_CMAC: u32 = oui_ieee80211 | 0x06;
    pub const GCMP: u32 = oui_ieee80211 | 0x08;
    pub const GCMP_256: u32 = oui_ieee80211 | 0x09;
    pub const CCMP_256: u32 = oui_ieee80211 | 0x0a;
    pub const BIP_GMAC_128: u32 = oui_ieee80211 | 0x0b;
    pub const BIP_GMAC_256: u32 = oui_ieee80211 | 0x0c;
    pub const BIP_CMAC_256: u32 = oui_ieee80211 | 0x0d;
};

/// `WLAN_AKM_SUITE_*`.
pub const AKM = struct {
    pub const @"8021X": u32 = oui_ieee80211 | 0x01;
    pub const PSK: u32 = oui_ieee80211 | 0x02;
    pub const FT_8021X: u32 = oui_ieee80211 | 0x03;
    pub const FT_PSK: u32 = oui_ieee80211 | 0x04;
    pub const @"8021X_SHA256": u32 = oui_ieee80211 | 0x05;
    pub const PSK_SHA256: u32 = oui_ieee80211 | 0x06;
    pub const TDLS: u32 = oui_ieee80211 | 0x07;
    pub const SAE: u32 = oui_ieee80211 | 0x08;
    pub const FT_OVER_SAE: u32 = oui_ieee80211 | 0x09;
    pub const @"8021X_SUITE_B": u32 = oui_ieee80211 | 0x0b;
    pub const @"8021X_SUITE_B_192": u32 = oui_ieee80211 | 0x0c;
    pub const FILS_SHA256: u32 = oui_ieee80211 | 0x0e;
    pub const FILS_SHA384: u32 = oui_ieee80211 | 0x0f;
    pub const OWE: u32 = oui_ieee80211 | 0x12;
};

/// Length of a WPA2/WPA3 pairwise master key (`NL80211_ATTR_PMK`).
pub const pmk_len = 32;

/// `IFNAMSIZ` — interface names including the terminating NUL.
pub const ifnamsiz = 16;

/// The 802.11 SSID ceiling (`IEEE80211_MAX_SSID_LEN`).
pub const max_ssid_len = 32;

/// A 48-bit MAC / BSSID.
pub const Mac = [6]u8;

/// Format a MAC as the lowercase colon-separated text `iw` prints.
pub fn formatMac(mac: Mac) [17]u8 {
    var out: [17]u8 = undefined;
    for (mac, 0..) |b, i| {
        if (i != 0) out[i * 3 - 1] = ':';
        _ = std.fmt.bufPrint(out[i * 3 ..][0..2], "{x:0>2}", .{b}) catch unreachable;
    }
    return out;
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

test "command + attribute ids match what iw put on the wire" {
    // Cross-checked against the captured `iw` requests in goldens.zig: the
    // genlmsghdr command byte and every nla_type there must appear here.
    try testing.expectEqual(@as(u8, 0x01), CMD.GET_WIPHY);
    try testing.expectEqual(@as(u8, 0x05), CMD.GET_INTERFACE);
    try testing.expectEqual(@as(u8, 0x11), CMD.GET_STATION);
    try testing.expectEqual(@as(u8, 0x1b), CMD.REQ_SET_REG);
    try testing.expectEqual(@as(u8, 0x1f), CMD.GET_REG);
    try testing.expectEqual(@as(u8, 0x20), CMD.GET_SCAN);
    try testing.expectEqual(@as(u8, 0x21), CMD.TRIGGER_SCAN);
    try testing.expectEqual(@as(u8, 0x2e), CMD.CONNECT);
    try testing.expectEqual(@as(u8, 0x30), CMD.DISCONNECT);

    try testing.expectEqual(@as(u16, 0x03), ATTR.IFINDEX);
    try testing.expectEqual(@as(u16, 0x21), ATTR.REG_ALPHA2);
    try testing.expectEqual(@as(u16, 0x26), ATTR.WIPHY_FREQ);
    try testing.expectEqual(@as(u16, 0x2c), ATTR.SCAN_FREQUENCIES);
    try testing.expectEqual(@as(u16, 0x2d), ATTR.SCAN_SSIDS);
    try testing.expectEqual(@as(u16, 0x34), ATTR.SSID);
    try testing.expectEqual(@as(u16, 0x46), ATTR.PRIVACY);
    try testing.expectEqual(@as(u16, 0x51), ATTR.KEYS);
    try testing.expectEqual(@as(u16, 0x9e), ATTR.SCAN_FLAGS);
    try testing.expectEqual(@as(u16, 0xae), ATTR.SPLIT_WIPHY_DUMP);
    try testing.expectEqual(@as(u16, 0xfe), ATTR.PMK);
}

test "suite selectors are the 00-0F-AC numbers the RSN IE carries" {
    // The captured beacon's RSN IE body is
    //   01 00 | 00 0f ac 04 | 01 00 | 00 0f ac 04 | 01 00 | 00 0f ac 02 | 0c 00
    // i.e. group CCMP, pairwise CCMP, AKM PSK.
    try testing.expectEqual(@as(u32, 0x000f_ac04), CIPHER.CCMP);
    try testing.expectEqual(@as(u32, 0x000f_ac02), CIPHER.TKIP);
    try testing.expectEqual(@as(u32, 0x000f_ac02), AKM.PSK);
    try testing.expectEqual(@as(u32, 0x000f_ac08), AKM.SAE);
    // …and the value the kernel reports in NL80211_ATTR_CIPHER_SUITES, which
    // arrived on this machine as `01 ac 0f 00` little-endian.
    try testing.expectEqual(@as(u32, 0x000f_ac01), CIPHER.WEP40);
}

test "channel width to MHz" {
    try testing.expectEqual(@as(?u16, 20), ChanWidth.@"20".megahertz());
    try testing.expectEqual(@as(?u16, 80), ChanWidth.@"80".megahertz());
    try testing.expectEqual(@as(?u16, 320), ChanWidth.@"320".megahertz());
    try testing.expectEqual(@as(?u16, null), ChanWidth.@"80p80".megahertz());
    try testing.expectEqual(@as(?u16, null), @as(ChanWidth, @enumFromInt(999)).megahertz());
}

test "formatMac" {
    try testing.expectEqualStrings("02:00:00:aa:bb:cc", &formatMac(.{ 0x02, 0, 0, 0xaa, 0xbb, 0xcc }));
    try testing.expectEqualStrings("00:00:00:00:00:00", &formatMac(@splat(0)));
}
