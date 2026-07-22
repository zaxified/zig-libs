// SPDX-License-Identifier: MIT
//! Kernel UAPI constants for the `ethtool` generic-netlink family, transcribed
//! from `linux/ethtool_netlink_generated.h` and `linux/ethtool.h` (GPL-2.0 WITH
//! Linux-syscall-note — command/attribute numbers and their layouts are the
//! kernel's OS ABI, not copyrightable interface code).
//!
//! Only the message types and attribute sets this module models are listed in
//! full; the rest of the `ETHTOOL_MSG_*` space is present as numbers so the
//! `raw` escape hatch and the notification decoder can name what they see.
//!
//! **Nothing here is a message-type id.** The genl family id for "ethtool" is
//! assigned at boot (it was 23 on the development machine) and is resolved at
//! runtime — see `client.zig`.

const std = @import("std");

/// `ETHTOOL_GENL_NAME` — the family name nlctrl resolves.
pub const family_name = "ethtool";
/// `ETHTOOL_GENL_VERSION`.
pub const family_version: u8 = 1;

/// The one multicast group the family publishes (`ETHTOOL_MCGRP_MONITOR_NAME`).
/// Every `*_NTF` message is emitted on it.
pub const mcast_group = struct {
    pub const monitor = "monitor";
};

/// `IFNAMSIZ` — interface names including the NUL the kernel expects.
pub const ifnamesize = 16;

// ── request message types (ETHTOOL_MSG_* user side) ────────────────────────

pub const MSG = struct {
    pub const STRSET_GET: u8 = 1;
    pub const LINKINFO_GET: u8 = 2;
    pub const LINKINFO_SET: u8 = 3;
    pub const LINKMODES_GET: u8 = 4;
    pub const LINKMODES_SET: u8 = 5;
    pub const LINKSTATE_GET: u8 = 6;
    pub const DEBUG_GET: u8 = 7;
    pub const DEBUG_SET: u8 = 8;
    pub const WOL_GET: u8 = 9;
    pub const WOL_SET: u8 = 10;
    pub const FEATURES_GET: u8 = 11;
    pub const FEATURES_SET: u8 = 12;
    pub const PRIVFLAGS_GET: u8 = 13;
    pub const PRIVFLAGS_SET: u8 = 14;
    pub const RINGS_GET: u8 = 15;
    pub const RINGS_SET: u8 = 16;
    pub const CHANNELS_GET: u8 = 17;
    pub const CHANNELS_SET: u8 = 18;
    pub const COALESCE_GET: u8 = 19;
    pub const COALESCE_SET: u8 = 20;
    pub const PAUSE_GET: u8 = 21;
    pub const PAUSE_SET: u8 = 22;
    pub const EEE_GET: u8 = 23;
    pub const EEE_SET: u8 = 24;
    pub const TSINFO_GET: u8 = 25;
    pub const CABLE_TEST_ACT: u8 = 26;
    pub const CABLE_TEST_TDR_ACT: u8 = 27;
    pub const TUNNEL_INFO_GET: u8 = 28;
    pub const FEC_GET: u8 = 29;
    pub const FEC_SET: u8 = 30;
    pub const MODULE_EEPROM_GET: u8 = 31;
    pub const STATS_GET: u8 = 32;
    pub const PHC_VCLOCKS_GET: u8 = 33;
    pub const MODULE_GET: u8 = 34;
    pub const MODULE_SET: u8 = 35;
    pub const PSE_GET: u8 = 36;
    pub const PSE_SET: u8 = 37;
    pub const RSS_GET: u8 = 38;
    pub const PLCA_GET_CFG: u8 = 39;
    pub const PLCA_SET_CFG: u8 = 40;
    pub const PLCA_GET_STATUS: u8 = 41;
    pub const MM_GET: u8 = 42;
    pub const MM_SET: u8 = 43;
    pub const MODULE_FW_FLASH_ACT: u8 = 44;
    pub const PHY_GET: u8 = 45;
    pub const TSCONFIG_GET: u8 = 46;
    pub const TSCONFIG_SET: u8 = 47;
};

// ── reply / notification message types (ETHTOOL_MSG_* kernel side) ─────────

pub const REPLY = struct {
    pub const STRSET_GET: u8 = 1;
    pub const LINKINFO_GET: u8 = 2;
    pub const LINKINFO_NTF: u8 = 3;
    pub const LINKMODES_GET: u8 = 4;
    pub const LINKMODES_NTF: u8 = 5;
    pub const LINKSTATE_GET: u8 = 6;
    pub const DEBUG_GET: u8 = 7;
    pub const DEBUG_NTF: u8 = 8;
    pub const WOL_GET: u8 = 9;
    pub const WOL_NTF: u8 = 10;
    pub const FEATURES_GET: u8 = 11;
    pub const FEATURES_SET: u8 = 12;
    pub const FEATURES_NTF: u8 = 13;
    pub const PRIVFLAGS_GET: u8 = 14;
    pub const PRIVFLAGS_NTF: u8 = 15;
    pub const RINGS_GET: u8 = 16;
    pub const RINGS_NTF: u8 = 17;
    pub const CHANNELS_GET: u8 = 18;
    pub const CHANNELS_NTF: u8 = 19;
    pub const COALESCE_GET: u8 = 20;
    pub const COALESCE_NTF: u8 = 21;
    pub const PAUSE_GET: u8 = 22;
    pub const PAUSE_NTF: u8 = 23;
    pub const EEE_GET: u8 = 24;
    pub const EEE_NTF: u8 = 25;
    pub const TSINFO_GET: u8 = 26;
    pub const CABLE_TEST_NTF: u8 = 27;
    pub const CABLE_TEST_TDR_NTF: u8 = 28;
    pub const TUNNEL_INFO_GET: u8 = 29;
    pub const FEC_GET: u8 = 30;
    pub const FEC_NTF: u8 = 31;
    pub const MODULE_EEPROM_GET: u8 = 32;
    pub const STATS_GET: u8 = 33;
    pub const PHC_VCLOCKS_GET: u8 = 34;
    pub const MODULE_GET: u8 = 35;
    pub const MODULE_NTF: u8 = 36;
    pub const PSE_GET: u8 = 37;
    pub const RSS_GET: u8 = 38;
    pub const PLCA_GET_CFG: u8 = 39;
    pub const PLCA_GET_STATUS: u8 = 40;
    pub const PLCA_NTF: u8 = 41;
    pub const MM_GET: u8 = 42;
    pub const MM_NTF: u8 = 43;
    pub const MODULE_FW_FLASH_NTF: u8 = 44;
    pub const PHY_GET: u8 = 45;
    pub const PHY_NTF: u8 = 46;
    pub const TSCONFIG_GET: u8 = 47;
    pub const TSCONFIG_SET: u8 = 48;
    pub const PSE_NTF: u8 = 49;
    pub const RSS_NTF: u8 = 50;
};

/// True for the kernel-side message types that are unsolicited notifications
/// (the `*_NTF` family) rather than replies to a request. Used to classify what
/// arrives on the `monitor` multicast group.
pub fn isNotification(reply_cmd: u8) bool {
    return switch (reply_cmd) {
        REPLY.LINKINFO_NTF,
        REPLY.LINKMODES_NTF,
        REPLY.DEBUG_NTF,
        REPLY.WOL_NTF,
        REPLY.FEATURES_NTF,
        REPLY.PRIVFLAGS_NTF,
        REPLY.RINGS_NTF,
        REPLY.CHANNELS_NTF,
        REPLY.COALESCE_NTF,
        REPLY.PAUSE_NTF,
        REPLY.EEE_NTF,
        REPLY.CABLE_TEST_NTF,
        REPLY.CABLE_TEST_TDR_NTF,
        REPLY.FEC_NTF,
        REPLY.MODULE_NTF,
        REPLY.PLCA_NTF,
        REPLY.MM_NTF,
        REPLY.MODULE_FW_FLASH_NTF,
        REPLY.PHY_NTF,
        REPLY.PSE_NTF,
        REPLY.RSS_NTF,
        => true,
        else => false,
    };
}

// ── the common request/reply header nest (ETHTOOL_A_HEADER_*) ─────────────

pub const HEADER = struct {
    pub const DEV_INDEX: u16 = 1;
    pub const DEV_NAME: u16 = 2;
    pub const FLAGS: u16 = 3;
    pub const PHY_INDEX: u16 = 4;
};

/// `enum ethtool_header_flags` — set in `ETHTOOL_A_HEADER_FLAGS`. These change
/// the *shape* of what comes back, so they are part of the protocol, not a
/// tuning knob:
///
/// * `COMPACT_BITSETS` — reply bitsets arrive as raw u32 word arrays instead of
///   the verbose per-bit nest with names. See `bitset.zig`.
/// * `OMIT_REPLY` — a SET/ACT request is answered with a bare ACK; the kernel
///   sends no `*_SET_REPLY`, so a caller cannot learn what actually stuck.
/// * `STATS` — ask the driver to attach the optional statistics nests
///   (e.g. `ETHTOOL_A_PAUSE_STATS`) that are omitted by default.
pub const FLAG = struct {
    pub const COMPACT_BITSETS: u32 = 1;
    pub const OMIT_REPLY: u32 = 2;
    pub const STATS: u32 = 4;
};

// ── bitsets (ETHTOOL_A_BITSET_*) ──────────────────────────────────────────

pub const BITSET = struct {
    /// Flag attribute (zero length): the set carries no mask — only the bits
    /// present/set are meaningful ("list" semantics).
    pub const NOMASK: u16 = 1;
    /// u32 — number of bits in the set.
    pub const SIZE: u16 = 2;
    /// Nest of `BITS_BIT` — the verbose form.
    pub const BITS: u16 = 3;
    /// u32 array (host order) — the compact form's value words.
    pub const VALUE: u16 = 4;
    /// u32 array (host order) — the compact form's mask words.
    pub const MASK: u16 = 5;
};

pub const BITSET_BITS = struct {
    /// Nest of `BITSET_BIT_*`.
    pub const BIT: u16 = 1;
};

pub const BITSET_BIT = struct {
    pub const INDEX: u16 = 1;
    pub const NAME: u16 = 2;
    /// Flag attribute (zero length): the bit is set. Absent = clear.
    pub const VALUE: u16 = 3;
};

// ── string sets (ETHTOOL_A_STRSET_* / STRINGSET* / STRING*) ───────────────

pub const STRSET = struct {
    pub const HEADER: u16 = 1;
    pub const STRINGSETS: u16 = 2;
    pub const COUNTS_ONLY: u16 = 3;
};

pub const STRINGSETS = struct {
    pub const STRINGSET: u16 = 1;
};

pub const STRINGSET = struct {
    pub const ID: u16 = 1;
    pub const COUNT: u16 = 2;
    pub const STRINGS: u16 = 3;
};

pub const STRINGS = struct {
    pub const STRING: u16 = 1;
};

pub const STRING = struct {
    pub const INDEX: u16 = 1;
    pub const VALUE: u16 = 2;
};

/// `enum ethtool_stringset` (`ETH_SS_*`) — which string table to fetch.
pub const StringSetId = enum(u32) {
    self_test = 0,
    stats = 1,
    priv_flags = 2,
    ntuple_filters = 3,
    features = 4,
    rss_hash_funcs = 5,
    tunables = 6,
    phy_stats = 7,
    phy_tunables = 8,
    link_modes = 9,
    msg_classes = 10,
    wol_modes = 11,
    sof_timestamping = 12,
    ts_tx_types = 13,
    ts_rx_filters = 14,
    udp_tunnel_types = 15,
    stats_std = 16,
    stats_eth_phy = 17,
    stats_eth_mac = 18,
    stats_eth_ctrl = 19,
    stats_rmon = 20,
    _,
};

// ── link information / modes / state ──────────────────────────────────────

pub const LINKINFO = struct {
    pub const HEADER: u16 = 1;
    pub const PORT: u16 = 2;
    pub const PHYADDR: u16 = 3;
    pub const TP_MDIX: u16 = 4;
    pub const TP_MDIX_CTRL: u16 = 5;
    pub const TRANSCEIVER: u16 = 6;
};

pub const LINKMODES = struct {
    pub const HEADER: u16 = 1;
    pub const AUTONEG: u16 = 2;
    pub const OURS: u16 = 3;
    pub const PEER: u16 = 4;
    pub const SPEED: u16 = 5;
    pub const DUPLEX: u16 = 6;
    pub const MASTER_SLAVE_CFG: u16 = 7;
    pub const MASTER_SLAVE_STATE: u16 = 8;
    pub const LANES: u16 = 9;
    pub const RATE_MATCHING: u16 = 10;
};

pub const LINKSTATE = struct {
    pub const HEADER: u16 = 1;
    pub const LINK: u16 = 2;
    pub const SQI: u16 = 3;
    pub const SQI_MAX: u16 = 4;
    pub const EXT_STATE: u16 = 5;
    pub const EXT_SUBSTATE: u16 = 6;
    pub const EXT_DOWN_CNT: u16 = 7;
};

/// `PORT_*` (linux/ethtool.h).
pub const Port = enum(u8) {
    tp = 0x00,
    aui = 0x01,
    mii = 0x02,
    fibre = 0x03,
    bnc = 0x04,
    da = 0x05,
    none = 0xef,
    other = 0xff,
    _,
};

/// `XCVR_*` (linux/ethtool.h).
pub const Transceiver = enum(u8) {
    internal = 0,
    external = 1,
    _,
};

/// `ETH_TP_MDI*` (linux/ethtool.h). As a *status* (`TP_MDIX`) `invalid` means
/// unknown; as a *control* (`TP_MDIX_CTRL`) it means the PHY has no control.
pub const MdiX = enum(u8) {
    invalid = 0,
    mdi = 1,
    mdi_x = 2,
    auto = 3,
    _,
};

/// `DUPLEX_*` (linux/ethtool.h).
pub const Duplex = enum(u8) {
    half = 0,
    full = 1,
    unknown = 0xff,
    _,
};

/// `AUTONEG_*` (linux/ethtool.h).
pub const AUTONEG_DISABLE: u8 = 0;
pub const AUTONEG_ENABLE: u8 = 1;

/// `SPEED_UNKNOWN` — the kernel's "no idea" for `ETHTOOL_A_LINKMODES_SPEED`,
/// which is a u32 on the wire but signed -1 in `linux/ethtool.h`.
pub const SPEED_UNKNOWN: u32 = 0xffff_ffff;

/// `MASTER_SLAVE_CFG_*`.
pub const MasterSlaveCfg = enum(u8) {
    unsupported = 0,
    unknown = 1,
    master_preferred = 2,
    slave_preferred = 3,
    master_force = 4,
    slave_force = 5,
    _,
};

/// `MASTER_SLAVE_STATE_*`.
pub const MasterSlaveState = enum(u8) {
    unsupported = 0,
    unknown = 1,
    master = 2,
    slave = 3,
    err = 4,
    _,
};

/// `enum ethtool_link_ext_state` — why the link is down, when the driver knows.
pub const LinkExtState = enum(u8) {
    autoneg = 0,
    link_training_failure = 1,
    link_logical_mismatch = 2,
    bad_signal_integrity = 3,
    no_cable = 4,
    cable_issue = 5,
    eeprom_issue = 6,
    calibration_failure = 7,
    power_budget_exceeded = 8,
    overheat = 9,
    module = 10,
    _,
};

/// Well-known `ETHTOOL_LINK_MODE_*_BIT` indices. The full table is 126 entries
/// and grows every release, so this module does **not** carry it: fetch the
/// kernel's own names with `stringSet(.link_modes)` (or read them out of a
/// verbose bitset, which carries a name per bit). These few are pinned because
/// they are stable, ancient, and asserted against the captured goldens.
pub const LINK_MODE = struct {
    pub const @"10baseT_Half": u32 = 0;
    pub const @"10baseT_Full": u32 = 1;
    pub const @"100baseT_Half": u32 = 2;
    pub const @"100baseT_Full": u32 = 3;
    pub const @"1000baseT_Half": u32 = 4;
    pub const @"1000baseT_Full": u32 = 5;
    pub const Autoneg: u32 = 6;
    pub const TP: u32 = 7;
    pub const AUI: u32 = 8;
    pub const MII: u32 = 9;
    pub const FIBRE: u32 = 10;
    pub const BNC: u32 = 11;
    pub const Pause: u32 = 13;
    pub const Asym_Pause: u32 = 14;
};

// ── ring / channel / coalesce / pause parameters ──────────────────────────

pub const RINGS = struct {
    pub const HEADER: u16 = 1;
    pub const RX_MAX: u16 = 2;
    pub const RX_MINI_MAX: u16 = 3;
    pub const RX_JUMBO_MAX: u16 = 4;
    pub const TX_MAX: u16 = 5;
    pub const RX: u16 = 6;
    pub const RX_MINI: u16 = 7;
    pub const RX_JUMBO: u16 = 8;
    pub const TX: u16 = 9;
    pub const RX_BUF_LEN: u16 = 10;
    pub const TCP_DATA_SPLIT: u16 = 11;
    pub const CQE_SIZE: u16 = 12;
    pub const TX_PUSH: u16 = 13;
    pub const RX_PUSH: u16 = 14;
    pub const TX_PUSH_BUF_LEN: u16 = 15;
    pub const TX_PUSH_BUF_LEN_MAX: u16 = 16;
    pub const HDS_THRESH: u16 = 17;
    pub const HDS_THRESH_MAX: u16 = 18;
};

/// `enum ethtool_tcp_data_split`.
pub const TcpDataSplit = enum(u8) {
    unknown = 0,
    disabled = 1,
    enabled = 2,
    _,
};

pub const CHANNELS = struct {
    pub const HEADER: u16 = 1;
    pub const RX_MAX: u16 = 2;
    pub const TX_MAX: u16 = 3;
    pub const OTHER_MAX: u16 = 4;
    pub const COMBINED_MAX: u16 = 5;
    pub const RX_COUNT: u16 = 6;
    pub const TX_COUNT: u16 = 7;
    pub const OTHER_COUNT: u16 = 8;
    pub const COMBINED_COUNT: u16 = 9;
};

pub const COALESCE = struct {
    pub const HEADER: u16 = 1;
    pub const RX_USECS: u16 = 2;
    pub const RX_MAX_FRAMES: u16 = 3;
    pub const RX_USECS_IRQ: u16 = 4;
    pub const RX_MAX_FRAMES_IRQ: u16 = 5;
    pub const TX_USECS: u16 = 6;
    pub const TX_MAX_FRAMES: u16 = 7;
    pub const TX_USECS_IRQ: u16 = 8;
    pub const TX_MAX_FRAMES_IRQ: u16 = 9;
    pub const STATS_BLOCK_USECS: u16 = 10;
    pub const USE_ADAPTIVE_RX: u16 = 11;
    pub const USE_ADAPTIVE_TX: u16 = 12;
    pub const PKT_RATE_LOW: u16 = 13;
    pub const RX_USECS_LOW: u16 = 14;
    pub const RX_MAX_FRAMES_LOW: u16 = 15;
    pub const TX_USECS_LOW: u16 = 16;
    pub const TX_MAX_FRAMES_LOW: u16 = 17;
    pub const PKT_RATE_HIGH: u16 = 18;
    pub const RX_USECS_HIGH: u16 = 19;
    pub const RX_MAX_FRAMES_HIGH: u16 = 20;
    pub const TX_USECS_HIGH: u16 = 21;
    pub const TX_MAX_FRAMES_HIGH: u16 = 22;
    pub const RATE_SAMPLE_INTERVAL: u16 = 23;
    pub const USE_CQE_MODE_TX: u16 = 24;
    pub const USE_CQE_MODE_RX: u16 = 25;
    pub const TX_AGGR_MAX_BYTES: u16 = 26;
    pub const TX_AGGR_MAX_FRAMES: u16 = 27;
    pub const TX_AGGR_TIME_USECS: u16 = 28;
};

pub const PAUSE = struct {
    pub const HEADER: u16 = 1;
    pub const AUTONEG: u16 = 2;
    pub const RX: u16 = 3;
    pub const TX: u16 = 4;
    pub const STATS: u16 = 5;
    pub const STATS_SRC: u16 = 6;
};

pub const PAUSE_STAT = struct {
    pub const PAD: u16 = 1;
    pub const TX_FRAMES: u16 = 2;
    pub const RX_FRAMES: u16 = 3;
};

// ── features ──────────────────────────────────────────────────────────────

pub const FEATURES = struct {
    pub const HEADER: u16 = 1;
    /// Bitset: features the device can do at all (with a mask).
    pub const HW: u16 = 2;
    /// Bitset: features userspace asked for.
    pub const WANTED: u16 = 3;
    /// Bitset: features actually in effect.
    pub const ACTIVE: u16 = 4;
    /// Bitset: features whose state cannot be changed.
    pub const NOCHANGE: u16 = 5;
};

// ── statistics ────────────────────────────────────────────────────────────

pub const STATS = struct {
    pub const PAD: u16 = 1;
    pub const HEADER: u16 = 2;
    /// Bitset selecting which groups to return.
    pub const GROUPS: u16 = 3;
    /// One nest per returned group.
    pub const GRP: u16 = 4;
    pub const SRC: u16 = 5;
};

pub const STATS_GRP = struct {
    pub const PAD: u16 = 1;
    pub const ID: u16 = 2;
    pub const SS_ID: u16 = 3;
    pub const STAT: u16 = 4;
    pub const HIST_RX: u16 = 5;
    pub const HIST_TX: u16 = 6;
    pub const HIST_BKT_LOW: u16 = 7;
    pub const HIST_BKT_HI: u16 = 8;
    pub const HIST_VAL: u16 = 9;
};

/// The standard statistics group ids (`ETHTOOL_A_STATS_GROUPS` bit indices).
/// The names are the kernel's own, from `ETH_SS_STATS_STD` — this module's
/// `stats.group_names` is asserted against a captured `STRSET` reply.
pub const StatsGroup = enum(u32) {
    eth_phy = 0,
    eth_mac = 1,
    eth_ctrl = 2,
    rmon = 3,
    _,
};

/// `enum ethtool_mac_stats_src` — which MAC the counters came from on a device
/// that implements frame preemption (802.3br).
pub const StatsSrc = enum(u32) {
    aggregate = 0,
    emac = 1,
    pmac = 2,
    _,
};

// ── pluggable module (SFP/QSFP) ───────────────────────────────────────────

pub const MODULE = struct {
    pub const HEADER: u16 = 1;
    pub const POWER_MODE_POLICY: u16 = 2;
    pub const POWER_MODE: u16 = 3;
};

pub const MODULE_EEPROM = struct {
    pub const HEADER: u16 = 1;
    pub const OFFSET: u16 = 2;
    pub const LENGTH: u16 = 3;
    pub const PAGE: u16 = 4;
    pub const BANK: u16 = 5;
    pub const I2C_ADDRESS: u16 = 6;
    pub const DATA: u16 = 7;
};

/// `enum ethtool_module_power_mode_policy`.
pub const ModulePowerModePolicy = enum(u8) {
    high = 1,
    auto = 2,
    _,
};

/// `enum ethtool_module_power_mode`.
pub const ModulePowerMode = enum(u8) {
    low = 1,
    high = 2,
    _,
};

/// The two I2C addresses a SFF-8636/CMIS module answers on. `ethtool -m` reads
/// page 0 at `0x50`; the diagnostics page lives at `0x51`.
pub const I2C_ADDRESS_LOW: u8 = 0x50;
pub const I2C_ADDRESS_HIGH: u8 = 0x51;

// ── tests ─────────────────────────────────────────────────────────────────

const testing = std.testing;

test "message-type numbering matches the ids seen on the wire" {
    // Every one of these was read out of a `genlmsghdr` in a real capture —
    // see goldens.zig for the commands that produced them.
    try testing.expectEqual(@as(u8, 0x0f), MSG.RINGS_GET);
    try testing.expectEqual(@as(u8, 0x10), MSG.RINGS_SET);
    try testing.expectEqual(@as(u8, 0x13), MSG.COALESCE_GET);
    try testing.expectEqual(@as(u8, 0x15), MSG.PAUSE_GET);
    try testing.expectEqual(@as(u8, 0x16), MSG.PAUSE_SET);
    try testing.expectEqual(@as(u8, 0x11), MSG.CHANNELS_GET);
    try testing.expectEqual(@as(u8, 0x0b), MSG.FEATURES_GET);
    try testing.expectEqual(@as(u8, 0x0c), MSG.FEATURES_SET);
    try testing.expectEqual(@as(u8, 0x20), MSG.STATS_GET);
    try testing.expectEqual(@as(u8, 0x1f), MSG.MODULE_EEPROM_GET);
    // Reply ids are a *different* enum that happens to start the same way.
    try testing.expectEqual(@as(u8, 0x10), REPLY.RINGS_GET);
    try testing.expectEqual(@as(u8, 0x21), REPLY.STATS_GET);
}

test "isNotification separates NTF from GET replies" {
    try testing.expect(isNotification(REPLY.LINKMODES_NTF));
    try testing.expect(isNotification(REPLY.FEATURES_NTF));
    try testing.expect(isNotification(REPLY.RINGS_NTF));
    try testing.expect(!isNotification(REPLY.LINKMODES_GET));
    try testing.expect(!isNotification(REPLY.STATS_GET));
    try testing.expect(!isNotification(REPLY.FEATURES_SET));
    try testing.expect(!isNotification(0));
    try testing.expect(!isNotification(255));
}

test "open enums tolerate values this kernel does not know" {
    try testing.expectEqual(Port.fibre, @as(Port, @enumFromInt(3)));
    try testing.expectEqual(@as(u8, 0xef), @intFromEnum(Port.none));
    // An unknown value stays representable rather than being illegal.
    const future: Duplex = @enumFromInt(7);
    try testing.expectEqual(@as(u8, 7), @intFromEnum(future));
    const grp: StatsGroup = @enumFromInt(99);
    try testing.expectEqual(@as(u32, 99), @intFromEnum(grp));
}
