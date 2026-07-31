// SPDX-License-Identifier: MIT
//! Kernel UAPI constants for the `devlink` generic-netlink family, transcribed
//! from `linux/devlink.h` (GPL-2.0+ WITH Linux-syscall-note — the command and
//! attribute numbers and their layouts are the kernel's OS ABI).
//!
//! Two things are worth knowing before reading anything else here.
//!
//! **The command numbers are positional.** `enum devlink_command` opens with
//! *"don't change the order or add anything between, this is ABI"*, so every
//! value below is the ordinal of its name in that enum. A transcription slip
//! shifts an entire block, which is why the numbers of every command this
//! module sends are pinned against **real `devlink` captures** in `goldens.zig`
//! rather than only against the header: `DEVLINK_CMD_PARAM_GET` is 38 because
//! the iproute2 binary put `0x26` on the wire, not because a counter said so.
//!
//! **Attribute numbers are one flat space** shared by every command —
//! `DEVLINK_ATTR_BUS_NAME` is 1 whether it appears in a `PORT_SET` or an
//! `INFO_GET` — unlike ethtool, which restarts numbering per message. So there
//! is one `ATTR` struct here, not one per command.

const std = @import("std");
const netlink = @import("netlink");
const codec = netlink.codec;
const native_endian = @import("builtin").cpu.arch.endian();

/// `DEVLINK_GENL_NAME` — resolved to a dynamic message-type id at runtime.
pub const family_name = "devlink";
/// `DEVLINK_GENL_VERSION`.
pub const family_version: u8 = 1;

/// The family's multicast groups. devlink publishes exactly one, unlike
/// nl80211's six — every notification (device, port, param, region, health,
/// flash progress, …) arrives on it.
pub const mcast_group = struct {
    /// `DEVLINK_GENL_MCGRP_CONFIG_NAME`.
    pub const config = "config";
};

// ── commands (enum devlink_command) ────────────────────────────────────────

pub const CMD = struct {
    pub const UNSPEC: u8 = 0;
    pub const GET: u8 = 1;
    pub const SET: u8 = 2;
    pub const NEW: u8 = 3;
    pub const DEL: u8 = 4;

    pub const PORT_GET: u8 = 5;
    pub const PORT_SET: u8 = 6;
    pub const PORT_NEW: u8 = 7;
    pub const PORT_DEL: u8 = 8;
    pub const PORT_SPLIT: u8 = 9;
    pub const PORT_UNSPLIT: u8 = 10;

    pub const SB_GET: u8 = 11;
    pub const SB_POOL_GET: u8 = 15;
    pub const SB_OCC_SNAPSHOT: u8 = 27;

    pub const ESWITCH_GET: u8 = 29;
    pub const ESWITCH_SET: u8 = 30;

    pub const DPIPE_TABLE_GET: u8 = 31;
    pub const DPIPE_ENTRIES_GET: u8 = 32;
    pub const DPIPE_HEADERS_GET: u8 = 33;

    pub const RESOURCE_SET: u8 = 35;
    pub const RESOURCE_DUMP: u8 = 36;
    pub const RELOAD: u8 = 37;

    pub const PARAM_GET: u8 = 38;
    pub const PARAM_SET: u8 = 39;
    pub const PARAM_NEW: u8 = 40;
    pub const PARAM_DEL: u8 = 41;

    pub const REGION_GET: u8 = 42;
    pub const REGION_SET: u8 = 43;
    pub const REGION_NEW: u8 = 44;
    pub const REGION_DEL: u8 = 45;
    pub const REGION_READ: u8 = 46;

    pub const PORT_PARAM_GET: u8 = 47;
    pub const PORT_PARAM_SET: u8 = 48;

    pub const INFO_GET: u8 = 51;

    pub const HEALTH_REPORTER_GET: u8 = 52;
    pub const HEALTH_REPORTER_SET: u8 = 53;
    pub const HEALTH_REPORTER_RECOVER: u8 = 54;
    pub const HEALTH_REPORTER_DIAGNOSE: u8 = 55;
    pub const HEALTH_REPORTER_DUMP_GET: u8 = 56;
    pub const HEALTH_REPORTER_DUMP_CLEAR: u8 = 57;

    pub const FLASH_UPDATE: u8 = 58;
    /// Notification only.
    pub const FLASH_UPDATE_END: u8 = 59;
    /// Notification only.
    pub const FLASH_UPDATE_STATUS: u8 = 60;

    pub const TRAP_GET: u8 = 61;
    pub const TRAP_SET: u8 = 62;
    pub const TRAP_GROUP_GET: u8 = 65;
    pub const TRAP_POLICER_GET: u8 = 69;

    pub const HEALTH_REPORTER_TEST: u8 = 73;

    pub const RATE_GET: u8 = 74;
    pub const RATE_SET: u8 = 75;
    pub const RATE_NEW: u8 = 76;
    pub const RATE_DEL: u8 = 77;

    pub const LINECARD_GET: u8 = 78;
    pub const LINECARD_SET: u8 = 79;

    pub const SELFTESTS_GET: u8 = 82;
    pub const SELFTESTS_RUN: u8 = 83;

    pub const NOTIFY_FILTER_SET: u8 = 84;
};

/// Is `cmd` one of the `*_NEW`/`*_DEL` commands the kernel also uses as an
/// unsolicited notification on the `config` group?
///
/// devlink has no separate `_NTF` namespace the way ethtool does: the kernel
/// multicasts the very same `DEVLINK_CMD_NEW` / `PORT_NEW` / `PARAM_NEW` /
/// `REGION_NEW` / … commands it uses for replies. So "is this a notification"
/// cannot be answered from the command byte alone — only "is this a command
/// that is ever multicast". That is what this reports.
pub fn isNotifyCommand(cmd: u8) bool {
    return switch (cmd) {
        CMD.NEW,
        CMD.DEL,
        CMD.PORT_NEW,
        CMD.PORT_DEL,
        CMD.PARAM_NEW,
        CMD.PARAM_DEL,
        CMD.REGION_NEW,
        CMD.REGION_DEL,
        CMD.HEALTH_REPORTER_GET,
        CMD.FLASH_UPDATE,
        CMD.FLASH_UPDATE_END,
        CMD.FLASH_UPDATE_STATUS,
        CMD.TRAP_GET,
        CMD.TRAP_GROUP_GET,
        CMD.TRAP_POLICER_GET,
        CMD.RATE_NEW,
        CMD.RATE_DEL,
        CMD.LINECARD_GET,
        => true,
        else => false,
    };
}

// ── attributes (enum devlink_attr — one flat space) ────────────────────────

pub const ATTR = struct {
    pub const UNSPEC: u16 = 0;
    /// Bus name + dev name together are the handle for a devlink entity.
    pub const BUS_NAME: u16 = 1; // string
    pub const DEV_NAME: u16 = 2; // string

    pub const PORT_INDEX: u16 = 3; // u32
    pub const PORT_TYPE: u16 = 4; // u16
    pub const PORT_DESIRED_TYPE: u16 = 5; // u16
    pub const PORT_NETDEV_IFINDEX: u16 = 6; // u32
    pub const PORT_NETDEV_NAME: u16 = 7; // string
    pub const PORT_IBDEV_NAME: u16 = 8; // string
    pub const PORT_SPLIT_COUNT: u16 = 9; // u32
    pub const PORT_SPLIT_GROUP: u16 = 10; // u32

    pub const SB_INDEX: u16 = 11; // u32

    pub const ESWITCH_MODE: u16 = 25; // u16
    pub const ESWITCH_INLINE_MODE: u16 = 26; // u8

    pub const DPIPE_TABLES: u16 = 27; // nested

    /// A zero-payload attribute the kernel inserts so that the u64 attributes
    /// that follow it land on an 8-byte boundary. Never carries information;
    /// every decoder here ignores it.
    pub const PAD: u16 = 61;

    pub const ESWITCH_ENCAP_MODE: u16 = 62; // u8

    pub const RESOURCE_LIST: u16 = 63; // nested
    pub const RESOURCE: u16 = 64; // nested
    pub const RESOURCE_NAME: u16 = 65; // string
    pub const RESOURCE_ID: u16 = 66; // u64
    pub const RESOURCE_SIZE: u16 = 67; // u64
    pub const RESOURCE_SIZE_NEW: u16 = 68; // u64
    pub const RESOURCE_SIZE_VALID: u16 = 69; // u8
    pub const RESOURCE_SIZE_MIN: u16 = 70; // u64
    pub const RESOURCE_SIZE_MAX: u16 = 71; // u64
    pub const RESOURCE_SIZE_GRAN: u16 = 72; // u64
    pub const RESOURCE_UNIT: u16 = 73; // u8
    pub const RESOURCE_OCC: u16 = 74; // u64

    pub const PORT_FLAVOUR: u16 = 77; // u16
    pub const PORT_NUMBER: u16 = 78; // u32
    pub const PORT_SPLIT_SUBPORT_NUMBER: u16 = 79; // u32

    pub const PARAM: u16 = 80; // nested
    pub const PARAM_NAME: u16 = 81; // string
    pub const PARAM_GENERIC: u16 = 82; // flag
    pub const PARAM_TYPE: u16 = 83; // u8 (enum devlink_var_attr_type)
    pub const PARAM_VALUES_LIST: u16 = 84; // nested
    pub const PARAM_VALUE: u16 = 85; // nested
    /// **Dynamic** — its wire width is whatever `PARAM_TYPE` says.
    pub const PARAM_VALUE_DATA: u16 = 86;
    pub const PARAM_VALUE_CMODE: u16 = 87; // u8

    pub const REGION_NAME: u16 = 88; // string
    pub const REGION_SIZE: u16 = 89; // u64
    pub const REGION_SNAPSHOTS: u16 = 90; // nested
    pub const REGION_SNAPSHOT: u16 = 91; // nested
    pub const REGION_SNAPSHOT_ID: u16 = 92; // u32

    pub const REGION_CHUNKS: u16 = 93; // nested
    pub const REGION_CHUNK: u16 = 94; // nested
    pub const REGION_CHUNK_DATA: u16 = 95; // binary
    pub const REGION_CHUNK_ADDR: u16 = 96; // u64
    pub const REGION_CHUNK_LEN: u16 = 97; // u64

    pub const INFO_DRIVER_NAME: u16 = 98; // string
    pub const INFO_SERIAL_NUMBER: u16 = 99; // string
    pub const INFO_VERSION_FIXED: u16 = 100; // nested
    pub const INFO_VERSION_RUNNING: u16 = 101; // nested
    pub const INFO_VERSION_STORED: u16 = 102; // nested
    pub const INFO_VERSION_NAME: u16 = 103; // string
    pub const INFO_VERSION_VALUE: u16 = 104; // string

    pub const HEALTH_REPORTER: u16 = 114; // nested
    pub const HEALTH_REPORTER_NAME: u16 = 115; // string
    pub const HEALTH_REPORTER_STATE: u16 = 116; // u8
    pub const HEALTH_REPORTER_ERR_COUNT: u16 = 117; // u64
    pub const HEALTH_REPORTER_RECOVER_COUNT: u16 = 118; // u64
    pub const HEALTH_REPORTER_DUMP_TS: u16 = 119; // u64
    pub const HEALTH_REPORTER_GRACEFUL_PERIOD: u16 = 120; // u64
    pub const HEALTH_REPORTER_AUTO_RECOVER: u16 = 121; // u8

    pub const FLASH_UPDATE_FILE_NAME: u16 = 122; // string
    pub const FLASH_UPDATE_COMPONENT: u16 = 123; // string
    pub const FLASH_UPDATE_STATUS_MSG: u16 = 124; // string
    pub const FLASH_UPDATE_STATUS_DONE: u16 = 125; // u64
    pub const FLASH_UPDATE_STATUS_TOTAL: u16 = 126; // u64

    pub const PORT_PCI_PF_NUMBER: u16 = 127; // u16
    pub const PORT_PCI_VF_NUMBER: u16 = 128; // u16

    pub const STATS: u16 = 129; // nested

    pub const TRAP_NAME: u16 = 130; // string

    pub const RELOAD_FAILED: u16 = 136; // u8
    pub const HEALTH_REPORTER_DUMP_TS_NS: u16 = 137; // u64

    pub const NETNS_FD: u16 = 138; // u32
    pub const NETNS_PID: u16 = 139; // u32
    pub const NETNS_ID: u16 = 140; // u32

    pub const HEALTH_REPORTER_AUTO_DUMP: u16 = 141; // u8

    pub const PORT_FUNCTION: u16 = 145; // nested
    pub const INFO_BOARD_SERIAL_NUMBER: u16 = 146; // string

    pub const PORT_LANES: u16 = 147; // u32
    pub const PORT_SPLITTABLE: u16 = 148; // u8
    pub const PORT_EXTERNAL: u16 = 149; // u8
    pub const PORT_CONTROLLER_NUMBER: u16 = 150; // u32

    pub const RELOAD_ACTION: u16 = 153; // u8
    pub const DEV_STATS: u16 = 156; // nested
    pub const RELOAD_STATS: u16 = 157; // nested

    pub const PORT_PCI_SF_NUMBER: u16 = 164; // u32

    pub const REGION_MAX_SNAPSHOTS: u16 = 170; // u32

    pub const LINECARD_INDEX: u16 = 171; // u32

    pub const NESTED_DEVLINK: u16 = 175; // nested
    pub const SELFTESTS: u16 = 176; // nested

    pub const REGION_DIRECT: u16 = 179; // flag

    pub const PARAM_VALUE_DEFAULT: u16 = 182; // dynamic
    pub const PARAM_RESET_DEFAULT: u16 = 183; // flag
};

// ── enums ──────────────────────────────────────────────────────────────────

/// `enum devlink_port_type`. `notset` is a real, common value: a port whose
/// type the driver has not decided yet.
pub const PortType = enum(u16) {
    notset = 0,
    auto = 1,
    eth = 2,
    ib = 3,
    _,
};

/// `enum devlink_port_flavour`.
pub const PortFlavour = enum(u16) {
    /// Any kind of port physically facing the user.
    physical = 0,
    cpu = 1,
    /// Distributed-switch-architecture interconnect port.
    dsa = 2,
    /// eswitch port facing the PCI physical function.
    pci_pf = 3,
    /// eswitch port facing a PCI virtual function.
    pci_vf = 4,
    /// Any virtual port facing the user.
    virtual = 5,
    /// Exists in the switch but is not used.
    unused = 6,
    /// eswitch port facing a PCI subfunction.
    pci_sf = 7,
    _,
};

/// `enum devlink_eswitch_mode`.
pub const EswitchMode = enum(u16) {
    legacy = 0,
    switchdev = 1,
    switchdev_inactive = 2,
    _,
};

/// `enum devlink_eswitch_inline_mode` — how much of the packet header the
/// eswitch must see inline.
pub const InlineMode = enum(u8) {
    none = 0,
    link = 1,
    network = 2,
    transport = 3,
    _,
};

/// `enum devlink_eswitch_encap_mode`.
pub const EncapMode = enum(u8) {
    none = 0,
    basic = 1,
    _,
};

/// `enum devlink_param_cmode` — **when** a parameter's value takes effect, and
/// therefore *which* of a parameter's several values you are looking at. One
/// parameter can carry all three at once, with different values in each.
pub const ParamCmode = enum(u8) {
    /// Takes effect immediately.
    runtime = 0,
    /// Takes effect at the next driver init (`devlink dev reload`).
    driverinit = 1,
    /// Stored in the device's non-volatile memory; survives a power cycle.
    permanent = 2,
    _,
};

/// `enum devlink_var_attr_type` — the type tag a parameter carries in
/// `DEVLINK_ATTR_PARAM_TYPE`, which decides how wide
/// `DEVLINK_ATTR_PARAM_VALUE_DATA` is on the wire. The low values deliberately
/// match the kernel's internal `NLA_*` numbering.
pub const ParamType = enum(u8) {
    u8_ = 1,
    u16_ = 2,
    u32_ = 3,
    u64_ = 4,
    string = 5,
    flag = 6,
    nul_string = 10,
    binary = 11,
    _,
};

/// `enum devlink_resource_unit`.
pub const ResourceUnit = enum(u8) {
    entry = 0,
    _,
};

/// Health-reporter state. Declared in the kernel's `include/net/devlink.h`
/// rather than in the UAPI header, but it is on the wire in
/// `DEVLINK_ATTR_HEALTH_REPORTER_STATE` and is therefore ABI all the same.
pub const HealthState = enum(u8) {
    healthy = 0,
    @"error" = 1,
    _,
};

// ── length caps ────────────────────────────────────────────────────────────
//
// devlink's strings have no UAPI-declared maxima the way `IFNAMSIZ` does, so
// the decoded structs below carry inline buffers sized for every bus and
// driver that exists today, plus room. A reply that overruns one is reported
// as `error.BadLength` rather than truncated — a silently shortened device
// name would be a *different* device.

/// Longest `DEVLINK_ATTR_BUS_NAME`. The registered buses are `pci`, `pdev`,
/// `platform`, `netdevsim`, `auxiliary`, `virtual` and `vsc`.
pub const bus_name_max = 16;
/// Longest `DEVLINK_ATTR_DEV_NAME`. A PCI handle is 12 bytes
/// (`0000:00:00.0`); an auxiliary-bus one is longer (`mlx5_core.eth.0`).
pub const dev_name_max = 64;
/// `IFNAMSIZ` — the cap on `DEVLINK_ATTR_PORT_NETDEV_NAME`.
pub const ifnamesize = 16;
/// Longest parameter / region / reporter / resource / version name kept.
pub const name_max = 64;
/// Longest string a parameter value or an info version value may carry.
/// The kernel's own `DEVLINK_PARAM_MAX_STRING_VALUE` is 32.
pub const value_max = 128;

// ── host-order u64 helpers ─────────────────────────────────────────────────
//
// devlink is full of u64 attributes (region sizes, resource sizes and
// occupancies, health counters) in **host** byte order. `netlink.codec` ships
// host-order accessors up to u32 and a big-endian u64 for the netfilter
// families, so the host-order u64 pair lives here.

/// Read a host-order u64 attribute, with the codec's exact-width guard.
pub fn asU64(a: codec.Attr) codec.Error!u64 {
    if (a.data.len != 8) return error.BadLength;
    return std.mem.readInt(u64, a.data[0..8], native_endian);
}

/// Append a host-order u64 attribute (12 bytes of TLV, no padding needed).
pub fn appendAttrU64(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    value: u64,
) std.mem.Allocator.Error!void {
    var raw: [8]u8 = undefined;
    std.mem.writeInt(u64, &raw, value, native_endian);
    codec.appendAttr(gpa, list, attr_type, &raw) catch |err| switch (err) {
        error.AttrTooLong => unreachable, // 12 bytes total
        error.OutOfMemory => return error.OutOfMemory,
    };
}

/// Copy a bounded string out of a reply attribute into an inline buffer.
/// `error.BadLength` when it does not fit — see the note on the length caps.
pub fn copyName(dst: []u8, len: *u8, a: codec.Attr) codec.Error!void {
    const s = a.asString();
    if (s.len > dst.len) return error.BadLength;
    @memcpy(dst[0..s.len], s);
    len.* = @intCast(s.len);
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

test "command numbers match the ordinals the real devlink binary put on the wire" {
    // Every one of these was read out of an `strace` of iproute2 6.19; see
    // goldens.zig. They are asserted here too so that a mistake in the table
    // fails even if a golden is skipped on a big-endian host.
    try testing.expectEqual(@as(u8, 0x01), CMD.GET);
    try testing.expectEqual(@as(u8, 0x05), CMD.PORT_GET);
    try testing.expectEqual(@as(u8, 0x06), CMD.PORT_SET);
    try testing.expectEqual(@as(u8, 0x09), CMD.PORT_SPLIT);
    try testing.expectEqual(@as(u8, 0x0a), CMD.PORT_UNSPLIT);
    try testing.expectEqual(@as(u8, 0x1d), CMD.ESWITCH_GET);
    try testing.expectEqual(@as(u8, 0x1e), CMD.ESWITCH_SET);
    try testing.expectEqual(@as(u8, 0x24), CMD.RESOURCE_DUMP);
    try testing.expectEqual(@as(u8, 0x26), CMD.PARAM_GET);
    try testing.expectEqual(@as(u8, 0x2a), CMD.REGION_GET);
    try testing.expectEqual(@as(u8, 0x2c), CMD.REGION_NEW);
    try testing.expectEqual(@as(u8, 0x2d), CMD.REGION_DEL);
    try testing.expectEqual(@as(u8, 0x2e), CMD.REGION_READ);
    try testing.expectEqual(@as(u8, 0x33), CMD.INFO_GET);
    try testing.expectEqual(@as(u8, 0x34), CMD.HEALTH_REPORTER_GET);
    try testing.expectEqual(@as(u8, 0x36), CMD.HEALTH_REPORTER_RECOVER);
}

test "attribute numbers match the ones seen on the wire" {
    try testing.expectEqual(@as(u16, 0x01), ATTR.BUS_NAME);
    try testing.expectEqual(@as(u16, 0x02), ATTR.DEV_NAME);
    try testing.expectEqual(@as(u16, 0x03), ATTR.PORT_INDEX);
    try testing.expectEqual(@as(u16, 0x04), ATTR.PORT_TYPE);
    try testing.expectEqual(@as(u16, 0x09), ATTR.PORT_SPLIT_COUNT);
    try testing.expectEqual(@as(u16, 0x19), ATTR.ESWITCH_MODE);
    try testing.expectEqual(@as(u16, 0x1a), ATTR.ESWITCH_INLINE_MODE);
    try testing.expectEqual(@as(u16, 0x3e), ATTR.ESWITCH_ENCAP_MODE);
    try testing.expectEqual(@as(u16, 0x51), ATTR.PARAM_NAME);
    try testing.expectEqual(@as(u16, 0x57), ATTR.PARAM_VALUE_CMODE);
    try testing.expectEqual(@as(u16, 0x58), ATTR.REGION_NAME);
    // REGION_SIZE and REGION_MAX_SNAPSHOTS are otherwise only exercised via
    // `appendAttrU64`/`parseRegion`, which both read the same symbol — a
    // swap of their two numeric values is invisible to that round trip
    // (different width, u64 vs u32, so it would not even fail to decode).
    // Pin the real kernel numbers here so a swap has an anchor to break.
    try testing.expectEqual(@as(u16, 0x59), ATTR.REGION_SIZE);
    try testing.expectEqual(@as(u16, 0xaa), ATTR.REGION_MAX_SNAPSHOTS);
    try testing.expectEqual(@as(u16, 0x5c), ATTR.REGION_SNAPSHOT_ID);
    try testing.expectEqual(@as(u16, 0x60), ATTR.REGION_CHUNK_ADDR);
    try testing.expectEqual(@as(u16, 0x61), ATTR.REGION_CHUNK_LEN);
    try testing.expectEqual(@as(u16, 0x73), ATTR.HEALTH_REPORTER_NAME);
    try testing.expectEqual(@as(u16, 0x43), ATTR.RESOURCE_SIZE);
}

test "asU64 / appendAttrU64 round-trip and reject a wrong width" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try appendAttrU64(gpa, &list, ATTR.REGION_SIZE, 0x0123_4567_89ab_cdef);
    try testing.expectEqual(@as(usize, 12), list.items.len);

    var it: codec.AttrIterator = .{ .buf = list.items };
    const a = (try it.next()).?;
    try testing.expectEqual(ATTR.REGION_SIZE, a.type);
    try testing.expectEqual(@as(u64, 0x0123_4567_89ab_cdef), try asU64(a));

    // A u32-wide attribute read as u64 is a malformed reply, not a wild read.
    list.clearRetainingCapacity();
    try codec.appendAttrU32(gpa, &list, ATTR.REGION_SIZE, 1);
    var it2: codec.AttrIterator = .{ .buf = list.items };
    try testing.expectError(error.BadLength, asU64((try it2.next()).?));
}

test "copyName bounds the destination instead of truncating" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try codec.appendAttrString(gpa, &list, ATTR.PARAM_NAME, "a" ** 8);
    var it: codec.AttrIterator = .{ .buf = list.items };
    const a = (try it.next()).?;

    var buf: [8]u8 = undefined;
    var len: u8 = 0;
    try copyName(&buf, &len, a);
    try testing.expectEqualStrings("a" ** 8, buf[0..len]);

    var small: [7]u8 = undefined;
    try testing.expectError(error.BadLength, copyName(&small, &len, a));
}

test "isNotifyCommand separates multicast commands from request-only ones" {
    try testing.expect(isNotifyCommand(CMD.NEW));
    try testing.expect(isNotifyCommand(CMD.PORT_NEW));
    try testing.expect(isNotifyCommand(CMD.PARAM_NEW));
    try testing.expect(isNotifyCommand(CMD.FLASH_UPDATE_STATUS));
    // A pure request command is never multicast.
    try testing.expect(!isNotifyCommand(CMD.GET));
    try testing.expect(!isNotifyCommand(CMD.PORT_SET));
    try testing.expect(!isNotifyCommand(CMD.RESOURCE_DUMP));
    try testing.expect(!isNotifyCommand(CMD.REGION_READ));
}

test "enums represent every value the kernel can send, including unknown ones" {
    // The `_` tag means a future kernel value round-trips instead of being
    // illegal behaviour.
    try testing.expectEqual(PortType.eth, @as(PortType, @enumFromInt(2)));
    try testing.expectEqual(@as(u16, 99), @intFromEnum(@as(PortFlavour, @enumFromInt(99))));
    try testing.expectEqual(ParamCmode.driverinit, @as(ParamCmode, @enumFromInt(1)));
    try testing.expectEqual(ParamType.u64_, @as(ParamType, @enumFromInt(4)));
    try testing.expectEqual(HealthState.@"error", @as(HealthState, @enumFromInt(1)));
    try testing.expectEqual(EswitchMode.switchdev, @as(EswitchMode, @enumFromInt(1)));
}
