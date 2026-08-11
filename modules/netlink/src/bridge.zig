// SPDX-License-Identifier: MIT
//! bridge — `AF_BRIDGE` extensions on top of the module's rtnetlink engine.
//!
//! Three surfaces the plain link/address/route API cannot express:
//!
//! 1. **Bridge device lifecycle** — `RTM_NEWLINK` with
//!    `IFLA_LINKINFO`/`IFLA_INFO_KIND = "bridge"` plus the `IFLA_BR_*`
//!    options inside `IFLA_INFO_DATA`, and enslaving/releasing a port with
//!    `IFLA_MASTER`.
//! 2. **FDB (forwarding database)** — `RTM_NEWNEIGH`/`RTM_DELNEIGH`/
//!    `RTM_GETNEIGH` with `ndm_family = AF_BRIDGE`, i.e. what `bridge fdb`
//!    drives.
//! 3. **VLAN filtering + bridge-port options** — `RTM_SETLINK` with a nested
//!    `IFLA_AF_SPEC` (`IFLA_BRIDGE_VLAN_INFO`, incl. VID ranges) and
//!    `IFLA_PROTINFO` (`IFLA_BRPORT_*`), i.e. `bridge vlan` and
//!    `bridge link set`.
//!
//! Everything here is a *builder* or a *parser*: pure functions over byte
//! buffers, offline-testable and golden-tested against real `iproute2` traffic
//! (captured from an `nlmon` tap inside `unshare -rn`; each golden test cites
//! the exact command). The transport is the existing engine — `Socket.nextSeq`
//! + `Socket.requestAck` — so nothing about sending, ACK handling, extended
//! ACKs or dump assembly is duplicated. The `Socket.bridge*`/`fdb*`/`brport*`
//! methods that wire the two together live in `root.zig`.
//!
//! ```zig
//! try nl.bridgeAdd(.{ .name = "br0", .vlan_filtering = true, .up = true }, .{});
//! try nl.portEnslave(veth_index, br_index);
//! try nl.bridgeVlanAdd(veth_index, .{ .vid = 10, .pvid = true, .untagged = true });
//! try nl.fdbAdd(.{ .ifindex = veth_index, .lladdr = &mac, .vlan = 10 }, .{});
//! ```
//!
//! Deliberately **not** covered (see README/SPEC for the full list): MDB /
//! multicast snooping (`RTM_*MDB`), VXLAN-specific link creation, VLAN tunnel
//! mapping (`IFLA_BRIDGE_VLAN_TUNNEL_INFO`), MRP/CFM/MST and bridge-port
//! backup/neighbour-suppression beyond the plain flag setters below.

const std = @import("std");
const builtin = @import("builtin");
const native_endian = builtin.cpu.arch.endian();

const codec = @import("codec.zig");
const root = @import("root.zig");

// ── kernel UAPI constants ───────────────────────────────────────────────────

/// `RTM_SETLINK` (linux/rtnetlink.h) — the message `bridge vlan`/`bridge link
/// set` use to change AF_BRIDGE state on an existing device. `RTM_DELLINK`
/// with `ifi_family = AF_BRIDGE` is the matching removal.
pub const RTM_SETLINK: u16 = @intFromEnum(std.os.linux.NetlinkMessageType.RTM_SETLINK);

/// `IFLA_MASTER` — the bridge (or bond) an interface is enslaved to; 0 releases.
pub const IFLA_MASTER: u16 = @intFromEnum(std.os.linux.IFLA.MASTER);
/// `IFLA_PROTINFO` — family-specific per-port state; for AF_BRIDGE this nests
/// `IFLA_BRPORT_*`.
pub const IFLA_PROTINFO: u16 = @intFromEnum(std.os.linux.IFLA.PROTINFO);
/// `IFLA_AF_SPEC` — family-specific link attributes; for AF_BRIDGE it nests
/// `IFLA_BRIDGE_FLAGS` / `IFLA_BRIDGE_VLAN_INFO`.
pub const IFLA_AF_SPEC: u16 = @intFromEnum(std.os.linux.IFLA.AF_SPEC);
/// `IFLA_EXT_MASK` — extra content to include in a link dump (`RTEXT_FILTER_*`).
pub const IFLA_EXT_MASK: u16 = @intFromEnum(std.os.linux.IFLA.EXT_MASK);

/// `RTEXT_FILTER_*` (linux/rtnetlink.h) — `IFLA_EXT_MASK` values selecting
/// optional dump content. `BRVLAN` is what makes `RTM_GETLINK` emit the
/// per-port VLAN list inside `IFLA_AF_SPEC`.
pub const RTEXT_FILTER = struct {
    pub const VF: u32 = 1 << 0;
    pub const BRVLAN: u32 = 1 << 1;
    pub const BRVLAN_COMPRESSED: u32 = 1 << 2;
    pub const SKIP_STATS: u32 = 1 << 3;
    pub const MRP: u32 = 1 << 4;
    pub const CFM_CONFIG: u32 = 1 << 5;
    pub const CFM_STATUS: u32 = 1 << 6;
    pub const MST: u32 = 1 << 7;
};

/// Bridge device options nested in `IFLA_INFO_DATA` (linux/if_link.h
/// `IFLA_BR_*`). Only the ones this module encodes are named; the enum is much
/// longer and the kernel ignores unknown members of a dump.
pub const IFLA_BR = struct {
    pub const UNSPEC: u16 = 0;
    /// u32, centiseconds — STP forward delay.
    pub const FORWARD_DELAY: u16 = 1;
    /// u32, centiseconds.
    pub const HELLO_TIME: u16 = 2;
    /// u32, centiseconds.
    pub const MAX_AGE: u16 = 3;
    /// u32, centiseconds — MAC-learning entry lifetime.
    pub const AGEING_TIME: u16 = 4;
    /// u32 — 0 = STP off (kernel-side), 1 = kernel STP.
    pub const STP_STATE: u16 = 5;
    /// u16 — bridge priority (root-election tiebreaker).
    pub const PRIORITY: u16 = 6;
    /// u8 — master VLAN filtering on/off.
    pub const VLAN_FILTERING: u16 = 7;
    /// u16, **big-endian** ethertype (0x8100 = 802.1Q, 0x88a8 = 802.1ad).
    pub const VLAN_PROTOCOL: u16 = 8;
    pub const GROUP_FWD_MASK: u16 = 9;
    pub const ROOT_ID: u16 = 10;
    pub const BRIDGE_ID: u16 = 11;
    pub const ROOT_PORT: u16 = 12;
    pub const ROOT_PATH_COST: u16 = 13;
    pub const TOPOLOGY_CHANGE: u16 = 14;
    pub const TOPOLOGY_CHANGE_DETECTED: u16 = 15;
    /// Corrected by `scripts/check-uapi-consts.py` (audit finding `netlink`
    /// F3): was hand-transcribed as 22, which is `linux/if_link.h`'s
    /// position *before* the block of `IFLA_BR_HELLO_TIMER`…
    /// `IFLA_BR_NF_CALL_ARPTABLES` entries this module does not name; the
    /// kernel's real value is 39. Unused by this module (no call sites), so
    /// the wrong id was latent, not live.
    pub const VLAN_DEFAULT_PVID: u16 = 39;
    /// Same correction as `VLAN_DEFAULT_PVID` above; kernel value is 41
    /// (was 24). Also unused.
    pub const VLAN_STATS_ENABLED: u16 = 41;
    pub const MCAST_SNOOPING: u16 = 23;
};

/// Bridge *port* options, nested in `IFLA_PROTINFO` on an AF_BRIDGE
/// `RTM_SETLINK` (and reported the same way in a link dump).
pub const IFLA_BRPORT = struct {
    pub const UNSPEC: u16 = 0;
    /// u8 — `BR_STATE.*` (0 disabled … 3 forwarding).
    pub const STATE: u16 = 1;
    /// u16 — STP port priority.
    pub const PRIORITY: u16 = 2;
    /// u32 — STP path cost.
    pub const COST: u16 = 3;
    /// u8 — hairpin mode (reflect frames back out the ingress port).
    pub const MODE: u16 = 4;
    /// u8 — BPDU guard.
    pub const GUARD: u16 = 5;
    /// u8 — root-port block.
    pub const PROTECT: u16 = 6;
    /// u8 — multicast fast leave.
    pub const FAST_LEAVE: u16 = 7;
    /// u8 — MAC learning on this port.
    pub const LEARNING: u16 = 8;
    /// u8 — flood unknown unicast out of this port.
    pub const UNICAST_FLOOD: u16 = 9;
    pub const PROXYARP: u16 = 10;
    pub const LEARNING_SYNC: u16 = 11;
    pub const PROXYARP_WIFI: u16 = 12;
    pub const ROOT_ID: u16 = 13;
    pub const BRIDGE_ID: u16 = 14;
    pub const DESIGNATED_PORT: u16 = 15;
    pub const DESIGNATED_COST: u16 = 16;
    pub const ID: u16 = 17;
    pub const NO: u16 = 18;
    pub const TOPOLOGY_CHANGE_ACK: u16 = 19;
    pub const CONFIG_PENDING: u16 = 20;
    pub const MESSAGE_AGE_TIMER: u16 = 21;
    pub const FORWARD_DELAY_TIMER: u16 = 22;
    pub const HOLD_TIMER: u16 = 23;
    pub const FLUSH: u16 = 24;
    pub const MULTICAST_ROUTER: u16 = 25;
    pub const PAD: u16 = 26;
    /// u8 — flood unknown multicast.
    pub const MCAST_FLOOD: u16 = 27;
    pub const MCAST_TO_UCAST: u16 = 28;
    pub const VLAN_TUNNEL: u16 = 29;
    /// u8 — flood broadcast.
    pub const BCAST_FLOOD: u16 = 30;
    pub const GROUP_FWD_MASK: u16 = 31;
    /// u8 — suppress ARP/ND flooding (EVPN).
    pub const NEIGH_SUPPRESS: u16 = 32;
    /// u8 — port isolation (no forwarding to other isolated ports).
    pub const ISOLATED: u16 = 33;
    pub const BACKUP_PORT: u16 = 34;
};

/// Attributes nested in `IFLA_AF_SPEC` for AF_BRIDGE (linux/if_bridge.h).
pub const IFLA_BRIDGE = struct {
    /// u16 — `BRIDGE_FLAGS.*`: whether the request targets the port's master
    /// bridge or the device itself.
    pub const FLAGS: u16 = 0;
    /// u16 — `BRIDGE_MODE.*` (VEB/VEPA), for SR-IOV embedded switches.
    pub const MODE: u16 = 1;
    /// `struct bridge_vlan_info` — see `VlanInfo`.
    pub const VLAN_INFO: u16 = 2;
    pub const VLAN_TUNNEL_INFO: u16 = 3;
    pub const MRP: u16 = 4;
    pub const CFM: u16 = 5;
    pub const MST: u16 = 6;
};

/// `BRIDGE_FLAGS_*` — the `IFLA_BRIDGE_FLAGS` value. Omitting the attribute
/// entirely means "master", which is what `bridge vlan add dev <port>` sends.
pub const BRIDGE_FLAGS = struct {
    /// Apply to the port's master bridge (the implicit default).
    pub const MASTER: u16 = 1;
    /// Apply to the device itself — used when the device *is* the bridge.
    pub const SELF: u16 = 2;
};

/// `BRIDGE_MODE_*` for `IFLA_BRIDGE_MODE`.
pub const BRIDGE_MODE = struct {
    pub const VEB: u16 = 0;
    pub const VEPA: u16 = 1;
    pub const UNDEF: u16 = 0xffff;
};

/// `BRIDGE_VLAN_INFO_*` — flags of `struct bridge_vlan_info`.
pub const BRIDGE_VLAN_INFO = struct {
    /// Operate on the port's master bridge.
    pub const MASTER: u16 = 1 << 0;
    /// This VID is the port's PVID (untagged ingress lands here).
    pub const PVID: u16 = 1 << 1;
    /// Egress untagged for this VID.
    pub const UNTAGGED: u16 = 1 << 2;
    /// First VID of an inclusive range; the next entry carries `RANGE_END`.
    pub const RANGE_BEGIN: u16 = 1 << 3;
    /// Last VID of an inclusive range.
    pub const RANGE_END: u16 = 1 << 4;
    /// Dump-only: the VLAN is configured on the bridge itself, not just a port.
    pub const BRENTRY: u16 = 1 << 5;
    pub const ONLY_OPTS: u16 = 1 << 6;
};

/// STP port states (linux/if_bridge.h `BR_STATE_*`) for `IFLA_BRPORT_STATE`.
pub const BR_STATE = struct {
    pub const DISABLED: u8 = 0;
    pub const LISTENING: u8 = 1;
    pub const LEARNING: u8 = 2;
    pub const FORWARDING: u8 = 3;
    pub const BLOCKING: u8 = 4;
};

/// Lowest/highest usable 802.1Q VID. 0 and 4095 are reserved by the standard
/// and rejected by the kernel's bridge code.
pub const vlan_id_min: u16 = 1;
pub const vlan_id_max: u16 = 4094;

/// sizeof(struct bridge_vlan_info) — `{ __u16 flags; __u16 vid; }`.
pub const bridge_vlan_info_len = 4;

// ── error sets ──────────────────────────────────────────────────────────────

/// Build failures for the bridge builders. A *superset* of the module's
/// `BuildError`, so `netlink`'s existing error sets are untouched.
pub const BuildError = root.BuildError || error{
    /// A VID outside 1..4094, which the kernel would reject anyway.
    InvalidVlanId,
    /// `vid_end` below `vid`, or a `pvid` request spanning a range (the
    /// kernel allows exactly one PVID per port, so a range cannot be one).
    InvalidVlanRange,
};

/// Everything a bridge write op can fail with.
pub const WriteError = root.RequestError || BuildError;

// ── typed results ───────────────────────────────────────────────────────────

/// One forwarding-database entry (`RTM_NEWNEIGH` with `ndm_family =
/// AF_BRIDGE`). Plain data — copies only, nothing borrows from the input.
pub const FdbEntry = struct {
    /// Port the entry lives on (`ndm_ifindex`).
    ifindex: u32,
    /// `NUD.*` bitmask. `PERMANENT` = a static entry, `REACHABLE|NOARP` =
    /// what `bridge fdb add … static` installs, plain `REACHABLE` = learned.
    state: u16,
    /// `NTF.*` — notably `SELF` (the device's own FDB) vs `MASTER` (the
    /// bridge's), and `EXT_LEARNED` for controller-installed entries.
    flags: u8,
    /// `ndm_type` (`RTN.*`); 0 for ordinary entries.
    ntype: u8,
    lladdr: [6]u8 = @splat(0),
    /// 6 when the kernel reported an `NDA_LLADDR`, else 0.
    lladdr_len: u8 = 0,
    /// `NDA_MASTER` — the bridge ifindex, when reported.
    master: ?u32 = null,
    /// `NDA_VLAN` — the VID the entry belongs to (absent = untagged/VLAN 0).
    vlan: ?u16 = null,
    /// `NDA_VNI` — VXLAN network identifier for an overlay entry.
    vni: ?u32 = null,
    dst: [16]u8 = @splat(0),
    /// Valid bytes in `dst`: 4 or 16 for a VXLAN remote, else 0.
    dst_len: u8 = 0,

    /// The MAC (6 bytes) or an empty slice when the kernel sent none.
    pub fn lladdrBytes(e: *const FdbEntry) []const u8 {
        return e.lladdr[0..e.lladdr_len];
    }

    /// `NDA_DST` — the VXLAN remote IP, or an empty slice.
    pub fn dstBytes(e: *const FdbEntry) []const u8 {
        return e.dst[0..e.dst_len];
    }

    /// The entry lives in the *device's* own FDB (`NTF_SELF`).
    pub fn isSelf(e: *const FdbEntry) bool {
        return e.flags & root.NTF.SELF != 0;
    }

    /// The entry lives in the master bridge's FDB (`NTF_MASTER`).
    pub fn isMaster(e: *const FdbEntry) bool {
        return e.flags & root.NTF.MASTER != 0;
    }

    /// Installed by a controller rather than learned (`NTF_EXT_LEARNED`).
    pub fn isExternLearned(e: *const FdbEntry) bool {
        return e.flags & root.NTF.EXT_LEARNED != 0;
    }

    /// Never ages out (`NUD_PERMANENT`) — a statically configured entry.
    pub fn isPermanent(e: *const FdbEntry) bool {
        return e.state & root.NUD.PERMANENT != 0;
    }
};

/// One VLAN configured on a bridge port (decoded from `IFLA_AF_SPEC` in an
/// `RTM_GETLINK`/`RTEXT_FILTER_BRVLAN` dump). A `RANGE_BEGIN`/`RANGE_END`
/// pair collapses into a single entry with `vid != vid_end`.
pub const VlanEntry = struct {
    /// Port (or bridge) the VLAN is configured on.
    ifindex: u32,
    /// First VID of the range.
    vid: u16,
    /// Last VID, inclusive; equals `vid` for a single-VID entry.
    vid_end: u16,
    /// `BRIDGE_VLAN_INFO.*` with the `RANGE_BEGIN`/`RANGE_END` bookkeeping
    /// bits cleared — they are represented by `vid`/`vid_end` instead.
    flags: u16,

    /// Untagged ingress on the port lands in this VLAN.
    pub fn isPvid(v: *const VlanEntry) bool {
        return v.flags & BRIDGE_VLAN_INFO.PVID != 0;
    }

    /// Frames leave the port untagged for this VLAN.
    pub fn isUntagged(v: *const VlanEntry) bool {
        return v.flags & BRIDGE_VLAN_INFO.UNTAGGED != 0;
    }

    /// How many VIDs the entry covers.
    pub fn count(v: *const VlanEntry) u32 {
        return @as(u32, v.vid_end - v.vid) + 1;
    }

    /// Whether `vid` falls inside this entry's range.
    pub fn contains(v: *const VlanEntry, vid: u16) bool {
        return vid >= v.vid and vid <= v.vid_end;
    }
};

/// Bridge-port state decoded from `IFLA_PROTINFO` of a link dump message.
/// Every field is optional: the kernel only reports what the port has.
pub const BrportInfo = struct {
    ifindex: u32,
    /// The bridge this port belongs to (`IFLA_MASTER`).
    master: ?u32 = null,
    /// `BR_STATE.*`.
    state: ?u8 = null,
    priority: ?u16 = null,
    cost: ?u32 = null,
    learning: ?bool = null,
    unicast_flood: ?bool = null,
    mcast_flood: ?bool = null,
    bcast_flood: ?bool = null,
    isolated: ?bool = null,
    neigh_suppress: ?bool = null,
    /// Hairpin mode (`IFLA_BRPORT_MODE`).
    hairpin: ?bool = null,
};

// ── write specs ─────────────────────────────────────────────────────────────

/// A bridge device to create with `Socket.bridgeAdd` — `RTM_NEWLINK` with
/// `IFLA_LINKINFO{ IFLA_INFO_KIND = "bridge", IFLA_INFO_DATA{ IFLA_BR_* } }`.
///
/// Every option is optional; a null field is simply not encoded and the kernel
/// keeps its default. Options are emitted in ascending `IFLA_BR_*` order,
/// which is also the order `ip link add … type bridge` produces when its
/// arguments are given in that order (see the golden test).
pub const BridgeSpec = struct {
    /// Device name (`IFLA_IFNAME`), 1..15 characters.
    name: []const u8,
    /// `IFLA_BR_FORWARD_DELAY`, centiseconds (`ip`'s `forward_delay`).
    forward_delay: ?u32 = null,
    /// `IFLA_BR_AGEING_TIME`, centiseconds — 0 disables MAC ageing.
    ageing_time: ?u32 = null,
    /// `IFLA_BR_STP_STATE` — 0 = STP off, 1 = kernel STP.
    stp_state: ?u32 = null,
    /// `IFLA_BR_PRIORITY`.
    priority: ?u16 = null,
    /// `IFLA_BR_VLAN_FILTERING` — the master switch for everything in
    /// `VlanSpec`; without it the bridge ignores VLAN tags.
    vlan_filtering: ?bool = null,
    /// `IFLA_BR_VLAN_PROTOCOL` — 0x8100 (802.1Q) or 0x88a8 (802.1ad),
    /// written big-endian on the wire as the kernel expects.
    vlan_protocol: ?u16 = null,
    mtu: ?u32 = null,
    /// `IFLA_ADDRESS` — pin the bridge MAC instead of letting it inherit the
    /// lowest port address.
    mac: ?[]const u8 = null,
    /// Bring the bridge up in the same request.
    up: bool = false,
};

/// An FDB entry for `Socket.fdbAdd`/`.fdbDel` — `RTM_NEWNEIGH`/`RTM_DELNEIGH`
/// with `ndm_family = AF_BRIDGE`.
///
/// The defaults reproduce `bridge fdb add <mac> dev <port> master`: a
/// permanent entry in the master bridge's database. `bridge fdb add … static`
/// is `.state = NUD.REACHABLE | NUD.NOARP`.
pub const FdbSpec = struct {
    /// Port the entry is attached to (`ndm_ifindex`).
    ifindex: u32,
    /// `NDA_LLADDR` — the MAC, 6 bytes for Ethernet.
    lladdr: []const u8,
    /// `NDA_DST` — VXLAN remote IP (4 or 16 bytes) for an overlay entry.
    dst: ?[]const u8 = null,
    /// `NDA_VLAN` — the VID this entry belongs to.
    vlan: ?u16 = null,
    /// `NDA_PORT` — VXLAN UDP destination port (big-endian on the wire).
    port: ?u16 = null,
    /// `NDA_VNI` — VXLAN network identifier.
    vni: ?u32 = null,
    /// `NDA_MASTER` — pin the entry to a specific bridge.
    master: ?u32 = null,
    /// `ndm_state`, a `NUD.*` bitmask.
    state: u16 = root.NUD.PERMANENT | root.NUD.NOARP,
    /// `ndm_flags`: `NTF.MASTER` (the bridge's FDB, default), `NTF.SELF` (the
    /// device's own), optionally `| NTF.EXT_LEARNED`.
    flags: u8 = root.NTF.MASTER,
    /// `ndm_type` (`RTN.*`); 0 is what iproute2 sends.
    ntype: u8 = 0,
};

/// Kernel-side scoping for an FDB dump. Both filters are applied by the
/// kernel, exactly as `bridge fdb show dev X` / `bridge fdb show br X` do.
pub const FdbFilter = struct {
    /// `ndm_ifindex` — only entries on this port.
    ifindex: ?u32 = null,
    /// `NDA_MASTER` — only entries belonging to this bridge.
    master: ?u32 = null,
};

/// A VLAN (or inclusive VID range) to add to / remove from a bridge port —
/// `RTM_SETLINK`/`RTM_DELLINK` with `IFLA_AF_SPEC{ IFLA_BRIDGE_VLAN_INFO }`.
///
/// With neither `self` nor `master` set, no `IFLA_BRIDGE_FLAGS` attribute is
/// emitted at all: that is the kernel's default (operate on the port's master
/// bridge) and is exactly what `bridge vlan add dev <port> …` sends.
pub const VlanSpec = struct {
    /// First (or only) VID, 1..4094.
    vid: u16,
    /// Inclusive end of a VID range; null for a single VLAN. Encoded as the
    /// `RANGE_BEGIN`/`RANGE_END` attribute pair.
    vid_end: ?u16 = null,
    /// `BRIDGE_VLAN_INFO_PVID` — untagged ingress lands in this VLAN. A port
    /// has at most one PVID, so this cannot be combined with a range.
    pvid: bool = false,
    /// `BRIDGE_VLAN_INFO_UNTAGGED` — egress untagged for this VLAN.
    untagged: bool = false,
    /// Emit `IFLA_BRIDGE_FLAGS = BRIDGE_FLAGS_SELF` — the device itself is
    /// the bridge (`bridge vlan add dev br0 vid N self`).
    self: bool = false,
    /// Emit `IFLA_BRIDGE_FLAGS = BRIDGE_FLAGS_MASTER` explicitly. Same
    /// semantics as the default, just spelled out on the wire.
    master: bool = false,
};

/// Bridge-port options for `Socket.brportSet` — `RTM_SETLINK` with a nested
/// `IFLA_PROTINFO`. Null leaves the option alone; a change with no option set
/// is rejected with `error.NothingToChange` rather than sent as a no-op.
///
/// Attributes are emitted in the order iproute2's `bridge link set` uses, so
/// the common combinations are byte-identical to it.
pub const BrportChange = struct {
    /// `IFLA_BRPORT_GUARD` — drop received BPDUs.
    guard: ?bool = null,
    /// `IFLA_BRPORT_FAST_LEAVE`.
    fast_leave: ?bool = null,
    /// `IFLA_BRPORT_PROTECT` — root-port block.
    protect: ?bool = null,
    /// `IFLA_BRPORT_MODE` — hairpin.
    hairpin: ?bool = null,
    /// `IFLA_BRPORT_PRIORITY`.
    priority: ?u16 = null,
    /// `IFLA_BRPORT_COST`.
    cost: ?u32 = null,
    /// `IFLA_BRPORT_UNICAST_FLOOD`.
    unicast_flood: ?bool = null,
    /// `IFLA_BRPORT_MCAST_FLOOD`.
    mcast_flood: ?bool = null,
    /// `IFLA_BRPORT_BCAST_FLOOD`.
    bcast_flood: ?bool = null,
    /// `IFLA_BRPORT_LEARNING` — MAC learning on this port.
    learning: ?bool = null,
    /// `IFLA_BRPORT_STATE` — `BR_STATE.*`.
    state: ?u8 = null,
    /// `IFLA_BRPORT_NEIGH_SUPPRESS`.
    neigh_suppress: ?bool = null,
    /// `IFLA_BRPORT_ISOLATED`.
    isolated: ?bool = null,
};

// ── small encoding helpers ──────────────────────────────────────────────────

fn attrChecked(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    data: []const u8,
) std.mem.Allocator.Error!void {
    std.debug.assert(data.len <= std.math.maxInt(u16) - codec.attr_header_len);
    codec.appendAttr(gpa, list, attr_type, data) catch |err| switch (err) {
        error.AttrTooLong => unreachable, // every caller here is <= 32 bytes
        error.OutOfMemory => return error.OutOfMemory,
    };
}

fn attrStringChecked(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    s: []const u8,
) std.mem.Allocator.Error!void {
    std.debug.assert(s.len < std.math.maxInt(u16) - codec.attr_header_len);
    codec.appendAttrString(gpa, list, attr_type, s) catch |err| switch (err) {
        error.AttrTooLong => unreachable,
        error.OutOfMemory => return error.OutOfMemory,
    };
}

fn attrBool(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    on: bool,
) std.mem.Allocator.Error!void {
    return codec.appendAttrU8(gpa, list, attr_type, @intFromBool(on));
}

/// struct ifinfomsg with an explicit family byte (AF_BRIDGE for every
/// port-scoped request here), which the plain link builders never need.
fn appendIfinfomsg(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    family: u8,
    ifindex: u32,
    flags: u32,
    change: u32,
) std.mem.Allocator.Error!void {
    var fixed: [root.ifinfomsg_len]u8 = @splat(0);
    fixed[0] = family;
    std.mem.writeInt(i32, fixed[4..8], @bitCast(ifindex), native_endian);
    std.mem.writeInt(u32, fixed[8..12], flags, native_endian);
    std.mem.writeInt(u32, fixed[12..16], change, native_endian);
    try codec.appendPadded(gpa, list, &fixed);
}

fn checkName(s: []const u8) BuildError!void {
    if (s.len == 0 or s.len >= root.ifnamsiz) return error.InvalidName;
}

fn checkVid(vid: u16) BuildError!void {
    if (vid < vlan_id_min or vid > vlan_id_max) return error.InvalidVlanId;
}

// ── builders ────────────────────────────────────────────────────────────────

/// Build the `RTM_NEWLINK` request that creates a bridge device.
///
/// Wire layout (verified byte-for-byte against
/// `ip link add name br0 type bridge forward_delay 100 ageing_time 20000
/// stp_state 1 priority 4096 vlan_filtering 1`):
/// nlmsghdr | ifinfomsg{index 0} | IFLA_IFNAME | [IFLA_MTU] | [IFLA_ADDRESS] |
/// IFLA_LINKINFO{ IFLA_INFO_KIND "bridge", [IFLA_INFO_DATA{ IFLA_BR_* }] }.
pub fn buildBridgeAddRequest(
    gpa: std.mem.Allocator,
    seq: u32,
    flags: u16,
    spec: BridgeSpec,
) BuildError![]u8 {
    try checkName(spec.name);
    if (spec.mac) |m| if (m.len == 0 or m.len > 32) return error.InvalidLinkAddress;

    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(gpa, &list, root.RTM_NEWLINK, flags, seq, 0);
    const up_bit: u32 = if (spec.up) root.IFF.UP else 0;
    try appendIfinfomsg(gpa, &list, root.AF.UNSPEC, 0, up_bit, up_bit);

    try attrStringChecked(gpa, &list, root.IFLA_IFNAME, spec.name);
    if (spec.mtu) |m| try codec.appendAttrU32(gpa, &list, root.IFLA_MTU, m);
    if (spec.mac) |m| try attrChecked(gpa, &list, root.IFLA_ADDRESS, m);

    const linkinfo = try codec.nestBegin(gpa, &list, root.IFLA_LINKINFO);
    try attrStringChecked(gpa, &list, root.IFLA_INFO.KIND, "bridge");
    if (hasBridgeOptions(spec)) {
        const data = try codec.nestBegin(gpa, &list, root.IFLA_INFO.DATA);
        if (spec.forward_delay) |v| try codec.appendAttrU32(gpa, &list, IFLA_BR.FORWARD_DELAY, v);
        if (spec.ageing_time) |v| try codec.appendAttrU32(gpa, &list, IFLA_BR.AGEING_TIME, v);
        if (spec.stp_state) |v| try codec.appendAttrU32(gpa, &list, IFLA_BR.STP_STATE, v);
        if (spec.priority) |v| try codec.appendAttrU16(gpa, &list, IFLA_BR.PRIORITY, v);
        if (spec.vlan_filtering) |v| try codec.appendAttrU8(gpa, &list, IFLA_BR.VLAN_FILTERING, @intFromBool(v));
        // The kernel reads IFLA_BR_VLAN_PROTOCOL as a network-order ethertype.
        if (spec.vlan_protocol) |v| {
            var raw: [2]u8 = undefined;
            std.mem.writeInt(u16, &raw, v, .big);
            try attrChecked(gpa, &list, IFLA_BR.VLAN_PROTOCOL, &raw);
        }
        codec.nestEnd(&list, data);
    }
    codec.nestEnd(&list, linkinfo);

    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

fn hasBridgeOptions(spec: BridgeSpec) bool {
    return spec.forward_delay != null or spec.ageing_time != null or
        spec.stp_state != null or spec.priority != null or
        spec.vlan_filtering != null or spec.vlan_protocol != null;
}

/// Build an `RTM_NEWNEIGH`/`RTM_DELNEIGH` FDB request.
///
/// Wire layout (verified against `bridge fdb add 02:00:00:00:00:01 dev veth0
/// master static vlan 10` and its `bridge fdb del` counterpart):
/// nlmsghdr | ndmsg{AF_BRIDGE, ifindex, state, flags, type} | NDA_LLADDR |
/// [NDA_DST] | [NDA_VLAN] | [NDA_PORT] | [NDA_VNI] | [NDA_MASTER]
/// — iproute2's `fdb_modify` attribute order.
pub fn buildFdbRequest(
    gpa: std.mem.Allocator,
    seq: u32,
    msg_type: u16,
    flags: u16,
    spec: FdbSpec,
) BuildError![]u8 {
    if (spec.lladdr.len == 0 or spec.lladdr.len > 32) return error.InvalidLinkAddress;
    if (spec.dst) |d| if (d.len != 4 and d.len != 16) return error.InvalidAddressLength;
    if (spec.vlan) |v| try checkVid(v);

    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(gpa, &list, msg_type, flags, seq, 0);

    var fixed: [root.ndmsg_len]u8 = @splat(0);
    fixed[0] = root.AF.BRIDGE;
    std.mem.writeInt(i32, fixed[4..8], @bitCast(spec.ifindex), native_endian);
    std.mem.writeInt(u16, fixed[8..10], spec.state, native_endian);
    fixed[10] = spec.flags;
    fixed[11] = spec.ntype;
    try codec.appendPadded(gpa, &list, &fixed);

    try attrChecked(gpa, &list, root.NDA.LLADDR, spec.lladdr);
    if (spec.dst) |d| try attrChecked(gpa, &list, root.NDA.DST, d);
    if (spec.vlan) |v| try codec.appendAttrU16(gpa, &list, root.NDA.VLAN, v);
    if (spec.port) |p| {
        // NDA_PORT is the VXLAN UDP port — network order, like iproute2.
        var raw: [2]u8 = undefined;
        std.mem.writeInt(u16, &raw, p, .big);
        try attrChecked(gpa, &list, root.NDA.PORT, &raw);
    }
    if (spec.vni) |v| try codec.appendAttrU32(gpa, &list, root.NDA.VNI, v);
    if (spec.master) |m| try codec.appendAttrU32(gpa, &list, root.NDA.MASTER, m);

    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

/// Build the `RTM_GETNEIGH` FDB dump request.
///
/// Wire layout (verified against `bridge fdb show`, `bridge fdb show dev
/// veth0` and `bridge fdb show br br0`): nlmsghdr{REQUEST|DUMP} |
/// ndmsg{AF_BRIDGE, [ifindex]} | [NDA_MASTER].
pub fn buildFdbDumpRequest(
    gpa: std.mem.Allocator,
    seq: u32,
    filter: FdbFilter,
) BuildError![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(
        gpa,
        &list,
        root.RTM_GETNEIGH,
        codec.NLM_F_REQUEST | codec.NLM_F_DUMP,
        seq,
        0,
    );

    var fixed: [root.ndmsg_len]u8 = @splat(0);
    fixed[0] = root.AF.BRIDGE;
    if (filter.ifindex) |i| std.mem.writeInt(i32, fixed[4..8], @bitCast(i), native_endian);
    try codec.appendPadded(gpa, &list, &fixed);
    if (filter.master) |m| try codec.appendAttrU32(gpa, &list, root.NDA.MASTER, m);

    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

/// Build the `RTM_SETLINK`/`RTM_DELLINK` request that adds or removes a VLAN
/// (or an inclusive VID range) on a bridge port.
///
/// Wire layout (verified against `bridge vlan add dev veth0 vid 10 pvid
/// untagged`, `bridge vlan add dev veth0 vid 100-200`, `bridge vlan add dev
/// br0 vid 20 self` and the matching `bridge vlan del`):
/// nlmsghdr | ifinfomsg{AF_BRIDGE, ifindex} |
/// IFLA_AF_SPEC{ [IFLA_BRIDGE_FLAGS], IFLA_BRIDGE_VLAN_INFO… }.
pub fn buildVlanRequest(
    gpa: std.mem.Allocator,
    seq: u32,
    msg_type: u16,
    ifindex: u32,
    spec: VlanSpec,
) BuildError![]u8 {
    try checkVid(spec.vid);
    if (spec.vid_end) |end| {
        try checkVid(end);
        if (end < spec.vid) return error.InvalidVlanRange;
        // A port has exactly one PVID, so a range can never be one.
        if (spec.pvid and end != spec.vid) return error.InvalidVlanRange;
    }
    if (spec.self and spec.master) return error.InvalidVlanRange;

    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(
        gpa,
        &list,
        msg_type,
        codec.NLM_F_REQUEST | codec.NLM_F_ACK,
        seq,
        0,
    );
    try appendIfinfomsg(gpa, &list, root.AF.BRIDGE, ifindex, 0, 0);

    const af_spec = try codec.nestBegin(gpa, &list, IFLA_AF_SPEC);
    if (spec.self) {
        try codec.appendAttrU16(gpa, &list, IFLA_BRIDGE.FLAGS, BRIDGE_FLAGS.SELF);
    } else if (spec.master) {
        try codec.appendAttrU16(gpa, &list, IFLA_BRIDGE.FLAGS, BRIDGE_FLAGS.MASTER);
    }

    var base: u16 = 0;
    if (spec.pvid) base |= BRIDGE_VLAN_INFO.PVID;
    if (spec.untagged) base |= BRIDGE_VLAN_INFO.UNTAGGED;

    const end = spec.vid_end orelse spec.vid;
    if (end == spec.vid) {
        try appendVlanInfo(gpa, &list, base, spec.vid);
    } else {
        try appendVlanInfo(gpa, &list, base | BRIDGE_VLAN_INFO.RANGE_BEGIN, spec.vid);
        try appendVlanInfo(gpa, &list, base | BRIDGE_VLAN_INFO.RANGE_END, end);
    }
    codec.nestEnd(&list, af_spec);

    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

fn appendVlanInfo(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    flags: u16,
    vid: u16,
) std.mem.Allocator.Error!void {
    var raw: [bridge_vlan_info_len]u8 = undefined;
    std.mem.writeInt(u16, raw[0..2], flags, native_endian);
    std.mem.writeInt(u16, raw[2..4], vid, native_endian);
    try attrChecked(gpa, list, IFLA_BRIDGE.VLAN_INFO, &raw);
}

/// Build the `RTM_GETLINK` request that dumps per-port VLAN configuration.
///
/// Wire layout (verified against `bridge vlan show`):
/// nlmsghdr{REQUEST|DUMP} | ifinfomsg{AF_BRIDGE} |
/// IFLA_EXT_MASK = RTEXT_FILTER_BRVLAN.
pub fn buildVlanDumpRequest(
    gpa: std.mem.Allocator,
    seq: u32,
    ext_mask: u32,
) BuildError![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(
        gpa,
        &list,
        root.RTM_GETLINK,
        codec.NLM_F_REQUEST | codec.NLM_F_DUMP,
        seq,
        0,
    );
    try appendIfinfomsg(gpa, &list, root.AF.BRIDGE, 0, 0, 0);
    try codec.appendAttrU32(gpa, &list, IFLA_EXT_MASK, ext_mask);
    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

/// Build the `RTM_GETLINK` request that dumps bridge-port state.
///
/// Wire layout (verified against `bridge link show`): nlmsghdr{REQUEST|DUMP} |
/// ifinfomsg{AF_BRIDGE} — nothing else. The family byte is what makes the
/// kernel attach `IFLA_PROTINFO`: a plain AF_UNSPEC `RTM_GETLINK` dump (what
/// `ip link show` sends) reports no bridge-port block at all.
pub fn buildBrportDumpRequest(gpa: std.mem.Allocator, seq: u32) BuildError![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(
        gpa,
        &list,
        root.RTM_GETLINK,
        codec.NLM_F_REQUEST | codec.NLM_F_DUMP,
        seq,
        0,
    );
    try appendIfinfomsg(gpa, &list, root.AF.BRIDGE, 0, 0, 0);
    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

/// Build the `RTM_SETLINK` request that changes bridge-port options.
///
/// Wire layout (verified against `bridge link set dev veth0 state 3 learning
/// off flood off isolated on`): nlmsghdr | ifinfomsg{AF_BRIDGE, ifindex} |
/// IFLA_PROTINFO|NLA_F_NESTED{ IFLA_BRPORT_* }. Unlike the other rtnetlink
/// nests, iproute2 *does* set `NLA_F_NESTED` on `IFLA_PROTINFO` here, and the
/// bytes below match it.
pub fn buildBrportRequest(
    gpa: std.mem.Allocator,
    seq: u32,
    ifindex: u32,
    change: BrportChange,
) BuildError![]u8 {
    if (!hasBrportOptions(change)) return error.NothingToChange;

    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(
        gpa,
        &list,
        RTM_SETLINK,
        codec.NLM_F_REQUEST | codec.NLM_F_ACK,
        seq,
        0,
    );
    try appendIfinfomsg(gpa, &list, root.AF.BRIDGE, ifindex, 0, 0);

    const protinfo = try codec.nestBegin(gpa, &list, IFLA_PROTINFO | codec.NLA_F_NESTED);
    if (change.guard) |v| try attrBool(gpa, &list, IFLA_BRPORT.GUARD, v);
    if (change.fast_leave) |v| try attrBool(gpa, &list, IFLA_BRPORT.FAST_LEAVE, v);
    if (change.protect) |v| try attrBool(gpa, &list, IFLA_BRPORT.PROTECT, v);
    if (change.hairpin) |v| try attrBool(gpa, &list, IFLA_BRPORT.MODE, v);
    if (change.priority) |v| try codec.appendAttrU16(gpa, &list, IFLA_BRPORT.PRIORITY, v);
    if (change.cost) |v| try codec.appendAttrU32(gpa, &list, IFLA_BRPORT.COST, v);
    if (change.unicast_flood) |v| try attrBool(gpa, &list, IFLA_BRPORT.UNICAST_FLOOD, v);
    if (change.mcast_flood) |v| try attrBool(gpa, &list, IFLA_BRPORT.MCAST_FLOOD, v);
    if (change.bcast_flood) |v| try attrBool(gpa, &list, IFLA_BRPORT.BCAST_FLOOD, v);
    if (change.learning) |v| try attrBool(gpa, &list, IFLA_BRPORT.LEARNING, v);
    if (change.state) |v| try codec.appendAttrU8(gpa, &list, IFLA_BRPORT.STATE, v);
    if (change.neigh_suppress) |v| try attrBool(gpa, &list, IFLA_BRPORT.NEIGH_SUPPRESS, v);
    if (change.isolated) |v| try attrBool(gpa, &list, IFLA_BRPORT.ISOLATED, v);
    codec.nestEnd(&list, protinfo);

    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

fn hasBrportOptions(c: BrportChange) bool {
    inline for (@typeInfo(BrportChange).@"struct".fields) |f| {
        if (@field(c, f.name) != null) return true;
    }
    return false;
}

// ── parsers ─────────────────────────────────────────────────────────────────

/// Parse one `RTM_NEWNEIGH` payload as an FDB entry (struct ndmsg + NDA_*).
/// Returns null for a non-AF_BRIDGE entry — an ordinary ARP/NDP neighbour that
/// happened to land in the same buffer belongs to `parseNeighbor` instead.
pub fn parseFdb(payload: []const u8) codec.Error!?FdbEntry {
    if (payload.len < root.ndmsg_len) return error.Truncated;
    if (payload[0] != root.AF.BRIDGE) return null;

    var e: FdbEntry = .{
        // struct ndmsg: u8 family, u8 pad1, u16 pad2, i32 ifindex,
        // u16 state, u8 flags, u8 type.
        .ifindex = @bitCast(std.mem.readInt(i32, payload[4..8], native_endian)),
        .state = std.mem.readInt(u16, payload[8..10], native_endian),
        .flags = payload[10],
        .ntype = payload[11],
    };

    var it: codec.AttrIterator = .{ .buf = payload[root.ndmsg_len..] };
    while (try it.next()) |a| switch (a.type) {
        root.NDA.LLADDR => if (a.data.len == 6) {
            @memcpy(&e.lladdr, a.data);
            e.lladdr_len = 6;
        },
        root.NDA.DST => if (a.data.len == 4 or a.data.len == 16) {
            @memcpy(e.dst[0..a.data.len], a.data);
            e.dst_len = @intCast(a.data.len);
        },
        root.NDA.VLAN => e.vlan = try a.asU16(),
        root.NDA.MASTER => e.master = try a.asU32(),
        root.NDA.VNI => e.vni = try a.asU32(),
        else => {},
    };
    return e;
}

/// Decode the `IFLA_AF_SPEC` VLAN list of one `RTM_NEWLINK` dump message,
/// appending every entry to `out`.
///
/// `RANGE_BEGIN`/`RANGE_END` pairs collapse into one `VlanEntry` spanning the
/// range. Hostile input is handled defensively rather than fatally: a
/// `RANGE_BEGIN` never closed by a `RANGE_END` (or a stray `RANGE_END`) is
/// emitted as a single-VID entry, so a malicious stream can produce odd data
/// but never a panic, an unbounded loop or an over-read.
pub fn parseVlans(
    gpa: std.mem.Allocator,
    out: *std.ArrayList(VlanEntry),
    payload: []const u8,
) (codec.Error || std.mem.Allocator.Error)!void {
    if (payload.len < root.ifinfomsg_len) return error.Truncated;
    if (payload[0] != root.AF.BRIDGE) return;
    const ifindex: u32 = @bitCast(std.mem.readInt(i32, payload[4..8], native_endian));

    var it: codec.AttrIterator = .{ .buf = payload[root.ifinfomsg_len..] };
    while (try it.next()) |a| {
        if (a.type != IFLA_AF_SPEC) continue;
        var nested = a.nested();
        var pending: ?VlanInfo = null;
        while (try nested.next()) |sub| {
            if (sub.type != IFLA_BRIDGE.VLAN_INFO) continue;
            const info = try VlanInfo.parse(sub.data);
            if (pending) |begin| {
                if (info.flags & BRIDGE_VLAN_INFO.RANGE_END != 0 and info.vid >= begin.vid) {
                    try out.append(gpa, .{
                        .ifindex = ifindex,
                        .vid = begin.vid,
                        .vid_end = info.vid,
                        .flags = maskRange(begin.flags),
                    });
                    pending = null;
                    continue;
                }
                // Unterminated range: keep the begin VID as a lone entry.
                try out.append(gpa, .{
                    .ifindex = ifindex,
                    .vid = begin.vid,
                    .vid_end = begin.vid,
                    .flags = maskRange(begin.flags),
                });
                pending = null;
            }
            if (info.flags & BRIDGE_VLAN_INFO.RANGE_BEGIN != 0) {
                pending = info;
                continue;
            }
            try out.append(gpa, .{
                .ifindex = ifindex,
                .vid = info.vid,
                .vid_end = info.vid,
                .flags = maskRange(info.flags),
            });
        }
        if (pending) |begin| try out.append(gpa, .{
            .ifindex = ifindex,
            .vid = begin.vid,
            .vid_end = begin.vid,
            .flags = maskRange(begin.flags),
        });
    }
}

fn maskRange(flags: u16) u16 {
    return flags & ~@as(u16, BRIDGE_VLAN_INFO.RANGE_BEGIN | BRIDGE_VLAN_INFO.RANGE_END);
}

/// `struct bridge_vlan_info { __u16 flags; __u16 vid; }`.
pub const VlanInfo = struct {
    flags: u16,
    vid: u16,

    pub fn parse(data: []const u8) codec.Error!VlanInfo {
        if (data.len != bridge_vlan_info_len) return error.BadLength;
        return .{
            .flags = std.mem.readInt(u16, data[0..2], native_endian),
            .vid = std.mem.readInt(u16, data[2..4], native_endian),
        };
    }
};

/// Decode the bridge-port state of one `RTM_NEWLINK` payload — `IFLA_MASTER`
/// plus whatever `IFLA_PROTINFO` carries. Returns null when the message
/// describes an interface that is not a bridge port (no `IFLA_PROTINFO`).
pub fn parseBrport(payload: []const u8) codec.Error!?BrportInfo {
    if (payload.len < root.ifinfomsg_len) return error.Truncated;
    var info: BrportInfo = .{
        .ifindex = @bitCast(std.mem.readInt(i32, payload[4..8], native_endian)),
    };
    var has_protinfo = false;

    var it: codec.AttrIterator = .{ .buf = payload[root.ifinfomsg_len..] };
    while (try it.next()) |a| switch (a.type) {
        IFLA_MASTER => info.master = try a.asU32(),
        IFLA_PROTINFO => {
            has_protinfo = true;
            var nested = a.nested();
            while (try nested.next()) |sub| switch (sub.type) {
                IFLA_BRPORT.STATE => info.state = try sub.asU8(),
                IFLA_BRPORT.PRIORITY => info.priority = try sub.asU16(),
                IFLA_BRPORT.COST => info.cost = try sub.asU32(),
                IFLA_BRPORT.MODE => info.hairpin = (try sub.asU8()) != 0,
                IFLA_BRPORT.LEARNING => info.learning = (try sub.asU8()) != 0,
                IFLA_BRPORT.UNICAST_FLOOD => info.unicast_flood = (try sub.asU8()) != 0,
                IFLA_BRPORT.MCAST_FLOOD => info.mcast_flood = (try sub.asU8()) != 0,
                IFLA_BRPORT.BCAST_FLOOD => info.bcast_flood = (try sub.asU8()) != 0,
                IFLA_BRPORT.NEIGH_SUPPRESS => info.neigh_suppress = (try sub.asU8()) != 0,
                IFLA_BRPORT.ISOLATED => info.isolated = (try sub.asU8()) != 0,
                else => {},
            };
        },
        else => {},
    };
    if (!has_protinfo) return null;
    return info;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

// Golden request bytes below were captured from real iproute2 inside a
// throw-away namespace, by tapping netlink itself:
//
//   unshare -rn bash -c 'ip link add nlmon0 type nlmon; ip link set nlmon0 up;
//                        tcpdump -i nlmon0 -Z root -w cap.pcap -U -s0 & …'
//
// which yields the exact datagrams `ip`/`bridge` hand to the kernel (a
// DLT_NETLINK pcap: a 16-byte Linux cooked header, then the raw nlmsghdr).
// The equivalent, slightly less direct capture is
//   unshare -rn strace -f -e trace=sendmsg -xx -s 400 ip …
// which decodes rather than dumps the buffer. Each test cites its command.
// Byte layouts were cross-checked field-by-field against the kernel UAPI
// headers (linux/if_link.h, linux/if_bridge.h, linux/neighbour.h).

fn expectRequestBytes(actual: []const u8, expected: []const u8) !void {
    try testing.expectEqual(expected.len, actual.len);
    try testing.expectEqualSlices(u8, expected, actual);
    try testing.expectEqual(
        @as(u32, @intCast(actual.len)),
        std.mem.readInt(u32, actual[0..4], native_endian),
    );
}

test "golden: bridge create == `ip link add name br0 type bridge forward_delay 100 ageing_time 20000 stp_state 1 priority 4096 vlan_filtering 1`" {
    if (native_endian != .little) return error.SkipZigTest; // golden bytes are LE
    const req = try buildBridgeAddRequest(testing.allocator, 1, (root.Create{}).flags(), .{
        .name = "br0",
        .forward_delay = 100,
        .ageing_time = 20000,
        .stp_state = 1,
        .priority = 4096,
        .vlan_filtering = true,
    });
    defer testing.allocator.free(req);
    try expectRequestBytes(req, &.{
        0x64, 0x00, 0x00, 0x00, // nlmsg_len = 100
        0x10, 0x00, // RTM_NEWLINK (16)
        0x05, 0x06, // REQUEST|ACK|EXCL|CREATE
        0x01, 0x00, 0x00, 0x00, // nlmsg_seq
        0x00, 0x00, 0x00, 0x00, // nlmsg_pid
        // ifinfomsg: AF_UNSPEC, ARPHRD_NETROM, index 0, flags 0, change 0
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x03, 0x00, 0x62, 0x72, 0x30, 0x00, // IFLA_IFNAME "br0"
        0x3c, 0x00, 0x12, 0x00, // IFLA_LINKINFO, len 60
        0x0b, 0x00, 0x01, 0x00, // IFLA_INFO_KIND, len 11
        0x62, 0x72, 0x69, 0x64, 0x67, 0x65, 0x00, 0x00, // "bridge\0" + pad
        0x2c, 0x00, 0x02, 0x00, // IFLA_INFO_DATA, len 44
        0x08, 0x00, 0x01, 0x00, 0x64, 0x00, 0x00, 0x00, // IFLA_BR_FORWARD_DELAY = 100
        0x08, 0x00, 0x04, 0x00, 0x20, 0x4e, 0x00, 0x00, // IFLA_BR_AGEING_TIME = 20000
        0x08, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, // IFLA_BR_STP_STATE = 1
        0x06, 0x00, 0x06, 0x00, 0x00, 0x10, 0x00, 0x00, // IFLA_BR_PRIORITY = 4096 (u16)
        0x05, 0x00, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, // IFLA_BR_VLAN_FILTERING = 1 (u8)
    });
}

test "golden: minimal bridge create == `ip link add name br0 type bridge vlan_filtering 1`" {
    if (native_endian != .little) return error.SkipZigTest;
    const req = try buildBridgeAddRequest(testing.allocator, 1, (root.Create{}).flags(), .{
        .name = "br0",
        .vlan_filtering = true,
    });
    defer testing.allocator.free(req);
    try expectRequestBytes(req, &.{
        0x44, 0x00, 0x00, 0x00, // nlmsg_len = 68
        0x10, 0x00, 0x05, 0x06,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x03, 0x00, 0x62, 0x72, 0x30, 0x00, // IFLA_IFNAME "br0"
        0x1c, 0x00, 0x12, 0x00, // IFLA_LINKINFO, len 28
        0x0b, 0x00, 0x01, 0x00,
        0x62, 0x72, 0x69, 0x64,
        0x67, 0x65, 0x00, 0x00,
        0x0c, 0x00, 0x02, 0x00, // IFLA_INFO_DATA, len 12
        0x05, 0x00, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, // IFLA_BR_VLAN_FILTERING = 1
    });

    // With no IFLA_BR_* option at all, IFLA_INFO_DATA is omitted entirely —
    // the same message `ip link add name br0 type bridge` sends.
    const bare = try buildBridgeAddRequest(testing.allocator, 1, (root.Create{}).flags(), .{
        .name = "br0",
    });
    defer testing.allocator.free(bare);
    try testing.expectEqual(@as(usize, 56), bare.len);
}

test "golden: FDB add == `bridge fdb add 02:00:00:00:00:01 dev veth0 master static vlan 10`" {
    if (native_endian != .little) return error.SkipZigTest;
    const mac = [_]u8{ 0x02, 0, 0, 0, 0, 0x01 };
    const req = try buildFdbRequest(
        testing.allocator,
        1,
        root.RTM_NEWNEIGH,
        (root.Create{}).flags(),
        .{
            .ifindex = 4,
            .lladdr = &mac,
            .vlan = 10,
            // `static` = NUD_REACHABLE|NUD_NOARP in iproute2's fdb parser.
            .state = root.NUD.REACHABLE | root.NUD.NOARP,
            .flags = root.NTF.MASTER,
        },
    );
    defer testing.allocator.free(req);
    try expectRequestBytes(req, &.{
        0x30, 0x00, 0x00, 0x00, // nlmsg_len = 48
        0x1c, 0x00, // RTM_NEWNEIGH (28)
        0x05, 0x06, // REQUEST|ACK|EXCL|CREATE
        0x01, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x07, 0x00, 0x00, 0x00, // ndmsg: AF_BRIDGE, pad
        0x04, 0x00, 0x00, 0x00, // ndm_ifindex = 4
        0x42, 0x00, // ndm_state = NUD_REACHABLE|NUD_NOARP
        0x04, // ndm_flags = NTF_MASTER
        0x00, // ndm_type = RTN_UNSPEC
        0x0a, 0x00, 0x02, 0x00, // NDA_LLADDR, len 10
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, // MAC + pad
        0x06, 0x00, 0x05, 0x00, 0x0a, 0x00, 0x00, 0x00, // NDA_VLAN = 10 (u16)
    });
}

test "golden: FDB del == `bridge fdb del 02:00:00:00:00:01 dev veth0 master vlan 10`" {
    if (native_endian != .little) return error.SkipZigTest;
    const mac = [_]u8{ 0x02, 0, 0, 0, 0, 0x01 };
    const req = try buildFdbRequest(
        testing.allocator,
        1,
        root.RTM_DELNEIGH,
        codec.NLM_F_REQUEST | codec.NLM_F_ACK,
        .{ .ifindex = 4, .lladdr = &mac, .vlan = 10 },
    );
    defer testing.allocator.free(req);
    try expectRequestBytes(req, &.{
        0x30, 0x00, 0x00, 0x00,
        0x1d, 0x00, // RTM_DELNEIGH (29)
        0x05, 0x00, // REQUEST|ACK
        0x01, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x07, 0x00,
        0x00, 0x00,
        0x04, 0x00,
        0x00, 0x00,
        0xc0, 0x00, // ndm_state = NUD_PERMANENT|NUD_NOARP (the delete default)
        0x04, 0x00, // NTF_MASTER, RTN_UNSPEC
        0x0a, 0x00,
        0x02, 0x00,
        0x02, 0x00,
        0x00, 0x00,
        0x00, 0x01,
        0x00, 0x00,
        0x06, 0x00,
        0x05, 0x00,
        0x0a, 0x00,
        0x00, 0x00,
    });
}

test "golden: FDB add self == `bridge fdb add 02:00:00:00:00:09 dev veth0 self static`" {
    if (native_endian != .little) return error.SkipZigTest;
    const mac = [_]u8{ 0x02, 0, 0, 0, 0, 0x09 };
    const req = try buildFdbRequest(
        testing.allocator,
        1,
        root.RTM_NEWNEIGH,
        (root.Create{}).flags(),
        .{
            .ifindex = 4,
            .lladdr = &mac,
            .state = root.NUD.REACHABLE | root.NUD.NOARP,
            .flags = root.NTF.SELF,
        },
    );
    defer testing.allocator.free(req);
    try expectRequestBytes(req, &.{
        0x28, 0x00, 0x00, 0x00, // nlmsg_len = 40
        0x1c, 0x00, 0x05, 0x06,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x07, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x42, 0x00, // NUD_REACHABLE|NUD_NOARP
        0x02, 0x00, // NTF_SELF
        0x0a, 0x00,
        0x02, 0x00,
        0x02, 0x00,
        0x00, 0x00,
        0x00, 0x09,
        0x00, 0x00,
    });
}

test "golden: FDB extern_learn == `bridge fdb add 02:00:00:00:00:03 dev veth0 master extern_learn`" {
    if (native_endian != .little) return error.SkipZigTest;
    const mac = [_]u8{ 0x02, 0, 0, 0, 0, 0x03 };
    const req = try buildFdbRequest(
        testing.allocator,
        1,
        root.RTM_NEWNEIGH,
        (root.Create{}).flags(),
        .{
            .ifindex = 4,
            .lladdr = &mac,
            .flags = root.NTF.MASTER | root.NTF.EXT_LEARNED,
        },
    );
    defer testing.allocator.free(req);
    try expectRequestBytes(req, &.{
        0x28, 0x00, 0x00, 0x00,
        0x1c, 0x00, 0x05, 0x06,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x07, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0xc0, 0x00, // NUD_PERMANENT|NUD_NOARP
        0x14, 0x00, // NTF_MASTER|NTF_EXT_LEARNED
        0x0a, 0x00,
        0x02, 0x00,
        0x02, 0x00,
        0x00, 0x00,
        0x00, 0x03,
        0x00, 0x00,
    });
}

test "golden: FDB append == `bridge fdb append 02:00:00:00:00:08 dev veth0 master`" {
    if (native_endian != .little) return error.SkipZigTest;
    const mac = [_]u8{ 0x02, 0, 0, 0, 0, 0x08 };
    const req = try buildFdbRequest(
        testing.allocator,
        1,
        root.RTM_NEWNEIGH,
        (root.Create{ .exclusive = false, .append = true }).flags(),
        .{ .ifindex = 4, .lladdr = &mac },
    );
    defer testing.allocator.free(req);
    // nlmsg_flags = REQUEST|ACK|CREATE|APPEND = 0x0c05
    try testing.expectEqual(@as(u16, 0x0c05), std.mem.readInt(u16, req[6..8], native_endian));
    try testing.expectEqual(@as(usize, 40), req.len);
}

test "golden: FDB dumps == `bridge fdb show`, `… dev veth0`, `… br br0`" {
    if (native_endian != .little) return error.SkipZigTest;
    const all = try buildFdbDumpRequest(testing.allocator, 1, .{});
    defer testing.allocator.free(all);
    try expectRequestBytes(all, &.{
        0x1c, 0x00, 0x00, 0x00, // nlmsg_len = 28
        0x1e, 0x00, // RTM_GETNEIGH (30)
        0x01, 0x03, // REQUEST|ROOT|MATCH (= NLM_F_DUMP)
        0x01, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x07, 0x00, 0x00, 0x00, // ndmsg: AF_BRIDGE
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    });

    const per_dev = try buildFdbDumpRequest(testing.allocator, 1, .{ .ifindex = 4 });
    defer testing.allocator.free(per_dev);
    try expectRequestBytes(per_dev, &.{
        0x1c, 0x00, 0x00, 0x00,
        0x1e, 0x00, 0x01, 0x03,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x07, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, // ndm_ifindex = 4
        0x00, 0x00, 0x00, 0x00,
    });

    const per_br = try buildFdbDumpRequest(testing.allocator, 1, .{ .master = 6 });
    defer testing.allocator.free(per_br);
    try expectRequestBytes(per_br, &.{
        0x24, 0x00, 0x00, 0x00, // nlmsg_len = 36
        0x1e, 0x00, 0x01, 0x03,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x07, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x09, 0x00, 0x06, 0x00, 0x00, 0x00, // NDA_MASTER = 6
    });
}

test "golden: VLAN add == `bridge vlan add dev veth0 vid 10 pvid untagged`" {
    if (native_endian != .little) return error.SkipZigTest;
    const req = try buildVlanRequest(testing.allocator, 1, RTM_SETLINK, 4, .{
        .vid = 10,
        .pvid = true,
        .untagged = true,
    });
    defer testing.allocator.free(req);
    try expectRequestBytes(req, &.{
        0x2c, 0x00, 0x00, 0x00, // nlmsg_len = 44
        0x13, 0x00, // RTM_SETLINK (19)
        0x05, 0x00, // REQUEST|ACK
        0x01, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x07, 0x00, 0x00, 0x00, // ifinfomsg: AF_BRIDGE
        0x04, 0x00, 0x00, 0x00, // ifi_index = 4
        0x00, 0x00, 0x00, 0x00, // ifi_flags
        0x00, 0x00, 0x00, 0x00, // ifi_change
        0x0c, 0x00, 0x1a, 0x00, // IFLA_AF_SPEC, len 12
        0x08, 0x00, 0x02, 0x00, // IFLA_BRIDGE_VLAN_INFO, len 8
        0x06, 0x00, // flags = PVID|UNTAGGED
        0x0a, 0x00, // vid = 10
    });
}

test "golden: VLAN untagged only == `bridge vlan add dev veth0 vid 30 untagged`" {
    if (native_endian != .little) return error.SkipZigTest;
    const req = try buildVlanRequest(testing.allocator, 1, RTM_SETLINK, 4, .{
        .vid = 30,
        .untagged = true,
    });
    defer testing.allocator.free(req);
    try expectRequestBytes(req, &.{
        0x2c, 0x00, 0x00, 0x00,
        0x13, 0x00, 0x05, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x07, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x1a, 0x00,
        0x08, 0x00, 0x02, 0x00,
        0x04, 0x00, // flags = UNTAGGED
        0x1e, 0x00, // vid = 30
    });
}

test "golden: VLAN range == `bridge vlan add dev veth0 vid 100-200`" {
    if (native_endian != .little) return error.SkipZigTest;
    const req = try buildVlanRequest(testing.allocator, 1, RTM_SETLINK, 4, .{
        .vid = 100,
        .vid_end = 200,
    });
    defer testing.allocator.free(req);
    try expectRequestBytes(req, &.{
        0x34, 0x00, 0x00, 0x00, // nlmsg_len = 52
        0x13, 0x00, 0x05, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x07, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x1a, 0x00, // IFLA_AF_SPEC, len 20
        0x08, 0x00, 0x02, 0x00, 0x08, 0x00, 0x64, 0x00, // {RANGE_BEGIN, 100}
        0x08, 0x00, 0x02, 0x00, 0x10, 0x00, 0xc8, 0x00, // {RANGE_END, 200}
    });

    // `bridge vlan del dev veth0 vid 100-200` is the same body as RTM_DELLINK.
    const del = try buildVlanRequest(testing.allocator, 1, root.RTM_DELLINK, 4, .{
        .vid = 100,
        .vid_end = 200,
    });
    defer testing.allocator.free(del);
    try testing.expectEqual(root.RTM_DELLINK, std.mem.readInt(u16, del[4..6], native_endian));
    try testing.expectEqualSlices(u8, req[16..], del[16..]);
}

test "golden: VLAN self == `bridge vlan add dev br0 vid 20 self`" {
    if (native_endian != .little) return error.SkipZigTest;
    const req = try buildVlanRequest(testing.allocator, 1, RTM_SETLINK, 6, .{
        .vid = 20,
        .self = true,
    });
    defer testing.allocator.free(req);
    try expectRequestBytes(req, &.{
        0x34, 0x00, 0x00, 0x00, // nlmsg_len = 52
        0x13, 0x00, 0x05, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x07, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x00, 0x00, // ifi_index = 6 (br0)
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x1a, 0x00, // IFLA_AF_SPEC, len 20
        0x06, 0x00, 0x00, 0x00, // IFLA_BRIDGE_FLAGS, len 6
        0x02, 0x00, // BRIDGE_FLAGS_SELF
        0x00, 0x00, // pad
        0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x14, 0x00, // {0, vid 20}
    });

    // `bridge vlan del dev br0 vid 20 self` — identical body, RTM_DELLINK.
    const del = try buildVlanRequest(testing.allocator, 1, root.RTM_DELLINK, 6, .{
        .vid = 20,
        .self = true,
    });
    defer testing.allocator.free(del);
    try testing.expectEqualSlices(u8, req[16..], del[16..]);
}

test "golden: VLAN dump == `bridge vlan show`" {
    if (native_endian != .little) return error.SkipZigTest;
    const req = try buildVlanDumpRequest(testing.allocator, 1, RTEXT_FILTER.BRVLAN);
    defer testing.allocator.free(req);
    try expectRequestBytes(req, &.{
        0x28, 0x00, 0x00, 0x00, // nlmsg_len = 40
        0x12, 0x00, // RTM_GETLINK (18)
        0x01, 0x03, // REQUEST|DUMP
        0x01, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x07, 0x00, 0x00, 0x00, // ifinfomsg: AF_BRIDGE
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x1d, 0x00, // IFLA_EXT_MASK
        0x02, 0x00, 0x00, 0x00, // RTEXT_FILTER_BRVLAN
    });
}

test "golden: brport dump == `bridge link show`" {
    if (native_endian != .little) return error.SkipZigTest;
    const req = try buildBrportDumpRequest(testing.allocator, 1);
    defer testing.allocator.free(req);
    try expectRequestBytes(req, &.{
        0x20, 0x00, 0x00, 0x00, // nlmsg_len = 32
        0x12, 0x00, // RTM_GETLINK (18)
        0x01, 0x03, // REQUEST|DUMP
        0x01, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x07, 0x00, 0x00, 0x00, // ifinfomsg: AF_BRIDGE — this is what makes
        0x00, 0x00, 0x00, 0x00, // the kernel attach IFLA_PROTINFO
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    });
}

test "golden: brport == `bridge link set dev veth0 state 3 learning off flood off isolated on`" {
    if (native_endian != .little) return error.SkipZigTest;
    const req = try buildBrportRequest(testing.allocator, 1, 4, .{
        .state = BR_STATE.FORWARDING,
        .learning = false,
        .unicast_flood = false,
        .isolated = true,
    });
    defer testing.allocator.free(req);
    try expectRequestBytes(req, &.{
        0x44, 0x00, 0x00, 0x00, // nlmsg_len = 68
        0x13, 0x00, // RTM_SETLINK (19)
        0x05, 0x00, // REQUEST|ACK
        0x01, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x07, 0x00, 0x00, 0x00, // ifinfomsg: AF_BRIDGE
        0x04, 0x00, 0x00, 0x00, // ifi_index = 4
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x24, 0x00, 0x0c, 0x80, // IFLA_PROTINFO|NLA_F_NESTED, len 36
        0x05, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, // BRPORT_UNICAST_FLOOD = 0
        0x05, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, // BRPORT_LEARNING = 0
        0x05, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, // BRPORT_STATE = 3
        0x05, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00, // BRPORT_ISOLATED = 1
    });
}

test "golden: brport subset == `bridge link set dev veth0 state 3 learning off`" {
    if (native_endian != .little) return error.SkipZigTest;
    const req = try buildBrportRequest(testing.allocator, 1, 4, .{
        .state = BR_STATE.FORWARDING,
        .learning = false,
    });
    defer testing.allocator.free(req);
    try expectRequestBytes(req, &.{
        0x34, 0x00, 0x00, 0x00, // nlmsg_len = 52
        0x13, 0x00, 0x05, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x07, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x0c, 0x80, // IFLA_PROTINFO|NESTED, len 20
        0x05, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, // BRPORT_LEARNING = 0
        0x05, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, // BRPORT_STATE = 3
    });
}

test "build: validation rejects bad specs before any syscall" {
    const mac = [_]u8{ 0x02, 0, 0, 0, 0, 0x01 };
    try testing.expectError(error.InvalidName, buildBridgeAddRequest(
        testing.allocator,
        1,
        0,
        .{ .name = "" },
    ));
    try testing.expectError(error.InvalidName, buildBridgeAddRequest(
        testing.allocator,
        1,
        0,
        .{ .name = "a-bridge-name-that-is-far-too-long" },
    ));
    try testing.expectError(error.InvalidLinkAddress, buildFdbRequest(
        testing.allocator,
        1,
        root.RTM_NEWNEIGH,
        0,
        .{ .ifindex = 1, .lladdr = &.{} },
    ));
    try testing.expectError(error.InvalidAddressLength, buildFdbRequest(
        testing.allocator,
        1,
        root.RTM_NEWNEIGH,
        0,
        .{ .ifindex = 1, .lladdr = &mac, .dst = &.{ 1, 2, 3 } },
    ));
    try testing.expectError(error.InvalidVlanId, buildFdbRequest(
        testing.allocator,
        1,
        root.RTM_NEWNEIGH,
        0,
        .{ .ifindex = 1, .lladdr = &mac, .vlan = 4095 },
    ));
    // VID 0 and 4095 are reserved; a reversed range and a PVID range are
    // rejected too — none of these ever reach the kernel.
    try testing.expectError(error.InvalidVlanId, buildVlanRequest(
        testing.allocator,
        1,
        RTM_SETLINK,
        1,
        .{ .vid = 0 },
    ));
    try testing.expectError(error.InvalidVlanId, buildVlanRequest(
        testing.allocator,
        1,
        RTM_SETLINK,
        1,
        .{ .vid = 4095 },
    ));
    try testing.expectError(error.InvalidVlanRange, buildVlanRequest(
        testing.allocator,
        1,
        RTM_SETLINK,
        1,
        .{ .vid = 200, .vid_end = 100 },
    ));
    try testing.expectError(error.InvalidVlanRange, buildVlanRequest(
        testing.allocator,
        1,
        RTM_SETLINK,
        1,
        .{ .vid = 100, .vid_end = 200, .pvid = true },
    ));
    try testing.expectError(error.InvalidVlanRange, buildVlanRequest(
        testing.allocator,
        1,
        RTM_SETLINK,
        1,
        .{ .vid = 10, .self = true, .master = true },
    ));
    try testing.expectError(error.NothingToChange, buildBrportRequest(
        testing.allocator,
        1,
        1,
        .{},
    ));
}

test "build: explicit master flag and VXLAN-style FDB attributes" {
    if (native_endian != .little) return error.SkipZigTest;
    const req = try buildVlanRequest(testing.allocator, 1, RTM_SETLINK, 4, .{
        .vid = 10,
        .master = true,
    });
    defer testing.allocator.free(req);
    // IFLA_BRIDGE_FLAGS = BRIDGE_FLAGS_MASTER right after IFLA_AF_SPEC.
    try testing.expectEqualSlices(u8, &.{
        0x14, 0x00, 0x1a, 0x00,
        0x06, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x02, 0x00,
        0x00, 0x00, 0x0a, 0x00,
    }, req[32..]);

    // A VXLAN remote: NDA_LLADDR, NDA_DST, NDA_VLAN, NDA_PORT (big-endian),
    // NDA_VNI, NDA_MASTER — iproute2's `fdb_modify` order.
    const mac = [_]u8{ 0x02, 0, 0, 0, 0, 0x01 };
    const vx = try buildFdbRequest(testing.allocator, 1, root.RTM_NEWNEIGH, 0, .{
        .ifindex = 9,
        .lladdr = &mac,
        .dst = &.{ 192, 0, 2, 1 },
        .vlan = 10,
        .port = 4789,
        .vni = 100,
        .master = 6,
    });
    defer testing.allocator.free(vx);
    try testing.expectEqualSlices(u8, &.{
        0x0a, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, // NDA_LLADDR
        0x08, 0x00, 0x01, 0x00, 192, 0, 2, 1, // NDA_DST
        0x06, 0x00, 0x05, 0x00, 0x0a, 0x00, 0x00, 0x00, // NDA_VLAN = 10
        0x06, 0x00, 0x06, 0x00, 0x12, 0xb5, 0x00, 0x00, // NDA_PORT = 4789 (be16)
        0x08, 0x00, 0x07, 0x00, 0x64, 0x00, 0x00, 0x00, // NDA_VNI = 100
        0x08, 0x00, 0x09, 0x00, 0x06, 0x00, 0x00, 0x00, // NDA_MASTER = 6
    }, vx[28..]);
}

test "build: 802.1ad bridge writes IFLA_BR_VLAN_PROTOCOL big-endian" {
    if (native_endian != .little) return error.SkipZigTest;
    const req = try buildBridgeAddRequest(testing.allocator, 1, (root.Create{}).flags(), .{
        .name = "br0",
        .vlan_filtering = true,
        .vlan_protocol = 0x88a8,
    });
    defer testing.allocator.free(req);
    // …IFLA_BR_VLAN_FILTERING then IFLA_BR_VLAN_PROTOCOL (0x88a8 as 88 a8).
    try testing.expectEqualSlices(u8, &.{
        0x05, 0x00, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x08, 0x00, 0x88, 0xa8, 0x00, 0x00,
    }, req[req.len - 16 ..]);
}

// ── decoder tests (canned kernel replies) ───────────────────────────────────

test "parseFdb: real `bridge fdb show` reply entry" {
    if (native_endian != .little) return error.SkipZigTest;
    // Captured RTM_NEWNEIGH payload (nlmsghdr stripped) from a live
    // `bridge fdb show` dump: a learned VLAN-200 entry on port 4 of bridge 5.
    const payload = [_]u8{
        0x07, 0x00, 0x00, 0x00, // AF_BRIDGE
        0x04, 0x00, 0x00, 0x00, // ndm_ifindex = 4
        0x80, 0x00, // NUD_PERMANENT
        0x00, 0x00, // ndm_flags = 0, ndm_type = 0
        0x0a, 0x00, 0x02, 0x00, 0xfe, 0xbf, 0xc2, 0x1d, 0x1f, 0x8e, 0x00, 0x00, // NDA_LLADDR
        0x08, 0x00, 0x09, 0x00, 0x05, 0x00, 0x00, 0x00, // NDA_MASTER = 5
        0x08, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, // NDA_FLAGS_EXT = 0
        0x14, 0x00, 0x03, 0x00, // NDA_CACHEINFO, len 20
        0x00, 0x00, 0x00, 0x00,
        0xc5, 0x01, 0x00, 0x00,
        0xc5, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x05, 0x00, 0xc8, 0x00, 0x00, 0x00, // NDA_VLAN = 200
    };
    const e = (try parseFdb(&payload)).?;
    try testing.expectEqual(@as(u32, 4), e.ifindex);
    try testing.expectEqual(root.NUD.PERMANENT, e.state);
    try testing.expect(e.isPermanent());
    try testing.expect(!e.isSelf());
    try testing.expectEqualSlices(
        u8,
        &.{ 0xfe, 0xbf, 0xc2, 0x1d, 0x1f, 0x8e },
        e.lladdrBytes(),
    );
    try testing.expectEqual(@as(?u32, 5), e.master);
    try testing.expectEqual(@as(?u16, 200), e.vlan);
    try testing.expectEqual(@as(u8, 0), e.dst_len);
}

test "parseFdb: NTF_SELF entry, and non-bridge families are skipped" {
    if (native_endian != .little) return error.SkipZigTest;
    const self_entry = [_]u8{
        0x07, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x80, 0x00, 0x02, 0x00, // NUD_PERMANENT, NTF_SELF
        0x0a, 0x00, 0x02, 0x00,
        0x33, 0x33, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00,
    };
    const e = (try parseFdb(&self_entry)).?;
    try testing.expect(e.isSelf());
    try testing.expect(!e.isMaster());
    try testing.expectEqual(@as(?u16, null), e.vlan);

    // An AF_INET ARP entry in the same buffer is not ours.
    var arp = self_entry;
    arp[0] = root.AF.INET;
    try testing.expectEqual(@as(?FdbEntry, null), try parseFdb(&arp));

    // Truncated ndmsg.
    try testing.expectError(error.Truncated, parseFdb(self_entry[0..8]));
}

test "parseFdb: VXLAN-style entry with NDA_DST and NDA_VNI" {
    if (native_endian != .little) return error.SkipZigTest;
    const payload = [_]u8{
        0x07, 0x00, 0x00, 0x00,
        0x09, 0x00, 0x00, 0x00,
        0xc0, 0x00, 0x12, 0x00, // NUD_PERMANENT|NOARP, NTF_SELF|NTF_EXT_LEARNED
        0x0a, 0x00, 0x02, 0x00,
        0x02, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00,
        0x08, 0x00, 0x01, 0x00, 192, 0, 2, 1, // NDA_DST
        0x08, 0x00, 0x07, 0x00, 0x64, 0x00, 0x00, 0x00, // NDA_VNI = 100
    };
    const e = (try parseFdb(&payload)).?;
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, e.dstBytes());
    try testing.expectEqual(@as(?u32, 100), e.vni);
    try testing.expect(e.isExternLearned());
    try testing.expect(e.isSelf());
}

test "parseVlans: real `bridge vlan show` reply, single VIDs" {
    if (native_endian != .little) return error.SkipZigTest;
    // Captured RTM_NEWLINK payload for veth0 (ifindex 4) after
    // `bridge vlan add dev veth0 vid 30 untagged`: PVID 1 plus VLAN 30.
    const payload = [_]u8{
        0x07, 0x00, 0x01, 0x00, // AF_BRIDGE, ARPHRD_ETHER
        0x04, 0x00, 0x00, 0x00, // ifi_index = 4
        0x03, 0x10, 0x00, 0x00, // ifi_flags
        0x00, 0x00, 0x00, 0x00, // ifi_change
        0x0a, 0x00, 0x03, 0x00, 0x76, 0x65, 0x74, 0x68, 0x30, 0x00, 0x00, 0x00, // IFLA_IFNAME
        0x08, 0x00, 0x0a, 0x00, 0x06, 0x00, 0x00, 0x00, // IFLA_MASTER = 6
        0x14, 0x00, 0x1a, 0x00, // IFLA_AF_SPEC, len 20
        0x08, 0x00, 0x02, 0x00, 0x06, 0x00, 0x01, 0x00, // {PVID|UNTAGGED, 1}
        0x08, 0x00, 0x02, 0x00, 0x04, 0x00, 0x1e, 0x00, // {UNTAGGED, 30}
    };
    var out: std.ArrayList(VlanEntry) = .empty;
    defer out.deinit(testing.allocator);
    try parseVlans(testing.allocator, &out, &payload);
    try testing.expectEqual(@as(usize, 2), out.items.len);
    try testing.expectEqual(@as(u32, 4), out.items[0].ifindex);
    try testing.expectEqual(@as(u16, 1), out.items[0].vid);
    try testing.expectEqual(@as(u16, 1), out.items[0].vid_end);
    try testing.expect(out.items[0].isPvid());
    try testing.expect(out.items[0].isUntagged());
    try testing.expectEqual(@as(u32, 1), out.items[0].count());
    try testing.expectEqual(@as(u16, 30), out.items[1].vid);
    try testing.expect(!out.items[1].isPvid());
    try testing.expect(out.items[1].isUntagged());
    try testing.expect(out.items[1].contains(30));
    try testing.expect(!out.items[1].contains(31));
}

test "parseVlans: RANGE_BEGIN/RANGE_END collapse into one entry" {
    if (native_endian != .little) return error.SkipZigTest;
    var payload: [32 + 24]u8 = @splat(0);
    payload[0] = root.AF.BRIDGE;
    std.mem.writeInt(i32, payload[4..8], 7, native_endian);
    // IFLA_AF_SPEC with {RANGE_BEGIN,100} {RANGE_END,200} {UNTAGGED,300}
    const af_spec = [_]u8{
        0x1c, 0x00, 0x1a, 0x00,
        0x08, 0x00, 0x02, 0x00,
        0x08, 0x00, 0x64, 0x00,
        0x08, 0x00, 0x02, 0x00,
        0x10, 0x00, 0xc8, 0x00,
        0x08, 0x00, 0x02, 0x00,
        0x04, 0x00, 0x2c, 0x01,
    };
    @memcpy(payload[16..][0..af_spec.len], &af_spec);

    var out: std.ArrayList(VlanEntry) = .empty;
    defer out.deinit(testing.allocator);
    try parseVlans(testing.allocator, &out, payload[0 .. 16 + af_spec.len]);
    try testing.expectEqual(@as(usize, 2), out.items.len);
    try testing.expectEqual(@as(u16, 100), out.items[0].vid);
    try testing.expectEqual(@as(u16, 200), out.items[0].vid_end);
    try testing.expectEqual(@as(u32, 101), out.items[0].count());
    // The RANGE_* bookkeeping bits never leak into the decoded flags.
    try testing.expectEqual(@as(u16, 0), out.items[0].flags);
    try testing.expect(out.items[0].contains(150));
    try testing.expectEqual(@as(u16, 300), out.items[1].vid);
    try testing.expect(out.items[1].isUntagged());
}

test "parseVlans: hostile nested streams never panic or over-read" {
    if (native_endian != .little) return error.SkipZigTest;
    var out: std.ArrayList(VlanEntry) = .empty;
    defer out.deinit(testing.allocator);

    // A dangling RANGE_BEGIN degrades to a single-VID entry.
    {
        const p = [_]u8{
            0x07, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x0c, 0x00, 0x1a, 0x00,
            0x08, 0x00, 0x02, 0x00, 0x08, 0x00, 0x64, 0x00, // RANGE_BEGIN, no END
        };
        out.clearRetainingCapacity();
        try parseVlans(testing.allocator, &out, &p);
        try testing.expectEqual(@as(usize, 1), out.items.len);
        try testing.expectEqual(@as(u16, 100), out.items[0].vid);
        try testing.expectEqual(@as(u16, 100), out.items[0].vid_end);
    }
    // A RANGE_END whose VID precedes the pending begin cannot invert the range.
    {
        const p = [_]u8{
            0x07, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x14, 0x00, 0x1a, 0x00,
            0x08, 0x00, 0x02, 0x00, 0x08, 0x00, 0xc8, 0x00, // RANGE_BEGIN 200
            0x08, 0x00, 0x02, 0x00, 0x10, 0x00, 0x64, 0x00, // RANGE_END 100
        };
        out.clearRetainingCapacity();
        try parseVlans(testing.allocator, &out, &p);
        for (out.items) |v| try testing.expect(v.vid <= v.vid_end);
    }
    // Truncated ifinfomsg, a bad-length bridge_vlan_info, an AF_SPEC whose
    // declared length runs past the buffer, and a nest length of 0.
    {
        out.clearRetainingCapacity();
        try testing.expectError(error.Truncated, parseVlans(testing.allocator, &out, &.{ 7, 0 }));
    }
    {
        const p = [_]u8{
            0x07, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x0a, 0x00, 0x1a, 0x00,
            0x06, 0x00, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, // 2-byte vlan_info
        };
        out.clearRetainingCapacity();
        try testing.expectError(error.BadLength, parseVlans(testing.allocator, &out, &p));
    }
    {
        const p = [_]u8{
            0x07, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xff, 0x00, 0x1a, 0x00, 0x08, 0x00, 0x02, 0x00,
        };
        out.clearRetainingCapacity();
        try testing.expectError(error.Truncated, parseVlans(testing.allocator, &out, &p));
    }
    {
        const p = [_]u8{
            0x07, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x1a, 0x00,
        };
        out.clearRetainingCapacity();
        try testing.expectError(error.BadLength, parseVlans(testing.allocator, &out, &p));
    }
}

test "parseBrport: real link-dump reply with IFLA_PROTINFO" {
    if (native_endian != .little) return error.SkipZigTest;
    const payload = [_]u8{
        0x07, 0x00, 0x01, 0x00,
        0x04, 0x00, 0x00, 0x00, // ifi_index = 4
        0x03, 0x10, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x0a, 0x00, 0x06, 0x00, 0x00, 0x00, // IFLA_MASTER = 6
        0x34, 0x00, 0x0c, 0x80, // IFLA_PROTINFO|NESTED, len 52
        0x05, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, // BRPORT_STATE = 3
        0x06, 0x00, 0x02, 0x00, 0x20, 0x00, 0x00, 0x00, // BRPORT_PRIORITY = 32
        0x08, 0x00, 0x03, 0x00, 0x02, 0x00, 0x00, 0x00, // BRPORT_COST = 2
        0x05, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, // BRPORT_LEARNING = 0
        0x05, 0x00, 0x09, 0x00, 0x01, 0x00, 0x00, 0x00, // BRPORT_UNICAST_FLOOD = 1
        0x05, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00, // BRPORT_ISOLATED = 1
    };
    const p = (try parseBrport(&payload)).?;
    try testing.expectEqual(@as(u32, 4), p.ifindex);
    try testing.expectEqual(@as(?u32, 6), p.master);
    try testing.expectEqual(@as(?u8, BR_STATE.FORWARDING), p.state);
    try testing.expectEqual(@as(?u16, 32), p.priority);
    try testing.expectEqual(@as(?u32, 2), p.cost);
    try testing.expectEqual(@as(?bool, false), p.learning);
    try testing.expectEqual(@as(?bool, true), p.unicast_flood);
    try testing.expectEqual(@as(?bool, true), p.isolated);
    try testing.expectEqual(@as(?bool, null), p.mcast_flood);

    // A plain (non-port) interface has no IFLA_PROTINFO at all.
    const plain = [_]u8{
        0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x03, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    try testing.expectEqual(@as(?BrportInfo, null), try parseBrport(&plain));
    try testing.expectError(error.Truncated, parseBrport(plain[0..4]));
}

test "wire constants agree with the kernel UAPI" {
    try testing.expectEqual(@as(u8, 7), root.AF.BRIDGE); // AF_BRIDGE
    try testing.expectEqual(@as(u16, 19), RTM_SETLINK);
    try testing.expectEqual(@as(u16, 10), IFLA_MASTER);
    try testing.expectEqual(@as(u16, 12), IFLA_PROTINFO);
    try testing.expectEqual(@as(u16, 26), IFLA_AF_SPEC);
    try testing.expectEqual(@as(u16, 29), IFLA_EXT_MASK);
    try testing.expectEqual(@as(u16, 2), RTEXT_FILTER.BRVLAN);
    try testing.expectEqual(@as(usize, 4), bridge_vlan_info_len);
    // 802.1Q's usable VID range (0 and 4095 are reserved) — pinned as
    // literals here, independent of `vlan_id_min`/`vlan_id_max` below, per
    // audit finding `netlink` F3: the old version of this test wrote 4094
    // into the buffer with a bare literal and then compared the parser's
    // output back against `vlan_id_max`, which only proves `VlanInfo.parse`
    // round-trips whatever `vlan_id_max` happens to be — it never checks the
    // constant's own value. `vlan_id_min`/`vlan_id_max` aren't literal
    // `#define`s in the kernel headers (802.1Q, not a netlink UAPI symbol),
    // so `scripts/check-uapi-consts.py` cannot anchor them either; pinning
    // both ends independently here is the substitute.
    try testing.expectEqual(@as(u16, 1), vlan_id_min);
    try testing.expectEqual(@as(u16, 4094), vlan_id_max);
    // struct bridge_vlan_info is {u16 flags, u16 vid} in host order.
    var raw: [4]u8 = undefined;
    std.mem.writeInt(u16, raw[0..2], BRIDGE_VLAN_INFO.PVID | BRIDGE_VLAN_INFO.UNTAGGED, native_endian);
    std.mem.writeInt(u16, raw[2..4], 4094, native_endian);
    const info = try VlanInfo.parse(&raw);
    try testing.expectEqual(@as(u16, 6), info.flags);
    try testing.expectEqual(@as(u16, 4094), info.vid);
}

test "fuzz: bridge builders never crash on arbitrary spec bytes" {
    try std.testing.fuzz({}, fuzzBuilders, .{});
}

fn fuzzBuilders(_: void, smith: *std.testing.Smith) !void {
    const gpa = testing.allocator;
    var name_buf: [24]u8 = undefined;
    smith.bytes(&name_buf);
    const name_len = smith.valueRangeAtMost(u8, 0, name_buf.len);
    var mac_buf: [40]u8 = undefined;
    smith.bytes(&mac_buf);
    const mac_len = smith.valueRangeAtMost(u8, 0, mac_buf.len);

    if (buildBridgeAddRequest(gpa, smith.value(u32), smith.value(u16), .{
        .name = name_buf[0..name_len],
        .forward_delay = if (smith.value(bool)) smith.value(u32) else null,
        .ageing_time = if (smith.value(bool)) smith.value(u32) else null,
        .stp_state = if (smith.value(bool)) smith.value(u32) else null,
        .priority = if (smith.value(bool)) smith.value(u16) else null,
        .vlan_filtering = if (smith.value(bool)) smith.value(bool) else null,
        .vlan_protocol = if (smith.value(bool)) smith.value(u16) else null,
        .mac = if (smith.value(bool)) mac_buf[0..mac_len] else null,
    })) |req| gpa.free(req) else |_| {}

    if (buildFdbRequest(gpa, smith.value(u32), smith.value(u16), smith.value(u16), .{
        .ifindex = smith.value(u32),
        .lladdr = mac_buf[0..mac_len],
        .dst = if (smith.value(bool)) name_buf[0..name_len] else null,
        .vlan = if (smith.value(bool)) smith.value(u16) else null,
        .port = if (smith.value(bool)) smith.value(u16) else null,
        .vni = if (smith.value(bool)) smith.value(u32) else null,
        .master = if (smith.value(bool)) smith.value(u32) else null,
        .state = smith.value(u16),
        .flags = smith.value(u8),
        .ntype = smith.value(u8),
    })) |req| gpa.free(req) else |_| {}

    if (buildVlanRequest(gpa, smith.value(u32), smith.value(u16), smith.value(u32), .{
        .vid = smith.value(u16),
        .vid_end = if (smith.value(bool)) smith.value(u16) else null,
        .pvid = smith.value(bool),
        .untagged = smith.value(bool),
        .self = smith.value(bool),
        .master = smith.value(bool),
    })) |req| gpa.free(req) else |_| {}

    if (buildBrportRequest(gpa, smith.value(u32), smith.value(u32), .{
        .state = if (smith.value(bool)) smith.value(u8) else null,
        .learning = if (smith.value(bool)) smith.value(bool) else null,
        .unicast_flood = if (smith.value(bool)) smith.value(bool) else null,
        .isolated = if (smith.value(bool)) smith.value(bool) else null,
        .priority = if (smith.value(bool)) smith.value(u16) else null,
        .cost = if (smith.value(bool)) smith.value(u32) else null,
    })) |req| gpa.free(req) else |_| {}

    if (buildFdbDumpRequest(gpa, smith.value(u32), .{
        .ifindex = if (smith.value(bool)) smith.value(u32) else null,
        .master = if (smith.value(bool)) smith.value(u32) else null,
    })) |req| gpa.free(req) else |_| {}
}

test "fuzz: bridge parsers never crash on arbitrary payloads" {
    try std.testing.fuzz({}, fuzzParsers, .{});
}

fn fuzzParsers(_: void, smith: *std.testing.Smith) !void {
    var raw: [512]u8 = undefined;
    smith.bytes(&raw);
    const len = smith.valueRangeAtMost(u16, 0, raw.len);
    const payload = raw[0..len];
    if (parseFdb(payload)) |_| {} else |_| {}
    if (parseBrport(payload)) |_| {} else |_| {}
    var out: std.ArrayList(VlanEntry) = .empty;
    defer out.deinit(testing.allocator);
    if (parseVlans(testing.allocator, &out, payload)) |_| {} else |_| {}
}
