// SPDX-License-Identifier: MIT
//! netlink — pure-Zig rtnetlink transport + query API over `NETLINK_ROUTE`.
//!
//! Enumerate links, addresses, routes, and neighbors straight from the kernel
//! control plane — no `ip`/`ss` shell-outs, no `/proc/net` parsing, no libc.
//! All syscalls go through `std.os.linux` (errno-encoded raw syscalls), so the
//! module is Linux-only by design (see `meta.platform`).
//!
//! RTM_GET* dumps are unprivileged: none of the query calls need root.
//!
//! ```zig
//! var nl = try netlink.Socket.open(gpa);
//! defer nl.close();
//! const ls = try nl.links(); // []Link, free with gpa.free(ls)
//! for (ls) |l| std.debug.print("{d}: {s} mtu {d}\n", .{ l.index, l.name(), l.mtu });
//! ```
//!
//! Write ops (`RTM_NEW*`/`RTM_DEL*`) are supported too — addresses, routes,
//! links (admin up/down, MTU, rename, MAC, virtual-device create/delete) and
//! neighbors. They need **CAP_NET_ADMIN**; every request carries `NLM_F_ACK`
//! and the `NLMSG_ERROR` reply is mapped to a typed Zig error, with the
//! kernel's extended-ACK reason string surfaced via `Socket.lastErrorMessage`.
//!
//! ```zig
//! try nl.linkSet(ifindex, .{ .up = true });
//! try nl.addressAdd(.{ .ifindex = ifindex, .local = &.{ 10, 0, 0, 1 }, .prefixlen = 24 }, .{});
//! try nl.routeAdd(.{ .dst = &.{ 10, 9, 0, 0 }, .dst_prefixlen = 24, .oif = ifindex,
//!                    .scope = netlink.RT_SCOPE.LINK }, .{});
//! ```
//!
//! Linux **bridges** are covered too (`bridge.zig`, re-exported as
//! `netlink.bridge`): create/configure a bridge device, enslave ports, manage
//! the forwarding database, VLAN filtering (incl. VID ranges) and bridge-port
//! options — everything `ip link … type bridge`, `bridge fdb`, `bridge vlan`
//! and `bridge link set` do.
//!
//! ```zig
//! try nl.bridgeAdd(.{ .name = "br0", .vlan_filtering = true, .up = true }, .{});
//! try nl.portEnslave(veth_index, br_index);
//! try nl.bridgeVlanAdd(veth_index, .{ .vid = 10, .pvid = true, .untagged = true });
//! try nl.fdbAdd(.{ .ifindex = veth_index, .lladdr = &mac, .vlan = 10 }, .{});
//! ```
//!
//! Still out of scope: multicast event monitoring (RTNLGRP_* subscription),
//! tc/qdisc (the sibling `tc` module), conntrack, and — within the bridge
//! surface — MDB/multicast snooping, VXLAN device creation, VLAN tunnels and
//! MRP/CFM/MST (see SPEC.md for the full deferred list). The transport is
//! generic enough for them — `nextSeq` + `requestAck` are public so sibling
//! modules can reuse the write+ACK engine with their own message builders.
//!
//! The wire codec (message framing + rtattr TLV walking) lives in
//! `codec.zig`, is platform-independent, golden-tested and fuzzed; every
//! length in a reply is bounds-checked, so a malformed or hostile buffer
//! yields an error — never a panic or an out-of-bounds read.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const native_endian = builtin.cpu.arch.endian();

pub const codec = @import("codec.zig");
pub const Message = codec.Message;
pub const MessageIterator = codec.MessageIterator;
pub const Attr = codec.Attr;
pub const AttrIterator = codec.AttrIterator;
/// The shared multi-part dump triage — see `codec.classifyDumpMessage`. Other
/// netlink protocols (`NETLINK_NETFILTER`, `NETLINK_GENERIC`) drive their own
/// sockets through it.
pub const DumpStep = codec.DumpStep;
pub const classifyDumpMessage = codec.classifyDumpMessage;

/// `AF_BRIDGE` extensions: bridge devices, FDB entries, VLAN filtering and
/// bridge-port options. The builders/parsers live there; the `Socket` methods
/// that drive them are further down this file.
pub const bridge = @import("bridge.zig");
pub const BridgeSpec = bridge.BridgeSpec;
pub const FdbSpec = bridge.FdbSpec;
pub const FdbFilter = bridge.FdbFilter;
pub const FdbEntry = bridge.FdbEntry;
pub const VlanSpec = bridge.VlanSpec;
pub const VlanEntry = bridge.VlanEntry;
pub const BrportChange = bridge.BrportChange;
pub const BrportInfo = bridge.BrportInfo;
pub const BridgeWriteError = bridge.WriteError;
pub const BRIDGE_VLAN_INFO = bridge.BRIDGE_VLAN_INFO;
pub const BRIDGE_FLAGS = bridge.BRIDGE_FLAGS;
pub const BR_STATE = bridge.BR_STATE;
pub const IFLA_BR = bridge.IFLA_BR;
pub const IFLA_BRPORT = bridge.IFLA_BRPORT;
pub const IFLA_BRIDGE = bridge.IFLA_BRIDGE;
pub const RTEXT_FILTER = bridge.RTEXT_FILTER;

pub const meta = .{
    .platform = .linux, // AF_NETLINK raw syscalls — conscious ceiling
    .role = .client,
    .concurrency = .reentrant, // no globals; one Socket per thread/loop
    .model_after = "libmnl (framing/validation) + vishvananda/netlink (typed queries); wire per kernel UAPI",
    .deps = .{}, // std only — keep this a dependency-free foundation
};

// ── kernel UAPI constants ───────────────────────────────────────────────────
// Names come from std.os.linux where it has them (NetlinkMessageType, IFLA,
// IFA, NLM_F_*); the rest are defined here from the kernel UAPI header noted
// on each declaration.

/// rtnetlink message types (std.os.linux.NetlinkMessageType values).
pub const RTM_NEWLINK: u16 = @intFromEnum(linux.NetlinkMessageType.RTM_NEWLINK);
pub const RTM_GETLINK: u16 = @intFromEnum(linux.NetlinkMessageType.RTM_GETLINK);
pub const RTM_NEWADDR: u16 = @intFromEnum(linux.NetlinkMessageType.RTM_NEWADDR);
pub const RTM_GETADDR: u16 = @intFromEnum(linux.NetlinkMessageType.RTM_GETADDR);
pub const RTM_NEWROUTE: u16 = @intFromEnum(linux.NetlinkMessageType.RTM_NEWROUTE);
pub const RTM_GETROUTE: u16 = @intFromEnum(linux.NetlinkMessageType.RTM_GETROUTE);
pub const RTM_NEWNEIGH: u16 = @intFromEnum(linux.NetlinkMessageType.RTM_NEWNEIGH);
pub const RTM_GETNEIGH: u16 = @intFromEnum(linux.NetlinkMessageType.RTM_GETNEIGH);
pub const RTM_DELLINK: u16 = @intFromEnum(linux.NetlinkMessageType.RTM_DELLINK);
pub const RTM_DELADDR: u16 = @intFromEnum(linux.NetlinkMessageType.RTM_DELADDR);
pub const RTM_DELROUTE: u16 = @intFromEnum(linux.NetlinkMessageType.RTM_DELROUTE);
pub const RTM_DELNEIGH: u16 = @intFromEnum(linux.NetlinkMessageType.RTM_DELNEIGH);
/// `RTM_SETLINK` — the AF_BRIDGE "change link state" message (`bridge vlan`,
/// `bridge link set`). Re-exported from `bridge` for symmetry with the rest.
pub const RTM_SETLINK: u16 = bridge.RTM_SETLINK;

/// `NETLINK_EXT_ACK` (linux/netlink.h, Linux >= 4.12) — socket option asking
/// the kernel to attach a reason string to `NLMSG_ERROR` replies.
pub const NETLINK_EXT_ACK: u32 = 11;

/// Fixed per-family header sizes (kernel UAPI):
/// sizeof(struct ifinfomsg), linux/rtnetlink.h.
pub const ifinfomsg_len = 16;
/// sizeof(struct ifaddrmsg), linux/if_addr.h.
pub const ifaddrmsg_len = 8;
/// sizeof(struct rtmsg), linux/rtnetlink.h.
pub const rtmsg_len = 12;
/// sizeof(struct ndmsg), linux/neighbour.h.
pub const ndmsg_len = 12;

/// IFNAMSIZ (linux/if.h) — interface names incl. NUL.
pub const ifnamsiz = 16;

/// Address families for `Filter.family` (linux/socket.h AF_*).
pub const AF = struct {
    pub const UNSPEC: u8 = 0;
    pub const INET: u8 = 2;
    pub const INET6: u8 = 10;
    /// `AF_BRIDGE` — the family of FDB entries and bridge VLAN/port requests.
    pub const BRIDGE: u8 = 7;
};

/// Link flags for `Link.flags` (linux/if.h IFF_*; extended bits >= 0x10000
/// are only visible via netlink, not via SIOCGIFFLAGS).
pub const IFF = struct {
    pub const UP: u32 = 0x1;
    pub const BROADCAST: u32 = 0x2;
    pub const DEBUG: u32 = 0x4;
    pub const LOOPBACK: u32 = 0x8;
    pub const POINTOPOINT: u32 = 0x10;
    pub const NOTRAILERS: u32 = 0x20;
    pub const RUNNING: u32 = 0x40;
    pub const NOARP: u32 = 0x80;
    pub const PROMISC: u32 = 0x100;
    pub const ALLMULTI: u32 = 0x200;
    pub const MASTER: u32 = 0x400;
    pub const SLAVE: u32 = 0x800;
    pub const MULTICAST: u32 = 0x1000;
    pub const PORTSEL: u32 = 0x2000;
    pub const AUTOMEDIA: u32 = 0x4000;
    pub const DYNAMIC: u32 = 0x8000;
    pub const LOWER_UP: u32 = 0x10000;
    pub const DORMANT: u32 = 0x20000;
    pub const ECHO: u32 = 0x40000;
};

/// Route attribute types (linux/rtnetlink.h enum rtattr_type_t).
pub const RTA = struct {
    pub const UNSPEC: u16 = 0;
    pub const DST: u16 = 1;
    pub const SRC: u16 = 2;
    pub const IIF: u16 = 3;
    pub const OIF: u16 = 4;
    pub const GATEWAY: u16 = 5;
    pub const PRIORITY: u16 = 6;
    pub const PREFSRC: u16 = 7;
    pub const METRICS: u16 = 8;
    pub const MULTIPATH: u16 = 9;
    pub const FLOW: u16 = 11;
    pub const CACHEINFO: u16 = 12;
    pub const TABLE: u16 = 15;
    pub const MARK: u16 = 16;
    pub const VIA: u16 = 18;
    pub const EXPIRES: u16 = 23;
};

/// Neighbor attribute types (linux/neighbour.h enum, NDA_*).
pub const NDA = struct {
    pub const UNSPEC: u16 = 0;
    pub const DST: u16 = 1;
    pub const LLADDR: u16 = 2;
    pub const CACHEINFO: u16 = 3;
    pub const PROBES: u16 = 4;
    pub const VLAN: u16 = 5;
    pub const PORT: u16 = 6;
    pub const VNI: u16 = 7;
    pub const IFINDEX: u16 = 8;
    pub const MASTER: u16 = 9;
    pub const LINK_NETNSID: u16 = 10;
    pub const SRC_VNI: u16 = 11;
    pub const PROTOCOL: u16 = 12;
    pub const NH_ID: u16 = 13;
    pub const FDB_EXT_ATTRS: u16 = 14;
    pub const FLAGS_EXT: u16 = 15;
};

/// Neighbor cache entry states for `Neighbor.state` (linux/neighbour.h
/// NUD_*) — a bitmask.
pub const NUD = struct {
    pub const NONE: u16 = 0x00;
    pub const INCOMPLETE: u16 = 0x01;
    pub const REACHABLE: u16 = 0x02;
    pub const STALE: u16 = 0x04;
    pub const DELAY: u16 = 0x08;
    pub const PROBE: u16 = 0x10;
    pub const FAILED: u16 = 0x20;
    pub const NOARP: u16 = 0x40;
    pub const PERMANENT: u16 = 0x80;
};

/// Routing table ids for `Route.table` (linux/rtnetlink.h rt_class_t).
pub const RT_TABLE = struct {
    pub const UNSPEC: u32 = 0;
    pub const COMPAT: u32 = 252;
    pub const DEFAULT: u32 = 253;
    pub const MAIN: u32 = 254;
    pub const LOCAL: u32 = 255;
};

/// Address/route scopes (linux/rtnetlink.h rt_scope_t).
pub const RT_SCOPE = struct {
    pub const UNIVERSE: u8 = 0;
    pub const SITE: u8 = 200;
    pub const LINK: u8 = 253;
    pub const HOST: u8 = 254;
    pub const NOWHERE: u8 = 255;
};

/// Route types for `Route.rtype` (linux/rtnetlink.h RTN_*).
pub const RTN = struct {
    pub const UNSPEC: u8 = 0;
    pub const UNICAST: u8 = 1;
    pub const LOCAL: u8 = 2;
    pub const BROADCAST: u8 = 3;
    pub const ANYCAST: u8 = 4;
    pub const MULTICAST: u8 = 5;
    pub const BLACKHOLE: u8 = 6;
    pub const UNREACHABLE: u8 = 7;
    pub const PROHIBIT: u8 = 8;
    pub const THROW: u8 = 9;
    pub const NAT: u8 = 10;
};

/// Routing protocol ids for `RouteSpec.protocol` (linux/rtnetlink.h RTPROT_*)
/// — "who installed this route". `ip route add` uses BOOT by default.
pub const RTPROT = struct {
    pub const UNSPEC: u8 = 0;
    pub const REDIRECT: u8 = 1;
    pub const KERNEL: u8 = 2;
    pub const BOOT: u8 = 3;
    pub const STATIC: u8 = 4;
    pub const RA: u8 = 9;
    pub const DHCP: u8 = 16;
};

/// Address flags (linux/if_addr.h IFA_F_*). Values <= 0xff fit the legacy
/// `ifaddrmsg.ifa_flags` byte; anything above needs `AddressSpec.flags32`
/// (the `IFA_FLAGS` attribute, Linux >= 4.4).
pub const IFA_F = struct {
    pub const SECONDARY: u32 = 0x01;
    pub const TEMPORARY: u32 = SECONDARY;
    pub const NODAD: u32 = 0x02;
    pub const OPTIMISTIC: u32 = 0x04;
    pub const DADFAILED: u32 = 0x08;
    pub const HOMEADDRESS: u32 = 0x10;
    pub const DEPRECATED: u32 = 0x20;
    pub const TENTATIVE: u32 = 0x40;
    pub const PERMANENT: u32 = 0x80;
    pub const MANAGETEMPADDR: u32 = 0x100;
    pub const NOPREFIXROUTE: u32 = 0x200;
    pub const MCAUTOJOIN: u32 = 0x400;
    pub const STABLE_PRIVACY: u32 = 0x800;
};

/// Neighbor entry flags (linux/neighbour.h NTF_*).
pub const NTF = struct {
    pub const USE: u8 = 0x01;
    pub const SELF: u8 = 0x02;
    pub const MASTER: u8 = 0x04;
    pub const PROXY: u8 = 0x08;
    pub const EXT_LEARNED: u8 = 0x10;
    pub const OFFLOADED: u8 = 0x20;
    pub const STICKY: u8 = 0x40;
    pub const ROUTER: u8 = 0x80;
};

/// Attributes nested inside `IFLA_LINKINFO` (linux/if_link.h IFLA_INFO_*),
/// used when creating a virtual device (`LinkAddSpec.kind`).
pub const IFLA_INFO = struct {
    pub const UNSPEC: u16 = 0;
    pub const KIND: u16 = 1;
    pub const DATA: u16 = 2;
    pub const XSTATS: u16 = 3;
    pub const SLAVE_KIND: u16 = 4;
    pub const SLAVE_DATA: u16 = 5;
};

// Attribute types taken from std.os.linux enums. Public so the bridge
// builders (and sibling modules) encode the same attribute numbers.
pub const IFLA_ADDRESS: u16 = @intFromEnum(linux.IFLA.ADDRESS);
pub const IFLA_IFNAME: u16 = @intFromEnum(linux.IFLA.IFNAME);
pub const IFLA_MTU: u16 = @intFromEnum(linux.IFLA.MTU);
pub const IFLA_TXQLEN: u16 = @intFromEnum(linux.IFLA.TXQLEN);
pub const IFLA_LINKINFO: u16 = @intFromEnum(linux.IFLA.LINKINFO);
/// `IFLA_MASTER` — the bridge/bond an interface is enslaved to (0 = release).
pub const IFLA_MASTER: u16 = bridge.IFLA_MASTER;

const ifla_address = IFLA_ADDRESS;
const ifla_ifname = IFLA_IFNAME;
const ifla_mtu = IFLA_MTU;
const ifla_txqlen = IFLA_TXQLEN;
const ifla_linkinfo = IFLA_LINKINFO;
const ifa_address: u16 = @intFromEnum(linux.IFA.ADDRESS);
const ifa_local: u16 = @intFromEnum(linux.IFA.LOCAL);
const ifa_label: u16 = @intFromEnum(linux.IFA.LABEL);
const ifa_broadcast: u16 = @intFromEnum(linux.IFA.BROADCAST);
const ifa_flags_attr: u16 = @intFromEnum(linux.IFA.FLAGS);

// ── typed results ───────────────────────────────────────────────────────────
// All result types are plain data (fixed inline buffers, no pointers), so an
// owned slice frees with a single `gpa.free(slice)`.

/// One network interface (RTM_GETLINK → struct ifinfomsg + IFLA_* attrs).
pub const Link = struct {
    /// Kernel interface index (`lo` is 1).
    index: u32,
    /// IFF_* bitmask, incl. extended bits (IFF.LOWER_UP…).
    flags: u32,
    /// Hardware type (ARPHRD_*; 1 = ether, 772 = loopback).
    hw_type: u16,
    /// 0 when the kernel did not report an MTU.
    mtu: u32,
    /// Present when IFLA_ADDRESS is a 6-byte EUI-48 (null for loopback/tun
    /// and exotic link layers such as InfiniBand).
    mac: ?[6]u8,
    name_buf: [ifnamsiz]u8 = @splat(0),
    name_len: u8 = 0,

    /// Interface name ("lo", "eth0", …).
    pub fn name(l: *const Link) []const u8 {
        return l.name_buf[0..l.name_len];
    }
};

/// One interface address (RTM_GETADDR → struct ifaddrmsg + IFA_* attrs).
/// Plain `{family, bytes, prefix, ifindex}` by design — no dependency on a
/// higher-level IP type, so `netlink` stays foundation-grade.
pub const Address = struct {
    /// AF.INET or AF.INET6.
    family: u8,
    /// CIDR prefix length.
    prefixlen: u8,
    /// RT_SCOPE.* value.
    scope: u8,
    /// IFA_F_* flags (the legacy u8 from struct ifaddrmsg).
    flags: u8,
    /// Owning interface index.
    ifindex: u32,
    addr: [16]u8 = @splat(0),
    /// Valid bytes in `addr`: 4 (IPv4) or 16 (IPv6).
    addr_len: u8 = 0,
    label_buf: [ifnamsiz]u8 = @splat(0),
    label_len: u8 = 0,

    /// The address bytes (4 or 16). For IPv4 this is IFA_LOCAL when present
    /// (the interface's own address on peer-to-peer links), else IFA_ADDRESS
    /// — the same preference iproute2 applies.
    pub fn bytes(a: *const Address) []const u8 {
        return a.addr[0..a.addr_len];
    }

    /// IFA_LABEL (IPv4 only, usually the interface name); may be empty.
    pub fn label(a: *const Address) []const u8 {
        return a.label_buf[0..a.label_len];
    }
};

/// One routing-table entry (RTM_GETROUTE → struct rtmsg + RTA_* attrs).
pub const Route = struct {
    /// AF.INET or AF.INET6.
    family: u8,
    /// Destination prefix length; 0 with `dst_len == 0` = default route.
    dst_prefixlen: u8,
    /// RTPROT_* (2 = kernel, 3 = boot, 4 = static, 16 = dhcp…).
    protocol: u8,
    /// RT_SCOPE.* value.
    scope: u8,
    /// RTN.* route type (unicast, local, broadcast…).
    rtype: u8,
    /// Routing table id (RTA_TABLE when present, else the u8 rtm_table —
    /// tables > 255 only fit in the attribute; RT_TABLE.MAIN = 254).
    table: u32,
    dst: [16]u8 = @splat(0),
    /// Valid bytes in `dst` (0 = no RTA_DST, i.e. default route).
    dst_len: u8 = 0,
    gateway: [16]u8 = @splat(0),
    /// Valid bytes in `gateway` (0 = directly connected).
    gateway_len: u8 = 0,
    /// Output interface index (RTA_OIF); 0 when absent.
    oif: u32 = 0,
    /// Route priority/metric (RTA_PRIORITY); 0 when absent.
    priority: u32 = 0,

    pub fn dstBytes(r: *const Route) []const u8 {
        return r.dst[0..r.dst_len];
    }

    pub fn gatewayBytes(r: *const Route) []const u8 {
        return r.gateway[0..r.gateway_len];
    }
};

/// One neighbor (ARP/NDP) cache entry (RTM_GETNEIGH → struct ndmsg + NDA_*).
pub const Neighbor = struct {
    /// AF.INET or AF.INET6.
    family: u8,
    /// Interface index the entry lives on.
    ifindex: u32,
    /// NUD.* state bitmask (REACHABLE, STALE, PERMANENT…).
    state: u16,
    /// NTF_* flags (linux/neighbour.h).
    flags: u8,
    /// RTN.* type (unicast, broadcast…).
    ntype: u8,
    dst: [16]u8 = @splat(0),
    /// Valid bytes in `dst`: 4 or 16 (0 when the kernel sent none).
    dst_len: u8 = 0,
    /// Link-layer address; 6 bytes for Ethernet, up to 32 for exotic media
    /// (InfiniBand GIDs are 20).
    lladdr: [32]u8 = @splat(0),
    lladdr_len: u8 = 0,

    pub fn dstBytes(n: *const Neighbor) []const u8 {
        return n.dst[0..n.dst_len];
    }

    pub fn lladdrBytes(n: *const Neighbor) []const u8 {
        return n.lladdr[0..n.lladdr_len];
    }
};

/// Optional dump scoping. `family` is applied kernel-side (the family byte of
/// the request's fixed header — supported by rtnetlink for address, route and
/// neighbor dumps) *and* re-checked client-side as a belt-and-braces measure.
/// `ifindex` is filtered client-side: kernel-side ifindex scoping needs
/// NETLINK_GET_STRICT_CHK (Linux ≥ 4.20 opt-in), which this module does not
/// require. For routes, `ifindex` matches the output interface (RTA_OIF).
pub const Filter = struct {
    family: ?u8 = null,
    ifindex: ?u32 = null,
};

// ── payload parsers (pure, offline-testable, fuzzed) ────────────────────────
// Each takes one message payload (fixed header + attrs) and returns the typed
// entry, null for a degenerate entry worth skipping, or a codec error for
// malformed bytes. They only copy — nothing borrows from the input buffer.

/// Parse an RTM_NEWLINK payload (struct ifinfomsg + IFLA_* attributes).
pub fn parseLink(payload: []const u8) codec.Error!?Link {
    if (payload.len < ifinfomsg_len) return error.Truncated;
    var l: Link = .{
        // struct ifinfomsg (linux/rtnetlink.h): u8 family, u8 pad,
        // u16 type, i32 index, u32 flags, u32 change.
        .index = @bitCast(std.mem.readInt(i32, payload[4..8], native_endian)),
        .flags = std.mem.readInt(u32, payload[8..12], native_endian),
        .hw_type = std.mem.readInt(u16, payload[2..4], native_endian),
        .mtu = 0,
        .mac = null,
    };
    var it: codec.AttrIterator = .{ .buf = payload[ifinfomsg_len..] };
    while (try it.next()) |a| switch (a.type) {
        ifla_ifname => {
            const s = a.asString();
            if (s.len > l.name_buf.len) return error.BadLength;
            @memcpy(l.name_buf[0..s.len], s);
            l.name_len = @intCast(s.len);
        },
        ifla_mtu => l.mtu = try a.asU32(),
        ifla_address => {
            if (a.data.len == 6) l.mac = a.data[0..6].*;
        },
        else => {},
    };
    return l;
}

/// Parse an RTM_NEWADDR payload (struct ifaddrmsg + IFA_* attributes).
/// Returns null for an entry carrying no usable address.
pub fn parseAddress(payload: []const u8) codec.Error!?Address {
    if (payload.len < ifaddrmsg_len) return error.Truncated;
    // struct ifaddrmsg (linux/if_addr.h): u8 family, u8 prefixlen, u8 flags,
    // u8 scope, u32 index.
    var a: Address = .{
        .family = payload[0],
        .prefixlen = payload[1],
        .flags = payload[2],
        .scope = payload[3],
        .ifindex = std.mem.readInt(u32, payload[4..8], native_endian),
    };
    var fallback: ?[]const u8 = null; // IFA_ADDRESS, used when no IFA_LOCAL
    var it: codec.AttrIterator = .{ .buf = payload[ifaddrmsg_len..] };
    while (try it.next()) |attr| switch (attr.type) {
        ifa_local => if (ipLen(attr.data.len)) {
            @memcpy(a.addr[0..attr.data.len], attr.data);
            a.addr_len = @intCast(attr.data.len);
        },
        ifa_address => if (ipLen(attr.data.len)) {
            fallback = attr.data;
        },
        ifa_label => {
            const s = attr.asString();
            if (s.len > a.label_buf.len) return error.BadLength;
            @memcpy(a.label_buf[0..s.len], s);
            a.label_len = @intCast(s.len);
        },
        else => {},
    };
    if (a.addr_len == 0) {
        const fb = fallback orelse return null; // no address at all — skip
        @memcpy(a.addr[0..fb.len], fb);
        a.addr_len = @intCast(fb.len);
    }
    return a;
}

/// Parse an RTM_NEWROUTE payload (struct rtmsg + RTA_* attributes).
pub fn parseRoute(payload: []const u8) codec.Error!?Route {
    if (payload.len < rtmsg_len) return error.Truncated;
    // struct rtmsg (linux/rtnetlink.h): u8 family, dst_len, src_len, tos,
    // table, protocol, scope, type; u32 flags.
    var r: Route = .{
        .family = payload[0],
        .dst_prefixlen = payload[1],
        .protocol = payload[5],
        .scope = payload[6],
        .rtype = payload[7],
        .table = payload[4],
    };
    var it: codec.AttrIterator = .{ .buf = payload[rtmsg_len..] };
    while (try it.next()) |a| switch (a.type) {
        RTA.DST => if (ipLen(a.data.len)) {
            @memcpy(r.dst[0..a.data.len], a.data);
            r.dst_len = @intCast(a.data.len);
        },
        RTA.GATEWAY => if (ipLen(a.data.len)) {
            @memcpy(r.gateway[0..a.data.len], a.data);
            r.gateway_len = @intCast(a.data.len);
        },
        RTA.OIF => r.oif = @bitCast(try a.asI32()),
        RTA.PRIORITY => r.priority = try a.asU32(),
        RTA.TABLE => r.table = try a.asU32(),
        else => {},
    };
    return r;
}

/// Parse an RTM_NEWNEIGH payload (struct ndmsg + NDA_* attributes).
pub fn parseNeighbor(payload: []const u8) codec.Error!?Neighbor {
    if (payload.len < ndmsg_len) return error.Truncated;
    // struct ndmsg (linux/neighbour.h): u8 family, u8 pad1, u16 pad2,
    // i32 ifindex, u16 state, u8 flags, u8 type.
    var n: Neighbor = .{
        .family = payload[0],
        .ifindex = @bitCast(std.mem.readInt(i32, payload[4..8], native_endian)),
        .state = std.mem.readInt(u16, payload[8..10], native_endian),
        .flags = payload[10],
        .ntype = payload[11],
    };
    var it: codec.AttrIterator = .{ .buf = payload[ndmsg_len..] };
    while (try it.next()) |a| switch (a.type) {
        NDA.DST => if (ipLen(a.data.len)) {
            @memcpy(n.dst[0..a.data.len], a.data);
            n.dst_len = @intCast(a.data.len);
        },
        NDA.LLADDR => if (a.data.len > 0 and a.data.len <= n.lladdr.len) {
            @memcpy(n.lladdr[0..a.data.len], a.data);
            n.lladdr_len = @intCast(a.data.len);
        },
        else => {},
    };
    return n;
}

/// True for the two IP payload sizes rtnetlink carries. Attributes with any
/// other length are ignored rather than rejected (defensive: kernels never
/// send them, and dropping one odd attribute beats failing a whole dump).
fn ipLen(n: usize) bool {
    return n == 4 or n == 16;
}

// ── client-side filter predicates ───────────────────────────────────────────

fn matchLink(_: Link, _: Filter) bool {
    return true;
}

fn matchAddress(a: Address, f: Filter) bool {
    if (f.family) |fam| if (a.family != fam) return false;
    if (f.ifindex) |ifi| if (a.ifindex != ifi) return false;
    return true;
}

fn matchRoute(r: Route, f: Filter) bool {
    if (f.family) |fam| if (r.family != fam) return false;
    if (f.ifindex) |ifi| if (r.oif != ifi) return false;
    return true;
}

fn matchNeighbor(n: Neighbor, f: Filter) bool {
    if (f.family) |fam| if (n.family != fam) return false;
    if (f.ifindex) |ifi| if (n.ifindex != ifi) return false;
    return true;
}

// ── write requests: specs ───────────────────────────────────────────────────
// Input structs for the RTM_NEW*/RTM_DEL* builders. Addresses are raw byte
// slices (4 = IPv4, 16 = IPv6) for the same reason the result types are: no
// dependency on a higher-level IP type.

/// Creation semantics for an `*Add` call, mapped onto the kernel's
/// "modifiers to NEW request" flags. `NLM_F_CREATE` is always set; this picks
/// what happens when the entry already exists.
pub const Create = struct {
    /// `NLM_F_EXCL` — fail with `error.Exists` instead of touching an
    /// existing entry. Ignored when `replace` is set (the kernel rejects the
    /// combination).
    exclusive: bool = true,
    /// `NLM_F_REPLACE` — overwrite an existing entry.
    replace: bool = false,
    /// `NLM_F_APPEND` — routes only: add a nexthop rather than replacing the
    /// existing route for the same prefix.
    append: bool = false,

    /// The `nlmsghdr.nlmsg_flags` these options encode — public so sibling
    /// modules building their own requests get identical semantics.
    pub fn flags(c: Create) u16 {
        var f: u16 = codec.NLM_F_REQUEST | codec.NLM_F_ACK | codec.NLM_F_CREATE;
        if (c.replace) {
            f |= codec.NLM_F_REPLACE;
        } else if (c.exclusive) {
            f |= codec.NLM_F_EXCL;
        }
        if (c.append) f |= codec.NLM_F_APPEND;
        return f;
    }
};

/// An interface address for `Socket.addressAdd`/`.addressDel`
/// (`RTM_NEWADDR`/`RTM_DELADDR` → struct ifaddrmsg + IFA_* attributes).
pub const AddressSpec = struct {
    /// Interface to add the address to.
    ifindex: u32,
    /// The interface's own address, 4 (IPv4) or 16 (IPv6) bytes — `IFA_LOCAL`.
    local: []const u8,
    /// CIDR prefix length.
    prefixlen: u8,
    /// Peer address on a point-to-point link (`IFA_ADDRESS`). When null the
    /// encoder repeats `local`, exactly like `ip addr add` on ordinary links.
    peer: ?[]const u8 = null,
    /// `IFA_BROADCAST` (IPv4 only; the kernel derives none by itself).
    broadcast: ?[]const u8 = null,
    /// `IFA_LABEL` — an IPv4 alias label, which must start with the interface
    /// name (kernel rule); omitted when null.
    label: ?[]const u8 = null,
    /// RT_SCOPE.* — UNIVERSE for a normal address, HOST for a loopback one.
    scope: u8 = RT_SCOPE.UNIVERSE,
    /// Legacy 8-bit `ifaddrmsg.ifa_flags` (IFA_F.* values <= 0xff).
    flags: u8 = 0,
    /// `IFA_FLAGS` attribute for the full 32-bit flag set (Linux >= 4.4);
    /// supersedes `flags` when set.
    flags32: ?u32 = null,
    /// AF.INET/AF.INET6; derived from `local.len` when null.
    family: ?u8 = null,
};

/// A route for `Socket.routeAdd`/`.routeDel` (`RTM_NEWROUTE`/`RTM_DELROUTE`
/// → struct rtmsg + RTA_* attributes). Omitting `dst` with
/// `dst_prefixlen == 0` is a default route (then `family` must be derivable
/// from `gateway`/`prefsrc`, or given explicitly).
pub const RouteSpec = struct {
    dst: ?[]const u8 = null,
    dst_prefixlen: u8 = 0,
    /// `RTA_GATEWAY` — a via-address; omit for a directly connected route
    /// (then `scope` is normally `RT_SCOPE.LINK`).
    gateway: ?[]const u8 = null,
    /// `RTA_PREFSRC` — preferred source address for locally generated traffic.
    prefsrc: ?[]const u8 = null,
    /// `RTA_OIF` — output interface index.
    oif: ?u32 = null,
    /// `RTA_PRIORITY` — the route metric.
    priority: ?u32 = null,
    /// Table id. Values <= 255 go in `rtmsg.rtm_table`; larger ids go in the
    /// `RTA_TABLE` attribute with `rtm_table = RT_TABLE.UNSPEC`, like iproute2.
    table: u32 = RT_TABLE.MAIN,
    protocol: u8 = RTPROT.BOOT,
    /// RT_SCOPE.* — UNIVERSE with a gateway, LINK for on-link routes.
    scope: u8 = RT_SCOPE.UNIVERSE,
    /// RTN.* route type (UNICAST, BLACKHOLE, UNREACHABLE…).
    rtype: u8 = RTN.UNICAST,
    /// RTM_F_* route flags (`rtmsg.rtm_flags`); 0 for an ordinary route.
    rt_flags: u32 = 0,
    /// AF.INET/AF.INET6; derived from the address fields when null.
    family: ?u8 = null,
};

/// A link modification for `Socket.linkSet` (`RTM_NEWLINK` without
/// `NLM_F_CREATE` — the "change an existing device" form).
///
/// **The `ifi_change` mask is the classic rtnetlink footgun**: the kernel
/// applies `new = (old & ~change) | (flags & change)`, so a request must set
/// in `ifi_change` exactly the IFF_* bits it intends to touch and no others.
/// This encoder never sets a bit in the mask that the caller did not ask for:
/// `up` contributes only `IFF_UP`, and `flags`/`flags_mask` are the raw
/// escape hatch for everything else. A change with no flag bits and no
/// attributes is rejected (`error.NothingToChange`) rather than sent as a
/// silent no-op.
pub const LinkChange = struct {
    /// Admin state: true → up, false → down, null → leave alone.
    up: ?bool = null,
    /// `IFLA_MTU`.
    mtu: ?u32 = null,
    /// `IFLA_IFNAME` — rename the device.
    name: ?[]const u8 = null,
    /// `IFLA_ADDRESS` — set the link-layer address (6 bytes for Ethernet).
    mac: ?[]const u8 = null,
    /// `IFLA_TXQLEN`.
    txqlen: ?u32 = null,
    /// `IFLA_MASTER` — enslave the device to this bridge/bond ifindex; 0
    /// releases it (`ip link set … nomaster`). See `Socket.portEnslave`.
    master: ?u32 = null,
    /// Raw IFF_* values to apply, gated by `flags_mask`.
    flags: u32 = 0,
    /// Raw `ifi_change` bits — which IFF_* bits `flags` may change.
    flags_mask: u32 = 0,
};

/// A virtual device to create with `Socket.linkAdd` (`RTM_NEWLINK` with
/// `NLM_F_CREATE` + `IFLA_LINKINFO`/`IFLA_INFO_KIND`).
pub const LinkAddSpec = struct {
    /// Device name (`IFLA_IFNAME`), 1..15 characters.
    name: []const u8,
    /// rtnl_link kind: "dummy", "veth", "bridge", "vlan", "vxlan"… The kernel
    /// answers `error.NotSupported` when no such link type is registered.
    kind: []const u8,
    mtu: ?u32 = null,
    mac: ?[]const u8 = null,
    /// Bring the device up in the same request (`ifi_flags`/`ifi_change` =
    /// IFF_UP).
    up: bool = false,
};

/// A neighbour (ARP/NDP) entry for `Socket.neighborAdd`/`.neighborDel`
/// (`RTM_NEWNEIGH`/`RTM_DELNEIGH` → struct ndmsg + NDA_* attributes).
pub const NeighborSpec = struct {
    ifindex: u32,
    /// `NDA_DST` — the IP being resolved (4 or 16 bytes).
    dst: []const u8,
    /// `NDA_LLADDR` — the link-layer address it maps to; required for a
    /// PERMANENT entry, omitted for a delete.
    lladdr: ?[]const u8 = null,
    /// NUD.* state; PERMANENT is what `ip neigh add … nud permanent` sends.
    state: u16 = NUD.PERMANENT,
    /// NTF.* flags.
    flags: u8 = 0,
    /// RTN.* type; 0 (RTN.UNSPEC) matches iproute2.
    ntype: u8 = RTN.UNSPEC,
    /// AF.INET/AF.INET6; derived from `dst.len` when null.
    family: ?u8 = null,
};

// ── write requests: builders (pure, offline-testable) ───────────────────────

pub const BuildError = error{
    OutOfMemory,
    /// An address slice was neither 4 (IPv4) nor 16 (IPv6) bytes.
    InvalidAddressLength,
    /// Two address fields of one request had different families.
    MixedFamilies,
    /// Nothing in the request implied an address family and none was given.
    FamilyRequired,
    /// An interface name/label was empty or >= IFNAMSIZ.
    InvalidName,
    /// A link-layer address was empty or longer than 32 bytes.
    InvalidLinkAddress,
    /// A `LinkChange` that would change nothing (empty `ifi_change`, no
    /// attributes) — rejected rather than sent as a silent no-op.
    NothingToChange,
};

/// Family implied by an address length (4 → INET, 16 → INET6).
fn familyOf(addr: []const u8) BuildError!u8 {
    return switch (addr.len) {
        4 => AF.INET,
        16 => AF.INET6,
        else => error.InvalidAddressLength,
    };
}

/// Fold one optional address into the family being derived, checking that all
/// addresses in a request agree.
fn mergeFamily(current: ?u8, addr: ?[]const u8) BuildError!?u8 {
    const a = addr orelse return current;
    const fam = try familyOf(a);
    const cur = current orelse return fam;
    if (cur != fam) return error.MixedFamilies;
    return cur;
}

fn checkName(s: []const u8) BuildError!void {
    if (s.len == 0 or s.len >= ifnamsiz) return error.InvalidName;
}

fn checkLinkAddr(s: []const u8) BuildError!void {
    if (s.len == 0 or s.len > 32) return error.InvalidLinkAddress;
}

/// `codec.appendAttr` for payloads whose length is statically bounded well
/// under 64 KiB — the `AttrTooLong` arm is unreachable for every caller here
/// (names are < 16 bytes, addresses <= 16, link addresses <= 32).
fn appendAttrChecked(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    data: []const u8,
) std.mem.Allocator.Error!void {
    std.debug.assert(data.len <= std.math.maxInt(u16) - codec.attr_header_len);
    codec.appendAttr(gpa, list, attr_type, data) catch |err| switch (err) {
        error.AttrTooLong => unreachable,
        error.OutOfMemory => return error.OutOfMemory,
    };
}

fn appendAttrStringChecked(
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

/// Build an `RTM_NEWADDR`/`RTM_DELADDR` request. Wire layout (verified
/// against `strace -e sendmsg ip addr add 10.11.12.1/24 dev lo`, see SPEC.md):
/// nlmsghdr | ifaddrmsg{family, prefixlen, flags, scope, index} | IFA_LOCAL |
/// IFA_ADDRESS | [IFA_BROADCAST] | [IFA_LABEL] | [IFA_FLAGS].
fn buildAddressRequest(
    gpa: std.mem.Allocator,
    seq: u32,
    msg_type: u16,
    flags: u16,
    spec: AddressSpec,
) BuildError![]u8 {
    var family = try familyOf(spec.local);
    family = (try mergeFamily(family, spec.peer)).?;
    if (spec.broadcast) |b| if (b.len != spec.local.len) return error.MixedFamilies;
    if (spec.family) |f| if (f != family) return error.MixedFamilies;
    if (spec.label) |l| try checkName(l);
    const max_prefix: u8 = if (family == AF.INET6) 128 else 32;
    if (spec.prefixlen > max_prefix) return error.InvalidAddressLength;

    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(gpa, &list, msg_type, flags, seq, 0);

    var fixed: [ifaddrmsg_len]u8 = @splat(0);
    fixed[0] = family;
    fixed[1] = spec.prefixlen;
    fixed[2] = spec.flags;
    fixed[3] = spec.scope;
    std.mem.writeInt(u32, fixed[4..8], spec.ifindex, native_endian);
    try codec.appendPadded(gpa, &list, &fixed);

    try appendAttrChecked(gpa, &list, ifa_local, spec.local);
    try appendAttrChecked(gpa, &list, ifa_address, spec.peer orelse spec.local);
    if (spec.broadcast) |b| try appendAttrChecked(gpa, &list, ifa_broadcast, b);
    if (spec.label) |l| try appendAttrStringChecked(gpa, &list, ifa_label, l);
    if (spec.flags32) |f| try codec.appendAttrU32(gpa, &list, ifa_flags_attr, f);

    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

/// Build an `RTM_NEWROUTE`/`RTM_DELROUTE` request. Wire layout (verified
/// against `strace -e sendmsg ip route add …`): nlmsghdr | rtmsg{family,
/// dst_len, src_len, tos, table, protocol, scope, type, flags} | [RTA_DST] |
/// [RTA_GATEWAY] | [RTA_OIF] | [RTA_PREFSRC] | [RTA_PRIORITY] | [RTA_TABLE].
fn buildRouteRequest(
    gpa: std.mem.Allocator,
    seq: u32,
    msg_type: u16,
    flags: u16,
    spec: RouteSpec,
) BuildError![]u8 {
    var family: ?u8 = spec.family;
    family = try mergeFamily(family, spec.dst);
    family = try mergeFamily(family, spec.gateway);
    family = try mergeFamily(family, spec.prefsrc);
    const fam = family orelse return error.FamilyRequired;
    const max_prefix: u8 = if (fam == AF.INET6) 128 else 32;
    if (spec.dst_prefixlen > max_prefix) return error.InvalidAddressLength;

    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(gpa, &list, msg_type, flags, seq, 0);

    var fixed: [rtmsg_len]u8 = @splat(0);
    fixed[0] = fam;
    fixed[1] = spec.dst_prefixlen;
    // fixed[2] = src_len, fixed[3] = tos — both 0 (policy routing is out of
    // scope; RTA_SRC/tos-based rules are a future extension).
    fixed[4] = if (spec.table <= 255) @intCast(spec.table) else @intCast(RT_TABLE.UNSPEC);
    fixed[5] = spec.protocol;
    fixed[6] = spec.scope;
    fixed[7] = spec.rtype;
    std.mem.writeInt(u32, fixed[8..12], spec.rt_flags, native_endian);
    try codec.appendPadded(gpa, &list, &fixed);

    if (spec.dst) |d| try appendAttrChecked(gpa, &list, RTA.DST, d);
    if (spec.gateway) |g| try appendAttrChecked(gpa, &list, RTA.GATEWAY, g);
    if (spec.oif) |o| try codec.appendAttrU32(gpa, &list, RTA.OIF, o);
    if (spec.prefsrc) |p| try appendAttrChecked(gpa, &list, RTA.PREFSRC, p);
    if (spec.priority) |p| try codec.appendAttrU32(gpa, &list, RTA.PRIORITY, p);
    if (spec.table > 255) try codec.appendAttrU32(gpa, &list, RTA.TABLE, spec.table);

    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

/// Build the `RTM_NEWLINK` "modify an existing device" request. See
/// `LinkChange` for the `ifi_change` mask discipline.
fn buildLinkSetRequest(
    gpa: std.mem.Allocator,
    seq: u32,
    ifindex: u32,
    change: LinkChange,
) BuildError![]u8 {
    if (change.name) |n| try checkName(n);
    if (change.mac) |m| try checkLinkAddr(m);

    var mask: u32 = change.flags_mask;
    var value: u32 = change.flags & change.flags_mask;
    if (change.up) |up| {
        mask |= IFF.UP;
        value = (value & ~IFF.UP) | (if (up) IFF.UP else 0);
    }
    const has_attrs = change.mtu != null or change.name != null or
        change.mac != null or change.txqlen != null or change.master != null;
    if (mask == 0 and !has_attrs) return error.NothingToChange;

    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(
        gpa,
        &list,
        RTM_NEWLINK,
        codec.NLM_F_REQUEST | codec.NLM_F_ACK,
        seq,
        0,
    );
    try appendIfinfomsg(gpa, &list, ifindex, value, mask);

    if (change.mtu) |m| try codec.appendAttrU32(gpa, &list, ifla_mtu, m);
    if (change.txqlen) |t| try codec.appendAttrU32(gpa, &list, ifla_txqlen, t);
    if (change.mac) |m| try appendAttrChecked(gpa, &list, ifla_address, m);
    if (change.name) |n| try appendAttrStringChecked(gpa, &list, ifla_ifname, n);
    // IFLA_MASTER last: with nothing else set this reproduces `ip link set dev
    // X master Y` / `… nomaster` byte-for-byte.
    if (change.master) |m| try codec.appendAttrU32(gpa, &list, IFLA_MASTER, m);

    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

/// Build the `RTM_NEWLINK` "create a virtual device" request. Wire layout
/// (verified against `strace -e sendmsg ip link add name zdum0 type dummy`):
/// nlmsghdr | ifinfomsg{index 0} | IFLA_IFNAME | IFLA_LINKINFO{IFLA_INFO_KIND}.
/// The nest carries no `NLA_F_NESTED` bit — matching iproute2; the kernel's
/// validator ignores it either way.
fn buildLinkAddRequest(
    gpa: std.mem.Allocator,
    seq: u32,
    flags: u16,
    spec: LinkAddSpec,
) BuildError![]u8 {
    try checkName(spec.name);
    try checkName(spec.kind);
    if (spec.mac) |m| try checkLinkAddr(m);

    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(gpa, &list, RTM_NEWLINK, flags, seq, 0);
    const up_bit: u32 = if (spec.up) IFF.UP else 0;
    try appendIfinfomsg(gpa, &list, 0, up_bit, up_bit);

    try appendAttrStringChecked(gpa, &list, ifla_ifname, spec.name);
    if (spec.mtu) |m| try codec.appendAttrU32(gpa, &list, ifla_mtu, m);
    if (spec.mac) |m| try appendAttrChecked(gpa, &list, ifla_address, m);
    const nest = try codec.nestBegin(gpa, &list, ifla_linkinfo);
    try appendAttrStringChecked(gpa, &list, IFLA_INFO.KIND, spec.kind);
    codec.nestEnd(&list, nest);

    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

/// Build an `RTM_DELLINK` request (index only — `ip link del` sends exactly
/// nlmsghdr + ifinfomsg with `ifi_change = 0`).
fn buildLinkDelRequest(gpa: std.mem.Allocator, seq: u32, ifindex: u32) BuildError![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(
        gpa,
        &list,
        RTM_DELLINK,
        codec.NLM_F_REQUEST | codec.NLM_F_ACK,
        seq,
        0,
    );
    try appendIfinfomsg(gpa, &list, ifindex, 0, 0);
    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

/// struct ifinfomsg: u8 family, u8 pad, u16 type, i32 index, u32 flags,
/// u32 change. Family/type stay 0 (AF_UNSPEC/ARPHRD_NETROM) exactly as
/// iproute2 sends them.
fn appendIfinfomsg(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    ifindex: u32,
    flags: u32,
    change: u32,
) std.mem.Allocator.Error!void {
    var fixed: [ifinfomsg_len]u8 = @splat(0);
    std.mem.writeInt(i32, fixed[4..8], @bitCast(ifindex), native_endian);
    std.mem.writeInt(u32, fixed[8..12], flags, native_endian);
    std.mem.writeInt(u32, fixed[12..16], change, native_endian);
    try codec.appendPadded(gpa, list, &fixed);
}

/// Build an `RTM_NEWNEIGH`/`RTM_DELNEIGH` request. Wire layout (verified
/// against `strace -e sendmsg ip neigh add … lladdr … nud permanent`):
/// nlmsghdr | ndmsg{family, pad, ifindex, state, flags, type} | NDA_DST |
/// [NDA_LLADDR].
fn buildNeighborRequest(
    gpa: std.mem.Allocator,
    seq: u32,
    msg_type: u16,
    flags: u16,
    spec: NeighborSpec,
) BuildError![]u8 {
    const family = try familyOf(spec.dst);
    if (spec.family) |f| if (f != family) return error.MixedFamilies;
    if (spec.lladdr) |l| try checkLinkAddr(l);

    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(gpa, &list, msg_type, flags, seq, 0);

    var fixed: [ndmsg_len]u8 = @splat(0);
    fixed[0] = family;
    std.mem.writeInt(i32, fixed[4..8], @bitCast(spec.ifindex), native_endian);
    std.mem.writeInt(u16, fixed[8..10], spec.state, native_endian);
    fixed[10] = spec.flags;
    fixed[11] = spec.ntype;
    try codec.appendPadded(gpa, &list, &fixed);

    try appendAttrChecked(gpa, &list, NDA.DST, spec.dst);
    if (spec.lladdr) |l| try appendAttrChecked(gpa, &list, NDA.LLADDR, l);

    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

// ── errno mapping ───────────────────────────────────────────────────────────

/// Map the negative errno of an NLMSG_ERROR reply onto the dump error set.
/// (The codec keeps the exact code — `Message.errorCode` — for callers doing
/// custom queries.)
pub fn errorFromCode(code: i32) DumpError {
    if (code >= 0 or code == std.math.minInt(i32)) return error.Unexpected;
    return switch (@as(u32, @intCast(-code))) {
        @intFromEnum(linux.E.PERM), @intFromEnum(linux.E.ACCES) => error.AccessDenied,
        @intFromEnum(linux.E.INVAL), @intFromEnum(linux.E.OPNOTSUPP) => error.InvalidRequest,
        @intFromEnum(linux.E.NOBUFS), @intFromEnum(linux.E.NOMEM) => error.SystemResources,
        else => error.Unexpected,
    };
}

/// Transport failures shared by the dump and write paths.
pub const RequestError = error{
    OutOfMemory,
    SendFailed,
    RecvFailed,
    SystemResources,
    /// A reply failed wire-format validation (bounds/length checks).
    MalformedReply,
    /// Missing CAP_NET_ADMIN (EPERM/EACCES) — every write op needs it.
    AccessDenied,
    /// The entry already exists and the request was exclusive (EEXIST).
    Exists,
    /// No such entry to delete (ENOENT/ESRCH).
    NotFound,
    /// No such interface (ENODEV) — e.g. a stale ifindex.
    NoSuchDevice,
    /// The address is not on this interface, or is not assignable
    /// (EADDRNOTAVAIL) — typically a delete of an address that is not there.
    AddressNotAvailable,
    /// The nexthop is not reachable (ENETUNREACH/EHOSTUNREACH) — e.g. a
    /// gateway outside every configured prefix.
    NetworkUnreachable,
    /// The device or entry is busy (EBUSY).
    Busy,
    /// The kernel rejected the request's shape (EINVAL).
    InvalidRequest,
    /// The kernel lacks this feature: unknown link kind, unsupported family
    /// (EOPNOTSUPP/EAFNOSUPPORT/EPROTONOSUPPORT).
    NotSupported,
    Unexpected,
};

/// Everything a write op can fail with: message construction + transport +
/// the kernel's mapped errno.
pub const WriteError = RequestError || BuildError;

/// Map the negative errno of an `NLMSG_ERROR` reply onto `RequestError`. The
/// exact code stays available via `codec.Message.errorCode`, and the kernel's
/// reason string via `Socket.lastErrorMessage`.
pub fn writeErrorFromCode(code: i32) RequestError {
    if (code >= 0 or code == std.math.minInt(i32)) return error.Unexpected;
    return switch (@as(u32, @intCast(-code))) {
        @intFromEnum(linux.E.PERM), @intFromEnum(linux.E.ACCES) => error.AccessDenied,
        @intFromEnum(linux.E.EXIST) => error.Exists,
        @intFromEnum(linux.E.NOENT), @intFromEnum(linux.E.SRCH) => error.NotFound,
        @intFromEnum(linux.E.NODEV) => error.NoSuchDevice,
        @intFromEnum(linux.E.ADDRNOTAVAIL) => error.AddressNotAvailable,
        @intFromEnum(linux.E.NETUNREACH), @intFromEnum(linux.E.HOSTUNREACH) => error.NetworkUnreachable,
        @intFromEnum(linux.E.BUSY) => error.Busy,
        @intFromEnum(linux.E.INVAL) => error.InvalidRequest,
        @intFromEnum(linux.E.OPNOTSUPP),
        @intFromEnum(linux.E.AFNOSUPPORT),
        @intFromEnum(linux.E.PROTONOSUPPORT),
        => error.NotSupported,
        @intFromEnum(linux.E.NOBUFS), @intFromEnum(linux.E.NOMEM) => error.SystemResources,
        else => error.Unexpected,
    };
}

// ── socket transport ────────────────────────────────────────────────────────

pub const OpenError = error{
    OutOfMemory,
    AccessDenied,
    /// Kernel without AF_NETLINK/NETLINK_ROUTE support.
    ProtocolNotSupported,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    SystemResources,
    Unexpected,
};

pub const DumpError = error{
    OutOfMemory,
    SendFailed,
    RecvFailed,
    SystemResources,
    /// A reply failed wire-format validation (bounds/length checks).
    MalformedReply,
    /// The kernel signalled NLM_F_DUMP_INTR on every retry — the tables were
    /// changing faster than they could be dumped.
    InconsistentDump,
    AccessDenied,
    InvalidRequest,
    Unexpected,
};

const initial_recv_buf_len = 8192; // libmnl's MNL_SOCKET_BUFFER_SIZE ceiling
const max_recv_buf_len = 1 << 24; // hard cap on receive-buffer growth
const max_dump_attempts = 4; // NLM_F_DUMP_INTR restarts before giving up
/// Cap on the kernel's extended-ACK reason string kept per socket; real ones
/// are short sentences ("Unknown device type"), and a longer one is truncated
/// rather than allocated for.
const ext_ack_msg_max = 256;

/// The subset of `RequestError` the receive path can raise; both `DumpError`
/// and `RequestError` are supersets, so the shared helpers below work for the
/// dump and the write path alike.
pub const RecvError = error{
    OutOfMemory,
    RecvFailed,
    SystemResources,
    MalformedReply,
};

/// The subset of `RequestError` the send path can raise.
pub const SendError = error{
    SendFailed,
    SystemResources,
    AccessDenied,
};

/// A blocking `NETLINK_ROUTE` socket. One instance per thread/loop; no shared
/// state. All slices returned by the query methods are allocated with the
/// allocator passed to `open` and free with a single `gpa.free(slice)`.
pub const Socket = struct {
    gpa: std.mem.Allocator,
    fd: i32,
    /// Kernel-assigned netlink port id (from getsockname after bind);
    /// replies are matched against it.
    portid: u32,
    seq: u32,
    /// Receive buffer; grown on demand (MSG_PEEK|MSG_TRUNC size probe).
    buf: []u8,
    /// Last extended-ACK reason string from the kernel (see
    /// `lastErrorMessage`), copied out of the receive buffer so it survives
    /// the next request.
    ext_ack_buf: [ext_ack_msg_max]u8 = @splat(0),
    ext_ack_len: usize = 0,

    pub fn open(gpa: std.mem.Allocator) OpenError!Socket {
        if (comptime builtin.os.tag != .linux)
            @compileError("netlink.Socket is Linux-only (AF_NETLINK raw syscalls)");

        const rc = linux.socket(
            linux.AF.NETLINK,
            linux.SOCK.RAW | linux.SOCK.CLOEXEC,
            linux.NETLINK.ROUTE,
        );
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .ACCES, .PERM => return error.AccessDenied,
            .AFNOSUPPORT, .PROTONOSUPPORT => return error.ProtocolNotSupported,
            .MFILE => return error.ProcessFdQuotaExceeded,
            .NFILE => return error.SystemFdQuotaExceeded,
            .NOBUFS, .NOMEM => return error.SystemResources,
            else => return error.Unexpected,
        }
        const fd: i32 = @intCast(rc);
        errdefer _ = linux.close(fd);

        // pid 0 = let the kernel assign a unique port id.
        const sa: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
        switch (linux.errno(linux.bind(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.nl)))) {
            .SUCCESS => {},
            .NOBUFS, .NOMEM => return error.SystemResources,
            else => return error.Unexpected,
        }
        var bound: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
        var blen: linux.socklen_t = @sizeOf(linux.sockaddr.nl);
        switch (linux.errno(linux.getsockname(fd, @ptrCast(&bound), &blen))) {
            .SUCCESS => {},
            else => return error.Unexpected,
        }

        // Ask for extended ACKs so a rejected write carries the kernel's
        // reason string. Best-effort: pre-4.12 kernels answer ENOPROTOOPT and
        // everything else keeps working, just without the message.
        const on: u32 = 1;
        _ = linux.setsockopt(
            fd,
            linux.SOL.NETLINK,
            NETLINK_EXT_ACK,
            @ptrCast(&on),
            @sizeOf(u32),
        );

        const buf = try gpa.alloc(u8, initial_recv_buf_len);
        return .{ .gpa = gpa, .fd = fd, .portid = bound.pid, .seq = 0, .buf = buf };
    }

    pub fn close(self: *Socket) void {
        self.gpa.free(self.buf);
        _ = linux.close(self.fd);
        self.* = undefined;
    }

    /// Dump all network interfaces.
    pub fn links(self: *Socket) DumpError![]Link {
        return self.dump(Link, parseLink, matchLink, RTM_GETLINK, RTM_NEWLINK, ifinfomsg_len, .{});
    }

    /// Dump interface addresses, optionally scoped (see `Filter`).
    pub fn addresses(self: *Socket, filter: Filter) DumpError![]Address {
        return self.dump(Address, parseAddress, matchAddress, RTM_GETADDR, RTM_NEWADDR, ifaddrmsg_len, filter);
    }

    /// Dump routing-table entries, optionally scoped (`Filter.ifindex`
    /// matches the output interface).
    pub fn routes(self: *Socket, filter: Filter) DumpError![]Route {
        return self.dump(Route, parseRoute, matchRoute, RTM_GETROUTE, RTM_NEWROUTE, rtmsg_len, filter);
    }

    /// Dump the neighbor (ARP/NDP) table, optionally scoped.
    pub fn neighbors(self: *Socket, filter: Filter) DumpError![]Neighbor {
        return self.dump(Neighbor, parseNeighbor, matchNeighbor, RTM_GETNEIGH, RTM_NEWNEIGH, ndmsg_len, filter);
    }

    // ── write ops (RTM_NEW*/RTM_DEL*; all need CAP_NET_ADMIN) ───────────────
    // Each builds one request, sends it with NLM_F_ACK and waits for the
    // NLMSG_ERROR reply: errno 0 = success, anything else = a typed error
    // (plus the kernel's reason string in `lastErrorMessage`).

    /// Add an IPv4/IPv6 address to an interface (`RTM_NEWADDR`).
    pub fn addressAdd(self: *Socket, spec: AddressSpec, opts: Create) WriteError!void {
        return self.writeOp(try buildAddressRequest(
            self.gpa,
            self.nextSeq(),
            RTM_NEWADDR,
            opts.flags(),
            spec,
        ));
    }

    /// Remove an address from an interface (`RTM_DELADDR`). Only `ifindex`,
    /// `local`/`peer` and `prefixlen` are matched by the kernel.
    pub fn addressDel(self: *Socket, spec: AddressSpec) WriteError!void {
        return self.writeOp(try buildAddressRequest(
            self.gpa,
            self.nextSeq(),
            RTM_DELADDR,
            codec.NLM_F_REQUEST | codec.NLM_F_ACK,
            spec,
        ));
    }

    /// Install a route (`RTM_NEWROUTE`).
    pub fn routeAdd(self: *Socket, spec: RouteSpec, opts: Create) WriteError!void {
        return self.writeOp(try buildRouteRequest(
            self.gpa,
            self.nextSeq(),
            RTM_NEWROUTE,
            opts.flags(),
            spec,
        ));
    }

    /// Remove a route (`RTM_DELROUTE`); the kernel matches on
    /// family/dst/prefixlen plus whatever else the spec pins down.
    pub fn routeDel(self: *Socket, spec: RouteSpec) WriteError!void {
        return self.writeOp(try buildRouteRequest(
            self.gpa,
            self.nextSeq(),
            RTM_DELROUTE,
            codec.NLM_F_REQUEST | codec.NLM_F_ACK,
            spec,
        ));
    }

    /// Change an existing interface: admin up/down, MTU, name, MAC, txqlen
    /// (`RTM_NEWLINK` without `NLM_F_CREATE`). See `LinkChange` for the
    /// `ifi_change` mask rules.
    pub fn linkSet(self: *Socket, ifindex: u32, change: LinkChange) WriteError!void {
        return self.writeOp(try buildLinkSetRequest(self.gpa, self.nextSeq(), ifindex, change));
    }

    /// Admin-up an interface — `linkSet(ifindex, .{ .up = true })`.
    pub fn linkUp(self: *Socket, ifindex: u32) WriteError!void {
        return self.linkSet(ifindex, .{ .up = true });
    }

    /// Admin-down an interface — `linkSet(ifindex, .{ .up = false })`.
    pub fn linkDown(self: *Socket, ifindex: u32) WriteError!void {
        return self.linkSet(ifindex, .{ .up = false });
    }

    /// Create a virtual device of the given kind ("dummy", "veth", "bridge",
    /// "vlan"…) — `RTM_NEWLINK` with `NLM_F_CREATE` + `IFLA_LINKINFO`.
    /// Kind-specific `IFLA_INFO_DATA` payloads are out of scope for now.
    pub fn linkAdd(self: *Socket, spec: LinkAddSpec, opts: Create) WriteError!void {
        return self.writeOp(try buildLinkAddRequest(
            self.gpa,
            self.nextSeq(),
            opts.flags(),
            spec,
        ));
    }

    /// Delete an interface by index (`RTM_DELLINK`) — virtual devices only;
    /// the kernel answers EOPNOTSUPP (`error.NotSupported`) for real NICs.
    pub fn linkDel(self: *Socket, ifindex: u32) WriteError!void {
        return self.writeOp(try buildLinkDelRequest(self.gpa, self.nextSeq(), ifindex));
    }

    /// Add a neighbour (ARP/NDP) entry (`RTM_NEWNEIGH`).
    pub fn neighborAdd(self: *Socket, spec: NeighborSpec, opts: Create) WriteError!void {
        return self.writeOp(try buildNeighborRequest(
            self.gpa,
            self.nextSeq(),
            RTM_NEWNEIGH,
            opts.flags(),
            spec,
        ));
    }

    /// Remove a neighbour entry (`RTM_DELNEIGH`).
    pub fn neighborDel(self: *Socket, spec: NeighborSpec) WriteError!void {
        return self.writeOp(try buildNeighborRequest(
            self.gpa,
            self.nextSeq(),
            RTM_DELNEIGH,
            codec.NLM_F_REQUEST | codec.NLM_F_ACK,
            spec,
        ));
    }

    // ── AF_BRIDGE ops (see bridge.zig for the wire encoding) ────────────────

    /// Create a bridge device (`RTM_NEWLINK` + `IFLA_INFO_KIND = "bridge"`),
    /// optionally setting the `IFLA_BR_*` options in the same request. Delete
    /// it again with `linkDel`.
    pub fn bridgeAdd(self: *Socket, spec: BridgeSpec, opts: Create) BridgeWriteError!void {
        return self.writeOpBridge(try bridge.buildBridgeAddRequest(
            self.gpa,
            self.nextSeq(),
            opts.flags(),
            spec,
        ));
    }

    /// Enslave an interface to a bridge (or bond) — `IFLA_MASTER`.
    pub fn portEnslave(self: *Socket, ifindex: u32, master: u32) WriteError!void {
        return self.linkSet(ifindex, .{ .master = master });
    }

    /// Detach an interface from its bridge (`ip link set … nomaster`).
    pub fn portRelease(self: *Socket, ifindex: u32) WriteError!void {
        return self.linkSet(ifindex, .{ .master = 0 });
    }

    /// Add a forwarding-database entry (`RTM_NEWNEIGH`, `ndm_family =
    /// AF_BRIDGE`) — the `bridge fdb add` operation.
    pub fn fdbAdd(self: *Socket, spec: FdbSpec, opts: Create) BridgeWriteError!void {
        return self.writeOpBridge(try bridge.buildFdbRequest(
            self.gpa,
            self.nextSeq(),
            RTM_NEWNEIGH,
            opts.flags(),
            spec,
        ));
    }

    /// Remove a forwarding-database entry (`RTM_DELNEIGH`). The kernel matches
    /// on ifindex + MAC + VLAN; the rest of the spec is ignored.
    pub fn fdbDel(self: *Socket, spec: FdbSpec) BridgeWriteError!void {
        return self.writeOpBridge(try bridge.buildFdbRequest(
            self.gpa,
            self.nextSeq(),
            RTM_DELNEIGH,
            codec.NLM_F_REQUEST | codec.NLM_F_ACK,
            spec,
        ));
    }

    /// Dump the bridge forwarding database (`bridge fdb show`). Both filters
    /// are applied kernel-side. Free the result with `gpa.free(entries)`.
    pub fn fdbEntries(self: *Socket, filter: FdbFilter) DumpError![]FdbEntry {
        const req = bridge.buildFdbDumpRequest(self.gpa, self.nextSeq(), filter) catch
            return error.OutOfMemory;
        defer self.gpa.free(req);
        return self.dumpCollect(FdbEntry, collectFdb, req, RTM_NEWNEIGH);
    }

    /// Add a VLAN — or an inclusive VID range — to a bridge port
    /// (`bridge vlan add`). Requires `vlan_filtering` on the bridge.
    pub fn bridgeVlanAdd(self: *Socket, ifindex: u32, spec: VlanSpec) BridgeWriteError!void {
        return self.writeOpBridge(try bridge.buildVlanRequest(
            self.gpa,
            self.nextSeq(),
            RTM_SETLINK,
            ifindex,
            spec,
        ));
    }

    /// Remove a VLAN (or VID range) from a bridge port (`bridge vlan del`).
    pub fn bridgeVlanDel(self: *Socket, ifindex: u32, spec: VlanSpec) BridgeWriteError!void {
        return self.writeOpBridge(try bridge.buildVlanRequest(
            self.gpa,
            self.nextSeq(),
            RTM_DELLINK,
            ifindex,
            spec,
        ));
    }

    /// Dump per-port VLAN configuration (`bridge vlan show`) — `RTM_GETLINK`
    /// with `IFLA_EXT_MASK = RTEXT_FILTER_BRVLAN`, decoding `IFLA_AF_SPEC`.
    /// `Filter.ifindex` scopes the result client-side; `Filter.family` is
    /// ignored (the dump is AF_BRIDGE by construction).
    pub fn bridgeVlans(self: *Socket, filter: Filter) DumpError![]VlanEntry {
        const req = bridge.buildVlanDumpRequest(
            self.gpa,
            self.nextSeq(),
            bridge.RTEXT_FILTER.BRVLAN,
        ) catch return error.OutOfMemory;
        defer self.gpa.free(req);
        const all = try self.dumpCollect(VlanEntry, collectVlans, req, RTM_NEWLINK);
        const want = filter.ifindex orelse return all;
        defer self.gpa.free(all);
        var kept: std.ArrayList(VlanEntry) = .empty;
        errdefer kept.deinit(self.gpa);
        for (all) |v| if (v.ifindex == want) try kept.append(self.gpa, v);
        return kept.toOwnedSlice(self.gpa);
    }

    /// Change bridge-port options (`bridge link set`) — STP state, learning,
    /// flooding, isolation… `RTM_SETLINK` with a nested `IFLA_PROTINFO`.
    pub fn brportSet(self: *Socket, ifindex: u32, change: BrportChange) BridgeWriteError!void {
        return self.writeOpBridge(try bridge.buildBrportRequest(
            self.gpa,
            self.nextSeq(),
            ifindex,
            change,
        ));
    }

    /// Read one interface's bridge-port state (`IFLA_MASTER` + the
    /// `IFLA_BRPORT_*` block). Null when the interface is not a bridge port
    /// or does not exist. Implemented over the plain link dump, so it needs
    /// no privilege.
    pub fn brportInfo(self: *Socket, ifindex: u32) DumpError!?BrportInfo {
        const ports = try self.brportInfos();
        defer self.gpa.free(ports);
        for (ports) |p| if (p.ifindex == ifindex) return p;
        return null;
    }

    /// Every bridge port on the system with its `IFLA_BRPORT_*` state — the
    /// `bridge link show` dump. Free with `gpa.free(ports)`.
    pub fn brportInfos(self: *Socket) DumpError![]BrportInfo {
        const req = bridge.buildBrportDumpRequest(self.gpa, self.nextSeq()) catch
            return error.OutOfMemory;
        defer self.gpa.free(req);
        return self.dumpCollect(BrportInfo, collectBrport, req, RTM_NEWLINK);
    }

    /// The kernel's reason for the last failed write, from the extended ACK
    /// (`NLMSGERR_ATTR_MSG`) — e.g. "Unknown device type". Empty when the
    /// kernel attached none (pre-4.12 kernel, or an errno with no message).
    /// Valid until the next request on this socket.
    pub fn lastErrorMessage(self: *const Socket) []const u8 {
        return self.ext_ack_buf[0..self.ext_ack_len];
    }

    /// Allocate the next sequence number. Public so sibling modules that build
    /// their own rtnetlink messages (tc, conntrack…) can drive `requestAck`.
    pub fn nextSeq(self: *Socket) u32 {
        self.seq +%= 1;
        if (self.seq == 0) self.seq = 1;
        return self.seq;
    }

    /// Send a fully-built request (which must carry `seq` and `NLM_F_ACK`) and
    /// wait for its ACK. The generic write+ACK engine behind every op above.
    pub fn requestAck(self: *Socket, request: []const u8, seq: u32) RequestError!void {
        try self.send(request);
        return self.awaitAck(seq);
    }

    /// Send an owned request buffer, await its ACK, then free it.
    fn writeOp(self: *Socket, request: []u8) WriteError!void {
        defer self.gpa.free(request);
        // The seq was taken from `nextSeq` when the request was built, and no
        // other request can have been sent in between (one Socket per thread).
        return self.requestAck(request, self.seq);
    }

    /// `writeOp` for the bridge ops — same engine, wider build-error set.
    fn writeOpBridge(self: *Socket, request: []u8) BridgeWriteError!void {
        defer self.gpa.free(request);
        return self.requestAck(request, self.seq);
    }

    /// Wait for the `NLMSG_ERROR` reply to `seq`: errno 0 = ACK (success),
    /// anything else = a mapped error. Replies for other ports/sequences (a
    /// stale dump, another process addressing our port id) are skipped;
    /// non-error messages carrying our seq (an `NLM_F_ECHO` copy) are ignored
    /// until the ACK itself arrives.
    fn awaitAck(self: *Socket, seq: u32) RequestError!void {
        self.ext_ack_len = 0;
        while (true) {
            const dgram = try self.recvDatagram();
            var it: codec.MessageIterator = .{ .buf = dgram };
            while (it.next() catch return error.MalformedReply) |m| {
                if (m.pid != self.portid or m.seq != seq) continue;
                switch (m.type) {
                    codec.NLMSG_ERROR => {
                        const code = m.errorCode() catch return error.MalformedReply;
                        self.captureExtAck(m);
                        if (code == 0) return; // ACK
                        return writeErrorFromCode(code);
                    },
                    codec.NLMSG_OVERRUN => return error.SystemResources,
                    else => {}, // NOOP / echo — keep waiting for the ACK
                }
            }
        }
    }

    /// Copy the extended-ACK reason string (if any) out of the reply buffer,
    /// truncating at `ext_ack_msg_max`. Never fails: a malformed ext-ack just
    /// leaves the message empty — the errno mapping is what callers act on.
    fn captureExtAck(self: *Socket, m: codec.Message) void {
        self.ext_ack_len = 0;
        const msg = (m.errorMessage() catch return) orelse return;
        const n = @min(msg.len, self.ext_ack_buf.len);
        @memcpy(self.ext_ack_buf[0..n], msg[0..n]);
        self.ext_ack_len = n;
    }

    /// The dump engine: send NLM_F_REQUEST|NLM_F_DUMP, then assemble
    /// multi-part replies until NLMSG_DONE (or an NLMSG_ERROR mapped to a
    /// Zig error). Replies are matched on (portid, seq) — anything stale or
    /// foreign is skipped, which also self-heals the queue after an aborted
    /// earlier dump. NLM_F_DUMP_INTR restarts the dump with a fresh sequence
    /// number, mirroring libnl's NLE_DUMP_INTR handling.
    fn dump(
        self: *Socket,
        comptime T: type,
        comptime parseFn: fn ([]const u8) codec.Error!?T,
        comptime matchFn: fn (T, Filter) bool,
        msg_type: u16,
        reply_type: u16,
        fixed_len: usize,
        filter: Filter,
    ) DumpError![]T {
        var attempt: usize = 0;
        retry: while (true) {
            attempt += 1;
            const seq = try self.sendDumpRequest(msg_type, fixed_len, filter.family orelse AF.UNSPEC);
            var out: std.ArrayList(T) = .empty;
            errdefer out.deinit(self.gpa);
            while (true) {
                const dgram = try self.recvDatagram();
                var it: codec.MessageIterator = .{ .buf = dgram };
                while (it.next() catch return error.MalformedReply) |m| {
                    switch (codec.classifyDumpMessage(m, self.portid, seq)) {
                        .skip => {},
                        .restart => {
                            out.deinit(self.gpa);
                            if (attempt < max_dump_attempts) continue :retry;
                            return error.InconsistentDump;
                        },
                        .done => return out.toOwnedSlice(self.gpa),
                        .failed => |code| return errorFromCode(code),
                        .overrun => return error.SystemResources,
                        .malformed => return error.MalformedReply,
                        .record => |rec| {
                            if (rec.type != reply_type) continue;
                            const parsed = parseFn(rec.payload) catch return error.MalformedReply;
                            if (parsed) |item| if (matchFn(item, filter))
                                try out.append(self.gpa, item);
                        },
                    }
                }
            }
        }
    }

    /// The dump engine for pre-built requests, used by the AF_BRIDGE dumps
    /// whose request carries attributes (`NDA_MASTER`, `IFLA_EXT_MASK`) that
    /// `sendDumpRequest`'s bare fixed header cannot express. Same reply
    /// discipline as `dump`: match on (portid, seq), assemble multi-part
    /// replies until NLMSG_DONE, restart on NLM_F_DUMP_INTR with a fresh
    /// sequence number — patched into the caller's buffer, which is why
    /// `request` is mutable.
    ///
    /// Unlike `dump`, `collectFn` may append any number of items per message,
    /// which is what a VLAN dump needs (one message lists a whole port).
    fn dumpCollect(
        self: *Socket,
        comptime T: type,
        comptime collectFn: fn (std.mem.Allocator, *std.ArrayList(T), []const u8) DumpError!void,
        request: []u8,
        reply_type: u16,
    ) DumpError![]T {
        if (request.len < codec.header_len) return error.InvalidRequest;
        var seq = std.mem.readInt(u32, request[8..12], native_endian);
        var attempt: usize = 0;
        retry: while (true) {
            attempt += 1;
            try self.send(request);
            var out: std.ArrayList(T) = .empty;
            errdefer out.deinit(self.gpa);
            while (true) {
                const dgram = try self.recvDatagram();
                var it: codec.MessageIterator = .{ .buf = dgram };
                while (it.next() catch return error.MalformedReply) |m| {
                    switch (codec.classifyDumpMessage(m, self.portid, seq)) {
                        .skip => {},
                        .restart => {
                            out.deinit(self.gpa);
                            if (attempt >= max_dump_attempts) return error.InconsistentDump;
                            seq = self.nextSeq();
                            std.mem.writeInt(u32, request[8..12], seq, native_endian);
                            continue :retry;
                        },
                        .done => return out.toOwnedSlice(self.gpa),
                        .failed => |code| return errorFromCode(code),
                        .overrun => return error.SystemResources,
                        .malformed => return error.MalformedReply,
                        .record => |rec| {
                            if (rec.type != reply_type) continue;
                            try collectFn(self.gpa, &out, rec.payload);
                        },
                    }
                }
            }
        }
    }

    /// Emit one dump request: nlmsghdr + a zeroed fixed family header with
    /// only the family byte set (offset 0 in ifinfomsg/ifaddrmsg/rtmsg/ndmsg
    /// alike). Sending the full fixed header — not the 1-byte rtgenmsg some
    /// legacy dumpers use — keeps NETLINK_GET_STRICT_CHK kernels happy while
    /// remaining compatible with old ones (iproute2 does the same).
    fn sendDumpRequest(self: *Socket, msg_type: u16, fixed_len: usize, family: u8) DumpError!u32 {
        const seq = self.nextSeq();
        var req: [codec.header_len + ifinfomsg_len]u8 = @splat(0);
        const total = codec.header_len + fixed_len; // fixed headers are 4-aligned
        std.debug.assert(total <= req.len);
        std.mem.writeInt(u32, req[0..4], @intCast(total), native_endian);
        std.mem.writeInt(u16, req[4..6], msg_type, native_endian);
        std.mem.writeInt(u16, req[6..8], codec.NLM_F_REQUEST | codec.NLM_F_DUMP, native_endian);
        std.mem.writeInt(u32, req[8..12], seq, native_endian);
        // nlmsg_pid stays 0: the kernel routes replies by socket, and fills
        // the reply pid with our bound portid (libmnl requests do the same).
        req[codec.header_len] = family;

        try self.send(req[0..total]);
        return seq;
    }

    /// Send one complete, pre-built netlink message to the kernel (pid 0),
    /// retrying on EINTR.
    ///
    /// Together with `recvDatagram` this is the module's **raw transport
    /// seam**: it lets a caller drive a message type this module does not
    /// model (`tc`'s `RTM_GET*` dumps, a custom `RTM_*` request) over the same
    /// bound socket, instead of reaching for `handle()` and re-implementing
    /// the syscall loops. Sequence numbers come from `nextSeq`; the reply
    /// triage is `codec.classifyDumpMessage`.
    pub fn send(self: *Socket, msg: []const u8) SendError!void {
        const dst: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
        while (true) {
            const rc = linux.sendto(self.fd, msg.ptr, msg.len, 0, @ptrCast(&dst), @sizeOf(linux.sockaddr.nl));
            switch (linux.errno(rc)) {
                .SUCCESS => return,
                .INTR => continue,
                .NOBUFS, .NOMEM => return error.SystemResources,
                .ACCES, .PERM => return error.AccessDenied,
                else => return error.SendFailed,
            }
        }
    }

    /// Receive one whole datagram, growing `self.buf` as needed: a
    /// MSG_PEEK|MSG_TRUNC probe reports the true datagram size without
    /// consuming it, so nothing is ever lost to truncation. Datagrams not
    /// sent by the kernel (sender pid != 0) are dropped — rtnetlink answers
    /// only ever come from the kernel, and any user process may address our
    /// port id.
    ///
    /// The returned slice borrows this socket's receive buffer and stays valid
    /// only until the next call on the socket. The other half of the raw
    /// transport seam — see `send`.
    pub fn recvDatagram(self: *Socket) RecvError![]const u8 {
        while (true) {
            const prc = linux.recvfrom(
                self.fd,
                self.buf.ptr,
                self.buf.len,
                linux.MSG.PEEK | linux.MSG.TRUNC,
                null,
                null,
            );
            switch (linux.errno(prc)) {
                .SUCCESS => {},
                .INTR => continue,
                .NOBUFS, .NOMEM => return error.SystemResources,
                else => return error.RecvFailed,
            }
            if (prc > self.buf.len) {
                if (prc > max_recv_buf_len) return error.MalformedReply;
                const new_len = std.mem.alignForward(usize, prc, initial_recv_buf_len);
                self.buf = self.gpa.realloc(self.buf, new_len) catch return error.OutOfMemory;
                continue; // re-probe; the datagram is still queued
            }

            var src: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
            var slen: linux.socklen_t = @sizeOf(linux.sockaddr.nl);
            const rc = linux.recvfrom(self.fd, self.buf.ptr, self.buf.len, 0, @ptrCast(&src), &slen);
            switch (linux.errno(rc)) {
                .SUCCESS => {},
                .INTR => continue,
                .NOBUFS, .NOMEM => return error.SystemResources,
                else => return error.RecvFailed,
            }
            if (slen >= @sizeOf(linux.sockaddr.nl) and src.pid != 0) continue; // not the kernel
            return self.buf[0..rc];
        }
    }
};

// ── AF_BRIDGE dump collectors (glue between `dumpCollect` and `bridge`) ─────

fn collectFdb(
    gpa: std.mem.Allocator,
    out: *std.ArrayList(FdbEntry),
    payload: []const u8,
) DumpError!void {
    const e = bridge.parseFdb(payload) catch return error.MalformedReply;
    if (e) |entry| try out.append(gpa, entry);
}

fn collectVlans(
    gpa: std.mem.Allocator,
    out: *std.ArrayList(VlanEntry),
    payload: []const u8,
) DumpError!void {
    bridge.parseVlans(gpa, out, payload) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedReply,
    };
}

fn collectBrport(
    gpa: std.mem.Allocator,
    out: *std.ArrayList(BrportInfo),
    payload: []const u8,
) DumpError!void {
    const p = bridge.parseBrport(payload) catch return error.MalformedReply;
    if (p) |info| try out.append(gpa, info);
}

// ── offline tests: parsers over canned buffers ──────────────────────────────

const testing = std.testing;

// Build a canned RTM_NEW* payload: fixed header bytes + encoded attributes.
fn cannedPayload(
    gpa: std.mem.Allocator,
    fixed: []const u8,
    comptime build: fn (std.mem.Allocator, *std.ArrayList(u8)) anyerror!void,
) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    try codec.appendPadded(gpa, &list, fixed);
    try build(gpa, &list);
    return list.toOwnedSlice(gpa);
}

test "parseLink: canned lo message" {
    const fixed = blk: {
        var f: [ifinfomsg_len]u8 = @splat(0);
        std.mem.writeInt(u16, f[2..4], 772, native_endian); // ARPHRD_LOOPBACK
        std.mem.writeInt(i32, f[4..8], 1, native_endian); // index
        std.mem.writeInt(u32, f[8..12], IFF.UP | IFF.LOOPBACK | IFF.RUNNING, native_endian);
        break :blk f;
    };
    const payload = try cannedPayload(testing.allocator, &fixed, struct {
        fn build(gpa: std.mem.Allocator, list: *std.ArrayList(u8)) !void {
            try codec.appendAttrString(gpa, list, ifla_ifname, "lo");
            try codec.appendAttrU32(gpa, list, ifla_mtu, 65536);
            try codec.appendAttr(gpa, list, ifla_address, &(.{0} ** 6));
            try codec.appendAttrU32(gpa, list, 999, 1); // unknown attr — ignored
        }
    }.build);
    defer testing.allocator.free(payload);

    const l = (try parseLink(payload)).?;
    try testing.expectEqual(@as(u32, 1), l.index);
    try testing.expectEqualStrings("lo", l.name());
    try testing.expectEqual(@as(u32, 65536), l.mtu);
    try testing.expectEqual(@as(u16, 772), l.hw_type);
    try testing.expect(l.flags & IFF.LOOPBACK != 0);
    try testing.expectEqual([6]u8{ 0, 0, 0, 0, 0, 0 }, l.mac.?);
}

test "parseLink: truncated fixed header and hostile attrs error out" {
    try testing.expectError(error.Truncated, parseLink(&[_]u8{0} ** 8));
    // Attr whose declared length overruns the payload.
    var bad: [ifinfomsg_len + 4]u8 = @splat(0);
    std.mem.writeInt(u16, bad[ifinfomsg_len..][0..2], 200, native_endian);
    std.mem.writeInt(u16, bad[ifinfomsg_len + 2 ..][0..2], ifla_mtu, native_endian);
    try testing.expectError(error.Truncated, parseLink(&bad));
    // MTU attribute with the wrong scalar size.
    var short: [ifinfomsg_len + 8]u8 = @splat(0);
    std.mem.writeInt(u16, short[ifinfomsg_len..][0..2], 6, native_endian);
    std.mem.writeInt(u16, short[ifinfomsg_len + 2 ..][0..2], ifla_mtu, native_endian);
    try testing.expectError(error.BadLength, parseLink(&short));
}

test "parseAddress: IFA_LOCAL preferred over IFA_ADDRESS, label kept" {
    var fixed: [ifaddrmsg_len]u8 = @splat(0);
    fixed[0] = AF.INET;
    fixed[1] = 8; // prefixlen
    fixed[3] = RT_SCOPE.HOST;
    std.mem.writeInt(u32, fixed[4..8], 1, native_endian); // ifindex
    const payload = try cannedPayload(testing.allocator, &fixed, struct {
        fn build(gpa: std.mem.Allocator, list: *std.ArrayList(u8)) !void {
            try codec.appendAttr(gpa, list, ifa_address, &.{ 10, 0, 0, 2 }); // peer
            try codec.appendAttr(gpa, list, ifa_local, &.{ 127, 0, 0, 1 });
            try codec.appendAttrString(gpa, list, ifa_label, "lo");
        }
    }.build);
    defer testing.allocator.free(payload);

    const a = (try parseAddress(payload)).?;
    try testing.expectEqual(AF.INET, a.family);
    try testing.expectEqual(@as(u8, 8), a.prefixlen);
    try testing.expectEqual(@as(u32, 1), a.ifindex);
    try testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, a.bytes());
    try testing.expectEqualStrings("lo", a.label());
}

test "parseAddress: IFA_ADDRESS fallback, and null when no address" {
    var fixed: [ifaddrmsg_len]u8 = @splat(0);
    fixed[0] = AF.INET6;
    fixed[1] = 128;
    const v6 = try cannedPayload(testing.allocator, &fixed, struct {
        fn build(gpa: std.mem.Allocator, list: *std.ArrayList(u8)) !void {
            const loopback6 = [_]u8{0} ** 15 ++ [_]u8{1};
            try codec.appendAttr(gpa, list, ifa_address, &loopback6);
        }
    }.build);
    defer testing.allocator.free(v6);
    const a = (try parseAddress(v6)).?;
    try testing.expectEqual(@as(u8, 16), a.addr_len);
    try testing.expectEqual(@as(u8, 1), a.bytes()[15]);

    // Entry with no address attribute at all is skipped (null).
    try testing.expectEqual(@as(?Address, null), try parseAddress(&fixed));
}

test "parseRoute: default route + RTA_TABLE override" {
    var fixed: [rtmsg_len]u8 = @splat(0);
    fixed[0] = AF.INET;
    fixed[4] = @intCast(RT_TABLE.COMPAT); // rtm_table, overridden by attr
    fixed[5] = 3; // RTPROT_BOOT
    fixed[7] = RTN.UNICAST;
    const payload = try cannedPayload(testing.allocator, &fixed, struct {
        fn build(gpa: std.mem.Allocator, list: *std.ArrayList(u8)) !void {
            try codec.appendAttr(gpa, list, RTA.GATEWAY, &.{ 192, 168, 1, 1 });
            try codec.appendAttrU32(gpa, list, RTA.OIF, 2);
            try codec.appendAttrU32(gpa, list, RTA.PRIORITY, 100);
            try codec.appendAttrU32(gpa, list, RTA.TABLE, RT_TABLE.MAIN);
        }
    }.build);
    defer testing.allocator.free(payload);

    const r = (try parseRoute(payload)).?;
    try testing.expectEqual(AF.INET, r.family);
    try testing.expectEqual(@as(u8, 0), r.dst_prefixlen);
    try testing.expectEqual(@as(u8, 0), r.dst_len); // default route: no RTA_DST
    try testing.expectEqualSlices(u8, &.{ 192, 168, 1, 1 }, r.gatewayBytes());
    try testing.expectEqual(@as(u32, 2), r.oif);
    try testing.expectEqual(@as(u32, 100), r.priority);
    try testing.expectEqual(RT_TABLE.MAIN, r.table);
    try testing.expectEqual(RTN.UNICAST, r.rtype);
}

test "parseNeighbor: dst + lladdr + state" {
    var fixed: [ndmsg_len]u8 = @splat(0);
    fixed[0] = AF.INET;
    std.mem.writeInt(i32, fixed[4..8], 2, native_endian); // ifindex
    std.mem.writeInt(u16, fixed[8..10], NUD.REACHABLE, native_endian);
    const payload = try cannedPayload(testing.allocator, &fixed, struct {
        fn build(gpa: std.mem.Allocator, list: *std.ArrayList(u8)) !void {
            try codec.appendAttr(gpa, list, NDA.DST, &.{ 192, 168, 1, 254 });
            try codec.appendAttr(gpa, list, NDA.LLADDR, &.{ 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01 });
        }
    }.build);
    defer testing.allocator.free(payload);

    const n = (try parseNeighbor(payload)).?;
    try testing.expectEqual(AF.INET, n.family);
    try testing.expectEqual(@as(u32, 2), n.ifindex);
    try testing.expectEqual(NUD.REACHABLE, n.state);
    try testing.expectEqualSlices(u8, &.{ 192, 168, 1, 254 }, n.dstBytes());
    try testing.expectEqualSlices(u8, &.{ 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01 }, n.lladdrBytes());
}

test "filters: family and ifindex predicates" {
    const a: Address = .{ .family = AF.INET, .prefixlen = 8, .scope = 0, .flags = 0, .ifindex = 1 };
    try testing.expect(matchAddress(a, .{}));
    try testing.expect(matchAddress(a, .{ .family = AF.INET }));
    try testing.expect(!matchAddress(a, .{ .family = AF.INET6 }));
    try testing.expect(matchAddress(a, .{ .ifindex = 1 }));
    try testing.expect(!matchAddress(a, .{ .family = AF.INET, .ifindex = 9 }));

    const r: Route = .{ .family = AF.INET6, .dst_prefixlen = 0, .protocol = 0, .scope = 0, .rtype = 0, .table = 254, .oif = 3 };
    try testing.expect(matchRoute(r, .{ .family = AF.INET6, .ifindex = 3 }));
    try testing.expect(!matchRoute(r, .{ .ifindex = 4 }));

    const n: Neighbor = .{ .family = AF.INET, .ifindex = 2, .state = NUD.STALE, .flags = 0, .ntype = 0 };
    try testing.expect(matchNeighbor(n, .{ .ifindex = 2 }));
    try testing.expect(!matchNeighbor(n, .{ .family = AF.INET6 }));
}

test "errorFromCode maps NLMSG_ERROR errnos" {
    try testing.expectEqual(error.AccessDenied, errorFromCode(-@as(i32, @intFromEnum(linux.E.PERM))));
    try testing.expectEqual(error.AccessDenied, errorFromCode(-@as(i32, @intFromEnum(linux.E.ACCES))));
    try testing.expectEqual(error.InvalidRequest, errorFromCode(-@as(i32, @intFromEnum(linux.E.INVAL))));
    try testing.expectEqual(error.SystemResources, errorFromCode(-@as(i32, @intFromEnum(linux.E.NOBUFS))));
    try testing.expectEqual(error.Unexpected, errorFromCode(-9999));
    // Non-errors / degenerate values must not be misread.
    try testing.expectEqual(error.Unexpected, errorFromCode(0));
    try testing.expectEqual(error.Unexpected, errorFromCode(7));
    try testing.expectEqual(error.Unexpected, errorFromCode(std.math.minInt(i32)));
}

// ── byte-exact request construction ─────────────────────────────────────────
// The expected bytes below are the exact requests iproute2 puts on the wire,
// captured with
//   unshare -rn strace -f -e trace=sendmsg -xx -s 300 ip <cmd>
// on Linux 7.0 / iproute2, and cross-checked field-by-field against the kernel
// UAPI headers (linux/rtnetlink.h, linux/if_addr.h, linux/neighbour.h,
// linux/if_link.h). Each test cites the exact `ip` command it mirrors.

fn expectRequestBytes(actual: []const u8, expected: []const u8) !void {
    try testing.expectEqual(expected.len, actual.len);
    try testing.expectEqualSlices(u8, expected, actual);
    // The declared nlmsg_len must always match the real buffer length.
    try testing.expectEqual(
        @as(u32, @intCast(actual.len)),
        std.mem.readInt(u32, actual[0..4], native_endian),
    );
}

test "build: RTM_NEWADDR == `ip addr add 10.11.12.1/24 dev lo`" {
    if (native_endian != .little) return error.SkipZigTest; // golden bytes are LE
    const req = try buildAddressRequest(testing.allocator, 1, RTM_NEWADDR, (Create{}).flags(), .{
        .ifindex = 1,
        .local = &.{ 10, 11, 12, 1 },
        .prefixlen = 24,
    });
    defer testing.allocator.free(req);
    try expectRequestBytes(req, &.{
        0x28, 0x00, 0x00, 0x00, // nlmsg_len = 40
        0x14, 0x00, // nlmsg_type = RTM_NEWADDR (20)
        0x05, 0x06, // NLM_F_REQUEST|ACK|EXCL|CREATE = 0x0605
        0x01, 0x00, 0x00, 0x00, // nlmsg_seq
        0x00, 0x00, 0x00, 0x00, // nlmsg_pid
        0x02, 0x18, 0x00, 0x00, // ifaddrmsg: AF_INET, /24, flags 0, scope UNIVERSE
        0x01, 0x00, 0x00, 0x00, // ifa_index = 1
        0x08, 0x00, 0x02, 0x00, 10, 11, 12, 1, // IFA_LOCAL
        0x08, 0x00, 0x01, 0x00, 10, 11, 12, 1, // IFA_ADDRESS (repeats local)
    });
}

test "build: RTM_DELADDR drops CREATE/EXCL, keeps REQUEST|ACK" {
    if (native_endian != .little) return error.SkipZigTest;
    const req = try buildAddressRequest(
        testing.allocator,
        7,
        RTM_DELADDR,
        codec.NLM_F_REQUEST | codec.NLM_F_ACK,
        .{ .ifindex = 2, .local = &.{ 10, 11, 12, 1 }, .prefixlen = 24 },
    );
    defer testing.allocator.free(req);
    try testing.expectEqual(RTM_DELADDR, std.mem.readInt(u16, req[4..6], native_endian));
    try testing.expectEqual(
        @as(u16, codec.NLM_F_REQUEST | codec.NLM_F_ACK),
        std.mem.readInt(u16, req[6..8], native_endian),
    );
    try testing.expectEqual(@as(usize, 40), req.len);
}

test "build: IPv6 address with scope/flags/label/broadcast attributes" {
    const v6 = [_]u8{ 0xfd, 0, 0, 0 } ++ [_]u8{0} ** 11 ++ [_]u8{1};
    const req = try buildAddressRequest(testing.allocator, 1, RTM_NEWADDR, (Create{}).flags(), .{
        .ifindex = 3,
        .local = &v6,
        .prefixlen = 64,
        .scope = RT_SCOPE.UNIVERSE,
        .flags32 = IFA_F.NODAD | IFA_F.NOPREFIXROUTE,
    });
    defer testing.allocator.free(req);
    // 16 hdr + 8 ifaddrmsg + 2*(4+16) + (4+4) IFA_FLAGS = 72
    try testing.expectEqual(@as(usize, 72), req.len);
    try testing.expectEqual(AF.INET6, req[codec.header_len]);
    try testing.expectEqual(@as(u8, 64), req[codec.header_len + 1]);

    // Mixed families and bad lengths are rejected before any allocation.
    try testing.expectError(error.InvalidAddressLength, buildAddressRequest(
        testing.allocator,
        1,
        RTM_NEWADDR,
        0,
        .{ .ifindex = 1, .local = &.{ 1, 2, 3 }, .prefixlen = 24 },
    ));
    try testing.expectError(error.MixedFamilies, buildAddressRequest(
        testing.allocator,
        1,
        RTM_NEWADDR,
        0,
        .{ .ifindex = 1, .local = &.{ 10, 0, 0, 1 }, .prefixlen = 24, .peer = &v6 },
    ));
    try testing.expectError(error.InvalidName, buildAddressRequest(
        testing.allocator,
        1,
        RTM_NEWADDR,
        0,
        .{ .ifindex = 1, .local = &.{ 10, 0, 0, 1 }, .prefixlen = 24, .label = "an-interface-label-way-too-long" },
    ));
    // A prefix wider than the family allows never reaches the kernel.
    try testing.expectError(error.InvalidAddressLength, buildAddressRequest(
        testing.allocator,
        1,
        RTM_NEWADDR,
        0,
        .{ .ifindex = 1, .local = &.{ 10, 0, 0, 1 }, .prefixlen = 64 },
    ));
}

test "build: RTM_NEWROUTE == `ip route add 10.99.0.0/24 dev lo scope link`" {
    if (native_endian != .little) return error.SkipZigTest;
    const req = try buildRouteRequest(testing.allocator, 1, RTM_NEWROUTE, (Create{}).flags(), .{
        .dst = &.{ 10, 99, 0, 0 },
        .dst_prefixlen = 24,
        .oif = 1,
        .scope = RT_SCOPE.LINK,
    });
    defer testing.allocator.free(req);
    try expectRequestBytes(req, &.{
        0x2c, 0x00, 0x00, 0x00, // nlmsg_len = 44
        0x18, 0x00, // RTM_NEWROUTE (24)
        0x05, 0x06, // REQUEST|ACK|EXCL|CREATE
        0x01, 0x00, 0x00, 0x00, // nlmsg_seq
        0x00, 0x00, 0x00, 0x00, // nlmsg_pid
        // rtmsg: AF_INET, dst_len 24, src_len 0, tos 0,
        //        table MAIN(254), proto BOOT(3), scope LINK(253), type UNICAST(1)
        0x02, 0x18, 0x00, 0x00, // family/dst_len/src_len/tos
        0xfe, 0x03, 0xfd, 0x01, // table/protocol/scope/type
        0x00, 0x00, 0x00, 0x00, // rtm_flags
        0x08, 0x00, 0x01, 0x00, 10, 99, 0, 0, // RTA_DST
        0x08, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, // RTA_OIF
    });
}

test "build: RTM_NEWROUTE == `ip route add 10.98.0.0/24 via 10.11.12.9 dev lo`" {
    if (native_endian != .little) return error.SkipZigTest;
    const req = try buildRouteRequest(testing.allocator, 1, RTM_NEWROUTE, (Create{}).flags(), .{
        .dst = &.{ 10, 98, 0, 0 },
        .dst_prefixlen = 24,
        .gateway = &.{ 10, 11, 12, 9 },
        .oif = 1,
    });
    defer testing.allocator.free(req);
    try expectRequestBytes(req, &.{
        0x34, 0x00, 0x00, 0x00, // nlmsg_len = 52
        0x18, 0x00, 0x05, 0x06,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x02, 0x18, 0x00, 0x00,
        0xfe, 0x03, 0x00, 0x01, // scope UNIVERSE with a gateway
        0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x01, 0x00, 10, 98, 0, 0, // RTA_DST
        0x08, 0x00, 0x05, 0x00, 10, 11, 12, 9, // RTA_GATEWAY
        0x08, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, // RTA_OIF
    });
}

test "build: route table > 255 moves to RTA_TABLE, family derivation, validation" {
    const req = try buildRouteRequest(testing.allocator, 1, RTM_NEWROUTE, (Create{}).flags(), .{
        .dst = &.{ 10, 97, 0, 0 },
        .dst_prefixlen = 24,
        .oif = 2,
        .table = 1000,
        .priority = 100,
    });
    defer testing.allocator.free(req);
    try testing.expectEqual(@as(u8, @intCast(RT_TABLE.UNSPEC)), req[codec.header_len + 4]);
    var it: codec.AttrIterator = .{ .buf = req[codec.header_len + rtmsg_len ..] };
    var saw_table = false;
    var saw_priority = false;
    while (try it.next()) |a| switch (a.type) {
        RTA.TABLE => {
            saw_table = true;
            try testing.expectEqual(@as(u32, 1000), try a.asU32());
        },
        RTA.PRIORITY => {
            saw_priority = true;
            try testing.expectEqual(@as(u32, 100), try a.asU32());
        },
        else => {},
    };
    try testing.expect(saw_table and saw_priority);

    // A default route with no addresses at all cannot imply a family.
    try testing.expectError(error.FamilyRequired, buildRouteRequest(
        testing.allocator,
        1,
        RTM_NEWROUTE,
        0,
        .{},
    ));
    // …but an explicit family (blackhole default route) is fine.
    const bh = try buildRouteRequest(testing.allocator, 1, RTM_NEWROUTE, 0, .{
        .family = AF.INET6,
        .rtype = RTN.BLACKHOLE,
    });
    defer testing.allocator.free(bh);
    try testing.expectEqual(@as(usize, codec.header_len + rtmsg_len), bh.len);
    try testing.expectEqual(RTN.BLACKHOLE, bh[codec.header_len + 7]);
    // A prefix length beyond the family's width is rejected.
    try testing.expectError(error.InvalidAddressLength, buildRouteRequest(
        testing.allocator,
        1,
        RTM_NEWROUTE,
        0,
        .{ .dst = &.{ 10, 0, 0, 0 }, .dst_prefixlen = 64 },
    ));
    // Gateway of a different family than the destination.
    try testing.expectError(error.MixedFamilies, buildRouteRequest(
        testing.allocator,
        1,
        RTM_NEWROUTE,
        0,
        .{ .dst = &.{ 10, 0, 0, 0 }, .dst_prefixlen = 8, .gateway = &([_]u8{0} ** 16) },
    ));
}

test "build: RTM_NEWLINK admin up == `ip link set lo up` (ifi_change = IFF_UP only)" {
    if (native_endian != .little) return error.SkipZigTest;
    const up = try buildLinkSetRequest(testing.allocator, 1, 1, .{ .up = true });
    defer testing.allocator.free(up);
    try expectRequestBytes(up, &.{
        0x20, 0x00, 0x00, 0x00, // nlmsg_len = 32
        0x10, 0x00, // RTM_NEWLINK (16) — no NLM_F_CREATE for a change
        0x05, 0x00, // REQUEST|ACK
        0x01, 0x00, 0x00, 0x00, // nlmsg_seq
        0x00, 0x00, 0x00, 0x00, // nlmsg_pid
        0x00, 0x00, 0x00, 0x00, // ifinfomsg: family AF_UNSPEC, pad, type 0
        0x01, 0x00, 0x00, 0x00, // ifi_index = 1
        0x01, 0x00, 0x00, 0x00, // ifi_flags = IFF_UP
        0x01, 0x00, 0x00, 0x00, // ifi_change = IFF_UP  ← only the bit we touch
    });

    // Down = same mask, cleared value. Never 0xffffffff, which would apply
    // every IFF_* bit in ifi_flags at once.
    const down = try buildLinkSetRequest(testing.allocator, 1, 1, .{ .up = false });
    defer testing.allocator.free(down);
    try testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, down[24..28], native_endian));
    try testing.expectEqual(IFF.UP, std.mem.readInt(u32, down[28..32], native_endian));
}

test "build: link MTU/name/mac change leaves ifi_change empty" {
    if (native_endian != .little) return error.SkipZigTest;
    const req = try buildLinkSetRequest(testing.allocator, 1, 4, .{
        .mtu = 1400,
        .name = "eth9",
        .mac = &.{ 0x02, 0, 0, 0, 0, 1 },
        .txqlen = 500,
    });
    defer testing.allocator.free(req);
    // No flag bit was requested → no IFF_* is touched at all.
    try testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, req[24..28], native_endian));
    try testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, req[28..32], native_endian));
    var it: codec.AttrIterator = .{ .buf = req[codec.header_len + ifinfomsg_len ..] };
    try testing.expectEqual(@as(u32, 1400), try (try it.next()).?.asU32()); // IFLA_MTU
    try testing.expectEqual(@as(u32, 500), try (try it.next()).?.asU32()); // IFLA_TXQLEN
    try testing.expectEqualSlices(u8, &.{ 0x02, 0, 0, 0, 0, 1 }, (try it.next()).?.data);
    try testing.expectEqualStrings("eth9", (try it.next()).?.asString());

    // The raw escape hatch only ever sets the bits the caller listed.
    const promisc = try buildLinkSetRequest(testing.allocator, 1, 4, .{
        .flags = IFF.PROMISC,
        .flags_mask = IFF.PROMISC,
        .up = true,
    });
    defer testing.allocator.free(promisc);
    try testing.expectEqual(IFF.PROMISC | IFF.UP, std.mem.readInt(u32, promisc[24..28], native_endian));
    try testing.expectEqual(IFF.PROMISC | IFF.UP, std.mem.readInt(u32, promisc[28..32], native_endian));

    // A request that would change nothing is refused, not sent as a no-op.
    try testing.expectError(error.NothingToChange, buildLinkSetRequest(testing.allocator, 1, 4, .{}));
    try testing.expectError(error.InvalidName, buildLinkSetRequest(
        testing.allocator,
        1,
        4,
        .{ .name = "an-interface-name-too-long" },
    ));
}

test "build: RTM_NEWLINK create == `ip link add name zdum0 type dummy`" {
    if (native_endian != .little) return error.SkipZigTest;
    const req = try buildLinkAddRequest(testing.allocator, 1, (Create{}).flags(), .{
        .name = "zdum0",
        .kind = "dummy",
    });
    defer testing.allocator.free(req);
    try expectRequestBytes(req, &.{
        0x3c, 0x00, 0x00, 0x00, // nlmsg_len = 60
        0x10, 0x00, // RTM_NEWLINK
        0x05, 0x06, // REQUEST|ACK|EXCL|CREATE
        0x01, 0x00, 0x00, 0x00, // nlmsg_seq
        0x00, 0x00, 0x00, 0x00, // nlmsg_pid
        0x00, 0x00, 0x00, 0x00, // ifinfomsg: family AF_UNSPEC, pad, type 0
        0x00, 0x00, 0x00, 0x00, // ifi_index = 0 (the kernel picks one)
        0x00, 0x00, 0x00, 0x00, // ifi_flags = 0 (device comes up DOWN)
        0x00, 0x00, 0x00, 0x00, // ifi_change = 0
        0x0a, 0x00, 0x03, 0x00, 'z', 'd', 'u', 'm', '0', 0x00, 0x00, 0x00, // IFLA_IFNAME
        0x10, 0x00, 0x12, 0x00, // IFLA_LINKINFO, len 16 (covers the inner pad)
        0x0a, 0x00, 0x01, 0x00, 'd', 'u', 'm', 'm', 'y', 0x00, 0x00, 0x00, // IFLA_INFO_KIND
    });

    // `up = true` sets both ifi_flags and ifi_change to exactly IFF_UP.
    const up = try buildLinkAddRequest(testing.allocator, 1, (Create{}).flags(), .{
        .name = "zdum1",
        .kind = "dummy",
        .up = true,
    });
    defer testing.allocator.free(up);
    try testing.expectEqual(IFF.UP, std.mem.readInt(u32, up[24..28], native_endian));
    try testing.expectEqual(IFF.UP, std.mem.readInt(u32, up[28..32], native_endian));
    try testing.expectError(error.InvalidName, buildLinkAddRequest(
        testing.allocator,
        1,
        0,
        .{ .name = "", .kind = "dummy" },
    ));
}

test "build: RTM_DELLINK == `ip link del zdum0`" {
    if (native_endian != .little) return error.SkipZigTest;
    const req = try buildLinkDelRequest(testing.allocator, 1, 2);
    defer testing.allocator.free(req);
    try expectRequestBytes(req, &.{
        0x20, 0x00, 0x00, 0x00, // nlmsg_len = 32
        0x11, 0x00, // RTM_DELLINK (17)
        0x05, 0x00, // REQUEST|ACK
        0x01, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x02, 0x00, 0x00, 0x00, // ifi_index = 2
        0x00, 0x00, 0x00, 0x00, // ifi_flags = 0
        0x00, 0x00, 0x00, 0x00, // ifi_change = 0
    });
}

test "build: IFLA_MASTER == `ip link set dev veth0 master br0` / `… nomaster`" {
    if (native_endian != .little) return error.SkipZigTest;
    const enslave = try buildLinkSetRequest(testing.allocator, 1, 4, .{ .master = 6 });
    defer testing.allocator.free(enslave);
    try expectRequestBytes(enslave, &.{
        0x28, 0x00, 0x00, 0x00, // nlmsg_len = 40
        0x10, 0x00, // RTM_NEWLINK (16)
        0x05, 0x00, // REQUEST|ACK
        0x01, 0x00, 0x00, 0x00, // nlmsg_seq
        0x00, 0x00, 0x00, 0x00, // nlmsg_pid
        0x00, 0x00, 0x00, 0x00, // ifinfomsg: AF_UNSPEC (not AF_BRIDGE here)
        0x04, 0x00, 0x00, 0x00, // ifi_index = 4
        0x00, 0x00, 0x00, 0x00, // ifi_flags = 0
        0x00, 0x00, 0x00, 0x00, // ifi_change = 0 — no IFF_* bit is touched
        0x08, 0x00, 0x0a, 0x00, 0x06, 0x00, 0x00, 0x00, // IFLA_MASTER = 6
    });

    // `nomaster` is the same message with IFLA_MASTER = 0 — and it must not
    // trip the "nothing to change" guard.
    const release = try buildLinkSetRequest(testing.allocator, 1, 4, .{ .master = 0 });
    defer testing.allocator.free(release);
    try testing.expectEqual(@as(usize, 40), release.len);
    try testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, release[36..40], native_endian));
}

test "build: RTM_NEWNEIGH == `ip neigh add … lladdr … dev lo nud permanent`" {
    if (native_endian != .little) return error.SkipZigTest;
    const req = try buildNeighborRequest(testing.allocator, 1, RTM_NEWNEIGH, (Create{}).flags(), .{
        .ifindex = 1,
        .dst = &.{ 10, 11, 12, 55 },
        .lladdr = &.{ 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01 },
    });
    defer testing.allocator.free(req);
    try expectRequestBytes(req, &.{
        0x30, 0x00, 0x00, 0x00, // nlmsg_len = 48
        0x1c, 0x00, // RTM_NEWNEIGH (28)
        0x05, 0x06, // REQUEST|ACK|EXCL|CREATE
        0x01, 0x00, 0x00, 0x00, // nlmsg_seq
        0x00, 0x00, 0x00, 0x00, // nlmsg_pid
        0x02, 0x00, 0x00, 0x00, // ndmsg: AF_INET + pads
        0x01, 0x00, 0x00, 0x00, // ndm_ifindex = 1
        0x80, 0x00, // ndm_state = NUD_PERMANENT
        0x00, // ndm_flags
        0x00, // ndm_type = RTN_UNSPEC
        0x08, 0x00, 0x01, 0x00, 10, 11, 12, 55, // NDA_DST
        0x0a, 0x00, 0x02, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x00, 0x00, // NDA_LLADDR
    });

    // Delete: same shape without the link-layer address.
    const del = try buildNeighborRequest(
        testing.allocator,
        2,
        RTM_DELNEIGH,
        codec.NLM_F_REQUEST | codec.NLM_F_ACK,
        .{ .ifindex = 1, .dst = &.{ 10, 11, 12, 55 } },
    );
    defer testing.allocator.free(del);
    try testing.expectEqual(@as(usize, 36), del.len);
    try testing.expectEqual(RTM_DELNEIGH, std.mem.readInt(u16, del[4..6], native_endian));
    try testing.expectError(error.InvalidAddressLength, buildNeighborRequest(
        testing.allocator,
        1,
        RTM_NEWNEIGH,
        0,
        .{ .ifindex = 1, .dst = &.{ 1, 2, 3, 4, 5 } },
    ));
}

test "build: Create option flags map onto NLM_F_* modifiers" {
    try testing.expectEqual(
        @as(u16, codec.NLM_F_REQUEST | codec.NLM_F_ACK | codec.NLM_F_CREATE | codec.NLM_F_EXCL),
        (Create{}).flags(),
    );
    try testing.expectEqual(
        @as(u16, codec.NLM_F_REQUEST | codec.NLM_F_ACK | codec.NLM_F_CREATE | codec.NLM_F_REPLACE),
        (Create{ .replace = true }).flags(),
    );
    // EXCL and REPLACE are mutually exclusive — replace wins.
    try testing.expectEqual(
        @as(u16, 0),
        (Create{ .replace = true, .exclusive = true }).flags() & codec.NLM_F_EXCL,
    );
    try testing.expectEqual(
        @as(u16, codec.NLM_F_REQUEST | codec.NLM_F_ACK | codec.NLM_F_CREATE | codec.NLM_F_APPEND),
        (Create{ .exclusive = false, .append = true }).flags(),
    );
}

test "writeErrorFromCode maps the write-path errnos" {
    try testing.expectEqual(error.AccessDenied, writeErrorFromCode(-@as(i32, @intFromEnum(linux.E.PERM))));
    try testing.expectEqual(error.Exists, writeErrorFromCode(-@as(i32, @intFromEnum(linux.E.EXIST))));
    try testing.expectEqual(error.NotFound, writeErrorFromCode(-@as(i32, @intFromEnum(linux.E.NOENT))));
    try testing.expectEqual(error.NoSuchDevice, writeErrorFromCode(-@as(i32, @intFromEnum(linux.E.NODEV))));
    try testing.expectEqual(
        error.AddressNotAvailable,
        writeErrorFromCode(-@as(i32, @intFromEnum(linux.E.ADDRNOTAVAIL))),
    );
    try testing.expectEqual(
        error.NetworkUnreachable,
        writeErrorFromCode(-@as(i32, @intFromEnum(linux.E.NETUNREACH))),
    );
    try testing.expectEqual(error.Busy, writeErrorFromCode(-@as(i32, @intFromEnum(linux.E.BUSY))));
    try testing.expectEqual(error.InvalidRequest, writeErrorFromCode(-@as(i32, @intFromEnum(linux.E.INVAL))));
    try testing.expectEqual(error.NotSupported, writeErrorFromCode(-@as(i32, @intFromEnum(linux.E.OPNOTSUPP))));
    try testing.expectEqual(error.SystemResources, writeErrorFromCode(-@as(i32, @intFromEnum(linux.E.NOMEM))));
    try testing.expectEqual(error.Unexpected, writeErrorFromCode(-9999));
    // Degenerate values must never be misread as a specific failure.
    try testing.expectEqual(error.Unexpected, writeErrorFromCode(0));
    try testing.expectEqual(error.Unexpected, writeErrorFromCode(7));
    try testing.expectEqual(error.Unexpected, writeErrorFromCode(std.math.minInt(i32)));
}

test "fuzz: request builders never crash on arbitrary spec bytes" {
    try testing.fuzz({}, fuzzBuilders, .{});
}

fn fuzzBuilders(_: void, smith: *std.testing.Smith) !void {
    var addr: [16]u8 = undefined;
    smith.bytes(&addr);
    const alen = smith.valueRangeAtMost(u8, 0, 16);
    const a = addr[0..alen];
    const prefix = smith.valueRangeAtMost(u8, 0, 255);
    const ifindex = smith.valueRangeAtMost(u32, 0, std.math.maxInt(u32));
    const gpa = testing.allocator;

    if (buildAddressRequest(gpa, 1, RTM_NEWADDR, 0, .{
        .ifindex = ifindex,
        .local = a,
        .prefixlen = prefix,
    })) |req| gpa.free(req) else |_| {}
    if (buildRouteRequest(gpa, 1, RTM_NEWROUTE, 0, .{
        .dst = a,
        .dst_prefixlen = prefix,
        .oif = ifindex,
        .table = smith.valueRangeAtMost(u32, 0, std.math.maxInt(u32)),
    })) |req| gpa.free(req) else |_| {}
    if (buildNeighborRequest(gpa, 1, RTM_NEWNEIGH, 0, .{
        .ifindex = ifindex,
        .dst = a,
        .lladdr = a,
    })) |req| gpa.free(req) else |_| {}
    if (buildLinkSetRequest(gpa, 1, ifindex, .{
        .mtu = smith.valueRangeAtMost(u32, 0, std.math.maxInt(u32)),
        .mac = a,
        .flags = smith.valueRangeAtMost(u32, 0, std.math.maxInt(u32)),
        .flags_mask = smith.valueRangeAtMost(u32, 0, std.math.maxInt(u32)),
    })) |req| gpa.free(req) else |_| {}
}

test "wire constants agree with std.os.linux" {
    try testing.expectEqual(@as(u16, @intFromEnum(linux.NetlinkMessageType.DONE)), codec.NLMSG_DONE);
    try testing.expectEqual(@as(u16, @intFromEnum(linux.NetlinkMessageType.ERROR)), codec.NLMSG_ERROR);
    try testing.expectEqual(@as(u16, linux.NLM_F_REQUEST), codec.NLM_F_REQUEST);
    try testing.expectEqual(@as(u16, linux.NLM_F_DUMP), codec.NLM_F_DUMP);
    try testing.expectEqual(@as(u16, linux.NLM_F_DUMP_INTR), codec.NLM_F_DUMP_INTR);
    try testing.expectEqual(@sizeOf(linux.nlmsghdr), codec.header_len);
    try testing.expectEqual(@sizeOf(linux.ifinfomsg), ifinfomsg_len);
    try testing.expectEqual(@as(u16, 18), RTM_GETLINK);
    try testing.expectEqual(@as(u16, 22), RTM_GETADDR);
    try testing.expectEqual(@as(u16, 26), RTM_GETROUTE);
    try testing.expectEqual(@as(u16, 30), RTM_GETNEIGH);
    // Write path (linux/rtnetlink.h).
    try testing.expectEqual(@as(u16, 16), RTM_NEWLINK);
    try testing.expectEqual(@as(u16, 17), RTM_DELLINK);
    try testing.expectEqual(@as(u16, 20), RTM_NEWADDR);
    try testing.expectEqual(@as(u16, 21), RTM_DELADDR);
    try testing.expectEqual(@as(u16, 24), RTM_NEWROUTE);
    try testing.expectEqual(@as(u16, 25), RTM_DELROUTE);
    try testing.expectEqual(@as(u16, 28), RTM_NEWNEIGH);
    try testing.expectEqual(@as(u16, 29), RTM_DELNEIGH);
    try testing.expectEqual(@as(u16, 0x100), codec.NLM_F_REPLACE);
    try testing.expectEqual(@as(u16, 0x200), codec.NLM_F_EXCL);
    try testing.expectEqual(@as(u16, 0x400), codec.NLM_F_CREATE);
    try testing.expectEqual(@as(u16, 0x800), codec.NLM_F_APPEND);
    try testing.expectEqual(@as(u16, 18), ifla_linkinfo);
}

test "fuzz: typed parsers never crash on arbitrary payloads" {
    try testing.fuzz({}, fuzzParsers, .{});
}

fn fuzzParsers(_: void, smith: *std.testing.Smith) !void {
    var raw: [256]u8 = undefined;
    smith.bytes(&raw);
    const len = smith.valueRangeAtMost(u16, 0, raw.len);
    const payload = raw[0..len];
    if (parseLink(payload)) |_| {} else |_| {}
    if (parseAddress(payload)) |_| {} else |_| {}
    if (parseRoute(payload)) |_| {} else |_| {}
    if (parseNeighbor(payload)) |_| {} else |_| {}
}

// ── integration tests (real kernel; RTM_GET* dumps need no root) ────────────
// Skipped only when a NETLINK_ROUTE socket cannot be opened at all.

fn openOrSkip() !Socket {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    return Socket.open(testing.allocator) catch return error.SkipZigTest;
}

test "integration: link dump contains lo (index 1, LOOPBACK)" {
    var nl = try openOrSkip();
    defer nl.close();
    const ls = try nl.links();
    defer testing.allocator.free(ls);
    try testing.expect(ls.len >= 1);
    const lo = for (ls) |*l| {
        if (std.mem.eql(u8, l.name(), "lo")) break l;
    } else return error.TestExpectedLoopback;
    try testing.expectEqual(@as(u32, 1), lo.index);
    try testing.expect(lo.flags & IFF.LOOPBACK != 0);
    try testing.expect(lo.mtu > 0);
}

test "integration: address dump has a loopback address on lo" {
    var nl = try openOrSkip();
    defer nl.close();
    const addrs = try nl.addresses(.{});
    defer testing.allocator.free(addrs);
    var found = false;
    for (addrs) |*a| {
        const is_v4_loop = a.family == AF.INET and std.mem.eql(u8, a.bytes(), &.{ 127, 0, 0, 1 });
        const is_v6_loop = a.family == AF.INET6 and
            std.mem.eql(u8, a.bytes(), &([_]u8{0} ** 15 ++ [_]u8{1}));
        if (is_v4_loop or is_v6_loop) {
            try testing.expectEqual(@as(u32, 1), a.ifindex);
            found = true;
        }
        // Structural validity for every entry.
        try testing.expect(a.addr_len == 4 or a.addr_len == 16);
    }
    if (!found and addrs.len == 0) {
        // A fresh network namespace (`unshare -rn zig build test-netlink`)
        // starts with `lo` down and unaddressed — the kernel really does
        // report nothing, which is not a failure of this module.
        std.debug.print(
            "SKIPPED (loopback address): the namespace has no addresses at all\n",
            .{},
        );
        return error.SkipZigTest;
    }
    try testing.expect(found);
}

test "integration: family + ifindex scoping" {
    var nl = try openOrSkip();
    defer nl.close();
    const v4 = try nl.addresses(.{ .family = AF.INET });
    defer testing.allocator.free(v4);
    for (v4) |a| try testing.expectEqual(AF.INET, a.family);

    const lo_only = try nl.addresses(.{ .ifindex = 1 });
    defer testing.allocator.free(lo_only);
    for (lo_only) |a| try testing.expectEqual(@as(u32, 1), a.ifindex);
}

test "integration: route dump parses and is structurally valid" {
    var nl = try openOrSkip();
    defer nl.close();
    const rs = try nl.routes(.{});
    defer testing.allocator.free(rs);
    for (rs) |r| {
        try testing.expect(r.family == AF.INET or r.family == AF.INET6 or r.family > 10);
        try testing.expect(r.dst_len == 0 or r.dst_len == 4 or r.dst_len == 16);
        try testing.expect(r.gateway_len == 0 or r.gateway_len == 4 or r.gateway_len == 16);
    }
    const v6 = try nl.routes(.{ .family = AF.INET6 });
    defer testing.allocator.free(v6);
    for (v6) |r| try testing.expectEqual(AF.INET6, r.family);
}

test "integration: neighbor dump parses and is structurally valid" {
    var nl = try openOrSkip();
    defer nl.close();
    const ns = try nl.neighbors(.{});
    defer testing.allocator.free(ns);
    for (ns) |n| {
        try testing.expect(n.dst_len == 0 or n.dst_len == 4 or n.dst_len == 16);
        try testing.expect(n.lladdr_len <= 32);
    }
}

test "integration: sequential dumps on one socket stay in sync" {
    var nl = try openOrSkip();
    defer nl.close();
    // Exercises seq matching + queue hygiene across several requests.
    const l1 = try nl.links();
    testing.allocator.free(l1);
    const a1 = try nl.addresses(.{});
    testing.allocator.free(a1);
    const l2 = try nl.links();
    defer testing.allocator.free(l2);
    try testing.expect(l2.len >= 1);
}

test "integration: a write to a nonexistent interface surfaces a mapped error" {
    var nl = try openOrSkip();
    defer nl.close();
    // Unprivileged this is EPERM, privileged it is ENODEV — either way it must
    // come back as a typed error, never as a silent success.
    if (nl.addressAdd(.{
        .ifindex = 0x7fff_fff0,
        .local = &.{ 10, 254, 0, 1 },
        .prefixlen = 24,
    }, .{})) |_| {
        return error.TestExpectedWriteToFail;
    } else |err| switch (err) {
        error.AccessDenied, error.NoSuchDevice, error.NotFound, error.InvalidRequest => {},
        else => return err,
    }
    // Whatever the kernel said, the socket stays usable for the next request.
    const ls = try nl.links();
    testing.allocator.free(ls);
}

test "integration: build-time validation rejects bad specs before any syscall" {
    var nl = try openOrSkip();
    defer nl.close();
    try testing.expectError(error.InvalidAddressLength, nl.addressAdd(.{
        .ifindex = 1,
        .local = &.{ 1, 2, 3, 4, 5, 6 },
        .prefixlen = 24,
    }, .{}));
    try testing.expectError(error.NothingToChange, nl.linkSet(1, .{}));
    try testing.expectError(error.FamilyRequired, nl.routeDel(.{}));
}

// ── live write→read round-trip inside a private network namespace ───────────
//
// Real writes need CAP_NET_ADMIN, so the whole scenario runs in a forked child
// that first isolates itself with `unshare(CLONE_NEWUSER|CLONE_NEWNET)` — the
// programmatic form of `unshare -rn`. Nothing here can touch the host's
// interfaces, addresses or routes: the namespace (and everything created in
// it) is destroyed when the child exits. When namespaces are unavailable
// (hardened kernel, restricted container, non-Linux) the child reports
// `netns_skip` and the test SKIPS — it never fails for lack of privilege.
// Running the suite under an outer `unshare -rn` or as root works too.

const netns_skip: u8 = 77; // "no netns/privileges here" — not a failure
const netns_fail: u8 = 1;
/// Interface created inside the child's namespace; never visible to the host.
const netns_dev = "nltest0";

test "integration (netns): link/address/route/neighbor write→read round-trip" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const rc = linux.fork();
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        else => {
            std.debug.print("SKIPPED (netns round-trip): fork() not permitted\n", .{});
            return error.SkipZigTest;
        },
    }
    if (rc == 0) {
        // Child. Exits without unwinding, so it never touches the parent's
        // test state or allocator.
        var code: u8 = netns_skip;
        if (enterNetns()) {
            if (netnsRoundTrip()) |_| {
                code = 0;
            } else |err| {
                std.debug.print("netns round-trip failed: {s}\n", .{@errorName(err)});
                code = netns_fail;
            }
        }
        linux.exit_group(code);
    }

    const pid: i32 = @intCast(rc);
    var status: u32 = 0;
    while (true) {
        const wrc = linux.waitpid(pid, &status, 0);
        switch (linux.errno(wrc)) {
            .SUCCESS => break,
            .INTR => continue,
            else => return error.TestUnexpectedResult,
        }
    }
    if (status & 0x7f != 0) return error.TestChildKilledBySignal; // WIFEXITED
    switch (@as(u8, @truncate(status >> 8))) {
        0 => {},
        netns_skip => {
            std.debug.print(
                "SKIPPED (netns round-trip): no CLONE_NEWUSER/CLONE_NEWNET here — " ++
                    "re-run as root or under `unshare -rn` for live write coverage\n",
                .{},
            );
            return error.SkipZigTest;
        },
        else => return error.TestNetnsRoundTripFailed,
    }
}

/// Move the calling (child) process into a throw-away network namespace.
/// First choice is a user+network namespace, which needs no privilege at all
/// on a stock kernel; if user namespaces are off but we already have
/// CAP_SYS_ADMIN (root, or an outer `unshare -rn`), a plain netns unshare is
/// enough. Returns false when neither is possible.
fn enterNetns() bool {
    const uid = linux.getuid();
    const gid = linux.getgid();
    if (linux.errno(linux.unshare(linux.CLONE.NEWUSER | linux.CLONE.NEWNET)) == .SUCCESS) {
        // Map ourselves to root inside the new user namespace (what
        // `unshare -r` does). Best-effort: CAP_NET_ADMIN in the new namespace
        // is already granted by the unshare itself.
        writeProcFile("/proc/self/setgroups", "deny");
        var buf: [64]u8 = undefined;
        if (std.fmt.bufPrint(&buf, "0 {d} 1", .{uid})) |m| {
            writeProcFile("/proc/self/uid_map", m);
        } else |_| {}
        var gbuf: [64]u8 = undefined;
        if (std.fmt.bufPrint(&gbuf, "0 {d} 1", .{gid})) |m| {
            writeProcFile("/proc/self/gid_map", m);
        } else |_| {}
        return true;
    }
    return linux.errno(linux.unshare(linux.CLONE.NEWNET)) == .SUCCESS;
}

fn writeProcFile(path: [*:0]const u8, data: []const u8) void {
    const rc = linux.openat(linux.AT.FDCWD, path, .{ .ACCMODE = .WRONLY }, 0);
    if (linux.errno(rc) != .SUCCESS) return;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    _ = linux.write(fd, data.ptr, data.len);
}

fn findLink(nl: *Socket, name: []const u8) !?Link {
    const ls = try nl.links();
    defer std.heap.page_allocator.free(ls);
    for (ls) |l| if (std.mem.eql(u8, l.name(), name)) return l;
    return null;
}

/// The full write→read cycle, executed inside the child's own namespace: every
/// write is verified by reading the state back through this module's own dump
/// path. Uses the page allocator (raw mmap) — no lock a fork could have caught
/// mid-flight.
fn netnsRoundTrip() !void {
    const gpa = std.heap.page_allocator;
    var nl = try Socket.open(gpa);
    defer nl.close();

    // 1. Create a dummy device. If the kernel has no dummy driver, fall back
    //    to `lo` — which exists in every fresh namespace, down and unaddressed.
    var created = true;
    nl.linkAdd(.{ .name = netns_dev, .kind = "dummy" }, .{}) catch |err| switch (err) {
        error.NotSupported, error.InvalidRequest, error.NotFound => created = false,
        else => return err,
    };
    const dev = if (created)
        (try findLink(&nl, netns_dev)) orelse return error.TestDummyNotFound
    else
        (try findLink(&nl, "lo")) orelse return error.TestLoopbackNotFound;
    const ifindex = dev.index;

    // 2. Admin up + MTU, verified through RTM_GETLINK.
    try nl.linkUp(ifindex);
    try nl.linkSet(ifindex, .{ .mtu = 1400 });
    {
        const l = (try findLink(&nl, if (created) netns_dev else "lo")).?;
        if (l.flags & IFF.UP == 0) return error.TestLinkNotUp;
        if (l.mtu != 1400) return error.TestMtuNotApplied;
    }

    // 3. Address add, verified through RTM_GETADDR.
    const ip: [4]u8 = .{ 10, 11, 12, 1 };
    try nl.addressAdd(.{ .ifindex = ifindex, .local = &ip, .prefixlen = 24 }, .{});
    {
        const addrs = try nl.addresses(.{ .ifindex = ifindex, .family = AF.INET });
        defer gpa.free(addrs);
        var found = false;
        for (addrs) |a| {
            if (std.mem.eql(u8, a.bytes(), &ip) and a.prefixlen == 24) found = true;
        }
        if (!found) return error.TestAddressNotFound;
    }
    // Re-adding the same address must hit NLM_F_EXCL.
    try expectWriteError(error.Exists, nl.addressAdd(
        .{ .ifindex = ifindex, .local = &ip, .prefixlen = 24 },
        .{},
    ));

    // 4. Route add (on-link, scope LINK), verified through RTM_GETROUTE.
    const dst: [4]u8 = .{ 10, 99, 0, 0 };
    try nl.routeAdd(.{
        .dst = &dst,
        .dst_prefixlen = 24,
        .oif = ifindex,
        .scope = RT_SCOPE.LINK,
    }, .{});
    {
        const rs = try nl.routes(.{ .ifindex = ifindex, .family = AF.INET });
        defer gpa.free(rs);
        var found = false;
        for (rs) |r| {
            if (std.mem.eql(u8, r.dstBytes(), &dst) and r.dst_prefixlen == 24) found = true;
        }
        if (!found) return error.TestRouteNotFound;
    }

    // 5. Neighbour add, verified through RTM_GETNEIGH.
    const neigh_ip: [4]u8 = .{ 10, 11, 12, 55 };
    const lladdr: [6]u8 = .{ 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01 };
    var neigh_supported = true;
    nl.neighborAdd(.{
        .ifindex = ifindex,
        .dst = &neigh_ip,
        .lladdr = &lladdr,
    }, .{}) catch |err| switch (err) {
        // `lo` has no link-layer addressing to speak of on some kernels.
        error.NotSupported, error.InvalidRequest => neigh_supported = false,
        else => return err,
    };
    if (neigh_supported) {
        const ns = try nl.neighbors(.{ .ifindex = ifindex, .family = AF.INET });
        defer gpa.free(ns);
        var found = false;
        for (ns) |n| {
            if (std.mem.eql(u8, n.dstBytes(), &neigh_ip) and
                std.mem.eql(u8, n.lladdrBytes(), &lladdr)) found = true;
        }
        if (!found) return error.TestNeighborNotFound;
        try nl.neighborDel(.{ .ifindex = ifindex, .dst = &neigh_ip });
    }

    // 6. Error paths with real privileges: mapped errno + the kernel's
    //    extended-ACK reason string where it provides one.
    try expectWriteError(error.NoSuchDevice, nl.addressAdd(
        .{ .ifindex = 0x7fff_fff0, .local = &.{ 10, 254, 0, 1 }, .prefixlen = 24 },
        .{},
    ));
    try expectWriteError(error.NotSupported, nl.linkAdd(
        .{ .name = "nlbogus0", .kind = "nosuchkind" },
        .{},
    ));
    // Extended ACK is best-effort (needs Linux >= 4.12) — when present it must
    // be a non-empty, bounded string.
    if (nl.lastErrorMessage().len > nl.ext_ack_buf.len) return error.TestExtAckOverrun;
    try expectWriteError(error.AddressNotAvailable, nl.addressDel(
        .{ .ifindex = ifindex, .local = &.{ 10, 11, 12, 200 }, .prefixlen = 24 },
    ));

    // 7. Tear everything down again and verify each removal.
    try nl.routeDel(.{ .dst = &dst, .dst_prefixlen = 24, .oif = ifindex, .scope = RT_SCOPE.LINK });
    {
        const rs = try nl.routes(.{ .ifindex = ifindex, .family = AF.INET });
        defer gpa.free(rs);
        for (rs) |r| {
            if (std.mem.eql(u8, r.dstBytes(), &dst)) return error.TestRouteNotRemoved;
        }
    }
    try nl.addressDel(.{ .ifindex = ifindex, .local = &ip, .prefixlen = 24 });
    {
        const addrs = try nl.addresses(.{ .ifindex = ifindex, .family = AF.INET });
        defer gpa.free(addrs);
        for (addrs) |a| {
            if (std.mem.eql(u8, a.bytes(), &ip)) return error.TestAddressNotRemoved;
        }
    }
    try nl.linkDown(ifindex);
    {
        const l = (try findLink(&nl, if (created) netns_dev else "lo")).?;
        if (l.flags & IFF.UP != 0) return error.TestLinkStillUp;
    }
    if (created) {
        try nl.linkDel(ifindex);
        if (try findLink(&nl, netns_dev) != null) return error.TestLinkNotDeleted;
    }
}

// ── live AF_BRIDGE round-trip inside a private network namespace ────────────
//
// Same harness as above: a forked child isolates itself with
// `unshare(CLONE_NEWUSER|CLONE_NEWNET)`, builds a bridge + veth pair there and
// exercises the whole bridge surface against the real kernel. It SKIPS (never
// fails) when namespaces or the veth/bridge drivers are unavailable.

const netns_bridge = "nlbr0";
const netns_veth_a = "nlveth0";

test "integration (netns): bridge/FDB/VLAN/brport write→read round-trip" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const rc = linux.fork();
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        else => {
            std.debug.print("SKIPPED (netns bridge round-trip): fork() not permitted\n", .{});
            return error.SkipZigTest;
        },
    }
    if (rc == 0) {
        var code: u8 = netns_skip;
        if (enterNetns()) {
            if (netnsBridgeRoundTrip()) |ok| {
                code = if (ok) 0 else netns_skip;
            } else |err| {
                std.debug.print("netns bridge round-trip failed: {s}\n", .{@errorName(err)});
                code = netns_fail;
            }
        }
        linux.exit_group(code);
    }

    const pid: i32 = @intCast(rc);
    var status: u32 = 0;
    while (true) {
        const wrc = linux.waitpid(pid, &status, 0);
        switch (linux.errno(wrc)) {
            .SUCCESS => break,
            .INTR => continue,
            else => return error.TestUnexpectedResult,
        }
    }
    if (status & 0x7f != 0) return error.TestChildKilledBySignal;
    switch (@as(u8, @truncate(status >> 8))) {
        0 => {},
        netns_skip => {
            std.debug.print(
                "SKIPPED (netns bridge round-trip): no CLONE_NEWUSER/CLONE_NEWNET or no " ++
                    "bridge/veth driver here — re-run as root or under `unshare -rn` " ++
                    "for live bridge coverage\n",
                .{},
            );
            return error.SkipZigTest;
        },
        else => return error.TestNetnsBridgeRoundTripFailed,
    }
}

/// Admin-up every non-loopback device in the namespace and return the index of
/// the veth peer — the one device that is neither the bridge nor the port. Its
/// name is chosen by the kernel, so it can only be identified positionally.
fn upAllButLoopback(nl: *Socket, br_index: u32, port_index: u32) !?u32 {
    const ls = try nl.links();
    defer std.heap.page_allocator.free(ls);
    var peer: ?u32 = null;
    for (ls) |l| {
        if (l.flags & IFF.LOOPBACK != 0) continue;
        try nl.linkUp(l.index);
        if (l.index != br_index and l.index != port_index) peer = l.index;
    }
    return peer;
}

/// Returns false (→ SKIP) when the kernel has no bridge or veth driver;
/// an error means a real failure of this module.
fn netnsBridgeRoundTrip() !bool {
    const gpa = std.heap.page_allocator;
    var nl = try Socket.open(gpa);
    defer nl.close();

    // 1. Bridge with VLAN filtering on, plus a veth pair to enslave.
    nl.bridgeAdd(.{
        .name = netns_bridge,
        .vlan_filtering = true,
        .forward_delay = 0,
        .stp_state = 0,
        .up = true,
    }, .{}) catch |err| switch (err) {
        error.NotSupported, error.InvalidRequest, error.NotFound => return false,
        else => return err,
    };
    const br = (try findLink(&nl, netns_bridge)) orelse return error.TestBridgeNotFound;
    nl.linkAdd(.{ .name = netns_veth_a, .kind = "veth" }, .{}) catch |err| switch (err) {
        error.NotSupported, error.InvalidRequest, error.NotFound => return false,
        else => return err,
    };
    const port = (try findLink(&nl, netns_veth_a)) orelse return error.TestVethNotFound;
    // Both ends of the pair must be up, or the port has no carrier and the
    // kernel answers ENETDOWN to a FORWARDING state change. The peer's name is
    // kernel-generated, so bring every non-loopback device up.
    const peer = try upAllButLoopback(&nl, br.index, port.index);

    // 2. Enslave, verified through IFLA_MASTER in a link dump.
    try nl.portEnslave(port.index, br.index);
    {
        const info = (try nl.brportInfo(port.index)) orelse return error.TestPortNotEnslaved;
        if (info.master != br.index) return error.TestWrongMaster;
    }

    // 3. Bridge-port options, verified through IFLA_PROTINFO.
    try nl.brportSet(port.index, .{
        .state = BR_STATE.FORWARDING,
        .learning = false,
        .unicast_flood = false,
        .isolated = true,
    });
    {
        const info = (try nl.brportInfo(port.index)).?;
        if (info.state != BR_STATE.FORWARDING) return error.TestBrportStateNotApplied;
        if (info.learning != false) return error.TestBrportLearningNotApplied;
        if (info.unicast_flood != false) return error.TestBrportFloodNotApplied;
        if (info.isolated != true) return error.TestBrportIsolatedNotApplied;
    }
    try expectBridgeError(error.NothingToChange, nl.brportSet(port.index, .{}));

    // 4. VLANs: a single PVID/untagged VLAN plus a range, read back through
    //    the RTEXT_FILTER_BRVLAN dump.
    try nl.bridgeVlanAdd(port.index, .{ .vid = 10, .pvid = true, .untagged = true });
    try nl.bridgeVlanAdd(port.index, .{ .vid = 100, .vid_end = 200 });
    {
        const vlans = try nl.bridgeVlans(.{ .ifindex = port.index });
        defer gpa.free(vlans);
        var saw_pvid = false;
        var covered: u32 = 0;
        for (vlans) |v| {
            if (v.ifindex != port.index) return error.TestVlanWrongPort;
            if (v.vid_end < v.vid) return error.TestVlanInvertedRange;
            if (v.contains(10) and v.isPvid() and v.isUntagged()) saw_pvid = true;
            if (v.vid >= 100 and v.vid_end <= 200) covered += v.count();
        }
        if (!saw_pvid) return error.TestPvidNotFound;
        if (covered != 101) return error.TestVlanRangeNotFound;
    }
    // Building a bad VLAN spec never reaches the kernel.
    try expectBridgeError(error.InvalidVlanId, nl.bridgeVlanAdd(port.index, .{ .vid = 4095 }));
    try expectBridgeError(
        error.InvalidVlanRange,
        nl.bridgeVlanAdd(port.index, .{ .vid = 200, .vid_end = 100 }),
    );

    // 5. FDB: add a static entry in the master's database, read it back, then
    //    a self entry, then delete both.
    const mac: [6]u8 = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
    try nl.fdbAdd(.{
        .ifindex = port.index,
        .lladdr = &mac,
        .vlan = 10,
        .state = NUD.REACHABLE | NUD.NOARP,
    }, .{});
    {
        const fdb = try nl.fdbEntries(.{ .ifindex = port.index });
        defer gpa.free(fdb);
        var found = false;
        for (fdb) |e| {
            if (std.mem.eql(u8, e.lladdrBytes(), &mac) and e.vlan == @as(?u16, 10)) {
                if (e.master != br.index) return error.TestFdbWrongMaster;
                found = true;
            }
        }
        if (!found) return error.TestFdbEntryNotFound;
    }
    // Kernel-side `bridge fdb show br <bridge>` scoping returns the same entry.
    {
        const fdb = try nl.fdbEntries(.{ .master = br.index });
        defer gpa.free(fdb);
        var found = false;
        for (fdb) |e| {
            if (std.mem.eql(u8, e.lladdrBytes(), &mac)) found = true;
        }
        if (!found) return error.TestFdbMasterFilterFailed;
    }
    // Re-adding the same entry exclusively must hit NLM_F_EXCL.
    try expectBridgeError(error.Exists, nl.fdbAdd(.{
        .ifindex = port.index,
        .lladdr = &mac,
        .vlan = 10,
        .state = NUD.REACHABLE | NUD.NOARP,
    }, .{}));

    try nl.fdbDel(.{ .ifindex = port.index, .lladdr = &mac, .vlan = 10 });
    {
        const fdb = try nl.fdbEntries(.{ .ifindex = port.index });
        defer gpa.free(fdb);
        for (fdb) |e| {
            if (std.mem.eql(u8, e.lladdrBytes(), &mac) and e.vlan == @as(?u16, 10))
                return error.TestFdbEntryNotRemoved;
        }
    }

    // 6. Tear the VLANs down and verify they are gone.
    try nl.bridgeVlanDel(port.index, .{ .vid = 100, .vid_end = 200 });
    try nl.bridgeVlanDel(port.index, .{ .vid = 10 });
    {
        const vlans = try nl.bridgeVlans(.{ .ifindex = port.index });
        defer gpa.free(vlans);
        for (vlans) |v| {
            if (v.contains(10) or v.contains(150)) return error.TestVlanNotRemoved;
        }
    }

    // 7. Release the port and delete both devices.
    try nl.portRelease(port.index);
    {
        const info = try nl.brportInfo(port.index);
        if (info != null and info.?.master != null) return error.TestPortStillEnslaved;
    }
    try nl.linkDel(port.index);
    if (try findLink(&nl, netns_veth_a) != null) return error.TestVethNotDeleted;
    // Deleting one end of a veth pair takes the peer with it.
    if (peer) |p| {
        const ls = try nl.links();
        defer gpa.free(ls);
        for (ls) |l| if (l.index == p) return error.TestVethPeerNotDeleted;
    }
    try nl.linkDel(br.index);
    if (try findLink(&nl, netns_bridge) != null) return error.TestBridgeNotDeleted;
    return true;
}

fn expectBridgeError(expected: anyerror, actual: BridgeWriteError!void) !void {
    if (actual) |_| {
        return error.TestExpectedWriteToFail;
    } else |err| {
        if (err != expected) {
            std.debug.print("expected {s}, got {s}\n", .{ @errorName(expected), @errorName(err) });
            return error.TestWrongWriteError;
        }
    }
}

fn expectWriteError(expected: anyerror, actual: WriteError!void) !void {
    if (actual) |_| {
        return error.TestExpectedWriteToFail;
    } else |err| {
        if (err != expected) {
            std.debug.print("expected {s}, got {s}\n", .{ @errorName(expected), @errorName(err) });
            return error.TestWrongWriteError;
        }
    }
}

test {
    _ = codec;
    _ = bridge;
}
