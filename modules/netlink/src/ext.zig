// SPDX-License-Identifier: MIT
//! ext — the rtnetlink surface added on 2026-11-02 for survey parity with
//! iproute2 / vishvananda-netlink / rust-netlink: multipath routes and route
//! metrics, nexthop objects (`ip nexthop`), the link kinds beyond veth/VLAN
//! (vxlan, macvlan/macvtap, ipvlan/ipvtap, vrf, bond, gre/gretap, ipip/sit,
//! geneve, plus a raw escape hatch for any other kind), and the read-back of
//! each kind's `IFLA_INFO_DATA` (including the bridge device's own options).
//!
//! Like `bridge.zig` this is a pure builder/parser layer: functions over byte
//! buffers, no I/O. The `Socket` methods that send them live in `root.zig`.
//! Constants are the kernel UAPI numbers (linux/if_link.h, if_tunnel.h,
//! rtnetlink.h, nexthop.h — ABI facts only, see NOTICE).
//!
//! Everything that parses kernel bytes is bounds-checked and fuzzed
//! (`NETLINK_FUZZ`, harness `netlink-ext`); every builder returns an error for
//! a spec the kernel could only mis-read, never asserts.

const std = @import("std");
const builtin = @import("builtin");
const native_endian = builtin.cpu.arch.endian();

const codec = @import("codec.zig");
const root = @import("root.zig");
const BuildError = root.BuildError;
const Allocator = std.mem.Allocator;

// ── kernel UAPI constants ───────────────────────────────────────────────────

/// Nexthop object messages (linux/rtnetlink.h).
pub const RTM_NEWNEXTHOP: u16 = 104;
pub const RTM_DELNEXTHOP: u16 = 105;
pub const RTM_GETNEXTHOP: u16 = 106;

/// `struct nhmsg` (linux/nexthop.h): family, scope, protocol, resvd (u8
/// each), flags (u32).
pub const nhmsg_len = 8;

/// `RTA_*` additions (linux/rtnetlink.h).
pub const RTA_NH_ID: u16 = 30;

/// `RTAX_*` (linux/rtnetlink.h) — inside `RTA_METRICS`.
pub const RTAX = struct {
    pub const MTU: u16 = 2;
    pub const ADVMSS: u16 = 8;
    pub const HOPLIMIT: u16 = 10;
};

/// `RTNH_F_*` — `rtnexthop.rtnh_flags` and `nhmsg.nh_flags`.
pub const RTNH_F = struct {
    pub const DEAD: u8 = 1;
    pub const PERVASIVE: u8 = 2;
    pub const ONLINK: u8 = 4;
    pub const OFFLOAD: u8 = 8;
    pub const LINKDOWN: u8 = 16;
    pub const UNRESOLVED: u8 = 32;
};

/// `NHA_*` (linux/nexthop.h).
pub const NHA = struct {
    pub const ID: u16 = 1;
    pub const GROUP: u16 = 2;
    pub const GROUP_TYPE: u16 = 3;
    pub const BLACKHOLE: u16 = 4;
    pub const OIF: u16 = 5;
    pub const GATEWAY: u16 = 6;
    pub const MASTER: u16 = 10;
    pub const FDB: u16 = 11;
};

pub const IFLA_VXLAN = struct {
    pub const ID: u16 = 1;
    pub const GROUP: u16 = 2;
    pub const LINK: u16 = 3;
    pub const LOCAL: u16 = 4;
    pub const TTL: u16 = 5;
    pub const TOS: u16 = 6;
    pub const LEARNING: u16 = 7;
    pub const AGEING: u16 = 8;
    pub const PORT: u16 = 15;
    pub const GROUP6: u16 = 16;
    pub const LOCAL6: u16 = 17;
    pub const UDP_CSUM: u16 = 18;
};

pub const IFLA_MACVLAN = struct {
    pub const MODE: u16 = 1;
    pub const FLAGS: u16 = 2;
};

pub const IFLA_IPVLAN = struct {
    pub const MODE: u16 = 1;
    pub const FLAGS: u16 = 2;
};

pub const IFLA_VRF = struct {
    pub const TABLE: u16 = 1;
};

pub const IFLA_BOND = struct {
    pub const MODE: u16 = 1;
    pub const MIIMON: u16 = 3;
    pub const UPDELAY: u16 = 4;
    pub const DOWNDELAY: u16 = 5;
    pub const XMIT_HASH_POLICY: u16 = 14;
    pub const MIN_LINKS: u16 = 18;
    pub const AD_LACP_RATE: u16 = 21;
};

/// `IFLA_GRE_*` (linux/if_tunnel.h).
pub const IFLA_GRE = struct {
    pub const LINK: u16 = 1;
    pub const IFLAGS: u16 = 2;
    pub const OFLAGS: u16 = 3;
    pub const IKEY: u16 = 4;
    pub const OKEY: u16 = 5;
    pub const LOCAL: u16 = 6;
    pub const REMOTE: u16 = 7;
    pub const TTL: u16 = 8;
    pub const TOS: u16 = 9;
    pub const PMTUDISC: u16 = 10;
};

/// `GRE_KEY` (linux/if_tunnel.h), the host-order value of the big-endian flag.
pub const GRE_KEY: u16 = 0x2000;

/// `IFLA_IPTUN_*` (linux/if_tunnel.h) — ipip and sit.
pub const IFLA_IPTUN = struct {
    pub const LINK: u16 = 1;
    pub const LOCAL: u16 = 2;
    pub const REMOTE: u16 = 3;
    pub const TTL: u16 = 4;
    pub const TOS: u16 = 5;
    pub const PMTUDISC: u16 = 10;
};

pub const IFLA_GENEVE = struct {
    pub const ID: u16 = 1;
    pub const REMOTE: u16 = 2;
    pub const TTL: u16 = 3;
    pub const TOS: u16 = 4;
    pub const PORT: u16 = 5;
    pub const REMOTE6: u16 = 7;
    pub const UDP_CSUM: u16 = 8;
};

/// `IFLA_BR_*` beyond the ones `bridge.IFLA_BR` already names.
pub const IFLA_BR = struct {
    pub const HELLO_TIME: u16 = 2;
    pub const MAX_AGE: u16 = 3;
    pub const GROUP_FWD_MASK: u16 = 9;
    pub const MCAST_SNOOPING: u16 = 23;
    pub const MCAST_QUERIER: u16 = 25;
    pub const VLAN_DEFAULT_PVID: u16 = 39;
};

// ── small shared helpers ────────────────────────────────────────────────────

/// An IPv4 (4) or IPv6 (16) address as plain data.
pub const IpAddr = struct {
    buf: [16]u8 = @splat(0),
    len: u8 = 0,

    pub fn bytes(a: *const IpAddr) []const u8 {
        return a.buf[0..a.len];
    }

    fn fromAttr(data: []const u8) IpAddr {
        var a: IpAddr = .{};
        if (data.len == 4 or data.len == 16) {
            @memcpy(a.buf[0..data.len], data);
            a.len = @intCast(data.len);
        }
        return a;
    }
};

fn famOf(addr: []const u8) BuildError!u8 {
    return switch (addr.len) {
        4 => root.AF.INET,
        16 => root.AF.INET6,
        else => error.InvalidAddressLength,
    };
}

fn merge(cur: ?u8, addr: ?[]const u8) BuildError!?u8 {
    const a = addr orelse return cur;
    const f = try famOf(a);
    const c = cur orelse return f;
    if (c != f) return error.MixedFamilies;
    return c;
}

fn put(gpa: Allocator, list: *std.ArrayList(u8), t: u16, data: []const u8) BuildError!void {
    try codec.appendAttr(gpa, list, t, data);
}

fn putBool(gpa: Allocator, list: *std.ArrayList(u8), t: u16, v: bool) BuildError!void {
    try codec.appendAttrU8(gpa, list, t, @intFromBool(v));
}

fn readBool(a: codec.Attr) codec.Error!bool {
    return (try a.asU8()) != 0;
}

// ── multipath routes ────────────────────────────────────────────────────────

/// How many hops of a multipath route `Route` carries inline. The count of
/// all hops is `Route.hop_count`; `MultipathIterator` walks every one of them
/// from the raw `RTA_MULTIPATH` bytes for a caller that needs more.
pub const max_route_hops = 4;

/// Most hops one `RouteSpec`/`NexthopSpec` group may carry (a message must
/// stay far below the 64 KiB attribute limit; iproute2/the kernel allow 256
/// for a resilient group, this module asks for no more).
pub const max_spec_hops = 128;

/// `struct rtnexthop` (linux/rtnetlink.h): u16 len, u8 flags, u8 hops,
/// i32 ifindex.
const rtnh_len = 8;

/// One hop of a multipath route, decoded from `struct rtnexthop`.
pub const RouteHop = struct {
    oif: u32 = 0,
    /// `RTNH_F.*` (ONLINK, DEAD, LINKDOWN…).
    flags: u8 = 0,
    /// `rtnh_hops + 1`, 1…256 (`ip route … nexthop … weight N`).
    weight: u16 = 1,
    gateway: [16]u8 = @splat(0),
    gateway_len: u8 = 0,

    pub fn gatewayBytes(h: *const RouteHop) []const u8 {
        return h.gateway[0..h.gateway_len];
    }
};

/// Walks the `struct rtnexthop` list inside an `RTA_MULTIPATH` attribute.
/// Every length is checked against what remains; a step advances at least
/// `rtnh_len` bytes, so N bytes cost at most N/8 steps.
pub const MultipathIterator = struct {
    buf: []const u8,
    off: usize = 0,

    pub fn next(it: *MultipathIterator) codec.Error!?RouteHop {
        if (it.off >= it.buf.len) return null;
        const rest = it.buf[it.off..];
        if (rest.len < rtnh_len) return error.Truncated;
        const len: usize = std.mem.readInt(u16, rest[0..2], native_endian);
        if (len < rtnh_len) return error.BadLength;
        if (len > rest.len) return error.Truncated;
        var h: RouteHop = .{
            .flags = rest[2],
            .weight = @as(u16, rest[3]) + 1,
            .oif = @bitCast(std.mem.readInt(i32, rest[4..8], native_endian)),
        };
        var ai: codec.AttrIterator = .{ .buf = rest[rtnh_len..len] };
        while (try ai.next()) |a| {
            if (a.type == root.RTA.GATEWAY and (a.data.len == 4 or a.data.len == 16)) {
                @memcpy(h.gateway[0..a.data.len], a.data);
                h.gateway_len = @intCast(a.data.len);
            }
        }
        it.off += @min(codec.alignUp(len), rest.len);
        return h;
    }
};

/// Decode an `RTA_MULTIPATH` payload: the first `max_route_hops` hops go to
/// `out`, the return value is the number of ALL hops (saturating at 65535).
pub fn parseMultipath(data: []const u8, out: *[max_route_hops]RouteHop) codec.Error!u16 {
    var it: MultipathIterator = .{ .buf = data };
    var n: u16 = 0;
    while (try it.next()) |h| {
        if (n < max_route_hops) out[n] = h;
        n +|= 1;
    }
    return n;
}

/// One hop of a multipath route to install (`ip route add … nexthop via G
/// dev D weight W`).
pub const HopSpec = struct {
    /// Output interface; 0 = let the kernel resolve it from the gateway.
    oif: u32 = 0,
    gateway: ?[]const u8 = null,
    /// 1…256.
    weight: u16 = 1,
    /// `RTNH_F_ONLINK`: the gateway is on-link even when no prefix says so.
    onlink: bool = false,
};

/// Check a hop list and return the family its gateways imply (null when none
/// has a gateway). Pure; no allocation.
pub fn hopsFamily(hops: []const HopSpec) BuildError!?u8 {
    if (hops.len > max_spec_hops) return error.TooManyHops;
    var fam: ?u8 = null;
    for (hops) |h| {
        if (h.weight < 1 or h.weight > 256) return error.InvalidHop;
        if (h.gateway == null and h.oif == 0) return error.InvalidHop;
        fam = try merge(fam, h.gateway);
    }
    return fam;
}

/// Append `RTA_MULTIPATH` for `hops`; refuses what `hopsFamily` refuses.
pub fn appendMultipath(gpa: Allocator, list: *std.ArrayList(u8), hops: []const HopSpec) BuildError!void {
    // Public, so it checks for itself: weights, gateway lengths and the hop
    // count are what the casts below rely on.
    _ = try hopsFamily(hops);
    const nest = try codec.nestBegin(gpa, list, root.RTA.MULTIPATH);
    for (hops) |h| {
        const start = list.items.len;
        var hdr: [rtnh_len]u8 = @splat(0);
        hdr[2] = if (h.onlink) RTNH_F.ONLINK else 0;
        hdr[3] = @intCast(h.weight - 1);
        std.mem.writeInt(i32, hdr[4..8], @bitCast(h.oif), native_endian);
        try list.appendSlice(gpa, &hdr);
        if (h.gateway) |g| try put(gpa, list, root.RTA.GATEWAY, g);
        // rtnh_len covers the header and the attributes, which are 4-aligned.
        std.mem.writeInt(u16, list.items[start..][0..2], @intCast(list.items.len - start), native_endian);
    }
    try codec.nestEnd(list, nest);
}

/// Append `RTA_METRICS` when any metric is set.
pub fn appendMetrics(gpa: Allocator, list: *std.ArrayList(u8), mtu: ?u32, advmss: ?u32, hoplimit: ?u32) BuildError!void {
    if (mtu == null and advmss == null and hoplimit == null) return;
    const nest = try codec.nestBegin(gpa, list, root.RTA.METRICS);
    if (mtu) |v| try codec.appendAttrU32(gpa, list, RTAX.MTU, v);
    if (advmss) |v| try codec.appendAttrU32(gpa, list, RTAX.ADVMSS, v);
    if (hoplimit) |v| try codec.appendAttrU32(gpa, list, RTAX.HOPLIMIT, v);
    try codec.nestEnd(list, nest);
}

/// The metrics `Route` reads back.
pub const Metrics = struct {
    mtu: u32 = 0,
    advmss: u32 = 0,
    hoplimit: u32 = 0,
};

/// Decode an `RTA_METRICS` payload (only the three this module models).
pub fn parseMetrics(data: []const u8) codec.Error!Metrics {
    var m: Metrics = .{};
    var it: codec.AttrIterator = .{ .buf = data };
    while (try it.next()) |a| switch (a.type) {
        RTAX.MTU => m.mtu = try a.asU32(),
        RTAX.ADVMSS => m.advmss = try a.asU32(),
        RTAX.HOPLIMIT => m.hoplimit = try a.asU32(),
        else => {},
    };
    return m;
}

// ── nexthop objects ─────────────────────────────────────────────────────────

/// How many members of a nexthop group `Nexthop` carries inline; the total is
/// `Nexthop.group_count`.
pub const max_group_members = 8;

/// A member of a nexthop group: another nexthop's id and its share.
pub const GroupMember = struct {
    id: u32,
    /// 1…256 (`ip nexthop add id 3 group 1,2/10,3`).
    weight: u16 = 1,
};

/// One nexthop object (`RTM_NEWNEXTHOP` → `struct nhmsg` + `NHA_*`).
pub const Nexthop = struct {
    id: u32,
    family: u8,
    protocol: u8 = 0,
    scope: u8 = 0,
    /// `nhmsg.nh_flags` (`RTNH_F.*`).
    flags: u32 = 0,
    oif: u32 = 0,
    gateway: IpAddr = .{},
    blackhole: bool = false,
    fdb: bool = false,
    /// `NHA_GROUP_TYPE`: 0 = hash-threshold multipath, 1 = resilient.
    group_type: u16 = 0,
    group: [max_group_members]GroupMember = @splat(.{ .id = 0 }),
    /// Number of members of ALL the group (>= those in `group`).
    group_count: u16 = 0,

    /// The inline members.
    pub fn members(n: *const Nexthop) []const GroupMember {
        return n.group[0..@min(n.group_count, max_group_members)];
    }
};

/// Decode an `RTM_NEWNEXTHOP` payload.
pub fn parseNexthop(payload: []const u8) codec.Error!?Nexthop {
    if (payload.len < nhmsg_len) return error.Truncated;
    var n: Nexthop = .{
        .id = 0,
        .family = payload[0],
        .scope = payload[1],
        .protocol = payload[2],
        .flags = std.mem.readInt(u32, payload[4..8], native_endian),
    };
    var have_id = false;
    var it: codec.AttrIterator = .{ .buf = payload[nhmsg_len..] };
    while (try it.next()) |a| switch (a.type) {
        NHA.ID => {
            n.id = try a.asU32();
            have_id = true;
        },
        NHA.GROUP => {
            if (a.data.len % 8 != 0) return error.BadLength;
            const total = a.data.len / 8;
            n.group_count = @intCast(@min(total, std.math.maxInt(u16)));
            for (0..@min(total, max_group_members)) |i| {
                const e = a.data[i * 8 ..][0..8];
                // struct nexthop_grp: u32 id, u8 weight, u8 weight_high, u16 resvd.
                n.group[i] = .{
                    .id = std.mem.readInt(u32, e[0..4], native_endian),
                    .weight = (@as(u16, e[5]) << 8 | e[4]) +| 1,
                };
            }
        },
        NHA.GROUP_TYPE => n.group_type = try a.asU16(),
        NHA.BLACKHOLE => n.blackhole = true,
        NHA.OIF => n.oif = try a.asU32(),
        NHA.GATEWAY => n.gateway = IpAddr.fromAttr(a.data),
        NHA.FDB => n.fdb = true,
        else => {},
    };
    if (!have_id) return null;
    return n;
}

/// A nexthop object to install (`ip nexthop add id N …`).
pub const NexthopSpec = struct {
    /// Non-zero; routes refer to it with `RouteSpec.nhid`.
    id: u32,
    gateway: ?[]const u8 = null,
    oif: ?u32 = null,
    /// `blackhole`: drops. Excludes gateway, oif and group.
    blackhole: bool = false,
    /// `fdb`: a nexthop for bridge/VXLAN FDB entries.
    fdb: bool = false,
    onlink: bool = false,
    /// A group of other nexthops (hash-threshold multipath). Excludes
    /// gateway, oif and blackhole; with `fdb` it is an FDB group (its
    /// members must be FDB nexthops).
    group: []const GroupMember = &.{},
    /// Derived from the gateway when null; IPv4 when nothing implies one
    /// (groups always go out as `AF_UNSPEC`).
    family: ?u8 = null,
    /// `nhmsg.nh_protocol` (`RTPROT.*`); the kernel records it as given.
    protocol: u8 = 0,
};

/// Validate a `NexthopSpec` and return the family byte its message carries.
pub fn nexthopFamily(spec: NexthopSpec) BuildError!u8 {
    if (spec.id == 0) return error.InvalidNexthop;
    const has_group = spec.group.len != 0;
    if (spec.blackhole and (spec.gateway != null or spec.oif != null or has_group)) return error.InvalidNexthop;
    if (has_group and (spec.gateway != null or spec.oif != null)) return error.InvalidNexthop;
    if (spec.group.len > max_spec_hops) return error.TooManyHops;
    for (spec.group) |g| {
        if (g.id == 0 or g.weight < 1 or g.weight > 256) return error.InvalidNexthop;
    }
    if (has_group) return root.AF.UNSPEC;
    const derived = try merge(null, spec.gateway);
    if (spec.family) |f| {
        if (derived) |d| if (d != f) return error.MixedFamilies;
        return f;
    }
    return derived orelse root.AF.INET;
}

/// Build `RTM_NEWNEXTHOP`/`RTM_DELNEXTHOP`/`RTM_GETNEXTHOP` for one id. For
/// a delete or a get only `spec.id` is sent.
pub fn buildNexthopRequest(gpa: Allocator, seq: u32, msg_type: u16, flags: u16, spec: NexthopSpec) BuildError![]u8 {
    const is_new = msg_type == RTM_NEWNEXTHOP;
    const family: u8 = if (is_new) try nexthopFamily(spec) else blk: {
        if (spec.id == 0) return error.InvalidNexthop;
        break :blk root.AF.UNSPEC;
    };

    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(gpa, &list, msg_type, flags, seq, 0);
    var fixed: [nhmsg_len]u8 = @splat(0);
    fixed[0] = family;
    if (is_new) {
        fixed[2] = spec.protocol;
        if (spec.onlink) std.mem.writeInt(u32, fixed[4..8], RTNH_F.ONLINK, native_endian);
    }
    try codec.appendPadded(gpa, &list, &fixed);
    try codec.appendAttrU32(gpa, &list, NHA.ID, spec.id);
    if (is_new) {
        if (spec.group.len != 0) {
            const nest = try codec.nestBegin(gpa, &list, NHA.GROUP);
            for (spec.group) |g| {
                var e: [8]u8 = @splat(0);
                std.mem.writeInt(u32, e[0..4], g.id, native_endian);
                e[4] = @intCast((g.weight - 1) & 0xff);
                e[5] = @intCast((g.weight - 1) >> 8);
                try list.appendSlice(gpa, &e);
            }
            try codec.nestEnd(&list, nest);
        }
        if (spec.blackhole) try put(gpa, &list, NHA.BLACKHOLE, &.{});
        if (spec.oif) |o| try codec.appendAttrU32(gpa, &list, NHA.OIF, o);
        if (spec.gateway) |g| try put(gpa, &list, NHA.GATEWAY, g);
        if (spec.fdb) try put(gpa, &list, NHA.FDB, &.{});
    }
    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

// ── link kinds: write side ──────────────────────────────────────────────────

/// `ip link add … type vxlan id VNI [group|remote A] [local A] [dev D]
/// [dstport P] [ttl T] [learning|nolearning]`. The lower device is
/// `LinkAddSpec.parent`, sent as `IFLA_VXLAN_LINK`.
pub const Vxlan = struct {
    /// 24-bit VXLAN network identifier.
    vni: u32,
    /// Multicast group or unicast remote (4 or 16 bytes).
    group: ?[]const u8 = null,
    local: ?[]const u8 = null,
    /// UDP destination port (host order; sent big-endian). The kernel's
    /// default is 8472.
    port: ?u16 = null,
    ttl: ?u8 = null,
    tos: ?u8 = null,
    learning: ?bool = null,
    /// FDB ageing, seconds.
    ageing: ?u32 = null,
    udp_csum: ?bool = null,
};

pub const MacvlanMode = enum(u32) {
    private = 1,
    vepa = 2,
    bridge = 4,
    passthru = 8,
    source = 16,
};

/// "macvlan" and "macvtap" share their data. The lower device is
/// `LinkAddSpec.parent` and is required.
pub const Macvlan = struct {
    mode: ?MacvlanMode = null,
};

pub const IpvlanMode = enum(u16) { l2 = 0, l3 = 1, l3s = 2 };

/// "ipvlan" and "ipvtap". `flags`: `IPVLAN_F_PRIVATE` (1), `IPVLAN_F_VEPA` (2).
pub const Ipvlan = struct {
    mode: ?IpvlanMode = null,
    flags: ?u16 = null,
};

/// "vrf": the routing table the device owns (non-zero).
pub const Vrf = struct {
    table: u32,
};

pub const BondMode = enum(u8) {
    balance_rr = 0,
    active_backup = 1,
    balance_xor = 2,
    broadcast = 3,
    lacp = 4,
    balance_tlb = 5,
    balance_alb = 6,
};

/// "bond". Intervals are milliseconds.
pub const Bond = struct {
    mode: ?BondMode = null,
    miimon: ?u32 = null,
    updelay: ?u32 = null,
    downdelay: ?u32 = null,
    min_links: ?u32 = null,
    /// `xmit_hash_policy` (0 = layer2, 1 = layer3+4, 2 = layer2+3, …).
    xmit_hash_policy: ?u8 = null,
    /// 802.3ad: 0 = slow, 1 = fast.
    lacp_rate: ?u8 = null,
};

/// "gre" and "gretap" over IPv4 (4-byte addresses). The lower device is
/// `LinkAddSpec.parent`, sent as `IFLA_GRE_LINK`. A key sets the
/// matching `GRE_KEY` flag, as `ip` does.
pub const Gre = struct {
    local: ?[]const u8 = null,
    remote: ?[]const u8 = null,
    ttl: ?u8 = null,
    tos: ?u8 = null,
    ikey: ?u32 = null,
    okey: ?u32 = null,
    pmtudisc: ?bool = null,
};

/// "ipip" and "sit" over IPv4 (4-byte addresses).
pub const Iptun = struct {
    local: ?[]const u8 = null,
    remote: ?[]const u8 = null,
    ttl: ?u8 = null,
    tos: ?u8 = null,
    pmtudisc: ?bool = null,
};

/// "geneve": 24-bit VNI, optional remote (4 or 16 bytes).
pub const Geneve = struct {
    vni: u32,
    remote: ?[]const u8 = null,
    ttl: ?u8 = null,
    tos: ?u8 = null,
    port: ?u16 = null,
    udp_csum: ?bool = null,
};

/// One raw attribute of an `IFLA_INFO_DATA` for a kind this module does not
/// type (`KindData.raw`). `data` is sent as given, in the byte order the kind
/// expects.
pub const RawAttr = struct {
    attr_type: u16,
    data: []const u8,
};

/// Most raw attributes one `KindData.raw` may carry.
pub const max_raw_attrs = 64;

fn dataBegin(gpa: Allocator, list: *std.ArrayList(u8)) BuildError!usize {
    return codec.nestBegin(gpa, list, root.IFLA_INFO.DATA);
}

fn checkAddr(a: ?[]const u8, want4: bool) BuildError!void {
    const x = a orelse return;
    if (want4) {
        if (x.len != 4) return error.InvalidAddressLength;
    } else _ = try famOf(x);
}

pub fn encodeVxlan(gpa: Allocator, list: *std.ArrayList(u8), v: Vxlan, link: ?u32) BuildError!void {
    if (v.vni > 0xffffff) return error.InvalidKindData;
    _ = try merge(try merge(null, v.group), v.local);
    const d = try dataBegin(gpa, list);
    try codec.appendAttrU32(gpa, list, IFLA_VXLAN.ID, v.vni);
    if (v.group) |g| try put(gpa, list, if (g.len == 4) IFLA_VXLAN.GROUP else IFLA_VXLAN.GROUP6, g);
    if (v.local) |l| try put(gpa, list, if (l.len == 4) IFLA_VXLAN.LOCAL else IFLA_VXLAN.LOCAL6, l);
    if (link) |l| try codec.appendAttrU32(gpa, list, IFLA_VXLAN.LINK, l);
    if (v.ttl) |t| try codec.appendAttrU8(gpa, list, IFLA_VXLAN.TTL, t);
    if (v.tos) |t| try codec.appendAttrU8(gpa, list, IFLA_VXLAN.TOS, t);
    if (v.learning) |b| try putBool(gpa, list, IFLA_VXLAN.LEARNING, b);
    if (v.ageing) |a| try codec.appendAttrU32(gpa, list, IFLA_VXLAN.AGEING, a);
    if (v.port) |p| try codec.appendAttrBe16(gpa, list, IFLA_VXLAN.PORT, p);
    if (v.udp_csum) |b| try putBool(gpa, list, IFLA_VXLAN.UDP_CSUM, b);
    try codec.nestEnd(list, d);
}

pub fn encodeMacvlan(gpa: Allocator, list: *std.ArrayList(u8), m: Macvlan) BuildError!void {
    const mode = m.mode orelse return;
    const d = try dataBegin(gpa, list);
    try codec.appendAttrU32(gpa, list, IFLA_MACVLAN.MODE, @backingInt(mode));
    try codec.nestEnd(list, d);
}

pub fn encodeIpvlan(gpa: Allocator, list: *std.ArrayList(u8), v: Ipvlan) BuildError!void {
    if (v.mode == null and v.flags == null) return;
    const d = try dataBegin(gpa, list);
    if (v.mode) |m| try codec.appendAttrU16(gpa, list, IFLA_IPVLAN.MODE, @backingInt(m));
    if (v.flags) |f| try codec.appendAttrU16(gpa, list, IFLA_IPVLAN.FLAGS, f);
    try codec.nestEnd(list, d);
}

pub fn encodeVrf(gpa: Allocator, list: *std.ArrayList(u8), v: Vrf) BuildError!void {
    if (v.table == 0) return error.InvalidKindData;
    const d = try dataBegin(gpa, list);
    try codec.appendAttrU32(gpa, list, IFLA_VRF.TABLE, v.table);
    try codec.nestEnd(list, d);
}

pub fn encodeBond(gpa: Allocator, list: *std.ArrayList(u8), b: Bond) BuildError!void {
    if (b.mode == null and b.miimon == null and b.updelay == null and b.downdelay == null and
        b.min_links == null and b.xmit_hash_policy == null and b.lacp_rate == null) return;
    const d = try dataBegin(gpa, list);
    if (b.mode) |m| try codec.appendAttrU8(gpa, list, IFLA_BOND.MODE, @backingInt(m));
    if (b.miimon) |v| try codec.appendAttrU32(gpa, list, IFLA_BOND.MIIMON, v);
    if (b.updelay) |v| try codec.appendAttrU32(gpa, list, IFLA_BOND.UPDELAY, v);
    if (b.downdelay) |v| try codec.appendAttrU32(gpa, list, IFLA_BOND.DOWNDELAY, v);
    if (b.xmit_hash_policy) |v| try codec.appendAttrU8(gpa, list, IFLA_BOND.XMIT_HASH_POLICY, v);
    if (b.min_links) |v| try codec.appendAttrU32(gpa, list, IFLA_BOND.MIN_LINKS, v);
    if (b.lacp_rate) |v| try codec.appendAttrU8(gpa, list, IFLA_BOND.AD_LACP_RATE, v);
    try codec.nestEnd(list, d);
}

pub fn encodeGre(gpa: Allocator, list: *std.ArrayList(u8), g: Gre, link: ?u32) BuildError!void {
    try checkAddr(g.local, true);
    try checkAddr(g.remote, true);
    const d = try dataBegin(gpa, list);
    if (link) |l| try codec.appendAttrU32(gpa, list, IFLA_GRE.LINK, l);
    if (g.ikey != null) try codec.appendAttrBe16(gpa, list, IFLA_GRE.IFLAGS, GRE_KEY);
    if (g.okey != null) try codec.appendAttrBe16(gpa, list, IFLA_GRE.OFLAGS, GRE_KEY);
    if (g.ikey) |k| try codec.appendAttrBe32(gpa, list, IFLA_GRE.IKEY, k);
    if (g.okey) |k| try codec.appendAttrBe32(gpa, list, IFLA_GRE.OKEY, k);
    if (g.local) |a| try put(gpa, list, IFLA_GRE.LOCAL, a);
    if (g.remote) |a| try put(gpa, list, IFLA_GRE.REMOTE, a);
    if (g.ttl) |v| try codec.appendAttrU8(gpa, list, IFLA_GRE.TTL, v);
    if (g.tos) |v| try codec.appendAttrU8(gpa, list, IFLA_GRE.TOS, v);
    if (g.pmtudisc) |v| try putBool(gpa, list, IFLA_GRE.PMTUDISC, v);
    try codec.nestEnd(list, d);
}

pub fn encodeIptun(gpa: Allocator, list: *std.ArrayList(u8), t: Iptun, link: ?u32) BuildError!void {
    try checkAddr(t.local, true);
    try checkAddr(t.remote, true);
    const d = try dataBegin(gpa, list);
    if (link) |l| try codec.appendAttrU32(gpa, list, IFLA_IPTUN.LINK, l);
    if (t.local) |a| try put(gpa, list, IFLA_IPTUN.LOCAL, a);
    if (t.remote) |a| try put(gpa, list, IFLA_IPTUN.REMOTE, a);
    if (t.ttl) |v| try codec.appendAttrU8(gpa, list, IFLA_IPTUN.TTL, v);
    if (t.tos) |v| try codec.appendAttrU8(gpa, list, IFLA_IPTUN.TOS, v);
    if (t.pmtudisc) |v| try putBool(gpa, list, IFLA_IPTUN.PMTUDISC, v);
    try codec.nestEnd(list, d);
}

pub fn encodeGeneve(gpa: Allocator, list: *std.ArrayList(u8), g: Geneve) BuildError!void {
    if (g.vni > 0xffffff) return error.InvalidKindData;
    try checkAddr(g.remote, false);
    const d = try dataBegin(gpa, list);
    try codec.appendAttrU32(gpa, list, IFLA_GENEVE.ID, g.vni);
    if (g.remote) |r| try put(gpa, list, if (r.len == 4) IFLA_GENEVE.REMOTE else IFLA_GENEVE.REMOTE6, r);
    if (g.ttl) |v| try codec.appendAttrU8(gpa, list, IFLA_GENEVE.TTL, v);
    if (g.tos) |v| try codec.appendAttrU8(gpa, list, IFLA_GENEVE.TOS, v);
    if (g.port) |p| try codec.appendAttrBe16(gpa, list, IFLA_GENEVE.PORT, p);
    if (g.udp_csum) |v| try putBool(gpa, list, IFLA_GENEVE.UDP_CSUM, v);
    try codec.nestEnd(list, d);
}

pub fn encodeRaw(gpa: Allocator, list: *std.ArrayList(u8), attrs: []const RawAttr) BuildError!void {
    if (attrs.len > max_raw_attrs) return error.TooManyAttrs;
    if (attrs.len == 0) return;
    const d = try dataBegin(gpa, list);
    for (attrs) |a| try put(gpa, list, a.attr_type, a.data);
    try codec.nestEnd(list, d);
}

// ── link kinds: read side ───────────────────────────────────────────────────

pub const VxlanInfo = struct {
    vni: u32 = 0,
    group: IpAddr = .{},
    local: IpAddr = .{},
    /// `IFLA_VXLAN_LINK`; 0 when absent.
    link: u32 = 0,
    port: u16 = 0,
    ttl: u8 = 0,
    tos: u8 = 0,
    learning: bool = false,
    ageing: u32 = 0,
    udp_csum: bool = false,
};

pub const MacvlanInfo = struct {
    /// `MacvlanMode` value (`@intFromEnum` of an unknown value is not safe,
    /// so the raw number is kept).
    mode: u32 = 0,
};

pub const IpvlanInfo = struct {
    mode: u16 = 0,
    flags: u16 = 0,
};

pub const VrfInfo = struct {
    table: u32 = 0,
};

pub const BondInfo = struct {
    mode: u8 = 0,
    miimon: u32 = 0,
    updelay: u32 = 0,
    downdelay: u32 = 0,
    min_links: u32 = 0,
    xmit_hash_policy: u8 = 0,
    lacp_rate: u8 = 0,
};

/// The options of a bridge device (`ip -d link show br0`). Times are the
/// kernel's centiseconds.
pub const BridgeInfo = struct {
    forward_delay: u32 = 0,
    hello_time: u32 = 0,
    max_age: u32 = 0,
    ageing_time: u32 = 0,
    stp_state: u32 = 0,
    priority: u16 = 0,
    vlan_filtering: bool = false,
    /// Host order: 0x8100 or 0x88a8.
    vlan_protocol: u16 = 0,
    group_fwd_mask: u16 = 0,
    vlan_default_pvid: u16 = 0,
    mcast_snooping: bool = false,
    mcast_querier: bool = false,
};

pub const GreInfo = struct {
    link: u32 = 0,
    local: IpAddr = .{},
    remote: IpAddr = .{},
    ttl: u8 = 0,
    tos: u8 = 0,
    /// Host order; valid when the `GRE_KEY` bit is in `iflags`/`oflags`.
    ikey: u32 = 0,
    okey: u32 = 0,
    iflags: u16 = 0,
    oflags: u16 = 0,
    pmtudisc: bool = false,
};

pub const IptunInfo = struct {
    link: u32 = 0,
    local: IpAddr = .{},
    remote: IpAddr = .{},
    ttl: u8 = 0,
    tos: u8 = 0,
    pmtudisc: bool = false,
};

pub const GeneveInfo = struct {
    vni: u32 = 0,
    remote: IpAddr = .{},
    ttl: u8 = 0,
    tos: u8 = 0,
    port: u16 = 0,
    udp_csum: bool = false,
};

/// A link's decoded `IFLA_INFO_DATA`, selected by its `IFLA_INFO_KIND`
/// ("vlan" keeps its own `Link.vlan_id`/`vlan_protocol`; veth has no data).
pub const KindInfo = union(enum) {
    none,
    vxlan: VxlanInfo,
    macvlan: MacvlanInfo,
    ipvlan: IpvlanInfo,
    vrf: VrfInfo,
    bond: BondInfo,
    bridge: BridgeInfo,
    gre: GreInfo,
    iptun: IptunInfo,
    geneve: GeneveInfo,
};

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

/// Decode `data` (the payload of `IFLA_INFO_DATA`) for `kind`. A kind this
/// module does not type yields `.none`; malformed bytes of a typed kind are
/// `error.Truncated`/`error.BadLength`, never a panic.
pub fn parseKindInfo(kind: []const u8, data: []const u8) codec.Error!KindInfo {
    var it: codec.AttrIterator = .{ .buf = data };
    if (eql(kind, "vxlan")) {
        var v: VxlanInfo = .{};
        while (try it.next()) |a| switch (a.type) {
            IFLA_VXLAN.ID => v.vni = try a.asU32(),
            IFLA_VXLAN.GROUP, IFLA_VXLAN.GROUP6 => v.group = IpAddr.fromAttr(a.data),
            IFLA_VXLAN.LOCAL, IFLA_VXLAN.LOCAL6 => v.local = IpAddr.fromAttr(a.data),
            IFLA_VXLAN.LINK => v.link = try a.asU32(),
            IFLA_VXLAN.TTL => v.ttl = try a.asU8(),
            IFLA_VXLAN.TOS => v.tos = try a.asU8(),
            IFLA_VXLAN.LEARNING => v.learning = try readBool(a),
            IFLA_VXLAN.AGEING => v.ageing = try a.asU32(),
            IFLA_VXLAN.PORT => v.port = try a.asBe16(),
            IFLA_VXLAN.UDP_CSUM => v.udp_csum = try readBool(a),
            else => {},
        };
        return .{ .vxlan = v };
    }
    if (eql(kind, "macvlan") or eql(kind, "macvtap")) {
        var v: MacvlanInfo = .{};
        while (try it.next()) |a| switch (a.type) {
            IFLA_MACVLAN.MODE => v.mode = try a.asU32(),
            else => {},
        };
        return .{ .macvlan = v };
    }
    if (eql(kind, "ipvlan") or eql(kind, "ipvtap")) {
        var v: IpvlanInfo = .{};
        while (try it.next()) |a| switch (a.type) {
            IFLA_IPVLAN.MODE => v.mode = try a.asU16(),
            IFLA_IPVLAN.FLAGS => v.flags = try a.asU16(),
            else => {},
        };
        return .{ .ipvlan = v };
    }
    if (eql(kind, "vrf")) {
        var v: VrfInfo = .{};
        while (try it.next()) |a| switch (a.type) {
            IFLA_VRF.TABLE => v.table = try a.asU32(),
            else => {},
        };
        return .{ .vrf = v };
    }
    if (eql(kind, "bond")) {
        var v: BondInfo = .{};
        while (try it.next()) |a| switch (a.type) {
            IFLA_BOND.MODE => v.mode = try a.asU8(),
            IFLA_BOND.MIIMON => v.miimon = try a.asU32(),
            IFLA_BOND.UPDELAY => v.updelay = try a.asU32(),
            IFLA_BOND.DOWNDELAY => v.downdelay = try a.asU32(),
            IFLA_BOND.MIN_LINKS => v.min_links = try a.asU32(),
            IFLA_BOND.XMIT_HASH_POLICY => v.xmit_hash_policy = try a.asU8(),
            IFLA_BOND.AD_LACP_RATE => v.lacp_rate = try a.asU8(),
            else => {},
        };
        return .{ .bond = v };
    }
    if (eql(kind, "bridge")) {
        var v: BridgeInfo = .{};
        while (try it.next()) |a| switch (a.type) {
            IFLA_BR.HELLO_TIME => v.hello_time = try a.asU32(),
            IFLA_BR.MAX_AGE => v.max_age = try a.asU32(),
            root.IFLA_BR.FORWARD_DELAY => v.forward_delay = try a.asU32(),
            root.IFLA_BR.AGEING_TIME => v.ageing_time = try a.asU32(),
            root.IFLA_BR.STP_STATE => v.stp_state = try a.asU32(),
            root.IFLA_BR.PRIORITY => v.priority = try a.asU16(),
            root.IFLA_BR.VLAN_FILTERING => v.vlan_filtering = try readBool(a),
            root.IFLA_BR.VLAN_PROTOCOL => v.vlan_protocol = try a.asBe16(),
            IFLA_BR.GROUP_FWD_MASK => v.group_fwd_mask = try a.asU16(),
            IFLA_BR.VLAN_DEFAULT_PVID => v.vlan_default_pvid = try a.asU16(),
            IFLA_BR.MCAST_SNOOPING => v.mcast_snooping = try readBool(a),
            IFLA_BR.MCAST_QUERIER => v.mcast_querier = try readBool(a),
            else => {},
        };
        return .{ .bridge = v };
    }
    if (eql(kind, "gre") or eql(kind, "gretap")) {
        var v: GreInfo = .{};
        while (try it.next()) |a| switch (a.type) {
            IFLA_GRE.LINK => v.link = try a.asU32(),
            IFLA_GRE.IFLAGS => v.iflags = try a.asBe16(),
            IFLA_GRE.OFLAGS => v.oflags = try a.asBe16(),
            IFLA_GRE.IKEY => v.ikey = try a.asBe32(),
            IFLA_GRE.OKEY => v.okey = try a.asBe32(),
            IFLA_GRE.LOCAL => v.local = IpAddr.fromAttr(a.data),
            IFLA_GRE.REMOTE => v.remote = IpAddr.fromAttr(a.data),
            IFLA_GRE.TTL => v.ttl = try a.asU8(),
            IFLA_GRE.TOS => v.tos = try a.asU8(),
            IFLA_GRE.PMTUDISC => v.pmtudisc = try readBool(a),
            else => {},
        };
        return .{ .gre = v };
    }
    if (eql(kind, "ipip") or eql(kind, "sit")) {
        var v: IptunInfo = .{};
        while (try it.next()) |a| switch (a.type) {
            IFLA_IPTUN.LINK => v.link = try a.asU32(),
            IFLA_IPTUN.LOCAL => v.local = IpAddr.fromAttr(a.data),
            IFLA_IPTUN.REMOTE => v.remote = IpAddr.fromAttr(a.data),
            IFLA_IPTUN.TTL => v.ttl = try a.asU8(),
            IFLA_IPTUN.TOS => v.tos = try a.asU8(),
            IFLA_IPTUN.PMTUDISC => v.pmtudisc = try readBool(a),
            else => {},
        };
        return .{ .iptun = v };
    }
    if (eql(kind, "geneve")) {
        var v: GeneveInfo = .{};
        while (try it.next()) |a| switch (a.type) {
            IFLA_GENEVE.ID => v.vni = try a.asU32(),
            IFLA_GENEVE.REMOTE, IFLA_GENEVE.REMOTE6 => v.remote = IpAddr.fromAttr(a.data),
            IFLA_GENEVE.TTL => v.ttl = try a.asU8(),
            IFLA_GENEVE.TOS => v.tos = try a.asU8(),
            IFLA_GENEVE.PORT => v.port = try a.asBe16(),
            IFLA_GENEVE.UDP_CSUM => v.udp_csum = try readBool(a),
            else => {},
        };
        return .{ .geneve = v };
    }
    return .none;
}
