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
//! Scope: read/dump only. Write ops (RTM_NEW*/RTM_DEL*) and multicast event
//! monitoring are deliberate future extensions — the transport already speaks
//! sequence numbers, ACK/NLMSG_ERROR errno decoding and multi-part assembly,
//! so adding them is a matter of new request builders, not a redesign.
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

pub const meta = .{
    .status = .gap, // no maintained pure-Zig netlink library exists
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

// Attribute types taken from std.os.linux enums.
const ifla_address: u16 = @intFromEnum(linux.IFLA.ADDRESS);
const ifla_ifname: u16 = @intFromEnum(linux.IFLA.IFNAME);
const ifla_mtu: u16 = @intFromEnum(linux.IFLA.MTU);
const ifa_address: u16 = @intFromEnum(linux.IFA.ADDRESS);
const ifa_local: u16 = @intFromEnum(linux.IFA.LOCAL);
const ifa_label: u16 = @intFromEnum(linux.IFA.LABEL);

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
                    if (m.pid != self.portid or m.seq != seq) continue;
                    if (m.flags & codec.NLM_F_DUMP_INTR != 0) {
                        out.deinit(self.gpa);
                        if (attempt < max_dump_attempts) continue :retry;
                        return error.InconsistentDump;
                    }
                    switch (m.type) {
                        codec.NLMSG_DONE => return out.toOwnedSlice(self.gpa),
                        codec.NLMSG_ERROR => {
                            const code = m.errorCode() catch return error.MalformedReply;
                            if (code == 0) return out.toOwnedSlice(self.gpa); // ACK
                            return errorFromCode(code);
                        },
                        codec.NLMSG_NOOP => {},
                        codec.NLMSG_OVERRUN => return error.SystemResources,
                        else => {
                            if (m.type != reply_type) continue;
                            const parsed = parseFn(m.payload) catch return error.MalformedReply;
                            if (parsed) |item| if (matchFn(item, filter))
                                try out.append(self.gpa, item);
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
        self.seq +%= 1;
        if (self.seq == 0) self.seq = 1;
        var req: [codec.header_len + ifinfomsg_len]u8 = @splat(0);
        const total = codec.header_len + fixed_len; // fixed headers are 4-aligned
        std.debug.assert(total <= req.len);
        std.mem.writeInt(u32, req[0..4], @intCast(total), native_endian);
        std.mem.writeInt(u16, req[4..6], msg_type, native_endian);
        std.mem.writeInt(u16, req[6..8], codec.NLM_F_REQUEST | codec.NLM_F_DUMP, native_endian);
        std.mem.writeInt(u32, req[8..12], self.seq, native_endian);
        // nlmsg_pid stays 0: the kernel routes replies by socket, and fills
        // the reply pid with our bound portid (libmnl requests do the same).
        req[codec.header_len] = family;

        const dst: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
        while (true) {
            const rc = linux.sendto(self.fd, &req, total, 0, @ptrCast(&dst), @sizeOf(linux.sockaddr.nl));
            switch (linux.errno(rc)) {
                .SUCCESS => return self.seq,
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
    fn recvDatagram(self: *Socket) DumpError![]const u8 {
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

test {
    _ = codec;
}
