// SPDX-License-Identifier: MIT
//! ctnetlink wire layer — the pure, I/O-free half of the `conntrack` module:
//! the `nfgenmsg` header, the CTA_* attribute tree, a typed `Flow`/`Tuple`
//! decoder and the request builders. No syscalls, no sockets: everything here
//! operates on byte slices and is unit-, golden- and fuzz-testable on any OS.
//!
//! Framing (kernel UAPI `linux/netfilter/nfnetlink.h`,
//! `linux/netfilter/nfnetlink_conntrack.h`):
//!
//! ```text
//! nlmsghdr  (16 B, netlink.codec)   nlmsg_type = subsys << 8 | cmd
//! nfgenmsg  (4 B)                   u8 nfgen_family | u8 version | be16 res_id
//! nlattr TLVs                       CTA_* (netlink.codec's nlattr walker)
//! ```
//!
//! **Byte order is the classic ctnetlink trap.** netlink itself is host-endian,
//! but every ctnetlink *integer* attribute — `CTA_STATUS`, `CTA_TIMEOUT`,
//! `CTA_MARK`, `CTA_ID`, `CTA_USE`, `CTA_ZONE`, the ports, the ICMP id, the
//! 64-bit counters, and `nfgenmsg.res_id` — is **big-endian on the wire**, and
//! the kernel does *not* set `NLA_F_NET_BYTEORDER` on them (verified against
//! the captures in `goldens.zig`: `CTA_STATUS` arrives as
//! `08 00 03 00 | 00 00 00 0a`, type word `0x0003` with no flag bits, payload
//! `0x0000000a` = `IPS_SEEN_REPLY|IPS_CONFIRMED`). Only the raw address bytes
//! (`CTA_IP_V4_*`/`CTA_IP_V6_*`) and the u8 fields are endian-free. Every
//! integer here therefore goes through `netlink.codec`'s big-endian accessors
//! (`Attr.asBe16/32/64`, `codec.appendAttrBe16/32/64`); the host-endian
//! `asU16`/`asU32` twins are deliberately **not** used for payload values.
//!
//! Provenance: clean-room from the kernel UAPI headers
//! (`nfnetlink.h`, `nfnetlink_conntrack.h`, `nf_conntrack_common.h`,
//! `nf_conntrack_tcp.h` — GPL-2.0 WITH Linux-syscall-note; the constants and
//! their layouts are the kernel's OS ABI) plus the on-the-wire captures in
//! `goldens.zig`. No libnetfilter_conntrack / conntrack-tools source was read.
//! See /NOTICE.

const std = @import("std");
const builtin = @import("builtin");
const netlink = @import("netlink");
const netaddr = @import("netaddr");
const codec = netlink.codec;
const native_endian = builtin.cpu.arch.endian();

// ── kernel UAPI constants ───────────────────────────────────────────────────

/// sizeof(struct nfgenmsg) — already 4-byte aligned.
pub const nfgenmsg_len = 4;

/// NFNETLINK_V0 — the only nfnetlink protocol version there is.
pub const NFNETLINK_V0: u8 = 0;

/// NFNL_SUBSYS_CTNETLINK — the conntrack subsystem id (linux/netfilter/nfnetlink.h).
pub const NFNL_SUBSYS_CTNETLINK: u16 = 1;

/// `enum cntl_msg_types` — the low byte of `nlmsg_type`.
pub const IPCTNL_MSG_CT_NEW: u8 = 0;
pub const IPCTNL_MSG_CT_GET: u8 = 1;
pub const IPCTNL_MSG_CT_DELETE: u8 = 2;
pub const IPCTNL_MSG_CT_GET_CTRZERO: u8 = 3;
pub const IPCTNL_MSG_CT_GET_STATS_CPU: u8 = 4;
pub const IPCTNL_MSG_CT_GET_STATS: u8 = 5;
pub const IPCTNL_MSG_CT_GET_DYING: u8 = 6;
pub const IPCTNL_MSG_CT_GET_UNCONFIRMED: u8 = 7;

/// Compose an nfnetlink `nlmsg_type`: `subsys << 8 | cmd`.
pub fn msgType(subsys: u16, cmd: u8) u16 {
    return (subsys << 8) | cmd;
}

/// The three ctnetlink message types this module speaks.
pub const msg_ct_new = msgType(NFNL_SUBSYS_CTNETLINK, IPCTNL_MSG_CT_NEW);
pub const msg_ct_get = msgType(NFNL_SUBSYS_CTNETLINK, IPCTNL_MSG_CT_GET);
pub const msg_ct_delete = msgType(NFNL_SUBSYS_CTNETLINK, IPCTNL_MSG_CT_DELETE);

/// `enum ctattr_type` — attributes of a conntrack entry.
pub const CTA = struct {
    pub const UNSPEC: u16 = 0;
    pub const TUPLE_ORIG: u16 = 1;
    pub const TUPLE_REPLY: u16 = 2;
    pub const STATUS: u16 = 3;
    pub const PROTOINFO: u16 = 4;
    pub const HELP: u16 = 5;
    pub const NAT_SRC: u16 = 6;
    pub const TIMEOUT: u16 = 7;
    pub const MARK: u16 = 8;
    pub const COUNTERS_ORIG: u16 = 9;
    pub const COUNTERS_REPLY: u16 = 10;
    pub const USE: u16 = 11;
    pub const ID: u16 = 12;
    pub const NAT_DST: u16 = 13;
    pub const TUPLE_MASTER: u16 = 14;
    pub const SEQ_ADJ_ORIG: u16 = 15;
    pub const SEQ_ADJ_REPLY: u16 = 16;
    pub const SECMARK: u16 = 17; // obsolete
    pub const ZONE: u16 = 18;
    pub const SECCTX: u16 = 19;
    pub const TIMESTAMP: u16 = 20;
    pub const MARK_MASK: u16 = 21;
    pub const LABELS: u16 = 22;
    pub const LABELS_MASK: u16 = 23;
    pub const SYNPROXY: u16 = 24;
    pub const FILTER: u16 = 25;
    pub const STATUS_MASK: u16 = 26;
    pub const TIMESTAMP_EVENT: u16 = 27;
};

/// `enum ctattr_tuple` — inside CTA_TUPLE_ORIG/REPLY/MASTER.
pub const CTA_TUPLE = struct {
    pub const UNSPEC: u16 = 0;
    pub const IP: u16 = 1;
    pub const PROTO: u16 = 2;
    pub const ZONE: u16 = 3;
};

/// `enum ctattr_ip` — inside CTA_TUPLE_IP.
pub const CTA_IP = struct {
    pub const UNSPEC: u16 = 0;
    pub const V4_SRC: u16 = 1;
    pub const V4_DST: u16 = 2;
    pub const V6_SRC: u16 = 3;
    pub const V6_DST: u16 = 4;
};

/// `enum ctattr_l4proto` — inside CTA_TUPLE_PROTO.
pub const CTA_PROTO = struct {
    pub const UNSPEC: u16 = 0;
    pub const NUM: u16 = 1;
    pub const SRC_PORT: u16 = 2;
    pub const DST_PORT: u16 = 3;
    pub const ICMP_ID: u16 = 4;
    pub const ICMP_TYPE: u16 = 5;
    pub const ICMP_CODE: u16 = 6;
    pub const ICMPV6_ID: u16 = 7;
    pub const ICMPV6_TYPE: u16 = 8;
    pub const ICMPV6_CODE: u16 = 9;
};

/// `enum ctattr_protoinfo` — inside CTA_PROTOINFO.
pub const CTA_PROTOINFO = struct {
    pub const UNSPEC: u16 = 0;
    pub const TCP: u16 = 1;
    pub const DCCP: u16 = 2;
    pub const SCTP: u16 = 3;
};

/// `enum ctattr_protoinfo_tcp` — inside CTA_PROTOINFO_TCP.
pub const CTA_PROTOINFO_TCP = struct {
    pub const UNSPEC: u16 = 0;
    pub const STATE: u16 = 1;
    pub const WSCALE_ORIGINAL: u16 = 2;
    pub const WSCALE_REPLY: u16 = 3;
    pub const FLAGS_ORIGINAL: u16 = 4;
    pub const FLAGS_REPLY: u16 = 5;
};

/// `enum ctattr_counters` — inside CTA_COUNTERS_ORIG/_REPLY.
pub const CTA_COUNTERS = struct {
    pub const UNSPEC: u16 = 0;
    pub const PACKETS: u16 = 1; // 64-bit, big-endian
    pub const BYTES: u16 = 2; // 64-bit, big-endian
    pub const PACKETS32: u16 = 3; // old 32-bit, unused by current kernels
    pub const BYTES32: u16 = 4;
    pub const PAD: u16 = 5;
};

/// `enum ctattr_tstamp` — inside CTA_TIMESTAMP (nanoseconds since boot-epoch).
pub const CTA_TIMESTAMP = struct {
    pub const UNSPEC: u16 = 0;
    pub const START: u16 = 1; // 64-bit, big-endian
    pub const STOP: u16 = 2;
    pub const PAD: u16 = 3;
};

/// `enum ip_conntrack_status` (linux/netfilter/nf_conntrack_common.h) — the
/// bits of `CTA_STATUS`.
pub const IPS = struct {
    pub const EXPECTED: u32 = 1 << 0;
    pub const SEEN_REPLY: u32 = 1 << 1;
    pub const ASSURED: u32 = 1 << 2;
    pub const CONFIRMED: u32 = 1 << 3;
    pub const SRC_NAT: u32 = 1 << 4;
    pub const DST_NAT: u32 = 1 << 5;
    pub const NAT_MASK: u32 = SRC_NAT | DST_NAT;
    pub const SEQ_ADJUST: u32 = 1 << 6;
    pub const SRC_NAT_DONE: u32 = 1 << 7;
    pub const DST_NAT_DONE: u32 = 1 << 8;
    pub const NAT_DONE_MASK: u32 = SRC_NAT_DONE | DST_NAT_DONE;
    pub const DYING: u32 = 1 << 9;
    pub const FIXED_TIMEOUT: u32 = 1 << 10;
    pub const TEMPLATE: u32 = 1 << 11;
    pub const UNTRACKED: u32 = 1 << 12;
    pub const HELPER: u32 = 1 << 13;
    pub const OFFLOAD: u32 = 1 << 14;
    pub const HW_OFFLOAD: u32 = 1 << 15;
};

/// `enum tcp_conntrack` (linux/netfilter/nf_conntrack_tcp.h) — the value of
/// `CTA_PROTOINFO_TCP_STATE`. Not the TCP wire state machine: conntrack's own.
pub const TcpState = enum(u8) {
    none = 0,
    syn_sent = 1,
    syn_recv = 2,
    established = 3,
    fin_wait = 4,
    close_wait = 5,
    last_ack = 6,
    time_wait = 7,
    close = 8,
    /// `TCP_CONNTRACK_LISTEN`, aliased `SYN_SENT2` — simultaneous open.
    syn_sent2 = 9,
    _,
};

/// `struct nf_ct_tcp_flags` — the payload of CTA_PROTOINFO_TCP_FLAGS_*.
pub const TcpFlags = struct {
    flags: u8 = 0,
    mask: u8 = 0,
};

/// IP protocol numbers this module gives special tuple treatment to.
pub const IPPROTO = struct {
    pub const ICMP: u8 = 1;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
    pub const DCCP: u8 = 33;
    pub const ICMPV6: u8 = 58;
    pub const SCTP: u8 = 132;
    pub const UDPLITE: u8 = 136;
};

/// Address family of a request or a decoded entry (`nfgen_family`). The
/// numeric values are `AF_UNSPEC`/`AF_INET`/`AF_INET6`.
pub const Family = enum(u8) {
    unspec = 0,
    ipv4 = 2,
    ipv6 = 10,
    _,

    pub fn of(ip: netaddr.Ip) Family {
        return switch (ip) {
            .v4 => .ipv4,
            .v6 => .ipv6,
        };
    }
};

// ── errors ──────────────────────────────────────────────────────────────────

/// Everything the decoder can reject. `Truncated`/`BadLength` come straight
/// from `netlink.codec`'s bounds-checked walkers.
pub const DecodeError = codec.Error;

/// Everything a request builder can reject.
pub const BuildError = std.mem.Allocator.Error || error{
    /// A tuple is missing the source address, the destination address or the
    /// protocol number — the kernel's lookup key is incomplete.
    IncompleteTuple,
    /// The source and destination addresses are of different families.
    AddressFamilyMismatch,
    /// An attribute payload exceeded 65535 bytes (cannot happen for any
    /// ctnetlink attribute this module builds; propagated for completeness).
    AttrTooLong,
};

// The net-byte-order attribute accessors this module needs — `asBe16/32/64`
// and `appendAttrBe16/32/64` — now live in `netlink.codec`, next to their
// host-order twins, and are used from there (`a.asBe32()`,
// `codec.appendAttrBe32(…)`). They were duplicated here and in
// `modules/nftables` before; every netfilter family (ctnetlink, nftables,
// nfqueue, nflog, cttimeout) needs exactly them.

// ── nfgenmsg ────────────────────────────────────────────────────────────────

/// The 4-byte nfnetlink family header plus the attribute bytes behind it.
pub const Nfgenmsg = struct {
    family: u8,
    version: u8,
    res_id: u16,
    /// The attribute region of the message payload (borrowed).
    attrs: []const u8,

    pub fn attrIterator(h: Nfgenmsg) codec.AttrIterator {
        return .{ .buf = h.attrs };
    }
};

/// Split a netlink message payload into its `nfgenmsg` and the TLVs after it.
pub fn parseNfgenmsg(payload: []const u8) DecodeError!Nfgenmsg {
    if (payload.len < nfgenmsg_len) return error.Truncated;
    return .{
        .family = payload[0],
        .version = payload[1],
        // res_id is __be16 (the kernel writes htons(0) for conntrack).
        .res_id = std.mem.readInt(u16, payload[2..4], .big),
        .attrs = payload[nfgenmsg_len..],
    };
}

/// Append a `struct nfgenmsg { u8 nfgen_family; u8 version; __be16 res_id; }`.
pub fn appendNfgenmsg(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    family: Family,
    res_id: u16,
) std.mem.Allocator.Error!void {
    var raw: [nfgenmsg_len]u8 = undefined;
    raw[0] = @intFromEnum(family);
    raw[1] = NFNETLINK_V0;
    std.mem.writeInt(u16, raw[2..4], res_id, .big);
    try list.appendSlice(gpa, &raw);
}

// ── typed model ─────────────────────────────────────────────────────────────

/// One direction's lookup key: L3 addresses plus the L4 discriminator.
///
/// Every field is optional because the decoder must survive a hostile or a
/// future-kernel attribute stream; a tuple decoded from a real entry always
/// has `src`, `dst` and `proto` set (`isComplete`). The builders reject an
/// incomplete tuple with `error.IncompleteTuple`.
///
/// The L4 fields are a flat union-by-convention, exactly like the wire: TCP,
/// UDP, DCCP, SCTP and UDP-Lite use `src_port`/`dst_port`; ICMP and ICMPv6 use
/// `icmp_id`/`icmp_type`/`icmp_code` (encoded as `CTA_PROTO_ICMP_*` or
/// `CTA_PROTO_ICMPV6_*` depending on `proto`, decoded from either).
pub const Tuple = struct {
    src: ?netaddr.Ip = null,
    dst: ?netaddr.Ip = null,
    proto: ?u8 = null,
    src_port: ?u16 = null,
    dst_port: ?u16 = null,
    icmp_id: ?u16 = null,
    icmp_type: ?u8 = null,
    icmp_code: ?u8 = null,
    /// `CTA_TUPLE_ZONE` — the per-direction conntrack zone, distinct from the
    /// entry-wide `Flow.zone` (`CTA_ZONE`).
    zone: ?u16 = null,

    /// A tuple the kernel can look an entry up with.
    pub fn isComplete(t: Tuple) bool {
        return t.src != null and t.dst != null and t.proto != null;
    }

    pub fn family(t: Tuple) Family {
        const ip = t.src orelse t.dst orelse return .unspec;
        return Family.of(ip);
    }

    /// The opposite direction of this tuple: addresses and ports swapped, and
    /// the ICMP type mapped to its answer (echo 8↔0, timestamp 13↔14, info
    /// 15↔16, address-mask 17↔18; ICMPv6 echo 128↔129). Types outside that
    /// table are copied unchanged — the kernel would not track them as a
    /// request/reply pair either. Convenience only: a caller who knows the
    /// exact reply tuple should build it explicitly.
    pub fn invert(t: Tuple) Tuple {
        var out = t;
        out.src = t.dst;
        out.dst = t.src;
        out.src_port = t.dst_port;
        out.dst_port = t.src_port;
        if (t.icmp_type) |ty| out.icmp_type = invertIcmpType(ty, t.proto orelse 0);
        return out;
    }
};

fn invertIcmpType(ty: u8, proto: u8) u8 {
    if (proto == IPPROTO.ICMPV6) return switch (ty) {
        128 => 129,
        129 => 128,
        else => ty,
    };
    return switch (ty) {
        8 => 0, // echo request -> echo reply
        0 => 8,
        13 => 14, // timestamp
        14 => 13,
        15 => 16, // information
        16 => 15,
        17 => 18, // address mask
        18 => 17,
        else => ty,
    };
}

/// A packet/byte counter pair (`CTA_COUNTERS_ORIG`/`_REPLY`). Present only
/// when the kernel has `net.netfilter.nf_conntrack_acct = 1`.
pub const Counters = struct {
    packets: u64 = 0,
    bytes: u64 = 0,
};

/// One conntrack entry, decoded. Fixed size and pointer-free: a `[]Flow`
/// frees with a single `gpa.free`.
pub const Flow = struct {
    /// `nfgen_family` of the carrying message.
    family: Family = .unspec,
    orig: Tuple = .{},
    reply: Tuple = .{},
    /// `CTA_STATUS` — a bit set of `IPS.*`.
    status: ?u32 = null,
    /// `CTA_TIMEOUT` — seconds until the entry expires.
    timeout: ?u32 = null,
    /// `CTA_MARK` — the connmark.
    mark: ?u32 = null,
    /// `CTA_ID` — the kernel's per-entry handle. Stable for the entry's
    /// lifetime, reused afterwards; usable only to *confirm* a delete, never
    /// as a lookup key (see `buildDeleteRequest`).
    id: ?u32 = null,
    /// `CTA_USE` — the entry's kernel refcount.
    use: ?u32 = null,
    /// `CTA_ZONE` — the conntrack zone of the whole entry.
    zone: ?u16 = null,
    counters_orig: ?Counters = null,
    counters_reply: ?Counters = null,
    /// `CTA_PROTOINFO_TCP_STATE`.
    tcp_state: ?TcpState = null,
    tcp_wscale_orig: ?u8 = null,
    tcp_wscale_reply: ?u8 = null,
    tcp_flags_orig: ?TcpFlags = null,
    tcp_flags_reply: ?TcpFlags = null,
    /// `CTA_TIMESTAMP_START`/`_STOP` in nanoseconds (kernel boot-based clock).
    /// Present only with `net.netfilter.nf_conntrack_timestamp = 1`.
    timestamp_start: ?u64 = null,
    timestamp_stop: ?u64 = null,

    /// True when every bit of `bits` is set in `CTA_STATUS`.
    pub fn hasStatus(f: Flow, bits: u32) bool {
        return (f.status orelse 0) & bits == bits;
    }
};

// ── decoding ────────────────────────────────────────────────────────────────

/// Decode a `CTA_TUPLE_*` nest (the attribute's payload bytes).
pub fn decodeTuple(nest: []const u8) DecodeError!Tuple {
    var out: Tuple = .{};
    var it: codec.AttrIterator = .{ .buf = nest };
    while (try it.next()) |a| switch (a.type) {
        CTA_TUPLE.IP => {
            var ips = a.nested();
            while (try ips.next()) |ia| switch (ia.type) {
                CTA_IP.V4_SRC => out.src = .{ .v4 = try fixed(4, ia) },
                CTA_IP.V4_DST => out.dst = .{ .v4 = try fixed(4, ia) },
                CTA_IP.V6_SRC => out.src = .{ .v6 = try fixed(16, ia) },
                CTA_IP.V6_DST => out.dst = .{ .v6 = try fixed(16, ia) },
                else => {},
            };
        },
        CTA_TUPLE.PROTO => {
            var ps = a.nested();
            while (try ps.next()) |pa| switch (pa.type) {
                CTA_PROTO.NUM => out.proto = try pa.asU8(),
                CTA_PROTO.SRC_PORT => out.src_port = try pa.asBe16(),
                CTA_PROTO.DST_PORT => out.dst_port = try pa.asBe16(),
                CTA_PROTO.ICMP_ID, CTA_PROTO.ICMPV6_ID => out.icmp_id = try pa.asBe16(),
                CTA_PROTO.ICMP_TYPE, CTA_PROTO.ICMPV6_TYPE => out.icmp_type = try pa.asU8(),
                CTA_PROTO.ICMP_CODE, CTA_PROTO.ICMPV6_CODE => out.icmp_code = try pa.asU8(),
                else => {},
            };
        },
        CTA_TUPLE.ZONE => out.zone = try a.asBe16(),
        else => {},
    };
    return out;
}

fn fixed(comptime n: usize, a: codec.Attr) DecodeError![n]u8 {
    if (a.data.len != n) return error.BadLength;
    return a.data[0..n].*;
}

fn decodeCounters(nest: []const u8) DecodeError!Counters {
    var out: Counters = .{};
    var it: codec.AttrIterator = .{ .buf = nest };
    while (try it.next()) |a| switch (a.type) {
        CTA_COUNTERS.PACKETS => out.packets = try a.asBe64(),
        CTA_COUNTERS.BYTES => out.bytes = try a.asBe64(),
        // The 32-bit forms are dead in every kernel that speaks the 64-bit
        // ones, but decode them rather than ignoring a real counter.
        CTA_COUNTERS.PACKETS32 => out.packets = try a.asBe32(),
        CTA_COUNTERS.BYTES32 => out.bytes = try a.asBe32(),
        else => {},
    };
    return out;
}

/// Decode one `IPCTNL_MSG_CT_NEW`/`_DELETE` message payload (the bytes after
/// the 16-byte `nlmsghdr`: `nfgenmsg` + CTA TLVs) into a `Flow`.
///
/// Unknown attributes are skipped, not rejected — the kernel gains new CTA_*
/// types over time and a dump must not break on one. Malformed *lengths* are
/// always rejected (`error.Truncated`/`error.BadLength`).
pub fn decodeFlow(payload: []const u8) DecodeError!Flow {
    const hdr = try parseNfgenmsg(payload);
    var out: Flow = .{ .family = @enumFromInt(hdr.family) };
    var it = hdr.attrIterator();
    while (try it.next()) |a| switch (a.type) {
        CTA.TUPLE_ORIG => out.orig = try decodeTuple(a.data),
        CTA.TUPLE_REPLY => out.reply = try decodeTuple(a.data),
        CTA.STATUS => out.status = try a.asBe32(),
        CTA.TIMEOUT => out.timeout = try a.asBe32(),
        CTA.MARK => out.mark = try a.asBe32(),
        CTA.ID => out.id = try a.asBe32(),
        CTA.USE => out.use = try a.asBe32(),
        CTA.ZONE => out.zone = try a.asBe16(),
        CTA.COUNTERS_ORIG => out.counters_orig = try decodeCounters(a.data),
        CTA.COUNTERS_REPLY => out.counters_reply = try decodeCounters(a.data),
        CTA.TIMESTAMP => {
            var ts = a.nested();
            while (try ts.next()) |ta| switch (ta.type) {
                CTA_TIMESTAMP.START => out.timestamp_start = try ta.asBe64(),
                CTA_TIMESTAMP.STOP => out.timestamp_stop = try ta.asBe64(),
                else => {},
            };
        },
        CTA.PROTOINFO => {
            var pi = a.nested();
            while (try pi.next()) |pa| {
                if (pa.type != CTA_PROTOINFO.TCP) continue; // DCCP/SCTP: deferred
                var tcp = pa.nested();
                while (try tcp.next()) |ta| switch (ta.type) {
                    CTA_PROTOINFO_TCP.STATE => out.tcp_state = @enumFromInt(try ta.asU8()),
                    CTA_PROTOINFO_TCP.WSCALE_ORIGINAL => out.tcp_wscale_orig = try ta.asU8(),
                    CTA_PROTOINFO_TCP.WSCALE_REPLY => out.tcp_wscale_reply = try ta.asU8(),
                    CTA_PROTOINFO_TCP.FLAGS_ORIGINAL => out.tcp_flags_orig = try tcpFlags(ta),
                    CTA_PROTOINFO_TCP.FLAGS_REPLY => out.tcp_flags_reply = try tcpFlags(ta),
                    else => {},
                };
            }
        },
        else => {},
    };
    return out;
}

fn tcpFlags(a: codec.Attr) DecodeError!TcpFlags {
    if (a.data.len != 2) return error.BadLength;
    return .{ .flags = a.data[0], .mask = a.data[1] };
}

// ── request building ────────────────────────────────────────────────────────

/// Append a `CTA_TUPLE_*` nest for `t`.
///
/// Attribute order matches what conntrack-tools puts on the wire (see the
/// goldens): `CTA_TUPLE_IP{src,dst}`, then `CTA_TUPLE_PROTO{num, ports…}` —
/// for ICMP `{num, code, type, id}`. The kernel's policy parser accepts any
/// order; byte-identical output is what makes the golden tests meaningful.
pub fn appendTuple(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    t: Tuple,
) BuildError!void {
    if (!t.isComplete()) return error.IncompleteTuple;
    const src = t.src.?;
    const dst = t.dst.?;
    if (Family.of(src) != Family.of(dst)) return error.AddressFamilyMismatch;

    const tuple_off = try codec.nestBegin(gpa, list, codec.NLA_F_NESTED | attr_type);
    {
        const ip_off = try codec.nestBegin(gpa, list, codec.NLA_F_NESTED | CTA_TUPLE.IP);
        switch (src) {
            .v4 => |b| try codec.appendAttr(gpa, list, CTA_IP.V4_SRC, &b),
            .v6 => |b| try codec.appendAttr(gpa, list, CTA_IP.V6_SRC, &b),
        }
        switch (dst) {
            .v4 => |b| try codec.appendAttr(gpa, list, CTA_IP.V4_DST, &b),
            .v6 => |b| try codec.appendAttr(gpa, list, CTA_IP.V6_DST, &b),
        }
        codec.nestEnd(list, ip_off);
    }
    {
        const proto = t.proto.?;
        const icmpv6 = proto == IPPROTO.ICMPV6;
        const p_off = try codec.nestBegin(gpa, list, codec.NLA_F_NESTED | CTA_TUPLE.PROTO);
        try codec.appendAttrU8(gpa, list, CTA_PROTO.NUM, proto);
        if (t.src_port) |p| try codec.appendAttrBe16(gpa, list, CTA_PROTO.SRC_PORT, p);
        if (t.dst_port) |p| try codec.appendAttrBe16(gpa, list, CTA_PROTO.DST_PORT, p);
        if (t.icmp_code) |c|
            try codec.appendAttrU8(gpa, list, if (icmpv6) CTA_PROTO.ICMPV6_CODE else CTA_PROTO.ICMP_CODE, c);
        if (t.icmp_type) |ty|
            try codec.appendAttrU8(gpa, list, if (icmpv6) CTA_PROTO.ICMPV6_TYPE else CTA_PROTO.ICMP_TYPE, ty);
        if (t.icmp_id) |id|
            try codec.appendAttrBe16(gpa, list, if (icmpv6) CTA_PROTO.ICMPV6_ID else CTA_PROTO.ICMP_ID, id);
        codec.nestEnd(list, p_off);
    }
    if (t.zone) |z| try codec.appendAttrBe16(gpa, list, CTA_TUPLE.ZONE, z);
    codec.nestEnd(list, tuple_off);
}

/// The complete `IPCTNL_MSG_CT_GET` + `NLM_F_DUMP` request — 20 fixed bytes,
/// so it needs no allocator. `family` scopes the dump (`.unspec` = both).
pub fn buildDumpRequest(seq: u32, family: Family) [codec.header_len + nfgenmsg_len]u8 {
    var req: [codec.header_len + nfgenmsg_len]u8 = @splat(0);
    std.mem.writeInt(u32, req[0..4], req.len, native_endian);
    std.mem.writeInt(u16, req[4..6], msg_ct_get, native_endian);
    std.mem.writeInt(u16, req[6..8], codec.NLM_F_REQUEST | codec.NLM_F_DUMP, native_endian);
    std.mem.writeInt(u32, req[8..12], seq, native_endian);
    // nlmsg_pid stays 0 — the kernel routes replies by socket.
    req[codec.header_len] = @intFromEnum(family);
    req[codec.header_len + 1] = NFNETLINK_V0;
    // res_id (__be16) stays 0.
    return req;
}

/// Which direction's tuple a lookup keys on.
pub const Direction = enum { orig, reply };

/// `IPCTNL_MSG_CT_GET` for a single entry (`NLM_F_REQUEST` only — the kernel
/// answers with one `IPCTNL_MSG_CT_NEW` message or `NLMSG_ERROR`, never a
/// multi-part dump). Caller frees the returned buffer.
pub fn buildGetRequest(
    gpa: std.mem.Allocator,
    seq: u32,
    family: Family,
    dir: Direction,
    tuple: Tuple,
) BuildError![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(gpa, &list, msg_ct_get, codec.NLM_F_REQUEST, seq, 0);
    try appendNfgenmsg(gpa, &list, family, 0);
    try appendTuple(gpa, &list, switch (dir) {
        .orig => CTA.TUPLE_ORIG,
        .reply => CTA.TUPLE_REPLY,
    }, tuple);
    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

/// `IPCTNL_MSG_CT_DELETE` for one entry, keyed on `tuple` in direction `dir`.
///
/// **A delete request without a tuple flushes the entire table** — that is the
/// kernel's `ctnetlink_del_conntrack` behaviour, not a quirk of this module —
/// so a tuple is mandatory here and flushing has its own explicitly-named
/// entry point (`buildFlushRequest`).
///
/// `expect_id` is *not* a lookup key either: the kernel finds the entry by
/// tuple and then, if `CTA_ID` is present, refuses (`-ENOENT`) unless the
/// found entry's id matches. Pass the id from a previous dump to make the
/// delete a compare-and-delete that cannot hit a recycled entry.
pub fn buildDeleteRequest(
    gpa: std.mem.Allocator,
    seq: u32,
    family: Family,
    dir: Direction,
    tuple: Tuple,
    expect_id: ?u32,
) BuildError![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(
        gpa,
        &list,
        msg_ct_delete,
        codec.NLM_F_REQUEST | codec.NLM_F_ACK,
        seq,
        0,
    );
    try appendNfgenmsg(gpa, &list, family, 0);
    try appendTuple(gpa, &list, switch (dir) {
        .orig => CTA.TUPLE_ORIG,
        .reply => CTA.TUPLE_REPLY,
    }, tuple);
    if (expect_id) |id| try codec.appendAttrBe32(gpa, &list, CTA.ID, id);
    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

/// `IPCTNL_MSG_CT_DELETE` with no tuple: the kernel drops **every** entry of
/// `family` (`.unspec` = all of them). Separate from `buildDeleteRequest` so
/// that a bug in a caller's tuple construction can never turn into a flush.
pub fn buildFlushRequest(
    gpa: std.mem.Allocator,
    seq: u32,
    family: Family,
) BuildError![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(
        gpa,
        &list,
        msg_ct_delete,
        codec.NLM_F_REQUEST | codec.NLM_F_ACK,
        seq,
        0,
    );
    try appendNfgenmsg(gpa, &list, family, 0);
    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

/// What `buildNewRequest` puts on the wire. Only `orig` and `reply` are
/// mandatory; every optional maps 1:1 onto the CTA_* attribute of the same
/// name and is omitted when null.
pub const NewSpec = struct {
    orig: Tuple,
    reply: Tuple,
    /// `CTA_STATUS` — `IPS.*` bits.
    ///
    /// The kernel does **not** treat this as an assignment: it XORs what you
    /// send against the entry's current status and rejects the request with
    /// `EBUSY` (`error.Busy`) if the difference would clear `IPS_EXPECTED`,
    /// `IPS_CONFIRMED`, `IPS_DYING`, `IPS_SEEN_REPLY` or `IPS_ASSURED` — those
    /// bits can only ever be set. A fresh entry is already `IPS_CONFIRMED` by
    /// the time the status is applied, so **an insert that sends any status at
    /// all must include `IPS.CONFIRMED`**; `conntrack -I -u SEEN_REPLY` sends
    /// `SEEN_REPLY|ASSURED|CONFIRMED` for exactly this reason (verified live —
    /// `.status = IPS.SEEN_REPLY` alone answers EBUSY). Sending no status is
    /// always safe.
    status: ?u32 = null,
    /// `CTA_TIMEOUT`, seconds. Required by the kernel for a *new* entry.
    timeout: ?u32 = null,
    mark: ?u32 = null,
    zone: ?u16 = null,
    tcp_state: ?TcpState = null,
    tcp_flags_orig: ?TcpFlags = null,
    tcp_flags_reply: ?TcpFlags = null,
};

/// Build an `IPCTNL_MSG_CT_NEW` request. `flags` selects the semantics:
/// `NLM_F_REQUEST|ACK|EXCL|CREATE` inserts a new entry (and fails `-EEXIST` if
/// it is already there — what `conntrack -I` sends), `NLM_F_REQUEST|ACK` alone
/// updates an existing one.
///
/// Attribute order matches conntrack-tools byte for byte: tuples, status,
/// timeout, mark, protoinfo, zone.
pub fn buildNewRequest(
    gpa: std.mem.Allocator,
    seq: u32,
    family: Family,
    flags: u16,
    spec: NewSpec,
) BuildError![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(gpa, &list, msg_ct_new, flags, seq, 0);
    try appendNfgenmsg(gpa, &list, family, 0);
    try appendTuple(gpa, &list, CTA.TUPLE_ORIG, spec.orig);
    try appendTuple(gpa, &list, CTA.TUPLE_REPLY, spec.reply);
    if (spec.status) |s| try codec.appendAttrBe32(gpa, &list, CTA.STATUS, s);
    if (spec.timeout) |t| try codec.appendAttrBe32(gpa, &list, CTA.TIMEOUT, t);
    if (spec.mark) |m| try codec.appendAttrBe32(gpa, &list, CTA.MARK, m);
    if (spec.tcp_state != null or spec.tcp_flags_orig != null or spec.tcp_flags_reply != null) {
        const pi_off = try codec.nestBegin(gpa, &list, codec.NLA_F_NESTED | CTA.PROTOINFO);
        const tcp_off = try codec.nestBegin(gpa, &list, codec.NLA_F_NESTED | CTA_PROTOINFO.TCP);
        if (spec.tcp_state) |s|
            try codec.appendAttrU8(gpa, &list, CTA_PROTOINFO_TCP.STATE, @intFromEnum(s));
        if (spec.tcp_flags_orig) |f| try codec.appendAttr(
            gpa,
            &list,
            CTA_PROTOINFO_TCP.FLAGS_ORIGINAL,
            &[_]u8{ f.flags, f.mask },
        );
        if (spec.tcp_flags_reply) |f| try codec.appendAttr(
            gpa,
            &list,
            CTA_PROTOINFO_TCP.FLAGS_REPLY,
            &[_]u8{ f.flags, f.mask },
        );
        codec.nestEnd(&list, tcp_off);
        codec.nestEnd(&list, pi_off);
    }
    if (spec.zone) |z| try codec.appendAttrBe16(gpa, &list, CTA.ZONE, z);
    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const goldens = @import("goldens.zig");

/// The sequence numbers the captured conntrack-tools runs happened to use
/// (conntrack-tools seeds its counter with `time(NULL)`).
const seq_capture1: u32 = 1784723839;
const seq_capture2: u32 = 1784723936;

test "golden: dump request bytes match `conntrack -L`" {
    if (native_endian != .little) return error.SkipZigTest; // golden bytes are LE
    const unspec = buildDumpRequest(seq_capture1, .unspec);
    try testing.expectEqualSlices(u8, &goldens.dump_request_unspec, &unspec);
    const v6 = buildDumpRequest(seq_capture1, .ipv6);
    try testing.expectEqualSlices(u8, &goldens.dump_request_inet6, &v6);
}

test "golden: get-by-tuple request bytes match `conntrack -G`" {
    if (native_endian != .little) return error.SkipZigTest;
    const req = try buildGetRequest(testing.allocator, seq_capture1, .ipv4, .orig, .{
        .src = .{ .v4 = .{ 10, 0, 0, 1 } },
        .dst = .{ .v4 = .{ 10, 0, 0, 2 } },
        .proto = IPPROTO.UDP,
        .src_port = 5353,
        .dst_port = 53,
    });
    defer testing.allocator.free(req);
    try testing.expectEqualSlices(u8, &goldens.get_request_udp4, req);
}

test "golden: insert request bytes match `conntrack -I` (udp/v4)" {
    if (native_endian != .little) return error.SkipZigTest;
    const orig: Tuple = .{
        .src = .{ .v4 = .{ 10, 0, 0, 1 } },
        .dst = .{ .v4 = .{ 10, 0, 0, 2 } },
        .proto = IPPROTO.UDP,
        .src_port = 5353,
        .dst_port = 53,
    };
    const req = try buildNewRequest(testing.allocator, seq_capture1, .ipv4, create_flags, .{
        .orig = orig,
        .reply = orig.invert(),
        .timeout = 30,
    });
    defer testing.allocator.free(req);
    try testing.expectEqualSlices(u8, &goldens.new_request_udp4, req);
}

test "golden: insert request bytes match `conntrack -I` (tcp/v4, mark + zone)" {
    if (native_endian != .little) return error.SkipZigTest;
    const orig: Tuple = .{
        .src = .{ .v4 = .{ 192, 168, 1, 10 } },
        .dst = .{ .v4 = .{ 93, 184, 216, 34 } },
        .proto = IPPROTO.TCP,
        .src_port = 51000,
        .dst_port = 443,
    };
    const req = try buildNewRequest(testing.allocator, seq_capture2, .ipv4, create_flags, .{
        .orig = orig,
        .reply = orig.invert(),
        .status = IPS.SEEN_REPLY | IPS.ASSURED | IPS.CONFIRMED,
        .timeout = 431990,
        .mark = 42,
        .zone = 7,
        .tcp_state = .established,
        // conntrack-tools always sends these two for a TCP insert
        // (SACK_PERM|BE_LIBERAL, both in the mask).
        .tcp_flags_orig = .{ .flags = 0x0a, .mask = 0x0a },
        .tcp_flags_reply = .{ .flags = 0x0a, .mask = 0x0a },
    });
    defer testing.allocator.free(req);
    try testing.expectEqualSlices(u8, &goldens.new_request_tcp4, req);
}

test "golden: insert request bytes match `conntrack -I` (tcp/v6)" {
    if (native_endian != .little) return error.SkipZigTest;
    const orig: Tuple = .{
        .src = .{ .v6 = .{ 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },
        .dst = .{ .v6 = .{ 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 } },
        .proto = IPPROTO.TCP,
        .src_port = 40000,
        .dst_port = 80,
    };
    const req = try buildNewRequest(testing.allocator, seq_capture1, .ipv6, create_flags, .{
        .orig = orig,
        .reply = orig.invert(),
        .status = IPS.SEEN_REPLY | IPS.CONFIRMED,
        .timeout = 300,
        .tcp_state = .established,
        .tcp_flags_orig = .{ .flags = 0x0a, .mask = 0x0a },
        .tcp_flags_reply = .{ .flags = 0x0a, .mask = 0x0a },
    });
    defer testing.allocator.free(req);
    try testing.expectEqualSlices(u8, &goldens.new_request_tcp6, req);
}

test "golden: insert request bytes match `conntrack -I` (icmp/v4)" {
    if (native_endian != .little) return error.SkipZigTest;
    const orig: Tuple = .{
        .src = .{ .v4 = .{ 172, 16, 0, 1 } },
        .dst = .{ .v4 = .{ 172, 16, 0, 9 } },
        .proto = IPPROTO.ICMP,
        .icmp_id = 1234,
        .icmp_type = 8,
        .icmp_code = 0,
    };
    const req = try buildNewRequest(testing.allocator, seq_capture2, .ipv4, create_flags, .{
        .orig = orig,
        // `invert()` maps echo-request 8 -> echo-reply 0, which is exactly
        // what conntrack-tools computed for the captured frame.
        .reply = orig.invert(),
        .timeout = 30,
    });
    defer testing.allocator.free(req);
    try testing.expectEqualSlices(u8, &goldens.new_request_icmp4, req);
}

/// `NLM_F_REQUEST|NLM_F_ACK|NLM_F_EXCL|NLM_F_CREATE` = 0x0605, what
/// `conntrack -I` sends.
const create_flags = codec.NLM_F_REQUEST | codec.NLM_F_ACK | codec.NLM_F_EXCL | codec.NLM_F_CREATE;

test "golden: delete request header + tuple match the captured `conntrack -D`" {
    if (native_endian != .little) return error.SkipZigTest;
    const req = try buildDeleteRequest(testing.allocator, seq_capture1, .ipv4, .orig, .{
        .src = .{ .v4 = .{ 10, 0, 0, 1 } },
        .dst = .{ .v4 = .{ 10, 0, 0, 2 } },
        .proto = IPPROTO.UDP,
        .src_port = 5353,
        .dst_port = 53,
    }, null);
    defer testing.allocator.free(req);

    // conntrack-tools dumps the entry first and echoes everything it read back
    // (CTA_TUPLE_REPLY, STATUS, TIMEOUT, MARK, SYNPROXY); the kernel matches on
    // CTA_TUPLE_ORIG alone, so this module stops there. Everything both send —
    // nlmsghdr (bar the length), nfgenmsg and the whole CTA_TUPLE_ORIG nest —
    // must be byte-identical.
    const golden = &goldens.delete_request_udp4;
    const prefix_len = codec.header_len + nfgenmsg_len + 52; // 52 = the tuple TLV
    try testing.expectEqual(prefix_len, req.len);
    try testing.expectEqualSlices(u8, golden[4..prefix_len], req[4..prefix_len]);
    // …only nlmsg_len differs, and it is ours, not theirs.
    try testing.expectEqual(@as(u32, prefix_len), std.mem.readInt(u32, req[0..4], native_endian));
    try testing.expectEqual(msg_ct_delete, std.mem.readInt(u16, req[4..6], native_endian));
    try testing.expectEqual(
        codec.NLM_F_REQUEST | codec.NLM_F_ACK,
        std.mem.readInt(u16, req[6..8], native_endian),
    );
}

test "delete with expect_id appends CTA_ID and a flush carries no tuple" {
    const with_id = try buildDeleteRequest(testing.allocator, 1, .ipv4, .reply, .{
        .src = .{ .v4 = .{ 10, 0, 0, 1 } },
        .dst = .{ .v4 = .{ 10, 0, 0, 2 } },
        .proto = IPPROTO.UDP,
        .src_port = 1,
        .dst_port = 2,
    }, 0xdeadbeef);
    defer testing.allocator.free(with_id);
    const hdr = try parseNfgenmsg(with_id[codec.header_len..]);
    var it = hdr.attrIterator();
    var saw_reply_tuple = false;
    var saw_id: ?u32 = null;
    while (try it.next()) |a| switch (a.type) {
        CTA.TUPLE_REPLY => saw_reply_tuple = true,
        CTA.TUPLE_ORIG => return error.TestUnexpectedResult,
        CTA.ID => saw_id = try a.asBe32(),
        else => {},
    };
    try testing.expect(saw_reply_tuple);
    try testing.expectEqual(@as(?u32, 0xdeadbeef), saw_id);

    const flush = try buildFlushRequest(testing.allocator, 2, .ipv4);
    defer testing.allocator.free(flush);
    try testing.expectEqual(@as(usize, codec.header_len + nfgenmsg_len), flush.len);
    try testing.expectEqual(msg_ct_delete, std.mem.readInt(u16, flush[4..6], native_endian));
}

test "builders reject an incomplete or mixed-family tuple" {
    try testing.expectError(error.IncompleteTuple, buildGetRequest(
        testing.allocator,
        1,
        .ipv4,
        .orig,
        .{ .src = .{ .v4 = .{ 1, 2, 3, 4 } }, .proto = IPPROTO.TCP },
    ));
    try testing.expectError(error.IncompleteTuple, buildGetRequest(
        testing.allocator,
        1,
        .ipv4,
        .orig,
        .{ .src = .{ .v4 = .{ 1, 2, 3, 4 } }, .dst = .{ .v4 = .{ 5, 6, 7, 8 } } },
    ));
    try testing.expectError(error.AddressFamilyMismatch, buildGetRequest(
        testing.allocator,
        1,
        .ipv4,
        .orig,
        .{
            .src = .{ .v4 = .{ 1, 2, 3, 4 } },
            .dst = .{ .v6 = @splat(0) },
            .proto = IPPROTO.TCP,
        },
    ));
}

test "golden: decode the three-flow `conntrack -L` reply" {
    var it: codec.MessageIterator = .{ .buf = &goldens.dump_reply_three_flows };
    var flows: [3]Flow = undefined;
    var n: usize = 0;
    while (try it.next()) |m| {
        try testing.expectEqual(msg_ct_new, m.type);
        try testing.expect(m.flags & codec.NLM_F_MULTI != 0);
        flows[n] = try decodeFlow(m.payload);
        n += 1;
    }
    try testing.expectEqual(@as(usize, 3), n);

    // 1) 10.0.0.1:5353 -> 10.0.0.2:53, UDP, unreplied (status = CONFIRMED only).
    const udp = flows[0];
    try testing.expectEqual(Family.ipv4, udp.family);
    try testing.expectEqual(@as(u8, IPPROTO.UDP), udp.orig.proto.?);
    try testing.expect(udp.orig.src.?.eql(.{ .v4 = .{ 10, 0, 0, 1 } }));
    try testing.expect(udp.orig.dst.?.eql(.{ .v4 = .{ 10, 0, 0, 2 } }));
    try testing.expectEqual(@as(u16, 5353), udp.orig.src_port.?);
    try testing.expectEqual(@as(u16, 53), udp.orig.dst_port.?);
    try testing.expectEqual(IPS.CONFIRMED, udp.status.?);
    try testing.expect(!udp.hasStatus(IPS.SEEN_REPLY));
    try testing.expectEqual(@as(u32, 29), udp.timeout.?);
    try testing.expectEqual(@as(u32, 0), udp.mark.?);
    try testing.expectEqual(@as(u32, 1), udp.use.?);
    try testing.expectEqual(@as(u32, 0x0cf8ff00), udp.id.?);
    try testing.expectEqual(@as(?TcpState, null), udp.tcp_state); // UDP: no protoinfo
    try testing.expectEqual(@as(?Counters, null), udp.counters_orig); // acct off

    // 2) 192.168.1.10:51000 -> 93.184.216.34:443, TCP, ASSURED.
    const tcp = flows[1];
    try testing.expectEqual(Family.ipv4, tcp.family);
    try testing.expect(tcp.hasStatus(IPS.SEEN_REPLY | IPS.ASSURED | IPS.CONFIRMED));
    try testing.expectEqual(@as(u32, 431989), tcp.timeout.?);
    try testing.expectEqual(@as(u32, 0xe3f8d65d), tcp.id.?);
    try testing.expect(tcp.reply.src.?.eql(.{ .v4 = .{ 93, 184, 216, 34 } }));
    try testing.expectEqual(@as(u16, 443), tcp.reply.src_port.?);
    try testing.expectEqual(TcpState.established, tcp.tcp_state.?);
    try testing.expectEqual(@as(u8, 0), tcp.tcp_wscale_orig.?);
    try testing.expectEqual(TcpFlags{ .flags = 0x0a, .mask = 0 }, tcp.tcp_flags_orig.?);

    // 3) fd00::1:40000 -> fd00::2:80, TCP, ESTABLISHED, 299 s left.
    const v6 = flows[2];
    try testing.expectEqual(Family.ipv6, v6.family);
    try testing.expectEqual(@as(u8, IPPROTO.TCP), v6.orig.proto.?);
    try testing.expect(v6.orig.src.?.eql(.{
        .v6 = .{ 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
    }));
    try testing.expect(v6.orig.dst.?.eql(.{
        .v6 = .{ 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 },
    }));
    try testing.expectEqual(@as(u16, 40000), v6.orig.src_port.?);
    try testing.expectEqual(@as(u16, 80), v6.orig.dst_port.?);
    // The reply direction is the mirror image.
    try testing.expectEqual(@as(u16, 80), v6.reply.src_port.?);
    try testing.expectEqual(@as(u16, 40000), v6.reply.dst_port.?);
    try testing.expectEqual(IPS.SEEN_REPLY | IPS.CONFIRMED, v6.status.?);
    try testing.expect(v6.hasStatus(IPS.SEEN_REPLY));
    try testing.expect(!v6.hasStatus(IPS.ASSURED));
    try testing.expectEqual(@as(u32, 299), v6.timeout.?);
    try testing.expectEqual(@as(u32, 0xdc2bbbd0), v6.id.?);
    try testing.expectEqual(TcpState.established, v6.tcp_state.?);
}

test "golden: decode a dump reply carrying 64-bit counters, zone and timestamps" {
    var it: codec.MessageIterator = .{ .buf = &goldens.dump_reply_with_counters };
    const icmp = try decodeFlow((try it.next()).?.payload);
    const tcp = try decodeFlow((try it.next()).?.payload);
    try testing.expectEqual(@as(?codec.Message, null), try it.next());

    // ICMP echo, id 1234: request in the orig direction, reply type 0.
    try testing.expectEqual(@as(u8, IPPROTO.ICMP), icmp.orig.proto.?);
    try testing.expectEqual(@as(u16, 1234), icmp.orig.icmp_id.?);
    try testing.expectEqual(@as(u8, 8), icmp.orig.icmp_type.?);
    try testing.expectEqual(@as(u8, 0), icmp.orig.icmp_code.?);
    try testing.expectEqual(@as(u8, 0), icmp.reply.icmp_type.?);
    try testing.expectEqual(@as(?u16, null), icmp.orig.src_port);
    // acct is on, but this hand-inserted entry never carried a packet.
    try testing.expectEqual(Counters{ .packets = 0, .bytes = 0 }, icmp.counters_orig.?);
    try testing.expectEqual(Counters{ .packets = 0, .bytes = 0 }, icmp.counters_reply.?);
    try testing.expectEqual(@as(u64, 0x18c49cf6f556989a), icmp.timestamp_start.?);
    try testing.expectEqual(@as(?u64, null), icmp.timestamp_stop);

    // The TCP entry was inserted with `-m 42 -w 7`.
    try testing.expectEqual(@as(u32, 42), tcp.mark.?);
    try testing.expectEqual(@as(u16, 7), tcp.zone.?);
    try testing.expectEqual(TcpState.established, tcp.tcp_state.?);
    try testing.expectEqual(@as(u64, 0x18c49cf6f545db7f), tcp.timestamp_start.?);
    try testing.expectEqual(Counters{ .packets = 0, .bytes = 0 }, tcp.counters_orig.?);
}

test "golden: decode the single-entry `conntrack -G` reply" {
    var it: codec.MessageIterator = .{ .buf = &goldens.get_reply_udp4 };
    const m = (try it.next()).?;
    try testing.expectEqual(msg_ct_new, m.type);
    // Worth knowing: the kernel sets NLM_F_MULTI even on this single-entry
    // answer, so a decoder must not use that flag to tell a GET reply from a
    // dump — the *request*'s NLM_F_DUMP is what decides, and this module tracks
    // it per sequence number instead.
    try testing.expectEqual(codec.NLM_F_MULTI, m.flags & codec.NLM_F_MULTI);
    const f = try decodeFlow(m.payload);
    try testing.expectEqual(Family.ipv4, f.family);
    try testing.expectEqual(@as(u16, 5353), f.orig.src_port.?);
    try testing.expectEqual(@as(u16, 53), f.orig.dst_port.?);
    try testing.expectEqual(@as(u32, 29), f.timeout.?);
    try testing.expectEqual(@as(u32, 2), f.use.?);
    try testing.expectEqual(@as(?Flow, null), null);
    try testing.expectEqual(@as(?codec.Message, null), try it.next());
}

test "golden: the captured `conntrack -D` request decodes as the flow it deletes" {
    var it: codec.MessageIterator = .{ .buf = &goldens.delete_request_udp4 };
    const m = (try it.next()).?;
    try testing.expectEqual(msg_ct_delete, m.type);
    const f = try decodeFlow(m.payload);
    try testing.expect(f.orig.src.?.eql(.{ .v4 = .{ 10, 0, 0, 1 } }));
    try testing.expectEqual(@as(u16, 53), f.orig.dst_port.?);
    try testing.expectEqual(@as(u32, 29), f.timeout.?);
    try testing.expectEqual(@as(?u32, null), f.id); // conntrack-tools omits CTA_ID
}

test "big-endian discipline: a host-endian read of CTA_TIMEOUT would be wrong" {
    // The exact bytes the kernel emitted for the 431989-second TCP timeout.
    const raw = [_]u8{ 0x08, 0x00, 0x07, 0x00, 0x00, 0x06, 0x97, 0x75 };
    var it: codec.AttrIterator = .{ .buf = &raw };
    const a = (try it.next()).?;
    try testing.expectEqual(@as(u32, 431989), try a.asBe32());
    // …and the trap this module exists to avoid:
    if (native_endian == .little)
        try testing.expectEqual(@as(u32, 0x75970600), try a.asU32());
    // The kernel does not flag these as net-byte-order, so nothing but the
    // attribute *type* tells a decoder which reader to use.
    try testing.expectEqual(@as(u16, 0), a.raw_type & codec.NLA_F_NET_BYTEORDER);
}

test "round-trip: build an entry, decode it back" {
    const orig: Tuple = .{
        .src = .{ .v4 = .{ 203, 0, 113, 5 } },
        .dst = .{ .v4 = .{ 198, 51, 100, 7 } },
        .proto = IPPROTO.TCP,
        .src_port = 65535,
        .dst_port = 1,
        .zone = 9,
    };
    const req = try buildNewRequest(testing.allocator, 42, .ipv4, create_flags, .{
        .orig = orig,
        .reply = orig.invert(),
        .status = IPS.SEEN_REPLY | IPS.ASSURED,
        .timeout = 4294967295,
        .mark = 0x80000000,
        .zone = 3,
        .tcp_state = .time_wait,
        .tcp_flags_orig = .{ .flags = 1, .mask = 2 },
    });
    defer testing.allocator.free(req);

    var it: codec.MessageIterator = .{ .buf = req };
    const f = try decodeFlow((try it.next()).?.payload);
    try testing.expectEqual(orig.src_port.?, f.orig.src_port.?);
    try testing.expectEqual(orig.dst_port.?, f.orig.dst_port.?);
    try testing.expectEqual(@as(u16, 9), f.orig.zone.?);
    try testing.expectEqual(orig.dst_port.?, f.reply.src_port.?);
    try testing.expectEqual(@as(u32, 4294967295), f.timeout.?);
    try testing.expectEqual(@as(u32, 0x80000000), f.mark.?);
    try testing.expectEqual(@as(u16, 3), f.zone.?);
    try testing.expectEqual(TcpState.time_wait, f.tcp_state.?);
    try testing.expectEqual(TcpFlags{ .flags = 1, .mask = 2 }, f.tcp_flags_orig.?);
    try testing.expectEqual(@as(?TcpFlags, null), f.tcp_flags_reply);
}

test "invert maps ICMP request types to their answers" {
    const t: Tuple = .{
        .src = .{ .v4 = .{ 1, 1, 1, 1 } },
        .dst = .{ .v4 = .{ 2, 2, 2, 2 } },
        .proto = IPPROTO.ICMP,
        .icmp_id = 7,
        .icmp_type = 8,
    };
    const r = t.invert();
    try testing.expect(r.src.?.eql(.{ .v4 = .{ 2, 2, 2, 2 } }));
    try testing.expectEqual(@as(u8, 0), r.icmp_type.?);
    try testing.expectEqual(@as(u16, 7), r.icmp_id.?);

    var v6 = t;
    v6.proto = IPPROTO.ICMPV6;
    v6.icmp_type = 128;
    try testing.expectEqual(@as(u8, 129), v6.invert().icmp_type.?);
    // An unpaired type is left alone.
    var dest_unreach = t;
    dest_unreach.icmp_type = 3;
    try testing.expectEqual(@as(u8, 3), dest_unreach.invert().icmp_type.?);
}

test "decoder rejects wrong-sized scalars, not unknown attributes" {
    const gpa = testing.allocator;
    // CTA_STATUS with a 2-byte payload.
    {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(gpa);
        try appendNfgenmsg(gpa, &list, .ipv4, 0);
        try codec.appendAttr(gpa, &list, CTA.STATUS, &.{ 0, 1 });
        try testing.expectError(error.BadLength, decodeFlow(list.items));
    }
    // A 5-byte IPv4 address.
    {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(gpa);
        try appendNfgenmsg(gpa, &list, .ipv4, 0);
        const t_off = try codec.nestBegin(gpa, &list, codec.NLA_F_NESTED | CTA.TUPLE_ORIG);
        const ip_off = try codec.nestBegin(gpa, &list, codec.NLA_F_NESTED | CTA_TUPLE.IP);
        try codec.appendAttr(gpa, &list, CTA_IP.V4_SRC, &.{ 1, 2, 3, 4, 5 });
        codec.nestEnd(&list, ip_off);
        codec.nestEnd(&list, t_off);
        try testing.expectError(error.BadLength, decodeFlow(list.items));
    }
    // An attribute type no kernel has ever emitted is simply skipped.
    {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(gpa);
        try appendNfgenmsg(gpa, &list, .ipv4, 0);
        try codec.appendAttr(gpa, &list, 4095, &.{ 0xde, 0xad, 0xbe, 0xef });
        try codec.appendAttrBe32(gpa, &list, CTA.MARK, 5);
        const f = try decodeFlow(list.items);
        try testing.expectEqual(@as(u32, 5), f.mark.?);
    }
}

test "decoder rejects a truncated nfgenmsg and truncated nests" {
    try testing.expectError(error.Truncated, parseNfgenmsg(&.{}));
    try testing.expectError(error.Truncated, parseNfgenmsg(&.{ 2, 0, 0 }));
    try testing.expectError(error.Truncated, decodeFlow(&.{ 2, 0, 0 }));

    // Attribute header claiming 64 bytes inside a 12-byte message.
    const bad = [_]u8{ 2, 0, 0, 0, 0x40, 0x00, 0x01, 0x80, 0, 0, 0, 0 };
    try testing.expectError(error.Truncated, decodeFlow(&bad));

    // A nest whose inner TLV runs past the nest.
    const bad_nest = [_]u8{
        2, 0, 0, 0, // nfgenmsg
        0x0c, 0x00, 0x01, 0x80, // CTA_TUPLE_ORIG, len 12
        0x40, 0x00, 0x01, 0x80, // CTA_TUPLE_IP, len 64 (> 8 remaining)
        0x00, 0x00, 0x00, 0x00,
    };
    try testing.expectError(error.Truncated, decodeFlow(&bad_nest));

    // Zero-length attribute header: must be rejected, never looped on.
    const zero_len = [_]u8{ 2, 0, 0, 0, 0x00, 0x00, 0x01, 0x00 };
    try testing.expectError(error.BadLength, decodeFlow(&zero_len));
}

test "decoder survives misaligned and adversarially nested attribute streams" {
    const gpa = testing.allocator;
    // A tuple nested inside itself 64 deep — the walker is iterative per level
    // and the recursion here is bounded by the decoder's fixed nesting depth
    // (tuple -> ip/proto), so deep input costs nothing.
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try appendNfgenmsg(gpa, &list, .ipv4, 0);
    var offs: [64]usize = undefined;
    for (&offs) |*o| o.* = try codec.nestBegin(gpa, &list, codec.NLA_F_NESTED | CTA.TUPLE_ORIG);
    try codec.appendAttrBe32(gpa, &list, CTA.MARK, 1);
    var i: usize = offs.len;
    while (i > 0) : (i -= 1) codec.nestEnd(&list, offs[i - 1]);
    _ = decodeFlow(list.items) catch {}; // must not crash or hang

    // Odd-length payloads at every position of a 3-attribute stream.
    for (1..8) |n| {
        var l2: std.ArrayList(u8) = .empty;
        defer l2.deinit(gpa);
        try appendNfgenmsg(gpa, &l2, .ipv4, 0);
        const payload: [8]u8 = @splat(0xa5);
        try codec.appendAttr(gpa, &l2, CTA.TIMEOUT, payload[0..n]);
        try codec.appendAttr(gpa, &l2, CTA.MARK, payload[0..n]);
        _ = decodeFlow(l2.items) catch {};
    }
}

test "fuzz: decodeFlow never crashes, hangs or reads out of bounds" {
    try testing.fuzz({}, fuzzDecode, .{});
}

fn fuzzDecode(_: void, smith: *std.testing.Smith) !void {
    var raw: [512]u8 = undefined;
    smith.bytes(&raw);
    const len = smith.valueRangeAtMost(u16, 0, raw.len);
    const buf = raw[0..len];

    _ = decodeFlow(buf) catch {};
    _ = parseNfgenmsg(buf) catch {};
    if (buf.len > nfgenmsg_len) _ = decodeTuple(buf[nfgenmsg_len..]) catch {};

    // …and the same bytes seen as a stream of whole netlink messages, which is
    // how a dump reply actually arrives.
    var it: codec.MessageIterator = .{ .buf = buf };
    var steps: usize = 0;
    while (it.next() catch null) |m| {
        steps += 1;
        try testing.expect(steps <= buf.len / 4 + 1);
        _ = decodeFlow(m.payload) catch {};
    }
}
