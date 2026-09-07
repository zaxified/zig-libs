// SPDX-License-Identifier: MIT
//! Classifier (filter) encoding: **u32** and **flower**.
//!
//! A filter is what binds traffic to a class. Two of its parameters do *not*
//! live in attributes at all — they are packed into the `tcmsg` fixed header:
//!
//! ```text
//! tcm_info = TC_H_MAKE(prio << 16, protocol)
//! ```
//!
//! with `protocol` an **ethertype in network byte order** (`ETH_P_IP` 0x0800
//! becomes 0x0008 on a little-endian host). Getting that pair wrong is the
//! classic tc-over-netlink bug: the kernel silently installs the filter under
//! the wrong priority/protocol and it never matches. `Filter.info` /
//! `parseInfo` are the only places this module encodes it.

const std = @import("std");
const builtin = @import("builtin");
const native_endian = builtin.cpu.arch.endian();

const netlink = @import("netlink");
const codec = netlink.codec;

const handle_mod = @import("handle.zig");
const Handle = handle_mod.Handle;

const qdisc = @import("qdisc.zig");
const TCA = qdisc.TCA;

const ratespec = @import("ratespec.zig");
const Psched = ratespec.Psched;

// Test-only (`build.zig`'s `test_deps`, never `deps`): the fuzz corpus seed
// helpers, in the format `std.testing.Smith` actually reads.
const testkit = @import("testkit");

const action = @import("action.zig");
const ActionSpec = action.ActionSpec;
const ActionList = action.ActionList;

// ── ethertypes / IP protocols (the handful filters need) ────────────────────

/// `ETH_P_*` (linux/if_ether.h), host byte order.
pub const ETH_P = struct {
    pub const ALL: u16 = 0x0003;
    pub const IP: u16 = 0x0800;
    pub const ARP: u16 = 0x0806;
    pub const IPV6: u16 = 0x86DD;
    pub const @"802_1Q": u16 = 0x8100;
};

/// The IP protocol numbers whose port attributes flower models.
pub const IPPROTO = struct {
    pub const ICMP: u8 = 1;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
    pub const ICMPV6: u8 = 58;
    pub const SCTP: u8 = 132;
};

// ── u32 ─────────────────────────────────────────────────────────────────────

/// u32 classifier attributes (linux/pkt_cls.h `TCA_U32_*`). There is no
/// `TCA_U32_MATCH`: individual matches are `tc_u32_key` entries appended to
/// the `TCA_U32_SEL` payload, which is what `U32.keys` builds.
pub const TCA_U32 = struct {
    pub const UNSPEC: u16 = 0;
    pub const CLASSID: u16 = 1;
    pub const HASH: u16 = 2;
    pub const LINK: u16 = 3;
    pub const DIVISOR: u16 = 4;
    pub const SEL: u16 = 5;
    pub const POLICE: u16 = 6;
    pub const ACT: u16 = 7;
    pub const INDEV: u16 = 8;
    pub const PCNT: u16 = 9;
    pub const MARK: u16 = 10;
    pub const FLAGS: u16 = 11;
    pub const PAD: u16 = 12;
};

/// `struct tc_u32_sel.flags` bits (linux/pkt_cls.h `TC_U32_*`).
pub const TC_U32 = struct {
    pub const TERMINAL: u8 = 1;
    pub const OFFSET: u8 = 2;
    pub const VAROFFSET: u8 = 4;
    pub const EAT: u8 = 8;
};

/// `sizeof(struct tc_u32_sel)` without keys: flags/offshift/nkeys + 1 pad,
/// offmask, off, offoff, hoff, hmask.
pub const tc_u32_sel_len = 16;
/// `sizeof(struct tc_u32_key)`: mask, val, off, offmask.
pub const tc_u32_key_len = 16;
/// The kernel's cap on keys in one selector (`TC_U32_MAXDEPTH`-independent —
/// `sel.nkeys` is a u8).
pub const u32_max_keys = 128;

/// One 32-bit masked match. `val` and `mask` are stored **as they appear in
/// the packet** (network byte order) and `val` is always pre-masked, matching
/// what `tc` puts on the wire.
pub const U32Key = struct {
    val: [4]u8,
    mask: [4]u8,
    /// Byte offset of the 32-bit word inside the header being matched.
    /// Negative offsets are legal (the kernel treats it as a signed value).
    off: i32,
    /// Optional offset mask for variable-length headers; 0 for fixed offsets.
    offmask: i32 = 0,

    /// A raw masked word match at `off`, both operands given in **host**
    /// order and written big-endian (this is `tc … match u32 VAL MASK at OFF`).
    pub fn word(val: u32, mask: u32, off: i32) U32Key {
        var k: U32Key = .{ .val = undefined, .mask = undefined, .off = off };
        std.mem.writeInt(u32, &k.val, val & mask, .big);
        std.mem.writeInt(u32, &k.mask, mask, .big);
        return k;
    }

    /// Mask for an IPv4 prefix length (0..32), network byte order.
    fn prefixMask4(prefix_len: u6) [4]u8 {
        var m: [4]u8 = @splat(0);
        if (prefix_len == 0) return m;
        const bits: u5 = @intCast(32 - @as(u6, @min(prefix_len, 32)));
        const v: u32 = @as(u32, 0xFFFFFFFF) << bits;
        std.mem.writeInt(u32, &m, v, .big);
        return m;
    }

    fn ipv4At(addr: [4]u8, prefix_len: u6, off: i32) U32Key {
        const mask = prefixMask4(prefix_len);
        var val: [4]u8 = undefined;
        for (&val, addr, mask) |*v, a, m| v.* = a & m;
        return .{ .val = val, .mask = mask, .off = off };
    }

    /// `match ip src A.B.C.D/LEN` — the IPv4 source address at offset 12.
    pub fn ipv4Src(addr: [4]u8, prefix_len: u6) U32Key {
        return ipv4At(addr, prefix_len, 12);
    }

    /// `match ip dst A.B.C.D/LEN` — the IPv4 destination at offset 16.
    pub fn ipv4Dst(addr: [4]u8, prefix_len: u6) U32Key {
        return ipv4At(addr, prefix_len, 16);
    }

    /// `match ip protocol N 0xff` — the protocol byte lives at offset 9, so
    /// the enclosing 32-bit word starts at 8 and the byte sits in the second
    /// most significant position (0x00ff0000 big-endian).
    pub fn ipv4Proto(proto: u8) U32Key {
        return word(@as(u32, proto) << 16, 0x00FF0000, 8);
    }

    fn encode(k: U32Key) [tc_u32_key_len]u8 {
        var out: [tc_u32_key_len]u8 = undefined;
        // mask and val are __be32: copied verbatim, never byte-swapped.
        out[0..4].* = k.mask;
        out[4..8].* = k.val;
        std.mem.writeInt(i32, out[8..12], k.off, native_endian);
        std.mem.writeInt(i32, out[12..16], k.offmask, native_endian);
        return out;
    }

    fn decode(b: *const [tc_u32_key_len]u8) U32Key {
        return .{
            .mask = b[0..4].*,
            .val = b[4..8].*,
            .off = std.mem.readInt(i32, b[8..12], native_endian),
            .offmask = std.mem.readInt(i32, b[12..16], native_endian),
        };
    }
};

/// A u32 classifier: a list of masked 32-bit matches plus the class they
/// select.
pub const U32 = struct {
    /// `flowid X:Y` — the class matched traffic is sent to.
    classid: ?Handle = null,
    /// The matches. All must hit for the filter to match (logical AND).
    keys: []const U32Key = &.{},
    /// `TC_U32_TERMINAL` — stop classification here on a match. `tc` sets it
    /// for any selector with a `flowid`, which is the normal case.
    terminal: bool = true,
    /// `sel.offshift`/`offmask`/`off`/`offoff`/`hoff`/`hmask` — the variable
    /// offset machinery for `at nexthdr+N` style matches. Left at zero for
    /// fixed-offset selectors; exposed so a caller can hand-build one.
    offshift: u8 = 0,
    offmask: u16 = 0,
    off: u16 = 0,
    offoff: i16 = 0,
    hoff: i16 = 0,
    hmask: u32 = 0,
    /// `action …` — the action list run on a match, emitted as the nested
    /// `TCA_U32_ACT`. Empty means "select a class and stop", the v2 behaviour.
    actions: []const ActionSpec = &.{},
};

/// Wire readback of a u32 filter's options.
pub const U32Wire = struct {
    classid: ?Handle = null,
    flags: u8 = 0,
    nkeys: u8 = 0,
    /// The decoded keys, up to what fits; `nkeys` is the count the kernel
    /// declared.
    keys: [8]U32Key = @splat(.{ .val = @splat(0), .mask = @splat(0), .off = 0 }),
    keys_len: u8 = 0,
};

fn appendU32Options(
    u: U32,
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    ps: Psched,
) EncodeError!void {
    if (u.keys.len > u32_max_keys) return error.TooManyKeys;
    // Emission order mirrors iproute2's f_u32.c: everything parsed from the
    // command line first (the classid, then the action list), then the
    // selector — which is why `flowid X:Y action …` puts CLASSID before ACT.
    if (u.classid) |c| try codec.appendAttrU32(gpa, list, TCA_U32.CLASSID, c.raw);
    try action.appendActionList(gpa, list, TCA_U32.ACT, u.actions, ps);

    const sel_len = tc_u32_sel_len + u.keys.len * tc_u32_key_len;
    var hdr: [codec.attr_header_len]u8 = undefined;
    std.mem.writeInt(u16, hdr[0..2], @intCast(codec.attr_header_len + sel_len), native_endian);
    std.mem.writeInt(u16, hdr[2..4], TCA_U32.SEL, native_endian);
    try list.appendSlice(gpa, &hdr);

    var sel: [tc_u32_sel_len]u8 = @splat(0);
    sel[0] = if (u.terminal) TC_U32.TERMINAL else 0;
    sel[1] = u.offshift;
    sel[2] = @intCast(u.keys.len);
    // sel[3] is the compiler's padding byte before the __be16 offmask.
    std.mem.writeInt(u16, sel[4..6], u.offmask, native_endian);
    std.mem.writeInt(u16, sel[6..8], u.off, native_endian);
    std.mem.writeInt(i16, sel[8..10], u.offoff, native_endian);
    std.mem.writeInt(i16, sel[10..12], u.hoff, native_endian);
    std.mem.writeInt(u32, sel[12..16], u.hmask, native_endian);
    try list.appendSlice(gpa, &sel);
    for (u.keys) |k| try list.appendSlice(gpa, &k.encode());
    // sel_len is a multiple of 4 by construction — no padding needed.
}

pub fn parseU32Options(data: []const u8) codec.Error!U32Wire {
    var uw: U32Wire = .{};
    var it: codec.AttrIterator = .{ .buf = data };
    while (try it.next()) |a| switch (a.type) {
        TCA_U32.CLASSID => if (a.data.len == 4) {
            uw.classid = Handle.fromRaw(std.mem.readInt(u32, a.data[0..4], native_endian));
        },
        TCA_U32.SEL => {
            if (a.data.len < tc_u32_sel_len) return error.BadLength;
            uw.flags = a.data[0];
            uw.nkeys = a.data[2];
            var off: usize = tc_u32_sel_len;
            while (off + tc_u32_key_len <= a.data.len and uw.keys_len < uw.keys.len) {
                uw.keys[uw.keys_len] = U32Key.decode(a.data[off..][0..tc_u32_key_len]);
                uw.keys_len += 1;
                off += tc_u32_key_len;
            }
        },
        else => {},
    };
    return uw;
}

// ── flower ──────────────────────────────────────────────────────────────────

/// flower classifier attributes (linux/pkt_cls.h `TCA_FLOWER_*`); only the
/// subset this module encodes is listed.
pub const TCA_FLOWER = struct {
    pub const UNSPEC: u16 = 0;
    pub const CLASSID: u16 = 1;
    pub const INDEV: u16 = 2;
    pub const ACT: u16 = 3;
    pub const KEY_ETH_DST: u16 = 4;
    pub const KEY_ETH_DST_MASK: u16 = 5;
    pub const KEY_ETH_SRC: u16 = 6;
    pub const KEY_ETH_SRC_MASK: u16 = 7;
    pub const KEY_ETH_TYPE: u16 = 8;
    pub const KEY_IP_PROTO: u16 = 9;
    pub const KEY_IPV4_SRC: u16 = 10;
    pub const KEY_IPV4_SRC_MASK: u16 = 11;
    pub const KEY_IPV4_DST: u16 = 12;
    pub const KEY_IPV4_DST_MASK: u16 = 13;
    pub const KEY_IPV6_SRC: u16 = 14;
    pub const KEY_IPV6_SRC_MASK: u16 = 15;
    pub const KEY_IPV6_DST: u16 = 16;
    pub const KEY_IPV6_DST_MASK: u16 = 17;
    pub const KEY_TCP_SRC: u16 = 18;
    pub const KEY_TCP_DST: u16 = 19;
    pub const KEY_UDP_SRC: u16 = 20;
    pub const KEY_UDP_DST: u16 = 21;
    pub const FLAGS: u16 = 22;
    pub const KEY_SCTP_SRC: u16 = 27;
    pub const KEY_SCTP_DST: u16 = 28;
};

/// An IPv4 prefix match (`dst_ip 10.0.0.0/24`).
pub const Prefix4 = struct {
    addr: [4]u8,
    prefix_len: u6 = 32,
};

/// An IPv6 prefix match (`src_ip 2001:db8::/32`).
pub const Prefix6 = struct {
    addr: [16]u8,
    prefix_len: u8 = 128,
};

/// A flower classifier: structured L2–L4 key matching, offloadable to
/// hardware.
pub const Flower = struct {
    /// `protocol` on the `tc` command line — required, and always the last
    /// attribute `tc` emits. Host byte order (`ETH_P.IP`); encoded big-endian.
    eth_type: u16,
    /// `ip_proto tcp|udp|…` — also selects which port attributes are used.
    ip_proto: ?u8 = null,
    ipv4_src: ?Prefix4 = null,
    ipv4_dst: ?Prefix4 = null,
    ipv6_src: ?Prefix6 = null,
    ipv6_dst: ?Prefix6 = null,
    /// `src_port` / `dst_port`, host byte order; encoded big-endian. Needs
    /// `ip_proto` to be tcp, udp or sctp — otherwise `error.PortWithoutProto`.
    src_port: ?u16 = null,
    dst_port: ?u16 = null,
    /// `classid X:Y`.
    classid: ?Handle = null,
    /// `TCA_FLOWER_FLAGS` (skip_hw / skip_sw); `tc` always emits it, so this
    /// module does too.
    flags: u32 = 0,
    /// `action …` — the action list run on a match, emitted as the nested
    /// `TCA_FLOWER_ACT` (after `classid`, before `FLAGS`/`KEY_ETH_TYPE`).
    actions: []const ActionSpec = &.{},
};

/// Wire readback of a flower filter's options (the parts this module models).
pub const FlowerWire = struct {
    classid: ?Handle = null,
    eth_type: ?u16 = null,
    ip_proto: ?u8 = null,
    ipv4_src: ?[4]u8 = null,
    ipv4_src_mask: ?[4]u8 = null,
    ipv4_dst: ?[4]u8 = null,
    ipv4_dst_mask: ?[4]u8 = null,
    ipv6_src: ?[16]u8 = null,
    ipv6_dst: ?[16]u8 = null,
    src_port: ?u16 = null,
    dst_port: ?u16 = null,
    flags: ?u32 = null,
};

fn prefixMask6(prefix_len: u8) [16]u8 {
    var m: [16]u8 = @splat(0);
    var left: u16 = @min(prefix_len, 128);
    var i: usize = 0;
    while (left >= 8) : (left -= 8) {
        m[i] = 0xFF;
        i += 1;
    }
    if (left > 0) m[i] = @intCast(@as(u16, 0xFF) << @intCast(8 - left) & 0xFF);
    return m;
}

fn appendBe16(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    value: u16,
) std.mem.Allocator.Error!void {
    var raw: [2]u8 = undefined;
    std.mem.writeInt(u16, &raw, value, .big);
    codec.appendAttr(gpa, list, attr_type, &raw) catch |err| switch (err) {
        error.AttrTooLong => unreachable,
        error.OutOfMemory => return error.OutOfMemory,
    };
}

fn appendBytes(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    data: []const u8,
) std.mem.Allocator.Error!void {
    codec.appendAttr(gpa, list, attr_type, data) catch |err| switch (err) {
        error.AttrTooLong => unreachable,
        error.OutOfMemory => return error.OutOfMemory,
    };
}

/// The `(src, dst)` attribute pair for a transport protocol, or null when the
/// protocol has no ports flower can match.
fn portAttrs(ip_proto: u8) ?struct { src: u16, dst: u16 } {
    return switch (ip_proto) {
        IPPROTO.TCP => .{ .src = TCA_FLOWER.KEY_TCP_SRC, .dst = TCA_FLOWER.KEY_TCP_DST },
        IPPROTO.UDP => .{ .src = TCA_FLOWER.KEY_UDP_SRC, .dst = TCA_FLOWER.KEY_UDP_DST },
        IPPROTO.SCTP => .{ .src = TCA_FLOWER.KEY_SCTP_SRC, .dst = TCA_FLOWER.KEY_SCTP_DST },
        else => null,
    };
}

fn appendFlowerOptions(
    f: Flower,
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    ps: Psched,
) EncodeError!void {
    if ((f.src_port != null or f.dst_port != null)) {
        const proto = f.ip_proto orelse return error.PortWithoutProto;
        if (portAttrs(proto) == null) return error.PortWithoutProto;
    }

    // Emission order: iproute2 emits key attributes in command-line order and
    // finishes with FLAGS then ETH_TYPE. This module fixes the key order
    // (proto, src, dst, ports, classid) so a request is reproducible; the
    // goldens use the matching `tc` argument order.
    if (f.ip_proto) |p| try appendBytes(gpa, list, TCA_FLOWER.KEY_IP_PROTO, &[_]u8{p});
    if (f.ipv4_src) |p| {
        const mask = U32Key.prefixMask4(@intCast(@min(p.prefix_len, 32)));
        var val: [4]u8 = undefined;
        for (&val, p.addr, mask) |*v, a, m| v.* = a & m;
        try appendBytes(gpa, list, TCA_FLOWER.KEY_IPV4_SRC, &val);
        try appendBytes(gpa, list, TCA_FLOWER.KEY_IPV4_SRC_MASK, &mask);
    }
    if (f.ipv4_dst) |p| {
        const mask = U32Key.prefixMask4(@intCast(@min(p.prefix_len, 32)));
        var val: [4]u8 = undefined;
        for (&val, p.addr, mask) |*v, a, m| v.* = a & m;
        try appendBytes(gpa, list, TCA_FLOWER.KEY_IPV4_DST, &val);
        try appendBytes(gpa, list, TCA_FLOWER.KEY_IPV4_DST_MASK, &mask);
    }
    if (f.ipv6_src) |p| {
        const mask = prefixMask6(p.prefix_len);
        var val: [16]u8 = undefined;
        for (&val, p.addr, mask) |*v, a, m| v.* = a & m;
        try appendBytes(gpa, list, TCA_FLOWER.KEY_IPV6_SRC, &val);
        try appendBytes(gpa, list, TCA_FLOWER.KEY_IPV6_SRC_MASK, &mask);
    }
    if (f.ipv6_dst) |p| {
        const mask = prefixMask6(p.prefix_len);
        var val: [16]u8 = undefined;
        for (&val, p.addr, mask) |*v, a, m| v.* = a & m;
        try appendBytes(gpa, list, TCA_FLOWER.KEY_IPV6_DST, &val);
        try appendBytes(gpa, list, TCA_FLOWER.KEY_IPV6_DST_MASK, &mask);
    }
    if (f.src_port) |p| try appendBe16(gpa, list, portAttrs(f.ip_proto.?).?.src, p);
    if (f.dst_port) |p| try appendBe16(gpa, list, portAttrs(f.ip_proto.?).?.dst, p);
    if (f.classid) |c| try codec.appendAttrU32(gpa, list, TCA_FLOWER.CLASSID, c.raw);
    try action.appendActionList(gpa, list, TCA_FLOWER.ACT, f.actions, ps);
    try codec.appendAttrU32(gpa, list, TCA_FLOWER.FLAGS, f.flags);
    try appendBe16(gpa, list, TCA_FLOWER.KEY_ETH_TYPE, f.eth_type);
}

pub fn parseFlowerOptions(data: []const u8) codec.Error!FlowerWire {
    var fw: FlowerWire = .{};
    var it: codec.AttrIterator = .{ .buf = data };
    while (try it.next()) |a| switch (a.type) {
        TCA_FLOWER.CLASSID => if (a.data.len == 4) {
            fw.classid = Handle.fromRaw(std.mem.readInt(u32, a.data[0..4], native_endian));
        },
        TCA_FLOWER.KEY_ETH_TYPE => if (a.data.len == 2) {
            fw.eth_type = std.mem.readInt(u16, a.data[0..2], .big);
        },
        TCA_FLOWER.KEY_IP_PROTO => if (a.data.len == 1) {
            fw.ip_proto = a.data[0];
        },
        TCA_FLOWER.KEY_IPV4_SRC => if (a.data.len == 4) {
            fw.ipv4_src = a.data[0..4].*;
        },
        TCA_FLOWER.KEY_IPV4_SRC_MASK => if (a.data.len == 4) {
            fw.ipv4_src_mask = a.data[0..4].*;
        },
        TCA_FLOWER.KEY_IPV4_DST => if (a.data.len == 4) {
            fw.ipv4_dst = a.data[0..4].*;
        },
        TCA_FLOWER.KEY_IPV4_DST_MASK => if (a.data.len == 4) {
            fw.ipv4_dst_mask = a.data[0..4].*;
        },
        TCA_FLOWER.KEY_IPV6_SRC => if (a.data.len == 16) {
            fw.ipv6_src = a.data[0..16].*;
        },
        TCA_FLOWER.KEY_IPV6_DST => if (a.data.len == 16) {
            fw.ipv6_dst = a.data[0..16].*;
        },
        TCA_FLOWER.KEY_TCP_SRC, TCA_FLOWER.KEY_UDP_SRC, TCA_FLOWER.KEY_SCTP_SRC => if (a.data.len == 2) {
            fw.src_port = std.mem.readInt(u16, a.data[0..2], .big);
        },
        TCA_FLOWER.KEY_TCP_DST, TCA_FLOWER.KEY_UDP_DST, TCA_FLOWER.KEY_SCTP_DST => if (a.data.len == 2) {
            fw.dst_port = std.mem.readInt(u16, a.data[0..2], .big);
        },
        TCA_FLOWER.FLAGS => if (a.data.len == 4) {
            fw.flags = std.mem.readInt(u32, a.data[0..4], native_endian);
        },
        else => {},
    };
    return fw;
}

// ── the filter spec ─────────────────────────────────────────────────────────

pub const EncodeError = std.mem.Allocator.Error || action.EncodeError || error{
    /// More `U32Key`s than `sel.nkeys` (a u8) can carry.
    TooManyKeys,
    /// A flower port match without a `ip_proto` that has ports.
    PortWithoutProto,
    /// A pre-encoded `raw` payload longer than one netlink attribute.
    OptionsTooLong,
};

/// What to attach as a **filter** (`RTM_NEWTFILTER`).
pub const FilterSpec = union(enum) {
    u32: U32,
    flower: Flower,
    raw: qdisc.Raw,

    pub fn kind(self: FilterSpec) []const u8 {
        return switch (self) {
            .u32 => "u32",
            .flower => "flower",
            .raw => |r| r.kind,
        };
    }

    /// Append the kind-specific `TCA_OPTIONS` body.
    ///
    /// Kept for source compatibility with v2, when no filter option needed a
    /// psched calibration: it pins `Psched.fallback`. The only thing that
    /// reads the calibration is a `police` **action**, whose burst would then
    /// be timed at 1 tick/µs — so anything carrying actions should go through
    /// `appendOptionsWith` (or simply through `Socket`, which passes its own).
    pub fn appendOptions(
        self: FilterSpec,
        gpa: std.mem.Allocator,
        list: *std.ArrayList(u8),
    ) EncodeError!void {
        return self.appendOptionsWith(gpa, list, Psched.fallback);
    }

    /// `appendOptions` with an explicit psched calibration.
    pub fn appendOptionsWith(
        self: FilterSpec,
        gpa: std.mem.Allocator,
        list: *std.ArrayList(u8),
        ps: Psched,
    ) EncodeError!void {
        switch (self) {
            .u32 => |u| try appendU32Options(u, gpa, list, ps),
            .flower => |f| try appendFlowerOptions(f, gpa, list, ps),
            .raw => |r| {
                if (r.options.len > std.math.maxInt(u16)) return error.OptionsTooLong;
                try list.appendSlice(gpa, r.options);
                try list.appendNTimes(gpa, 0, codec.alignUp(r.options.len) - r.options.len);
            },
        }
    }
};

/// Compose a filter's `tcm_info` from its priority and ethertype —
/// `TC_H_MAKE(prio << 16, htons(protocol))`.
pub fn makeInfo(prio: u16, eth_type: u16) u32 {
    const be: u16 = std.mem.nativeToBig(u16, eth_type);
    return handle_mod.make(@as(u32, prio) << 16, be);
}

/// Split a filter's `tcm_info` back into `(prio, protocol)`, undoing the
/// network-byte-order dance on the protocol half.
pub fn parseInfo(info: u32) struct { prio: u16, eth_type: u16 } {
    return .{
        .prio = @intCast(info >> 16),
        .eth_type = std.mem.bigToNative(u16, @truncate(info)),
    };
}

/// One filter, as read back by an `RTM_GETTFILTER` dump.
pub const Filter = struct {
    ifindex: u32,
    handle: Handle,
    parent: Handle,
    prio: u16,
    eth_type: u16,
    kind_buf: [qdisc.kind_max]u8 = @splat(0),
    kind_len: u8 = 0,
    /// Decoded u32 selector, when `kind() == "u32"`. (Named `u32_sel`
    /// because `u32` is a primitive type name.)
    u32_sel: ?U32Wire = null,
    /// Decoded flower keys, when `kind() == "flower"`.
    flower: ?FlowerWire = null,
    /// The decoded action list, capped at `action.max_actions_decoded`
    /// entries (`act_list.total` reports the true count). Reach it through
    /// `actions()`.
    act_list: ActionList = .{},

    pub fn kind(f: *const Filter) []const u8 {
        return f.kind_buf[0..f.kind_len];
    }

    /// The actions attached to this filter, in list order.
    pub fn actions(f: *const Filter) []const action.Action {
        return f.act_list.slice();
    }

    /// The class this filter selects, whatever classifier it uses.
    pub fn classid(f: *const Filter) ?Handle {
        if (f.u32_sel) |u| return u.classid;
        if (f.flower) |fl| return fl.classid;
        return null;
    }
};

/// Parse an `RTM_NEWTFILTER` payload into a `Filter`.
pub fn parseFilter(payload: []const u8) codec.Error!Filter {
    if (payload.len < qdisc.tcmsg_len) return error.Truncated;
    const info = std.mem.readInt(u32, payload[16..20], native_endian);
    const split = parseInfo(info);
    var f: Filter = .{
        .ifindex = @bitCast(std.mem.readInt(i32, payload[4..8], native_endian)),
        .handle = Handle.fromRaw(std.mem.readInt(u32, payload[8..12], native_endian)),
        .parent = Handle.fromRaw(std.mem.readInt(u32, payload[12..16], native_endian)),
        .prio = split.prio,
        .eth_type = split.eth_type,
    };
    var options_data: ?[]const u8 = null;
    var it: codec.AttrIterator = .{ .buf = payload[qdisc.tcmsg_len..] };
    while (try it.next()) |a| switch (a.type) {
        TCA.KIND => {
            const s = a.asString();
            if (s.len > qdisc.kind_max) return error.BadLength;
            @memcpy(f.kind_buf[0..s.len], s);
            f.kind_len = @intCast(s.len);
        },
        TCA.OPTIONS => options_data = a.data,
        else => {},
    };
    if (options_data) |opt| {
        const k = f.kind();
        if (std.mem.eql(u8, k, "u32")) {
            f.u32_sel = try parseU32Options(opt);
        } else if (std.mem.eql(u8, k, "flower")) {
            f.flower = try parseFlowerOptions(opt);
        }
        if (actionAttrId(k)) |act_id| {
            var ait: codec.AttrIterator = .{ .buf = opt };
            while (try ait.next()) |a| {
                if (a.type != act_id) continue;
                f.act_list = try action.parseActionList(a.data);
                break;
            }
        }
    }
    return f;
}

/// Which attribute inside a classifier's `TCA_OPTIONS` carries its action
/// list. Both are `TCA_ACT_*`-shaped; only the id differs per classifier.
fn actionAttrId(kind: []const u8) ?u16 {
    if (std.mem.eql(u8, kind, "u32")) return TCA_U32.ACT;
    if (std.mem.eql(u8, kind, "flower")) return TCA_FLOWER.ACT;
    // matchall/basic/bpf/fw all place their action list at attribute 1..3 of
    // their own enum; not modelled, so no guessing here.
    return null;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// The capture host's calibration; only `police` actions read it.
const test_ps = ratespec.golden_psched;

test "filter attribute constants agree with the kernel UAPI" {
    try testing.expectEqual(@as(u16, 1), TCA_U32.CLASSID);
    try testing.expectEqual(@as(u16, 5), TCA_U32.SEL);
    try testing.expectEqual(@as(u16, 1), TCA_FLOWER.CLASSID);
    try testing.expectEqual(@as(u16, 8), TCA_FLOWER.KEY_ETH_TYPE);
    try testing.expectEqual(@as(u16, 9), TCA_FLOWER.KEY_IP_PROTO);
    try testing.expectEqual(@as(u16, 13), TCA_FLOWER.KEY_IPV4_DST_MASK);
    try testing.expectEqual(@as(u16, 19), TCA_FLOWER.KEY_TCP_DST);
    try testing.expectEqual(@as(u16, 22), TCA_FLOWER.FLAGS);
    try testing.expectEqual(@as(usize, 16), tc_u32_sel_len);
    try testing.expectEqual(@as(usize, 16), tc_u32_key_len);
}

test "tcm_info packs prio + network-order protocol (the classic pitfall)" {
    // `protocol ip prio 1` → 0x00010008, not 0x00010800.
    try testing.expectEqual(@as(u32, 0x00010008), makeInfo(1, ETH_P.IP));
    try testing.expectEqual(@as(u32, 0x00020008), makeInfo(2, ETH_P.IP));
    try testing.expectEqual(@as(u32, 0x0004dd86), makeInfo(4, ETH_P.IPV6));
    const back = parseInfo(makeInfo(4, ETH_P.IPV6));
    try testing.expectEqual(@as(u16, 4), back.prio);
    try testing.expectEqual(ETH_P.IPV6, back.eth_type);
    const back2 = parseInfo(makeInfo(1, ETH_P.IP));
    try testing.expectEqual(@as(u16, 1), back2.prio);
    try testing.expectEqual(ETH_P.IP, back2.eth_type);
}

test "U32Key helpers place matches at the right IPv4 offsets" {
    const dst = U32Key.ipv4Dst(.{ 10, 0, 0, 1 }, 32);
    try testing.expectEqual(@as(i32, 16), dst.off);
    try testing.expectEqualSlices(u8, &.{ 0xff, 0xff, 0xff, 0xff }, &dst.mask);
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 1 }, &dst.val);

    const src = U32Key.ipv4Src(.{ 192, 168, 1, 77 }, 24);
    try testing.expectEqual(@as(i32, 12), src.off);
    try testing.expectEqualSlices(u8, &.{ 0xff, 0xff, 0xff, 0x00 }, &src.mask);
    try testing.expectEqualSlices(u8, &.{ 192, 168, 1, 0 }, &src.val); // pre-masked

    const any = U32Key.ipv4Src(.{ 1, 2, 3, 4 }, 0);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0 }, &any.mask);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0 }, &any.val);

    const proto = U32Key.ipv4Proto(IPPROTO.TCP);
    try testing.expectEqual(@as(i32, 8), proto.off);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0xff, 0x00, 0x00 }, &proto.mask);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x06, 0x00, 0x00 }, &proto.val);
}

test "prefixMask6 builds IPv6 masks bit-exactly" {
    try testing.expectEqualSlices(u8, &([_]u8{0xff} ** 4 ++ [_]u8{0} ** 12), &prefixMask6(32));
    try testing.expectEqualSlices(u8, &([_]u8{0xff} ** 16), &prefixMask6(128));
    try testing.expectEqualSlices(u8, &([_]u8{0} ** 16), &prefixMask6(0));
    try testing.expectEqualSlices(u8, &([_]u8{ 0xff, 0xe0 } ++ [_]u8{0} ** 14), &prefixMask6(11));
}

test "encode/decode round-trip: u32 selector with two keys" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    const keys = [_]U32Key{
        U32Key.ipv4Src(.{ 192, 168, 1, 0 }, 24),
        U32Key.ipv4Dst(.{ 10, 0, 0, 1 }, 32),
    };
    try appendU32Options(.{ .classid = Handle.init(1, 0x10), .keys = &keys }, gpa, &list, test_ps);
    const uw = try parseU32Options(list.items);
    try testing.expectEqual(Handle.init(1, 0x10).raw, uw.classid.?.raw);
    try testing.expectEqual(@as(u8, TC_U32.TERMINAL), uw.flags);
    try testing.expectEqual(@as(u8, 2), uw.nkeys);
    try testing.expectEqual(@as(u8, 2), uw.keys_len);
    try testing.expectEqual(@as(i32, 12), uw.keys[0].off);
    try testing.expectEqual(@as(i32, 16), uw.keys[1].off);
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 1 }, &uw.keys[1].val);
}

test "encode/decode round-trip: flower over IPv6" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    const v6: [16]u8 = .{ 0x20, 0x01, 0x0d, 0xb8 } ++ [_]u8{0} ** 12;
    try appendFlowerOptions(.{
        .eth_type = ETH_P.IPV6,
        .ip_proto = IPPROTO.UDP,
        .ipv6_src = .{ .addr = v6, .prefix_len = 32 },
        .dst_port = 53,
        .classid = Handle.init(1, 0x30),
    }, gpa, &list, test_ps);
    const fw = try parseFlowerOptions(list.items);
    try testing.expectEqual(ETH_P.IPV6, fw.eth_type.?);
    try testing.expectEqual(IPPROTO.UDP, fw.ip_proto.?);
    try testing.expectEqual(@as(u16, 53), fw.dst_port.?);
    try testing.expectEqual(Handle.init(1, 0x30).raw, fw.classid.?.raw);
    try testing.expectEqualSlices(u8, &v6, &fw.ipv6_src.?);
    try testing.expectEqual(@as(u32, 0), fw.flags.?);
}

test "flower rejects a port match the protocol cannot carry" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try testing.expectError(error.PortWithoutProto, appendFlowerOptions(
        .{ .eth_type = ETH_P.IP, .dst_port = 80 },
        gpa,
        &list,
        test_ps,
    ));
    try testing.expectError(error.PortWithoutProto, appendFlowerOptions(
        .{ .eth_type = ETH_P.IP, .ip_proto = IPPROTO.ICMP, .src_port = 1 },
        gpa,
        &list,
        test_ps,
    ));
    try testing.expectEqual(@as(usize, 0), list.items.len);
}

test "u32 rejects an oversized key list" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    const many = try gpa.alloc(U32Key, u32_max_keys + 1);
    defer gpa.free(many);
    @memset(many, U32Key.word(0, 0, 0));
    try testing.expectError(error.TooManyKeys, appendU32Options(.{ .keys = many }, gpa, &list, test_ps));
}

/// Classifier `TCA_OPTIONS` bodies and whole `RTM_NEWTFILTER` payloads for
/// `fuzzParseFilter`, laid out the way its draws read them: a `testkit.fuzz`
/// slice seed (u32 length + frame) and then an eight-octet little-endian word
/// carrying the `tcmsg.info` value handed to `parseInfo`.
///
/// ⭐ Built at run time by this file's own encoders rather than quoted as hex:
/// a classifier option is a netlink TLV whose length and scalars are HOST byte
/// order, so a hex corpus would be a little-endian one and the counts pinned
/// below would be false on a big-endian target instead of failing there.
///
/// ⛔ The `info` word is not decoration. `parseInfo` splits a `tcmsg.info`
/// into a priority and an ethertype, and it used to be fed
/// `smith.value(u32)` — a draw made AFTER the byte draw had eaten the seed,
/// so it read **0 on every seed** and the one input this target ever ran
/// asked for prio 0 / ethertype 0. It travels in the seed now.
const FilterCorpus = struct {
    scratch: [8192]u8 = undefined,
    store: [8192]u8 = undefined,
    used: usize = 0,
    entries: [12][]const u8 = undefined,
    infos: [12]u32 = undefined,
    n: usize = 0,

    fn push(self: *FilterCorpus, frame: []const u8, info: u32) void {
        const head = testkit.fuzz.seedInto(self.store[self.used..], frame);
        std.mem.writeInt(u64, self.store[self.used + head.len ..][0..8], info, .little);
        self.entries[self.n] = self.store[self.used..][0 .. head.len + 8];
        self.infos[self.n] = info;
        self.used += head.len + 8;
        self.n += 1;
    }

    /// A `struct tcmsg` header, which is what `parseFilter` takes in front of
    /// the attribute list. Written here rather than borrowed from
    /// `message.appendTcmsg` because `message.zig` imports this file.
    fn tcmsg(
        gpa: std.mem.Allocator,
        list: *std.ArrayList(u8),
        ifindex: u32,
        h: Handle,
        parent: Handle,
        info: u32,
    ) !void {
        var hdr: [qdisc.tcmsg_len]u8 = @splat(0);
        std.mem.writeInt(i32, hdr[4..8], @bitCast(ifindex), native_endian);
        std.mem.writeInt(u32, hdr[8..12], h.raw, native_endian);
        std.mem.writeInt(u32, hdr[12..16], parent.raw, native_endian);
        std.mem.writeInt(u32, hdr[16..20], info, native_endian);
        try codec.appendPadded(gpa, list, &hdr);
    }

    fn build(self: *FilterCorpus) ![]const []const u8 {
        var fba = std.heap.FixedBufferAllocator.init(&self.scratch);
        const gpa = fba.allocator();
        const info_http = makeInfo(10, ETH_P.IP);

        // ── option bodies ──────────────────────────────────────────────────
        // A u32 selector with two keys, a classid and an action list — the
        // three parts of `parseU32Options` that a bare selector never reaches.
        var u32_opts: std.ArrayList(u8) = .empty;
        try appendU32Options(.{
            .classid = Handle.init(1, 0x10),
            .keys = &.{
                U32Key.ipv4Dst(.{ 10, 0, 0, 1 }, 32),
                U32Key.word(0xff00_0000, 0x0000_0006, 8),
            },
            .actions = &.{.{ .gact = .{ .action = .shot } }},
        }, gpa, &u32_opts, test_ps);
        self.push(u32_opts.items, info_http);

        // flower, IPv4, with ports and an action.
        var fl4: std.ArrayList(u8) = .empty;
        try appendFlowerOptions(.{
            .eth_type = ETH_P.IP,
            .ip_proto = IPPROTO.TCP,
            .ipv4_src = .{ .addr = .{ 10, 0, 0, 0 }, .prefix_len = 8 },
            .ipv4_dst = .{ .addr = .{ 192, 168, 1, 1 }, .prefix_len = 32 },
            .src_port = 12345,
            .dst_port = 80,
            .classid = Handle.init(1, 0x20),
            .flags = 1,
            .actions = &.{.{ .gact = .{ .action = .shot } }},
        }, gpa, &fl4, test_ps);
        self.push(fl4.items, info_http);

        // flower, IPv6 — the only path that reads a 16-octet key.
        var fl6: std.ArrayList(u8) = .empty;
        try appendFlowerOptions(.{
            .eth_type = ETH_P.IPV6,
            .ip_proto = IPPROTO.UDP,
            .ipv6_src = .{ .addr = @splat(0x20), .prefix_len = 64 },
            .ipv6_dst = .{ .addr = @splat(0xfe), .prefix_len = 128 },
            .src_port = 53,
            .dst_port = 53,
        }, gpa, &fl6, test_ps);
        self.push(fl6.items, makeInfo(1, ETH_P.IPV6));

        // ── whole tcmsg payloads, which is what a dump hands `parseFilter` ──
        var f_u32: std.ArrayList(u8) = .empty;
        try tcmsg(gpa, &f_u32, 2, Handle.fromRaw(0x800_0800), Handle.init(1, 0), info_http);
        try codec.appendAttrString(gpa, &f_u32, TCA.KIND, "u32");
        try codec.appendAttr(gpa, &f_u32, TCA.OPTIONS, u32_opts.items);
        self.push(f_u32.items, info_http);

        var f_flower: std.ArrayList(u8) = .empty;
        try tcmsg(gpa, &f_flower, 2, Handle.fromRaw(1), Handle.clsact, info_http);
        try codec.appendAttrString(gpa, &f_flower, TCA.KIND, "flower");
        try codec.appendAttr(gpa, &f_flower, TCA.OPTIONS, fl4.items);
        self.push(f_flower.items, info_http);

        // A classifier this module does not model: KIND is copied, OPTIONS is
        // left alone and `actionAttrId` returns null.
        var f_matchall: std.ArrayList(u8) = .empty;
        try tcmsg(gpa, &f_matchall, 2, Handle.fromRaw(1), Handle.clsact, info_http);
        try codec.appendAttrString(gpa, &f_matchall, TCA.KIND, "matchall");
        try codec.appendAttr(gpa, &f_matchall, TCA.OPTIONS, &[_]u8{ 8, 0, 1, 0, 1, 0, 0, 0 });
        self.push(f_matchall.items, info_http);

        // ── attributes that arrive with the WRONG length ───────────────────
        // Every `if (a.data.len == N)` here is a bound only a malformed reply
        // reaches; a well-formed capture cannot exercise one.
        var u32_short: std.ArrayList(u8) = .empty;
        try codec.appendAttr(gpa, &u32_short, TCA_U32.CLASSID, &[_]u8{0} ** 2);
        try codec.appendAttr(gpa, &u32_short, TCA_U32.SEL, &[_]u8{0} ** 8);
        self.push(u32_short.items, 0xffff_ffff);

        // A selector whose declared `nkeys` is 8 but whose payload holds one
        // and a half — the `off + tc_u32_key_len <= a.data.len` loop bound.
        var u32_partial: std.ArrayList(u8) = .empty;
        {
            var sel: [tc_u32_sel_len + tc_u32_key_len + 8]u8 = @splat(0);
            sel[0] = TC_U32.TERMINAL;
            sel[2] = 8; // nkeys the kernel claims
            try codec.appendAttr(gpa, &u32_partial, TCA_U32.SEL, &sel);
        }
        self.push(u32_partial.items, 0);

        var flower_short: std.ArrayList(u8) = .empty;
        try codec.appendAttr(gpa, &flower_short, TCA_FLOWER.KEY_ETH_TYPE, &[_]u8{0} ** 1);
        try codec.appendAttr(gpa, &flower_short, TCA_FLOWER.KEY_IP_PROTO, &.{});
        try codec.appendAttr(gpa, &flower_short, TCA_FLOWER.KEY_IPV4_SRC, &[_]u8{0} ** 2);
        try codec.appendAttr(gpa, &flower_short, TCA_FLOWER.KEY_IPV6_SRC, &[_]u8{0} ** 8);
        try codec.appendAttr(gpa, &flower_short, TCA_FLOWER.KEY_TCP_SRC, &[_]u8{0} ** 1);
        try codec.appendAttr(gpa, &flower_short, TCA_FLOWER.FLAGS, &[_]u8{0} ** 2);
        try codec.appendAttr(gpa, &flower_short, TCA_FLOWER.CLASSID, &[_]u8{0} ** 3);
        self.push(flower_short.items, 0x0800_0001);

        // ── the refusals ───────────────────────────────────────────────────
        // A payload one octet short of `struct tcmsg`.
        self.push(&([_]u8{0} ** (qdisc.tcmsg_len - 1)), 0);
        // A KIND string one octet past `qdisc.kind_max`.
        var long_kind: std.ArrayList(u8) = .empty;
        try tcmsg(gpa, &long_kind, 2, Handle.unspec, Handle.clsact, 0);
        try codec.appendAttrString(gpa, &long_kind, TCA.KIND, "0123456789abcdefg");
        self.push(long_kind.items, 0);
        // An attribute header declaring 0x40 octets over a 2-octet buffer.
        self.push(&[_]u8{ 0x40, 0x00 }, 0);

        return self.entries[0..self.n];
    }
};

test "fuzz: filter parsers never crash on arbitrary payloads" {
    var corpus: FilterCorpus = .{};
    try testing.fuzz({}, fuzzParseFilter, .{ .corpus = try corpus.build() });
}

fn fuzzParseFilter(_: void, smith: *std.testing.Smith) !void {
    // 1024, not 256: a u32 selector carrying the kernel's maximum key count is
    // 16 + 128*16 octets, and a seed longer than the buffer is not a big seed
    // — `Smith.slice` reads it back as the EMPTY one.
    var raw: [1024]u8 = undefined;
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
    // length. `bytes` takes `@min(raw.len, in.len)` octets and the ranged draw
    // then finds fewer than the eight it needs and returns the range MINIMUM,
    // so `len` was 0 for every seed and all three parsers were handed an EMPTY
    // slice with the filter sitting unread in `raw`.
    //
    // ⛔ Measured 2026-09-07 over the corpus above: **0 of 12 seeds non-empty,
    // 0 u32 keys decoded, 0 flower fields decoded and 0 kinds read before;
    // 12 of 12 non-empty, 3 keys, 18 flower fields and 3 kinds after.**
    // `parseU32Options` and `parseFlowerOptions` both SUCCEED on the empty
    // slice — an empty options body is a legal classifier reply — so an
    // acceptance count called this harness healthy while it walked nothing.
    const len: usize = smith.slice(&raw);
    const buf = raw[0..len];
    if (parseU32Options(buf)) |_| {} else |_| {}
    if (parseFlowerOptions(buf)) |_| {} else |_| {}
    if (parseFilter(buf)) |f| std.mem.doNotOptimizeAway(f.kind().len) else |_| {}
    // ⚠ `value(u64)` truncated, not `value(u32)`: a `u32` draw reads eight
    // input octets as a little-endian u64 and only survives if the whole word
    // fits in 32 bits, so it was 0 for every seed. The word travels in the
    // seed's tail now.
    _ = parseInfo(@truncate(smith.value(u64)));
}

test "corpus: every filter seed reaches the parsers, and the decoded counts are pinned" {
    // ⭐ The measurement, executable rather than written in a comment, over the
    // SAME corpus the harness gets. `nonempty` is the reach claim and the only
    // check that catches a seed grown past the harness's buffer, which
    // `Smith.slice` reads back as the EMPTY one, silently. `keys`, `flower`
    // and `kinds` are the numbers an empty options body cannot produce, and
    // `infos` pins that the `tcmsg.info` word arrived as written — without it
    // the `parseInfo` half of the harness silently goes back to asking about 0.
    var corpus: FilterCorpus = .{};
    const entries = try corpus.build();
    var nonempty: usize = 0;
    var keys: usize = 0;
    var flower: usize = 0;
    var kinds: usize = 0;
    var infos: usize = 0;
    for (entries, corpus.infos[0..corpus.n]) |sd, want_info| {
        var smith: std.testing.Smith = .{ .in = sd };
        var raw: [1024]u8 = undefined;
        const len: usize = smith.slice(&raw);
        if (len != 0) nonempty += 1;
        const buf = raw[0..len];
        if (parseU32Options(buf)) |w| keys += w.keys_len else |_| {}
        if (parseFlowerOptions(buf)) |w| flower += qdisc.optionalsSet(w) else |_| {}
        if (parseFilter(buf)) |f| {
            if (f.kind().len != 0) kinds += 1;
        } else |_| {}
        const info: u32 = @truncate(smith.value(u64));
        if (info == want_info) infos += 1;
        std.mem.doNotOptimizeAway(parseInfo(info));
    }
    try testing.expectEqual(entries.len, nonempty);
    try testing.expectEqual(@as(usize, 3), keys);
    try testing.expectEqual(@as(usize, 18), flower);
    try testing.expectEqual(@as(usize, 3), kinds);
    try testing.expectEqual(entries.len, infos);
}

test "the v2 entry points keep working unchanged (source compatibility)" {
    const gpa = testing.allocator;
    var a: std.ArrayList(u8) = .empty;
    defer a.deinit(gpa);
    var b: std.ArrayList(u8) = .empty;
    defer b.deinit(gpa);
    const spec: FilterSpec = .{ .u32 = .{
        .classid = Handle.init(1, 0x10),
        .keys = &.{U32Key.ipv4Dst(.{ 10, 0, 0, 1 }, 32)},
    } };
    // The three-argument form (no psched) still exists and, for any spec
    // without a `police` action, produces exactly what the psched-aware one
    // does — the calibration is only ever read by police.
    try spec.appendOptions(gpa, &a);
    try spec.appendOptionsWith(gpa, &b, test_ps);
    try testing.expectEqualSlices(u8, a.items, b.items);
}
