// SPDX-License-Identifier: MIT
//! Classifier (filter) encoding: **u32**, **flower**, **matchall** and **bpf**
//! (classic-BPF bytecode form).
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

/// A u32 hash-table handle word: `ht` is the table id (`800:` is 0x800), `bucket`
/// the hash bucket, `node` the entry in it. It is what `TCA_U32_HASH` and
/// `TCA_U32_LINK` carry, and what a filter's `tcm_handle` holds for a node
/// (`Handle.fromRaw(htHandle(…))`).
pub fn htHandle(ht: u12, bucket: u8, node: u12) u32 {
    return (@as(u32, ht) << 20) | (@as(u32, bucket) << 12) | @as(u32, node);
}

/// `struct tc_u32_mark` — `match mark VAL MASK`, a match on the packet's
/// firewall mark. The kernel keeps a hit counter next to it; a request sends 0.
pub const U32Mark = struct {
    val: u32,
    mask: u32,
    success: u32 = 0,
};

/// `TCA_CLS_FLAGS_*` — bits of `U32.flags` and `Flower.flags`.
pub const TCA_CLS_FLAGS = struct {
    pub const SKIP_HW: u32 = 1;
    pub const SKIP_SW: u32 = 2;
    pub const IN_HW: u32 = 4;
    pub const NOT_IN_HW: u32 = 8;
    pub const VERBOSE: u32 = 16;
};

/// `sizeof(struct tc_u32_sel)` without keys: flags/offshift/nkeys + 1 pad,
/// offmask, off, offoff, hoff, hmask.
pub const tc_u32_sel_len = 16;
/// `sizeof(struct tc_u32_key)`: mask, val, off, offmask.
pub const tc_u32_key_len = 16;
/// The most keys one selector can carry: `tc_u32_sel.nkeys` is a `u8`.
pub const u32_max_keys = std.math.maxInt(u8);

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
    /// `divisor N` — create a hash table of N buckets (`tc filter add …
    /// handle 10: u32 divisor 16`). `tc` sends nothing else with it, and so
    /// does this encoder.
    divisor: ?u32 = null,
    /// `ht ID:BUCKET:NODE` — put this filter into that hash table
    /// (`TCA_U32_HASH`); see `htHandle`.
    hash: ?u32 = null,
    /// `link ID:` — a match continues in the hash table with that id
    /// (`TCA_U32_LINK`); see `htHandle`.
    link: ?u32 = null,
    /// `match mark VAL MASK`.
    mark: ?U32Mark = null,
    /// `indev NAME` — only for packets received on that interface.
    indev: ?[]const u8 = null,
    /// `TCA_U32_FLAGS` — `TCA_CLS_FLAGS.*` (`skip_hw`, `skip_sw`).
    flags: u32 = 0,
    /// Further `tc_u32_sel.flags` bits (`TC_U32.OFFSET | VAROFFSET | EAT`),
    /// next to `TERMINAL`, for a selector with variable offsets.
    sel_flags: u8 = 0,
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
    /// The selector's offset fields, as the kernel stores them.
    offshift: u8 = 0,
    offmask: u16 = 0,
    off: u16 = 0,
    offoff: i16 = 0,
    hoff: i16 = 0,
    hmask: u32 = 0,
    hash: ?u32 = null,
    link: ?u32 = null,
    divisor: ?u32 = null,
    mark: ?U32Mark = null,
    /// `TCA_U32_FLAGS`.
    cls_flags: ?u32 = null,
    indev_buf: [qdisc.kind_max]u8 = @splat(0),
    indev_len: u8 = 0,

    /// `indev`, or an empty slice.
    pub fn indev(w: *const U32Wire) []const u8 {
        return w.indev_buf[0..w.indev_len];
    }
};

fn appendU32Options(
    u: U32,
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    ps: Psched,
) EncodeError!void {
    if (u.keys.len > u32_max_keys) return error.TooManyKeys;
    if (u.divisor) |d| {
        // A hash-table creation request carries the divisor and nothing else.
        return codec.appendAttrU32(gpa, list, TCA_U32.DIVISOR, d);
    }
    // Emission order matches the `tc` binary's requests (the goldens pin it):
    // everything given on the command line first (the classid, then the action list), then the
    // selector — which is why `flowid X:Y action …` puts CLASSID before ACT.
    if (u.mark) |m| {
        var raw: [12]u8 = undefined;
        std.mem.writeInt(u32, raw[0..4], m.val, native_endian);
        std.mem.writeInt(u32, raw[4..8], m.mask, native_endian);
        std.mem.writeInt(u32, raw[8..12], m.success, native_endian);
        try appendBytes(gpa, list, TCA_U32.MARK, &raw);
    }
    if (u.classid) |c| try codec.appendAttrU32(gpa, list, TCA_U32.CLASSID, c.raw);
    try action.appendActionList(gpa, list, TCA_U32.ACT, u.actions, ps);
    if (u.link) |l| try codec.appendAttrU32(gpa, list, TCA_U32.LINK, l);
    if (u.hash) |h| try codec.appendAttrU32(gpa, list, TCA_U32.HASH, h);
    if (u.indev) |name| {
        codec.appendAttrString(gpa, list, TCA_U32.INDEV, name) catch |err| switch (err) {
            error.AttrTooLong => return error.OptionsTooLong,
            error.OutOfMemory => return error.OutOfMemory,
        };
    }

    const sel_len = tc_u32_sel_len + u.keys.len * tc_u32_key_len;
    var hdr: [codec.attr_header_len]u8 = undefined;
    std.mem.writeInt(u16, hdr[0..2], @intCast(codec.attr_header_len + sel_len), native_endian);
    std.mem.writeInt(u16, hdr[2..4], TCA_U32.SEL, native_endian);
    try list.appendSlice(gpa, &hdr);

    var sel: [tc_u32_sel_len]u8 = @splat(0);
    sel[0] = (if (u.terminal) TC_U32.TERMINAL else 0) | u.sel_flags;
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
    if (u.flags != 0) try codec.appendAttrU32(gpa, list, TCA_U32.FLAGS, u.flags);
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
            uw.offshift = a.data[1];
            uw.nkeys = a.data[2];
            uw.offmask = std.mem.readInt(u16, a.data[4..6], native_endian);
            uw.off = std.mem.readInt(u16, a.data[6..8], native_endian);
            uw.offoff = std.mem.readInt(i16, a.data[8..10], native_endian);
            uw.hoff = std.mem.readInt(i16, a.data[10..12], native_endian);
            uw.hmask = std.mem.readInt(u32, a.data[12..16], native_endian);
            var off: usize = tc_u32_sel_len;
            while (off + tc_u32_key_len <= a.data.len and uw.keys_len < uw.keys.len) {
                uw.keys[uw.keys_len] = U32Key.decode(a.data[off..][0..tc_u32_key_len]);
                uw.keys_len += 1;
                off += tc_u32_key_len;
            }
        },
        TCA_U32.HASH => uw.hash = readScalar(u32, a.data, native_endian),
        TCA_U32.LINK => uw.link = readScalar(u32, a.data, native_endian),
        TCA_U32.DIVISOR => uw.divisor = readScalar(u32, a.data, native_endian),
        TCA_U32.FLAGS => uw.cls_flags = readScalar(u32, a.data, native_endian),
        TCA_U32.MARK => if (a.data.len >= 12) {
            uw.mark = .{
                .val = std.mem.readInt(u32, a.data[0..4], native_endian),
                .mask = std.mem.readInt(u32, a.data[4..8], native_endian),
                .success = std.mem.readInt(u32, a.data[8..12], native_endian),
            };
        },
        TCA_U32.INDEV => {
            const name = a.asString();
            const n = @min(name.len, uw.indev_buf.len);
            @memcpy(uw.indev_buf[0..n], name[0..n]);
            uw.indev_len = @intCast(n);
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
    pub const KEY_VLAN_ID: u16 = 23;
    pub const KEY_VLAN_PRIO: u16 = 24;
    pub const KEY_VLAN_ETH_TYPE: u16 = 25;
    pub const KEY_ENC_KEY_ID: u16 = 26;
    pub const KEY_ENC_IPV4_SRC: u16 = 27;
    pub const KEY_ENC_IPV4_SRC_MASK: u16 = 28;
    pub const KEY_ENC_IPV4_DST: u16 = 29;
    pub const KEY_ENC_IPV4_DST_MASK: u16 = 30;
    pub const KEY_ENC_IPV6_SRC: u16 = 31;
    pub const KEY_ENC_IPV6_SRC_MASK: u16 = 32;
    pub const KEY_ENC_IPV6_DST: u16 = 33;
    pub const KEY_ENC_IPV6_DST_MASK: u16 = 34;
    pub const KEY_ENC_UDP_DST_PORT: u16 = 45;
    pub const KEY_FLAGS: u16 = 47;
    pub const KEY_FLAGS_MASK: u16 = 48;
    pub const KEY_ICMPV4_CODE: u16 = 49;
    pub const KEY_ICMPV4_CODE_MASK: u16 = 50;
    pub const KEY_ICMPV4_TYPE: u16 = 51;
    pub const KEY_ICMPV4_TYPE_MASK: u16 = 52;
    pub const KEY_ICMPV6_CODE: u16 = 53;
    pub const KEY_ICMPV6_CODE_MASK: u16 = 54;
    pub const KEY_ICMPV6_TYPE: u16 = 55;
    pub const KEY_ICMPV6_TYPE_MASK: u16 = 56;
    pub const KEY_ARP_SIP: u16 = 57;
    pub const KEY_ARP_SIP_MASK: u16 = 58;
    pub const KEY_ARP_TIP: u16 = 59;
    pub const KEY_ARP_TIP_MASK: u16 = 60;
    pub const KEY_ARP_OP: u16 = 61;
    pub const KEY_ARP_OP_MASK: u16 = 62;
    pub const KEY_ARP_SHA: u16 = 63;
    pub const KEY_ARP_SHA_MASK: u16 = 64;
    pub const KEY_ARP_THA: u16 = 65;
    pub const KEY_ARP_THA_MASK: u16 = 66;
    pub const KEY_MPLS_TTL: u16 = 67;
    pub const KEY_MPLS_BOS: u16 = 68;
    pub const KEY_MPLS_TC: u16 = 69;
    pub const KEY_MPLS_LABEL: u16 = 70;
    pub const KEY_TCP_FLAGS: u16 = 71;
    pub const KEY_TCP_FLAGS_MASK: u16 = 72;
    pub const KEY_IP_TOS: u16 = 73;
    pub const KEY_IP_TOS_MASK: u16 = 74;
    pub const KEY_IP_TTL: u16 = 75;
    pub const KEY_IP_TTL_MASK: u16 = 76;
    pub const KEY_CVLAN_ID: u16 = 77;
    pub const KEY_CVLAN_PRIO: u16 = 78;
    pub const KEY_CVLAN_ETH_TYPE: u16 = 79;
    pub const KEY_ENC_IP_TOS: u16 = 80;
    pub const KEY_ENC_IP_TOS_MASK: u16 = 81;
    pub const KEY_ENC_IP_TTL: u16 = 82;
    pub const KEY_ENC_IP_TTL_MASK: u16 = 83;
    pub const KEY_PORT_SRC_MIN: u16 = 87;
    pub const KEY_PORT_SRC_MAX: u16 = 88;
    pub const KEY_PORT_DST_MIN: u16 = 89;
    pub const KEY_PORT_DST_MAX: u16 = 90;
    pub const KEY_CT_STATE: u16 = 91;
    pub const KEY_CT_STATE_MASK: u16 = 92;
    pub const KEY_CT_ZONE: u16 = 93;
    pub const KEY_CT_ZONE_MASK: u16 = 94;
    pub const KEY_CT_MARK: u16 = 95;
    pub const KEY_CT_MARK_MASK: u16 = 96;
    pub const KEY_CT_LABELS: u16 = 97;
    pub const KEY_CT_LABELS_MASK: u16 = 98;
    /// The SCTP port keys come after the whole mask block, not at 27/28 (which
    /// are the tunnel IPv4 source keys): iproute2 6.19 sends 41 and 42.
    pub const KEY_SCTP_SRC: u16 = 41;
    pub const KEY_SCTP_DST: u16 = 42;
};

/// `TCA_FLOWER_KEY_CT_FLAGS_*` — bits of `Flower.ct_state`.
pub const FLOWER_CT = struct {
    pub const NEW: u16 = 0x01;
    pub const ESTABLISHED: u16 = 0x02;
    pub const RELATED: u16 = 0x04;
    pub const TRACKED: u16 = 0x08;
    pub const INVALID: u16 = 0x10;
    pub const REPLY: u16 = 0x20;
};

/// `TCA_FLOWER_KEY_FLAGS_*` — bits of `Flower.ip_flags`.
pub const FLOWER_KEY_FLAGS = struct {
    pub const IS_FRAGMENT: u32 = 1;
    pub const FRAG_IS_FIRST: u32 = 2;
};

fn allOnes(comptime T: type) T {
    return switch (@typeInfo(T)) {
        .int => std.math.maxInt(T),
        .array => @splat(0xff),
        else => @compileError("allOnes: integer or array"),
    };
}

/// A value and the mask flower applies to it. `.mask` defaults to all ones
/// (an exact match), which is what `tc` sends for a bare value.
pub fn Masked(comptime T: type) type {
    return struct {
        value: T,
        mask: T = allOnes(T),
    };
}

/// What flower read back for a value/mask pair: either half may be absent.
pub fn MaskedWire(comptime T: type) type {
    return struct {
        value: ?T = null,
        mask: ?T = null,
    };
}

/// `dst_port MIN-MAX` / `src_port MIN-MAX` (`TCA_FLOWER_KEY_PORT_*_MIN/MAX`).
pub const PortRange = struct {
    min: u16,
    max: u16,
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
    /// `dst_mac` / `src_mac`; `tc` sends the full mask for a bare address.
    eth_dst: ?Masked([6]u8) = null,
    eth_src: ?Masked([6]u8) = null,
    /// `vlan_id`, `vlan_prio`, `vlan_ethtype` (the ethertype inside the tag,
    /// host order) and the same three for the inner tag, `cvlan_*`.
    vlan_id: ?u16 = null,
    vlan_prio: ?u8 = null,
    vlan_eth_type: ?u16 = null,
    cvlan_id: ?u16 = null,
    cvlan_prio: ?u8 = null,
    cvlan_eth_type: ?u16 = null,
    /// `tcp_flags V/M` (big-endian on the wire; `tc` defaults the mask to
    /// 0x0fff).
    tcp_flags: ?Masked(u16) = null,
    /// `ip_tos V/M` and `ip_ttl V/M` (the IPv6 traffic class and hop limit).
    ip_tos: ?Masked(u8) = null,
    ip_ttl: ?Masked(u8) = null,
    /// `type` / `code` of an ICMP or ICMPv6 message; needs `ip_proto` icmp or
    /// icmpv6 (`error.PortWithoutProto` otherwise).
    icmp_type: ?Masked(u8) = null,
    icmp_code: ?Masked(u8) = null,
    /// `src_port MIN-MAX` / `dst_port MIN-MAX`; need a port protocol.
    src_port_range: ?PortRange = null,
    dst_port_range: ?PortRange = null,
    /// `indev NAME` — the receiving interface.
    indev: ?[]const u8 = null,
    /// `ct_state`, `ct_zone`, `ct_mark`, `ct_label` (`FLOWER_CT` bits for the
    /// state).
    ct_state: ?Masked(u16) = null,
    ct_zone: ?Masked(u16) = null,
    ct_mark: ?Masked(u32) = null,
    ct_labels: ?Masked([16]u8) = null,
    /// `arp_sip`, `arp_tip` (addresses with a mask, not pre-masked), `arp_op`,
    /// `arp_sha`, `arp_tha`.
    arp_sip: ?Masked([4]u8) = null,
    arp_tip: ?Masked([4]u8) = null,
    arp_op: ?Masked(u8) = null,
    arp_sha: ?Masked([6]u8) = null,
    arp_tha: ?Masked([6]u8) = null,
    /// `mpls_label`, `mpls_tc`, `mpls_bos`, `mpls_ttl`.
    mpls_label: ?u32 = null,
    mpls_tc: ?u8 = null,
    mpls_bos: ?u8 = null,
    mpls_ttl: ?u8 = null,
    /// `ip_flags` (`FLOWER_KEY_FLAGS` bits; `nofrag` is value 0, mask
    /// `IS_FRAGMENT`).
    ip_flags: ?Masked(u32) = null,
    /// Tunnel keys: `enc_key_id` (big-endian), `enc_src_ip`, `enc_dst_ip`
    /// (IPv4 and IPv6), `enc_dst_port`, `enc_tos`, `enc_ttl`.
    enc_key_id: ?u32 = null,
    enc_ipv4_src: ?Masked([4]u8) = null,
    enc_ipv4_dst: ?Masked([4]u8) = null,
    enc_ipv6_src: ?Masked([16]u8) = null,
    enc_ipv6_dst: ?Masked([16]u8) = null,
    enc_dst_port: ?u16 = null,
    enc_tos: ?Masked(u8) = null,
    enc_ttl: ?Masked(u8) = null,
    /// `classid X:Y`.
    classid: ?Handle = null,
    /// `TCA_FLOWER_FLAGS` (skip_hw / skip_sw); always sent, 0 by default.
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
    eth_dst: MaskedWire([6]u8) = .{},
    eth_src: MaskedWire([6]u8) = .{},
    vlan_id: ?u16 = null,
    vlan_prio: ?u8 = null,
    vlan_eth_type: ?u16 = null,
    cvlan_id: ?u16 = null,
    cvlan_prio: ?u8 = null,
    cvlan_eth_type: ?u16 = null,
    tcp_flags: MaskedWire(u16) = .{},
    ip_tos: MaskedWire(u8) = .{},
    ip_ttl: MaskedWire(u8) = .{},
    /// The ICMPv4 or ICMPv6 type/code, whichever the kernel sent.
    icmp_type: MaskedWire(u8) = .{},
    icmp_code: MaskedWire(u8) = .{},
    src_port_min: ?u16 = null,
    src_port_max: ?u16 = null,
    dst_port_min: ?u16 = null,
    dst_port_max: ?u16 = null,
    indev_buf: [qdisc.kind_max]u8 = @splat(0),
    indev_len: u8 = 0,
    ct_state: MaskedWire(u16) = .{},
    ct_zone: MaskedWire(u16) = .{},
    ct_mark: MaskedWire(u32) = .{},
    ct_labels: MaskedWire([16]u8) = .{},
    arp_sip: MaskedWire([4]u8) = .{},
    arp_tip: MaskedWire([4]u8) = .{},
    arp_op: MaskedWire(u8) = .{},
    arp_sha: MaskedWire([6]u8) = .{},
    arp_tha: MaskedWire([6]u8) = .{},
    mpls_label: ?u32 = null,
    mpls_tc: ?u8 = null,
    mpls_bos: ?u8 = null,
    mpls_ttl: ?u8 = null,
    ip_flags: MaskedWire(u32) = .{},
    enc_key_id: ?u32 = null,
    enc_ipv4_src: MaskedWire([4]u8) = .{},
    enc_ipv4_dst: MaskedWire([4]u8) = .{},
    enc_ipv6_src: MaskedWire([16]u8) = .{},
    enc_ipv6_dst: MaskedWire([16]u8) = .{},
    enc_dst_port: ?u16 = null,
    enc_tos: MaskedWire(u8) = .{},
    enc_ttl: MaskedWire(u8) = .{},

    /// `indev`, or an empty slice.
    pub fn indev(w: *const FlowerWire) []const u8 {
        return w.indev_buf[0..w.indev_len];
    }
};

fn appendScalar(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    v: anytype,
    endian: std.builtin.Endian,
) std.mem.Allocator.Error!void {
    const T = @TypeOf(v);
    switch (@typeInfo(T)) {
        .int => {
            var raw: [@sizeOf(T)]u8 = undefined;
            std.mem.writeInt(T, &raw, v, endian);
            try appendBytes(gpa, list, attr_type, &raw);
        },
        .array => try appendBytes(gpa, list, attr_type, &v),
        else => @compileError("appendScalar: integer or array"),
    }
}

fn appendMasked(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    val_type: u16,
    mask_type: u16,
    m: anytype,
    endian: std.builtin.Endian,
) std.mem.Allocator.Error!void {
    try appendScalar(gpa, list, val_type, m.value, endian);
    try appendScalar(gpa, list, mask_type, m.mask, endian);
}

fn readScalar(comptime T: type, data: []const u8, endian: std.builtin.Endian) ?T {
    switch (@typeInfo(T)) {
        .int => {
            if (data.len != @sizeOf(T)) return null;
            return std.mem.readInt(T, data[0..@sizeOf(T)], endian);
        },
        .array => {
            if (data.len != @sizeOf(T)) return null;
            return data[0..@sizeOf(T)].*;
        },
        else => @compileError("readScalar: integer or array"),
    }
}

/// Store one half of a value/mask pair (`is_mask` picks which).
fn setMasked(
    comptime T: type,
    slot: *MaskedWire(T),
    is_mask: bool,
    data: []const u8,
    endian: std.builtin.Endian,
) void {
    const v = readScalar(T, data, endian) orelse return;
    if (is_mask) slot.mask = v else slot.value = v;
}

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

/// The keys beyond L2-L4 basics, in this module's fixed order.
fn appendFlowerExtra(
    f: Flower,
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
) EncodeError!void {
    const T = TCA_FLOWER;
    if (f.eth_dst) |m| try appendMasked(gpa, list, T.KEY_ETH_DST, T.KEY_ETH_DST_MASK, m, .big);
    if (f.eth_src) |m| try appendMasked(gpa, list, T.KEY_ETH_SRC, T.KEY_ETH_SRC_MASK, m, .big);
    if (f.vlan_id) |v| try appendScalar(gpa, list, T.KEY_VLAN_ID, v, native_endian);
    if (f.vlan_prio) |v| try appendScalar(gpa, list, T.KEY_VLAN_PRIO, v, native_endian);
    if (f.vlan_eth_type) |v| try appendScalar(gpa, list, T.KEY_VLAN_ETH_TYPE, v, .big);
    if (f.cvlan_id) |v| try appendScalar(gpa, list, T.KEY_CVLAN_ID, v, native_endian);
    if (f.cvlan_prio) |v| try appendScalar(gpa, list, T.KEY_CVLAN_PRIO, v, native_endian);
    if (f.cvlan_eth_type) |v| try appendScalar(gpa, list, T.KEY_CVLAN_ETH_TYPE, v, .big);
    if (f.tcp_flags) |m| try appendMasked(gpa, list, T.KEY_TCP_FLAGS, T.KEY_TCP_FLAGS_MASK, m, .big);
    if (f.ip_tos) |m| try appendMasked(gpa, list, T.KEY_IP_TOS, T.KEY_IP_TOS_MASK, m, native_endian);
    if (f.ip_ttl) |m| try appendMasked(gpa, list, T.KEY_IP_TTL, T.KEY_IP_TTL_MASK, m, native_endian);
    const v6 = f.ip_proto != null and f.ip_proto.? == IPPROTO.ICMPV6;
    if (f.icmp_type) |m| try appendMasked(
        gpa,
        list,
        if (v6) T.KEY_ICMPV6_TYPE else T.KEY_ICMPV4_TYPE,
        if (v6) T.KEY_ICMPV6_TYPE_MASK else T.KEY_ICMPV4_TYPE_MASK,
        m,
        native_endian,
    );
    if (f.icmp_code) |m| try appendMasked(
        gpa,
        list,
        if (v6) T.KEY_ICMPV6_CODE else T.KEY_ICMPV4_CODE,
        if (v6) T.KEY_ICMPV6_CODE_MASK else T.KEY_ICMPV4_CODE_MASK,
        m,
        native_endian,
    );
    if (f.src_port_range) |r| {
        try appendScalar(gpa, list, T.KEY_PORT_SRC_MIN, r.min, .big);
        try appendScalar(gpa, list, T.KEY_PORT_SRC_MAX, r.max, .big);
    }
    if (f.dst_port_range) |r| {
        try appendScalar(gpa, list, T.KEY_PORT_DST_MIN, r.min, .big);
        try appendScalar(gpa, list, T.KEY_PORT_DST_MAX, r.max, .big);
    }
    if (f.indev) |name| {
        codec.appendAttrString(gpa, list, T.INDEV, name) catch |err| switch (err) {
            error.AttrTooLong => return error.OptionsTooLong,
            error.OutOfMemory => return error.OutOfMemory,
        };
    }
    if (f.ct_state) |m| try appendMasked(gpa, list, T.KEY_CT_STATE, T.KEY_CT_STATE_MASK, m, native_endian);
    if (f.ct_zone) |m| try appendMasked(gpa, list, T.KEY_CT_ZONE, T.KEY_CT_ZONE_MASK, m, native_endian);
    if (f.ct_mark) |m| try appendMasked(gpa, list, T.KEY_CT_MARK, T.KEY_CT_MARK_MASK, m, native_endian);
    if (f.ct_labels) |m| try appendMasked(gpa, list, T.KEY_CT_LABELS, T.KEY_CT_LABELS_MASK, m, .big);
    if (f.arp_sip) |m| try appendMasked(gpa, list, T.KEY_ARP_SIP, T.KEY_ARP_SIP_MASK, m, .big);
    if (f.arp_tip) |m| try appendMasked(gpa, list, T.KEY_ARP_TIP, T.KEY_ARP_TIP_MASK, m, .big);
    if (f.arp_op) |m| try appendMasked(gpa, list, T.KEY_ARP_OP, T.KEY_ARP_OP_MASK, m, native_endian);
    if (f.arp_sha) |m| try appendMasked(gpa, list, T.KEY_ARP_SHA, T.KEY_ARP_SHA_MASK, m, .big);
    if (f.arp_tha) |m| try appendMasked(gpa, list, T.KEY_ARP_THA, T.KEY_ARP_THA_MASK, m, .big);
    if (f.mpls_label) |v| try appendScalar(gpa, list, T.KEY_MPLS_LABEL, v, native_endian);
    if (f.mpls_tc) |v| try appendScalar(gpa, list, T.KEY_MPLS_TC, v, native_endian);
    if (f.mpls_bos) |v| try appendScalar(gpa, list, T.KEY_MPLS_BOS, v, native_endian);
    if (f.mpls_ttl) |v| try appendScalar(gpa, list, T.KEY_MPLS_TTL, v, native_endian);
    if (f.enc_key_id) |v| try appendScalar(gpa, list, T.KEY_ENC_KEY_ID, v, .big);
    if (f.enc_ipv4_src) |m| try appendMasked(gpa, list, T.KEY_ENC_IPV4_SRC, T.KEY_ENC_IPV4_SRC_MASK, m, .big);
    if (f.enc_ipv4_dst) |m| try appendMasked(gpa, list, T.KEY_ENC_IPV4_DST, T.KEY_ENC_IPV4_DST_MASK, m, .big);
    if (f.enc_ipv6_src) |m| try appendMasked(gpa, list, T.KEY_ENC_IPV6_SRC, T.KEY_ENC_IPV6_SRC_MASK, m, .big);
    if (f.enc_ipv6_dst) |m| try appendMasked(gpa, list, T.KEY_ENC_IPV6_DST, T.KEY_ENC_IPV6_DST_MASK, m, .big);
    if (f.enc_dst_port) |v| try appendScalar(gpa, list, T.KEY_ENC_UDP_DST_PORT, v, .big);
    if (f.enc_tos) |m| try appendMasked(gpa, list, T.KEY_ENC_IP_TOS, T.KEY_ENC_IP_TOS_MASK, m, native_endian);
    if (f.enc_ttl) |m| try appendMasked(gpa, list, T.KEY_ENC_IP_TTL, T.KEY_ENC_IP_TTL_MASK, m, native_endian);
}

fn appendFlowerOptions(
    f: Flower,
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    ps: Psched,
) EncodeError!void {
    if (f.src_port != null or f.dst_port != null or
        f.src_port_range != null or f.dst_port_range != null)
    {
        const proto = f.ip_proto orelse return error.PortWithoutProto;
        if (portAttrs(proto) == null) return error.PortWithoutProto;
    }
    if (f.icmp_type != null or f.icmp_code != null) {
        const proto = f.ip_proto orelse return error.PortWithoutProto;
        if (proto != IPPROTO.ICMP and proto != IPPROTO.ICMPV6) return error.PortWithoutProto;
    }

    // Emission order is this module's own fixed order (keys as proto, src,
    // dst, ports; then classid, the action list, FLAGS and ETH_TYPE), so a
    // request is reproducible; the kernel does not care, and the goldens use
    // the matching `tc` argument order.
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
    try appendFlowerExtra(f, gpa, list);
    if (f.classid) |c| try codec.appendAttrU32(gpa, list, TCA_FLOWER.CLASSID, c.raw);
    try action.appendActionList(gpa, list, TCA_FLOWER.ACT, f.actions, ps);
    try codec.appendAttrU32(gpa, list, TCA_FLOWER.FLAGS, f.flags);
    // `tc` puts the fragment flags after `TCA_FLOWER_FLAGS`, unlike the other keys.
    if (f.ip_flags) |m| try appendMasked(gpa, list, TCA_FLOWER.KEY_FLAGS, TCA_FLOWER.KEY_FLAGS_MASK, m, .big);
    try appendBe16(gpa, list, TCA_FLOWER.KEY_ETH_TYPE, f.eth_type);
}

fn parseFlowerExtra(fw: *FlowerWire, a: codec.Attr) void {
    const T = TCA_FLOWER;
    const ne = native_endian;
    switch (a.type) {
        T.INDEV => {
            const name = a.asString();
            const n = @min(name.len, fw.indev_buf.len);
            @memcpy(fw.indev_buf[0..n], name[0..n]);
            fw.indev_len = @intCast(n);
        },
        T.KEY_ETH_DST => setMasked([6]u8, &fw.eth_dst, false, a.data, .big),
        T.KEY_ETH_DST_MASK => setMasked([6]u8, &fw.eth_dst, true, a.data, .big),
        T.KEY_ETH_SRC => setMasked([6]u8, &fw.eth_src, false, a.data, .big),
        T.KEY_ETH_SRC_MASK => setMasked([6]u8, &fw.eth_src, true, a.data, .big),
        T.KEY_VLAN_ID => fw.vlan_id = readScalar(u16, a.data, ne),
        T.KEY_VLAN_PRIO => fw.vlan_prio = readScalar(u8, a.data, ne),
        T.KEY_VLAN_ETH_TYPE => fw.vlan_eth_type = readScalar(u16, a.data, .big),
        T.KEY_CVLAN_ID => fw.cvlan_id = readScalar(u16, a.data, ne),
        T.KEY_CVLAN_PRIO => fw.cvlan_prio = readScalar(u8, a.data, ne),
        T.KEY_CVLAN_ETH_TYPE => fw.cvlan_eth_type = readScalar(u16, a.data, .big),
        T.KEY_TCP_FLAGS => setMasked(u16, &fw.tcp_flags, false, a.data, .big),
        T.KEY_TCP_FLAGS_MASK => setMasked(u16, &fw.tcp_flags, true, a.data, .big),
        T.KEY_IP_TOS => setMasked(u8, &fw.ip_tos, false, a.data, ne),
        T.KEY_IP_TOS_MASK => setMasked(u8, &fw.ip_tos, true, a.data, ne),
        T.KEY_IP_TTL => setMasked(u8, &fw.ip_ttl, false, a.data, ne),
        T.KEY_IP_TTL_MASK => setMasked(u8, &fw.ip_ttl, true, a.data, ne),
        T.KEY_ICMPV4_TYPE, T.KEY_ICMPV6_TYPE => setMasked(u8, &fw.icmp_type, false, a.data, ne),
        T.KEY_ICMPV4_TYPE_MASK, T.KEY_ICMPV6_TYPE_MASK => setMasked(u8, &fw.icmp_type, true, a.data, ne),
        T.KEY_ICMPV4_CODE, T.KEY_ICMPV6_CODE => setMasked(u8, &fw.icmp_code, false, a.data, ne),
        T.KEY_ICMPV4_CODE_MASK, T.KEY_ICMPV6_CODE_MASK => setMasked(u8, &fw.icmp_code, true, a.data, ne),
        T.KEY_PORT_SRC_MIN => fw.src_port_min = readScalar(u16, a.data, .big),
        T.KEY_PORT_SRC_MAX => fw.src_port_max = readScalar(u16, a.data, .big),
        T.KEY_PORT_DST_MIN => fw.dst_port_min = readScalar(u16, a.data, .big),
        T.KEY_PORT_DST_MAX => fw.dst_port_max = readScalar(u16, a.data, .big),
        T.KEY_CT_STATE => setMasked(u16, &fw.ct_state, false, a.data, ne),
        T.KEY_CT_STATE_MASK => setMasked(u16, &fw.ct_state, true, a.data, ne),
        T.KEY_CT_ZONE => setMasked(u16, &fw.ct_zone, false, a.data, ne),
        T.KEY_CT_ZONE_MASK => setMasked(u16, &fw.ct_zone, true, a.data, ne),
        T.KEY_CT_MARK => setMasked(u32, &fw.ct_mark, false, a.data, ne),
        T.KEY_CT_MARK_MASK => setMasked(u32, &fw.ct_mark, true, a.data, ne),
        T.KEY_CT_LABELS => setMasked([16]u8, &fw.ct_labels, false, a.data, .big),
        T.KEY_CT_LABELS_MASK => setMasked([16]u8, &fw.ct_labels, true, a.data, .big),
        T.KEY_ARP_SIP => setMasked([4]u8, &fw.arp_sip, false, a.data, .big),
        T.KEY_ARP_SIP_MASK => setMasked([4]u8, &fw.arp_sip, true, a.data, .big),
        T.KEY_ARP_TIP => setMasked([4]u8, &fw.arp_tip, false, a.data, .big),
        T.KEY_ARP_TIP_MASK => setMasked([4]u8, &fw.arp_tip, true, a.data, .big),
        T.KEY_ARP_OP => setMasked(u8, &fw.arp_op, false, a.data, ne),
        T.KEY_ARP_OP_MASK => setMasked(u8, &fw.arp_op, true, a.data, ne),
        T.KEY_ARP_SHA => setMasked([6]u8, &fw.arp_sha, false, a.data, .big),
        T.KEY_ARP_SHA_MASK => setMasked([6]u8, &fw.arp_sha, true, a.data, .big),
        T.KEY_ARP_THA => setMasked([6]u8, &fw.arp_tha, false, a.data, .big),
        T.KEY_ARP_THA_MASK => setMasked([6]u8, &fw.arp_tha, true, a.data, .big),
        T.KEY_MPLS_LABEL => fw.mpls_label = readScalar(u32, a.data, ne),
        T.KEY_MPLS_TC => fw.mpls_tc = readScalar(u8, a.data, ne),
        T.KEY_MPLS_BOS => fw.mpls_bos = readScalar(u8, a.data, ne),
        T.KEY_MPLS_TTL => fw.mpls_ttl = readScalar(u8, a.data, ne),
        T.KEY_FLAGS => setMasked(u32, &fw.ip_flags, false, a.data, .big),
        T.KEY_FLAGS_MASK => setMasked(u32, &fw.ip_flags, true, a.data, .big),
        T.KEY_ENC_KEY_ID => fw.enc_key_id = readScalar(u32, a.data, .big),
        T.KEY_ENC_IPV4_SRC => setMasked([4]u8, &fw.enc_ipv4_src, false, a.data, .big),
        T.KEY_ENC_IPV4_SRC_MASK => setMasked([4]u8, &fw.enc_ipv4_src, true, a.data, .big),
        T.KEY_ENC_IPV4_DST => setMasked([4]u8, &fw.enc_ipv4_dst, false, a.data, .big),
        T.KEY_ENC_IPV4_DST_MASK => setMasked([4]u8, &fw.enc_ipv4_dst, true, a.data, .big),
        T.KEY_ENC_IPV6_SRC => setMasked([16]u8, &fw.enc_ipv6_src, false, a.data, .big),
        T.KEY_ENC_IPV6_SRC_MASK => setMasked([16]u8, &fw.enc_ipv6_src, true, a.data, .big),
        T.KEY_ENC_IPV6_DST => setMasked([16]u8, &fw.enc_ipv6_dst, false, a.data, .big),
        T.KEY_ENC_IPV6_DST_MASK => setMasked([16]u8, &fw.enc_ipv6_dst, true, a.data, .big),
        T.KEY_ENC_UDP_DST_PORT => fw.enc_dst_port = readScalar(u16, a.data, .big),
        T.KEY_ENC_IP_TOS => setMasked(u8, &fw.enc_tos, false, a.data, ne),
        T.KEY_ENC_IP_TOS_MASK => setMasked(u8, &fw.enc_tos, true, a.data, ne),
        T.KEY_ENC_IP_TTL => setMasked(u8, &fw.enc_ttl, false, a.data, ne),
        T.KEY_ENC_IP_TTL_MASK => setMasked(u8, &fw.enc_ttl, true, a.data, ne),
        else => {},
    }
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
        else => parseFlowerExtra(&fw, a),
    };
    return fw;
}

// ── matchall ────────────────────────────────────────────────────────────────

/// matchall classifier attributes (linux/pkt_cls.h `TCA_MATCHALL_*`).
pub const TCA_MATCHALL = struct {
    pub const UNSPEC: u16 = 0;
    pub const CLASSID: u16 = 1;
    pub const ACT: u16 = 2;
    pub const FLAGS: u16 = 3;
    pub const PCNT: u16 = 4;
    pub const PAD: u16 = 5;
};

/// The "everything" classifier (`tc filter add ... matchall`): no key at all,
/// it only binds every packet to a class and/or an action list. iproute2
/// 6.19 sends, in this order, `classid`, the action list, then the flags
/// (`skip_sw`/`skip_hw`), each only when given.
///
/// ⚠ A matchall with none of the three is encoded as an EMPTY `TCA_OPTIONS`
/// nest. A stock `tc filter add ... matchall` with nothing after it sends no
/// `TCA_OPTIONS` at all and the kernel refuses it (`Invalid argument`,
/// measured on Linux 7.0), so there is no golden for the bare form.
pub const Matchall = struct {
    /// `classid X:Y` (`flowid` is the same keyword).
    classid: ?Handle = null,
    /// `action …`, emitted as the nested `TCA_MATCHALL_ACT`.
    actions: []const ActionSpec = &.{},
    /// `TCA_MATCHALL_FLAGS` (`skip_sw` = 2, `skip_hw` = 1); sent only when non-zero.
    flags: u32 = 0,
};

/// Wire readback of a matchall filter's options.
pub const MatchallWire = struct {
    classid: ?Handle = null,
    flags: ?u32 = null,
};

fn appendMatchallOptions(
    m: Matchall,
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    ps: Psched,
) EncodeError!void {
    if (m.classid) |c| try codec.appendAttrU32(gpa, list, TCA_MATCHALL.CLASSID, c.raw);
    try action.appendActionList(gpa, list, TCA_MATCHALL.ACT, m.actions, ps);
    if (m.flags != 0) try codec.appendAttrU32(gpa, list, TCA_MATCHALL.FLAGS, m.flags);
}

pub fn parseMatchallOptions(data: []const u8) codec.Error!MatchallWire {
    var mw: MatchallWire = .{};
    var it: codec.AttrIterator = .{ .buf = data };
    while (try it.next()) |a| switch (a.type) {
        TCA_MATCHALL.CLASSID => if (a.data.len == 4) {
            mw.classid = Handle.fromRaw(std.mem.readInt(u32, a.data[0..4], native_endian));
        },
        TCA_MATCHALL.FLAGS => if (a.data.len == 4) {
            mw.flags = std.mem.readInt(u32, a.data[0..4], native_endian);
        },
        else => {},
    };
    return mw;
}

// ── bpf ─────────────────────────────────────────────────────────────────────

/// bpf classifier attributes (linux/pkt_cls.h `TCA_BPF_*`).
pub const TCA_BPF = struct {
    pub const UNSPEC: u16 = 0;
    pub const ACT: u16 = 1;
    pub const POLICE: u16 = 2;
    pub const CLASSID: u16 = 3;
    pub const OPS_LEN: u16 = 4;
    pub const OPS: u16 = 5;
    pub const FD: u16 = 6;
    pub const NAME: u16 = 7;
    pub const FLAGS: u16 = 8;
    pub const FLAGS_GEN: u16 = 9;
    pub const TAG: u16 = 10;
    pub const ID: u16 = 11;
};

/// `TCA_BPF_FLAG_ACT_DIRECT` (`da` / `direct-action` on the command line).
pub const TCA_BPF_FLAG_ACT_DIRECT: u32 = 1;

/// One classic-BPF instruction (`struct sock_filter`), host byte order;
/// shared with the `bpf` action.
pub const BpfInsn = action.BpfInsn;

/// `BPF_MAXINSNS`: the longest classic program the kernel accepts.
pub const bpf_max_insns = 4096;
pub const bpf_insn_len = 8;

/// A bpf classifier carrying either an inline **classic-BPF** program
/// (`tc filter add ... bpf bytecode '<n>,<code> <jt> <jf> <k>,...'`, `ops`)
/// or an already-loaded **eBPF** program by file descriptor (`fd`; what `tc
/// … bpf obj FILE`, `pinned PATH` and `fd N` all end up sending). Loading an
/// object file or opening a pin is the caller's job (`bpf(2)`); the fd form has
/// no golden, since producing one needs a loaded program (privileged).
///
/// iproute2 6.19 order on the wire: `classid`, the action list, `OPS_LEN`,
/// `OPS`, `FLAGS_GEN` (`skip_sw`/`skip_hw`), `FLAGS` (`da`); each only when
/// given.
pub const Bpf = struct {
    /// The classic program, 1..`bpf_max_insns` instructions — or empty when
    /// `fd` names an eBPF program (exactly one of the two).
    ops: []const BpfInsn = &.{},
    /// `TCA_BPF_FD` — a loaded eBPF program's file descriptor.
    fd: ?u32 = null,
    /// `TCA_BPF_NAME` — the program name shown by `tc filter show` (`name
    /// foo`).
    name: ?[]const u8 = null,
    classid: ?Handle = null,
    actions: []const ActionSpec = &.{},
    /// `da` / `direct-action`: the program's return value is the verdict.
    direct_action: bool = false,
    /// `TCA_BPF_FLAGS_GEN` (`skip_sw` = 2, `skip_hw` = 1); sent only when non-zero.
    flags_gen: u32 = 0,
};

/// Wire readback of a bpf filter's options.
pub const BpfWire = struct {
    classid: ?Handle = null,
    /// `TCA_BPF_OPS_LEN`: the instruction count of the inline classic program.
    ops_len: ?u16 = null,
    flags: ?u32 = null,
    flags_gen: ?u32 = null,
    /// `TCA_BPF_ID` — the kernel's program id (eBPF).
    id: ?u32 = null,
    /// `TCA_BPF_TAG` — the program's 8-byte tag (eBPF).
    tag: ?[8]u8 = null,
    name_buf: [qdisc.kind_max * 2]u8 = @splat(0),
    name_len: u8 = 0,

    /// `TCA_BPF_NAME`, or an empty slice.
    pub fn name(w: *const BpfWire) []const u8 {
        return w.name_buf[0..w.name_len];
    }
};

fn appendBpfOptions(
    b: Bpf,
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    ps: Psched,
) EncodeError!void {
    // Exactly one program: inline classic bytecode, or an eBPF fd.
    if ((b.ops.len == 0) == (b.fd == null) or b.ops.len > bpf_max_insns) return error.BadBpfProgram;
    if (b.classid) |c| try codec.appendAttrU32(gpa, list, TCA_BPF.CLASSID, c.raw);
    try action.appendActionList(gpa, list, TCA_BPF.ACT, b.actions, ps);
    if (b.ops.len != 0) {
        var len_raw: [2]u8 = undefined;
        std.mem.writeInt(u16, &len_raw, @intCast(b.ops.len), native_endian);
        try appendBytes(gpa, list, TCA_BPF.OPS_LEN, &len_raw);
        // The OPS attribute (8 bytes per instruction, at most 32 KiB) fits one attribute.
        var ops: std.ArrayList(u8) = .empty;
        defer ops.deinit(gpa);
        for (b.ops) |i| {
            var raw: [bpf_insn_len]u8 = undefined;
            std.mem.writeInt(u16, raw[0..2], i.code, native_endian);
            raw[2] = i.jt;
            raw[3] = i.jf;
            std.mem.writeInt(u32, raw[4..8], i.k, native_endian);
            try ops.appendSlice(gpa, &raw);
        }
        try appendBytes(gpa, list, TCA_BPF.OPS, ops.items);
    }
    if (b.fd) |fd| try codec.appendAttrU32(gpa, list, TCA_BPF.FD, fd);
    if (b.name) |name| {
        codec.appendAttrString(gpa, list, TCA_BPF.NAME, name) catch |err| switch (err) {
            error.AttrTooLong => return error.OptionsTooLong,
            error.OutOfMemory => return error.OutOfMemory,
        };
    }
    if (b.flags_gen != 0) try codec.appendAttrU32(gpa, list, TCA_BPF.FLAGS_GEN, b.flags_gen);
    if (b.direct_action) try codec.appendAttrU32(gpa, list, TCA_BPF.FLAGS, TCA_BPF_FLAG_ACT_DIRECT);
}

pub fn parseBpfOptions(data: []const u8) codec.Error!BpfWire {
    var bw: BpfWire = .{};
    var it: codec.AttrIterator = .{ .buf = data };
    while (try it.next()) |a| switch (a.type) {
        TCA_BPF.CLASSID => if (a.data.len == 4) {
            bw.classid = Handle.fromRaw(std.mem.readInt(u32, a.data[0..4], native_endian));
        },
        TCA_BPF.OPS_LEN => if (a.data.len == 2) {
            bw.ops_len = std.mem.readInt(u16, a.data[0..2], native_endian);
        },
        TCA_BPF.FLAGS => if (a.data.len == 4) {
            bw.flags = std.mem.readInt(u32, a.data[0..4], native_endian);
        },
        TCA_BPF.FLAGS_GEN => if (a.data.len == 4) {
            bw.flags_gen = std.mem.readInt(u32, a.data[0..4], native_endian);
        },
        TCA_BPF.ID => bw.id = readScalar(u32, a.data, native_endian),
        TCA_BPF.TAG => bw.tag = readScalar([8]u8, a.data, .big),
        TCA_BPF.NAME => {
            const name = a.asString();
            const n = @min(name.len, bw.name_buf.len);
            @memcpy(bw.name_buf[0..n], name[0..n]);
            bw.name_len = @intCast(n);
        },
        else => {},
    };
    return bw;
}

// ── ematch trees (basic, cgroup) ────────────────────────────────────────────

/// `TCA_EMATCH_TREE_*`.
pub const TCA_EMATCH_TREE = struct {
    pub const HDR: u16 = 1;
    pub const LIST: u16 = 2;
};

/// `TCF_EM_*` — the kind of one extended match.
pub const EM_KIND = struct {
    pub const CONTAINER: u16 = 0;
    pub const CMP: u16 = 1;
    pub const NBYTE: u16 = 2;
    pub const U32: u16 = 3;
    pub const META: u16 = 4;
    pub const TEXT: u16 = 5;
    pub const VLAN: u16 = 6;
    pub const CANID: u16 = 7;
    pub const IPSET: u16 = 8;
    pub const IPT: u16 = 9;
};

/// `TCF_EM_REL_*` / `TCF_EM_INVERT` — bits of `Ematch.flags`. `REL_AND` and
/// `REL_OR` join this match to the NEXT one (the last match has neither);
/// `INVERT` is the `not` prefix.
pub const EM_FLAG = struct {
    pub const REL_AND: u16 = 1;
    pub const REL_OR: u16 = 2;
    pub const INVERT: u16 = 4;
};

/// `tcf_em_cmp.align`.
pub const EmAlign = enum(u4) { u8 = 1, u16 = 2, u32 = 4 };
/// `tcf_em_cmp.layer` — `TCF_LAYER_*`.
pub const EmLayer = enum(u4) { link = 0, network = 1, transport = 2 };
/// `tcf_em_cmp.opnd` — `TCF_EM_OPND_*`.
pub const EmOpnd = enum(u4) { eq = 0, gt = 1, lt = 2 };

/// The `cmp(u8 at 0 layer network eq 4)` match: a masked comparison of 1, 2
/// or 4 bytes at an offset inside one header layer.
pub const EmCmp = struct {
    val: u32,
    mask: u32 = 0,
    off: u16 = 0,
    @"align": EmAlign = .u8,
    layer: EmLayer = .network,
    opnd: EmOpnd = .eq,
    /// `TCF_EM_CMP_TRANS` (the `trans` flag: compare after byte-order conversion).
    trans: bool = false,

    /// `struct tcf_em_cmp`, the data of an `EM_KIND.CMP` match.
    pub fn encode(c: EmCmp) [12]u8 {
        var out: [12]u8 = undefined;
        std.mem.writeInt(u32, out[0..4], c.val, native_endian);
        std.mem.writeInt(u32, out[4..8], c.mask, native_endian);
        std.mem.writeInt(u16, out[8..10], c.off, native_endian);
        out[10] = @as(u8, @backingInt(c.@"align")) | (@as(u8, @intFromBool(c.trans)) << 4);
        out[11] = @as(u8, @backingInt(c.layer)) | (@as(u8, @backingInt(c.opnd)) << 4);
        return out;
    }
};

/// One extended match of a `basic` or `cgroup` filter: its kind, its flags
/// (`EM_FLAG`) and the kind's data (`EmCmp.encode`, a `u32` key from
/// `emU32`, or a pre-encoded blob for `meta`, `nbyte`, `text` …).
pub const Ematch = struct {
    kind: u16,
    flags: u16 = 0,
    data: []const u8 = &.{},
};

/// `struct tc_u32_key`, the data of an `EM_KIND.U32` match (`u32(u32 0x1
/// 0xff at 0)`).
pub fn emU32(key: U32Key) [tc_u32_key_len]u8 {
    return key.encode();
}

/// The most extended matches one tree may carry here.
pub const em_max_matches = 255;
/// How many ematches a decoded `basic`/`cgroup` filter keeps.
pub const em_max_decoded = 4;
/// How many data bytes of each decoded ematch are kept.
pub const em_data_decoded = 16;

/// One decoded ematch.
pub const EmatchWire = struct {
    kind: u16 = 0,
    flags: u16 = 0,
    /// The first `em_data_decoded` bytes of the match's data.
    data: [em_data_decoded]u8 = @splat(0),
    data_len: u8 = 0,
    /// The data length the kernel sent.
    full_len: u16 = 0,

    pub fn dataBytes(e: *const EmatchWire) []const u8 {
        return e.data[0..e.data_len];
    }
};

/// The decoded ematch tree of a `basic` or `cgroup` filter.
pub const EmatchTreeWire = struct {
    /// `tcf_ematch_tree_hdr.nmatches`.
    nmatches: u16 = 0,
    items: [em_max_decoded]EmatchWire = @splat(.{}),
    len: u8 = 0,

    pub fn slice(t: *const EmatchTreeWire) []const EmatchWire {
        return t.items[0..t.len];
    }
};

fn appendEmatchTree(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    ems: []const Ematch,
) EncodeError!void {
    if (ems.len == 0) return;
    if (ems.len > em_max_matches) return error.TooManyKeys;
    const outer = try codec.nestBegin(gpa, list, attr_type);
    var hdr: [4]u8 = @splat(0);
    std.mem.writeInt(u16, hdr[0..2], @intCast(ems.len), native_endian);
    try appendBytes(gpa, list, TCA_EMATCH_TREE.HDR, &hdr);
    const tree = try codec.nestBegin(gpa, list, TCA_EMATCH_TREE.LIST);
    for (ems, 0..) |e, i| {
        if (e.data.len > std.math.maxInt(u16) - 12) return error.OptionsTooLong;
        const entry = try codec.nestBegin(gpa, list, @intCast(i + 1));
        // struct tcf_ematch_hdr: matchid, kind, flags, pad.
        var eh: [8]u8 = @splat(0);
        std.mem.writeInt(u16, eh[2..4], e.kind, native_endian);
        std.mem.writeInt(u16, eh[4..6], e.flags, native_endian);
        try list.appendSlice(gpa, &eh);
        try list.appendSlice(gpa, e.data);
        try list.appendNTimes(gpa, 0, codec.alignUp(e.data.len) - e.data.len);
        codec.nestEnd(list, entry) catch return error.OptionsTooLong;
    }
    codec.nestEnd(list, tree) catch return error.OptionsTooLong;
    codec.nestEnd(list, outer) catch return error.OptionsTooLong;
}

fn parseEmatchTree(data: []const u8) codec.Error!EmatchTreeWire {
    var t: EmatchTreeWire = .{};
    var it: codec.AttrIterator = .{ .buf = data };
    while (try it.next()) |a| switch (a.type) {
        TCA_EMATCH_TREE.HDR => if (a.data.len >= 2) {
            t.nmatches = std.mem.readInt(u16, a.data[0..2], native_endian);
        },
        TCA_EMATCH_TREE.LIST => {
            var lit: codec.AttrIterator = .{ .buf = a.data };
            while (try lit.next()) |e| {
                if (e.data.len < 8) return error.BadLength;
                if (t.len >= t.items.len) continue;
                var w: EmatchWire = .{
                    .kind = std.mem.readInt(u16, e.data[2..4], native_endian),
                    .flags = std.mem.readInt(u16, e.data[4..6], native_endian),
                };
                const body = e.data[8..];
                const n = @min(body.len, em_data_decoded);
                @memcpy(w.data[0..n], body[0..n]);
                w.data_len = @intCast(n);
                w.full_len = @intCast(body.len);
                t.items[t.len] = w;
                t.len += 1;
            }
        },
        else => {},
    };
    return t;
}

// ── fw ──────────────────────────────────────────────────────────────────────

/// `TCA_FW_*`.
pub const TCA_FW = struct {
    pub const UNSPEC: u16 = 0;
    pub const CLASSID: u16 = 1;
    pub const POLICE: u16 = 2;
    pub const INDEV: u16 = 3;
    pub const ACT: u16 = 4;
    pub const MASK: u16 = 5;
};

/// The firewall-mark classifier (`tc filter add … handle 5 fw classid 1:10`).
/// The mark it matches is the filter's **handle** (`FilterTarget.handle`),
/// not an attribute.
pub const Fw = struct {
    classid: ?Handle = null,
    /// `handle MARK/MASK` — the mask half, sent as `TCA_FW_MASK`.
    mask: ?u32 = null,
    indev: ?[]const u8 = null,
    actions: []const ActionSpec = &.{},
};

pub const FwWire = struct {
    classid: ?Handle = null,
    mask: ?u32 = null,
    indev_buf: [qdisc.kind_max]u8 = @splat(0),
    indev_len: u8 = 0,

    pub fn indev(w: *const FwWire) []const u8 {
        return w.indev_buf[0..w.indev_len];
    }
};

fn appendFwOptions(f: Fw, gpa: std.mem.Allocator, list: *std.ArrayList(u8), ps: Psched) EncodeError!void {
    if (f.mask) |m| try codec.appendAttrU32(gpa, list, TCA_FW.MASK, m);
    if (f.classid) |c| try codec.appendAttrU32(gpa, list, TCA_FW.CLASSID, c.raw);
    if (f.indev) |name| {
        codec.appendAttrString(gpa, list, TCA_FW.INDEV, name) catch |err| switch (err) {
            error.AttrTooLong => return error.OptionsTooLong,
            error.OutOfMemory => return error.OutOfMemory,
        };
    }
    try action.appendActionList(gpa, list, TCA_FW.ACT, f.actions, ps);
}

pub fn parseFwOptions(data: []const u8) codec.Error!FwWire {
    var w: FwWire = .{};
    var it: codec.AttrIterator = .{ .buf = data };
    while (try it.next()) |a| switch (a.type) {
        TCA_FW.CLASSID => if (a.data.len == 4) {
            w.classid = Handle.fromRaw(std.mem.readInt(u32, a.data[0..4], native_endian));
        },
        TCA_FW.MASK => w.mask = readScalar(u32, a.data, native_endian),
        TCA_FW.INDEV => {
            const name = a.asString();
            const n = @min(name.len, w.indev_buf.len);
            @memcpy(w.indev_buf[0..n], name[0..n]);
            w.indev_len = @intCast(n);
        },
        else => {},
    };
    return w;
}

// ── route ───────────────────────────────────────────────────────────────────

/// `TCA_ROUTE4_*`.
pub const TCA_ROUTE4 = struct {
    pub const UNSPEC: u16 = 0;
    pub const CLASSID: u16 = 1;
    pub const TO: u16 = 2;
    pub const FROM: u16 = 3;
    pub const IIF: u16 = 4;
    pub const POLICE: u16 = 5;
    pub const ACT: u16 = 6;
};

/// The filter handle a route filter needs (`FilterTarget.handle`): `to` in
/// the low half (0x8000 when absent), and in the high half `0x8000 | iif`
/// for `fromif`, else `from` (0xffff when both are absent).
pub fn route4Handle(to: ?u8, from: ?u8, iif: ?u16) Handle {
    const lo: u32 = if (to) |t| t else 0x8000;
    const hi: u32 = if (iif) |i| 0x8000 | @as(u32, i) else if (from) |f| f else 0xffff;
    return Handle.fromRaw((hi << 16) | lo);
}

/// The routing-realm classifier (`tc filter add … route from 1 to 2 classid
/// 1:10`). The realms are also encoded in the filter's handle; see
/// `route4Handle`.
pub const Route4 = struct {
    to: ?u32 = null,
    from: ?u32 = null,
    /// `fromif DEV` as an interface index (`TCA_ROUTE4_IIF`).
    iif: ?u32 = null,
    classid: ?Handle = null,
    actions: []const ActionSpec = &.{},
};

pub const Route4Wire = struct {
    classid: ?Handle = null,
    to: ?u32 = null,
    from: ?u32 = null,
    iif: ?u32 = null,
};

fn appendRoute4Options(r: Route4, gpa: std.mem.Allocator, list: *std.ArrayList(u8), ps: Psched) EncodeError!void {
    if (r.iif) |v| try codec.appendAttrU32(gpa, list, TCA_ROUTE4.IIF, v);
    if (r.from) |v| try codec.appendAttrU32(gpa, list, TCA_ROUTE4.FROM, v);
    if (r.to) |v| try codec.appendAttrU32(gpa, list, TCA_ROUTE4.TO, v);
    if (r.classid) |c| try codec.appendAttrU32(gpa, list, TCA_ROUTE4.CLASSID, c.raw);
    try action.appendActionList(gpa, list, TCA_ROUTE4.ACT, r.actions, ps);
}

pub fn parseRoute4Options(data: []const u8) codec.Error!Route4Wire {
    var w: Route4Wire = .{};
    var it: codec.AttrIterator = .{ .buf = data };
    while (try it.next()) |a| switch (a.type) {
        TCA_ROUTE4.CLASSID => if (a.data.len == 4) {
            w.classid = Handle.fromRaw(std.mem.readInt(u32, a.data[0..4], native_endian));
        },
        TCA_ROUTE4.TO => w.to = readScalar(u32, a.data, native_endian),
        TCA_ROUTE4.FROM => w.from = readScalar(u32, a.data, native_endian),
        TCA_ROUTE4.IIF => w.iif = readScalar(u32, a.data, native_endian),
        else => {},
    };
    return w;
}

// ── basic ───────────────────────────────────────────────────────────────────

/// `TCA_BASIC_*`.
pub const TCA_BASIC = struct {
    pub const UNSPEC: u16 = 0;
    pub const CLASSID: u16 = 1;
    pub const EMATCHES: u16 = 2;
    pub const ACT: u16 = 3;
    pub const POLICE: u16 = 4;
};

/// The ematch classifier (`tc filter add … basic match 'cmp(…)' classid
/// 1:10`): a tree of extended matches, flat here (joined by `EM_FLAG.REL_*`).
pub const Basic = struct {
    ematches: []const Ematch = &.{},
    classid: ?Handle = null,
    actions: []const ActionSpec = &.{},
};

pub const BasicWire = struct {
    classid: ?Handle = null,
    ematches: EmatchTreeWire = .{},
};

fn appendBasicOptions(b: Basic, gpa: std.mem.Allocator, list: *std.ArrayList(u8), ps: Psched) EncodeError!void {
    try appendEmatchTree(gpa, list, TCA_BASIC.EMATCHES, b.ematches);
    try action.appendActionList(gpa, list, TCA_BASIC.ACT, b.actions, ps);
    if (b.classid) |c| try codec.appendAttrU32(gpa, list, TCA_BASIC.CLASSID, c.raw);
}

pub fn parseBasicOptions(data: []const u8) codec.Error!BasicWire {
    var w: BasicWire = .{};
    var it: codec.AttrIterator = .{ .buf = data };
    while (try it.next()) |a| switch (a.type) {
        TCA_BASIC.CLASSID => if (a.data.len == 4) {
            w.classid = Handle.fromRaw(std.mem.readInt(u32, a.data[0..4], native_endian));
        },
        TCA_BASIC.EMATCHES => w.ematches = try parseEmatchTree(a.data),
        else => {},
    };
    return w;
}

// ── cgroup ──────────────────────────────────────────────────────────────────

/// `TCA_CGROUP_*`.
pub const TCA_CGROUP = struct {
    pub const UNSPEC: u16 = 0;
    pub const ACT: u16 = 1;
    pub const POLICE: u16 = 2;
    pub const EMATCHES: u16 = 3;
};

/// The cgroup classifier (`tc filter add … cgroup [match …]`): matches the
/// packet's net_cls cgroup, with optional extended matches and actions.
pub const Cgroup = struct {
    ematches: []const Ematch = &.{},
    actions: []const ActionSpec = &.{},
};

pub const CgroupWire = struct {
    ematches: EmatchTreeWire = .{},
};

fn appendCgroupOptions(c: Cgroup, gpa: std.mem.Allocator, list: *std.ArrayList(u8), ps: Psched) EncodeError!void {
    try appendEmatchTree(gpa, list, TCA_CGROUP.EMATCHES, c.ematches);
    try action.appendActionList(gpa, list, TCA_CGROUP.ACT, c.actions, ps);
}

pub fn parseCgroupOptions(data: []const u8) codec.Error!CgroupWire {
    var w: CgroupWire = .{};
    var it: codec.AttrIterator = .{ .buf = data };
    while (try it.next()) |a| switch (a.type) {
        TCA_CGROUP.EMATCHES => w.ematches = try parseEmatchTree(a.data),
        else => {},
    };
    return w;
}

// ── the filter spec ─────────────────────────────────────────────────────────

pub const EncodeError = std.mem.Allocator.Error || action.EncodeError || error{
    /// More `U32Key`s than `sel.nkeys` (a u8) can carry.
    TooManyKeys,
    /// A flower port match without a `ip_proto` that has ports.
    PortWithoutProto,
    /// A pre-encoded `raw` payload longer than one netlink attribute.
    OptionsTooLong,
    /// A `Bpf` with neither instructions nor an fd, with both, or with more than
    /// `bpf_max_insns` instructions.
    BadBpfProgram,
};

/// What to attach as a **filter** (`RTM_NEWTFILTER`).
pub const FilterSpec = union(enum) {
    u32: U32,
    flower: Flower,
    matchall: Matchall,
    bpf: Bpf,
    fw: Fw,
    route: Route4,
    basic: Basic,
    cgroup: Cgroup,
    raw: qdisc.Raw,

    pub fn kind(self: FilterSpec) []const u8 {
        return switch (self) {
            .u32 => "u32",
            .flower => "flower",
            .matchall => "matchall",
            .bpf => "bpf",
            .fw => "fw",
            .route => "route",
            .basic => "basic",
            .cgroup => "cgroup",
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
            .matchall => |m| try appendMatchallOptions(m, gpa, list, ps),
            .bpf => |b| try appendBpfOptions(b, gpa, list, ps),
            .fw => |x| try appendFwOptions(x, gpa, list, ps),
            .route => |x| try appendRoute4Options(x, gpa, list, ps),
            .basic => |x| try appendBasicOptions(x, gpa, list, ps),
            .cgroup => |x| try appendCgroupOptions(x, gpa, list, ps),
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
    /// Decoded matchall options, when `kind() == "matchall"`.
    matchall: ?MatchallWire = null,
    /// Decoded bpf options, when `kind() == "bpf"`.
    bpf: ?BpfWire = null,
    /// Decoded `fw`, `route`, `basic` and `cgroup` options.
    fw: ?FwWire = null,
    route: ?Route4Wire = null,
    basic: ?BasicWire = null,
    cgroup: ?CgroupWire = null,
    /// The decoded action list, capped at `action.max_actions_decoded`
    /// entries (`act_list.total` reports the true count). Reach it through
    /// `actions()`.
    act_list: ActionList = .{},
    /// `TCA_CHAIN` — the chain the filter (or the chain template) lives in;
    /// null on chain 0, where the kernel sends none.
    chain: ?u32 = null,

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
        if (f.matchall) |m| return m.classid;
        if (f.bpf) |b| return b.classid;
        if (f.fw) |x| return x.classid;
        if (f.route) |x| return x.classid;
        if (f.basic) |x| return x.classid;
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
        TCA.CHAIN => f.chain = readScalar(u32, a.data, native_endian),
        else => {},
    };
    if (options_data) |opt| {
        const k = f.kind();
        if (std.mem.eql(u8, k, "u32")) {
            f.u32_sel = try parseU32Options(opt);
        } else if (std.mem.eql(u8, k, "flower")) {
            f.flower = try parseFlowerOptions(opt);
        } else if (std.mem.eql(u8, k, "matchall")) {
            f.matchall = try parseMatchallOptions(opt);
        } else if (std.mem.eql(u8, k, "bpf")) {
            f.bpf = try parseBpfOptions(opt);
        } else if (std.mem.eql(u8, k, "fw")) {
            f.fw = try parseFwOptions(opt);
        } else if (std.mem.eql(u8, k, "route")) {
            f.route = try parseRoute4Options(opt);
        } else if (std.mem.eql(u8, k, "basic")) {
            f.basic = try parseBasicOptions(opt);
        } else if (std.mem.eql(u8, k, "cgroup")) {
            f.cgroup = try parseCgroupOptions(opt);
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
    if (std.mem.eql(u8, kind, "matchall")) return TCA_MATCHALL.ACT;
    if (std.mem.eql(u8, kind, "bpf")) return TCA_BPF.ACT;
    if (std.mem.eql(u8, kind, "fw")) return TCA_FW.ACT;
    if (std.mem.eql(u8, kind, "route")) return TCA_ROUTE4.ACT;
    if (std.mem.eql(u8, kind, "basic")) return TCA_BASIC.ACT;
    if (std.mem.eql(u8, kind, "cgroup")) return TCA_CGROUP.ACT;
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

test "parseU32Options: a selector with more keys than U32Wire holds fills it and stops" {
    // Audit A1 tc F13: removing the `keys_len < keys.len` bound left the
    // suite green, while a selector with more than 8 keys then writes past
    // `keys` (a panic in safe modes, silent corruption in ReleaseFast).
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    var keys: [40]U32Key = undefined;
    for (&keys, 0..) |*k, i| k.* = U32Key.ipv4Dst(.{ 10, 0, 0, @intCast(i) }, 32);
    try appendU32Options(.{ .keys = &keys }, gpa, &list, test_ps);
    const uw = try parseU32Options(list.items);
    try testing.expectEqual(@as(u8, 40), uw.nkeys);
    try testing.expectEqual(@as(u8, uw.keys.len), uw.keys_len);
    try testing.expectEqual(@as(u8, 7), uw.keys[7].val[3]);
}

test "prefixMask6 builds IPv6 masks bit-exactly" {
    try testing.expectEqualSlices(u8, &(@as([4]u8, @splat(0xff)) ++ @as([12]u8, @splat(0))), &prefixMask6(32));
    try testing.expectEqualSlices(u8, &(@as([16]u8, @splat(0xff))), &prefixMask6(128));
    try testing.expectEqualSlices(u8, &(@as([16]u8, @splat(0))), &prefixMask6(0));
    try testing.expectEqualSlices(u8, &([_]u8{ 0xff, 0xe0 } ++ @as([14]u8, @splat(0))), &prefixMask6(11));
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
    const v6: [16]u8 = .{ 0x20, 0x01, 0x0d, 0xb8 } ++ @as([12]u8, @splat(0));
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
    // F5 in the A1 audit: pin the shipped limit literally before deriving
    // `many`'s length from the same symbol (see the equivalent action.zig
    // pins for `max_actions`/`max_cookie_len`/`max_actions_decoded`).
    try testing.expectEqual(@as(usize, 255), u32_max_keys);

    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    const many = try gpa.alloc(U32Key, u32_max_keys + 1);
    defer gpa.free(many);
    @memset(many, U32Key.word(0, 0, 0));
    try testing.expectError(error.TooManyKeys, appendU32Options(.{ .keys = many }, gpa, &list, test_ps));
}

test "parseU32Options rejects a TCA_U32_SEL attribute shorter than tc_u32_sel_len (F3)" {
    // Wave-3 audit's F3 named this bound as untested fault-injection surface.
    // The fuzz-corpus fix already feeds `parseU32Options` a
    // shorter-than-16-byte SEL (`u32_short` in the corpus below), which
    // proves the parser doesn't CRASH on it — but a too-short SEL here reads
    // `a.data[0]`/`a.data[2]` inside bounds and just silently produces a
    // wrong `flags`/`nkeys`, so crash-only fuzzing cannot see whether the
    // guard actually rejects it. Pinned directly instead.
    const gpa = testing.allocator;

    var short_list: std.ArrayList(u8) = .empty;
    defer short_list.deinit(gpa);
    try codec.appendAttr(gpa, &short_list, TCA_U32.SEL, &(@as([tc_u32_sel_len - 1]u8, @splat(0))));
    try testing.expectError(error.BadLength, parseU32Options(short_list.items));

    // Positive control: exactly tc_u32_sel_len bytes must still parse.
    var ok_list: std.ArrayList(u8) = .empty;
    defer ok_list.deinit(gpa);
    try codec.appendAttr(gpa, &ok_list, TCA_U32.SEL, &(@as([tc_u32_sel_len]u8, @splat(0))));
    _ = try parseU32Options(ok_list.items);
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
        try codec.appendAttr(gpa, &u32_short, TCA_U32.CLASSID, &@as([2]u8, @splat(0)));
        try codec.appendAttr(gpa, &u32_short, TCA_U32.SEL, &@as([8]u8, @splat(0)));
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
        try codec.appendAttr(gpa, &flower_short, TCA_FLOWER.KEY_ETH_TYPE, &@as([1]u8, @splat(0)));
        try codec.appendAttr(gpa, &flower_short, TCA_FLOWER.KEY_IP_PROTO, &.{});
        try codec.appendAttr(gpa, &flower_short, TCA_FLOWER.KEY_IPV4_SRC, &@as([2]u8, @splat(0)));
        try codec.appendAttr(gpa, &flower_short, TCA_FLOWER.KEY_IPV6_SRC, &@as([8]u8, @splat(0)));
        try codec.appendAttr(gpa, &flower_short, TCA_FLOWER.KEY_TCP_SRC, &@as([1]u8, @splat(0)));
        try codec.appendAttr(gpa, &flower_short, TCA_FLOWER.FLAGS, &@as([2]u8, @splat(0)));
        try codec.appendAttr(gpa, &flower_short, TCA_FLOWER.CLASSID, &@as([3]u8, @splat(0)));
        self.push(flower_short.items, 0x0800_0001);

        // ── the refusals ───────────────────────────────────────────────────
        // A payload one octet short of `struct tcmsg`.
        self.push(&(@as([qdisc.tcmsg_len - 1]u8, @splat(0))), 0);
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

const fz = @import("fuzz_test.zig");
const FilterMark = fz.Marker(enum { u32, flower, filter, refused });

test "fuzz: filter parsers never crash on arbitrary payloads" {
    var corpus: FilterCorpus = .{};
    try testing.fuzz({}, fuzzParseFilterSmith, .{ .corpus = try corpus.build() });
}

test "fuzz driver: TC_FUZZ (filter)" {
    try fz.fuzz_driver.run(fuzzParseFilter, .{ .prefix = "TC_FUZZ", .name = "tc-filter" });
}

test "fuzz harness: filter, 500 seeds, reaches every outcome" {
    try FilterMark.reach(fuzzParseFilter, "tc-filter", 500);
}

fn fuzzParseFilterSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzParseFilter(std.testing.Smith, smith, testing.allocator);
}

fn fuzzParseFilter(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var corpus: FilterCorpus = .{};
    const entries = corpus.build() catch return;
    // 1024, not 256: a u32 selector carrying the kernel's maximum key count is
    // 16 + 128*16 octets, and a seed longer than the buffer is not a big seed
    // — `Smith.slice` reads it back as the EMPTY one.
    var raw: [1024]u8 = undefined;
    // ⚠ One `src.slice` call, never `src.bytes` followed by a ranged
    // length. `bytes` takes `@min(raw.len, in.len)` octets and the ranged draw
    // then finds fewer than the eight it needs and returns the range MINIMUM,
    // so `len` was 0 for every seed and all three parsers were handed an EMPTY
    // slice with the filter sitting unread in `raw`.
    //
    // ⛔ Measured over the corpus above: **0 of 12 seeds non-empty,
    // 0 u32 keys decoded, 0 flower fields decoded and 0 kinds read before;
    // 12 of 12 non-empty, 3 keys, 18 flower fields and 3 kinds after.**
    // `parseU32Options` and `parseFlowerOptions` both SUCCEED on the empty
    // slice — an empty options body is a legal classifier reply — so an
    // acceptance count called this harness healthy while it walked nothing.
    const len: usize = fz.drawInput(S, src, &raw, entries);
    const buf = raw[0..len];
    if (parseU32Options(buf)) |w| {
        if (w.keys_len != 0) FilterMark.mark(.u32);
    } else |_| FilterMark.mark(.refused);
    if (parseFlowerOptions(buf)) |w| {
        if (qdisc.optionalsSet(w) != 0) FilterMark.mark(.flower);
    } else |_| {}
    if (parseFilter(buf)) |f| {
        std.mem.doNotOptimizeAway(f.kind().len);
        if (f.kind().len != 0) FilterMark.mark(.filter);
    } else |_| {}
    // ⚠ `value(u64)` truncated, not `value(u32)`: a `u32` draw reads eight
    // input octets as a little-endian u64 and only survives if the whole word
    // fits in 32 bits, so it was 0 for every seed. The word travels in the
    // seed's tail now.
    _ = parseInfo(@truncate(src.value(u64)));
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
