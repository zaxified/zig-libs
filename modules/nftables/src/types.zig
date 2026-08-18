// SPDX-License-Identifier: MIT

//! Shared nftables vocabulary — the enums both backends speak.
//!
//! The JSON builder (`root.zig`) serializes these with `@tagName`/`jsonStringify`
//! into the documented `nft -j` schema; the native nfnetlink backend
//! (`wire.zig`/`expr.zig`) maps the same values onto the kernel's numeric ABI
//! via the `nf*()` helpers below. Keeping one vocabulary is what makes the two
//! paths comparable — see `SPEC.md` "JSON ↔ native consistency".
//!
//! Every numeric mapping is a kernel UAPI constant
//! (`linux/netfilter.h`, `linux/netfilter/nf_tables.h`) except the set
//! *datatype ids* (`SetDataType.id`), which are a userspace convention the
//! kernel does not interpret; those were read off byte-exact `nft` captures —
//! see `goldens.zig`.

const std = @import("std");

pub const JsonError = error{WriteFailed};

// ── kernel UAPI: protocol families and hooks ────────────────────────────────

/// `NFPROTO_*` (linux/netfilter.h) — the value of `nfgenmsg.nfgen_family`.
pub const NFPROTO = struct {
    pub const UNSPEC: u8 = 0;
    pub const INET: u8 = 1;
    pub const IPV4: u8 = 2;
    pub const ARP: u8 = 3;
    pub const NETDEV: u8 = 5;
    pub const BRIDGE: u8 = 7;
    pub const IPV6: u8 = 10;
};

/// `NF_INET_*` hook numbers (linux/netfilter.h).
pub const NF_INET = struct {
    pub const PRE_ROUTING: u32 = 0;
    pub const LOCAL_IN: u32 = 1;
    pub const FORWARD: u32 = 2;
    pub const LOCAL_OUT: u32 = 3;
    pub const POST_ROUTING: u32 = 4;
};

/// `NF_NETDEV_*` hook numbers (linux/netfilter.h).
pub const NF_NETDEV = struct {
    pub const INGRESS: u32 = 0;
    pub const EGRESS: u32 = 1;
};

/// `NF_ARP_*` hook numbers (linux/netfilter_arp.h).
pub const NF_ARP = struct {
    pub const IN: u32 = 0;
    pub const OUT: u32 = 1;
    pub const FORWARD: u32 = 2;
};

/// Base verdicts (`NF_DROP`/`NF_ACCEPT`, linux/netfilter.h) as they appear in
/// `NFTA_VERDICT_CODE` / `NFTA_CHAIN_POLICY`.
pub const NF = struct {
    pub const DROP: i32 = 0;
    pub const ACCEPT: i32 = 1;
    pub const STOLEN: i32 = 2;
    pub const QUEUE: i32 = 3;
    pub const REPEAT: i32 = 4;
};

/// `enum nft_verdicts` — the nftables-only verdict codes, all negative.
pub const NFT = struct {
    pub const CONTINUE: i32 = -1;
    pub const BREAK: i32 = -2;
    pub const JUMP: i32 = -3;
    pub const GOTO: i32 = -4;
    pub const RETURN: i32 = -5;
};

/// A hook/family combination the kernel has no hook number for.
pub const HookError = error{UnsupportedHook};

// ── vocabulary enums ────────────────────────────────────────────────────────
// For every enum below whose tag names equal the JSON schema tokens verbatim,
// the default std.json enum serialization (`@tagName`) is exactly right; the
// few whose tokens are not Zig identifiers ("==", "fully-random", "tcp reset")
// carry a custom `jsonStringify`.

/// Address family of a table.
pub const Family = enum {
    ip,
    ip6,
    inet,
    arp,
    bridge,
    netdev,

    /// `nfgen_family` for the native backend.
    pub fn nfproto(self: Family) u8 {
        return switch (self) {
            .ip => NFPROTO.IPV4,
            .ip6 => NFPROTO.IPV6,
            .inet => NFPROTO.INET,
            .arp => NFPROTO.ARP,
            .bridge => NFPROTO.BRIDGE,
            .netdev => NFPROTO.NETDEV,
        };
    }

    /// Reverse of `.nfproto()` — recovers the typed family from a decoded
    /// `nfgen_family` byte, e.g. `TableInfo.family`/`ChainInfo.family`/
    /// `RuleInfo.family`/`SetInfo.family` after an **unspec** dump
    /// (`Socket.listTables(null)` and friends) has swept every family in one
    /// round trip. Returns null for `NFPROTO.UNSPEC` (0) and any byte this
    /// module does not model — a dump *request* may legitimately name
    /// `unspec` to ask for everything, but every *object* the kernel hands
    /// back names one concrete family, never 0, so this mapping is total
    /// over what a real dump reply can contain. `@tagName(family.fromNfproto(b).?)`
    /// is exactly the JSON schema token (`"ip"`/`"inet"`/…) for that family —
    /// there is no separate "family name" string table to keep in sync.
    pub fn fromNfproto(byte: u8) ?Family {
        return switch (byte) {
            NFPROTO.IPV4 => .ip,
            NFPROTO.IPV6 => .ip6,
            NFPROTO.INET => .inet,
            NFPROTO.ARP => .arp,
            NFPROTO.BRIDGE => .bridge,
            NFPROTO.NETDEV => .netdev,
            else => null,
        };
    }
};

/// Base chain type.
pub const ChainType = enum {
    filter,
    nat,
    route,

    /// The `NFTA_CHAIN_TYPE` string the kernel matches on.
    pub fn wireName(self: ChainType) []const u8 {
        return @tagName(self);
    }
};

/// Base chain hook point.
pub const Hook = enum {
    prerouting,
    input,
    forward,
    output,
    postrouting,
    ingress,
    egress,

    /// `NFTA_HOOK_HOOKNUM` for this hook in `family`. The numbering is
    /// per-family: netdev has its own two hooks, arp has three, and the
    /// inet/ip/ip6/bridge families share `NF_INET_*`.
    pub fn num(self: Hook, family: Family) HookError!u32 {
        return switch (family) {
            .netdev => switch (self) {
                .ingress => NF_NETDEV.INGRESS,
                .egress => NF_NETDEV.EGRESS,
                else => error.UnsupportedHook,
            },
            .arp => switch (self) {
                .input => NF_ARP.IN,
                .output => NF_ARP.OUT,
                .forward => NF_ARP.FORWARD,
                else => error.UnsupportedHook,
            },
            .ip, .ip6, .inet, .bridge => switch (self) {
                .prerouting => NF_INET.PRE_ROUTING,
                .input => NF_INET.LOCAL_IN,
                .forward => NF_INET.FORWARD,
                .output => NF_INET.LOCAL_OUT,
                .postrouting => NF_INET.POST_ROUTING,
                // `ingress` exists in the inet/ip/ip6 families on modern
                // kernels too, but as NF_INET_INGRESS (=5); the bridge family
                // has no ingress hook at all. Deferred — see SPEC.md.
                .ingress, .egress => error.UnsupportedHook,
            },
        };
    }
};

/// Base chain default policy.
pub const Policy = enum {
    accept,
    drop,

    /// `NFTA_CHAIN_POLICY` value.
    pub fn verdict(self: Policy) i32 {
        return switch (self) {
            .accept => NF.ACCEPT,
            .drop => NF.DROP,
        };
    }

    /// Reverse of `.verdict()` — recovers the typed policy from a decoded
    /// `ChainInfo.policy` (`?i32`). A base chain's policy is only ever
    /// `NF_ACCEPT` or `NF_DROP` — the kernel does not accept any other verdict
    /// there — so this mapping is total for anything `ChainInfo.policy` can
    /// hold; null means the byte was neither, which cannot happen for a real
    /// base chain but is reported rather than assumed.
    pub fn fromVerdict(v: i32) ?Policy {
        return switch (v) {
            NF.ACCEPT => .accept,
            NF.DROP => .drop,
            else => null,
        };
    }
};

/// Comparison operator of a `match` statement. `in` performs a lookup
/// (bits-contained / set membership).
pub const Op = enum {
    eq,
    ne,
    lt,
    gt,
    le,
    ge,
    in,

    pub fn token(self: Op) []const u8 {
        return switch (self) {
            .eq => "==",
            .ne => "!=",
            .lt => "<",
            .gt => ">",
            .le => "<=",
            .ge => ">=",
            .in => "in",
        };
    }

    /// `enum nft_cmp_ops` value, or null for `in` — set membership is a
    /// `lookup` expression, not a `cmp`.
    pub fn cmpOp(self: Op) ?u32 {
        return switch (self) {
            .eq => 0, // NFT_CMP_EQ
            .ne => 1, // NFT_CMP_NEQ
            .lt => 2, // NFT_CMP_LT
            .le => 3, // NFT_CMP_LTE
            .gt => 4, // NFT_CMP_GT
            .ge => 5, // NFT_CMP_GTE
            .in => null,
        };
    }

    pub fn jsonStringify(self: Op, jw: anytype) JsonError!void {
        try jw.write(self.token());
    }
};

/// Packet metadata keys (`meta` expression). The numeric mapping is
/// `enum nft_meta_keys`.
pub const MetaKey = enum {
    length,
    protocol,
    priority,
    random,
    mark,
    iif,
    iifname,
    iiftype,
    oif,
    oifname,
    oiftype,
    skuid,
    skgid,
    nftrace,
    rtclassid,
    ibriport,
    obriport,
    ibridgename,
    obridgename,
    pkttype,
    cpu,
    iifgroup,
    oifgroup,
    cgroup,
    nfproto,
    l4proto,
    secpath,

    /// `NFTA_META_KEY` value (`enum nft_meta_keys`), or null for the two
    /// bridge-name keys whose kernel key this module could not ground in
    /// either the UAPI header or a capture (see SPEC.md "Deferred").
    pub fn key(self: MetaKey) ?u32 {
        return switch (self) {
            .length => 0, // NFT_META_LEN
            .protocol => 1,
            .priority => 2,
            .mark => 3,
            .iif => 4,
            .oif => 5,
            .iifname => 6,
            .oifname => 7,
            .iiftype => 8, // NFT_META_IFTYPE, aliased NFT_META_IIFTYPE
            .oiftype => 9,
            .skuid => 10,
            .skgid => 11,
            .nftrace => 12,
            .rtclassid => 13,
            .nfproto => 15, // 14 = NFT_META_SECMARK, no JSON token
            .l4proto => 16,
            .ibriport => 17, // NFT_META_BRI_IIFNAME
            .obriport => 18, // NFT_META_BRI_OIFNAME
            .pkttype => 19,
            .cpu => 20,
            .iifgroup => 21,
            .oifgroup => 22,
            .cgroup => 23,
            .random => 24, // NFT_META_PRANDOM
            .secpath => 25,
            .ibridgename, .obridgename => null,
        };
    }

    /// Width in bytes of the value this key loads into a register — needed to
    /// size the `cmp` data (and to reject a mismatched immediate).
    pub fn width(self: MetaKey) u32 {
        return switch (self) {
            .iifname, .oifname, .ibriport, .obriport, .ibridgename, .obridgename => 16, // IFNAMSIZ
            .nfproto, .l4proto, .pkttype, .nftrace, .secpath => 1,
            .protocol, .iiftype, .oiftype => 2,
            else => 4,
        };
    }
};

/// Named packet headers usable in a `payload` expression.
pub const PayloadProto = enum {
    ether,
    vlan,
    arp,
    ip,
    icmp,
    igmp,
    ip6,
    icmpv6,
    tcp,
    udp,
    udplite,
    sctp,
    dccp,
    ah,
    esp,
    comp,
    th,
};

/// Reference point of a raw `payload` expression (`enum nft_payload_bases`).
pub const PayloadBase = enum {
    ll,
    nh,
    th,

    pub fn base(self: PayloadBase) u32 {
        return switch (self) {
            .ll => 0, // NFT_PAYLOAD_LL_HEADER
            .nh => 1, // NFT_PAYLOAD_NETWORK_HEADER
            .th => 2, // NFT_PAYLOAD_TRANSPORT_HEADER
        };
    }
};

/// Conntrack direction for `ct` expressions (`NFTA_CT_DIRECTION`).
pub const CtDir = enum {
    original,
    reply,

    pub fn dir(self: CtDir) u8 {
        return switch (self) {
            .original => 0, // IP_CT_DIR_ORIGINAL
            .reply => 1,
        };
    }
};

/// NAT statement flags. The numeric values are `NF_NAT_RANGE_*`
/// (linux/netfilter/nf_nat.h).
pub const NatFlag = enum {
    random,
    fully_random,
    persistent,

    pub fn token(self: NatFlag) []const u8 {
        return switch (self) {
            .random => "random",
            .fully_random => "fully-random",
            .persistent => "persistent",
        };
    }

    /// `NF_NAT_RANGE_*` bit.
    pub fn bit(self: NatFlag) u32 {
        return switch (self) {
            .random => 1 << 2, // NF_NAT_RANGE_PROTO_RANDOM
            .persistent => 1 << 3, // NF_NAT_RANGE_PERSISTENT
            .fully_random => 1 << 4, // NF_NAT_RANGE_PROTO_RANDOM_FULLY
        };
    }

    pub fn jsonStringify(self: NatFlag, jw: anytype) JsonError!void {
        try jw.write(self.token());
    }
};

/// `NF_NAT_RANGE_PROTO_SPECIFIED` — set whenever a port register is present.
pub const NF_NAT_RANGE_PROTO_SPECIFIED: u32 = 1 << 1;
/// `NF_NAT_RANGE_MAP_IPS` — set whenever an address register is present.
pub const NF_NAT_RANGE_MAP_IPS: u32 = 1 << 0;

/// Reject statement variants.
pub const RejectType = enum {
    tcp_reset,
    icmpx,
    icmp,
    icmpv6,

    pub fn token(self: RejectType) []const u8 {
        return switch (self) {
            .tcp_reset => "tcp reset",
            .icmpx => "icmpx",
            .icmp => "icmp",
            .icmpv6 => "icmpv6",
        };
    }

    pub fn jsonStringify(self: RejectType, jw: anytype) JsonError!void {
        try jw.write(self.token());
    }
};

/// Log statement severity. The numeric values are the syslog levels the
/// kernel stores in `NFTA_LOG_LEVEL`.
pub const LogLevel = enum {
    emerg,
    alert,
    crit,
    err,
    warn,
    notice,
    info,
    debug,
    audit,

    pub fn level(self: LogLevel) u32 {
        return switch (self) {
            .emerg => 0,
            .alert => 1,
            .crit => 2,
            .err => 3,
            .warn => 4,
            .notice => 5,
            .info => 6,
            .debug => 7,
            .audit => 8, // NFT_LOGLEVEL_AUDIT
        };
    }
};

/// Denominator of a limit rate. The native `NFTA_LIMIT_UNIT` is the number of
/// seconds the rate is measured over.
pub const LimitPer = enum {
    second,
    minute,
    hour,
    day,
    week,

    pub fn seconds(self: LimitPer) u64 {
        return switch (self) {
            .second => 1,
            .minute => 60,
            .hour => 60 * 60,
            .day => 24 * 60 * 60,
            .week => 7 * 24 * 60 * 60,
        };
    }
};

/// Unit of a limit rate. `packets` selects `NFT_LIMIT_PKTS`; every byte unit
/// selects `NFT_LIMIT_PKT_BYTES` and scales the rate.
pub const LimitUnit = enum {
    packets,
    bytes,
    kbytes,
    mbytes,

    /// `enum nft_limit_type`.
    pub fn limitType(self: LimitUnit) u32 {
        return switch (self) {
            .packets => 0, // NFT_LIMIT_PKTS
            .bytes, .kbytes, .mbytes => 1, // NFT_LIMIT_PKT_BYTES
        };
    }

    /// Multiplier applied to the rate to reach bytes/second.
    pub fn scale(self: LimitUnit) u64 {
        return switch (self) {
            .packets, .bytes => 1,
            .kbytes => 1024,
            .mbytes => 1024 * 1024,
        };
    }
};

/// Named set flags (`enum nft_set_flags`).
pub const SetFlag = enum {
    constant,
    interval,
    timeout,

    pub fn bit(self: SetFlag) u32 {
        return switch (self) {
            .constant => 0x2, // NFT_SET_CONSTANT
            .interval => 0x4, // NFT_SET_INTERVAL
            .timeout => 0x10, // NFT_SET_TIMEOUT
        };
    }
};

/// Named set element datatype.
///
/// `id` is **not** a kernel constant: `NFTA_SET_KEY_TYPE` is opaque to the
/// kernel (only `NFTA_SET_KEY_LEN` matters for matching) and carries nft's own
/// userspace datatype number so that `nft list ruleset` can name the type
/// again. The values below were read off `nft add set … { type <t>; }`
/// captures — see `goldens.zig` "set datatype ids".
pub const SetDataType = enum {
    ipv4_addr,
    ipv6_addr,
    ether_addr,
    inet_proto,
    inet_service,
    mark,
    ifname,

    pub fn id(self: SetDataType) u32 {
        return switch (self) {
            .ipv4_addr => 7,
            .ipv6_addr => 8,
            .ether_addr => 9,
            .inet_proto => 12,
            .inet_service => 13,
            .mark => 19,
            .ifname => 41,
        };
    }

    /// `NFTA_SET_KEY_LEN` — the width of one element key in bytes.
    pub fn keyLen(self: SetDataType) u32 {
        return switch (self) {
            .ipv4_addr, .mark => 4,
            .ipv6_addr, .ifname => 16,
            .ether_addr => 6,
            .inet_proto => 1,
            .inet_service => 2,
        };
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "family to nfgen_family follows NFPROTO_*" {
    try testing.expectEqual(@as(u8, 2), Family.ip.nfproto());
    try testing.expectEqual(@as(u8, 10), Family.ip6.nfproto());
    try testing.expectEqual(@as(u8, 1), Family.inet.nfproto());
    try testing.expectEqual(@as(u8, 3), Family.arp.nfproto());
    try testing.expectEqual(@as(u8, 7), Family.bridge.nfproto());
    try testing.expectEqual(@as(u8, 5), Family.netdev.nfproto());
}

test "fromNfproto reverses nfproto for every Family member, and rejects unspec" {
    inline for ([_]Family{ .ip, .ip6, .inet, .arp, .bridge, .netdev }) |f| {
        try testing.expectEqual(f, Family.fromNfproto(f.nfproto()).?);
    }
    try testing.expectEqual(@as(?Family, null), Family.fromNfproto(NFPROTO.UNSPEC));
    try testing.expectEqual(@as(?Family, null), Family.fromNfproto(255));
}

test "fromVerdict reverses verdict for every Policy member, and rejects other verdicts" {
    try testing.expectEqual(Policy.accept, Policy.fromVerdict(Policy.accept.verdict()).?);
    try testing.expectEqual(Policy.drop, Policy.fromVerdict(Policy.drop.verdict()).?);
    // A verdict a base chain policy can never actually hold.
    try testing.expectEqual(@as(?Policy, null), Policy.fromVerdict(NFT.JUMP));
}

test "hook numbering is per-family" {
    try testing.expectEqual(@as(u32, 1), try Hook.input.num(.inet));
    try testing.expectEqual(@as(u32, 4), try Hook.postrouting.num(.ip));
    try testing.expectEqual(@as(u32, 0), try Hook.ingress.num(.netdev));
    try testing.expectEqual(@as(u32, 1), try Hook.egress.num(.netdev));
    // arp reuses input/output/forward with its own numbering.
    try testing.expectEqual(@as(u32, 0), try Hook.input.num(.arp));
    try testing.expectEqual(@as(u32, 1), try Hook.output.num(.arp));
    // …and rejects the hooks it does not have.
    try testing.expectError(error.UnsupportedHook, Hook.prerouting.num(.arp));
    try testing.expectError(error.UnsupportedHook, Hook.input.num(.netdev));
    try testing.expectError(error.UnsupportedHook, Hook.ingress.num(.bridge));
}

test "policy, cmp op and limit unit mappings" {
    try testing.expectEqual(@as(i32, 0), Policy.drop.verdict());
    try testing.expectEqual(@as(i32, 1), Policy.accept.verdict());
    try testing.expectEqual(@as(?u32, 0), Op.eq.cmpOp());
    try testing.expectEqual(@as(?u32, 1), Op.ne.cmpOp());
    try testing.expectEqual(@as(?u32, 3), Op.le.cmpOp());
    try testing.expectEqual(@as(?u32, null), Op.in.cmpOp());
    try testing.expectEqual(@as(u64, 60), LimitPer.minute.seconds());
    try testing.expectEqual(@as(u32, 1), LimitUnit.kbytes.limitType());
    try testing.expectEqual(@as(u64, 1024), LimitUnit.kbytes.scale());
}

test "meta key numbering matches the captured nft traffic" {
    // The two keys the goldens pin: `meta l4proto` = 16, `meta nfproto` = 15.
    try testing.expectEqual(@as(?u32, 16), MetaKey.l4proto.key());
    try testing.expectEqual(@as(?u32, 15), MetaKey.nfproto.key());
    try testing.expectEqual(@as(?u32, 6), MetaKey.iifname.key());
    try testing.expectEqual(@as(?u32, 7), MetaKey.oifname.key());
    try testing.expectEqual(@as(?u32, null), MetaKey.ibridgename.key());
    try testing.expectEqual(@as(u32, 16), MetaKey.iifname.width());
    try testing.expectEqual(@as(u32, 1), MetaKey.l4proto.width());
    try testing.expectEqual(@as(u32, 4), MetaKey.mark.width());
}

test "set datatype ids and key widths" {
    try testing.expectEqual(@as(u32, 7), SetDataType.ipv4_addr.id());
    try testing.expectEqual(@as(u32, 4), SetDataType.ipv4_addr.keyLen());
    try testing.expectEqual(@as(u32, 13), SetDataType.inet_service.id());
    try testing.expectEqual(@as(u32, 2), SetDataType.inet_service.keyLen());
    try testing.expectEqual(@as(u32, 41), SetDataType.ifname.id());
    try testing.expectEqual(@as(u32, 16), SetDataType.ifname.keyLen());
}
