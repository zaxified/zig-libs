// SPDX-License-Identifier: MIT

//! nftables **rule expressions** — the ordered list of `NFTA_RULE_EXPRESSIONS`
//! entries that makes a rule do something, and the register discipline that
//! makes it match.
//!
//! ## The wire shape
//!
//! A rule's `NFTA_RULE_EXPRESSIONS` is a nest of `NFTA_LIST_ELEM` entries, each
//! of which is itself a nest of exactly two attributes:
//!
//! ```text
//! NFTA_LIST_ELEM
//!   NFTA_EXPR_NAME  "payload" | "cmp" | "meta" | "immediate" | …   (string)
//!   NFTA_EXPR_DATA  { expression-specific attributes }             (nest)
//! ```
//!
//! ## The register model — the part that silently mis-matches
//!
//! nftables evaluates a rule as a little machine over a register file. *Load*
//! expressions (`payload`, `meta`, `ct`) write into a **destination register**
//! (`dreg`); *consumer* expressions (`cmp`, `lookup`, `bitwise`, `nat`) read a
//! **source register** (`sreg`). A rule whose `cmp` reads a register nothing
//! wrote is accepted by the kernel and then never matches — nothing tells you.
//!
//! The kernel exposes two overlapping views of the same file
//! (`enum nft_registers`): the four legacy 16-byte registers
//! `NFT_REG_1`…`NFT_REG_4` (values 1–4) and the sixteen 4-byte registers
//! `NFT_REG32_00`…`NFT_REG32_15` (values 8–23), where `NFT_REG_1` aliases
//! `NFT_REG32_00`…`_03`. `NFT_REG_VERDICT` (0) is not a data register at all —
//! it is where an `immediate` puts a verdict.
//!
//! **The model this module uses** (identical to what a stock `nft` binary puts
//! on the wire — see `goldens.zig`):
//!
//! 1. Only the 16-byte registers `NFT_REG_1`…`NFT_REG_4` are allocated. A
//!    4-byte value in a 16-byte register is fine; the kernel compares
//!    `NFTA_CMP_DATA`'s length, not the register width.
//! 2. A *match sequence* is `load → [bitwise] → cmp|lookup`. The value is dead
//!    the moment the comparison consumes it, so the allocator is **reset to
//!    `NFT_REG_1` at the start of every match sequence**. Two independent
//!    matches in one rule therefore both use `NFT_REG_1`, exactly like `nft`.
//! 3. The only place where two values are live at once is a NAT statement
//!    (address in one register, port in the next), so `nat()` allocates
//!    sequentially without an intervening reset.
//! 4. `Program.push` (the escape hatch for hand-built expressions) does **not**
//!    touch the allocator: a caller assembling raw expressions owns the whole
//!    register model for that rule.
//!
//! `Program.regs.reset()` is public so a caller mixing raw `push` with the
//! high-level helpers can re-establish the invariant.
//!
//! Provenance: clean-room from the kernel UAPI header
//! `linux/netfilter/nf_tables.h` (constants and layouts = the kernel's OS ABI)
//! plus the byte-exact `nft` captures in `goldens.zig`. No nftables or
//! libnftnl source was consulted. See `/NOTICE`.

const std = @import("std");
const builtin = @import("builtin");
const nl = @import("nl.zig");
// Test-only (`build.zig`'s `test_deps`, never `deps`): the fuzz corpus seed
// helpers, in the format `std.testing.Smith` actually reads.
const testkit = @import("testkit");
const types = @import("types.zig");

const Family = types.Family;
const MetaKey = types.MetaKey;
const PayloadBase = types.PayloadBase;
const CtDir = types.CtDir;
const Op = types.Op;
const LogLevel = types.LogLevel;
const LimitPer = types.LimitPer;
const LimitUnit = types.LimitUnit;

// ── kernel UAPI: expression attribute numbers ───────────────────────────────

/// `enum nft_expr_attributes`.
pub const NFTA_EXPR = struct {
    pub const NAME: u16 = 1;
    pub const DATA: u16 = 2;
};

/// `enum nft_list_attributes`.
pub const NFTA_LIST_ELEM: u16 = 1;

/// `enum nft_data_attributes`.
pub const NFTA_DATA = struct {
    pub const VALUE: u16 = 1;
    pub const VERDICT: u16 = 2;
};

/// `enum nft_verdict_attributes`.
pub const NFTA_VERDICT = struct {
    pub const CODE: u16 = 1;
    pub const CHAIN: u16 = 2;
    pub const CHAIN_ID: u16 = 3;
};

/// `enum nft_payload_attributes`.
pub const NFTA_PAYLOAD = struct {
    pub const DREG: u16 = 1;
    pub const BASE: u16 = 2;
    pub const OFFSET: u16 = 3;
    pub const LEN: u16 = 4;
    pub const SREG: u16 = 5;
    pub const CSUM_TYPE: u16 = 6;
    pub const CSUM_OFFSET: u16 = 7;
    pub const CSUM_FLAGS: u16 = 8;
};

/// `enum nft_cmp_attributes`.
pub const NFTA_CMP = struct {
    pub const SREG: u16 = 1;
    pub const OP: u16 = 2;
    pub const DATA: u16 = 3;
};

/// `enum nft_meta_attributes`.
pub const NFTA_META = struct {
    pub const DREG: u16 = 1;
    pub const KEY: u16 = 2;
    pub const SREG: u16 = 3;
};

/// `enum nft_ct_attributes`.
pub const NFTA_CT = struct {
    pub const DREG: u16 = 1;
    pub const KEY: u16 = 2;
    pub const DIRECTION: u16 = 3;
    pub const SREG: u16 = 4;
};

/// `enum nft_bitwise_attributes`.
pub const NFTA_BITWISE = struct {
    pub const SREG: u16 = 1;
    pub const DREG: u16 = 2;
    pub const LEN: u16 = 3;
    pub const MASK: u16 = 4;
    pub const XOR: u16 = 5;
    pub const OP: u16 = 6;
    pub const DATA: u16 = 7;
};

/// `enum nft_lookup_attributes`.
pub const NFTA_LOOKUP = struct {
    pub const SET: u16 = 1;
    pub const SREG: u16 = 2;
    pub const DREG: u16 = 3;
    pub const SET_ID: u16 = 4;
    pub const FLAGS: u16 = 5;
};

/// `enum nft_counter_attributes`.
pub const NFTA_COUNTER = struct {
    pub const BYTES: u16 = 1;
    pub const PACKETS: u16 = 2;
};

/// `enum nft_immediate_attributes`.
pub const NFTA_IMMEDIATE = struct {
    pub const DREG: u16 = 1;
    pub const DATA: u16 = 2;
};

/// `enum nft_limit_attributes`.
pub const NFTA_LIMIT = struct {
    pub const RATE: u16 = 1;
    pub const UNIT: u16 = 2;
    pub const BURST: u16 = 3;
    pub const TYPE: u16 = 4;
    pub const FLAGS: u16 = 5;
};

/// `enum nft_log_attributes`.
pub const NFTA_LOG = struct {
    pub const GROUP: u16 = 1;
    pub const PREFIX: u16 = 2;
    pub const SNAPLEN: u16 = 3;
    pub const QTHRESHOLD: u16 = 4;
    pub const LEVEL: u16 = 5;
    pub const FLAGS: u16 = 6;
};

/// `enum nft_nat_attributes`.
pub const NFTA_NAT = struct {
    pub const TYPE: u16 = 1;
    pub const FAMILY: u16 = 2;
    pub const REG_ADDR_MIN: u16 = 3;
    pub const REG_ADDR_MAX: u16 = 4;
    pub const REG_PROTO_MIN: u16 = 5;
    pub const REG_PROTO_MAX: u16 = 6;
    pub const FLAGS: u16 = 7;
};

/// `enum nft_masq_attributes`.
pub const NFTA_MASQ = struct {
    pub const FLAGS: u16 = 1;
    pub const REG_PROTO_MIN: u16 = 2;
    pub const REG_PROTO_MAX: u16 = 3;
};

/// `enum nft_reject_attributes`.
pub const NFTA_REJECT = struct {
    pub const TYPE: u16 = 1;
    pub const ICMP_CODE: u16 = 2;
};

/// `enum nft_reject_types`.
pub const NFT_REJECT = struct {
    pub const ICMP_UNREACH: u32 = 0;
    pub const TCP_RST: u32 = 1;
    pub const ICMPX_UNREACH: u32 = 2;
};

/// `enum nft_queue_attributes`. All three values are `NLA_U16`.
pub const NFTA_QUEUE = struct {
    pub const NUM: u16 = 1;
    pub const TOTAL: u16 = 2;
    pub const FLAGS: u16 = 3;
    pub const SREG_QNUM: u16 = 4;
};

/// `NFT_QUEUE_FLAG_BYPASS` — accept the packet when no listener is bound.
pub const NFT_QUEUE_FLAG_BYPASS: u16 = 0x01;
/// `NFT_QUEUE_FLAG_CPU_FANOUT` — pick the queue by CPU instead of a hash.
pub const NFT_QUEUE_FLAG_CPU_FANOUT: u16 = 0x02;

/// `enum nft_redir_attributes`.
pub const NFTA_REDIR = struct {
    pub const REG_PROTO_MIN: u16 = 1;
    pub const REG_PROTO_MAX: u16 = 2;
    pub const FLAGS: u16 = 3;
};

/// `enum nft_quota_attributes`. 3 is `NFTA_QUOTA_PAD` (alignment only,
/// never sent), which is why `CONSUMED` is 4.
pub const NFTA_QUOTA = struct {
    pub const BYTES: u16 = 1;
    pub const FLAGS: u16 = 2;
    pub const CONSUMED: u16 = 4;
};

/// `enum nft_quota_flags`.
pub const NFT_QUOTA_F_INV: u32 = 1 << 0;
pub const NFT_QUOTA_F_DEPLETED: u32 = 1 << 1;

/// `enum nft_objref_attributes`.
pub const NFTA_OBJREF = struct {
    pub const IMM_TYPE: u16 = 1;
    pub const IMM_NAME: u16 = 2;
    pub const SET_SREG: u16 = 3;
    pub const SET_NAME: u16 = 4;
    pub const SET_ID: u16 = 5;
};

/// `NFT_OBJECT_*` — the stateful object types this module models. The raw
/// number is always accepted (`ObjectType` is non-exhaustive).
pub const ObjectType = enum(u32) {
    counter = 1,
    quota = 2,
    ct_helper = 3,
    limit = 4,
    connlimit = 5,
    tunnel = 6,
    ct_timeout = 7,
    secmark = 8,
    ct_expect = 9,
    synproxy = 10,
    _,
};

/// `enum nft_byteorder_attributes`.
pub const NFTA_BYTEORDER = struct {
    pub const SREG: u16 = 1;
    pub const DREG: u16 = 2;
    pub const OP: u16 = 3;
    pub const LEN: u16 = 4;
    pub const SIZE: u16 = 5;
};
/// `enum nft_exthdr_attributes`.
pub const NFTA_EXTHDR = struct {
    pub const DREG: u16 = 1;
    pub const TYPE: u16 = 2;
    pub const OFFSET: u16 = 3;
    pub const LEN: u16 = 4;
    pub const FLAGS: u16 = 5;
    pub const OP: u16 = 6;
    pub const SREG: u16 = 7;
};
/// `NFT_EXTHDR_F_PRESENT` — load a 0/1 "is it there" instead of the bytes.
pub const NFT_EXTHDR_F_PRESENT: u32 = 1;
/// `enum nft_fib_attributes`.
pub const NFTA_FIB = struct {
    pub const DREG: u16 = 1;
    pub const RESULT: u16 = 2;
    pub const FLAGS: u16 = 3;
};
/// `NFTA_FIB_F_*` — which header fields the route lookup uses.
pub const NFTA_FIB_F = struct {
    pub const SADDR: u32 = 1;
    pub const DADDR: u32 = 2;
    pub const MARK: u32 = 4;
    pub const IIF: u32 = 8;
    pub const OIF: u32 = 16;
    pub const PRESENT: u32 = 32;
};
/// `enum nft_fib_result`.
pub const NFT_FIB_RESULT = struct {
    pub const OIF: u32 = 1;
    pub const OIFNAME: u32 = 2;
    pub const ADDRTYPE: u32 = 3;
};
/// `enum nft_hash_attributes`.
pub const NFTA_HASH = struct {
    pub const SREG: u16 = 1;
    pub const DREG: u16 = 2;
    pub const LEN: u16 = 3;
    pub const MODULUS: u16 = 4;
    pub const SEED: u16 = 5;
    pub const OFFSET: u16 = 6;
    pub const TYPE: u16 = 7;
};
/// `enum nft_ng_attributes`.
pub const NFTA_NG = struct {
    pub const DREG: u16 = 1;
    pub const MODULUS: u16 = 2;
    pub const TYPE: u16 = 3;
    pub const OFFSET: u16 = 4;
};
/// `enum nft_range_attributes`.
pub const NFTA_RANGE = struct {
    pub const SREG: u16 = 1;
    pub const OP: u16 = 2;
    pub const FROM_DATA: u16 = 3;
    pub const TO_DATA: u16 = 4;
};
/// `enum nft_rt_attributes`.
pub const NFTA_RT = struct {
    pub const DREG: u16 = 1;
    pub const KEY: u16 = 2;
};
/// `enum nft_rt_keys`.
pub const NFT_RT = struct {
    pub const CLASSID: u32 = 0;
    pub const NEXTHOP4: u32 = 1;
    pub const NEXTHOP6: u32 = 2;
    pub const TCPMSS: u32 = 3;
    pub const XFRM: u32 = 4;
};
/// `enum nft_socket_attributes`.
pub const NFTA_SOCKET = struct {
    pub const KEY: u16 = 1;
    pub const DREG: u16 = 2;
    pub const LEVEL: u16 = 3;
};
/// `enum nft_socket_keys`.
pub const NFT_SOCKET = struct {
    pub const TRANSPARENT: u32 = 0;
    pub const MARK: u32 = 1;
    pub const WILDCARD: u32 = 2;
    pub const CGROUPV2: u32 = 3;
};
/// `enum nft_dup_attributes`.
pub const NFTA_DUP = struct {
    pub const SREG_ADDR: u16 = 1;
    pub const SREG_DEV: u16 = 2;
};
/// `enum nft_fwd_attributes`.
pub const NFTA_FWD = struct {
    pub const SREG_DEV: u16 = 1;
    pub const SREG_ADDR: u16 = 2;
    pub const NFPROTO: u16 = 3;
};
/// `enum nft_tproxy_attributes`.
pub const NFTA_TPROXY = struct {
    pub const FAMILY: u16 = 1;
    pub const REG_ADDR: u16 = 2;
    pub const REG_PORT: u16 = 3;
};
/// `enum nft_synproxy_attributes`.
pub const NFTA_SYNPROXY = struct {
    pub const MSS: u16 = 1;
    pub const WSCALE: u16 = 2;
    pub const FLAGS: u16 = 3;
};
/// `NF_SYNPROXY_OPT_*`.
pub const SYNPROXY_OPT = struct {
    pub const MSS: u32 = 0x01;
    pub const WSCALE: u32 = 0x02;
    pub const SACK_PERM: u32 = 0x04;
    pub const TIMESTAMP: u32 = 0x08;
};
/// `enum nft_connlimit_attributes`.
pub const NFTA_CONNLIMIT = struct {
    pub const COUNT: u16 = 1;
    pub const FLAGS: u16 = 2;
};
/// `NFT_CONNLIMIT_F_INV`.
pub const NFT_CONNLIMIT_F_INV: u32 = 1;
/// `enum nft_dynset_attributes`.
pub const NFTA_DYNSET = struct {
    pub const SET_NAME: u16 = 1;
    pub const SET_ID: u16 = 2;
    pub const OP: u16 = 3;
    pub const SREG_KEY: u16 = 4;
    pub const SREG_DATA: u16 = 5;
    pub const TIMEOUT: u16 = 6;
    pub const EXPR: u16 = 7;
    pub const FLAGS: u16 = 9;
    pub const EXPRESSIONS: u16 = 10;
};
/// `NFT_DYNSET_F_INV` / `NFT_DYNSET_F_EXPR`.
pub const NFT_DYNSET_F_INV: u32 = 1;
pub const NFT_DYNSET_F_EXPR: u32 = 2;
/// `enum nft_osf_attributes`.
pub const NFTA_OSF = struct {
    pub const DREG: u16 = 1;
    pub const TTL: u16 = 2;
    pub const FLAGS: u16 = 3;
};
/// `enum nft_last_attributes`.
pub const NFTA_LAST = struct {
    pub const SET: u16 = 1;
    pub const MSECS: u16 = 2;
};
/// `enum nft_flow_attributes` (`NFTA_FLOW_TABLE_NAME`).
pub const NFTA_FLOW_TABLE_NAME: u16 = 1;
/// `enum nft_payload_csum_types`.
pub const NFT_PAYLOAD_CSUM = struct {
    pub const NONE: u32 = 0;
    pub const INET: u32 = 1;
    pub const SCTP: u32 = 2;
};

/// `enum nft_byteorder_ops`.
pub const ByteorderOp = enum(u32) { ntoh = 0, hton = 1 };
/// `enum nft_exthdr_op`.
pub const ExthdrOp = enum(u32) { ipv6 = 0, tcpopt = 1, ipv4 = 2, sctp = 3, dccp = 4, _ };
/// `enum nft_hash_types`.
pub const HashKind = enum(u32) { jenkins = 0, sym = 1 };
/// `enum nft_ng_types`.
pub const NumgenKind = enum(u32) { incremental = 0, random = 1 };
/// `enum nft_range_ops` (`range eq` / `range neq`).
pub const RangeOp = enum(u32) { eq = 0, neq = 1 };
/// `enum nft_dynset_ops`.
pub const DynsetOp = enum(u32) { add = 0, update = 1, delete = 2 };
/// Direction of a `bitwise` shift (`NFT_BITWISE_LSHIFT` / `_RSHIFT`).
pub const ShiftDir = enum(u32) { left = 1, right = 2 };

/// `enum nft_reject_inet_code` — the family-independent reject codes an
/// `inet`/`bridge`/`netdev` rule uses (`reject with icmpx …`).
pub const IcmpxCode = enum(u8) {
    no_route = 0,
    port_unreach = 1,
    host_unreach = 2,
    admin_prohibited = 3,
};

/// What a `reject` answers with.
pub const RejectWith = union(enum) {
    /// ICMP (in an `ip` table) or ICMPv6 (in `ip6`) destination-unreachable
    /// with this raw code — e.g. 1 = host unreachable, 3 = port unreachable
    /// for ICMP (RFC 792).
    icmp: u8,
    /// The abstract code `inet`/`bridge`/`netdev` tables use; the kernel maps
    /// it to the right ICMP or ICMPv6 code per packet. Bare `reject` in an
    /// `inet` table is `.{ .icmpx = .port_unreach }` (captured).
    icmpx: IcmpxCode,
    /// A TCP RST. Match TCP first (`tcpDport`, `l4proto`) — `nft` only
    /// accepts it after a TCP dependency, and the golden has one.
    tcp_reset,
};

/// `NFT_LOOKUP_F_INV` — invert set membership (`!= @set`).
pub const NFT_LOOKUP_F_INV: u32 = 1;
/// `NFT_LIMIT_F_INV` — match when the limit is *exceeded*.
pub const NFT_LIMIT_F_INV: u32 = 1;
/// `enum nft_nat_types`.
pub const NFT_NAT_SNAT: u32 = 0;
pub const NFT_NAT_DNAT: u32 = 1;

/// `enum nft_ct_keys` — only the keys this module names; the raw number is
/// always accepted by `Expr.ct_load`.
pub const NFT_CT = struct {
    pub const STATE: u32 = 0;
    pub const DIRECTION: u32 = 1;
    pub const STATUS: u32 = 2;
    pub const MARK: u32 = 3;
    pub const SECMARK: u32 = 4;
    pub const EXPIRATION: u32 = 5;
    pub const HELPER: u32 = 6;
    pub const L3PROTOCOL: u32 = 7;
    pub const SRC: u32 = 8;
    pub const DST: u32 = 9;
    pub const PROTOCOL: u32 = 10;
    pub const PROTO_SRC: u32 = 11;
    pub const PROTO_DST: u32 = 12;
    pub const LABELS: u32 = 13;
    pub const PKTS: u32 = 14;
    pub const BYTES: u32 = 15;
    pub const AVGPKT: u32 = 16;
    pub const ZONE: u32 = 17;
    pub const EVENTMASK: u32 = 18;
    pub const ID: u32 = 23;
};

/// `enum ip_conntrack_status`-derived bits that `ct state` compares against.
/// These are the *state* bits (`NF_CT_STATE_BIT(x) = 1 << (x + 1)`), not
/// `IPS_*`: the kernel's `nft_ct` puts this bitmask in a register.
pub const CT_STATE = struct {
    pub const INVALID: u32 = 1 << 0;
    pub const ESTABLISHED: u32 = 1 << 1;
    pub const RELATED: u32 = 1 << 2;
    pub const NEW: u32 = 1 << 3;
    pub const UNTRACKED: u32 = 1 << 6;
};

/// IP protocol numbers used by the payload helpers.
pub const IPPROTO = struct {
    pub const ICMP: u8 = 1;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
    pub const ICMPV6: u8 = 58;
    pub const SCTP: u8 = 132;
};

// ── registers ───────────────────────────────────────────────────────────────

/// `enum nft_registers`. Only the 16-byte registers are allocated by this
/// module (see the register model in the file header); `NFT_REG32_*` values
/// remain expressible for a caller that hand-builds expressions.
pub const Reg = enum(u32) {
    verdict = 0,
    r1 = 1,
    r2 = 2,
    r3 = 3,
    r4 = 4,
    reg32_00 = 8,
    _,
};

pub const RegError = error{OutOfRegisters};

/// Width, in bytes, of one legacy data register (`NFT_REG_1`…`NFT_REG_4`).
/// `payloadCmp`/`payloadMaskedCmp` load into a single such register, so a
/// requested `len` above this cannot be serviced — see the register model
/// in the file header.
pub const max_value_len: u32 = 16;

/// Hands out `NFT_REG_1`…`NFT_REG_4` in order; `reset` starts over.
pub const RegAlloc = struct {
    next: u32 = 1,

    pub fn reset(a: *RegAlloc) void {
        a.next = 1;
    }

    pub fn alloc(a: *RegAlloc) RegError!Reg {
        if (a.next > 4) return error.OutOfRegisters;
        defer a.next += 1;
        return @fromBackingInt(@intCast(a.next));
    }
};

// ── the expression model ────────────────────────────────────────────────────

/// A verdict: a base verdict (`NF_ACCEPT`/`NF_DROP`/…) or a chain jump.
pub const Verdict = struct {
    code: i32,
    /// Target chain for `NFT_JUMP`/`NFT_GOTO`; null otherwise.
    chain: ?[]const u8 = null,

    pub const accept: Verdict = .{ .code = types.NF.ACCEPT };
    pub const drop: Verdict = .{ .code = types.NF.DROP };
    pub const cont: Verdict = .{ .code = types.NFT.CONTINUE };
    pub const ret: Verdict = .{ .code = types.NFT.RETURN };

    pub fn jumpTo(chain: []const u8) Verdict {
        return .{ .code = types.NFT.JUMP, .chain = chain };
    }

    pub fn gotoChain(chain: []const u8) Verdict {
        return .{ .code = types.NFT.GOTO, .chain = chain };
    }
};

/// The payload of an `NFTA_*_DATA` nest: either raw bytes (`NFTA_DATA_VALUE`)
/// or a verdict (`NFTA_DATA_VERDICT`).
pub const Data = union(enum) {
    value: []const u8,
    verdict: Verdict,
};

/// A `limit` statement.
pub const Limit = struct {
    /// Packets (or bytes, per `unit`) allowed per `per`.
    rate: u64,
    per: LimitPer = .second,
    burst: u32 = 0,
    unit: LimitUnit = .packets,
    /// Match when the limit is exceeded rather than when it is respected.
    inv: bool = false,
};

/// A `log` statement. All-null is the bare `log`.
pub const LogSpec = struct {
    prefix: ?[]const u8 = null,
    group: ?u32 = null,
    snaplen: ?u32 = null,
    qthreshold: ?u32 = null,
    level: ?LogLevel = null,
    flags: ?u32 = null,
};

/// An `nat` statement's wire form: which registers hold the translation.
pub const NatSpec = struct {
    /// `NFT_NAT_SNAT` or `NFT_NAT_DNAT`.
    kind: u32,
    /// Address family of the translated address (`NFPROTO_*`).
    family: u8,
    reg_addr_min: ?Reg = null,
    reg_addr_max: ?Reg = null,
    reg_proto_min: ?Reg = null,
    reg_proto_max: ?Reg = null,
    flags: u32 = 0,
};

/// One nftables expression, at the level the kernel sees it.
pub const Expr = union(enum) {
    /// `payload` load: `len` bytes at `offset` from `base` into `dreg`.
    payload_load: struct { base: PayloadBase, offset: u32, len: u32, dreg: Reg },
    /// `meta` load.
    meta_load: struct { key: MetaKey, dreg: Reg },
    /// `meta` store (`meta mark set …`).
    meta_set: struct { key: MetaKey, sreg: Reg },
    /// `ct` load. `key` is a raw `enum nft_ct_keys` value (see `NFT_CT`).
    ct_load: struct { key: u32, dir: ?CtDir = null, dreg: Reg },
    /// `cmp`.
    cmp: struct { sreg: Reg, op: u32, data: Data },
    /// `bitwise` mask/xor — `dreg = (sreg & mask) ^ xor`. `mask` and `xor`
    /// must both be `len` bytes long.
    bitwise: struct {
        sreg: Reg,
        dreg: Reg,
        len: u32,
        mask: []const u8,
        xor: []const u8,
        /// Send `NFTA_BITWISE_OP = NFT_BITWISE_MASK_XOR` (0) explicitly, as
        /// `nft` does for the read-modify-write behind `ip ttl set 64`
        /// but not for a plain `ip saddr 10.0.0.0/12` mask.
        explicit_op: bool = false,
    },
    /// `lookup` in a named set.
    lookup: struct {
        set: []const u8,
        sreg: Reg,
        /// Map lookups write the data half here.
        dreg: ?Reg = null,
        /// Only needed for a set created in the *same* batch.
        set_id: ?u32 = null,
        invert: bool = false,
    },
    /// `counter`, optionally seeded.
    counter: struct { packets: u64 = 0, bytes: u64 = 0 },
    /// `immediate` — a verdict (into `NFT_REG_VERDICT`) or a value.
    immediate: struct { dreg: Reg, data: Data },
    limit: Limit,
    log: LogSpec,
    nat: NatSpec,
    /// `masq` — masquerade, optionally with a port range.
    masq: struct { flags: u32 = 0, reg_proto_min: ?Reg = null, reg_proto_max: ?Reg = null },
    /// `reject` — `type` is `NFT_REJECT_*`, `icmp_code` the ICMP/ICMPX code
    /// (0 for a TCP RST). Build it with `Program.reject`.
    reject: struct { type: u32, icmp_code: u8 },
    /// `queue` — hand the packet to userspace on `num` … `num + total - 1`.
    queue: struct { num: u16, total: u16 = 1, flags: u16 = 0 },
    /// `redir` — `redirect [to :port]`, the port read from a register.
    redir: struct { reg_proto_min: ?Reg = null, reg_proto_max: ?Reg = null, flags: u32 = 0 },
    /// `quota` — anonymous byte quota. `over` matches once it is exceeded.
    quota: struct { bytes: u64, consumed: u64 = 0, over: bool = false },
    /// `objref` — use a named stateful object (`counter name "c"`).
    objref: struct { obj_type: ObjectType, name: []const u8 },
    /// `byteorder` — convert `len` bytes of `sreg` in `size`-byte units.
    byteorder: struct { sreg: Reg, dreg: Reg, op: ByteorderOp, len: u32, size: u32 },
    /// `bitwise` shift by a constant (`meta mark lshift 8`). The kernel's
    /// `and`/`or`/`xor` operators are never needed: `nft` itself lowers
    /// those to mask/xor (captured), which `bitwise` already carries.
    bitshift: struct { sreg: Reg, dreg: Reg, len: u32, dir: ShiftDir, amount: u32 },
    /// `exthdr` — IPv6 extension header / TCP option / IPv4 option / SCTP
    /// chunk / DCCP option. Exactly one of `dreg` (load) and `sreg` (set).
    exthdr: struct {
        op: ExthdrOp,
        hdr_type: u8,
        offset: u32,
        len: u32,
        /// Load a 0/1 "present" instead of the bytes (`… exists`).
        present: bool = false,
        dreg: ?Reg = null,
        sreg: ?Reg = null,
    },
    /// `fib` — reverse-path / address-type lookup. `flags` are `NFTA_FIB_F`.
    fib: struct { dreg: Reg, result: u32, flags: u32 },
    /// `hash` — `jhash` over `len` bytes of `sreg`, or `symhash` (no `sreg`).
    hash: struct {
        kind: HashKind,
        dreg: Reg,
        sreg: ?Reg = null,
        len: u32 = 0,
        modulus: u32,
        seed: u32 = 0,
        offset: u32 = 0,
    },
    /// `numgen` — incrementing or random number modulo `modulus`.
    numgen: struct { dreg: Reg, kind: NumgenKind, modulus: u32, offset: u32 = 0 },
    /// `range` — `sreg` in `[from, to]` (or outside, for `neq`).
    range: struct { sreg: Reg, op: RangeOp, from: []const u8, to: []const u8 },
    /// `rt` — routing key (`NFT_RT`).
    rt: struct { key: u32, dreg: Reg },
    /// `socket` — transparent/mark/wildcard/cgroupv2 of the matched socket.
    socket: struct { key: u32, dreg: Reg, level: u32 = 0 },
    /// `notrack` — no attributes at all (`nft` sends no data nest).
    notrack,
    /// `dup` — copy the packet to an address and/or device.
    dup: struct { sreg_addr: Reg, sreg_dev: ?Reg = null },
    /// `fwd` — forward to a device (netdev family), optionally via a neighbour.
    fwd: struct { sreg_dev: Reg, sreg_addr: ?Reg = null, nfproto: ?u32 = null },
    /// `tproxy` — transparent proxy; `family` is `NFPROTO_*`.
    tproxy: struct { family: u8, reg_addr: ?Reg = null, reg_port: ?Reg = null },
    /// `synproxy`; `flags` are `SYNPROXY_OPT`.
    synproxy: struct { mss: u16, wscale: u8, flags: u32 },
    /// `connlimit` (`ct count [over] N`).
    connlimit: struct { count: u32, over: bool = false },
    /// `dynset` — add/update/delete the key in a dynamic set. `exprs` are the
    /// per-element expressions (`limit`, `counter`, …); one is sent as
    /// `NFTA_DYNSET_EXPR` (as `nft` does), several as the list.
    dynset: struct {
        set: []const u8,
        set_id: ?u32 = null,
        op: DynsetOp,
        sreg_key: Reg,
        sreg_data: ?Reg = null,
        timeout_ms: ?u64 = null,
        exprs: []const Expr = &.{},
        invert: bool = false,
    },
    /// `osf` — passive OS fingerprint name into `dreg` (16 bytes).
    osf: struct { dreg: Reg, ttl: u8 = 0, version: bool = false },
    /// `ct` store (`ct mark set …`).
    ct_set: struct { key: u32, dir: ?CtDir = null, sreg: Reg },
    /// `payload` write (`ip ttl set …`) with an optional checksum fix-up.
    payload_set: struct {
        base: PayloadBase,
        offset: u32,
        len: u32,
        sreg: Reg,
        csum_type: u32 = 0,
        csum_offset: u32 = 0,
        csum_flags: u32 = 0,
    },
    /// `last` — when the rule last matched; `msecs` since then, `set` once it has.
    last: struct { msecs: u64 = 0, set: bool = false },
    /// `flow add @ft` — hand the flow to a flowtable.
    flow_offload: struct { table: []const u8 },
    /// Escape hatch: a fully pre-encoded `NFTA_EXPR_DATA` payload under
    /// `name`. Lets a caller reach an expression this module does not model
    /// without forking it.
    raw: struct { name: []const u8, data: []const u8 },

    /// The `NFTA_EXPR_NAME` string the kernel dispatches on.
    pub fn name(e: Expr) []const u8 {
        return switch (e) {
            .payload_load => "payload",
            .meta_load, .meta_set => "meta",
            .ct_load => "ct",
            .cmp => "cmp",
            .bitwise => "bitwise",
            .lookup => "lookup",
            .counter => "counter",
            .immediate => "immediate",
            .limit => "limit",
            .log => "log",
            .nat => "nat",
            .masq => "masq",
            .reject => "reject",
            .queue => "queue",
            .redir => "redir",
            .quota => "quota",
            .objref => "objref",
            .byteorder => "byteorder",
            .bitshift => "bitwise",
            .exthdr => "exthdr",
            .fib => "fib",
            .hash => "hash",
            .numgen => "numgen",
            .range => "range",
            .rt => "rt",
            .socket => "socket",
            .notrack => "notrack",
            .dup => "dup",
            .fwd => "fwd",
            .tproxy => "tproxy",
            .synproxy => "synproxy",
            .connlimit => "connlimit",
            .dynset => "dynset",
            .osf => "osf",
            .ct_set => "ct",
            .payload_set => "payload",
            .flow_offload => "flow_offload",
            .last => "last",
            .raw => |r| r.name,
        };
    }
};

pub const BuildError = std.mem.Allocator.Error || RegError || error{
    AttrTooLong,
    /// `bitwise.mask` / `.xor` disagree with `bitwise.len`.
    BitwiseLengthMismatch,
    /// A `MetaKey` this module cannot map onto `enum nft_meta_keys`.
    UnsupportedMetaKey,
    /// `Op.in` used where a `cmp` was required (use `lookup`).
    UnsupportedOperator,
    /// A hook/family combination with no kernel hook number.
    UnsupportedHook,
    /// A comparison value whose width does not match what the load produces.
    ValueWidthMismatch,
    /// An interface name at or past `IFNAMSIZ` (16 bytes including the NUL).
    /// `nft(8)` refuses the same name — "String exceeds maximum length of 16".
    InterfaceNameTooLong,
    /// An IPv4 prefix length above 32.
    InvalidPrefixLength,
    /// A `limit` rate that overflows once scaled by its unit.
    RateOutOfRange,
    /// A `queue` range that is empty or runs past queue 65535.
    InvalidQueueRange,
    /// A set element carrying both `data` and `verdict` — a map element has
    /// one data half, so one of them would be silently dropped.
    ElemDataConflict,
    /// An interval whose last key sorts below its first.
    InvalidRange,
    /// An expression whose fields contradict each other (`exthdr` with both
    /// or neither of `dreg`/`sreg`, `hash` without a source, a zero modulus).
    InvalidExpression,
};

// ── encoding ────────────────────────────────────────────────────────────────

pub fn appendData(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    d: Data,
) BuildError!void {
    const off = try nl.nestBegin(gpa, list, nl.NLA_F_NESTED | attr_type);
    switch (d) {
        .value => |bytes| try nl.appendAttr(gpa, list, NFTA_DATA.VALUE, bytes),
        .verdict => |v| {
            const voff = try nl.nestBegin(gpa, list, nl.NLA_F_NESTED | NFTA_DATA.VERDICT);
            try nl.appendAttrBe32(gpa, list, NFTA_VERDICT.CODE, @bitCast(v.code));
            if (v.chain) |c| try nl.appendAttrString(gpa, list, NFTA_VERDICT.CHAIN, c);
            try nl.nestEnd(list, voff);
        },
    }
    try nl.nestEnd(list, off);
}

/// The attributes of a `limit` expression or object (they are the same).
pub fn appendLimitAttrs(gpa: std.mem.Allocator, list: *std.ArrayList(u8), l: Limit) BuildError!void {
    const scaled = std.math.mul(u64, l.rate, l.unit.scale()) catch
        return error.RateOutOfRange;
    try nl.appendAttrBe64(gpa, list, NFTA_LIMIT.RATE, scaled);
    try nl.appendAttrBe64(gpa, list, NFTA_LIMIT.UNIT, l.per.seconds());
    try nl.appendAttrBe32(gpa, list, NFTA_LIMIT.BURST, l.burst);
    try nl.appendAttrBe32(gpa, list, NFTA_LIMIT.TYPE, l.unit.limitType());
    try nl.appendAttrBe32(gpa, list, NFTA_LIMIT.FLAGS, if (l.inv) NFT_LIMIT_F_INV else 0);
}

/// The body of one expression (`NFTA_EXPR_NAME` + `NFTA_EXPR_DATA`) without
/// the `NFTA_LIST_ELEM` wrapper — what `NFTA_DYNSET_EXPR` and
/// `NFTA_SET_EXPR` hold directly.
pub fn appendExprBody(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    e: Expr,
) BuildError!void {
    const start = list.items.len;
    try appendExpr(gpa, list, e);
    // `appendExpr` wrote `[nlattr header][body]`; drop its 4-byte wrapper
    // header and keep the body, which is already padded to 4 bytes.
    std.mem.copyForwards(u8, list.items[start..], list.items[start + 4 ..]);
    list.shrinkRetainingCapacity(list.items.len - 4);
}

/// Append one expression as an `NFTA_LIST_ELEM` nest.
///
/// Attribute order inside every `NFTA_EXPR_DATA` matches the byte-exact `nft`
/// captures in `goldens.zig`. The kernel's policy parser accepts any order;
/// matching `nft` is what makes the goldens meaningful.
pub fn appendExpr(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    e: Expr,
) BuildError!void {
    const elem = try nl.nestBegin(gpa, list, nl.NLA_F_NESTED | NFTA_LIST_ELEM);
    try nl.appendAttrString(gpa, list, NFTA_EXPR.NAME, e.name());
    if (e == .notrack) {
        // `nft` sends the bare name for `notrack`: no data nest at all.
        try nl.nestEnd(list, elem);
        return;
    }
    const data = try nl.nestBegin(gpa, list, nl.NLA_F_NESTED | NFTA_EXPR.DATA);
    switch (e) {
        .payload_load => |p| {
            try nl.appendAttrBe32(gpa, list, NFTA_PAYLOAD.DREG, @backingInt(p.dreg));
            try nl.appendAttrBe32(gpa, list, NFTA_PAYLOAD.BASE, p.base.base());
            try nl.appendAttrBe32(gpa, list, NFTA_PAYLOAD.OFFSET, p.offset);
            try nl.appendAttrBe32(gpa, list, NFTA_PAYLOAD.LEN, p.len);
        },
        .meta_load => |m| {
            try nl.appendAttrBe32(gpa, list, NFTA_META.KEY, m.key.key() orelse
                return error.UnsupportedMetaKey);
            try nl.appendAttrBe32(gpa, list, NFTA_META.DREG, @backingInt(m.dreg));
        },
        .meta_set => |m| {
            try nl.appendAttrBe32(gpa, list, NFTA_META.KEY, m.key.key() orelse
                return error.UnsupportedMetaKey);
            try nl.appendAttrBe32(gpa, list, NFTA_META.SREG, @backingInt(m.sreg));
        },
        .ct_load => |c| {
            try nl.appendAttrBe32(gpa, list, NFTA_CT.KEY, c.key);
            try nl.appendAttrBe32(gpa, list, NFTA_CT.DREG, @backingInt(c.dreg));
            if (c.dir) |d| try nl.appendAttrU8(gpa, list, NFTA_CT.DIRECTION, d.dir());
        },
        .cmp => |c| {
            try nl.appendAttrBe32(gpa, list, NFTA_CMP.SREG, @backingInt(c.sreg));
            try nl.appendAttrBe32(gpa, list, NFTA_CMP.OP, c.op);
            try appendData(gpa, list, NFTA_CMP.DATA, c.data);
        },
        .bitwise => |b| {
            if (b.mask.len != b.len or b.xor.len != b.len)
                return error.BitwiseLengthMismatch;
            try nl.appendAttrBe32(gpa, list, NFTA_BITWISE.SREG, @backingInt(b.sreg));
            try nl.appendAttrBe32(gpa, list, NFTA_BITWISE.DREG, @backingInt(b.dreg));
            if (b.explicit_op) try nl.appendAttrBe32(gpa, list, NFTA_BITWISE.OP, 0);
            try nl.appendAttrBe32(gpa, list, NFTA_BITWISE.LEN, b.len);
            try appendData(gpa, list, NFTA_BITWISE.MASK, .{ .value = b.mask });
            try appendData(gpa, list, NFTA_BITWISE.XOR, .{ .value = b.xor });
        },
        .lookup => |l| {
            // `nft` puts DREG between SREG and SET when there is one (the
            // `tcp dport vmap @vm` golden) and leaves it out otherwise.
            try nl.appendAttrBe32(gpa, list, NFTA_LOOKUP.SREG, @backingInt(l.sreg));
            if (l.dreg) |d| try nl.appendAttrBe32(gpa, list, NFTA_LOOKUP.DREG, @backingInt(d));
            try nl.appendAttrString(gpa, list, NFTA_LOOKUP.SET, l.set);
            if (l.set_id) |id| try nl.appendAttrBe32(gpa, list, NFTA_LOOKUP.SET_ID, id);
            if (l.invert) try nl.appendAttrBe32(gpa, list, NFTA_LOOKUP.FLAGS, NFT_LOOKUP_F_INV);
        },
        .counter => |c| {
            // `nft` sends an empty NFTA_EXPR_DATA for a fresh counter; only a
            // seeded counter carries the two 64-bit values.
            if (c.bytes != 0 or c.packets != 0) {
                try nl.appendAttrBe64(gpa, list, NFTA_COUNTER.BYTES, c.bytes);
                try nl.appendAttrBe64(gpa, list, NFTA_COUNTER.PACKETS, c.packets);
            }
        },
        .immediate => |i| {
            try nl.appendAttrBe32(gpa, list, NFTA_IMMEDIATE.DREG, @backingInt(i.dreg));
            try appendData(gpa, list, NFTA_IMMEDIATE.DATA, i.data);
        },
        .limit => |l| {
            // ⚠ `rate * scale` wrapped: `(1 << 44) + 1` bytes/s scaled to
            // mbytes came out as 1 MiB/s -- a limit far TIGHTER than asked
            // for, which is a rule that silently drops traffic the caller
            // meant to admit (Debug panicked; ReleaseFast encoded the wrapped
            // value with no error). Audit 2026-09-02.
            try appendLimitAttrs(gpa, list, l);
        },
        .log => |l| {
            // GROUP and QTHRESHOLD are NLA_U16 in the kernel (captured: `log group 5
            // queue-threshold 3` sends 2-byte values); SNAPLEN is a u32.
            if (l.group) |g| try nl.appendAttrBe16(gpa, list, NFTA_LOG.GROUP, std.math.cast(u16, g) orelse return error.InvalidExpression);
            if (l.prefix) |p| try nl.appendAttrString(gpa, list, NFTA_LOG.PREFIX, p);
            if (l.snaplen) |s| try nl.appendAttrBe32(gpa, list, NFTA_LOG.SNAPLEN, s);
            if (l.qthreshold) |q| try nl.appendAttrBe16(gpa, list, NFTA_LOG.QTHRESHOLD, std.math.cast(u16, q) orelse return error.InvalidExpression);
            if (l.level) |lv| try nl.appendAttrBe32(gpa, list, NFTA_LOG.LEVEL, lv.level());
            if (l.flags) |f| try nl.appendAttrBe32(gpa, list, NFTA_LOG.FLAGS, f);
        },
        .nat => |n| {
            try nl.appendAttrBe32(gpa, list, NFTA_NAT.TYPE, n.kind);
            try nl.appendAttrBe32(gpa, list, NFTA_NAT.FAMILY, n.family);
            if (n.reg_addr_min) |r|
                try nl.appendAttrBe32(gpa, list, NFTA_NAT.REG_ADDR_MIN, @backingInt(r));
            if (n.reg_addr_max) |r|
                try nl.appendAttrBe32(gpa, list, NFTA_NAT.REG_ADDR_MAX, @backingInt(r));
            if (n.reg_proto_min) |r|
                try nl.appendAttrBe32(gpa, list, NFTA_NAT.REG_PROTO_MIN, @backingInt(r));
            if (n.reg_proto_max) |r|
                try nl.appendAttrBe32(gpa, list, NFTA_NAT.REG_PROTO_MAX, @backingInt(r));
            if (n.flags != 0) try nl.appendAttrBe32(gpa, list, NFTA_NAT.FLAGS, n.flags);
        },
        .masq => |m| {
            if (m.flags != 0) try nl.appendAttrBe32(gpa, list, NFTA_MASQ.FLAGS, m.flags);
            if (m.reg_proto_min) |r|
                try nl.appendAttrBe32(gpa, list, NFTA_MASQ.REG_PROTO_MIN, @backingInt(r));
            if (m.reg_proto_max) |r|
                try nl.appendAttrBe32(gpa, list, NFTA_MASQ.REG_PROTO_MAX, @backingInt(r));
        },
        .reject => |r| {
            try nl.appendAttrBe32(gpa, list, NFTA_REJECT.TYPE, r.type);
            try nl.appendAttrU8(gpa, list, NFTA_REJECT.ICMP_CODE, r.icmp_code);
        },
        .queue => |q| {
            // ⚠ Checked here, not only in `Program.queue`: an empty range
            // or one wrapping past 65535 reaches the kernel otherwise, and a
            // hand-built `Expr` never passes through the Program.
            if (q.total == 0 or @as(u32, q.num) + q.total - 1 > std.math.maxInt(u16))
                return error.InvalidQueueRange;
            try nl.appendAttrBe16(gpa, list, NFTA_QUEUE.NUM, q.num);
            try nl.appendAttrBe16(gpa, list, NFTA_QUEUE.TOTAL, q.total);
            try nl.appendAttrBe16(gpa, list, NFTA_QUEUE.FLAGS, q.flags);
        },
        .redir => |r| {
            if (r.reg_proto_min) |reg|
                try nl.appendAttrBe32(gpa, list, NFTA_REDIR.REG_PROTO_MIN, @backingInt(reg));
            if (r.reg_proto_max) |reg|
                try nl.appendAttrBe32(gpa, list, NFTA_REDIR.REG_PROTO_MAX, @backingInt(reg));
            if (r.flags != 0) try nl.appendAttrBe32(gpa, list, NFTA_REDIR.FLAGS, r.flags);
        },
        .quota => |q| {
            // `nft` sends all three, CONSUMED before FLAGS, even when zero.
            try nl.appendAttrBe64(gpa, list, NFTA_QUOTA.BYTES, q.bytes);
            try nl.appendAttrBe64(gpa, list, NFTA_QUOTA.CONSUMED, q.consumed);
            try nl.appendAttrBe32(gpa, list, NFTA_QUOTA.FLAGS, if (q.over) NFT_QUOTA_F_INV else 0);
        },
        .objref => |o| {
            try nl.appendAttrBe32(gpa, list, NFTA_OBJREF.IMM_TYPE, @backingInt(o.obj_type));
            // `nft` sends the object name WITHOUT a terminating NUL here
            // (`counter name c1` → a 6-byte attribute, captured), unlike every
            // other name attribute; the kernel's NLA_STRING policy accepts
            // both. Raw bytes keep the golden byte-exact.
            try nl.appendAttr(gpa, list, NFTA_OBJREF.IMM_NAME, o.name);
        },
        .byteorder => |b| {
            try nl.appendAttrBe32(gpa, list, NFTA_BYTEORDER.SREG, @backingInt(b.sreg));
            try nl.appendAttrBe32(gpa, list, NFTA_BYTEORDER.DREG, @backingInt(b.dreg));
            try nl.appendAttrBe32(gpa, list, NFTA_BYTEORDER.OP, @backingInt(b.op));
            try nl.appendAttrBe32(gpa, list, NFTA_BYTEORDER.LEN, b.len);
            try nl.appendAttrBe32(gpa, list, NFTA_BYTEORDER.SIZE, b.size);
        },
        .bitshift => |b| {
            try nl.appendAttrBe32(gpa, list, NFTA_BITWISE.SREG, @backingInt(b.sreg));
            try nl.appendAttrBe32(gpa, list, NFTA_BITWISE.DREG, @backingInt(b.dreg));
            try nl.appendAttrBe32(gpa, list, NFTA_BITWISE.OP, @backingInt(b.dir));
            try nl.appendAttrBe32(gpa, list, NFTA_BITWISE.LEN, b.len);
            // The shift amount is a register-style value: host byte order.
            var amount: [4]u8 = undefined;
            std.mem.writeInt(u32, &amount, b.amount, builtin.cpu.arch.endian());
            try appendData(gpa, list, NFTA_BITWISE.DATA, .{ .value = &amount });
        },
        .exthdr => |x| {
            if ((x.dreg == null) == (x.sreg == null)) return error.InvalidExpression;
            if (x.dreg) |d| try nl.appendAttrBe32(gpa, list, NFTA_EXTHDR.DREG, @backingInt(d));
            if (x.sreg) |r| try nl.appendAttrBe32(gpa, list, NFTA_EXTHDR.SREG, @backingInt(r));
            try nl.appendAttrU8(gpa, list, NFTA_EXTHDR.TYPE, x.hdr_type);
            try nl.appendAttrBe32(gpa, list, NFTA_EXTHDR.OFFSET, x.offset);
            try nl.appendAttrBe32(gpa, list, NFTA_EXTHDR.LEN, x.len);
            try nl.appendAttrBe32(gpa, list, NFTA_EXTHDR.OP, @backingInt(x.op));
            if (x.dreg != null)
                try nl.appendAttrBe32(gpa, list, NFTA_EXTHDR.FLAGS, if (x.present) NFT_EXTHDR_F_PRESENT else 0);
        },
        .fib => |f| {
            try nl.appendAttrBe32(gpa, list, NFTA_FIB.FLAGS, f.flags);
            try nl.appendAttrBe32(gpa, list, NFTA_FIB.RESULT, f.result);
            try nl.appendAttrBe32(gpa, list, NFTA_FIB.DREG, @backingInt(f.dreg));
        },
        .hash => |h| {
            if (h.kind == .jenkins and h.sreg == null) return error.InvalidExpression;
            if (h.modulus == 0) return error.InvalidExpression;
            if (h.sreg) |r| try nl.appendAttrBe32(gpa, list, NFTA_HASH.SREG, @backingInt(r));
            try nl.appendAttrBe32(gpa, list, NFTA_HASH.DREG, @backingInt(h.dreg));
            if (h.sreg != null) try nl.appendAttrBe32(gpa, list, NFTA_HASH.LEN, h.len);
            try nl.appendAttrBe32(gpa, list, NFTA_HASH.MODULUS, h.modulus);
            if (h.seed != 0) try nl.appendAttrBe32(gpa, list, NFTA_HASH.SEED, h.seed);
            try nl.appendAttrBe32(gpa, list, NFTA_HASH.OFFSET, h.offset);
            try nl.appendAttrBe32(gpa, list, NFTA_HASH.TYPE, @backingInt(h.kind));
        },
        .numgen => |n| {
            if (n.modulus == 0) return error.InvalidExpression;
            try nl.appendAttrBe32(gpa, list, NFTA_NG.DREG, @backingInt(n.dreg));
            try nl.appendAttrBe32(gpa, list, NFTA_NG.MODULUS, n.modulus);
            try nl.appendAttrBe32(gpa, list, NFTA_NG.TYPE, @backingInt(n.kind));
            try nl.appendAttrBe32(gpa, list, NFTA_NG.OFFSET, n.offset);
        },
        .range => |r| {
            try nl.appendAttrBe32(gpa, list, NFTA_RANGE.SREG, @backingInt(r.sreg));
            try nl.appendAttrBe32(gpa, list, NFTA_RANGE.OP, @backingInt(r.op));
            try appendData(gpa, list, NFTA_RANGE.FROM_DATA, .{ .value = r.from });
            try appendData(gpa, list, NFTA_RANGE.TO_DATA, .{ .value = r.to });
        },
        .rt => |r| {
            try nl.appendAttrBe32(gpa, list, NFTA_RT.KEY, r.key);
            try nl.appendAttrBe32(gpa, list, NFTA_RT.DREG, @backingInt(r.dreg));
        },
        .socket => |k| {
            try nl.appendAttrBe32(gpa, list, NFTA_SOCKET.KEY, k.key);
            try nl.appendAttrBe32(gpa, list, NFTA_SOCKET.DREG, @backingInt(k.dreg));
            try nl.appendAttrBe32(gpa, list, NFTA_SOCKET.LEVEL, k.level);
        },
        .notrack => unreachable,
        .dup => |d| {
            try nl.appendAttrBe32(gpa, list, NFTA_DUP.SREG_ADDR, @backingInt(d.sreg_addr));
            if (d.sreg_dev) |r| try nl.appendAttrBe32(gpa, list, NFTA_DUP.SREG_DEV, @backingInt(r));
        },
        .fwd => |f| {
            try nl.appendAttrBe32(gpa, list, NFTA_FWD.SREG_DEV, @backingInt(f.sreg_dev));
            if (f.sreg_addr) |r| {
                try nl.appendAttrBe32(gpa, list, NFTA_FWD.SREG_ADDR, @backingInt(r));
                try nl.appendAttrBe32(gpa, list, NFTA_FWD.NFPROTO, f.nfproto orelse return error.InvalidExpression);
            }
        },
        .tproxy => |t| {
            try nl.appendAttrBe32(gpa, list, NFTA_TPROXY.FAMILY, t.family);
            if (t.reg_addr) |r| try nl.appendAttrBe32(gpa, list, NFTA_TPROXY.REG_ADDR, @backingInt(r));
            if (t.reg_port) |r| try nl.appendAttrBe32(gpa, list, NFTA_TPROXY.REG_PORT, @backingInt(r));
        },
        .synproxy => |y| {
            try nl.appendAttrBe16(gpa, list, NFTA_SYNPROXY.MSS, y.mss);
            try nl.appendAttrU8(gpa, list, NFTA_SYNPROXY.WSCALE, y.wscale);
            try nl.appendAttrBe32(gpa, list, NFTA_SYNPROXY.FLAGS, y.flags);
        },
        .connlimit => |c| {
            try nl.appendAttrBe32(gpa, list, NFTA_CONNLIMIT.COUNT, c.count);
            try nl.appendAttrBe32(gpa, list, NFTA_CONNLIMIT.FLAGS, if (c.over) NFT_CONNLIMIT_F_INV else 0);
        },
        .dynset => |d| {
            try nl.appendAttrBe32(gpa, list, NFTA_DYNSET.SREG_KEY, @backingInt(d.sreg_key));
            if (d.sreg_data) |r| try nl.appendAttrBe32(gpa, list, NFTA_DYNSET.SREG_DATA, @backingInt(r));
            try nl.appendAttrBe32(gpa, list, NFTA_DYNSET.OP, @backingInt(d.op));
            if (d.timeout_ms) |t| try nl.appendAttrBe64(gpa, list, NFTA_DYNSET.TIMEOUT, t);
            try nl.appendAttrString(gpa, list, NFTA_DYNSET.SET_NAME, d.set);
            if (d.set_id) |id| try nl.appendAttrBe32(gpa, list, NFTA_DYNSET.SET_ID, id);
            var flags: u32 = if (d.invert) NFT_DYNSET_F_INV else 0;
            if (d.exprs.len > 1) flags |= NFT_DYNSET_F_EXPR;
            if (flags != 0) try nl.appendAttrBe32(gpa, list, NFTA_DYNSET.FLAGS, flags);
            if (d.exprs.len == 1) {
                // `NFTA_DYNSET_EXPR` holds ONE expression directly (name +
                // data), not a list element wrapper.
                const eoff = try nl.nestBegin(gpa, list, nl.NLA_F_NESTED | NFTA_DYNSET.EXPR);
                try appendExprBody(gpa, list, d.exprs[0]);
                try nl.nestEnd(list, eoff);
            } else if (d.exprs.len > 1) {
                const loff = try nl.nestBegin(gpa, list, nl.NLA_F_NESTED | NFTA_DYNSET.EXPRESSIONS);
                for (d.exprs) |sub| try appendExpr(gpa, list, sub);
                try nl.nestEnd(list, loff);
            }
        },
        .osf => |o| {
            try nl.appendAttrBe32(gpa, list, NFTA_OSF.DREG, @backingInt(o.dreg));
            try nl.appendAttrU8(gpa, list, NFTA_OSF.TTL, o.ttl);
            if (o.version) try nl.appendAttrBe32(gpa, list, NFTA_OSF.FLAGS, 1);
        },
        .ct_set => |c| {
            try nl.appendAttrBe32(gpa, list, NFTA_CT.KEY, c.key);
            if (c.dir) |d| try nl.appendAttrU8(gpa, list, NFTA_CT.DIRECTION, d.dir());
            try nl.appendAttrBe32(gpa, list, NFTA_CT.SREG, @backingInt(c.sreg));
        },
        .payload_set => |p| {
            try nl.appendAttrBe32(gpa, list, NFTA_PAYLOAD.SREG, @backingInt(p.sreg));
            try nl.appendAttrBe32(gpa, list, NFTA_PAYLOAD.BASE, p.base.base());
            try nl.appendAttrBe32(gpa, list, NFTA_PAYLOAD.OFFSET, p.offset);
            try nl.appendAttrBe32(gpa, list, NFTA_PAYLOAD.LEN, p.len);
            try nl.appendAttrBe32(gpa, list, NFTA_PAYLOAD.CSUM_TYPE, p.csum_type);
            try nl.appendAttrBe32(gpa, list, NFTA_PAYLOAD.CSUM_OFFSET, p.csum_offset);
            if (p.csum_flags != 0)
                try nl.appendAttrBe32(gpa, list, NFTA_PAYLOAD.CSUM_FLAGS, p.csum_flags);
        },
        .flow_offload => |f| try nl.appendAttrString(gpa, list, NFTA_FLOW_TABLE_NAME, f.table),
        .last => |l| {
            // `nft` sends MSECS before SET.
            try nl.appendAttrBe64(gpa, list, NFTA_LAST.MSECS, l.msecs);
            try nl.appendAttrBe32(gpa, list, NFTA_LAST.SET, if (l.set) 1 else 0);
        },
        .raw => |r| try list.appendSlice(gpa, r.data),
    }
    try nl.nestEnd(list, data);
    try nl.nestEnd(list, elem);
}

// ── decoding ────────────────────────────────────────────────────────────────

/// One expression as it came back from the kernel: its name and the raw bytes
/// of its `NFTA_EXPR_DATA` nest (walk them with `nl.AttrIterator`).
pub const ExprView = struct {
    name: []const u8,
    data: []const u8,

    pub fn attrs(v: ExprView) nl.AttrIterator {
        return .{ .buf = v.data };
    }
};

/// Walk the `NFTA_RULE_EXPRESSIONS` nest of a decoded rule.
pub const ExprIterator = struct {
    attrs: nl.AttrIterator,

    pub fn next(it: *ExprIterator) nl.Error!?ExprView {
        while (try it.attrs.next()) |elem| {
            var inner = elem.nested();
            var view: ExprView = .{ .name = "", .data = &.{} };
            while (try inner.next()) |a| switch (a.type) {
                NFTA_EXPR.NAME => view.name = a.asString(),
                NFTA_EXPR.DATA => view.data = a.data,
                else => {},
            };
            if (view.name.len == 0) continue; // not an expression element
            return view;
        }
        return null;
    }
};

/// Decode the verdict out of an `immediate` expression's data, or null when
/// the expression carries a value rather than a verdict.
pub fn decodeVerdict(data: []const u8) nl.Error!?struct { code: i32, chain: ?[]const u8 } {
    var it: nl.AttrIterator = .{ .buf = data };
    while (try it.next()) |a| {
        if (a.type != NFTA_IMMEDIATE.DATA) continue;
        var d = a.nested();
        while (try d.next()) |da| {
            if (da.type != NFTA_DATA.VERDICT) continue;
            var v = da.nested();
            var code: ?i32 = null;
            var chain: ?[]const u8 = null;
            while (try v.next()) |va| switch (va.type) {
                NFTA_VERDICT.CODE => code = @bitCast(try va.asBe32()),
                NFTA_VERDICT.CHAIN => chain = va.asString(),
                else => {},
            };
            if (code) |c| return .{ .code = c, .chain = chain };
        }
    }
    return null;
}

/// Decode a `counter` expression's data (`ExprView.data` of an expression
/// named `"counter"`): the packet and byte totals the kernel reports on a
/// rule dump. Null when the data carries neither attribute.
pub fn decodeCounter(data: []const u8) nl.Error!?struct { packets: u64, bytes: u64 } {
    var it: nl.AttrIterator = .{ .buf = data };
    var packets: ?u64 = null;
    var bytes: ?u64 = null;
    while (try it.next()) |a| switch (a.type) {
        NFTA_COUNTER.PACKETS => packets = try a.asBe64(),
        NFTA_COUNTER.BYTES => bytes = try a.asBe64(),
        else => {},
    };
    if (packets == null and bytes == null) return null;
    return .{ .packets = packets orelse 0, .bytes = bytes orelse 0 };
}

/// Typed view of one listed expression: the inverse of `appendExpr`.
///
/// Returns the `Expr` the module would have to send to produce it. Byte
/// slices and strings BORROW from `view.data` (nothing is allocated), so the
/// result lives as long as the reply the view came from. An expression whose
/// name this module does not model, or whose attributes carry a value the
/// typed model cannot name (an unknown `meta` key, an `nft_payload_bases`
/// value past the transport header, a `limit` that is not a whole number of
/// packets or bytes per `LimitPer`, a bitwise boolean operator, …) comes
/// back as `.raw` with its name and untouched data, never as an error and
/// never as a wrong typed value. Malformed lengths are `error.Truncated` /
/// `error.BadLength` like every other decoder here.
pub fn decodeExpr(view: ExprView) nl.Error!Expr {
    const raw: Expr = .{ .raw = .{ .name = view.name, .data = view.data } };
    var at: Attrs = .{};
    try at.collect(view.data);
    const n = view.name;
    if (eq(n, "payload")) {
        const base_raw = (try at.g32(NFTA_PAYLOAD.BASE)) orelse return raw;
        const base = enumOf(types.PayloadBase, base_raw, PayloadBaseKey) orelse return raw;
        const off = (try at.g32(NFTA_PAYLOAD.OFFSET)) orelse return raw;
        const len = (try at.g32(NFTA_PAYLOAD.LEN)) orelse return raw;
        if (try at.reg(NFTA_PAYLOAD.DREG)) |d| return .{ .payload_load = .{ .base = base, .offset = off, .len = len, .dreg = d } };
        const sreg = (try at.reg(NFTA_PAYLOAD.SREG)) orelse return raw;
        return .{ .payload_set = .{
            .base = base,
            .offset = off,
            .len = len,
            .sreg = sreg,
            .csum_type = (try at.g32(NFTA_PAYLOAD.CSUM_TYPE)) orelse 0,
            .csum_offset = (try at.g32(NFTA_PAYLOAD.CSUM_OFFSET)) orelse 0,
            .csum_flags = (try at.g32(NFTA_PAYLOAD.CSUM_FLAGS)) orelse 0,
        } };
    }
    if (eq(n, "meta")) {
        const key = (try at.g32(NFTA_META.KEY)) orelse return raw;
        const mk = types.MetaKey.fromKey(key) orelse return raw;
        if (try at.reg(NFTA_META.DREG)) |d| return .{ .meta_load = .{ .key = mk, .dreg = d } };
        if (try at.reg(NFTA_META.SREG)) |r| return .{ .meta_set = .{ .key = mk, .sreg = r } };
        return raw;
    }
    if (eq(n, "ct")) {
        const key = (try at.g32(NFTA_CT.KEY)) orelse return raw;
        var dir: ?CtDir = null;
        if (try at.g8(NFTA_CT.DIRECTION)) |d| dir = enumOf(CtDir, d, CtDirKey) orelse return raw;
        if (try at.reg(NFTA_CT.DREG)) |d| return .{ .ct_load = .{ .key = key, .dir = dir, .dreg = d } };
        if (try at.reg(NFTA_CT.SREG)) |r| return .{ .ct_set = .{ .key = key, .dir = dir, .sreg = r } };
        return raw;
    }
    if (eq(n, "cmp")) {
        const sreg = (try at.reg(NFTA_CMP.SREG)) orelse return raw;
        const op = (try at.g32(NFTA_CMP.OP)) orelse return raw;
        const d = (try at.data(NFTA_CMP.DATA)) orelse return raw;
        return .{ .cmp = .{ .sreg = sreg, .op = op, .data = d } };
    }
    if (eq(n, "bitwise")) {
        const sreg = (try at.reg(NFTA_BITWISE.SREG)) orelse return raw;
        const dreg = (try at.reg(NFTA_BITWISE.DREG)) orelse return raw;
        const len = (try at.g32(NFTA_BITWISE.LEN)) orelse return raw;
        const op_attr = try at.g32(NFTA_BITWISE.OP);
        const op = op_attr orelse 0;
        if (op == 0) {
            const mask = (try at.value(NFTA_BITWISE.MASK)) orelse return raw;
            const xor = (try at.value(NFTA_BITWISE.XOR)) orelse return raw;
            if (mask.len != len or xor.len != len) return raw;
            return .{ .bitwise = .{ .sreg = sreg, .dreg = dreg, .len = len, .mask = mask, .xor = xor, .explicit_op = op_attr != null } };
        }
        if (op == 1 or op == 2) {
            const amt = (try at.value(NFTA_BITWISE.DATA)) orelse return raw;
            if (amt.len != 4) return raw;
            return .{ .bitshift = .{
                .sreg = sreg,
                .dreg = dreg,
                .len = len,
                .dir = if (op == 1) .left else .right,
                .amount = std.mem.readInt(u32, amt[0..4], builtin.cpu.arch.endian()),
            } };
        }
        return raw;
    }
    if (eq(n, "lookup")) {
        const set = at.str(NFTA_LOOKUP.SET) orelse return raw;
        const sreg = (try at.reg(NFTA_LOOKUP.SREG)) orelse return raw;
        const flags = (try at.g32(NFTA_LOOKUP.FLAGS)) orelse 0;
        return .{ .lookup = .{
            .set = set,
            .sreg = sreg,
            .dreg = try at.reg(NFTA_LOOKUP.DREG),
            .set_id = try at.g32(NFTA_LOOKUP.SET_ID),
            .invert = flags & NFT_LOOKUP_F_INV != 0,
        } };
    }
    if (eq(n, "counter")) {
        const c = (try decodeCounter(view.data)) orelse return .{ .counter = .{} };
        return .{ .counter = .{ .packets = c.packets, .bytes = c.bytes } };
    }
    if (eq(n, "immediate")) {
        const dreg = (try at.reg(NFTA_IMMEDIATE.DREG)) orelse return raw;
        const d = (try at.data(NFTA_IMMEDIATE.DATA)) orelse return raw;
        return .{ .immediate = .{ .dreg = dreg, .data = d } };
    }
    if (eq(n, "limit")) {
        const rate = (try at.g64(NFTA_LIMIT.RATE)) orelse return raw;
        const unit_secs = (try at.g64(NFTA_LIMIT.UNIT)) orelse return raw;
        const per = enumOf(LimitPer, unit_secs, LimitPerKey) orelse return raw;
        const ty = (try at.g32(NFTA_LIMIT.TYPE)) orelse 0;
        const flags = (try at.g32(NFTA_LIMIT.FLAGS)) orelse 0;
        if (ty > 1) return raw;
        return .{ .limit = .{
            .rate = rate,
            .per = per,
            .burst = (try at.g32(NFTA_LIMIT.BURST)) orelse 0,
            .unit = if (ty == 0) .packets else .bytes,
            .inv = flags & NFT_LIMIT_F_INV != 0,
        } };
    }
    if (eq(n, "log")) {
        var lvl: ?LogLevel = null;
        if (try at.g32(NFTA_LOG.LEVEL)) |l| lvl = enumOf(LogLevel, l, LogLevelKey) orelse return raw;
        return .{ .log = .{
            .prefix = at.str(NFTA_LOG.PREFIX),
            .group = if (try at.g16(NFTA_LOG.GROUP)) |v| @as(u32, v) else null,
            .snaplen = try at.g32(NFTA_LOG.SNAPLEN),
            .qthreshold = if (try at.g16(NFTA_LOG.QTHRESHOLD)) |v| @as(u32, v) else null,
            .level = lvl,
            .flags = try at.g32(NFTA_LOG.FLAGS),
        } };
    }
    if (eq(n, "nat")) {
        return .{ .nat = .{
            .kind = (try at.g32(NFTA_NAT.TYPE)) orelse return raw,
            .family = std.math.cast(u8, (try at.g32(NFTA_NAT.FAMILY)) orelse return raw) orelse return raw,
            .reg_addr_min = try at.reg(NFTA_NAT.REG_ADDR_MIN),
            .reg_addr_max = try at.reg(NFTA_NAT.REG_ADDR_MAX),
            .reg_proto_min = try at.reg(NFTA_NAT.REG_PROTO_MIN),
            .reg_proto_max = try at.reg(NFTA_NAT.REG_PROTO_MAX),
            .flags = (try at.g32(NFTA_NAT.FLAGS)) orelse 0,
        } };
    }
    if (eq(n, "masq")) return .{ .masq = .{
        .flags = (try at.g32(NFTA_MASQ.FLAGS)) orelse 0,
        .reg_proto_min = try at.reg(NFTA_MASQ.REG_PROTO_MIN),
        .reg_proto_max = try at.reg(NFTA_MASQ.REG_PROTO_MAX),
    } };
    if (eq(n, "reject")) return .{ .reject = .{
        .type = (try at.g32(NFTA_REJECT.TYPE)) orelse return raw,
        .icmp_code = (try at.g8(NFTA_REJECT.ICMP_CODE)) orelse 0,
    } };
    if (eq(n, "queue")) return .{ .queue = .{
        .num = (try at.g16(NFTA_QUEUE.NUM)) orelse 0,
        .total = (try at.g16(NFTA_QUEUE.TOTAL)) orelse 1,
        .flags = (try at.g16(NFTA_QUEUE.FLAGS)) orelse 0,
    } };
    if (eq(n, "redir")) return .{ .redir = .{
        .reg_proto_min = try at.reg(NFTA_REDIR.REG_PROTO_MIN),
        .reg_proto_max = try at.reg(NFTA_REDIR.REG_PROTO_MAX),
        .flags = (try at.g32(NFTA_REDIR.FLAGS)) orelse 0,
    } };
    if (eq(n, "quota")) return .{ .quota = .{
        .bytes = (try at.g64(NFTA_QUOTA.BYTES)) orelse return raw,
        .consumed = (try at.g64(NFTA_QUOTA.CONSUMED)) orelse 0,
        .over = ((try at.g32(NFTA_QUOTA.FLAGS)) orelse 0) & NFT_QUOTA_F_INV != 0,
    } };
    if (eq(n, "objref")) {
        const name_attr = at.raw(NFTA_OBJREF.IMM_NAME) orelse return raw;
        const t = (try at.g32(NFTA_OBJREF.IMM_TYPE)) orelse return raw;
        // `nft` sends the name without a NUL; a kernel dump may carry one.
        var nm = name_attr.data;
        if (nm.len > 0 and nm[nm.len - 1] == 0) nm = nm[0 .. nm.len - 1];
        return .{ .objref = .{ .obj_type = @fromBackingInt(@intCast(t)), .name = nm } };
    }
    if (eq(n, "byteorder")) return .{ .byteorder = .{
        .sreg = (try at.reg(NFTA_BYTEORDER.SREG)) orelse return raw,
        .dreg = (try at.reg(NFTA_BYTEORDER.DREG)) orelse return raw,
        .op = enumOfRaw(ByteorderOp, (try at.g32(NFTA_BYTEORDER.OP)) orelse return raw) orelse return raw,
        .len = (try at.g32(NFTA_BYTEORDER.LEN)) orelse return raw,
        .size = (try at.g32(NFTA_BYTEORDER.SIZE)) orelse return raw,
    } };
    if (eq(n, "exthdr")) {
        const ty = (try at.g8(NFTA_EXTHDR.TYPE)) orelse return raw;
        const dreg = try at.reg(NFTA_EXTHDR.DREG);
        const sreg = try at.reg(NFTA_EXTHDR.SREG);
        if ((dreg == null) == (sreg == null)) return raw;
        return .{ .exthdr = .{
            .op = @fromBackingInt(@intCast((try at.g32(NFTA_EXTHDR.OP)) orelse 0)),
            .hdr_type = ty,
            .offset = (try at.g32(NFTA_EXTHDR.OFFSET)) orelse return raw,
            .len = (try at.g32(NFTA_EXTHDR.LEN)) orelse return raw,
            .present = ((try at.g32(NFTA_EXTHDR.FLAGS)) orelse 0) & NFT_EXTHDR_F_PRESENT != 0,
            .dreg = dreg,
            .sreg = sreg,
        } };
    }
    if (eq(n, "fib")) return .{ .fib = .{
        .dreg = (try at.reg(NFTA_FIB.DREG)) orelse return raw,
        .result = (try at.g32(NFTA_FIB.RESULT)) orelse return raw,
        .flags = (try at.g32(NFTA_FIB.FLAGS)) orelse return raw,
    } };
    if (eq(n, "hash")) return .{ .hash = .{
        .kind = enumOfRaw(HashKind, (try at.g32(NFTA_HASH.TYPE)) orelse 0) orelse return raw,
        .dreg = (try at.reg(NFTA_HASH.DREG)) orelse return raw,
        .sreg = try at.reg(NFTA_HASH.SREG),
        .len = (try at.g32(NFTA_HASH.LEN)) orelse 0,
        .modulus = (try at.g32(NFTA_HASH.MODULUS)) orelse return raw,
        .seed = (try at.g32(NFTA_HASH.SEED)) orelse 0,
        .offset = (try at.g32(NFTA_HASH.OFFSET)) orelse 0,
    } };
    if (eq(n, "numgen")) return .{ .numgen = .{
        .dreg = (try at.reg(NFTA_NG.DREG)) orelse return raw,
        .kind = enumOfRaw(NumgenKind, (try at.g32(NFTA_NG.TYPE)) orelse return raw) orelse return raw,
        .modulus = (try at.g32(NFTA_NG.MODULUS)) orelse return raw,
        .offset = (try at.g32(NFTA_NG.OFFSET)) orelse 0,
    } };
    if (eq(n, "range")) return .{ .range = .{
        .sreg = (try at.reg(NFTA_RANGE.SREG)) orelse return raw,
        .op = enumOfRaw(RangeOp, (try at.g32(NFTA_RANGE.OP)) orelse return raw) orelse return raw,
        .from = (try at.value(NFTA_RANGE.FROM_DATA)) orelse return raw,
        .to = (try at.value(NFTA_RANGE.TO_DATA)) orelse return raw,
    } };
    if (eq(n, "rt")) return .{ .rt = .{
        .key = (try at.g32(NFTA_RT.KEY)) orelse return raw,
        .dreg = (try at.reg(NFTA_RT.DREG)) orelse return raw,
    } };
    if (eq(n, "socket")) return .{ .socket = .{
        .key = (try at.g32(NFTA_SOCKET.KEY)) orelse return raw,
        .dreg = (try at.reg(NFTA_SOCKET.DREG)) orelse return raw,
        .level = (try at.g32(NFTA_SOCKET.LEVEL)) orelse 0,
    } };
    if (eq(n, "notrack")) return .notrack;
    if (eq(n, "dup")) return .{ .dup = .{
        .sreg_addr = (try at.reg(NFTA_DUP.SREG_ADDR)) orelse return raw,
        .sreg_dev = try at.reg(NFTA_DUP.SREG_DEV),
    } };
    if (eq(n, "fwd")) return .{ .fwd = .{
        .sreg_dev = (try at.reg(NFTA_FWD.SREG_DEV)) orelse return raw,
        .sreg_addr = try at.reg(NFTA_FWD.SREG_ADDR),
        .nfproto = try at.g32(NFTA_FWD.NFPROTO),
    } };
    if (eq(n, "tproxy")) return .{ .tproxy = .{
        .family = std.math.cast(u8, (try at.g32(NFTA_TPROXY.FAMILY)) orelse return raw) orelse return raw,
        .reg_addr = try at.reg(NFTA_TPROXY.REG_ADDR),
        .reg_port = try at.reg(NFTA_TPROXY.REG_PORT),
    } };
    if (eq(n, "synproxy")) return .{ .synproxy = .{
        .mss = (try at.g16(NFTA_SYNPROXY.MSS)) orelse 0,
        .wscale = (try at.g8(NFTA_SYNPROXY.WSCALE)) orelse 0,
        .flags = (try at.g32(NFTA_SYNPROXY.FLAGS)) orelse 0,
    } };
    if (eq(n, "connlimit")) return .{ .connlimit = .{
        .count = (try at.g32(NFTA_CONNLIMIT.COUNT)) orelse return raw,
        .over = ((try at.g32(NFTA_CONNLIMIT.FLAGS)) orelse 0) & NFT_CONNLIMIT_F_INV != 0,
    } };
    if (eq(n, "osf")) return .{ .osf = .{
        .dreg = (try at.reg(NFTA_OSF.DREG)) orelse return raw,
        .ttl = (try at.g8(NFTA_OSF.TTL)) orelse 0,
        .version = ((try at.g32(NFTA_OSF.FLAGS)) orelse 0) & 1 != 0,
    } };
    if (eq(n, "last")) return .{ .last = .{
        .msecs = (try at.g64(NFTA_LAST.MSECS)) orelse 0,
        .set = ((try at.g32(NFTA_LAST.SET)) orelse 0) != 0,
    } };
    if (eq(n, "flow_offload")) return .{ .flow_offload = .{
        .table = at.str(NFTA_FLOW_TABLE_NAME) orelse return raw,
    } };
    // `dynset` carries nested expressions, which would need an allocator to
    // return typed: it stays `.raw` here (walk `NFTA_DYNSET_EXPR` with
    // `ExprView` yourself).
    return raw;
}

fn eq(a: []const u8, comptime b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn PayloadBaseKey(v: types.PayloadBase) u64 {
    return v.base();
}
fn CtDirKey(v: CtDir) u64 {
    return v.dir();
}
fn LimitPerKey(v: LimitPer) u64 {
    return v.seconds();
}
fn LogLevelKey(v: LogLevel) u64 {
    return v.level();
}

fn enumOf(comptime E: type, v: u64, comptime key: fn (E) u64) ?E {
    inline for (@typeInfo(E).@"enum".field_values) |fv| {
        const m: E = @fromBackingInt(fv);
        if (key(m) == v) return m;
    }
    return null;
}

/// The member of the enum `E` that is `value`, if any (for the enums that
/// map one-to-one onto the kernel's numbers).
fn enumOfRaw(comptime E: type, value: u32) ?E {
    inline for (@typeInfo(E).@"enum".field_values) |fv| {
        if (fv == value) return @fromBackingInt(fv);
    }
    return null;
}

/// Collected top-level attributes of one expression, indexed by type.
const Attrs = struct {
    slots: [16]?nl.Attr = @splat(null),

    fn collect(self: *Attrs, buf: []const u8) nl.Error!void {
        var it: nl.AttrIterator = .{ .buf = buf };
        while (try it.next()) |a| {
            if (a.type < self.slots.len) self.slots[a.type] = a;
        }
    }
    fn raw(self: *const Attrs, t: u16) ?nl.Attr {
        return self.slots[t];
    }
    fn g8(self: *const Attrs, t: u16) nl.Error!?u8 {
        return if (self.slots[t]) |a| try a.asU8() else null;
    }
    fn g16(self: *const Attrs, t: u16) nl.Error!?u16 {
        return if (self.slots[t]) |a| try a.asBe16() else null;
    }
    fn g32(self: *const Attrs, t: u16) nl.Error!?u32 {
        return if (self.slots[t]) |a| try a.asBe32() else null;
    }
    fn g64(self: *const Attrs, t: u16) nl.Error!?u64 {
        return if (self.slots[t]) |a| try a.asBe64() else null;
    }
    fn reg(self: *const Attrs, t: u16) nl.Error!?Reg {
        return if (try self.g32(t)) |v| @as(Reg, @fromBackingInt(@intCast(v))) else null;
    }
    fn str(self: *const Attrs, t: u16) ?[]const u8 {
        return if (self.slots[t]) |a| a.asString() else null;
    }
    /// A nested `NFTA_DATA` holding `NFTA_DATA_VALUE`.
    fn value(self: *const Attrs, t: u16) nl.Error!?[]const u8 {
        const a = self.slots[t] orelse return null;
        var it = a.nested();
        while (try it.next()) |x| if (x.type == NFTA_DATA.VALUE) return x.data;
        return null;
    }
    /// A nested `NFTA_DATA`: a value or a verdict.
    fn data(self: *const Attrs, t: u16) nl.Error!?Data {
        const a = self.slots[t] orelse return null;
        var it = a.nested();
        while (try it.next()) |x| switch (x.type) {
            NFTA_DATA.VALUE => return .{ .value = x.data },
            NFTA_DATA.VERDICT => {
                var v = x.nested();
                var code: ?i32 = null;
                var chain: ?[]const u8 = null;
                while (try v.next()) |va| switch (va.type) {
                    NFTA_VERDICT.CODE => code = @bitCast(try va.asBe32()),
                    NFTA_VERDICT.CHAIN => chain = va.asString(),
                    else => {},
                };
                return .{ .verdict = .{ .code = code orelse return null, .chain = chain } };
            },
            else => {},
        };
        return null;
    }
};

// ── value helpers ───────────────────────────────────────────────────────────

/// A 2-byte network-order port, ready for a `cmp` against a payload load.
pub fn portBytes(p: u16) [2]u8 {
    var out: [2]u8 = undefined;
    std.mem.writeInt(u16, &out, p, .big);
    return out;
}

/// A 4-byte IPv4 address in wire order.
pub fn ipv4Bytes(a: u8, b: u8, c: u8, d: u8) [4]u8 {
    return .{ a, b, c, d };
}

/// The 4-byte network mask of an IPv4 prefix length, in wire order.
///
/// ⚠ `prefix_len` is a `u6` because no integer type spells 0..32, so the
/// out-of-range half has to be REFUSED rather than typed away. It used to be
/// computed anyway: `/33` shifted by `32 - 33` — a panic in Debug, and in
/// ReleaseFast a shift by 63 that produced `80000000`, the mask of a `/1`,
/// silently widening a rule from one host to half the internet. `ipPrefix`
/// has always guarded this; the public helper beside it did not (audit
/// 2026-09-02).
pub fn ipv4MaskBytes(prefix_len: u6) error{InvalidPrefixLength}![4]u8 {
    if (prefix_len > 32) return error.InvalidPrefixLength;
    var out: [4]u8 = undefined;
    const bits: u32 = if (prefix_len == 0)
        0
    else
        ~@as(u32, 0) << @intCast(32 - @as(u32, prefix_len));
    std.mem.writeInt(u32, &out, bits, .big);
    return out;
}

/// The 16-byte network mask of an IPv6 prefix length, in wire order.
/// `prefix_len` above 128 is refused, for the reason `ipv4MaskBytes` gives.
pub fn ipv6MaskBytes(prefix_len: u8) error{InvalidPrefixLength}![16]u8 {
    if (prefix_len > 128) return error.InvalidPrefixLength;
    var out: [16]u8 = @splat(0);
    const full: usize = prefix_len / 8;
    @memset(out[0..full], 0xff);
    const rem: u3 = @intCast(prefix_len % 8);
    if (rem != 0) out[full] = @as(u8, 0xff) << @intCast(8 - @as(u4, rem));
    return out;
}

/// A register-resident 32-bit value. Registers hold **host** byte order —
/// this is what `meta mark`, `ct state` and friends compare against, and it is
/// deliberately not the big-endian encoding used for attribute *integers*.
pub fn regU32(v: u32) [4]u8 {
    var out: [4]u8 = undefined;
    std.mem.writeInt(u32, &out, v, builtin.cpu.arch.endian());
    return out;
}

/// An interface name padded to `IFNAMSIZ` — the width `meta iifname`/`oifname`
/// loads and therefore the width its `cmp` must carry.
///
/// ⚠ A name that does not fit is an ERROR, not something to trim. It used to
/// be trimmed (`@min(name.len, 16)`), which built a rule comparing against the
/// first 16 bytes of the name — and since no Linux interface can be named
/// those 16 bytes, a `drop` built that way never fired. Fail-open, from a
/// silent success. `nft(8)` refuses the same input: "String exceeds maximum
/// length of 16" (measured: 15 accepted, 16 and 17 refused — the 16th byte is
/// the NUL). Audit 2026-09-02.
pub fn ifnameBytes(name: []const u8) error{InterfaceNameTooLong}![16]u8 {
    var out: [16]u8 = @splat(0);
    if (name.len >= out.len) return error.InterfaceNameTooLong;
    @memcpy(out[0..name.len], name);
    return out;
}

// ── the program builder ─────────────────────────────────────────────────────

/// An ordered list of expressions for one rule, with the register discipline
/// applied. Byte slices handed to the high-level helpers are copied into the
/// program's arena, so temporaries are safe; `push` borrows.
///
/// Errors are **latched**: a failing helper records the error and the chain
/// keeps type-checking, so a whole rule reads as one expression. `finish()`
/// reports it.
pub const Program = struct {
    arena: std.heap.ArenaAllocator,
    family: Family,
    items: std.ArrayList(Expr) = .empty,
    regs: RegAlloc = .{},
    latched: ?BuildError = null,

    /// `family` is the *table's* family: it decides whether a layer-3 match
    /// needs a preceding `meta nfproto` dependency (it does in `inet`, it does
    /// not in `ip`/`ip6` — verified against the captures).
    pub fn init(gpa: std.mem.Allocator, family: Family) Program {
        return .{ .arena = std.heap.ArenaAllocator.init(gpa), .family = family };
    }

    pub fn deinit(p: *Program) void {
        p.arena.deinit();
        p.* = undefined;
    }

    fn alloc(p: *Program) std.mem.Allocator {
        return p.arena.allocator();
    }

    fn fail(p: *Program, err: BuildError) *Program {
        if (p.latched == null) p.latched = err;
        return p;
    }

    fn dupe(p: *Program, bytes: []const u8) ?[]const u8 {
        return p.alloc().dupe(u8, bytes) catch {
            _ = p.fail(error.OutOfMemory);
            return null;
        };
    }

    /// Append a pre-built expression verbatim. Does not touch the register
    /// allocator and does not copy `Expr`'s slices — the caller owns both.
    pub fn push(p: *Program, e: Expr) *Program {
        p.items.append(p.alloc(), e) catch return p.fail(error.OutOfMemory);
        return p;
    }

    /// The finished expression list, or the first latched error.
    pub fn finish(p: *Program) BuildError![]const Expr {
        if (p.latched) |err| return err;
        return p.items.items;
    }

    // ── loads + comparisons ────────────────────────────────────────────────

    /// `payload(base, offset, len) <op> value` — one complete match sequence.
    /// Resets the register allocator first (see the register model).
    pub fn payloadCmp(
        p: *Program,
        base: PayloadBase,
        offset: u32,
        len: u32,
        op: Op,
        value: []const u8,
    ) *Program {
        if (value.len != len) return p.fail(error.ValueWidthMismatch);
        if (len > max_value_len) return p.fail(error.ValueWidthMismatch);
        const cmp_op = op.cmpOp() orelse return p.fail(error.UnsupportedOperator);
        p.regs.reset();
        const reg = p.regs.alloc() catch |e| return p.fail(e);
        const v = p.dupe(value) orelse return p;
        _ = p.push(.{ .payload_load = .{ .base = base, .offset = offset, .len = len, .dreg = reg } });
        return p.push(.{ .cmp = .{ .sreg = reg, .op = cmp_op, .data = .{ .value = v } } });
    }

    /// `payload(base, offset, len) & mask <op> value` — the shape a CIDR match
    /// takes whenever the prefix is not a whole number of bytes.
    pub fn payloadMaskedCmp(
        p: *Program,
        base: PayloadBase,
        offset: u32,
        len: u32,
        mask: []const u8,
        op: Op,
        value: []const u8,
    ) *Program {
        if (value.len != len or mask.len != len) return p.fail(error.ValueWidthMismatch);
        if (len > max_value_len) return p.fail(error.ValueWidthMismatch);
        const cmp_op = op.cmpOp() orelse return p.fail(error.UnsupportedOperator);
        p.regs.reset();
        const reg = p.regs.alloc() catch |e| return p.fail(e);
        const m = p.dupe(mask) orelse return p;
        const z = p.alloc().alloc(u8, len) catch return p.fail(error.OutOfMemory);
        @memset(z, 0);
        const v = p.dupe(value) orelse return p;
        _ = p.push(.{ .payload_load = .{ .base = base, .offset = offset, .len = len, .dreg = reg } });
        _ = p.push(.{ .bitwise = .{ .sreg = reg, .dreg = reg, .len = len, .mask = m, .xor = z } });
        return p.push(.{ .cmp = .{ .sreg = reg, .op = cmp_op, .data = .{ .value = v } } });
    }

    /// `meta <key> <op> value`. `value` must be `key.width()` bytes wide.
    pub fn metaCmp(p: *Program, key: MetaKey, op: Op, value: []const u8) *Program {
        if (value.len != key.width()) return p.fail(error.ValueWidthMismatch);
        const cmp_op = op.cmpOp() orelse return p.fail(error.UnsupportedOperator);
        p.regs.reset();
        const reg = p.regs.alloc() catch |e| return p.fail(e);
        const v = p.dupe(value) orelse return p;
        _ = p.push(.{ .meta_load = .{ .key = key, .dreg = reg } });
        return p.push(.{ .cmp = .{ .sreg = reg, .op = cmp_op, .data = .{ .value = v } } });
    }

    /// `iifname "name"` / `oifname "name"` — the `IFNAMSIZ`-padded form.
    pub fn ifnameCmp(p: *Program, key: MetaKey, op: Op, name: []const u8) *Program {
        const padded = ifnameBytes(name) catch |e| return p.fail(e);
        return p.metaCmp(key, op, &padded);
    }

    /// `ct state & mask != 0` — the exact shape `nft` emits for
    /// `ct state established,related` (load, mask, compare-not-equal-zero).
    pub fn ctStateAny(p: *Program, mask: u32) *Program {
        p.regs.reset();
        const reg = p.regs.alloc() catch |e| return p.fail(e);
        const m = p.dupe(&regU32(mask)) orelse return p;
        const zero = p.dupe(&regU32(0)) orelse return p;
        const xor = p.dupe(&regU32(0)) orelse return p;
        _ = p.push(.{ .ct_load = .{ .key = NFT_CT.STATE, .dreg = reg } });
        _ = p.push(.{ .bitwise = .{ .sreg = reg, .dreg = reg, .len = 4, .mask = m, .xor = xor } });
        return p.push(.{ .cmp = .{
            .sreg = reg,
            .op = Op.ne.cmpOp().?,
            .data = .{ .value = zero },
        } });
    }

    /// `payload(base, offset, len) @set` — a set lookup instead of a `cmp`.
    /// `set_id` is only needed when the set is created in the same batch; the
    /// kernel resolves the name first and only falls back to the id.
    pub fn payloadLookup(
        p: *Program,
        base: PayloadBase,
        offset: u32,
        len: u32,
        set: []const u8,
        set_id: ?u32,
        invert: bool,
    ) *Program {
        // The same bound its two siblings got when the 2026-08-11 audit's F3
        // was fixed -- `payloadCmp` and `payloadMaskedCmp` were bounded, this
        // one was left out of the fix set, and a `len` past a register's width
        // went to the kernel to be refused there (audit 2026-09-02).
        if (len > max_value_len) return p.fail(error.ValueWidthMismatch);
        p.regs.reset();
        const reg = p.regs.alloc() catch |e| return p.fail(e);
        const s = p.dupe(set) orelse return p;
        _ = p.push(.{ .payload_load = .{ .base = base, .offset = offset, .len = len, .dreg = reg } });
        return p.push(.{ .lookup = .{
            .set = s,
            .sreg = reg,
            .set_id = set_id,
            .invert = invert,
        } });
    }

    // ── protocol conveniences ──────────────────────────────────────────────

    /// The `meta l4proto` dependency `nft` inserts before any transport-header
    /// match. Emitted in every family (verified in both `inet` and `ip`).
    pub fn l4proto(p: *Program, proto: u8) *Program {
        return p.metaCmp(.l4proto, .eq, &.{proto});
    }

    /// The `meta nfproto` dependency an `inet` table needs before a
    /// network-header match; a no-op in the single-family tables.
    pub fn nfprotoDep(p: *Program, want: Family) *Program {
        if (p.family != .inet) return p;
        return p.metaCmp(.nfproto, .eq, &.{want.nfproto()});
    }

    /// `tcp dport <port>` including the `meta l4proto tcp` dependency.
    pub fn tcpDport(p: *Program, dport: u16) *Program {
        _ = p.l4proto(IPPROTO.TCP);
        return p.payloadCmp(.th, 2, 2, .eq, &portBytes(dport));
    }

    /// `tcp sport <port>`.
    pub fn tcpSport(p: *Program, sport: u16) *Program {
        _ = p.l4proto(IPPROTO.TCP);
        return p.payloadCmp(.th, 0, 2, .eq, &portBytes(sport));
    }

    /// `udp dport <port>`.
    pub fn udpDport(p: *Program, dport: u16) *Program {
        _ = p.l4proto(IPPROTO.UDP);
        return p.payloadCmp(.th, 2, 2, .eq, &portBytes(dport));
    }

    /// `ip saddr <a.b.c.d>` (offset 12, 4 bytes into the network header).
    pub fn ipSaddr(p: *Program, addr: [4]u8) *Program {
        _ = p.nfprotoDep(.ip);
        return p.payloadCmp(.nh, 12, 4, .eq, &addr);
    }

    /// `ip daddr <a.b.c.d>`.
    pub fn ipDaddr(p: *Program, addr: [4]u8) *Program {
        _ = p.nfprotoDep(.ip);
        return p.payloadCmp(.nh, 16, 4, .eq, &addr);
    }

    /// `ip saddr <a.b.c.d>/<len>`.
    ///
    /// A byte-aligned prefix needs no `bitwise` — `nft` shortens the payload
    /// load to the covered bytes instead, and this does too, byte for byte.
    pub fn ipSaddrPrefix(p: *Program, addr: [4]u8, prefix_len: u6) *Program {
        return p.ipPrefix(12, addr, prefix_len);
    }

    /// `ip daddr <a.b.c.d>/<len>`.
    pub fn ipDaddrPrefix(p: *Program, addr: [4]u8, prefix_len: u6) *Program {
        return p.ipPrefix(16, addr, prefix_len);
    }

    fn ipPrefix(p: *Program, offset: u32, addr: [4]u8, prefix_len: u6) *Program {
        if (prefix_len > 32) return p.fail(error.ValueWidthMismatch);
        _ = p.nfprotoDep(.ip);
        if (prefix_len % 8 == 0) {
            const n: u32 = @as(u32, prefix_len) / 8;
            if (n == 0) return p; // /0 matches everything
            return p.payloadCmp(.nh, offset, n, .eq, addr[0..n]);
        }
        const mask = ipv4MaskBytes(prefix_len) catch |e| return p.fail(e);
        var masked: [4]u8 = undefined;
        for (&masked, addr, mask) |*m, a, k| m.* = a & k;
        return p.payloadMaskedCmp(.nh, offset, 4, &mask, .eq, &masked);
    }

    /// `ip6 saddr <addr>` (offset 8, 16 bytes into the IPv6 header — RFC 8200
    /// §3: 4 bytes version/class/label, 2 payload length, 1 next header,
    /// 1 hop limit). Emits `meta nfproto ipv6` in an `inet` table.
    pub fn ip6Saddr(p: *Program, addr: [16]u8) *Program {
        _ = p.nfprotoDep(.ip6);
        return p.payloadCmp(.nh, 8, 16, .eq, &addr);
    }

    /// `ip6 daddr <addr>` (offset 24 = 8 + the 16-byte source address).
    pub fn ip6Daddr(p: *Program, addr: [16]u8) *Program {
        _ = p.nfprotoDep(.ip6);
        return p.payloadCmp(.nh, 24, 16, .eq, &addr);
    }

    /// `ip6 saddr <addr>/<len>` — byte-aligned prefixes shorten the load,
    /// others load all 16 bytes and mask, exactly as `ip saddr` does (both
    /// shapes captured: `/32` and `/33`).
    pub fn ip6SaddrPrefix(p: *Program, addr: [16]u8, prefix_len: u8) *Program {
        return p.ip6Prefix(8, addr, prefix_len);
    }

    /// `ip6 daddr <addr>/<len>`.
    pub fn ip6DaddrPrefix(p: *Program, addr: [16]u8, prefix_len: u8) *Program {
        return p.ip6Prefix(24, addr, prefix_len);
    }

    fn ip6Prefix(p: *Program, offset: u32, addr: [16]u8, prefix_len: u8) *Program {
        const mask = ipv6MaskBytes(prefix_len) catch |e| return p.fail(e);
        _ = p.nfprotoDep(.ip6);
        if (prefix_len % 8 == 0) {
            const n: u32 = prefix_len / 8;
            if (n == 0) return p; // /0 matches everything
            return p.payloadCmp(.nh, offset, n, .eq, addr[0..n]);
        }
        var masked: [16]u8 = undefined;
        for (&masked, addr, mask) |*m, a, k| m.* = a & k;
        return p.payloadMaskedCmp(.nh, offset, 16, &mask, .eq, &masked);
    }

    /// `ip saddr @set`.
    pub fn ipSaddrSet(p: *Program, set: []const u8, set_id: ?u32, invert: bool) *Program {
        _ = p.nfprotoDep(.ip);
        return p.payloadLookup(.nh, 12, 4, set, set_id, invert);
    }

    // ── statements ─────────────────────────────────────────────────────────

    pub fn counter(p: *Program) *Program {
        return p.push(.{ .counter = .{} });
    }

    pub fn verdict(p: *Program, v: Verdict) *Program {
        const owned: Verdict = if (v.chain) |c| .{
            .code = v.code,
            .chain = p.dupe(c) orelse return p,
        } else v;
        return p.push(.{ .immediate = .{ .dreg = .verdict, .data = .{ .verdict = owned } } });
    }

    pub fn accept(p: *Program) *Program {
        return p.verdict(.accept);
    }

    pub fn drop(p: *Program) *Program {
        return p.verdict(.drop);
    }

    pub fn ret(p: *Program) *Program {
        return p.verdict(.ret);
    }

    pub fn jump(p: *Program, chain: []const u8) *Program {
        return p.verdict(Verdict.jumpTo(chain));
    }

    pub fn goto(p: *Program, chain: []const u8) *Program {
        return p.verdict(Verdict.gotoChain(chain));
    }

    pub fn limit(p: *Program, l: Limit) *Program {
        return p.push(.{ .limit = l });
    }

    pub fn log(p: *Program, l: LogSpec) *Program {
        const owned: LogSpec = if (l.prefix) |pfx| blk: {
            var copy = l;
            copy.prefix = p.dupe(pfx) orelse return p;
            break :blk copy;
        } else l;
        return p.push(.{ .log = owned });
    }

    pub fn masquerade(p: *Program) *Program {
        return p.push(.{ .masq = .{} });
    }

    /// `reject [with …]`. See `RejectWith` for which variant a table family
    /// takes; the kernel refuses an `icmpx` reject in an `ip` table and a
    /// plain `icmp` one in `inet`.
    pub fn reject(p: *Program, with: RejectWith) *Program {
        return p.push(.{ .reject = switch (with) {
            .icmp => |code| .{ .type = NFT_REJECT.ICMP_UNREACH, .icmp_code = code },
            .icmpx => |code| .{ .type = NFT_REJECT.ICMPX_UNREACH, .icmp_code = @backingInt(code) },
            .tcp_reset => .{ .type = NFT_REJECT.TCP_RST, .icmp_code = 0 },
        } });
    }

    pub const QueueOptions = struct {
        /// How many queues to spread over (`queue num 2-5` = num 2, total 4).
        total: u16 = 1,
        /// Accept instead of drop when no program listens on the queue.
        bypass: bool = false,
        /// Choose the queue by CPU rather than by flow hash.
        fanout: bool = false,
    };

    /// `queue num <num>[-<num+total-1>] [bypass] [fanout]`.
    pub fn queue(p: *Program, num: u16, opts: QueueOptions) *Program {
        if (opts.total == 0 or @as(u32, num) + opts.total - 1 > std.math.maxInt(u16))
            return p.fail(error.InvalidQueueRange);
        var flags: u16 = 0;
        if (opts.bypass) flags |= NFT_QUEUE_FLAG_BYPASS;
        if (opts.fanout) flags |= NFT_QUEUE_FLAG_CPU_FANOUT;
        return p.push(.{ .queue = .{ .num = num, .total = opts.total, .flags = flags } });
    }

    /// `redirect [to :<port>]` (nat chains). The port goes through a
    /// register, like `nat`'s, so this resets the allocator first.
    pub fn redirect(p: *Program, port: ?u16) *Program {
        p.regs.reset();
        const pt = port orelse return p.push(.{ .redir = .{} });
        const reg = p.regs.alloc() catch |e| return p.fail(e);
        const v = p.dupe(&portBytes(pt)) orelse return p;
        _ = p.push(.{ .immediate = .{ .dreg = reg, .data = .{ .value = v } } });
        return p.push(.{ .redir = .{
            .reg_proto_min = reg,
            .flags = types.NF_NAT_RANGE_PROTO_SPECIFIED,
        } });
    }

    /// `quota [over] <bytes> bytes` — an anonymous quota on this rule.
    pub fn quota(p: *Program, bytes: u64, over: bool) *Program {
        return p.push(.{ .quota = .{ .bytes = bytes, .over = over } });
    }

    /// `<type> name "<name>"` — reference a named stateful object.
    /// `notrack` — exempt the packet from connection tracking.
    pub fn notrack(p: *Program) *Program {
        return p.push(.notrack);
    }

    /// `ct count [over] N` — at most (or, `over`, more than) `count`
    /// simultaneous connections per source.
    pub fn connlimit(p: *Program, count: u32, over: bool) *Program {
        return p.push(.{ .connlimit = .{ .count = count, .over = over } });
    }

    /// `flow add @name` — offload the flow to a flowtable.
    pub fn flowAdd(p: *Program, table: []const u8) *Program {
        const t = p.dupe(table) orelse return p;
        return p.push(.{ .flow_offload = .{ .table = t } });
    }

    /// `meta mark set <value>`.
    pub fn markSet(p: *Program, value: u32) *Program {
        p.regs.reset();
        const reg = p.regs.alloc() catch |e| return p.fail(e);
        const v = p.dupe(&regU32(value)) orelse return p;
        _ = p.push(.{ .immediate = .{ .dreg = reg, .data = .{ .value = v } } });
        return p.push(.{ .meta_set = .{ .key = .mark, .sreg = reg } });
    }

    /// `ct mark set <value>`.
    pub fn ctMarkSet(p: *Program, value: u32) *Program {
        p.regs.reset();
        const reg = p.regs.alloc() catch |e| return p.fail(e);
        const v = p.dupe(&regU32(value)) orelse return p;
        _ = p.push(.{ .immediate = .{ .dreg = reg, .data = .{ .value = v } } });
        return p.push(.{ .ct_set = .{ .key = NFT_CT.MARK, .sreg = reg } });
    }

    /// `tcp dport lo-hi` (or `!= lo-hi`) as one `range` comparison.
    pub fn tcpDportRange(p: *Program, lo: u16, hi: u16, outside: bool) *Program {
        if (lo > hi) return p.fail(error.InvalidRange);
        _ = p.l4proto(IPPROTO.TCP);
        p.regs.reset();
        const reg = p.regs.alloc() catch |e| return p.fail(e);
        const from = p.dupe(&portBytes(lo)) orelse return p;
        const to = p.dupe(&portBytes(hi)) orelse return p;
        _ = p.push(.{ .payload_load = .{ .base = .th, .offset = 2, .len = 2, .dreg = reg } });
        return p.push(.{ .range = .{ .sreg = reg, .op = if (outside) .neq else .eq, .from = from, .to = to } });
    }

    /// `socket transparent 1`.
    pub fn socketTransparent(p: *Program) *Program {
        p.regs.reset();
        const reg = p.regs.alloc() catch |e| return p.fail(e);
        const one = p.dupe(&.{1}) orelse return p;
        _ = p.push(.{ .socket = .{ .key = NFT_SOCKET.TRANSPARENT, .dreg = reg } });
        return p.push(.{ .cmp = .{ .sreg = reg, .op = Op.eq.cmpOp().?, .data = .{ .value = one } } });
    }

    pub fn objref(p: *Program, obj_type: ObjectType, name: []const u8) *Program {
        const n = p.dupe(name) orelse return p;
        return p.push(.{ .objref = .{ .obj_type = obj_type, .name = n } });
    }

    /// `counter name "<name>"`.
    pub fn counterRef(p: *Program, name: []const u8) *Program {
        return p.objref(.counter, name);
    }

    /// `quota name "<name>"`.
    pub fn quotaRef(p: *Program, name: []const u8) *Program {
        return p.objref(.quota, name);
    }

    /// `payload(base, offset, len) vmap @map` — look the field up in a
    /// verdict map and apply the verdict found (no verdict when absent).
    /// `set_id` as in `payloadLookup`.
    pub fn payloadVmap(
        p: *Program,
        base: PayloadBase,
        offset: u32,
        len: u32,
        map: []const u8,
        set_id: ?u32,
    ) *Program {
        if (len > max_value_len) return p.fail(error.ValueWidthMismatch);
        p.regs.reset();
        const reg = p.regs.alloc() catch |e| return p.fail(e);
        const m = p.dupe(map) orelse return p;
        _ = p.push(.{ .payload_load = .{ .base = base, .offset = offset, .len = len, .dreg = reg } });
        return p.push(.{ .lookup = .{ .set = m, .sreg = reg, .dreg = .verdict, .set_id = set_id } });
    }

    /// `tcp dport vmap @map`, with the `meta l4proto tcp` dependency.
    pub fn tcpDportVmap(p: *Program, map: []const u8, set_id: ?u32) *Program {
        _ = p.l4proto(IPPROTO.TCP);
        return p.payloadVmap(.th, 2, 2, map, set_id);
    }

    /// `snat`/`dnat to <addr>[:<port>]`.
    ///
    /// The address and the port must be live in registers **at the same
    /// time**, so this is the one helper that allocates two registers without
    /// an intervening reset (address first, then port — matching `nft`).
    pub fn nat(
        p: *Program,
        kind: enum { snat, dnat },
        family: Family,
        addr: ?[]const u8,
        port: ?u16,
        extra_flags: u32,
    ) *Program {
        p.regs.reset();
        var spec: NatSpec = .{
            .kind = if (kind == .snat) NFT_NAT_SNAT else NFT_NAT_DNAT,
            .family = family.nfproto(),
            .flags = extra_flags,
        };
        if (addr) |a| {
            const reg = p.regs.alloc() catch |e| return p.fail(e);
            const v = p.dupe(a) orelse return p;
            _ = p.push(.{ .immediate = .{ .dreg = reg, .data = .{ .value = v } } });
            spec.reg_addr_min = reg;
        }
        if (port) |pt| {
            const reg = p.regs.alloc() catch |e| return p.fail(e);
            const v = p.dupe(&portBytes(pt)) orelse return p;
            _ = p.push(.{ .immediate = .{ .dreg = reg, .data = .{ .value = v } } });
            spec.reg_proto_min = reg;
            spec.flags |= types.NF_NAT_RANGE_PROTO_SPECIFIED;
        }
        return p.push(.{ .nat = spec });
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn encode(gpa: std.mem.Allocator, exprs: []const Expr) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    for (exprs) |e| try appendExpr(gpa, &list, e);
    return list.toOwnedSlice(gpa);
}

test "register allocator resets per match sequence and runs out honestly" {
    var a: RegAlloc = .{};
    try testing.expectEqual(Reg.r1, try a.alloc());
    try testing.expectEqual(Reg.r2, try a.alloc());
    a.reset();
    try testing.expectEqual(Reg.r1, try a.alloc());
    _ = try a.alloc();
    _ = try a.alloc();
    _ = try a.alloc();
    try testing.expectError(error.OutOfRegisters, a.alloc());
}

test "every helper match sequence starts at NFT_REG_1" {
    var p = Program.init(testing.allocator, .inet);
    defer p.deinit();
    _ = p.tcpDport(22).ipSaddr(.{ 10, 0, 0, 1 }).counter().accept();
    const exprs = try p.finish();

    var loads: usize = 0;
    for (exprs) |e| switch (e) {
        .payload_load => |x| {
            loads += 1;
            try testing.expectEqual(Reg.r1, x.dreg);
        },
        .meta_load => |x| {
            loads += 1;
            try testing.expectEqual(Reg.r1, x.dreg);
        },
        .cmp => |x| try testing.expectEqual(Reg.r1, x.sreg),
        else => {},
    };
    try testing.expect(loads >= 4);
}

test "cmp value width is validated against the load" {
    var p = Program.init(testing.allocator, .inet);
    defer p.deinit();
    // A 4-byte value against a 2-byte payload load.
    _ = p.payloadCmp(.th, 2, 2, .eq, &.{ 0, 0, 0, 22 });
    try testing.expectError(error.ValueWidthMismatch, p.finish());

    var q = Program.init(testing.allocator, .inet);
    defer q.deinit();
    _ = q.metaCmp(.iifname, .eq, "lo"); // needs 16 bytes
    try testing.expectError(error.ValueWidthMismatch, q.finish());

    var r = Program.init(testing.allocator, .inet);
    defer r.deinit();
    _ = r.metaCmp(.mark, .in, &.{ 0, 0, 0, 1 });
    try testing.expectError(error.UnsupportedOperator, r.finish());
}

test "payloadCmp/payloadMaskedCmp reject a value wider than one data register" {
    // 16 bytes = width of one legacy nft_registers data register
    // (NFT_REG_1..NFT_REG_4, see the register model in the file header);
    // pinned literally, not via `max_value_len`, so a change to the
    // constant is caught here.
    const over_wide: [17]u8 = @splat(0);
    const exactly_wide: [16]u8 = @splat(0);

    var p = Program.init(testing.allocator, .inet);
    defer p.deinit();
    _ = p.payloadCmp(.nh, 0, 17, .eq, &over_wide);
    try testing.expectError(error.ValueWidthMismatch, p.finish());

    // The boundary itself must still be accepted.
    var q = Program.init(testing.allocator, .inet);
    defer q.deinit();
    _ = q.payloadCmp(.nh, 0, 16, .eq, &exactly_wide);
    _ = try q.finish();

    var r = Program.init(testing.allocator, .inet);
    defer r.deinit();
    _ = r.payloadMaskedCmp(.nh, 0, 17, &over_wide, .eq, &over_wide);
    try testing.expectError(error.ValueWidthMismatch, r.finish());
}

test "every meta key maps and encodes; the bridge-name keys alias ibriport/obriport" {
    // Until 2026-10-04 `ibridgename`/`obridgename` had no grounded number and
    // were refused here with `error.UnsupportedMetaKey`. The `nft` capture
    // (`meta ibrname` → 17, `meta obrname` → 18) grounded them, so no key is
    // refused any more — and the only two keys allowed to share a number are
    // those aliases.
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    inline for (@typeInfo(MetaKey).@"enum".field_names, @typeInfo(MetaKey).@"enum".field_values) |_, f_value| {
        const k: MetaKey = @fromBackingInt(@intCast(f_value));
        try testing.expect(k.key() != null);
        try appendExpr(testing.allocator, &list, .{ .meta_load = .{ .key = k, .dreg = .r1 } });
        inline for (@typeInfo(MetaKey).@"enum".field_names, @typeInfo(MetaKey).@"enum".field_values) |_, g_value| {
            const j: MetaKey = @fromBackingInt(@intCast(g_value));
            if (f_value < g_value and k.key().? == j.key().?) {
                const alias = (k == .ibriport and j == .ibridgename) or (k == .obriport and j == .obridgename);
                try testing.expect(alias);
            }
        }
    }
}

test "bitwise rejects a mask/xor that disagrees with len" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    try testing.expectError(error.BitwiseLengthMismatch, appendExpr(
        testing.allocator,
        &list,
        .{ .bitwise = .{
            .sreg = .r1,
            .dreg = .r1,
            .len = 4,
            .mask = &.{ 0xff, 0xff },
            .xor = &.{ 0, 0, 0, 0 },
        } },
    ));
}

test "ipv4 prefix masks" {
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0 }, &(try ipv4MaskBytes(0)));
    try testing.expectEqualSlices(u8, &.{ 0xff, 0, 0, 0 }, &(try ipv4MaskBytes(8)));
    try testing.expectEqualSlices(u8, &.{ 0xff, 0xf0, 0, 0 }, &(try ipv4MaskBytes(12)));
    try testing.expectEqualSlices(u8, &.{ 0xff, 0xff, 0xff, 0xff }, &(try ipv4MaskBytes(32)));
    // ⚠ Above 32 it used to compute a mask anyway: `/33` gave `80000000` in
    // ReleaseFast -- a `/1`, half the internet, where the caller asked for a
    // single host's worth of a typo (audit 2026-09-02).
    try testing.expectError(error.InvalidPrefixLength, ipv4MaskBytes(33));
    try testing.expectError(error.InvalidPrefixLength, ipv4MaskBytes(63));
}

test "an interface name that cannot fit IFNAMSIZ is refused, not trimmed into a rule that never matches" {
    // `nft(8)` refuses the same name ("String exceeds maximum length of 16");
    // this used to trim it to 16 bytes and build a `drop` against a name no
    // interface can have -- a fail-open rule that looks installed.
    try testing.expectError(error.InterfaceNameTooLong, ifnameBytes("abcdefghijklmnopqrstuvwxyz"));
    try testing.expectError(error.InterfaceNameTooLong, ifnameBytes("abcdefghijklmnop")); // exactly 16: the NUL has nowhere to go
    const ok = try ifnameBytes("abcdefghijklmno"); // 15
    try testing.expectEqual(@as(u8, 0), ok[15]);

    var p = Program.init(testing.allocator, .inet);
    defer p.deinit();
    _ = p.ifnameCmp(.iifname, .eq, "abcdefghijklmnopqrstuvwxyz").drop();
    try testing.expectError(error.InterfaceNameTooLong, p.finish());
}

test "ipv4Bytes packs its four octets in argument order, unmodified" {
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 1 }, &ipv4Bytes(10, 0, 0, 1));
    try testing.expectEqualSlices(u8, &.{ 255, 255, 255, 255 }, &ipv4Bytes(255, 255, 255, 255));
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0 }, &ipv4Bytes(0, 0, 0, 0));
}

test "a byte-aligned prefix shortens the load instead of masking" {
    var p = Program.init(testing.allocator, .inet);
    defer p.deinit();
    _ = p.ipSaddrPrefix(.{ 10, 0, 0, 0 }, 8);
    const exprs = try p.finish();
    for (exprs) |e| try testing.expect(e != .bitwise);
    // meta nfproto + cmp, payload(len 1) + cmp
    try testing.expectEqual(@as(usize, 4), exprs.len);
    try testing.expectEqual(@as(u32, 1), exprs[2].payload_load.len);

    var q = Program.init(testing.allocator, .inet);
    defer q.deinit();
    _ = q.ipSaddrPrefix(.{ 10, 0, 0, 0 }, 12);
    const qe = try q.finish();
    try testing.expectEqual(@as(usize, 5), qe.len);
    try testing.expectEqual(@as(u32, 4), qe[2].payload_load.len);
    try testing.expectEqualSlices(u8, &.{ 0xff, 0xf0, 0, 0 }, qe[3].bitwise.mask);
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 0 }, qe[4].cmp.data.value);
}

test "nat keeps address and port live in different registers" {
    var p = Program.init(testing.allocator, .ip);
    defer p.deinit();
    _ = p.nat(.dnat, .ip, &.{ 10, 0, 0, 5 }, 8080, 0);
    const exprs = try p.finish();
    try testing.expectEqual(@as(usize, 3), exprs.len);
    try testing.expectEqual(Reg.r1, exprs[0].immediate.dreg);
    try testing.expectEqual(Reg.r2, exprs[1].immediate.dreg);
    try testing.expectEqual(Reg.r1, exprs[2].nat.reg_addr_min.?);
    try testing.expectEqual(Reg.r2, exprs[2].nat.reg_proto_min.?);
    try testing.expectEqual(types.NF_NAT_RANGE_PROTO_SPECIFIED, exprs[2].nat.flags);
}

test "encode/decode round-trip: names, verdicts and expression count" {
    const gpa = testing.allocator;
    var p = Program.init(gpa, .inet);
    defer p.deinit();
    _ = p.tcpDport(22).counter().jump("other");
    const exprs = try p.finish();
    const bytes = try encode(gpa, exprs);
    defer gpa.free(bytes);

    var it: ExprIterator = .{ .attrs = .{ .buf = bytes } };
    var names: std.ArrayList([]const u8) = .empty;
    defer names.deinit(gpa);
    var verdict_seen: ?i32 = null;
    var chain_seen: ?[]const u8 = null;
    while (try it.next()) |v| {
        try names.append(gpa, v.name);
        if (std.mem.eql(u8, v.name, "immediate")) {
            if (try decodeVerdict(v.data)) |vd| {
                verdict_seen = vd.code;
                chain_seen = vd.chain;
            }
        }
    }
    try testing.expectEqual(@as(usize, 6), names.items.len);
    try testing.expectEqualStrings("meta", names.items[0]);
    try testing.expectEqualStrings("cmp", names.items[1]);
    try testing.expectEqualStrings("payload", names.items[2]);
    try testing.expectEqualStrings("cmp", names.items[3]);
    try testing.expectEqualStrings("counter", names.items[4]);
    try testing.expectEqualStrings("immediate", names.items[5]);
    try testing.expectEqual(@as(?i32, types.NFT.JUMP), verdict_seen);
    try testing.expectEqualStrings("other", chain_seen.?);
}

test "expression decoding survives a truncated or hostile stream" {
    // Declared nest length runs past the buffer.
    var it: ExprIterator = .{ .attrs = .{ .buf = &.{ 0xff, 0x00, 0x01, 0x80, 0x00, 0x00 } } };
    try testing.expectError(error.Truncated, it.next());
    // Zero-length TLV must not loop.
    var it2: ExprIterator = .{ .attrs = .{ .buf = &.{ 0x00, 0x00, 0x01, 0x80 } } };
    try testing.expectError(error.BadLength, it2.next());
    // Well-formed elem whose inner attributes are garbage: skipped, not fatal.
    var it3: ExprIterator = .{ .attrs = .{ .buf = &.{ 0x04, 0x00, 0x01, 0x80 } } };
    try testing.expectEqual(@as(?ExprView, null), try it3.next());
}

/// `NFTA_RULE_EXPRESSIONS` nest bodies for `fuzzExprWalk`, in the format
/// `Smith.slice` reads (see `testkit.fuzz`): a little-endian u32 length, then
/// the nest body.
///
/// ⭐ Built at run time by this file's own `Program` and `appendExpr` rather
/// than quoted as hex. An nftables expression is a tree of netlink TLVs whose
/// `nla_len`/`nla_type` are HOST byte order (the register values inside are
/// big-endian, the framing is not), so a hex corpus would be a little-endian
/// one and the counts pinned below would be false on a big-endian target
/// instead of failing there.
const ExprCorpus = struct {
    scratch: [16384]u8 = undefined,
    store: [32768]u8 = undefined,
    used: usize = 0,
    entries: [24][]const u8 = undefined,
    n: usize = 0,

    fn push(self: *ExprCorpus, frame: []const u8) void {
        const sd = testkit.fuzz.seedInto(self.store[self.used..], frame);
        self.entries[self.n] = sd;
        self.used += sd.len;
        self.n += 1;
    }

    /// Every expression a `Program` produced, appended into one nest body —
    /// which is exactly what `ExprIterator` is handed at run time.
    fn pushProgram(self: *ExprCorpus, gpa: std.mem.Allocator, p: *Program) !void {
        const exprs = try p.finish();
        var list: std.ArrayList(u8) = .empty;
        for (exprs) |e| try appendExpr(gpa, &list, e);
        self.push(list.items);
    }

    fn build(self: *ExprCorpus) ![]const []const u8 {
        var fba = std.heap.FixedBufferAllocator.init(&self.scratch);
        const gpa = fba.allocator();

        // A filter rule: meta l4proto dependency, a payload compare, a
        // counter, and an immediate verdict — the four expression shapes the
        // walker's inner loop and `decodeVerdict` both have to handle.
        {
            var p = Program.init(gpa, .inet);
            _ = p.tcpDport(22).counter().drop();
            try self.pushProgram(gpa, &p);
        }
        // A verdict that names a chain: `decodeVerdict`'s other arm, the one
        // that returns a borrowed string rather than only a code.
        {
            var p = Program.init(gpa, .inet);
            _ = p.ipDaddr(.{ 10, 0, 0, 1 }).jump("mychain");
            try self.pushProgram(gpa, &p);
        }
        // A masked compare and a set lookup: the two expressions carrying a
        // value wide enough for the inner attribute walk to have work to do.
        {
            var p = Program.init(gpa, .inet);
            _ = p.ipSaddrPrefix(.{ 192, 168, 0, 0 }, 16)
                .payloadLookup(.nh, 12, 4, "badhosts", null, false)
                .accept();
            try self.pushProgram(gpa, &p);
        }
        // A limit and a log: expressions whose data is scalars only.
        {
            var p = Program.init(gpa, .inet);
            _ = p.limit(.{ .rate = 10, .unit = .kbytes, .per = .second, .burst = 5 })
                .log(.{ .prefix = "drop: " })
                .drop();
            try self.pushProgram(gpa, &p);
        }

        // ── the walker's own bounds, from this file's hostile-stream test ──
        // A declared nest length running past the buffer.
        self.push(&.{ 0xff, 0x00, 0x01, 0x80, 0x00, 0x00 });
        // A zero-length TLV, which must not loop.
        self.push(&.{ 0x00, 0x00, 0x01, 0x80 });
        // A well-formed elem whose inner attributes are empty: skipped
        // (`view.name.len == 0`), not fatal — the `continue` branch, which no
        // program-built seed can reach.
        self.push(&.{ 0x04, 0x00, 0x01, 0x80 });
        // An elem carrying a NAME but a DATA nest that runs off the end.
        self.push(&.{
            0x14, 0x00, 0x01, 0x80, // elem, 20 octets
            0x0b, 0x00, 0x01, 0x00,
            'p',  'a',  'y',  'l',
            'o',  'a',  'd',  0x00,
            0xff, 0x00, 0x02, 0x80, // DATA declaring 255
        });
        // An elem whose NAME is there and whose DATA is empty: the name is
        // returned and `decodeVerdict` gets nothing to walk.
        self.push(&.{
            0x10, 0x00, 0x01, 0x80,
            0x0b, 0x00, 0x01, 0x00,
            'c',  'o',  'u',  'n',
            't',  'e',  'r',  0x00,
        });
        // Nothing at all: a rule with no expressions is legal.
        self.push(&.{});

        // ── the kernel's own bytes (2026-11-07, `kernel_dumps.zig`) ────────
        // Expression nests exactly as a Linux 7.0 kernel dumped them: the
        // typed decoder's reach (byteorder, hash, range, connlimit, numgen,
        // log with its 16-bit group, last, socket, dynset, vmap lookup,
        // objref, bitshift, rt, synproxy) starts from real bytes, not from
        // what this module's encoder would write.
        const kd = @import("kernel_dumps.zig");
        const kb = try gpa.alloc(u8, kd.k_rules.len / 2);
        _ = try std.fmt.hexToBytes(kb, kd.k_rules);
        var kit: nl.MessageIterator = .{ .buf = kb };
        var kidx: usize = 0;
        while (try kit.next()) |m| : (kidx += 1) {
            switch (kidx) {
                0, 1, 2, 3, 4, 6, 7, 9, 10, 12, 13, 15, 16, 17 => {},
                else => continue,
            }
            var ai: nl.AttrIterator = .{ .buf = m.payload[4..] };
            while (try ai.next()) |a| if (a.type == 4) self.push(a.data); // NFTA_RULE_EXPRESSIONS
        }

        return self.entries[0..self.n];
    }
};

/// What one nest body yielded. Shared by the fuzz target and its corpus guard
/// so the guard drives the SAME walk.
const ExprTally = struct {
    typed: usize = 0,
    exprs: usize = 0,
    inner: usize = 0,
    verdicts: usize = 0,
};

fn walkExprs(buf: []const u8) !ExprTally {
    var t: ExprTally = .{};
    var steps: usize = 0;
    var it: ExprIterator = .{ .attrs = .{ .buf = buf } };
    while (it.next() catch null) |v| {
        steps += 1;
        try testing.expect(steps <= buf.len / 4 + 1);
        t.exprs += 1;
        if (decodeVerdict(v.data) catch null) |_| t.verdicts += 1;
        if (decodeExpr(v)) |e| {
            if (e != .raw) t.typed += 1;
        } else |_| {}
        var inner = v.attrs();
        var isteps: usize = 0;
        while (inner.next() catch null) |a| {
            isteps += 1;
            try testing.expect(isteps <= v.data.len / 4 + 1);
            t.inner += 1;
            _ = a.asBe32() catch {};
            _ = a.asString();
        }
    }
    return t;
}

const fz = @import("fuzz_test.zig");
const ExprMark = fz.Marker(enum { nothing, exprs, inner, verdicts, typed_expr });

test "fuzz: the expression walker never crashes, loops or over-reads" {
    var corpus: ExprCorpus = .{};
    try testing.fuzz({}, fuzzExprWalkSmith, .{ .corpus = try corpus.build() });
}

test "fuzz driver: NFTABLES_FUZZ (expression walker)" {
    try fz.fuzz_driver.run(fuzzExprWalk, .{ .prefix = "NFTABLES_FUZZ", .name = "nftables-expr" });
}

test "fuzz harness: expression walker, 300 seeds, reaches every outcome" {
    try ExprMark.reach(fuzzExprWalk, "nftables-expr", 300);
}

test "corpus: every expression seed reaches the walker, and the counts are pinned" {
    // ⭐ The measurement, executable rather than written in a comment, over the
    // SAME corpus the harness gets, through the SAME `walkExprs`. `nonempty`
    // is the reach claim and the only check that catches a seed grown past the
    // harness's buffer, which `Smith.slice` reads back as the EMPTY one.
    //
    // ⛔ There is no acceptance number to pin here, deliberately: an empty
    // nest is a legal `NFTA_RULE_EXPRESSIONS` body — a rule may carry no
    // expressions — so "the walk completed" is true of every seed including
    // the empty one. `exprs`, `inner` and `verdicts` count work the empty
    // input cannot do.
    var corpus: ExprCorpus = .{};
    const entries = try corpus.build();
    var nonempty: usize = 0;
    var total: ExprTally = .{};
    for (entries) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var raw: [2048]u8 = undefined;
        const len: usize = smith.slice(&raw);
        if (len != 0) nonempty += 1;
        const t = try walkExprs(raw[0..len]);
        total.exprs += t.exprs;
        total.inner += t.inner;
        total.verdicts += t.verdicts;
        total.typed += t.typed;
    }
    try testing.expectEqual(entries.len - 1, nonempty); // one seed IS the empty nest
    // 22/56/4 from the synthetic seeds; the 14 kernel rule nests added the rest.
    try testing.expectEqual(@as(usize, 71), total.exprs);
    try testing.expectEqual(@as(usize, 201), total.inner);
    try testing.expectEqual(@as(usize, 11), total.verdicts);
    try testing.expectEqual(@as(usize, 70), total.typed); // the dynset stays raw
}

fn fuzzExprWalkSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [fz.script_cap]u8 = undefined;
    const n = smith.slice(&script);
    try fz.runFrom(fuzzExprWalk, smith, script[0..n]);
}

fn fuzzExprWalk(comptime S: type, smith: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    // 2048, not 512: a `Program` with a set lookup and a masked compare in it
    // already runs past 512, and a seed longer than the buffer is not a big
    // seed — `Smith.slice` reads it back as the EMPTY one.
    var raw: [2048]u8 = undefined;
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
    // length. `bytes` takes `@min(raw.len, in.len)` octets and the ranged draw
    // then finds fewer than the eight it needs and returns the range MINIMUM,
    // so `len` was 0 for every seed and the iterator was handed an EMPTY nest.
    //
    // ⛔ And that looked HEALTHY: an empty `NFTA_RULE_EXPRESSIONS` nest is a
    // legal rule body, so the walk "completed" every round while the loop it
    // is made of never executed. Measured 2026-09-07 over the corpus above:
    // **0 of 10 seeds non-empty, 0 expressions walked, 0 inner attributes read
    // and 0 verdicts decoded before; 9 of 10 non-empty (one seed IS the empty
    // nest), 22 expressions walked, 56 inner attributes read and 4 verdicts
    // decoded, after.**
    var cstore: ExprCorpus = .{};
    const entries: []const []const u8 = if (S == fz.fuzz_driver.Rng) (cstore.build() catch &.{}) else &.{};
    const len: usize = fz.drawInput(S, smith, &raw, entries);
    const buf = raw[0..len];

    var steps: usize = 0;
    var it: ExprIterator = .{ .attrs = .{ .buf = buf } };
    while (it.next() catch null) |v| {
        steps += 1;
        ExprMark.mark(.exprs);
        try testing.expect(steps <= buf.len / 4 + 1);
        if (decodeVerdict(v.data)) |_| ExprMark.mark(.verdicts) else |_| {}
        // The typed decoder reads the same hostile bytes: it must return a
        // value or an error, never crash and never read past `v.data`.
        if (decodeExpr(v)) |e| {
            if (e != .raw) ExprMark.mark(.typed_expr);
        } else |_| {}
        var inner = v.attrs();
        var isteps: usize = 0;
        while (inner.next() catch null) |a| {
            isteps += 1;
            ExprMark.mark(.inner);
            try testing.expect(isteps <= v.data.len / 4 + 1);
            _ = a.asBe32() catch {};
            _ = a.asString();
        }
    }
    if (steps == 0) ExprMark.mark(.nothing);
}

test "a payload set lookup is bounded like its two cmp siblings" {
    // The 2026-08-11 fix bounded `payloadCmp` and `payloadMaskedCmp` at
    // `max_value_len` and left `payloadLookup` out of the fix set — the shape
    // `feedback_take_the_finding_not_the_fix_set` is about. Nothing between
    // the caller and the kernel checked it.
    var p = Program.init(testing.allocator, .inet);
    defer p.deinit();
    _ = p.payloadLookup(.nh, 0, 4096, "badhosts", null, false).drop();
    try testing.expectError(error.ValueWidthMismatch, p.finish());

    var ok = Program.init(testing.allocator, .inet);
    defer ok.deinit();
    _ = ok.payloadLookup(.nh, 12, 4, "badhosts", null, false).drop();
    _ = try ok.finish();
}

test "a limit rate that overflows its unit scaling is refused, not wrapped into a tighter one" {
    // `rate * unit.scale()` wrapped: (1 << 44) + 1 mbytes/s encoded as
    // 1 MiB/s. A limit tighter than the caller asked for drops traffic they
    // meant to admit, and it did it with no error at all in ReleaseFast.
    var p = Program.init(testing.allocator, .inet);
    defer p.deinit();
    _ = p.limit(.{ .rate = (1 << 44) + 1, .unit = .mbytes, .per = .second, .burst = 5 }).drop();
    const exprs = try p.finish();
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    try testing.expectError(
        error.RateOutOfRange,
        appendExpr(testing.allocator, &list, exprs[0]),
    );
}
