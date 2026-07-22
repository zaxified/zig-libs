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
const nl = @import("nl.zig");
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

/// Hands out `NFT_REG_1`…`NFT_REG_4` in order; `reset` starts over.
pub const RegAlloc = struct {
    next: u32 = 1,

    pub fn reset(a: *RegAlloc) void {
        a.next = 1;
    }

    pub fn alloc(a: *RegAlloc) RegError!Reg {
        if (a.next > 4) return error.OutOfRegisters;
        defer a.next += 1;
        return @enumFromInt(a.next);
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
    bitwise: struct { sreg: Reg, dreg: Reg, len: u32, mask: []const u8, xor: []const u8 },
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
};

// ── encoding ────────────────────────────────────────────────────────────────

fn appendData(
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
            nl.nestEnd(list, voff);
        },
    }
    nl.nestEnd(list, off);
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
    const data = try nl.nestBegin(gpa, list, nl.NLA_F_NESTED | NFTA_EXPR.DATA);
    switch (e) {
        .payload_load => |p| {
            try nl.appendAttrBe32(gpa, list, NFTA_PAYLOAD.DREG, @intFromEnum(p.dreg));
            try nl.appendAttrBe32(gpa, list, NFTA_PAYLOAD.BASE, p.base.base());
            try nl.appendAttrBe32(gpa, list, NFTA_PAYLOAD.OFFSET, p.offset);
            try nl.appendAttrBe32(gpa, list, NFTA_PAYLOAD.LEN, p.len);
        },
        .meta_load => |m| {
            try nl.appendAttrBe32(gpa, list, NFTA_META.KEY, m.key.key() orelse
                return error.UnsupportedMetaKey);
            try nl.appendAttrBe32(gpa, list, NFTA_META.DREG, @intFromEnum(m.dreg));
        },
        .meta_set => |m| {
            try nl.appendAttrBe32(gpa, list, NFTA_META.KEY, m.key.key() orelse
                return error.UnsupportedMetaKey);
            try nl.appendAttrBe32(gpa, list, NFTA_META.SREG, @intFromEnum(m.sreg));
        },
        .ct_load => |c| {
            try nl.appendAttrBe32(gpa, list, NFTA_CT.KEY, c.key);
            try nl.appendAttrBe32(gpa, list, NFTA_CT.DREG, @intFromEnum(c.dreg));
            if (c.dir) |d| try nl.appendAttrU8(gpa, list, NFTA_CT.DIRECTION, d.dir());
        },
        .cmp => |c| {
            try nl.appendAttrBe32(gpa, list, NFTA_CMP.SREG, @intFromEnum(c.sreg));
            try nl.appendAttrBe32(gpa, list, NFTA_CMP.OP, c.op);
            try appendData(gpa, list, NFTA_CMP.DATA, c.data);
        },
        .bitwise => |b| {
            if (b.mask.len != b.len or b.xor.len != b.len)
                return error.BitwiseLengthMismatch;
            try nl.appendAttrBe32(gpa, list, NFTA_BITWISE.SREG, @intFromEnum(b.sreg));
            try nl.appendAttrBe32(gpa, list, NFTA_BITWISE.DREG, @intFromEnum(b.dreg));
            try nl.appendAttrBe32(gpa, list, NFTA_BITWISE.LEN, b.len);
            try appendData(gpa, list, NFTA_BITWISE.MASK, .{ .value = b.mask });
            try appendData(gpa, list, NFTA_BITWISE.XOR, .{ .value = b.xor });
        },
        .lookup => |l| {
            try nl.appendAttrBe32(gpa, list, NFTA_LOOKUP.SREG, @intFromEnum(l.sreg));
            try nl.appendAttrString(gpa, list, NFTA_LOOKUP.SET, l.set);
            if (l.dreg) |d| try nl.appendAttrBe32(gpa, list, NFTA_LOOKUP.DREG, @intFromEnum(d));
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
            try nl.appendAttrBe32(gpa, list, NFTA_IMMEDIATE.DREG, @intFromEnum(i.dreg));
            try appendData(gpa, list, NFTA_IMMEDIATE.DATA, i.data);
        },
        .limit => |l| {
            try nl.appendAttrBe64(gpa, list, NFTA_LIMIT.RATE, l.rate * l.unit.scale());
            try nl.appendAttrBe64(gpa, list, NFTA_LIMIT.UNIT, l.per.seconds());
            try nl.appendAttrBe32(gpa, list, NFTA_LIMIT.BURST, l.burst);
            try nl.appendAttrBe32(gpa, list, NFTA_LIMIT.TYPE, l.unit.limitType());
            try nl.appendAttrBe32(gpa, list, NFTA_LIMIT.FLAGS, if (l.inv) NFT_LIMIT_F_INV else 0);
        },
        .log => |l| {
            if (l.group) |g| try nl.appendAttrBe32(gpa, list, NFTA_LOG.GROUP, g);
            if (l.prefix) |p| try nl.appendAttrString(gpa, list, NFTA_LOG.PREFIX, p);
            if (l.snaplen) |s| try nl.appendAttrBe32(gpa, list, NFTA_LOG.SNAPLEN, s);
            if (l.qthreshold) |q| try nl.appendAttrBe32(gpa, list, NFTA_LOG.QTHRESHOLD, q);
            if (l.level) |lv| try nl.appendAttrBe32(gpa, list, NFTA_LOG.LEVEL, lv.level());
            if (l.flags) |f| try nl.appendAttrBe32(gpa, list, NFTA_LOG.FLAGS, f);
        },
        .nat => |n| {
            try nl.appendAttrBe32(gpa, list, NFTA_NAT.TYPE, n.kind);
            try nl.appendAttrBe32(gpa, list, NFTA_NAT.FAMILY, n.family);
            if (n.reg_addr_min) |r|
                try nl.appendAttrBe32(gpa, list, NFTA_NAT.REG_ADDR_MIN, @intFromEnum(r));
            if (n.reg_addr_max) |r|
                try nl.appendAttrBe32(gpa, list, NFTA_NAT.REG_ADDR_MAX, @intFromEnum(r));
            if (n.reg_proto_min) |r|
                try nl.appendAttrBe32(gpa, list, NFTA_NAT.REG_PROTO_MIN, @intFromEnum(r));
            if (n.reg_proto_max) |r|
                try nl.appendAttrBe32(gpa, list, NFTA_NAT.REG_PROTO_MAX, @intFromEnum(r));
            if (n.flags != 0) try nl.appendAttrBe32(gpa, list, NFTA_NAT.FLAGS, n.flags);
        },
        .masq => |m| {
            if (m.flags != 0) try nl.appendAttrBe32(gpa, list, NFTA_MASQ.FLAGS, m.flags);
            if (m.reg_proto_min) |r|
                try nl.appendAttrBe32(gpa, list, NFTA_MASQ.REG_PROTO_MIN, @intFromEnum(r));
            if (m.reg_proto_max) |r|
                try nl.appendAttrBe32(gpa, list, NFTA_MASQ.REG_PROTO_MAX, @intFromEnum(r));
        },
        .raw => |r| try list.appendSlice(gpa, r.data),
    }
    nl.nestEnd(list, data);
    nl.nestEnd(list, elem);
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
pub fn ipv4MaskBytes(prefix_len: u6) [4]u8 {
    var out: [4]u8 = undefined;
    const bits: u32 = if (prefix_len == 0)
        0
    else
        ~@as(u32, 0) << @intCast(32 - @as(u32, prefix_len));
    std.mem.writeInt(u32, &out, bits, .big);
    return out;
}

/// A register-resident 32-bit value. Registers hold **host** byte order —
/// this is what `meta mark`, `ct state` and friends compare against, and it is
/// deliberately not the big-endian encoding used for attribute *integers*.
pub fn regU32(v: u32) [4]u8 {
    var out: [4]u8 = undefined;
    std.mem.writeInt(u32, &out, v, @import("builtin").cpu.arch.endian());
    return out;
}

/// An interface name padded to `IFNAMSIZ` — the width `meta iifname`/`oifname`
/// loads and therefore the width its `cmp` must carry.
pub fn ifnameBytes(name: []const u8) [16]u8 {
    var out: [16]u8 = @splat(0);
    const n = @min(name.len, out.len);
    @memcpy(out[0..n], name[0..n]);
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
        const padded = ifnameBytes(name);
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
        const mask = ipv4MaskBytes(prefix_len);
        var masked: [4]u8 = undefined;
        for (&masked, addr, mask) |*m, a, k| m.* = a & k;
        return p.payloadMaskedCmp(.nh, offset, 4, &mask, .eq, &masked);
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

test "an unmappable meta key is rejected at encode time" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    try testing.expectError(error.UnsupportedMetaKey, appendExpr(
        testing.allocator,
        &list,
        .{ .meta_load = .{ .key = .ibridgename, .dreg = .r1 } },
    ));
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
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0 }, &ipv4MaskBytes(0));
    try testing.expectEqualSlices(u8, &.{ 0xff, 0, 0, 0 }, &ipv4MaskBytes(8));
    try testing.expectEqualSlices(u8, &.{ 0xff, 0xf0, 0, 0 }, &ipv4MaskBytes(12));
    try testing.expectEqualSlices(u8, &.{ 0xff, 0xff, 0xff, 0xff }, &ipv4MaskBytes(32));
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

test "fuzz: the expression walker never crashes, loops or over-reads" {
    try testing.fuzz({}, fuzzExprWalk, .{});
}

fn fuzzExprWalk(_: void, smith: *std.testing.Smith) !void {
    var raw: [512]u8 = undefined;
    smith.bytes(&raw);
    const len = smith.valueRangeAtMost(u16, 0, raw.len);
    const buf = raw[0..len];

    var steps: usize = 0;
    var it: ExprIterator = .{ .attrs = .{ .buf = buf } };
    while (it.next() catch null) |v| {
        steps += 1;
        try testing.expect(steps <= buf.len / 4 + 1);
        _ = decodeVerdict(v.data) catch {};
        var inner = v.attrs();
        var isteps: usize = 0;
        while (inner.next() catch null) |a| {
            isteps += 1;
            try testing.expect(isteps <= v.data.len / 4 + 1);
            _ = a.asBe32() catch {};
            _ = a.asString();
        }
    }
}
