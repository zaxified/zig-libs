// SPDX-License-Identifier: MIT

//! nftables **nfnetlink wire layer** — the pure, I/O-free half of the native
//! backend: the `nfgenmsg` header, the `NFT_MSG_*` object messages, the
//! transactional batch, and the decoders for what the kernel sends back.
//! No syscalls, no sockets: everything here operates on byte slices and is
//! unit-, golden- and fuzz-testable on any OS.
//!
//! ## Framing
//!
//! ```text
//! nlmsghdr  (16 B)   nlmsg_type = NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_*
//! nfgenmsg  (4 B)    u8 nfgen_family | u8 version | be16 res_id
//! nlattr TLVs        NFTA_*
//! ```
//!
//! **Byte order.** netlink itself is host-endian, but every nftables *integer*
//! attribute — and `nfgenmsg.res_id` — is **big-endian on the wire**, and the
//! kernel does not set `NLA_F_NET_BYTEORDER` on them. Verified against the
//! captures in `goldens.zig`: `NFTA_TABLE_FLAGS` arrives as
//! `08 00 02 00 | 00 00 00 00`, `NFTA_HOOK_HOOKNUM` for the input hook as
//! `08 00 01 00 | 00 00 00 01` — network order, no flag bits. The one thing
//! that is *not* big-endian is the content of a **register**: `NFTA_DATA_VALUE`
//! is raw bytes, so a port is network order because that is how it sits in the
//! packet, while `ct state` or `meta mark` are host order because that is how
//! the kernel put them in the register (`expr.regU32`).
//!
//! ## The batch — atomicity
//!
//! nftables commits are transactions. A batch is
//!
//! ```text
//! NFNL_MSG_BATCH_BEGIN   res_id = NFNL_SUBSYS_NFTABLES, seq = S
//! NFT_MSG_…              seq = S+1
//! NFT_MSG_…              seq = S+2
//! NFNL_MSG_BATCH_END     res_id = NFNL_SUBSYS_NFTABLES, seq = S+n+1
//! ```
//!
//! sent as **one** `sendmsg`. The kernel stages every message into a
//! transaction and only applies it when `BATCH_END` arrives cleanly: if any
//! message fails, the whole transaction is aborted and *nothing* is applied.
//! That is the property `socket.zig`'s live test proves.
//!
//! **Error attribution.** Every message carries its own sequence number, and
//! the kernel's `NLMSG_ERROR` for a rejected message carries that message's
//! seq — so a failure names *which* command failed, not just "the batch".
//! `Batch.entryForSeq` maps a sequence number back to the message index and
//! type; a failure reported against the `BATCH_BEGIN` seq comes from the
//! commit stage rather than from an individual command, and
//! `Batch.stageForSeq` distinguishes the two. With `NLM_F_ACK` set (the
//! default here, and *not* what the `nft` binary does) each queued message is
//! acknowledged, so a caller sees a positive result rather than inferring
//! success from silence.
//!
//! Provenance: clean-room from the kernel UAPI headers
//! (`linux/netfilter/nfnetlink.h`, `linux/netfilter/nf_tables.h`,
//! `linux/netfilter.h` — GPL-2.0 WITH Linux-syscall-note; the constants and
//! their layouts are the kernel's OS ABI) plus the byte-exact on-the-wire
//! captures of a stock `nft` binary in `goldens.zig`. No nftables, libnftnl or
//! libmnl source was consulted. See `/NOTICE`.

const std = @import("std");
const builtin = @import("builtin");
const nl = @import("nl.zig");
const types = @import("types.zig");
const expr = @import("expr.zig");

const native_endian = builtin.cpu.arch.endian();

const Family = types.Family;
const ChainType = types.ChainType;
const Hook = types.Hook;
const Policy = types.Policy;
const SetFlag = types.SetFlag;
const SetDataType = types.SetDataType;

// ── kernel UAPI constants ───────────────────────────────────────────────────

/// sizeof(struct nfgenmsg) — already 4-byte aligned.
pub const nfgenmsg_len = 4;

/// NFNETLINK_V0 — the only nfnetlink protocol version there is.
pub const NFNETLINK_V0: u8 = 0;

/// `NFNL_SUBSYS_NFTABLES` (linux/netfilter/nfnetlink.h).
pub const NFNL_SUBSYS_NFTABLES: u16 = 10;

/// `NFNL_MSG_BATCH_BEGIN`/`_END` — subsystem-independent control messages.
pub const NFNL_MSG_BATCH_BEGIN: u16 = 16;
pub const NFNL_MSG_BATCH_END: u16 = 17;

/// `enum nf_tables_msg_types` — the low byte of `nlmsg_type`.
pub const NFT_MSG = struct {
    pub const NEWTABLE: u8 = 0;
    pub const GETTABLE: u8 = 1;
    pub const DELTABLE: u8 = 2;
    pub const NEWCHAIN: u8 = 3;
    pub const GETCHAIN: u8 = 4;
    pub const DELCHAIN: u8 = 5;
    pub const NEWRULE: u8 = 6;
    pub const GETRULE: u8 = 7;
    pub const DELRULE: u8 = 8;
    pub const NEWSET: u8 = 9;
    pub const GETSET: u8 = 10;
    pub const DELSET: u8 = 11;
    pub const NEWSETELEM: u8 = 12;
    pub const GETSETELEM: u8 = 13;
    pub const DELSETELEM: u8 = 14;
    pub const NEWGEN: u8 = 15;
    pub const GETGEN: u8 = 16;
    pub const TRACE: u8 = 17;
    pub const NEWOBJ: u8 = 18;
    pub const GETOBJ: u8 = 19;
    pub const DELOBJ: u8 = 20;
};

/// Compose an nfnetlink `nlmsg_type`: `subsys << 8 | cmd`.
pub fn msgType(subsys: u16, cmd: u8) u16 {
    return (subsys << 8) | cmd;
}

/// `nlmsg_type` for an nftables command.
pub fn nftMsg(cmd: u8) u16 {
    return msgType(NFNL_SUBSYS_NFTABLES, cmd);
}

/// `enum nft_table_attributes`.
pub const NFTA_TABLE = struct {
    pub const NAME: u16 = 1;
    pub const FLAGS: u16 = 2;
    pub const USE: u16 = 3;
    pub const HANDLE: u16 = 4;
    pub const USERDATA: u16 = 6;
    pub const OWNER: u16 = 7;
};

/// `enum nft_chain_attributes`.
pub const NFTA_CHAIN = struct {
    pub const TABLE: u16 = 1;
    pub const HANDLE: u16 = 2;
    pub const NAME: u16 = 3;
    pub const HOOK: u16 = 4;
    pub const POLICY: u16 = 5;
    pub const USE: u16 = 6;
    pub const TYPE: u16 = 7;
    pub const COUNTERS: u16 = 8;
    pub const FLAGS: u16 = 10;
    pub const ID: u16 = 11;
    pub const USERDATA: u16 = 12;
};

/// `enum nft_hook_attributes`.
pub const NFTA_HOOK = struct {
    pub const HOOKNUM: u16 = 1;
    pub const PRIORITY: u16 = 2;
    pub const DEV: u16 = 3;
    pub const DEVS: u16 = 4;
};

/// `enum nft_rule_attributes`.
pub const NFTA_RULE = struct {
    pub const TABLE: u16 = 1;
    pub const CHAIN: u16 = 2;
    pub const HANDLE: u16 = 3;
    pub const EXPRESSIONS: u16 = 4;
    pub const COMPAT: u16 = 5;
    pub const POSITION: u16 = 6;
    pub const USERDATA: u16 = 7;
    pub const ID: u16 = 9;
    pub const POSITION_ID: u16 = 10;
    pub const CHAIN_ID: u16 = 11;
};

/// `enum nft_set_attributes`.
pub const NFTA_SET = struct {
    pub const TABLE: u16 = 1;
    pub const NAME: u16 = 2;
    pub const FLAGS: u16 = 3;
    pub const KEY_TYPE: u16 = 4;
    pub const KEY_LEN: u16 = 5;
    pub const DATA_TYPE: u16 = 6;
    pub const DATA_LEN: u16 = 7;
    pub const POLICY: u16 = 8;
    pub const DESC: u16 = 9;
    pub const ID: u16 = 10;
    pub const TIMEOUT: u16 = 11;
    pub const GC_INTERVAL: u16 = 12;
    pub const USERDATA: u16 = 13;
    pub const OBJ_TYPE: u16 = 15;
    pub const HANDLE: u16 = 16;
};

/// `enum nft_set_desc_attributes`.
pub const NFTA_SET_DESC = struct {
    pub const SIZE: u16 = 1;
    pub const CONCAT: u16 = 2;
};

/// `enum nft_set_elem_attributes`.
pub const NFTA_SET_ELEM = struct {
    pub const KEY: u16 = 1;
    pub const DATA: u16 = 2;
    pub const FLAGS: u16 = 3;
    pub const TIMEOUT: u16 = 4;
    pub const EXPIRATION: u16 = 5;
    pub const USERDATA: u16 = 6;
    pub const EXPR: u16 = 7;
    pub const OBJREF: u16 = 9;
    pub const KEY_END: u16 = 10;
};

/// `enum nft_set_elem_list_attributes`.
pub const NFTA_SET_ELEM_LIST = struct {
    pub const TABLE: u16 = 1;
    pub const SET: u16 = 2;
    pub const ELEMENTS: u16 = 3;
    pub const SET_ID: u16 = 4;
};

/// `enum nft_set_elem_flags`.
pub const NFT_SET_ELEM_INTERVAL_END: u32 = 0x1;
pub const NFT_SET_ELEM_CATCHALL: u32 = 0x2;

// ── errors ──────────────────────────────────────────────────────────────────

/// Everything the decoders can reject.
pub const DecodeError = nl.Error;

/// Everything a request builder can reject.
pub const BuildError = expr.BuildError;

// ── nfgenmsg ────────────────────────────────────────────────────────────────

/// The 4-byte nfnetlink family header plus the attribute bytes behind it.
pub const Nfgenmsg = struct {
    family: u8,
    version: u8,
    res_id: u16,
    /// The attribute region of the message payload (borrowed).
    attrs: []const u8,

    pub fn attrIterator(h: Nfgenmsg) nl.AttrIterator {
        return .{ .buf = h.attrs };
    }
};

/// Split a netlink message payload into its `nfgenmsg` and the TLVs after it.
pub fn parseNfgenmsg(payload: []const u8) DecodeError!Nfgenmsg {
    if (payload.len < nfgenmsg_len) return error.Truncated;
    return .{
        .family = payload[0],
        .version = payload[1],
        // res_id is __be16.
        .res_id = std.mem.readInt(u16, payload[2..4], .big),
        .attrs = payload[nfgenmsg_len..],
    };
}

/// Append a `struct nfgenmsg { u8 nfgen_family; u8 version; __be16 res_id; }`.
pub fn appendNfgenmsg(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    nfproto: u8,
    res_id: u16,
) std.mem.Allocator.Error!void {
    var raw: [nfgenmsg_len]u8 = undefined;
    raw[0] = nfproto;
    raw[1] = NFNETLINK_V0;
    std.mem.writeInt(u16, raw[2..4], res_id, .big);
    try list.appendSlice(gpa, &raw);
}

// ── object specifications ───────────────────────────────────────────────────

/// A table. `userdata` is an opaque blob the kernel stores and returns
/// untouched — the `nft` binary keeps its own versioned TLVs there, which is
/// why the goldens can hand this module those exact bytes and get byte-exact
/// output.
pub const TableSpec = struct {
    family: Family,
    name: []const u8,
    flags: u32 = 0,
    userdata: ?[]const u8 = null,
};

/// A chain. Base chains (attached to a netfilter hook) set `chain_type`,
/// `hook` and `prio`; regular chains leave them null.
pub const ChainSpec = struct {
    family: Family,
    table: []const u8,
    name: []const u8,
    chain_type: ?ChainType = null,
    hook: ?Hook = null,
    prio: ?i32 = null,
    /// Bound interface (netdev family base chains).
    dev: ?[]const u8 = null,
    policy: ?Policy = null,
    userdata: ?[]const u8 = null,
};

/// A rule: an ordered expression list in a chain.
pub const RuleSpec = struct {
    family: Family,
    table: []const u8,
    chain: []const u8,
    exprs: []const expr.Expr = &.{},
    /// Existing rule handle (delete/replace).
    handle: ?u64 = null,
    /// Insert relative to this handle.
    position: ?u64 = null,
    userdata: ?[]const u8 = null,
};

/// A named set.
pub const SetSpec = struct {
    family: Family,
    table: []const u8,
    name: []const u8,
    key_type: SetDataType,
    flags: []const SetFlag = &.{},
    /// Per-batch identifier; a `lookup` in the same batch refers to it.
    id: u32 = 1,
    /// Maximum number of elements (`NFTA_SET_DESC_SIZE`).
    size: ?u32 = null,
    /// Element timeout in **milliseconds** (the kernel's unit here).
    timeout_ms: ?u64 = null,
    userdata: ?[]const u8 = null,
};

/// One set element. `key` is the raw key bytes (`key_type.keyLen()` of them).
pub const SetElem = struct {
    key: []const u8,
    /// Closing bound of an interval element (`NFTA_SET_ELEM_KEY_END`).
    key_end: ?[]const u8 = null,
    /// `NFT_SET_ELEM_*` bits — notably `NFT_SET_ELEM_INTERVAL_END`, which
    /// marks the *exclusive* upper bound of an interval-set range in the
    /// classic (pre-`KEY_END`) encoding the `nft` binary still uses.
    flags: u32 = 0,
    /// Element timeout in milliseconds.
    timeout_ms: ?u64 = null,
    /// Map data half.
    data: ?[]const u8 = null,
};

// ── message building ────────────────────────────────────────────────────────

fn appendTableBody(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    spec: TableSpec,
    with_flags: bool,
) BuildError!void {
    try nl.appendAttrString(gpa, list, NFTA_TABLE.NAME, spec.name);
    if (with_flags) try nl.appendAttrBe32(gpa, list, NFTA_TABLE.FLAGS, spec.flags);
    if (spec.userdata) |u| try nl.appendAttr(gpa, list, NFTA_TABLE.USERDATA, u);
}

fn appendChainBody(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    spec: ChainSpec,
) BuildError!void {
    try nl.appendAttrString(gpa, list, NFTA_CHAIN.TABLE, spec.table);
    try nl.appendAttrString(gpa, list, NFTA_CHAIN.NAME, spec.name);
    if (spec.policy) |p|
        try nl.appendAttrBe32(gpa, list, NFTA_CHAIN.POLICY, @bitCast(p.verdict()));
    if (spec.chain_type) |t|
        try nl.appendAttrString(gpa, list, NFTA_CHAIN.TYPE, t.wireName());
    if (spec.hook) |h| {
        const off = try nl.nestBegin(gpa, list, nl.NLA_F_NESTED | NFTA_CHAIN.HOOK);
        try nl.appendAttrBe32(gpa, list, NFTA_HOOK.HOOKNUM, try h.num(spec.family));
        try nl.appendAttrBe32(
            gpa,
            list,
            NFTA_HOOK.PRIORITY,
            @bitCast(spec.prio orelse 0),
        );
        if (spec.dev) |d| try nl.appendAttrString(gpa, list, NFTA_HOOK.DEV, d);
        nl.nestEnd(list, off);
    }
    if (spec.userdata) |u| try nl.appendAttr(gpa, list, NFTA_CHAIN.USERDATA, u);
}

fn appendRuleBody(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    spec: RuleSpec,
) BuildError!void {
    try nl.appendAttrString(gpa, list, NFTA_RULE.TABLE, spec.table);
    try nl.appendAttrString(gpa, list, NFTA_RULE.CHAIN, spec.chain);
    if (spec.handle) |h| try nl.appendAttrBe64(gpa, list, NFTA_RULE.HANDLE, h);
    if (spec.position) |p| try nl.appendAttrBe64(gpa, list, NFTA_RULE.POSITION, p);
    if (spec.exprs.len > 0) {
        const off = try nl.nestBegin(gpa, list, nl.NLA_F_NESTED | NFTA_RULE.EXPRESSIONS);
        for (spec.exprs) |e| try expr.appendExpr(gpa, list, e);
        nl.nestEnd(list, off);
    }
    if (spec.userdata) |u| try nl.appendAttr(gpa, list, NFTA_RULE.USERDATA, u);
}

fn appendSetBody(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    spec: SetSpec,
    full: bool,
) BuildError!void {
    try nl.appendAttrString(gpa, list, NFTA_SET.TABLE, spec.table);
    try nl.appendAttrString(gpa, list, NFTA_SET.NAME, spec.name);
    if (!full) return; // a delete keys on table+name only
    var flag_bits: u32 = 0;
    for (spec.flags) |f| flag_bits |= f.bit();
    try nl.appendAttrBe32(gpa, list, NFTA_SET.FLAGS, flag_bits);
    try nl.appendAttrBe32(gpa, list, NFTA_SET.KEY_TYPE, spec.key_type.id());
    try nl.appendAttrBe32(gpa, list, NFTA_SET.KEY_LEN, spec.key_type.keyLen());
    try nl.appendAttrBe32(gpa, list, NFTA_SET.ID, spec.id);
    if (spec.size) |s| {
        const off = try nl.nestBegin(gpa, list, nl.NLA_F_NESTED | NFTA_SET.DESC);
        try nl.appendAttrBe32(gpa, list, NFTA_SET_DESC.SIZE, s);
        nl.nestEnd(list, off);
    }
    if (spec.timeout_ms) |t| try nl.appendAttrBe64(gpa, list, NFTA_SET.TIMEOUT, t);
    if (spec.userdata) |u| try nl.appendAttr(gpa, list, NFTA_SET.USERDATA, u);
}

fn appendSetElems(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    table: []const u8,
    set: []const u8,
    set_id: ?u32,
    elems: []const SetElem,
) BuildError!void {
    try nl.appendAttrString(gpa, list, NFTA_SET_ELEM_LIST.TABLE, table);
    try nl.appendAttrString(gpa, list, NFTA_SET_ELEM_LIST.SET, set);
    if (set_id) |id| try nl.appendAttrBe32(gpa, list, NFTA_SET_ELEM_LIST.SET_ID, id);
    const off = try nl.nestBegin(gpa, list, nl.NLA_F_NESTED | NFTA_SET_ELEM_LIST.ELEMENTS);
    // The elements nest is a list whose member type is a 1-based *index*, not
    // a constant `NFTA_LIST_ELEM` — the kernel walks it with
    // `nla_for_each_nested` and ignores the type, and the `nft` binary numbers
    // them (verified in goldens.zig: types 1, 2, 3 for a three-element list).
    for (elems, 1..) |el, i| {
        const eoff = try nl.nestBegin(gpa, list, nl.NLA_F_NESTED | @as(u16, @intCast(i)));
        if (el.flags != 0) try nl.appendAttrBe32(gpa, list, NFTA_SET_ELEM.FLAGS, el.flags);
        {
            const koff = try nl.nestBegin(gpa, list, nl.NLA_F_NESTED | NFTA_SET_ELEM.KEY);
            try nl.appendAttr(gpa, list, expr.NFTA_DATA.VALUE, el.key);
            nl.nestEnd(list, koff);
        }
        if (el.key_end) |ke| {
            const koff = try nl.nestBegin(gpa, list, nl.NLA_F_NESTED | NFTA_SET_ELEM.KEY_END);
            try nl.appendAttr(gpa, list, expr.NFTA_DATA.VALUE, ke);
            nl.nestEnd(list, koff);
        }
        if (el.data) |d| {
            const doff = try nl.nestBegin(gpa, list, nl.NLA_F_NESTED | NFTA_SET_ELEM.DATA);
            try nl.appendAttr(gpa, list, expr.NFTA_DATA.VALUE, d);
            nl.nestEnd(list, doff);
        }
        if (el.timeout_ms) |t| try nl.appendAttrBe64(gpa, list, NFTA_SET_ELEM.TIMEOUT, t);
        nl.nestEnd(list, eoff);
    }
    nl.nestEnd(list, off);
}

// ── the batch ───────────────────────────────────────────────────────────────

/// Which part of the transaction an error came from.
pub const Stage = enum {
    /// The kernel rejected one staged command; `Entry` names it.
    message,
    /// The kernel rejected the transaction as a whole (the error is reported
    /// against the `BATCH_BEGIN` sequence number).
    commit,
    /// The sequence number belongs to no message of this batch.
    unknown,
};

/// One message of a batch, for error attribution.
pub const Entry = struct {
    /// Zero-based position among the batch's *commands* (BATCH_BEGIN excluded).
    index: usize,
    seq: u32,
    /// `nlmsg_type`, e.g. `nftMsg(NFT_MSG.NEWCHAIN)`.
    msg_type: u16,

    /// The `NFT_MSG_*` name, for diagnostics.
    pub fn commandName(e: Entry) []const u8 {
        return commandNameOf(e.msg_type);
    }
};

/// Human-readable `NFT_MSG_*` name of an nftables `nlmsg_type`.
pub fn commandNameOf(msg_type: u16) []const u8 {
    if (msg_type == NFNL_MSG_BATCH_BEGIN) return "BATCH_BEGIN";
    if (msg_type == NFNL_MSG_BATCH_END) return "BATCH_END";
    if (msg_type >> 8 != NFNL_SUBSYS_NFTABLES) return "?";
    return switch (@as(u8, @truncate(msg_type))) {
        NFT_MSG.NEWTABLE => "NEWTABLE",
        NFT_MSG.GETTABLE => "GETTABLE",
        NFT_MSG.DELTABLE => "DELTABLE",
        NFT_MSG.NEWCHAIN => "NEWCHAIN",
        NFT_MSG.GETCHAIN => "GETCHAIN",
        NFT_MSG.DELCHAIN => "DELCHAIN",
        NFT_MSG.NEWRULE => "NEWRULE",
        NFT_MSG.GETRULE => "GETRULE",
        NFT_MSG.DELRULE => "DELRULE",
        NFT_MSG.NEWSET => "NEWSET",
        NFT_MSG.GETSET => "GETSET",
        NFT_MSG.DELSET => "DELSET",
        NFT_MSG.NEWSETELEM => "NEWSETELEM",
        NFT_MSG.GETSETELEM => "GETSETELEM",
        NFT_MSG.DELSETELEM => "DELSETELEM",
        else => "?",
    };
}

pub const BatchOptions = struct {
    /// Set `NLM_F_ACK` on every command so the kernel confirms each one.
    ///
    /// The `nft` binary leaves this off and infers success from the absence of
    /// an error, which needs a receive timeout and cannot distinguish "applied"
    /// from "reply lost". Default on; the goldens turn it off to stay
    /// byte-identical to `nft`.
    ack: bool = true,
};

/// A transactional nftables batch: `BATCH_BEGIN`, n commands, `BATCH_END`, all
/// in one buffer to be sent with a single `sendmsg`.
///
/// The buffer is complete only after `finish()`; `bytes()` before that returns
/// the commands without their `BATCH_END` and the kernel would apply nothing.
pub const Batch = struct {
    gpa: std.mem.Allocator,
    buf: std.ArrayList(u8) = .empty,
    entries: std.ArrayList(Entry) = .empty,
    opts: BatchOptions,
    /// The `BATCH_BEGIN` sequence number; commands run from `first_seq + 1`.
    first_seq: u32,
    next_seq: u32,
    finished: bool = false,

    /// Start a batch whose `BATCH_BEGIN` carries `first_seq`.
    pub fn init(gpa: std.mem.Allocator, first_seq: u32, opts: BatchOptions) BuildError!Batch {
        var b: Batch = .{
            .gpa = gpa,
            .opts = opts,
            .first_seq = first_seq,
            .next_seq = first_seq +% 1,
        };
        errdefer b.deinit();
        try b.appendControl(NFNL_MSG_BATCH_BEGIN, first_seq);
        return b;
    }

    pub fn deinit(b: *Batch) void {
        b.buf.deinit(b.gpa);
        b.entries.deinit(b.gpa);
        b.* = undefined;
    }

    fn appendControl(b: *Batch, msg_type: u16, seq: u32) BuildError!void {
        const h = try nl.appendHeader(b.gpa, &b.buf, msg_type, nl.NLM_F_REQUEST, seq, 0);
        // The control messages carry AF_UNSPEC and put the *subsystem* in
        // res_id — that is how the kernel routes the batch to nf_tables.
        try appendNfgenmsg(b.gpa, &b.buf, types.NFPROTO.UNSPEC, NFNL_SUBSYS_NFTABLES);
        nl.finishHeader(&b.buf, h);
    }

    /// Begin a command message; returns the header offset for `endCommand`.
    fn beginCommand(b: *Batch, cmd: u8, extra_flags: u16, nfproto: u8) BuildError!usize {
        std.debug.assert(!b.finished);
        const seq = b.next_seq;
        b.next_seq +%= 1;
        const flags: u16 = nl.NLM_F_REQUEST | extra_flags |
            (if (b.opts.ack) nl.NLM_F_ACK else 0);
        try b.entries.append(b.gpa, .{
            .index = b.entries.items.len,
            .seq = seq,
            .msg_type = nftMsg(cmd),
        });
        const h = try nl.appendHeader(b.gpa, &b.buf, nftMsg(cmd), flags, seq, 0);
        try appendNfgenmsg(b.gpa, &b.buf, nfproto, 0);
        return h;
    }

    fn endCommand(b: *Batch, h: usize) void {
        nl.finishHeader(&b.buf, h);
    }

    /// Close the batch with `BATCH_END`. Idempotent.
    pub fn finish(b: *Batch) BuildError![]const u8 {
        if (!b.finished) {
            try b.appendControl(NFNL_MSG_BATCH_END, b.next_seq);
            b.next_seq +%= 1;
            b.finished = true;
        }
        return b.buf.items;
    }

    /// The bytes accumulated so far.
    pub fn bytes(b: *const Batch) []const u8 {
        return b.buf.items;
    }

    /// How many commands (excluding BATCH_BEGIN/END) the batch carries.
    pub fn commandCount(b: *const Batch) usize {
        return b.entries.items.len;
    }

    /// The command a sequence number belongs to, or null.
    pub fn entryForSeq(b: *const Batch, seq: u32) ?Entry {
        for (b.entries.items) |e| {
            if (e.seq == seq) return e;
        }
        return null;
    }

    /// Which stage of the transaction a reply's sequence number names.
    pub fn stageForSeq(b: *const Batch, seq: u32) Stage {
        if (seq == b.first_seq) return .commit;
        if (b.entryForSeq(seq) != null) return .message;
        return .unknown;
    }

    // ── commands ───────────────────────────────────────────────────────────

    /// `add table` — `NLM_F_CREATE` is deliberately *not* set, matching `nft`:
    /// a `NEWTABLE` for an existing table is a no-op rather than an error.
    pub fn addTable(b: *Batch, spec: TableSpec) BuildError!void {
        const h = try b.beginCommand(NFT_MSG.NEWTABLE, 0, spec.family.nfproto());
        try appendTableBody(b.gpa, &b.buf, spec, true);
        b.endCommand(h);
    }

    /// `delete table` — removes the table and everything in it.
    pub fn deleteTable(b: *Batch, family: Family, name: []const u8) BuildError!void {
        const h = try b.beginCommand(NFT_MSG.DELTABLE, 0, family.nfproto());
        try appendTableBody(b.gpa, &b.buf, .{ .family = family, .name = name }, false);
        b.endCommand(h);
    }

    /// `flush ruleset` — a `DELTABLE` with no name and `NFPROTO_UNSPEC` wipes
    /// every table of every family. Named separately so it cannot happen by
    /// accident through `deleteTable`.
    pub fn flushRuleset(b: *Batch) BuildError!void {
        const h = try b.beginCommand(NFT_MSG.DELTABLE, 0, types.NFPROTO.UNSPEC);
        b.endCommand(h);
    }

    pub fn addChain(b: *Batch, spec: ChainSpec) BuildError!void {
        const h = try b.beginCommand(NFT_MSG.NEWCHAIN, nl.NLM_F_CREATE, spec.family.nfproto());
        try appendChainBody(b.gpa, &b.buf, spec);
        b.endCommand(h);
    }

    pub fn deleteChain(b: *Batch, family: Family, table: []const u8, name: []const u8) BuildError!void {
        const h = try b.beginCommand(NFT_MSG.DELCHAIN, 0, family.nfproto());
        try nl.appendAttrString(b.gpa, &b.buf, NFTA_CHAIN.TABLE, table);
        try nl.appendAttrString(b.gpa, &b.buf, NFTA_CHAIN.NAME, name);
        b.endCommand(h);
    }

    /// `add rule` — appended to the end of the chain (`NLM_F_APPEND`).
    pub fn addRule(b: *Batch, spec: RuleSpec) BuildError!void {
        const h = try b.beginCommand(
            NFT_MSG.NEWRULE,
            nl.NLM_F_CREATE | nl.NLM_F_APPEND,
            spec.family.nfproto(),
        );
        try appendRuleBody(b.gpa, &b.buf, spec);
        b.endCommand(h);
    }

    /// `insert rule` — prepended (or placed before `spec.position`).
    pub fn insertRule(b: *Batch, spec: RuleSpec) BuildError!void {
        const h = try b.beginCommand(NFT_MSG.NEWRULE, nl.NLM_F_CREATE, spec.family.nfproto());
        try appendRuleBody(b.gpa, &b.buf, spec);
        b.endCommand(h);
    }

    /// `delete rule … handle N`.
    pub fn deleteRule(
        b: *Batch,
        family: Family,
        table: []const u8,
        chain: []const u8,
        handle: u64,
    ) BuildError!void {
        const h = try b.beginCommand(NFT_MSG.DELRULE, 0, family.nfproto());
        try appendRuleBody(b.gpa, &b.buf, .{
            .family = family,
            .table = table,
            .chain = chain,
            .handle = handle,
        });
        b.endCommand(h);
    }

    /// `flush chain` — a handle-less `DELRULE` empties the whole chain.
    pub fn flushChain(b: *Batch, family: Family, table: []const u8, chain: []const u8) BuildError!void {
        const h = try b.beginCommand(NFT_MSG.DELRULE, 0, family.nfproto());
        try nl.appendAttrString(b.gpa, &b.buf, NFTA_RULE.TABLE, table);
        try nl.appendAttrString(b.gpa, &b.buf, NFTA_RULE.CHAIN, chain);
        b.endCommand(h);
    }

    pub fn addSet(b: *Batch, spec: SetSpec) BuildError!void {
        const h = try b.beginCommand(NFT_MSG.NEWSET, nl.NLM_F_CREATE, spec.family.nfproto());
        try appendSetBody(b.gpa, &b.buf, spec, true);
        b.endCommand(h);
    }

    pub fn deleteSet(b: *Batch, family: Family, table: []const u8, name: []const u8) BuildError!void {
        const h = try b.beginCommand(NFT_MSG.DELSET, 0, family.nfproto());
        try nl.appendAttrString(b.gpa, &b.buf, NFTA_SET.TABLE, table);
        try nl.appendAttrString(b.gpa, &b.buf, NFTA_SET.NAME, name);
        b.endCommand(h);
    }

    /// `add element` — `set_id` is only needed when the set is created in this
    /// same batch (the kernel resolves the name first and falls back to the id).
    pub fn addSetElems(
        b: *Batch,
        family: Family,
        table: []const u8,
        set: []const u8,
        set_id: ?u32,
        elems: []const SetElem,
    ) BuildError!void {
        const h = try b.beginCommand(NFT_MSG.NEWSETELEM, nl.NLM_F_CREATE, family.nfproto());
        try appendSetElems(b.gpa, &b.buf, table, set, set_id, elems);
        b.endCommand(h);
    }

    /// `delete element`.
    pub fn deleteSetElems(
        b: *Batch,
        family: Family,
        table: []const u8,
        set: []const u8,
        elems: []const SetElem,
    ) BuildError!void {
        const h = try b.beginCommand(NFT_MSG.DELSETELEM, 0, family.nfproto());
        try appendSetElems(b.gpa, &b.buf, table, set, null, elems);
        b.endCommand(h);
    }
};

// ── dump requests (outside any batch) ───────────────────────────────────────

/// A bare `NFT_MSG_GET*` + `NLM_F_DUMP` request — 20 fixed bytes, no
/// allocator. Dumps are *not* batched: they are ordinary nfnetlink
/// request/response traffic.
pub fn buildDumpRequest(seq: u32, cmd: u8, family: Family) [nl.header_len + nfgenmsg_len]u8 {
    var req: [nl.header_len + nfgenmsg_len]u8 = @splat(0);
    std.mem.writeInt(u32, req[0..4], req.len, native_endian);
    std.mem.writeInt(u16, req[4..6], nftMsg(cmd), native_endian);
    std.mem.writeInt(u16, req[6..8], nl.NLM_F_REQUEST | nl.NLM_F_DUMP, native_endian);
    std.mem.writeInt(u32, req[8..12], seq, native_endian);
    req[nl.header_len] = family.nfproto();
    req[nl.header_len + 1] = NFNETLINK_V0;
    // res_id (__be16) stays 0.
    return req;
}

/// `NFT_MSG_GETRULE` + `NLM_F_DUMP` scoped to one table/chain. Caller frees.
pub fn buildRuleDumpRequest(
    gpa: std.mem.Allocator,
    seq: u32,
    family: Family,
    table: ?[]const u8,
    chain: ?[]const u8,
) BuildError![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const h = try nl.appendHeader(
        gpa,
        &list,
        nftMsg(NFT_MSG.GETRULE),
        nl.NLM_F_REQUEST | nl.NLM_F_DUMP,
        seq,
        0,
    );
    try appendNfgenmsg(gpa, &list, family.nfproto(), 0);
    if (table) |t| try nl.appendAttrString(gpa, &list, NFTA_RULE.TABLE, t);
    if (chain) |c| try nl.appendAttrString(gpa, &list, NFTA_RULE.CHAIN, c);
    nl.finishHeader(&list, h);
    return list.toOwnedSlice(gpa);
}

/// `NFT_MSG_GETSETELEM` + `NLM_F_DUMP` for one set. Caller frees.
pub fn buildSetElemDumpRequest(
    gpa: std.mem.Allocator,
    seq: u32,
    family: Family,
    table: []const u8,
    set: []const u8,
) BuildError![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const h = try nl.appendHeader(
        gpa,
        &list,
        nftMsg(NFT_MSG.GETSETELEM),
        nl.NLM_F_REQUEST | nl.NLM_F_DUMP,
        seq,
        0,
    );
    try appendNfgenmsg(gpa, &list, family.nfproto(), 0);
    try nl.appendAttrString(gpa, &list, NFTA_SET_ELEM_LIST.TABLE, table);
    try nl.appendAttrString(gpa, &list, NFTA_SET_ELEM_LIST.SET, set);
    nl.finishHeader(&list, h);
    return list.toOwnedSlice(gpa);
}

// ── decoding ────────────────────────────────────────────────────────────────

/// A table as the kernel reports it. All slices borrow from the reply buffer.
pub const TableInfo = struct {
    family: u8,
    name: []const u8 = "",
    flags: u32 = 0,
    use: u32 = 0,
    handle: u64 = 0,
};

/// A chain as the kernel reports it.
pub const ChainInfo = struct {
    family: u8,
    table: []const u8 = "",
    name: []const u8 = "",
    handle: u64 = 0,
    chain_type: ?[]const u8 = null,
    hooknum: ?u32 = null,
    prio: ?i32 = null,
    dev: ?[]const u8 = null,
    policy: ?i32 = null,
    /// Number of rules referencing this chain.
    use: u32 = 0,
};

/// A rule as the kernel reports it. `expressions` are the raw
/// `NFTA_RULE_EXPRESSIONS` bytes — walk them with `expr.ExprIterator`.
pub const RuleInfo = struct {
    family: u8,
    table: []const u8 = "",
    chain: []const u8 = "",
    handle: u64 = 0,
    expressions: []const u8 = &.{},

    pub fn exprIterator(r: RuleInfo) expr.ExprIterator {
        return .{ .attrs = .{ .buf = r.expressions } };
    }
};

/// A set as the kernel reports it.
pub const SetInfo = struct {
    family: u8,
    table: []const u8 = "",
    name: []const u8 = "",
    flags: u32 = 0,
    key_type: u32 = 0,
    key_len: u32 = 0,
    handle: u64 = 0,
    size: ?u32 = null,
    timeout_ms: ?u64 = null,
};

/// One decoded set element. `key`/`key_end`/`data` borrow from the reply.
pub const SetElemInfo = struct {
    key: []const u8 = &.{},
    key_end: ?[]const u8 = null,
    data: ?[]const u8 = null,
    flags: u32 = 0,
    timeout_ms: ?u64 = null,
};

fn dataValue(a: nl.Attr) DecodeError![]const u8 {
    var it = a.nested();
    while (try it.next()) |d| {
        if (d.type == expr.NFTA_DATA.VALUE) return d.data;
    }
    return &.{};
}

pub fn decodeTable(payload: []const u8) DecodeError!TableInfo {
    const hdr = try parseNfgenmsg(payload);
    var out: TableInfo = .{ .family = hdr.family };
    var it = hdr.attrIterator();
    while (try it.next()) |a| switch (a.type) {
        NFTA_TABLE.NAME => out.name = a.asString(),
        NFTA_TABLE.FLAGS => out.flags = try a.asBe32(),
        NFTA_TABLE.USE => out.use = try a.asBe32(),
        NFTA_TABLE.HANDLE => out.handle = try a.asBe64(),
        else => {},
    };
    return out;
}

pub fn decodeChain(payload: []const u8) DecodeError!ChainInfo {
    const hdr = try parseNfgenmsg(payload);
    var out: ChainInfo = .{ .family = hdr.family };
    var it = hdr.attrIterator();
    while (try it.next()) |a| switch (a.type) {
        NFTA_CHAIN.TABLE => out.table = a.asString(),
        NFTA_CHAIN.NAME => out.name = a.asString(),
        NFTA_CHAIN.HANDLE => out.handle = try a.asBe64(),
        NFTA_CHAIN.TYPE => out.chain_type = a.asString(),
        NFTA_CHAIN.POLICY => out.policy = @bitCast(try a.asBe32()),
        NFTA_CHAIN.USE => out.use = try a.asBe32(),
        NFTA_CHAIN.HOOK => {
            var hk = a.nested();
            while (try hk.next()) |ha| switch (ha.type) {
                NFTA_HOOK.HOOKNUM => out.hooknum = try ha.asBe32(),
                NFTA_HOOK.PRIORITY => out.prio = @bitCast(try ha.asBe32()),
                NFTA_HOOK.DEV => out.dev = ha.asString(),
                else => {},
            };
        },
        else => {},
    };
    return out;
}

pub fn decodeRule(payload: []const u8) DecodeError!RuleInfo {
    const hdr = try parseNfgenmsg(payload);
    var out: RuleInfo = .{ .family = hdr.family };
    var it = hdr.attrIterator();
    while (try it.next()) |a| switch (a.type) {
        NFTA_RULE.TABLE => out.table = a.asString(),
        NFTA_RULE.CHAIN => out.chain = a.asString(),
        NFTA_RULE.HANDLE => out.handle = try a.asBe64(),
        NFTA_RULE.EXPRESSIONS => out.expressions = a.data,
        else => {},
    };
    return out;
}

pub fn decodeSet(payload: []const u8) DecodeError!SetInfo {
    const hdr = try parseNfgenmsg(payload);
    var out: SetInfo = .{ .family = hdr.family };
    var it = hdr.attrIterator();
    while (try it.next()) |a| switch (a.type) {
        NFTA_SET.TABLE => out.table = a.asString(),
        NFTA_SET.NAME => out.name = a.asString(),
        NFTA_SET.FLAGS => out.flags = try a.asBe32(),
        NFTA_SET.KEY_TYPE => out.key_type = try a.asBe32(),
        NFTA_SET.KEY_LEN => out.key_len = try a.asBe32(),
        NFTA_SET.HANDLE => out.handle = try a.asBe64(),
        NFTA_SET.TIMEOUT => out.timeout_ms = try a.asBe64(),
        NFTA_SET.DESC => {
            var d = a.nested();
            while (try d.next()) |da| switch (da.type) {
                NFTA_SET_DESC.SIZE => out.size = try da.asBe32(),
                else => {},
            };
        },
        else => {},
    };
    return out;
}

/// The table/set a `NFT_MSG_NEWSETELEM` reply belongs to, plus a walker over
/// its elements.
pub const SetElemReply = struct {
    family: u8,
    table: []const u8 = "",
    set: []const u8 = "",
    elements: []const u8 = &.{},

    pub fn iterator(r: SetElemReply) SetElemIterator {
        return .{ .attrs = .{ .buf = r.elements } };
    }
};

pub const SetElemIterator = struct {
    attrs: nl.AttrIterator,

    pub fn next(it: *SetElemIterator) DecodeError!?SetElemInfo {
        while (try it.attrs.next()) |elem| {
            var out: SetElemInfo = .{};
            var seen_key = false;
            var inner = elem.nested();
            while (try inner.next()) |a| switch (a.type) {
                NFTA_SET_ELEM.KEY => {
                    out.key = try dataValue(a);
                    seen_key = true;
                },
                NFTA_SET_ELEM.KEY_END => out.key_end = try dataValue(a),
                NFTA_SET_ELEM.DATA => out.data = try dataValue(a),
                NFTA_SET_ELEM.FLAGS => out.flags = try a.asBe32(),
                NFTA_SET_ELEM.TIMEOUT => out.timeout_ms = try a.asBe64(),
                else => {},
            };
            if (!seen_key) continue;
            return out;
        }
        return null;
    }
};

pub fn decodeSetElemReply(payload: []const u8) DecodeError!SetElemReply {
    const hdr = try parseNfgenmsg(payload);
    var out: SetElemReply = .{ .family = hdr.family };
    var it = hdr.attrIterator();
    while (try it.next()) |a| switch (a.type) {
        NFTA_SET_ELEM_LIST.TABLE => out.table = a.asString(),
        NFTA_SET_ELEM_LIST.SET => out.set = a.asString(),
        NFTA_SET_ELEM_LIST.ELEMENTS => out.elements = a.data,
        else => {},
    };
    return out;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "message type composition" {
    try testing.expectEqual(@as(u16, 0x0a00), nftMsg(NFT_MSG.NEWTABLE));
    try testing.expectEqual(@as(u16, 0x0a03), nftMsg(NFT_MSG.NEWCHAIN));
    try testing.expectEqual(@as(u16, 0x0a06), nftMsg(NFT_MSG.NEWRULE));
    try testing.expectEqual(@as(u16, 0x0a0c), nftMsg(NFT_MSG.NEWSETELEM));
    try testing.expectEqualStrings("NEWRULE", commandNameOf(nftMsg(NFT_MSG.NEWRULE)));
    try testing.expectEqualStrings("BATCH_END", commandNameOf(NFNL_MSG_BATCH_END));
}

test "nfgenmsg round-trip keeps res_id big-endian" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    try appendNfgenmsg(testing.allocator, &list, types.NFPROTO.INET, NFNL_SUBSYS_NFTABLES);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x00, 0x00, 0x0a }, list.items);
    const parsed = try parseNfgenmsg(list.items);
    try testing.expectEqual(@as(u8, 1), parsed.family);
    try testing.expectEqual(@as(u16, 10), parsed.res_id);
    try testing.expectEqual(@as(usize, 0), parsed.attrs.len);
    try testing.expectError(error.Truncated, parseNfgenmsg(&.{ 1, 0 }));
}

test "batch framing: begin/end sequence numbers and command attribution" {
    const gpa = testing.allocator;
    var b = try Batch.init(gpa, 100, .{});
    defer b.deinit();
    try b.addTable(.{ .family = .inet, .name = "t" });
    try b.addChain(.{ .family = .inet, .table = "t", .name = "c" });
    try b.addRule(.{ .family = .inet, .table = "t", .chain = "c" });
    const bytes = try b.finish();

    try testing.expectEqual(@as(usize, 3), b.commandCount());
    try testing.expectEqual(Stage.commit, b.stageForSeq(100));
    try testing.expectEqual(Stage.message, b.stageForSeq(101));
    try testing.expectEqual(Stage.message, b.stageForSeq(103));
    try testing.expectEqual(Stage.unknown, b.stageForSeq(104)); // BATCH_END
    try testing.expectEqual(@as(usize, 1), b.entryForSeq(102).?.index);
    try testing.expectEqualStrings("NEWCHAIN", b.entryForSeq(102).?.commandName());

    // Walk the finished buffer: BEGIN, three commands, END.
    var it: nl.MessageIterator = .{ .buf = bytes };
    const begin = (try it.next()).?;
    try testing.expectEqual(NFNL_MSG_BATCH_BEGIN, begin.type);
    try testing.expectEqual(@as(u32, 100), begin.seq);
    try testing.expectEqual(@as(u16, NFNL_SUBSYS_NFTABLES), (try parseNfgenmsg(begin.payload)).res_id);

    var n: usize = 0;
    var last: nl.Message = begin;
    while (try it.next()) |m| {
        last = m;
        if (m.type == NFNL_MSG_BATCH_END) break;
        n += 1;
        try testing.expectEqual(@as(u32, 100 + @as(u32, @intCast(n))), m.seq);
        try testing.expect(m.flags & nl.NLM_F_ACK != 0);
    }
    try testing.expectEqual(@as(usize, 3), n);
    try testing.expectEqual(NFNL_MSG_BATCH_END, last.type);
    try testing.expectEqual(@as(u32, 104), last.seq);
    try testing.expectEqual(@as(?nl.Message, null), try it.next());

    // finish() is idempotent — a second call must not append another END.
    const again = try b.finish();
    try testing.expectEqual(bytes.len, again.len);
}

test "ack option is what distinguishes our framing from nft's" {
    const gpa = testing.allocator;
    var b = try Batch.init(gpa, 0, .{ .ack = false });
    defer b.deinit();
    try b.addTable(.{ .family = .inet, .name = "t" });
    _ = try b.finish();
    var it: nl.MessageIterator = .{ .buf = b.bytes() };
    _ = try it.next(); // BATCH_BEGIN
    const cmd = (try it.next()).?;
    try testing.expectEqual(nl.NLM_F_REQUEST, cmd.flags);
}

test "chain hook nest is rejected for an impossible family/hook pair" {
    const gpa = testing.allocator;
    var b = try Batch.init(gpa, 1, .{});
    defer b.deinit();
    try testing.expectError(error.UnsupportedHook, b.addChain(.{
        .family = .netdev,
        .table = "t",
        .name = "c",
        .chain_type = .filter,
        .hook = .input,
        .prio = 0,
    }));
}

test "decode round-trip: table, chain, rule, set and elements" {
    const gpa = testing.allocator;
    var b = try Batch.init(gpa, 1, .{});
    defer b.deinit();
    try b.addTable(.{ .family = .inet, .name = "filter" });
    try b.addChain(.{
        .family = .inet,
        .table = "filter",
        .name = "input",
        .chain_type = .filter,
        .hook = .input,
        .prio = -5,
        .policy = .drop,
    });
    var p = expr.Program.init(gpa, .inet);
    defer p.deinit();
    _ = p.tcpDport(22).counter().accept();
    try b.addRule(.{
        .family = .inet,
        .table = "filter",
        .chain = "input",
        .exprs = try p.finish(),
    });
    try b.addSet(.{
        .family = .inet,
        .table = "filter",
        .name = "blocked",
        .key_type = .ipv4_addr,
        .flags = &.{.interval},
        .size = 1024,
        .timeout_ms = 10_000,
    });
    try b.addSetElems(.inet, "filter", "blocked", 1, &.{
        .{ .key = &.{ 10, 0, 0, 1 } },
        .{ .key = &.{ 10, 0, 0, 2 }, .flags = NFT_SET_ELEM_INTERVAL_END },
    });
    _ = try b.finish();

    var it: nl.MessageIterator = .{ .buf = b.bytes() };
    _ = try it.next(); // BATCH_BEGIN

    const t = try decodeTable((try it.next()).?.payload);
    try testing.expectEqual(types.NFPROTO.INET, t.family);
    try testing.expectEqualStrings("filter", t.name);

    const c = try decodeChain((try it.next()).?.payload);
    try testing.expectEqualStrings("input", c.name);
    try testing.expectEqualStrings("filter", c.chain_type.?);
    try testing.expectEqual(@as(?u32, 1), c.hooknum);
    try testing.expectEqual(@as(?i32, -5), c.prio);
    try testing.expectEqual(@as(?i32, 0), c.policy); // NF_DROP

    const r = try decodeRule((try it.next()).?.payload);
    try testing.expectEqualStrings("input", r.chain);
    var ei = r.exprIterator();
    var names: usize = 0;
    while (try ei.next()) |_| names += 1;
    try testing.expectEqual(@as(usize, 6), names); // meta,cmp,payload,cmp,counter,immediate

    const s = try decodeSet((try it.next()).?.payload);
    try testing.expectEqualStrings("blocked", s.name);
    try testing.expectEqual(SetFlag.interval.bit(), s.flags);
    try testing.expectEqual(@as(u32, 7), s.key_type);
    try testing.expectEqual(@as(u32, 4), s.key_len);
    try testing.expectEqual(@as(?u32, 1024), s.size);
    try testing.expectEqual(@as(?u64, 10_000), s.timeout_ms);

    const se = try decodeSetElemReply((try it.next()).?.payload);
    try testing.expectEqualStrings("blocked", se.set);
    var sit = se.iterator();
    const e1 = (try sit.next()).?;
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 1 }, e1.key);
    try testing.expectEqual(@as(u32, 0), e1.flags);
    const e2 = (try sit.next()).?;
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 2 }, e2.key);
    try testing.expectEqual(NFT_SET_ELEM_INTERVAL_END, e2.flags);
    try testing.expectEqual(@as(?SetElemInfo, null), try sit.next());
}

test "dump requests are 20 fixed bytes with the right type and family" {
    if (native_endian != .little) return error.SkipZigTest;
    const req = buildDumpRequest(7, NFT_MSG.GETTABLE, .ip);
    try testing.expectEqualSlices(u8, &.{
        0x14, 0x00, 0x00, 0x00, // len 20
        0x01, 0x0a, // NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_GETTABLE
        0x01, 0x03, // REQUEST | DUMP
        0x07, 0x00, 0x00, 0x00, // seq
        0x00, 0x00, 0x00, 0x00, // pid
        0x02, 0x00, 0x00, 0x00, // NFPROTO_IPV4, v0, res_id 0
    }, &req);
}

test "scoped rule and set-element dump requests carry their names" {
    const gpa = testing.allocator;
    const req = try buildRuleDumpRequest(gpa, 3, .inet, "filter", "input");
    defer gpa.free(req);
    var it: nl.MessageIterator = .{ .buf = req };
    const m = (try it.next()).?;
    try testing.expectEqual(nftMsg(NFT_MSG.GETRULE), m.type);
    try testing.expect(m.flags & nl.NLM_F_DUMP != 0);
    const hdr = try parseNfgenmsg(m.payload);
    var a = hdr.attrIterator();
    try testing.expectEqualStrings("filter", (try a.next()).?.asString());
    try testing.expectEqualStrings("input", (try a.next()).?.asString());

    const sreq = try buildSetElemDumpRequest(gpa, 4, .inet, "filter", "blocked");
    defer gpa.free(sreq);
    var sit: nl.MessageIterator = .{ .buf = sreq };
    const sm = (try sit.next()).?;
    try testing.expectEqual(nftMsg(NFT_MSG.GETSETELEM), sm.type);
}

test "decoders survive hostile and truncated attribute streams" {
    // nfgenmsg present, attribute claims 200 bytes inside 8.
    var bad: [nfgenmsg_len + 8]u8 = @splat(0);
    std.mem.writeInt(u16, bad[nfgenmsg_len..][0..2], 200, native_endian);
    std.mem.writeInt(u16, bad[nfgenmsg_len..][2..4], NFTA_TABLE.NAME, native_endian);
    try testing.expectError(error.Truncated, decodeTable(&bad));

    // Zero-length TLV must not loop forever.
    var zero: [nfgenmsg_len + 4]u8 = @splat(0);
    std.mem.writeInt(u16, zero[nfgenmsg_len..][2..4], NFTA_CHAIN.NAME, native_endian);
    try testing.expectError(error.BadLength, decodeChain(&zero));

    // A NFTA_TABLE_FLAGS of the wrong width is a length error, not a panic.
    var wide: std.ArrayList(u8) = .empty;
    defer wide.deinit(testing.allocator);
    try appendNfgenmsg(testing.allocator, &wide, types.NFPROTO.INET, 0);
    try nl.appendAttr(testing.allocator, &wide, NFTA_TABLE.FLAGS, &.{ 1, 2 });
    try testing.expectError(error.BadLength, decodeTable(wide.items));

    // Payload shorter than nfgenmsg.
    try testing.expectError(error.Truncated, decodeRule(&.{ 1, 0 }));
}

test "fuzz: object decoders never crash, loop or over-read" {
    try testing.fuzz({}, fuzzDecoders, .{});
}

fn fuzzDecoders(_: void, smith: *std.testing.Smith) !void {
    var raw: [512]u8 = undefined;
    smith.bytes(&raw);
    const len = smith.valueRangeAtMost(u16, 0, raw.len);
    const buf = raw[0..len];

    _ = decodeTable(buf) catch {};
    _ = decodeChain(buf) catch {};
    _ = decodeSet(buf) catch {};
    if (decodeRule(buf) catch null) |r| {
        var ei = r.exprIterator();
        var steps: usize = 0;
        while (ei.next() catch null) |_| {
            steps += 1;
            try testing.expect(steps <= r.expressions.len / 4 + 1);
        }
    }
    if (decodeSetElemReply(buf) catch null) |sr| {
        var si = sr.iterator();
        var steps: usize = 0;
        while (si.next() catch null) |_| {
            steps += 1;
            try testing.expect(steps <= sr.elements.len / 4 + 1);
        }
    }
}
