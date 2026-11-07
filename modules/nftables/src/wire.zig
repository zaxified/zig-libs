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
// Test-only (`build.zig`'s `test_deps`, never `deps`): the fuzz corpus seed
// helpers, in the format `std.testing.Smith` actually reads.
const testkit = @import("testkit");

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
    pub const GETOBJ_RESET: u8 = 21;
    pub const NEWFLOWTABLE: u8 = 22;
    pub const GETFLOWTABLE: u8 = 23;
    pub const DELFLOWTABLE: u8 = 24;
    pub const GETRULE_RESET: u8 = 25;
    /// `destroy` = delete, but not an error when the object is absent
    /// (kernel 6.3+; older kernels answer `EOPNOTSUPP`).
    pub const DESTROYTABLE: u8 = 26;
    pub const DESTROYCHAIN: u8 = 27;
    pub const DESTROYRULE: u8 = 28;
    pub const DESTROYSET: u8 = 29;
    pub const DESTROYSETELEM: u8 = 30;
    pub const DESTROYOBJ: u8 = 31;
    pub const DESTROYFLOWTABLE: u8 = 32;
    pub const GETSETELEM_RESET: u8 = 33;
};

/// `NFNL_BATCH_GENID` — attribute of `BATCH_BEGIN`: the ruleset generation
/// the batch was built against (the kernel answers `ERESTART`/`EINTR` when
/// it has moved on).
pub const NFNL_BATCH_GENID: u16 = 1;

/// `enum nft_table_flags`.
pub const NFT_TABLE_F = struct {
    pub const DORMANT: u32 = 1;
    pub const OWNER: u32 = 2;
    pub const PERSIST: u32 = 4;
};

/// `enum nft_chain_flags`.
pub const NFT_CHAIN_F = struct {
    pub const BASE: u32 = 1;
    pub const HW_OFFLOAD: u32 = 2;
    pub const BINDING: u32 = 4;
};

/// `enum nft_set_flags` — the bits `SetFlag` does not name (`SetSpec.raw_flags`).
pub const NFT_SET_F = struct {
    pub const ANONYMOUS: u32 = 0x01;
    pub const CONSTANT: u32 = 0x02;
    pub const INTERVAL: u32 = 0x04;
    pub const MAP: u32 = 0x08;
    pub const TIMEOUT: u32 = 0x10;
    pub const EVAL: u32 = 0x20;
    pub const OBJECT: u32 = 0x40;
    pub const CONCAT: u32 = 0x80;
    pub const EXPR: u32 = 0x100;
};

/// `enum nft_set_policies`.
pub const SetPolicy = enum(u32) { performance = 0, memory = 1 };

/// The name `nft` gives an anonymous set (`tcp dport { 22, 80 }`): the
/// kernel substitutes a unique one, the `lookup` finds it by `SetSpec.id`.
pub const anon_set_name = "__set%d";

/// `enum nft_flowtable_flags`.
pub const NFT_FLOWTABLE_F = struct {
    pub const HW_OFFLOAD: u32 = 1;
    pub const COUNTER: u32 = 2;
};

/// `enum nft_flowtable_attributes`.
pub const NFTA_FLOWTABLE = struct {
    pub const TABLE: u16 = 1;
    pub const NAME: u16 = 2;
    pub const HOOK: u16 = 3;
    pub const USE: u16 = 4;
    pub const HANDLE: u16 = 5;
    pub const FLAGS: u16 = 7;
};

/// `enum nft_flowtable_hook_attributes`.
pub const NFTA_FLOWTABLE_HOOK = struct {
    pub const NUM: u16 = 1;
    pub const PRIORITY: u16 = 2;
    pub const DEVS: u16 = 3;
};

/// `enum nft_devices_attributes`.
pub const NFTA_DEVICE_NAME: u16 = 1;

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
    pub const EXPR: u16 = 17;
};

/// `NFTA_SET_FIELD_LEN` — one component's length inside `NFTA_SET_DESC_CONCAT`.
pub const NFTA_SET_FIELD_LEN: u16 = 1;

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

/// `enum nft_object_attributes`. `NFTA_OBJ_TABLE` … `USERDATA`.
pub const NFTA_OBJ = struct {
    pub const TABLE: u16 = 1;
    pub const NAME: u16 = 2;
    pub const TYPE: u16 = 3;
    pub const DATA: u16 = 4;
    pub const USE: u16 = 5;
    pub const HANDLE: u16 = 6;
    pub const USERDATA: u16 = 8;
};

/// `NFT_SET_MAP` — the set carries a data half per element.
pub const NFT_SET_MAP: u32 = 0x8;

/// `NFT_DATA_VERDICT` — `NFTA_SET_DATA_TYPE` of a verdict map.
pub const NFT_DATA_VERDICT: u32 = 0xffffff00;

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
    /// Several bound interfaces (`devices = { lo, eth0 }`, kernel 5.5+);
    /// wins over `dev` when non-empty.
    devs: []const []const u8 = &.{},
    /// `NFT_CHAIN_F.*` (`HW_OFFLOAD` for `flags offload`).
    flags: u32 = 0,
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
    /// Non-null makes this a **map** (`NFT_SET_MAP` is set for you): every
    /// element then carries a data half of this type.
    data: ?SetData = null,
    /// Concatenated key (`type ipv4_addr . inet_service`): non-empty makes
    /// the key the concatenation of these types (`key_type` is ignored). Every
    /// component is padded to 4 bytes in the key (`concatKey` builds one),
    /// and with `.interval` the field lengths are sent as `NFTA_SET_DESC_CONCAT`
    /// with `NFT_SET_CONCAT` set — both exactly as `nft` does.
    key_concat: []const SetDataType = &.{},
    /// `NFT_SET_F.*` bits `SetFlag` has no name for (`ANONYMOUS | CONSTANT`
    /// for an inline `{ 22, 80 }`, `EVAL` for a dynamic set, `OBJECT`, `EXPR`).
    raw_flags: u32 = 0,
    policy: ?SetPolicy = null,
    /// Garbage-collection interval of a timeout set, milliseconds.
    gc_interval_ms: ?u32 = null,
    /// A per-element expression the set attaches (`counter`) — `NFTA_SET_EXPR`.
    expr: ?expr.Expr = null,
};

/// The padded size in bytes one component takes inside a concatenated key.
pub fn concatFieldSize(t: SetDataType) u32 {
    return (t.keyLen() + 3) & ~@as(u32, 3);
}

/// `NFTA_SET_KEY_TYPE` of a concatenation: `nft` packs the component type
/// ids six bits apiece, first component highest (`ipv4_addr . inet_service`
/// = 7 << 6 | 13 = 461, captured). At most five components fit.
pub fn concatKeyType(parts: []const SetDataType) BuildError!u32 {
    if (parts.len < 2 or parts.len > 5) return error.InvalidExpression;
    var v: u32 = 0;
    for (parts) |t| v = (v << 6) | t.id();
    return v;
}

/// Build the key bytes of one concatenated element: every part is
/// zero-padded to a multiple of 4 bytes. `out` must hold the padded total
/// (sum of `concatFieldSize`); returns the used prefix. A part of the wrong
/// width is `error.ValueWidthMismatch`.
pub fn concatKey(out: []u8, comps: []const SetDataType, parts: []const []const u8) BuildError![]u8 {
    if (comps.len != parts.len) return error.InvalidExpression;
    var o: usize = 0;
    for (comps, parts) |c, part| {
        if (part.len != c.keyLen()) return error.ValueWidthMismatch;
        const sz = concatFieldSize(c);
        if (o + sz > out.len) return error.AttrTooLong;
        @memcpy(out[o .. o + part.len], part);
        @memset(out[o + part.len .. o + sz], 0);
        o += sz;
    }
    return out[0..o];
}

/// The data half of a map.
pub const SetData = union(enum) {
    /// A verdict map (`type … : verdict`) — elements carry `SetElem.verdict`.
    verdict,
    /// A data map (`type … : ipv4_addr`, …) — elements carry `SetElem.data`
    /// of `t.keyLen()` bytes.
    value: SetDataType,
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
    /// Time left, in milliseconds (`expires 30m`).
    expiration_ms: ?u64 = null,
    /// A per-element expression (`counter packets 1 bytes 2`).
    expr: ?expr.Expr = null,
    /// Map data half (a data map).
    data: ?[]const u8 = null,
    /// Map data half (a verdict map). Setting both this and `data` is
    /// `error.ElemDataConflict`.
    verdict: ?expr.Verdict = null,
    /// Opaque per-element blob (`NFTA_SET_ELEM_USERDATA`); `nft` keeps its
    /// own flags there (e.g. an interval open to the top of the key space).
    userdata: ?[]const u8 = null,
};

/// One interval of an interval set, as the two classic wire elements: the
/// first key, and the key one past the last flagged `INTERVAL_END`. `open`
/// means the interval runs to the top of the key space (last key all-ones),
/// where "one past" does not exist and `nft` sends the start element alone.
pub fn Interval(comptime n: usize) type {
    return struct {
        start: [n]u8,
        end: [n]u8,
        open: bool,

        const Self = @This();

        /// The wire elements (one when `open`, else two). They BORROW
        /// `self.start`/`self.end`: keep the `Interval` in a variable that
        /// outlives the batch call — `(try interval(…)).elems(&out)` on a
        /// temporary leaves the keys dangling.
        pub fn elems(self: *const Self, out: *[2]SetElem) []const SetElem {
            out[0] = .{ .key = &self.start };
            if (self.open) return out[0..1];
            out[1] = .{ .key = &self.end, .flags = NFT_SET_ELEM_INTERVAL_END };
            return out[0..2];
        }
    };
}

/// `first-last` (both inclusive, big-endian keys, as the payload carries
/// them) as an interval-set range. `error.InvalidRange` if `last < first`.
pub fn interval(comptime n: usize, first: [n]u8, last: [n]u8) BuildError!Interval(n) {
    if (std.mem.order(u8, &last, &first) == .lt) return error.InvalidRange;
    var end = last;
    // end = last + 1, big-endian; a carry out of the top byte means `last`
    // was all-ones and the interval is open.
    var i: usize = n;
    var carry = true;
    while (carry and i > 0) {
        i -= 1;
        end[i] +%= 1;
        carry = end[i] == 0;
    }
    return .{ .start = first, .end = end, .open = carry };
}

/// `addr/prefix_len` as an interval-set range: the network address to its
/// broadcast address. Host bits in `addr` are cleared, as `nft` does.
pub fn prefixInterval(comptime n: usize, addr: [n]u8, prefix_len: u8) BuildError!Interval(n) {
    if (prefix_len > n * 8) return error.InvalidPrefixLength;
    var first = addr;
    var last = addr;
    for (0..n) |i| {
        const bits_before: usize = i * 8;
        const keep: u8 = if (prefix_len >= bits_before + 8)
            0xff
        else if (prefix_len <= bits_before)
            0
        else
            @as(u8, 0xff) << @intCast(8 - (prefix_len - bits_before));
        first[i] = addr[i] & keep;
        last[i] = first[i] | ~keep;
    }
    return interval(n, first, last);
}

/// A named stateful object (`add counter`/`add quota`).
pub const ObjectSpec = struct {
    family: Family,
    table: []const u8,
    name: []const u8,
    obj: ObjectData,
    userdata: ?[]const u8 = null,
};

/// The state a named object starts with.
pub const ObjectData = union(enum) {
    counter: struct { packets: u64 = 0, bytes: u64 = 0 },
    quota: struct { bytes: u64, consumed: u64 = 0, over: bool = false },
    /// `add limit` — the same fields as the `limit` statement.
    limit: expr.Limit,
    /// `add ct helper … { type "ftp" protocol tcp; l3proto ip; }`.
    ct_helper: struct { name: []const u8, l3proto: u16, l4proto: u8 },
    /// `add secmark … "<security context>"`.
    secmark: struct { ctx: []const u8 },
    /// `add ct timeout`: per-state timeouts in seconds, by the protocol's own
    /// `NFTA_CT_TIMEOUT_<proto>_*` attribute number (TCP 1…11, UDP 1…2, …).
    ct_timeout: struct { l3proto: u16, l4proto: u8, timeouts: []const CtTimeout },
    /// `add ct expectation`.
    ct_expect: struct { l3proto: u16, l4proto: u8, dport: u16, timeout_ms: u32, size: u8 },
    /// `add synproxy` (`flags` are `expr.SYNPROXY_OPT`).
    synproxy: struct { mss: u16, wscale: u8, flags: u32 },
    /// A connection-count limit (`ct count` as a stateful object).
    connlimit: struct { count: u32, over: bool = false },

    pub fn objType(d: ObjectData) expr.ObjectType {
        return switch (d) {
            .counter => .counter,
            .quota => .quota,
            .limit => .limit,
            .ct_helper => .ct_helper,
            .secmark => .secmark,
            .ct_timeout => .ct_timeout,
            .ct_expect => .ct_expect,
            .synproxy => .synproxy,
            .connlimit => .connlimit,
        };
    }
};

/// One state timeout of a `ct timeout` object.
pub const CtTimeout = struct { attr: u16, seconds: u32 };

/// `enum nft_ct_helper_attributes` / `nft_ct_timeout_*` / `nft_ct_expectation_*`.
pub const NFTA_CT_HELPER = struct {
    pub const NAME: u16 = 1;
    pub const L3PROTO: u16 = 2;
    pub const L4PROTO: u16 = 3;
};
pub const NFTA_CT_TIMEOUT = struct {
    pub const L3PROTO: u16 = 1;
    pub const L4PROTO: u16 = 2;
    pub const DATA: u16 = 3;
};
pub const NFTA_CT_EXPECT = struct {
    pub const L3PROTO: u16 = 1;
    pub const L4PROTO: u16 = 2;
    pub const DPORT: u16 = 3;
    pub const TIMEOUT: u16 = 4;
    pub const SIZE: u16 = 5;
};
/// `NFTA_SECMARK_CTX`.
pub const NFTA_SECMARK_CTX: u16 = 1;

/// A flowtable (`add flowtable … { hook ingress priority 0; devices = { lo }; }`).
pub const FlowtableSpec = struct {
    family: Family,
    table: []const u8,
    name: []const u8,
    /// `NF_NETDEV_INGRESS` (0) — the only hook flowtables have.
    hook_num: u32 = 0,
    prio: i32 = 0,
    devs: []const []const u8,
    /// `NFT_FLOWTABLE_F.*`.
    flags: u32 = 0,
};

/// Append `NFTA_OBJ_DATA`'s attributes for `d`.
fn appendObjectData(gpa: std.mem.Allocator, list: *std.ArrayList(u8), d: ObjectData) BuildError!void {
    switch (d) {
        // Unlike the `counter` expression, the object always carries
        // both values, zero or not (captured `add counter`).
        .counter => |c| {
            try nl.appendAttrBe64(gpa, list, expr.NFTA_COUNTER.BYTES, c.bytes);
            try nl.appendAttrBe64(gpa, list, expr.NFTA_COUNTER.PACKETS, c.packets);
        },
        .quota => |q| {
            try nl.appendAttrBe64(gpa, list, expr.NFTA_QUOTA.BYTES, q.bytes);
            try nl.appendAttrBe64(gpa, list, expr.NFTA_QUOTA.CONSUMED, q.consumed);
            try nl.appendAttrBe32(gpa, list, expr.NFTA_QUOTA.FLAGS, if (q.over) expr.NFT_QUOTA_F_INV else 0);
        },
        .limit => |l| try expr.appendLimitAttrs(gpa, list, l),
        .ct_helper => |h| {
            // Also without a NUL: the helper name is a bare 3-byte attribute.
            try nl.appendAttr(gpa, list, NFTA_CT_HELPER.NAME, h.name);
            try nl.appendAttrBe16(gpa, list, NFTA_CT_HELPER.L3PROTO, h.l3proto);
            try nl.appendAttrU8(gpa, list, NFTA_CT_HELPER.L4PROTO, h.l4proto);
        },
        // `nft` sends the security context WITHOUT a NUL (captured).
        .secmark => |m| try nl.appendAttr(gpa, list, NFTA_SECMARK_CTX, m.ctx),
        .ct_timeout => |t| {
            try nl.appendAttrBe16(gpa, list, NFTA_CT_TIMEOUT.L3PROTO, t.l3proto);
            try nl.appendAttrU8(gpa, list, NFTA_CT_TIMEOUT.L4PROTO, t.l4proto);
            const off = try nl.nestBegin(gpa, list, nl.NLA_F_NESTED | NFTA_CT_TIMEOUT.DATA);
            for (t.timeouts) |e| try nl.appendAttrBe32(gpa, list, e.attr, e.seconds);
            try nl.nestEnd(list, off);
        },
        .ct_expect => |e| {
            try nl.appendAttrBe16(gpa, list, NFTA_CT_EXPECT.L3PROTO, e.l3proto);
            try nl.appendAttrU8(gpa, list, NFTA_CT_EXPECT.L4PROTO, e.l4proto);
            try nl.appendAttrBe16(gpa, list, NFTA_CT_EXPECT.DPORT, e.dport);
            // The one host-order integer: `NFTA_CT_EXPECT_TIMEOUT` is a
            // plain NLA_U32 (captured: 60000 ms goes out as `60 ea 00 00`).
            var t: [4]u8 = undefined;
            std.mem.writeInt(u32, &t, e.timeout_ms, native_endian);
            try nl.appendAttr(gpa, list, NFTA_CT_EXPECT.TIMEOUT, &t);
            try nl.appendAttrU8(gpa, list, NFTA_CT_EXPECT.SIZE, e.size);
        },
        .synproxy => |y| {
            try nl.appendAttrBe16(gpa, list, expr.NFTA_SYNPROXY.MSS, y.mss);
            try nl.appendAttrU8(gpa, list, expr.NFTA_SYNPROXY.WSCALE, y.wscale);
            try nl.appendAttrBe32(gpa, list, expr.NFTA_SYNPROXY.FLAGS, y.flags);
        },
        .connlimit => |c| {
            try nl.appendAttrBe32(gpa, list, expr.NFTA_CONNLIMIT.COUNT, c.count);
            try nl.appendAttrBe32(gpa, list, expr.NFTA_CONNLIMIT.FLAGS, if (c.over) expr.NFT_CONNLIMIT_F_INV else 0);
        },
    }
}

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
    if (spec.flags != 0) try nl.appendAttrBe32(gpa, list, NFTA_CHAIN.FLAGS, spec.flags);
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
        if (spec.devs.len > 0) {
            const doff = try nl.nestBegin(gpa, list, nl.NLA_F_NESTED | NFTA_HOOK.DEVS);
            for (spec.devs) |d| try nl.appendAttrString(gpa, list, NFTA_DEVICE_NAME, d);
            try nl.nestEnd(list, doff);
        } else if (spec.dev) |d| try nl.appendAttrString(gpa, list, NFTA_HOOK.DEV, d);
        try nl.nestEnd(list, off);
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
        try nl.nestEnd(list, off);
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
    var flag_bits: u32 = (if (spec.data != null) NFT_SET_MAP else 0) | spec.raw_flags;
    for (spec.flags) |f| flag_bits |= f.bit();
    const concat = spec.key_concat.len > 0;
    var key_type = spec.key_type.id();
    var key_len = spec.key_type.keyLen();
    if (concat) {
        key_type = try concatKeyType(spec.key_concat);
        key_len = 0;
        for (spec.key_concat) |c| key_len += concatFieldSize(c);
        // `nft` marks only an INTERVAL concatenation (pipapo) CONCAT.
        if (flag_bits & NFT_SET_F.INTERVAL != 0) flag_bits |= NFT_SET_F.CONCAT;
    }
    try nl.appendAttrBe32(gpa, list, NFTA_SET.FLAGS, flag_bits);
    try nl.appendAttrBe32(gpa, list, NFTA_SET.KEY_TYPE, key_type);
    try nl.appendAttrBe32(gpa, list, NFTA_SET.KEY_LEN, key_len);
    if (spec.data) |d| switch (d) {
        // A verdict map's data length is 0: the kernel sizes a verdict itself
        // (captured: `type inet_service : verdict` → 0xffffff00, 0).
        .verdict => {
            try nl.appendAttrBe32(gpa, list, NFTA_SET.DATA_TYPE, NFT_DATA_VERDICT);
            try nl.appendAttrBe32(gpa, list, NFTA_SET.DATA_LEN, 0);
        },
        .value => |t| {
            try nl.appendAttrBe32(gpa, list, NFTA_SET.DATA_TYPE, t.id());
            try nl.appendAttrBe32(gpa, list, NFTA_SET.DATA_LEN, t.keyLen());
        },
    };
    try nl.appendAttrBe32(gpa, list, NFTA_SET.ID, spec.id);
    if (spec.policy) |pol| try nl.appendAttrBe32(gpa, list, NFTA_SET.POLICY, @backingInt(pol));
    const concat_desc = concat and flag_bits & NFT_SET_F.CONCAT != 0;
    if (spec.size != null or concat_desc) {
        const off = try nl.nestBegin(gpa, list, nl.NLA_F_NESTED | NFTA_SET.DESC);
        if (spec.size) |s| try nl.appendAttrBe32(gpa, list, NFTA_SET_DESC.SIZE, s);
        if (concat_desc) {
            const coff = try nl.nestBegin(gpa, list, nl.NLA_F_NESTED | NFTA_SET_DESC.CONCAT);
            for (spec.key_concat) |c| {
                const foff = try nl.nestBegin(gpa, list, nl.NLA_F_NESTED | expr.NFTA_LIST_ELEM);
                try nl.appendAttrBe32(gpa, list, NFTA_SET_FIELD_LEN, c.keyLen());
                try nl.nestEnd(list, foff);
            }
            try nl.nestEnd(list, coff);
        }
        try nl.nestEnd(list, off);
    }
    if (spec.timeout_ms) |t| try nl.appendAttrBe64(gpa, list, NFTA_SET.TIMEOUT, t);
    if (spec.gc_interval_ms) |g| try nl.appendAttrBe32(gpa, list, NFTA_SET.GC_INTERVAL, g);
    if (spec.userdata) |u| try nl.appendAttr(gpa, list, NFTA_SET.USERDATA, u);
    if (spec.expr) |e| {
        const eoff = try nl.nestBegin(gpa, list, nl.NLA_F_NESTED | NFTA_SET.EXPR);
        try expr.appendExprBody(gpa, list, e);
        try nl.nestEnd(list, eoff);
    }
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
    // The 1-based index is the nlattr type, a u16: more than 65535 elements
    // cannot be numbered (and cannot fit one nest anyway) — `AttrTooLong`,
    // not an unchecked cast (sweep NF-5). Split the list across commands.
    if (elems.len > std.math.maxInt(u16)) return error.AttrTooLong;
    for (elems, 1..) |el, i| {
        const eoff = try nl.nestBegin(gpa, list, nl.NLA_F_NESTED | @as(u16, @intCast(i)));
        if (el.flags != 0) try nl.appendAttrBe32(gpa, list, NFTA_SET_ELEM.FLAGS, el.flags);
        if (el.timeout_ms) |t| try nl.appendAttrBe64(gpa, list, NFTA_SET_ELEM.TIMEOUT, t);
        if (el.expiration_ms) |t| try nl.appendAttrBe64(gpa, list, NFTA_SET_ELEM.EXPIRATION, t);
        // The catch-all element (`{ * : accept }`) has no key at all.
        if (el.key.len > 0 or el.flags & NFT_SET_ELEM_CATCHALL == 0) {
            const koff = try nl.nestBegin(gpa, list, nl.NLA_F_NESTED | NFTA_SET_ELEM.KEY);
            try nl.appendAttr(gpa, list, expr.NFTA_DATA.VALUE, el.key);
            try nl.nestEnd(list, koff);
        }
        if (el.key_end) |ke| {
            const koff = try nl.nestBegin(gpa, list, nl.NLA_F_NESTED | NFTA_SET_ELEM.KEY_END);
            try nl.appendAttr(gpa, list, expr.NFTA_DATA.VALUE, ke);
            try nl.nestEnd(list, koff);
        }
        if (el.data != null and el.verdict != null) return error.ElemDataConflict;
        if (el.data) |d| {
            const doff = try nl.nestBegin(gpa, list, nl.NLA_F_NESTED | NFTA_SET_ELEM.DATA);
            try nl.appendAttr(gpa, list, expr.NFTA_DATA.VALUE, d);
            try nl.nestEnd(list, doff);
        }
        if (el.verdict) |v| try expr.appendData(gpa, list, NFTA_SET_ELEM.DATA, .{ .verdict = v });
        if (el.expr) |e| {
            const xoff = try nl.nestBegin(gpa, list, nl.NLA_F_NESTED | NFTA_SET_ELEM.EXPR);
            try expr.appendExprBody(gpa, list, e);
            try nl.nestEnd(list, xoff);
        }
        if (el.userdata) |u| try nl.appendAttr(gpa, list, NFTA_SET_ELEM.USERDATA, u);
        try nl.nestEnd(list, eoff);
    }
    try nl.nestEnd(list, off);
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
        NFT_MSG.NEWOBJ => "NEWOBJ",
        NFT_MSG.GETOBJ => "GETOBJ",
        NFT_MSG.DELOBJ => "DELOBJ",
        NFT_MSG.GETOBJ_RESET => "GETOBJ_RESET",
        NFT_MSG.NEWFLOWTABLE => "NEWFLOWTABLE",
        NFT_MSG.GETFLOWTABLE => "GETFLOWTABLE",
        NFT_MSG.DELFLOWTABLE => "DELFLOWTABLE",
        NFT_MSG.GETRULE_RESET => "GETRULE_RESET",
        NFT_MSG.DESTROYTABLE => "DESTROYTABLE",
        NFT_MSG.DESTROYCHAIN => "DESTROYCHAIN",
        NFT_MSG.DESTROYRULE => "DESTROYRULE",
        NFT_MSG.DESTROYSET => "DESTROYSET",
        NFT_MSG.DESTROYSETELEM => "DESTROYSETELEM",
        NFT_MSG.DESTROYOBJ => "DESTROYOBJ",
        NFT_MSG.DESTROYFLOWTABLE => "DESTROYFLOWTABLE",
        NFT_MSG.GETSETELEM_RESET => "GETSETELEM_RESET",
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
    /// Ruleset generation the batch was built against (`NFNL_BATCH_GENID`
    /// on `BATCH_BEGIN`). The kernel refuses the whole batch if the ruleset
    /// changed since — the optimistic-concurrency check `nft` uses.
    gen_id: ?u32 = null,
};

/// A transactional nftables batch: `BATCH_BEGIN`, n commands, `BATCH_END`, all
/// in one buffer to be sent with a single `sendmsg`.
///
/// The buffer is complete only after `finish()`; `bytes()` before that returns
/// the commands without their `BATCH_END` and the kernel would apply nothing.
/// Adding a command after `finish()` (or `Socket.commit`) is a sequencing bug
/// of the caller and panics: `@panic("nftables: Batch command after finish()")`.
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
        if (msg_type == NFNL_MSG_BATCH_BEGIN) if (b.opts.gen_id) |g|
            try nl.appendAttrBe32(b.gpa, &b.buf, NFNL_BATCH_GENID, g);
        nl.finishHeader(&b.buf, h);
    }

    /// Begin a command message; returns the header offset for `endCommand`.
    fn beginCommand(b: *Batch, cmd: u8, extra_flags: u16, nfproto: u8) BuildError!usize {
        // A command after `finish()` would land behind BATCH_END, in a buffer
        // the kernel treats as complete: a caller sequencing bug, never input.
        if (b.finished) @panic("nftables: Batch command after finish()");
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
        return b.delTable(NFT_MSG.DELTABLE, family, name);
    }

    /// `destroy table` — like `deleteTable`, but no error when it is absent
    /// (kernel 6.3+).
    pub fn destroyTable(b: *Batch, family: Family, name: []const u8) BuildError!void {
        return b.delTable(NFT_MSG.DESTROYTABLE, family, name);
    }

    fn delTable(b: *Batch, cmd: u8, family: Family, name: []const u8) BuildError!void {
        const h = try b.beginCommand(cmd, 0, family.nfproto());
        try appendTableBody(b.gpa, &b.buf, .{ .family = family, .name = name }, false);
        b.endCommand(h);
    }

    /// `flush table` — a `DELRULE` naming only the table empties every
    /// chain in it (the chains stay).
    pub fn flushTable(b: *Batch, family: Family, table: []const u8) BuildError!void {
        const h = try b.beginCommand(NFT_MSG.DELRULE, 0, family.nfproto());
        try nl.appendAttrString(b.gpa, &b.buf, NFTA_RULE.TABLE, table);
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
        return b.delChain(NFT_MSG.DELCHAIN, family, table, name);
    }

    /// `destroy chain` — no error when it is absent (kernel 6.3+).
    pub fn destroyChain(b: *Batch, family: Family, table: []const u8, name: []const u8) BuildError!void {
        return b.delChain(NFT_MSG.DESTROYCHAIN, family, table, name);
    }

    fn delChain(b: *Batch, cmd: u8, family: Family, table: []const u8, name: []const u8) BuildError!void {
        const h = try b.beginCommand(cmd, 0, family.nfproto());
        try nl.appendAttrString(b.gpa, &b.buf, NFTA_CHAIN.TABLE, table);
        try nl.appendAttrString(b.gpa, &b.buf, NFTA_CHAIN.NAME, name);
        b.endCommand(h);
    }

    /// `rename chain` — keyed by the chain's kernel `handle` (from a dump).
    pub fn renameChain(
        b: *Batch,
        family: Family,
        table: []const u8,
        handle: u64,
        new_name: []const u8,
    ) BuildError!void {
        const h = try b.beginCommand(NFT_MSG.NEWCHAIN, 0, family.nfproto());
        try nl.appendAttrString(b.gpa, &b.buf, NFTA_CHAIN.TABLE, table);
        try nl.appendAttrString(b.gpa, &b.buf, NFTA_CHAIN.NAME, new_name);
        try nl.appendAttrBe64(b.gpa, &b.buf, NFTA_CHAIN.HANDLE, handle);
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

    /// `replace rule … handle N` — swaps the rule's expressions in place;
    /// `spec.handle` is required (`error.InvalidExpression` otherwise).
    pub fn replaceRule(b: *Batch, spec: RuleSpec) BuildError!void {
        if (spec.handle == null) return error.InvalidExpression;
        const h = try b.beginCommand(NFT_MSG.NEWRULE, nl.NLM_F_REPLACE, spec.family.nfproto());
        try appendRuleBody(b.gpa, &b.buf, spec);
        b.endCommand(h);
    }

    /// `destroy rule … handle N` — no error when the handle is gone (6.3+).
    pub fn destroyRule(
        b: *Batch,
        family: Family,
        table: []const u8,
        chain: []const u8,
        handle: u64,
    ) BuildError!void {
        const h = try b.beginCommand(NFT_MSG.DESTROYRULE, 0, family.nfproto());
        try appendRuleBody(b.gpa, &b.buf, .{
            .family = family,
            .table = table,
            .chain = chain,
            .handle = handle,
        });
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
        return b.delSet(NFT_MSG.DELSET, family, table, name);
    }

    /// `destroy set` — no error when it is absent (kernel 6.3+).
    pub fn destroySet(b: *Batch, family: Family, table: []const u8, name: []const u8) BuildError!void {
        return b.delSet(NFT_MSG.DESTROYSET, family, table, name);
    }

    fn delSet(b: *Batch, cmd: u8, family: Family, table: []const u8, name: []const u8) BuildError!void {
        const h = try b.beginCommand(cmd, 0, family.nfproto());
        try nl.appendAttrString(b.gpa, &b.buf, NFTA_SET.TABLE, table);
        try nl.appendAttrString(b.gpa, &b.buf, NFTA_SET.NAME, name);
        b.endCommand(h);
    }

    /// `flush set` — a `DELSETELEM` naming the set and no elements removes
    /// every element. (`nft` writes SET before TABLE here; so does this.)
    pub fn flushSet(b: *Batch, family: Family, table: []const u8, set: []const u8) BuildError!void {
        const h = try b.beginCommand(NFT_MSG.DELSETELEM, 0, family.nfproto());
        try nl.appendAttrString(b.gpa, &b.buf, NFTA_SET_ELEM_LIST.SET, set);
        try nl.appendAttrString(b.gpa, &b.buf, NFTA_SET_ELEM_LIST.TABLE, table);
        b.endCommand(h);
    }

    /// `destroy element` — absent keys are not an error (kernel 6.3+).
    pub fn destroySetElems(
        b: *Batch,
        family: Family,
        table: []const u8,
        set: []const u8,
        elems: []const SetElem,
    ) BuildError!void {
        const h = try b.beginCommand(NFT_MSG.DESTROYSETELEM, 0, family.nfproto());
        try appendSetElems(b.gpa, &b.buf, table, set, null, elems);
        b.endCommand(h);
    }

    /// `add flowtable`.
    pub fn addFlowtable(b: *Batch, spec: FlowtableSpec) BuildError!void {
        const h = try b.beginCommand(NFT_MSG.NEWFLOWTABLE, nl.NLM_F_CREATE, spec.family.nfproto());
        try nl.appendAttrString(b.gpa, &b.buf, NFTA_FLOWTABLE.TABLE, spec.table);
        try nl.appendAttrString(b.gpa, &b.buf, NFTA_FLOWTABLE.NAME, spec.name);
        try nl.appendAttrBe32(b.gpa, &b.buf, NFTA_FLOWTABLE.FLAGS, spec.flags);
        const off = try nl.nestBegin(b.gpa, &b.buf, nl.NLA_F_NESTED | NFTA_FLOWTABLE.HOOK);
        try nl.appendAttrBe32(b.gpa, &b.buf, NFTA_FLOWTABLE_HOOK.NUM, spec.hook_num);
        try nl.appendAttrBe32(b.gpa, &b.buf, NFTA_FLOWTABLE_HOOK.PRIORITY, @bitCast(spec.prio));
        const doff = try nl.nestBegin(b.gpa, &b.buf, nl.NLA_F_NESTED | NFTA_FLOWTABLE_HOOK.DEVS);
        for (spec.devs) |d| try nl.appendAttrString(b.gpa, &b.buf, NFTA_DEVICE_NAME, d);
        try nl.nestEnd(&b.buf, doff);
        try nl.nestEnd(&b.buf, off);
        b.endCommand(h);
    }

    /// `delete flowtable`.
    pub fn deleteFlowtable(b: *Batch, family: Family, table: []const u8, name: []const u8) BuildError!void {
        return b.delFlowtable(NFT_MSG.DELFLOWTABLE, family, table, name);
    }

    /// `destroy flowtable` — no error when absent (kernel 6.3+).
    pub fn destroyFlowtable(b: *Batch, family: Family, table: []const u8, name: []const u8) BuildError!void {
        return b.delFlowtable(NFT_MSG.DESTROYFLOWTABLE, family, table, name);
    }

    fn delFlowtable(b: *Batch, cmd: u8, family: Family, table: []const u8, name: []const u8) BuildError!void {
        const h = try b.beginCommand(cmd, 0, family.nfproto());
        try nl.appendAttrString(b.gpa, &b.buf, NFTA_FLOWTABLE.TABLE, table);
        try nl.appendAttrString(b.gpa, &b.buf, NFTA_FLOWTABLE.NAME, name);
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

    /// `add counter|quota <family> <table> <name> …` — a named stateful
    /// object that rules reference with `Program.counterRef`/`quotaRef`.
    pub fn addObject(b: *Batch, spec: ObjectSpec) BuildError!void {
        const h = try b.beginCommand(NFT_MSG.NEWOBJ, nl.NLM_F_CREATE, spec.family.nfproto());
        try nl.appendAttrString(b.gpa, &b.buf, NFTA_OBJ.TABLE, spec.table);
        try nl.appendAttrString(b.gpa, &b.buf, NFTA_OBJ.NAME, spec.name);
        try nl.appendAttrBe32(b.gpa, &b.buf, NFTA_OBJ.TYPE, @backingInt(spec.obj.objType()));
        // `nft` puts the userdata (comment) between TYPE and DATA.
        if (spec.userdata) |u| try nl.appendAttr(b.gpa, &b.buf, NFTA_OBJ.USERDATA, u);
        const off = try nl.nestBegin(b.gpa, &b.buf, nl.NLA_F_NESTED | NFTA_OBJ.DATA);
        try appendObjectData(b.gpa, &b.buf, spec.obj);
        try nl.nestEnd(&b.buf, off);
        b.endCommand(h);
    }

    /// `delete counter|quota …`. The kernel keys on table + name + type;
    /// `nft` also sends an empty `NFTA_OBJ_DATA` nest, and so does this.
    pub fn deleteObject(
        b: *Batch,
        family: Family,
        table: []const u8,
        name: []const u8,
        obj_type: expr.ObjectType,
    ) BuildError!void {
        return b.delObject(NFT_MSG.DELOBJ, family, table, name, obj_type);
    }

    /// `destroy <object>` — no error when absent (kernel 6.3+).
    pub fn destroyObject(
        b: *Batch,
        family: Family,
        table: []const u8,
        name: []const u8,
        obj_type: expr.ObjectType,
    ) BuildError!void {
        return b.delObject(NFT_MSG.DESTROYOBJ, family, table, name, obj_type);
    }

    fn delObject(
        b: *Batch,
        cmd: u8,
        family: Family,
        table: []const u8,
        name: []const u8,
        obj_type: expr.ObjectType,
    ) BuildError!void {
        const h = try b.beginCommand(cmd, 0, family.nfproto());
        try nl.appendAttrString(b.gpa, &b.buf, NFTA_OBJ.TABLE, table);
        try nl.appendAttrString(b.gpa, &b.buf, NFTA_OBJ.NAME, name);
        try nl.appendAttrBe32(b.gpa, &b.buf, NFTA_OBJ.TYPE, @backingInt(obj_type));
        const off = try nl.nestBegin(b.gpa, &b.buf, nl.NLA_F_NESTED | NFTA_OBJ.DATA);
        try nl.nestEnd(&b.buf, off);
        b.endCommand(h);
    }
};

// ── dump requests (outside any batch) ───────────────────────────────────────

/// `nfgen_family` for a dump request: the family's own `nfproto()`, or
/// `NFPROTO_UNSPEC` (0) when the caller wants every family swept in one
/// request — see `buildDumpRequest`/`buildRuleDumpRequest`.
fn dumpNfproto(family: ?Family) u8 {
    return if (family) |f| f.nfproto() else types.NFPROTO.UNSPEC;
}

/// A bare `NFT_MSG_GET*` + `NLM_F_DUMP` request — 20 fixed bytes, no
/// allocator. Dumps are *not* batched: they are ordinary nfnetlink
/// request/response traffic.
///
/// `family = null` sends `nfgen_family = NFPROTO_UNSPEC` (0), which asks the
/// kernel for objects of **every** family in this one request — the same
/// framing `nft list ruleset` uses. Without it, a caller wanting the whole
/// ruleset must walk all six families itself, one dump per family per object
/// kind. Every decoded result already carries its own concrete family byte
/// (`TableInfo.family` etc., recoverable as a typed `Family` via
/// `Family.fromNfproto`), so mixing families in one reply loses no
/// information.
pub fn buildDumpRequest(seq: u32, cmd: u8, family: ?Family) [nl.header_len + nfgenmsg_len]u8 {
    var req: [nl.header_len + nfgenmsg_len]u8 = @splat(0);
    std.mem.writeInt(u32, req[0..4], req.len, native_endian);
    std.mem.writeInt(u16, req[4..6], nftMsg(cmd), native_endian);
    std.mem.writeInt(u16, req[6..8], nl.NLM_F_REQUEST | nl.NLM_F_DUMP, native_endian);
    std.mem.writeInt(u32, req[8..12], seq, native_endian);
    req[nl.header_len] = dumpNfproto(family);
    req[nl.header_len + 1] = NFNETLINK_V0;
    // res_id (__be16) stays 0.
    return req;
}

/// `NFT_MSG_GETRULE` + `NLM_F_DUMP` scoped to one table/chain. Caller frees.
/// `family = null` sweeps every family in one request — see
/// `buildDumpRequest`.
pub fn buildRuleDumpRequest(
    gpa: std.mem.Allocator,
    seq: u32,
    family: ?Family,
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
    try appendNfgenmsg(gpa, &list, dumpNfproto(family), 0);
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
    /// `NFT_CHAIN_F.*`.
    flags: u32 = 0,
    /// The raw `NFTA_HOOK_DEVS` nest of a multi-device chain; walk it with
    /// `devices()`.
    devs: []const u8 = &.{},

    pub fn devices(c: ChainInfo) DevIterator {
        return .{ .attrs = .{ .buf = c.devs } };
    }
};

/// Walks an `NFTA_HOOK_DEVS` / `NFTA_FLOWTABLE_HOOK_DEVS` nest: one interface
/// name per step, borrowed.
pub const DevIterator = struct {
    attrs: nl.AttrIterator,

    pub fn next(it: *DevIterator) DecodeError!?[]const u8 {
        while (try it.attrs.next()) |a| {
            if (a.type == NFTA_DEVICE_NAME) return a.asString();
        }
        return null;
    }
};

/// A flowtable as the kernel reports it.
pub const FlowtableInfo = struct {
    family: u8,
    table: []const u8 = "",
    name: []const u8 = "",
    handle: u64 = 0,
    use: u32 = 0,
    flags: u32 = 0,
    hooknum: ?u32 = null,
    prio: ?i32 = null,
    /// Raw device-name nest, see `devices()`.
    devs: []const u8 = &.{},

    pub fn devices(f: FlowtableInfo) DevIterator {
        return .{ .attrs = .{ .buf = f.devs } };
    }
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
    /// A map's data half: `NFT_DATA_VERDICT` for a verdict map, else nft's
    /// datatype id. Null for a plain set.
    data_type: ?u32 = null,
    data_len: ?u32 = null,
    policy: ?u32 = null,
    gc_interval_ms: ?u32 = null,
    /// Field lengths of a concatenated key (`NFTA_SET_DESC_CONCAT`), raw
    /// nest; `concatFields()` walks it.
    concat: []const u8 = &.{},
    /// The `nft` userdata blob (type description, comment), raw.
    userdata: []const u8 = &.{},

    pub fn concatFields(s: SetInfo) ConcatIterator {
        return .{ .attrs = .{ .buf = s.concat } };
    }
};

/// One component length per step of a concatenated set key.
pub const ConcatIterator = struct {
    attrs: nl.AttrIterator,

    pub fn next(it: *ConcatIterator) DecodeError!?u32 {
        while (try it.attrs.next()) |elem| {
            var inner = elem.nested();
            while (try inner.next()) |a| {
                if (a.type == NFTA_SET_FIELD_LEN) return try a.asBe32();
            }
        }
        return null;
    }
};

/// A named stateful object as the kernel reports it (`NFT_MSG_NEWOBJ` in a
/// `GETOBJ` dump). `counter`/`quota` carry the decoded state for those two
/// types; any other type leaves both null and its raw `data` in place.
pub const ObjectInfo = struct {
    family: u8,
    table: []const u8 = "",
    name: []const u8 = "",
    obj_type: u32 = 0,
    handle: u64 = 0,
    use: u32 = 0,
    data: []const u8 = &.{},
    counter: ?struct { packets: u64 = 0, bytes: u64 = 0 } = null,
    quota: ?struct { bytes: u64 = 0, consumed: u64 = 0, flags: u32 = 0 } = null,

    /// The typed state for every object type this module can create
    /// (`decodeObjectData`); null for other types. Borrows from `data`.
    pub fn state(o: ObjectInfo) DecodeError!?ObjectData {
        return decodeObjectData(o.obj_type, o.data);
    }
};

/// One decoded set element. `key`/`key_end`/`data` borrow from the reply.
pub const SetElemInfo = struct {
    key: []const u8 = &.{},
    key_end: ?[]const u8 = null,
    data: ?[]const u8 = null,
    flags: u32 = 0,
    timeout_ms: ?u64 = null,
    /// Time left, milliseconds (`NFTA_SET_ELEM_EXPIRATION`).
    expiration_ms: ?u64 = null,
    /// Per-element userdata (`nft`'s comment), raw.
    userdata: []const u8 = &.{},
    /// The per-element expression (`counter`), ready for `expr.decodeExpr`.
    expr: ?expr.ExprView = null,
    /// The data half of a verdict-map element.
    verdict: ?struct { code: i32, chain: ?[]const u8 = null } = null,
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
        NFTA_CHAIN.FLAGS => out.flags = try a.asBe32(),
        NFTA_CHAIN.HOOK => {
            var hk = a.nested();
            while (try hk.next()) |ha| switch (ha.type) {
                NFTA_HOOK.HOOKNUM => out.hooknum = try ha.asBe32(),
                NFTA_HOOK.PRIORITY => out.prio = @bitCast(try ha.asBe32()),
                NFTA_HOOK.DEV => out.dev = ha.asString(),
                NFTA_HOOK.DEVS => out.devs = ha.data,
                else => {},
            };
        },
        else => {},
    };
    return out;
}

/// `NFT_MSG_GETRULE_RESET` + `NLM_F_DUMP`: the rules with their counters
/// zeroed as they are read. Caller frees.
pub fn buildRuleResetRequest(
    gpa: std.mem.Allocator,
    seq: u32,
    family: ?Family,
    table: ?[]const u8,
    chain: ?[]const u8,
) BuildError![]u8 {
    const req = try buildRuleDumpRequest(gpa, seq, family, table, chain);
    // The message type is bytes 4..6 of the header.
    std.mem.writeInt(u16, req[4..6], nftMsg(NFT_MSG.GETRULE_RESET), native_endian);
    return req;
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
        NFTA_SET.DATA_TYPE => out.data_type = try a.asBe32(),
        NFTA_SET.DATA_LEN => out.data_len = try a.asBe32(),
        NFTA_SET.POLICY => out.policy = try a.asBe32(),
        NFTA_SET.GC_INTERVAL => out.gc_interval_ms = try a.asBe32(),
        NFTA_SET.USERDATA => out.userdata = a.data,
        NFTA_SET.DESC => {
            var d = a.nested();
            while (try d.next()) |da| switch (da.type) {
                NFTA_SET_DESC.SIZE => out.size = try da.asBe32(),
                NFTA_SET_DESC.CONCAT => out.concat = da.data,
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
                NFTA_SET_ELEM.DATA => {
                    var d = a.nested();
                    while (try d.next()) |da| switch (da.type) {
                        expr.NFTA_DATA.VALUE => out.data = da.data,
                        expr.NFTA_DATA.VERDICT => {
                            var v = da.nested();
                            var code: ?i32 = null;
                            var chain: ?[]const u8 = null;
                            while (try v.next()) |va| switch (va.type) {
                                expr.NFTA_VERDICT.CODE => code = @bitCast(try va.asBe32()),
                                expr.NFTA_VERDICT.CHAIN => chain = va.asString(),
                                else => {},
                            };
                            if (code) |c| out.verdict = .{ .code = c, .chain = chain };
                        },
                        else => {},
                    };
                },
                NFTA_SET_ELEM.FLAGS => out.flags = try a.asBe32(),
                NFTA_SET_ELEM.TIMEOUT => out.timeout_ms = try a.asBe64(),
                NFTA_SET_ELEM.EXPIRATION => out.expiration_ms = try a.asBe64(),
                NFTA_SET_ELEM.USERDATA => out.userdata = a.data,
                NFTA_SET_ELEM.EXPR => {
                    var ev: expr.ExprView = .{ .name = "", .data = &.{} };
                    var ea = a.nested();
                    while (try ea.next()) |x| switch (x.type) {
                        expr.NFTA_EXPR.NAME => ev.name = x.asString(),
                        expr.NFTA_EXPR.DATA => ev.data = x.data,
                        else => {},
                    };
                    if (ev.name.len > 0) out.expr = ev;
                },
                else => {},
            };
            // A catch-all element has no key; it is still an element.
            if (!seen_key and out.flags & NFT_SET_ELEM_CATCHALL == 0) continue;
            return out;
        }
        return null;
    }
};

pub fn decodeObject(payload: []const u8) DecodeError!ObjectInfo {
    const hdr = try parseNfgenmsg(payload);
    var out: ObjectInfo = .{ .family = hdr.family };
    var it = hdr.attrIterator();
    while (try it.next()) |a| switch (a.type) {
        NFTA_OBJ.TABLE => out.table = a.asString(),
        NFTA_OBJ.NAME => out.name = a.asString(),
        NFTA_OBJ.TYPE => out.obj_type = try a.asBe32(),
        NFTA_OBJ.HANDLE => out.handle = try a.asBe64(),
        NFTA_OBJ.USE => out.use = try a.asBe32(),
        NFTA_OBJ.DATA => out.data = a.data,
        else => {},
    };
    // TYPE may arrive after DATA, so the state is decoded once both are in.
    var d: nl.AttrIterator = .{ .buf = out.data };
    switch (out.obj_type) {
        @backingInt(expr.ObjectType.counter) => {
            out.counter = .{};
            while (try d.next()) |da| switch (da.type) {
                expr.NFTA_COUNTER.PACKETS => out.counter.?.packets = try da.asBe64(),
                expr.NFTA_COUNTER.BYTES => out.counter.?.bytes = try da.asBe64(),
                else => {},
            };
        },
        @backingInt(expr.ObjectType.quota) => {
            out.quota = .{};
            while (try d.next()) |da| switch (da.type) {
                expr.NFTA_QUOTA.BYTES => out.quota.?.bytes = try da.asBe64(),
                expr.NFTA_QUOTA.CONSUMED => out.quota.?.consumed = try da.asBe64(),
                expr.NFTA_QUOTA.FLAGS => out.quota.?.flags = try da.asBe32(),
                else => {},
            };
        },
        else => {},
    }
    return out;
}

/// Decode a flowtable message (`NFT_MSG_NEWFLOWTABLE` in a dump).
pub fn decodeFlowtable(payload: []const u8) DecodeError!FlowtableInfo {
    const hdr = try parseNfgenmsg(payload);
    var out: FlowtableInfo = .{ .family = hdr.family };
    var it = hdr.attrIterator();
    while (try it.next()) |a| switch (a.type) {
        NFTA_FLOWTABLE.TABLE => out.table = a.asString(),
        NFTA_FLOWTABLE.NAME => out.name = a.asString(),
        NFTA_FLOWTABLE.HANDLE => out.handle = try a.asBe64(),
        NFTA_FLOWTABLE.USE => out.use = try a.asBe32(),
        NFTA_FLOWTABLE.FLAGS => out.flags = try a.asBe32(),
        NFTA_FLOWTABLE.HOOK => {
            var hk = a.nested();
            while (try hk.next()) |ha| switch (ha.type) {
                NFTA_FLOWTABLE_HOOK.NUM => out.hooknum = try ha.asBe32(),
                NFTA_FLOWTABLE_HOOK.PRIORITY => out.prio = @bitCast(try ha.asBe32()),
                NFTA_FLOWTABLE_HOOK.DEVS => out.devs = ha.data,
                else => {},
            };
        },
        else => {},
    };
    return out;
}

/// The typed state of any object this module can create, decoded from an
/// `ObjectInfo`'s raw `data` by its `obj_type`; null for a type it does not
/// model (the raw bytes stay in `ObjectInfo.data`). Strings borrow from `data`.
pub fn decodeObjectData(obj_type: u32, data: []const u8) DecodeError!?ObjectData {
    var at: [16]?nl.Attr = @splat(null);
    var it: nl.AttrIterator = .{ .buf = data };
    while (try it.next()) |a| if (a.type < at.len) {
        at[a.type] = a;
    };
    const T = expr.ObjectType;
    switch (obj_type) {
        @backingInt(T.counter) => return .{ .counter = .{
            .packets = if (at[expr.NFTA_COUNTER.PACKETS]) |a| try a.asBe64() else 0,
            .bytes = if (at[expr.NFTA_COUNTER.BYTES]) |a| try a.asBe64() else 0,
        } },
        @backingInt(T.quota) => return .{ .quota = .{
            .bytes = if (at[expr.NFTA_QUOTA.BYTES]) |a| try a.asBe64() else 0,
            .consumed = if (at[expr.NFTA_QUOTA.CONSUMED]) |a| try a.asBe64() else 0,
            .over = (if (at[expr.NFTA_QUOTA.FLAGS]) |a| try a.asBe32() else 0) & expr.NFT_QUOTA_F_INV != 0,
        } },
        @backingInt(T.limit) => {
            const rate = (if (at[expr.NFTA_LIMIT.RATE]) |a| try a.asBe64() else null) orelse return null;
            const secs = (if (at[expr.NFTA_LIMIT.UNIT]) |a| try a.asBe64() else null) orelse return null;
            const per: types.LimitPer = switch (secs) {
                1 => .second,
                60 => .minute,
                3600 => .hour,
                86400 => .day,
                604800 => .week,
                else => return null,
            };
            const ty = if (at[expr.NFTA_LIMIT.TYPE]) |a| try a.asBe32() else 0;
            if (ty > 1) return null;
            return .{ .limit = .{
                .rate = rate,
                .per = per,
                .burst = if (at[expr.NFTA_LIMIT.BURST]) |a| try a.asBe32() else 0,
                .unit = if (ty == 0) .packets else .bytes,
                .inv = (if (at[expr.NFTA_LIMIT.FLAGS]) |a| try a.asBe32() else 0) & expr.NFT_LIMIT_F_INV != 0,
            } };
        },
        @backingInt(T.ct_helper) => return .{ .ct_helper = .{
            .name = (at[NFTA_CT_HELPER.NAME] orelse return null).asString(),
            .l3proto = if (at[NFTA_CT_HELPER.L3PROTO]) |a| try a.asBe16() else 0,
            .l4proto = if (at[NFTA_CT_HELPER.L4PROTO]) |a| try a.asU8() else 0,
        } },
        @backingInt(T.secmark) => return .{ .secmark = .{
            .ctx = (at[NFTA_SECMARK_CTX] orelse return null).asString(),
        } },
        @backingInt(T.ct_expect) => {
            const tm = at[NFTA_CT_EXPECT.TIMEOUT];
            return .{ .ct_expect = .{
                .l3proto = if (at[NFTA_CT_EXPECT.L3PROTO]) |a| try a.asBe16() else 0,
                .l4proto = if (at[NFTA_CT_EXPECT.L4PROTO]) |a| try a.asU8() else 0,
                .dport = if (at[NFTA_CT_EXPECT.DPORT]) |a| try a.asBe16() else 0,
                .timeout_ms = if (tm) |a| try a.asU32() else 0,
                .size = if (at[NFTA_CT_EXPECT.SIZE]) |a| try a.asU8() else 0,
            } };
        },
        @backingInt(T.synproxy) => return .{ .synproxy = .{
            .mss = if (at[expr.NFTA_SYNPROXY.MSS]) |a| try a.asBe16() else 0,
            .wscale = if (at[expr.NFTA_SYNPROXY.WSCALE]) |a| try a.asU8() else 0,
            .flags = if (at[expr.NFTA_SYNPROXY.FLAGS]) |a| try a.asBe32() else 0,
        } },
        @backingInt(T.connlimit) => return .{ .connlimit = .{
            .count = if (at[expr.NFTA_CONNLIMIT.COUNT]) |a| try a.asBe32() else 0,
            .over = (if (at[expr.NFTA_CONNLIMIT.FLAGS]) |a| try a.asBe32() else 0) & expr.NFT_CONNLIMIT_F_INV != 0,
        } },
        // `ct timeout` carries a slice of attr/seconds pairs, which needs an
        // allocator to return: read `data` with `nl.AttrIterator`.
        else => return null,
    }
}

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

/// `NFT_MSG_GETRULE` for one rule by handle (`GetRuleByHandle`): a plain
/// request, answered by one `NFT_MSG_NEWRULE`. Caller frees.
pub fn buildRuleGetRequest(
    gpa: std.mem.Allocator,
    seq: u32,
    family: Family,
    table: []const u8,
    chain: []const u8,
    handle: u64,
) BuildError![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const h = try nl.appendHeader(gpa, &list, nftMsg(NFT_MSG.GETRULE), nl.NLM_F_REQUEST, seq, 0);
    try appendNfgenmsg(gpa, &list, family.nfproto(), 0);
    try nl.appendAttrString(gpa, &list, NFTA_RULE.TABLE, table);
    try nl.appendAttrString(gpa, &list, NFTA_RULE.CHAIN, chain);
    try nl.appendAttrBe64(gpa, &list, NFTA_RULE.HANDLE, handle);
    nl.finishHeader(&list, h);
    return list.toOwnedSlice(gpa);
}

/// `NFT_MSG_GETGEN` — ask for the current ruleset generation id (not a dump:
/// one request, one `NFT_MSG_NEWGEN` reply). 20 bytes, no allocator.
pub fn buildGenIdRequest(seq: u32) [nl.header_len + nfgenmsg_len]u8 {
    var req: [nl.header_len + nfgenmsg_len]u8 = @splat(0);
    std.mem.writeInt(u32, req[0..4], req.len, native_endian);
    std.mem.writeInt(u16, req[4..6], nftMsg(NFT_MSG.GETGEN), native_endian);
    std.mem.writeInt(u16, req[6..8], nl.NLM_F_REQUEST, native_endian);
    std.mem.writeInt(u32, req[8..12], seq, native_endian);
    req[nl.header_len] = types.NFPROTO.UNSPEC;
    req[nl.header_len + 1] = NFNETLINK_V0;
    return req;
}

/// `NFT_MSG_GETSETELEM` (or `_RESET`) for specific keys of one set — a plain
/// request answered by one `NFT_MSG_NEWSETELEM` (`nft get element`). `nft`
/// writes SET before TABLE here. Caller frees.
pub fn buildSetElemGetRequest(
    gpa: std.mem.Allocator,
    seq: u32,
    family: Family,
    table: []const u8,
    set: []const u8,
    keys: []const []const u8,
    reset: bool,
) BuildError![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const cmd = if (reset) NFT_MSG.GETSETELEM_RESET else NFT_MSG.GETSETELEM;
    // NLM_F_ACK matters: the kernel answers EACH requested key with its own
    // NEWSETELEM (verified live, two keys -> two messages) and the ACK is the
    // only end marker.
    const h = try nl.appendHeader(gpa, &list, nftMsg(cmd), nl.NLM_F_REQUEST | nl.NLM_F_ACK, seq, 0);
    try appendNfgenmsg(gpa, &list, family.nfproto(), 0);
    try nl.appendAttrString(gpa, &list, NFTA_SET_ELEM_LIST.SET, set);
    try nl.appendAttrString(gpa, &list, NFTA_SET_ELEM_LIST.TABLE, table);
    const off = try nl.nestBegin(gpa, &list, nl.NLA_F_NESTED | NFTA_SET_ELEM_LIST.ELEMENTS);
    if (keys.len > std.math.maxInt(u16)) return error.AttrTooLong;
    for (keys, 1..) |k, i| {
        const eoff = try nl.nestBegin(gpa, &list, nl.NLA_F_NESTED | @as(u16, @intCast(i)));
        const koff = try nl.nestBegin(gpa, &list, nl.NLA_F_NESTED | NFTA_SET_ELEM.KEY);
        try nl.appendAttr(gpa, &list, expr.NFTA_DATA.VALUE, k);
        try nl.nestEnd(&list, koff);
        try nl.nestEnd(&list, eoff);
    }
    try nl.nestEnd(&list, off);
    nl.finishHeader(&list, h);
    return list.toOwnedSlice(gpa);
}

/// `NFT_MSG_GETSETELEM_RESET` + `NLM_F_DUMP`: every element of one set with
/// its counters zeroed as it is read (`nft reset set`). Caller frees.
pub fn buildSetElemResetRequest(
    gpa: std.mem.Allocator,
    seq: u32,
    family: Family,
    table: []const u8,
    set: []const u8,
) BuildError![]u8 {
    const req = try buildSetElemDumpRequest(gpa, seq, family, table, set);
    std.mem.writeInt(u16, req[4..6], nftMsg(NFT_MSG.GETSETELEM_RESET), native_endian);
    return req;
}

// ── events (`nft monitor`) ──────────────────────────────────────────────────

/// `enum nfnetlink_groups` as a **bind mask** (group *n* is bit *n-1*):
/// the nf_tables event group and the packet-trace group.
pub const Group = struct {
    /// `NFNLGRP_NFTABLES` = 7: every ruleset change.
    pub const NFTABLES: u32 = 1 << 6;
    /// `NFNLGRP_NFT_TRACE` = 9: `nftrace` packet traces.
    pub const TRACE: u32 = 1 << 8;
};

/// What a ruleset event is about.
pub const EventObject = enum { table, chain, rule, set, set_elem, object, flowtable, generation };

/// What happened to it. `generation` events (`NFT_MSG_NEWGEN`, one per
/// committed transaction) are always `.new`.
pub const EventAction = enum { new, delete };

/// One `nft monitor` notification: the object kind, the action, and the
/// message payload — decode it with the matching decoder (`decodeTable`,
/// `decodeChain`, `decodeRule`, `decodeSet`, `decodeSetElemReply`,
/// `decodeObject`, `decodeFlowtable`). `payload` borrows the datagram.
pub const Event = struct {
    object: EventObject,
    action: EventAction,
    payload: []const u8,
};

/// Classify one message of an event datagram; null for anything that is not
/// an nf_tables ruleset event (a stray reply, `NFT_MSG_TRACE`).
pub fn eventOf(m: nl.Message) ?Event {
    if (m.type >> 8 != NFNL_SUBSYS_NFTABLES) return null;
    const o: EventObject, const a: EventAction = switch (@as(u8, @truncate(m.type))) {
        NFT_MSG.NEWTABLE => .{ .table, .new },
        NFT_MSG.DELTABLE => .{ .table, .delete },
        NFT_MSG.NEWCHAIN => .{ .chain, .new },
        NFT_MSG.DELCHAIN => .{ .chain, .delete },
        NFT_MSG.NEWRULE => .{ .rule, .new },
        NFT_MSG.DELRULE => .{ .rule, .delete },
        NFT_MSG.NEWSET => .{ .set, .new },
        NFT_MSG.DELSET => .{ .set, .delete },
        NFT_MSG.NEWSETELEM => .{ .set_elem, .new },
        NFT_MSG.DELSETELEM => .{ .set_elem, .delete },
        NFT_MSG.NEWOBJ => .{ .object, .new },
        NFT_MSG.DELOBJ => .{ .object, .delete },
        NFT_MSG.NEWFLOWTABLE => .{ .flowtable, .new },
        NFT_MSG.DELFLOWTABLE => .{ .flowtable, .delete },
        NFT_MSG.NEWGEN => .{ .generation, .new },
        else => return null,
    };
    return .{ .object = o, .action = a, .payload = m.payload };
}

/// The ruleset generation id out of a `NFT_MSG_NEWGEN` event payload
/// (`NFTA_GEN_ID`), or null when absent.
pub fn decodeGenId(payload: []const u8) DecodeError!?u32 {
    const hdr = try parseNfgenmsg(payload);
    var it = hdr.attrIterator();
    while (try it.next()) |a| if (a.type == NFTA_GEN_ID) return try a.asBe32();
    return null;
}

/// `NFTA_GEN_ID`.
pub const NFTA_GEN_ID: u16 = 1;

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

test "family = null sends NFPROTO_UNSPEC, not a per-family walk" {
    // This is the whole point of Gap A: a caller wanting the full ruleset
    // passes `null` once instead of looping over all six families. If a
    // future edit regressed `null` back to defaulting to one concrete
    // family (or to looping internally and building six requests), the
    // fixed nfgen_family byte below would no longer be 0.
    if (native_endian != .little) return error.SkipZigTest;
    const req = buildDumpRequest(7, NFT_MSG.GETTABLE, null);
    try testing.expectEqual(@as(u8, types.NFPROTO.UNSPEC), req[nl.header_len]);
    try testing.expectEqual(@as(u8, 0), req[nl.header_len]);

    const gpa = testing.allocator;
    const rreq = try buildRuleDumpRequest(gpa, 9, null, null, null);
    defer gpa.free(rreq);
    var it: nl.MessageIterator = .{ .buf = rreq };
    const m = (try it.next()).?;
    const hdr = try parseNfgenmsg(m.payload);
    try testing.expectEqual(@as(u8, types.NFPROTO.UNSPEC), hdr.family);
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

/// `NFT_MSG_NEW*` reply payloads for `fuzzDecoders`, in the format
/// `Smith.slice` reads (see `testkit.fuzz`): a little-endian u32 length, then
/// the payload.
///
/// ⭐ Built at run time by this file's own `appendNfgenmsg` and the shared
/// netlink attribute writers rather than quoted as hex: an `nla_len`/
/// `nla_type` pair is HOST byte order (the nftables VALUES are big-endian, the
/// framing is not), so a hex corpus would be a little-endian one and the
/// counts pinned below would be false on a big-endian target instead of
/// failing there.
///
/// The harness reads every payload through all five decoders at once, which is
/// the point: the attribute NUMBERS collide across object kinds, so a chain
/// reply read as a table is a shape only a fuzzer would produce and exactly
/// the one that finds a decoder trusting a length it did not check.
const WireCorpus = struct {
    scratch: [16384]u8 = undefined,
    store: [32768]u8 = undefined,
    used: usize = 0,
    entries: [32][]const u8 = undefined,
    n: usize = 0,

    fn push(self: *WireCorpus, frame: []const u8) void {
        const sd = testkit.fuzz.seedInto(self.store[self.used..], frame);
        self.entries[self.n] = sd;
        self.used += sd.len;
        self.n += 1;
    }

    fn build(self: *WireCorpus) ![]const []const u8 {
        var fba = std.heap.FixedBufferAllocator.init(&self.scratch);
        const gpa = fba.allocator();

        // A table reply with every field the decoder types out.
        var table: std.ArrayList(u8) = .empty;
        try appendNfgenmsg(gpa, &table, types.NFPROTO.INET, 0);
        try nl.appendAttrString(gpa, &table, NFTA_TABLE.NAME, "filter");
        try nl.appendAttrBe32(gpa, &table, NFTA_TABLE.FLAGS, 0);
        try nl.appendAttrBe32(gpa, &table, NFTA_TABLE.USE, 3);
        try nl.appendAttrBe64(gpa, &table, NFTA_TABLE.HANDLE, 42);
        self.push(table.items);

        // A base chain: the HOOK nest, the policy, and a device.
        var chain: std.ArrayList(u8) = .empty;
        try appendNfgenmsg(gpa, &chain, types.NFPROTO.INET, 0);
        try nl.appendAttrString(gpa, &chain, NFTA_CHAIN.TABLE, "filter");
        try nl.appendAttrString(gpa, &chain, NFTA_CHAIN.NAME, "input");
        try nl.appendAttrBe64(gpa, &chain, NFTA_CHAIN.HANDLE, 1);
        try nl.appendAttrString(gpa, &chain, NFTA_CHAIN.TYPE, "filter");
        try nl.appendAttrBe32(gpa, &chain, NFTA_CHAIN.POLICY, 0);
        {
            const hook = try nl.nestBegin(gpa, &chain, nl.NLA_F_NESTED | NFTA_CHAIN.HOOK);
            try nl.appendAttrBe32(gpa, &chain, NFTA_HOOK.HOOKNUM, 1);
            try nl.appendAttrBe32(gpa, &chain, NFTA_HOOK.PRIORITY, 0);
            try nl.appendAttrString(gpa, &chain, NFTA_HOOK.DEV, "eth0");
            try nl.nestEnd(&chain, hook);
        }
        self.push(chain.items);

        // A rule carrying two expressions, so `exprIterator` has a nest with
        // something in it — the loop the harness bounds and never entered.
        var rule: std.ArrayList(u8) = .empty;
        try appendNfgenmsg(gpa, &rule, types.NFPROTO.INET, 0);
        try nl.appendAttrString(gpa, &rule, NFTA_RULE.TABLE, "filter");
        try nl.appendAttrString(gpa, &rule, NFTA_RULE.CHAIN, "input");
        try nl.appendAttrBe64(gpa, &rule, NFTA_RULE.HANDLE, 7);
        {
            var p = expr.Program.init(gpa, .inet);
            const exprs = try p.tcpDport(22).counter().drop().finish();
            const nest = try nl.nestBegin(gpa, &rule, nl.NLA_F_NESTED | NFTA_RULE.EXPRESSIONS);
            for (exprs) |e| try expr.appendExpr(gpa, &rule, e);
            try nl.nestEnd(&rule, nest);
        }
        self.push(rule.items);

        // A set reply with the optional scalars present.
        var set: std.ArrayList(u8) = .empty;
        try appendNfgenmsg(gpa, &set, types.NFPROTO.INET, 0);
        try nl.appendAttrString(gpa, &set, NFTA_SET.TABLE, "filter");
        try nl.appendAttrString(gpa, &set, NFTA_SET.NAME, "badhosts");
        try nl.appendAttrBe32(gpa, &set, NFTA_SET.FLAGS, 0);
        try nl.appendAttrBe32(gpa, &set, NFTA_SET.KEY_LEN, 4);
        try nl.appendAttrBe64(gpa, &set, NFTA_SET.TIMEOUT, 3_600_000);
        try nl.appendAttrBe64(gpa, &set, NFTA_SET.HANDLE, 9);
        {
            const desc = try nl.nestBegin(gpa, &set, nl.NLA_F_NESTED | NFTA_SET.DESC);
            try nl.appendAttrBe32(gpa, &set, NFTA_SET_DESC.SIZE, 65536);
            try nl.nestEnd(&set, desc);
        }
        self.push(set.items);

        // A set-element reply with three elements, so `SetElemIterator` walks.
        var elems: std.ArrayList(u8) = .empty;
        try appendNfgenmsg(gpa, &elems, types.NFPROTO.INET, 0);
        try nl.appendAttrString(gpa, &elems, NFTA_SET_ELEM_LIST.TABLE, "filter");
        try nl.appendAttrString(gpa, &elems, NFTA_SET_ELEM_LIST.SET, "badhosts");
        {
            const list = try nl.nestBegin(gpa, &elems, nl.NLA_F_NESTED | NFTA_SET_ELEM_LIST.ELEMENTS);
            for ([_][4]u8{ .{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, .{ 192, 168, 1, 1 } }) |addr| {
                const el = try nl.nestBegin(gpa, &elems, nl.NLA_F_NESTED | expr.NFTA_LIST_ELEM);
                const key = try nl.nestBegin(gpa, &elems, nl.NLA_F_NESTED | NFTA_SET_ELEM.KEY);
                try nl.appendAttr(gpa, &elems, expr.NFTA_DATA.VALUE, &addr);
                try nl.nestEnd(&elems, key);
                try nl.nestEnd(&elems, el);
            }
            try nl.nestEnd(&elems, list);
        }
        self.push(elems.items);

        // A bare `nfgenmsg`: every decoder succeeds and returns all defaults.
        // The shape a reach guard must not count as work.
        var bare: std.ArrayList(u8) = .empty;
        try appendNfgenmsg(gpa, &bare, types.NFPROTO.INET, 0);
        self.push(bare.items);

        // ── the length checks a real reply cannot exercise ─────────────────
        // A FLAGS of two octets where `asBe32` wants four.
        var wide: std.ArrayList(u8) = .empty;
        try appendNfgenmsg(gpa, &wide, types.NFPROTO.INET, 0);
        try nl.appendAttr(gpa, &wide, NFTA_TABLE.FLAGS, &.{ 1, 2 });
        self.push(wide.items);
        // A HANDLE of four octets where `asBe64` wants eight.
        var short_handle: std.ArrayList(u8) = .empty;
        try appendNfgenmsg(gpa, &short_handle, types.NFPROTO.INET, 0);
        try nl.appendAttr(gpa, &short_handle, NFTA_TABLE.HANDLE, &.{ 0, 0, 0, 1 });
        self.push(short_handle.items);
        // A zero-length TLV, which must not loop.
        {
            var zero: [nfgenmsg_len + 4]u8 = @splat(0);
            std.mem.writeInt(u16, zero[nfgenmsg_len..][2..4], NFTA_CHAIN.NAME, native_endian);
            self.push(&zero);
        }
        // An attribute declaring 200 octets over a four-octet payload.
        {
            var over: [nfgenmsg_len + 4]u8 = @splat(0);
            std.mem.writeInt(u16, over[nfgenmsg_len..][0..2], 200, native_endian);
            std.mem.writeInt(u16, over[nfgenmsg_len..][2..4], NFTA_RULE.EXPRESSIONS, native_endian);
            self.push(&over);
        }
        // An EXPRESSIONS nest whose own body is a truncated element.
        var bad_exprs: std.ArrayList(u8) = .empty;
        try appendNfgenmsg(gpa, &bad_exprs, types.NFPROTO.INET, 0);
        try nl.appendAttr(gpa, &bad_exprs, NFTA_RULE.EXPRESSIONS, &.{ 0xff, 0x00, 0x01, 0x80 });
        self.push(bad_exprs.items);

        // Two octets: shorter than an `nfgenmsg`.
        self.push(&.{ 1, 0 });

        // ── the kernel's own bytes (2026-11-07, `kernel_dumps.zig`) ────────
        // Payloads of a real dump — flowtable, chain, sets (one concatenated
        // interval set), objects of every type, set-element replies with a
        // timeout, a key_end and a catch-all — and one whole datagram of
        // header-carrying messages for the event classifier.
        const kd = @import("kernel_dumps.zig");
        inline for (.{ kd.k_flowtables, kd.k_chains, kd.k_sets, kd.k_objs, kd.k_setelems_s, kd.k_setelems_cs, kd.k_setelems_vm }) |hex| {
            const kb = try gpa.alloc(u8, hex.len / 2);
            _ = try std.fmt.hexToBytes(kb, hex);
            var kit: nl.MessageIterator = .{ .buf = kb };
            while (try kit.next()) |m| self.push(m.payload);
        }
        {
            const hex = kd.k_setelems_vm;
            const kb = try gpa.alloc(u8, hex.len / 2);
            _ = try std.fmt.hexToBytes(kb, hex);
            self.push(kb);
        }

        return self.entries[0..self.n];
    }
};

/// What one payload yielded. Shared by the fuzz target and its corpus guard so
/// the guard drives the SAME five decoders.
const WireTally = struct {
    named: usize = 0,
    handles: usize = 0,
    exprs: usize = 0,
    elements: usize = 0,
    flowtables: usize = 0,
    typed_objects: usize = 0,
    events: usize = 0,
    catchall: usize = 0,
    concat: usize = 0,
    devices: usize = 0,
    elem_attrs: usize = 0,
};

fn walkDecoders(buf: []const u8) !WireTally {
    var t: WireTally = .{};
    if (decodeTable(buf)) |x| {
        if (x.name.len != 0) t.named += 1;
        if (x.handle != 0) t.handles += 1;
    } else |_| {}
    if (decodeChain(buf)) |x| {
        if (x.name.len != 0) t.named += 1;
        if (x.handle != 0) t.handles += 1;
        var di = x.devices();
        var steps: usize = 0;
        while (di.next() catch null) |_| {
            steps += 1;
            try testing.expect(steps <= x.devs.len / 4 + 1);
            t.devices += 1;
        }
    } else |_| {}
    if (decodeSet(buf)) |x| {
        if (x.name.len != 0) t.named += 1;
        var ci = x.concatFields();
        var steps: usize = 0;
        while (ci.next() catch null) |_| {
            steps += 1;
            try testing.expect(steps <= x.concat.len / 4 + 1);
            t.concat += 1;
        }
    } else |_| {}
    if (decodeFlowtable(buf)) |ft| {
        if (ft.name.len != 0) t.flowtables += 1;
        var di = ft.devices();
        var steps: usize = 0;
        while (di.next() catch null) |_| {
            steps += 1;
            try testing.expect(steps <= ft.devs.len / 4 + 1);
            t.devices += 1;
        }
    } else |_| {}
    if (decodeObject(buf)) |o| {
        if (o.name.len != 0) {
            if (o.state() catch null) |_| t.typed_objects += 1;
        }
    } else |_| {}
    {
        // `buf` read as a datagram of whole messages: the event classifier.
        var mi: nl.MessageIterator = .{ .buf = buf };
        var steps: usize = 0;
        while (mi.next() catch null) |m| {
            steps += 1;
            try testing.expect(steps <= buf.len / 16 + 1);
            if (eventOf(m)) |ev| {
                t.events += 1;
                _ = decodeGenId(ev.payload) catch null;
            }
        }
    }
    if (decodeRule(buf) catch null) |r| {
        if (r.chain.len != 0) t.named += 1;
        if (r.handle != 0) t.handles += 1;
        var ei = r.exprIterator();
        var steps: usize = 0;
        while (ei.next() catch null) |_| {
            steps += 1;
            try testing.expect(steps <= r.expressions.len / 4 + 1);
            t.exprs += 1;
        }
    }
    if (decodeSetElemReply(buf) catch null) |sr| {
        if (sr.set.len != 0) t.named += 1;
        var si = sr.iterator();
        var steps: usize = 0;
        while (si.next() catch null) |el| {
            steps += 1;
            try testing.expect(steps <= sr.elements.len / 4 + 1);
            t.elements += 1;
            if (el.flags & NFT_SET_ELEM_CATCHALL != 0) t.catchall += 1;
            if (el.userdata.len != 0 or el.expiration_ms != null) t.elem_attrs += 1;
            if (el.expr) |x| _ = expr.decodeExpr(x) catch null;
        }
    }
    return t;
}

const fz = @import("fuzz_test.zig");
const WireMark = fz.Marker(enum { nothing, named, handles, exprs, elements, flowtable, object_typed, event, catchall });

test "fuzz: object decoders never crash, loop or over-read" {
    var corpus: WireCorpus = .{};
    try testing.fuzz({}, fuzzDecodersSmith, .{ .corpus = try corpus.build() });
}

test "fuzz driver: NFTABLES_FUZZ (wire decoders)" {
    try fz.fuzz_driver.run(fuzzDecoders, .{ .prefix = "NFTABLES_FUZZ", .name = "nftables-wire" });
}

test "fuzz harness: wire decoders, 300 seeds, reaches every outcome" {
    try WireMark.reach(fuzzDecoders, "nftables-wire", 300);
}

fn fuzzDecodersSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [fz.script_cap]u8 = undefined;
    const n = smith.slice(&script);
    try fz.runFrom(fuzzDecoders, smith, script[0..n]);
}

fn fuzzDecoders(comptime S: type, smith: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    // 2048, not 512: a rule reply carrying real expressions and a set-element
    // reply carrying several elements both run past 512, and a seed longer
    // than the buffer is not a big seed — `Smith.slice` reads it back as the
    // EMPTY one.
    var raw: [2048]u8 = undefined;
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
    // length. `bytes` takes `@min(raw.len, in.len)` octets and the ranged draw
    // then finds fewer than the eight it needs and returns the range MINIMUM,
    // so `len` was 0 for every seed and all five decoders were handed an EMPTY
    // slice with the reply sitting unread in `raw`.
    //
    // ⛔ Measured 2026-09-07 over the corpus above: **0 of 12 seeds non-empty,
    // 0 objects named, 0 expressions and 0 set elements walked before; 12 of
    // 12 non-empty, 11 objects named, 3 handles read, 6 expressions and 3 set
    // elements walked, after.** The empty
    // slice is refused at `payload.len < nfgenmsg_len`, so neither the
    // expression iterator nor the set-element iterator — the two loops this
    // target bounds with a `try testing.expect` — had ever executed.
    var cstore: WireCorpus = .{};
    const entries: []const []const u8 = if (S == fz.fuzz_driver.Rng) (cstore.build() catch &.{}) else &.{};
    const len: usize = fz.drawInput(S, smith, &raw, entries);
    const t = try walkDecoders(raw[0..len]);
    std.mem.doNotOptimizeAway(t);
    if (t.named != 0) WireMark.mark(.named);
    if (t.handles != 0) WireMark.mark(.handles);
    if (t.exprs != 0) WireMark.mark(.exprs);
    if (t.elements != 0) WireMark.mark(.elements);
    if (t.flowtables != 0) WireMark.mark(.flowtable);
    if (t.typed_objects != 0) WireMark.mark(.object_typed);
    if (t.events != 0) WireMark.mark(.event);
    if (t.catchall != 0) WireMark.mark(.catchall);
    if (t.named == 0 and t.handles == 0 and t.exprs == 0 and t.elements == 0) WireMark.mark(.nothing);
}

test "corpus: every wire seed reaches the decoders, and the walked counts are pinned" {
    // ⭐ The measurement, executable rather than written in a comment, over the
    // SAME corpus the harness gets, through the SAME `walkDecoders`.
    // `nonempty` is the reach claim and the only check that catches a seed
    // grown past the harness's buffer, which `Smith.slice` reads back as the
    // EMPTY one.
    //
    // ⛔ A decode count would not be a guard: a bare `nfgenmsg` with no
    // attributes behind it is a legal reply and ALL FIVE decoders succeed on
    // it, returning structs of defaults — one of the seeds above is exactly
    // that, on purpose. `named`, `handles`, `exprs` and `elements` count work
    // the empty payload cannot do.
    var corpus: WireCorpus = .{};
    const entries = try corpus.build();
    var nonempty: usize = 0;
    var total: WireTally = .{};
    for (entries) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var raw: [2048]u8 = undefined;
        const len: usize = smith.slice(&raw);
        if (len != 0) nonempty += 1;
        const t = try walkDecoders(raw[0..len]);
        total.named += t.named;
        total.handles += t.handles;
        total.exprs += t.exprs;
        total.elements += t.elements;
        total.flowtables += t.flowtables;
        total.typed_objects += t.typed_objects;
        total.events += t.events;
        total.catchall += t.catchall;
        total.concat += t.concat;
        total.devices += t.devices;
        total.elem_attrs += t.elem_attrs;
    }
    try testing.expectEqual(entries.len, nonempty);
    // The first 12 seeds are the pre-2026-11-07 ones; the 18 kernel-dump seeds
    // added the rest (named 11 -> 32, handles 3 -> 4, elements 3 -> 9) and
    // every counter below that no synthetic seed could move.
    try testing.expectEqual(@as(usize, 32), total.named);
    try testing.expectEqual(@as(usize, 4), total.handles);
    try testing.expectEqual(@as(usize, 6), total.exprs);
    try testing.expectEqual(@as(usize, 9), total.elements);
    try testing.expectEqual(@as(usize, 4), total.flowtables);
    try testing.expectEqual(@as(usize, 5), total.typed_objects);
    try testing.expectEqual(@as(usize, 2), total.events);
    try testing.expectEqual(@as(usize, 1), total.catchall);
    try testing.expectEqual(@as(usize, 2), total.concat);
    try testing.expectEqual(@as(usize, 1), total.devices);
    try testing.expectEqual(@as(usize, 1), total.elem_attrs);
}

test "a set-element list too big for one message is refused, not silently truncated" {
    // ⛔ CRITICAL regression (audit 2026-09-02). The ELEMENTS nest's length is
    // an `nlattr` u16, and `codec.nestEnd` used to write the low sixteen bits
    // of whatever the nest had grown to. There is nothing hostile in the
    // input here -- an ordinary blocklist of a few thousand addresses -- and
    // the outcome was the worst shape available for a module that writes
    // firewall policy: the batch COMMITTED, the kernel installed the fraction
    // the wrapped length described, and `commit()` reported success with
    // `lastFailure()` null. Measured before the fix: 6000 elements asked for,
    // 1904 landed (96000 mod 65536 = 30464 bytes = exactly 1904 elements).
    //
    // Refusing is this layer's honest answer: splitting the list across
    // several NEWSETELEM messages, which is what `nft(8)` does, is the
    // caller's decision to make. Recorded as a follow-up in the ledger.
    const gpa = testing.allocator;
    var b = try Batch.init(gpa, 1, .{});
    defer b.deinit();

    var elems: [6000]SetElem = undefined;
    var keys: [6000][4]u8 = undefined;
    for (&keys, 0..) |*k, i| {
        std.mem.writeInt(u32, k, @intCast(0x0A00_0000 + i), .big);
        elems[i] = .{ .key = k };
    }
    try testing.expectError(error.AttrTooLong, b.addSetElems(.inet, "filter", "blocked", null, &elems));

    // A list that does fit still works, so the bound did not become a refusal
    // of everything.
    try b.addSetElems(.inet, "filter", "blocked", null, elems[0..1000]);
}

// ── 2026-10-04: objects, maps, counter decode ───────────────────────────────

/// The first command message of a finished batch.
fn firstCommand(bytes: []const u8) !nl.Message {
    var it: nl.MessageIterator = .{ .buf = bytes };
    _ = try it.next(); // BATCH_BEGIN
    return (try it.next()).?;
}

test "decodeObject reads back what addObject encodes (counter and quota)" {
    // The encoder is pinned byte-for-byte by the `add counter`/`add quota`
    // goldens; a GETOBJ dump reply has the same attribute layout plus
    // USE/HANDLE (`enum nft_object_attributes`), so decoding the request
    // checks the decoder against the captured shape.
    const gpa = testing.allocator;
    var b = try Batch.init(gpa, 0, .{});
    defer b.deinit();
    try b.addObject(.{ .family = .inet, .table = "t", .name = "c", .obj = .{ .counter = .{ .packets = 7, .bytes = 900 } } });
    try b.addObject(.{ .family = .ip, .table = "t", .name = "q", .obj = .{ .quota = .{ .bytes = 5000, .consumed = 12, .over = true } } });
    var it: nl.MessageIterator = .{ .buf = try b.finish() };
    _ = try it.next();
    const mc = (try it.next()).?;
    try testing.expectEqual(nftMsg(NFT_MSG.NEWOBJ), mc.type);
    try testing.expect(mc.flags & nl.NLM_F_CREATE != 0);
    const c = try decodeObject(mc.payload);
    try testing.expectEqual(types.NFPROTO.INET, c.family);
    try testing.expectEqualStrings("c", c.name);
    try testing.expectEqual(@as(u32, 1), c.obj_type); // NFT_OBJECT_COUNTER
    try testing.expectEqual(@as(u64, 7), c.counter.?.packets);
    try testing.expectEqual(@as(u64, 900), c.counter.?.bytes);
    try testing.expect(c.quota == null);
    const q = try decodeObject((try it.next()).?.payload);
    try testing.expectEqual(@as(u32, 2), q.obj_type); // NFT_OBJECT_QUOTA
    try testing.expectEqual(@as(u64, 5000), q.quota.?.bytes);
    try testing.expectEqual(@as(u64, 12), q.quota.?.consumed);
    try testing.expectEqual(expr.NFT_QUOTA_F_INV, q.quota.?.flags);
    try testing.expect(q.counter == null);
    try testing.expectEqualStrings("NEWOBJ", commandNameOf(nftMsg(NFT_MSG.NEWOBJ)));
    try testing.expectEqualStrings("DELOBJ", commandNameOf(nftMsg(NFT_MSG.DELOBJ)));
    try testing.expectEqualStrings("GETOBJ", commandNameOf(nftMsg(NFT_MSG.GETOBJ)));
}

test "decodeObject: an unknown object type keeps its raw data; hostile lengths are refused" {
    // TYPE after DATA, type 9 (not modelled): both decoded-state fields stay
    // null and the raw nest is handed back.
    const reply = [_]u8{ 1, 0, 0, 0 } ++ // nfgenmsg: inet
        [_]u8{ 0x0c, 0x00, 0x04, 0x80, 0x08, 0x00, 0x01, 0x00, 0xaa, 0xbb, 0xcc, 0xdd } ++ // DATA{ [1]=… }
        [_]u8{ 0x08, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x09 }; // TYPE = 9 (BE)
    const o = try decodeObject(&reply);
    try testing.expectEqual(@as(u32, 9), o.obj_type);
    try testing.expect(o.counter == null and o.quota == null);
    try testing.expectEqual(@as(usize, 8), o.data.len);
    // A counter whose PACKETS attribute is 4 bytes instead of 8.
    const bad = [_]u8{ 1, 0, 0, 0 } ++
        [_]u8{ 0x08, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01 } ++ // TYPE = counter
        [_]u8{ 0x0c, 0x00, 0x04, 0x80, 0x08, 0x00, 0x02, 0x00, 0, 0, 0, 1 };
    try testing.expectError(error.BadLength, decodeObject(&bad));
    // A DATA nest that claims more bytes than the message has.
    const trunc = [_]u8{ 1, 0, 0, 0 } ++ [_]u8{ 0x40, 0x00, 0x04, 0x80, 0, 0, 0, 0 };
    try testing.expectError(error.Truncated, decodeObject(&trunc));
}

test "a verdict-map set and its elements decode back to verdicts" {
    const gpa = testing.allocator;
    var b = try Batch.init(gpa, 0, .{});
    defer b.deinit();
    try b.addSet(.{ .family = .inet, .table = "t", .name = "vm", .key_type = .inet_service, .data = .verdict, .flags = &.{.interval} });
    const s = try decodeSet((try firstCommand(b.bytes())).payload);
    // MAP is ORed into the caller's flags, not instead of them.
    try testing.expectEqual(NFT_SET_MAP | types.SetFlag.interval.bit(), s.flags);
    try testing.expectEqual(@as(?u32, NFT_DATA_VERDICT), s.data_type);
    try testing.expectEqual(@as(?u32, 0), s.data_len);

    var d = try Batch.init(gpa, 0, .{});
    defer d.deinit();
    try d.addSet(.{ .family = .ip, .table = "t", .name = "dm", .key_type = .inet_service, .data = .{ .value = .ipv4_addr } });
    const dm = try decodeSet((try firstCommand(d.bytes())).payload);
    try testing.expectEqual(NFT_SET_MAP, dm.flags);
    // A data map: nft's ipv4_addr datatype id (7) and its 4-byte length.
    try testing.expectEqual(@as(?u32, 7), dm.data_type);
    try testing.expectEqual(@as(?u32, 4), dm.data_len);

    // A plain set has no data half at all.
    var p = try Batch.init(gpa, 0, .{});
    defer p.deinit();
    try p.addSet(.{ .family = .ip, .table = "t", .name = "s", .key_type = .ipv4_addr });
    const ps = try decodeSet((try firstCommand(p.bytes())).payload);
    try testing.expectEqual(@as(u32, 0), ps.flags);
    try testing.expectEqual(@as(?u32, null), ps.data_type);

    var e = try Batch.init(gpa, 0, .{});
    defer e.deinit();
    try e.addSetElems(.inet, "t", "vm", null, &.{
        .{ .key = &.{ 0, 22 }, .verdict = .drop },
        .{ .key = &.{ 0, 80 }, .verdict = expr.Verdict.gotoChain("web") },
        .{ .key = &.{ 0, 81 }, .data = &.{ 10, 0, 0, 1 } },
    });
    const reply = try decodeSetElemReply((try firstCommand(e.bytes())).payload);
    var it = reply.iterator();
    const e1 = (try it.next()).?;
    try testing.expectEqual(types.NF.DROP, e1.verdict.?.code);
    try testing.expect(e1.data == null);
    const e2 = (try it.next()).?;
    try testing.expectEqual(types.NFT.GOTO, e2.verdict.?.code);
    try testing.expectEqualStrings("web", e2.verdict.?.chain.?);
    const e3 = (try it.next()).?;
    try testing.expect(e3.verdict == null);
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 1 }, e3.data.?);
    try testing.expect((try it.next()) == null);
}

test "decodeCounter reads a rule dump's counter and refuses a short value" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try expr.appendExpr(gpa, &list, .{ .counter = .{ .packets = 3, .bytes = 180 } });
    var it: expr.ExprIterator = .{ .attrs = .{ .buf = list.items } };
    const v = (try it.next()).?;
    try testing.expectEqualStrings("counter", v.name);
    const c = (try expr.decodeCounter(v.data)).?;
    try testing.expectEqual(@as(u64, 3), c.packets);
    try testing.expectEqual(@as(u64, 180), c.bytes);
    // A fresh counter as `nft` sends it (empty data) decodes to null.
    try testing.expect((try expr.decodeCounter(&.{})) == null);
    // Only BYTES present: packets default to 0, not garbage.
    const only_bytes = [_]u8{ 0x0c, 0x00, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0x01, 0x00 };
    const ob = (try expr.decodeCounter(&only_bytes)).?;
    try testing.expectEqual(@as(u64, 0), ob.packets);
    try testing.expectEqual(@as(u64, 256), ob.bytes);
    // PACKETS with a 4-byte value is malformed.
    const short = [_]u8{ 0x08, 0x00, 0x02, 0x00, 0, 0, 0, 1 };
    try testing.expectError(error.BadLength, expr.decodeCounter(&short));
}

test "eventOf classifies nf_tables notifications and ignores everything else" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    // NEWTABLE "t" (as the kernel multicasts it after a commit) ...
    var h = try nl.appendHeader(gpa, &list, nftMsg(NFT_MSG.NEWTABLE), 0, 5, 0);
    try appendNfgenmsg(gpa, &list, types.NFPROTO.INET, 0);
    try nl.appendAttrString(gpa, &list, NFTA_TABLE.NAME, "t");
    nl.finishHeader(&list, h);
    // ... DELCHAIN ...
    h = try nl.appendHeader(gpa, &list, nftMsg(NFT_MSG.DELCHAIN), 0, 6, 0);
    try appendNfgenmsg(gpa, &list, types.NFPROTO.IPV4, 0);
    try nl.appendAttrString(gpa, &list, NFTA_CHAIN.NAME, "c");
    nl.finishHeader(&list, h);
    // ... a trace (not a ruleset event) ...
    h = try nl.appendHeader(gpa, &list, nftMsg(NFT_MSG.TRACE), 0, 7, 0);
    try appendNfgenmsg(gpa, &list, types.NFPROTO.IPV4, 0);
    nl.finishHeader(&list, h);
    // ... and NEWGEN carrying the generation id.
    h = try nl.appendHeader(gpa, &list, nftMsg(NFT_MSG.NEWGEN), 0, 8, 0);
    try appendNfgenmsg(gpa, &list, types.NFPROTO.UNSPEC, 0);
    try nl.appendAttrBe32(gpa, &list, NFTA_GEN_ID, 42);
    nl.finishHeader(&list, h);

    var it: nl.MessageIterator = .{ .buf = list.items };
    const e1 = eventOf((try it.next()).?).?;
    try testing.expectEqual(EventObject.table, e1.object);
    try testing.expectEqual(EventAction.new, e1.action);
    try testing.expectEqualStrings("t", (try decodeTable(e1.payload)).name);
    const e2 = eventOf((try it.next()).?).?;
    try testing.expectEqual(EventObject.chain, e2.object);
    try testing.expectEqual(EventAction.delete, e2.action);
    try testing.expect(eventOf((try it.next()).?) == null);
    const e4 = eventOf((try it.next()).?).?;
    try testing.expectEqual(EventObject.generation, e4.object);
    try testing.expectEqual(@as(?u32, 42), try decodeGenId(e4.payload));
    try testing.expect((try it.next()) == null);
    // A message of another subsystem is not ours.
    try testing.expect(eventOf(.{ .type = 0x0100, .flags = 0, .seq = 0, .pid = 0, .payload = &.{} }) == null);
}

test "BatchOptions.gen_id adds NFNL_BATCH_GENID to BATCH_BEGIN only" {
    var b = try Batch.init(testing.allocator, 0, .{ .ack = false, .gen_id = 0x01020304 });
    defer b.deinit();
    try b.addTable(.{ .family = .inet, .name = "t" });
    const bytes = try b.finish();
    // BATCH_BEGIN: header 16 + nfgenmsg 4 + one 8-byte attribute.
    try testing.expectEqual(@as(u32, 28), std.mem.readInt(u32, bytes[0..4], native_endian));
    try testing.expectEqualSlices(u8, &.{ 8, 0, 1, 0, 1, 2, 3, 4 }, bytes[20..28]);
    // BATCH_END stays 20 bytes: find it as the last message.
    try testing.expectEqual(@as(u16, NFNL_MSG_BATCH_END), std.mem.readInt(u16, bytes[bytes.len - 16 ..][0..2], native_endian));
}

test "set concatenation helpers: type id, key length, padding, refusals" {
    try testing.expectEqual(@as(u32, 461), try concatKeyType(&.{ .ipv4_addr, .inet_service }));
    try testing.expectEqual((@as(u32, 7) << 12) | (13 << 6) | 12, try concatKeyType(&.{ .ipv4_addr, .inet_service, .inet_proto }));
    try testing.expectError(error.InvalidExpression, concatKeyType(&.{.ipv4_addr}));
    var buf: [8]u8 = undefined;
    const k = try concatKey(&buf, &.{ .ipv4_addr, .inet_service }, &.{ &.{ 1, 2, 3, 4 }, &.{ 0, 80 } });
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 0, 80, 0, 0 }, k);
    try testing.expectError(error.ValueWidthMismatch, concatKey(&buf, &.{ .ipv4_addr, .inet_service }, &.{ &.{ 1, 2, 3 }, &.{ 0, 80 } }));
    var small: [6]u8 = undefined;
    try testing.expectError(error.AttrTooLong, concatKey(&small, &.{ .ipv4_addr, .inet_service }, &.{ &.{ 1, 2, 3, 4 }, &.{ 0, 80 } }));
    try testing.expectEqual(@as(u32, 4), concatFieldSize(.inet_service));
    try testing.expectEqual(@as(u32, 16), concatFieldSize(.ipv6_addr));
}

test "decodeObjectData: every creatable object type decodes back to what addObject sent" {
    const gpa = testing.allocator;
    const specs = [_]ObjectData{
        .{ .counter = .{ .packets = 3, .bytes = 90 } },
        .{ .quota = .{ .bytes = 100, .consumed = 5, .over = true } },
        .{ .limit = .{ .rate = 10, .per = .minute, .burst = 5, .unit = .bytes, .inv = true } },
        .{ .ct_helper = .{ .name = "ftp", .l3proto = 2, .l4proto = 6 } },
        .{ .secmark = .{ .ctx = "system_u:object_r:x_t:s0" } },
        .{ .ct_expect = .{ .l3proto = 2, .l4proto = 6, .dport = 5000, .timeout_ms = 60000, .size = 12 } },
        .{ .synproxy = .{ .mss = 1460, .wscale = 7, .flags = 15 } },
        .{ .connlimit = .{ .count = 10, .over = true } },
    };
    for (specs) |spec| {
        var b = try Batch.init(gpa, 0, .{ .ack = false });
        defer b.deinit();
        try b.addObject(.{ .family = .inet, .table = "filter", .name = "o", .obj = spec });
        const bytes = try b.finish();
        var it: nl.MessageIterator = .{ .buf = bytes };
        _ = try it.next(); // BATCH_BEGIN
        const m = (try it.next()).?;
        const info = try decodeObject(m.payload);
        try testing.expectEqualDeep(spec, (try info.state()).?);
    }
}

test "decoders read the new set, chain and flowtable attributes" {
    const gpa = testing.allocator;
    var b = try Batch.init(gpa, 0, .{ .ack = false });
    defer b.deinit();
    try b.addSet(.{
        .family = .inet,
        .table = "t",
        .name = "ci",
        .key_type = .ipv4_addr,
        .key_concat = &.{ .ipv4_addr, .inet_service },
        .flags = &.{.interval},
        .policy = .memory,
        .gc_interval_ms = 60000,
        .size = 10,
    });
    try b.addChain(.{ .family = .netdev, .table = "nd", .name = "ing", .chain_type = .filter, .hook = .ingress, .prio = 0, .devs = &.{ "dummy0", "lo" }, .flags = NFT_CHAIN_F.HW_OFFLOAD });
    try b.addFlowtable(.{ .family = .inet, .table = "t", .name = "ft", .prio = -10, .devs = &.{ "lo", "eth0" }, .flags = NFT_FLOWTABLE_F.COUNTER });
    const bytes = try b.finish();
    var it: nl.MessageIterator = .{ .buf = bytes };
    _ = try it.next();
    const set = try decodeSet((try it.next()).?.payload);
    try testing.expectEqual(@as(u32, NFT_SET_F.INTERVAL | NFT_SET_F.CONCAT), set.flags);
    try testing.expectEqual(@as(u32, 8), set.key_len);
    try testing.expectEqual(@as(?u32, 1), set.policy);
    try testing.expectEqual(@as(?u32, 60000), set.gc_interval_ms);
    try testing.expectEqual(@as(?u32, 10), set.size);
    var cf = set.concatFields();
    try testing.expectEqual(@as(?u32, 4), try cf.next());
    try testing.expectEqual(@as(?u32, 2), try cf.next());
    try testing.expectEqual(@as(?u32, null), try cf.next());
    const chain = try decodeChain((try it.next()).?.payload);
    try testing.expectEqual(@as(u32, NFT_CHAIN_F.HW_OFFLOAD), chain.flags);
    var di = chain.devices();
    try testing.expectEqualStrings("dummy0", (try di.next()).?);
    try testing.expectEqualStrings("lo", (try di.next()).?);
    try testing.expect((try di.next()) == null);
    const ft = try decodeFlowtable((try it.next()).?.payload);
    try testing.expectEqualStrings("ft", ft.name);
    try testing.expectEqual(@as(?i32, -10), ft.prio);
    try testing.expectEqual(@as(u32, NFT_FLOWTABLE_F.COUNTER), ft.flags);
    var fd = ft.devices();
    try testing.expectEqualStrings("lo", (try fd.next()).?);
    try testing.expectEqualStrings("eth0", (try fd.next()).?);
}

test "get-element, reset and genid requests have nft's layout" {
    const gpa = testing.allocator;
    // `nft get element inet filter s2 '{ 1.2.3.4 }'`, captured 2026-11-07
    // (flags 0x0005 = REQUEST|ACK, as in the capture).
    const req = try buildSetElemGetRequest(gpa, 1, .inet, "filter", "s2", &.{&.{ 1, 2, 3, 4 }}, false);
    defer gpa.free(req);
    const want = [_]u8{
        0x3c, 0x00, 0x00, 0x00, 0x0d, 0x0a, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x02, 0x00, 0x73, 0x32, 0x00, 0x00, 0x0b, 0x00, 0x01, 0x00,
        0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x00, 0x00, 0x14, 0x00, 0x03, 0x80, 0x10, 0x00, 0x01, 0x80,
        0x0c, 0x00, 0x01, 0x80, 0x08, 0x00, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04,
    };
    if (native_endian == .little) try testing.expectEqualSlices(u8, &want, req);
    const gen = buildGenIdRequest(7);
    try testing.expectEqual(@as(u16, nftMsg(NFT_MSG.GETGEN)), std.mem.readInt(u16, gen[4..6], native_endian));
    const rr = try buildSetElemResetRequest(gpa, 2, .inet, "filter", "s2");
    defer gpa.free(rr);
    try testing.expectEqual(@as(u16, nftMsg(NFT_MSG.GETSETELEM_RESET)), std.mem.readInt(u16, rr[4..6], native_endian));
    try testing.expect(std.mem.readInt(u16, rr[6..8], native_endian) & nl.NLM_F_DUMP == nl.NLM_F_DUMP);
}

test "rule get request names table, chain and handle" {
    const gpa = testing.allocator;
    const req = try buildRuleGetRequest(gpa, 3, .inet, "filter", "input", 7);
    defer gpa.free(req);
    var it: nl.MessageIterator = .{ .buf = req };
    const m = (try it.next()).?;
    try testing.expectEqual(nftMsg(NFT_MSG.GETRULE), m.type);
    try testing.expectEqual(@as(u16, nl.NLM_F_REQUEST), m.flags);
    const hdr = try parseNfgenmsg(m.payload);
    var ai = hdr.attrIterator();
    var handle: u64 = 0;
    while (try ai.next()) |a| if (a.type == NFTA_RULE.HANDLE) {
        handle = try a.asBe64();
    };
    try testing.expectEqual(@as(u64, 7), handle);
}
