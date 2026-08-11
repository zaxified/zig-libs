// SPDX-License-Identifier: MIT
//! Netlink message + attribute (rtattr/nlattr TLV) codec — the pure-wire,
//! security-critical core of the `netlink` module. No I/O, no syscalls, no
//! platform dependency: everything here operates on byte slices and is fully
//! unit- and fuzz-testable on any OS.
//!
//! Wire format (host byte order, 4-byte alignment) per the kernel UAPI
//! `linux/netlink.h` + `linux/rtnetlink.h` and RFC 3549 §2.3.2:
//!
//! ```text
//! nlmsghdr:  u32 len | u16 type | u16 flags | u32 seq | u32 pid   (16 bytes)
//! rtattr:    u16 len | u16 type | payload | pad-to-4              (len covers hdr+payload)
//! ```
//!
//! Every length field is validated against the enclosing buffer before any
//! slice is formed: a truncated, hostile, or bit-flipped buffer yields
//! `error.Truncated` / `error.BadLength`, never a panic or an out-of-bounds
//! read. Iteration always advances by at least 4 bytes, so a walk over a
//! buffer of N bytes is capped at N/4 steps — no input can loop forever.
//! Semantics (what counts as a valid message/attribute, how the final
//! unpadded element is accepted) mirror libmnl's `mnl_nlmsg_ok`/`mnl_attr_ok`
//! (behavior only — clean-room, no source consulted).

const std = @import("std");
const native_endian = @import("builtin").cpu.arch.endian();

pub const Error = error{
    /// A header or a declared length runs past the end of the buffer.
    Truncated,
    /// A declared length is impossibly small (or a fixed-size value has the
    /// wrong size).
    BadLength,
};

// ── wire constants (kernel UAPI linux/netlink.h) ────────────────────────────

/// NLMSG_ALIGNTO — netlink messages and attributes align to 4 bytes.
pub const align_to = 4;
/// NLMSG_HDRLEN — sizeof(struct nlmsghdr), already 4-byte aligned.
pub const header_len = 16;
/// sizeof(struct rtattr) == sizeof(struct nlattr) — the TLV header.
pub const attr_header_len = 4;

/// Control message types (linux/netlink.h `NLMSG_*`).
pub const NLMSG_NOOP: u16 = 0x1;
pub const NLMSG_ERROR: u16 = 0x2;
pub const NLMSG_DONE: u16 = 0x3;
pub const NLMSG_OVERRUN: u16 = 0x4;

/// Request/response flags (linux/netlink.h `NLM_F_*`).
pub const NLM_F_REQUEST: u16 = 0x01;
pub const NLM_F_MULTI: u16 = 0x02;
pub const NLM_F_ACK: u16 = 0x04;
pub const NLM_F_ECHO: u16 = 0x08;
/// Dump was inconsistent due to sequence change — the caller should restart.
pub const NLM_F_DUMP_INTR: u16 = 0x10;
pub const NLM_F_ROOT: u16 = 0x100;
pub const NLM_F_MATCH: u16 = 0x200;
pub const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;

/// Write-path request modifiers (linux/netlink.h, "Modifiers to NEW/DELETE
/// request"). These numerically overlap the dump flags above — they are only
/// meaningful on `RTM_NEW*`/`RTM_DEL*` messages, never on a dump.
pub const NLM_F_REPLACE: u16 = 0x100;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLM_F_CREATE: u16 = 0x400;
pub const NLM_F_APPEND: u16 = 0x800;

/// Flags the kernel sets on an `NLMSG_ERROR` reply (linux/netlink.h,
/// "Flags for ACK message"). `NLM_F_CAPPED` = the offending request's payload
/// was *not* echoed back (only its 16-byte header); `NLM_F_ACK_TLVS` =
/// extended-ACK attributes follow the echoed request.
pub const NLM_F_CAPPED: u16 = 0x100;
pub const NLM_F_ACK_TLVS: u16 = 0x200;

/// Extended-ACK attribute types (linux/netlink.h `NLMSGERR_ATTR_*`), carried
/// after `struct nlmsgerr` when `NLM_F_ACK_TLVS` is set.
pub const NLMSGERR_ATTR = struct {
    pub const UNSPEC: u16 = 0;
    /// NUL-terminated string: the kernel's reason for the rejection.
    pub const MSG: u16 = 1;
    /// u32 byte offset into the request that the kernel objected to.
    pub const OFFS: u16 = 2;
    pub const COOKIE: u16 = 3;
    pub const POLICY: u16 = 4;
    pub const MISS_TYPE: u16 = 5;
    pub const MISS_NLATTR: u16 = 6;
};

/// Attribute-type flag bits (linux/netlink.h `NLA_F_*` / `NLA_TYPE_MASK`).
pub const NLA_F_NESTED: u16 = 0x8000;
pub const NLA_F_NET_BYTEORDER: u16 = 0x4000;
pub const NLA_TYPE_MASK: u16 = 0x3fff;

/// NLMSG_ALIGN(n): round `n` up to the netlink 4-byte boundary.
pub fn alignUp(n: usize) usize {
    return (n + (align_to - 1)) & ~@as(usize, align_to - 1);
}

// ── message parsing ─────────────────────────────────────────────────────────

/// One parsed netlink message: the decoded `nlmsghdr` fields plus the payload
/// slice that follows the 16-byte header (borrowed from the input buffer).
pub const Message = struct {
    type: u16,
    flags: u16,
    seq: u32,
    pid: u32,
    payload: []const u8,

    /// For an `NLMSG_ERROR` message: the negative errno in the payload's
    /// leading i32 (`struct nlmsgerr.error`). 0 means ACK (success).
    pub fn errorCode(m: Message) Error!i32 {
        if (m.payload.len < 4) return error.Truncated;
        return std.mem.readInt(i32, m.payload[0..4], native_endian);
    }

    /// Iterate this message's attributes, treating `fixed_len` leading bytes
    /// of the payload as the fixed family header (ifinfomsg/rtmsg/…).
    pub fn attrs(m: Message, fixed_len: usize) Error!AttrIterator {
        if (m.payload.len < fixed_len) return error.Truncated;
        return .{ .buf = m.payload[fixed_len..] };
    }

    /// Extended-ACK attributes of an `NLMSG_ERROR` message, or null when the
    /// kernel attached none (`NLM_F_ACK_TLVS` clear — old kernel, or the
    /// socket never enabled `NETLINK_EXT_ACK`).
    ///
    /// Layout per the kernel's `netlink_ack()`: the payload starts with
    /// `struct nlmsgerr { int error; struct nlmsghdr msg; }`; the echoed
    /// request is the bare 16-byte header when `NLM_F_CAPPED` is set and the
    /// *whole* original message (`msg.nlmsg_len` bytes) otherwise. The TLVs
    /// begin right after that — every offset is bounds-checked here.
    pub fn errorAttrs(m: Message) Error!?AttrIterator {
        if (m.flags & NLM_F_ACK_TLVS == 0) return null;
        if (m.payload.len < 4 + header_len) return error.Truncated;
        var off: usize = 4 + header_len; // sizeof(struct nlmsgerr)
        if (m.flags & NLM_F_CAPPED == 0) {
            const echoed: usize = std.mem.readInt(u32, m.payload[4..8], native_endian);
            if (echoed < header_len) return error.BadLength;
            off = 4 + echoed;
        }
        off = alignUp(off);
        if (off > m.payload.len) return error.Truncated;
        return .{ .buf = m.payload[off..] };
    }

    /// The kernel's human-readable reason for an `NLMSG_ERROR`
    /// (`NLMSGERR_ATTR_MSG`), or null when none was attached. The slice
    /// borrows from the message payload.
    pub fn errorMessage(m: Message) Error!?[]const u8 {
        var it = (try m.errorAttrs()) orelse return null;
        while (try it.next()) |a| {
            if (a.type == NLMSGERR_ATTR.MSG) return a.asString();
        }
        return null;
    }

    /// The `nlmsg_seq` of the request the kernel is complaining about, taken
    /// from the echoed `nlmsghdr` inside `struct nlmsgerr`, or null when the
    /// payload is too short to carry one. **This is what turns a batch failure
    /// into "message #N failed"** — the `NLMSG_ERROR` message's own seq
    /// normally carries it too, but the echoed copy proves it (and some
    /// kernels report a commit failure with seq 0).
    pub fn errorRequestSeq(m: Message) Error!?u32 {
        if (m.payload.len < 4 + header_len) return null;
        return std.mem.readInt(u32, m.payload[4 + 8 ..][0..4], native_endian);
    }
};

/// Walk a buffer of concatenated netlink messages (one recv datagram, or a
/// canned test buffer). Each `next()` validates the header length against the
/// remaining bytes; malformed input errors out instead of over-reading.
pub const MessageIterator = struct {
    buf: []const u8,
    offset: usize = 0,

    pub fn next(it: *MessageIterator) Error!?Message {
        if (it.offset >= it.buf.len) return null;
        const rest = it.buf[it.offset..];
        if (rest.len < header_len) return error.Truncated;
        const mlen: usize = std.mem.readInt(u32, rest[0..4], native_endian);
        if (mlen < header_len) return error.BadLength;
        if (mlen > rest.len) return error.Truncated;
        const msg: Message = .{
            .type = std.mem.readInt(u16, rest[4..6], native_endian),
            .flags = std.mem.readInt(u16, rest[6..8], native_endian),
            .seq = std.mem.readInt(u32, rest[8..12], native_endian),
            .pid = std.mem.readInt(u32, rest[12..16], native_endian),
            .payload = rest[header_len..mlen],
        };
        // Advance by the aligned length; the final message of a buffer may
        // omit its trailing pad (mnl_nlmsg_next tolerates this too).
        it.offset += @min(alignUp(mlen), rest.len);
        return msg;
    }
};

// ── attribute parsing ───────────────────────────────────────────────────────

/// One parsed rtattr/nlattr TLV. `data` borrows from the input buffer.
pub const Attr = struct {
    /// Attribute type with the NLA_F_* flag bits masked off — this is what
    /// IFLA_*/IFA_*/RTA_*/NDA_* constants compare against.
    type: u16,
    /// The raw type field including NLA_F_NESTED / NLA_F_NET_BYTEORDER bits.
    raw_type: u16,
    data: []const u8,

    /// Walk a nested attribute's payload as its own attribute list.
    pub fn nested(a: Attr) AttrIterator {
        return .{ .buf = a.data };
    }

    pub fn asU8(a: Attr) Error!u8 {
        if (a.data.len != 1) return error.BadLength;
        return a.data[0];
    }

    pub fn asU16(a: Attr) Error!u16 {
        if (a.data.len != 2) return error.BadLength;
        return std.mem.readInt(u16, a.data[0..2], native_endian);
    }

    pub fn asU32(a: Attr) Error!u32 {
        if (a.data.len != 4) return error.BadLength;
        return std.mem.readInt(u32, a.data[0..4], native_endian);
    }

    pub fn asI32(a: Attr) Error!i32 {
        if (a.data.len != 4) return error.BadLength;
        return std.mem.readInt(i32, a.data[0..4], native_endian);
    }

    /// String payload with any trailing NULs stripped (kernel strings are
    /// NUL-terminated on the wire; a missing terminator is tolerated).
    pub fn asString(a: Attr) []const u8 {
        return std.mem.trimEnd(u8, a.data, "\x00");
    }

    // ── big-endian accessors ────────────────────────────────────────────────
    //
    // rtnetlink puts its integers on the wire in **host** byte order, which is
    // what `asU16`/`asU32` above decode. Every netfilter family (ctnetlink,
    // nftables, nfqueue, nflog, cttimeout) does the opposite: its integer
    // attributes are **network** byte order and the kernel does *not* set
    // `NLA_F_NET_BYTEORDER` on them, so nothing on the wire distinguishes the
    // two — the reader has to know its family. These are the net-order twins
    // of the host-order accessors, with the same exact-width guards.

    pub fn asBe16(a: Attr) Error!u16 {
        if (a.data.len != 2) return error.BadLength;
        return std.mem.readInt(u16, a.data[0..2], .big);
    }

    pub fn asBe32(a: Attr) Error!u32 {
        if (a.data.len != 4) return error.BadLength;
        return std.mem.readInt(u32, a.data[0..4], .big);
    }

    pub fn asBe64(a: Attr) Error!u64 {
        if (a.data.len != 8) return error.BadLength;
        return std.mem.readInt(u64, a.data[0..8], .big);
    }
};

/// Bounds-checked TLV walker. Validation per attribute (mirrors mnl_attr_ok):
/// at least 4 header bytes remain, `len >= 4`, and `len` fits in the
/// remaining buffer — otherwise `error.Truncated`/`error.BadLength`, never an
/// OOB read. Since `len >= 4`, every step advances >= 4 bytes: iteration over
/// N bytes is capped at N/4 steps by construction.
pub const AttrIterator = struct {
    buf: []const u8,
    offset: usize = 0,

    pub fn next(it: *AttrIterator) Error!?Attr {
        if (it.offset >= it.buf.len) return null;
        const rest = it.buf[it.offset..];
        if (rest.len < attr_header_len) return error.Truncated;
        const alen: usize = std.mem.readInt(u16, rest[0..2], native_endian);
        const raw_type = std.mem.readInt(u16, rest[2..4], native_endian);
        if (alen < attr_header_len) return error.BadLength;
        if (alen > rest.len) return error.Truncated;
        // The final attribute may omit its trailing pad (mnl tolerates this).
        it.offset += @min(alignUp(alen), rest.len);
        return .{
            .type = raw_type & NLA_TYPE_MASK,
            .raw_type = raw_type,
            .data = rest[attr_header_len..alen],
        };
    }
};

// ── message building ────────────────────────────────────────────────────────

/// Append a 16-byte nlmsghdr with a zero length placeholder; returns the
/// header's offset for the closing `finishHeader` call.
pub fn appendHeader(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    msg_type: u16,
    flags: u16,
    seq: u32,
    pid: u32,
) std.mem.Allocator.Error!usize {
    const start = list.items.len;
    var hdr: [header_len]u8 = @splat(0);
    std.mem.writeInt(u16, hdr[4..6], msg_type, native_endian);
    std.mem.writeInt(u16, hdr[6..8], flags, native_endian);
    std.mem.writeInt(u32, hdr[8..12], seq, native_endian);
    std.mem.writeInt(u32, hdr[12..16], pid, native_endian);
    try list.appendSlice(gpa, &hdr);
    return start;
}

/// Patch the nlmsghdr at `hdr_offset` so its length covers everything
/// appended since `appendHeader`. Call once per message, before starting the
/// next one.
pub fn finishHeader(list: *std.ArrayList(u8), hdr_offset: usize) void {
    const mlen: u32 = @intCast(list.items.len - hdr_offset);
    std.mem.writeInt(u32, list.items[hdr_offset..][0..4], mlen, native_endian);
}

/// Append raw payload bytes (e.g. a fixed ifinfomsg/rtmsg header) and pad to
/// the 4-byte netlink boundary.
pub fn appendPadded(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    bytes: []const u8,
) std.mem.Allocator.Error!void {
    try list.appendSlice(gpa, bytes);
    try list.appendNTimes(gpa, 0, alignUp(bytes.len) - bytes.len);
}

/// Append one rtattr TLV: u16 len (header + payload), u16 type, payload,
/// zero-padding to the 4-byte boundary (RTA_ALIGN). The length field does not
/// include the padding — matching the kernel/libmnl encoders.
pub fn appendAttr(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    data: []const u8,
) (std.mem.Allocator.Error || error{AttrTooLong})!void {
    const total = attr_header_len + data.len;
    if (total > std.math.maxInt(u16)) return error.AttrTooLong;
    var hdr: [attr_header_len]u8 = undefined;
    std.mem.writeInt(u16, hdr[0..2], @intCast(total), native_endian);
    std.mem.writeInt(u16, hdr[2..4], attr_type, native_endian);
    try list.appendSlice(gpa, &hdr);
    try list.appendSlice(gpa, data);
    try list.appendNTimes(gpa, 0, alignUp(total) - total);
}

/// Append a u32-valued rtattr (host byte order, like the kernel).
pub fn appendAttrU32(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    value: u32,
) std.mem.Allocator.Error!void {
    var raw: [4]u8 = undefined;
    std.mem.writeInt(u32, &raw, value, native_endian);
    appendAttr(gpa, list, attr_type, &raw) catch |err| switch (err) {
        error.AttrTooLong => unreachable, // 8 bytes total
        error.OutOfMemory => return error.OutOfMemory,
    };
}

/// Append a u16-valued rtattr (host byte order, like the kernel). The TLV is
/// 6 bytes long and padded to 8 — `nla_len` excludes the padding.
pub fn appendAttrU16(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    value: u16,
) std.mem.Allocator.Error!void {
    var raw: [2]u8 = undefined;
    std.mem.writeInt(u16, &raw, value, native_endian);
    appendAttr(gpa, list, attr_type, &raw) catch |err| switch (err) {
        error.AttrTooLong => unreachable, // 6 bytes total
        error.OutOfMemory => return error.OutOfMemory,
    };
}

/// Append a u8-valued rtattr (`nla_len` 5, padded to 8) — the shape the
/// kernel's boolean/enum link options use.
pub fn appendAttrU8(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    value: u8,
) std.mem.Allocator.Error!void {
    appendAttr(gpa, list, attr_type, &.{value}) catch |err| switch (err) {
        error.AttrTooLong => unreachable, // 5 bytes total
        error.OutOfMemory => return error.OutOfMemory,
    };
}

// ── big-endian writers ──────────────────────────────────────────────────────
//
// The net-order twins of `appendAttrU16`/`appendAttrU32` above, for the
// netfilter families whose integer attributes are network byte order (see the
// note on `Attr.asBe16`). Like their host-order twins they cannot overflow the
// u16 length field — the payload is a fixed 2/4/8 bytes — so `AttrTooLong` is
// asserted away rather than propagated.

/// Append a u16-valued attribute in network byte order.
pub fn appendAttrBe16(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    value: u16,
) std.mem.Allocator.Error!void {
    var raw: [2]u8 = undefined;
    std.mem.writeInt(u16, &raw, value, .big);
    appendAttr(gpa, list, attr_type, &raw) catch |err| switch (err) {
        error.AttrTooLong => unreachable, // 6 bytes total
        error.OutOfMemory => return error.OutOfMemory,
    };
}

/// Append a u32-valued attribute in network byte order.
pub fn appendAttrBe32(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    value: u32,
) std.mem.Allocator.Error!void {
    var raw: [4]u8 = undefined;
    std.mem.writeInt(u32, &raw, value, .big);
    appendAttr(gpa, list, attr_type, &raw) catch |err| switch (err) {
        error.AttrTooLong => unreachable, // 8 bytes total
        error.OutOfMemory => return error.OutOfMemory,
    };
}

/// Append a u64-valued attribute in network byte order (ctnetlink counters,
/// nftables handles).
pub fn appendAttrBe64(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    value: u64,
) std.mem.Allocator.Error!void {
    var raw: [8]u8 = undefined;
    std.mem.writeInt(u64, &raw, value, .big);
    appendAttr(gpa, list, attr_type, &raw) catch |err| switch (err) {
        error.AttrTooLong => unreachable, // 12 bytes total
        error.OutOfMemory => return error.OutOfMemory,
    };
}

/// Open a nested attribute: appends a TLV header with a placeholder length
/// and returns its offset for the closing `nestEnd`. `attr_type` is written
/// verbatim — rtnetlink nests (`IFLA_LINKINFO`, `TCA_OPTIONS`, …) are
/// conventionally sent *without* `NLA_F_NESTED` by iproute2 and the kernel's
/// validators ignore the bit, so OR it in only if you want it on the wire.
pub fn nestBegin(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
) std.mem.Allocator.Error!usize {
    const off = list.items.len;
    var hdr: [attr_header_len]u8 = undefined;
    std.mem.writeInt(u16, hdr[0..2], 0, native_endian); // patched by nestEnd
    std.mem.writeInt(u16, hdr[2..4], attr_type, native_endian);
    try list.appendSlice(gpa, &hdr);
    return off;
}

/// Close the nested attribute opened at `off`, patching its length to cover
/// everything appended since — including each inner attribute's alignment
/// padding, exactly like the kernel's `nla_nest_end`.
pub fn nestEnd(list: *std.ArrayList(u8), off: usize) void {
    const total: u16 = @intCast(list.items.len - off);
    std.mem.writeInt(u16, list.items[off..][0..2], total, native_endian);
}

/// Append a NUL-terminated string rtattr (kernel string convention).
pub fn appendAttrString(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    s: []const u8,
) (std.mem.Allocator.Error || error{AttrTooLong})!void {
    const total = attr_header_len + s.len + 1;
    if (total > std.math.maxInt(u16)) return error.AttrTooLong;
    var hdr: [attr_header_len]u8 = undefined;
    std.mem.writeInt(u16, hdr[0..2], @intCast(total), native_endian);
    std.mem.writeInt(u16, hdr[2..4], attr_type, native_endian);
    try list.appendSlice(gpa, &hdr);
    try list.appendSlice(gpa, s);
    // One zero run covers both the terminating NUL and the alignment pad.
    try list.appendNTimes(gpa, 0, alignUp(total) - total + 1);
}

// ── multi-part dump triage ──────────────────────────────────────────────────

/// What a caller's dump loop should do with one message of a multi-part reply.
/// See `classifyDumpMessage`.
pub const DumpStep = union(enum) {
    /// Not ours (stale/foreign portid or seq) or an explicit no-op — drop it
    /// and read on.
    skip,
    /// `NLM_F_DUMP_INTR`: the kernel's tables changed mid-dump, so everything
    /// collected so far may be inconsistent. Discard it and re-send the
    /// request (with a fresh sequence number).
    restart,
    /// `NLMSG_DONE`, or an `NLMSG_ERROR` carrying code 0 (a bare ACK, which is
    /// how an empty dump ends). The collected items are complete.
    done,
    /// `NLMSG_ERROR` with a non-zero negative errno. The caller maps it onto
    /// its own error set (`errorFromCode`, `writeErrorFromCode`, …) and may
    /// first pull the extended-ACK reason out of `msg`.
    failed: i32,
    /// `NLMSG_OVERRUN`: the kernel dropped messages; the dump is incomplete
    /// and the caller must resynchronise.
    overrun,
    /// The `NLMSG_ERROR` payload is too short to hold an errno — the reply
    /// failed wire validation.
    malformed,
    /// A payload message for the caller's parser. The caller still decides
    /// whether `msg.type` is a reply type it wants.
    record: Message,
};

/// Classify one message of a multi-part reply against the socket's identity.
///
/// This is the triage every netlink dump loop performs, in the order the
/// kernel's framing requires: match on (portid, seq) first — anything stale or
/// foreign is skipped, which also self-heals the queue after an aborted
/// earlier dump — then honour `NLM_F_DUMP_INTR`, then dispatch on the control
/// message types. Everything *above* it (which request, which reply type,
/// which parser, which error mapping, how items are allocated) is per-family
/// policy and stays with the caller, which is why this returns a verdict
/// instead of driving the loop.
///
/// Pure: no I/O, no allocation. Callers on other netlink protocols
/// (`NETLINK_NETFILTER`, `NETLINK_GENERIC`) use it with their own sockets.
pub fn classifyDumpMessage(m: Message, portid: u32, seq: u32) DumpStep {
    if (m.pid != portid or m.seq != seq) return .skip;
    if (m.flags & NLM_F_DUMP_INTR != 0) return .restart;
    return switch (m.type) {
        NLMSG_DONE => .done,
        NLMSG_ERROR => blk: {
            const code = m.errorCode() catch break :blk .malformed;
            break :blk if (code == 0) .done else .{ .failed = code };
        },
        NLMSG_NOOP => .skip,
        NLMSG_OVERRUN => .overrun,
        else => .{ .record = m },
    };
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "alignUp rounds to the netlink 4-byte boundary" {
    try testing.expectEqual(@as(usize, 0), alignUp(0));
    try testing.expectEqual(@as(usize, 4), alignUp(1));
    try testing.expectEqual(@as(usize, 4), alignUp(4));
    try testing.expectEqual(@as(usize, 8), alignUp(5));
    try testing.expectEqual(@as(usize, 8), alignUp(7));
}

test "golden: rtattr encode — string, u32, raw" {
    if (native_endian != .little) return error.SkipZigTest; // golden bytes are LE
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);

    // IFLA_IFNAME(3) = "lo" → len 7 (4 hdr + "lo\0"), padded to 8.
    try appendAttrString(testing.allocator, &list, 3, "lo");
    try testing.expectEqualSlices(u8, &.{ 0x07, 0x00, 0x03, 0x00, 'l', 'o', 0x00, 0x00 }, list.items);

    // IFLA_MTU(4) = 65536 → len 8, no padding.
    list.clearRetainingCapacity();
    try appendAttrU32(testing.allocator, &list, 4, 65536);
    try testing.expectEqualSlices(u8, &.{ 0x08, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00 }, list.items);

    // Raw 6-byte payload (a MAC) → len 10, padded to 12.
    list.clearRetainingCapacity();
    try appendAttr(testing.allocator, &list, 1, &.{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff });
    try testing.expectEqualSlices(
        u8,
        &.{ 0x0a, 0x00, 0x01, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00 },
        list.items,
    );
}

test "golden: nlmsghdr encode" {
    if (native_endian != .little) return error.SkipZigTest;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    const at = try appendHeader(testing.allocator, &list, 18, NLM_F_REQUEST | NLM_F_DUMP, 0x01020304, 0);
    try appendPadded(testing.allocator, &list, &.{ 0x02, 0x00, 0x00, 0x00 });
    finishHeader(&list, at);
    try testing.expectEqualSlices(u8, &.{
        0x14, 0x00, 0x00, 0x00, // len = 20
        0x12, 0x00, // type = RTM_GETLINK (18)
        0x01, 0x03, // flags = REQUEST | DUMP (0x301)
        0x04, 0x03, 0x02, 0x01, // seq
        0x00, 0x00, 0x00, 0x00, // pid
        0x02, 0x00, 0x00, 0x00, // payload
    }, list.items);
}

test "attr round-trip incl. odd-length alignment edge" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    try appendAttr(testing.allocator, &list, 1, &.{0x7f}); // len 5 → 3 pad bytes
    try appendAttrU32(testing.allocator, &list, 4, 1500);
    try appendAttrString(testing.allocator, &list, 3, "eth0"); // len 9 → 3 pad

    var it: AttrIterator = .{ .buf = list.items };
    const a1 = (try it.next()).?;
    try testing.expectEqual(@as(u16, 1), a1.type);
    try testing.expectEqual(@as(u8, 0x7f), try a1.asU8());
    const a2 = (try it.next()).?;
    try testing.expectEqual(@as(u32, 1500), try a2.asU32());
    const a3 = (try it.next()).?;
    try testing.expectEqualStrings("eth0", a3.asString());
    try testing.expectEqual(@as(?Attr, null), try it.next());
}

test "attr walker accepts a final unpadded attribute" {
    // len 5 attr at the very end of the buffer, pad omitted (mnl-compatible).
    const buf = [_]u8{ 0x05, 0x00, 0x02, 0x00, 0xee };
    var it: AttrIterator = .{ .buf = &buf };
    const a = (try it.next()).?;
    try testing.expectEqual(@as(u16, 2), a.type);
    try testing.expectEqualSlices(u8, &.{0xee}, a.data);
    try testing.expectEqual(@as(?Attr, null), try it.next());
}

test "attr walker rejects truncated and bad-length TLVs" {
    // Header cut short.
    var it: AttrIterator = .{ .buf = &.{ 0x08, 0x00, 0x01 } };
    try testing.expectError(error.Truncated, it.next());
    // Declared length runs past the buffer.
    it = .{ .buf = &.{ 0xff, 0x00, 0x01, 0x00, 0xaa, 0xbb } };
    try testing.expectError(error.Truncated, it.next());
    // Impossibly small length (< 4).
    it = .{ .buf = &.{ 0x03, 0x00, 0x01, 0x00, 0xaa, 0xbb, 0xcc, 0xdd } };
    try testing.expectError(error.BadLength, it.next());
    // Zero length must not loop forever either.
    it = .{ .buf = &.{ 0x00, 0x00, 0x01, 0x00 } };
    try testing.expectError(error.BadLength, it.next());
    // A valid attr followed by garbage still reports the garbage.
    it = .{ .buf = &.{ 0x04, 0x00, 0x01, 0x00, 0x02, 0x00 } };
    _ = (try it.next()).?;
    try testing.expectError(error.Truncated, it.next());
}

test "attr flag bits are masked and preserved" {
    const raw: u16 = NLA_F_NESTED | 5;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    try appendAttr(testing.allocator, &list, raw, &.{ 0x08, 0x00, 0x01, 0x00, 0xde, 0xad, 0xbe, 0xef });
    var it: AttrIterator = .{ .buf = list.items };
    const a = (try it.next()).?;
    try testing.expectEqual(@as(u16, 5), a.type);
    try testing.expectEqual(raw, a.raw_type);
}

test "nested attribute walking" {
    var inner: std.ArrayList(u8) = .empty;
    defer inner.deinit(testing.allocator);
    try appendAttrU32(testing.allocator, &inner, 1, 42);
    try appendAttrString(testing.allocator, &inner, 2, "kind");

    var outer: std.ArrayList(u8) = .empty;
    defer outer.deinit(testing.allocator);
    try appendAttr(testing.allocator, &outer, NLA_F_NESTED | 18, inner.items);

    var it: AttrIterator = .{ .buf = outer.items };
    const container = (try it.next()).?;
    try testing.expectEqual(@as(u16, 18), container.type);
    var sub = container.nested();
    const s1 = (try sub.next()).?;
    try testing.expectEqual(@as(u32, 42), try s1.asU32());
    const s2 = (try sub.next()).?;
    try testing.expectEqualStrings("kind", s2.asString());
    try testing.expectEqual(@as(?Attr, null), try sub.next());
}

test "scalar accessors validate their exact size" {
    const a: Attr = .{ .type = 1, .raw_type = 1, .data = &.{ 0x01, 0x02 } };
    try testing.expectError(error.BadLength, a.asU32());
    try testing.expectError(error.BadLength, a.asU8());
    try testing.expectEqual(@as(u16, 0x0201), try a.asU16());
}

test "message iterator: single and multi-part with NLMSG_DONE" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);

    var h = try appendHeader(gpa, &list, 16, NLM_F_MULTI, 7, 100);
    try appendPadded(gpa, &list, &.{ 0, 0, 0, 0 });
    try appendAttrU32(gpa, &list, 4, 1500);
    finishHeader(&list, h);

    h = try appendHeader(gpa, &list, 16, NLM_F_MULTI, 7, 100);
    try appendPadded(gpa, &list, &.{ 0, 0, 0, 0 });
    finishHeader(&list, h);

    h = try appendHeader(gpa, &list, NLMSG_DONE, NLM_F_MULTI, 7, 100);
    try appendPadded(gpa, &list, &.{ 0, 0, 0, 0 }); // int dump return code
    finishHeader(&list, h);

    var it: MessageIterator = .{ .buf = list.items };
    const m1 = (try it.next()).?;
    try testing.expectEqual(@as(u16, 16), m1.type);
    try testing.expectEqual(@as(u32, 7), m1.seq);
    try testing.expectEqual(@as(u32, 100), m1.pid);
    var attrs1 = try m1.attrs(4);
    try testing.expectEqual(@as(u32, 1500), try (try attrs1.next()).?.asU32());
    const m2 = (try it.next()).?;
    try testing.expectEqual(@as(usize, 4), m2.payload.len);
    const m3 = (try it.next()).?;
    try testing.expectEqual(NLMSG_DONE, m3.type);
    try testing.expectEqual(@as(?Message, null), try it.next());
}

test "message iterator rejects truncated and bad-length headers" {
    // Buffer shorter than one header.
    var it: MessageIterator = .{ .buf = &[_]u8{0} ** 10 };
    try testing.expectError(error.Truncated, it.next());
    // Declared length smaller than the header itself.
    var small: [16]u8 = @splat(0);
    std.mem.writeInt(u32, small[0..4], 8, native_endian);
    it = .{ .buf = &small };
    try testing.expectError(error.BadLength, it.next());
    // Declared length longer than the buffer.
    var long: [16]u8 = @splat(0);
    std.mem.writeInt(u32, long[0..4], 64, native_endian);
    it = .{ .buf = &long };
    try testing.expectError(error.Truncated, it.next());
}

test "NLMSG_ERROR payload yields the errno (and ACK)" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    const h = try appendHeader(gpa, &list, NLMSG_ERROR, 0, 9, 55);
    var code: [4]u8 = undefined;
    std.mem.writeInt(i32, &code, -1, native_endian); // -EPERM
    try appendPadded(gpa, &list, &code);
    // struct nlmsgerr also carries the offending header; append one.
    try appendPadded(gpa, &list, &([_]u8{0} ** header_len));
    finishHeader(&list, h);

    var it: MessageIterator = .{ .buf = list.items };
    const m = (try it.next()).?;
    try testing.expectEqual(NLMSG_ERROR, m.type);
    try testing.expectEqual(@as(i32, -1), try m.errorCode());

    // ACK = error code 0.
    const ack: Message = .{ .type = NLMSG_ERROR, .flags = 0, .seq = 0, .pid = 0, .payload = &.{ 0, 0, 0, 0 } };
    try testing.expectEqual(@as(i32, 0), try ack.errorCode());
    // Truncated error payload must not over-read.
    const cut: Message = .{ .type = NLMSG_ERROR, .flags = 0, .seq = 0, .pid = 0, .payload = &.{ 0, 0 } };
    try testing.expectError(error.Truncated, cut.errorCode());
}

test "nestBegin/nestEnd length covers inner padding (nla_nest_end)" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    // IFLA_LINKINFO(18) { IFLA_INFO_KIND(1) = "dummy" } — the exact shape
    // `ip link add name X type dummy` puts on the wire (see SPEC.md).
    const off = try nestBegin(gpa, &list, 18);
    try appendAttrString(gpa, &list, 1, "dummy"); // len 10, padded to 12
    nestEnd(&list, off);
    try testing.expectEqual(@as(usize, 16), list.items.len);
    var it: AttrIterator = .{ .buf = list.items };
    const nest = (try it.next()).?;
    try testing.expectEqual(@as(u16, 18), nest.type);
    try testing.expectEqual(@as(u16, 0), nest.raw_type & NLA_F_NESTED); // iproute2 style
    var inner = nest.nested();
    try testing.expectEqualStrings("dummy", (try inner.next()).?.asString());
}

test "extended ACK: NLMSGERR_ATTR_MSG extracted for capped and echoed errors" {
    const gpa = testing.allocator;
    // Capped form: error code + bare 16-byte echoed header, then the TLVs.
    var capped: std.ArrayList(u8) = .empty;
    defer capped.deinit(gpa);
    const h1 = try appendHeader(gpa, &capped, NLMSG_ERROR, NLM_F_ACK_TLVS | NLM_F_CAPPED, 3, 42);
    var code: [4]u8 = undefined;
    std.mem.writeInt(i32, &code, -22, native_endian); // -EINVAL
    try appendPadded(gpa, &capped, &code);
    try appendPadded(gpa, &capped, &([_]u8{0} ** header_len)); // echoed request hdr
    try appendAttrString(gpa, &capped, NLMSGERR_ATTR.MSG, "Unknown device type");
    finishHeader(&capped, h1);

    var it: MessageIterator = .{ .buf = capped.items };
    const m = (try it.next()).?;
    try testing.expectEqual(@as(i32, -22), try m.errorCode());
    try testing.expectEqualStrings("Unknown device type", (try m.errorMessage()).?);

    // Uncapped form: the whole original request is echoed, so the TLVs start
    // after `4 + original nlmsg_len` bytes.
    var full: std.ArrayList(u8) = .empty;
    defer full.deinit(gpa);
    const h2 = try appendHeader(gpa, &full, NLMSG_ERROR, NLM_F_ACK_TLVS, 3, 42);
    try appendPadded(gpa, &full, &code);
    var echoed: [header_len + 8]u8 = @splat(0);
    std.mem.writeInt(u32, echoed[0..4], echoed.len, native_endian);
    try appendPadded(gpa, &full, &echoed);
    try appendAttrString(gpa, &full, NLMSGERR_ATTR.MSG, "no such device");
    finishHeader(&full, h2);

    it = .{ .buf = full.items };
    const m2 = (try it.next()).?;
    try testing.expectEqualStrings("no such device", (try m2.errorMessage()).?);

    // No NLM_F_ACK_TLVS → no attributes at all, not an error.
    const plain: Message = .{ .type = NLMSG_ERROR, .flags = 0, .seq = 0, .pid = 0, .payload = &.{ 0, 0, 0, 0 } };
    try testing.expectEqual(@as(?AttrIterator, null), try plain.errorAttrs());
    try testing.expectEqual(@as(?[]const u8, null), try plain.errorMessage());
}

test "extended ACK: NLMSGERR_ATTR_MSG id is really 1 on a real kernel's wire (external anchor)" {
    // Every other extended-ACK test in this file writes and reads
    // `NLMSGERR_ATTR.MSG` through the same symbol, so a consistent mutation
    // of the id is invisible to the whole suite (audit finding `netlink` F1).
    // This one is different: the bytes below are a genuine `NLMSG_ERROR`
    // reply, captured verbatim from a real Linux kernel — not built with
    // `appendAttrString`/`NLMSGERR_ATTR.MSG` at all.
    //
    // Capture recipe (`iproute2-6.19.0`, unprivileged netns):
    //   unshare -rn strace -f -e trace=recvmsg -e read=all -xx -s 4096 \
    //           -e abbrev=none ip link set br1 master br0
    // (two bridges, the second enslaved to the first — the kernel's
    // `br_add_if()` rejects "bridge under a bridge" with an extack string,
    // NLM_F_ACK_TLVS set, NLM_F_CAPPED clear so the whole original request
    // is echoed before the TLVs, exactly the "uncapped" shape the sibling
    // test above exercises with synthetic bytes).
    //
    // `-e read=all -xx` dumps the raw recv buffer with no re-encoding step;
    // the TLV header immediately preceding the message string reads
    // `29 00 01 00` little-endian = nla_len 0x29 (41), nla_type **0x0001**.
    // That `01 00` is the literal being pinned here, independent of
    // `NLMSGERR_ATTR.MSG`'s value in this file.
    const raw = [_]u8{
        0x68, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x02, 0x01, 0x9b, 0x7a, 0x6a,
        0x8a, 0x5b, 0x12, 0x00, 0xd8, 0xff, 0xff, 0xff, 0x28, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x05, 0x00, 0x01, 0x9b, 0x7a, 0x6a, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x0a, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x29, 0x00, 0x01, 0x00, 'C',  'a',  'n',  ' ',  'n',  'o',  't',  ' ',
        'e',  'n',  's',  'l',  'a',  'v',  'e',  ' ',  'a',  ' ',  'b',  'r',
        'i',  'd',  'g',  'e',  ' ',  't',  'o',  ' ',  'a',  ' ',  'b',  'r',
        'i',  'd',  'g',  'e',  0x00, 0x00, 0x00, 0x00,
    };
    // The id byte pinned literally: byte 62 is the low byte of the
    // little-endian nla_type in the `29 00 01 00` TLV header above.
    try testing.expectEqual(@as(u8, 0x01), raw[62]);

    var it: MessageIterator = .{ .buf = &raw };
    const m = (try it.next()).?;
    try testing.expectEqual(@as(i32, -40), try m.errorCode()); // -ELOOP
    try testing.expectEqualStrings("Can not enslave a bridge to a bridge", (try m.errorMessage()).?);
}

test "extended ACK: hostile offsets are rejected, never over-read" {
    // NLM_F_ACK_TLVS set but the payload is shorter than struct nlmsgerr.
    const short: Message = .{ .type = NLMSG_ERROR, .flags = NLM_F_ACK_TLVS, .seq = 0, .pid = 0, .payload = &.{ 0, 0, 0, 0 } };
    try testing.expectError(error.Truncated, short.errorAttrs());
    // Echoed nlmsg_len smaller than a header.
    var bad: [4 + header_len]u8 = @splat(0);
    std.mem.writeInt(u32, bad[4..8], 4, native_endian);
    const badm: Message = .{ .type = NLMSG_ERROR, .flags = NLM_F_ACK_TLVS, .seq = 0, .pid = 0, .payload = &bad };
    try testing.expectError(error.BadLength, badm.errorAttrs());
    // Echoed nlmsg_len running past the reply.
    var over: [4 + header_len]u8 = @splat(0);
    std.mem.writeInt(u32, over[4..8], 4096, native_endian);
    const overm: Message = .{ .type = NLMSG_ERROR, .flags = NLM_F_ACK_TLVS, .seq = 0, .pid = 0, .payload = &over };
    try testing.expectError(error.Truncated, overm.errorAttrs());
}

test "extended ACK: unaligned echoed length is padded before the TLVs" {
    // nlmsg_len is the echoed request's *unpadded* size (linux/netlink.h:
    // NLMSG_LENGTH), so a header-only echo of `header_len + 1` bytes is a
    // legal, if unusual, encoding on the wire — the sender still pads the
    // buffer to a 4-byte boundary before appending the TLVs. `errorAttrs`
    // must apply that same NLMSG_ALIGN before reading, or it desyncs by up
    // to 3 bytes and returns garbage instead of the real attributes (or a
    // spurious Truncated/BadLength).
    const gpa = testing.allocator;
    var full: std.ArrayList(u8) = .empty;
    defer full.deinit(gpa);
    const h = try appendHeader(gpa, &full, NLMSG_ERROR, NLM_F_ACK_TLVS, 3, 42);
    var code: [4]u8 = undefined;
    std.mem.writeInt(i32, &code, -22, native_endian);
    try appendPadded(gpa, &full, &code);
    // Declared echoed length = header_len + 1 (unaligned); the bytes on the
    // wire are still padded to a 4-byte boundary, per appendPadded below.
    var echoed: [header_len + 1]u8 = @splat(0);
    std.mem.writeInt(u32, echoed[0..4], echoed.len, native_endian);
    try appendPadded(gpa, &full, &echoed); // pads to header_len + 4 on the wire
    try appendAttrString(gpa, &full, NLMSGERR_ATTR.MSG, "unaligned echo");
    finishHeader(&full, h);

    var it: MessageIterator = .{ .buf = full.items };
    const m = (try it.next()).?;
    try testing.expectEqualStrings("unaligned echo", (try m.errorMessage()).?);
}

test "big-endian accessors read network order and reject wrong widths" {
    const a16: Attr = .{ .type = 1, .raw_type = 1, .data = &.{ 0x00, 0x16 } };
    try testing.expectEqual(@as(u16, 22), try a16.asBe16());
    try testing.expectError(error.BadLength, a16.asBe32());
    try testing.expectError(error.BadLength, a16.asBe64());

    const a32: Attr = .{ .type = 1, .raw_type = 1, .data = &.{ 0x00, 0x00, 0x00, 0x0a } };
    try testing.expectEqual(@as(u32, 10), try a32.asBe32());
    try testing.expectError(error.BadLength, a32.asBe16());

    const a64: Attr = .{ .type = 1, .raw_type = 1, .data = &(([_]u8{0} ** 7) ++ [_]u8{0x2a}) };
    try testing.expectEqual(@as(u64, 42), try a64.asBe64());
    try testing.expectError(error.BadLength, a64.asBe16());

    // The host-order twin of the same bytes must disagree on little-endian —
    // proof the two families really do need separate accessors.
    if (native_endian == .little)
        try testing.expectEqual(@as(u32, 0x0a000000), try a32.asU32());
}

test "golden: big-endian writers emit network order" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);

    try appendAttrBe16(testing.allocator, &list, 3, 22);
    try testing.expectEqualSlices(u8, &.{ 0x06, 0x00, 0x03, 0x00, 0x00, 0x16, 0x00, 0x00 }, list.items);

    list.clearRetainingCapacity();
    try appendAttrBe32(testing.allocator, &list, 3, 10);
    try testing.expectEqualSlices(u8, &.{ 0x08, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x0a }, list.items);

    list.clearRetainingCapacity();
    try appendAttrBe64(testing.allocator, &list, 1, 10);
    try testing.expectEqualSlices(
        u8,
        &.{ 0x0c, 0x00, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0x0a },
        list.items,
    );

    // Round-trip through the matching readers.
    list.clearRetainingCapacity();
    try appendAttrBe16(testing.allocator, &list, 1, 0xbeef);
    try appendAttrBe32(testing.allocator, &list, 2, 0xdeadbeef);
    try appendAttrBe64(testing.allocator, &list, 3, 0x0123456789abcdef);
    var it: AttrIterator = .{ .buf = list.items };
    try testing.expectEqual(@as(u16, 0xbeef), try (try it.next()).?.asBe16());
    try testing.expectEqual(@as(u32, 0xdeadbeef), try (try it.next()).?.asBe32());
    try testing.expectEqual(@as(u64, 0x0123456789abcdef), try (try it.next()).?.asBe64());
}

test "errorRequestSeq recovers the offending request's sequence number" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    const h = try appendHeader(gpa, &list, NLMSG_ERROR, 0, 7, 42);
    var code: [4]u8 = undefined;
    std.mem.writeInt(i32, &code, -22, native_endian);
    try appendPadded(gpa, &list, &code);
    // The echoed request header: seq 7 sits at offset 8 of the nlmsghdr.
    var echoed: [header_len]u8 = @splat(0);
    std.mem.writeInt(u32, echoed[0..4], header_len, native_endian);
    std.mem.writeInt(u32, echoed[8..12], 7, native_endian);
    try appendPadded(gpa, &list, &echoed);
    finishHeader(&list, h);

    var it: MessageIterator = .{ .buf = list.items };
    const m = (try it.next()).?;
    try testing.expectEqual(@as(i32, -22), try m.errorCode());
    try testing.expectEqual(@as(?u32, 7), try m.errorRequestSeq());

    // Too short to carry an echoed header: null, never an over-read.
    const cut: Message = .{ .type = NLMSG_ERROR, .flags = 0, .seq = 0, .pid = 0, .payload = &.{ 0, 0, 0, 0 } };
    try testing.expectEqual(@as(?u32, null), try cut.errorRequestSeq());
}

test "classifyDumpMessage triages a multi-part reply" {
    const me: u32 = 42;
    const seq: u32 = 7;
    const mk = struct {
        fn f(t: u16, flags: u16, pid: u32, s: u32, payload: []const u8) Message {
            return .{ .type = t, .flags = flags, .seq = s, .pid = pid, .payload = payload };
        }
    }.f;

    // Foreign portid / stale sequence are dropped before anything else — even
    // when they look like a control message.
    try testing.expectEqual(DumpStep.skip, classifyDumpMessage(mk(NLMSG_DONE, 0, 99, seq, &.{}), me, seq));
    try testing.expectEqual(DumpStep.skip, classifyDumpMessage(mk(NLMSG_DONE, 0, me, seq + 1, &.{}), me, seq));
    // NLM_F_DUMP_INTR outranks the message type.
    try testing.expectEqual(
        DumpStep.restart,
        classifyDumpMessage(mk(NLMSG_DONE, NLM_F_DUMP_INTR, me, seq, &.{}), me, seq),
    );
    try testing.expectEqual(DumpStep.done, classifyDumpMessage(mk(NLMSG_DONE, 0, me, seq, &.{}), me, seq));
    try testing.expectEqual(DumpStep.skip, classifyDumpMessage(mk(NLMSG_NOOP, 0, me, seq, &.{}), me, seq));
    try testing.expectEqual(DumpStep.overrun, classifyDumpMessage(mk(NLMSG_OVERRUN, 0, me, seq, &.{}), me, seq));

    // NLMSG_ERROR: code 0 is a bare ACK (an empty dump), non-zero is a failure.
    var zero: [4]u8 = @splat(0);
    try testing.expectEqual(DumpStep.done, classifyDumpMessage(mk(NLMSG_ERROR, 0, me, seq, &zero), me, seq));
    var einval: [4]u8 = undefined;
    std.mem.writeInt(i32, &einval, -22, native_endian);
    try testing.expectEqual(
        DumpStep{ .failed = -22 },
        classifyDumpMessage(mk(NLMSG_ERROR, 0, me, seq, &einval), me, seq),
    );
    // A truncated errno is a wire-format failure, not an errno of 0.
    try testing.expectEqual(
        DumpStep.malformed,
        classifyDumpMessage(mk(NLMSG_ERROR, 0, me, seq, &.{ 0, 0 }), me, seq),
    );

    // Anything else is a record for the caller's parser, type included.
    const rec = classifyDumpMessage(mk(16, NLM_F_MULTI, me, seq, &.{0xaa}), me, seq);
    try testing.expectEqual(@as(u16, 16), rec.record.type);
    try testing.expectEqualSlices(u8, &.{0xaa}, rec.record.payload);
}

test "fuzz: message + attribute walkers never crash, loop, or read OOB" {
    try testing.fuzz({}, fuzzWalkers, .{});
}

fn fuzzWalkers(_: void, smith: *std.testing.Smith) !void {
    var raw: [512]u8 = undefined;
    smith.bytes(&raw);
    const len = smith.valueRangeAtMost(u16, 0, raw.len);
    const buf = raw[0..len];

    // Message walk: each step consumes >= 4 bytes, so bound the step count.
    var steps: usize = 0;
    var mit: MessageIterator = .{ .buf = buf };
    while (mit.next() catch null) |m| {
        steps += 1;
        try testing.expect(steps <= buf.len / 4 + 1);
        _ = m.errorCode() catch {};
        _ = m.errorMessage() catch {};
        if (m.errorAttrs() catch null) |maybe| {
            var eit = maybe;
            var esteps: usize = 0;
            while (eit.next() catch null) |_| {
                esteps += 1;
                try testing.expect(esteps <= m.payload.len / 4 + 1);
            }
        }
        // Walk the payload as attributes with a fuzzed fixed-header skip.
        const skip = smith.valueRangeAtMost(u16, 0, 32);
        var ait = m.attrs(skip) catch continue;
        var asteps: usize = 0;
        while (ait.next() catch null) |a| {
            asteps += 1;
            try testing.expect(asteps <= m.payload.len / 4 + 1);
            _ = a.asU8() catch {};
            _ = a.asU16() catch {};
            _ = a.asU32() catch {};
            _ = a.asString();
            var nit = a.nested();
            while (nit.next() catch null) |_| {}
        }
    }

    // Raw attribute walk over the same bytes.
    var ait: AttrIterator = .{ .buf = buf };
    var asteps: usize = 0;
    while (ait.next() catch null) |a| {
        asteps += 1;
        try testing.expect(asteps <= buf.len / 4 + 1);
        var nit = a.nested();
        while (nit.next() catch null) |_| {}
    }
}
