// SPDX-License-Identifier: MIT

//! Minimal netlink message/attribute codec — the wire primitives the native
//! nfnetlink backend needs, plus the **big-endian** TLV accessors nftables
//! (unlike rtnetlink) requires.
//!
//! **DRY candidate — the whole host-endian half of this file is a copy of
//! `modules/netlink/src/codec.zig`.** `alignUp`, `Message`, `MessageIterator`,
//! `Attr`, `AttrIterator`, `appendHeader`/`finishHeader`, `appendAttr`,
//! `appendAttrString`, `nestBegin`/`nestEnd` and the `NLM_F_*`/`NLMSG_*`/
//! `NLA_F_*`/`NLMSGERR_ATTR_*` constants are that module's, re-typed here only
//! because `modules/nftables` declares no dependencies in the root `build.zig`
//! and this wave may not edit it. **The follow-up is one line** — add
//! `.deps = &.{"netlink"}` to the `nftables` entry of `module_list`, then
//! delete everything above the "big-endian accessors" banner and make this
//! file `pub const codec = @import("netlink").codec;`.
//!
//! The *second* half — `asBe16/32/64` and `appendAttrBe16/32/64` — is the same
//! gap `modules/conntrack/src/wire.zig` documents: every netfilter family
//! (ctnetlink, nftables, nfqueue, nflog, cttimeout) puts its integers on the
//! wire in **network byte order** without setting `NLA_F_NET_BYTEORDER`, while
//! `netlink.codec.Attr` only offers host-endian `asU16`/`asU32`. Those eight
//! functions want to live next to their host-endian twins in
//! `netlink/src/codec.zig`; two modules have now written them independently.
//!
//! Wire format (kernel UAPI `linux/netlink.h`, host byte order, 4-byte
//! alignment):
//!
//! ```text
//! nlmsghdr:  u32 len | u16 type | u16 flags | u32 seq | u32 pid   (16 bytes)
//! nlattr:    u16 len | u16 type | payload | pad-to-4              (len covers hdr+payload)
//! ```
//!
//! Every length field is validated against the enclosing buffer before any
//! slice is formed: a truncated or hostile buffer yields `error.Truncated` /
//! `error.BadLength`, never a panic or an out-of-bounds read. Iteration always
//! advances by at least 4 bytes, so a walk over N bytes is capped at N/4 steps.

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

/// NLMSG_ALIGNTO.
pub const align_to = 4;
/// NLMSG_HDRLEN — sizeof(struct nlmsghdr).
pub const header_len = 16;
/// sizeof(struct nlattr) — the TLV header.
pub const attr_header_len = 4;

pub const NLMSG_NOOP: u16 = 0x1;
pub const NLMSG_ERROR: u16 = 0x2;
pub const NLMSG_DONE: u16 = 0x3;
pub const NLMSG_OVERRUN: u16 = 0x4;

pub const NLM_F_REQUEST: u16 = 0x01;
pub const NLM_F_MULTI: u16 = 0x02;
pub const NLM_F_ACK: u16 = 0x04;
pub const NLM_F_ECHO: u16 = 0x08;
pub const NLM_F_DUMP_INTR: u16 = 0x10;
pub const NLM_F_ROOT: u16 = 0x100;
pub const NLM_F_MATCH: u16 = 0x200;
pub const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;

/// Write-path request modifiers. These numerically overlap the dump flags —
/// they are only meaningful on NEW/DEL messages.
pub const NLM_F_REPLACE: u16 = 0x100;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLM_F_CREATE: u16 = 0x400;
pub const NLM_F_APPEND: u16 = 0x800;

/// Flags the kernel sets on an `NLMSG_ERROR` reply.
pub const NLM_F_CAPPED: u16 = 0x100;
pub const NLM_F_ACK_TLVS: u16 = 0x200;

/// Extended-ACK attribute types, carried after `struct nlmsgerr`.
pub const NLMSGERR_ATTR = struct {
    pub const UNSPEC: u16 = 0;
    /// NUL-terminated string: the kernel's reason for the rejection.
    pub const MSG: u16 = 1;
    /// u32 byte offset into the request the kernel objected to.
    pub const OFFS: u16 = 2;
    pub const COOKIE: u16 = 3;
    pub const POLICY: u16 = 4;
    pub const MISS_TYPE: u16 = 5;
    pub const MISS_NLATTR: u16 = 6;
};

pub const NLA_F_NESTED: u16 = 0x8000;
pub const NLA_F_NET_BYTEORDER: u16 = 0x4000;
pub const NLA_TYPE_MASK: u16 = 0x3fff;

/// `NETLINK_EXT_ACK` socket option (linux/netlink.h).
pub const NETLINK_EXT_ACK: u32 = 11;

/// NLMSG_ALIGN(n).
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
    /// leading i32. 0 means ACK (success).
    pub fn errorCode(m: Message) Error!i32 {
        if (m.payload.len < 4) return error.Truncated;
        return std.mem.readInt(i32, m.payload[0..4], native_endian);
    }

    /// Iterate this message's attributes, treating `fixed_len` leading bytes
    /// of the payload as the fixed family header (`nfgenmsg`).
    pub fn attrs(m: Message, fixed_len: usize) Error!AttrIterator {
        if (m.payload.len < fixed_len) return error.Truncated;
        return .{ .buf = m.payload[fixed_len..] };
    }

    /// Extended-ACK attributes of an `NLMSG_ERROR` message, or null when the
    /// kernel attached none.
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
    /// (`NLMSGERR_ATTR_MSG`), or null when none was attached.
    pub fn errorMessage(m: Message) Error!?[]const u8 {
        var it = (try m.errorAttrs()) orelse return null;
        while (try it.next()) |a| {
            if (a.type == NLMSGERR_ATTR.MSG) return a.asString();
        }
        return null;
    }

    /// The `nlmsg_seq` of the request the kernel is complaining about, taken
    /// from the echoed header inside `struct nlmsgerr`. **This is what turns a
    /// batch failure into "message #N failed"** — the `NLMSG_ERROR` message's
    /// own seq already carries it, but the echoed copy proves it.
    pub fn errorRequestSeq(m: Message) Error!?u32 {
        if (m.payload.len < 4 + header_len) return null;
        return std.mem.readInt(u32, m.payload[4 + 8 ..][0..4], native_endian);
    }
};

/// Walk a buffer of concatenated netlink messages.
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
        it.offset += @min(alignUp(mlen), rest.len);
        return msg;
    }
};

// ── attribute parsing ───────────────────────────────────────────────────────

/// One parsed nlattr TLV. `data` borrows from the input buffer.
pub const Attr = struct {
    /// Attribute type with the `NLA_F_*` flag bits masked off.
    type: u16,
    /// The raw type field including `NLA_F_NESTED`/`NLA_F_NET_BYTEORDER`.
    raw_type: u16,
    data: []const u8,

    pub fn nested(a: Attr) AttrIterator {
        return .{ .buf = a.data };
    }

    pub fn asU8(a: Attr) Error!u8 {
        if (a.data.len != 1) return error.BadLength;
        return a.data[0];
    }

    /// String payload with trailing NULs stripped.
    pub fn asString(a: Attr) []const u8 {
        return std.mem.trimEnd(u8, a.data, "\x00");
    }

    // ── big-endian accessors ────────────────────────────────────────────────
    // See the DRY note at the top of this file: nftables integers are network
    // byte order on the wire and the kernel does not flag them.

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

/// Bounds-checked TLV walker: at least 4 header bytes remain, `len >= 4`, and
/// `len` fits the remaining buffer — otherwise an error, never an OOB read.
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
        it.offset += @min(alignUp(alen), rest.len);
        return .{
            .type = raw_type & NLA_TYPE_MASK,
            .raw_type = raw_type,
            .data = rest[attr_header_len..alen],
        };
    }
};

// ── message building ────────────────────────────────────────────────────────

pub const BuildError = std.mem.Allocator.Error || error{AttrTooLong};

/// Append a 16-byte nlmsghdr with a zero length placeholder; returns the
/// header's offset for the closing `finishHeader`.
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

/// Patch the nlmsghdr at `hdr_offset` so its length covers everything appended
/// since `appendHeader`.
pub fn finishHeader(list: *std.ArrayList(u8), hdr_offset: usize) void {
    const mlen: u32 = @intCast(list.items.len - hdr_offset);
    std.mem.writeInt(u32, list.items[hdr_offset..][0..4], mlen, native_endian);
}

/// Append raw payload bytes and pad to the 4-byte boundary.
pub fn appendPadded(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    bytes: []const u8,
) std.mem.Allocator.Error!void {
    try list.appendSlice(gpa, bytes);
    try list.appendNTimes(gpa, 0, alignUp(bytes.len) - bytes.len);
}

/// Append one nlattr TLV: u16 len (header + payload), u16 type, payload,
/// zero-padding to the 4-byte boundary. The length field excludes the padding.
pub fn appendAttr(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    data: []const u8,
) BuildError!void {
    const total = attr_header_len + data.len;
    if (total > std.math.maxInt(u16)) return error.AttrTooLong;
    var hdr: [attr_header_len]u8 = undefined;
    std.mem.writeInt(u16, hdr[0..2], @intCast(total), native_endian);
    std.mem.writeInt(u16, hdr[2..4], attr_type, native_endian);
    try list.appendSlice(gpa, &hdr);
    try list.appendSlice(gpa, data);
    try list.appendNTimes(gpa, 0, alignUp(total) - total);
}

/// Append a NUL-terminated string attribute (kernel string convention).
pub fn appendAttrString(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    s: []const u8,
) BuildError!void {
    const total = attr_header_len + s.len + 1;
    if (total > std.math.maxInt(u16)) return error.AttrTooLong;
    var hdr: [attr_header_len]u8 = undefined;
    std.mem.writeInt(u16, hdr[0..2], @intCast(total), native_endian);
    std.mem.writeInt(u16, hdr[2..4], attr_type, native_endian);
    try list.appendSlice(gpa, &hdr);
    try list.appendSlice(gpa, s);
    // One zero run covers the terminating NUL and the alignment pad.
    try list.appendNTimes(gpa, 0, alignUp(total) - total + 1);
}

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

pub fn appendAttrBe16(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    value: u16,
) std.mem.Allocator.Error!void {
    var raw: [2]u8 = undefined;
    std.mem.writeInt(u16, &raw, value, .big);
    appendAttr(gpa, list, attr_type, &raw) catch |err| switch (err) {
        error.AttrTooLong => unreachable,
        error.OutOfMemory => return error.OutOfMemory,
    };
}

pub fn appendAttrBe32(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    value: u32,
) std.mem.Allocator.Error!void {
    var raw: [4]u8 = undefined;
    std.mem.writeInt(u32, &raw, value, .big);
    appendAttr(gpa, list, attr_type, &raw) catch |err| switch (err) {
        error.AttrTooLong => unreachable,
        error.OutOfMemory => return error.OutOfMemory,
    };
}

pub fn appendAttrBe64(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    value: u64,
) std.mem.Allocator.Error!void {
    var raw: [8]u8 = undefined;
    std.mem.writeInt(u64, &raw, value, .big);
    appendAttr(gpa, list, attr_type, &raw) catch |err| switch (err) {
        error.AttrTooLong => unreachable,
        error.OutOfMemory => return error.OutOfMemory,
    };
}

/// Open a nested attribute; returns its offset for the closing `nestEnd`.
/// `attr_type` is written verbatim — nftables nests always carry
/// `NLA_F_NESTED` on the wire (verified against the captures in `goldens.zig`),
/// so callers OR it in.
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
/// everything appended since — including inner padding, like `nla_nest_end`.
pub fn nestEnd(list: *std.ArrayList(u8), off: usize) void {
    const total: u16 = @intCast(list.items.len - off);
    std.mem.writeInt(u16, list.items[off..][0..2], total, native_endian);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "alignUp rounds to the netlink 4-byte boundary" {
    try testing.expectEqual(@as(usize, 0), alignUp(0));
    try testing.expectEqual(@as(usize, 4), alignUp(1));
    try testing.expectEqual(@as(usize, 4), alignUp(4));
    try testing.expectEqual(@as(usize, 8), alignUp(5));
}

test "big-endian accessors reject wrong widths and read network order" {
    const a16: Attr = .{ .type = 1, .raw_type = 1, .data = &.{ 0x00, 0x16 } };
    try testing.expectEqual(@as(u16, 22), try a16.asBe16());
    try testing.expectError(error.BadLength, a16.asBe32());
    const a32: Attr = .{ .type = 1, .raw_type = 1, .data = &.{ 0x00, 0x00, 0x00, 0x0a } };
    try testing.expectEqual(@as(u32, 10), try a32.asBe32());
    const a64: Attr = .{ .type = 1, .raw_type = 1, .data = &(([_]u8{0} ** 7) ++ [_]u8{0x2a}) };
    try testing.expectEqual(@as(u64, 42), try a64.asBe64());
    try testing.expectError(error.BadLength, a64.asBe16());
}

test "big-endian writers emit network order" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    try appendAttrBe32(testing.allocator, &list, 3, 10);
    try testing.expectEqualSlices(
        u8,
        &.{ 0x08, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x0a },
        list.items,
    );
    list.clearRetainingCapacity();
    try appendAttrBe64(testing.allocator, &list, 1, 10);
    try testing.expectEqualSlices(
        u8,
        &.{ 0x0c, 0x00, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0x0a },
        list.items,
    );
}

test "nested attribute round-trip carries NLA_F_NESTED" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    const off = try nestBegin(testing.allocator, &list, NLA_F_NESTED | 4);
    try appendAttrBe32(testing.allocator, &list, 1, 1);
    try appendAttrBe32(testing.allocator, &list, 2, 0);
    nestEnd(&list, off);
    try testing.expectEqual(@as(usize, 20), list.items.len);

    var it: AttrIterator = .{ .buf = list.items };
    const nest = (try it.next()).?;
    try testing.expectEqual(@as(u16, 4), nest.type);
    try testing.expect(nest.raw_type & NLA_F_NESTED != 0);
    var inner = nest.nested();
    try testing.expectEqual(@as(u32, 1), try (try inner.next()).?.asBe32());
    try testing.expectEqual(@as(u32, 0), try (try inner.next()).?.asBe32());
    try testing.expectEqual(@as(?Attr, null), try inner.next());
}

test "walkers reject truncated and bad-length input" {
    var it: AttrIterator = .{ .buf = &.{ 0x08, 0x00, 0x01 } };
    try testing.expectError(error.Truncated, it.next());
    it = .{ .buf = &.{ 0xff, 0x00, 0x01, 0x00, 0xaa, 0xbb } };
    try testing.expectError(error.Truncated, it.next());
    it = .{ .buf = &.{ 0x00, 0x00, 0x01, 0x00 } };
    try testing.expectError(error.BadLength, it.next());

    var mit: MessageIterator = .{ .buf = &[_]u8{0} ** 10 };
    try testing.expectError(error.Truncated, mit.next());
    var small: [16]u8 = @splat(0);
    std.mem.writeInt(u32, small[0..4], 8, native_endian);
    mit = .{ .buf = &small };
    try testing.expectError(error.BadLength, mit.next());
}

test "errorRequestSeq recovers the offending request's sequence number" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    const h = try appendHeader(testing.allocator, &list, NLMSG_ERROR, 0, 7, 42);
    var code: [4]u8 = undefined;
    std.mem.writeInt(i32, &code, -22, native_endian);
    try appendPadded(testing.allocator, &list, &code);
    // The echoed request header: seq 7 sat at offset 8 of the nlmsghdr.
    var echoed: [header_len]u8 = @splat(0);
    std.mem.writeInt(u32, echoed[0..4], header_len, native_endian);
    std.mem.writeInt(u32, echoed[8..12], 7, native_endian);
    try appendPadded(testing.allocator, &list, &echoed);
    finishHeader(&list, h);

    var it: MessageIterator = .{ .buf = list.items };
    const m = (try it.next()).?;
    try testing.expectEqual(@as(i32, -22), try m.errorCode());
    try testing.expectEqual(@as(?u32, 7), try m.errorRequestSeq());
}
