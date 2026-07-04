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
