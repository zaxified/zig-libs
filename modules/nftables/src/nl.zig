// SPDX-License-Identifier: MIT

//! The netlink wire codec this module's native nfnetlink backend runs on —
//! a **thin alias layer over `netlink.codec`**, kept as its own file (and
//! re-exported as `nftables.nl`) so the backend has one stable name for the
//! primitives and so this module's own expectations of that shared codec are
//! regression-tested here.
//!
//! There is no codec code left in this file. Everything below is
//! `modules/netlink`'s: the framing constants, the bounds-checked
//! `Message`/`Attr` walkers, the builders, and — since the DRY payoff wave —
//! the **big-endian** accessors (`Attr.asBe16/32/64`,
//! `appendAttrBe16/32/64`) that nftables, like every other netfilter family,
//! needs because its integer attributes are network byte order while
//! rtnetlink's are host order. This file used to re-type all of that, purely
//! because the `nftables` entry in the root `build.zig` declared no
//! dependencies and so could not import `netlink`; it now declares
//! `.deps = &.{"netlink"}`.
//!
//! Wire format (kernel UAPI `linux/netlink.h`, host byte order, 4-byte
//! alignment) and the validation discipline (`error.Truncated` /
//! `error.BadLength` instead of an out-of-bounds read, iteration bounded at
//! N/4 steps) are documented on `netlink/src/codec.zig`.

const std = @import("std");
const netlink = @import("netlink");
const codec = netlink.codec;
const native_endian = @import("builtin").cpu.arch.endian();

// ── framing constants ───────────────────────────────────────────────────────

pub const Error = codec.Error;

pub const align_to = codec.align_to;
pub const header_len = codec.header_len;
pub const attr_header_len = codec.attr_header_len;

pub const NLMSG_NOOP = codec.NLMSG_NOOP;
pub const NLMSG_ERROR = codec.NLMSG_ERROR;
pub const NLMSG_DONE = codec.NLMSG_DONE;
pub const NLMSG_OVERRUN = codec.NLMSG_OVERRUN;

pub const NLM_F_REQUEST = codec.NLM_F_REQUEST;
pub const NLM_F_MULTI = codec.NLM_F_MULTI;
pub const NLM_F_ACK = codec.NLM_F_ACK;
pub const NLM_F_ECHO = codec.NLM_F_ECHO;
pub const NLM_F_DUMP_INTR = codec.NLM_F_DUMP_INTR;
pub const NLM_F_ROOT = codec.NLM_F_ROOT;
pub const NLM_F_MATCH = codec.NLM_F_MATCH;
pub const NLM_F_DUMP = codec.NLM_F_DUMP;

pub const NLM_F_REPLACE = codec.NLM_F_REPLACE;
pub const NLM_F_EXCL = codec.NLM_F_EXCL;
pub const NLM_F_CREATE = codec.NLM_F_CREATE;
pub const NLM_F_APPEND = codec.NLM_F_APPEND;

pub const NLM_F_CAPPED = codec.NLM_F_CAPPED;
pub const NLM_F_ACK_TLVS = codec.NLM_F_ACK_TLVS;
pub const NLMSGERR_ATTR = codec.NLMSGERR_ATTR;

pub const NLA_F_NESTED = codec.NLA_F_NESTED;
pub const NLA_F_NET_BYTEORDER = codec.NLA_F_NET_BYTEORDER;
pub const NLA_TYPE_MASK = codec.NLA_TYPE_MASK;

/// `NETLINK_EXT_ACK` socket option (linux/netlink.h) — a socket-level
/// constant, so it lives in `netlink`'s root rather than its codec.
pub const NETLINK_EXT_ACK = netlink.NETLINK_EXT_ACK;

pub const alignUp = codec.alignUp;

// ── parsing ─────────────────────────────────────────────────────────────────

pub const Message = codec.Message;
pub const MessageIterator = codec.MessageIterator;
pub const Attr = codec.Attr;
pub const AttrIterator = codec.AttrIterator;

/// The shared multi-part dump triage — see `netlink.classifyDumpMessage`.
pub const DumpStep = codec.DumpStep;
pub const classifyDumpMessage = codec.classifyDumpMessage;

// ── building ────────────────────────────────────────────────────────────────

pub const BuildError = std.mem.Allocator.Error || error{AttrTooLong};

pub const appendHeader = codec.appendHeader;
pub const finishHeader = codec.finishHeader;
pub const appendPadded = codec.appendPadded;
pub const appendAttr = codec.appendAttr;
pub const appendAttrString = codec.appendAttrString;
pub const appendAttrU8 = codec.appendAttrU8;
pub const appendAttrBe16 = codec.appendAttrBe16;
pub const appendAttrBe32 = codec.appendAttrBe32;
pub const appendAttrBe64 = codec.appendAttrBe64;

/// Open a nested attribute; returns its offset for the closing `nestEnd`.
/// `attr_type` is written verbatim — nftables nests always carry
/// `NLA_F_NESTED` on the wire (verified against the captures in `goldens.zig`),
/// so callers OR it in.
pub const nestBegin = codec.nestBegin;
pub const nestEnd = codec.nestEnd;

// ── tests ───────────────────────────────────────────────────────────────────
//
// These are not codec tests (those live in `netlink`); they are this module's
// standing assertions about the shared codec — the exact properties the
// nfnetlink backend depends on and would be silently broken by.

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
