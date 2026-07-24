// SPDX-License-Identifier: MIT

//! The IS-IS TLV framework — the bounds-checked heart of the codec.
//!
//! After its fixed header every IS-IS PDU carries a flat stream of TLVs, each
//! `code(1) length(1) value(length)`. Sub-TLVs (as used by Extended IS
//! Reachability #22 and the SPB MT-Capability #144) are the same shape nested
//! inside a value. This file is the generic machinery both layers reuse:
//!
//! - `TlvIterator` — a zero-copy walker that yields `{ code, value }` where
//!   `value` is a subslice of the input. It bounds-checks every declared length
//!   against the remaining buffer before slicing, so a length that lies about
//!   the buffer size is a typed error, never an over-read. It advances by at
//!   least two bytes per step, so it always terminates.
//! - `Builder` — appends TLVs into a caller-supplied buffer; no allocation, no
//!   hidden growth. A value longer than the 8-bit length field (255) is a typed
//!   error.
//! - `findFirst` / `count` — convenience reads over the same safe walk.
//!
//! ## Untrusted-decode guarantee
//! Both the top-level and sub-TLV walks are the *same* `TlvIterator`; there is
//! exactly one length-check implementation to audit. A `length` byte is at most
//! 255 and is compared as `pos + 2 + length > buf.len` in `usize` arithmetic
//! (operands are small, so the sum cannot wrap), so no lie can push the value
//! slice outside the input. The walker never recurses on its own — nesting is
//! driven one explicit level at a time by the typed decoders, so a crafted PDU
//! cannot induce unbounded recursion.

const std = @import("std");

pub const Error = error{
    /// A TLV code+length header (2 bytes) does not fit in the remaining buffer.
    Truncated,
    /// A TLV's declared length overruns the remaining buffer.
    TruncatedTlv,
};

pub const BuildError = error{
    /// The caller buffer cannot hold another TLV.
    BufferTooSmall,
    /// A value longer than the 8-bit length field permits (255 octets).
    ValueTooLong,
};

/// The largest value an 8-bit TLV length field can express.
pub const max_value_len: usize = 255;

/// One raw TLV: its 8-bit type code and a **subslice of the walked buffer**
/// (never copied, never owned). An unmodeled type round-trips verbatim by
/// re-emitting `code` + `value` — the raw escape hatch.
pub const RawTlv = struct {
    code: u8,
    value: []const u8,
};

/// A zero-copy, bounds-checked walk over a flat TLV stream. Works identically
/// for the top-level PDU TLVs and for sub-TLVs nested inside a value — hand it
/// the value slice and iterate.
pub const TlvIterator = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(bytes: []const u8) TlvIterator {
        return .{ .buf = bytes };
    }

    /// Yields the next `{ code, value }`, or `null` at a clean end of buffer.
    /// A partial header or a length that overruns the buffer is a typed error.
    /// The returned `value` always lies strictly within `buf`.
    pub fn next(it: *TlvIterator) Error!?RawTlv {
        if (it.pos == it.buf.len) return null;
        if (it.pos + 2 > it.buf.len) return error.Truncated;
        const code = it.buf[it.pos];
        const len: usize = it.buf[it.pos + 1];
        const value_start = it.pos + 2;
        // The load-bearing bounds check: never slice past the buffer end.
        if (value_start + len > it.buf.len) return error.TruncatedTlv;
        const value = it.buf[value_start..][0..len];
        it.pos = value_start + len; // advances >= 2, so the walk terminates
        return .{ .code = code, .value = value };
    }

    /// Restarts the walk from the beginning.
    pub fn reset(it: *TlvIterator) void {
        it.pos = 0;
    }
};

/// Returns the value of the first TLV whose code equals `code`, or `null`. A
/// malformed stream surfaces as an error, exactly as a full walk would.
pub fn findFirst(bytes: []const u8, code: u8) Error!?[]const u8 {
    var it = TlvIterator.init(bytes);
    while (try it.next()) |tlv| {
        if (tlv.code == code) return tlv.value;
    }
    return null;
}

/// Counts the TLVs in a stream (validating it end to end).
pub fn count(bytes: []const u8) Error!usize {
    var it = TlvIterator.init(bytes);
    var n: usize = 0;
    while (try it.next()) |_| n += 1;
    return n;
}

/// Appends TLVs into a caller-supplied buffer. Zero allocation; `written`
/// returns the filled prefix. Sub-TLV containers are built with a nested
/// `Builder` over a scratch buffer, then emitted as one TLV value.
pub const Builder = struct {
    buf: []u8,
    pos: usize = 0,

    pub fn init(buf: []u8) Builder {
        return .{ .buf = buf };
    }

    /// Appends one `code/length/value` TLV.
    pub fn addTlv(b: *Builder, code: u8, value: []const u8) BuildError!void {
        if (value.len > max_value_len) return error.ValueTooLong;
        if (b.pos + 2 + value.len > b.buf.len) return error.BufferTooSmall;
        b.buf[b.pos] = code;
        b.buf[b.pos + 1] = @intCast(value.len);
        @memcpy(b.buf[b.pos + 2 ..][0..value.len], value);
        b.pos += 2 + value.len;
    }

    /// The bytes written so far.
    pub fn written(b: *const Builder) []const u8 {
        return b.buf[0..b.pos];
    }

    /// Remaining free space in the buffer.
    pub fn remaining(b: *const Builder) usize {
        return b.buf.len - b.pos;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "walker yields code + value subslices, then null" {
    const bytes = [_]u8{ 0x01, 0x03, 0xaa, 0xbb, 0xcc, 0x81, 0x01, 0xcc };
    var it = TlvIterator.init(&bytes);
    const a = (try it.next()).?;
    try testing.expectEqual(@as(u8, 0x01), a.code);
    try testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb, 0xcc }, a.value);
    // The value is a subslice of the input, not a copy.
    try testing.expectEqual(bytes[2..5].ptr, a.value.ptr);
    const b = (try it.next()).?;
    try testing.expectEqual(@as(u8, 0x81), b.code);
    try testing.expectEqualSlices(u8, &.{0xcc}, b.value);
    try testing.expectEqual(@as(?RawTlv, null), try it.next());
}

test "zero-length and 255-length TLVs both walk safely" {
    var buf: [2 + 255 + 2]u8 = undefined;
    var b = Builder.init(&buf);
    try b.addTlv(0x08, &.{}); // padding, empty value
    const big = [_]u8{0x5a} ** 255;
    try b.addTlv(0x08, &big); // maximum-length value
    var it = TlvIterator.init(b.written());
    const t0 = (try it.next()).?;
    try testing.expectEqual(@as(usize, 0), t0.value.len);
    const t1 = (try it.next()).?;
    try testing.expectEqual(@as(usize, 255), t1.value.len);
    try testing.expectEqual(@as(?RawTlv, null), try it.next());
}

test "truncated header and overrunning length are typed errors" {
    // Single dangling byte: cannot even read a code+length header.
    var it1 = TlvIterator.init(&[_]u8{0x01});
    try testing.expectError(error.Truncated, it1.next());
    // Declared length 10 but only 3 value bytes present.
    var it2 = TlvIterator.init(&[_]u8{ 0x84, 0x0a, 0xaa, 0xbb, 0xcc });
    try testing.expectError(error.TruncatedTlv, it2.next());
}

test "positive control: a length-trusting walk WOULD over-read; the safe walk refuses" {
    // Permanent guard that the length check in `next` is load-bearing. The TLV
    // declares 10 value bytes but only 3 are present.
    const bytes = [_]u8{ 0x84, 0x0a, 0xaa, 0xbb, 0xcc };
    // Prove the lie is real: header(2) + declared(10) genuinely exceeds the
    // buffer, so a decoder that trusted `length` would slice 7 bytes past the
    // end (a panic in safe Zig / an out-of-bounds read without it).
    try testing.expect(2 + @as(usize, bytes[1]) > bytes.len);
    // The safe walker returns the typed error instead. If the bounds check in
    // `next` were removed, this expectError would fail (the slice would panic),
    // so this test goes RED the moment the guard is dropped.
    var it = TlvIterator.init(&bytes);
    try testing.expectError(error.TruncatedTlv, it.next());
}

test "sub-TLVs reuse the same bounds-checked walk" {
    // A value that is itself a TLV stream: code 3 len 2, code 4 len 0.
    const inner = [_]u8{ 0x03, 0x02, 0x11, 0x22, 0x04, 0x00 };
    var outer_buf: [64]u8 = undefined;
    var ob = Builder.init(&outer_buf);
    try ob.addTlv(0x16, &inner); // Extended IS Reachability-shaped container
    var it = TlvIterator.init(ob.written());
    const container = (try it.next()).?;
    // Walk the nested stream with the *same* iterator type.
    var sub = TlvIterator.init(container.value);
    const s0 = (try sub.next()).?;
    try testing.expectEqual(@as(u8, 3), s0.code);
    try testing.expectEqualSlices(u8, &.{ 0x11, 0x22 }, s0.value);
    const s1 = (try sub.next()).?;
    try testing.expectEqual(@as(u8, 4), s1.code);
    try testing.expectEqual(@as(usize, 0), s1.value.len);
    try testing.expectEqual(@as(?RawTlv, null), try sub.next());
}

test "builder rejects oversize value and buffer overflow" {
    var small: [4]u8 = undefined;
    var b = Builder.init(&small);
    try b.addTlv(0x01, &.{0xaa}); // fits: 3 bytes
    try testing.expectError(error.BufferTooSmall, b.addTlv(0x02, &.{ 0xbb, 0xcc })); // needs 4, 1 left
    var big_buf: [512]u8 = undefined;
    var b2 = Builder.init(&big_buf);
    const too_long = [_]u8{0} ** 256;
    try testing.expectError(error.ValueTooLong, b2.addTlv(0x01, &too_long));
}

test "findFirst and count walk safely" {
    const bytes = [_]u8{ 0x01, 0x01, 0xaa, 0x81, 0x01, 0xcc, 0x01, 0x01, 0xbb };
    try testing.expectEqual(@as(usize, 3), try count(&bytes));
    const first_area = (try findFirst(&bytes, 0x01)).?;
    try testing.expectEqualSlices(u8, &.{0xaa}, first_area); // first #1, not the later one
    try testing.expectEqual(@as(?[]const u8, null), try findFirst(&bytes, 0x99));
}

test "repeated same-code TLVs all enumerate" {
    const bytes = [_]u8{ 0x06, 0x00, 0x06, 0x00, 0x06, 0x00 };
    var it = TlvIterator.init(&bytes);
    var seen: usize = 0;
    while (try it.next()) |tlv| {
        try testing.expectEqual(@as(u8, 0x06), tlv.code);
        seen += 1;
    }
    try testing.expectEqual(@as(usize, 3), seen);
}
