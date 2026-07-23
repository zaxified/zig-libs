// SPDX-License-Identifier: MIT

//! Minimal definite-length BER/DER tag-length-value reader and writer.
//!
//! Both halves of this module speak BER: IEC 62351-6's GOOSE/SV `Extension`
//! is a tagged structure appended to the 61850-8-1 link-layer PDU, and IEC
//! 62351-4's ACSE authentication fields are context-tagged elements inside an
//! AARQ/AARE. Neither needs a general ASN.1 engine — a handful of
//! single-octet tags with definite lengths covers both — so this is
//! deliberately small rather than a second `std.crypto.Certificate.der`.
//!
//! Deliberate restrictions, all of them enforced rather than assumed:
//!
//! - **Definite lengths only.** The indefinite form (`0x80`) is rejected.
//!   Nothing in either profile uses it, and accepting it would mean scanning
//!   forward for an end-of-contents marker inside attacker-supplied bytes.
//! - **Single-octet tags only.** A high-tag-number form (low five bits all
//!   set, `0x1F`) is rejected. Every tag both profiles use is low-number.
//! - **Non-minimal lengths are rejected.** A length that could have been
//!   encoded in fewer octets (`81 05` for 5, or a leading zero) is an error,
//!   so one encoding maps to one length and a re-encode is byte-exact.
//! - **Every content slice is bounds-checked against the buffer** before it
//!   is produced, so a declared length that overruns is a typed error and
//!   never a slice past the end.

const std = @import("std");

pub const Error = error{
    /// The buffer ends inside the tag, the length, or the content.
    Truncated,
    /// Indefinite length, a non-minimal length encoding, or a length that
    /// does not fit in a `usize`.
    InvalidLength,
    /// High-tag-number form (`tag & 0x1f == 0x1f`).
    UnsupportedTag,
    /// `readTagged` found a different tag than the caller required.
    UnexpectedTag,
    /// The output buffer is too small for the element being written.
    BufferTooSmall,
};

/// One decoded TLV. `content` borrows from the input buffer; `encoded_len` is
/// the whole element (identifier + length octets + content), so a caller
/// walking siblings advances by exactly that.
pub const Element = struct {
    tag: u8,
    content: []const u8,
    encoded_len: usize,

    /// True for a constructed element (identifier bit 6 set).
    pub fn isConstructed(e: Element) bool {
        return e.tag & 0x20 != 0;
    }
};

/// Number of octets `writeHeader` spends on the length field for `n`.
pub fn lengthSize(n: usize) usize {
    if (n < 0x80) return 1;
    if (n <= 0xff) return 2;
    if (n <= 0xffff) return 3;
    if (n <= 0xff_ffff) return 4;
    return 5;
}

/// Total encoded size of an element with `content_len` content octets.
pub fn encodedSize(content_len: usize) usize {
    return 1 + lengthSize(content_len) + content_len;
}

/// Decode the element at the start of `bytes`.
pub fn read(bytes: []const u8) Error!Element {
    if (bytes.len < 2) return error.Truncated;
    const tag = bytes[0];
    if (tag & 0x1f == 0x1f) return error.UnsupportedTag;

    const first = bytes[1];
    var content_start: usize = 2;
    var content_len: usize = undefined;
    if (first < 0x80) {
        content_len = first;
    } else {
        const n: usize = first & 0x7f;
        // 0x80 is the indefinite form; 0xff is reserved.
        if (n == 0 or n == 0x7f) return error.InvalidLength;
        if (n > @sizeOf(usize)) return error.InvalidLength;
        if (bytes.len < 2 + n) return error.Truncated;
        const octets = bytes[2..][0..n];
        // Minimal encoding: no leading zero octet, and the value must not
        // have fitted in the short form.
        if (octets[0] == 0) return error.InvalidLength;
        var v: usize = 0;
        for (octets) |b| v = (v << 8) | b;
        if (v < 0x80) return error.InvalidLength;
        content_len = v;
        content_start = 2 + n;
    }

    // Overflow-safe bound: `content_start` is already <= bytes.len here.
    if (content_len > bytes.len - content_start) return error.Truncated;
    return .{
        .tag = tag,
        .content = bytes[content_start..][0..content_len],
        .encoded_len = content_start + content_len,
    };
}

/// `read`, additionally requiring a specific tag.
pub fn readTagged(bytes: []const u8, tag: u8) Error!Element {
    const e = try read(bytes);
    if (e.tag != tag) return error.UnexpectedTag;
    return e;
}

/// Write an identifier + length into `out`, returning the header size. The
/// caller writes `content_len` content octets immediately after it.
pub fn writeHeader(out: []u8, tag: u8, content_len: usize) Error!usize {
    const hdr = 1 + lengthSize(content_len);
    if (out.len < hdr) return error.BufferTooSmall;
    out[0] = tag;
    if (content_len < 0x80) {
        out[1] = @intCast(content_len);
        return 2;
    }
    const n = hdr - 2;
    out[1] = @intCast(0x80 | n);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const shift: u6 = @intCast(8 * (n - 1 - i));
        out[2 + i] = @truncate(content_len >> shift);
    }
    return hdr;
}

/// Write a complete element (header + `content`) into `out`, returning the
/// slice of `out` that was written.
pub fn writeElement(out: []u8, tag: u8, content: []const u8) Error![]u8 {
    const total = encodedSize(content.len);
    if (out.len < total) return error.BufferTooSmall;
    const hdr = try writeHeader(out, tag, content.len);
    @memcpy(out[hdr..][0..content.len], content);
    return out[0..total];
}

/// Walk the direct children of a constructed element's content.
pub const Iterator = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn next(it: *Iterator) Error!?Element {
        if (it.pos >= it.bytes.len) return null;
        const e = try read(it.bytes[it.pos..]);
        it.pos += e.encoded_len;
        return e;
    }
};

pub fn iterate(content: []const u8) Iterator {
    return .{ .bytes = content };
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "read: short form" {
    const e = try read(&.{ 0x04, 0x03, 0xaa, 0xbb, 0xcc, 0xff });
    try testing.expectEqual(@as(u8, 0x04), e.tag);
    try testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb, 0xcc }, e.content);
    try testing.expectEqual(@as(usize, 5), e.encoded_len);
}

test "read: long form" {
    var buf: [4 + 200]u8 = undefined;
    buf[0] = 0x04;
    buf[1] = 0x81;
    buf[2] = 200;
    @memset(buf[3..][0..200], 0x5a);
    const e = try read(buf[0 .. 3 + 200]);
    try testing.expectEqual(@as(usize, 200), e.content.len);
    try testing.expectEqual(@as(usize, 203), e.encoded_len);
}

test "read: rejects indefinite, non-minimal, truncated and high-tag forms" {
    try testing.expectError(error.InvalidLength, read(&.{ 0x30, 0x80, 0x00, 0x00 }));
    // 0x81 0x05 could have been the short form.
    try testing.expectError(error.InvalidLength, read(&.{ 0x04, 0x81, 0x05, 1, 2, 3, 4, 5 }));
    // Leading zero octet in the long form.
    try testing.expectError(error.InvalidLength, read(&.{ 0x04, 0x82, 0x00, 0x81 }));
    try testing.expectError(error.Truncated, read(&.{ 0x04, 0x05, 1, 2 }));
    try testing.expectError(error.UnsupportedTag, read(&.{ 0xbf, 0x01, 0x00 }));
    try testing.expectError(error.Truncated, read(&.{0x04}));
}

test "writeHeader/writeElement round-trip across the length-form boundary" {
    var content: [300]u8 = undefined;
    for (&content, 0..) |*c, i| c.* = @truncate(i);
    var out: [400]u8 = undefined;
    for ([_]usize{ 0, 1, 127, 128, 255, 256, 300 }) |n| {
        const written = try writeElement(&out, 0x85, content[0..n]);
        try testing.expectEqual(encodedSize(n), written.len);
        const e = try read(written);
        try testing.expectEqual(@as(u8, 0x85), e.tag);
        try testing.expectEqualSlices(u8, content[0..n], e.content);
        try testing.expectEqual(written.len, e.encoded_len);
    }
}

test "writeElement: buffer too small" {
    var out: [3]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, writeElement(&out, 0x04, &.{ 1, 2, 3 }));
}

test "iterate: walks siblings" {
    const bytes = [_]u8{ 0x80, 0x01, 0xaa, 0x81, 0x02, 0xbb, 0xcc };
    var it = iterate(&bytes);
    const a = (try it.next()).?;
    try testing.expectEqual(@as(u8, 0x80), a.tag);
    const b = (try it.next()).?;
    try testing.expectEqual(@as(u8, 0x81), b.tag);
    try testing.expect(try it.next() == null);
}

test "fuzz: BER reader never panics and never escapes the buffer" {
    try testing.fuzz({}, fuzzRead, .{});
}

fn fuzzRead(_: void, smith: *std.testing.Smith) !void {
    var buf: [96]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u8, 0, buf.len);
    const bytes = buf[0..len];
    const e = read(bytes) catch return;
    // Any element the reader accepts must sit wholly inside the input.
    try testing.expect(e.encoded_len <= bytes.len);
    try testing.expect(e.content.len <= bytes.len);
    if (e.isConstructed()) {
        var it = iterate(e.content);
        while (it.next() catch return) |child| {
            try testing.expect(child.encoded_len <= e.content.len);
        }
    }
}
