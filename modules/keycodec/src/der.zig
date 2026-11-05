// SPDX-License-Identifier: MIT

//! A strict DER reader and a forward DER writer, just what key structures
//! need: definite lengths, minimal length octets, at most three length octets
//! (16 MiB, far above any key). Every branch is on a tag or a length, i.e. on
//! the structure's (public) layout, never on content bytes.

const std = @import("std");

pub const Error = error{MalformedKey};

pub const Reader = struct {
    b: []const u8,
    pos: usize = 0,

    pub fn init(b: []const u8) Reader {
        return .{ .b = b };
    }

    pub fn peekTag(r: *const Reader) ?u8 {
        return if (r.pos < r.b.len) r.b[r.pos] else null;
    }

    pub fn atEnd(r: *const Reader) bool {
        return r.pos == r.b.len;
    }

    /// The next element's content, which must carry `tag`.
    pub fn expect(r: *Reader, tag: u8) Error![]const u8 {
        if (r.b.len - r.pos < 2 or r.b[r.pos] != tag) return error.MalformedKey;
        var len: usize = r.b[r.pos + 1];
        var at = r.pos + 2;
        if (len >= 0x80) {
            const n = len & 0x7f;
            if (n == 0 or n > 3 or n > r.b.len - at) return error.MalformedKey;
            len = 0;
            for (r.b[at..][0..n]) |o| len = len << 8 | o;
            // Minimal: the long form only from 0x80, and no leading zero octet.
            if (len < 0x80 or r.b[at] == 0) return error.MalformedKey;
            at += n;
        }
        if (len > r.b.len - at) return error.MalformedKey;
        r.pos = at + len;
        return r.b[at..][0..len];
    }

    /// A constructed element (SEQUENCE, explicit tag) as a reader of its own.
    pub fn sub(r: *Reader, tag: u8) Error!Reader {
        return .{ .b = try r.expect(tag) };
    }

    pub fn end(r: *const Reader) Error!void {
        if (!r.atEnd()) return error.MalformedKey;
    }

    /// A small non-negative INTEGER (version fields): minimal encoding,
    /// one content octet.
    pub fn smallInt(r: *Reader) Error!u7 {
        const c = try r.expect(0x02);
        if (c.len != 1 or c[0] >= 0x80) return error.MalformedKey;
        return @intCast(c[0]);
    }
};

/// Bytes a TLV with `content_len` content octets takes.
pub fn tlvLen(content_len: usize) usize {
    return 1 + lenOctets(content_len) + content_len;
}

fn lenOctets(n: usize) usize {
    if (n < 0x80) return 1;
    if (n <= 0xff) return 2;
    if (n <= 0xffff) return 3;
    return 4;
}

/// Writes DER forward into a caller buffer. A TLV whose content has parts is
/// written header first, with the content length computed up front by the
/// caller from `tlvLen`. Running out of room is `NoSpaceLeft`, sticky: the
/// first failing write records it and later writes do nothing, so a builder
/// can write a whole structure and check once with `finish`.
pub const Writer = struct {
    out: []u8,
    n: usize = 0,
    overflow: bool = false,

    pub fn init(out: []u8) Writer {
        return .{ .out = out };
    }

    pub fn bytes(w: *Writer, b: []const u8) void {
        if (w.overflow or b.len > w.out.len - w.n) {
            w.overflow = true;
            return;
        }
        @memcpy(w.out[w.n..][0..b.len], b);
        w.n += b.len;
    }

    pub fn byte(w: *Writer, b: u8) void {
        w.bytes(&.{b});
    }

    pub fn header(w: *Writer, tag: u8, content_len: usize) void {
        if (content_len > 0xffffff) { // the reader's bound; no key comes near it
            w.overflow = true;
            return;
        }
        w.byte(tag);
        switch (lenOctets(content_len)) {
            1 => w.byte(@intCast(content_len)),
            2 => w.bytes(&.{ 0x81, @intCast(content_len) }),
            3 => w.bytes(&.{ 0x82, @intCast(content_len >> 8), @truncate(content_len) }),
            else => w.bytes(&.{ 0x83, @intCast(content_len >> 16), @truncate(content_len >> 8), @truncate(content_len) }),
        }
    }

    /// A primitive TLV.
    pub fn tlv(w: *Writer, tag: u8, content: []const u8) void {
        w.header(tag, content.len);
        w.bytes(content);
    }

    /// The DER written, or `NoSpaceLeft` -- and then the part already
    /// written is zeroed: a key writer must not leave half a secret in a
    /// buffer the caller believes unused.
    pub fn finish(w: *const Writer) error{NoSpaceLeft}![]u8 {
        if (w.overflow) {
            std.crypto.secureZero(u8, w.out[0..w.n]);
            return error.NoSpaceLeft;
        }
        return w.out[0..w.n];
    }
};

const t = std.testing;

test "reader: minimal lengths only, bounded, tags checked" {
    var r = Reader.init(&.{ 0x04, 0x02, 0xaa, 0xbb });
    try t.expectEqualSlices(u8, &.{ 0xaa, 0xbb }, try r.expect(0x04));
    try r.end();

    // Long form for a length under 0x80 is not DER.
    r = Reader.init(&.{ 0x04, 0x81, 0x01, 0xaa });
    try t.expectError(error.MalformedKey, r.expect(0x04));
    // Leading zero length octet.
    var padded: [4 + 0x80]u8 = @splat(0);
    padded[0..4].* = .{ 0x04, 0x82, 0x00, 0x80 };
    r = Reader.init(&padded);
    try t.expectError(error.MalformedKey, r.expect(0x04));
    // Indefinite length.
    r = Reader.init(&.{ 0x30, 0x80, 0x00, 0x00 });
    try t.expectError(error.MalformedKey, r.expect(0x30));
    // Four length octets.
    r = Reader.init(&.{ 0x04, 0x84, 0x01, 0x00, 0x00, 0x00 });
    try t.expectError(error.MalformedKey, r.expect(0x04));
    // Length past the end, and the wrong tag.
    r = Reader.init(&.{ 0x04, 0x03, 0xaa });
    try t.expectError(error.MalformedKey, r.expect(0x04));
    r = Reader.init(&.{ 0x02, 0x01, 0x00 });
    try t.expectError(error.MalformedKey, r.expect(0x04));
    // One byte left: no header.
    r = Reader.init(&.{0x04});
    try t.expectError(error.MalformedKey, r.expect(0x04));
    // The long form at its boundaries.
    var long: [3 + 0x80]u8 = undefined;
    long[0..3].* = .{ 0x04, 0x81, 0x80 };
    r = Reader.init(&long);
    try t.expectEqual(@as(usize, 0x80), (try r.expect(0x04)).len);
}

test "reader: smallInt refuses negative and non-minimal" {
    var r = Reader.init(&.{ 0x02, 0x01, 0x01 });
    try t.expectEqual(@as(u7, 1), try r.smallInt());
    r = Reader.init(&.{ 0x02, 0x01, 0x80 });
    try t.expectError(error.MalformedKey, r.smallInt());
    r = Reader.init(&.{ 0x02, 0x02, 0x00, 0x01 });
    try t.expectError(error.MalformedKey, r.smallInt());
    r = Reader.init(&.{ 0x02, 0x00 });
    try t.expectError(error.MalformedKey, r.smallInt());
}

test "writer: length forms agree with the reader, overflow is sticky" {
    var buf: [0x10010]u8 = undefined;
    for ([_]usize{ 0, 0x7f, 0x80, 0xff, 0x100, 0xffff, 0x10000 }) |n| {
        var w = Writer.init(&buf);
        const content: [0x10000]u8 = @splat(0x5a);
        w.tlv(0x04, content[0..n]);
        const der = try w.finish();
        try t.expectEqual(tlvLen(n), der.len);
        var r = Reader.init(der);
        try t.expectEqual(n, (try r.expect(0x04)).len);
        try r.end();
    }
    var small: [3]u8 = undefined;
    var w = Writer.init(&small);
    w.tlv(0x04, &.{ 1, 2 });
    w.byte(0); // would fit alone, but the overflow already happened
    try t.expectError(error.NoSpaceLeft, w.finish());
    try t.expectEqualSlices(u8, &.{ 0, 0 }, small[0..2]); // the written header is wiped
}
