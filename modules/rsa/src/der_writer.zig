// SPDX-License-Identifier: MIT

//! Arena-backed bottom-up DER *encoder* (X.690 §10): every `Builder` method
//! returns one complete TLV (identifier + definite length + content) allocated
//! from `Builder.a`; callers compose them by nesting (`seq(&.{ a, b })`). Use
//! an arena and free everything at once.
//!
//! Shared by `selfSignedCert` here, `acme`'s CSR / TLS-ALPN certificate / key
//! PEM writers and `ocsp`'s request builder and test fixtures — one encoder
//! instead of three hand copies (2026-10-17 cross-module dedupe).
//!
//! An ENCODER only: it never reads untrusted bytes. Content is not validated
//! (a `utcTime` is not checked to be a UTCTime, `oid` takes already-encoded
//! arcs); the caller builds what the ASN.1 module says. `integer` strips the
//! magnitude's leading zero octets with a branch per octet, so it is for
//! public values (serials, versions, moduli); secret INTEGERs go through
//! `marshal.zig`, which writes them by position.

const std = @import("std");

pub const Error = std.mem.Allocator.Error;

pub const Builder = struct {
    a: std.mem.Allocator,

    /// Identifier + definite length in minimal form (short form below 128,
    /// else `0x80 | n` and n big-endian octets). Returns the header length.
    fn encodeHeader(buf: *[2 + @sizeOf(usize)]u8, tag: u8, len: usize) usize {
        buf[0] = tag;
        if (len < 0x80) {
            buf[1] = @intCast(len);
            return 2;
        }
        const n: usize = @sizeOf(usize) - @clz(len) / 8;
        buf[1] = @intCast(0x80 | n);
        var v = len;
        var i = n;
        while (i > 0) : (i -= 1) {
            buf[1 + i] = @truncate(v);
            v >>= 8;
        }
        return 2 + n;
    }

    /// One TLV with an explicit identifier octet and already-built content.
    pub fn tlv(d: Builder, tag: u8, content: []const u8) Error![]const u8 {
        var head: [2 + @sizeOf(usize)]u8 = undefined;
        const head_len = encodeHeader(&head, tag, content.len);
        const out = try d.a.alloc(u8, head_len + content.len);
        @memcpy(out[0..head_len], head[0..head_len]);
        @memcpy(out[head_len..], content);
        return out;
    }

    /// Concatenation of already-built TLVs (no header of its own).
    pub fn cat(d: Builder, parts: []const []const u8) Error![]const u8 {
        return std.mem.concat(d.a, u8, parts);
    }

    /// SEQUENCE / SEQUENCE OF (both tag 0x30).
    pub fn seq(d: Builder, parts: []const []const u8) Error![]const u8 {
        return d.tlv(0x30, try d.cat(parts));
    }

    /// SET / SET OF (tag 0x31). The parts are written in the order given:
    /// DER wants a SET OF sorted by encoding, which is the caller's job (a
    /// one-element RDN, the usual case, is trivially sorted).
    pub fn set(d: Builder, parts: []const []const u8) Error![]const u8 {
        return d.tlv(0x31, try d.cat(parts));
    }

    /// OBJECT IDENTIFIER from its already-encoded content octets.
    pub fn oid(d: Builder, encoded: []const u8) Error![]const u8 {
        return d.tlv(0x06, encoded);
    }

    /// BIT STRING with zero unused bits.
    pub fn bitString(d: Builder, bytes: []const u8) Error![]const u8 {
        return d.tlv(0x03, try d.cat(&.{ "\x00", bytes }));
    }

    pub fn octetString(d: Builder, bytes: []const u8) Error![]const u8 {
        return d.tlv(0x04, bytes);
    }

    pub fn boolean(d: Builder, value: bool) Error![]const u8 {
        return d.tlv(0x01, if (value) "\xff" else "\x00");
    }

    pub fn @"null"(d: Builder) Error![]const u8 {
        return d.tlv(0x05, "");
    }

    /// INTEGER from a non-negative big-endian magnitude: leading zeros are
    /// stripped, and one 0x00 sign octet is (re)inserted when the top bit is
    /// set (DER INTEGER is two's complement). An empty magnitude is 0.
    pub fn integer(d: Builder, magnitude: []const u8) Error![]const u8 {
        return d.tlv(0x02, try d.minimalUnsigned(magnitude));
    }

    pub fn integerU64(d: Builder, value: u64) Error![]const u8 {
        var buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf, value, .big);
        return d.integer(&buf);
    }

    /// INTEGER whose content octets are already canonical (a serialNumber
    /// re-emitted verbatim from a parsed certificate) — written as given.
    pub fn integerRaw(d: Builder, content: []const u8) Error![]const u8 {
        return d.tlv(0x02, content);
    }

    /// ENUMERATED (tag 0x0a; same content rules as INTEGER).
    pub fn enumerated(d: Builder, value: u64) Error![]const u8 {
        var buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf, value, .big);
        return d.tlv(0x0a, try d.minimalUnsigned(&buf));
    }

    /// UTCTime (RFC 5280 §4.1.2.5.1: `YYMMDDHHMMSSZ`); `text` is not checked.
    pub fn utcTime(d: Builder, text: []const u8) Error![]const u8 {
        return d.tlv(0x17, text);
    }

    /// GeneralizedTime (RFC 5280 §4.1.2.5.2: `YYYYMMDDHHMMSSZ`); `text` is not checked.
    pub fn generalizedTime(d: Builder, text: []const u8) Error![]const u8 {
        return d.tlv(0x18, text);
    }

    pub fn utf8String(d: Builder, text: []const u8) Error![]const u8 {
        return d.tlv(0x0c, text);
    }

    /// `[n] EXPLICIT ...` — and `[n] IMPLICIT` of a constructed type, which
    /// is the same identifier octet: context-specific constructed tag
    /// `0xa0 | n` around complete content. Low tag numbers only (0..30).
    pub fn explicit(d: Builder, tag_num: u5, content: []const u8) Error![]const u8 {
        if (tag_num == 31) @panic("rsa: der_writer: tag number 31 is the high-tag-number escape"); // sweep RS-5
        return d.tlv(0xa0 | @as(u8, tag_num), content);
    }

    /// `[n] IMPLICIT` of a primitive type: context-specific primitive tag
    /// `0x80 | n` with raw content (`dNSName [2]`, `good [0] IMPLICIT NULL`).
    pub fn implicitPrimitive(d: Builder, tag_num: u5, content: []const u8) Error![]const u8 {
        if (tag_num == 31) @panic("rsa: der_writer: tag number 31 is the high-tag-number escape"); // sweep RS-5
        return d.tlv(0x80 | @as(u8, tag_num), content);
    }

    fn minimalUnsigned(d: Builder, magnitude: []const u8) Error![]const u8 {
        var i: usize = 0;
        while (i < magnitude.len and magnitude[i] == 0) : (i += 1) {}
        const m = magnitude[i..];
        if (m.len == 0) return "\x00";
        if (m[0] & 0x80 != 0) return d.cat(&.{ "\x00", m });
        return m;
    }
};

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

fn expectTlv(expected: []const u8, got: Error![]const u8) !void {
    try testing.expectEqualSlices(u8, expected, try got);
}

test "der: length octets at every form boundary, checked by std's DER reader" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const d: Builder = .{ .a = arena.allocator() };

    const Case = struct { len: usize, head: []const u8 };
    const cases = [_]Case{
        .{ .len = 0, .head = "\x04\x00" },
        .{ .len = 0x7f, .head = "\x04\x7f" },
        .{ .len = 0x80, .head = "\x04\x81\x80" },
        .{ .len = 0xff, .head = "\x04\x81\xff" },
        .{ .len = 0x100, .head = "\x04\x82\x01\x00" },
        .{ .len = 0xffff, .head = "\x04\x82\xff\xff" },
        .{ .len = 0x10000, .head = "\x04\x83\x01\x00\x00" },
        .{ .len = 0x123456, .head = "\x04\x83\x12\x34\x56" },
        .{ .len = 0x1000000, .head = "\x04\x84\x01\x00\x00\x00" },
    };
    const content = try d.a.alloc(u8, 0x1000000);
    for (content, 0..) |*b, i| b.* = @truncate(i *% 31);
    for (cases) |c| {
        const out = try d.octetString(content[0..c.len]);
        try testing.expectEqualSlices(u8, c.head, out[0..c.head.len]);
        try testing.expectEqualSlices(u8, content[0..c.len], out[c.head.len..]);
        // An independent reader agrees on the framing.
        const el = try std.crypto.Certificate.der.Element.parse(out, 0);
        try testing.expectEqual(@as(u32, @intCast(c.head.len)), el.slice.start);
        try testing.expectEqual(@as(u32, @intCast(out.len)), el.slice.end);
    }
}

test "der: INTEGER and ENUMERATED are minimal two's complement" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const d: Builder = .{ .a = arena.allocator() };

    try expectTlv("\x02\x01\x00", d.integer(""));
    try expectTlv("\x02\x01\x00", d.integer("\x00\x00"));
    try expectTlv("\x02\x01\x7f", d.integer("\x00\x7f"));
    try expectTlv("\x02\x02\x00\x80", d.integer("\x80"));
    try expectTlv("\x02\x02\x00\x80", d.integer("\x00\x00\x80"));
    try expectTlv("\x02\x02\x01\x00", d.integer("\x00\x01\x00"));
    try expectTlv("\x02\x01\x00", d.integerU64(0));
    try expectTlv("\x02\x01\x02", d.integerU64(2));
    try expectTlv("\x02\x02\x00\xff", d.integerU64(0xff));
    try expectTlv("\x02\x09\x00\xff\xff\xff\xff\xff\xff\xff\xff", d.integerU64(std.math.maxInt(u64)));
    try expectTlv("\x02\x02\x00\x05", d.integerRaw("\x00\x05")); // verbatim, not re-normalised
    try expectTlv("\x0a\x01\x00", d.enumerated(0));
    try expectTlv("\x0a\x01\x06", d.enumerated(6));
    try expectTlv("\x0a\x02\x00\x80", d.enumerated(0x80));
}

test "der: tags of the primitive and constructed helpers" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const d: Builder = .{ .a = arena.allocator() };

    try expectTlv("\x30\x05\x05\x00\x01\x01\xff", d.seq(&.{ try d.null(), try d.boolean(true) }));
    try expectTlv("\x31\x03\x01\x01\x00", d.set(&.{try d.boolean(false)}));
    try expectTlv("\x05\x00\x01\x01\x00", d.cat(&.{ try d.null(), try d.boolean(false) }));
    try expectTlv("\x06\x03\x55\x04\x03", d.oid("\x55\x04\x03"));
    try expectTlv("\x03\x03\x00\xab\xcd", d.bitString("\xab\xcd"));
    try expectTlv("\x03\x01\x00", d.bitString(""));
    try expectTlv("\x04\x02\x01\x02", d.octetString("\x01\x02"));
    try expectTlv("\x17\x0d" ++ "260101000000Z", d.utcTime("260101000000Z"));
    try expectTlv("\x18\x0f" ++ "20260101000000Z", d.generalizedTime("20260101000000Z"));
    try expectTlv("\x0c\x02hi", d.utf8String("hi"));
    try expectTlv("\xa0\x03\x02\x01\x02", d.explicit(0, try d.integerU64(2)));
    try expectTlv("\xa3\x00", d.explicit(3, ""));
    try expectTlv("\xbe\x00", d.explicit(30, ""));
    try expectTlv("\x82\x01x", d.implicitPrimitive(2, "x"));
    try expectTlv("\x86\x00", d.implicitPrimitive(6, ""));
    try expectTlv("\x9e\x00", d.implicitPrimitive(30, ""));
    try expectTlv("\xc0\x01\x00", d.tlv(0xc0, "\x00"));
}

test "der: allocation failure surfaces as OutOfMemory at every step" {
    var fa: testing.FailingAllocator = .init(testing.allocator, .{ .fail_index = 0 });
    var arena: std.heap.ArenaAllocator = .init(fa.allocator());
    defer arena.deinit();
    const d: Builder = .{ .a = arena.allocator() };
    try testing.expectError(error.OutOfMemory, d.seq(&.{ "\x05\x00", "\x05\x00" }));
}
