// SPDX-License-Identifier: MIT

//! Wire-format helpers shared by the mechanical (non-crypto) parts of this
//! module: canonical name encoding (RFC 4034 §6.2) and uncompressed
//! domain-name decoding for names embedded inside RDATA (RRSIG's Signer's
//! Name, NSEC's Next Domain Name — RFC 4034 §6.2 requires both to be
//! uncompressed on the wire, so a strict uncompressed-only decoder is
//! spec-correct, not merely a simplification).
//!
//! No cryptography here — just careful, bounds-checked byte shuffling, in the
//! same spirit as `dns.message`'s codec.

const std = @import("std");

pub const max_name_text_len = 253;
pub const max_label_len = 63;

pub const NameError = error{
    Truncated,
    BadLabel,
    NameTooLong,
    /// A compression pointer (top two bits `11`) appeared where RFC 4034
    /// §6.2 forbids one (RRSIG signer name / NSEC next name must be
    /// uncompressed).
    CompressionNotAllowed,
};

pub const DecodedName = struct {
    text_len: usize,
    next_pos: usize,
};

/// Decode an uncompressed domain name (length-prefixed labels, zero
/// terminator) starting at `bytes[start]` into `out` as dotted text. Rejects
/// compression pointers outright (RFC 4034 §6.2 forbids them here) rather
/// than silently supporting a form the spec says a signer must never emit.
pub fn decodeUncompressedName(bytes: []const u8, start: usize, out: *[max_name_text_len]u8) NameError!DecodedName {
    var pos = start;
    var out_len: usize = 0;
    while (true) {
        if (pos >= bytes.len) return error.Truncated;
        const b = bytes[pos];
        switch (b & 0xc0) {
            0x00 => {
                if (b == 0) {
                    pos += 1;
                    break;
                }
                const len: usize = b;
                if (bytes.len - pos - 1 < len) return error.Truncated;
                const label = bytes[pos + 1 ..][0..len];
                const sep: usize = @intFromBool(out_len != 0);
                if (out_len + sep + label.len > max_name_text_len) return error.NameTooLong;
                if (sep != 0) {
                    out[out_len] = '.';
                    out_len += 1;
                }
                @memcpy(out[out_len..][0..label.len], label);
                out_len += label.len;
                pos += 1 + len;
            },
            0xc0 => return error.CompressionNotAllowed,
            else => return error.BadLabel,
        }
    }
    return .{ .text_len = out_len, .next_pos = pos };
}

/// Longest wire encoding of a canonical name: 253-char text -> at most 255
/// wire bytes (label lengths replace dots 1:1, plus the leading length byte
/// and the trailing root zero).
pub const max_canonical_wire_len = 255;

/// Encode `name` (dotted text, optional single trailing dot, "" or "." =
/// root) into wire format with every label ASCII-lowercased (RFC 4034 §6.2
/// canonical name form: US-ASCII letters downcased, everything else — digits,
/// hyphens, non-ASCII bytes in u-label form — passed through unchanged).
/// Returns the written slice of `out` (`out.len >= max_canonical_wire_len`
/// always fits).
pub fn encodeCanonicalName(name: []const u8, out: []u8) NameError![]u8 {
    var n = name;
    if (std.mem.endsWith(u8, n, ".")) n = n[0 .. n.len - 1];
    if (n.len > max_name_text_len) return error.NameTooLong;
    var w: std.Io.Writer = .fixed(out);
    if (n.len != 0) {
        var it = std.mem.splitScalar(u8, n, '.');
        while (it.next()) |label| {
            if (label.len == 0 or label.len > max_label_len) return error.BadLabel;
            w.writeByte(@intCast(label.len)) catch return error.NameTooLong;
            for (label) |c| w.writeByte(std.ascii.toLower(c)) catch return error.NameTooLong;
        }
    }
    w.writeByte(0) catch return error.NameTooLong;
    return w.buffered();
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "decodeUncompressedName: simple name" {
    const wire = "\x03www\x07example\x03com\x00";
    var buf: [max_name_text_len]u8 = undefined;
    const res = try decodeUncompressedName(wire, 0, &buf);
    try testing.expectEqualStrings("www.example.com", buf[0..res.text_len]);
    try testing.expectEqual(@as(usize, wire.len), res.next_pos);
}

test "decodeUncompressedName: root name" {
    const wire = "\x00";
    var buf: [max_name_text_len]u8 = undefined;
    const res = try decodeUncompressedName(wire, 0, &buf);
    try testing.expectEqual(@as(usize, 0), res.text_len);
    try testing.expectEqual(@as(usize, 1), res.next_pos);
}

test "decodeUncompressedName: compression pointer rejected" {
    const wire = "\xc0\x0c";
    var buf: [max_name_text_len]u8 = undefined;
    try testing.expectError(error.CompressionNotAllowed, decodeUncompressedName(wire, 0, &buf));
}

test "decodeUncompressedName: truncated label errors, never panics" {
    const wire = "\x05www";
    var buf: [max_name_text_len]u8 = undefined;
    try testing.expectError(error.Truncated, decodeUncompressedName(wire, 0, &buf));
}

test "encodeCanonicalName: lowercases and preserves structure" {
    var buf: [max_canonical_wire_len]u8 = undefined;
    const wire = try encodeCanonicalName("WWW.Example.COM", &buf);
    try testing.expectEqualSlices(u8, "\x03www\x07example\x03com\x00", wire);
}

test "encodeCanonicalName: root" {
    var buf: [max_canonical_wire_len]u8 = undefined;
    try testing.expectEqualSlices(u8, "\x00", try encodeCanonicalName("", &buf));
    try testing.expectEqualSlices(u8, "\x00", try encodeCanonicalName(".", &buf));
}

test "encodeCanonicalName: round-trips through decodeUncompressedName (lowercased)" {
    var buf: [max_canonical_wire_len]u8 = undefined;
    const wire = try encodeCanonicalName("Foo.BAR.example.", &buf);
    var text_buf: [max_name_text_len]u8 = undefined;
    const res = try decodeUncompressedName(wire, 0, &text_buf);
    try testing.expectEqualStrings("foo.bar.example", text_buf[0..res.text_len]);
}

test "encodeCanonicalName: label too long errors" {
    var buf: [max_canonical_wire_len]u8 = undefined;
    const long_label = "a" ** 64;
    try testing.expectError(error.BadLabel, encodeCanonicalName(long_label, &buf));
}

// ── fuzz: uncompressed name decode off hostile RDATA, never panics ─────────
//
// Called directly on an RRSIG signer name / NSEC next name straight out of
// an unauthenticated DNS response, at an attacker-influenced starting
// offset (both `rdata.parseRrsig` and `rdata.parseNsec` call this at a
// caller-chosen `start`, not necessarily 0).

test "fuzz: decodeUncompressedName never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzDecodeUncompressedName, .{});
}

fn fuzzDecodeUncompressedName(_: void, smith: *std.testing.Smith) !void {
    var buf: [300]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const start: usize = smith.valueRangeAtMost(u16, 0, buf.len);

    var out: [max_name_text_len]u8 = undefined;
    _ = decodeUncompressedName(buf[0..len], start, &out) catch return;
}
