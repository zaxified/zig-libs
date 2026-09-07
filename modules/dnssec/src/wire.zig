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

/// Test-only. `testkit.fuzz.seed` is the corpus format `Smith.slice` actually
/// reads: it prefixes a little-endian `u32` length, so a raw wire name handed
/// to a harness arrives minus its own first four octets — which for a name
/// means minus its first label. `testkit/src/fuzz.zig` carries the other two
/// hazards.
const seed = @import("testkit").fuzz.seed;

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

// ⚠ This harness used to open with `smith.bytes(&buf)` followed by
// `smith.valueRangeAtMost(u16, 0, buf.len)`. `bytes` copies `min(buf.len,
// in.len)` octets and the ranged draw then reads EIGHT more as a little-endian
// u64, returning the range minimum when fewer remain -- so `len` was 0 for
// every input a corpus can carry and the decoder was handed an EMPTY slice with
// the name sitting unread in `buf`.
//
// ⛔ `start` was a second ranged draw and it collapsed with the first, to 0.
// That matters more here than the length does: the doc comment above this
// harness says the point is "an attacker-influenced starting offset (both
// `rdata.parseRrsig` and `rdata.parseNsec` call this at a caller-chosen
// `start`, not necessarily 0)" -- and start was 0 on every iteration this
// harness ever ran. The comment was describing something that had never
// happened.
//
// A knob drawn after the byte draw reads an exhausted input, so the offset
// cannot come back as a draw. It is swept instead: every offset from 0 to
// `len` inclusive, which is both cheaper to reason about than a random one and
// strictly more thorough -- `decodeUncompressedName` is linear in the name, so
// the whole sweep is quadratic in a 300-octet buffer and still trivial.

/// Uncompressed wire names, in the format the length draw reads.
const name_seeds = [_][]const u8{
    seed("\x03foo\x03bar\x07example\x00"), // the ordinary three-label name
    seed("\x07example\x00"), // one label
    seed("\x00"), // the root name: an empty text result, and a legal one
    seed("\x03foo\x00\x03bar\x00"), // two names back to back: the sweep decodes both
    seed("\x01a" ** 100 ++ "\x00"), // 100 single-octet labels: 199 text octets
    seed("\x3f" ++ ("a" ** 63) ++ "\x00"), // a label at the 63-octet maximum
    seed("\x40" ++ ("a" ** 64) ++ "\x00"), // 0x40: the top bits are 01, so BadLabel
    seed("\x80" ++ ("a" ** 10) ++ "\x00"), // 0x80: top bits 10, also BadLabel
    seed("\xc0\x0c"), // a compression pointer: forbidden by RFC 4034 §6.2
    seed("\x03foo\xc0\x00"), // a pointer after a legitimate label
    seed("\x03fo"), // a label length that runs off the end
    seed("\x03foo"), // a name with no root terminator
    seed(("\x01a" ** 130) ++ "\x00"), // 259 text octets: over `max_name_text_len`
    seed("\xff"), // a single 0xff octet
    seed(""), // the empty buffer
};

test "fuzz: decodeUncompressedName never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzDecodeUncompressedName, .{ .corpus = &name_seeds });
}

fn fuzzDecodeUncompressedName(_: void, smith: *std.testing.Smith) !void {
    var buf: [300]u8 = undefined;
    const len: usize = smith.slice(&buf);

    var out: [max_name_text_len]u8 = undefined;
    var start: usize = 0;
    while (start <= len) : (start += 1) {
        _ = decodeUncompressedName(buf[0..len], start, &out) catch continue;
    }
}

test "corpus: every name seed reaches the decoder, and the offsets that decode are pinned" {
    // ⭐ Three numbers. `decoded` counts (seed, offset) pairs that produced a
    // name at all -- and it is deliberately counted over the SWEEP, because a
    // guard that only tried offset 0 would be measuring a different harness
    // from the one it guards.
    //
    // `text_octets` is the second number and the discriminating one: the ROOT
    // name is a legal decode with a zero-length text result, so a corpus of
    // "\x00" seeds would score full marks on `decoded` while never once
    // copying a label into `out` -- and copying labels into a fixed
    // `[253]u8` is the entire risk this decoder carries.
    var nonempty: usize = 0;
    var decoded: usize = 0;
    var text_octets: usize = 0;
    var longest: usize = 0;
    for (name_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [300]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        var out: [max_name_text_len]u8 = undefined;
        var start: usize = 0;
        while (start <= len) : (start += 1) {
            const res = decodeUncompressedName(buf[0..len], start, &out) catch continue;
            decoded += 1;
            text_octets += res.text_len;
            longest = @max(longest, res.text_len);
        }
    }
    // One seed is deliberately the empty buffer.
    try testing.expectEqual(name_seeds.len - 1, nonempty);
    // Measured 2026-09-07: 0 of 15 seeds non-empty, 0 decodes and 0 text octets
    // before the draw was fixed — and `start` had been 0 on every iteration
    // this harness ever ran, which is the offset its own doc comment says is
    // not the interesting one.
    try testing.expectEqual(@as(usize, 245), decoded);
    try testing.expectEqual(@as(usize, 26238), text_octets);
    // ⭐ 253 is `max_name_text_len` exactly: the offset sweep found a starting
    // point in the 130-label seed that fills `out` to the last octet without
    // overflowing it. That is the boundary this decoder's `NameTooLong` check
    // defends, and the collapsed harness had never been within 253 of it.
    try testing.expectEqual(@as(usize, max_name_text_len), longest);
}
