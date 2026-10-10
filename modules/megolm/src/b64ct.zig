// SPDX-License-Identifier: MIT

//! b64ct — constant-time unpadded standard base64 (RFC 4648 §4 alphabet, no
//! `=`), for the one thing this module writes out as base64 that is secret:
//! the session-sharing key and its export (`SessionKey`/`ExportedSessionKey`
//! `toBase64`/`fromBase64`), which carry the Megolm ratchet.
//!
//! `std.base64` encodes through a 64-entry table indexed by each secret
//! sextet and decodes through a 256-entry table indexed by each secret
//! character, branching on its validity — secret-dependent memory addresses
//! and branches (memcheck: `ctgrind.sh megolm`, target `skey`, 2026-10-10).
//! Here every character is computed arithmetically: each range decision is a
//! borrow turned into a mask, never a branch or an index.
//!
//! Accepts exactly what `std.base64.standard_no_pad` accepts and returns the
//! same error for what it rejects: `InvalidPadding` for a length ≡ 1 (mod 4)
//! (public: the length), else `InvalidCharacter` if any character is outside
//! the alphabet, else `InvalidPadding` if the final character's unused low
//! bits are not zero. Validity is accumulated over the whole input and
//! branched on once, at the end. Messages (public ciphertext) still use std.

const std = @import("std");

pub const Error = std.base64.Error;

/// Encoded length of `n` octets, no padding.
pub fn encodedLen(n: usize) usize {
    return n / 3 * 4 + (n % 3 * 4 + 2) / 3;
}

/// Decoded length of `n` characters, or `InvalidPadding` for n ≡ 1 (mod 4).
pub fn decodedLen(n: usize) Error!usize {
    if (n % 4 == 1) return error.InvalidPadding;
    return n / 4 * 3 + (n % 4 * 3) / 4;
}

/// 0xff when `a >= b` (both < 256), else 0 — from the borrow of `b-1 - a`.
inline fn ge(a: u8, b: u8) u8 {
    return @truncate((@as(u16, b) -% 1 -% a) >> 8);
}

/// 0xff when lo <= c <= hi, else 0.
inline fn inRange(c: u8, lo: u8, hi: u8) u8 {
    const v = (@as(u16, c) -% lo) | (@as(u16, hi) -% c);
    return ~@as(u8, @truncate(v >> 8));
}

/// One sextet (0..63) to its alphabet character, branch- and table-free.
inline fn encodeSextet(v: u8) u8 {
    var c: u8 = v +% 'A';
    c +%= ge(v, 26) & 6; // 'a' - 'A' - 26
    c +%= ge(v, 52) & @as(u8, @bitCast(@as(i8, -75))); // '0' - 'a' - 26
    c +%= ge(v, 62) & @as(u8, @bitCast(@as(i8, -15))); // '+' - '0' - 10
    c +%= ge(v, 63) & 3; // '/' - '+'
    return c;
}

/// One character to its sextet; `valid` gets 0xff ANDed out when it is not
/// in the alphabet (the sextet is then 0).
inline fn decodeChar(c: u8, valid: *u8) u8 {
    const up = inRange(c, 'A', 'Z');
    const lo = inRange(c, 'a', 'z');
    const dg = inRange(c, '0', '9');
    const pl = inRange(c, '+', '+');
    const sl = inRange(c, '/', '/');
    valid.* &= up | lo | dg | pl | sl;
    return (up & (c -% 'A')) | (lo & (c -% 71)) | (dg & (c +% 4)) | (pl & 62) | (sl & 63);
}

/// `out.len` must be `encodedLen(src.len)`.
pub fn encode(out: []u8, src: []const u8) void {
    std.debug.assert(out.len == encodedLen(src.len));
    var o: usize = 0;
    var i: usize = 0;
    while (i + 3 <= src.len) : (i += 3) {
        const a = src[i];
        const b = src[i + 1];
        const c = src[i + 2];
        out[o] = encodeSextet(a >> 2);
        out[o + 1] = encodeSextet(((a & 3) << 4) | (b >> 4));
        out[o + 2] = encodeSextet(((b & 15) << 2) | (c >> 6));
        out[o + 3] = encodeSextet(c & 63);
        o += 4;
    }
    switch (src.len - i) {
        0 => {},
        1 => {
            const a = src[i];
            out[o] = encodeSextet(a >> 2);
            out[o + 1] = encodeSextet((a & 3) << 4);
        },
        2 => {
            const a = src[i];
            const b = src[i + 1];
            out[o] = encodeSextet(a >> 2);
            out[o + 1] = encodeSextet(((a & 3) << 4) | (b >> 4));
            out[o + 2] = encodeSextet((b & 15) << 2);
        },
        else => unreachable,
    }
}

/// `out.len` must be `decodedLen(src.len)`. On error `out` holds garbage
/// derived from the input; the caller wipes it.
pub fn decode(out: []u8, src: []const u8) Error!void {
    std.debug.assert(out.len == try decodedLen(src.len));
    var valid: u8 = 0xff;
    var o: usize = 0;
    var i: usize = 0;
    while (i + 4 <= src.len) : (i += 4) {
        const a = decodeChar(src[i], &valid);
        const b = decodeChar(src[i + 1], &valid);
        const c = decodeChar(src[i + 2], &valid);
        const d = decodeChar(src[i + 3], &valid);
        out[o] = (a << 2) | (b >> 4);
        out[o + 1] = (b << 4) | (c >> 2);
        out[o + 2] = (c << 6) | d;
        o += 3;
    }
    // The final character's unused low bits: must be zero (std: InvalidPadding).
    var stray: u8 = 0;
    switch (src.len - i) {
        0 => {},
        2 => {
            const a = decodeChar(src[i], &valid);
            const b = decodeChar(src[i + 1], &valid);
            out[o] = (a << 2) | (b >> 4);
            stray = b & 15;
        },
        3 => {
            const a = decodeChar(src[i], &valid);
            const b = decodeChar(src[i + 1], &valid);
            const c = decodeChar(src[i + 2], &valid);
            out[o] = (a << 2) | (b >> 4);
            out[o + 1] = (b << 4) | (c >> 2);
            stray = c & 3;
        },
        else => unreachable, // decodedLen refused 1
    }
    // The verdict, once: public (the caller rejects the input on it).
    if (valid != 0xff) return error.InvalidCharacter;
    if (stray != 0) return error.InvalidPadding;
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;
const std_codec = std.base64.standard_no_pad;

test "encode matches std for every length 0..200 over varied bytes" {
    var src: [200]u8 = undefined;
    for (&src, 0..) |*b, i| b.* = @truncate(i *% 157 +% 11);
    for (0..src.len + 1) |n| {
        var ours: [272]u8 = undefined;
        var theirs: [272]u8 = undefined;
        const len = encodedLen(n);
        try testing.expectEqual(std_codec.Encoder.calcSize(n), len);
        encode(ours[0..len], src[0..n]);
        _ = std_codec.Encoder.encode(theirs[0..len], src[0..n]);
        try testing.expectEqualStrings(theirs[0..len], ours[0..len]);
    }
}

test "every sextet and every byte value round-trips like std" {
    var all: [256]u8 = undefined;
    for (&all, 0..) |*b, i| b.* = @intCast(i);
    var enc: [344]u8 = undefined;
    const len = encodedLen(all.len);
    encode(enc[0..len], &all);
    var dec: [256]u8 = undefined;
    try decode(&dec, enc[0..len]);
    try testing.expectEqualSlices(u8, &all, &dec);
}

test "decode accepts and rejects exactly what std does, with std's error" {
    // Every character value in every position of a 2-, 3- and 4-character
    // tail after one full quantum, against std's verdict.
    const base = "QUJD"; // "ABC"
    for ([_]usize{ 2, 3, 4 }) |tail| {
        for (0..tail) |pos| {
            for (0..256) |cv| {
                var s: [8]u8 = undefined;
                @memcpy(s[0..4], base);
                @memcpy(s[4..][0..tail], "QUJD"[0..tail]);
                s[4 + pos] = @intCast(cv);
                const src = s[0 .. 4 + tail];
                var ours: [6]u8 = undefined;
                var theirs: [6]u8 = undefined;
                const n = try decodedLen(src.len);
                const r_ours = decode(ours[0..n], src);
                const r_theirs = std_codec.Decoder.decode(theirs[0..n], src);
                if (r_theirs) |_| {
                    try r_ours;
                    try testing.expectEqualSlices(u8, theirs[0..n], ours[0..n]);
                } else |e| try testing.expectError(e, r_ours);
            }
        }
    }
    // Length ≡ 1 (mod 4): std refuses it in calcSizeForSlice.
    try testing.expectError(error.InvalidPadding, decodedLen(5));
    try testing.expectError(error.InvalidPadding, std_codec.Decoder.calcSizeForSlice("QUJDQ"));
}
