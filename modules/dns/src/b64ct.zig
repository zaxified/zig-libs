// SPDX-License-Identifier: MIT

//! b64ct — constant-time PADDED standard base64 (RFC 4648 §4), for the one
//! secret this module reads as base64: a TSIG key's secret as BIND's
//! `secret "...";` and `nsupdate -y` carry it (`tsig.decodeSecret`).
//!
//! `std.base64` decodes through a 256-entry table indexed by each secret
//! character — secret-dependent load addresses. Here every character is
//! computed arithmetically: each range decision is a borrow turned into a
//! mask, never a branch or an index. Validity is accumulated and branched on
//! once, at the end.
//!
//! Copied verbatim from `acme`'s `b64ct.zig` (2026-10-16; itself smtp's
//! encoder and megolm's decoder) — a fourth copy rather than a shared module,
//! as with every other small helper in this repo. The encoder rides along so
//! its tests (byte-identical to std) keep pinning the decoder's inverse.

const std = @import("std");

pub const Error = std.base64.Error;

/// Encoded length of `n` octets, with `=` padding (std's `calcSize`).
pub fn encodedLen(n: usize) usize {
    return (n + 2) / 3 * 4;
}

/// 0xff when `a >= b` (both < 256), else 0 — from the borrow of `b-1 - a`.
inline fn ge(a: u8, b: u8) u8 {
    return @truncate((@as(u16, b) -% 1 -% a) >> 8);
}

/// One sextet (0..63) to its alphabet character, branch- and table-free.
inline fn sextet(v: u8) u8 {
    var c: u8 = v +% 'A';
    c +%= ge(v, 26) & 6; // 'a' - 'A' - 26
    c +%= ge(v, 52) & @as(u8, @bitCast(@as(i8, -75))); // '0' - 'a' - 26
    c +%= ge(v, 62) & @as(u8, @bitCast(@as(i8, -15))); // '+' - '0' - 10
    c +%= ge(v, 63) & 3; // '/' - '+'
    return c;
}

/// Encodes `src` into the front of `out` (`out.len >= encodedLen(src.len)`)
/// and returns the written slice.
pub fn encode(out: []u8, src: []const u8) []const u8 {
    const len = encodedLen(src.len);
    std.debug.assert(out.len >= len);
    var o: usize = 0;
    var i: usize = 0;
    while (i + 3 <= src.len) : (i += 3) {
        const a = src[i];
        const b = src[i + 1];
        const c = src[i + 2];
        out[o] = sextet(a >> 2);
        out[o + 1] = sextet(((a & 3) << 4) | (b >> 4));
        out[o + 2] = sextet(((b & 15) << 2) | (c >> 6));
        out[o + 3] = sextet(c & 63);
        o += 4;
    }
    switch (src.len - i) {
        0 => {},
        1 => {
            const a = src[i];
            out[o] = sextet(a >> 2);
            out[o + 1] = sextet((a & 3) << 4);
            out[o + 2] = '=';
            out[o + 3] = '=';
        },
        2 => {
            const a = src[i];
            const b = src[i + 1];
            out[o] = sextet(a >> 2);
            out[o + 1] = sextet(((a & 3) << 4) | (b >> 4));
            out[o + 2] = sextet((b & 15) << 2);
            out[o + 3] = '=';
        },
        else => unreachable,
    }
    return out[0..len];
}

/// Length of the unpadded data `n` characters decode to; `InvalidPadding`
/// for n ≡ 1 (mod 4).
fn unpaddedLen(n: usize) Error!usize {
    if (n % 4 == 1) return error.InvalidPadding;
    return n / 4 * 3 + (n % 4 * 3) / 4;
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

/// `out.len` must be `unpaddedLen(src.len)`. On error `out` holds garbage
/// derived from the input; the caller wipes it.
fn decodeUnpadded(out: []u8, src: []const u8) Error!void {
    std.debug.assert(out.len == try unpaddedLen(src.len));
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
        else => unreachable, // unpaddedLen refused 1
    }
    // The verdict, once: public (the caller rejects the input on it).
    if (valid != 0xff) return error.InvalidCharacter;
    if (stray != 0) return error.InvalidPadding;
}

/// Decode padded standard base64 (no whitespace: the caller strips it) into
/// the front of `out` and return the written slice. Accepts exactly what
/// `std.base64.standard.Decoder` accepts, with the same bytes; the error
/// for a rejected input may differ from std's (a `=` inside the data is
/// `InvalidCharacter` here; the PEM caller maps both to `InvalidPem`). The length and the count of trailing `=` (0..2) are public —
/// they follow from the encoded length — and are branched on; the data
/// characters are not. `out.len` must be at least `src.len / 4 * 3`; on
/// error `out` holds garbage derived from the input, which the caller wipes.
pub fn decode(out: []u8, src: []const u8) Error![]u8 {
    if (src.len % 4 != 0) return error.InvalidPadding;
    var pad: usize = 0;
    if (src.len >= 1 and src[src.len - 1] == '=') pad += 1;
    if (src.len >= 2 and src[src.len - 2] == '=') pad += 1;
    // "x==" ends a quantum; "=x" or a third '=' is not padding.
    if (pad == 1 and src.len >= 2 and src[src.len - 2] == '=') return error.InvalidPadding;
    const body = src[0 .. src.len - pad];
    const n = try unpaddedLen(body.len);
    std.debug.assert(out.len >= n);
    try decodeUnpadded(out[0..n], body);
    return out[0..n];
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "encode is byte-identical to std for every length 0..300 and every byte value" {
    var src: [300]u8 = undefined;
    for (&src, 0..) |*b, i| b.* = @truncate(i *% 157 +% 11);
    var all: [256]u8 = undefined;
    for (&all, 0..) |*b, i| b.* = @intCast(i);
    const codec = std.base64.standard.Encoder;
    for ([_][]const u8{ &src, &all }) |s| {
        for (0..s.len + 1) |n| {
            var ours: [400]u8 = undefined;
            var theirs: [400]u8 = undefined;
            try testing.expectEqual(codec.calcSize(n), encodedLen(n));
            try testing.expectEqualStrings(codec.encode(&theirs, s[0..n]), encode(&ours, s[0..n]));
        }
    }
}

test "decode inverts encode for every length 0..300" {
    var src: [300]u8 = undefined;
    for (&src, 0..) |*b, i| b.* = @truncate(i *% 89 +% 3);
    for (0..src.len + 1) |n| {
        var enc: [400]u8 = undefined;
        const e = encode(&enc, src[0..n]);
        var dec: [300]u8 = undefined;
        try testing.expectEqualSlices(u8, src[0..n], try decode(&dec, e));
    }
}

test "decode accepts exactly what std.base64.standard accepts, with the same bytes" {
    // Every character value in every position of a final quantum (after
    // one full quantum), against std's verdict — '=' included, so every
    // padding shape is covered.
    const std_dec = std.base64.standard.Decoder;
    for (0..4) |pos| {
        for (0..256) |cv| {
            for ([_][]const u8{ "QUJD", "QUI=", "QQ==" }) |tail| {
                var s: [8]u8 = undefined;
                @memcpy(s[0..4], "QUJD");
                @memcpy(s[4..8], tail);
                s[4 + pos] = @intCast(cv);
                var ours: [6]u8 = undefined;
                var theirs: [6]u8 = undefined;
                const r_theirs: Error![]const u8 = blk: {
                    const n = std_dec.calcSizeForSlice(&s) catch |e| break :blk e;
                    std_dec.decode(theirs[0..n], &s) catch |e| break :blk e;
                    break :blk theirs[0..n];
                };
                const r_ours = decode(&ours, &s);
                if (r_theirs) |want| {
                    try testing.expectEqualSlices(u8, want, try r_ours);
                } else |_| try testing.expect(std.meta.isError(r_ours));
            }
        }
    }
    var out: [8]u8 = undefined;
    try testing.expectError(error.InvalidPadding, decode(&out, "QUJ"));
    try testing.expect(std.meta.isError(decode(&out, "Q===")));
    try testing.expect(std.meta.isError(decode(&out, "QU=D")));
}
