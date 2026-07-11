// SPDX-License-Identifier: MIT
//! codec — Falcon-512 wire encodings (Round-3 spec §3.11) + hash-to-point.
//!
//! * `modq` — 14-bit packed coefficients in [0, q), used by the public key.
//! * `trimI8` — fixed-width signed coefficients, used by the secret key
//!   (6 bits for f/g, 8 bits for F at n = 512).
//! * `comp` — the compressed Golomb-Rice-style signature encoding
//!   (sign bit + 7 low bits + unary high part), canonical: "-0" and
//!   nonzero padding bits are rejected, |coefficient| <= 2047.
//! * `hashToPoint` — SHAKE256(nonce || message) squeezed to n points of
//!   Z_q by 16-bit big-endian rejection sampling (spec §3.7, the plain
//!   variant; not constant-time, same as the reference vartime version).

const std = @import("std");
const poly = @import("poly.zig");

const n = poly.n;
const q = poly.q;

/// Byte length of a 14-bit-packed public-key body (without header byte).
pub const modq_encoded_len: usize = n * 14 / 8; // 896

/// Decode a 14-bit-packed polynomial; rejects coefficients >= q and
/// nonzero padding. `in` must be exactly `modq_encoded_len` bytes.
pub fn modqDecode(out: *poly.Poly, in: *const [modq_encoded_len]u8) error{InvalidEncoding}!void {
    var acc: u32 = 0;
    var acc_len: u5 = 0;
    var u: usize = 0;
    for (in) |byte| {
        acc = (acc << 8) | byte;
        acc_len += 8;
        if (acc_len >= 14) {
            acc_len -= 14;
            const w: u32 = (acc >> acc_len) & 0x3fff;
            if (w >= q) return error.InvalidEncoding;
            out[u] = @intCast(w);
            u += 1;
        }
    }
    std.debug.assert(u == n);
    if ((acc & ((@as(u32, 1) << acc_len) - 1)) != 0) return error.InvalidEncoding;
}

/// Encode a polynomial with coefficients in [0, q) as 14-bit packed bytes.
pub fn modqEncode(out: *[modq_encoded_len]u8, in: *const poly.Poly) void {
    var acc: u32 = 0;
    var acc_len: u5 = 0;
    var v: usize = 0;
    for (in) |x| {
        std.debug.assert(x < q);
        acc = (acc << 14) | x;
        acc_len += 14;
        while (acc_len >= 8) {
            acc_len -= 8;
            out[v] = @truncate(acc >> acc_len);
            v += 1;
        }
    }
    if (acc_len > 0) {
        out[v] = @truncate(acc << (8 - acc_len));
        v += 1;
    }
    std.debug.assert(v == modq_encoded_len);
}

/// Decode fixed-width (`bits`-bit) signed coefficients; the most negative
/// value -2^(bits-1) and nonzero padding are rejected. `in.len` must be
/// exactly n*bits/8.
pub fn trimI8Decode(out: *[n]i8, comptime bits: u4, in: *const [n * bits / 8]u8) error{InvalidEncoding}!void {
    const mask1: u32 = (@as(u32, 1) << bits) - 1;
    const mask2: u32 = @as(u32, 1) << (bits - 1);
    var acc: u32 = 0;
    var acc_len: u5 = 0;
    var u: usize = 0;
    for (in) |byte| {
        acc = (acc << 8) | byte;
        acc_len += 8;
        while (acc_len >= bits and u < n) {
            acc_len -= bits;
            const w: u32 = (acc >> acc_len) & mask1;
            if (w == mask2) return error.InvalidEncoding; // forbidden -2^(bits-1)
            const v: i32 = if (w & mask2 != 0)
                @as(i32, @intCast(w)) - @as(i32, @intCast(mask1)) - 1
            else
                @intCast(w);
            out[u] = @intCast(v);
            u += 1;
        }
    }
    std.debug.assert(u == n);
    if ((acc & ((@as(u32, 1) << acc_len) - 1)) != 0) return error.InvalidEncoding;
}

/// Decode a compressed signature value s2. Consumes bytes from `in`;
/// succeeds only if the encoding is canonical AND uses exactly `in.len`
/// bytes (the reference enforces the same via its length check).
pub fn compDecode(out: *[n]i16, in: []const u8) error{InvalidEncoding}!void {
    var acc: u32 = 0;
    var acc_len: u5 = 0;
    var v: usize = 0;
    for (out) |*coef| {
        // Sign bit + low seven bits of the absolute value.
        if (v >= in.len) return error.InvalidEncoding;
        acc = ((acc << 8) | in[v]) & 0xffff;
        v += 1;
        const b: u32 = acc >> acc_len;
        const s: bool = (b & 128) != 0;
        var m: u32 = b & 127;
        // Unary high part: count zeros until a one.
        while (true) {
            if (acc_len == 0) {
                if (v >= in.len) return error.InvalidEncoding;
                acc = ((acc << 8) | in[v]) & 0xffff;
                v += 1;
                acc_len = 8;
            }
            acc_len -= 1;
            if ((acc >> acc_len) & 1 != 0) break;
            m += 128;
            if (m > 2047) return error.InvalidEncoding;
        }
        if (s and m == 0) return error.InvalidEncoding; // "-0" forbidden
        coef.* = if (s) -@as(i16, @intCast(m)) else @intCast(m);
    }
    // Unused bits in the last byte must be zero, and the signature field
    // must be exactly consumed (no trailing bytes).
    if ((acc & ((@as(u32, 1) << acc_len) - 1)) != 0) return error.InvalidEncoding;
    if (v != in.len) return error.InvalidEncoding;
}

/// Compress a signature value s2 (inverse of `compDecode`; byte-canonical,
/// mirrors the reference `comp_encode`). Returns the number of bytes
/// written, or error if a coefficient is out of range or `out` too small.
pub fn compEncode(out: []u8, in: *const [n]i16) error{ CoefficientOutOfRange, NoSpaceLeft }!usize {
    var acc: u32 = 0;
    var acc_len: u5 = 0;
    var v: usize = 0;
    for (in) |x| {
        if (x < -2047 or x > 2047) return error.CoefficientOutOfRange;
        // Sign bit, then the low 7 bits of |x|.
        acc <<= 1;
        var w: u32 = if (x < 0) blk: {
            acc |= 1;
            break :blk @intCast(-@as(i32, x));
        } else @intCast(x);
        acc = (acc << 7) | (w & 127);
        w >>= 7;
        acc_len += 8;
        // Unary high part: w zeros, then a one (at most 16 more bits, so
        // the u32 accumulator never overflows: <= 7 leftover + 24).
        acc = (acc << @intCast(w + 1)) | 1;
        acc_len += @intCast(w + 1);
        while (acc_len >= 8) {
            acc_len -= 8;
            if (v >= out.len) return error.NoSpaceLeft;
            out[v] = @truncate(acc >> acc_len);
            v += 1;
        }
    }
    if (acc_len > 0) {
        if (v >= out.len) return error.NoSpaceLeft;
        out[v] = @truncate(acc << (8 - acc_len));
        v += 1;
    }
    return v;
}

/// Hash a (nonce, message) pair to a point c in Z_q^n — SHAKE256 with
/// 16-bit big-endian rejection sampling below 61445 = 5q (spec §3.7).
pub fn hashToPoint(nonce: []const u8, msg: []const u8, out: *poly.Poly) void {
    var st = std.crypto.hash.sha3.Shake256.init(.{});
    st.update(nonce);
    st.update(msg);
    var u: usize = 0;
    while (u < n) {
        var buf: [2]u8 = undefined;
        st.squeeze(&buf);
        var w: u32 = (@as(u32, buf[0]) << 8) | buf[1];
        if (w < 61445) {
            while (w >= q) w -= q;
            out[u] = @intCast(w);
            u += 1;
        }
    }
}

test "modq encode/decode round-trip; out-of-range and padding rejected" {
    var prng = std.Random.DefaultPrng.init(0x51ac);
    const random = prng.random();
    var a: poly.Poly = undefined;
    for (&a) |*x| x.* = random.uintLessThan(u16, @intCast(q));
    var buf: [modq_encoded_len]u8 = undefined;
    modqEncode(&buf, &a);
    var b: poly.Poly = undefined;
    try modqDecode(&b, &buf);
    try std.testing.expectEqualSlices(u16, &a, &b);

    // First 14-bit field = 0x3fff >= q must be rejected.
    var bad = buf;
    bad[0] = 0xff;
    bad[1] |= 0xfc;
    try std.testing.expectError(error.InvalidEncoding, modqDecode(&b, &bad));
}

test "trimI8 decode: values, forbidden minimum, padding" {
    // 6-bit fields: 512*6/8 = 384 bytes. Encode 0,1,-1,31,-31,... manually:
    // field values: 0->0, 1->1, -1->63, 31->31, -31->33; forbidden: 32 (-32).
    var in = std.mem.zeroes([384]u8);
    // First four 6-bit fields across 3 bytes: 000000 000001 111111 011111.
    in[0] = 0b00000000;
    in[1] = 0b00011111;
    in[2] = 0b11011111;
    var out: [n]i8 = undefined;
    try trimI8Decode(&out, 6, &in);
    try std.testing.expectEqual(@as(i8, 0), out[0]);
    try std.testing.expectEqual(@as(i8, 1), out[1]);
    try std.testing.expectEqual(@as(i8, -1), out[2]);
    try std.testing.expectEqual(@as(i8, 31), out[3]);
    for (out[4..]) |x| try std.testing.expectEqual(@as(i8, 0), x);

    // Field value 0b100000 = -32 is forbidden at 6 bits.
    var bad = std.mem.zeroes([384]u8);
    bad[0] = 0b10000000;
    try std.testing.expectError(error.InvalidEncoding, trimI8Decode(&out, 6, &bad));
}

test "comp encode/decode round-trip; minus-zero and junk padding rejected" {
    var prng = std.Random.DefaultPrng.init(0xc0de);
    const random = prng.random();
    var s: [n]i16 = undefined;
    for (&s) |*x| {
        // Realistic Falcon-512 s2 magnitudes (sigma ~ 165) plus outliers.
        const mag = random.uintLessThan(u16, 800);
        x.* = if (random.boolean() and mag != 0) -@as(i16, @intCast(mag)) else @intCast(mag);
    }
    var buf: [2048]u8 = undefined;
    const len = try compEncode(&buf, &s);
    var back: [n]i16 = undefined;
    try compDecode(&back, buf[0..len]);
    try std.testing.expectEqualSlices(i16, &s, &back);

    // Trailing extra zero byte => not exactly consumed => reject.
    buf[len] = 0;
    try std.testing.expectError(error.InvalidEncoding, compDecode(&back, buf[0 .. len + 1]));

    // Truncation => reject.
    try std.testing.expectError(error.InvalidEncoding, compDecode(&back, buf[0 .. len - 1]));

    // "-0": sign bit set, zero mantissa, immediate stop bit -> 1000_0000 1...
    // First coefficient encoded as sign=1, low7=0, then unary stop "1".
    var mz = [_]u8{ 0x80, 0x80 } ++ [_]u8{0} ** 16;
    try std.testing.expectError(error.InvalidEncoding, compDecode(&back, &mz));

    // Out-of-range coefficient rejected by the encoder.
    s[0] = 2048;
    try std.testing.expectError(error.CoefficientOutOfRange, compEncode(&buf, &s));
}

test "hashToPoint: deterministic, all points < q, nonce-sensitive" {
    var c1: poly.Poly = undefined;
    var c2: poly.Poly = undefined;
    var c3: poly.Poly = undefined;
    const nonce1 = [_]u8{0xab} ** 40;
    const nonce2 = [_]u8{0xac} ** 40;
    hashToPoint(&nonce1, "falcon", &c1);
    hashToPoint(&nonce1, "falcon", &c2);
    hashToPoint(&nonce2, "falcon", &c3);
    try std.testing.expectEqualSlices(u16, &c1, &c2);
    try std.testing.expect(!std.mem.eql(u16, &c1, &c3));
    for (c1) |x| try std.testing.expect(x < q);
}
