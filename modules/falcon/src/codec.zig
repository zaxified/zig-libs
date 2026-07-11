// SPDX-License-Identifier: MIT
//! codec — Falcon wire encodings (Round-3 spec §3.11) + hash-to-point,
//! generic over the ring degree so the same code serves Falcon-512 and
//! Falcon-1024.
//!
//! * `modq` — 14-bit packed coefficients in [0, q), used by the public key.
//! * `trimI8` — fixed-width signed coefficients, used by the secret key
//!   (6 bits for f/g at n = 512, 5 bits at n = 1024; 8 bits for F either
//!   way).
//! * `comp` — the compressed Golomb-Rice-style signature encoding
//!   (sign bit + 7 low bits + unary high part), canonical: "-0" and
//!   nonzero padding bits are rejected, |coefficient| <= 2047.
//! * `hashToPoint` — SHAKE256(nonce || message) squeezed to n points of
//!   Z_q by 16-bit big-endian rejection sampling (spec §3.7, the plain
//!   variant; not constant-time, same as the reference vartime version).
//!
//! `Codec(Ring)` builds all of the above against a `poly.Ring(logn)`
//! instantiation; `Codec512`/`Codec1024` are the two Falcon parameter
//! sets, and the module's flat top-level names mirror `poly.zig`'s
//! Falcon-512-by-default convention for backward compatibility.

const std = @import("std");
const poly = @import("poly.zig");

const q = poly.q;

/// Wire encodings + hash-to-point over a given `poly.Ring(logn)`.
pub fn Codec(comptime Ring: type) type {
    return struct {
        const Self = @This();

        /// Byte length of a 14-bit-packed public-key body (without header
        /// byte).
        pub const modq_encoded_len: usize = Ring.n * 14 / 8;

        /// Decode a 14-bit-packed polynomial; rejects coefficients >= q and
        /// nonzero padding. `in` must be exactly `modq_encoded_len` bytes.
        pub fn modqDecode(out: *Ring.Poly, in: *const [Self.modq_encoded_len]u8) error{InvalidEncoding}!void {
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
            std.debug.assert(u == Ring.n);
            if ((acc & ((@as(u32, 1) << acc_len) - 1)) != 0) return error.InvalidEncoding;
        }

        /// Encode a polynomial with coefficients in [0, q) as 14-bit packed
        /// bytes.
        pub fn modqEncode(out: *[Self.modq_encoded_len]u8, in: *const Ring.Poly) void {
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
            std.debug.assert(v == Self.modq_encoded_len);
        }

        /// Decode fixed-width (`bits`-bit) signed coefficients; the most
        /// negative value -2^(bits-1) and nonzero padding are rejected.
        /// `in.len` must be exactly n*bits/8.
        pub fn trimI8Decode(out: *[Ring.n]i8, comptime bits: u4, in: *const [Ring.n * bits / 8]u8) error{InvalidEncoding}!void {
            const mask1: u32 = (@as(u32, 1) << bits) - 1;
            const mask2: u32 = @as(u32, 1) << (bits - 1);
            var acc: u32 = 0;
            var acc_len: u5 = 0;
            var u: usize = 0;
            for (in) |byte| {
                acc = (acc << 8) | byte;
                acc_len += 8;
                while (acc_len >= bits and u < Ring.n) {
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
            std.debug.assert(u == Ring.n);
            if ((acc & ((@as(u32, 1) << acc_len) - 1)) != 0) return error.InvalidEncoding;
        }

        /// Decode a compressed signature value s2. Consumes bytes from
        /// `in`; succeeds only if the encoding is canonical AND uses
        /// exactly `in.len` bytes (the reference enforces the same via its
        /// length check).
        pub fn compDecode(out: *[Ring.n]i16, in: []const u8) error{InvalidEncoding}!void {
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
            // Unused bits in the last byte must be zero, and the signature
            // field must be exactly consumed (no trailing bytes).
            if ((acc & ((@as(u32, 1) << acc_len) - 1)) != 0) return error.InvalidEncoding;
            if (v != in.len) return error.InvalidEncoding;
        }

        /// Compress a signature value s2 (inverse of `compDecode`;
        /// byte-canonical, mirrors the reference `comp_encode`). Returns
        /// the number of bytes written, or error if a coefficient is out
        /// of range or `out` too small.
        pub fn compEncode(out: []u8, in: *const [Ring.n]i16) error{ CoefficientOutOfRange, NoSpaceLeft }!usize {
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
                // Unary high part: w zeros, then a one (at most 16 more
                // bits, so the u32 accumulator never overflows: <= 7
                // leftover + 24).
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

        /// Hash a (nonce, message) pair to a point c in Z_q^n — SHAKE256
        /// with 16-bit big-endian rejection sampling below 61445 = 5q
        /// (spec §3.7).
        pub fn hashToPoint(nonce: []const u8, msg: []const u8, out: *Ring.Poly) void {
            var st = std.crypto.hash.sha3.Shake256.init(.{});
            st.update(nonce);
            st.update(msg);
            var u: usize = 0;
            while (u < Ring.n) {
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
    };
}

/// Falcon-512 codec.
pub const Codec512 = Codec(poly.Ring512);
/// Falcon-1024 codec.
pub const Codec1024 = Codec(poly.Ring1024);

// Flat aliases = Falcon-512, kept for backward compatibility.
pub const modq_encoded_len = Codec512.modq_encoded_len;
pub const modqDecode = Codec512.modqDecode;
pub const modqEncode = Codec512.modqEncode;
pub const trimI8Decode = Codec512.trimI8Decode;
pub const compDecode = Codec512.compDecode;
pub const compEncode = Codec512.compEncode;
pub const hashToPoint = Codec512.hashToPoint;

const n = poly.n;

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

test "Falcon-1024 codec: modq encode/decode round-trip; out-of-range rejected" {
    var prng = std.Random.DefaultPrng.init(0x51ac1024);
    const random = prng.random();
    var a: poly.Ring1024.Poly = undefined;
    for (&a) |*x| x.* = random.uintLessThan(u16, @intCast(q));
    var buf: [Codec1024.modq_encoded_len]u8 = undefined;
    Codec1024.modqEncode(&buf, &a);
    var b: poly.Ring1024.Poly = undefined;
    try Codec1024.modqDecode(&b, &buf);
    try std.testing.expectEqualSlices(u16, &a, &b);

    var bad = buf;
    bad[0] = 0xff;
    bad[1] |= 0xfc;
    try std.testing.expectError(error.InvalidEncoding, Codec1024.modqDecode(&b, &bad));
}

const Ring1024FgBytes = poly.Ring1024.n * 5 / 8;

test "Falcon-1024 codec: trimI8 decode at 5 bits (the n=1024 f/g width)" {
    // 5-bit fields: 1024*5/8 = 640 bytes. Field values: 0->0, 1->1, -1->31.
    // Forbidden minimum at 5 bits is 0b10000 = 16 (-16).
    var in = std.mem.zeroes([Ring1024FgBytes]u8);
    // First three 5-bit fields across 2 bytes: 00000 00001 11111 (+0 pad).
    in[0] = 0b00000000;
    in[1] = 0b01111110;
    var out: [poly.Ring1024.n]i8 = undefined;
    try Codec1024.trimI8Decode(&out, 5, &in);
    try std.testing.expectEqual(@as(i8, 0), out[0]);
    try std.testing.expectEqual(@as(i8, 1), out[1]);
    try std.testing.expectEqual(@as(i8, -1), out[2]);
    for (out[3..]) |x| try std.testing.expectEqual(@as(i8, 0), x);

    // Field value 0b10000 = -16 is forbidden at 5 bits.
    var bad = std.mem.zeroes([Ring1024FgBytes]u8);
    bad[0] = 0b10000000;
    try std.testing.expectError(error.InvalidEncoding, Codec1024.trimI8Decode(&out, 5, &bad));
}

test "Falcon-1024 codec: comp encode/decode round-trip; minus-zero rejected" {
    var prng = std.Random.DefaultPrng.init(0xc0de1024);
    const random = prng.random();
    var s: [poly.Ring1024.n]i16 = undefined;
    for (&s) |*x| {
        const mag = random.uintLessThan(u16, 800);
        x.* = if (random.boolean() and mag != 0) -@as(i16, @intCast(mag)) else @intCast(mag);
    }
    var buf: [4096]u8 = undefined;
    const len = try Codec1024.compEncode(&buf, &s);
    var back: [poly.Ring1024.n]i16 = undefined;
    try Codec1024.compDecode(&back, buf[0..len]);
    try std.testing.expectEqualSlices(i16, &s, &back);

    buf[len] = 0;
    try std.testing.expectError(error.InvalidEncoding, Codec1024.compDecode(&back, buf[0 .. len + 1]));
    try std.testing.expectError(error.InvalidEncoding, Codec1024.compDecode(&back, buf[0 .. len - 1]));

    var mz = [_]u8{ 0x80, 0x80 } ++ [_]u8{0} ** 16;
    try std.testing.expectError(error.InvalidEncoding, Codec1024.compDecode(&back, &mz));
}

test "Falcon-1024 codec: hashToPoint deterministic, all points < q, nonce-sensitive" {
    var c1: poly.Ring1024.Poly = undefined;
    var c2: poly.Ring1024.Poly = undefined;
    var c3: poly.Ring1024.Poly = undefined;
    const nonce1 = [_]u8{0xab} ** 40;
    const nonce2 = [_]u8{0xac} ** 40;
    Codec1024.hashToPoint(&nonce1, "falcon", &c1);
    Codec1024.hashToPoint(&nonce1, "falcon", &c2);
    Codec1024.hashToPoint(&nonce2, "falcon", &c3);
    try std.testing.expectEqualSlices(u16, &c1, &c2);
    try std.testing.expect(!std.mem.eql(u16, &c1, &c3));
    for (c1) |x| try std.testing.expect(x < q);
}
