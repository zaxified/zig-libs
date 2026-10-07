// SPDX-License-Identifier: MIT
//! One-shot Poly1305 (RFC 8439 § 2.5) with a 4-way vector bulk path.
//!
//! `std.crypto.onetimeauth.Poly1305` runs one block per multiply, each
//! depending on the last (~1.4 GB/s here), which capped `seal`/`open` once
//! Salsa20 got faster. This splits the message into four interleaved Horner
//! chains: lane j absorbs blocks j, j+4, j+8, ... multiplying by r^4, and the
//! final batch multiplies lane j by r^(4-j) instead, so the lane sum is the
//! ordinary polynomial. The accumulator is 5 limbs of 26 bits so every
//! product is a 32x32->64 multiply (a single instruction on any vector unit);
//! the < 4 leftover blocks and the finalisation run the same arithmetic on
//! one lane. Output is identical to std's (differential tests below).
//!
//! Limb bounds, for the multiply (`mul`): after `carry` every limb is < 2^26
//! except limb 1, < 2^26 + 2^11. Adding a message block keeps every limb
//! < 2^28, and 5*r_i < 2^30, so each of the five products in a column is
//! < 2^58 and their sum < 2^61 — no u64 overflow.
//!
//! Poly1305 is D. J. Bernstein's public design (RFC 8439). No third-party
//! source was copied.

const std = @import("std");
const mem = std.mem;

pub const key_length = 32;
pub const mac_length = 16;

const mask26: u64 = (1 << 26) - 1;

fn Limbs(comptime n: comptime_int) type {
    return [5]@Vector(n, u64);
}

/// `h * r mod 2^130-5`, partially reduced. Every operand limb must fit in
/// 32 bits (see the bounds in the file header); the products are formed from
/// u32 vectors so the compiler emits 32x32->64 multiplies.
inline fn mul(comptime n: comptime_int, h: Limbs(n), r: Limbs(n), s: Limbs(n)) Limbs(n) {
    const V = @Vector(n, u64);
    const W = @Vector(n, u32);
    var hh: [5]V = undefined;
    var rr: [5]V = undefined;
    var ss: [5]V = undefined;
    inline for (0..5) |i| {
        hh[i] = @as(W, @truncate(h[i]));
        rr[i] = @as(W, @truncate(r[i]));
        ss[i] = @as(W, @truncate(s[i]));
    }
    var d: [5]V = undefined;
    d[0] = hh[0] * rr[0] + hh[1] * ss[4] + hh[2] * ss[3] + hh[3] * ss[2] + hh[4] * ss[1];
    d[1] = hh[0] * rr[1] + hh[1] * rr[0] + hh[2] * ss[4] + hh[3] * ss[3] + hh[4] * ss[2];
    d[2] = hh[0] * rr[2] + hh[1] * rr[1] + hh[2] * rr[0] + hh[3] * ss[4] + hh[4] * ss[3];
    d[3] = hh[0] * rr[3] + hh[1] * rr[2] + hh[2] * rr[1] + hh[3] * rr[0] + hh[4] * ss[4];
    d[4] = hh[0] * rr[4] + hh[1] * rr[3] + hh[2] * rr[2] + hh[3] * rr[1] + hh[4] * rr[0];
    return carry(n, d);
}

inline fn carry(comptime n: comptime_int, d_in: Limbs(n)) Limbs(n) {
    const V = @Vector(n, u64);
    const m: V = @splat(mask26);
    const sh: @Vector(n, u6) = @splat(26);
    var d = d_in;
    var c: V = undefined;
    c = d[0] >> sh;
    d[0] &= m;
    d[1] += c;
    c = d[1] >> sh;
    d[1] &= m;
    d[2] += c;
    c = d[2] >> sh;
    d[2] &= m;
    d[3] += c;
    c = d[3] >> sh;
    d[3] &= m;
    d[4] += c;
    c = d[4] >> sh;
    d[4] &= m;
    d[0] += c * @as(V, @splat(5));
    c = d[0] >> sh;
    d[0] &= m;
    d[1] += c;
    return d;
}

inline fn times5(comptime n: comptime_int, r: Limbs(n)) Limbs(n) {
    var s: Limbs(n) = undefined;
    inline for (0..5) |i| s[i] = r[i] * @as(@Vector(n, u64), @splat(5));
    return s;
}

/// Message block(s) `n` x 16 bytes at stride `stride` as limbs, with the
/// 2^128 bit set (`hibit` = 1 << 24 in limb 4) for a full block.
inline fn load(comptime n: comptime_int, m: []const u8, comptime stride: usize) Limbs(n) {
    const V = @Vector(n, u64);
    var lo: V = undefined;
    var hi: V = undefined;
    inline for (0..n) |j| {
        lo[j] = mem.readInt(u64, m[stride * j ..][0..8], .little);
        hi[j] = mem.readInt(u64, m[stride * j + 8 ..][0..8], .little);
    }
    const m26: V = @splat(mask26);
    return .{
        lo & m26,
        (lo >> @splat(26)) & m26,
        ((lo >> @splat(52)) | (hi << @splat(12))) & m26,
        (hi >> @splat(14)) & m26,
        (hi >> @splat(40)) | @as(V, @splat(1 << 24)),
    };
}

fn add(comptime n: comptime_int, a: Limbs(n), b: Limbs(n)) Limbs(n) {
    var r: Limbs(n) = undefined;
    inline for (0..5) |i| r[i] = a[i] + b[i];
    return r;
}

fn scalar(x: [5]u64) Limbs(1) {
    var r: Limbs(1) = undefined;
    inline for (0..5) |i| r[i] = @splat(x[i]);
    return r;
}

fn splat4(x: Limbs(1)) Limbs(4) {
    var r: Limbs(4) = undefined;
    inline for (0..5) |i| r[i] = @splat(x[i][0]);
    return r;
}

/// Tag of `msg` under the one-time `key`. Same output as
/// `std.crypto.onetimeauth.Poly1305.create`.
pub fn create(out: *[mac_length]u8, msg: []const u8, key: *const [key_length]u8) void {
    const t0 = mem.readInt(u64, key[0..8], .little) & 0x0ffffffc0fffffff;
    const t1 = mem.readInt(u64, key[8..16], .little) & 0x0ffffffc0ffffffc;
    const r1 = scalar(.{
        t0 & mask26,
        (t0 >> 26) & mask26,
        ((t0 >> 52) | (t1 << 12)) & mask26,
        (t1 >> 14) & mask26,
        t1 >> 40,
    });
    const s1 = times5(1, r1);

    var h: Limbs(1) = scalar(.{ 0, 0, 0, 0, 0 });
    var i: usize = 0;

    if (msg.len >= 4 * 16) {
        const r2 = mul(1, r1, r1, s1);
        const r3 = mul(1, r2, r1, s1);
        const r4 = mul(1, r2, r2, times5(1, r2));
        const R4 = splat4(r4);
        const S4 = times5(4, R4);
        var tail_r: Limbs(4) = undefined;
        inline for (0..5) |k| tail_r[k] = .{ r4[k][0], r3[k][0], r2[k][0], r1[k][0] };
        const tail_s = times5(4, tail_r);

        // Lanes hold blocks 4b+j; the last full batch is multiplied by the
        // per-lane powers so the chains line up.
        var H: Limbs(4) = .{ @splat(0), @splat(0), @splat(0), @splat(0), @splat(0) };
        while (msg.len - i >= 8 * 16) : (i += 4 * 16) {
            H = mul(4, add(4, H, load(4, msg[i..], 16)), R4, S4);
        }
        H = mul(4, add(4, H, load(4, msg[i..], 16)), tail_r, tail_s);
        i += 4 * 16;
        var sum: Limbs(1) = undefined;
        inline for (0..5) |k| sum[k] = @splat(@reduce(.Add, H[k]));
        h = carry(1, sum);
    }

    while (msg.len - i >= 16) : (i += 16) {
        h = mul(1, add(1, h, load(1, msg[i..], 16)), r1, s1);
    }
    if (i < msg.len) {
        var buf = [_]u8{0} ** 16;
        @memcpy(buf[0 .. msg.len - i], msg[i..]);
        buf[msg.len - i] = 1;
        var b = load(1, &buf, 16);
        b[4] &= @splat((1 << 24) - 1); // a padded final block has no 2^128 bit
        h = mul(1, add(1, h, b), r1, s1);
    }

    // Full reduction mod 2^130-5, then add the pad mod 2^128.
    var f: [5]u64 = undefined;
    inline for (0..5) |k| f[k] = h[k][0];
    var c: u64 = f[1] >> 26;
    f[1] &= mask26;
    f[2] += c;
    c = f[2] >> 26;
    f[2] &= mask26;
    f[3] += c;
    c = f[3] >> 26;
    f[3] &= mask26;
    f[4] += c;
    c = f[4] >> 26;
    f[4] &= mask26;
    f[0] += c * 5;
    c = f[0] >> 26;
    f[0] &= mask26;
    f[1] += c;

    var g: [5]u64 = undefined;
    g[0] = f[0] + 5;
    c = g[0] >> 26;
    g[0] &= mask26;
    inline for (1..5) |k| {
        g[k] = f[k] + c;
        c = g[k] >> 26;
        g[k] &= mask26;
    }
    // c == 1 iff h + 5 >= 2^130, i.e. h >= p: take g then (no branch).
    const take_g = 0 -% c;
    inline for (0..5) |k| f[k] = (f[k] & ~take_g) | (g[k] & take_g);

    const acc: u128 = @as(u128, f[0]) | (@as(u128, f[1]) << 26) | (@as(u128, f[2]) << 52) |
        (@as(u128, f[3]) << 78) | (@as(u128, f[4]) << 104);
    const tag = acc +% mem.readInt(u128, key[16..32], .little);
    mem.writeInt(u128, out, tag, .little);
}

// ── differential tests against std ───────────────────────────────────────────

test "matches std Poly1305 across lengths" {
    var prng = std.Random.DefaultPrng.init(0x9013);
    const r = prng.random();
    var msg: [1200]u8 = undefined;
    for (0..40) |round| {
        r.bytes(&msg);
        var key: [32]u8 = undefined;
        r.bytes(&key);
        // Extreme keys: an all-ones r/s stresses the limb bounds.
        if (round == 0) @memset(&key, 0xff);
        if (round == 1) @memset(msg[0..], 0xff);
        var len: usize = 0;
        while (len <= msg.len) : (len += if (len < 200) 1 else 37) {
            var a: [16]u8 = undefined;
            var b: [16]u8 = undefined;
            std.crypto.onetimeauth.Poly1305.create(&a, msg[0..len], &key);
            create(&b, msg[0..len], &key);
            try std.testing.expectEqual(a, b);
        }
    }
}

test "RFC 8439 2.5.2 vector" {
    var key: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&key, "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
    var want: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, "a8061dc1305136c6c22b8baf0c0127a9");
    var got: [16]u8 = undefined;
    create(&got, "Cryptographic Forum Research Group", &key);
    try std.testing.expectEqual(want, got);
}

test "h near the modulus takes the reduced branch" {
    // Messages whose accumulator lands in [p, 2^130): all-0xff blocks under
    // r = 1 make h = sum of (2^129 - 1) values, exercising the final select.
    var key = [_]u8{0} ** 32;
    key[0] = 1;
    var msg = [_]u8{0xff} ** 160;
    for (0..msg.len + 1) |len| {
        var a: [16]u8 = undefined;
        var b: [16]u8 = undefined;
        std.crypto.onetimeauth.Poly1305.create(&a, msg[0..len], &key);
        create(&b, msg[0..len], &key);
        try std.testing.expectEqual(a, b);
    }
}
