// SPDX-License-Identifier: MIT
//! Ring arithmetic of ML-KEM (FIPS 203 §4.3): R_q = Z_q[X]/(X^256 + 1),
//! q = 3329, computed on 16-lane `i16` vectors (one AVX2 register; LLVM
//! lowers the same code to SSE2/NEON pairs elsewhere).
//!
//! **Layout.** A `Poly` is 256 `i16` coefficients held as sixteen vectors.
//! In the normal domain they are in natural order. In the NTT domain (the
//! output of `ntt`) the coefficients are in FIPS 203's bit-reversed order
//! (Algorithm 9), but every block of 32 is stored *deinterleaved*: the
//! first vector of the block holds the 16 even entries (the constant terms
//! of the 16 degree-1 residues), the second the 16 odd ones. The base-case
//! multiplication (Algorithm 12) is then lane-wise, with no shuffles. The
//! FIPS 203 byte order is restored only at the encoding boundary
//! (`toNttBytes` / `fromNttBytes`, `ntt_pos`).
//!
//! **Arithmetic.** Montgomery multiplication with R = 2^16 on signed
//! representatives, Barrett reduction to [0, q] (the pq-crystals AVX2
//! formulation: `mulhi` by 20159, shift 10), and a conditional subtraction
//! to [0, q) wherever a canonical value is needed (encoding, compression).
//! Every function here is constant-time in its inputs: no branch and no
//! memory index depends on a coefficient. The single exception is
//! `rejUniform`, whose input (the matrix seed rho) is public.
//!
//! Coefficient bounds are stated at each function; `ntt` takes |a| < q
//! (small noise, or decompressed values in [0, q)) and its seven
//! unreduced layers stay below 8q = 26632 < 2^15.

const std = @import("std");

pub const n: usize = 256;
pub const q: i16 = 3329;
/// q^-1 mod 2^16, as a signed 16-bit value.
const qinv: i16 = -3327;
/// 2^16 mod q, centred.
const mont: i16 = -1044;
/// 2^32 mod q: `fqmul(a, r2)` brings a into the Montgomery domain.
const r2: i16 = 1353;
/// R^2 / 128 mod q: the final scaling of the inverse NTT (leaves a factor R
/// that cancels the R^-1 of `basemul`).
const f_inv: i16 = 1441;
/// round(2^26 / q): Barrett constant for `mulhi` + arithmetic shift by 10.
const barrett_v: i16 = 20159;

pub const V = @Vector(16, i16);
const W = @Vector(16, i32);
const U64x4 = @Vector(4, u64);
const U32x8 = @Vector(8, u32);

inline fn sp(x: i16) V {
    return @splat(x);
}

/// High 16 bits of the 32-bit signed products (vpmulhw).
inline fn mulhi(a: V, b: V) V {
    const p: W = @as(W, a) * @as(W, b);
    return @truncate(p >> @splat(16));
}

/// Montgomery product a·b·2^-16 mod q with `bq` = b·q^-1 mod 2^16
/// precomputed. Needs |a·b| < q·2^15; returns |r| < q.
inline fn fqmulPre(a: V, b: V, bq: V) V {
    return mulhi(a, b) -% mulhi(a *% bq, sp(q));
}

inline fn fqmul(a: V, b: V) V {
    return fqmulPre(a, b, b *% sp(qinv));
}

/// Barrett reduction of any i16 to a representative in [0, q].
inline fn barrett(a: V) V {
    const t = mulhi(a, sp(barrett_v)) >> @splat(10);
    return a -% t *% sp(q);
}

/// [0, 2q) → [0, q).
inline fn csubq(a: V) V {
    const t = a -% sp(q);
    return t +% ((t >> @splat(15)) & sp(q));
}

// ---------------------------------------------------------------- zetas --

fn powMod(base: i32, e: u32) i32 {
    var r: i32 = 1;
    var b: i32 = @mod(base, q);
    var k = e;
    while (k != 0) : (k >>= 1) {
        if (k & 1 == 1) r = @mod(r * b, q);
        b = @mod(b * b, q);
    }
    return r;
}

fn centre(x: i32) i16 {
    const m = @mod(x, q);
    return @intCast(if (m > q / 2) m - q else m);
}

/// zetas[i] = 17^BitRev7(i) · 2^16 mod q, centred (the pq-crystals table).
pub const zetas: [128]i16 = blk: {
    @setEvalBranchQuota(100_000);
    var z: [128]i16 = undefined;
    for (0..128) |i| {
        const br = @bitReverse(@as(u7, @intCast(i)));
        z[i] = centre(powMod(17, br) * 65536);
    }
    break :blk z;
};

fn zetaVec(comptime k: usize) V {
    return sp(zetas[k]);
}

fn zetaQinvVec(comptime k: usize) V {
    return sp(zetas[k] *% qinv);
}

// ------------------------------------------------------------- shuffles --
//
// The three in-register layers of the NTT pair lanes 8, 4 and 2 apart.
// Each takes the two vectors x, y of a 32-coefficient block and splits
// them into `lo` (butterfly tops) and `hi` (bottoms); applying the same
// split to (lo, hi) restores (x, y). The patterns are the AVX2-native
// ones: 128-bit halves (vperm2i128), 64-bit and 32-bit interleaves.

inline fn split8(x: V, y: V) [2]V {
    const a: U64x4 = @bitCast(x);
    const b: U64x4 = @bitCast(y);
    const lo = @shuffle(u64, a, b, [4]i32{ 0, 1, ~@as(i32, 0), ~@as(i32, 1) });
    const hi = @shuffle(u64, a, b, [4]i32{ 2, 3, ~@as(i32, 2), ~@as(i32, 3) });
    return .{ @bitCast(lo), @bitCast(hi) };
}

inline fn split4(x: V, y: V) [2]V {
    const a: U64x4 = @bitCast(x);
    const b: U64x4 = @bitCast(y);
    const lo = @shuffle(u64, a, b, [4]i32{ 0, ~@as(i32, 0), 2, ~@as(i32, 2) });
    const hi = @shuffle(u64, a, b, [4]i32{ 1, ~@as(i32, 1), 3, ~@as(i32, 3) });
    return .{ @bitCast(lo), @bitCast(hi) };
}

inline fn split2(x: V, y: V) [2]V {
    const a: U32x8 = @bitCast(x);
    const b: U32x8 = @bitCast(y);
    const lo = @shuffle(u32, a, b, [8]i32{ 0, ~@as(i32, 0), 2, ~@as(i32, 2), 4, ~@as(i32, 4), 6, ~@as(i32, 6) });
    const hi = @shuffle(u32, a, b, [8]i32{ 1, ~@as(i32, 1), 3, ~@as(i32, 3), 5, ~@as(i32, 5), 7, ~@as(i32, 7) });
    return .{ @bitCast(lo), @bitCast(hi) };
}

inline fn split(comptime len: usize, x: V, y: V) [2]V {
    return switch (len) {
        8 => split8(x, y),
        4 => split4(x, y),
        2 => split2(x, y),
        else => @compileError("split: len must be 8, 4 or 2"),
    };
}

/// Natural block (x = coefficients 0..15, y = 16..31) → (evens, odds).
inline fn deinterleave(x: V, y: V) [2]V {
    comptime var ev: [16]i32 = undefined;
    comptime var od: [16]i32 = undefined;
    inline for (0..16) |l| {
        const e = 2 * l;
        const o = 2 * l + 1;
        ev[l] = if (e < 16) e else ~@as(i32, e - 16);
        od[l] = if (o < 16) o else ~@as(i32, o - 16);
    }
    return .{ @shuffle(i16, x, y, ev), @shuffle(i16, x, y, od) };
}

/// (evens, odds) → natural block (x, y).
inline fn interleave(e: V, o: V) [2]V {
    comptime var xm: [16]i32 = undefined;
    comptime var ym: [16]i32 = undefined;
    inline for (0..16) |l| {
        const lx = l / 2;
        const ly = 8 + l / 2;
        xm[l] = if (l % 2 == 0) lx else ~@as(i32, lx);
        ym[l] = if (l % 2 == 0) ly else ~@as(i32, ly);
    }
    return .{ @shuffle(i16, e, o, xm), @shuffle(i16, e, o, ym) };
}

/// Index (0..31) of the coefficient each lane of `hi` holds after
/// `split(len)` of a natural block.
fn hiIndex(comptime len: usize) [16]usize {
    var x: V = undefined;
    var y: V = undefined;
    for (0..16) |l| {
        x[l] = @intCast(l);
        y[l] = @intCast(16 + l);
    }
    const s = split(len, x, y);
    var out: [16]usize = undefined;
    for (0..16) |l| out[l] = @intCast(s[1][l]);
    return out;
}

/// Per-block zeta vectors of the in-register layers: lane l of block i
/// gets the zeta of the butterfly group of coefficient 32i + hiIndex[l].
fn lowZetas(comptime len: usize, comptime inverse: bool) [8][2]V {
    @setEvalBranchQuota(100_000);
    const hi = hiIndex(len);
    var out: [8][2]V = undefined;
    for (0..8) |i| {
        for (0..16) |l| {
            const c = 32 * i + hi[l];
            const g = c / (2 * len);
            const k = if (inverse) 256 / len - 1 - g else 128 / len + g;
            out[i][0][l] = zetas[k];
            out[i][1][l] = zetas[k] *% qinv;
        }
    }
    return out;
}

const fwd8 = lowZetas(8, false);
const fwd4 = lowZetas(4, false);
const fwd2 = lowZetas(2, false);
const inv8 = lowZetas(8, true);
const inv4 = lowZetas(4, true);
const inv2 = lowZetas(2, true);

/// Base-case multiplication zetas in the NTT layout: lane l of block i is
/// residue pair p = 16i + l, whose modulus is X^2 − ζ^(2·BitRev7(p/2)+1)
/// with ζ = ±zetas[64 + p/2] (FIPS 203 Algorithm 11).
const base_zetas: [8][2]V = blk: {
    var out: [8][2]V = undefined;
    for (0..8) |i| {
        for (0..16) |l| {
            const p = 16 * i + l;
            const z = zetas[64 + p / 2];
            const zs: i16 = if (p % 2 == 0) z else -z;
            out[i][0][l] = zs;
            out[i][1][l] = zs *% qinv;
        }
    }
    break :blk out;
};

/// FIPS 203 NTT-order index j → position in the internal layout.
pub const ntt_pos: [256]u8 = blk: {
    var t: [256]u8 = undefined;
    for (0..256) |j| {
        const b = j / 32;
        const r = j % 32;
        t[j] = @intCast(32 * b + (if (r % 2 == 1) 16 else 0) + r / 2);
    }
    break :blk t;
};

// ----------------------------------------------------------------- Poly --

pub const Poly = struct {
    // Zig 0.17.0 on aarch64 lost the error of an error union whose payload
    // held this (#37110; `SecretKey.fromBytes` accepted every bad key) and
    // needed `align(32)` here; 0.17.1 fixed it. The bad-key tests guard it.
    v: [16]V,

    pub const zero: Poly = .{ .v = @splat(@as(V, @splat(0))) };

    pub fn coeffs(p: *Poly) *[256]i16 {
        return @ptrCast(&p.v);
    }

    pub fn coeffsConst(p: *const Poly) *const [256]i16 {
        return @ptrCast(&p.v);
    }

    pub fn add(a: Poly, b: Poly) Poly {
        var r: Poly = undefined;
        inline for (0..16) |i| r.v[i] = a.v[i] +% b.v[i];
        return r;
    }

    pub fn sub(a: Poly, b: Poly) Poly {
        var r: Poly = undefined;
        inline for (0..16) |i| r.v[i] = a.v[i] -% b.v[i];
        return r;
    }

    /// Barrett-reduce every coefficient to [0, q].
    pub fn reduce(p: *Poly) void {
        inline for (0..16) |i| p.v[i] = barrett(p.v[i]);
    }

    /// Reduce every coefficient to the canonical [0, q).
    pub fn normalize(p: *Poly) void {
        inline for (0..16) |i| p.v[i] = csubq(barrett(p.v[i]));
    }

    /// Multiply by R (into the Montgomery domain); |r| < q.
    pub fn toMont(p: *Poly) void {
        const c = sp(r2);
        const cq = sp(r2 *% qinv);
        inline for (0..16) |i| p.v[i] = fqmulPre(p.v[i], c, cq);
    }

    /// Forward NTT (FIPS 203 Algorithm 9) into the internal NTT layout.
    /// Input |a| < q; output in [0, q].
    pub fn ntt(p: *Poly) void {
        // Layers len = 128 .. 16: whole vectors, one broadcast zeta per group.
        comptime var k: usize = 1;
        inline for ([_]usize{ 128, 64, 32, 16 }) |len| {
            const lv = len / 16;
            inline for (0..128 / len) |g| {
                const z = zetaVec(k);
                const zq = zetaQinvVec(k);
                k += 1;
                inline for (0..lv) |o| {
                    const ia = g * 2 * lv + o;
                    const ib = ia + lv;
                    const t = fqmulPre(p.v[ib], z, zq);
                    p.v[ib] = p.v[ia] -% t;
                    p.v[ia] = p.v[ia] +% t;
                }
            }
        }
        // Layers len = 8, 4, 2 inside each 32-coefficient block.
        inline for (0..8) |i| {
            var x = p.v[2 * i];
            var y = p.v[2 * i + 1];
            inline for (.{ .{ 8, fwd8 }, .{ 4, fwd4 }, .{ 2, fwd2 } }) |layer| {
                const s = split(layer[0], x, y);
                const t = fqmulPre(s[1], layer[1][i][0], layer[1][i][1]);
                const lo = s[0] +% t;
                const hi = s[0] -% t;
                const b = split(layer[0], lo, hi);
                x = b[0];
                y = b[1];
            }
            const d = deinterleave(barrett(x), barrett(y));
            p.v[2 * i] = d[0];
            p.v[2 * i + 1] = d[1];
        }
    }

    /// Inverse NTT (FIPS 203 Algorithm 10) from the internal NTT layout,
    /// times R (cancelling `basemul`'s R^-1). Input |a| ≤ q; output |r| < q.
    pub fn invNtt(p: *Poly) void {
        inline for (0..8) |i| {
            const nat = interleave(p.v[2 * i], p.v[2 * i + 1]);
            var x = nat[0];
            var y = nat[1];
            inline for (.{ .{ 2, inv2 }, .{ 4, inv4 }, .{ 8, inv8 } }) |layer| {
                const s = split(layer[0], x, y);
                const lo = barrett(s[0] +% s[1]);
                const hi = fqmulPre(s[1] -% s[0], layer[1][i][0], layer[1][i][1]);
                const b = split(layer[0], lo, hi);
                x = b[0];
                y = b[1];
            }
            p.v[2 * i] = x;
            p.v[2 * i + 1] = y;
        }
        inline for ([_]usize{ 16, 32, 64, 128 }) |len| {
            const lv = len / 16;
            inline for (0..128 / len) |g| {
                const k = 256 / len - 1 - g;
                const z = zetaVec(k);
                const zq = zetaQinvVec(k);
                inline for (0..lv) |o| {
                    const ia = g * 2 * lv + o;
                    const ib = ia + lv;
                    const a = p.v[ia];
                    const b = p.v[ib];
                    p.v[ia] = barrett(a +% b);
                    p.v[ib] = fqmulPre(b -% a, z, zq);
                }
            }
        }
        const f = sp(f_inv);
        const fq = sp(f_inv *% qinv);
        inline for (0..16) |i| p.v[i] = fqmulPre(p.v[i], f, fq);
    }

    /// r += a ∘ b (FIPS 203 Algorithm 11, times R^-1), both in the NTT
    /// layout with |coefficient| ≤ q. Each call adds less than 2q in
    /// absolute value per coefficient; callers reduce after at most 4.
    pub fn baseMulAcc(r: *Poly, a: *const Poly, b: *const Poly) void {
        inline for (0..8) |i| {
            const ae = a.v[2 * i];
            const ao = a.v[2 * i + 1];
            const be = b.v[2 * i];
            const bo = b.v[2 * i + 1];
            const oo = fqmul(ao, bo);
            const re = fqmulPre(oo, base_zetas[i][0], base_zetas[i][1]) +% fqmul(ae, be);
            const ro = fqmul(ae, bo) +% fqmul(ao, be);
            r.v[2 * i] +%= re;
            r.v[2 * i + 1] +%= ro;
        }
    }

    // ------------------------------------------------------- encodings --

    /// FIPS 203 NTT order → internal layout (deinterleave every block).
    pub fn fromNttOrder(p: *Poly) void {
        inline for (0..8) |i| {
            const d = deinterleave(p.v[2 * i], p.v[2 * i + 1]);
            p.v[2 * i] = d[0];
            p.v[2 * i + 1] = d[1];
        }
    }

    /// Internal layout → FIPS 203 NTT order.
    pub fn toNttOrder(p: *Poly) void {
        inline for (0..8) |i| {
            const d = interleave(p.v[2 * i], p.v[2 * i + 1]);
            p.v[2 * i] = d[0];
            p.v[2 * i + 1] = d[1];
        }
    }

    /// ByteEncode_12 of an NTT-domain polynomial with coefficients in
    /// [0, q), in FIPS 203 order.
    pub fn toNttBytes(p: *const Poly, out: *[384]u8) void {
        var t = p.*;
        t.toNttOrder();
        const c = t.coeffsConst();
        for (0..128) |i| {
            const a: u16 = @bitCast(c[2 * i]);
            const b: u16 = @bitCast(c[2 * i + 1]);
            out[3 * i] = @truncate(a);
            out[3 * i + 1] = @truncate((a >> 8) | (b << 4));
            out[3 * i + 2] = @truncate(b >> 4);
        }
    }

    /// ByteDecode_12 into the NTT layout. Returns false when a coefficient
    /// is ≥ q (FIPS 203 §7.2 modulus check). Constant-time in the data.
    pub fn fromNttBytes(p: *Poly, in: *const [384]u8) bool {
        const c = p.coeffs();
        var bad: u16 = 0;
        for (0..128) |i| {
            const b0: u16 = in[3 * i];
            const b1: u16 = in[3 * i + 1];
            const b2: u16 = in[3 * i + 2];
            const a = b0 | ((b1 & 0x0f) << 8);
            const b = (b1 >> 4) | (b2 << 4);
            // (a - q) >> 15 is 1 exactly when a < q.
            bad |= ((a -% 3329) >> 15) ^ 1;
            bad |= ((b -% 3329) >> 15) ^ 1;
            c[2 * i] = @bitCast(a);
            c[2 * i + 1] = @bitCast(b);
        }
        p.fromNttOrder();
        return bad == 0;
    }

    /// Compress_d then ByteEncode_d of a normal-domain polynomial with
    /// coefficients in [0, q) (FIPS 203 §4.2.1), d ∈ {1, 4, 5, 10, 11}.
    /// Works on byte-aligned groups of `group(d)` coefficients (d·g bits,
    /// at most 88) assembled in a u128, so the loop has no bit cursor.
    pub fn compress(p: *const Poly, comptime d: u4, out: *[32 * @as(usize, d)]u8) void {
        const c = p.coeffsConst();
        const g = comptime group(d);
        const gb = g * @as(usize, d) / 8;
        for (0..256 / g) |i| {
            var acc: u128 = 0;
            inline for (0..g) |j| acc |= @as(u128, compressCoeff(d, c[g * i + j])) << (d * j);
            inline for (0..gb) |b| out[gb * i + b] = @truncate(acc >> (8 * b));
        }
    }

    /// ByteDecode_d then Decompress_d into the normal domain, [0, q).
    pub fn decompress(p: *Poly, comptime d: u4, in: *const [32 * @as(usize, d)]u8) void {
        const c = p.coeffs();
        const g = comptime group(d);
        const gb = g * @as(usize, d) / 8;
        const mask: u32 = (@as(u32, 1) << d) - 1;
        for (0..256 / g) |i| {
            var acc: u128 = 0;
            inline for (0..gb) |b| acc |= @as(u128, in[gb * i + b]) << (8 * b);
            inline for (0..g) |j| {
                const y: u32 = @as(u32, @truncate(acc >> (d * j))) & mask;
                c[g * i + j] = @intCast((y * 3329 + (@as(u32, 1) << (d - 1))) >> d);
            }
        }
    }

    /// Decompress_1 of a 32-byte message: bit b → b · 1665.
    pub fn fromMsg(p: *Poly, m: *const [32]u8) void {
        const c = p.coeffs();
        for (0..256) |i| {
            const bit: i16 = @intCast((m[i / 8] >> @intCast(i % 8)) & 1);
            c[i] = (-bit) & 1665;
        }
    }

    /// Encode_1(Compress_1(p)) for coefficients in [0, q).
    pub fn toMsg(p: *const Poly, out: *[32]u8) void {
        p.compress(1, out);
    }

    // ------------------------------------------------------- sampling --

    /// SamplePolyCBD_eta (FIPS 203 Algorithm 8) from 64·eta bytes into the
    /// normal domain; coefficients in [−eta, eta].
    pub fn cbd(p: *Poly, comptime eta: u2, buf: *const [64 * @as(usize, eta)]u8) void {
        const c = p.coeffs();
        switch (eta) {
            2 => for (0..32) |i| {
                const t = std.mem.readInt(u32, buf[4 * i ..][0..4], .little);
                var d = t & 0x55555555;
                d +%= (t >> 1) & 0x55555555;
                inline for (0..8) |j| {
                    const a: i16 = @intCast((d >> (4 * j)) & 3);
                    const b: i16 = @intCast((d >> (4 * j + 2)) & 3);
                    c[8 * i + j] = a - b;
                }
            },
            3 => for (0..64) |i| {
                const t: u32 = @as(u32, buf[3 * i]) | (@as(u32, buf[3 * i + 1]) << 8) | (@as(u32, buf[3 * i + 2]) << 16);
                var d = t & 0x00249249;
                d +%= (t >> 1) & 0x00249249;
                d +%= (t >> 2) & 0x00249249;
                inline for (0..4) |j| {
                    const a: i16 = @intCast((d >> (6 * j)) & 7);
                    const b: i16 = @intCast((d >> (6 * j + 3)) & 7);
                    c[4 * i + j] = a - b;
                }
            },
            else => @compileError("cbd: eta must be 2 or 3"),
        }
    }
};

/// Compress_d(x) = round(2^d · x / q) mod 2^d for x in [0, q), without a
/// division: floor(t / q) = (t · ceil(2^36 / q)) >> 36 is exact for
/// t < 2^24 (error < 5e-5 < 1/q). Pinned exhaustively by a test.
pub inline fn compressCoeff(comptime d: u4, x: i16) u16 {
    const t: u64 = (@as(u64, @as(u16, @bitCast(x))) << d) + 1664;
    const quot = (t * 20642679) >> 36;
    return @truncate(quot & ((@as(u64, 1) << d) - 1));
}

/// Coefficients per byte-aligned group of d-bit values.
fn group(comptime d: u4) usize {
    return switch (d) {
        1, 5, 11 => 8,
        4 => 2,
        10 => 4,
        else => @compileError("compress: d must be 1, 4, 5, 10 or 11"),
    };
}

/// Room `rejUniform` needs past the 256 coefficients it keeps: one
/// 3-byte group writes two candidates before the count is checked.
pub const rej_slack = 2;

/// SampleNTT's rejection step (FIPS 203 Algorithm 7, lines 4–15) over a
/// squeezed XOF buffer: appends accepted values to `c` in FIPS 203 order
/// from `ctr_in`, returns the new count (≥ 256 means done; entries past
/// 255 are scratch). Branch-free per candidate — the store always happens
/// and the count advances by the comparison — so the accept pattern costs
/// no mispredictions. Vartime in the loop length only; rho is public.
pub fn rejUniform(c: *[256 + rej_slack]i16, ctr_in: usize, buf: []const u8) usize {
    var ctr = ctr_in;
    var i: usize = 0;
    while (ctr < 256 and i + 3 <= buf.len) : (i += 3) {
        const b0: u16 = buf[i];
        const b1: u16 = buf[i + 1];
        const b2: u16 = buf[i + 2];
        const d1 = b0 | ((b1 & 0x0f) << 8);
        const d2 = (b1 >> 4) | (b2 << 4);
        c[ctr] = @bitCast(d1);
        ctr += @intFromBool(d1 < 3329);
        c[ctr] = @bitCast(d2);
        ctr += @intFromBool(d2 < 3329);
    }
    return ctr;
}

// ---------------------------------------------------------------- tests --

const testing = std.testing;

/// Scalar reference: pq-crystals `ntt` + `poly_reduce` in FIPS order.
fn refNtt(a: *[256]i16) void {
    var k: usize = 1;
    var len: usize = 128;
    while (len >= 2) : (len >>= 1) {
        var start: usize = 0;
        while (start < 256) : (start += 2 * len) {
            const z: i32 = zetas[k];
            k += 1;
            for (start..start + len) |j| {
                const t = refMont(z * a[j + len]);
                a[j + len] = a[j] - t;
                a[j] = a[j] + t;
            }
        }
    }
}

fn refMont(x: i32) i16 {
    const lo: i16 = @truncate(x);
    const t: i16 = lo *% qinv;
    return @intCast((x - @as(i32, t) * q) >> 16);
}

fn modq(x: i32) i32 {
    return @mod(x, q);
}

test "zetas match the pq-crystals table head" {
    try testing.expectEqual(@as(i16, -1044), zetas[0]);
    try testing.expectEqual(@as(i16, -758), zetas[1]);
    try testing.expectEqual(@as(i16, -359), zetas[2]);
    try testing.expectEqual(@as(i16, -1517), zetas[3]);
    try testing.expectEqual(@as(i16, 1628), zetas[127]);
}

test "vector NTT equals the scalar reference, mod q, in FIPS order" {
    var prng = std.Random.DefaultPrng.init(0x5eed);
    const rnd = prng.random();
    for (0..200) |_| {
        var p: Poly = undefined;
        var ref: [256]i16 = undefined;
        for (0..256) |i| {
            const x = rnd.intRangeAtMost(i16, -(q - 1), q - 1);
            p.coeffs()[i] = x;
            ref[i] = x;
        }
        p.ntt();
        refNtt(&ref);
        for (0..256) |j| {
            const got = p.coeffs()[ntt_pos[j]];
            try testing.expect(got >= 0 and got <= q);
            try testing.expectEqual(modq(ref[j]), modq(got));
        }
    }
}

test "invNtt(ntt(a)) = a·R mod q" {
    var prng = std.Random.DefaultPrng.init(7);
    const rnd = prng.random();
    for (0..200) |_| {
        var p: Poly = undefined;
        var orig: [256]i16 = undefined;
        for (0..256) |i| {
            const x = rnd.intRangeAtMost(i16, -(q - 1), q - 1);
            p.coeffs()[i] = x;
            orig[i] = x;
        }
        p.ntt();
        p.invNtt();
        for (0..256) |i| {
            const got = p.coeffs()[i];
            try testing.expect(got > -q and got < q);
            try testing.expectEqual(modq(@as(i32, orig[i]) * 65536), modq(got));
        }
    }
}

/// Schoolbook product in Z_q[X]/(X^256+1).
fn schoolbook(a: *const [256]i16, b: *const [256]i16, out: *[256]i32) void {
    @memset(out, 0);
    for (0..256) |i| {
        for (0..256) |j| {
            const prod = modq(@as(i32, a[i]) * b[j]);
            if (i + j < 256) {
                out[i + j] = modq(out[i + j] + prod);
            } else {
                out[i + j - 256] = modq(out[i + j - 256] - prod);
            }
        }
    }
}

test "invNtt(ntt(a) ∘ ntt(b)) is the negacyclic product" {
    var prng = std.Random.DefaultPrng.init(11);
    const rnd = prng.random();
    for (0..20) |_| {
        var a: Poly = undefined;
        var b: Poly = undefined;
        var ra: [256]i16 = undefined;
        var rb: [256]i16 = undefined;
        for (0..256) |i| {
            ra[i] = rnd.intRangeAtMost(i16, 0, q - 1);
            rb[i] = rnd.intRangeAtMost(i16, -3, 3);
            a.coeffs()[i] = ra[i];
            b.coeffs()[i] = rb[i];
        }
        var want: [256]i32 = undefined;
        schoolbook(&ra, &rb, &want);
        a.ntt();
        b.ntt();
        var r: Poly = .zero;
        r.baseMulAcc(&a, &b);
        r.reduce();
        r.invNtt();
        for (0..256) |i| try testing.expectEqual(want[i], modq(r.coeffs()[i]));
    }
}

test "compressCoeff equals the exact rounding for every x and d" {
    inline for ([_]u4{ 1, 4, 5, 10, 11 }) |d| {
        for (0..3329) |x| {
            const exact: u64 = (((@as(u64, x) << d) + 1664) / 3329) & ((@as(u64, 1) << d) - 1);
            try testing.expectEqual(exact, compressCoeff(d, @intCast(x)));
        }
    }
}

test "12-bit NTT encoding round-trips and rejects coefficients ≥ q" {
    var prng = std.Random.DefaultPrng.init(3);
    const rnd = prng.random();
    var bytes: [384]u8 = undefined;
    var p: Poly = undefined;
    for (0..256) |i| p.coeffs()[i] = rnd.intRangeAtMost(i16, 0, q - 1);
    p.toNttBytes(&bytes);
    var p2: Poly = undefined;
    try testing.expect(p2.fromNttBytes(&bytes));
    try testing.expectEqualSlices(i16, p.coeffs(), p2.coeffs());
    // 3329 in the first slot: low byte 0x01, high nibble 0xD.
    bytes[0] = 0x01;
    bytes[1] = (bytes[1] & 0xf0) | 0x0d;
    try testing.expect(!p2.fromNttBytes(&bytes));
}

test "decompress(compress(x)) stays within the FIPS 203 rounding error" {
    var prng = std.Random.DefaultPrng.init(5);
    const rnd = prng.random();
    inline for ([_]u4{ 1, 4, 5, 10, 11 }) |d| {
        var p: Poly = undefined;
        for (0..256) |i| p.coeffs()[i] = rnd.intRangeAtMost(i16, 0, q - 1);
        var buf: [32 * @as(usize, d)]u8 = undefined;
        p.compress(d, &buf);
        var r: Poly = undefined;
        r.decompress(d, &buf);
        const bound: i32 = (q + (1 << d)) >> (d + 1); // round(q / 2^(d+1))
        for (0..256) |i| {
            var diff = @mod(@as(i32, r.coeffs()[i]) - p.coeffs()[i], q);
            if (diff > q / 2) diff -= q;
            try testing.expect(@abs(diff) <= bound);
        }
    }
}

test "decompress equals the exact Decompress_d rounding for every d-bit code" {
    inline for ([_]u4{ 1, 4, 5, 10, 11 }) |d| {
        const codes: usize = @as(usize, 1) << d;
        var base: usize = 0;
        while (base < codes) : (base += 256) {
            var buf: [32 * @as(usize, d)]u8 = @splat(0);
            var ys: [256]u64 = undefined;
            for (0..256) |i| {
                const y: u64 = (base + i) % codes;
                ys[i] = y;
                for (0..d) |bit| {
                    if ((y >> @intCast(bit)) & 1 == 1) {
                        const pos = i * d + bit;
                        buf[pos / 8] |= @as(u8, 1) << @intCast(pos % 8);
                    }
                }
            }
            var p: Poly = undefined;
            p.decompress(d, &buf);
            for (0..256) |i| {
                // round-half-up of q·y / 2^d, as one division-free expression
                const want = (2 * ys[i] * 3329 + (@as(u64, 1) << d)) >> (@as(u6, d) + 1);
                try testing.expectEqual(@as(i16, @intCast(want)), p.coeffs()[i]);
            }
        }
    }
}

test "rejUniform: stops at 256, stays inside the slack, ignores a trailing partial group" {
    var c: [256 + rej_slack]i16 = @splat(-1);
    // Zero candidates are always accepted (0 < q): two per 3-byte group.
    const zeros: [60]u8 = @splat(0);
    try testing.expectEqual(@as(usize, 256), rejUniform(&c, 250, &zeros));
    // From 255 one group writes two candidates before the count is checked.
    try testing.expectEqual(@as(usize, 256 + rej_slack - 1), rejUniform(&c, 255, &zeros));
    // 4 and 5 bytes hold one full group; the partial rest must not be read.
    try testing.expectEqual(@as(usize, 2), rejUniform(&c, 0, zeros[0..4]));
    try testing.expectEqual(@as(usize, 2), rejUniform(&c, 0, zeros[0..5]));
    try testing.expectEqual(@as(usize, 0), rejUniform(&c, 0, zeros[0..2]));
    // Decoding and the exact acceptance bound (candidate < q):
    // {01 23 45} = (769, 1106); {01 0D D0} = (3329 rejected, 3328 kept);
    // {00 10 D0} = (0 kept, 3329 rejected).
    const group_a = [3]u8{ 0x01, 0x23, 0x45 };
    try testing.expectEqual(@as(usize, 2), rejUniform(&c, 0, &group_a));
    try testing.expectEqual(@as(i16, 769), c[0]);
    try testing.expectEqual(@as(i16, 1106), c[1]);
    const group_b = [3]u8{ 0x01, 0x0d, 0xd0 };
    try testing.expectEqual(@as(usize, 1), rejUniform(&c, 0, &group_b));
    try testing.expectEqual(@as(i16, 3328), c[0]);
    const group_c = [3]u8{ 0x00, 0x10, 0xd0 };
    try testing.expectEqual(@as(usize, 1), rejUniform(&c, 0, &group_c));
    try testing.expectEqual(@as(i16, 0), c[0]);
}

// Tests added by the 2026-11-11 whole-module mutation run.

test "zetas equal the pq-crystals table entry by entry" {
    const want = [128]i16{
        -1044, -758,  -359,  -1517, 1493,  1422,  287,   202,
        -171,  622,   1577,  182,   962,   -1202, -1474, 1468,
        573,   -1325, 264,   383,   -829,  1458,  -1602, -130,
        -681,  1017,  732,   608,   -1542, 411,   -205,  -1571,
        1223,  652,   -552,  1015,  -1293, 1491,  -282,  -1544,
        516,   -8,    -320,  -666,  -1618, -1162, 126,   1469,
        -853,  -90,   -271,  830,   107,   -1421, -247,  -951,
        -398,  961,   -1508, -725,  448,   -1065, 677,   -1275,
        -1103, 430,   555,   843,   -1251, 871,   1550,  105,
        422,   587,   177,   -235,  -291,  -460,  1574,  1653,
        -246,  778,   1159,  -147,  -777,  1483,  -602,  1119,
        -1590, 644,   -872,  349,   418,   329,   -156,  -75,
        817,   1097,  603,   610,   1322,  -1285, -1465, 384,
        -1215, -136,  1218,  -1335, -874,  220,   -1187, -1659,
        -1185, -1530, -1278, 794,   -1510, -854,  -870,  478,
        -108,  -308,  996,   991,   958,   -1460, 1522,  1628,
    };
    try testing.expectEqualSlices(i16, &want, &zetas);
}

test "barrett maps every i16 into [0, q] congruently, and normalize into [0, q)" {
    var base: i32 = -32768;
    while (base < 32768) : (base += 16) {
        var xs: [16]i16 = undefined;
        for (0..16) |l| xs[l] = @intCast(base + @as(i32, @intCast(l)));
        const r: [16]i16 = barrett(xs);
        for (0..16) |l| {
            const a: i32 = xs[l];
            try testing.expect(r[l] >= 0 and r[l] <= q);
            try testing.expectEqual(@as(i32, 0), @mod(@as(i32, r[l]) - a, q));
        }
    }
    // The same through Poly.normalize: canonical, and equal to a mod q.
    var p: Poly = undefined;
    var v: i32 = -32768;
    while (v < 32768) {
        for (0..256) |i| {
            p.coeffs()[i] = @intCast(v);
            v += 1;
        }
        const orig = p.coeffsConst().*;
        p.normalize();
        for (0..256) |i| try testing.expectEqual(@as(i16, @intCast(@mod(@as(i32, orig[i]), q))), p.coeffsConst()[i]);
    }
}

test "csubq maps [0, 2q) onto [0, q) and Poly.reduce is barrett" {
    var a: i32 = 0;
    while (a < 2 * q) : (a += 16) {
        var xs: [16]i16 = undefined;
        for (0..16) |l| xs[l] = @intCast(@min(a + @as(i32, @intCast(l)), 2 * q - 1));
        const r: [16]i16 = csubq(xs);
        for (0..16) |l| try testing.expectEqual(@as(i16, @intCast(@mod(@as(i32, xs[l]), q))), r[l]);
    }
    var p: Poly = undefined;
    var ref: Poly = undefined;
    for (0..256) |i| p.coeffs()[i] = @intCast(@as(i32, @intCast(i)) * 257 - 32768);
    ref = p;
    p.reduce();
    inline for (0..16) |i| ref.v[i] = barrett(ref.v[i]);
    try testing.expectEqualSlices(i16, ref.coeffsConst(), p.coeffsConst());
}

test "Poly.add and Poly.sub are lane-wise wrapping +/-" {
    var a: Poly = undefined;
    var b: Poly = undefined;
    for (0..256) |i| {
        a.coeffs()[i] = @intCast(@as(i32, @intCast(i)) * 101 - 12000);
        b.coeffs()[i] = @intCast(@as(i32, @intCast(i)) * -37 + 5000);
    }
    const s = a.add(b);
    const d = a.sub(b);
    for (0..256) |i| {
        try testing.expectEqual(a.coeffsConst()[i] +% b.coeffsConst()[i], s.coeffsConst()[i]);
        try testing.expectEqual(a.coeffsConst()[i] -% b.coeffsConst()[i], d.coeffsConst()[i]);
    }
}

test "fromNttBytes decides every one of the 256 slots at the q boundary" {
    var p: Poly = undefined;
    for ([_]u16{ 0, 3328, 3329, 3330, 4000, 4095 }) |val| {
        for (0..256) |slot| {
            var bytes: [384]u8 = @splat(0);
            const pair = slot / 2;
            const lo = val & 0xff;
            const hi = val >> 8;
            if (slot % 2 == 0) {
                bytes[3 * pair] = @truncate(lo);
                bytes[3 * pair + 1] = @truncate(hi);
            } else {
                bytes[3 * pair + 1] = @truncate(lo << 4);
                bytes[3 * pair + 2] = @truncate((lo >> 4) | (hi << 4));
            }
            try testing.expectEqual(val < q, p.fromNttBytes(&bytes));
            // the decoded value sits at its FIPS 203 slot
            var back: [384]u8 = undefined;
            if (val < q) {
                p.toNttBytes(&back);
                try testing.expectEqualSlices(u8, &bytes, &back);
            }
        }
    }
}

test "fromMsg / toMsg: bit i of the message is coefficient i (0 or 1665) and back" {
    var p: Poly = undefined;
    var m: [32]u8 = undefined;
    for (0..256) |i| {
        m = @splat(0);
        m[i / 8] = @as(u8, 1) << @intCast(i % 8);
        p.fromMsg(&m);
        for (0..256) |j| try testing.expectEqual(@as(i16, if (i == j) 1665 else 0), p.coeffsConst()[j]);
        var back: [32]u8 = undefined;
        p.toMsg(&back);
        try testing.expectEqualSlices(u8, &m, &back);
    }
    m = @splat(0xff);
    p.fromMsg(&m);
    for (0..256) |j| try testing.expectEqual(@as(i16, 1665), p.coeffsConst()[j]);
}

test "Compress_1 is symmetric: x and q - x give the same bit, so decrypt may subtract either way" {
    try testing.expectEqual(@as(u16, 0), compressCoeff(1, 0));
    for (1..3329) |x| {
        try testing.expectEqual(compressCoeff(1, @intCast(x)), compressCoeff(1, @intCast(3329 - x)));
    }
}

test "baseMulAcc adds under 3700 per call: four calls and invNtt need no reduce in front (k <= 4)" {
    // Pins the bound behind the redundant `reduce` before invNtt (encrypt u and v,
    // decrypt w, keygen t): |fqmul| <= ~0.56 q for |a|, |b| <= q, so a call adds < 3700 per
    // coefficient and four calls stay below 14800, where invNtt's first layer (s0 + s1 < 29600)
    // and its Montgomery products still fit in i16.
    var prng = std.Random.DefaultPrng.init(0xb0d);
    const rnd = prng.random();
    var worst: i32 = 0;
    for (0..400) |round| {
        var acc: Poly = .zero;
        for (0..4) |_| {
            var a: Poly = undefined;
            var b: Poly = undefined;
            for (0..256) |i| {
                switch (round % 4) {
                    0 => {
                        a.coeffs()[i] = q;
                        b.coeffs()[i] = q;
                    },
                    1 => {
                        a.coeffs()[i] = if (rnd.boolean()) q else -q;
                        b.coeffs()[i] = if (rnd.boolean()) q else -q;
                    },
                    else => {
                        a.coeffs()[i] = rnd.intRangeAtMost(i16, -q, q);
                        b.coeffs()[i] = rnd.intRangeAtMost(i16, -q, q);
                    },
                }
            }
            acc.baseMulAcc(&a, &b);
        }
        for (acc.coeffsConst()) |c| {
            const mag: i32 = @intCast(@abs(@as(i32, c)));
            worst = @max(worst, mag);
        }
        var reduced = acc;
        reduced.reduce();
        var plain = acc;
        plain.invNtt();
        reduced.invNtt();
        for (0..256) |i| try testing.expectEqual(modq(reduced.coeffsConst()[i]), modq(plain.coeffsConst()[i]));
    }
    try testing.expect(worst < 4 * 3700);
}
