// SPDX-License-Identifier: MIT
//! ntru — NTRUGen + NTRUSolve, Falcon/FN-DSA key generation's
//! number-theoretic core (spec §3.8.1 Algorithm 5 `NTRUGen`, §3.8.2
//! Algorithm 6 `NTRUSolve`): sample a small secret pair (f, g), then
//! solve the NTRU equation f*G - g*F = q over Z[x]/(x^n+1) for the
//! co-basis (F, G).
//!
//! Ported faithfully from the Falcon Round-3 reference implementation's
//! `keygen.c` (Falcon-impl-20211101, falcon-sign.info; MIT license,
//! Copyright (c) 2017-2019 Falcon Project, author Thomas Pornin) so that
//! keygen is BYTE-EXACT against the NIST Round-3 KAT vectors:
//!
//!   * `mkgauss`/`polySmallMkgauss` — the keygen Gaussian sampler for
//!     (f, g), consuming the caller's RNG in 8-byte little-endian draws
//!     exactly like the reference's SHAKE256-backed `get_rng_u64` (the
//!     default, non-CHACHA20 build that produced the KATs).
//!   * The full acceptance loop — trimmed-encoding limit, integer
//!     ||(g,-f)||^2 < 16823, the FP Gram-Schmidt `bnorm` bound (through
//!     the byte-exact `fpr`/`fft` layers), f invertible mod q, and
//!     NTRUSolve solvability — with the reference's exact reject order,
//!     so the accepted (f, g) matches the vectors draw-for-draw.
//!   * `solveNtru*` — the tower-of-number-fields recursion: field norms
//!     down to degree 1 (`makeFg`), extended binary GCD over big
//!     integers at the bottom (`zintBezout`), lifting back up, and the
//!     FP-FFT-guided Babai reduction of (F, G) against (f, g). Big
//!     integers use the reference's own 31-bit-limb / RNS-CRT
//!     representation (`zint_*`/`modp_*` helpers ported 1:1) — NOT
//!     std.math.big — because the reduction's decisions read exact limb
//!     windows of those integers; keeping the representation keeps the
//!     decisions, and hence the final reduced (F, G), byte-identical.
//!
//! The only intentional divergence from the reference source: the
//! PRIMES table (522 hardcoded entries there) is generated at runtime in
//! `computePrimes` — the primes are "all primes p < 2^31 with
//! p = 1 mod 2048, in decreasing order", which is a canonical set, and
//! the CRT coefficient `s` is recomputed per its definition (checked
//! against the reference table's own values in a test below). The `g`
//! member (a 2048-th root of unity mod p) legitimately differs from the
//! reference's choice: it only parametrizes the *internal* NTT used to
//! multiply exactly mod p, and any valid root yields the same exact
//! products, so the CRT-rebuilt integers — the only thing downstream
//! code sees — are unchanged.
//!
//! Keygen runs once per key and, unlike signing's `gaussian.samplerZ`,
//! is not exposed to per-signature timing attacks; the reference's own
//! constant-time discipline for these routines is preserved by the 1:1
//! port, but no machine-checked constant-time verification has been run
//! (same caveat as gaussian.zig, lower stakes).

const std = @import("std");
const fpr = @import("fpr.zig");
const fft = @import("fft.zig");

// ---- fpr constants used only by keygen (exact reference fpr.h bits) ----

const fpr_ptwo31: f64 = @bitCast(@as(u64, 4746794007248502784)); // 2^31
const fpr_ptwo31m1: f64 = @bitCast(@as(u64, 4746794007244308480)); // 2^31-1
const fpr_mtwo31m1: f64 = @bitCast(@as(u64, 13970166044099084288)); // -(2^31-1)
const fpr_ptwo63m1: f64 = @bitCast(@as(u64, 4890909195324358656)); // 2^63-1 (rounded)
const fpr_mtwo63m1: f64 = @bitCast(@as(u64, 14114281232179134464)); // -(2^63-1) (rounded)
const fpr_bnorm_max: f64 = @bitCast(@as(u64, 4670353323383631276)); // 16822.4121

// ---- Small primes for the RNS/CRT big-integer arithmetic ----

/// Number of small primes generated; must cover the largest RNS width
/// used anywhere, which is MAX_BL_LARGE[9] = 308 limbs (Falcon-1024's
/// depth-9 unreduced F/G).
const NPRIMES = 320;

const SmallPrime = struct {
    /// The prime p itself: 2^30 < p < 2^31, p = 1 mod 2048.
    p: u32,
    /// A primitive 2048-th root of unity mod p (g^1024 = -1 mod p).
    g: u32,
    /// Montgomery representation of the inverse of the product of all
    /// previous primes in the array, mod p (the CRT lift coefficient).
    s: u32,
};

fn powMod(base: u64, exp: u32, p: u64) u64 {
    var r: u64 = 1;
    var b = base % p;
    var e = exp;
    while (e != 0) : (e >>= 1) {
        if (e & 1 != 0) r = r * b % p;
        b = b * b % p;
    }
    return r;
}

/// Deterministic Miller-Rabin for p < 2^31: bases {2, 3, 5, 7} are a
/// proven-complete witness set below 3,215,031,751 > 2^31.
fn isPrime31(p: u32) bool {
    if (p < 2) return false;
    for ([_]u32{ 2, 3, 5, 7 }) |sp| {
        if (p == sp) return true;
        if (p % sp == 0) return false;
    }
    var d: u32 = p - 1;
    var r: u6 = 0;
    while (d & 1 == 0) {
        d >>= 1;
        r += 1;
    }
    base: for ([_]u32{ 2, 3, 5, 7 }) |bb| {
        var x = powMod(bb, d, p);
        if (x == 1 or x == p - 1) continue;
        var i: u6 = 1;
        while (i < r) : (i += 1) {
            x = x * x % p;
            if (x == p - 1) continue :base;
        }
        return false;
    }
    return true;
}

/// Regenerate the reference's PRIMES table (see module doc comment for
/// why runtime generation is exact-equivalent to the hardcoded table).
fn computePrimes() [NPRIMES]SmallPrime {
    var out: [NPRIMES]SmallPrime = undefined;
    var idx: usize = 0;
    // Largest candidate = 1 mod 2048 below 2^31.
    var p: u32 = 2147481601;
    while (idx < NPRIMES) : (p -= 2048) {
        if (!isPrime31(p)) continue;
        // Find an element of order exactly 2048: x^((p-1)/2048) has
        // order dividing 2048; order is exactly 2048 iff its 1024-th
        // power is -1.
        var g: u32 = 0;
        var x: u32 = 2;
        while (true) : (x += 1) {
            const cand = powMod(x, (p - 1) / 2048, p);
            if (powMod(cand, 1024, p) == p - 1) {
                g = @intCast(cand);
                break;
            }
        }
        out[idx] = .{ .p = p, .g = g, .s = 0 };
        idx += 1;
    }
    // s = R * (product of previous primes)^-1 mod p, R = 2^31 mod p.
    out[0].s = modpR(out[0].p);
    for (1..NPRIMES) |i| {
        const pi: u64 = out[i].p;
        var prod: u64 = 1;
        for (0..i) |j| prod = prod * (out[j].p % pi) % pi;
        const inv = powMod(prod, out[i].p - 2, pi);
        out[i].s = @intCast((inv << 31) % pi);
    }
    return out;
}

// ---- Modular arithmetic mod one small prime (reference modp_*) ----

inline fn modpSet(x: i32, p: u32) u32 {
    var w: u32 = @bitCast(x);
    w +%= p & (0 -% (w >> 31));
    return w;
}

inline fn modpNorm(x: u32, p: u32) i32 {
    return @bitCast(x -% (p & (((x -% ((p + 1) >> 1)) >> 31) -% 1)));
}

fn modpNinv31(p: u32) u32 {
    var y: u32 = 2 -% p;
    y *%= 2 -% p *% y;
    y *%= 2 -% p *% y;
    y *%= 2 -% p *% y;
    y *%= 2 -% p *% y;
    return 0x7FFFFFFF & (0 -% y);
}

inline fn modpR(p: u32) u32 {
    return (@as(u32, 1) << 31) - p;
}

inline fn modpAdd(a: u32, b: u32, p: u32) u32 {
    var d = a +% b -% p;
    d +%= p & (0 -% (d >> 31));
    return d;
}

inline fn modpSub(a: u32, b: u32, p: u32) u32 {
    var d = a -% b;
    d +%= p & (0 -% (d >> 31));
    return d;
}

inline fn modpMontymul(a: u32, b: u32, p: u32, p0i: u32) u32 {
    const z = @as(u64, a) * @as(u64, b);
    const w = ((z *% @as(u64, p0i)) & 0x7FFFFFFF) * @as(u64, p);
    var d = @as(u32, @truncate((z + w) >> 31)) -% p;
    d +%= p & (0 -% (d >> 31));
    return d;
}

fn modpR2(p: u32, p0i: u32) u32 {
    var z = modpR(p);
    z = modpAdd(z, z, p);
    z = modpMontymul(z, z, p, p0i);
    z = modpMontymul(z, z, p, p0i);
    z = modpMontymul(z, z, p, p0i);
    z = modpMontymul(z, z, p, p0i);
    z = modpMontymul(z, z, p, p0i);
    z = (z + (p & (0 -% (z & 1)))) >> 1;
    return z;
}

/// 2^(31*x) mod p, 1 <= x < 2^11.
fn modpRx(x_in: u32, p: u32, p0i: u32, R2: u32) u32 {
    const x = x_in - 1;
    var r = R2;
    var z = modpR(p);
    var i: u5 = 0;
    while ((@as(u32, 1) << i) <= x) : (i += 1) {
        if ((x & (@as(u32, 1) << i)) != 0) z = modpMontymul(z, r, p, p0i);
        r = modpMontymul(r, r, p, p0i);
    }
    return z;
}

fn modpDiv(a: u32, b: u32, p: u32, p0i: u32, R: u32) u32 {
    const e = p - 2;
    var z = R;
    var i: i32 = 30;
    while (i >= 0) : (i -= 1) {
        z = modpMontymul(z, z, p, p0i);
        const z2 = modpMontymul(z, b, p, p0i);
        z ^= (z ^ z2) & (0 -% ((e >> @intCast(i)) & 1));
    }
    z = modpMontymul(z, 1, p, p0i);
    return modpMontymul(a, z, p, p0i);
}

/// 10-bit bit-reversal table (reference REV10), computed at comptime.
const REV10: [1024]u16 = blk: {
    @setEvalBranchQuota(30_000);
    var t: [1024]u16 = undefined;
    for (0..1024) |i| {
        var r: u32 = 0;
        var v: u32 = i;
        for (0..10) |_| {
            r = (r << 1) | (v & 1);
            v >>= 1;
        }
        t[i] = @intCast(r);
    }
    break :blk t;
};

/// Build NTT twiddle tables gm/igm for degree 2^logn from a primitive
/// 2048-th root g (reference modp_mkgm2). Values are in Montgomery rep.
fn modpMkgm2(gm: []u32, igm: []u32, logn: u5, g_in: u32, p: u32, p0i: u32) void {
    const n = @as(usize, 1) << logn;
    const R2 = modpR2(p, p0i);
    var g = modpMontymul(g_in, R2, p, p0i);
    var k: u5 = logn;
    while (k < 10) : (k += 1) g = modpMontymul(g, g, p, p0i);
    const ig = modpDiv(R2, g, p, p0i, modpR(p));
    const kk: u4 = @intCast(10 - @as(u32, logn));
    var x1 = modpR(p);
    var x2 = x1;
    for (0..n) |u| {
        const v = REV10[u << kk];
        gm[v] = x1;
        igm[v] = x2;
        x1 = modpMontymul(x1, g, p, p0i);
        x2 = modpMontymul(x2, ig, p, p0i);
    }
}

/// Forward NTT over a strided polynomial (reference modp_NTT2_ext).
fn modpNTT2Ext(a: []u32, stride: usize, gm: []const u32, logn: u5, p: u32, p0i: u32) void {
    if (logn == 0) return;
    const n = @as(usize, 1) << logn;
    var t = n;
    var m: usize = 1;
    while (m < n) : (m <<= 1) {
        const ht = t >> 1;
        var u: usize = 0;
        var v1: usize = 0;
        while (u < m) : ({
            u += 1;
            v1 += t;
        }) {
            const s = gm[m + u];
            var r1 = v1 * stride;
            var r2 = r1 + ht * stride;
            for (0..ht) |_| {
                const x = a[r1];
                const y = modpMontymul(a[r2], s, p, p0i);
                a[r1] = modpAdd(x, y, p);
                a[r2] = modpSub(x, y, p);
                r1 += stride;
                r2 += stride;
            }
        }
        t = ht;
    }
}

/// Inverse NTT over a strided polynomial (reference modp_iNTT2_ext).
fn modpINTT2Ext(a: []u32, stride: usize, igm: []const u32, logn: u5, p: u32, p0i: u32) void {
    if (logn == 0) return;
    const n = @as(usize, 1) << logn;
    var t: usize = 1;
    var m = n;
    while (m > 1) : (m >>= 1) {
        const hm = m >> 1;
        const dt = t << 1;
        var u: usize = 0;
        var v1: usize = 0;
        while (u < hm) : ({
            u += 1;
            v1 += dt;
        }) {
            const s = igm[hm + u];
            var r1 = v1 * stride;
            var r2 = r1 + t * stride;
            for (0..t) |_| {
                const x = a[r1];
                const y = a[r2];
                a[r1] = modpAdd(x, y, p);
                a[r2] = modpMontymul(modpSub(x, y, p), s, p, p0i);
                r1 += stride;
                r2 += stride;
            }
        }
        t = dt;
    }
    const ni = @as(u32, 1) << @intCast(31 - @as(u32, logn));
    var k: usize = 0;
    var r: usize = 0;
    while (k < n) : ({
        k += 1;
        r += stride;
    }) {
        a[r] = modpMontymul(a[r], ni, p, p0i);
    }
}

/// f (NTT rep, degree 2^logn) -> f0^2 - X*f1^2 (NTT rep, degree
/// 2^(logn-1)), written over the first half (reference modp_poly_rec_res).
fn modpPolyRecRes(f: []u32, logn: u5, p: u32, p0i: u32, R2: u32) void {
    const hn = @as(usize, 1) << @intCast(@as(u32, logn) - 1);
    for (0..hn) |u| {
        const w0 = f[(u << 1) + 0];
        const w1 = f[(u << 1) + 1];
        f[u] = modpMontymul(modpMontymul(w0, w1, p, p0i), R2, p, p0i);
    }
}

// ---- 31-bit-limb big integers (reference zint_*) ----

/// a -= b if ctl = 1 (memory access pattern independent of ctl); returns
/// the borrow.
fn zintSub(a: []u32, b: []const u32, ctl: u32) u32 {
    var cc: u32 = 0;
    const m = 0 -% ctl;
    for (a, b) |*aw_p, bw| {
        var aw = aw_p.*;
        const w = aw -% bw -% cc;
        cc = w >> 31;
        aw ^= ((w & 0x7FFFFFFF) ^ aw) & m;
        aw_p.* = aw;
    }
    return cc;
}

/// m *= x (x < 2^31); returns the carry word.
fn zintMulSmall(m: []u32, x: u32) u32 {
    var cc: u32 = 0;
    for (m) |*w| {
        const z = @as(u64, w.*) * @as(u64, x) + cc;
        w.* = @as(u32, @truncate(z)) & 0x7FFFFFFF;
        cc = @truncate(z >> 31);
    }
    return cc;
}

/// Unsigned big integer mod small prime p (R2 = 2^62 mod p).
fn zintModSmallUnsigned(d: []const u32, p: u32, p0i: u32, R2: u32) u32 {
    var x: u32 = 0;
    var u = d.len;
    while (u > 0) {
        u -= 1;
        x = modpMontymul(x, R2, p, p0i);
        var w = d[u] -% p;
        w +%= p & (0 -% (w >> 31));
        x = modpAdd(x, w, p);
    }
    return x;
}

/// Signed (two's complement) big integer mod p; Rx = 2^(31*dlen) mod p.
fn zintModSmallSigned(d: []const u32, p: u32, p0i: u32, R2: u32, Rx: u32) u32 {
    if (d.len == 0) return 0;
    var z = zintModSmallUnsigned(d, p, p0i, R2);
    z = modpSub(z, Rx & (0 -% (d[d.len - 1] >> 30)), p);
    return z;
}

/// x += y*s; x must be one limb longer than y (receives the carry).
fn zintAddMulSmall(x: []u32, y: []const u32, s: u32) void {
    const len = y.len;
    var cc: u32 = 0;
    for (0..len) |u| {
        const z = @as(u64, y[u]) * @as(u64, s) + @as(u64, x[u]) + @as(u64, cc);
        x[u] = @as(u32, @truncate(z)) & 0x7FFFFFFF;
        cc = @truncate(z >> 31);
    }
    x[len] = cc;
}

/// If x > p/2, replace x with x - p (two's complement).
fn zintNormZero(x: []u32, p: []const u32) void {
    var r: u32 = 0;
    var bb: u32 = 0;
    var u = x.len;
    while (u > 0) {
        u -= 1;
        const wx = x[u];
        const wp = (p[u] >> 1) | (bb << 30);
        bb = p[u] & 1;
        var cc = wp -% wx;
        cc = ((0 -% cc) >> 31) | (0 -% (cc >> 31));
        r |= cc & ((r & 1) -% 1);
    }
    _ = zintSub(x, p, r >> 31);
}

/// Rebuild `num` big integers (xlen limbs each, xstride apart in xx)
/// from their RNS residues (reference zint_rebuild_CRT). tmp needs xlen
/// limbs.
fn zintRebuildCRT(
    xx: []u32,
    xlen: usize,
    xstride: usize,
    num: usize,
    primes: []const SmallPrime,
    normalize_signed: bool,
    tmp: []u32,
) void {
    tmp[0] = primes[0].p;
    var u: usize = 1;
    while (u < xlen) : (u += 1) {
        const p = primes[u].p;
        const s = primes[u].s;
        const p0i = modpNinv31(p);
        const R2 = modpR2(p, p0i);
        var v: usize = 0;
        var xo: usize = 0;
        while (v < num) : ({
            v += 1;
            xo += xstride;
        }) {
            const xp = xx[xo + u];
            const xq = zintModSmallUnsigned(xx[xo .. xo + u], p, p0i, R2);
            const xr = modpMontymul(s, modpSub(xp, xq, p), p, p0i);
            zintAddMulSmall(xx[xo .. xo + u + 1], tmp[0..u], xr);
        }
        tmp[u] = zintMulSmall(tmp[0..u], p);
    }
    if (normalize_signed) {
        var v: usize = 0;
        var xo: usize = 0;
        while (v < num) : ({
            v += 1;
            xo += xstride;
        }) {
            zintNormZero(xx[xo .. xo + xlen], tmp[0..xlen]);
        }
    }
}

/// a = -a if ctl = 1.
fn zintNegate(a: []u32, ctl: u32) void {
    var cc: u32 = ctl;
    const m = (0 -% ctl) >> 1;
    for (a) |*w| {
        var aw = w.*;
        aw = (aw ^ m) +% cc;
        w.* = aw & 0x7FFFFFFF;
        cc = aw >> 31;
    }
}

/// a <- (a*xa + b*xb)/2^31, b <- (a*ya + b*yb)/2^31, negating results
/// that come out negative; returns which were negated (bit0 = a, bit1 = b).
fn zintCoReduce(a: []u32, b: []u32, xa: i64, xb: i64, ya: i64, yb: i64) u32 {
    const len = a.len;
    const uxa: u64 = @bitCast(xa);
    const uxb: u64 = @bitCast(xb);
    const uya: u64 = @bitCast(ya);
    const uyb: u64 = @bitCast(yb);
    var cca: i64 = 0;
    var ccb: i64 = 0;
    for (0..len) |u| {
        const wa: u64 = a[u];
        const wb: u64 = b[u];
        const za = wa *% uxa +% wb *% uxb +% @as(u64, @bitCast(cca));
        const zb = wa *% uya +% wb *% uyb +% @as(u64, @bitCast(ccb));
        if (u > 0) {
            a[u - 1] = @as(u32, @truncate(za)) & 0x7FFFFFFF;
            b[u - 1] = @as(u32, @truncate(zb)) & 0x7FFFFFFF;
        }
        cca = @as(i64, @bitCast(za)) >> 31;
        ccb = @as(i64, @bitCast(zb)) >> 31;
    }
    a[len - 1] = @truncate(@as(u64, @bitCast(cca)));
    b[len - 1] = @truncate(@as(u64, @bitCast(ccb)));
    const nega: u32 = @truncate(@as(u64, @bitCast(cca)) >> 63);
    const negb: u32 = @truncate(@as(u64, @bitCast(ccb)) >> 63);
    zintNegate(a, nega);
    zintNegate(b, negb);
    return nega | (negb << 1);
}

/// Finish Montgomery reduction: -m <= a < 0 (neg = 1) or 0 <= a < 2m
/// (neg = 0) -> canonical 0 <= a < m.
fn zintFinishMod(a: []u32, m: []const u32, neg: u32) void {
    var cc: u32 = 0;
    for (a, m) |aw, mw| {
        cc = (aw -% mw -% cc) >> 31;
    }
    const xm = (0 -% neg) >> 1;
    const ym = 0 -% (neg | (1 -% cc));
    cc = neg;
    for (a, m) |*aw_p, mw_in| {
        var aw = aw_p.*;
        const mw = (mw_in ^ xm) & ym;
        aw = aw -% mw -% cc;
        aw_p.* = aw & 0x7FFFFFFF;
        cc = aw >> 31;
    }
}

/// a <- (a*xa + b*xb)/2^31 mod m, b <- (a*ya + b*yb)/2^31 mod m.
fn zintCoReduceMod(a: []u32, b: []u32, m: []const u32, m0i: u32, xa: i64, xb: i64, ya: i64, yb: i64) void {
    const len = m.len;
    const uxa: u64 = @bitCast(xa);
    const uxb: u64 = @bitCast(xb);
    const uya: u64 = @bitCast(ya);
    const uyb: u64 = @bitCast(yb);
    var cca: i64 = 0;
    var ccb: i64 = 0;
    const fa = ((a[0] *% @as(u32, @truncate(uxa)) +% b[0] *% @as(u32, @truncate(uxb))) *% m0i) & 0x7FFFFFFF;
    const fb = ((a[0] *% @as(u32, @truncate(uya)) +% b[0] *% @as(u32, @truncate(uyb))) *% m0i) & 0x7FFFFFFF;
    for (0..len) |u| {
        const wa: u64 = a[u];
        const wb: u64 = b[u];
        const za = wa *% uxa +% wb *% uxb +% @as(u64, m[u]) *% @as(u64, fa) +% @as(u64, @bitCast(cca));
        const zb = wa *% uya +% wb *% uyb +% @as(u64, m[u]) *% @as(u64, fb) +% @as(u64, @bitCast(ccb));
        if (u > 0) {
            a[u - 1] = @as(u32, @truncate(za)) & 0x7FFFFFFF;
            b[u - 1] = @as(u32, @truncate(zb)) & 0x7FFFFFFF;
        }
        cca = @as(i64, @bitCast(za)) >> 31;
        ccb = @as(i64, @bitCast(zb)) >> 31;
    }
    a[len - 1] = @truncate(@as(u64, @bitCast(cca)));
    b[len - 1] = @truncate(@as(u64, @bitCast(ccb)));
    zintFinishMod(a, m, @truncate(@as(u64, @bitCast(cca)) >> 63));
    zintFinishMod(b, m, @truncate(@as(u64, @bitCast(ccb)) >> 63));
}

/// Extended binary GCD: on success (GCD(x,y) = 1, x and y odd) fills
/// u_arr/v_arr with 0 <= u <= y, 0 <= v <= x such that x*u - y*v = 1.
/// tmp needs 4*len limbs.
fn zintBezout(u_arr: []u32, v_arr: []u32, x: []const u32, y: []const u32, tmp: []u32) bool {
    const len = x.len;
    if (len == 0) return false;
    const bu0 = u_arr;
    const bv0 = v_arr;
    const bu1 = tmp[0..len];
    const bv1 = tmp[len .. 2 * len];
    const a = tmp[2 * len .. 3 * len];
    const b = tmp[3 * len .. 4 * len];
    const x0i = modpNinv31(x[0]);
    const y0i = modpNinv31(y[0]);
    @memcpy(a, x);
    @memcpy(b, y);
    bu0[0] = 1;
    @memset(bu0[1..], 0);
    @memset(bv0, 0);
    @memcpy(bu1, y);
    @memcpy(bv1, x);
    bv1[0] -%= 1;

    var num: u32 = @intCast(62 * len + 30);
    while (num >= 30) : (num -= 30) {
        // Extract the top words of a and b.
        var c0: u32 = 0xFFFFFFFF;
        var c1: u32 = 0xFFFFFFFF;
        var a0: u32 = 0;
        var a1: u32 = 0;
        var b0: u32 = 0;
        var b1: u32 = 0;
        var j = len;
        while (j > 0) {
            j -= 1;
            const aw = a[j];
            const bw = b[j];
            a0 ^= (a0 ^ aw) & c0;
            a1 ^= (a1 ^ aw) & c1;
            b0 ^= (b0 ^ bw) & c0;
            b1 ^= (b1 ^ bw) & c1;
            c1 = c0;
            c0 &= (((aw | bw) +% 0x7FFFFFFF) >> 31) -% 1;
        }
        a1 |= a0 & c1;
        a0 &= ~c1;
        b1 |= b0 & c1;
        b0 &= ~c1;
        var a_hi: u64 = (@as(u64, a0) << 31) + a1;
        var b_hi: u64 = (@as(u64, b0) << 31) + b1;
        var a_lo: u32 = a[0];
        var b_lo: u32 = b[0];

        var pa: i64 = 1;
        var pb: i64 = 0;
        var qa: i64 = 0;
        var qb: i64 = 1;
        var i: u5 = 0;
        while (i < 31) : (i += 1) {
            const rz = b_hi -% a_hi;
            const rt: u32 = @truncate((rz ^ ((a_hi ^ b_hi) & (a_hi ^ rz))) >> 63);
            const oa: u32 = (a_lo >> i) & 1;
            const ob: u32 = (b_lo >> i) & 1;
            const cAB: u32 = oa & ob & rt;
            const cBA: u32 = oa & ob & ~rt;
            const cA: u32 = cAB | (oa ^ 1);

            a_lo -%= b_lo & (0 -% cAB);
            a_hi -%= b_hi & (0 -% @as(u64, cAB));
            pa -%= qa & (0 -% @as(i64, cAB));
            pb -%= qb & (0 -% @as(i64, cAB));
            b_lo -%= a_lo & (0 -% cBA);
            b_hi -%= a_hi & (0 -% @as(u64, cBA));
            qa -%= pa & (0 -% @as(i64, cBA));
            qb -%= pb & (0 -% @as(i64, cBA));

            a_lo +%= a_lo & (cA -% 1);
            pa +%= pa & (@as(i64, cA) -% 1);
            pb +%= pb & (@as(i64, cA) -% 1);
            a_hi ^= (a_hi ^ (a_hi >> 1)) & (0 -% @as(u64, cA));
            b_lo +%= b_lo & (0 -% cA);
            qa +%= qa & (0 -% @as(i64, cA));
            qb +%= qb & (0 -% @as(i64, cA));
            b_hi ^= (b_hi ^ (b_hi >> 1)) & (@as(u64, cA) -% 1);
        }

        const r = zintCoReduce(a, b, pa, pb, qa, qb);
        pa -%= (pa +% pa) & (0 -% @as(i64, r & 1));
        pb -%= (pb +% pb) & (0 -% @as(i64, r & 1));
        qa -%= (qa +% qa) & (0 -% @as(i64, r >> 1));
        qb -%= (qb +% qb) & (0 -% @as(i64, r >> 1));
        zintCoReduceMod(bu0, bu1, y, y0i, pa, pb, qa, qb);
        zintCoReduceMod(bv0, bv1, x, x0i, pa, pb, qa, qb);
    }

    var rc: u32 = a[0] ^ 1;
    for (1..len) |jj| rc |= a[jj];
    return ((1 -% ((rc | (0 -% rc)) >> 31)) & x[0] & y[0]) != 0;
}

/// x += y*k*2^sc (sc = 31*sch + scl); x and y are signed (two's
/// complement); truncated to x.len limbs.
fn zintAddScaledMulSmall(x: []u32, y: []const u32, k: i32, sch: u32, scl: u5) void {
    const xlen = x.len;
    const ylen = y.len;
    if (ylen == 0) return;
    const ysign = (0 -% (y[ylen - 1] >> 30)) >> 1;
    var tw: u32 = 0;
    var cc: i32 = 0;
    var u: usize = sch;
    while (u < xlen) : (u += 1) {
        const v = u - sch;
        const wy = if (v < ylen) y[v] else ysign;
        const wys = ((wy << scl) & 0x7FFFFFFF) | tw;
        tw = wy >> @intCast(31 - @as(u32, scl));
        const z: u64 = @bitCast(@as(i64, wys) * @as(i64, k) + @as(i64, x[u]) + @as(i64, cc));
        x[u] = @as(u32, @truncate(z)) & 0x7FFFFFFF;
        const ccu: u32 = @truncate(z >> 31);
        cc = @bitCast(ccu);
    }
}

/// x -= y*2^sc; same conventions as zintAddScaledMulSmall.
fn zintSubScaled(x: []u32, y: []const u32, sch: u32, scl: u5) void {
    const xlen = x.len;
    const ylen = y.len;
    if (ylen == 0) return;
    const ysign = (0 -% (y[ylen - 1] >> 30)) >> 1;
    var tw: u32 = 0;
    var cc: u32 = 0;
    var u: usize = sch;
    while (u < xlen) : (u += 1) {
        const v = u - sch;
        const wy = if (v < ylen) y[v] else ysign;
        const wys = ((wy << scl) & 0x7FFFFFFF) | tw;
        tw = wy >> @intCast(31 - @as(u32, scl));
        const w = x[u] -% wys -% cc;
        x[u] = w & 0x7FFFFFFF;
        cc = w >> 31;
    }
}

/// One-limb signed big integer -> i32 (sign bit is bit 30).
inline fn zintOneToPlain(x: []const u32) i32 {
    var w = x[0];
    w |= (w & 0x40000000) << 1;
    return @bitCast(w);
}

// ---- Polynomial helpers over big-integer coefficients ----

/// Convert big-int coefficients to floating point (top `flen` limbs of
/// each coefficient, coefficients `fstride` limbs apart).
fn polyBigToFp(d: []f64, f: []const u32, flen: usize, fstride: usize, logn: u5) void {
    const n = @as(usize, 1) << logn;
    if (flen == 0) {
        for (d[0..n]) |*x| x.* = 0.0;
        return;
    }
    var fo: usize = 0;
    for (0..n) |u| {
        const fw = f[fo .. fo + flen];
        const neg = 0 -% (fw[flen - 1] >> 30);
        const xm = neg >> 1;
        var cc: u32 = neg & 1;
        var x: f64 = 0.0;
        var fsc: f64 = 1.0;
        for (0..flen) |v| {
            var w = (fw[v] ^ xm) +% cc;
            cc = w >> 31;
            w &= 0x7FFFFFFF;
            w -%= (w << 1) & neg;
            x = fpr.add(x, fpr.mul(fpr.of(@as(i32, @bitCast(w))), fsc));
            fsc = fpr.mul(fsc, fpr_ptwo31);
        }
        d[u] = x;
        fo += fstride;
    }
}

/// One-limb signed coefficients -> i8, bounds-checked against lim.
fn polyBigToSmall(d: []i8, s: []const u32, lim: i32, logn: u5) bool {
    const n = @as(usize, 1) << logn;
    for (0..n) |u| {
        const z = zintOneToPlain(s[u .. u + 1]);
        if (z < -lim or z > lim) return false;
        d[u] = @intCast(z);
    }
    return true;
}

/// F -= k*f*2^sc, schoolbook version (high depths, big coefficients).
fn polySubScaled(
    F: []u32,
    Flen: usize,
    Fstride: usize,
    f: []const u32,
    flen: usize,
    fstride: usize,
    k: []const i32,
    sch: u32,
    scl: u5,
    logn: u5,
) void {
    const n = @as(usize, 1) << logn;
    for (0..n) |u| {
        var kf: i32 = -k[u];
        var xo = u * Fstride;
        var yo: usize = 0;
        for (0..n) |v| {
            zintAddScaledMulSmall(F[xo .. xo + Flen], f[yo .. yo + flen], kf, sch, scl);
            if (u + v == n - 1) {
                xo = 0;
                kf = -kf;
            } else {
                xo += Fstride;
            }
            yo += fstride;
        }
    }
}

/// F -= k*f*2^sc, NTT version (low depths, small coefficients). tmp
/// needs 3n + n*(flen+1) limbs.
fn polySubScaledNtt(
    F: []u32,
    Flen: usize,
    Fstride: usize,
    f: []const u32,
    flen: usize,
    fstride: usize,
    k: []const i32,
    sch: u32,
    scl: u5,
    logn: u5,
    tmp: []u32,
    primes: []const SmallPrime,
) void {
    const n = @as(usize, 1) << logn;
    const tlen = flen + 1;
    const gm = tmp[0..n];
    const igm = tmp[n .. 2 * n];
    const fk_off = 2 * n;
    const t1 = tmp[fk_off + n * tlen .. fk_off + n * tlen + n];
    for (0..tlen) |u| {
        const p = primes[u].p;
        const p0i = modpNinv31(p);
        const R2 = modpR2(p, p0i);
        const Rx = modpRx(@intCast(flen), p, p0i, R2);
        modpMkgm2(gm, igm, logn, primes[u].g, p, p0i);
        for (0..n) |v| t1[v] = modpSet(k[v], p);
        modpNTT2Ext(t1, 1, gm, logn, p, p0i);
        {
            var v: usize = 0;
            var yo: usize = 0;
            var xo = fk_off + u;
            while (v < n) : ({
                v += 1;
                yo += fstride;
                xo += tlen;
            }) {
                tmp[xo] = zintModSmallSigned(f[yo .. yo + flen], p, p0i, R2, Rx);
            }
        }
        modpNTT2Ext(tmp[fk_off + u ..], tlen, gm, logn, p, p0i);
        {
            var v: usize = 0;
            var xo = fk_off + u;
            while (v < n) : ({
                v += 1;
                xo += tlen;
            }) {
                tmp[xo] = modpMontymul(modpMontymul(t1[v], tmp[xo], p, p0i), R2, p, p0i);
            }
        }
        modpINTT2Ext(tmp[fk_off + u ..], tlen, igm, logn, p, p0i);
    }
    zintRebuildCRT(tmp[fk_off..], tlen, tlen, n, primes, true, t1);
    {
        var u: usize = 0;
        var xo: usize = 0;
        var yo = fk_off;
        while (u < n) : ({
            u += 1;
            xo += Fstride;
            yo += tlen;
        }) {
            zintSubScaled(F[xo .. xo + Flen], tmp[yo .. yo + tlen], sch, scl);
        }
    }
}

// ---- Keygen Gaussian sampler for (f, g) (reference mkgauss) ----

/// P(x = 0) then P(x >= k+1 | x > 0) for the keygen Gaussian at N = 1024
/// (sigma = 1.17*sqrt(q/(2*1024))), scaled by 2^63 (reference
/// gauss_1024_12289).
const GAUSS_1024_12289 = [_]u64{
    1283868770400643928, 6416574995475331444, 4078260278032692663,
    2353523259288686585, 1227179971273316331, 575931623374121527,
    242543240509105209,  91437049221049666,   30799446349977173,
    9255276791179340,    2478152334826140,    590642893610164,
    125206034929641,     23590435911403,      3948334035941,
    586753615614,        77391054539,         9056793210,
    940121950,           86539696,            7062824,
    510971,              32764,               1862,
    94,                  4,                   0,
};

/// Eight little-endian bytes from the RNG (reference get_rng_u64 —
/// mirrors inner_shake256_extract of 8 bytes at a time).
fn getRngU64(rng: std.Random) u64 {
    var b: [8]u8 = undefined;
    rng.bytes(&b);
    return std.mem.readInt(u64, &b, .little);
}

/// One keygen Gaussian sample; at logn < 10, 2^(10-logn) N=1024 samples
/// are summed (reference mkgauss).
fn mkgauss(rng: std.Random, logn: u5) i32 {
    const g = @as(u32, 1) << @intCast(10 - @as(u32, logn));
    var val: i32 = 0;
    for (0..g) |_| {
        var r = getRngU64(rng);
        const neg: u32 = @truncate(r >> 63);
        r &= ~(@as(u64, 1) << 63);
        var f: u32 = @truncate((r -% GAUSS_1024_12289[0]) >> 63);
        var v: u32 = 0;
        r = getRngU64(rng);
        r &= ~(@as(u64, 1) << 63);
        for (1..GAUSS_1024_12289.len) |k| {
            const t: u32 = @as(u32, @truncate((r -% GAUSS_1024_12289[k]) >> 63)) ^ 1;
            v |= @as(u32, @intCast(k)) & (0 -% (t & (f ^ 1)));
            f |= t;
        }
        v = (v ^ (0 -% neg)) +% neg;
        val +%= @as(i32, @bitCast(v));
    }
    return val;
}

/// Fill f with Gaussian coefficients, restarting any coefficient outside
/// -127..127 and forcing the coefficient sum odd (so Res(f, x^n+1) is
/// odd, as the binary GCD requires) — reference poly_small_mkgauss.
fn polySmallMkgauss(rng: std.Random, f: []i8, logn: u5) void {
    const n = @as(usize, 1) << logn;
    var mod2: u32 = 0;
    for (0..n) |u| {
        var s: i32 = undefined;
        while (true) {
            s = mkgauss(rng, logn);
            if (s < -127 or s > 127) continue;
            if (u == n - 1) {
                if ((mod2 ^ @as(u32, @intCast(s & 1))) == 0) continue;
            } else {
                mod2 ^= @as(u32, @intCast(s & 1));
            }
            break;
        }
        f[u] = @intCast(s);
    }
}

// ---- NTRUSolve: the tower-of-number-fields recursion ----

/// Limb counts for f/g (SMALL) and unreduced F/G (LARGE) per depth
/// (reference MAX_BL_SMALL / MAX_BL_LARGE).
const MAX_BL_SMALL = [_]usize{ 1, 1, 2, 2, 4, 7, 14, 27, 53, 106, 209 };
const MAX_BL_LARGE = [_]usize{ 2, 2, 5, 7, 12, 21, 40, 78, 157, 308 };

/// Measured average/std-dev of max (f,g) coefficient bit length per
/// depth (reference BITLENGTH), used to bound the Babai reduction.
const BITLENGTH_AVG = [_]i32{ 4, 11, 24, 50, 102, 202, 401, 794, 1577, 3138, 6308 };
const BITLENGTH_STD = [_]i32{ 0, 1, 1, 1, 1, 2, 4, 5, 8, 13, 25 };

/// Depth at or below which k*f is computed via NTT rather than
/// schoolbook (reference DEPTH_INT_FG).
const DEPTH_INT_FG = 4;

/// memmove within the shared u32 pool.
fn moveWords(pool: []u32, dst: usize, src: usize, len: usize) void {
    if (dst == src or len == 0) return;
    if (dst < src) {
        std.mem.copyForwards(u32, pool[dst .. dst + len], pool[src .. src + len]);
    } else {
        std.mem.copyBackwards(u32, pool[dst .. dst + len], pool[src .. src + len]);
    }
}

/// One descent step of the field norm: f, g at some depth (degree n,
/// slen limbs, RNS[+NTT]) -> f', g' at depth+1 (degree n/2, tlen limbs)
/// (reference make_fg_step).
fn makeFgStep(data: []u32, logn: u5, depth: usize, in_ntt: bool, out_ntt: bool, primes: []const SmallPrime) void {
    const n = @as(usize, 1) << logn;
    const hn = n >> 1;
    const slen = MAX_BL_SMALL[depth];
    const tlen = MAX_BL_SMALL[depth + 1];

    // fd @0, gd @hn*tlen, fs @2*hn*tlen, gs @fs+n*slen, gm, igm, t1.
    const fd_off: usize = 0;
    const gd_off = hn * tlen;
    const fs_off = 2 * hn * tlen;
    const gs_off = fs_off + n * slen;
    const gm_off = gs_off + n * slen;
    const igm_off = gm_off + n;
    const t1_off = igm_off + n;
    moveWords(data, fs_off, 0, 2 * n * slen);

    const gm = data[gm_off .. gm_off + n];
    const igm = data[igm_off .. igm_off + n];
    const t1 = data[t1_off .. t1_off + n];

    // First slen limb planes: direct residues, de-NTTizing as we go.
    for (0..slen) |u| {
        const p = primes[u].p;
        const p0i = modpNinv31(p);
        const R2 = modpR2(p, p0i);
        modpMkgm2(gm, igm, logn, primes[u].g, p, p0i);

        for (0..n) |v| t1[v] = data[fs_off + v * slen + u];
        if (!in_ntt) modpNTT2Ext(t1, 1, gm, logn, p, p0i);
        {
            var v: usize = 0;
            var xo = fd_off + u;
            while (v < hn) : ({
                v += 1;
                xo += tlen;
            }) {
                const w0 = t1[(v << 1) + 0];
                const w1 = t1[(v << 1) + 1];
                data[xo] = modpMontymul(modpMontymul(w0, w1, p, p0i), R2, p, p0i);
            }
        }
        if (in_ntt) modpINTT2Ext(data[fs_off + u ..], slen, igm, logn, p, p0i);

        for (0..n) |v| t1[v] = data[gs_off + v * slen + u];
        if (!in_ntt) modpNTT2Ext(t1, 1, gm, logn, p, p0i);
        {
            var v: usize = 0;
            var xo = gd_off + u;
            while (v < hn) : ({
                v += 1;
                xo += tlen;
            }) {
                const w0 = t1[(v << 1) + 0];
                const w1 = t1[(v << 1) + 1];
                data[xo] = modpMontymul(modpMontymul(w0, w1, p, p0i), R2, p, p0i);
            }
        }
        if (in_ntt) modpINTT2Ext(data[gs_off + u ..], slen, igm, logn, p, p0i);

        if (!out_ntt) {
            modpINTT2Ext(data[fd_off + u ..], tlen, igm, logn - 1, p, p0i);
            modpINTT2Ext(data[gd_off + u ..], tlen, igm, logn - 1, p, p0i);
        }
    }

    // fs/gs are now plain RNS; rebuild them as big integers for the
    // remaining limb planes. (gm region doubles as CRT scratch, exactly
    // like the reference — trailing pool space absorbs slen > n cases.)
    zintRebuildCRT(data[fs_off..], slen, slen, n, primes, true, data[gm_off..]);
    zintRebuildCRT(data[gs_off..], slen, slen, n, primes, true, data[gm_off..]);

    var u: usize = slen;
    while (u < tlen) : (u += 1) {
        const p = primes[u].p;
        const p0i = modpNinv31(p);
        const R2 = modpR2(p, p0i);
        const Rx = modpRx(@intCast(slen), p, p0i, R2);
        modpMkgm2(gm, igm, logn, primes[u].g, p, p0i);
        for (0..n) |v| {
            t1[v] = zintModSmallSigned(data[fs_off + v * slen .. fs_off + v * slen + slen], p, p0i, R2, Rx);
        }
        modpNTT2Ext(t1, 1, gm, logn, p, p0i);
        {
            var v: usize = 0;
            var xo = fd_off + u;
            while (v < hn) : ({
                v += 1;
                xo += tlen;
            }) {
                const w0 = t1[(v << 1) + 0];
                const w1 = t1[(v << 1) + 1];
                data[xo] = modpMontymul(modpMontymul(w0, w1, p, p0i), R2, p, p0i);
            }
        }
        for (0..n) |v| {
            t1[v] = zintModSmallSigned(data[gs_off + v * slen .. gs_off + v * slen + slen], p, p0i, R2, Rx);
        }
        modpNTT2Ext(t1, 1, gm, logn, p, p0i);
        {
            var v: usize = 0;
            var xo = gd_off + u;
            while (v < hn) : ({
                v += 1;
                xo += tlen;
            }) {
                const w0 = t1[(v << 1) + 0];
                const w1 = t1[(v << 1) + 1];
                data[xo] = modpMontymul(modpMontymul(w0, w1, p, p0i), R2, p, p0i);
            }
        }
        if (!out_ntt) {
            modpINTT2Ext(data[fd_off + u ..], tlen, igm, logn - 1, p, p0i);
            modpINTT2Ext(data[gd_off + u ..], tlen, igm, logn - 1, p, p0i);
        }
    }
}

/// Compute f and g at `depth`, in RNS (optionally NTT) — reference
/// make_fg. Output at data[0..], f then g, MAX_BL_SMALL[depth] limbs per
/// coefficient.
fn makeFg(data: []u32, f: []const i8, g: []const i8, logn_top: u5, depth: u5, out_ntt: bool, primes: []const SmallPrime) void {
    const n = @as(usize, 1) << logn_top;
    const p0 = primes[0].p;
    for (0..n) |u| {
        data[u] = modpSet(f[u], p0);
        data[n + u] = modpSet(g[u], p0);
    }

    if (depth == 0 and out_ntt) {
        const p0i = modpNinv31(p0);
        const gm = data[2 * n .. 3 * n];
        const igm = data[3 * n .. 4 * n];
        modpMkgm2(gm, igm, logn_top, primes[0].g, p0, p0i);
        modpNTT2Ext(data[0..n], 1, gm, logn_top, p0, p0i);
        modpNTT2Ext(data[n .. 2 * n], 1, gm, logn_top, p0, p0i);
        return;
    }

    var d: u5 = 0;
    while (d < depth) : (d += 1) {
        makeFgStep(data, logn_top - d, d, d != 0, (d + 1) < depth or out_ntt, primes);
    }
}

/// Deepest level: resultants of f and g with x^n+1 (single big
/// integers), extended GCD, scale by q (reference solve_NTRU_deepest).
/// F, G are left at tmp[0..len] and tmp[len..2*len].
fn solveNtruDeepest(logn_top: u5, f: []const i8, g: []const i8, tmp: []u32, primes: []const SmallPrime) bool {
    const len = MAX_BL_SMALL[logn_top];
    // Fp @0, Gp @len, fp @2len, gp @3len, t1 @4len.
    makeFg(tmp[2 * len ..], f, g, logn_top, logn_top, false, primes);
    zintRebuildCRT(tmp[2 * len ..], len, len, 2, primes, false, tmp[4 * len ..]);
    if (!zintBezout(
        tmp[len .. 2 * len],
        tmp[0..len],
        tmp[2 * len .. 3 * len],
        tmp[3 * len .. 4 * len],
        tmp[4 * len ..],
    )) {
        return false;
    }
    if (zintMulSmall(tmp[0..len], 12289) != 0 or zintMulSmall(tmp[len .. 2 * len], 12289) != 0) {
        return false;
    }
    return true;
}

/// Intermediate level: lift F', G' from depth+1 (in tmp) to unreduced
/// F, G at `depth` via field-norm identities mod many small primes, then
/// Babai-reduce against (f, g) with the FP FFT (reference
/// solve_NTRU_intermediate). Output at tmp[0..], slen limbs per coeff.
fn solveNtruIntermediate(comptime logn_top: u5, f: []const i8, g: []const i8, depth: u5, tmp: []u32, primes: []const SmallPrime) bool {
    const logn: u5 = logn_top - depth;
    const n = @as(usize, 1) << logn;
    const hn = n >> 1;
    const slen = MAX_BL_SMALL[depth];
    const dlen = MAX_BL_SMALL[depth + 1];
    const llen = MAX_BL_LARGE[depth];

    // FP scratch bound: for logn_top >= 3 this function only runs at
    // depth >= 2 (shallower depths use the specialized binary_depth1/0),
    // so n <= 2^(logn_top-2).
    const max_fp = if (logn_top <= 2) (@as(usize, 1) << logn_top) else (@as(usize, 1) << (logn_top - 2));
    std.debug.assert(n <= max_fp);

    // Fd @0 (dlen limbs x hn), Gd follows; compute this level's f, g
    // after them (RNS+NTT).
    makeFg(tmp[2 * dlen * hn ..], f, g, logn_top, depth, true, primes);

    // Final layout: Ft @0 (llen x n), Gt, then f, g (slen x n), then
    // the moved Fd, Gd (dlen x hn each), then scratch.
    const ft_off = 2 * n * llen;
    moveWords(tmp, ft_off, 2 * dlen * hn, 2 * n * slen);
    const gt_off = ft_off + slen * n;
    const t1_off = gt_off + slen * n;
    moveWords(tmp, t1_off, 0, 2 * hn * dlen);
    const fd_off = t1_off;
    const gd_off = fd_off + hn * dlen;
    const gt_glob_off = n * llen; // Gt within tmp

    // Reduce Fd, Gd modulo all llen primes, into Ft, Gt.
    for (0..llen) |u| {
        const p = primes[u].p;
        const p0i = modpNinv31(p);
        const R2 = modpR2(p, p0i);
        const Rx = modpRx(@intCast(dlen), p, p0i, R2);
        var v: usize = 0;
        var xs = fd_off;
        var ys = gd_off;
        var xd = u;
        var yd = gt_glob_off + u;
        while (v < hn) : ({
            v += 1;
            xs += dlen;
            ys += dlen;
            xd += llen;
            yd += llen;
        }) {
            tmp[xd] = zintModSmallSigned(tmp[xs .. xs + dlen], p, p0i, R2, Rx);
            tmp[yd] = zintModSmallSigned(tmp[ys .. ys + dlen], p, p0i, R2, Rx);
        }
    }

    // Compute unreduced F, G modulo each prime:
    //   F = F'(x^2) * adj-half(g), G = G'(x^2) * adj-half(f) in NTT.
    for (0..llen) |u| {
        const p = primes[u].p;
        const p0i = modpNinv31(p);
        const R2 = modpR2(p, p0i);

        if (u == slen) {
            zintRebuildCRT(tmp[ft_off..], slen, slen, n, primes, true, tmp[t1_off..]);
            zintRebuildCRT(tmp[gt_off..], slen, slen, n, primes, true, tmp[t1_off..]);
        }

        const gm = tmp[t1_off .. t1_off + n];
        const igm = tmp[t1_off + n .. t1_off + 2 * n];
        const fx = tmp[t1_off + 2 * n .. t1_off + 3 * n];
        const gx = tmp[t1_off + 3 * n .. t1_off + 4 * n];
        modpMkgm2(gm, igm, logn, primes[u].g, p, p0i);

        if (u < slen) {
            for (0..n) |v| {
                fx[v] = tmp[ft_off + v * slen + u];
                gx[v] = tmp[gt_off + v * slen + u];
            }
            modpINTT2Ext(tmp[ft_off + u ..], slen, igm, logn, p, p0i);
            modpINTT2Ext(tmp[gt_off + u ..], slen, igm, logn, p, p0i);
        } else {
            const Rx = modpRx(@intCast(slen), p, p0i, R2);
            for (0..n) |v| {
                fx[v] = zintModSmallSigned(tmp[ft_off + v * slen .. ft_off + v * slen + slen], p, p0i, R2, Rx);
                gx[v] = zintModSmallSigned(tmp[gt_off + v * slen .. gt_off + v * slen + slen], p, p0i, R2, Rx);
            }
            modpNTT2Ext(fx, 1, gm, logn, p, p0i);
            modpNTT2Ext(gx, 1, gm, logn, p, p0i);
        }

        const Fp = tmp[t1_off + 4 * n .. t1_off + 4 * n + hn];
        const Gp = tmp[t1_off + 4 * n + hn .. t1_off + 4 * n + 2 * hn];
        {
            var v: usize = 0;
            var xo = u;
            var yo = gt_glob_off + u;
            while (v < hn) : ({
                v += 1;
                xo += llen;
                yo += llen;
            }) {
                Fp[v] = tmp[xo];
                Gp[v] = tmp[yo];
            }
        }
        modpNTT2Ext(Fp, 1, gm, logn - 1, p, p0i);
        modpNTT2Ext(Gp, 1, gm, logn - 1, p, p0i);

        {
            var v: usize = 0;
            var xo = u;
            var yo = gt_glob_off + u;
            while (v < hn) : ({
                v += 1;
                xo += llen << 1;
                yo += llen << 1;
            }) {
                const ftA = fx[(v << 1) + 0];
                const ftB = fx[(v << 1) + 1];
                const gtA = gx[(v << 1) + 0];
                const gtB = gx[(v << 1) + 1];
                const mFp = modpMontymul(Fp[v], R2, p, p0i);
                const mGp = modpMontymul(Gp[v], R2, p, p0i);
                tmp[xo] = modpMontymul(gtB, mFp, p, p0i);
                tmp[xo + llen] = modpMontymul(gtA, mFp, p, p0i);
                tmp[yo] = modpMontymul(ftB, mGp, p, p0i);
                tmp[yo + llen] = modpMontymul(ftA, mGp, p, p0i);
            }
        }
        modpINTT2Ext(tmp[u..], llen, igm, logn, p, p0i);
        modpINTT2Ext(tmp[gt_glob_off + u ..], llen, igm, logn, p, p0i);
    }

    zintRebuildCRT(tmp[0..], llen, llen, n, primes, true, tmp[t1_off..]);
    zintRebuildCRT(tmp[gt_glob_off..], llen, llen, n, primes, true, tmp[t1_off..]);

    // ---- Babai reduction of (F, G) against (f, g), FP-FFT guided ----

    var rt1: [max_fp]f64 = undefined;
    var rt2: [max_fp]f64 = undefined;
    var rt3: [max_fp]f64 = undefined;
    var rt4: [max_fp]f64 = undefined;
    var rt5: [max_fp]f64 = undefined;
    var k: [max_fp]i32 = undefined;

    var rlen = @min(slen, 10);
    polyBigToFp(rt3[0..n], tmp[ft_off + slen - rlen ..], rlen, slen, logn);
    polyBigToFp(rt4[0..n], tmp[gt_off + slen - rlen ..], rlen, slen, logn);
    const scale_fg: i32 = 31 * @as(i32, @intCast(slen - rlen));

    const minbl_fg = BITLENGTH_AVG[depth] - 6 * BITLENGTH_STD[depth];
    const maxbl_fg = BITLENGTH_AVG[depth] + 6 * BITLENGTH_STD[depth];

    fft.fftRaw(rt3[0..n], logn);
    fft.fftRaw(rt4[0..n], logn);
    fft.polyInvnorm2Fft(rt5[0..n], rt3[0..n], rt4[0..n], logn);
    fft.polyAdjFft(rt3[0..n], logn);
    fft.polyAdjFft(rt4[0..n], logn);

    var FGlen = llen;
    var maxbl_FG: i32 = 31 * @as(i32, @intCast(llen));
    var scale_k: i32 = maxbl_FG - minbl_fg;

    while (true) {
        rlen = @min(FGlen, 10);
        const scale_FG: i32 = 31 * @as(i32, @intCast(FGlen - rlen));
        polyBigToFp(rt1[0..n], tmp[FGlen - rlen ..], rlen, llen, logn);
        polyBigToFp(rt2[0..n], tmp[gt_glob_off + FGlen - rlen ..], rlen, llen, logn);

        fft.fftRaw(rt1[0..n], logn);
        fft.fftRaw(rt2[0..n], logn);
        fft.polyMulFft(rt1[0..n], rt3[0..n], logn);
        fft.polyMulFft(rt2[0..n], rt4[0..n], logn);
        fft.polyAdd(rt2[0..n], rt1[0..n], logn);
        fft.polyMulAutoadjFft(rt2[0..n], rt5[0..n], logn);
        fft.ifftRaw(rt2[0..n], logn);

        var dc: i32 = scale_k - scale_FG + scale_fg;
        var pt: f64 = undefined;
        if (dc < 0) {
            dc = -dc;
            pt = 2.0;
        } else {
            pt = 0.5;
        }
        var pdc: f64 = 1.0;
        while (dc != 0) {
            if ((dc & 1) != 0) pdc = fpr.mul(pdc, pt);
            dc >>= 1;
            pt = fpr.sqr(pt);
        }

        for (0..n) |u| {
            const xv = fpr.mul(rt2[u], pdc);
            // Out-of-bounds k means the reduction failed; reject (f, g).
            if (!fpr.lt(fpr_mtwo31m1, xv) or !fpr.lt(xv, fpr_ptwo31m1)) return false;
            k[u] = @intCast(fpr.rint(xv));
        }

        const sch: u32 = @intCast(@divTrunc(scale_k, 31));
        const scl: u5 = @intCast(@rem(scale_k, 31));
        if (depth <= DEPTH_INT_FG) {
            polySubScaledNtt(tmp[0..], FGlen, llen, tmp[ft_off..], slen, slen, k[0..n], sch, scl, logn, tmp[t1_off..], primes);
            polySubScaledNtt(tmp[gt_glob_off..], FGlen, llen, tmp[gt_off..], slen, slen, k[0..n], sch, scl, logn, tmp[t1_off..], primes);
        } else {
            polySubScaled(tmp[0..], FGlen, llen, tmp[ft_off..], slen, slen, k[0..n], sch, scl, logn);
            polySubScaled(tmp[gt_glob_off..], FGlen, llen, tmp[gt_off..], slen, slen, k[0..n], sch, scl, logn);
        }

        const new_maxbl_FG: i32 = scale_k + maxbl_fg + 10;
        if (new_maxbl_FG < maxbl_FG) {
            maxbl_FG = new_maxbl_FG;
            if (@as(i32, @intCast(FGlen)) * 31 >= maxbl_FG + 31) FGlen -= 1;
        }

        if (scale_k <= 0) break;
        scale_k -= 25;
        if (scale_k < 0) scale_k = 0;
    }

    // Re-extend the sign if FGlen dropped below slen.
    if (FGlen < slen) {
        var fo: usize = 0;
        var go: usize = gt_glob_off;
        for (0..n) |_| {
            var sw = (0 -% (tmp[fo + FGlen - 1] >> 30)) >> 1;
            for (FGlen..slen) |v| tmp[fo + v] = sw;
            sw = (0 -% (tmp[go + FGlen - 1] >> 30)) >> 1;
            for (FGlen..slen) |v| tmp[go + v] = sw;
            fo += llen;
            go += llen;
        }
    }

    // Compress F, G to slen limbs per coefficient at tmp[0..].
    {
        var xo: usize = 0;
        var yo: usize = 0;
        for (0..(n << 1)) |_| {
            moveWords(tmp, xo, yo, slen);
            xo += slen;
            yo += llen;
        }
    }
    return true;
}

/// Depth-1 specialization: unreduced F, G fit in 53-bit floats, so a
/// single unscaled Babai pass suffices (reference
/// solve_NTRU_binary_depth1).
fn solveNtruBinaryDepth1(comptime logn_top: u5, f: []const i8, g: []const i8, tmp: []u32, primes: []const SmallPrime) bool {
    const n_top = @as(usize, 1) << logn_top;
    const logn: u5 = logn_top - 1;
    const n = @as(usize, 1) << logn;
    const hn = n >> 1;
    const slen = MAX_BL_SMALL[1];
    const dlen = MAX_BL_SMALL[2];
    const llen = MAX_BL_LARGE[1];

    // Fd @0, Gd @dlen*hn; Ft/Gt provisionally after them.
    const fd_off: usize = 0;
    const gd_off = dlen * hn;
    const pft_off = 2 * dlen * hn;
    const pgt_off = pft_off + llen * n;

    // Reduce Fd, Gd modulo all llen primes into (provisional) Ft, Gt.
    for (0..llen) |u| {
        const p = primes[u].p;
        const p0i = modpNinv31(p);
        const R2 = modpR2(p, p0i);
        const Rx = modpRx(@intCast(dlen), p, p0i, R2);
        var v: usize = 0;
        var xs = fd_off;
        var ys = gd_off;
        var xd = pft_off + u;
        var yd = pgt_off + u;
        while (v < hn) : ({
            v += 1;
            xs += dlen;
            ys += dlen;
            xd += llen;
            yd += llen;
        }) {
            tmp[xd] = zintModSmallSigned(tmp[xs .. xs + dlen], p, p0i, R2, Rx);
            tmp[yd] = zintModSmallSigned(tmp[ys .. ys + dlen], p, p0i, R2, Rx);
        }
    }

    // Squeeze Fd/Gd out: Ft @0, Gt @llen*n, then ft, gt, then scratch.
    moveWords(tmp, 0, pft_off, llen * n);
    moveWords(tmp, llen * n, pgt_off, llen * n);
    const gt_glob_off = llen * n;
    const ft_off = 2 * llen * n;
    const gt_off = ft_off + slen * n;
    const t1_off = gt_off + slen * n;

    // Compute unreduced F, G modulo each prime, recomputing f', g' from
    // the top-degree f, g via repeated field norms.
    for (0..llen) |u| {
        const p = primes[u].p;
        const p0i = modpNinv31(p);
        const R2 = modpR2(p, p0i);

        // gm and igm need n_top space (mkgm2 fills the full degree).
        const gm = tmp[t1_off .. t1_off + n_top];
        const igm = tmp[t1_off + n_top .. t1_off + 2 * n_top];
        const fx = tmp[t1_off + 2 * n_top .. t1_off + 3 * n_top];
        const gx = tmp[t1_off + 3 * n_top .. t1_off + 4 * n_top];
        modpMkgm2(gm, igm, logn_top, primes[u].g, p, p0i);

        for (0..n_top) |v| {
            fx[v] = modpSet(f[v], p);
            gx[v] = modpSet(g[v], p);
        }
        modpNTT2Ext(fx, 1, gm, logn_top, p, p0i);
        modpNTT2Ext(gx, 1, gm, logn_top, p, p0i);
        var e: u5 = logn_top;
        while (e > logn) : (e -= 1) {
            modpPolyRecRes(fx, e, p, p0i, R2);
            modpPolyRecRes(gx, e, p, p0i, R2);
        }
        // (The reference compacts gm/igm/fx/gx here to save RAM; the
        // tables nest, so using the same arrays in place is
        // value-identical.)

        const Fp = tmp[t1_off + 4 * n_top .. t1_off + 4 * n_top + hn];
        const Gp = tmp[t1_off + 4 * n_top + hn .. t1_off + 4 * n_top + 2 * hn];
        {
            var v: usize = 0;
            var xo = u;
            var yo = gt_glob_off + u;
            while (v < hn) : ({
                v += 1;
                xo += llen;
                yo += llen;
            }) {
                Fp[v] = tmp[xo];
                Gp[v] = tmp[yo];
            }
        }
        modpNTT2Ext(Fp, 1, gm, logn - 1, p, p0i);
        modpNTT2Ext(Gp, 1, gm, logn - 1, p, p0i);

        {
            var v: usize = 0;
            var xo = u;
            var yo = gt_glob_off + u;
            while (v < hn) : ({
                v += 1;
                xo += llen << 1;
                yo += llen << 1;
            }) {
                const ftA = fx[(v << 1) + 0];
                const ftB = fx[(v << 1) + 1];
                const gtA = gx[(v << 1) + 0];
                const gtB = gx[(v << 1) + 1];
                const mFp = modpMontymul(Fp[v], R2, p, p0i);
                const mGp = modpMontymul(Gp[v], R2, p, p0i);
                tmp[xo] = modpMontymul(gtB, mFp, p, p0i);
                tmp[xo + llen] = modpMontymul(gtA, mFp, p, p0i);
                tmp[yo] = modpMontymul(ftB, mGp, p, p0i);
                tmp[yo + llen] = modpMontymul(ftA, mGp, p, p0i);
            }
        }
        modpINTT2Ext(tmp[u..], llen, igm, logn, p, p0i);
        modpINTT2Ext(tmp[gt_glob_off + u ..], llen, igm, logn, p, p0i);

        // Save this level's f, g (only the first slen planes).
        if (u < slen) {
            modpINTT2Ext(fx[0..n], 1, igm, logn, p, p0i);
            modpINTT2Ext(gx[0..n], 1, igm, logn, p, p0i);
            var v: usize = 0;
            var xo = ft_off + u;
            var yo = gt_off + u;
            while (v < n) : ({
                v += 1;
                xo += slen;
                yo += slen;
            }) {
                tmp[xo] = fx[v];
                tmp[yo] = gx[v];
            }
        }
    }

    // Rebuild F, G (2n consecutive llen-limb ints) and f, g (2n
    // consecutive slen-limb ints) with the CRT.
    zintRebuildCRT(tmp[0..], llen, llen, n << 1, primes, true, tmp[t1_off..]);
    zintRebuildCRT(tmp[ft_off..], slen, slen, n << 1, primes, true, tmp[t1_off..]);

    // ---- Single-pass Babai reduction in floating point ----

    const half = @as(usize, 1) << (logn_top - 1);
    var rt1: [half]f64 = undefined;
    var rt2: [half]f64 = undefined;
    var rt3: [half]f64 = undefined;
    var rt4: [half]f64 = undefined;
    var rt5: [half]f64 = undefined;
    var rt6: [half]f64 = undefined;

    polyBigToFp(rt1[0..n], tmp[0..], llen, llen, logn);
    polyBigToFp(rt2[0..n], tmp[gt_glob_off..], llen, llen, logn);
    polyBigToFp(rt3[0..n], tmp[ft_off..], slen, slen, logn);
    polyBigToFp(rt4[0..n], tmp[gt_off..], slen, slen, logn);

    fft.fftRaw(rt1[0..n], logn);
    fft.fftRaw(rt2[0..n], logn);
    fft.fftRaw(rt3[0..n], logn);
    fft.fftRaw(rt4[0..n], logn);

    fft.polyAddMuladjFft(rt5[0..n], rt1[0..n], rt2[0..n], rt3[0..n], rt4[0..n], logn);
    fft.polyInvnorm2Fft(rt6[0..n], rt3[0..n], rt4[0..n], logn);
    fft.polyMulAutoadjFft(rt5[0..n], rt6[0..n], logn);
    fft.ifftRaw(rt5[0..n], logn);

    for (0..n) |u| {
        const z = rt5[u];
        if (!fpr.lt(z, fpr_ptwo63m1) or !fpr.lt(fpr_mtwo63m1, z)) return false;
        rt5[u] = fpr.of(fpr.rint(z));
    }
    fft.fftRaw(rt5[0..n], logn);

    fft.polyMulFft(rt3[0..n], rt5[0..n], logn);
    fft.polyMulFft(rt4[0..n], rt5[0..n], logn);
    fft.polySub(rt1[0..n], rt3[0..n], logn);
    fft.polySub(rt2[0..n], rt4[0..n], logn);
    fft.ifftRaw(rt1[0..n], logn);
    fft.ifftRaw(rt2[0..n], logn);

    // Convert back to integers (one word per coefficient).
    for (0..n) |u| {
        tmp[u] = @truncate(@as(u64, @bitCast(fpr.rint(rt1[u]))));
        tmp[n + u] = @truncate(@as(u64, @bitCast(fpr.rint(rt2[u]))));
    }
    return true;
}

/// Top level (depth 0): everything fits one word mod the first small
/// prime; one exact mod-p Babai pass (reference solve_NTRU_binary_depth0).
fn solveNtruBinaryDepth0(comptime logn: u5, f: []const i8, g: []const i8, tmp: []u32, primes: []const SmallPrime) bool {
    const n = @as(usize, 1) << logn;
    const hn = n >> 1;
    const p = primes[0].p;
    const p0i = modpNinv31(p);
    const R2 = modpR2(p, p0i);

    // Fp @0 (hn), Gp @hn, ft @n, gt @2n, gm @3n, igm @4n.
    modpMkgm2(tmp[3 * n .. 4 * n], tmp[4 * n .. 5 * n], logn, primes[0].g, p, p0i);
    for (0..hn) |u| {
        tmp[u] = modpSet(zintOneToPlain(tmp[u .. u + 1]), p);
        tmp[hn + u] = modpSet(zintOneToPlain(tmp[hn + u .. hn + u + 1]), p);
    }
    modpNTT2Ext(tmp[0..hn], 1, tmp[3 * n ..], logn - 1, p, p0i);
    modpNTT2Ext(tmp[hn .. 2 * hn], 1, tmp[3 * n ..], logn - 1, p, p0i);

    for (0..n) |u| {
        tmp[n + u] = modpSet(f[u], p);
        tmp[2 * n + u] = modpSet(g[u], p);
    }
    modpNTT2Ext(tmp[n .. 2 * n], 1, tmp[3 * n ..], logn, p, p0i);
    modpNTT2Ext(tmp[2 * n .. 3 * n], 1, tmp[3 * n ..], logn, p, p0i);

    // Build the unreduced F, G over ft/gt.
    {
        var u: usize = 0;
        while (u < n) : (u += 2) {
            const ftA = tmp[n + u + 0];
            const ftB = tmp[n + u + 1];
            const gtA = tmp[2 * n + u + 0];
            const gtB = tmp[2 * n + u + 1];
            const mFp = modpMontymul(tmp[u >> 1], R2, p, p0i);
            const mGp = modpMontymul(tmp[hn + (u >> 1)], R2, p, p0i);
            tmp[n + u + 0] = modpMontymul(gtB, mFp, p, p0i);
            tmp[n + u + 1] = modpMontymul(gtA, mFp, p, p0i);
            tmp[2 * n + u + 0] = modpMontymul(ftB, mGp, p, p0i);
            tmp[2 * n + u + 1] = modpMontymul(ftA, mGp, p, p0i);
        }
    }
    modpINTT2Ext(tmp[n .. 2 * n], 1, tmp[4 * n ..], logn, p, p0i);
    modpINTT2Ext(tmp[2 * n .. 3 * n], 1, tmp[4 * n ..], logn, p, p0i);

    // Fp @0 (n), Gp @n (n); then t1..t5, one n each.
    moveWords(tmp, 0, n, 2 * n);
    const t1 = 2 * n;
    const t2 = 3 * n;
    const t3 = 4 * n;
    const t4 = 5 * n;
    const t5 = 6 * n;

    // NTT tables (t2's igm copy is scratch, recomputed later).
    modpMkgm2(tmp[t1 .. t1 + n], tmp[t2 .. t2 + n], logn, primes[0].g, p, p0i);
    modpNTT2Ext(tmp[0..n], 1, tmp[t1..], logn, p, p0i);
    modpNTT2Ext(tmp[n .. 2 * n], 1, tmp[t1..], logn, p, p0i);

    // t2 = F*adj(f), t3 = f*adj(f) (NTT, Montgomery-adjusted).
    tmp[t4] = modpSet(f[0], p);
    tmp[t5] = tmp[t4];
    for (1..n) |u| {
        tmp[t4 + u] = modpSet(f[u], p);
        tmp[t5 + n - u] = modpSet(-@as(i32, f[u]), p);
    }
    modpNTT2Ext(tmp[t4 .. t4 + n], 1, tmp[t1..], logn, p, p0i);
    modpNTT2Ext(tmp[t5 .. t5 + n], 1, tmp[t1..], logn, p, p0i);
    for (0..n) |u| {
        const w = modpMontymul(tmp[t5 + u], R2, p, p0i);
        tmp[t2 + u] = modpMontymul(w, tmp[u], p, p0i);
        tmp[t3 + u] = modpMontymul(w, tmp[t4 + u], p, p0i);
    }

    // Add G*adj(g) to t2 and g*adj(g) to t3.
    tmp[t4] = modpSet(g[0], p);
    tmp[t5] = tmp[t4];
    for (1..n) |u| {
        tmp[t4 + u] = modpSet(g[u], p);
        tmp[t5 + n - u] = modpSet(-@as(i32, g[u]), p);
    }
    modpNTT2Ext(tmp[t4 .. t4 + n], 1, tmp[t1..], logn, p, p0i);
    modpNTT2Ext(tmp[t5 .. t5 + n], 1, tmp[t1..], logn, p, p0i);
    for (0..n) |u| {
        const w = modpMontymul(tmp[t5 + u], R2, p, p0i);
        tmp[t2 + u] = modpAdd(tmp[t2 + u], modpMontymul(w, tmp[n + u], p, p0i), p);
        tmp[t3 + u] = modpAdd(tmp[t3 + u], modpMontymul(w, tmp[t4 + u], p, p0i), p);
    }

    // Back to plain, normalized around 0: t1 = F*adj(f)+G*adj(g),
    // t2 = f*adj(f)+g*adj(g).
    modpMkgm2(tmp[t1 .. t1 + n], tmp[t4 .. t4 + n], logn, primes[0].g, p, p0i);
    modpINTT2Ext(tmp[t2 .. t2 + n], 1, tmp[t4..], logn, p, p0i);
    modpINTT2Ext(tmp[t3 .. t3 + n], 1, tmp[t4..], logn, p, p0i);
    for (0..n) |u| {
        tmp[t1 + u] = @bitCast(modpNorm(tmp[t2 + u], p));
        tmp[t2 + u] = @bitCast(modpNorm(tmp[t3 + u], p));
    }

    // k = round((F*adj(f)+G*adj(g)) / (f*adj(f)+g*adj(g))) via FFT.
    var rt_den: [@as(usize, 1) << logn]f64 = undefined;
    var rt_num: [@as(usize, 1) << logn]f64 = undefined;
    for (0..n) |u| rt_den[u] = fpr.of(@as(i32, @bitCast(tmp[t2 + u])));
    fft.fftRaw(&rt_den, logn);
    for (0..n) |u| rt_num[u] = fpr.of(@as(i32, @bitCast(tmp[t1 + u])));
    fft.fftRaw(&rt_num, logn);
    fft.polyDivAutoadjFft(&rt_num, &rt_den, logn);
    fft.ifftRaw(&rt_num, logn);
    for (0..n) |u| {
        const z: i32 = @bitCast(@as(u32, @truncate(@as(u64, @bitCast(fpr.rint(rt_num[u]))))));
        tmp[t1 + u] = modpSet(z, p);
    }

    // F -= k*f, G -= k*g (mod p, exact since everything is small).
    modpMkgm2(tmp[t2 .. t2 + n], tmp[t3 .. t3 + n], logn, primes[0].g, p, p0i);
    for (0..n) |u| {
        tmp[t4 + u] = modpSet(f[u], p);
        tmp[t5 + u] = modpSet(g[u], p);
    }
    modpNTT2Ext(tmp[t1 .. t1 + n], 1, tmp[t2..], logn, p, p0i);
    modpNTT2Ext(tmp[t4 .. t4 + n], 1, tmp[t2..], logn, p, p0i);
    modpNTT2Ext(tmp[t5 .. t5 + n], 1, tmp[t2..], logn, p, p0i);
    for (0..n) |u| {
        const kw = modpMontymul(tmp[t1 + u], R2, p, p0i);
        tmp[u] = modpSub(tmp[u], modpMontymul(kw, tmp[t4 + u], p, p0i), p);
        tmp[n + u] = modpSub(tmp[n + u], modpMontymul(kw, tmp[t5 + u], p, p0i), p);
    }
    modpINTT2Ext(tmp[0..n], 1, tmp[t3..], logn, p, p0i);
    modpINTT2Ext(tmp[n .. 2 * n], 1, tmp[t3..], logn, p, p0i);
    for (0..n) |u| {
        tmp[u] = @bitCast(modpNorm(tmp[u], p));
        tmp[n + u] = @bitCast(modpNorm(tmp[n + u], p));
    }
    return true;
}

/// NTRUSolve (spec §3.8.2 Algorithm 6): solve f*G - g*F = q for small
/// (F, G). Deterministic; consumes no randomness. `tmp` is the shared
/// u32 pool (see `Ntru.generate` for sizing). Reference solve_NTRU,
/// including its final NTT-based verification of the NTRU equation.
fn solveNtru(comptime logn: u5, f: []const i8, g: []const i8, F_out: []i8, G_out: []i8, lim: i32, tmp: []u32, primes: []const SmallPrime) bool {
    const n = @as(usize, 1) << logn;

    if (!solveNtruDeepest(logn, f, g, tmp, primes)) return false;
    if (logn <= 2) {
        var depth: u5 = logn;
        while (depth > 0) {
            depth -= 1;
            if (!solveNtruIntermediate(logn, f, g, depth, tmp, primes)) return false;
        }
    } else {
        var depth: u5 = logn;
        while (depth > 2) {
            depth -= 1;
            if (!solveNtruIntermediate(logn, f, g, depth, tmp, primes)) return false;
        }
        if (!solveNtruBinaryDepth1(logn, f, g, tmp, primes)) return false;
        if (!solveNtruBinaryDepth0(logn, f, g, tmp, primes)) return false;
    }

    if (!polyBigToSmall(F_out, tmp[0..n], lim, logn)) return false;
    if (!polyBigToSmall(G_out, tmp[n .. 2 * n], lim, logn)) return false;

    // Verify f*G - g*F = q via NTT modulo one small prime.
    // Layout: Gt @0, ft @n, gt @2n, Ft @3n, gm @4n (igm scratch @0
    // before Gt is filled, same order as the reference).
    const p = primes[0].p;
    const p0i = modpNinv31(p);
    modpMkgm2(tmp[4 * n .. 5 * n], tmp[0..n], logn, primes[0].g, p, p0i);
    for (0..n) |u| tmp[u] = modpSet(G_out[u], p);
    for (0..n) |u| {
        tmp[n + u] = modpSet(f[u], p);
        tmp[2 * n + u] = modpSet(g[u], p);
        tmp[3 * n + u] = modpSet(F_out[u], p);
    }
    modpNTT2Ext(tmp[n .. 2 * n], 1, tmp[4 * n ..], logn, p, p0i);
    modpNTT2Ext(tmp[2 * n .. 3 * n], 1, tmp[4 * n ..], logn, p, p0i);
    modpNTT2Ext(tmp[3 * n .. 4 * n], 1, tmp[4 * n ..], logn, p, p0i);
    modpNTT2Ext(tmp[0..n], 1, tmp[4 * n ..], logn, p, p0i);
    const r = modpMontymul(12289, 1, p, p0i);
    for (0..n) |u| {
        const z = modpSub(
            modpMontymul(tmp[n + u], tmp[u], p, p0i),
            modpMontymul(tmp[2 * n + u], tmp[3 * n + u], p, p0i),
            p,
        );
        if (z != r) return false;
    }
    return true;
}

// ---- NTRUGen: the public entry point ----

/// Squared norm of a small vector, saturated to 2^32-1 above 2^31
/// (reference poly_small_sqnorm).
fn polySmallSqnorm(f: []const i8) u32 {
    var s: u32 = 0;
    var ng: u32 = 0;
    for (f) |x| {
        const z: i32 = x;
        s +%= @intCast(z * z);
        ng |= s;
    }
    return s | (0 -% (ng >> 31));
}

/// Per-degree secret-key encoding widths (reference max_fg_bits; F/G
/// are always 8 bits).
const max_fg_bits = [_]u5{ 0, 8, 8, 8, 8, 8, 7, 7, 6, 6, 5 };

/// NTRU basis generation, specialized to one `poly.Ring(logn)` degree.
pub fn Ntru(comptime Ring: type) type {
    return struct {
        /// The full NTRU secret basis: (f, g) plus the co-basis (F, G)
        /// solving f*G - g*F = q. Only (f, g, F) are ever written to the
        /// wire (`root.zig`'s `SecretKey`, `keygen.zig`'s
        /// `toSecretKeyBytes`); G is kept in memory only, to drive the
        /// ffSampling basis (`ffsampling.buildTree`) at signing time.
        pub const Basis = struct {
            f: [Ring.n]i8,
            g: [Ring.n]i8,
            big_f: [Ring.n]i8,
            big_g: [Ring.n]i8,
        };

        /// Generate a fresh NTRU basis (reference Zf(keygen)'s loop,
        /// minus the h output — `keygen.zig` recomputes h via the
        /// already-KAT-verified `poly.Ring.computePublic`).
        ///
        /// `rng` drives the (f, g) Gaussian sampling in 8-byte draws.
        /// For byte-exact NIST-KAT reproduction, feed it a
        /// `sign.ShakePrng` seeded with the 48 bytes the KAT DRBG hands
        /// `crypto_sign_keypair` (that is exactly the reference's
        /// SHAKE256 keygen RNG); NTRUSolve itself is deterministic. The
        /// acceptance loop (encoding-width limit, ||(g,-f)||^2 bound,
        /// FP Gram-Schmidt bnorm bound, f invertible mod q, NTRU
        /// equation solvable) retries internally until a valid basis is
        /// found — the spec's own analysis says a few tries suffice, so
        /// no iteration cap is exposed here.
        pub fn generate(rng: std.Random) Basis {
            const logn = Ring.logn;
            const n = Ring.n;
            comptime std.debug.assert(Ring.n == @as(usize, 1) << Ring.logn);

            const primes = computePrimes();
            var basis: Basis = undefined;
            // Shared u32 pool for all of NTRUSolve; 8n limbs covers the
            // deepest make_fg layout (6n at the top step, offset 2*209)
            // and every solver level (see the per-level layouts above).
            // `pool`/`rt1`/`rt2`/`rt3` are scratch that carries the secret
            // (f, g) basis through NTRUSolve's big-integer descent and the
            // FP Gram-Schmidt norm check; wiped on return. `basis` itself
            // is NOT wiped here — it is the function's return value (the
            // actual signing key material the caller still needs).
            var pool: [8 * n + 64]u32 = undefined;
            defer std.crypto.secureZero(u32, &pool);
            var rt1: [n]f64 = undefined;
            defer std.crypto.secureZero(f64, &rt1);
            var rt2: [n]f64 = undefined;
            defer std.crypto.secureZero(f64, &rt2);
            var rt3: [n]f64 = undefined;
            defer std.crypto.secureZero(f64, &rt3);
            const fg_lim: i32 = @as(i32, 1) << (max_fg_bits[logn] - 1);

            outer: while (true) {
                polySmallMkgauss(rng, &basis.f, logn);
                polySmallMkgauss(rng, &basis.g, logn);

                // Coefficients must fit the trimmed sk encoding.
                for (0..n) |u| {
                    if (basis.f[u] >= fg_lim or basis.f[u] <= -fg_lim or
                        basis.g[u] >= fg_lim or basis.g[u] <= -fg_lim)
                    {
                        continue :outer;
                    }
                }

                // ||(g,-f)||^2 < floor(1.17^2 * q) + 1 = 16823.
                const normf = polySmallSqnorm(&basis.f);
                const normg = polySmallSqnorm(&basis.g);
                const norm = (normf +% normg) | (0 -% ((normf | normg) >> 31));
                if (norm >= 16823) continue;

                // Orthogonalized-vector norm bound (FP, byte-exact fft).
                for (0..n) |u| {
                    rt1[u] = fpr.of(basis.f[u]);
                    rt2[u] = fpr.of(basis.g[u]);
                }
                fft.fftRaw(&rt1, logn);
                fft.fftRaw(&rt2, logn);
                fft.polyInvnorm2Fft(&rt3, &rt1, &rt2, logn);
                fft.polyAdjFft(&rt1, logn);
                fft.polyAdjFft(&rt2, logn);
                fft.polyMulconst(&rt1, fpr.q, logn);
                fft.polyMulconst(&rt2, fpr.q, logn);
                fft.polyMulAutoadjFft(&rt1, &rt3, logn);
                fft.polyMulAutoadjFft(&rt2, &rt3, logn);
                fft.ifftRaw(&rt1, logn);
                fft.ifftRaw(&rt2, logn);
                var bnorm: f64 = 0.0;
                for (0..n) |u| {
                    bnorm = fpr.add(bnorm, fpr.sqr(rt1[u]));
                    bnorm = fpr.add(bnorm, fpr.sqr(rt2[u]));
                }
                if (!fpr.lt(bnorm, fpr_bnorm_max)) continue;

                // f must be invertible mod q (h = g/f computable).
                _ = Ring.computePublic(&basis.f, &basis.g) catch continue;

                // Solve the NTRU equation; |F|, |G| <= 127.
                if (!solveNtru(logn, &basis.f, &basis.g, &basis.big_f, &basis.big_g, 127, &pool, &primes)) {
                    continue;
                }

                return basis;
            }
        }
    };
}

// ---- Tests ----

test "Ntru(Ring) instantiates for both parameter sets" {
    const poly = @import("poly.zig");
    _ = Ntru(poly.Ring512).Basis;
    _ = Ntru(poly.Ring1024).Basis;
}

test "computePrimes reproduces the reference PRIMES table head (p and s)" {
    // First 14 (p, s) pairs transcribed from the reference keygen.c
    // PRIMES[] table. `g` is intentionally not compared — see the module
    // doc comment (any primitive 2048-th root gives identical CRT
    // output; the reference's specific choice is not canonical).
    const want = [_][2]u32{
        .{ 2147473409, 10239 },      .{ 2147389441, 471403745 },
        .{ 2147387393, 1329335065 }, .{ 2147377153, 968223422 },
        .{ 2147358721, 132460015 },  .{ 2147352577, 598693809 },
        .{ 2147346433, 1056257184 }, .{ 2147338241, 421286710 },
        .{ 2147309569, 1111201074 }, .{ 2147297281, 1042003613 },
        .{ 2147295233, 19440033 },   .{ 2147239937, 353296760 },
        .{ 2147235841, 1703918027 }, .{ 2147217409, 1258919613 },
    };
    const primes = computePrimes();
    for (want, 0..) |w, i| {
        try std.testing.expectEqual(w[0], primes[i].p);
        try std.testing.expectEqual(w[1], primes[i].s);
    }
    // Structural invariants over the whole table.
    for (0..NPRIMES) |i| {
        try std.testing.expectEqual(@as(u32, 1), primes[i].p % 2048);
        try std.testing.expect(primes[i].p > (1 << 30));
        if (i > 0) try std.testing.expect(primes[i].p < primes[i - 1].p);
        // g has order exactly 2048.
        try std.testing.expectEqual(@as(u64, primes[i].p - 1), powMod(primes[i].g, 1024, primes[i].p));
    }
}

test "NTRUSolve reproduces the Falcon-512 KAT secret key's F byte-exact" {
    const falcon = @import("root.zig");
    const v = @import("kat_vectors.zig");
    const gpa = std.testing.allocator;

    const sk = try gpa.alloc(u8, v.falcon512[0].sk.len / 2);
    defer gpa.free(sk);
    _ = try std.fmt.hexToBytes(sk, v.falcon512[0].sk);
    const dsk = try falcon.SecretKey.fromBytes(sk[0..falcon.SecretKey.encoded_length]);

    const primes = computePrimes();
    var pool: [8 * 512 + 64]u32 = undefined;
    var big_f: [512]i8 = undefined;
    var big_g: [512]i8 = undefined;
    try std.testing.expect(solveNtru(9, &dsk.f, &dsk.g, &big_f, &big_g, 127, &pool, &primes));
    // The KAT sk's F field is the reference's own solve_NTRU output for
    // this (f, g) — a byte-exact NTRUSolve check isolated from NTRUGen.
    try std.testing.expectEqualSlices(i8, &dsk.big_f, &big_f);
}

test "NTRUSolve reproduces the Falcon-1024 KAT secret key's F byte-exact" {
    const falcon = @import("root.zig");
    const v = @import("kat_vectors.zig");
    const gpa = std.testing.allocator;

    const sk = try gpa.alloc(u8, v.falcon1024[0].sk.len / 2);
    defer gpa.free(sk);
    _ = try std.fmt.hexToBytes(sk, v.falcon1024[0].sk);
    const dsk = try falcon.SecretKey1024.fromBytes(sk[0..falcon.SecretKey1024.encoded_length]);

    const primes = computePrimes();
    var pool: [8 * 1024 + 64]u32 = undefined;
    var big_f: [1024]i8 = undefined;
    var big_g: [1024]i8 = undefined;
    try std.testing.expect(solveNtru(10, &dsk.f, &dsk.g, &big_f, &big_g, 127, &pool, &primes));
    try std.testing.expectEqualSlices(i8, &dsk.big_f, &big_f);
}
