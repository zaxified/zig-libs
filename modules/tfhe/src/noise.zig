// SPDX-License-Identifier: MIT

//! noise — **constant-time** centred Gaussian sampling for TFHE errors.
//!
//! The tfhe-rs parameter sets (`params.tfhers_*`) specify Gaussian errors by
//! their standard deviation as a fraction of `q`. This file turns two uniform
//! 64-bit draws into one such error with the Box–Muller transform,
//!
//!     z = √(−2·ln u₁) · cos(2π·u₂),   e = round(z · σ·2^32)  (mod 2^32),
//!
//! and does it without a single data-dependent branch or memory index.
//!
//! ## Why not `std.math.log` / `std.math.cos`
//!
//! The error is as secret as the key: `b − ⟨a,s⟩ = μ + e`, so a known `e`
//! turns one ciphertext into a linear equation in `s`. `std.math`'s `log` and
//! `cos` branch on their argument (special cases, range reduction), so the
//! time they take depends on the error being drawn. Here instead:
//!
//!   * `ln` reads the exponent off the IEEE bits, folds the mantissa into
//!     `[√½, √2)` with an arithmetic select, and sums a fixed-length atanh
//!     series (`ln m = 2·atanh((m−1)/(m+1))`, `|z| ≤ 0.1716`, 11 terms:
//!     truncation `< 10^-17`).
//!   * `cos(2π·v)` folds `v` into `[0, ¼]` with integer arithmetic on the draw
//!     itself (no `@floor`, which can lower to a libm call on baseline x86-64)
//!     and evaluates a fixed 12-term Taylor polynomial on `[0, π/2]`
//!     (truncation `< 2·10^-17`).
//!   * rounding uses the `1.5·2^52` magic constant and reads the integer out of
//!     the mantissa bits: no `@intFromFloat`, whose safety check is a branch.
//!
//! What this does **not** claim: IEEE division and square root are not
//! guaranteed fixed-latency on every microarchitecture. There is no branch and
//! no secret-indexed load (what `ctgrind_harness.zig`'s `noise` target checks
//! under valgrind), which is the property a compiler-and-tool check can
//! establish; operand-dependent latency of `divsd`/`sqrtsd` is outside it.
//!
//! ## Tails
//!
//! `u₁ ≥ 2^-53` (it is never 0), so `|z| ≤ √(2·53·ln 2) ≈ 8.57`: the sampler
//! is the Gaussian truncated at 8.57σ, a statistical distance of about
//! `10^-17`.

const std = @import("std");

/// `2^-53`.
const ulp53: f64 = 1.0 / 9007199254740992.0;
const sqrt2: f64 = 1.4142135623730951;
const ln2: f64 = 0.6931471805599453;
const two_pi: f64 = 6.283185307179586;

/// All-ones iff `c`, laundered through `blackBox` so the select below stays a
/// select.
inline fn maskOf(c: bool) u64 {
    return blackBox(0 -% @as(u64, @intFromBool(c)));
}

/// Optimization barrier (the `p256`/`hqc`/`montint` idiom): an empty inline
/// asm hides from LLVM that the mask is `0` or all-ones. Without it LLVM
/// recognised `(a & m) | (b & ~m)` as a select of two `f64`s and, x86 having
/// no `f64` cmov, lowered it to a `jbe` around the multiply — measured by
/// `ctgrind_harness.zig`'s `noise` target (4 contexts, 2026-10-02) and
/// confirmed in the disassembly. No-op at runtime.
inline fn blackBox(x: u64) u64 {
    if (@inComptime()) return x;
    return asm volatile (""
        : [ret] "=r" (-> u64),
        : [x] "0" (x),
    );
}

/// `c ? a : b` on the bit patterns — no branch for a compiler to keep.
inline fn select(c: bool, a: f64, b: f64) f64 {
    const m = maskOf(c);
    const ab: u64 = @bitCast(a);
    const bb: u64 = @bitCast(b);
    return @bitCast((ab & m) | (bb & ~m));
}

/// A draw mapped to `(0, 1]`: `(⌊u/2^11⌋ + 1)·2^-53`. Never 0 (so `ln` is
/// finite) and never subnormal. The conversion is signed (`< 2^53`), so it is
/// one `cvtsi2sd`, not the branchy unsigned 64-bit path.
pub fn unitOpenZero(u: u64) f64 {
    const v: i64 = @intCast((u >> 11) + 1);
    return @as(f64, @floatFromInt(v)) * ulp53;
}

/// Natural logarithm for `x ∈ [2^-53, 1]` (any normal positive `x` works).
/// Branch-free; relative error a few ulp.
pub fn ln(x: f64) f64 {
    const bits: u64 = @bitCast(x);
    var e: i64 = @as(i64, @intCast(bits >> 52)) - 1023;
    var m: f64 = @bitCast((bits & 0x000F_FFFF_FFFF_FFFF) | 0x3FF0_0000_0000_0000); // [1, 2)
    const big = m > sqrt2;
    m = select(big, m * 0.5, m); // [√½, √2)
    e += @intFromBool(big);
    const z = (m - 1.0) / (m + 1.0);
    const z2 = z * z;
    // 2·(z + z³/3 + … + z²¹/21), Horner in z².
    var s: f64 = 2.0 / 21.0;
    s = s * z2 + 2.0 / 19.0;
    s = s * z2 + 2.0 / 17.0;
    s = s * z2 + 2.0 / 15.0;
    s = s * z2 + 2.0 / 13.0;
    s = s * z2 + 2.0 / 11.0;
    s = s * z2 + 2.0 / 9.0;
    s = s * z2 + 2.0 / 7.0;
    s = s * z2 + 2.0 / 5.0;
    s = s * z2 + 2.0 / 3.0;
    s = s * z2 + 2.0;
    return @as(f64, @floatFromInt(e)) * ln2 + s * z;
}

/// `cos(2π·v)` for the 53-bit fraction `v = w·2^-53`, `w = ⌊u/2^11⌋`.
/// Branch-free.
pub fn cos2pi(u: u64) f64 {
    const w: i64 = @intCast(u >> 11); // [0, 2^53)
    // Fold v ∈ [0,1) to t ∈ [−½, ½): subtract 1 when v ≥ ½.
    const t_int: i64 = w - (@as(i64, @intCast(u >> 63)) << 53);
    const a_int: i64 = @intCast(@abs(t_int)); // [0, 2^52]
    const a = @as(f64, @floatFromInt(a_int)) * ulp53; // |t| ∈ [0, ½]
    // cos(2πa) = −cos(2π(½ − a)): fold a into [0, ¼].
    const far = a > 0.25;
    const b = select(far, 0.5 - a, a);
    const x = two_pi * b; // [0, π/2]
    const x2 = x * x;
    // Σ (−1)^i x^{2i}/(2i)!, i = 0..11, Horner in x².
    var c: f64 = 1.0 / 1.1240007277776077e21; // 1/22!
    c = c * -x2 + 1.0 / 2.43290200817664e18; // 1/20!
    c = c * -x2 + 1.0 / 6.402373705728e15; // 1/18!
    c = c * -x2 + 1.0 / 20922789888000.0; // 1/16!
    c = c * -x2 + 1.0 / 87178291200.0; // 1/14!
    c = c * -x2 + 1.0 / 479001600.0; // 1/12!
    c = c * -x2 + 1.0 / 3628800.0; // 1/10!
    c = c * -x2 + 1.0 / 40320.0; // 1/8!
    c = c * -x2 + 1.0 / 720.0; // 1/6!
    c = c * -x2 + 1.0 / 24.0; // 1/4!
    c = c * -x2 + 1.0 / 2.0; // 1/2!
    c = c * -x2 + 1.0;
    return select(far, -c, c);
}

/// Round to the nearest integer (ties to even) for `|x| < 2^51`: adding
/// `1.5·2^52` lands `x` in a binade whose ulp is 1, and the integer is the
/// difference of the two bit patterns. No conversion instruction, no branch.
pub fn roundToInt(x: f64) i64 {
    const magic: f64 = 6755399441055744.0; // 1.5 · 2^52
    const y = x + magic;
    return @as(i64, @bitCast(@as(u64, @bitCast(y)))) - @as(i64, @bitCast(@as(u64, @bitCast(magic))));
}

/// One standard normal variate from two uniform 64-bit draws (Box–Muller,
/// cosine branch only: a fixed two draws per sample).
pub fn standardNormal(d1: u64, d2: u64) f64 {
    return @sqrt(-2.0 * ln(unitOpenZero(d1))) * cos2pi(d2);
}

/// A torus error with standard deviation `sigma_q` torus units (`σ·2^32` for
/// tfhe-rs's fractional `σ`), as a wrapping `u32`.
pub fn gaussianTorus(sigma_q: f64, d1: u64, d2: u64) u32 {
    const e = roundToInt(standardNormal(d1, d2) * sigma_q);
    return @truncate(@as(u64, @bitCast(e)));
}

const testing = std.testing;

test "ln agrees with std.math.log across [2^-53, 1]" {
    var prng = std.Random.DefaultPrng.init(0x10a);
    const rnd = prng.random();
    const fixed = [_]f64{ 1.0, 0.5, 0.25, ulp53, 1.0 - ulp53, 0.7071067811865476, 0.7071067811865475, 1.0 / 3.0 };
    for (fixed) |x| try testing.expectApproxEqAbs(@log(x), ln(x), 4e-15 * @max(1.0, @abs(@log(x))));
    for (0..100_000) |_| {
        const x = unitOpenZero(rnd.int(u64));
        try testing.expectApproxEqAbs(@log(x), ln(x), 4e-15 * @max(1.0, @abs(@log(x))));
    }
    // Small values: every binade down to 2^-53.
    var x: f64 = 1.0;
    for (0..53) |_| {
        x *= 0.5;
        try testing.expectApproxEqAbs(@log(x * 1.37), ln(x * 1.37), 4e-15 * @abs(@log(x * 1.37)));
    }
}

test "cos2pi agrees with std.math.cos(2πv) across [0, 1)" {
    var prng = std.Random.DefaultPrng.init(0xc05);
    const rnd = prng.random();
    const fixed = [_]u64{ 0, 1 << 61, 1 << 62, 3 << 61, 1 << 63, 5 << 61, 3 << 62, 7 << 61, std.math.maxInt(u64) };
    for (fixed) |u| {
        const v = @as(f64, @floatFromInt(u >> 11)) * ulp53;
        try testing.expectApproxEqAbs(@cos(two_pi * v), cos2pi(u), 1e-14);
    }
    for (0..100_000) |_| {
        const u = rnd.int(u64);
        const v = @as(f64, @floatFromInt(u >> 11)) * ulp53;
        try testing.expectApproxEqAbs(@cos(two_pi * v), cos2pi(u), 1e-14);
    }
}

test "roundToInt is round-to-nearest-even on both signs" {
    const cases = [_]struct { f64, i64 }{
        .{ 0.0, 0 },           .{ 0.4999, 0 },          .{ 0.5, 0 },                      .{ 1.5, 2 },
        .{ 2.5, 2 },           .{ -0.5, 0 },            .{ -1.5, -2 },                    .{ -2.6, -3 },
        .{ 123456.7, 123457 }, .{ -123456.7, -123457 }, .{ 1e15, 1_000_000_000_000_000 },
    };
    for (cases) |c| try testing.expectEqual(c[1], roundToInt(c[0]));
}

test "gaussianTorus: moments match σ, the sign is symmetric, tails are bounded" {
    var prng = std.Random.DefaultPrng.init(0x6a55);
    const rnd = prng.random();
    const sigma: f64 = 25175.5; // tfhers_default's LWE width in torus units
    const count = 200_000;
    var sum: f64 = 0;
    var sum2: f64 = 0;
    var neg: usize = 0;
    var max_abs: i64 = 0;
    for (0..count) |_| {
        const e: i32 = @bitCast(gaussianTorus(sigma, rnd.int(u64), rnd.int(u64)));
        const f: f64 = @floatFromInt(e);
        sum += f;
        sum2 += f * f;
        if (e < 0) neg += 1;
        max_abs = @max(max_abs, @as(i64, @abs(e)));
    }
    const mean = sum / count;
    const sd = @sqrt(sum2 / count - mean * mean);
    // Standard error of the mean: σ/√n ≈ 56; of the stddev: σ/√(2n) ≈ 40.
    try testing.expect(@abs(mean) < 5 * sigma / @sqrt(@as(f64, count)));
    try testing.expectApproxEqRel(sigma, sd, 0.01);
    try testing.expect(neg > count / 2 - 2000 and neg < count / 2 + 2000);
    try testing.expect(@as(f64, @floatFromInt(max_abs)) <= 8.6 * sigma);
}

test "KAT: Box–Muller on fixed draws (values from Python's math.log/math.cos)" {
    // python3: u1=((d1>>11)+1)/2**53; v=(d2>>11)/2**53;
    //          round(math.sqrt(-2*math.log(u1))*math.cos(2*math.pi*v)*sigma)
    const sigma: f64 = 25175.5;
    const cases = [_]struct { u64, u64, i32 }{
        .{ 0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210, 82826 },
        .{ 0x8000_0000_0000_0000, 0x0000_0000_0000_0000, 29642 },
        .{ 0xffff_ffff_ffff_ffff, 0x4000_0000_0000_0000, 0 },
        .{ 0x0000_0000_0000_0000, 0x8000_0000_0000_0000, -215796 },
        .{ 0x5555_5555_5555_5555, 0x2aaa_aaaa_aaaa_aaaa, 18659 },
    };
    for (cases) |c| try testing.expectEqual(c[2], @as(i32, @bitCast(gaussianTorus(sigma, c[0], c[1]))));
}
