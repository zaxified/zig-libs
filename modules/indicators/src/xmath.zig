// SPDX-License-Identifier: MIT
//! The C library functions of the ported TA-Lib sources that Zig has no builtin
//! for (`atan`, `asin`, `acos`, `sinh`, `cosh`, `tanh`), written so that their
//! rounding matches what a good C library answers, to the last bit in all but the
//! rarest cases, on every platform and without linking one.
//!
//! The three inverse trigonometric functions are evaluated in double-double
//! arithmetic (about 106 bits: argument reduction by the half-angle identity
//! `atan x = 2 atan(x / (1 + sqrt(1 + x^2)))`, a Taylor series, results rounded
//! once), so they are correctly rounded except where the exact value lies within
//! ~1e-30 of a rounding boundary. A C library whose own error bound is below
//! one ULP (the usual 0.5x) then differs from them only where *it* misrounds.
//! The hyperbolic functions follow the classical fdlibm formulas (`expm1` below
//! 22, `exp` above), the ones C libraries derive theirs from.
//!
//! Why not `std.math`: its `atan` / `asin` / `acos` are fdlibm polynomials
//! (error up to 1 ULP, 0.3% of the results differ from the correctly rounded
//! one), and its `sinh` / `cosh` / `tanh` use a different `exp` scaling above
//! 22: both showed up against TA-Lib's oracle as last-bit differences that a
//! recursive indicator (the Hilbert-transform family) then carries along.

const std = @import("std");

// ── double-double ───────────────────────────────────────────────────────────

const DD = struct { hi: f64, lo: f64 };

fn quickTwoSum(a: f64, b: f64) DD {
    const s = a + b;
    return .{ .hi = s, .lo = b - (s - a) };
}
fn twoSum(a: f64, b: f64) DD {
    const s = a + b;
    const bb = s - a;
    return .{ .hi = s, .lo = (a - (s - bb)) + (b - bb) };
}
fn twoProd(a: f64, b: f64) DD {
    const p = a * b;
    return .{ .hi = p, .lo = @mulAdd(f64, a, b, -p) };
}
fn add(a: DD, b: DD) DD {
    const s = twoSum(a.hi, b.hi);
    const t = twoSum(a.lo, b.lo);
    var r = quickTwoSum(s.hi, s.lo + t.hi);
    r = quickTwoSum(r.hi, r.lo + t.lo);
    return r;
}
fn neg(a: DD) DD {
    return .{ .hi = -a.hi, .lo = -a.lo };
}
fn sub(a: DD, b: DD) DD {
    return add(a, neg(b));
}
fn mul(a: DD, b: DD) DD {
    var p = twoProd(a.hi, b.hi);
    p.lo += a.hi * b.lo + a.lo * b.hi;
    return quickTwoSum(p.hi, p.lo);
}
fn mulD(a: DD, b: f64) DD {
    var p = twoProd(a.hi, b);
    p.lo += a.lo * b;
    return quickTwoSum(p.hi, p.lo);
}
fn div(a: DD, b: DD) DD {
    const q1 = a.hi / b.hi;
    var r = sub(a, mulD(b, q1));
    const q2 = r.hi / b.hi;
    r = sub(r, mulD(b, q2));
    const q3 = r.hi / b.hi;
    return add(quickTwoSum(q1, q2), .{ .hi = q3, .lo = 0.0 });
}
/// Square root of a positive double-double.
fn sqrtDD(a: DD) DD {
    if (a.hi <= 0.0) return .{ .hi = 0.0, .lo = 0.0 };
    const s0 = @sqrt(a.hi);
    const r = sub(a, twoProd(s0, s0));
    return quickTwoSum(s0, r.hi / (2.0 * s0));
}

const one: DD = .{ .hi = 1.0, .lo = 0.0 };
/// pi / 2 to 106 bits.
const half_pi: DD = .{ .hi = 1.5707963267948966, .lo = 6.123233995736766e-17 };

/// 1/(2k+1) as a double-double, for the Taylor series.
fn recip(comptime d: comptime_int) DD {
    const q: f128 = 1.0 / @as(f128, d);
    const hi: f64 = @floatCast(q);
    const lo: f64 = @floatCast(q - @as(f128, hi));
    return .{ .hi = hi, .lo = lo };
}
const n_terms = 18;
const inv_odd = blk: {
    var t: [n_terms]DD = undefined;
    for (&t, 0..) |*e, k| e.* = recip(2 * k + 1);
    break :blk t;
};

/// atan of a double-double in [0, 1].
fn atanUnit(x: DD) DD {
    var t = x;
    // three half-angle reductions: t <= tan(pi/32) = 0.0985
    for (0..3) |_| {
        const s = sqrtDD(add(one, mul(t, t)));
        t = div(t, add(one, s));
    }
    const t2 = mul(t, t);
    var p = inv_odd[n_terms - 1];
    var k: usize = n_terms - 1;
    while (k > 0) {
        k -= 1;
        p = sub(inv_odd[k], mul(t2, p));
    }
    const r = mul(t, p);
    return .{ .hi = r.hi * 8.0, .lo = r.lo * 8.0 };
}

/// atan of a double-double >= 0 (any size).
fn atanPos(x: DD) DD {
    if (x.hi <= 1.0) return atanUnit(x);
    return sub(half_pi, atanUnit(div(one, x)));
}

fn finish(r: DD, x: f64) f64 {
    return std.math.copysign(r.hi + r.lo, x);
}

/// atan(x), correctly rounded except for a ~1e-30 sliver around the rounding boundaries.
pub fn atan(x: f64) f64 {
    if (std.math.isNan(x) or x == 0.0) return x;
    const ax = @abs(x);
    if (ax < 7.450580596923828e-9) return x; // 2^-27: atan x rounds to x
    if (std.math.isInf(ax)) return std.math.copysign(half_pi.hi, x);
    return finish(atanPos(.{ .hi = ax, .lo = 0.0 }), x);
}

fn asinDD(ax: f64) DD {
    if (ax == 1.0) return half_pi;
    const u = sub(one, twoProd(ax, ax));
    return atanPos(div(.{ .hi = ax, .lo = 0.0 }, sqrtDD(u)));
}

/// asin(x), NaN outside [-1, 1].
pub fn asin(x: f64) f64 {
    if (std.math.isNan(x) or x == 0.0) return x;
    const ax = @abs(x);
    if (ax > 1.0) return std.math.nan(f64);
    if (ax < 7.450580596923828e-9) return x;
    return finish(asinDD(ax), x);
}

/// acos(x), NaN outside [-1, 1].
pub fn acos(x: f64) f64 {
    if (std.math.isNan(x)) return x;
    const ax = @abs(x);
    if (ax > 1.0) return std.math.nan(f64);
    const a: DD = if (ax < 7.450580596923828e-9) .{ .hi = ax, .lo = 0.0 } else asinDD(ax);
    const r = if (x >= 0.0) sub(half_pi, a) else add(half_pi, a);
    return r.hi + r.lo;
}

// ── exp in double-double, for the large-argument hyperbolics ────────────────

const ln2_dd: DD = .{ .hi = 0.6931471805599453, .lo = 2.3190468138462996e-17 };

/// exp(x) = p * 2^k for 22 <= x <= 710.48: `p` in [0.7, 1.42] as a double-double.
fn expParts(x: f64) struct { p: DD, k: i32 } {
    const kf = @round(x * 1.4426950408889634);
    const r0 = sub(.{ .hi = x, .lo = 0.0 }, mulD(ln2_dd, kf));
    const r: DD = .{ .hi = r0.hi / 256.0, .lo = r0.lo / 256.0 }; // |r| <= 0.00136
    var p = one;
    var j: f64 = 10.0;
    while (j >= 1.0) : (j -= 1.0) p = add(one, div(mul(r, p), .{ .hi = j, .lo = 0.0 }));
    for (0..8) |_| p = mul(p, p);
    return .{ .p = p, .k = @intFromFloat(kf) };
}

/// (exp(x) + sign * exp(-x)) / 2 for 22 <= x <= 710.48, correctly rounded.
fn halfExpPlus(x: f64, comptime sign: f64) f64 {
    const e = expParts(x);
    var v = e.p;
    if (x < 45.0) {
        const inv = div(one, e.p);
        const sc = std.math.ldexp(@as(f64, 1.0), -2 * e.k);
        v = add(v, .{ .hi = sign * inv.hi * sc, .lo = sign * inv.lo * sc });
    }
    return std.math.ldexp(v.hi + v.lo, e.k - 1);
}

// ── hyperbolic functions (fdlibm's formulas) ────────────────────────────────

const overflow_threshold: f64 = 710.4758600739439;

fn highWord(x: f64) u32 {
    return @intCast((@as(u64, @bitCast(x)) >> 32) & 0x7fffffff);
}

pub fn sinh(x: f64) f64 {
    const ix = highWord(x);
    if (ix >= 0x7ff00000) return x + x; // inf, NaN
    const h: f64 = if (std.math.signbit(x)) -0.5 else 0.5; // sign of the small-argument branch
    const ax = @abs(x);
    if (ix < 0x40360000) { // |x| < 22
        if (ix < 0x3e300000) return x; // |x| < 2^-28
        const t = std.math.expm1(ax);
        if (ix < 0x3ff00000) return h * (2.0 * t - t * t / (t + 1.0));
        return h * (t + t / (t + 1.0));
    }
    if (ax <= overflow_threshold) return std.math.copysign(halfExpPlus(ax, -1.0), x);
    return std.math.copysign(std.math.inf(f64), x);
}

pub fn cosh(x: f64) f64 {
    const ix = highWord(x);
    if (ix >= 0x7ff00000) return x * x;
    const ax = @abs(x);
    if (ix < 0x3fd62e43) { // |x| < 0.5 ln 2
        const t = std.math.expm1(ax);
        const w = 1.0 + t;
        if (ix < 0x3c800000) return w; // cosh = 1 to the last bit
        return 1.0 + (t * t) / (w + w);
    }
    if (ix < 0x40360000) { // |x| < 22
        const t = @exp(ax);
        return 0.5 * t + 0.5 / t;
    }
    if (ax <= overflow_threshold) return halfExpPlus(ax, 1.0);
    return std.math.inf(f64);
}

pub fn tanh(x: f64) f64 {
    const ix = highWord(x);
    if (ix >= 0x7ff00000) return if (std.math.isNan(x)) x else std.math.copysign(@as(f64, 1.0), x);
    var z: f64 = undefined;
    if (ix < 0x40360000) { // |x| < 22
        if (ix < 0x3c800000) return x * (1.0 + x); // |x| < 2^-55
        const ax = @abs(x);
        if (ix >= 0x3ff00000) {
            const t = std.math.expm1(2.0 * ax);
            z = 1.0 - 2.0 / (t + 2.0);
        } else {
            const t = std.math.expm1(-2.0 * ax);
            z = -t / (t + 2.0);
        }
    } else {
        z = 1.0; // 1 - tiny
    }
    return if (std.math.signbit(x)) -z else z;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn ulpsApart(a: f64, b: f64) u64 {
    const ia: i64 = @bitCast(a);
    const ib: i64 = @bitCast(b);
    return @abs(ia - ib);
}

test "atan, asin, acos: special values and exact points" {
    try testing.expectEqual(@as(f64, 0.7853981633974483), atan(1.0));
    try testing.expectEqual(@as(f64, -0.7853981633974483), atan(-1.0));
    try testing.expectEqual(@as(f64, 1.5707963267948966), atan(std.math.inf(f64)));
    try testing.expectEqual(@as(f64, -1.5707963267948966), atan(-std.math.inf(f64)));
    try testing.expect(std.math.signbit(atan(-0.0)));
    try testing.expect(std.math.isNan(atan(std.math.nan(f64))));
    try testing.expectEqual(@as(f64, 1.5707963267948966), asin(1.0));
    try testing.expectEqual(@as(f64, -1.5707963267948966), asin(-1.0));
    try testing.expectEqual(@as(f64, 0.5235987755982989), asin(0.5)); // pi/6
    try testing.expect(std.math.isNan(asin(1.0000000000000002)));
    try testing.expectEqual(@as(f64, 0.0), acos(1.0));
    try testing.expectEqual(@as(f64, 3.141592653589793), acos(-1.0));
    try testing.expectEqual(@as(f64, 1.5707963267948966), acos(0.0));
    try testing.expectEqual(@as(f64, 1.0471975511965979), acos(0.5)); // pi/3
    try testing.expect(std.math.isNan(acos(-1.5)));
    // 1e-20 is below 2^-27: atan and asin are the argument
    try testing.expectEqual(@as(f64, 1e-20), atan(1e-20));
    try testing.expectEqual(@as(f64, 1e-300), asin(1e-300));
}

test "atan, asin, acos agree with std.math within one ULP over a sweep, identities hold" {
    var prng = std.Random.DefaultPrng.init(99);
    const r = prng.random();
    var same: usize = 0;
    const n = 4000;
    for (0..n) |_| {
        const mag = std.math.pow(f64, 10.0, (r.float(f64) - 0.5) * 12.0);
        const x = if (r.boolean()) mag else -mag;
        const a = atan(x);
        try testing.expect(ulpsApart(a, std.math.atan(x)) <= 1);
        if (a == std.math.atan(x)) same += 1;
        const u = (r.float(f64) - 0.5) * 2.0;
        try testing.expect(ulpsApart(asin(u), std.math.asin(u)) <= 1);
        try testing.expect(ulpsApart(acos(u), std.math.acos(u)) <= 1);
        // odd symmetry is exact
        try testing.expectEqual(-a, atan(-x));
    }
    try testing.expect(same > n * 9 / 10); // the std version is within one ULP, and right most of the time
}

test "sinh, cosh, tanh: values and special cases" {
    try testing.expectEqual(@as(f64, 0.0), sinh(0.0));
    try testing.expect(std.math.signbit(sinh(-0.0)));
    try testing.expectEqual(@as(f64, 1.0), cosh(0.0));
    try testing.expect(std.math.signbit(tanh(-0.0)));
    try testing.expect(std.math.isInf(sinh(std.math.inf(f64))));
    try testing.expectEqual(-std.math.inf(f64), sinh(-800.0));
    try testing.expectEqual(std.math.inf(f64), cosh(711.0));
    try testing.expect(std.math.isFinite(cosh(710.0)));
    try testing.expectEqual(@as(f64, 1.0), tanh(30.0));
    try testing.expectEqual(@as(f64, -1.0), tanh(-std.math.inf(f64)));
    try testing.expect(std.math.isNan(tanh(std.math.nan(f64))));
    try testing.expectApproxEqRel(@as(f64, 1.1752011936438014), sinh(1.0), 1e-15);
    try testing.expectApproxEqRel(@as(f64, 1.5430806348152437), cosh(1.0), 1e-15);
    try testing.expectApproxEqRel(@as(f64, 0.7615941559557649), tanh(1.0), 1e-15);
    var prng = std.Random.DefaultPrng.init(7);
    const rr = prng.random();
    for (0..2000) |_| {
        const x = (rr.float(f64) - 0.5) * 60.0;
        try testing.expect(ulpsApart(sinh(x), std.math.sinh(x)) <= 3);
        try testing.expect(ulpsApart(cosh(x), std.math.cosh(x)) <= 3);
        try testing.expect(ulpsApart(tanh(x), std.math.tanh(x)) <= 3);
    }
}
