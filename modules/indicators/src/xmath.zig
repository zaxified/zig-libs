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
///
/// Ziv's strategy: `atanFast` answers `atan |x|` as an unevaluated sum `h + l`
/// whose relative error is provably below 2^-64 (bound used: 2^-62); when every
/// value within that bound of `h + l` rounds to the same double, that double is
/// the correctly rounded atan and is returned. Otherwise (about 1 call in 500) the
/// double-double evaluation `atanPos` decides, so the answer is the same double
/// the double-double path alone gives, wherever that one is correctly rounded.
pub fn atan(x: f64) f64 {
    if (std.math.isNan(x) or x == 0.0) return x;
    const ax = @abs(x);
    if (ax < 7.450580596923828e-9) return x; // 2^-27: atan x rounds to x
    if (std.math.isInf(ax)) return std.math.copysign(half_pi.hi, x);
    const f = atanFast(ax);
    if (fastRounds(f)) |r| return std.math.copysign(r, x);
    return finish(atanPos(.{ .hi = ax, .lo = 0.0 }), x);
}

// ── atan fast path ──────────────────────────────────────────────────────────
//
// For 0 <= y <= 1 pick c = i/64 (i = round(64 y)) and use
//     atan y = atan c + atan t,   t = (y - c) / (1 + y c),   |t| <= 1/128,
// with atan c from a 65-entry double-double table and atan t from its Taylor
// series to t^9 (truncation t^11/11 <= 2^-73.5 |t|). y - c is exact (Sterbenz:
// c/2 <= y <= 2c for i >= 1), t is a double-double (one division plus a
// correction), the series' correction term t^3 Q(t^2) <= 2^-15.6 |t| is computed
// in double (relative error a few 2^-53, i.e. <= 2^-66 |t| absolute; the 1/3
// coefficient's own rounding adds 2^-69.6 |t|). Since |atan y| >= 0.78 |t| when
// i >= 1 (and atan y ~ t when i = 0), the sum is within 2^-64 of atan y,
// relative. For y > 1, atan y = pi/2 - atan(1/y) with 1/y as a double-double;
// the subtraction cannot cancel (atan(1/y) <= pi/4). The bound `fast_err` is
// 2^-62, four times the analysis; the test "atan fast path" checks the measured
// distance to the double-double value against 2^-64 over a large sample.

const fast_err: f64 = 0x1p-62;

const atan_tbl: [65]DD = blk: {
    @setEvalBranchQuota(10_000_000);
    var t: [65]DD = undefined;
    t[0] = .{ .hi = 0.0, .lo = 0.0 };
    for (1..65) |i| t[i] = atanUnit(.{ .hi = @as(f64, @floatFromInt(i)) / 64.0, .lo = 0.0 });
    break :blk t;
};

const Fast = struct { h: f64, l: f64 };

/// atan of a double-double y = yh + yl in [0, 1] (yl tiny), as atan c + atan t.
inline fn atanFastUnit(yh: f64, yl: f64) Fast {
    const i: usize = @intFromFloat(@round(yh * 64.0));
    const c: f64 = @as(f64, @floatFromInt(i)) * (1.0 / 64.0);
    // numerator (y - c) as a double-double
    const num = twoSum(yh - c, yl);
    // denominator 1 + y c as a double-double
    const p = yh * c;
    const pe = @mulAdd(f64, yh, c, -p) + yl * c;
    const d = quickTwoSum(1.0, p);
    const dl = d.lo + pe;
    // t = num / d
    const th = num.hi / d.hi;
    const r = @mulAdd(f64, -th, d.hi, num.hi) + num.lo - th * dl;
    const tl = r / d.hi;
    // atan t = t - t^3 (1/3 - z/5 + z^2/7 - z^3/9), z = t^2
    const z = th * th;
    const q = @mulAdd(f64, @mulAdd(f64, @mulAdd(f64, -1.0 / 9.0, z, 1.0 / 7.0), z, -1.0 / 5.0), z, 1.0 / 3.0);
    const cubic = th * z * q;
    const a = atan_tbl[i];
    const s = twoSum(a.hi, th);
    const l = s.lo + (a.lo + (tl - cubic));
    return .{ .h = s.hi, .l = l };
}

/// atan of a finite ax >= 2^-27 as an unevaluated sum within 2^-64 (relative).
fn atanFast(ax: f64) Fast {
    if (ax <= 1.0) return atanFastUnit(ax, 0.0);
    const yh = 1.0 / ax;
    const yl = @mulAdd(f64, -yh, ax, 1.0) / ax;
    const u = atanFastUnit(yh, yl);
    const s = twoSum(half_pi.hi, -u.h);
    return .{ .h = s.hi, .l = s.lo + (half_pi.lo - u.l) };
}

/// The correctly rounded double of `f`, or null when the error bound straddles a
/// rounding boundary.
inline fn fastRounds(f: Fast) ?f64 {
    const n = quickTwoSum(f.h, f.l);
    const e = @abs(n.hi) * fast_err;
    if (n.hi + (n.lo + e) == n.hi and n.hi + (n.lo - e) == n.hi) return n.hi;
    return null;
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

/// The double-double path alone (what `atan` was before the fast path).
fn atanDD(x: f64) f64 {
    if (std.math.isNan(x) or x == 0.0) return x;
    const ax = @abs(x);
    if (ax < 7.450580596923828e-9) return x;
    if (std.math.isInf(ax)) return std.math.copysign(half_pi.hi, x);
    return finish(atanPos(.{ .hi = ax, .lo = 0.0 }), x);
}

/// Checks one argument: the fast sum is within 2^-64 of the double-double value
/// (a quarter of the bound the rounding test assumes), and `atan` is bitwise the
/// double-double answer. Returns whether the fast path decided.
fn checkFast(x: f64) !bool {
    const want = atanDD(x);
    try testing.expectEqual(@as(u64, @bitCast(want)), @as(u64, @bitCast(atan(x))));
    const ax = @abs(x);
    if (!(ax >= 7.450580596923828e-9) or std.math.isInf(ax)) return true;
    const f = atanFast(ax);
    const dd = atanPos(.{ .hi = ax, .lo = 0.0 });
    const dist = @abs((f.h - dd.hi) + (f.l - dd.lo));
    if (!(dist <= 0x1p-64 * dd.hi)) {
        std.debug.print("atan fast path off: x={e} dist/val={e}\n", .{ x, dist / dd.hi });
        return error.TestUnexpectedResult;
    }
    return fastRounds(f) != null;
}

test "atan fast path: table, error bound and bitwise agreement with the double-double path" {
    // the comptime table is the runtime double-double value
    for (1..65) |i| {
        const want = atanUnit(.{ .hi = @as(f64, @floatFromInt(i)) / 64.0, .lo = 0.0 });
        try testing.expectEqual(want.hi, atan_tbl[i].hi);
        try testing.expectEqual(want.lo, atan_tbl[i].lo);
    }
    var prng = std.Random.DefaultPrng.init(0x5eed_a7a);
    const r = prng.random();
    var decided: usize = 0;
    const n = 30_000;
    for (0..n) |_| {
        // log-uniform magnitude over 2^-30 .. 2^60, both signs
        const e = r.float(f64) * 90.0 - 30.0;
        const mag = std.math.exp2(e);
        const x = if (r.boolean()) mag else -mag;
        if (try checkFast(x)) decided += 1;
        // and a uniform draw in (-4, 4), where the indicators' ratios mostly land
        _ = try checkFast((r.float(f64) - 0.5) * 8.0);
    }
    // the fast path decides all but a few in a thousand
    try testing.expect(decided > n - n / 100);
    // hard cases: the table nodes, their reciprocals and neighbours, the branch
    // edges (1/128, 1, 2^-27), the extremes
    for (0..65) |i| {
        const c = @as(f64, @floatFromInt(i)) / 64.0;
        for ([_]f64{ c, c + 1.0 / 128.0, c - 1.0 / 128.0 }) |b| {
            if (!(b > 0.0)) continue;
            var v = b;
            for (0..4) |_| v = std.math.nextAfter(f64, v, 0.0);
            for (0..9) |_| {
                _ = try checkFast(v);
                _ = try checkFast(-v);
                _ = try checkFast(1.0 / v);
                v = std.math.nextAfter(f64, v, std.math.inf(f64));
            }
        }
    }
    for ([_]f64{ 7.450580596923828e-9, 7.450580596923829e-9, 1e-8, 0.5, 1.0, 2.0, 1e15, 0x1p53, 1e300, std.math.floatMax(f64), std.math.floatMin(f64), 3.0, 0.1, 1.0 / 3.0 }) |v| {
        _ = try checkFast(v);
        _ = try checkFast(-v);
    }
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
