// SPDX-License-Identifier: MIT
//! Helpers shared by `finstats`'s two surfaces, the plain-slice functions in
//! `slice.zig` and the `Dataset` functions in `root.zig`. Not public API.

const std = @import("std");

/// The rate-space search interval every IRR here works in: `[-0.99, 10]`, i.e.
/// −99 % to +1000 % a year. Deliberately not wider — a genuine +1000 % IRR
/// exists on a small position, so what is wanted from a series that falls
/// outside it is DETECTION (`error.XirrNoRoot`), not more room.
///
/// Named because four sites had written the same two literals out: bisection's
/// starting bracket, `xirr`'s sign-change check, `xirrPrecise`'s sign-change
/// check, and Newton's "this step left the bracket" test. Those four have to
/// agree — Newton's bail-out is *why* checking the sign change once, before
/// either phase, is sound — and a byte-identical copy is a byte-identical gap.
pub const bracket_lo: f64 = -0.99;
/// Upper end of the IRR search interval. See `bracket_lo`.
pub const bracket_hi: f64 = 10.0;

/// Default `rate_tol` for every spec that has one (`XirrSpec`,
/// `XirrNodeSpec`, `XirrPreciseSpec`, `XirrPreciseNodeSpec`) — the width in
/// RATE space the answer must be narrowed to, as opposed to a threshold on
/// NPV, which is absolute and so means something different at every cashflow
/// magnitude. See `XirrSpec.rate_tol` for what it buys, measured.
///
/// One constant rather than four copies of `1e-9`: the four specs are four
/// doors onto the same two functions, and a default that drifted between them
/// would make the same call mean different things depending on which door it
/// came through.
pub const default_rate_tol: f64 = 1e-9;

pub fn mean(xs: []const f64) f64 {
    if (xs.len == 0) return 0;
    var s: f64 = 0;
    for (xs) |x| s += x;
    return s / @as(f64, @floatFromInt(xs.len));
}
pub fn stdSample(xs: []const f64) f64 {
    if (xs.len < 2) return 0;
    const m = mean(xs);
    var ss: f64 = 0;
    for (xs) |x| ss += (x - m) * (x - m);
    return @sqrt(ss / @as(f64, @floatFromInt(xs.len - 1)));
}
/// Ascending, NaN LAST. A bare `a < b` is false both ways for a NaN, which
/// makes "equal" non-transitive: the sort is then free to leave the finite
/// values out of order, and a quantile read off it is a plausible wrong number.
/// With NaN last the order is total, so the finite values are sorted and a NaN
/// shows up where it belongs -- in the top quantiles.
pub fn f64lt(_: void, a: f64, b: f64) bool {
    if (std.math.isNan(a)) return false;
    return std.math.isNan(b) or a < b;
}

pub const Cashflow = struct { t: i64, cf: f64 };

/// The bisection both functions share: 200 halvings of `[lo, hi]`, returning
/// as soon as |NPV| is under `npv_tol` AND — when `rate_tol` is set — the
/// bracket has narrowed below it. Callers check `bracketHasRoot` first.
pub fn bisect(items: []const Cashflow, base: i64, npv_tol: f64, rate_tol: ?f64) f64 {
    var lo: f64 = bracket_lo;
    var hi: f64 = bracket_hi;
    var mid: f64 = 0;
    var i: usize = 0;
    while (i < 200) : (i += 1) {
        mid = (lo + hi) / 2.0;
        const nv_mid = npv(items, base, mid);
        if (@abs(nv_mid) < npv_tol and (rate_tol == null or (hi - lo) < rate_tol.?)) return mid;
        const nv_lo = npv(items, base, lo);
        if ((nv_lo < 0) == (nv_mid < 0)) lo = mid else hi = mid;
    }
    return mid;
}

/// Does NPV change sign across `[lo, hi]`? If it does not, no amount of
/// bisecting finds a root and the loop below just walks to a bound — which is
/// what used to be returned as the answer. NaN compares false both ways and so
/// reports "no root", which is the honest verdict for it too.
///
/// ⭐ CONSTANT NPV IS NOT A ROOT, AND THAT INCLUDES THE CONSTANT ZERO. When
/// every cashflow lands on the same date — a window narrow enough to hold one
/// row, which is the realistic path — every discount exponent is 0 and NPV is
/// the constant Σcf at every rate. Under `.value_includes_flow` that constant
/// is exactly 0 (seed −value[0], terminal +value[0]), so `nv_lo == 0` read as
/// "a bound IS the root": true, and useless. Every rate is a root, so no rate
/// is the answer, and bisection walked its 200 halvings to `hi` and returned
/// 9.99999999968015 — a confident +1000 %, indistinguishable at the call site
/// from a real result. Reported from a consumer against a real database with a
/// one-day range, 2026-08-24.
///
/// The predicate is stated as "NPV is constant", not as a row count, because
/// the row count is a proxy for it and misses the shape from the other side:
/// unseeded, the same one row gives the constant +1000, which is a genuine
/// no-root that the sign test below already rejected. Equality at the two ends
/// also costs nothing when NPV merely happens to return to the same value —
/// that case has no sign change either, so it was already `false`.
///
/// This gates `xirrPrecise` too: its Newton phase would otherwise start from a
/// derivative that is identically 0 here.
pub fn bracketHasRoot(items: []const Cashflow, base: i64, lo: f64, hi: f64) bool {
    const nv_lo = npv(items, base, lo);
    const nv_hi = npv(items, base, hi);
    if (nv_lo == nv_hi) return false; // constant across the bracket: no unique rate
    if (nv_lo == 0 or nv_hi == 0) return true; // a bound IS the root
    return (nv_lo < 0) != (nv_hi < 0);
}

pub fn npv(items: []const Cashflow, base: i64, r: f64) f64 {
    var sum: f64 = 0;
    for (items) |it| {
        const dt: f64 = @floatFromInt(it.t - base);
        sum += it.cf / std.math.pow(f64, 1.0 + r, dt / 365.25);
    }
    return sum;
}

pub fn gauss(rnd: std.Random) f64 {
    var u: f64 = 0;
    var v: f64 = 0;
    while (u == 0) u = rnd.float(f64);
    while (v == 0) v = rnd.float(f64);
    return @sqrt(-2.0 * @log(u)) * @cos(2.0 * std.math.pi * v);
}

/// d(NPV)/dr for the Newton step above.
pub fn dnpv(items: []const Cashflow, base: i64, r: f64) f64 {
    var sum: f64 = 0;
    for (items) |it| {
        const dt: f64 = @floatFromInt(it.t - base);
        const yrs = dt / 365.25;
        sum += -it.cf * yrs / std.math.pow(f64, 1.0 + r, yrs + 1.0);
    }
    return sum;
}

/// Compound annual growth of a return series with `ppy` periods per year:
/// Π(1+r)^(ppy/n) − 1 (empyrical's `annual_return`). 0 for an empty series.
pub fn cagrOf(xs: []const f64, ppy: f64) f64 {
    if (xs.len == 0) return 0;
    return levelPow(xs, ppy / @as(f64, @floatFromInt(xs.len))) - 1;
}

/// cov(p, b) / var(b) over two equal-length series (0 when var(b) is 0).
pub fn betaOf(p: []const f64, b: []const f64) f64 {
    const mp = mean(p);
    const mb = mean(b);
    var cov: f64 = 0;
    var varb: f64 = 0;
    for (p, b) |x, y| {
        cov += (x - mp) * (y - mb);
        varb += (y - mb) * (y - mb);
    }
    return if (varb > 0) cov / varb else 0;
}

/// Up (or down) capture: CAGR of the portfolio over the periods where the
/// benchmark rose (fell), divided by the benchmark's CAGR over the same periods
/// (empyrical's `up_capture` / `down_capture`). 0 when there is no such period.
pub fn capture(a: std.mem.Allocator, p: []const f64, b: []const f64, ppy: f64, up: bool) std.mem.Allocator.Error!f64 {
    var ps: std.ArrayList(f64) = .empty;
    defer ps.deinit(a);
    var bs: std.ArrayList(f64) = .empty;
    defer bs.deinit(a);
    for (p, b) |x, y| {
        if (if (up) y > 0 else y < 0) {
            try ps.append(a, x);
            try bs.append(a, y);
        }
    }
    const bench = cagrOf(bs.items, ppy); // 0 for no such period
    if (bench == 0) return 0;
    return cagrOf(ps.items, ppy) / bench;
}

pub fn finiteAll(xs: []const f64) bool {
    for (xs) |x| if (!std.math.isFinite(x)) return false;
    return true;
}

/// Finite and every value >= -1: a series whose compounded level is defined.
pub fn compoundable(xs: []const f64) bool {
    for (xs) |x| if (!std.math.isFinite(x) or x < -1) return false;
    return true;
}

/// Per-period risk-free rate from an annual one, compounded:
/// (1 + rf)^(1/ppy) - 1 (quantstats' conversion; empyrical takes the
/// per-period rate directly, which is this with the conversion done by the
/// caller). NaN when `ppy` is not positive finite or `rf <= -1`.
pub fn rfPerPeriod(rf: f64, ppy: f64) f64 {
    if (!(ppy > 0) or !std.math.isFinite(ppy) or !std.math.isFinite(rf) or rf <= -1) return std.math.nan(f64);
    if (rf == 0) return 0;
    // 1 / ppy overflows for ppy below ~5.6e-309: pow gives inf, which is no rate
    const p = std.math.pow(f64, 1 + rf, 1 / ppy);
    if (!std.math.isFinite(p)) return std.math.nan(f64);
    return p - 1;
}

/// Π(1 + r) as `m * 2^e`, with the mantissa renormalised whenever it leaves
/// [2^-500, 2^500]: a long series of small losses (7e4 periods of -1 %) or gains
/// would underflow or overflow the plain product long before the answer is out
/// of range. `m` is 0 after a -100 % period (exact), inf only if one factor is.
pub const Level = struct { m: f64, e: i64 };

pub fn levelOf(xs: []const f64) Level {
    var m: f64 = 1;
    var e: i64 = 0;
    for (xs) |x| {
        m *= 1 + x;
        if (m > 0x1p500 or (m < 0x1p-500 and m != 0)) {
            if (std.math.isInf(m)) return .{ .m = m, .e = 0 };
            const fr = std.math.frexp(m);
            m = fr.significand;
            e += fr.exponent;
        }
    }
    return .{ .m = m, .e = e };
}

/// (Π(1 + r))^g without the intermediate under/overflow of `levelOf`'s product.
pub fn levelPow(xs: []const f64, g: f64) f64 {
    const l = levelOf(xs);
    if (l.m == 0) return if (g > 0) 0 else 1;
    return std.math.pow(f64, l.m, g) * std.math.exp2(@as(f64, @floatFromInt(l.e)) * g);
}

const lanes = 8;
const Vec = @Vector(lanes, f64);

const Moments = struct { mean: f64, sd: f64, scale: f64, finite: bool };

/// Mean, sample standard deviation (ddof 1), largest |x| and the all-finite
/// flag in two passes over `xs`, each with `lanes` independent accumulators (a
/// single running sum is latency-bound at one add per ~4 cycles; this is what
/// NumPy's pairwise sum buys it). The finite flag sums `x - x`, which is 0 for
/// a finite x and NaN for NaN or infinity, and a NaN stays in the sum.
///
/// Both passes work on deviations from the first element, `x - xs[0]`, and the
/// second from the mean of those: for a CONSTANT series every deviation is
/// exactly 0, so `sd` is exactly 0 for any n and any level (a plain running sum
/// of n equal values drifts by up to n/2 ulp, which made `sd` 1e-16 relative
/// instead of 0 and a Sharpe of 1e14). For other series the shift also keeps
/// the sums small when the mean is large next to the spread. Summation order
/// differs from a plain loop by rounding (not a fixed number of ulp: it grows
/// slowly with n, like a pairwise sum). `sd` is 0 for fewer than two values and
/// when not finite; a range wider than f64 (x - xs[0] overflows) gives NaN.
pub fn moments(xs: []const f64) Moments {
    if (xs.len == 0) return .{ .mean = 0, .sd = 0, .scale = 0, .finite = true };
    const x0 = xs[0];
    const x0v: Vec = @splat(x0);
    var s: Vec = @splat(0);
    var chk: Vec = @splat(0);
    var mx: Vec = @splat(0);
    var i: usize = 0;
    while (i + lanes <= xs.len) : (i += lanes) {
        const v: Vec = xs[i..][0..lanes].*;
        s += v - x0v;
        chk += v - v;
        mx = @max(mx, @abs(v));
    }
    var dsum: f64 = @reduce(.Add, s);
    var check: f64 = @reduce(.Add, chk);
    var scale: f64 = @reduce(.Max, mx);
    for (xs[i..]) |x| {
        dsum += x - x0;
        check += x - x;
        scale = @max(scale, @abs(x));
    }
    if (check != 0) return .{ .mean = std.math.nan(f64), .sd = 0, .scale = scale, .finite = false };
    const dm = dsum / @as(f64, @floatFromInt(xs.len)); // mean deviation from x0
    const m = x0 + dm;
    if (xs.len < 2) return .{ .mean = m, .sd = 0, .scale = scale, .finite = true };
    const mv: Vec = @splat(dm);
    var q: Vec = @splat(0);
    i = 0;
    while (i + lanes <= xs.len) : (i += lanes) {
        const d: Vec = @as(Vec, xs[i..][0..lanes].*) - x0v - mv;
        q += d * d;
    }
    var ss: f64 = @reduce(.Add, q);
    for (xs[i..]) |x| ss += (x - x0 - dm) * (x - x0 - dm);
    return .{ .mean = m, .sd = @sqrt(ss / @as(f64, @floatFromInt(xs.len - 1))), .scale = scale, .finite = true };
}

/// Rearranges `xs` so that `xs[k]` is the k-th smallest, everything before it
/// is <= and everything after is >= (quickselect: median-of-three pivot,
/// three-way partition so that runs of equal values cost nothing). A bounded
/// number of rounds, then a full sort of what is left: a hostile input cannot
/// drive it quadratic. NaN must not be present (every comparison with it is false).
pub fn selectNth(xs: []f64, k: usize) void {
    var lo: usize = 0;
    var hi: usize = xs.len;
    var budget: usize = 2 * @as(usize, std.math.log2_int_ceil(usize, @max(xs.len, 2))) + 8;
    while (hi - lo > 16) {
        if (budget == 0) break;
        budget -= 1;
        const x0 = xs[lo];
        const x1 = xs[lo + (hi - lo) / 2];
        const x2 = xs[hi - 1];
        const p = @max(@min(x0, x1), @min(@max(x0, x1), x2)); // median of three
        var lt = lo;
        var i = lo;
        var gt = hi;
        while (i < gt) {
            const v = xs[i];
            if (v < p) {
                xs[i] = xs[lt];
                xs[lt] = v;
                lt += 1;
                i += 1;
            } else if (v > p) {
                gt -= 1;
                xs[i] = xs[gt];
                xs[gt] = v;
            } else i += 1;
        }
        if (k < lt) {
            hi = lt;
        } else if (k >= gt) {
            lo = gt;
        } else return; // k sits inside the run equal to the pivot
    }
    std.mem.sort(f64, xs[lo..hi], {}, f64lt);
}

/// `quantileSorted(sorted(xs), q)` for a NaN-free `xs`, without the full sort:
/// two order statistics by `selectNth`. Destroys the order of `xs`.
pub fn quantileSelect(xs: []f64, q: f64) f64 {
    const n = xs.len;
    if (n == 0) return 0;
    if (n == 1) return xs[0];
    const qc = if (std.math.isNan(q)) 0.0 else std.math.clamp(q, 0.0, 1.0);
    const pos = qc * @as(f64, @floatFromInt(n - 1));
    const lo: usize = @intFromFloat(@floor(pos));
    const hi: usize = @intFromFloat(@ceil(pos));
    const frac = pos - @floor(pos);
    selectNth(xs, lo);
    const a = xs[lo];
    // the (lo+1)-th order statistic is the smallest of what is right of lo
    const b = if (hi == lo) a else std.mem.min(f64, xs[lo + 1 ..]);
    return a * (1.0 - frac) + b * frac;
}

/// The `i`-th of `bins` equal-width edges between `lo` and `hi`. An ordinary
/// range is `lo + span * i / bins` (the original formula); a `wide` one, whose
/// `span` overflowed, is `lo * (1 - t) + hi * t`.
pub fn histEdge(lo: f64, hi: f64, span: f64, wide: bool, i: f64, bins: usize) f64 {
    const nb: f64 = @floatFromInt(bins);
    if (!wide) return lo + span * i / nb;
    const t = i / nb;
    return lo * (1 - t) + hi * t;
}

/// Day number of `YYYY-MM-DD`, optionally followed by `T` or a space and anything
/// else. Null for anything else, including a day that does not exist.
pub fn isoDayNumber(s: []const u8) ?i64 {
    if (s.len < 10 or s[4] != '-' or s[7] != '-') return null;
    if (s.len > 10 and s[10] != 'T' and s[10] != ' ') return null;
    const y = digits(s[0..4]) orelse return null;
    const m = digits(s[5..7]) orelse return null;
    const d = digits(s[8..10]) orelse return null;
    if (m < 1 or m > 12 or d < 1) return null;
    const leap = @mod(y, 4) == 0 and (@mod(y, 100) != 0 or @mod(y, 400) == 0);
    const month_days = [12]i64{ 31, if (leap) 29 else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    if (d > month_days[@intCast(m - 1)]) return null;
    // Days from the civil calendar, March-based year (Hinnant).
    const ya = if (m <= 2) y - 1 else y;
    const era = @divFloor(ya, 400);
    const yoe = ya - era * 400;
    const mp = @mod(m + 9, 12);
    const doy = @divFloor(153 * mp + 2, 5) + d - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

fn digits(s: []const u8) ?i64 {
    var v: i64 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return null;
        v = v * 10 + (c - '0');
    }
    return v;
}
