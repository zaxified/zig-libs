// SPDX-License-Identifier: MIT

//! Performance ratios that quantstats, empyrical or ffn users expect on a plain
//! return slice: the "smart"/probabilistic/deflated family, the trade-quality
//! ratios, outlier helpers, sample skew and kurtosis, a normal CDF.
//!
//! Conventions are those of `slice.zig` ("period statistics"): plain
//! `[]const f64` of simple period returns, `rf` ANNUAL and compounded down to a
//! period, `ppy` periods per year. A bare-number function answers NaN for a NaN
//! or infinite value in a series, a bad `ppy` (not positive finite) or series of
//! different lengths; one that allocates returns `Error` (`TooLarge`,
//! `OutOfMemory`; `LengthMismatch` is not needed here, the two-series function
//! answers NaN like `slice.beta`). An empty series answers 0 where a ratio of
//! "nothing" is meaningful, and a zero denominator follows `slice.gainToPain`:
//! +inf for a positive numerator, else 0 (the Sharpe-like ratios follow
//! `slice.sharpeRatio`: zero spread, 0). The probabilistic family needs at least
//! two periods and answers NaN below that: a probability from no data is not 0.
//!
//! Every reference number was produced by running quantstats 0.0.86 / ffn 1.3.0
//! as a black box (`tools/ratios_oracle.py`); where a library's own answer is
//! odd, the function's doc comment says so and says which one this module follows.

const std = @import("std");
const core = @import("core.zig");
const slice = @import("slice.zig");

pub const Error = slice.Error;

/// Cap on the work of `pctRank`: `len * min(window, len)` comparisons. Larger
/// input answers `error.TooLarge`.
pub const max_rank_work: usize = 1 << 28;

const nan = std.math.nan(f64);
const inf = std.math.inf(f64);
const finiteAll = core.finiteAll;

/// num / den with this module's zero-denominator convention: den == 0 gives +inf
/// for a positive numerator, else 0. A NaN numerator stays NaN.
fn ratio(num: f64, den: f64) f64 {
    if (std.math.isNan(num) or std.math.isNan(den)) return nan;
    if (den == 0) return if (num > 0) inf else 0;
    return num / den;
}

// ── plain ratios ────────────────────────────────────────────────────────────

/// Mean of the NON-ZERO periods (quantstats `avg_return`: exact zeros are "not
/// in the market" and are left out of the average). 0 if there is none. NaN on
/// non-finite input.
pub fn avgReturn(xs: []const f64) f64 {
    if (!finiteAll(xs)) return nan;
    var s: f64 = 0;
    var n: usize = 0;
    for (xs) |x| if (x != 0) {
        s += x;
        n += 1;
    };
    return if (n == 0) 0 else s / @as(f64, @floatFromInt(n));
}

/// mean(r) / std(r), sample std (ddof 1), NOT annualised (quantstats
/// `risk_return_ratio`; `sharpeRatio` without the risk-free rate and the
/// sqrt(ppy)). Fewer than two periods or zero spread: 0. NaN on non-finite input.
pub fn riskReturnRatio(xs: []const f64) f64 {
    const m = core.moments(xs);
    if (!m.finite) return nan;
    if (xs.len < 2 or m.sd <= 8 * std.math.floatEps(f64) * m.scale) return 0;
    return m.mean / m.sd;
}

/// Martin ratio / ulcer performance index, (totalReturn - rf) / ulcerIndex
/// (quantstats `ulcer_performance_index`). Following quantstats, `rf` is
/// subtracted from the whole-sample compounded return as given, NOT converted to
/// the sample length, and there is no `ppy`: quantstats takes none either. The
/// ulcer index is `slice.ulcerIndex` (a fraction; the oracle feeds quantstats a
/// series that starts with a 0.0 return so that both measure from the level 1).
/// Empty: 0. Flat series (ulcer 0): +inf for a positive numerator, else 0.
/// NaN if not compoundable or `rf` is not finite. Difference from quantstats on a
/// plain n-point series: its ulcer divides by n - 1 and measures from the first
/// point, `ulcerIndex` by n and from the level 1, so the numbers differ by
/// sqrt(n / (n - 1)) (more if the first return is a loss); the oracle compares
/// with that factor applied, on a series that starts with a 0.0 return.
pub fn ulcerPerformanceIndex(xs: []const f64, rf: f64) f64 {
    if (!std.math.isFinite(rf)) return nan;
    const u = slice.ulcerIndex(xs);
    if (std.math.isNan(u)) return nan;
    if (xs.len == 0) return 0;
    return ratio(slice.totalReturn(xs) - rf, u);
}

/// Serenity index, (sum(r) - rf) / (ulcer * pitfall), pitfall = CVaR95 of the
/// DRAWDOWN series / std(r) (quantstats `serenity_index`). The drawdown series
/// is the compounded level over its running peak minus one, the peak starting at
/// 1 (as `slice.ulcerIndex`). Its "CVaR" is quantstats' own `cvar`, which is the
/// closed-form GAUSSIAN expected shortfall of the series at 95 %, -mean(dd) +
/// std(dd) * pdf(z) / 0.05 with z = Φ^-1(0.05) and the sample std, a positive
/// number (found by running it: it is neither the historical tail mean of
/// `slice.cvarHistoric` nor the mean below the parametric VaR). It is followed
/// because the function's purpose is quantstats parity.
/// `rf` is subtracted from the plain SUM, as quantstats does. Empty: 0.
/// Zero ulcer, CVaR or spread: the zero-denominator convention. NaN if not
/// compoundable or `rf` not finite. Same ulcer divisor / baseline difference
/// from quantstats as `ulcerPerformanceIndex` (the oracle applies it).
pub fn serenityIndex(a: std.mem.Allocator, xs: []const f64, rf: f64) Error!f64 {
    if (!std.math.isFinite(rf) or !core.compoundable(xs)) return nan;
    if (xs.len == 0) return 0;
    const dd = try a.alloc(f64, xs.len);
    defer a.free(dd);
    var level: f64 = 1;
    var peak: f64 = 1;
    var sum: f64 = 0;
    var ss: f64 = 0;
    for (xs, dd) |x, *d| {
        sum += x;
        level *= 1 + x;
        peak = @max(peak, level);
        d.* = (level - peak) / peak;
        ss += d.* * d.*;
        if (peak > 0x1p500) {
            level *= 0x1p-500;
            peak *= 0x1p-500;
        }
    }
    const u = @sqrt(ss / @as(f64, @floatFromInt(xs.len)));
    const m = core.moments(xs);
    // quantstats' cvar is the PARAMETRIC (Gaussian) expected shortfall of the
    // series it is given: -mean + std * pdf(z) / 0.05, z = Φ^-1(0.05), std ddof 1
    const z95 = invNormLower(0.05);
    const cv = -core.mean(dd) + core.stdSample(dd) * slice.normalPdf(z95) / 0.05;
    const spread_zero = xs.len < 2 or m.sd <= 8 * std.math.floatEps(f64) * m.scale;
    const den = if (spread_zero or u == 0 or cv == 0) 0 else u * cv / m.sd;
    return ratio(sum - rf, den);
}

/// `slice.tailRatio * slice.profitFactor` (quantstats `common_sense_ratio`).
/// Empty or a zero factor: 0. NaN on non-finite input.
pub fn commonSenseRatio(a: std.mem.Allocator, xs: []const f64) Error!f64 {
    if (!finiteAll(xs)) return nan;
    const t = try slice.tailRatio(a, xs);
    const p = slice.profitFactor(xs);
    if (t == 0 or p == 0) return 0;
    return t * p;
}

/// `profitFactor * winRate * payoffRatio` (quantstats `cpc_index`). No wins or
/// empty: 0. NaN on non-finite input.
pub fn cpcIndex(xs: []const f64) f64 {
    if (!finiteAll(xs)) return nan;
    const w = slice.winRate(xs);
    const pay = slice.payoffRatio(xs);
    if (w == 0 or pay == 0) return 0;
    return slice.profitFactor(xs) * w * pay;
}

/// win ratio / loss ratio with win ratio = |mean(wins) / count(wins)| over the
/// periods >= 0 (zeros count as wins here) and loss ratio the same over the
/// periods < 0 (quantstats `profit_ratio`). Dividing the mean by the COUNT as
/// well is quantstats' definition, kept for parity: the number depends on the
/// series length, so it is not comparable across samples of different size.
/// No losses: the zero-denominator convention (+inf if there is a win). Empty: 0.
/// NaN on non-finite input.
pub fn profitRatio(xs: []const f64) f64 {
    if (!finiteAll(xs)) return nan;
    var ws: f64 = 0;
    var ls: f64 = 0;
    var wn: usize = 0;
    var ln: usize = 0;
    for (xs) |x| {
        if (x >= 0) {
            ws += x;
            wn += 1;
        } else {
            ls += x;
            ln += 1;
        }
    }
    const win: f64 = if (wn == 0) 0 else @abs(ws / @as(f64, @floatFromInt(wn)) / @as(f64, @floatFromInt(wn)));
    const loss: f64 = if (ln == 0) 0 else @abs(ls / @as(f64, @floatFromInt(ln)) / @as(f64, @floatFromInt(ln)));
    return ratio(win, loss);
}

/// Average win / |average loss|: quantstats `win_loss_ratio` is `payoff_ratio`
/// (checked by running both), so this is `slice.payoffRatio` with a finite-input
/// guard. NaN on non-finite input.
pub fn winLossRatio(xs: []const f64) f64 {
    if (!finiteAll(xs)) return nan;
    return slice.payoffRatio(xs);
}

/// Share of periods with a non-zero return, rounded UP to two decimals,
/// ceil(100 * k / n) / 100 (quantstats `exposure`), in exact integer arithmetic.
/// quantstats computes it in floating point and is one step too high where the
/// product lands just above a whole number: 7 of 100 is 0.08 there, 0.07 here.
/// Empty: 0. NaN on non-finite input.
pub fn exposure(xs: []const f64) f64 {
    if (!finiteAll(xs)) return nan;
    if (xs.len == 0) return 0;
    var k: usize = 0;
    for (xs) |x| if (x != 0) {
        k += 1;
    };
    // k <= n, and n * 100 cannot overflow for a slice of 8-byte values on 64 bits.
    const pct = (k * 100 + xs.len - 1) / xs.len;
    return @as(f64, @floatFromInt(pct)) / 100;
}

/// Return over risk-adjusted-exposure, cagr / exposure (quantstats `rar`). The
/// Rust quantstats crate documents `rar` as an alias of `cagr`; Python's divides
/// by the exposure, and this follows Python. The CAGR is by period count (as
/// `slice.cagrPeriods`) of the EXCESS returns r - rf_p; the exposure is that of the
/// raw series. quantstats' own `rar(rf > 0)` counts the exposure of the excess
/// series, in which every exact zero has become non-zero, so for rf > 0 its answer
/// differs from this one on purpose (identical at rf = 0, which is what the
/// oracle compares). Zero exposure: the zero-denominator convention; empty: 0.
/// NaN if not compoundable, `ppy` bad, or a period's excess return is below -1.
pub fn rar(xs: []const f64, rf: f64, ppy: f64) f64 {
    if (!core.compoundable(xs)) return nan;
    const rfp = core.rfPerPeriod(rf, ppy);
    if (std.math.isNan(rfp)) return nan;
    if (xs.len == 0) return 0;
    var m: f64 = 1;
    var e: i64 = 0;
    for (xs) |x| {
        const f = 1 + x - rfp;
        if (!(f >= 0)) return nan;
        m *= f;
        if (m > 0x1p500 or (m < 0x1p-500 and m != 0)) {
            if (std.math.isInf(m)) break;
            const fr = std.math.frexp(m);
            m = fr.significand;
            e += fr.exponent;
        }
    }
    const g = ppy / @as(f64, @floatFromInt(xs.len));
    const cagr = if (m == 0) -1.0 else std.math.pow(f64, m, g) * std.math.exp2(@as(f64, @floatFromInt(e)) * g) - 1;
    return ratio(cagr, exposure(xs));
}

// ── outliers ────────────────────────────────────────────────────────────────

/// The periods strictly ABOVE the `q`-quantile of the series (linear
/// interpolation, `slice.quantile`), in their original order (quantstats
/// `outliers`). The caller frees the result. Empty slice for an empty series,
/// non-finite input or a NaN `q`; `q` outside [0, 1] is clamped.
pub fn outliers(a: std.mem.Allocator, xs: []const f64, q: f64) Error![]f64 {
    return pick(a, xs, q, true);
}

/// The periods strictly BELOW the `q`-quantile, original order (quantstats
/// `remove_outliers`, which keeps the lower part). Same conventions as `outliers`.
pub fn removeOutliers(a: std.mem.Allocator, xs: []const f64, q: f64) Error![]f64 {
    return pick(a, xs, q, false);
}

fn pick(a: std.mem.Allocator, xs: []const f64, q: f64, above: bool) Error![]f64 {
    if (xs.len == 0 or std.math.isNan(q) or !finiteAll(xs)) return a.alloc(f64, 0);
    const cut = try slice.quantile(a, xs, q);
    var k: usize = 0;
    for (xs) |x| {
        if ((above and x > cut) or (!above and x < cut)) k += 1;
    }
    const out = try a.alloc(f64, k);
    var i: usize = 0;
    for (xs) |x| {
        if ((above and x > cut) or (!above and x < cut)) {
            out[i] = x;
            i += 1;
        }
    }
    return out;
}

/// quantile(q) / mean of the periods >= 0 (quantstats `outlier_win_ratio`,
/// whose default is q = 0.99): how far the best periods sit above a typical
/// non-negative one. No non-negative period or a zero mean: the zero-denominator
/// convention. Empty: 0. NaN on non-finite input or NaN `q`.
pub fn outlierWinRatio(a: std.mem.Allocator, xs: []const f64, q: f64) Error!f64 {
    return outlierRatio(a, xs, q, true);
}

/// quantile(q) / mean of the periods < 0 (quantstats `outlier_loss_ratio`,
/// default q = 0.01). No loss: the zero-denominator convention. Empty: 0.
/// NaN on non-finite input or NaN `q`.
pub fn outlierLossRatio(a: std.mem.Allocator, xs: []const f64, q: f64) Error!f64 {
    return outlierRatio(a, xs, q, false);
}

fn outlierRatio(a: std.mem.Allocator, xs: []const f64, q: f64, wins: bool) Error!f64 {
    if (std.math.isNan(q) or !finiteAll(xs)) return nan;
    if (xs.len == 0) return 0;
    var s: f64 = 0;
    var n: usize = 0;
    for (xs) |x| if ((wins and x >= 0) or (!wins and x < 0)) {
        s += x;
        n += 1;
    };
    const cut = try slice.quantile(a, xs, q);
    if (n == 0) return ratio(cut, 0);
    return ratio(cut, s / @as(f64, @floatFromInt(n)));
}

// ── smart / adjusted family ─────────────────────────────────────────────────

/// Lag-1 autocorrelation penalty of Lo (2002) as quantstats writes it,
/// sqrt(1 + 2 Σ_{k=1}^{n-1} ((n - k) / n) c^k) with c the ABSOLUTE Pearson
/// correlation of r[0..n-1] with r[1..n] (quantstats `autocorr_penalty`). Always
/// >= 1; 1 when c is undefined (fewer than 3 periods, zero variance). NaN on
/// non-finite input. O(n).
pub fn autocorrPenalty(xs: []const f64) f64 {
    if (!finiteAll(xs)) return nan;
    const n = xs.len;
    if (n < 3) return 1;
    // deviations from the first value: exactly 0 for a constant series
    const x0 = xs[0];
    var sa: f64 = 0;
    var sb: f64 = 0;
    for (0..n - 1) |i| {
        sa += xs[i] - x0;
        sb += xs[i + 1] - x0;
    }
    const m: f64 = @floatFromInt(n - 1);
    const ma = sa / m;
    const mb = sb / m;
    var saa: f64 = 0;
    var sbb: f64 = 0;
    var sab: f64 = 0;
    for (0..n - 1) |i| {
        const da = xs[i] - x0 - ma;
        const db = xs[i + 1] - x0 - mb;
        saa += da * da;
        sbb += db * db;
        sab += da * db;
    }
    const c: f64 = if (saa > 0 and sbb > 0) @min(1.0, @abs(sab / @sqrt(saa * sbb))) else 0;
    const nf: f64 = @floatFromInt(n);
    var sum: f64 = 0;
    var ck: f64 = 1;
    for (1..n) |k| {
        ck *= c;
        if (ck == 0) break;
        sum += (nf - @as(f64, @floatFromInt(k))) / nf * ck;
    }
    return @sqrt(1 + 2 * sum);
}

/// `slice.sharpeRatio / autocorrPenalty` (quantstats `smart_sharpe`).
pub fn smartSharpe(xs: []const f64, rf: f64, ppy: f64) f64 {
    return slice.sharpeRatio(xs, rf, ppy) / autocorrPenalty(xs);
}

/// `slice.sortinoRatio / autocorrPenalty` (quantstats `smart_sortino`).
pub fn smartSortino(xs: []const f64, rf: f64, ppy: f64) f64 {
    return slice.sortinoRatio(xs, rf, ppy) / autocorrPenalty(xs);
}

/// `slice.sortinoRatio / sqrt(2)` (the Rust quantstats crate's `sortino_sqrt2`;
/// Python quantstats 0.0.86 has no function of that name, its
/// `adjusted_sortino` is this number).
pub fn sortinoSqrt2(xs: []const f64, rf: f64, ppy: f64) f64 {
    return slice.sortinoRatio(xs, rf, ppy) / std.math.sqrt2;
}

/// `smartSortino / sqrt(2)` (Rust `smart_sortino_sqrt2`; Python
/// `adjusted_sortino(smart=True)`).
pub fn smartSortinoSqrt2(xs: []const f64, rf: f64, ppy: f64) f64 {
    return smartSortino(xs, rf, ppy) / std.math.sqrt2;
}

/// Adjusted Sortino of Jack Schwager, sortino / sqrt(2) (quantstats
/// `adjusted_sortino`, non-smart): the same number as `sortinoSqrt2`, under the
/// Python name. For the smart variant use `smartSortinoSqrt2`.
pub fn adjustedSortino(xs: []const f64, rf: f64, ppy: f64) f64 {
    return sortinoSqrt2(xs, rf, ppy);
}

// ── sample skewness and kurtosis ────────────────────────────────────────────

/// Bias-corrected sample skewness G1 = g1 * sqrt(n (n - 1)) / (n - 2), g1 the
/// population coefficient of `slice.skewness` (pandas `.skew()`, quantstats
/// `skew`; scipy `skew(bias=False)`). Fewer than 3 periods or zero variance: 0
/// (pandas answers NaN there). NaN on non-finite input.
pub fn skewSample(xs: []const f64) f64 {
    if (!finiteAll(xs)) return nan;
    if (xs.len < 3 or flat(xs)) return 0;
    const n: f64 = @floatFromInt(xs.len);
    return slice.skewness(xs) * @sqrt(n * (n - 1)) / (n - 2);
}

/// Bias-corrected sample EXCESS kurtosis G2 = (n - 1) / ((n - 2)(n - 3)) *
/// ((n + 1) g2 + 6), g2 the population excess kurtosis of `slice.excessKurtosis`
/// (pandas `.kurt()`, quantstats `kurtosis`, which is excess). Fewer than 4
/// periods or zero variance: 0 (pandas: NaN). NaN on non-finite input.
pub fn kurtosisSample(xs: []const f64) f64 {
    if (!finiteAll(xs)) return nan;
    if (xs.len < 4 or flat(xs)) return 0;
    const n: f64 = @floatFromInt(xs.len);
    return (n - 1) / ((n - 2) * (n - 3)) * ((n + 1) * slice.excessKurtosis(xs) + 6);
}

fn flat(xs: []const f64) bool {
    const m = core.moments(xs);
    return m.sd <= 8 * std.math.floatEps(f64) * m.scale;
}

// ── normal and Student-t distribution functions ─────────────────────────────

/// Standard normal CDF Φ(z), for the probabilistic ratios. std has no erf, so
/// this is computed from erfc: the Kummer series e^{-x²} Σ 2^n x^(2n+1) / (2n+1)!!
/// for x = |z|/sqrt(2) < 1.2 and Laplace's continued fraction beyond. Pinned
/// against scipy `norm.cdf` at 1e-13 relative over -37 <= z <= 8 (the tails keep
/// their RELATIVE accuracy, Φ(-37) is right to 13 digits, not just near 0).
/// NaN for NaN; 0 / 1 beyond +-40.
pub fn normalCdf(z: f64) f64 {
    if (std.math.isNan(z)) return nan;
    if (z > 40) return 1;
    if (z < -40) return 0;
    const x = @abs(z) / std.math.sqrt2;
    const half_erfc = 0.5 * erfcPos(x);
    return if (z < 0) half_erfc else 1 - half_erfc;
}

/// erfc(x) for x >= 0.
fn erfcPos(x: f64) f64 {
    const e = @exp(-x * x);
    const two_over_sqrt_pi = 2.0 / @sqrt(std.math.pi);
    if (x < 1.2) {
        var term = x;
        var sum = x;
        const x2 = 2 * x * x;
        var k: f64 = 1;
        while (k < 200) : (k += 1) {
            term *= x2 / (2 * k + 1);
            sum += term;
            if (term < 1e-18 * sum) break;
        }
        return 1 - two_over_sqrt_pi * e * sum;
    }
    // erfc(x) = e^{-x²} / sqrt(pi) / (x + (1/2)/(x + 1/(x + (3/2)/(x + ...))))
    var t = x;
    var k: f64 = 300;
    while (k >= 1) : (k -= 1) t = x + (k / 2) / t;
    return e / @sqrt(std.math.pi) / t;
}

/// Φ^-1(p) for 0 < p <= 1/2 to ~1e-15: Acklam's start (`slice.invNormCdf`) and
/// one Halley step on the accurate `normalCdf`.
fn invNormLower(p: f64) f64 {
    const x = slice.invNormCdf(p);
    if (!std.math.isFinite(x)) return x;
    const e = normalCdf(x) - p;
    const u = e * @sqrt(2 * std.math.pi) * @exp(x * x / 2);
    return x - u / (1 + x * u / 2);
}

/// Regularised incomplete beta I_x(a, b) by Lentz's continued fraction (a, b > 0).
fn betaInc(a: f64, b: f64, x: f64) f64 {
    if (!(x > 0)) return 0;
    if (x >= 1) return 1;
    const bt = @exp(std.math.lgamma(f64, a + b) - std.math.lgamma(f64, a) - std.math.lgamma(f64, b) + a * @log(x) + b * std.math.log1p(-x));
    if (x < (a + 1) / (a + b + 2)) return bt * betaCf(a, b, x) / a;
    return 1 - bt * betaCf(b, a, 1 - x) / b;
}

fn betaCf(a: f64, b: f64, x: f64) f64 {
    const tiny = 1e-300;
    const qab = a + b;
    const qap = a + 1;
    const qam = a - 1;
    var c: f64 = 1;
    var d = 1 - qab * x / qap;
    if (@abs(d) < tiny) d = tiny;
    d = 1 / d;
    var h = d;
    var m: f64 = 1;
    while (m <= 100_000) : (m += 1) {
        const m2 = 2 * m;
        var aa = m * (b - m) * x / ((qam + m2) * (a + m2));
        d = 1 + aa * d;
        if (@abs(d) < tiny) d = tiny;
        c = 1 + aa / c;
        if (@abs(c) < tiny) c = tiny;
        d = 1 / d;
        h *= d * c;
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2));
        d = 1 + aa * d;
        if (@abs(d) < tiny) d = tiny;
        c = 1 + aa / c;
        if (@abs(c) < tiny) c = tiny;
        d = 1 / d;
        const del = d * c;
        h *= del;
        if (@abs(del - 1) < 1e-16) break;
    }
    return h;
}

/// Student-t CDF with `nu` degrees of freedom (accurate to ~1e-14 for nu up to
/// about 1e6; the continued fraction needs O(sqrt(nu)) steps).
fn studentCdf(t: f64, nu: f64) f64 {
    if (std.math.isNan(t)) return nan;
    const x = nu / (nu + t * t);
    const p = 0.5 * betaInc(nu / 2, 0.5, x);
    return if (t > 0) 1 - p else p;
}

// ── probabilistic and deflated Sharpe ───────────────────────────────────────

/// Which ratio `probabilisticRatio` is built on.
pub const RatioBase = enum { sharpe, sortino, adjusted_sortino };

/// Probabilistic ratio of Bailey and López de Prado (quantstats
/// `probabilistic_ratio`): the probability that the true ratio exceeds 0,
/// Φ(b / σ), with b the PER-PERIOD ratio (the annualised `slice.sharpeRatio` /
/// `sortinoRatio`, divided by sqrt(ppy); `adjusted_sortino` also by sqrt(2))
/// and σ² = (1 + b²/2 - skew b + excess_kurtosis b² / 4) / (n - 1), skew and
/// kurtosis the sample ones (`skewSample`, `kurtosisSample`). With `smart`, b is
/// divided by `autocorrPenalty` first. quantstats' `annualize` flag changes
/// nothing in this function (checked), so there is none here. σ = 0: 1, 0 or 0.5
/// by the sign of b. Fewer than 2 periods or a negative variance: NaN; NaN
/// also on non-finite input or bad `ppy`/`rf`.
pub fn probabilisticRatio(xs: []const f64, base: RatioBase, rf: f64, ppy: f64, smart: bool) f64 {
    const raw = switch (base) {
        .sharpe => slice.sharpeRatio(xs, rf, ppy),
        .sortino => slice.sortinoRatio(xs, rf, ppy),
        .adjusted_sortino => slice.sortinoRatio(xs, rf, ppy) / std.math.sqrt2,
    };
    var b = raw / @sqrt(ppy);
    if (smart) b /= autocorrPenalty(xs);
    if (std.math.isNan(b) or xs.len < 2) return nan;
    return probFromRatio(xs, b);
}

fn probFromRatio(xs: []const f64, b: f64) f64 {
    const n: f64 = @floatFromInt(xs.len);
    const v = (1 + 0.5 * b * b - skewSample(xs) * b + kurtosisSample(xs) / 4 * b * b) / (n - 1);
    if (std.math.isNan(v) or v < 0) return nan;
    const sigma = @sqrt(v);
    if (sigma == 0) return if (b > 0) 1 else if (b < 0) 0 else 0.5;
    return normalCdf(b / sigma);
}

/// `probabilisticRatio(.sharpe, ..., smart = false)` (quantstats
/// `probabilistic_sharpe_ratio`).
pub fn probabilisticSharpeRatio(xs: []const f64, rf: f64, ppy: f64) f64 {
    return probabilisticRatio(xs, .sharpe, rf, ppy, false);
}

/// `probabilisticRatio(.sortino, ...)` (quantstats `probabilistic_sortino_ratio`).
pub fn probabilisticSortinoRatio(xs: []const f64, rf: f64, ppy: f64) f64 {
    return probabilisticRatio(xs, .sortino, rf, ppy, false);
}

/// `probabilisticRatio(.adjusted_sortino, ...)` (quantstats
/// `probabilistic_adjusted_sortino_ratio`).
pub fn probabilisticAdjustedSortinoRatio(xs: []const f64, rf: f64, ppy: f64) f64 {
    return probabilisticRatio(xs, .adjusted_sortino, rf, ppy, false);
}

/// Expected maximum Sharpe ratio of `n_trials` skill-less strategies whose
/// Sharpe ratios have standard deviation `sr_std`:
/// sr_std * ((1 - γ) Φ^-1(1 - 1/n) + γ Φ^-1(1 - 1/(n e))), γ the
/// Euler-Mascheroni constant (ffn `calc_expected_max_sharpe`, equal to scipy
/// `norm.ppf` evaluation of that formula). The result is in the units of `sr_std`.
/// One trial: 0 (no selection effect; ffn agrees). No trial or a negative or
/// non-finite `sr_std`: NaN (ffn raises for 0 trials).
pub fn expectedMaxSharpe(n_trials: usize, sr_std: f64) f64 {
    if (n_trials == 0 or !std.math.isFinite(sr_std) or sr_std < 0) return nan;
    if (n_trials == 1) return 0;
    const gamma = 0.5772156649015329;
    const n: f64 = @floatFromInt(n_trials);
    const z1 = -invNormLower(1 / n);
    const z2 = -invNormLower(1 / (n * std.math.e));
    return sr_std * ((1 - gamma) * z1 + gamma * z2);
}

/// Deflated Sharpe ratio of the best of several trials (ffn
/// `calc_deflated_sharpe_ratio`, Bailey and López de Prado 2014):
/// Φ((SR - SR0) sqrt(n - 1) / sqrt(1 - skew SR + (excess_kurtosis + 2) SR² / 4))
/// with SR the PER-PERIOD Sharpe ratio of `xs` after the risk-free rate
/// (`slice.sharpeRatio / sqrt(ppy)`), skew and kurtosis the sample ones, and
/// SR0 = `expectedMaxSharpe(trials.len, std(trial_sharpes) / sqrt(ppy))`, the
/// trial standard deviation sample (ddof 1). `trial_sharpes` are ANNUALISED Sharpe
/// ratios of ALL trials tried (as `sharpeRatio` returns them; ffn's default
/// `annualized_trials = true`, the other mode is not offered). Fewer than 2
/// periods or 2 trials, a non-finite value, bad `ppy`/`rf` or a negative
/// variance term: NaN.
pub fn deflatedSharpeRatio(xs: []const f64, trial_sharpes: []const f64, rf: f64, ppy: f64) f64 {
    if (xs.len < 2 or trial_sharpes.len < 2 or !finiteAll(trial_sharpes)) return nan;
    const sr = slice.sharpeRatio(xs, rf, ppy) / @sqrt(ppy);
    if (std.math.isNan(sr)) return nan;
    const s0 = expectedMaxSharpe(trial_sharpes.len, core.stdSample(trial_sharpes) / @sqrt(ppy));
    const n: f64 = @floatFromInt(xs.len);
    const den2 = 1 - skewSample(xs) * sr + (kurtosisSample(xs) + 2) / 4 * sr * sr;
    if (std.math.isNan(s0) or !(den2 > 0)) return nan;
    return normalCdf((sr - s0) * @sqrt(n - 1) / @sqrt(den2));
}

/// Probabilistic momentum (ffn `calc_prob_mom`; the CSS Analytics idea): the
/// probability that `p` outperforms `b`, the Student-t CDF (n - 1 degrees of
/// freedom) of the paired t statistic mean(d) / (std(d) / sqrt(n)), d = p - b,
/// sample std. Equal series: 0.5. Zero spread of d: 1, 0 or 0.5 by the sign of the
/// mean. NaN for different lengths, fewer than 2 periods or non-finite input.
pub fn probMom(p: []const f64, b: []const f64) f64 {
    if (p.len != b.len or p.len < 2 or !finiteAll(p) or !finiteAll(b)) return nan;
    const n: f64 = @floatFromInt(p.len);
    const d0 = p[0] - b[0];
    var s: f64 = 0;
    var scale: f64 = 0;
    for (p, b) |x, y| {
        const d = (x - y) - d0;
        s += d;
        scale = @max(scale, @abs(x - y));
    }
    const dm = s / n;
    var ss: f64 = 0;
    for (p, b) |x, y| ss += ((x - y) - d0 - dm) * ((x - y) - d0 - dm);
    const mean = d0 + dm;
    const sd = @sqrt(ss / (n - 1));
    if (!std.math.isFinite(mean) or !std.math.isFinite(sd)) return nan;
    if (sd <= 8 * std.math.floatEps(f64) * scale) return if (mean > 0) 1 else if (mean < 0) 0 else 0.5;
    return studentCdf(mean / (sd / @sqrt(n)), n - 1);
}

// ── rolling rank, risk of ruin ──────────────────────────────────────────────

/// Rolling percentile rank of each price among the last `window` prices
/// including itself, 0..100, ties by their average rank (quantstats `pct_rank`,
/// scipy `percentileofscore(kind = "rank")`): (below + (equal + 1) / 2) / m * 100,
/// m the number of prices in the window. The first `window - 1` rows use the
/// shorter window they have (quantstats does the same, no NaN warm-up). The
/// caller frees the result, one value per price. `window == 0` or non-finite
/// prices: every value NaN. O(n * window); more than `max_rank_work` comparisons:
/// `error.TooLarge`.
pub fn pctRank(a: std.mem.Allocator, prices: []const f64, window: usize) Error![]f64 {
    const n = prices.len;
    const w = @min(window, n);
    if (window != 0 and w != 0 and n > max_rank_work / w) return error.TooLarge;
    const out = try a.alloc(f64, n);
    errdefer a.free(out);
    if (window == 0 or !finiteAll(prices)) {
        @memset(out, nan);
        return out;
    }
    for (prices, 0..) |v, i| {
        const lo = if (i + 1 > window) i + 1 - window else 0;
        var below: usize = 0;
        var equal: usize = 0;
        for (prices[lo .. i + 1]) |u| {
            if (u < v) below += 1 else if (u == v) equal += 1;
        }
        const m: f64 = @floatFromInt(i + 1 - lo);
        out[i] = (@as(f64, @floatFromInt(below)) + (@as(f64, @floatFromInt(equal)) + 1) / 2) / m * 100;
    }
    return out;
}

/// Classical gambler's ruin probability ((1 - edge) / (1 + edge))^units, with
/// edge = 2p - 1 for a win probability p (a fair game, p = 0.5, edge 0, ruins
/// with certainty: 1) and `units` the number of bankroll units at risk. No edge
/// (edge <= 0): 1. Edge >= 1 (a sure win): 0, or 1 for zero units. NaN for NaN
/// or negative `units`, or NaN `edge`.
///
/// This is NOT quantstats' `risk_of_ruin`, which computes
/// ((1 - win_rate) / (1 + win_rate))^len(returns): it puts the WIN RATE where the
/// edge belongs and the length of the series where the units belong. Its numbers
/// differ from this function's on purpose and are not a reference for it.
pub fn riskOfRuin(edge: f64, units: f64) f64 {
    if (std.math.isNan(edge) or std.math.isNan(units) or units < 0) return nan;
    if (units == 0 or edge <= 0) return 1;
    if (edge >= 1) return 0;
    return std.math.pow(f64, (1 - edge) / (1 + edge), units);
}
