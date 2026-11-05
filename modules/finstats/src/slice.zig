// SPDX-License-Identifier: MIT
//! Plain-slice statistics: `finstats.slice`. No table type anywhere: inputs are
//! `[]const f64`, dates are ISO `YYYY-MM-DD` text, a row is a named struct.
//! Everything in it is reachable without `dataset`.
//!
//! Failures. A function that returns an error set reports a bad input through
//! it: `error.LengthMismatch` for series of different lengths, `error.BadDate`
//! for a date that is not a real ISO date, `error.TooLarge` past a stated cap.
//! A function that returns a bare number or row answers NaN for the same bad
//! input, as it does for every other undefined statistic. Nothing panics.

const std = @import("std");
const core = @import("core.zig");
const mean = core.mean;
const stdSample = core.stdSample;
const f64lt = core.f64lt;
const finiteAll = core.finiteAll;
const compoundable = core.compoundable;
const rfPerPeriod = core.rfPerPeriod;
const levelOf = core.levelOf;
const cagrOf = core.cagrOf;
const betaOf = core.betaOf;
const moments = core.moments;
const quantileSelect = core.quantileSelect;
const Cashflow = core.Cashflow;

/// Most bins `histogram` will produce (`HistogramSpec.bins` above it is
/// `error.TooLarge`). A histogram with more than 65 536 buckets is not a
/// histogram anyone reads, and the bin count comes straight from a spec: at
/// `bins = 1e9` the count buffer alone is 8 GB.
pub const max_histogram_bins: usize = 65_536;

/// Most simulated values (`paths` x (months + 1)) `monteCarlo` will hold and
/// draw in one call: 2^25 `f64` = 256 MiB of scratch and about 33 million
/// normal draws. The default 2000 paths over 100 years is 2.4 million.
/// Above it `error.TooLarge` (it used to be left to the allocator, which with
/// overcommit says yes and then gets the process killed).
pub const max_monte_carlo_cells: usize = 1 << 25;

/// Most months `monteCarlo` will project (1000 years). Every month costs a
/// path buffer, a slice header, an output row and a `Value[4]` whatever
/// `paths` is, so a one-path run of 3e7 months passes the cell cap and still
/// needs about 6 GB. Above it `error.TooLarge`.
pub const max_monte_carlo_months: usize = 12_000;

/// Most distinct keys `correlationMatrix` will correlate: the output is
/// keys^2 cells and the key count comes from the DATA. One more than this is
/// `error.TooLarge`.
pub const max_corr_keys: usize = 1024;

/// Most hash lookups `correlationMatrix` will do: the sum over key pairs of
/// the shorter series' length (each pair walks its shorter series), counted
/// from the series sizes BEFORE the pair loop. 2^28 is a few seconds; above
/// it `error.TooLarge`. With `max_corr_keys` keys of D dates each the work is
/// about keys^2 / 2 x D, which is what this bounds.
pub const max_corr_work: usize = 1 << 28;

/// `xirrPrecise` bounds its Newton steps so that steps x cashflows stays under
/// this many NPV terms (each step is two passes over the cashflows): 2^26.
/// The budget never drops below 10 steps, and running out is not an error.
pub const max_xirr_work: usize = 1 << 26;

/// Most window-evaluations x window length (`rollingApply`,
/// `rollingBetaAlpha`) one call will do: 2^30 element visits, a few seconds.
/// Rolling with a generic reducer costs O(rows x window), which is quadratic
/// for a window of about half the series; above the cap `error.TooLarge`.
pub const max_rolling_work: usize = 1 << 30;

/// `xirrPrecise` runs at most this many Newton steps whatever
/// `max_newton_iter` says (see there).
pub const max_newton_iter_cap: usize = 10_000;

/// CAGR: (1 + total_return)^(365.25/days) − 1.
pub fn annualize(total_return: f64, days: f64) f64 {
    if (days <= 0) return 0;
    return std.math.pow(f64, 1.0 + total_return, 365.25 / days) - 1.0;
}

/// Linear-interpolation quantile of a pre-sorted slice (exact port). `q` is
/// clamped into `[0, 1]` (and NaN maps to 0), so an out-of-range caller value
/// cannot drive `pos` negative/NaN into `@intFromFloat` (a panic in ReleaseSafe,
/// an out-of-bounds read in ReleaseFast).
pub fn quantileSorted(sorted: []const f64, q: f64) f64 {
    const n = sorted.len;
    if (n == 0) return 0;
    if (n == 1) return sorted[0];
    const qc = if (std.math.isNan(q)) 0.0 else std.math.clamp(q, 0.0, 1.0);
    const pos = qc * @as(f64, @floatFromInt(n - 1));
    const lo: usize = @intFromFloat(@floor(pos));
    const hi: usize = @intFromFloat(@ceil(pos));
    const frac = pos - @floor(pos);
    return sorted[lo] * (1.0 - frac) + sorted[hi] * frac;
}

/// Quantile of an unsorted slice (sorts a copy).
pub fn quantile(a: std.mem.Allocator, xs: []const f64, q: f64) std.mem.Allocator.Error!f64 {
    const s = try a.dupe(f64, xs);
    defer a.free(s);
    std.mem.sort(f64, s, {}, f64lt);
    return quantileSorted(s, q);
}

// ── parametric VaR/CVaR (Gaussian + Cornish-Fisher — backlog item) ──────────
// Historical (empirical) VaR/CVaR already live in `riskMetrics`; these are
// the parametric siblings: Gaussian fits mean/stdev to a normal and reads the
// loss quantile off it; Cornish-Fisher additionally skew/kurtosis-corrects
// the z-score before reading it off the same normal machinery. Confidence is
// a free parameter here (riskMetrics' historical var95/cvar95 stay hardcoded
// at 95% for behavioral pinning).

/// Standard normal PDF.
pub fn normalPdf(z: f64) f64 {
    return @exp(-z * z / 2.0) / @sqrt(2.0 * std.math.pi);
}

/// Inverse standard normal CDF (quantile function) — Peter Acklam's rational
/// approximation (|relative error| < 1.15e-9 on (0,1); std has no erf/erfinv
/// to refine further with a Halley step, and this is already ample precision
/// for risk-metric z-scores).
pub fn invNormCdf(p: f64) f64 {
    if (p <= 0) return -std.math.inf(f64);
    if (p >= 1) return std.math.inf(f64);
    const a = [_]f64{ -3.969683028665376e+01, 2.209460984245205e+02, -2.759285104469687e+02, 1.383577518672690e+02, -3.066479806614716e+01, 2.506628277459239e+00 };
    const b = [_]f64{ -5.447609879822406e+01, 1.615858368580409e+02, -1.556989798598866e+02, 6.680131188771972e+01, -1.328068155288572e+01 };
    const c = [_]f64{ -7.784894002430293e-03, -3.223964580411365e-01, -2.400758277161838e+00, -2.549732539343734e+00, 4.374664141464968e+00, 2.938163982698783e+00 };
    const d = [_]f64{ 7.784695709041462e-03, 3.224671290700398e-01, 2.445134137142996e+00, 3.754408661907416e+00 };
    const p_low = 0.02425;
    const p_high = 1.0 - p_low;
    if (p < p_low) {
        const q = @sqrt(-2.0 * @log(p));
        return (((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]) /
            ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1.0);
    } else if (p <= p_high) {
        const q = p - 0.5;
        const r = q * q;
        return (((((a[0] * r + a[1]) * r + a[2]) * r + a[3]) * r + a[4]) * r + a[5]) * q /
            (((((b[0] * r + b[1]) * r + b[2]) * r + b[3]) * r + b[4]) * r + 1.0);
    } else {
        const q = @sqrt(-2.0 * @log(1.0 - p));
        return -(((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]) /
            ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1.0);
    }
}

/// Gaussian (parametric) VaR: loss magnitude at `confidence` under a normal
/// fit to `mean_`/`std_dev`. `VaR = -(mean + z·std_dev)`, z = Φ⁻¹(1−confidence).
pub fn gaussianVaR(mean_: f64, std_dev: f64, confidence: f64) f64 {
    const z = invNormCdf(1.0 - confidence);
    return -(mean_ + z * std_dev);
}

/// Gaussian (parametric) CVaR / expected shortfall: mean loss beyond the
/// Gaussian VaR threshold. `CVaR = -mean + std_dev·φ(z)/α`, α = 1−confidence,
/// z = Φ⁻¹(α). Always ≥ VaR (the tail mean is at least as extreme as the
/// tail boundary).
pub fn gaussianCVaR(mean_: f64, std_dev: f64, confidence: f64) f64 {
    const alpha = 1.0 - confidence;
    if (alpha <= 0) return gaussianVaR(mean_, std_dev, confidence);
    const z = invNormCdf(alpha);
    return -mean_ + std_dev * normalPdf(z) / alpha;
}

/// Cornish-Fisher skew/kurtosis-adjusted z-score (the standard 3-term
/// expansion). `excess_kurt` is kurtosis − 3 (0 for a normal). Collapses to
/// `z` exactly when skew = excess_kurt = 0.
pub fn cornishFisherZ(z: f64, skew: f64, excess_kurt: f64) f64 {
    const z2 = z * z;
    const z3 = z2 * z;
    return z + (z2 - 1.0) * skew / 6.0 + (z3 - 3.0 * z) * excess_kurt / 24.0 - (2.0 * z3 - 5.0 * z) * skew * skew / 36.0;
}

/// Cornish-Fisher (modified) VaR: Gaussian VaR with the CF-adjusted z-score
/// in place of the raw normal one.
pub fn cornishFisherVaR(mean_: f64, std_dev: f64, skew: f64, excess_kurt: f64, confidence: f64) f64 {
    const z = invNormCdf(1.0 - confidence);
    const zcf = cornishFisherZ(z, skew, excess_kurt);
    return -(mean_ + zcf * std_dev);
}

/// Cornish-Fisher (modified) CVaR: −(1/α)·∫₀^α Q_CF(p) dp — the tail mean of
/// the CF-implied quantile function, `Q_CF(p) = mean + std_dev·cf(Φ⁻¹(p))`.
/// Exact, in closed form: substituting p = Φ(z) turns the integral into
/// ∫ cf(z)·φ(z) dz over (−∞, a], a = Φ⁻¹(α), and `cf` is a cubic, whose
/// truncated Gaussian moments are ∫z⁰φ = α, ∫z¹φ = −φ(a), ∫z²φ = α − a·φ(a),
/// ∫z³φ = −(a² + 2)·φ(a). Collecting the terms:
///
///   CVaR = −mean + std_dev·φ(a)/α · [1 + a·s/6 − (1 − a²)·k/24 + (1 − 2a²)·s²/36]
///
/// (s = skew, k = excess_kurt), which is `gaussianCVaR` exactly when s = k = 0.
/// Until 2026-10-07 this was a 2000-step trapezoidal quadrature from p = 1e-9,
/// which overstated CVaR by up to 1.4e-3 relative on fat-tailed series (the
/// integrand is steep as p → 0); R PerformanceAnalytics' modified-VaR quantile
/// integrated by R's adaptive quadrature exposed it (src/oracle_test.zig).
/// A naive shortcut — plugging the CF z-score into the Gaussian ES ratio
/// (`φ(z_cf)/α`) the way `cornishFisherVaR` plugs it into the VaR formula — is
/// a different, wrong quantity: for negative-skew/fat-tailed inputs it can
/// report CVaR < VaR. Nor is this PerformanceAnalytics' `ES(method =
/// "modified")`, which is Boudt, Peterson & Croux's Edgeworth estimator.
pub fn cornishFisherCVaR(mean_: f64, std_dev: f64, skew: f64, excess_kurt: f64, confidence: f64) f64 {
    const alpha = 1.0 - confidence;
    if (alpha <= 0) return cornishFisherVaR(mean_, std_dev, skew, excess_kurt, confidence);
    const a = invNormCdf(alpha);
    const a2 = a * a;
    const bracket = 1.0 + a * skew / 6.0 - (1.0 - a2) * excess_kurt / 24.0 + (1.0 - 2.0 * a2) * skew * skew / 36.0;
    return -mean_ + std_dev * normalPdf(a) / alpha * bracket;
}

/// Sample skewness (moment coefficient g1, population-normalized: divides by
/// n not n−1 — the conventional definition for CF/parametric-risk use).
pub fn skewness(xs: []const f64) f64 {
    const n = xs.len;
    if (n < 2) return 0;
    const m = mean(xs);
    var m2: f64 = 0;
    var m3: f64 = 0;
    for (xs) |x| {
        const dx = x - m;
        m2 += dx * dx;
        m3 += dx * dx * dx;
    }
    const nf: f64 = @floatFromInt(n);
    m2 /= nf;
    m3 /= nf;
    if (m2 <= 0) return 0;
    return m3 / std.math.pow(f64, m2, 1.5);
}

/// Sample excess kurtosis (g2 = kurtosis − 3; 0 for a normal).
pub fn excessKurtosis(xs: []const f64) f64 {
    const n = xs.len;
    if (n < 2) return 0;
    const m = mean(xs);
    var m2: f64 = 0;
    var m4: f64 = 0;
    for (xs) |x| {
        const dx = x - m;
        const dx2 = dx * dx;
        m2 += dx2;
        m4 += dx2 * dx2;
    }
    const nf: f64 = @floatFromInt(n);
    m2 /= nf;
    m4 /= nf;
    if (m2 <= 0) return 0;
    return m4 / (m2 * m2) - 3.0;
}

// ── Omega ratio (backlog item) ───────────────────────────────────────────────

/// Omega ratio at `threshold`: Σ gains-above-threshold / Σ losses-below-
/// threshold (both accumulated as positive magnitudes). > 1 ⇒ more upside
/// mass than downside mass around the threshold. No losses in the series
/// (denominator 0) ⇒ +∞ when there is any gain, 1.0 when the whole series
/// sits exactly at the threshold (both sums 0).
pub fn omegaRatio(xs: []const f64, threshold: f64) f64 {
    var gains: f64 = 0;
    var losses: f64 = 0;
    for (xs) |x| {
        const diff = x - threshold;
        if (diff > 0) gains += diff else losses += -diff;
    }
    if (losses == 0) return if (gains == 0) 1.0 else std.math.inf(f64);
    return gains / losses;
}

pub fn rollingMeanReducer(xs: []const f64) f64 {
    return mean(xs);
}
pub fn rollingVolReducer(xs: []const f64) f64 {
    return stdSample(xs);
}
pub fn rollingSharpeReducer(xs: []const f64) f64 {
    const s = stdSample(xs);
    return if (s != 0) mean(xs) / s else 0;
}

// ── trade statistics (survey 2026-09-30) ────────────────────────────────────
// quantstats' definitions: a "win" is a positive period return, a "loss" a
// negative one; zero returns are neither (they are excluded from win rate and
// from the averages).

/// Positive periods / non-zero periods; 0 when every period is zero.
pub fn winRate(xs: []const f64) f64 {
    var wins: usize = 0;
    var losses: usize = 0;
    for (xs) |x| {
        if (x > 0) wins += 1 else if (x < 0) losses += 1;
    }
    if (wins + losses == 0) return 0;
    return @as(f64, @floatFromInt(wins)) / @as(f64, @floatFromInt(wins + losses));
}

/// Average win / |average loss|. No losses: +inf when there are wins, 0 when
/// there are none either.
pub fn payoffRatio(xs: []const f64) f64 {
    var wsum: f64 = 0;
    var lsum: f64 = 0;
    var wins: usize = 0;
    var losses: usize = 0;
    for (xs) |x| {
        if (x > 0) {
            wsum += x;
            wins += 1;
        } else if (x < 0) {
            lsum += x;
            losses += 1;
        }
    }
    if (wins == 0) return 0;
    if (losses == 0) return std.math.inf(f64);
    const avg_win = wsum / @as(f64, @floatFromInt(wins));
    const avg_loss = lsum / @as(f64, @floatFromInt(losses));
    return avg_win / @abs(avg_loss);
}

/// Σ gains / |Σ losses| — the Omega ratio at threshold 0 (`omegaRatio`, with
/// its conventions: no losses → +inf, a flat series → 1).
pub fn profitFactor(xs: []const f64) f64 {
    return omegaRatio(xs, 0);
}

/// Kelly fraction f = p − q / b with p = `winRate`, q = 1 − p, b =
/// `payoffRatio` (quantstats' `kelly_criterion`, rearranged). No wins → −inf
/// (never bet); no losses → p; no non-zero period → 0.
pub fn kellyCriterion(xs: []const f64) f64 {
    const p = winRate(xs);
    const b = payoffRatio(xs);
    if (p == 0 and b == 0) {
        for (xs) |x| if (x < 0) return -std.math.inf(f64);
        return 0;
    }
    return p - (1 - p) / b;
}

/// |95th percentile| / |5th percentile| (empyrical / quantstats `tail_ratio`,
/// linear interpolation as numpy's default). A zero 5th percentile gives +inf,
/// or 0 when the 95th is zero too. Sorts a scratch copy.
pub fn tailRatio(a: std.mem.Allocator, xs: []const f64) std.mem.Allocator.Error!f64 {
    if (xs.len == 0) return 0;
    const s = try a.dupe(f64, xs);
    defer a.free(s);
    std.mem.sort(f64, s, {}, f64lt);
    const hi = @abs(quantileSorted(s, 0.95));
    const lo = @abs(quantileSorted(s, 0.05));
    if (lo == 0) return if (hi == 0) 0 else std.math.inf(f64);
    return hi / lo;
}

// ── period statistics: empyrical / ffn / quantstats conventions (survey 2026-11-02)
//
// Non-finite input. A NaN or infinite return makes a statistic undefined, and
// every function in this section, `riskMetrics` and `tradeStats` answers NaN
// (the whole row, for the nodes) rather than a finite number computed around
// the hole: `@min` and `<` skip a NaN silently, so unguarded arithmetic mixes
// finite and NaN cells. A return below -1 (a loss of more than the whole stake)
// is not a return either: the functions that compound (`totalReturn`,
// `cagrPeriods`, `geometricMean`, `maxDrawdown`, `calmarRatio`,
// `recoveryFactor`, `stability`) and `riskMetrics` answer NaN for it; the
// mean/std ones accept it. An empty series, zero variance and a zero
// denominator are not errors. Zero denominator, by function: `sharpeRatio`
// (zero spread, to rounding; exactly zero for a constant series),
// `sortinoRatio` (no downside), `calmarRatio` (no drawdown) answer 0;
// `gainToPain` (no losses) and `recoveryFactor` (no drawdown) answer +inf for a
// positive numerator, else 0, as `omegaRatio` does. Products are kept inside
// f64 by renormalising (`levelOf`), so a long series does not underflow to -1
// or overflow to NaN terms before its true answer is out of range; the total
// return is +inf past the f64 range.

/// Π(1 + r) - 1, the compounded total return (empyrical `cum_returns_final`,
/// quantstats `comp`). 0 for an empty series; NaN if not `compoundable`; +inf if
/// the level exceeds f64, -1 (not -0.99999...) if it underflows to nothing.
pub fn totalReturn(xs: []const f64) f64 {
    if (!compoundable(xs)) return std.math.nan(f64);
    const l = levelOf(xs);
    const e: i32 = @intCast(std.math.clamp(l.e, -5000, 5000));
    return std.math.ldexp(l.m, e) - 1;
}

/// Compound growth per year, Π(1 + r)^(ppy / n) - 1, periods counted by row
/// (empyrical `annual_return`, quantstats `cagr(periods = ppy)`; the two agree
/// to 1e-12). ffn's `calc_cagr` instead measures calendar time between the
/// first and last date of a PRICE series, so it differs on the same returns;
/// `riskMetrics` follows that calendar idea through `date_col`. 0 for an empty
/// series; NaN if not `compoundable` or `ppy` is not positive finite.
pub fn cagrPeriods(xs: []const f64, ppy: f64) f64 {
    if (!compoundable(xs) or !(ppy > 0) or !std.math.isFinite(ppy)) return std.math.nan(f64);
    return cagrOf(xs, ppy);
}

/// Geometric mean return per period, Π(1 + r)^(1/n) - 1 (quantstats
/// `geometric_mean` / `expected_return`). 0 for an empty series.
pub fn geometricMean(xs: []const f64) f64 {
    return cagrPeriods(xs, 1);
}

/// Worst peak-to-trough fall of the compounded level, a fraction <= 0, measured
/// from the starting level 1 (so a first-period loss is a drawdown; empyrical
/// `max_drawdown`). 0 for an empty series; NaN if not `compoundable`.
pub fn maxDrawdown(xs: []const f64) f64 {
    if (!compoundable(xs)) return std.math.nan(f64);
    var level: f64 = 1;
    var peak: f64 = 1;
    var worst: f64 = 0;
    for (xs) |x| {
        level *= 1 + x;
        peak = @max(peak, level);
        worst = @min(worst, (level - peak) / peak);
        // keep the level inside f64: only the ratio level / peak matters, and an
        // infinite peak would turn every later term into NaN, which @min skips
        if (peak > 0x1p500) {
            level *= 0x1p-500;
            peak *= 0x1p-500;
        }
    }
    return worst;
}

/// Sharpe ratio, mean(r - rf_p) / std(r) * sqrt(ppy), sample std (ddof 1).
/// `rf` is ANNUAL and compounded down to a period, rf_p = (1 + rf)^(1/ppy) - 1
/// (quantstats `sharpe(rf, periods)`). empyrical's `sharpe_ratio` takes rf_p
/// directly and gives the same number; ffn 1.3.0's `calc_sharpe` agrees too
/// (all three measured equal to 1e-12 on the oracle series). NOT
/// `riskMetrics.sharpe`, which divides the calendar-day CAGR by the volatility.
/// Fewer than two periods or zero spread: 0. NaN on non-finite input.
pub fn sharpeRatio(xs: []const f64, rf: f64, ppy: f64) f64 {
    const rfp = rfPerPeriod(rf, ppy);
    if (std.math.isNan(rfp)) return std.math.nan(f64);
    const m = moments(xs);
    if (!m.finite) return std.math.nan(f64);
    if (xs.len < 2) return 0;
    // A standard deviation that is zero up to rounding: the sample std of a
    // constant series is not exactly 0 in floating point (x - mean is ~1e-18),
    // and dividing by it would print a huge, meaningless ratio.
    if (m.sd <= 8 * std.math.floatEps(f64) * m.scale) return 0;
    return (m.mean - rfp) / m.sd * @sqrt(ppy);
}

/// Sortino ratio, mean(r - rf_p) / downside * sqrt(ppy), downside =
/// sqrt(Σ min(r - rf_p, 0)² / n) over ALL n periods (empyrical `sortino_ratio`
/// with required return rf_p, quantstats `sortino`; equal to 1e-12). The
/// threshold is rf_p, unlike `riskMetrics.downside`, which is measured against
/// 0. ffn 1.3.0's `calc_sortino_ratio` agrees at rf = 0 on the oracle series.
/// Zero downside: 0. NaN on non-finite input.
pub fn sortinoRatio(xs: []const f64, rf: f64, ppy: f64) f64 {
    const rfp = rfPerPeriod(rf, ppy);
    if (!finiteAll(xs) or std.math.isNan(rfp)) return std.math.nan(f64);
    if (xs.len == 0) return 0;
    var dsum: f64 = 0;
    for (xs) |x| {
        const m = @min(x - rfp, 0.0);
        dsum += m * m;
    }
    const dd = @sqrt(dsum / @as(f64, @floatFromInt(xs.len)));
    if (dd == 0) return 0;
    return (mean(xs) - rfp) / dd * @sqrt(ppy);
}

/// `cagrPeriods / |maxDrawdown|` (empyrical `calmar_ratio`, quantstats `calmar`,
/// equal to 1e-12). No drawdown: 0. NOT `riskMetrics.calmar` (calendar-day CAGR).
pub fn calmarRatio(xs: []const f64, ppy: f64) f64 {
    const g = cagrPeriods(xs, ppy);
    const dd = maxDrawdown(xs);
    if (std.math.isNan(g) or std.math.isNan(dd)) return std.math.nan(f64);
    if (dd == 0) return 0;
    return g / @abs(dd);
}

/// Σ r / |Σ losses| (quantstats `gain_to_pain_ratio`). No losses: +inf when the
/// sum is positive, else 0. NaN on non-finite input.
pub fn gainToPain(xs: []const f64) f64 {
    if (!finiteAll(xs)) return std.math.nan(f64);
    var sum: f64 = 0;
    var loss: f64 = 0;
    for (xs) |x| {
        sum += x;
        if (x < 0) loss += x;
    }
    if (loss == 0) return if (sum > 0) std.math.inf(f64) else 0;
    return sum / @abs(loss);
}

/// |Σ r| / |maxDrawdown| (quantstats `recovery_factor`: the SUM of returns, not
/// the compounded total). No drawdown: +inf when the sum is non-zero, else 0.
pub fn recoveryFactor(xs: []const f64) f64 {
    const dd = maxDrawdown(xs);
    if (std.math.isNan(dd)) return std.math.nan(f64);
    var sum: f64 = 0;
    for (xs) |x| sum += x;
    if (dd == 0) return if (sum != 0) std.math.inf(f64) else 0;
    return @abs(sum) / @abs(dd);
}

/// Largest single-period return (quantstats `best`); 0 for an empty series, NaN
/// on non-finite input.
pub fn bestReturn(xs: []const f64) f64 {
    if (!finiteAll(xs)) return std.math.nan(f64);
    if (xs.len == 0) return 0;
    return std.mem.max(f64, xs);
}

/// Smallest single-period return (quantstats `worst`); 0 for an empty series,
/// NaN on non-finite input.
pub fn worstReturn(xs: []const f64) f64 {
    if (!finiteAll(xs)) return std.math.nan(f64);
    if (xs.len == 0) return 0;
    return std.mem.min(f64, xs);
}

/// Mean of the strictly positive periods (quantstats `avg_win`); 0 if none.
pub fn avgWin(xs: []const f64) f64 {
    if (!finiteAll(xs)) return std.math.nan(f64);
    var s: f64 = 0;
    var n: usize = 0;
    for (xs) |x| if (x > 0) {
        s += x;
        n += 1;
    };
    return if (n == 0) 0 else s / @as(f64, @floatFromInt(n));
}

/// Mean of the strictly negative periods, a value <= 0 (quantstats `avg_loss`); 0 if none.
pub fn avgLoss(xs: []const f64) f64 {
    if (!finiteAll(xs)) return std.math.nan(f64);
    var s: f64 = 0;
    var n: usize = 0;
    for (xs) |x| if (x < 0) {
        s += x;
        n += 1;
    };
    return if (n == 0) 0 else s / @as(f64, @floatFromInt(n));
}

/// Longest run of consecutive strictly positive periods (quantstats
/// `consecutive_wins`). A zero or NaN period ends a run.
pub fn maxConsecutiveWins(xs: []const f64) usize {
    var best: usize = 0;
    var run: usize = 0;
    for (xs) |x| {
        if (x > 0) run += 1 else run = 0;
        best = @max(best, run);
    }
    return best;
}

/// Longest run of consecutive strictly negative periods (quantstats `consecutive_losses`).
pub fn maxConsecutiveLosses(xs: []const f64) usize {
    var best: usize = 0;
    var run: usize = 0;
    for (xs) |x| {
        if (x < 0) run += 1 else run = 0;
        best = @max(best, run);
    }
    return best;
}

/// R² of the cumulative log return against time (empyrical
/// `stability_of_timeseries`): how straight the compounded growth line is, in
/// [0, 1]. Fewer than two periods or a flat cumulative line: 0. NaN if not
/// `compoundable`, and for a -100 % period (its logarithm is -inf).
pub fn stability(xs: []const f64) f64 {
    if (!compoundable(xs)) return std.math.nan(f64);
    for (xs) |x| if (x == -1) return std.math.nan(f64); // log1p(-1) = -inf, whatever n
    if (xs.len < 2) return 0;
    // Welford co-moments of (t, y), y = cumulative log1p(r), t = 0..n-1.
    var cnt: f64 = 0;
    var mt: f64 = 0;
    var my: f64 = 0;
    var ctt: f64 = 0;
    var cyy: f64 = 0;
    var cty: f64 = 0;
    var y: f64 = 0;
    for (xs, 0..) |x, i| {
        if (x == -1) return std.math.nan(f64);
        y += std.math.log1p(x);
        const t: f64 = @floatFromInt(i);
        cnt += 1;
        const dt = t - mt;
        const dy = y - my;
        mt += dt / cnt;
        my += dy / cnt;
        ctt += dt * (t - mt);
        cyy += dy * (y - my);
        cty += dt * (y - my);
    }
    if (cyy <= 0 or ctt <= 0) return 0;
    return cty * cty / (ctt * cyy);
}

/// Whether the series starts from nothing, and — if it does not — whether the
/// first row's `value_col` already contains the flow recorded on that same row.
///
/// The default `.none` is right for an inception-to-date series: the portfolio
/// starts at ~0 and every unit in it arrived as a flow, so external flows plus
/// the terminal value are the whole story. It is WRONG for a series sliced out
/// of the middle of a portfolio's life — a date-range window — where the
/// opening market value would otherwise appear out of nothing, NPV never
/// crosses zero inside the bracket, and the result is `error.XirrNoRoot`.
///
/// Which of the two seeding variants applies is a property of the caller's
/// data and is invisible in the output, so it has to be stated rather than
/// guessed:
pub const Opening = enum {
    /// No opening position. The series begins at zero (inception-to-date).
    none,
    /// `value[0]` is an END-of-period figure that ALREADY includes row 0's own
    /// flow — the usual shape when `value` is an end-of-day market value and
    /// `flow` is that day's external contribution. Seeds `-value[0]` at
    /// `date[0]` and SKIPS row 0's flow, which would otherwise be counted
    /// twice: once inside the seed and once on its own.
    value_includes_flow,
    /// `value[0]` is an OPENING figure taken BEFORE row 0's flow. Seeds
    /// `-value[0]` at `date[0]` and ALSO keeps row 0's flow.
    value_excludes_flow,
};

// ── errors, dates ───────────────────────────────────────────────────────────

/// What the slice functions report. `LengthMismatch`: two series that must be
/// aligned have different lengths. `BadDate`: a date that is not a real ISO date.
/// `TooLarge`: the call asks for more work or output than the stated cap.
/// `DatesNotSorted`: a calendar function got dates that go backwards.
pub const Error = error{ OutOfMemory, TooLarge, LengthMismatch, BadDate, DatesNotSorted };

/// `xirr` and `xirrPrecise`. `XirrNoRoot`: NPV has no single crossing across
/// `[bracket_lo, bracket_hi]`, or a flow or value is not finite. `EmptyWindow`:
/// no rows, which is no answer rather than a return of 0.
pub const XirrError = Error || error{ XirrNoRoot, EmptyWindow };

pub const bracket_lo = core.bracket_lo;
pub const bracket_hi = core.bracket_hi;
pub const default_rate_tol = core.default_rate_tol;

/// Day number of an ISO date: `YYYY-MM-DD`, optionally followed by `T` or a space
/// and anything else (a time, which is ignored). Year 0000 to 9999. Anything
/// else, including 2023-02-29, is `error.BadDate`. Only differences between day
/// numbers mean anything here.
pub fn dayNumber(iso: []const u8) error{BadDate}!i64 {
    return core.isoDayNumber(iso) orelse error.BadDate;
}

/// Calendar days from `first` to `last`, the `span_days` of `riskMetrics`.
pub fn daySpan(first: []const u8, last: []const u8) error{BadDate}!f64 {
    return @floatFromInt(try dayNumber(last) - try dayNumber(first));
}

// ── xirr, twr ───────────────────────────────────────────────────────────────

fn buildCashflows(
    a: std.mem.Allocator,
    dates: []const []const u8,
    flows: []const f64,
    values: []const f64,
    opening: Opening,
) XirrError!std.ArrayList(Cashflow) {
    if (dates.len != flows.len or dates.len != values.len) return error.LengthMismatch;
    if (dates.len == 0) return error.EmptyWindow;
    var cfs: std.ArrayList(Cashflow) = .empty;
    errdefer cfs.deinit(a);
    if (opening != .none) try cfs.append(a, .{ .t = try dayNumber(dates[0]), .cf = -values[0] });
    for (dates, flows, 0..) |date, fl, i| {
        const t = try dayNumber(date); // every date is checked, flow or not
        if (i == 0 and opening == .value_includes_flow) continue;
        // A NaN flow is kept: dropped, it would be a plausible rate without it.
        if (std.math.isNan(fl) or @abs(fl) > 1e-6) try cfs.append(a, .{ .t = t, .cf = -fl });
    }
    try cfs.append(a, .{ .t = try dayNumber(dates[dates.len - 1]), .cf = values[values.len - 1] });
    return cfs;
}

/// Dated-flow internal rate of return: 200-step bisection of NPV = 0 over
/// `[bracket_lo, bracket_hi]`, ACT/365.25. `flows[i]` is the external flow of row
/// i (positive = contribution), `values[last]` the terminal value. A flow of at
/// most 1e-6 in size counts as no flow. `opening` is required: see `Opening`.
/// `rate_tol`: see `default_rate_tol`; null stops on |NPV| < 1e-2 alone.
pub fn xirr(
    a: std.mem.Allocator,
    dates: []const []const u8,
    flows: []const f64,
    values: []const f64,
    opening: Opening,
    rate_tol: ?f64,
) XirrError!f64 {
    var cfs = try buildCashflows(a, dates, flows, values, opening);
    defer cfs.deinit(a);
    const base = cfs.items[0].t;
    if (!core.bracketHasRoot(cfs.items, base, bracket_lo, bracket_hi)) return error.XirrNoRoot;
    return core.bisect(cfs.items, base, 1e-2, rate_tol);
}

pub const PreciseOpts = struct {
    /// |NPV| threshold of both phases.
    tol: f64 = 1e-8,
    /// Newton budget, clamped to `max_newton_iter_cap` and to the work cap; running
    /// out falls back to bisection and is not an error.
    max_newton_iter: usize = 50,
    initial_guess: f64 = 0.1,
    rate_tol: ?f64 = default_rate_tol,
};

/// `xirr` by Newton-Raphson, falling back to the same bisection when Newton
/// leaves the bracket, loses its derivative or runs out of steps.
pub fn xirrPrecise(
    a: std.mem.Allocator,
    dates: []const []const u8,
    flows: []const f64,
    values: []const f64,
    opening: Opening,
    opts: PreciseOpts,
) XirrError!f64 {
    var cfs = try buildCashflows(a, dates, flows, values, opening);
    defer cfs.deinit(a);
    const base = cfs.items[0].t;
    if (!core.bracketHasRoot(cfs.items, base, bracket_lo, bracket_hi)) return error.XirrNoRoot;
    newton: {
        var r: f64 = opts.initial_guess;
        const work_steps = @max(10, max_xirr_work / cfs.items.len);
        const budget = @min(opts.max_newton_iter, max_newton_iter_cap, work_steps);
        for (0..budget) |_| {
            const f = core.npv(cfs.items, base, r);
            // NPV alone only when no rate width is asked for: |NPV| is absolute, and on
            // tiny cashflows the first guess would pass it without any work done.
            if (opts.rate_tol == null and @abs(f) < opts.tol) return r;
            const df = core.dnpv(cfs.items, base, r);
            if (std.math.isNan(df) or @abs(df) < 1e-14) break :newton;
            const r_new = r - f / df;
            if (std.math.isNan(r_new) or r_new <= bracket_lo or r_new >= bracket_hi) break :newton;
            if (opts.rate_tol) |rt| {
                if (@abs(r_new - r) < rt) return r_new;
            }
            r = r_new;
        }
    }
    return core.bisect(cfs.items, base, opts.tol, opts.rate_tol);
}

/// One return of `twrDaily`: `row` is the index into the input series.
pub const Twr = struct { row: usize, r: f64 };

/// Daily time-weighted return, Modified Dietz with the average capital supplied
/// by the caller: r = (value - previous value - flow) / base. A row with base at
/// most 1e-6 gives no return. Leading rows with value below `min_value` are
/// skipped, and the first row at or above it only seeds the previous value.
pub fn twrDaily(a: std.mem.Allocator, values: []const f64, flows: []const f64, base: []const f64, min_value: f64) Error![]Twr {
    if (values.len != flows.len or values.len != base.len) return error.LengthMismatch;
    var out: std.ArrayList(Twr) = .empty;
    errdefer out.deinit(a);
    var have_prev = false;
    var prev: f64 = 0;
    for (values, flows, base, 0..) |v, fl, pe, i| {
        if (!have_prev and v < min_value) continue;
        if (have_prev and pe > 1e-6) try out.append(a, .{ .row = i, .r = (v - prev - fl) / pe });
        prev = v;
        have_prev = true;
    }
    return out.toOwnedSlice(a);
}

// ── histogram ───────────────────────────────────────────────────────────────

pub const Bin = struct { lo: f64, hi: f64, count: u64 };

/// Equal-width histogram of the finite values (NaN and infinities are left out).
/// A range of zero width gets span 1. `bins` 0 means 1; above `max_histogram_bins`
/// `error.TooLarge`. No finite value at all: no bins.
pub fn histogram(a: std.mem.Allocator, xs: []const f64, bins_in: usize) Error![]Bin {
    if (bins_in > max_histogram_bins) return error.TooLarge;
    var lo: f64 = std.math.inf(f64);
    var hi: f64 = -std.math.inf(f64);
    for (xs) |v| {
        if (!std.math.isFinite(v)) continue;
        lo = @min(lo, v);
        hi = @max(hi, v);
    }
    if (lo > hi) return a.alloc(Bin, 0);
    const bins = @max(bins_in, 1);
    const nb: f64 = @floatFromInt(bins);
    const span = if (hi > lo) hi - lo else 1;
    // Near the f64 limit `hi - lo` or an edge overflows; such a range is measured
    // in halves, and its edges are convex combinations of `lo` and `hi`.
    const wide = !std.math.isFinite(span * nb);
    const out = try a.alloc(Bin, bins);
    for (out, 0..) |*b, i| {
        const fi: f64 = @floatFromInt(i);
        b.* = .{ .lo = core.histEdge(lo, hi, span, wide, fi, bins), .hi = core.histEdge(lo, hi, span, wide, fi + 1, bins), .count = 0 };
    }
    for (xs) |v| {
        if (!std.math.isFinite(v)) continue;
        const t = if (wide) (v / 2 - lo / 2) / (hi / 2 - lo / 2) else (v - lo) / span;
        const k: i64 = @intFromFloat(@floor(t * nb));
        out[@intCast(std.math.clamp(k, 0, @as(i64, @intCast(bins - 1))))].count += 1;
    }
    return out;
}

// ── risk ────────────────────────────────────────────────────────────────────

/// Annualised sample standard deviation, std(ddof 1) * sqrt(ppy) (empyrical
/// `annual_volatility`, quantstats `volatility`). Fewer than two periods: 0. NaN
/// on non-finite input or a `ppy` that is not positive finite.
pub fn volatility(xs: []const f64, ppy: f64) f64 {
    if (!(ppy > 0) or !std.math.isFinite(ppy)) return std.math.nan(f64);
    const m = moments(xs);
    if (!m.finite) return std.math.nan(f64);
    return m.sd * @sqrt(ppy);
}

/// Annualised downside deviation against `mar`, a minimum acceptable return per
/// period: sqrt(Σ min(x - mar, 0)² / n) * sqrt(ppy), over ALL n periods (empyrical
/// `downside_risk`). Empty: 0. NaN on non-finite input or a bad `ppy`.
pub fn downsideDeviation(xs: []const f64, mar: f64, ppy: f64) f64 {
    if (!(ppy > 0) or !std.math.isFinite(ppy) or !std.math.isFinite(mar) or !finiteAll(xs)) return std.math.nan(f64);
    if (xs.len == 0) return 0;
    var s: f64 = 0;
    for (xs) |x| {
        const m = @min(x - mar, 0.0);
        s += m * m;
    }
    return @sqrt(s / @as(f64, @floatFromInt(xs.len))) * @sqrt(ppy);
}

/// Historical VaR, a loss as a positive number: -quantile(xs, 1 - confidence),
/// linear interpolation. Empty: 0. NaN on non-finite input or a confidence outside
/// [0, 1].
pub fn varHistoric(a: std.mem.Allocator, xs: []const f64, confidence: f64) Error!f64 {
    if (!(confidence >= 0 and confidence <= 1) or !finiteAll(xs)) return std.math.nan(f64);
    if (xs.len == 0) return 0;
    const s = try a.dupe(f64, xs);
    defer a.free(s);
    return -quantileSelect(s, 1 - confidence);
}

/// Historical CVaR: the mean loss of the periods at or below the VaR quantile, a
/// positive number when they lose. Same conventions as `varHistoric`.
pub fn cvarHistoric(a: std.mem.Allocator, xs: []const f64, confidence: f64) Error!f64 {
    const q = -(try varHistoric(a, xs, confidence));
    if (std.math.isNan(q)) return q;
    var s: f64 = 0;
    var n: usize = 0;
    for (xs) |x| if (x <= q) {
        s += x;
        n += 1;
    };
    return if (n > 0) -(s / @as(f64, @floatFromInt(n))) else 0;
}

/// Ulcer index as a fraction: sqrt(Σ dd² / n), dd the drawdown of the compounded
/// level from its running peak, the peak starting at 1. `RiskRow.ulcer` is the same
/// number in percent. Empty: 0. NaN if not compoundable.
pub fn ulcerIndex(xs: []const f64) f64 {
    if (!compoundable(xs)) return std.math.nan(f64);
    if (xs.len == 0) return 0;
    var level: f64 = 1;
    var peak: f64 = 1;
    var s: f64 = 0;
    for (xs) |x| {
        level *= 1 + x;
        peak = @max(peak, level);
        const dd = (level - peak) / peak;
        s += dd * dd;
        if (peak > 0x1p500) {
            level *= 0x1p-500;
            peak *= 0x1p-500;
        }
    }
    return @sqrt(s / @as(f64, @floatFromInt(xs.len)));
}

pub const RiskOpts = struct {
    periods_per_year: f64 = 252,
    /// Annual risk-free rate, subtracted from the annualised return in Sharpe and
    /// Sortino. Calmar has no risk-free term.
    rf: f64 = 0,
    /// Annualised return for the ratios, used when `span_days` is null.
    ann_return: f64 = 0,
    /// Calendar days the series covers (`daySpan`). When set, and there are at
    /// least two returns, the annualised return is level^(365.25 / days) - 1.
    span_days: ?f64 = null,
};

pub const RiskRow = struct {
    ann_vol: f64,
    downside: f64,
    var95: f64,
    cvar95: f64,
    mdd: f64,
    /// In percent, unlike `ulcerIndex`.
    ulcer: f64,
    sharpe: f64,
    sortino: f64,
    calmar: f64,

    const nan_row: RiskRow = blk: {
        const n = std.math.nan(f64);
        break :blk .{ .ann_vol = n, .downside = n, .var95 = n, .cvar95 = n, .mdd = n, .ulcer = n, .sharpe = n, .sortino = n, .calmar = n };
    };
};

/// Historical risk row. Sharpe, Sortino and Calmar here divide the annualised
/// return in `opts`, not a mean: the module's older convention, which no library
/// computes (`sharpeRatio` is the mean/std one). `downside` is against 0. Every
/// field is NaN if the series is not compoundable or `periods_per_year` is not
/// positive finite.
pub fn riskMetrics(a: std.mem.Allocator, rets: []const f64, opts: RiskOpts) Error!RiskRow {
    if (!compoundable(rets) or !(opts.periods_per_year > 0) or !std.math.isFinite(opts.periods_per_year)) return RiskRow.nan_row;
    const sq = @sqrt(opts.periods_per_year);
    const ann_vol = stdSample(rets) * sq;
    var dsum: f64 = 0;
    for (rets) |v| {
        const m = @min(v, 0.0);
        dsum += m * m;
    }
    const downside = if (rets.len > 0) @sqrt(dsum / @as(f64, @floatFromInt(rets.len))) * sq else 0;

    const scratch = try a.dupe(f64, rets);
    defer a.free(scratch);
    const q05 = quantileSelect(scratch, 0.05);
    var cv_sum: f64 = 0;
    var cv_n: usize = 0;
    for (rets) |v| if (v <= q05) {
        cv_sum += v;
        cv_n += 1;
    };
    const cvar95 = if (cv_n > 0) -(cv_sum / @as(f64, @floatFromInt(cv_n))) else 0;

    var level: f64 = 1;
    var peak: f64 = 1;
    var min_dd: f64 = 0;
    var ulcer_sq: f64 = 0;
    for (rets) |r| {
        level *= 1 + r;
        if (level > peak) peak = level;
        const dd = (level - peak) / peak * 100.0;
        min_dd = @min(min_dd, dd);
        ulcer_sq += dd * dd;
        if (peak > 0x1p500) {
            level *= 0x1p-500;
            peak *= 0x1p-500;
        }
    }
    const mdd = min_dd / 100.0;
    const ulcer = if (rets.len > 0) @sqrt(ulcer_sq / @as(f64, @floatFromInt(rets.len))) else 0;

    var ann = opts.ann_return;
    if (opts.span_days) |days| {
        if (rets.len >= 2) {
            ann = if (std.math.isNan(days)) days else core.levelPow(rets, 365.25 / @max(1.0, days)) - 1;
        }
    }
    const excess = ann - opts.rf;
    return .{
        .ann_vol = ann_vol,
        .downside = downside,
        .var95 = -q05,
        .cvar95 = cvar95,
        .mdd = mdd,
        .ulcer = ulcer,
        .sharpe = if (ann_vol != 0) excess / ann_vol else 0,
        .sortino = if (downside != 0) excess / downside else 0,
        .calmar = if (mdd != 0) ann / @abs(mdd) else 0,
    };
}

pub const ParamRow = struct {
    mean: f64,
    std: f64,
    skew: f64,
    kurt: f64,
    var_gaussian: f64,
    cvar_gaussian: f64,
    var_cf: f64,
    cvar_cf: f64,
};

/// Parametric risk at `confidence`: sample mean and std, population skew and
/// excess kurtosis, Gaussian and Cornish-Fisher VaR and CVaR.
pub fn parametricRisk(xs: []const f64, confidence: f64) ParamRow {
    const m = mean(xs);
    const sd = stdSample(xs);
    const sk = skewness(xs);
    const ek = excessKurtosis(xs);
    return .{
        .mean = m,
        .std = sd,
        .skew = sk,
        .kurt = ek,
        .var_gaussian = gaussianVaR(m, sd, confidence),
        .cvar_gaussian = gaussianCVaR(m, sd, confidence),
        .var_cf = cornishFisherVaR(m, sd, sk, ek, confidence),
        .cvar_cf = cornishFisherCVaR(m, sd, sk, ek, confidence),
    };
}

// ── against a benchmark ─────────────────────────────────────────────────────

/// cov(p, b) / var(b). No variance in `b`: 0. Different lengths or non-finite input: NaN.
pub fn beta(p: []const f64, b: []const f64) f64 {
    if (p.len != b.len or !finiteAll(p) or !finiteAll(b)) return std.math.nan(f64);
    return betaOf(p, b);
}

/// Squared correlation of `p` and `b`. No variance on either side: 0. Different
/// lengths or non-finite input: NaN.
pub fn rSquared(p: []const f64, b: []const f64) f64 {
    if (p.len != b.len or !finiteAll(p) or !finiteAll(b)) return std.math.nan(f64);
    const mp = mean(p);
    const mb = mean(b);
    var cov: f64 = 0;
    var varp: f64 = 0;
    var varb: f64 = 0;
    for (p, b) |x, y| {
        const dp = x - mp;
        const db = y - mb;
        cov += dp * db;
        varp += dp * dp;
        varb += db * db;
    }
    return if (varp * varb > 0) (cov * cov) / (varp * varb) else 0;
}

pub const BetaRow = struct { beta: f64, alpha: f64, r2: f64 };

/// beta, R² and alpha = port_ann - beta * bench_ann, from annualised returns the
/// caller computed. Different lengths or non-finite input: every field NaN.
pub fn betaAlpha(p: []const f64, b: []const f64, port_ann: f64, bench_ann: f64) BetaRow {
    const bt = beta(p, b);
    return .{ .beta = bt, .alpha = port_ann - bt * bench_ann, .r2 = rSquared(p, b) };
}

pub const TrackRow = struct { tracking_error: f64, information_ratio: f64 };

/// Annualised tracking error of the active return p - b, and the information ratio
/// mean(active) * ppy / tracking error (0 when the tracking error is 0). Different
/// lengths, a non-finite value or a `ppy` not positive finite: every field NaN.
pub fn trackingRisk(p: []const f64, b: []const f64, ppy: f64) TrackRow {
    if (p.len != b.len or !finiteAll(p) or !finiteAll(b) or !(ppy > 0) or !std.math.isFinite(ppy)) return .{ .tracking_error = std.math.nan(f64), .information_ratio = std.math.nan(f64) };
    var sum: f64 = 0;
    for (p, b) |x, y| sum += x - y;
    const m = if (p.len > 0) sum / @as(f64, @floatFromInt(p.len)) else 0;
    var ss: f64 = 0;
    for (p, b) |x, y| {
        const d = (x - y) - m;
        ss += d * d;
    }
    const sd = if (p.len >= 2) @sqrt(ss / @as(f64, @floatFromInt(p.len - 1))) else 0;
    const te = sd * @sqrt(ppy);
    return .{ .tracking_error = te, .information_ratio = if (te != 0) m * ppy / te else 0 };
}

pub const BenchRow = struct { treynor: f64, up_capture: f64, down_capture: f64 };

/// Treynor = (port_ann - rf) / beta (0 when beta is 0), and up and down capture:
/// CAGR of the portfolio over the periods the benchmark rose or fell, over the
/// benchmark's CAGR on those periods (empyrical `up_capture`, `down_capture`). Every
/// field NaN if a series is not compoundable or `ppy` is not positive finite.
pub fn benchmarkStats(a: std.mem.Allocator, p: []const f64, b: []const f64, port_ann: f64, rf: f64, ppy: f64) Error!BenchRow {
    if (p.len != b.len) return error.LengthMismatch;
    if (!compoundable(p) or !compoundable(b) or !(ppy > 0) or !std.math.isFinite(ppy)) {
        const n = std.math.nan(f64);
        return .{ .treynor = n, .up_capture = n, .down_capture = n };
    }
    const bt = betaOf(p, b);
    return .{
        .treynor = if (bt != 0) (port_ann - rf) / bt else 0,
        .up_capture = try core.capture(a, p, b, ppy, true),
        .down_capture = try core.capture(a, p, b, ppy, false),
    };
}

/// mean(p - b) / std(p - b), sample std, NOT annualised (quantstats
/// `information_ratio`, ffn `calc_information_ratio`). `trackingRisk` has the
/// annualised form. Fewer than two periods or zero spread: 0. Different lengths or
/// non-finite input: NaN.
pub fn informationRatio(p: []const f64, b: []const f64) f64 {
    if (p.len != b.len or !finiteAll(p) or !finiteAll(b)) return std.math.nan(f64);
    if (p.len < 2) return 0;
    var sum: f64 = 0;
    var scale: f64 = 0;
    for (p, b) |x, y| {
        sum += x - y;
        scale = @max(scale, @abs(x - y));
    }
    const m = sum / @as(f64, @floatFromInt(p.len));
    var ss: f64 = 0;
    for (p, b) |x, y| ss += (x - y - m) * (x - y - m);
    const sd = @sqrt(ss / @as(f64, @floatFromInt(p.len - 1)));
    if (sd <= 8 * std.math.floatEps(f64) * scale) return 0;
    return m / sd;
}

/// (total return of `p` - rf) / beta (quantstats `treynor_ratio`: the compounded
/// return of the whole sample, with `rf` taken off as it stands, not annualised;
/// `benchmarkStats` takes an annualised numerator instead). Zero beta: 0. Different
/// lengths, a non-compoundable `p` or a non-finite `b` or `rf`: NaN.
pub fn treynorRatio(p: []const f64, b: []const f64, rf: f64) f64 {
    if (p.len != b.len or !finiteAll(b) or !std.math.isFinite(rf)) return std.math.nan(f64);
    const total = totalReturn(p);
    if (std.math.isNan(total)) return total;
    const bt = betaOf(p, b);
    return if (bt != 0) (total - rf) / bt else 0;
}

pub const Greeks = struct { beta: f64, alpha: f64 };

/// beta = cov(p, b) / var(b) and alpha = (mean(p) - beta * mean(b)) * ppy, annualised
/// arithmetically (quantstats `greeks`, the static form of `rollingBetaAlpha`).
/// Different lengths or non-finite input: every field NaN.
pub fn greeks(p: []const f64, b: []const f64, ppy: f64) Greeks {
    if (p.len != b.len or !finiteAll(p) or !finiteAll(b)) return .{ .beta = std.math.nan(f64), .alpha = std.math.nan(f64) };
    const bt = betaOf(p, b);
    return .{ .beta = bt, .alpha = (mean(p) - bt * mean(b)) * ppy };
}

pub const BrinsonRow = struct { allocation: f64, selection: f64, interaction: f64, total: f64 };
pub const BrinsonResult = struct {
    /// One per segment, in input order. Free with `a.free(rows)`.
    rows: []BrinsonRow,
    total: BrinsonRow,
};

/// Brinson-Fachler attribution over aligned per-segment slices: portfolio weight,
/// benchmark weight, portfolio return, benchmark return. NaN is "no return". The
/// three effects sum to the active return when each weight column sums to 1. A
/// segment not held is pure allocation; one outside the benchmark with no return of
/// its own is measured against the benchmark total. A return missing where the
/// position exists gives NaN in that row and in the total.
pub fn brinsonAttribution(a: std.mem.Allocator, wp: []const f64, wb: []const f64, rp: []const f64, rb: []const f64) Error!BrinsonResult {
    if (wp.len != wb.len or wp.len != rp.len or wp.len != rb.len) return error.LengthMismatch;
    var rb_total: f64 = 0;
    for (wb, rb) |w, r| {
        if (w != 0) rb_total += w * r;
    }
    const rows = try a.alloc(BrinsonRow, wp.len);
    var t: BrinsonRow = .{ .allocation = 0, .selection = 0, .interaction = 0, .total = 0 };
    for (rows, wp, wb, rp, rb) |*row, wpi, wbi, rpi, rb_stated| {
        const rbi = if (wbi == 0 and std.math.isNan(rb_stated)) rb_total else rb_stated;
        const rpx = if (wpi == 0) rbi else rpi;
        const al = (wpi - wbi) * (rbi - rb_total);
        const se = wbi * (rpx - rbi);
        const it = (wpi - wbi) * (rpx - rbi);
        t.allocation += al;
        t.selection += se;
        t.interaction += it;
        row.* = .{ .allocation = al, .selection = se, .interaction = it, .total = al + se + it };
    }
    t.total = t.allocation + t.selection + t.interaction;
    return .{ .rows = rows, .total = t };
}

// ── series ──────────────────────────────────────────────────────────────────

/// The compounded return curve into `out`: Π_{j<=i}(1 + x_j) - 1 (empyrical
/// `cum_returns`). From the first non-compoundable value on: NaN.
pub fn cumulativeReturnsInto(out: []f64, xs: []const f64) error{LengthMismatch}!void {
    if (out.len != xs.len) return error.LengthMismatch;
    var level: f64 = 1;
    for (out, xs) |*o, x| {
        level = if (std.math.isFinite(x) and x >= -1) level * (1 + x) else std.math.nan(f64);
        o.* = level - 1;
    }
}

/// `cumulativeReturnsInto` on a new slice.
pub fn cumulativeReturns(a: std.mem.Allocator, xs: []const f64) Error![]f64 {
    const out = try a.alloc(f64, xs.len);
    cumulativeReturnsInto(out, xs) catch unreachable; // same length by construction
    return out;
}

/// The drawdown curve into `out`: level / running peak - 1, a fraction <= 0, level
/// and peak starting at 1 (empyrical `drawdown_series`). `maxDrawdown` is its
/// minimum. From the first non-compoundable value on: NaN.
pub fn drawdownSeriesInto(out: []f64, xs: []const f64) error{LengthMismatch}!void {
    if (out.len != xs.len) return error.LengthMismatch;
    var level: f64 = 1;
    var peak: f64 = 1;
    for (out, xs) |*o, x| {
        level = if (std.math.isFinite(x) and x >= -1) level * (1 + x) else std.math.nan(f64);
        peak = @max(peak, level);
        o.* = if (std.math.isNan(level)) level else level / peak - 1;
        if (peak > 0x1p500) {
            level *= 0x1p-500;
            peak *= 0x1p-500;
        }
    }
}

/// `drawdownSeriesInto` on a new slice.
pub fn drawdownSeries(a: std.mem.Allocator, xs: []const f64) Error![]f64 {
    const out = try a.alloc(f64, xs.len);
    drawdownSeriesInto(out, xs) catch unreachable; // same length by construction
    return out;
}

pub const Episode = struct {
    /// Indices into the input series.
    peak_i: usize,
    trough_i: usize,
    /// Null while still under water at the end of the series.
    recovery_i: ?usize,
    /// A fraction <= 0.
    depth: f64,
    fall_days: i64,
    recover_days: ?i64,
};

/// Drawdown episodes of a LEVEL series (prices, not returns), the deepest `top_n`
/// first. A level at or above the running peak ends an episode. A NaN, infinite or
/// negative level is a missing price and is skipped, which leaves the same episodes
/// as ffn's forward fill; so are zero levels before the first positive one, since a
/// fall from 0 has no depth. `error.DatesNotSorted` if the dates go backwards.
pub fn drawdownEpisodes(a: std.mem.Allocator, dates: []const []const u8, levels: []const f64, top_n: usize) Error![]Episode {
    if (dates.len != levels.len) return error.LengthMismatch;
    const days = try a.alloc(i64, dates.len);
    defer a.free(days);
    for (days, dates, 0..) |*d, s, i| {
        d.* = try dayNumber(s);
        if (i > 0 and d.* < days[i - 1]) return error.DatesNotSorted;
    }

    var eps: std.ArrayList(Episode) = .empty;
    defer eps.deinit(a);
    var peak: f64 = 0;
    var peak_i: usize = 0;
    var trough: f64 = 0;
    var trough_i: usize = 0;
    var under = false;
    for (levels, 0..) |v, i| {
        if (!std.math.isFinite(v) or v < 0 or (peak == 0 and v == 0)) continue;
        if (v >= peak) {
            if (under) {
                try eps.append(a, .{ .peak_i = peak_i, .trough_i = trough_i, .recovery_i = i, .depth = (trough - peak) / peak, .fall_days = days[trough_i] - days[peak_i], .recover_days = days[i] - days[trough_i] });
                under = false;
            }
            peak = v;
            peak_i = i;
            trough = v;
            trough_i = i;
        } else {
            if (!under) {
                under = true;
                trough = v;
                trough_i = i;
            }
            if (v < trough) {
                trough = v;
                trough_i = i;
            }
        }
    }
    if (under) try eps.append(a, .{ .peak_i = peak_i, .trough_i = trough_i, .recovery_i = null, .depth = (trough - peak) / peak, .fall_days = days[trough_i] - days[peak_i], .recover_days = null });
    std.mem.sort(Episode, eps.items, {}, struct {
        fn lt(_: void, x: Episode, y: Episode) bool {
            return f64lt({}, x.depth, y.depth);
        }
    }.lt);
    return a.dupe(Episode, eps.items[0..@min(top_n, eps.items.len)]);
}

// ── rolling ─────────────────────────────────────────────────────────────────

fn rollingCount(n: usize, window: usize) error{TooLarge}!usize {
    if (window == 0 or n < window) return 0;
    const count = n - window + 1;
    const work = std.math.mul(usize, count, window) catch return error.TooLarge;
    if (work > max_rolling_work) return error.TooLarge;
    return count;
}

/// `reducer` over each full trailing window: n - window + 1 values, none if `n <
/// window` or `window` is 0. O(rows * window), capped by `max_rolling_work`.
pub fn rollingApply(a: std.mem.Allocator, xs: []const f64, window: usize, comptime reducer: fn ([]const f64) f64) Error![]f64 {
    const out = try a.alloc(f64, try rollingCount(xs.len, window));
    for (out, 0..) |*o, k| o.* = reducer(xs[k .. k + window]);
    return out;
}

/// `rollingApply` for a reducer that takes parameters, such as a risk-free rate.
pub fn rollingApplyCtx(a: std.mem.Allocator, xs: []const f64, window: usize, ctx: anytype, comptime reducer: fn (@TypeOf(ctx), []const f64) f64) Error![]f64 {
    const out = try a.alloc(f64, try rollingCount(xs.len, window));
    for (out, 0..) |*o, k| o.* = reducer(ctx, xs[k .. k + window]);
    return out;
}

pub fn rollingMean(a: std.mem.Allocator, xs: []const f64, window: usize) Error![]f64 {
    return rollingApply(a, xs, window, rollingMeanReducer);
}

/// Sample std per window, not annualised.
pub fn rollingVolatility(a: std.mem.Allocator, xs: []const f64, window: usize) Error![]f64 {
    return rollingApply(a, xs, window, rollingVolReducer);
}

/// mean / std per window, rf 0, not annualised.
pub fn rollingSharpe(a: std.mem.Allocator, xs: []const f64, window: usize) Error![]f64 {
    return rollingApply(a, xs, window, rollingSharpeReducer);
}

pub const BetaAlphaPoint = struct { beta: f64, alpha: f64 };

/// {beta, alpha} over each full trailing window, alpha = (mean(p) - beta * mean(b))
/// * ppy (Jensen's alpha with rf 0, annualised arithmetically). A window with a
/// non-finite value: NaN for that window.
pub fn rollingBetaAlpha(a: std.mem.Allocator, p: []const f64, b: []const f64, window: usize, ppy: f64) Error![]BetaAlphaPoint {
    if (p.len != b.len) return error.LengthMismatch;
    const out = try a.alloc(BetaAlphaPoint, try rollingCount(p.len, window));
    for (out, 0..) |*o, k| {
        const wp = p[k .. k + window];
        const wb = b[k .. k + window];
        const bt = beta(wp, wb);
        o.* = .{ .beta = bt, .alpha = (mean(wp) - bt * mean(wb)) * ppy };
    }
    return out;
}

// ── trade and period rows ───────────────────────────────────────────────────

pub const TradeRow = struct { win_rate: f64, payoff: f64, profit_factor: f64, kelly: f64, tail_ratio: f64 };

/// {win rate, payoff, profit factor, Kelly, tail ratio}. Every field NaN on
/// non-finite input.
pub fn tradeStats(a: std.mem.Allocator, xs: []const f64) Error!TradeRow {
    if (!finiteAll(xs)) {
        const n = std.math.nan(f64);
        return .{ .win_rate = n, .payoff = n, .profit_factor = n, .kelly = n, .tail_ratio = n };
    }
    return .{
        .win_rate = winRate(xs),
        .payoff = payoffRatio(xs),
        .profit_factor = profitFactor(xs),
        .kelly = kellyCriterion(xs),
        .tail_ratio = try tailRatio(a, xs),
    };
}

pub const PeriodRow = struct {
    total_return: f64,
    cagr: f64,
    geometric_mean: f64,
    sharpe: f64,
    sortino: f64,
    calmar: f64,
    gain_to_pain: f64,
    recovery_factor: f64,
    best: f64,
    worst: f64,
    avg_win: f64,
    avg_loss: f64,
    max_consec_wins: usize,
    max_consec_losses: usize,
    stability: f64,
};

/// The period-based statistics a quantstats or empyrical user expects, each by the
/// convention on its own function. `rf` is annual.
pub fn periodStats(xs: []const f64, ppy: f64, rf: f64) PeriodRow {
    return .{
        .total_return = totalReturn(xs),
        .cagr = cagrPeriods(xs, ppy),
        .geometric_mean = geometricMean(xs),
        .sharpe = sharpeRatio(xs, rf, ppy),
        .sortino = sortinoRatio(xs, rf, ppy),
        .calmar = calmarRatio(xs, ppy),
        .gain_to_pain = gainToPain(xs),
        .recovery_factor = recoveryFactor(xs),
        .best = bestReturn(xs),
        .worst = worstReturn(xs),
        .avg_win = avgWin(xs),
        .avg_loss = avgLoss(xs),
        .max_consec_wins = maxConsecutiveWins(xs),
        .max_consec_losses = maxConsecutiveLosses(xs),
        .stability = stability(xs),
    };
}

// ── correlation ─────────────────────────────────────────────────────────────

fn pearsonMin(x: []const f64, y: []const f64, min_overlap: usize) f64 {
    var n: usize = 0;
    var sx: f64 = 0;
    var sy: f64 = 0;
    for (x, y) |u, v| {
        if (std.math.isNan(u) or std.math.isNan(v)) continue;
        n += 1;
        sx += u;
        sy += v;
    }
    if (n == 0 or n < min_overlap) return std.math.nan(f64);
    const nf: f64 = @floatFromInt(n);
    const mx = sx / nf;
    const my = sy / nf;
    var cov: f64 = 0;
    var vx: f64 = 0;
    var vy: f64 = 0;
    for (x, y) |u, v| {
        if (std.math.isNan(u) or std.math.isNan(v)) continue;
        cov += (u - mx) * (v - my);
        vx += (u - mx) * (u - mx);
        vy += (v - my) * (v - my);
    }
    return if (vx * vy > 0) cov / @sqrt(vx * vy) else std.math.nan(f64);
}

/// Pearson correlation over the positions where both are present (NaN = missing).
/// No shared position or no variance: NaN. Different lengths: NaN.
pub fn pearson(x: []const f64, y: []const f64) f64 {
    if (x.len != y.len) return std.math.nan(f64);
    return pearsonMin(x, y, 1);
}

/// Pairwise correlation of k aligned series as a k*k matrix, row-major (pandas
/// `DataFrame.corr(min_periods)`; NaN = missing). The diagonal is 1. A pair with
/// fewer than `min_overlap` shared positions or no variance is NaN. Above
/// `max_corr_keys` series or `max_corr_work` pair visits: `error.TooLarge`.
pub fn correlationMatrix(a: std.mem.Allocator, series: []const []const f64, min_overlap: usize) Error![]f64 {
    const k = series.len;
    if (k > max_corr_keys) return error.TooLarge;
    const n = if (k > 0) series[0].len else 0;
    for (series) |s| if (s.len != n) return error.LengthMismatch;
    if (k > 1) {
        const pairs = k * (k - 1) / 2;
        const work = std.math.mul(usize, pairs, n) catch return error.TooLarge;
        if (work > max_corr_work) return error.TooLarge;
    }
    const out = try a.alloc(f64, k * k);
    for (0..k) |i| {
        out[i * k + i] = 1;
        for (i + 1..k) |j| {
            const v = pearsonMin(series[i], series[j], min_overlap);
            out[i * k + j] = v;
            out[j * k + i] = v;
        }
    }
    return out;
}

// ── Monte Carlo projection ──────────────────────────────────────────────────

pub const MonteCarloSpec = struct {
    start: f64,
    mu_ann: f64,
    vol_ann: f64,
    monthly: f64,
    years: f64,
    paths: usize = 2000,
    seed: u64 = 0x9E3779B97F4A7C15,
};

pub const McRow = struct { month: usize, p10: f64, p50: f64, p90: f64 };

/// Net-worth projection with a fixed-seed PRNG: monthly v = max(0, v * (1 + mu_m +
/// sig_m * Z) + monthly), Box-Muller Z. A different question from quantstats'
/// resampling of returns. `years` below one month or NaN: only month 0. A `start`,
/// `mu_ann`, `vol_ann` or `monthly` that is not finite, `mu_ann` at or below -1 or a
/// negative `vol_ann`: every percentile NaN, never a path floored at 0. Above
/// `max_monte_carlo_months` or `max_monte_carlo_cells`: `error.TooLarge`.
pub fn monteCarlo(a: std.mem.Allocator, spec: MonteCarloSpec) Error![]McRow {
    const months_f = @round(spec.years * 12);
    const months_cap: f64 = @floatFromInt(std.math.maxInt(u32));
    const months: usize = if (!(months_f >= 1))
        0
    else if (months_f >= months_cap)
        std.math.maxInt(u32)
    else
        @intFromFloat(months_f);
    if (months > max_monte_carlo_months) return error.TooLarge;
    const mu_m = std.math.pow(f64, 1 + spec.mu_ann, 1.0 / 12.0) - 1;
    const sig_m = spec.vol_ann / @sqrt(12.0);
    const n = @max(spec.paths, 1);
    const cells = std.math.mul(usize, n, months + 1) catch return error.TooLarge;
    if (cells > max_monte_carlo_cells) return error.TooLarge;
    const defined = std.math.isFinite(spec.start) and std.math.isFinite(spec.mu_ann) and
        std.math.isFinite(spec.vol_ann) and std.math.isFinite(spec.monthly) and
        spec.mu_ann > -1 and spec.vol_ann >= 0;
    if (!defined) {
        const nan_rows = try a.alloc(McRow, months + 1);
        const n_ = std.math.nan(f64);
        for (nan_rows, 0..) |*row, t| row.* = .{ .month = t, .p10 = n_, .p50 = n_, .p90 = n_ };
        return nan_rows;
    }

    // One block, month t at [t * n ..], so a failure has only one thing to release.
    const grid = try a.alloc(f64, cells);
    defer a.free(grid);
    var prng = std.Random.DefaultPrng.init(spec.seed);
    const rnd = prng.random();
    for (0..n) |i| {
        var v = spec.start;
        grid[i] = v;
        for (0..months) |t| {
            v = @max(0, v * (1 + mu_m + sig_m * core.gauss(rnd)) + spec.monthly);
            grid[(t + 1) * n + i] = v;
        }
    }
    const out = try a.alloc(McRow, months + 1);
    for (out, 0..) |*row, t| {
        const col = grid[t * n ..][0..n];
        std.mem.sort(f64, col, {}, f64lt);
        row.* = .{ .month = t, .p10 = quantileSorted(col, 0.1), .p50 = quantileSorted(col, 0.5), .p90 = quantileSorted(col, 0.9) };
    }
    return out;
}

// ── the rest of the surface, by file ────────────────────────────────────────

const ratios = @import("ratios.zig");
pub const max_rank_work = ratios.max_rank_work;
pub const avgReturn = ratios.avgReturn;
pub const riskReturnRatio = ratios.riskReturnRatio;
pub const ulcerPerformanceIndex = ratios.ulcerPerformanceIndex;
pub const serenityIndex = ratios.serenityIndex;
pub const commonSenseRatio = ratios.commonSenseRatio;
pub const cpcIndex = ratios.cpcIndex;
pub const profitRatio = ratios.profitRatio;
pub const winLossRatio = ratios.winLossRatio;
pub const exposure = ratios.exposure;
pub const rar = ratios.rar;
pub const outliers = ratios.outliers;
pub const removeOutliers = ratios.removeOutliers;
pub const outlierWinRatio = ratios.outlierWinRatio;
pub const outlierLossRatio = ratios.outlierLossRatio;
pub const autocorrPenalty = ratios.autocorrPenalty;
pub const smartSharpe = ratios.smartSharpe;
pub const smartSortino = ratios.smartSortino;
pub const sortinoSqrt2 = ratios.sortinoSqrt2;
pub const smartSortinoSqrt2 = ratios.smartSortinoSqrt2;
pub const adjustedSortino = ratios.adjustedSortino;
pub const skewSample = ratios.skewSample;
pub const kurtosisSample = ratios.kurtosisSample;
pub const normalCdf = ratios.normalCdf;
pub const RatioBase = ratios.RatioBase;
pub const probabilisticRatio = ratios.probabilisticRatio;
pub const probabilisticSharpeRatio = ratios.probabilisticSharpeRatio;
pub const probabilisticSortinoRatio = ratios.probabilisticSortinoRatio;
pub const probabilisticAdjustedSortinoRatio = ratios.probabilisticAdjustedSortinoRatio;
pub const expectedMaxSharpe = ratios.expectedMaxSharpe;
pub const deflatedSharpeRatio = ratios.deflatedSharpeRatio;
pub const probMom = ratios.probMom;
pub const pctRank = ratios.pctRank;
pub const riskOfRuin = ratios.riskOfRuin;

const calendar = @import("calendar.zig");
pub const max_resample_cells = calendar.max_resample_cells;
pub const max_resample_sims = calendar.max_resample_sims;
pub const max_hurst_len = calendar.max_hurst_len;
pub const max_gpd_work = calendar.max_gpd_work;
pub const Period = calendar.Period;
pub const PeriodReturn = calendar.PeriodReturn;
pub const aggregateReturns = calendar.aggregateReturns;
pub const monthlyReturns = calendar.monthlyReturns;
pub const yearlyReturns = calendar.yearlyReturns;
pub const mtdReturn = calendar.mtdReturn;
pub const ytdReturn = calendar.ytdReturn;
pub const winQuarter = calendar.winQuarter;
pub const bestPeriod = calendar.bestPeriod;
pub const worstPeriod = calendar.worstPeriod;
pub const avgUpMonth = calendar.avgUpMonth;
pub const avgDownMonth = calendar.avgDownMonth;
pub const expectedMonthlyReturn = calendar.expectedMonthlyReturn;
pub const expectedYearlyReturn = calendar.expectedYearlyReturn;
pub const gainToPainMonthly = calendar.gainToPainMonthly;
pub const toReturns = calendar.toReturns;
pub const toReturnsInto = calendar.toReturnsInto;
pub const toLogReturns = calendar.toLogReturns;
pub const toLogReturnsInto = calendar.toLogReturnsInto;
pub const toPriceIndex = calendar.toPriceIndex;
pub const toPriceIndexInto = calendar.toPriceIndexInto;
pub const rebase = calendar.rebase;
pub const rebaseInto = calendar.rebaseInto;
pub const deannualize = calendar.deannualize;
pub const toExcessReturns = calendar.toExcessReturns;
pub const toExcessReturnsInto = calendar.toExcessReturnsInto;
pub const winsorize = calendar.winsorize;
pub const rescale = calendar.rescale;
pub const rollingSortino = calendar.rollingSortino;
pub const rollingSharpeRf = calendar.rollingSharpeRf;
pub const rollingCagr = calendar.rollingCagr;
pub const rollingMaxDrawdown = calendar.rollingMaxDrawdown;
pub const rollingWinRate = calendar.rollingWinRate;
pub const rollUpCapture = calendar.rollUpCapture;
pub const rollDownCapture = calendar.rollDownCapture;
pub const Dist = calendar.Dist;
pub const McResult = calendar.McResult;
pub const montecarlo = calendar.montecarlo;
pub const montecarloCagr = calendar.montecarloCagr;
pub const montecarloDrawdown = calendar.montecarloDrawdown;
pub const montecarloSharpe = calendar.montecarloSharpe;
pub const AlphaBeta = calendar.AlphaBeta;
pub const alphaBeta = calendar.alphaBeta;
pub const jensenAlpha = calendar.jensenAlpha;
pub const upAlphaBeta = calendar.upAlphaBeta;
pub const downAlphaBeta = calendar.downAlphaBeta;
pub const excessSharpe = calendar.excessSharpe;
pub const Batting = calendar.Batting;
pub const battingAverage = calendar.battingAverage;
pub const betaFragilityHeuristic = calendar.betaFragilityHeuristic;
pub const GpdRisk = calendar.GpdRisk;
pub const gpdVarEs = calendar.gpdVarEs;
pub const gpdRiskEstimates = calendar.gpdRiskEstimates;
pub const conditionalDrawdownAtRisk = calendar.conditionalDrawdownAtRisk;
pub const lambdaFromSpan = calendar.lambdaFromSpan;
pub const ewmaVolatility = calendar.ewmaVolatility;
pub const hurstExponent = calendar.hurstExponent;
pub const evarGaussian = calendar.evarGaussian;

pub const capture = calendar.capture;
pub const upCapture = calendar.upCapture;
pub const downCapture = calendar.downCapture;
pub const upDownCapture = calendar.upDownCapture;
pub const rollUpDownCapture = calendar.rollUpDownCapture;
pub const rollAlphaBeta = calendar.rollAlphaBeta;
pub const rollingGreeks = calendar.rollingGreeks;
pub const yearFrac = calendar.yearFrac;
pub const resampleReturns = calendar.resampleReturns;

const overfit = @import("overfit.zig");
pub const max_combinations = overfit.max_combinations;
pub const max_work = overfit.max_work;
pub const max_cells = overfit.max_cells;
pub const sharpePerPeriod = overfit.sharpePerPeriod;
pub const OverfitDetail = overfit.Detail;
pub const probBacktestOverfitting = overfit.probBacktestOverfitting;
pub const probBacktestOverfittingDetail = overfit.probBacktestOverfittingDetail;

const factor = @import("factor.zig");
pub const max_output_cells = factor.max_output_cells;
pub const Shape = factor.Shape;
pub const Attribution = factor.Attribution;
pub const computeExposures = factor.computeExposures;
pub const perfAttrib = factor.perfAttrib;
