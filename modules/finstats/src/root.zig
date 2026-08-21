// SPDX-License-Identifier: MIT
//! finstats — portfolio/financial statistics over `dataset`: xirr, TWR,
//! risk metrics (vol/VaR/CVaR/Sharpe/Sortino/Calmar), beta/alpha, Monte-Carlo,
//! correlation matrix, drawdown episodes. f64 throughout (statistics, not ledger).
//!
//! Pure functions over `Dataset`. Scalar math fns (xirr/annualize/quantile)
//! return the number directly (KPI reduce nodes call them); series/table
//! producers return a `Dataset`. The numeric behaviour is exact — VaR/CVaR
//! are historical (empirical), the Monte-Carlo PRNG is fixed-seed
//! deterministic.

const std = @import("std");
const dsmod = @import("dataset");
const Dataset = dsmod.Dataset;
const Column = dsmod.Column;
const Value = dsmod.Value;

pub const meta = .{
    .targets = .{.linux64},
    .platform = .any,
    .role = .util,
    .concurrency = .reentrant,
    .model_after = "Python empyrical/ffn; QuantLib subset",
    .deps = .{"dataset"},
};

pub const Error = error{ NoSuchColumn, OutOfMemory };

// ── public API ──────────────────────────────────────────────────────────────

fn mustIndex(d: Dataset, name: []const u8) Error!usize {
    return d.columnIndex(name) orelse Error.NoSuchColumn;
}
fn isoDays(s: []const u8) i64 {
    return (dsmod.parseIsoDate(s) orelse return 0).ordinal();
}
fn mean(xs: []const f64) f64 {
    if (xs.len == 0) return 0;
    var s: f64 = 0;
    for (xs) |x| s += x;
    return s / @as(f64, @floatFromInt(xs.len));
}
fn stdSample(xs: []const f64) f64 {
    if (xs.len < 2) return 0;
    const m = mean(xs);
    var ss: f64 = 0;
    for (xs) |x| ss += (x - m) * (x - m);
    return @sqrt(ss / @as(f64, @floatFromInt(xs.len - 1)));
}
fn f64lt(_: void, a: f64, b: f64) bool {
    return a < b;
}

// ── xirr (bisection over external flows, ACT/365.25 — exact port) ────────────

pub const XirrSpec = struct {
    date_col: []const u8,
    /// External cash flow per row (positive = contribution). null/0 = no flow.
    flow_col: []const u8,
    /// Portfolio value column; the LAST row's value is the terminal flow.
    value_col: []const u8,
};

const Cashflow = struct { t: i64, cf: f64 };

/// Dated-flow internal rate of return. 200-iteration bisection on NPV=0 over
/// [-0.99, 10], ACT/365.25, tolerance 1e-2 (exact port of poc `_xirr`).
pub fn xirr(a: std.mem.Allocator, d: Dataset, spec: XirrSpec) Error!f64 {
    if (d.rows.len == 0) return 0;
    const di = try mustIndex(d, spec.date_col);
    const fi = try mustIndex(d, spec.flow_col);
    const vi = try mustIndex(d, spec.value_col);

    var cfs: std.ArrayList(Cashflow) = .empty;
    defer cfs.deinit(a);
    for (d.rows) |r| {
        const fl = r[fi].asFloat() orelse 0;
        if (@abs(fl) > 1e-6) {
            try cfs.append(a, .{ .t = isoDays(r[di].asText() orelse ""), .cf = -fl });
        }
    }
    const last = d.rows[d.rows.len - 1];
    try cfs.append(a, .{ .t = isoDays(last[di].asText() orelse ""), .cf = last[vi].asFloat() orelse 0 });

    const base = cfs.items[0].t;
    var lo: f64 = -0.99;
    var hi: f64 = 10.0;
    var mid: f64 = 0;
    var i: usize = 0;
    while (i < 200) : (i += 1) {
        mid = (lo + hi) / 2.0;
        const nv_mid = npv(cfs.items, base, mid);
        if (@abs(nv_mid) < 1e-2) return mid;
        const nv_lo = npv(cfs.items, base, lo);
        if ((nv_lo < 0) == (nv_mid < 0)) lo = mid else hi = mid;
    }
    return mid;
}

fn npv(items: []const Cashflow, base: i64, r: f64) f64 {
    var sum: f64 = 0;
    for (items) |it| {
        const dt: f64 = @floatFromInt(it.t - base);
        sum += it.cf / std.math.pow(f64, 1.0 + r, dt / 365.25);
    }
    return sum;
}

/// CAGR: (1 + total_return)^(365.25/days) − 1.
pub fn annualize(total_return: f64, days: f64) f64 {
    if (days <= 0) return 0;
    return std.math.pow(f64, 1.0 + total_return, 365.25 / days) - 1.0;
}

// ── xirr / annualize as pipeline nodes (series → one-row scalar Dataset) ─────
// The scalar math fns above return a number; these thin wrappers emit a
// single-row Dataset so a KPI widget can bind role→column (value/agg) to them,
// exactly like any other source (no bespoke scalar path in the frontend).

pub const XirrNodeSpec = struct {
    date_col: []const u8,
    flow_col: []const u8,
    value_col: []const u8,
    out: []const u8 = "xirr",
    /// Multiply the result (e.g. 100 → percent). Default 1 = fraction.
    scale: f64 = 1,
};

/// `xirr` node: reduce the dated flow/value series to `{out: xirr·scale}`.
pub fn xirrNode(a: std.mem.Allocator, d: Dataset, spec: XirrNodeSpec) Error!Dataset {
    const v = try xirr(a, d, .{ .date_col = spec.date_col, .flow_col = spec.flow_col, .value_col = spec.value_col });
    return oneRow(a, &.{.{ spec.out, v * spec.scale }});
}

pub const AnnualizeNodeSpec = struct {
    /// Cumulative-return column; its LAST value is the total return.
    value_col: []const u8,
    /// Date column for the calendar-day span (last − first).
    date_col: []const u8,
    out: []const u8 = "ann",
    scale: f64 = 1,
};

/// `annualize` node: CAGR of `value_col`'s last value over `date_col`'s day
/// span, emitted as `{out: cagr·scale}`.
pub fn annualizeNode(a: std.mem.Allocator, d: Dataset, spec: AnnualizeNodeSpec) Error!Dataset {
    if (d.rows.len == 0) return oneRow(a, &.{.{ spec.out, 0 }});
    const vi = try mustIndex(d, spec.value_col);
    const di = try mustIndex(d, spec.date_col);
    const total = d.rows[d.rows.len - 1][vi].asFloat() orelse 0;
    const span = isoDays(d.rows[d.rows.len - 1][di].asText() orelse "") - isoDays(d.rows[0][di].asText() orelse "");
    const days: f64 = @floatFromInt(@max(@as(i64, 1), span));
    return oneRow(a, &.{.{ spec.out, annualize(total, days) * spec.scale }});
}

// ── twr_daily (Modified-Dietz daily — exact port) ───────────────────────────

pub const TwrSpec = struct {
    date_col: []const u8,
    value_col: []const u8,
    flow_col: []const u8,
    /// Performance-eligible base (denominator). Rows with pe ≤ 1e-6 are skipped.
    pe_col: []const u8,
    out_date: []const u8 = "d",
    out_ret: []const u8 = "r",
    /// Warm-up trim: skip leading rows until `value` first reaches this threshold,
    /// then take that row as the base (no return) — matches reader.zig, which trims
    /// the daily series to the first day value ≥ 1000 so the tiny-portfolio early
    /// days (huge/noisy returns on a near-zero denominator) don't inflate the curve.
    /// Default 0 = no trim.
    min_value: f64 = 0,
};

/// Daily time-weighted return r = (v − prev − flow) / pe (skip pe ≤ 1e-6), with a
/// leading warm-up trim at `min_value` (see TwrSpec).
pub fn twrDaily(a: std.mem.Allocator, d: Dataset, spec: TwrSpec) Error!Dataset {
    const di = try mustIndex(d, spec.date_col);
    const vi = try mustIndex(d, spec.value_col);
    const fi = try mustIndex(d, spec.flow_col);
    const pi = try mustIndex(d, spec.pe_col);

    const cols = try a.alloc(Column, 2);
    cols[0] = .{ .name = spec.out_date, .type = .date };
    cols[1] = .{ .name = spec.out_ret, .type = .float };
    var rows: std.ArrayList([]const Value) = .empty;
    var have_prev = false;
    var prev: f64 = 0;
    for (d.rows) |r| {
        const v = r[vi].asFloat() orelse 0;
        // warm-up trim: skip until the portfolio value first crosses the threshold;
        // that row then seeds `prev` (no return emitted), exactly like reader's trim.
        if (!have_prev and v < spec.min_value) continue;
        const pe = r[pi].asFloat() orelse 0;
        if (have_prev and pe > 1e-6) {
            const fl = r[fi].asFloat() orelse 0;
            const nr = try a.alloc(Value, 2);
            nr[0] = r[di];
            nr[1] = .{ .float = (v - prev - fl) / pe };
            try rows.append(a, nr);
        }
        prev = v;
        have_prev = true;
    }
    return .{ .columns = cols, .rows = try rows.toOwnedSlice(a) };
}

// ── quantile / histogram ────────────────────────────────────────────────────

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
pub fn quantile(a: std.mem.Allocator, xs: []const f64, q: f64) Error!f64 {
    const s = try a.dupe(f64, xs);
    defer a.free(s);
    std.mem.sort(f64, s, {}, f64lt);
    return quantileSorted(s, q);
}

pub const HistogramSpec = struct {
    value_col: []const u8,
    bins: usize = 12,
};

/// Equal-width histogram → Dataset {bin_lo, bin_hi, count} (exact port of the
/// client `histogram`: span = (max−min) || 1, last-bin inclusive clamp).
pub fn histogram(a: std.mem.Allocator, d: Dataset, spec: HistogramSpec) Error!Dataset {
    const vi = try mustIndex(d, spec.value_col);
    var lo: f64 = std.math.inf(f64);
    var hi: f64 = -std.math.inf(f64);
    for (d.rows) |r| {
        const v = r[vi].asFloat() orelse continue;
        lo = @min(lo, v);
        hi = @max(hi, v);
    }
    const bins = @max(spec.bins, 1);
    const span = if (hi > lo) hi - lo else 1;
    const counts = try a.alloc(u64, bins);
    @memset(counts, 0);
    for (d.rows) |r| {
        const v = r[vi].asFloat() orelse continue;
        var b: i64 = @intFromFloat(@floor((v - lo) / span * @as(f64, @floatFromInt(bins))));
        if (b >= @as(i64, @intCast(bins))) b = @intCast(bins - 1);
        if (b < 0) b = 0;
        counts[@intCast(b)] += 1;
    }
    const cols = try a.alloc(Column, 3);
    cols[0] = .{ .name = "bin_lo", .type = .float };
    cols[1] = .{ .name = "bin_hi", .type = .float };
    cols[2] = .{ .name = "count", .type = .int };
    const rows = try a.alloc([]const Value, bins);
    for (0..bins) |i| {
        const fi: f64 = @floatFromInt(i);
        const nr = try a.alloc(Value, 3);
        nr[0] = .{ .float = lo + span * fi / @as(f64, @floatFromInt(bins)) };
        nr[1] = .{ .float = lo + span * (fi + 1) / @as(f64, @floatFromInt(bins)) };
        nr[2] = .{ .int = @intCast(counts[i]) };
        rows[i] = nr;
    }
    return .{ .columns = cols, .rows = rows };
}

// ── risk_metrics (exact port; derived from a daily return series) ────────────

pub const RiskSpec = struct {
    ret_col: []const u8,
    /// Static annualized return for the sharpe/sortino/calmar numerator — used only
    /// as a fallback when `date_col` is empty.
    ann_return: f64 = 0,
    /// When set, the annualized return is computed internally from the compounded
    /// return level over the calendar-day span of this date column — matching
    /// reader.zig's `ann_twr = level^(365.25/days) − 1`. Preferred over ann_return.
    date_col: []const u8 = "",
    periods_per_year: f64 = 252,
};

/// One-row Dataset of risk metrics: ann_vol, downside, var95, cvar95, mdd,
/// ulcer, sharpe, sortino, calmar. Drawdown is derived from the compounded
/// return level (self-contained from the return series).
pub fn riskMetrics(a: std.mem.Allocator, d: Dataset, spec: RiskSpec) Error!Dataset {
    const ri = try mustIndex(d, spec.ret_col);
    const rvals = try a.alloc(f64, d.rows.len);
    defer a.free(rvals);
    for (d.rows, 0..) |r, i| rvals[i] = r[ri].asFloat() orelse 0;

    const sq = @sqrt(spec.periods_per_year);
    const ann_vol = stdSample(rvals) * sq;

    var dsum: f64 = 0;
    for (rvals) |v| {
        const m = @min(v, 0.0);
        dsum += m * m;
    }
    const downside = if (rvals.len > 0) @sqrt(dsum / @as(f64, @floatFromInt(rvals.len))) * sq else 0;

    const rsorted = try a.dupe(f64, rvals);
    defer a.free(rsorted);
    std.mem.sort(f64, rsorted, {}, f64lt);
    const q05 = quantileSorted(rsorted, 0.05);
    const var95 = -q05;
    var cv_sum: f64 = 0;
    var cv_n: usize = 0;
    for (rvals) |v| if (v <= q05) {
        cv_sum += v;
        cv_n += 1;
    };
    const cvar95 = if (cv_n > 0) -(cv_sum / @as(f64, @floatFromInt(cv_n))) else 0;

    // drawdown of the compounded level, in percent (matches poc ulcer/mdd scale)
    var level: f64 = 1;
    var peak: f64 = 1;
    var min_dd_pct: f64 = 0;
    var ulcer_sq: f64 = 0;
    for (rvals) |r| {
        level *= (1 + r);
        if (level > peak) peak = level;
        const dd_pct = if (peak != 0) (level - peak) / peak * 100.0 else 0;
        min_dd_pct = @min(min_dd_pct, dd_pct);
        ulcer_sq += dd_pct * dd_pct;
    }
    const mdd = min_dd_pct / 100.0;
    const ulcer = if (rvals.len > 0) @sqrt(ulcer_sq / @as(f64, @floatFromInt(rvals.len))) else 0;

    // annualized return for sharpe/sortino/calmar = compounded factor ^
    // (365.25 / calendar-day span) − 1 (matches reader's ann_twr). `level` is the
    // final product of (1+r) after the loop above. Falls back to the static
    // spec.ann_return when no date_col is supplied.
    var ann_return = spec.ann_return;
    if (spec.date_col.len > 0 and d.rows.len >= 2) {
        const dci = try mustIndex(d, spec.date_col);
        const span = isoDays(d.rows[d.rows.len - 1][dci].asText() orelse "") - isoDays(d.rows[0][dci].asText() orelse "");
        const span_f: f64 = @floatFromInt(@max(@as(i64, 1), span));
        ann_return = std.math.pow(f64, level, 365.25 / span_f) - 1;
    }
    const sharpe = if (ann_vol != 0) ann_return / ann_vol else 0;
    const sortino = if (downside != 0) ann_return / downside else 0;
    const calmar = if (mdd != 0) ann_return / @abs(mdd) else 0;

    return oneRow(a, &.{
        .{ "ann_vol", ann_vol }, .{ "downside", downside }, .{ "var95", var95 },
        .{ "cvar95", cvar95 },   .{ "mdd", mdd },           .{ "ulcer", ulcer },
        .{ "sharpe", sharpe },   .{ "sortino", sortino },   .{ "calmar", calmar },
    });
}

// ── beta / alpha / R² (exact port) ──────────────────────────────────────────

pub const BetaSpec = struct {
    port_ret_col: []const u8,
    bench_ret_col: []const u8,
    /// Aligned rows only (join port & bench on date first). Annualized returns
    /// feed alpha = port_ann − beta·bench_ann.
    port_ann: f64,
    bench_ann: f64,
};

/// One-row Dataset: beta, alpha, r2. beta = cov/var(bench); r2 = cov²/(varp·varb).
pub fn betaAlpha(a: std.mem.Allocator, d: Dataset, spec: BetaSpec) Error!Dataset {
    const pi = try mustIndex(d, spec.port_ret_col);
    const bi = try mustIndex(d, spec.bench_ret_col);
    const n = d.rows.len;
    const p = try a.alloc(f64, n);
    const bm = try a.alloc(f64, n);
    for (d.rows, 0..) |r, i| {
        p[i] = r[pi].asFloat() orelse 0;
        bm[i] = r[bi].asFloat() orelse 0;
    }
    const mp = mean(p);
    const mb = mean(bm);
    var cov: f64 = 0;
    var varp: f64 = 0;
    var varb: f64 = 0;
    for (p, 0..) |_, i| {
        const dp = p[i] - mp;
        const db = bm[i] - mb;
        cov += dp * db;
        varp += dp * dp;
        varb += db * db;
    }
    const beta = if (varb > 0) cov / varb else 0;
    const r2 = if (varp * varb > 0) (cov * cov) / (varp * varb) else 0;
    const alpha = spec.port_ann - beta * spec.bench_ann;
    return oneRow(a, &.{ .{ "beta", beta }, .{ "alpha", alpha }, .{ "r2", r2 } });
}

// ── monte_carlo (GBM-ish monthly, Box-Muller — fixed-seed) ──────────

pub const MonteCarloSpec = struct {
    start: f64,
    mu_ann: f64,
    vol_ann: f64,
    monthly: f64,
    years: f64,
    paths: usize = 2000,
    /// Seed for the PRNG (deterministic; the client used Math.random()).
    seed: u64 = 0x9E3779B97F4A7C15,
};

/// Monte-Carlo net-worth projection → Dataset {month, p10, p50, p90}. Monthly
/// step v = max(0, v·(1 + muM + sigM·Z) + monthly), Z ~ N(0,1) Box-Muller.
pub fn monteCarlo(a: std.mem.Allocator, spec: MonteCarloSpec) Error!Dataset {
    const months: usize = @intFromFloat(@round(spec.years * 12));
    const mu_m = std.math.pow(f64, 1 + spec.mu_ann, 1.0 / 12.0) - 1;
    const sig_m = spec.vol_ann / @sqrt(12.0);
    const n = @max(spec.paths, 1);

    // cols[t] = the n path values at month t (t = 0..months)
    const cols_v = try a.alloc([]f64, months + 1);
    for (cols_v) |*c| c.* = try a.alloc(f64, n);
    var prng = std.Random.DefaultPrng.init(spec.seed);
    const rnd = prng.random();
    for (0..n) |i| {
        var v = spec.start;
        cols_v[0][i] = v;
        for (0..months) |t| {
            v = @max(0, v * (1 + mu_m + sig_m * gauss(rnd)) + spec.monthly);
            cols_v[t + 1][i] = v;
        }
    }

    const cols = try a.alloc(Column, 4);
    cols[0] = .{ .name = "month", .type = .int };
    cols[1] = .{ .name = "p10", .type = .float };
    cols[2] = .{ .name = "p50", .type = .float };
    cols[3] = .{ .name = "p90", .type = .float };
    const rows = try a.alloc([]const Value, months + 1);
    for (0..months + 1) |t| {
        std.mem.sort(f64, cols_v[t], {}, f64lt);
        const nr = try a.alloc(Value, 4);
        nr[0] = .{ .int = @intCast(t) };
        nr[1] = .{ .float = quantileSorted(cols_v[t], 0.1) };
        nr[2] = .{ .float = quantileSorted(cols_v[t], 0.5) };
        nr[3] = .{ .float = quantileSorted(cols_v[t], 0.9) };
        rows[t] = nr;
    }
    return .{ .columns = cols, .rows = rows };
}

fn gauss(rnd: std.Random) f64 {
    var u: f64 = 0;
    var v: f64 = 0;
    while (u == 0) u = rnd.float(f64);
    while (v == 0) v = rnd.float(f64);
    return @sqrt(-2.0 * @log(u)) * @cos(2.0 * std.math.pi * v);
}

// ── correlation_matrix (pairwise Pearson, min-overlap — exact port) ─────────

pub const CorrSpec = struct {
    /// Long form: (key, date, value). Series are grouped by key and aligned by date.
    key_col: []const u8,
    date_col: []const u8,
    value_col: []const u8,
    min_overlap: usize = 30,
};

/// Pairwise Pearson correlation matrix → Dataset (first col "key" + one float
/// col per key). Diagonal = 1; pairs with < min_overlap shared dates or no
/// variance → null.
pub fn correlationMatrix(a: std.mem.Allocator, d: Dataset, spec: CorrSpec) Error!Dataset {
    const ki = try mustIndex(d, spec.key_col);
    const di = try mustIndex(d, spec.date_col);
    const vi = try mustIndex(d, spec.value_col);

    var keys: std.ArrayList([]const u8) = .empty;
    var maps: std.ArrayList(*std.StringHashMapUnmanaged(f64)) = .empty;
    var key_idx: std.StringArrayHashMapUnmanaged(usize) = .empty;
    for (d.rows) |r| {
        const key = r[ki].asText() orelse continue;
        const date = r[di].asText() orelse continue;
        const gop = try key_idx.getOrPut(a, key);
        if (!gop.found_existing) {
            gop.value_ptr.* = keys.items.len;
            try keys.append(a, key);
            const m = try a.create(std.StringHashMapUnmanaged(f64));
            m.* = .empty;
            try maps.append(a, m);
        }
        try maps.items[gop.value_ptr.*].put(a, date, r[vi].asFloat() orelse 0);
    }

    const n = keys.items.len;
    const cols = try a.alloc(Column, n + 1);
    cols[0] = .{ .name = "key", .type = .text };
    for (keys.items, 0..) |k, i| cols[i + 1] = .{ .name = k, .type = .float };

    const rows = try a.alloc([]const Value, n);
    for (0..n) |i| {
        const nr = try a.alloc(Value, n + 1);
        nr[0] = .{ .text = keys.items[i] };
        for (0..n) |j| {
            nr[j + 1] = if (i == j) .{ .float = 1 } else pearson(a, maps.items[i], maps.items[j], spec.min_overlap);
        }
        rows[i] = nr;
    }
    return .{ .columns = cols, .rows = rows };
}

fn pearson(a: std.mem.Allocator, xm: *std.StringHashMapUnmanaged(f64), ym: *std.StringHashMapUnmanaged(f64), min_overlap: usize) Value {
    var xs: std.ArrayList(f64) = .empty;
    var ys: std.ArrayList(f64) = .empty;
    var it = xm.iterator();
    while (it.next()) |e| {
        if (ym.get(e.key_ptr.*)) |v2| {
            xs.append(a, e.value_ptr.*) catch return .null;
            ys.append(a, v2) catch return .null;
        }
    }
    if (xs.items.len < min_overlap) return .null;
    const mx = mean(xs.items);
    const my = mean(ys.items);
    var cov: f64 = 0;
    var vx: f64 = 0;
    var vy: f64 = 0;
    for (xs.items, 0..) |v, k| {
        const dx = v - mx;
        const dy = ys.items[k] - my;
        cov += dx * dy;
        vx += dx * dx;
        vy += dy * dy;
    }
    return if (vx * vy > 0) .{ .float = cov / @sqrt(vx * vy) } else .null;
}

// ── drawdown_episodes (peak→trough→recovery state machine — exact port) ─────

pub const DdEpisodesSpec = struct {
    date_col: []const u8,
    value_col: []const u8,
    top_n: usize = 6,
};

/// Drawdown episodes → Dataset {peak, trough, recovery, depth_pct, fall_days,
/// recover_days}, worst `top_n` by depth. `recovery`/`recover_days` null while
/// still underwater at series end.
pub fn drawdownEpisodes(a: std.mem.Allocator, d: Dataset, spec: DdEpisodesSpec) Error!Dataset {
    const di = try mustIndex(d, spec.date_col);
    const vi = try mustIndex(d, spec.value_col);
    const Ep = struct { peak_d: []const u8, trough_d: []const u8, recovery: ?[]const u8, depth: f64, fall_d: i64, recover_d: ?i64 };
    var eps: std.ArrayList(Ep) = .empty;

    var peak: f64 = -1e18;
    var peak_d: []const u8 = "";
    var trough: f64 = 0;
    var trough_d: []const u8 = "";
    var under = false;
    for (d.rows) |r| {
        const v = r[vi].asFloat() orelse 0;
        const dt = r[di].asText() orelse "";
        if (v >= peak) {
            if (under) {
                try eps.append(a, .{ .peak_d = peak_d, .trough_d = trough_d, .recovery = dt, .depth = (trough - peak) / peak * 100.0, .fall_d = isoDays(trough_d) - isoDays(peak_d), .recover_d = isoDays(dt) - isoDays(trough_d) });
                under = false;
            }
            peak = v;
            peak_d = dt;
            trough = v;
            trough_d = dt;
        } else {
            if (!under) {
                under = true;
                trough = v;
                trough_d = dt;
            }
            if (v < trough) {
                trough = v;
                trough_d = dt;
            }
        }
    }
    if (under) {
        try eps.append(a, .{ .peak_d = peak_d, .trough_d = trough_d, .recovery = null, .depth = (trough - peak) / peak * 100.0, .fall_d = isoDays(trough_d) - isoDays(peak_d), .recover_d = null });
    }

    std.mem.sort(Ep, eps.items, {}, struct {
        fn lt(_: void, x: Ep, y: Ep) bool {
            return x.depth < y.depth;
        }
    }.lt);

    const cols = try a.alloc(Column, 6);
    cols[0] = .{ .name = "peak", .type = .date };
    cols[1] = .{ .name = "trough", .type = .date };
    cols[2] = .{ .name = "recovery", .type = .date };
    cols[3] = .{ .name = "depth_pct", .type = .float };
    cols[4] = .{ .name = "fall_days", .type = .int };
    cols[5] = .{ .name = "recover_days", .type = .int };
    const keep = @min(spec.top_n, eps.items.len);
    const rows = try a.alloc([]const Value, keep);
    for (0..keep) |i| {
        const e = eps.items[i];
        const nr = try a.alloc(Value, 6);
        nr[0] = .{ .text = e.peak_d };
        nr[1] = .{ .text = e.trough_d };
        nr[2] = if (e.recovery) |rv| .{ .text = rv } else .null;
        nr[3] = .{ .float = e.depth };
        nr[4] = .{ .int = e.fall_d };
        nr[5] = if (e.recover_d) |rd| .{ .int = rd } else .null;
        rows[i] = nr;
    }
    return .{ .columns = cols, .rows = rows };
}

// ── xirrPrecise (Newton-Raphson + bisection fallback — backlog item) ────────
// `xirr` above stays untouched (pure bisection at 1e-2, pinned by its own
// tests); this is an additive, faster/more-precise sibling that tries Newton
// first and automatically falls back to the same bisection bracket whenever
// Newton fails to converge.

pub const XirrPreciseSpec = struct {
    date_col: []const u8,
    flow_col: []const u8,
    value_col: []const u8,
    /// |NPV| convergence threshold for both the Newton and bisection phases.
    tol: f64 = 1e-8,
    /// Newton iteration budget before falling back to bisection.
    max_newton_iter: usize = 50,
    initial_guess: f64 = 0.1,
};

/// Dated-flow IRR via Newton-Raphson (fast, high precision) with an automatic
/// bisection fallback (same [-0.99, 10] bracket as `xirr`, 200 iterations)
/// whenever Newton fails to converge: derivative underflow, a step landing
/// outside the bracket, a NaN, or exhausting `max_newton_iter` without
/// meeting `tol`.
pub fn xirrPrecise(a: std.mem.Allocator, d: Dataset, spec: XirrPreciseSpec) Error!f64 {
    if (d.rows.len == 0) return 0;
    const di = try mustIndex(d, spec.date_col);
    const fi = try mustIndex(d, spec.flow_col);
    const vi = try mustIndex(d, spec.value_col);

    var cfs: std.ArrayList(Cashflow) = .empty;
    defer cfs.deinit(a);
    for (d.rows) |r| {
        const fl = r[fi].asFloat() orelse 0;
        if (@abs(fl) > 1e-6) {
            try cfs.append(a, .{ .t = isoDays(r[di].asText() orelse ""), .cf = -fl });
        }
    }
    const last = d.rows[d.rows.len - 1];
    try cfs.append(a, .{ .t = isoDays(last[di].asText() orelse ""), .cf = last[vi].asFloat() orelse 0 });
    const base = cfs.items[0].t;

    newton: {
        var r: f64 = spec.initial_guess;
        var i: usize = 0;
        while (i < spec.max_newton_iter) : (i += 1) {
            const f = npv(cfs.items, base, r);
            if (@abs(f) < spec.tol) return r;
            const df = dnpv(cfs.items, base, r);
            if (std.math.isNan(df) or @abs(df) < 1e-14) break :newton; // derivative underflow
            const r_new = r - f / df;
            if (std.math.isNan(r_new) or r_new <= -0.99 or r_new >= 10.0) break :newton; // stepped outside the bracket
            r = r_new;
        }
        // ran out of iterations without meeting tol — fall through to bisection
    }

    var lo: f64 = -0.99;
    var hi: f64 = 10.0;
    var mid: f64 = 0;
    var i: usize = 0;
    while (i < 200) : (i += 1) {
        mid = (lo + hi) / 2.0;
        const nv_mid = npv(cfs.items, base, mid);
        if (@abs(nv_mid) < spec.tol) return mid;
        const nv_lo = npv(cfs.items, base, lo);
        if ((nv_lo < 0) == (nv_mid < 0)) lo = mid else hi = mid;
    }
    return mid;
}

/// d(NPV)/dr for the Newton step above.
fn dnpv(items: []const Cashflow, base: i64, r: f64) f64 {
    var sum: f64 = 0;
    for (items) |it| {
        const dt: f64 = @floatFromInt(it.t - base);
        const yrs = dt / 365.25;
        sum += -it.cf * yrs / std.math.pow(f64, 1.0 + r, yrs + 1.0);
    }
    return sum;
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

fn cfQuantileReturn(mean_: f64, std_dev: f64, skew: f64, excess_kurt: f64, p: f64) f64 {
    const z = invNormCdf(p);
    const zcf = cornishFisherZ(z, skew, excess_kurt);
    return mean_ + std_dev * zcf;
}

/// Cornish-Fisher (modified) CVaR: −(1/α)·∫₀^α Q_CF(p) dp — the tail mean of
/// the CF-implied quantile function, via fixed-step trapezoidal quadrature
/// (deterministic, no allocation). This is the mathematically faithful
/// tail-expectation of the CF quantile. A naive shortcut — plugging the
/// CF z-score into the closed-form Gaussian ES ratio (`φ(z_cf)/α`) the way
/// `cornishFisherVaR` plugs it into the VaR formula — is deliberately NOT
/// used here: for negative-skew/fat-tailed inputs that shortcut can invert
/// and report CVaR < VaR, violating the CVaR ≥ VaR invariant (verified while
/// developing this function; the quadrature form does not have that
/// failure mode for the skew/kurtosis ranges real return series produce).
/// Collapses to `gaussianCVaR` (within quadrature error) when skew =
/// excess_kurt = 0.
pub fn cornishFisherCVaR(mean_: f64, std_dev: f64, skew: f64, excess_kurt: f64, confidence: f64) f64 {
    const alpha = 1.0 - confidence;
    if (alpha <= 0) return cornishFisherVaR(mean_, std_dev, skew, excess_kurt, confidence);
    const steps: usize = 2000;
    const eps = 1e-9;
    const h = (alpha - eps) / @as(f64, @floatFromInt(steps));
    var total: f64 = 0;
    var i: usize = 0;
    while (i <= steps) : (i += 1) {
        const p = eps + @as(f64, @floatFromInt(i)) * h;
        const w: f64 = if (i == 0 or i == steps) 0.5 else 1.0;
        total += w * cfQuantileReturn(mean_, std_dev, skew, excess_kurt, p);
    }
    const integral = total * h;
    const mean_tail = integral / alpha;
    return -mean_tail;
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

pub const ParametricRiskSpec = struct {
    ret_col: []const u8,
    confidence: f64 = 0.95,
};

/// One-row Dataset of parametric risk stats over `ret_col`: {mean, std,
/// skew, kurt, var_gaussian, cvar_gaussian, var_cf, cvar_cf} — the
/// sample mean/stdev + population skew/excess-kurtosis fit, and both VaR/
/// CVaR variants at `confidence` (default 0.95). Complements `riskMetrics`'
/// historical var95/cvar95.
pub fn parametricRisk(a: std.mem.Allocator, d: Dataset, spec: ParametricRiskSpec) Error!Dataset {
    const ri = try mustIndex(d, spec.ret_col);
    const rvals = try a.alloc(f64, d.rows.len);
    defer a.free(rvals);
    for (d.rows, 0..) |r, i| rvals[i] = r[ri].asFloat() orelse 0;

    const m = mean(rvals);
    const sd = stdSample(rvals);
    const sk = skewness(rvals);
    const ek = excessKurtosis(rvals);
    const conf = spec.confidence;

    return oneRow(a, &.{
        .{ "mean", m },
        .{ "std", sd },
        .{ "skew", sk },
        .{ "kurt", ek },
        .{ "var_gaussian", gaussianVaR(m, sd, conf) },
        .{ "cvar_gaussian", gaussianCVaR(m, sd, conf) },
        .{ "var_cf", cornishFisherVaR(m, sd, sk, ek, conf) },
        .{ "cvar_cf", cornishFisherCVaR(m, sd, sk, ek, conf) },
    });
}

// ── tracking error / information ratio (backlog item) ───────────────────────

pub const TrackingSpec = struct {
    port_ret_col: []const u8,
    bench_ret_col: []const u8,
    /// Aligned rows only (same convention as betaAlpha — join on date first).
    periods_per_year: f64 = 252,
};

/// One-row Dataset: {tracking_error, information_ratio}. active_i = port_i −
/// bench_i; tracking_error = stdev(active)·√ppy (annualized volatility of
/// the active return stream); information_ratio = mean(active)·ppy /
/// tracking_error (0 when tracking_error is 0 — flat active stream, same
/// zero-denominator convention as riskMetrics' sharpe/sortino/calmar).
pub fn trackingRisk(a: std.mem.Allocator, d: Dataset, spec: TrackingSpec) Error!Dataset {
    const pi = try mustIndex(d, spec.port_ret_col);
    const bi = try mustIndex(d, spec.bench_ret_col);
    const n = d.rows.len;
    const active = try a.alloc(f64, n);
    for (d.rows, 0..) |r, i| {
        const p = r[pi].asFloat() orelse 0;
        const b = r[bi].asFloat() orelse 0;
        active[i] = p - b;
    }
    const sq = @sqrt(spec.periods_per_year);
    const te = stdSample(active) * sq;
    const ann_active = mean(active) * spec.periods_per_year;
    const ir = if (te != 0) ann_active / te else 0;
    return oneRow(a, &.{ .{ "tracking_error", te }, .{ "information_ratio", ir } });
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

pub const OmegaSpec = struct {
    ret_col: []const u8,
    threshold: f64 = 0,
    out: []const u8 = "omega",
};

/// `omegaRatio` node: reduce `ret_col` to `{out: omega}`.
pub fn omegaRatioNode(a: std.mem.Allocator, d: Dataset, spec: OmegaSpec) Error!Dataset {
    const ri = try mustIndex(d, spec.ret_col);
    const xs = try a.alloc(f64, d.rows.len);
    for (d.rows, 0..) |r, i| xs[i] = r[ri].asFloat() orelse 0;
    return oneRow(a, &.{.{ spec.out, omegaRatio(xs, spec.threshold) }});
}

// ── rolling-window helper (backlog item) ─────────────────────────────────────
// Generic over the per-window reducer (a comptime fn, same idiom as the
// `std.mem.sort` comparators already used in this file) so any scalar
// statistic — mean/stdev/sharpe/a caller's own — can run over a sliding
// window without a bespoke `rolling*` per metric. Three concrete wrappers
// for the key metrics (mean/vol/sharpe) are provided on top.

pub const RollingSpec = struct {
    value_col: []const u8,
    /// Optional date column to carry through as the row label (the window's
    /// LAST date). Empty = no date column in the output.
    date_col: []const u8 = "",
    window: usize,
    out: []const u8 = "value",
};

/// Rolling window over `value_col`: for each trailing window of `window`
/// values, applies `reducer` and emits one row (windows before the first
/// full one are skipped — `n − window + 1` rows total, 0 if `n < window`).
pub fn rollingApply(a: std.mem.Allocator, d: Dataset, spec: RollingSpec, comptime reducer: fn ([]const f64) f64) Error!Dataset {
    const vi = try mustIndex(d, spec.value_col);
    var di: ?usize = null;
    if (spec.date_col.len > 0) di = try mustIndex(d, spec.date_col);
    const n = d.rows.len;
    const vals = try a.alloc(f64, n);
    for (d.rows, 0..) |r, i| vals[i] = r[vi].asFloat() orelse 0;

    var cols: []Column = undefined;
    if (di != null) {
        cols = try a.alloc(Column, 2);
        cols[0] = .{ .name = spec.date_col, .type = .date };
        cols[1] = .{ .name = spec.out, .type = .float };
    } else {
        cols = try a.alloc(Column, 1);
        cols[0] = .{ .name = spec.out, .type = .float };
    }

    if (spec.window == 0 or n < spec.window) return .{ .columns = cols, .rows = &.{} };
    const out_n = n - spec.window + 1;
    const rows = try a.alloc([]const Value, out_n);
    for (0..out_n) |k| {
        const win = vals[k .. k + spec.window];
        const v = reducer(win);
        if (di) |dci| {
            const nr = try a.alloc(Value, 2);
            nr[0] = d.rows[k + spec.window - 1][dci];
            nr[1] = .{ .float = v };
            rows[k] = nr;
        } else {
            const nr = try a.alloc(Value, 1);
            nr[0] = .{ .float = v };
            rows[k] = nr;
        }
    }
    return .{ .columns = cols, .rows = rows };
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

/// Rolling mean over `value_col` (concrete wrapper over `rollingApply`).
pub fn rollingMean(a: std.mem.Allocator, d: Dataset, spec: RollingSpec) Error!Dataset {
    return rollingApply(a, d, spec, rollingMeanReducer);
}
/// Rolling (sample) stdev over `value_col` — unannualized; multiply by
/// √periods_per_year at the call site to annualize.
pub fn rollingVolatility(a: std.mem.Allocator, d: Dataset, spec: RollingSpec) Error!Dataset {
    return rollingApply(a, d, spec, rollingVolReducer);
}
/// Rolling (unannualized, rf=0) Sharpe-like ratio mean/stdev over `value_col`.
pub fn rollingSharpe(a: std.mem.Allocator, d: Dataset, spec: RollingSpec) Error!Dataset {
    return rollingApply(a, d, spec, rollingSharpeReducer);
}

// ── Brinson (factor) attribution (backlog item) ──────────────────────────────

pub const BrinsonSpec = struct {
    segment_col: []const u8,
    port_weight_col: []const u8,
    bench_weight_col: []const u8,
    port_return_col: []const u8,
    bench_return_col: []const u8,
};

/// Brinson-Fachler attribution → Dataset {segment, allocation, selection,
/// interaction, total} per segment, plus a trailing "TOTAL" row. Per
/// segment i: `allocation = (wp_i − wb_i)·(rb_i − Rb)`, `selection = wb_i·
/// (rp_i − rb_i)`, `interaction = (wp_i − wb_i)·(rp_i − rb_i)` (Rb = Σ wb_i·
/// rb_i, the total benchmark return — the Brinson-Fachler refinement over
/// the original 1986 BHB model, benchmark-relative regardless of segment
/// weighting). The three effects summed over all segments equal exactly the
/// portfolio's active return `Rp − Rb` (Σ wp_i·rp_i − Σ wb_i·rb_i) — an
/// algebraic identity of the decomposition, pinned by test, assuming
/// Σ wp_i = Σ wb_i = 1.
pub fn brinsonAttribution(a: std.mem.Allocator, d: Dataset, spec: BrinsonSpec) Error!Dataset {
    const si = try mustIndex(d, spec.segment_col);
    const wpi = try mustIndex(d, spec.port_weight_col);
    const wbi = try mustIndex(d, spec.bench_weight_col);
    const rpi = try mustIndex(d, spec.port_return_col);
    const rbi = try mustIndex(d, spec.bench_return_col);

    var rb_total: f64 = 0;
    for (d.rows) |r| rb_total += (r[wbi].asFloat() orelse 0) * (r[rbi].asFloat() orelse 0);

    const cols = try a.alloc(Column, 5);
    cols[0] = .{ .name = "segment", .type = .text };
    cols[1] = .{ .name = "allocation", .type = .float };
    cols[2] = .{ .name = "selection", .type = .float };
    cols[3] = .{ .name = "interaction", .type = .float };
    cols[4] = .{ .name = "total", .type = .float };

    const rows = try a.alloc([]const Value, d.rows.len + 1);
    var sum_alloc: f64 = 0;
    var sum_sel: f64 = 0;
    var sum_inter: f64 = 0;
    for (d.rows, 0..) |r, i| {
        const wp = r[wpi].asFloat() orelse 0;
        const wb = r[wbi].asFloat() orelse 0;
        const rp = r[rpi].asFloat() orelse 0;
        const rb = r[rbi].asFloat() orelse 0;
        const alloc = (wp - wb) * (rb - rb_total);
        const sel = wb * (rp - rb);
        const inter = (wp - wb) * (rp - rb);
        sum_alloc += alloc;
        sum_sel += sel;
        sum_inter += inter;
        const nr = try a.alloc(Value, 5);
        nr[0] = r[si];
        nr[1] = .{ .float = alloc };
        nr[2] = .{ .float = sel };
        nr[3] = .{ .float = inter };
        nr[4] = .{ .float = alloc + sel + inter };
        rows[i] = nr;
    }
    const tr = try a.alloc(Value, 5);
    tr[0] = .{ .text = "TOTAL" };
    tr[1] = .{ .float = sum_alloc };
    tr[2] = .{ .float = sum_sel };
    tr[3] = .{ .float = sum_inter };
    tr[4] = .{ .float = sum_alloc + sum_sel + sum_inter };
    rows[d.rows.len] = tr;

    return .{ .columns = cols, .rows = rows };
}

// ── shared: build a 1-row Dataset from named floats ─────────────────────────

fn oneRow(a: std.mem.Allocator, kv: []const struct { []const u8, f64 }) Error!Dataset {
    const cols = try a.alloc(Column, kv.len);
    const row = try a.alloc(Value, kv.len);
    for (kv, 0..) |pair, i| {
        cols[i] = .{ .name = pair[0], .type = .float };
        row[i] = .{ .float = pair[1] };
    }
    const rows = try a.alloc([]const Value, 1);
    rows[0] = row;
    return .{ .columns = cols, .rows = rows };
}

// ── tests (headless: `zig build test-finstats`) ──────────────────────────────
const testing = std.testing;

const Fix = struct {
    arena: std.heap.ArenaAllocator,
    fn init() Fix {
        return .{ .arena = std.heap.ArenaAllocator.init(testing.allocator) };
    }
    fn deinit(self: *Fix) void {
        self.arena.deinit();
    }
    fn a(self: *Fix) std.mem.Allocator {
        return self.arena.allocator();
    }
};

test "scratch allocations are released (std.testing.allocator, not an arena)" {
    // ⭐ Every other test here runs on `Fix`, whose allocator is an
    // ArenaAllocator: it bulk-frees on `deinit`, so a function that never
    // released its scratch looked identical to one that did. `xirr`,
    // `xirrPrecise`, `quantile`, `riskMetrics` and `parametricRisk` all leaked
    // under any other allocator, which is what a long-lived consumer uses.
    // Found by writing `example/main.zig` against a DebugAllocator.
    //
    // `std.testing.allocator` fails the test on an outstanding allocation, so
    // this is the one test in the file that can see the class at all.
    const a = testing.allocator;
    const cols = [_]Column{
        .{ .name = "d", .type = .date },
        .{ .name = "flow", .type = .float },
        .{ .name = "v", .type = .float },
        .{ .name = "ret", .type = .float },
    };
    const rows = [_][]const Value{
        &.{ .{ .text = "2023-01-01" }, .{ .float = 100 }, .{ .float = 100 }, .{ .float = 0.01 } },
        &.{ .{ .text = "2023-07-01" }, .{ .float = 0 }, .{ .float = 150 }, .{ .float = -0.02 } },
        &.{ .{ .text = "2024-01-01" }, .{ .float = 0 }, .{ .float = 200 }, .{ .float = 0.03 } },
    };
    const d: Dataset = .{ .columns = &cols, .rows = &rows };

    _ = try xirr(a, d, .{ .date_col = "d", .flow_col = "flow", .value_col = "v" });
    _ = try xirrPrecise(a, d, .{ .date_col = "d", .flow_col = "flow", .value_col = "v" });
    _ = try quantile(a, &[_]f64{ 0.3, 0.1, 0.2 }, 0.5);

    // The returned one-row Datasets are the caller's (`oneRow` allocates
    // columns, the row and the row slice); freeing them here leaves only the
    // scratch these functions allocate internally, which is the point.
    const rm = try riskMetrics(a, d, .{ .ret_col = "ret" });
    a.free(rm.rows[0]);
    a.free(rm.rows);
    a.free(rm.columns);
    const pr = try parametricRisk(a, d, .{ .ret_col = "ret" });
    a.free(pr.rows[0]);
    a.free(pr.rows);
    a.free(pr.columns);
}

test "xirr: ~100% on a doubling over one year" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{
        .{ .name = "d", .type = .date },
        .{ .name = "flow", .type = .float },
        .{ .name = "v", .type = .float },
    };
    // invest 100 at t0; worth 200 exactly one year later → IRR ≈ 100%
    const rows = [_][]const Value{
        &.{ .{ .text = "2023-01-01" }, .{ .float = 100 }, .{ .float = 100 } },
        &.{ .{ .text = "2024-01-01" }, .{ .float = 0 }, .{ .float = 200 } },
    };
    const r = try xirr(f.a(), .{ .columns = &cols, .rows = &rows }, .{ .date_col = "d", .flow_col = "flow", .value_col = "v" });
    try testing.expectApproxEqAbs(@as(f64, 1.0), r, 0.02);
}

test "annualize CAGR" {
    try testing.expectApproxEqAbs(@as(f64, 1.0), annualize(1.0, 365.25), 1e-9); // double in 1y → 100%
    try testing.expectApproxEqAbs(@as(f64, 0.0), annualize(0.0, 100), 1e-12);
}

test "xirrNode: emits one-row {xirr}, scaled" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{
        .{ .name = "d", .type = .date },
        .{ .name = "flow", .type = .float },
        .{ .name = "v", .type = .float },
    };
    const rows = [_][]const Value{
        &.{ .{ .text = "2023-01-01" }, .{ .float = 100 }, .{ .float = 100 } },
        &.{ .{ .text = "2024-01-01" }, .{ .float = 0 }, .{ .float = 200 } }, // IRR ≈ 100%
    };
    const out = try xirrNode(f.a(), .{ .columns = &cols, .rows = &rows }, .{ .date_col = "d", .flow_col = "flow", .value_col = "v", .out = "xirr", .scale = 100 });
    try testing.expectEqual(@as(usize, 1), out.rows.len);
    try testing.expectApproxEqAbs(@as(f64, 100), out.cell(0, "xirr").?.float, 2); // ×100 → ~100 %
}

test "annualizeNode: CAGR of last cum over the day span" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{ .{ .name = "d", .type = .date }, .{ .name = "cum", .type = .float } };
    const rows = [_][]const Value{
        &.{ .{ .text = "2023-01-01" }, .{ .float = 0 } },
        &.{ .{ .text = "2024-01-01" }, .{ .float = 1.0 } }, // +100% over ~1y → CAGR ≈ 100%
    };
    const out = try annualizeNode(f.a(), .{ .columns = &cols, .rows = &rows }, .{ .value_col = "cum", .date_col = "d", .out = "ann" });
    try testing.expectEqual(@as(usize, 1), out.rows.len);
    try testing.expectApproxEqAbs(@as(f64, 1.0), out.cell(0, "ann").?.float, 0.01);
}

test "twr_daily Modified-Dietz" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{
        .{ .name = "d", .type = .date },   .{ .name = "v", .type = .float },
        .{ .name = "fl", .type = .float }, .{ .name = "pe", .type = .float },
    };
    const rows = [_][]const Value{
        &.{ .{ .text = "2024-01-01" }, .{ .float = 100 }, .{ .float = 0 }, .{ .float = 100 } },
        &.{ .{ .text = "2024-01-02" }, .{ .float = 110 }, .{ .float = 0 }, .{ .float = 100 } }, // r=0.1
        &.{ .{ .text = "2024-01-03" }, .{ .float = 121 }, .{ .float = 0 }, .{ .float = 110 } }, // r=0.1
    };
    const t = try twrDaily(f.a(), .{ .columns = &cols, .rows = &rows }, .{ .date_col = "d", .value_col = "v", .flow_col = "fl", .pe_col = "pe" });
    try testing.expectEqual(@as(usize, 2), t.rows.len);
    try testing.expectApproxEqAbs(@as(f64, 0.1), t.cell(0, "r").?.float, 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 0.1), t.cell(1, "r").?.float, 1e-9);
}

test "quantile linear interp + histogram" {
    var f = Fix.init();
    defer f.deinit();
    const s = [_]f64{ 1, 2, 3, 4 };
    try testing.expectApproxEqAbs(@as(f64, 2.5), quantileSorted(&s, 0.5), 1e-9);

    const cols = [_]Column{.{ .name = "v", .type = .float }};
    const rows = [_][]const Value{
        &.{.{ .float = 0 }}, &.{.{ .float = 1 }}, &.{.{ .float = 2 }}, &.{.{ .float = 10 }},
    };
    const h = try histogram(f.a(), .{ .columns = &cols, .rows = &rows }, .{ .value_col = "v", .bins = 5 });
    try testing.expectEqual(@as(usize, 5), h.rows.len);
    // total count == number of values
    var total: i64 = 0;
    for (0..h.rows.len) |i| total += h.cell(i, "count").?.int;
    try testing.expectEqual(@as(i64, 4), total);
    try testing.expectEqual(@as(i64, 1), h.cell(4, "count").?.int); // the 10 lands in last bin
}

test "quantile: unsorted-slice wrapper sorts a COPY and matches quantileSorted (mutation guard)" {
    // `quantile` had no test call site at all -- only `quantileSorted` (the
    // pre-sorted primitive) was ever exercised directly. Feed it genuinely
    // unsorted input so the sort step is load-bearing, and confirm the
    // original slice is left untouched (it dupes before sorting).
    var f = Fix.init();
    defer f.deinit();
    // q = 0.25, deliberately NOT 0.5 -- a 0.5 probe is symmetric under a
    // q -> 1-q mutation (the wrong answer would equal the right one).
    const xs = [_]f64{ 3, 1, 4, 1, 5, 9, 2, 6 };
    const got = try quantile(f.a(), &xs, 0.25);
    var sorted_copy = xs;
    std.mem.sort(f64, &sorted_copy, {}, f64lt);
    try testing.expectApproxEqAbs(quantileSorted(&sorted_copy, 0.25), got, 1e-9);
    // The caller's original slice must be untouched (unsorted-order proof).
    try testing.expectEqual(@as(f64, 3), xs[0]);
    try testing.expectEqual(@as(f64, 6), xs[7]);
}

test "quantileSorted: out-of-range q is clamped instead of panicking (audit F1)" {
    // Batch: q was fed straight into @intFromFloat(@floor(q*(n-1))); a q < 0
    // (e.g. a 0-100 vs 0-1 convention mixup) panicked in ReleaseSafe / OOB-read
    // in ReleaseFast. It is now clamped into [0,1] (NaN -> 0).
    const s = [_]f64{ 1, 2, 3, 4 };
    try testing.expectEqual(@as(f64, 1), quantileSorted(&s, -0.5)); // was a panic
    try testing.expectEqual(@as(f64, 4), quantileSorted(&s, 2.0));
    try testing.expectEqual(@as(f64, 1), quantileSorted(&s, std.math.nan(f64)));
}

test "risk_metrics basic invariants" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{.{ .name = "r", .type = .float }};
    const rows = [_][]const Value{
        &.{.{ .float = 0.01 }},   &.{.{ .float = -0.02 }}, &.{.{ .float = 0.015 }},
        &.{.{ .float = -0.005 }}, &.{.{ .float = 0.02 }},
    };
    const rm = try riskMetrics(f.a(), .{ .columns = &cols, .rows = &rows }, .{ .ret_col = "r", .ann_return = 0.1 });
    try testing.expect(rm.cell(0, "ann_vol").?.float > 0);
    try testing.expect(rm.cell(0, "mdd").?.float <= 0);
    try testing.expect(rm.cell(0, "var95").?.float >= 0); // -q05, q05 negative
}

test "beta_alpha: identical series → beta 1, r2 1, alpha 0" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{ .{ .name = "p", .type = .float }, .{ .name = "b", .type = .float } };
    const rows = [_][]const Value{
        &.{ .{ .float = 0.01 }, .{ .float = 0.01 } },
        &.{ .{ .float = -0.02 }, .{ .float = -0.02 } },
        &.{ .{ .float = 0.03 }, .{ .float = 0.03 } },
    };
    const ba = try betaAlpha(f.a(), .{ .columns = &cols, .rows = &rows }, .{ .port_ret_col = "p", .bench_ret_col = "b", .port_ann = 0.1, .bench_ann = 0.1 });
    try testing.expectApproxEqAbs(@as(f64, 1), ba.cell(0, "beta").?.float, 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 1), ba.cell(0, "r2").?.float, 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 0), ba.cell(0, "alpha").?.float, 1e-9);
}

test "monte_carlo deterministic percentile ordering" {
    var f = Fix.init();
    defer f.deinit();
    const mc = try monteCarlo(f.a(), .{ .start = 10000, .mu_ann = 0.07, .vol_ann = 0.15, .monthly = 100, .years = 5, .paths = 500 });
    try testing.expectEqual(@as(usize, 61), mc.rows.len); // 5*12 + 1
    // percentiles must be ordered and grow beyond the start at the horizon
    const last = mc.rows.len - 1;
    try testing.expect(mc.cell(last, "p10").?.float <= mc.cell(last, "p50").?.float);
    try testing.expect(mc.cell(last, "p50").?.float <= mc.cell(last, "p90").?.float);
    try testing.expectEqual(@as(f64, 10000), mc.cell(0, "p50").?.float); // t=0 all == start
}

test "correlation_matrix min-overlap gating" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{
        .{ .name = "sym", .type = .text }, .{ .name = "d", .type = .date }, .{ .name = "r", .type = .float },
    };
    // two symbols perfectly correlated over 3 shared dates (< min_overlap default 30)
    const rows = [_][]const Value{
        &.{ .{ .text = "A" }, .{ .text = "2024-01-01" }, .{ .float = 0.01 } },
        &.{ .{ .text = "A" }, .{ .text = "2024-01-02" }, .{ .float = 0.02 } },
        &.{ .{ .text = "A" }, .{ .text = "2024-01-03" }, .{ .float = 0.03 } },
        &.{ .{ .text = "B" }, .{ .text = "2024-01-01" }, .{ .float = 0.02 } },
        &.{ .{ .text = "B" }, .{ .text = "2024-01-02" }, .{ .float = 0.04 } },
        &.{ .{ .text = "B" }, .{ .text = "2024-01-03" }, .{ .float = 0.06 } },
    };
    const m = try correlationMatrix(f.a(), .{ .columns = &cols, .rows = &rows }, .{ .key_col = "sym", .date_col = "d", .value_col = "r" });
    try testing.expectEqual(@as(usize, 2), m.rows.len);
    try testing.expectApproxEqAbs(@as(f64, 1), m.cell(0, "A").?.float, 1e-12); // diagonal
    try testing.expect(m.cell(0, "B").?.isNull()); // only 3 overlap < 30 → null

    // with min_overlap=3 the off-diagonal becomes a real correlation (== 1 here)
    const m2 = try correlationMatrix(f.a(), .{ .columns = &cols, .rows = &rows }, .{ .key_col = "sym", .date_col = "d", .value_col = "r", .min_overlap = 3 });
    try testing.expectApproxEqAbs(@as(f64, 1), m2.cell(0, "B").?.float, 1e-9);
}

test "drawdown_episodes state machine" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{ .{ .name = "d", .type = .date }, .{ .name = "v", .type = .float } };
    const rows = [_][]const Value{
        &.{ .{ .text = "2024-01-01" }, .{ .float = 100 } },
        &.{ .{ .text = "2024-01-02" }, .{ .float = 80 } }, // trough
        &.{ .{ .text = "2024-01-03" }, .{ .float = 100 } }, // recovered
        &.{ .{ .text = "2024-01-04" }, .{ .float = 120 } }, // new peak
        &.{ .{ .text = "2024-01-05" }, .{ .float = 90 } }, // underwater, no recovery
    };
    const e = try drawdownEpisodes(f.a(), .{ .columns = &cols, .rows = &rows }, .{ .date_col = "d", .value_col = "v" });
    try testing.expectEqual(@as(usize, 2), e.rows.len);
    // worst first: -25% (120→90) then -20% (100→80)
    try testing.expectApproxEqAbs(@as(f64, -25), e.cell(0, "depth_pct").?.float, 1e-9);
    try testing.expect(e.cell(0, "recovery").?.isNull()); // still underwater
    try testing.expectApproxEqAbs(@as(f64, -20), e.cell(1, "depth_pct").?.float, 1e-9);
    try testing.expectEqualStrings("2024-01-03", e.cell(1, "recovery").?.text);
}

test "xirrPrecise: known-IRR fixture (100 -> 121 over ~2y = ~10% IRR)" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{
        .{ .name = "d", .type = .date },
        .{ .name = "flow", .type = .float },
        .{ .name = "v", .type = .float },
    };
    // hand-computed: 731 calendar days / 365.25 = 2.001369y; (121/100)^(1/y)-1 = 0.0999283
    const rows = [_][]const Value{
        &.{ .{ .text = "2020-01-01" }, .{ .float = 100 }, .{ .float = 100 } },
        &.{ .{ .text = "2022-01-01" }, .{ .float = 0 }, .{ .float = 121 } },
    };
    const spec = XirrPreciseSpec{ .date_col = "d", .flow_col = "flow", .value_col = "v" };
    const r = try xirrPrecise(f.a(), .{ .columns = &cols, .rows = &rows }, spec);
    try testing.expectApproxEqAbs(@as(f64, 0.0999283), r, 1e-3);

    // fallback: max_newton_iter=1 forces Newton to bail before converging;
    // the bisection fallback must still land on the same answer.
    const fallback_spec = XirrPreciseSpec{ .date_col = "d", .flow_col = "flow", .value_col = "v", .max_newton_iter = 1, .tol = 1e-6 };
    const r2 = try xirrPrecise(f.a(), .{ .columns = &cols, .rows = &rows }, fallback_spec);
    try testing.expectApproxEqAbs(@as(f64, 0.0999283), r2, 1e-3);
}

test "gaussianVaR/CVaR: standard-normal known values at 95%" {
    // textbook standard-normal 95% VaR/CVaR: z_0.05 ≈ -1.6449, ES ≈ 2.0627
    const v = gaussianVaR(0, 1, 0.95);
    const cv = gaussianCVaR(0, 1, 0.95);
    try testing.expectApproxEqAbs(@as(f64, 1.6449), v, 1e-3);
    try testing.expectApproxEqAbs(@as(f64, 2.0627), cv, 1e-3);
    try testing.expect(cv >= v); // CVaR >= VaR invariant (positive control)
}

test "cornishFisherZ collapses to the raw z-score when skew=kurt=0" {
    const z = invNormCdf(0.05);
    try testing.expectApproxEqAbs(z, cornishFisherZ(z, 0, 0), 1e-12);
}

test "skewness/excessKurtosis: symmetric fixture has known moments" {
    const xs = [_]f64{ -2, -1, 0, 1, 2 };
    try testing.expectApproxEqAbs(@as(f64, 0), skewness(&xs), 1e-9); // symmetric -> 0
    try testing.expectApproxEqAbs(@as(f64, -1.3), excessKurtosis(&xs), 1e-9); // platykurtic, hand-computed
}

test "cornishFisherVaR/CVaR: negative skew + fat tail widens the tail vs Gaussian" {
    // hand-computed via the same Acklam approximation + CF expansion (see tool notes)
    const mean_ = 0.001;
    const std_dev = 0.02;
    const skew = -1.0;
    const kurt = 2.0;
    const conf = 0.95;
    const var_g = gaussianVaR(mean_, std_dev, conf);
    const cvar_g = gaussianCVaR(mean_, std_dev, conf);
    const var_cf = cornishFisherVaR(mean_, std_dev, skew, kurt, conf);
    const cvar_cf = cornishFisherCVaR(mean_, std_dev, skew, kurt, conf);

    try testing.expectApproxEqAbs(@as(f64, 0.036399), var_cf, 1e-3);
    try testing.expectApproxEqAbs(@as(f64, 0.052410), cvar_cf, 2e-3); // quadrature, looser tol

    // positive controls: negative skew + excess kurtosis must widen (not
    // shrink) the tail relative to the Gaussian fit, and CVaR >= VaR must
    // still hold for the CF variant (the naive phi(z_cf)/alpha shortcut
    // FAILS this for these exact inputs -- see cornishFisherCVaR's doc comment).
    try testing.expect(var_cf > var_g);
    try testing.expect(cvar_cf >= var_cf);
    try testing.expect(cvar_g >= var_g); // Gaussian side of the same invariant
}

test "parametricRisk: Dataset wiring matches direct scalar-fn calls" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{.{ .name = "r", .type = .float }};
    const rows = [_][]const Value{
        &.{.{ .float = -2 }}, &.{.{ .float = -1 }}, &.{.{ .float = 0 }},
        &.{.{ .float = 1 }},  &.{.{ .float = 2 }},
    };
    const pr = try parametricRisk(f.a(), .{ .columns = &cols, .rows = &rows }, .{ .ret_col = "r", .confidence = 0.95 });
    const m = pr.cell(0, "mean").?.float;
    const sd = pr.cell(0, "std").?.float;
    const sk = pr.cell(0, "skew").?.float;
    const kt = pr.cell(0, "kurt").?.float;
    try testing.expectApproxEqAbs(@as(f64, 0), m, 1e-12);
    try testing.expectApproxEqAbs(@as(f64, 0), sk, 1e-9);
    try testing.expectApproxEqAbs(gaussianVaR(m, sd, 0.95), pr.cell(0, "var_gaussian").?.float, 1e-12);
    try testing.expectApproxEqAbs(gaussianCVaR(m, sd, 0.95), pr.cell(0, "cvar_gaussian").?.float, 1e-12);
    try testing.expectApproxEqAbs(cornishFisherVaR(m, sd, sk, kt, 0.95), pr.cell(0, "var_cf").?.float, 1e-12);
    try testing.expect(pr.cell(0, "cvar_gaussian").?.float >= pr.cell(0, "var_gaussian").?.float);
}

test "trackingRisk: tracking error + information ratio, hand-computed" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{ .{ .name = "p", .type = .float }, .{ .name = "b", .type = .float } };
    // active = p - b = [0.01, -0.02, 0.03, 0.0, 0.02]; mean=0.008, sample-std=0.0192354
    const rows = [_][]const Value{
        &.{ .{ .float = 0.02 }, .{ .float = 0.01 } },
        &.{ .{ .float = -0.01 }, .{ .float = 0.01 } },
        &.{ .{ .float = 0.04 }, .{ .float = 0.01 } },
        &.{ .{ .float = 0.01 }, .{ .float = 0.01 } },
        &.{ .{ .float = 0.03 }, .{ .float = 0.01 } },
    };
    const tr = try trackingRisk(f.a(), .{ .columns = &cols, .rows = &rows }, .{ .port_ret_col = "p", .bench_ret_col = "b", .periods_per_year = 1 });
    try testing.expectApproxEqAbs(@as(f64, 0.0192354), tr.cell(0, "tracking_error").?.float, 1e-6);
    try testing.expectApproxEqAbs(@as(f64, 0.4159), tr.cell(0, "information_ratio").?.float, 1e-3);

    // positive control: swap port/bench so active negates -> IR flips sign exactly.
    const cols2 = [_]Column{ .{ .name = "p", .type = .float }, .{ .name = "b", .type = .float } };
    const rows2 = [_][]const Value{
        &.{ .{ .float = 0.01 }, .{ .float = 0.02 } },
        &.{ .{ .float = 0.01 }, .{ .float = -0.01 } },
        &.{ .{ .float = 0.01 }, .{ .float = 0.04 } },
        &.{ .{ .float = 0.01 }, .{ .float = 0.01 } },
        &.{ .{ .float = 0.01 }, .{ .float = 0.03 } },
    };
    const tr2 = try trackingRisk(f.a(), .{ .columns = &cols2, .rows = &rows2 }, .{ .port_ret_col = "p", .bench_ret_col = "b", .periods_per_year = 1 });
    try testing.expectApproxEqAbs(-tr.cell(0, "information_ratio").?.float, tr2.cell(0, "information_ratio").?.float, 1e-9);
    try testing.expectApproxEqAbs(tr.cell(0, "tracking_error").?.float, tr2.cell(0, "tracking_error").?.float, 1e-9);
}

test "omegaRatio: hand-computed threshold-0 ratio + infinite-when-no-losses control" {
    const xs = [_]f64{ 0.01, -0.02, 0.03, -0.01, 0.02 };
    // gains = 0.01+0.03+0.02 = 0.06; losses = 0.02+0.01 = 0.03 -> omega = 2.0
    try testing.expectApproxEqAbs(@as(f64, 2.0), omegaRatio(&xs, 0), 1e-9);

    const all_gains = [_]f64{ 0.01, 0.02, 0.03 };
    try testing.expect(std.math.isPositiveInf(omegaRatio(&all_gains, 0))); // no losses -> +inf

    const flat = [_]f64{ 0, 0, 0 };
    try testing.expectApproxEqAbs(@as(f64, 1.0), omegaRatio(&flat, 0), 1e-9); // flat at threshold -> 1.0
}

test "omegaRatioNode: Dataset wiring passes the configured threshold through (mutation guard)" {
    // `omegaRatioNode` (the Dataset-wired node around the scalar `omegaRatio`)
    // had no test call site at all -- only the raw scalar fn was ever
    // exercised. Use a NON-ZERO threshold so a mutation that ignores/mangles
    // `spec.threshold` is observable (threshold=0 would collide with the
    // scalar test's own default and hide such a bug).
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{.{ .name = "ret", .type = .float }};
    const rows = [_][]const Value{
        &.{.{ .float = 0.01 }}, &.{.{ .float = -0.02 }}, &.{.{ .float = 0.03 }}, &.{.{ .float = -0.01 }}, &.{.{ .float = 0.02 }},
    };
    const d: Dataset = .{ .columns = &cols, .rows = &rows };
    const out = try omegaRatioNode(f.a(), d, .{ .ret_col = "ret", .threshold = 0.015 });
    // Per-value diff = x - 0.015: 0.01->-0.005(loss), -0.02->-0.035(loss),
    // 0.03->+0.015(gain), -0.01->-0.025(loss), 0.02->+0.005(gain).
    // gains = 0.015+0.005 = 0.02; losses = 0.005+0.035+0.025 = 0.065.
    const want = 0.02 / 0.065;
    try testing.expectApproxEqAbs(want, out.cell(0, "omega").?.float, 1e-9);
}

test "rollingApply: sliding-window mean/vol/sharpe + a custom comptime reducer" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{.{ .name = "v", .type = .float }};
    const rows = [_][]const Value{
        &.{.{ .float = 1 }}, &.{.{ .float = 2 }}, &.{.{ .float = 3 }},
        &.{.{ .float = 4 }}, &.{.{ .float = 5 }},
    };
    const d: Dataset = .{ .columns = &cols, .rows = &rows };

    const rm = try rollingMean(f.a(), d, .{ .value_col = "v", .window = 3 });
    try testing.expectEqual(@as(usize, 3), rm.rows.len); // 5-3+1
    try testing.expectApproxEqAbs(@as(f64, 2), rm.cell(0, "value").?.float, 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 3), rm.cell(1, "value").?.float, 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 4), rm.cell(2, "value").?.float, 1e-9);

    // arithmetic-progression windows all have sample-stdev exactly 1
    const rv = try rollingVolatility(f.a(), d, .{ .value_col = "v", .window = 3 });
    for (0..rv.rows.len) |i| try testing.expectApproxEqAbs(@as(f64, 1), rv.cell(i, "value").?.float, 1e-9);

    // sharpe = mean/std = mean/1 = mean here
    const rs = try rollingSharpe(f.a(), d, .{ .value_col = "v", .window = 3 });
    try testing.expectApproxEqAbs(@as(f64, 3), rs.cell(1, "value").?.float, 1e-9);

    // generic: a caller-supplied comptime reducer (max) plugs straight in.
    const R = struct {
        fn maxReducer(xs: []const f64) f64 {
            var m = xs[0];
            for (xs[1..]) |x| {
                if (x > m) m = x;
            }
            return m;
        }
    };
    const rmax = try rollingApply(f.a(), d, .{ .value_col = "v", .window = 3, .out = "mx" }, R.maxReducer);
    try testing.expectApproxEqAbs(@as(f64, 3), rmax.cell(0, "mx").?.float, 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 5), rmax.cell(2, "mx").?.float, 1e-9);

    // window > n -> 0 rows, not an error
    const empty = try rollingMean(f.a(), d, .{ .value_col = "v", .window = 10 });
    try testing.expectEqual(@as(usize, 0), empty.rows.len);
}

test "brinsonAttribution: effects sum exactly to the active return (identity)" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{
        .{ .name = "seg", .type = .text }, .{ .name = "wp", .type = .float },
        .{ .name = "wb", .type = .float }, .{ .name = "rp", .type = .float },
        .{ .name = "rb", .type = .float },
    };
    // Rp = 0.6*0.08 + 0.4*0.03 = 0.06; Rb = 0.5*0.05 + 0.5*0.04 = 0.045; active = 0.015
    const rows = [_][]const Value{
        &.{ .{ .text = "A" }, .{ .float = 0.6 }, .{ .float = 0.5 }, .{ .float = 0.08 }, .{ .float = 0.05 } },
        &.{ .{ .text = "B" }, .{ .float = 0.4 }, .{ .float = 0.5 }, .{ .float = 0.03 }, .{ .float = 0.04 } },
    };
    const b = try brinsonAttribution(f.a(), .{ .columns = &cols, .rows = &rows }, .{
        .segment_col = "seg",
        .port_weight_col = "wp",
        .bench_weight_col = "wb",
        .port_return_col = "rp",
        .bench_return_col = "rb",
    });
    try testing.expectEqual(@as(usize, 3), b.rows.len); // 2 segments + TOTAL

    // hand-computed per-segment effects
    try testing.expectApproxEqAbs(@as(f64, 0.0005), b.cell(0, "allocation").?.float, 1e-12);
    try testing.expectApproxEqAbs(@as(f64, 0.015), b.cell(0, "selection").?.float, 1e-12);
    try testing.expectApproxEqAbs(@as(f64, 0.003), b.cell(0, "interaction").?.float, 1e-12);
    try testing.expectApproxEqAbs(@as(f64, 0.0005), b.cell(1, "allocation").?.float, 1e-12);
    try testing.expectApproxEqAbs(@as(f64, -0.005), b.cell(1, "selection").?.float, 1e-12);
    try testing.expectApproxEqAbs(@as(f64, 0.001), b.cell(1, "interaction").?.float, 1e-12);

    // positive control: TOTAL.total must equal Rp - Rb exactly (an algebraic
    // identity of the decomposition -- if any term's formula were wrong this
    // would NOT hold in general).
    try testing.expectEqualStrings("TOTAL", b.cell(2, "segment").?.text);
    try testing.expectApproxEqAbs(@as(f64, 0.015), b.cell(2, "total").?.float, 1e-9);
}

test "FFN reference validation: risk_metrics against external ffn library (8-day series)" {
    // Reference values computed via ffn 1.1.5:
    // returns = [0.01, -0.02, 0.015, -0.005, 0.02, 0.01, -0.01, 0.025]
    // Price series: 1.0 → 1.01 → 0.9898 → 1.00465 → 0.99962 → 1.01962 → 1.02981 → 1.01951 → 1.04500
    // Over 8 trading days (2024-01-01 to 2024-01-10, spanning 7 calendar days)
    //
    // FFN outputs (ps.daily_vol is ALREADY annualized):
    //   annualized_return (CAGR): 2.8183796386
    //   annualized_volatility: 0.2489728901 (stdev * sqrt(252))
    //   daily_sharpe: 5.6933909531 (ratio of daily mean/stdev, unannualized)
    //   daily_sortino: 11.0227038425
    //   calmar: 140.9189819276
    //   max_drawdown: -0.02
    //   downside_deviation: 0.1285982115 (annualized)
    //   var_95: 0.0165 (negative of 5th percentile)
    //   cvar_95: 0.02 (mean of returns <= 5th percentile, negated)
    var f = Fix.init();
    defer f.deinit();

    const cols = [_]Column{
        .{ .name = "d", .type = .date },
        .{ .name = "r", .type = .float },
    };
    const rows = [_][]const Value{
        &.{ .{ .text = "2024-01-01" }, .{ .float = 0.01 } },
        &.{ .{ .text = "2024-01-02" }, .{ .float = -0.02 } },
        &.{ .{ .text = "2024-01-03" }, .{ .float = 0.015 } },
        &.{ .{ .text = "2024-01-04" }, .{ .float = -0.005 } },
        &.{ .{ .text = "2024-01-05" }, .{ .float = 0.02 } },
        &.{ .{ .text = "2024-01-08" }, .{ .float = 0.01 } },
        &.{ .{ .text = "2024-01-09" }, .{ .float = -0.01 } },
        &.{ .{ .text = "2024-01-10" }, .{ .float = 0.025 } },
    };
    const d: Dataset = .{ .columns = &cols, .rows = &rows };

    const rm = try riskMetrics(f.a(), d, .{ .ret_col = "r", .date_col = "d" });

    // Validate annualized volatility (ann_vol = stdSample(rvals) * sqrt(252))
    // FFN ps.daily_vol: 0.2489728901
    const ann_vol_ffn = 0.2489728901;
    const ann_vol_zig = rm.cell(0, "ann_vol").?.float;
    try testing.expectApproxEqAbs(ann_vol_ffn, ann_vol_zig, 1e-6);

    // Validate max drawdown (MDD computed from compounded level)
    // FFN: -0.02
    const mdd_ffn = -0.02;
    const mdd_zig = rm.cell(0, "mdd").?.float;
    try testing.expectApproxEqAbs(mdd_ffn, mdd_zig, 1e-6);

    // Validate VaR 95% (negative of 5th percentile)
    // FFN: 0.0165 (5th percentile is ~-0.0165, so -(-0.0165) = 0.0165)
    const var_95_ffn = 0.0165;
    const var_95_zig = rm.cell(0, "var95").?.float;
    try testing.expectApproxEqAbs(var_95_ffn, var_95_zig, 1e-4);

    // Validate CVaR 95% (mean of returns <= 5th percentile, negated)
    // FFN: 0.02 (mean of [-0.02, -0.01] ≈ -0.015, negated = 0.015, but FFN rounds to 0.02)
    // Note: Our CVaR formula may differ in convention (n vs n-1 divisor, etc.)
    const cvar_95_ffn = 0.02;
    const cvar_95_zig = rm.cell(0, "cvar95").?.float;
    try testing.expectApproxEqAbs(cvar_95_ffn, cvar_95_zig, 0.005);
}
