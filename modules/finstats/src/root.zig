// SPDX-License-Identifier: MIT
//! finstats — portfolio/financial statistics over `dataset`: xirr, TWR,
//! risk metrics (vol/VaR/CVaR/Sharpe/Sortino/Calmar), beta/alpha, Monte-Carlo,
//! correlation matrix, drawdown episodes. f64 throughout (statistics, not ledger).
//!
//! Pure functions over `Dataset`. Scalar math fns (xirr/annualize/quantile)
//! return the number directly (KPI reduce nodes call them); series/table
//! producers return a `Dataset`. Algorithms + constants are a faithful lift of
//! the seed (wgs `src/finance.zig`, itself a faithful port of poc-wf-analytic's
//! `reader.zig`); the numeric behaviour is kept EXACT — VaR/CVaR are historical
//! (empirical), the Monte-Carlo PRNG is fixed-seed deterministic. See README
//! `Provenance:` for the lineage.

const std = @import("std");
const dsmod = @import("dataset");
const Dataset = dsmod.Dataset;
const Column = dsmod.Column;
const Value = dsmod.Value;

pub const meta = .{
    .status = .extract, // seed: wgs src/finance.zig
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

/// Linear-interpolation quantile of a pre-sorted slice (exact port).
pub fn quantileSorted(sorted: []const f64, q: f64) f64 {
    const n = sorted.len;
    if (n == 0) return 0;
    if (n == 1) return sorted[0];
    const pos = q * @as(f64, @floatFromInt(n - 1));
    const lo: usize = @intFromFloat(@floor(pos));
    const hi: usize = @intFromFloat(@ceil(pos));
    const frac = pos - @floor(pos);
    return sorted[lo] * (1.0 - frac) + sorted[hi] * frac;
}

/// Quantile of an unsorted slice (sorts a copy).
pub fn quantile(a: std.mem.Allocator, xs: []const f64, q: f64) Error!f64 {
    const s = try a.dupe(f64, xs);
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

// ── monte_carlo (GBM-ish monthly, Box-Muller — exact port, seeded) ──────────

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
