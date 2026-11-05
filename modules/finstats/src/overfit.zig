// SPDX-License-Identifier: MIT

//! Probability of backtest overfitting (PBO) by combinatorially symmetric
//! cross-validation, after Bailey, Borwein, Lopez de Prado and Zhu, "The
//! Probability of Backtest Overfitting" (Journal of Computational Finance,
//! 2017); the counterpart of ffn's `calc_prob_backtest_overfitting`.
//!
//! The input is the full matrix of a strategy search: one slice of period
//! returns per strategy, all the same length (`error.LengthMismatch`
//! otherwise). The periods are cut into `n_blocks` contiguous blocks of
//! `T / n_blocks` periods each (the surplus periods at the END are dropped). For
//! every way of choosing half of the blocks as in-sample, in lexicographic
//! order of block numbers, the metric is taken per strategy on the in-sample
//! blocks (concatenated in time order) and on the remaining out-of-sample
//! blocks. The in-sample winner (largest metric, the first strategy on a tie)
//! gets its out-of-sample rank among all `N` strategies (tied strategies share
//! the average rank). With `omega = rank / (N + 1)` the combination's logit is
//! `ln(omega / (1 - omega))`. PBO is the share of combinations whose logit is
//! `<= 0`, i.e. where the in-sample winner is at or below the out-of-sample
//! median. Pure noise gives about one half (a single draw can sit far from it),
//! a strategy that is better in every part of the sample gives 0.
//!
//! Undefined cases. These answer NaN (PBO and mean rank; `logits` empty), not an
//! error: `n_blocks` odd or below 2, fewer than 2 strategies, fewer periods
//! than blocks (a block would be empty), no strategies at all. (ffn raises
//! `ValueError` for the same input.) If the metric is not finite for any strategy
//! on either half of any combination, that combination's logit is NaN and the
//! PBO and the mean rank are NaN too: an undefined combination is not dropped
//! (same as ffn). Size is an error, not NaN: see `max_combinations` and
//! `max_work`, both checked before anything is allocated.
//!
//! The default metric `sharpePerPeriod` skips NaN values, like ffn's, so a NaN
//! hole in a series is NOT a NaN answer there; a metric of your own sees the
//! half as it is (NaN included) and decides.
//!
//! Every reference number was produced by running ffn 1.3.0 as a black box
//! (`tools/overfit_oracle.py`, which lists the conventions it measured).

const std = @import("std");
const core = @import("core.zig");
const slice = @import("slice.zig");

pub const Error = slice.Error;

/// Most block combinations C(n_blocks, n_blocks / 2) one call will evaluate:
/// 2^20 (16 blocks give 12 870, 22 blocks 705 432, 24 blocks 2 704 156 and are
/// refused). Above it `error.TooLarge`.
pub const max_combinations: usize = 1 << 20;

/// Most `combinations * strategies * periods` (periods counted after the surplus
/// is dropped) one call will do, 2^31: the true element count is about half of
/// that (every half is measured once). Above it `error.TooLarge`.
pub const max_work: usize = 1 << 31;

/// Most `combinations * strategies` metric values the call keeps in memory
/// (2^25 `f64` = 256 MiB). Above it `error.TooLarge`.
pub const max_cells: usize = 1 << 25;

const nan = std.math.nan(f64);

/// The default metric (ffn's): the per-period Sharpe ratio, mean over sample
/// standard deviation (n - 1), of the values that are not NaN. NaN if fewer
/// than 2 values are left, if they are all equal (the spread is zero), or if
/// the spread or the result is not finite (values near the f64 limit).
pub fn sharpePerPeriod(xs: []const f64) f64 {
    var n: usize = 0;
    var sum: f64 = 0;
    var lo: f64 = std.math.inf(f64);
    var hi: f64 = -std.math.inf(f64);
    for (xs) |x| {
        if (std.math.isNan(x)) continue;
        n += 1;
        sum += x;
        lo = @min(lo, x);
        hi = @max(hi, x);
    }
    if (n < 2 or lo == hi) return nan;
    const m = sum / @as(f64, @floatFromInt(n));
    var ss: f64 = 0;
    for (xs) |x| {
        if (std.math.isNan(x)) continue;
        ss += (x - m) * (x - m);
    }
    const sd = @sqrt(ss / @as(f64, @floatFromInt(n - 1)));
    if (!(sd > 0) or !std.math.isFinite(sd)) return nan;
    const r = m / sd;
    return if (std.math.isFinite(r)) r else nan;
}

/// What a PBO run found, with the per-combination detail (ffn's `full_output`).
pub const Detail = struct {
    /// Share of combinations with a logit `<= 0`; NaN if undefined (see above).
    pbo: f64,
    /// Mean of `omega = rank / (N + 1)` of the in-sample winner over all
    /// combinations; 0.5 is the middle, near 1 the winner stays on top.
    mean_oos_rank: f64,
    /// One logit per combination, in lexicographic order of the in-sample
    /// block numbers; NaN for an undefined combination. Empty if the input
    /// itself was undefined. Owned: free it with `deinit`.
    logits: []f64,

    /// Frees `logits`.
    pub fn deinit(self: Detail, a: std.mem.Allocator) void {
        a.free(self.logits);
    }
};

const Plan = struct {
    n: usize, // strategies
    len: usize, // periods per block
    half: usize, // periods in one half
    combos: usize,
};

/// C(s, s / 2) for an even `s >= 2`, or null if it exceeds `max_combinations`.
fn combinations(s: usize) ?usize {
    const k = s / 2;
    var c: usize = 1;
    var i: usize = 1;
    while (i <= k) : (i += 1) {
        // C(s - k + i, i) = C(s - k + i - 1, i - 1) * (s - k + i) / i, exactly.
        const f = s - k + i;
        const p, const ov = @mulWithOverflow(c, f);
        if (ov != 0) return null;
        c = p / i;
        if (c > max_combinations) return null;
    }
    return c;
}

/// Validates the shape. Null: undefined input (NaN answer).
fn plan(trials: []const []const f64, n_blocks: usize) Error!?Plan {
    if (trials.len == 0) return null;
    const t = trials[0].len;
    for (trials) |x| if (x.len != t) return error.LengthMismatch;
    if (n_blocks < 2 or n_blocks % 2 != 0 or trials.len < 2 or n_blocks > t) return null;
    const combos = combinations(n_blocks) orelse return error.TooLarge;
    const len = t / n_blocks;
    const used = len * n_blocks; // <= t
    const cells, const ov1 = @mulWithOverflow(combos, trials.len);
    if (ov1 != 0 or cells > max_cells) return error.TooLarge;
    const work, const ov2 = @mulWithOverflow(cells, used);
    if (ov2 != 0 or work > max_work) return error.TooLarge;
    return .{ .n = trials.len, .len = len, .half = used / 2, .combos = combos };
}

/// Steps `c` (strictly increasing indices below `s`) to the next combination
/// in lexicographic order; false after the last one.
fn nextCombination(c: []usize, s: usize) bool {
    var i = c.len;
    while (i > 0) {
        i -= 1;
        if (c[i] < s - (c.len - i)) {
            c[i] += 1;
            var j = i + 1;
            while (j < c.len) : (j += 1) c[j] = c[j - 1] + 1;
            return true;
        }
    }
    return false;
}

fn run(
    a: std.mem.Allocator,
    trials: []const []const f64,
    n_blocks: usize,
    p: Plan,
    comptime metric: fn ([]const f64) f64,
    logits: ?[]f64,
) std.mem.Allocator.Error!struct { pbo: f64, mean_rank: f64 } {
    const comb = try a.alloc(usize, n_blocks / 2);
    defer a.free(comb);
    const buf = try a.alloc(f64, p.half);
    defer a.free(buf);
    const table = try a.alloc(f64, p.combos * p.n);
    defer a.free(table);

    // The metric of every strategy on every in-sample half. The out-of-sample
    // half of combination i is the in-sample half of combination combos - 1 - i
    // (the complement of the i-th combination in lexicographic order).
    for (comb, 0..) |*c, i| c.* = i;
    var ci: usize = 0;
    while (true) : (ci += 1) {
        for (trials, 0..) |x, j| {
            var w: usize = 0;
            for (comb) |b| {
                @memcpy(buf[w..][0..p.len], x[b * p.len ..][0..p.len]);
                w += p.len;
            }
            table[ci * p.n + j] = metric(buf);
        }
        if (!nextCombination(comb, n_blocks)) break;
    }

    var le: usize = 0;
    var omega_sum: f64 = 0;
    var undefined_seen = false;
    const denom: f64 = @floatFromInt(2 * (p.n + 1));
    for (0..p.combos) |i| {
        const is = table[i * p.n ..][0..p.n];
        const os = table[(p.combos - 1 - i) * p.n ..][0..p.n];
        var ok = true;
        for (is) |v| ok = ok and std.math.isFinite(v);
        for (os) |v| ok = ok and std.math.isFinite(v);
        if (!ok) {
            undefined_seen = true;
            if (logits) |l| l[i] = nan;
            continue;
        }
        var win: usize = 0;
        for (is, 0..) |v, j| if (v > is[win]) {
            win = j;
        };
        // Doubled average rank (1-based): 2 * smaller + equal (itself included) + 1.
        var smaller: usize = 0;
        var equal: usize = 0;
        for (os) |v| {
            if (v < os[win]) smaller += 1 else if (v == os[win]) equal += 1;
        }
        const rank2 = 2 * smaller + equal + 1;
        const omega = @as(f64, @floatFromInt(rank2)) / denom;
        if (rank2 <= p.n + 1) le += 1;
        omega_sum += omega;
        if (logits) |l| l[i] = @log(omega / (1.0 - omega));
    }
    if (undefined_seen) return .{ .pbo = nan, .mean_rank = nan };
    const c: f64 = @floatFromInt(p.combos);
    return .{ .pbo = @as(f64, @floatFromInt(le)) / c, .mean_rank = omega_sum / c };
}

/// Probability of backtest overfitting of the search `trials` (one return
/// slice per strategy) with `n_blocks` blocks (even, at least 2) and the
/// performance measure `metric` (larger is better; it is called on a slice of
/// concatenated blocks, in time order). Use `sharpePerPeriod` for ffn's
/// default. The result is in `[0, 1]`, or NaN for the undefined cases listed in
/// the module comment. `error.LengthMismatch` for slices of different lengths,
/// `error.TooLarge` past `max_combinations`, `max_work` or `max_cells` (before
/// allocating), `error.OutOfMemory`.
pub fn probBacktestOverfitting(
    a: std.mem.Allocator,
    trials: []const []const f64,
    n_blocks: usize,
    comptime metric: fn ([]const f64) f64,
) Error!f64 {
    const p = (try plan(trials, n_blocks)) orelse return nan;
    return (try run(a, trials, n_blocks, p, metric, null)).pbo;
}

/// Like `probBacktestOverfitting`, but also returns the mean out-of-sample
/// rank and the logit of every combination (ffn's `full_output`). The caller
/// owns `logits`: call `Detail.deinit`.
pub fn probBacktestOverfittingDetail(
    a: std.mem.Allocator,
    trials: []const []const f64,
    n_blocks: usize,
    comptime metric: fn ([]const f64) f64,
) Error!Detail {
    const p = (try plan(trials, n_blocks)) orelse
        return .{ .pbo = nan, .mean_oos_rank = nan, .logits = &.{} };
    const logits = try a.alloc(f64, p.combos);
    errdefer a.free(logits);
    const r = try run(a, trials, n_blocks, p, metric, logits);
    return .{ .pbo = r.pbo, .mean_oos_rank = r.mean_rank, .logits = logits };
}
