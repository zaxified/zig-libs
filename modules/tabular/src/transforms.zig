// SPDX-License-Identifier: MIT
//! Dataset algebra **Tier 0** — the pure `dataset → dataset` primitives that
//! cover the bulk of dataset transform workloads. Each is a pure function of
//! `(allocator, Dataset, Spec) → Dataset`; nothing is mutated in place. The
//! allocator is normally a caller-owned arena for the whole pipeline (see the
//! memory model note in `dataset`).
//!
//! T0 set: map · aggregate(+fx) · weighted_group_sum(+fx) · sort (multi-key) ·
//! top_n / top_n_with_tail · page · pivot (numeric-aware col ordering) ·
//! unpivot · resample · reduce · clamp_range · format · filter / filterBy ·
//! select / drop / rename · dropna / fillna · tail · nlargest · sample ·
//! concatByName · valueCounts · describe · clip · replace · cut.
//!
//! `fx-convert-before-sum` is first-class on aggregate/weighted_group_sum — the
//! recurring multi-currency correctness fix (a null per-row rate means 1.0).

const std = @import("std");
const ds = @import("dataset");
const keys = @import("keys.zig");
const Dataset = ds.Dataset;
const Column = ds.Column;
const ColumnType = ds.ColumnType;
const Value = ds.Value;

/// `TooLarge`: `pivot` would produce more than `max_pivot_cells` cells. The
/// limit is a constant, not a spec field -- specs come from user files.
pub const Error = error{ NoSuchColumn, OutOfMemory, TooLarge };

/// Most cells (`groups x aggs.len`) one `aggregate` may build accumulators for.
/// Each cell is a ~280-byte accumulator plus an output `Value`; `aggs` is spec
/// data and the group count is data cardinality, so the product is checked
/// as groups appear (before their accumulators are allocated). 2^24 cells.
pub const max_aggregate_cells: usize = 1 << 24;

/// Most output cells (`rows x melted columns`) one `unpivot` may produce. The
/// melted-column list is spec data and may repeat a column. 2^22 cells.
pub const max_unpivot_cells: usize = 1 << 22;

/// Most cells (`distinct row keys x distinct col keys`) one `pivot` may produce.
/// The matrix is dense and BOTH key counts come from the data, so a few
/// thousand rows with all-distinct keys are millions of cells (and `a.print`
/// calls); one more than this is `error.TooLarge`. 2^22 cells.
pub const max_pivot_cells: usize = 1 << 22;

// ── shared helpers ──────────────────────────────────────────────────────────

fn mustIndex(d: Dataset, name: []const u8) Error!usize {
    return d.columnIndex(name) orelse Error.NoSuchColumn;
}

/// Effective fx rate for a row: value in `rate_col` (null / missing → 1.0).
fn fxRate(row: []const Value, rate_idx: ?usize) f64 {
    const ri = rate_idx orelse return 1.0;
    return row[ri].asFloat() orelse 1.0;
}

/// Append a value's canonical key bytes (for group-key strings).
fn appendValueKey(a: std.mem.Allocator, buf: *std.ArrayList(u8), v: Value) Error!void {
    switch (v) {
        .null => try buf.append(a, 0),
        .bool => |b| try buf.append(a, if (b) '1' else '0'),
        .int => |i| try buf.print(a, "{d}", .{i}),
        .float => |f| try buf.print(a, "{d}", .{f}),
        .text => |t| try buf.appendSlice(a, t),
        .decimal => |r| try buf.print(a, "d{d}", .{r}), // raw i128, exact key
    }
}

// ── map ─────────────────────────────────────────────────────────────────────

pub const Operand = union(enum) {
    col: []const u8,
    num: f64,
};

/// `abs` and `sqrt` are unary: they read `lhs` and ignore `rhs`.
pub const BinOp = enum { add, sub, mul, div, min, max, abs, sqrt };

/// What `map` writes when an operand is missing (null or non-numeric) or the
/// result is undefined (`div` by zero, `sqrt` of a negative number).
pub const OnMissing = enum {
    /// A missing operand reads as 0 and an undefined result is 0 — the
    /// historical behaviour, kept as the default.
    zero,
    /// Null in, null out; an undefined result is null (SQL's rule, and
    /// pandas' NaN propagation).
    null,
};

pub const MapSpec = struct {
    /// Name of the appended column.
    out: []const u8,
    out_type: ColumnType = .float,
    lhs: Operand,
    op: BinOp,
    /// Ignored by the unary ops (`abs`, `sqrt`).
    rhs: Operand = .{ .num = 0 },
    on_missing: OnMissing = .zero,
};

/// Append `out = lhs op rhs` as a new float column (per-row arithmetic:
/// pl = mv - cost, base = gross * fx, …). Multi-term expressions compose via
/// successive `map` steps. `min`/`max` follow IEEE `@min`/`@max` (a NaN
/// operand loses to a number).
pub fn map(a: std.mem.Allocator, d: Dataset, spec: MapSpec) Error!Dataset {
    try keys.checkRect(d);
    const li: ?usize = switch (spec.lhs) {
        .col => |c| try mustIndex(d, c),
        .num => null,
    };
    const unary = spec.op == .abs or spec.op == .sqrt;
    const rgi: ?usize = if (unary) null else switch (spec.rhs) {
        .col => |c| try mustIndex(d, c),
        .num => null,
    };

    const cols = try a.alloc(Column, d.columns.len + 1);
    @memcpy(cols[0..d.columns.len], d.columns);
    cols[d.columns.len] = .{ .name = spec.out, .type = spec.out_type };

    const rows = try a.alloc([]const Value, d.rows.len);
    const cells = try a.alloc(Value, d.rows.len * cols.len);
    const missing: Value = if (spec.on_missing == .null) .null else .{ .float = 0 };
    for (d.rows, 0..) |r, ri| {
        const nr = cells[ri * cols.len ..][0..cols.len];
        @memcpy(nr[0..d.columns.len], r);
        rows[ri] = nr;
        const lo: ?f64 = if (li) |i| r[i].asFloat() else spec.lhs.num;
        const ro: ?f64 = if (unary) 0 else if (rgi) |i| r[i].asFloat() else spec.rhs.num;
        if (spec.on_missing == .null and (lo == null or ro == null)) {
            nr[d.columns.len] = .null;
            continue;
        }
        const lv = lo orelse 0;
        const rv = ro orelse 0;
        nr[d.columns.len] = switch (spec.op) {
            .add => .{ .float = lv + rv },
            .sub => .{ .float = lv - rv },
            .mul => .{ .float = lv * rv },
            .div => if (rv == 0) missing else .{ .float = lv / rv },
            .min => .{ .float = @min(lv, rv) },
            .max => .{ .float = @max(lv, rv) },
            .abs => .{ .float = @abs(lv) },
            .sqrt => if (lv < 0) missing else .{ .float = @sqrt(lv) },
        };
    }
    return .{ .columns = cols, .rows = rows };
}

// ── aggregate (+fx) ─────────────────────────────────────────────────────────

/// `sum`/`mean`/`count` count every row of the group (a null or non-numeric
/// cell adds 0 to `sum` and 1 to `count` — historical behaviour, unlike
/// pandas' skip-NA). The statistics added 2026-10-04 skip MISSING values
/// (null, non-numeric, NaN), as pandas does by default:
///   `std`/`var` — sample (n−1, pandas' default `ddof=1`), null below 2 values;
///   `median`, `quantile` (`AggCol.q`) — linear interpolation between order
///     statistics (numpy/pandas default, Hyndman–Fan type 7), null when empty;
///   `nunique` — distinct non-missing values of any kind, text included
///     (pandas `nunique()`, `dropna=True`); int 1 and float 1.0 are one value, text
///     "1" another, and a `.decimal` equal to them is the same value too;
///   `sum_exact` — i128 sum at `dataset.decimal_scale`, output `.decimal`:
///     `.decimal` cells exactly, `.int` cells exactly (× scale), `.float` cells
///     through `Value.cast(.decimal)`; null if the total overflows i128.
/// Added 2026-11-02, all skipping missing values whatever `skip_na` says (except
/// `size`, which is the row count):
///   `size` rows of the group; `prod` product (1 when empty); `any`/`all` truth of
///   non-missing cells (a number is true when non-zero, text when non-empty);
///   `sem` standard error (`std`/sqrt(n)); `skew`/`kurt` pandas' bias-corrected
///   sample skewness (null below 3 values) and excess kurtosis (below 4);
///   `mode` the most frequent value, a tie going to the smallest; `arg_min`/`arg_max`
///   the row position (in the input) of the first smallest/largest value.
pub const AggFn = enum { sum, mean, count, min, max, first, last, std, @"var", median, quantile, nunique, sum_exact, size, prod, any, all, sem, skew, kurt, mode, arg_min, arg_max };

pub const AggCol = struct {
    src: []const u8,
    out: []const u8,
    func: AggFn,
    /// Probability for `func = .quantile`, in [0, 1]; anything else (or NaN)
    /// gives null. Ignored by the other functions.
    q: f64 = 0.5,
};

pub const FxConvert = struct {
    /// Column holding the per-row conversion rate (null/absent → 1.0). The
    /// numeric aggregate value is multiplied by this before accumulation.
    rate_col: []const u8,
};

pub const AggregateSpec = struct {
    group_by: []const []const u8,
    aggs: []const AggCol,
    fx: ?FxConvert = null,
    /// pandas' `skipna=True` for the functions that historically count every
    /// row: `sum`/`mean` over non-missing numbers (`mean` null when none),
    /// `count` of non-missing cells, `min`/`max`/`first`/`last` of non-missing
    /// cells. false keeps the historical behaviour documented on `AggFn`.
    skip_na: bool = false,
    /// Sort the output by the group columns ascending, missing last (pandas'
    /// `groupby(sort=True)`). false keeps first-seen order.
    sort_groups: bool = false,
    /// Drop groups with a missing key (pandas' `dropna=True`). false keeps them
    /// as a group of their own; null and NaN are one key either way.
    drop_missing_keys: bool = false,
};

/// The fx-converted cell, as `aggregate` sees it.
inline fn fxCell(r: []const Value, ci: usize, rate_idx: ?usize) Value {
    const v = r[ci];
    if (rate_idx == null) return v;
    return if (v.asFloat()) |f| .{ .float = f * fxRate(r, rate_idx) } else v;
}

inline fn truthy(v: Value) ?bool {
    return switch (v) {
        .bool => |b| b,
        .int => |i| i != 0,
        .float => |f| f != 0,
        .decimal => |d| d != 0,
        else => null,
    };
}

/// Where one aggregate column's per-group results go.
const Sink = struct {
    cells: []Value,
    stride: usize,
    offset: usize,
    inline fn set(s: Sink, g: usize, v: Value) void {
        s.cells[g * s.stride + s.offset] = v;
    }
};

/// Online central moments (Welford/Terriberry), stable where the textbook
/// sums cancel.
const Moments = struct {
    n: f64 = 0,
    mean: f64 = 0,
    m2: f64 = 0,
    m3: f64 = 0,
    m4: f64 = 0,

    inline fn add2(s: *Moments, x: f64) void {
        s.n += 1;
        const delta = x - s.mean;
        s.mean += delta / s.n;
        s.m2 += delta * (x - s.mean);
    }

    inline fn add4(s: *Moments, x: f64) void {
        const n1 = s.n;
        s.n += 1;
        const n = s.n;
        const delta = x - s.mean;
        const dn = delta / n;
        const dn2 = dn * dn;
        const t = delta * dn * n1;
        s.mean += dn;
        s.m4 += t * dn2 * (n * n - 3 * n + 3) + 6 * dn2 * s.m2 - 4 * dn * s.m3;
        s.m3 += t * dn * (n - 2) - 3 * dn * s.m2;
        s.m2 += t;
    }
};

/// One aggregate column over all groups: one loop per function, so a row costs
/// what its function needs and nothing else. `skip` is `AggregateSpec.skip_na`.
fn accumulate(
    a: std.mem.Allocator,
    rows: []const []const Value,
    ids: []const u32,
    n: usize,
    ci: usize,
    rate_idx: ?usize,
    func: AggFn,
    q: f64,
    skip: bool,
    out: Sink,
) Error!void {
    switch (func) {
        .sum, .mean, .prod => {
            const acc = try a.alloc(f64, n);
            defer a.free(acc);
            @memset(acc, if (func == .prod) 1 else 0);
            const cnt = try a.alloc(u64, if (func == .mean) n else 0);
            defer a.free(cnt);
            @memset(cnt, 0);
            const miss_skips = skip or func == .prod;
            for (rows, ids) |r, g| {
                const raw = r[ci].asFloat();
                if (miss_skips and (raw == null or std.math.isNan(raw.?))) continue;
                const x = (raw orelse 0) * fxRate(r, rate_idx);
                if (func == .prod) acc[g] *= x else acc[g] += x;
                if (func == .mean) cnt[g] += 1;
            }
            for (acc, 0..) |x, g| out.set(g, switch (func) {
                .mean => if (cnt[g] == 0)
                    (if (skip) .null else .{ .float = 0 })
                else
                    .{ .float = x / @as(f64, @floatFromInt(cnt[g])) },
                else => .{ .float = x },
            });
        },
        .count, .size => {
            const cnt = try a.alloc(u64, n);
            defer a.free(cnt);
            @memset(cnt, 0);
            const miss_skips = skip and func == .count;
            for (rows, ids) |r, g| {
                if (miss_skips and isMissing(r[ci])) continue;
                cnt[g] += 1;
            }
            for (cnt, 0..) |x, g| out.set(g, .{ .int = @intCast(x) });
        },
        .any, .all => {
            const res = try a.alloc(bool, n);
            defer a.free(res);
            @memset(res, func == .all);
            for (rows, ids) |r, g| {
                if (isMissing(r[ci])) continue;
                const t = truthy(r[ci]) orelse (r[ci] == .text and r[ci].text.len != 0);
                if (func == .any) res[g] = res[g] or t else res[g] = res[g] and t;
            }
            for (res, 0..) |x, g| out.set(g, .{ .bool = x });
        },
        .min, .max, .first, .last => {
            const best = try a.alloc(Value, n);
            defer a.free(best);
            const have = try a.alloc(bool, n);
            defer a.free(have);
            @memset(have, false);
            for (rows, ids) |r, g| {
                const v = fxCell(r, ci, rate_idx);
                if (skip and isMissing(v)) continue;
                const take = !have[g] or switch (func) {
                    .min => v.order(best[g]) == .lt,
                    .max => v.order(best[g]) == .gt,
                    .first => false,
                    else => true,
                };
                if (take) {
                    best[g] = v;
                    have[g] = true;
                }
            }
            for (best, have, 0..) |v, h, g| out.set(g, if (h) v else .null);
        },
        .arg_min, .arg_max => {
            const best = try a.alloc(u32, n);
            defer a.free(best);
            const none = std.math.maxInt(u32);
            @memset(best, none);
            for (rows, ids, 0..) |r, g, ri| {
                if (isMissing(r[ci])) continue;
                const take = best[g] == none or switch (func) {
                    .arg_min => r[ci].order(rows[best[g]][ci]) == .lt,
                    else => r[ci].order(rows[best[g]][ci]) == .gt,
                };
                if (take) best[g] = @intCast(ri);
            }
            for (best, 0..) |b, g| out.set(g, if (b == none) .null else .{ .int = b });
        },
        .std, .@"var", .sem, .skew, .kurt => {
            const st = try a.alloc(Moments, n);
            defer a.free(st);
            @memset(st, .{});
            const high = func == .skew or func == .kurt;
            for (rows, ids) |r, g| {
                const x = fxCell(r, ci, rate_idx).asFloat() orelse continue;
                if (std.math.isNan(x)) continue;
                if (high) st[g].add4(x) else st[g].add2(x);
            }
            for (st, 0..) |s, g| out.set(g, momentResult(s, func));
        },
        .median, .quantile => try accumulateQuantile(a, rows, ids, n, ci, rate_idx, if (func == .median) 0.5 else q, out),
        .nunique, .mode => try accumulateDistinct(a, rows, ids, n, ci, rate_idx, func, out),
        .sum_exact => {
            const acc = try a.alloc(i128, n);
            defer a.free(acc);
            @memset(acc, 0);
            const over = try a.alloc(bool, n);
            defer a.free(over);
            @memset(over, false);
            for (rows, ids) |r, g| {
                const v = fxCell(r, ci, rate_idx);
                if (isMissing(v) or v.asFloat() == null) continue;
                // A rate of exactly 1 (a null rate included) keeps the stored cell.
                const term: ?i128 = switch (if (fxRate(r, rate_idx) == 1) r[ci] else v) {
                    .decimal => |d| d,
                    .int => |i| @as(i128, i) * ds.decimal_scale, // |i| < 2^63, scale < 2^40: fits
                    .float => if (v.cast(.decimal)) |c| c.decimal else null,
                    else => null,
                };
                if (term) |t| {
                    // Sticky: once the running total has left i128, no later
                    // term can make the result trustworthy again.
                    const s = @addWithOverflow(acc[g], t);
                    if (s[1] != 0) over[g] = true else acc[g] = s[0];
                }
            }
            for (acc, over, 0..) |x, o, g| out.set(g, if (o) .null else .{ .decimal = x });
        },
    }
}

fn momentResult(s: Moments, func: AggFn) Value {
    const n = s.n;
    switch (func) {
        .@"var" => return if (n < 2) .null else .{ .float = s.m2 / (n - 1) },
        .std => return if (n < 2) .null else .{ .float = @sqrt(s.m2 / (n - 1)) },
        .sem => return if (n < 2) .null else .{ .float = @sqrt(s.m2 / (n - 1)) / @sqrt(n) },
        .skew => {
            if (n < 3) return .null;
            if (s.m2 == 0) return .{ .float = 0 };
            const g1 = @sqrt(n) * s.m3 / std.math.pow(f64, s.m2, 1.5);
            return .{ .float = @sqrt(n * (n - 1)) / (n - 2) * g1 };
        },
        .kurt => {
            if (n < 4) return .null;
            if (s.m2 == 0) return .{ .float = 0 };
            const num = n * (n + 1) * (n - 1) * s.m4;
            const den = (n - 2) * (n - 3) * s.m2 * s.m2;
            return .{ .float = num / den - 3 * (n - 1) * (n - 1) / ((n - 2) * (n - 3)) };
        },
        else => unreachable, // the caller's switch names these five
    }
}

/// Type-7 quantile per group (numpy's and pandas' default): the values of every
/// group in one block, then a selection per group, not a sort.
fn accumulateQuantile(a: std.mem.Allocator, rows: []const []const Value, ids: []const u32, n: usize, ci: usize, rate_idx: ?usize, q: f64, out: Sink) Error!void {
    if (!(q >= 0 and q <= 1)) {
        for (0..n) |g| out.set(g, .null);
        return;
    }
    const offs = try a.alloc(usize, n + 1);
    defer a.free(offs);
    @memset(offs, 0);
    for (rows, ids) |r, g| {
        const x = fxCell(r, ci, rate_idx).asFloat() orelse continue;
        if (!std.math.isNan(x)) offs[g + 1] += 1;
    }
    for (0..n) |g| offs[g + 1] += offs[g];
    const vals = try a.alloc(f64, offs[n]);
    defer a.free(vals);
    const next = try a.dupe(usize, offs[0..n]);
    defer a.free(next);
    for (rows, ids) |r, g| {
        const x = fxCell(r, ci, rate_idx).asFloat() orelse continue;
        if (std.math.isNan(x)) continue;
        vals[next[g]] = x;
        next[g] += 1;
    }
    for (0..n) |g| out.set(g, quantileInPlace(vals[offs[g]..offs[g + 1]], q));
}

/// `nunique` and `mode`: a table over (group, value).
fn accumulateDistinct(a: std.mem.Allocator, rows: []const []const Value, ids: []const u32, n: usize, ci: usize, rate_idx: ?usize, func: AggFn, out: Sink) Error!void {
    var t = try keys.Table.initBytes(a, rows.len, keys.freshSeed(@intFromPtr(rows.ptr)));
    var scratch: std.ArrayList(u8) = .empty;
    defer scratch.deinit(a);
    var counts: std.ArrayList(u64) = .empty;
    defer counts.deinit(a);
    var vals: std.ArrayList(Value) = .empty;
    defer vals.deinit(a);
    var owner: std.ArrayList(u32) = .empty;
    defer owner.deinit(a);
    for (rows, ids) |r, g| {
        const v = fxCell(r, ci, rate_idx);
        if (isMissing(v)) continue;
        scratch.clearRetainingCapacity();
        try scratch.appendSlice(a, std.mem.asBytes(&g));
        try keys.encode(a, &scratch, v, .as_null);
        const id = try t.getOrPutBytes(a, scratch.items);
        if (id == counts.items.len) {
            try counts.append(a, 0);
            try vals.append(a, v);
            try owner.append(a, g);
        }
        counts.items[id] += 1;
    }
    if (func == .nunique) {
        const cnt = try a.alloc(u64, n);
        defer a.free(cnt);
        @memset(cnt, 0);
        for (owner.items) |g| cnt[g] += 1;
        for (cnt, 0..) |x, g| out.set(g, .{ .int = @intCast(x) });
        return;
    }
    // The most frequent; a tie goes to the smallest, pandas' `mode()[0]`.
    const best = try a.alloc(u32, n);
    defer a.free(best);
    const none = std.math.maxInt(u32);
    @memset(best, none);
    for (owner.items, 0..) |g, id| {
        const b = best[g];
        if (b == none or counts.items[id] > counts.items[b] or
            (counts.items[id] == counts.items[b] and vals.items[id].order(vals.items[b]) == .lt))
        {
            best[g] = @intCast(id);
        }
    }
    for (best, 0..) |b, g| out.set(g, if (b == none) .null else vals.items[b]);
}

const Want = struct { ci: usize, vals: []f64, dirty: bool = false };

/// The functions `accumulateClean` has a loop for.
fn cleanFn(func: AggFn) bool {
    return switch (func) {
        .sum, .mean, .std, .@"var", .median, .quantile => true,
        else => false,
    };
}

/// `accumulate` for a column that holds a number in every row (NaN allowed).
fn accumulateClean(a: std.mem.Allocator, vals: []f64, ids: []const u32, n: usize, func: AggFn, q: f64, skip: bool, out: Sink) Error!void {
    switch (func) {
        .sum, .mean => {
            const acc = try a.alloc(f64, n);
            defer a.free(acc);
            @memset(acc, 0);
            const cnt = try a.alloc(u64, if (func == .mean) n else 0);
            defer a.free(cnt);
            @memset(cnt, 0);
            if (skip) {
                for (vals, ids) |x, g| {
                    if (std.math.isNan(x)) continue;
                    acc[g] += x;
                    if (func == .mean) cnt[g] += 1;
                }
            } else if (func == .sum) {
                for (vals, ids) |x, g| acc[g] += x;
            } else {
                for (vals, ids) |x, g| {
                    acc[g] += x;
                    cnt[g] += 1;
                }
            }
            for (acc, 0..) |x, g| out.set(g, if (func == .sum)
                .{ .float = x }
            else if (cnt[g] == 0)
                (if (skip) .null else .{ .float = 0 })
            else
                .{ .float = x / @as(f64, @floatFromInt(cnt[g])) });
        },
        .std, .@"var" => {
            const st = try a.alloc(Moments, n);
            defer a.free(st);
            @memset(st, .{});
            for (vals, ids) |x, g| {
                if (!std.math.isNan(x)) st[g].add2(x);
            }
            for (st, 0..) |s, g| out.set(g, momentResult(s, func));
        },
        .median, .quantile => {
            const p: f64 = if (func == .median) 0.5 else q;
            if (!(p >= 0 and p <= 1)) {
                for (0..n) |g| out.set(g, .null);
                return;
            }
            const offs = try a.alloc(usize, n + 1);
            defer a.free(offs);
            @memset(offs, 0);
            for (vals, ids) |x, g| {
                if (!std.math.isNan(x)) offs[g + 1] += 1;
            }
            for (0..n) |g| offs[g + 1] += offs[g];
            const block = try a.alloc(f64, offs[n]);
            defer a.free(block);
            const next = try a.dupe(usize, offs[0..n]);
            defer a.free(next);
            for (vals, ids) |x, g| {
                if (std.math.isNan(x)) continue;
                block[next[g]] = x;
                next[g] += 1;
            }
            for (0..n) |g| out.set(g, quantileInPlace(block[offs[g]..offs[g + 1]], p));
        },
        else => unreachable, // `cleanFn` names these
    }
}

/// Type-7 quantile of `xs` (no NaN), reordering it.
fn quantileInPlace(xs: []f64, q: f64) Value {
    if (xs.len == 0) return .null;
    const h = @as(f64, @floatFromInt(xs.len - 1)) * q;
    const lo: usize = @intFromFloat(@floor(h));
    keys.selectKth(xs, lo);
    const frac = h - @floor(h);
    if (frac == 0 or lo + 1 >= xs.len) return .{ .float = xs[lo] };
    var hi = xs[lo + 1];
    for (xs[lo + 2 ..]) |x| hi = @min(hi, x);
    return .{ .float = xs[lo] + frac * (hi - xs[lo]) };
}

/// `error.TooLarge` once `groups x aggs` exceeds `max_aggregate_cells`.
fn aggregateCellsWithin(groups: usize, aggs: usize) Error!void {
    const cells = std.math.mul(usize, groups, aggs) catch return error.TooLarge;
    if (cells > max_aggregate_cells) return error.TooLarge;
}

pub fn aggregate(a: std.mem.Allocator, d: Dataset, spec: AggregateSpec) Error!Dataset {
    try keys.checkRect(d);
    const gidx = try a.alloc(usize, spec.group_by.len);
    for (spec.group_by, 0..) |name, i| gidx[i] = try mustIndex(d, name);
    const sidx = try a.alloc(usize, spec.aggs.len);
    for (spec.aggs, 0..) |ag, i| sidx[i] = try mustIndex(d, ag.src);
    const rate_idx: ?usize = if (spec.fx) |fx| try mustIndex(d, fx.rate_col) else null;

    // One pass over the rows: a row store costs a cache line or two per row, per
    // pass, whatever the column. The key and every value column that is wholly
    // numeric come out together; the loops below then run over flat arrays.
    const clean = try a.alloc(?[]f64, spec.aggs.len);
    defer a.free(clean);
    @memset(clean, null);
    var want: std.ArrayList(Want) = .empty;
    defer want.deinit(a);
    if (rate_idx == null) {
        for (spec.aggs, sidx, 0..) |ag, ci, i| {
            if (!cleanFn(ag.func)) continue;
            for (want.items) |w| {
                if (w.ci == ci) clean[i] = w.vals;
            }
            if (clean[i] == null) {
                const vals = try a.alloc(f64, d.rows.len);
                clean[i] = vals;
                try want.append(a, .{ .ci = ci, .vals = vals });
            }
        }
    }
    const kcols = try a.alloc(keys.KeyCol, gidx.len);
    defer a.free(kcols);
    for (kcols, gidx) |*kc, ci| kc.* = try keys.keyColFor(a, d.rows, ci);
    if (gidx.len > 0 or want.items.len > 0) {
        for (d.rows, 0..) |r, ri| {
            for (kcols, gidx) |*kc, ci| {
                keys.prefetchCell(d.rows, ri, ci);
                keys.keyColPut(kc, a, ri, r[ci]);
            }
            for (want.items) |*w| {
                keys.prefetchCell(d.rows, ri, w.ci);
                switch (r[w.ci]) {
                    .float => |x| w.vals[ri] = x,
                    .int => |x| w.vals[ri] = @floatFromInt(x),
                    else => w.dirty = w.dirty or (r[w.ci] != .decimal),
                }
                if (r[w.ci] == .decimal) w.vals[ri] = r[w.ci].asFloat().?;
            }
        }
    }
    const f = try keys.factorizeMany(a, kcols, d.rows, gidx, .as_null);
    defer a.free(f.ids);
    const n = f.groups();
    try aggregateCellsWithin(n, spec.aggs.len);

    // output columns: group-by cols (source types) + one per agg
    const cols = try a.alloc(Column, gidx.len + spec.aggs.len);
    for (gidx, 0..) |ci, i| cols[i] = d.columns[ci];
    for (spec.aggs, 0..) |ag, i| {
        cols[gidx.len + i] = .{ .name = ag.out, .type = aggOutType(d, sidx[i], ag.func, rate_idx != null) };
    }
    // Group keys keep their names; a colliding output is numbered, never unreachable.
    try keys.uniqueNames(a, cols);

    const rows = try a.alloc([]const Value, n);
    const cells = try a.alloc(Value, n * cols.len);
    for (rows, f.firsts, 0..) |*row, first, g| {
        const nr = cells[g * cols.len ..][0..cols.len];
        const src = d.rows[first];
        for (gidx, 0..) |ci, i| nr[i] = src[ci];
        row.* = nr;
    }
    for (spec.aggs, sidx, clean, 0..) |ag, ci, vals, i| {
        const sink: Sink = .{ .cells = cells, .stride = cols.len, .offset = gidx.len + i };
        var dirty = true;
        for (want.items) |w| {
            if (w.ci == ci) dirty = w.dirty;
        }
        if (vals != null and !dirty) {
            try accumulateClean(a, vals.?, f.ids, n, ag.func, ag.q, spec.skip_na, sink);
        } else {
            try accumulate(a, d.rows, f.ids, n, ci, rate_idx, ag.func, ag.q, spec.skip_na, sink);
        }
    }

    var out: Dataset = .{ .columns = cols, .rows = rows };
    if (spec.drop_missing_keys) out = try dropna(a, out, .{ .subset = spec.group_by });
    if (spec.sort_groups and spec.group_by.len > 0) {
        const by = try a.alloc(usize, gidx.len);
        for (by, 0..) |*b, i| b.* = i;
        const dirs = try a.alloc(SortDir, gidx.len);
        @memset(dirs, .asc);
        out = try sortBy(a, out, by, dirs, .last);
    }
    return out;
}

fn aggOutType(d: Dataset, src_idx: usize, func: AggFn, fx: bool) ColumnType {
    return switch (func) {
        // fx writes a converted cell as a float, whatever the source's numeric kind.
        .min, .max, .first, .last, .mode => if (fx and (d.columns[src_idx].type == .int or d.columns[src_idx].type == .decimal))
            .float
        else
            d.columns[src_idx].type,
        .sum, .mean, .std, .@"var", .median, .quantile, .prod, .sem, .skew, .kurt => .float,
        .count, .nunique, .size, .arg_min, .arg_max => .int,
        .any, .all => .bool,
        .sum_exact => .decimal,
    };
}

// ── weighted_group_sum (+fx) ────────────────────────────────────────────────

pub const WeightedGroupSumSpec = struct {
    /// Column naming the group (asset-class / region / currency). null/empty →
    /// the unassigned bucket.
    group_col: []const u8,
    value_col: []const u8,
    weight_col: []const u8,
    fx: ?FxConvert = null,
    out_group: []const u8 = "group",
    out_value: []const u8 = "value",
    unassigned_label: []const u8 = "(unassigned)",
};

/// Σ (value · weight · fxrate) per group. Each input row is one
/// (member, group, weight) tuple — multi-category expansion (one asset → several
/// (cat,weight) rows) is done upstream by a join/map. Rows with a null/empty
/// group fold into the `unassigned_label` bucket. Output: `{out_group, out_value}`.
pub fn weightedGroupSum(a: std.mem.Allocator, d: Dataset, spec: WeightedGroupSumSpec) Error!Dataset {
    try keys.checkRect(d);
    const gi = try mustIndex(d, spec.group_col);
    const vi = try mustIndex(d, spec.value_col);
    const wi = try mustIndex(d, spec.weight_col);
    const rate_idx: ?usize = if (spec.fx) |fx| try mustIndex(d, fx.rate_col) else null;

    var groups: std.StringArrayHashMapUnmanaged(f64) = .empty;
    var labels: std.StringArrayHashMapUnmanaged([]const u8) = .empty; // key → display label

    for (d.rows) |r| {
        const gv = r[gi];
        const is_unassigned = gv == .null or (gv == .text and gv.text.len == 0);
        const label: []const u8 = if (is_unassigned) spec.unassigned_label else (gv.asText() orelse blk: {
            var buf: std.ArrayList(u8) = .empty;
            try appendValueKey(a, &buf, gv);
            break :blk try buf.toOwnedSlice(a);
        });
        const contrib = (r[vi].asFloat() orelse 0) * (r[wi].asFloat() orelse 0) * fxRate(r, rate_idx);
        const gop = try groups.getOrPut(a, label);
        if (!gop.found_existing) {
            gop.value_ptr.* = 0;
            try labels.put(a, label, label);
        }
        gop.value_ptr.* += contrib;
    }

    const cols = try a.alloc(Column, 2);
    cols[0] = .{ .name = spec.out_group, .type = .text };
    cols[1] = .{ .name = spec.out_value, .type = .float };
    const rows = try a.alloc([]const Value, groups.count());
    var it = groups.iterator();
    var ri: usize = 0;
    while (it.next()) |kv| : (ri += 1) {
        const nr = try a.alloc(Value, 2);
        nr[0] = .{ .text = kv.key_ptr.* };
        nr[1] = .{ .float = kv.value_ptr.* };
        rows[ri] = nr;
    }
    return .{ .columns = cols, .rows = rows };
}

// ── percent_of_total ─────────────────────────────────────────────────────────

pub const PercentSpec = struct {
    value_col: []const u8,
    out: []const u8,
    /// Scale: 100 → percent (default), 1 → fraction.
    scale: f64 = 100,
};

/// Append `out = value / Σvalue * scale` — each row's share of the column total.
pub fn percentOfTotal(a: std.mem.Allocator, d: Dataset, spec: PercentSpec) Error!Dataset {
    try keys.checkRect(d);
    const vi = try mustIndex(d, spec.value_col);
    var total: f64 = 0;
    for (d.rows) |r| total += r[vi].asFloat() orelse 0;
    const cols = try a.alloc(Column, d.columns.len + 1);
    @memcpy(cols[0..d.columns.len], d.columns);
    cols[d.columns.len] = .{ .name = spec.out, .type = .float };
    const rows = try a.alloc([]const Value, d.rows.len);
    for (d.rows, 0..) |r, i| {
        const nr = try a.alloc(Value, cols.len);
        @memcpy(nr[0..d.columns.len], r);
        const share = if (total != 0) (r[vi].asFloat() orelse 0) / total * spec.scale else 0;
        nr[d.columns.len] = .{ .float = share };
        rows[i] = nr;
    }
    return .{ .columns = cols, .rows = rows };
}

// ── sort ────────────────────────────────────────────────────────────────────

pub const SortDir = enum { asc, desc };
pub const SortKey = struct { key: []const u8, dir: SortDir = .asc };
pub const SortSpec = struct {
    key: []const u8,
    dir: SortDir = .asc,
    /// Additional tie-break keys, applied in order after `key`/`dir`.
    then_by: []const SortKey = &.{},
    /// `.auto`: `Value.order` (null lowest, NaN the highest number), reversed by
    /// `.desc` (historical). `.first`/`.last`: every missing cell (null, NaN) goes
    /// there whatever the direction (pandas' `na_position`).
    missing: enum { auto, first, last } = .auto,
};

/// One sort key as bitwise-comparable u64s: straight images for an all-int or
/// all-float column, otherwise ranks of the distinct values under `Value.order`.
fn sortKeyColumn(a: std.mem.Allocator, rows: []const []const Value, ci: usize, dir: SortDir, out: []u64) Error!void {
    var ints = false;
    var floats = false;
    var other = false;
    for (rows) |r| switch (r[ci]) {
        .int => ints = true,
        .float => floats = true,
        .null => {},
        else => other = true,
    };
    if (!other and !(ints and floats)) {
        for (rows, out) |r, *k| k.* = switch (r[ci]) {
            .int => |i| keys.intKey(i),
            .float => |x| keys.floatKey(x),
            else => 0, // a null: placed by the flag pass
        };
    } else {
        const f = try keys.factorize(a, rows, &.{ci}, .own);
        defer a.free(f.ids);
        const order = try a.alloc(u32, f.groups());
        defer a.free(order);
        for (order, 0..) |*o, i| o.* = @intCast(i);
        const Ctx = struct {
            rows: []const []const Value,
            firsts: []const u32,
            ci: usize,
            fn lt(c: @This(), l: u32, m: u32) bool {
                return c.rows[c.firsts[l]][c.ci].order(c.rows[c.firsts[m]][c.ci]) == .lt;
            }
        };
        const ctx: Ctx = .{ .rows = rows, .firsts = f.firsts, .ci = ci };
        std.mem.sort(u32, order, ctx, Ctx.lt);
        const rank = try a.alloc(u64, f.groups());
        defer a.free(rank);
        var cur: u64 = 0;
        for (order, 0..) |o, i| {
            // Canonical keys already merge equals; a tie left over still ranks equal.
            if (i > 0 and ctx.lt(order[i - 1], o)) cur += 1;
            rank[o] = cur;
        }
        for (f.ids, out) |id, *k| k.* = rank[id];
    }
    if (dir == .desc) {
        for (out) |*k| k.* = ~k.*;
    }
}

/// Stable sort rows by `key`/`dir`, breaking ties with `then_by` (in order). The
/// rows are borrowed. LSD over the key columns: a radix pass per key (and a pass
/// for the missing cells where there are any), least significant first.
pub fn sort(a: std.mem.Allocator, d: Dataset, spec: SortSpec) Error!Dataset {
    try keys.checkRect(d);
    const n = 1 + spec.then_by.len;
    const idxs = try a.alloc(usize, n);
    const dirs = try a.alloc(SortDir, n);
    idxs[0] = try mustIndex(d, spec.key);
    dirs[0] = spec.dir;
    for (spec.then_by, 0..) |tb, i| {
        idxs[1 + i] = try mustIndex(d, tb.key);
        dirs[1 + i] = tb.dir;
    }
    return sortBy(a, d, idxs, dirs, spec.missing);
}

const MissingPos = @FieldType(SortSpec, "missing");

/// `sort` by column positions: names can repeat in an output being built.
fn sortBy(a: std.mem.Allocator, d: Dataset, idxs: []const usize, dirs: []const SortDir, missing: MissingPos) Error!Dataset {
    const n = idxs.len;
    if (d.rows.len >= std.math.maxInt(u32)) return error.TooLarge;
    const pairs = try a.alloc(keys.Pair, d.rows.len);
    defer a.free(pairs);
    for (pairs, 0..) |*p, i| p.idx = @intCast(i);
    const vals = try a.alloc(u64, d.rows.len);
    defer a.free(vals);
    var k = n;
    while (k > 0) {
        k -= 1;
        const ci = idxs[k];
        try sortKeyColumn(a, d.rows, ci, dirs[k], vals);
        for (pairs) |*p| p.key = vals[p.idx];
        try keys.radixSort(a, pairs);

        // `.auto`: a null is the lowest value, so first ascending, last descending,
        // and a NaN stays where the value pass put it. `.first`/`.last`: every
        // missing cell goes there, whatever the direction.
        const front = switch (missing) {
            .auto => dirs[k] == .asc,
            .first => true,
            .last => false,
        };
        var flagged = false;
        for (pairs) |*p| {
            const c = d.rows[p.idx][ci];
            const hit = if (missing == .auto) c == .null else isMissing(c);
            flagged = flagged or hit;
            p.key = if (hit == front) 0 else 1;
        }
        if (flagged) try keys.radixSort(a, pairs);
    }
    const rows = try a.alloc([]const Value, d.rows.len);
    for (rows, pairs) |*r, p| r.* = d.rows[p.idx];
    return .{ .columns = d.columns, .rows = rows };
}

// ── top_n / top_n_with_tail ─────────────────────────────────────────────────

pub const TopNSpec = struct {
    n: usize,
    /// When set, rows beyond `n` are folded into one tail row whose `label_col`
    /// cell = `label` and whose `value_col` cell = Σ of the dropped values (all
    /// other cells null). When null, the tail is simply dropped.
    tail: ?struct {
        label_col: []const u8,
        label: []const u8,
        value_col: []const u8,
    } = null,
};

/// Keep the first `n` rows (call `sort` first to make "top" meaningful),
/// optionally folding the remainder into a labeled tail row.
pub fn topN(a: std.mem.Allocator, d: Dataset, spec: TopNSpec) Error!Dataset {
    try keys.checkRect(d);
    const keep = @min(spec.n, d.rows.len);
    if (spec.tail == null or d.rows.len <= keep) {
        const rows = try a.alloc([]const Value, keep);
        @memcpy(rows, d.rows[0..keep]);
        return .{ .columns = d.columns, .rows = rows };
    }
    const t = spec.tail.?;
    const label_idx = try mustIndex(d, t.label_col);
    const value_idx = try mustIndex(d, t.value_col);
    var tail_sum: f64 = 0;
    for (d.rows[keep..]) |r| tail_sum += r[value_idx].asFloat() orelse 0;

    const rows = try a.alloc([]const Value, keep + 1);
    @memcpy(rows[0..keep], d.rows[0..keep]);
    const tail_row = try a.alloc(Value, d.columns.len);
    @memset(tail_row, .null);
    tail_row[label_idx] = .{ .text = t.label };
    tail_row[value_idx] = .{ .float = tail_sum };
    rows[keep] = tail_row;
    return .{ .columns = d.columns, .rows = rows };
}

// ── page (limit/offset) ─────────────────────────────────────────────────────

pub const PageSpec = struct {
    offset: usize = 0,
    /// Rows to keep after `offset`; null = to the end.
    limit: ?usize = null,
};

/// Windowed row slice: skip `offset` rows, then keep at most `limit`.
/// Complements `topN` (whose window always starts at row 0) for arbitrary
/// pagination. Out-of-range `offset` yields an empty (not erroring) result.
pub fn page(a: std.mem.Allocator, d: Dataset, spec: PageSpec) Error!Dataset {
    try keys.checkRect(d);
    const start = @min(spec.offset, d.rows.len);
    const avail = d.rows.len - start;
    const take = if (spec.limit) |l| @min(l, avail) else avail;
    const rows = try a.alloc([]const Value, take);
    @memcpy(rows, d.rows[start .. start + take]);
    return .{ .columns = d.columns, .rows = rows };
}

// ── pivot ───────────────────────────────────────────────────────────────────

pub const PivotSpec = struct {
    row_key: []const u8,
    col_key: []const u8,
    value_col: []const u8,
    agg: AggFn = .sum,
    /// Probability when `agg = .quantile`.
    q: f64 = 0.5,
    /// `AggregateSpec.skip_na` for the cells (pandas' `pivot_table` skips).
    skip_na: bool = false,
    /// Written into a cell no row fell into; null leaves it null.
    fill_value: ?f64 = null,
};

/// rowKey × colKey → agg(value) matrix (month×year heatmaps, …). Output: first
/// column = `row_key` (source type), then one column per distinct col-key (numeric-aware
/// ascending, for determinism), typed by what `agg` gives: float for `sum`, int for
/// `count`. Rows in first-seen order. A missing cell is null, or `fill_value`. Two
/// keys printing alike get `uniqueNames`' numbered names.
pub fn pivot(a: std.mem.Allocator, d: Dataset, spec: PivotSpec) Error!Dataset {
    try keys.checkRect(d);
    const rki = try mustIndex(d, spec.row_key);
    const cki = try mustIndex(d, spec.col_key);
    const vi = try mustIndex(d, spec.value_col);

    const rf = try keys.factorize(a, d.rows, &.{rki}, .as_null);
    defer a.free(rf.ids);
    const cf = try keys.factorize(a, d.rows, &.{cki}, .as_null);
    defer a.free(cf.ids);
    const nr = rf.groups();
    const nc = cf.groups();
    const n_cells = std.math.mul(usize, nr, nc) catch return error.TooLarge;
    if (n_cells > max_pivot_cells) return error.TooLarge;

    // Column keys, with the numeric order decided once and each key parsed once.
    const Ck = struct { name: []const u8, num: f64, id: u32 };
    const cks = try a.alloc(Ck, nc);
    defer a.free(cks);
    var numeric = true;
    for (cks, cf.firsts, 0..) |*ck, first, id| {
        var buf: std.ArrayList(u8) = .empty;
        try appendValueKey(a, &buf, d.rows[first][cki]);
        const name = try buf.toOwnedSlice(a);
        // `parseFloat` also accepts "nan": a NaN compares false both ways, so the
        // numeric order would not be a total order; such a set stays lexicographic.
        const num = std.fmt.parseFloat(f64, name) catch std.math.nan(f64);
        if (std.math.isNan(num)) numeric = false;
        ck.* = .{ .name = name, .num = num, .id = @intCast(id) };
    }
    const Less = struct {
        fn byName(_: void, l: Ck, m: Ck) bool {
            return std.mem.order(u8, l.name, m.name) == .lt;
        }
        fn byNum(_: void, l: Ck, m: Ck) bool {
            return l.num < m.num;
        }
    };
    if (numeric) std.mem.sort(Ck, cks, {}, Less.byNum) else std.mem.sort(Ck, cks, {}, Less.byName);

    // What the cells hold: `fill_value` on a numeric function, promoting an int column
    // when it is not whole; on any other it stays null, no number belongs there.
    var cell_type = aggOutType(d, vi, spec.agg, false);
    var fill: Value = .null;
    var promote = false;
    if (spec.fill_value) |x| switch (cell_type) {
        .float => fill = .{ .float = x },
        .int => {
            if (Value.floatToInt(i64, x)) |i| {
                if (@as(f64, @floatFromInt(i)) == x) fill = .{ .int = i };
            }
            if (fill == .null) {
                cell_type = .float;
                promote = true;
                fill = .{ .float = x };
            }
        },
        .decimal => fill = (Value{ .float = x }).cast(.decimal) orelse .null,
        else => {},
    };
    const cols = try a.alloc(Column, 1 + nc);
    cols[0] = .{ .name = spec.row_key, .type = d.columns[rki].type };
    for (cks, 0..) |ck, i| cols[1 + i] = .{ .name = ck.name, .type = cell_type };
    // Int 1 and text "1" are two keys that print alike; a key may print as `row_key`.
    try keys.uniqueNames(a, cols);

    const ids = try a.alloc(u32, d.rows.len);
    defer a.free(ids);
    const present = try a.alloc(bool, n_cells);
    defer a.free(present);
    @memset(present, false);
    for (ids, rf.ids, cf.ids) |*id, r, c| {
        id.* = @intCast(r * nc + c); // < n_cells <= max_pivot_cells: fits
        present[id.*] = true;
    }
    const tmp = try a.alloc(Value, n_cells);
    defer a.free(tmp);
    try accumulate(a, d.rows, ids, n_cells, vi, null, spec.agg, spec.q, spec.skip_na, .{ .cells = tmp, .stride = 1, .offset = 0 });

    const rows = try a.alloc([]const Value, nr);
    const cells = try a.alloc(Value, nr * cols.len);
    for (rows, rf.firsts, 0..) |*row, first, r| {
        const out = cells[r * cols.len ..][0..cols.len];
        out[0] = d.rows[first][rki];
        for (cks, out[1..]) |ck, *o| {
            const id = r * nc + ck.id;
            o.* = if (present[id]) tmp[id] else fill;
            if (promote and o.* == .int) {
                const x: f64 = @floatFromInt(o.int);
                o.* = .{ .float = x };
            }
        }
        row.* = out;
    }
    return .{ .columns = cols, .rows = rows };
}

fn strLess(_: void, l: []const u8, r: []const u8) bool {
    return std.mem.order(u8, l, r) == .lt;
}

// ── unpivot / melt ──────────────────────────────────────────────────────────

pub const UnpivotSpec = struct {
    /// Columns copied as-is (row identity) to every output row.
    id_cols: []const []const u8,
    /// Wide columns to melt into (key,value) row pairs. Empty (default) melts
    /// every column NOT in `id_cols`.
    value_cols: []const []const u8 = &.{},
    out_key: []const u8 = "variable",
    out_value: []const u8 = "value",
};

/// Wide → long reshape: one output row per (input row × melted column),
/// carrying the id columns plus `{out_key: <melted column's name>, out_value:
/// <that cell>}`. Loose inverse of `pivot` (round-trips when `pivot`'s `agg`
/// doesn't collapse information, e.g. one row per row_key×col_key already).
/// `out_value`'s declared type is the first melted column's type — melted
/// columns of mixed types are still carried correctly (`Value` is
/// self-describing), this only affects the type hint on the output column.
pub fn unpivot(a: std.mem.Allocator, d: Dataset, spec: UnpivotSpec) Error!Dataset {
    try keys.checkRect(d);
    const id_idxs = try a.alloc(usize, spec.id_cols.len);
    for (spec.id_cols, 0..) |name, i| id_idxs[i] = try mustIndex(d, name);

    var val_idxs: std.ArrayList(usize) = .empty;
    if (spec.value_cols.len > 0) {
        for (spec.value_cols) |name| try val_idxs.append(a, try mustIndex(d, name));
    } else {
        col_loop: for (0..d.columns.len) |ci| {
            for (id_idxs) |ii| if (ii == ci) continue :col_loop;
            try val_idxs.append(a, ci);
        }
    }

    const out_value_type: ColumnType = if (val_idxs.items.len > 0) d.columns[val_idxs.items[0]].type else .text;
    const cols = try a.alloc(Column, id_idxs.len + 2);
    for (id_idxs, 0..) |ii, i| cols[i] = d.columns[ii];
    cols[id_idxs.len] = .{ .name = spec.out_key, .type = .text };
    cols[id_idxs.len + 1] = .{ .name = spec.out_value, .type = out_value_type };
    try keys.uniqueNames(a, cols); // an id column may carry either output name

    // rows x melted columns, counted before a single output row is built.
    const total = std.math.mul(usize, d.rows.len, val_idxs.items.len) catch return error.TooLarge;
    if (total > max_unpivot_cells) return error.TooLarge;
    const rows = try a.alloc([]const Value, total);
    const cells = try a.alloc(Value, total * cols.len);
    var at: usize = 0;
    for (d.rows) |r| {
        for (val_idxs.items) |vi| {
            const nr = cells[at * cols.len ..][0..cols.len];
            for (id_idxs, 0..) |ii, ci| nr[ci] = r[ii];
            nr[id_idxs.len] = .{ .text = d.columns[vi].name };
            nr[id_idxs.len + 1] = r[vi];
            rows[at] = nr;
            at += 1;
        }
    }
    return .{ .columns = cols, .rows = rows };
}

// ── resample ────────────────────────────────────────────────────────────────

pub const Freq = enum { day, month, year, week, quarter };
pub const ResampleAgg = enum { sum, mean, last, first, compound, min, max, count };

pub const ResampleSpec = struct {
    date_col: []const u8,
    value_col: []const u8,
    freq: Freq,
    agg: ResampleAgg = .sum,
    out_date: []const u8 = "period",
    out_value: []const u8 = "value",
};

const ResAcc = struct {
    sum: f64 = 0,
    count: u64 = 0,
    first: f64 = 0,
    last: f64 = 0,
    compound: f64 = 1,
    min: f64 = std.math.inf(f64),
    max: f64 = -std.math.inf(f64),
    has: bool = false,

    fn observe(self: *ResAcc, v: f64) void {
        self.sum += v;
        self.compound *= (1 + v);
        self.min = @min(self.min, v);
        self.max = @max(self.max, v);
        self.last = v;
        if (!self.has) self.first = v;
        self.has = true;
        self.count += 1;
    }
    fn result(self: ResAcc, agg: ResampleAgg) f64 {
        return switch (agg) {
            .sum => self.sum,
            .mean => if (self.count == 0) 0 else self.sum / @as(f64, @floatFromInt(self.count)),
            .first => self.first,
            .last => self.last,
            .compound => self.compound - 1,
            .min => self.min,
            .max => self.max,
            .count => @floatFromInt(self.count),
        };
    }
};

/// Bucket a dated series by `freq`, aggregating the value. Bucket labels: day →
/// "YYYY-MM-DD", week → the date of its Monday (ISO weeks), month → "YYYY-MM",
/// quarter → "YYYY-Qn", year → "YYYY" (all lexicographically ordered). `compound` = Π(1+v)−1 (return chaining). Rows with an unparseable
/// date are skipped. Output: `{out_date (text), out_value (float)}`, ascending.
pub fn resample(a: std.mem.Allocator, d: Dataset, spec: ResampleSpec) Error!Dataset {
    try keys.checkRect(d);
    const di = try mustIndex(d, spec.date_col);
    const vi = try mustIndex(d, spec.value_col);

    var buckets: std.StringArrayHashMapUnmanaged(ResAcc) = .empty;
    for (d.rows) |r| {
        const date = rowDate(d, di, r) orelse continue;
        const label = try bucketLabel(a, date, spec.freq);
        const bop = try buckets.getOrPut(a, label);
        if (!bop.found_existing) bop.value_ptr.* = .{};
        bop.value_ptr.observe(r[vi].asFloat() orelse 0);
    }

    const labels = try a.alloc([]const u8, buckets.count());
    for (buckets.keys(), 0..) |k, i| labels[i] = k;
    std.mem.sort([]const u8, labels, {}, strLess);

    const cols = try a.alloc(Column, 2);
    cols[0] = .{ .name = spec.out_date, .type = if (spec.freq == .day or spec.freq == .week) .date else .text };
    cols[1] = .{ .name = spec.out_value, .type = .float };
    const rows = try a.alloc([]const Value, labels.len);
    for (labels, 0..) |k, i| {
        const nr = try a.alloc(Value, 2);
        nr[0] = .{ .text = k };
        nr[1] = .{ .float = buckets.get(k).?.result(spec.agg) };
        rows[i] = nr;
    }
    return .{ .columns = cols, .rows = rows };
}

fn bucketLabel(a: std.mem.Allocator, date: ds.Date, freq: Freq) Error![]const u8 {
    // Cast the year to unsigned: zero-padding a signed int reserves a sign slot
    // ('+2024'). Real dates are positive; clamp defensively.
    const y: u32 = if (date.y < 0) 0 else @intCast(date.y);
    return switch (freq) {
        .day => a.print("{d:0>4}-{d:0>2}-{d:0>2}", .{ y, date.m, date.d }),
        .month => a.print("{d:0>4}-{d:0>2}", .{ y, date.m }),
        .year => a.print("{d:0>4}", .{y}),
        .quarter => a.print("{d:0>4}-Q{d}", .{ y, (date.m - 1) / 3 + 1 }),
        .week => blk: {
            const ord = date.ordinal();
            // 1970-01-01, ordinal 0, was a Thursday: Monday is 3 days before.
            const monday = ds.Date.fromOrdinal(ord - @mod(ord + 3, 7)) orelse date;
            const my: u32 = if (monday.y < 0) 0 else @intCast(monday.y);
            break :blk a.print("{d:0>4}-{d:0>2}-{d:0>2}", .{ my, monday.m, monday.d });
        },
    };
}

/// The calendar date (UTC) of a row's date cell: ISO text in any column, or —
/// in a `.timestamp` column — an `.int` of microseconds since the epoch.
fn rowDate(d: Dataset, di: usize, r: []const Value) ?ds.Date {
    if (d.columns[di].type == .timestamp and r[di] == .int)
        return ds.Date.fromOrdinal(@divFloor(r[di].int, 86_400 * ds.timestamp_units_per_second));
    return ds.parseIsoDate(r[di].asText() orelse return null);
}

// ── reduce ──────────────────────────────────────────────────────────────────

/// KPI reduction: aggregate the whole table into a single row (aggregate with no
/// group-by). Output has one row and one column per `aggs` entry.
pub fn reduce(a: std.mem.Allocator, d: Dataset, aggs: []const AggCol) Error!Dataset {
    try keys.checkRect(d);
    return aggregate(a, d, .{ .group_by = &.{}, .aggs = aggs });
}

// ── clamp_range ─────────────────────────────────────────────────────────────

pub const ClampRangeSpec = struct {
    date_col: []const u8,
    /// Inclusive ISO bounds; null = unbounded on that side.
    from: ?[]const u8 = null,
    to: ?[]const u8 = null,
};

/// Keep rows whose `date_col` (ISO) falls within [from, to] inclusive. Rows with
/// an unparseable date are dropped.
pub fn clampRange(a: std.mem.Allocator, d: Dataset, spec: ClampRangeSpec) Error!Dataset {
    try keys.checkRect(d);
    const di = try mustIndex(d, spec.date_col);
    const from_ord: ?i64 = if (spec.from) |f| (ds.parseIsoDate(f) orelse return Error.NoSuchColumn).ordinal() else null;
    const to_ord: ?i64 = if (spec.to) |t| (ds.parseIsoDate(t) orelse return Error.NoSuchColumn).ordinal() else null;

    var kept: std.ArrayList([]const Value) = .empty;
    for (d.rows) |r| {
        const date = rowDate(d, di, r) orelse continue;
        const o = date.ordinal();
        if (from_ord) |f| if (o < f) continue;
        if (to_ord) |t| if (o > t) continue;
        try kept.append(a, r);
    }
    return .{ .columns = d.columns, .rows = try kept.toOwnedSlice(a) };
}

// ── filter ──────────────────────────────────────────────────────────────────

pub const CmpOp = enum { eq, ne, lt, le, gt, ge, is_null, not_null };

/// `col op value`. A MISSING cell (null, or a NaN float) satisfies only
/// `is_null` — every comparison against it is false, `ne` included (SQL's
/// three-valued rule: an absent value is not "different", it is unknown).
/// A comparison needs comparable kinds: number with number (int/float/decimal
/// by value, two decimals exactly), text with text (bytewise, so ISO dates
/// order correctly), bool with bool. A cell of another kind than `value`
/// matches nothing — a numeric cell never equals a text literal.
pub const Predicate = struct {
    col: []const u8,
    op: CmpOp,
    /// Ignored by `is_null` / `not_null`.
    value: Value = .null,
};

pub const FilterSpec = struct {
    where: []const Predicate,
    /// `.all`: a row is kept when every predicate holds (AND; an empty
    /// `where` keeps every row). `.any`: when at least one holds (OR; an
    /// empty `where` keeps none).
    mode: enum { all, any } = .all,
};

const isMissing = keys.isMissing;

fn kindOf(v: Value) enum { number, text, bool, other } {
    return switch (v) {
        .int, .float, .decimal => .number,
        .text => .text,
        .bool => .bool,
        .null => .other,
    };
}

inline fn cmpHolds(op: CmpOp, comptime T: type, x: T, y: T) bool {
    return switch (op) {
        .eq => x == y,
        .ne => x != y,
        .lt => x < y,
        .le => x <= y,
        .gt => x > y,
        .ge => x >= y,
        .is_null, .not_null => unreachable, // `holds` handled them
    };
}

fn holds(p: Predicate, cell: Value) bool {
    if (p.op != .is_null and p.op != .not_null) {
        // The usual pairs, without the exact cross-kind order.
        if (cell == .int and p.value == .int) return cmpHolds(p.op, i64, cell.int, p.value.int);
        if (cell == .float and p.value == .float) {
            const x = cell.float;
            const y = p.value.float;
            if (std.math.isNan(x) or std.math.isNan(y)) return false;
            return cmpHolds(p.op, f64, x, y);
        }
    }
    const missing = isMissing(cell);
    switch (p.op) {
        .is_null => return missing,
        .not_null => return !missing,
        else => {},
    }
    if (missing or isMissing(p.value)) return false;
    if (kindOf(cell) != kindOf(p.value)) return false;
    const o = cell.order(p.value);
    return switch (p.op) {
        .eq => o == .eq,
        .ne => o != .eq,
        .lt => o == .lt,
        .le => o != .gt,
        .gt => o == .gt,
        .ge => o != .lt,
        .is_null, .not_null => unreachable,
    };
}

/// Keep the rows satisfying `spec` (rows are borrowed, not copied).
pub fn filter(a: std.mem.Allocator, d: Dataset, spec: FilterSpec) Error!Dataset {
    try keys.checkRect(d);
    const idxs = try a.alloc(usize, spec.where.len);
    for (spec.where, 0..) |p, i| idxs[i] = try mustIndex(d, p.col);
    var kept: std.ArrayList([]const Value) = .empty;
    try kept.ensureTotalCapacityPrecise(a, d.rows.len);
    for (d.rows, 0..) |r, ri| {
        for (idxs) |ci| keys.prefetchCell(d.rows, ri, ci);
        const keep = switch (spec.mode) {
            .all => blk: {
                for (spec.where, idxs) |p, ci| if (!holds(p, r[ci])) break :blk false;
                break :blk true;
            },
            .any => blk: {
                for (spec.where, idxs) |p, ci| if (holds(p, r[ci])) break :blk true;
                break :blk false;
            },
        };
        if (keep) kept.appendAssumeCapacity(r);
    }
    return .{ .columns = d.columns, .rows = try kept.toOwnedSlice(a) };
}

/// Keep the rows for which `predicate(context, row)` is true — the escape
/// hatch for any logic `filter`'s spec cannot say. Rows are borrowed.
pub fn filterBy(
    a: std.mem.Allocator,
    d: Dataset,
    context: anytype,
    comptime predicate: fn (@TypeOf(context), []const Value) bool,
) Error!Dataset {
    try keys.checkRect(d);
    var kept: std.ArrayList([]const Value) = .empty;
    for (d.rows) |r| if (predicate(context, r)) try kept.append(a, r);
    return .{ .columns = d.columns, .rows = try kept.toOwnedSlice(a) };
}

// ── select / drop / rename ──────────────────────────────────────────────────

/// `select`/`rename`'s error set: a result with two columns of the same name
/// is refused, since `Dataset.columnIndex` would only ever find the first.
pub const ColumnsError = Error || error{DuplicateColumn};

fn project(a: std.mem.Allocator, d: Dataset, idxs: []const usize) Error!Dataset {
    const cols = try a.alloc(Column, idxs.len);
    for (idxs, 0..) |ci, i| cols[i] = d.columns[ci];
    const rows = try a.alloc([]const Value, d.rows.len);
    for (d.rows, 0..) |r, ri| {
        const nr = try a.alloc(Value, idxs.len);
        for (idxs, 0..) |ci, i| nr[i] = r[ci];
        rows[ri] = nr;
    }
    return .{ .columns = cols, .rows = rows };
}

/// Keep exactly `names`, in that order.
pub fn select(a: std.mem.Allocator, d: Dataset, names: []const []const u8) ColumnsError!Dataset {
    try keys.checkRect(d);
    const idxs = try a.alloc(usize, names.len);
    // A hash set, not a scan of the earlier names: `names` is spec data.
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    for (names, 0..) |n, i| {
        const gop = try seen.getOrPut(a, n);
        if (gop.found_existing) return error.DuplicateColumn;
        idxs[i] = try mustIndex(d, n);
    }
    return project(a, d, idxs);
}

/// Remove `names` (each must exist); the rest keep their order.
pub fn drop(a: std.mem.Allocator, d: Dataset, names: []const []const u8) Error!Dataset {
    try keys.checkRect(d);
    const gone = try a.alloc(bool, d.columns.len);
    @memset(gone, false);
    for (names) |n| gone[try mustIndex(d, n)] = true;
    var idxs: std.ArrayList(usize) = .empty;
    for (gone, 0..) |g, ci| if (!g) try idxs.append(a, ci);
    return project(a, d, idxs.items);
}

pub const Rename = struct { from: []const u8, to: []const u8 };

/// Rename columns; rows are shared with `d` (only the schema is new). Each
/// `from` must exist; renames apply simultaneously (`a→b, b→a` swaps).
pub fn rename(a: std.mem.Allocator, d: Dataset, renames: []const Rename) ColumnsError!Dataset {
    try keys.checkRect(d);
    const cols = try a.dupe(Column, d.columns);
    const touched = try a.alloc(bool, d.columns.len);
    @memset(touched, false);
    for (renames) |rn| {
        const ci = try mustIndex(d, rn.from);
        if (touched[ci]) return error.DuplicateColumn; // the same column renamed twice
        touched[ci] = true;
        cols[ci].name = rn.to;
    }
    for (cols, 0..) |c, i| {
        if (!touched[i]) continue;
        for (cols, 0..) |o, j| if (i != j and std.mem.eql(u8, c.name, o.name)) return error.DuplicateColumn;
    }
    return .{ .columns = cols, .rows = d.rows };
}

// ── dropna / fillna ─────────────────────────────────────────────────────────

/// Missing = null, or a NaN float (pandas' `isna`).
pub const DropNaSpec = struct {
    /// Columns to inspect; empty = every column.
    subset: []const []const u8 = &.{},
    /// `.any`: drop a row with any missing cell in `subset`; `.all`: only a
    /// row whose `subset` cells are all missing.
    how: enum { any, all } = .any,
};

fn subsetIdxs(a: std.mem.Allocator, d: Dataset, subset: []const []const u8) Error![]const usize {
    const n = if (subset.len == 0) d.columns.len else subset.len;
    const idxs = try a.alloc(usize, n);
    for (idxs, 0..) |*ix, i| ix.* = if (subset.len == 0) i else try mustIndex(d, subset[i]);
    return idxs;
}

pub fn dropna(a: std.mem.Allocator, d: Dataset, spec: DropNaSpec) Error!Dataset {
    try keys.checkRect(d);
    const idxs = try subsetIdxs(a, d, spec.subset);
    var kept: std.ArrayList([]const Value) = .empty;
    for (d.rows) |r| {
        var n_missing: usize = 0;
        for (idxs) |ci| n_missing += @intFromBool(isMissing(r[ci]));
        const drop_row = switch (spec.how) {
            .any => n_missing > 0,
            .all => n_missing == idxs.len and idxs.len > 0,
        };
        if (!drop_row) try kept.append(a, r);
    }
    return .{ .columns = d.columns, .rows = try kept.toOwnedSlice(a) };
}

pub const FillNaSpec = struct {
    /// Columns to fill; empty = every column.
    subset: []const []const u8 = &.{},
    /// Written into every missing cell as is — the column's declared type is
    /// not changed, so fill a `.float` column with a `.float`.
    value: Value,
};

/// Replace missing cells (null, NaN). Rows without a missing cell in `subset`
/// are shared with `d`, not copied.
pub fn fillna(a: std.mem.Allocator, d: Dataset, spec: FillNaSpec) Error!Dataset {
    try keys.checkRect(d);
    const idxs = try subsetIdxs(a, d, spec.subset);
    const rows = try a.alloc([]const Value, d.rows.len);
    for (d.rows, 0..) |r, ri| {
        rows[ri] = r;
        for (idxs) |ci| {
            if (!isMissing(r[ci])) continue;
            const nr = try a.dupe(Value, r);
            for (idxs) |cj| if (isMissing(nr[cj])) {
                nr[cj] = spec.value;
            };
            rows[ri] = nr;
            break;
        }
    }
    return .{ .columns = d.columns, .rows = rows };
}

// ── tail / nlargest / sample ────────────────────────────────────────────────

/// The last `n` rows (borrowed), in order; `page` and `topN` window from the front.
pub fn tail(a: std.mem.Allocator, d: Dataset, n: usize) Error!Dataset {
    try keys.checkRect(d);
    const take = @min(n, d.rows.len);
    return .{ .columns = d.columns, .rows = try a.dupe([]const Value, d.rows[d.rows.len - take ..]) };
}

pub const TopSpec = struct { col: []const u8, n: usize, dir: SortDir = .desc };

/// The `n` rows with the largest (`.desc`, pandas' `nlargest`) or smallest (`.asc`,
/// `nsmallest`) `col`, best first, ties in row order, missing cells never chosen.
pub fn nlargest(a: std.mem.Allocator, d: Dataset, spec: TopSpec) Error!Dataset {
    try keys.checkRect(d);
    const present = try dropna(a, d, .{ .subset = &.{spec.col} });
    const sorted = try sort(a, present, .{ .key = spec.col, .dir = spec.dir });
    return page(a, sorted, .{ .limit = spec.n });
}

pub const SampleSpec = struct {
    /// Rows to draw; above the row count without `replace` it is the row count.
    n: usize,
    seed: u64,
    /// Draw with replacement (pandas' `replace=True`).
    replace: bool = false,
};

/// A random sample of rows (borrowed), reproducible from `seed`, in draw order.
/// No engine's stream is reproduced: the same seed agrees only with itself.
pub fn sample(a: std.mem.Allocator, d: Dataset, spec: SampleSpec) Error!Dataset {
    try keys.checkRect(d);
    var prng = std.Random.DefaultPrng.init(spec.seed);
    const r = prng.random();
    if (spec.replace) {
        if (d.rows.len == 0) return .{ .columns = d.columns, .rows = &.{} };
        const cells = std.math.mul(usize, spec.n, @max(d.columns.len, 1)) catch return error.TooLarge;
        if (cells > max_aggregate_cells) return error.TooLarge;
        const rows = try a.alloc([]const Value, spec.n);
        for (rows) |*o| o.* = d.rows[r.uintLessThan(usize, d.rows.len)];
        return .{ .columns = d.columns, .rows = rows };
    }
    const rows = try a.dupe([]const Value, d.rows);
    const take = @min(spec.n, rows.len);
    // Partial Fisher-Yates: the first `take` slots are the draw.
    for (0..take) |i| {
        const j = i + r.uintLessThan(usize, rows.len - i);
        std.mem.swap([]const Value, &rows[i], &rows[j]);
    }
    return .{ .columns = d.columns, .rows = rows[0..take] };
}

// ── partition ───────────────────────────────────────────────────────────────

pub const Partition = struct {
    /// The partition's key cells, in `by` order, from its first row.
    key: []const Value,
    /// Its rows (borrowed), in input order.
    table: Dataset,
};

/// One table per distinct key, first-seen order (polars' `partition_by`, pandas'
/// `for key, group in df.groupby(...)`): the escape hatch for per-group logic no verb
/// says, as `filterBy` is for predicates. A missing key is a partition of its own.
pub fn partitionBy(a: std.mem.Allocator, d: Dataset, by: []const []const u8) Error![]const Partition {
    try keys.checkRect(d);
    const idxs = try a.alloc(usize, by.len);
    for (idxs, by) |*ix, name| ix.* = try mustIndex(d, name);
    const f = try keys.factorize(a, d.rows, idxs, .as_null);
    defer a.free(f.ids);
    const mem = try keys.members(a, f.ids, f.groups());
    const rows = try a.alloc([]const Value, d.rows.len);
    const out = try a.alloc(Partition, f.groups());
    for (out, f.firsts, 0..) |*p, first, g| {
        const key = try a.alloc(Value, idxs.len);
        for (key, idxs) |*k, ci| k.* = d.rows[first][ci];
        const part = rows[mem.offs[g]..mem.offs[g + 1]];
        for (part, mem.of(g)) |*r, ri| r.* = d.rows[ri];
        p.* = .{ .key = key, .table = .{ .columns = d.columns, .rows = part } };
    }
    return out;
}

// ── concat by name ──────────────────────────────────────────────────────────

/// Stack tables, matching columns by name (pandas' `concat`, polars' `diagonal`,
/// SQL's `UNION ALL BY NAME`; `Dataset.concat` needs one schema). Columns in
/// first-seen order, a table without a column gives null there, the declared type is
/// the first table's that has it. A name a single table repeats reads as its first.
pub fn concatByName(a: std.mem.Allocator, tables: []const Dataset) Error!Dataset {
    var names: std.StringArrayHashMapUnmanaged(ColumnType) = .empty;
    var total: usize = 0;
    for (tables) |t| {
        try keys.checkRect(t);
        total = std.math.add(usize, total, t.rows.len) catch return error.TooLarge;
        for (t.columns) |c| {
            const gop = try names.getOrPut(a, c.name);
            if (!gop.found_existing) gop.value_ptr.* = c.type;
        }
    }
    const width = names.count();
    const n_cells = std.math.mul(usize, total, width) catch return error.TooLarge;
    if (n_cells > max_aggregate_cells) return error.TooLarge;
    const cols = try a.alloc(Column, width);
    for (cols, names.keys(), names.values()) |*c, n, ty| c.* = .{ .name = n, .type = ty };
    const rows = try a.alloc([]const Value, total);
    const cells = try a.alloc(Value, n_cells);
    const source = try a.alloc(?usize, width);
    defer a.free(source);
    var at: usize = 0;
    for (tables) |t| {
        for (source, cols) |*m, c| m.* = t.columnIndex(c.name);
        for (t.rows) |r| {
            const nr = cells[at * width ..][0..width];
            for (nr, source) |*o, m| o.* = if (m) |ci| r[ci] else .null;
            rows[at] = nr;
            at += 1;
        }
    }
    return .{ .columns = cols, .rows = rows };
}

// ── value_counts / describe ─────────────────────────────────────────────────

pub const ValueCountsSpec = struct {
    cols: []const []const u8,
    out: []const u8 = "count",
    /// Count missing keys too (pandas' `dropna=False`).
    keep_missing: bool = false,
};

/// Rows per distinct key, most frequent first, ties in first-seen order.
pub fn valueCounts(a: std.mem.Allocator, d: Dataset, spec: ValueCountsSpec) Error!Dataset {
    try keys.checkRect(d);
    if (spec.cols.len == 0) return error.NoSuchColumn;
    const g = try aggregate(a, d, .{
        .group_by = spec.cols,
        .aggs = &.{.{ .src = spec.cols[0], .out = spec.out, .func = .size }},
        .drop_missing_keys = !spec.keep_missing,
    });
    // By position: `out` may be numbered if a key column has that name.
    return sortBy(a, g, &.{g.columns.len - 1}, &.{.desc}, .auto);
}

/// pandas' `describe()`: one row per statistic (`count`, `mean`, `std`, `min`, `25%`,
/// `50%`, `75%`, `max`), a first column `statistic`, then one float column per
/// numeric column (`cols` empty) or per named column, missing values skipped.
pub fn describe(a: std.mem.Allocator, d: Dataset, cols_in: []const []const u8) Error!Dataset {
    try keys.checkRect(d);
    var names: std.ArrayList([]const u8) = .empty;
    if (cols_in.len > 0) {
        for (cols_in) |c| {
            _ = try mustIndex(d, c);
            try names.append(a, c);
        }
    } else {
        for (d.columns) |c| {
            if (c.type == .int or c.type == .float or c.type == .decimal) try names.append(a, c.name);
        }
    }
    const stats = [_]struct { name: []const u8, func: AggFn, q: f64 = 0.5 }{
        .{ .name = "count", .func = .count },
        .{ .name = "mean", .func = .mean },
        .{ .name = "std", .func = .std },
        .{ .name = "min", .func = .min },
        .{ .name = "25%", .func = .quantile, .q = 0.25 },
        .{ .name = "50%", .func = .median },
        .{ .name = "75%", .func = .quantile, .q = 0.75 },
        .{ .name = "max", .func = .max },
    };
    const cols = try a.alloc(Column, 1 + names.items.len);
    cols[0] = .{ .name = "statistic", .type = .text };
    for (cols[1..], names.items) |*c, n| c.* = .{ .name = n, .type = .float };
    const rows = try a.alloc([]const Value, stats.len);
    const cells = try a.alloc(Value, stats.len * cols.len);
    @memset(cells, .null);
    for (rows, stats, 0..) |*row, st, si| {
        const nr = cells[si * cols.len ..][0..cols.len];
        nr[0] = .{ .text = st.name };
        row.* = nr;
    }
    const aggs = try a.alloc(AggCol, stats.len);
    defer a.free(aggs);
    for (names.items, 0..) |n, ci| {
        for (aggs, stats) |*ag, st| ag.* = .{ .src = n, .out = st.name, .func = st.func, .q = st.q };
        const one = try aggregate(a, d, .{ .group_by = &.{}, .aggs = aggs, .skip_na = true });
        if (one.rows.len == 0) continue; // no rows: every statistic stays null
        for (one.rows[0], 0..) |v, si| {
            cells[si * cols.len + 1 + ci] = if (v.asFloat()) |x| .{ .float = x } else .null;
        }
    }
    return .{ .columns = cols, .rows = rows };
}

// ── clip / replace / cut ────────────────────────────────────────────────────

pub const ClipSpec = struct { col: []const u8, lower: ?f64 = null, upper: ?f64 = null };

/// Bound a numeric column in place of the old one (pandas' `clip`). Missing and
/// non-numeric cells stay as they are. An int column stays int under whole bounds and
/// turns float, every cell, under a bound that is not (both engines promote too).
pub fn clip(a: std.mem.Allocator, d: Dataset, spec: ClipSpec) Error!Dataset {
    try keys.checkRect(d);
    const ci = try mustIndex(d, spec.col);
    const col_type = d.columns[ci].type;
    const whole = struct {
        fn f(b: ?f64) bool {
            const x = b orelse return true;
            if (std.math.isNan(x)) return true; // never applies
            const i = Value.floatToInt(i64, x) orelse return false;
            return @as(f64, @floatFromInt(i)) == x;
        }
    }.f;
    const to_float = col_type == .int and !(whole(spec.lower) and whole(spec.upper));
    const cols = try a.dupe(Column, d.columns);
    if (to_float) cols[ci].type = .float;
    const bound = struct {
        fn f(x: f64, ty: ColumnType) Value {
            return switch (ty) {
                .int => .{ .int = Value.floatToInt(i64, x).? },
                .decimal => (Value{ .float = x }).cast(.decimal) orelse .{ .float = x },
                else => .{ .float = x },
            };
        }
    }.f;
    const out_type = cols[ci].type;
    const rows = try a.alloc([]const Value, d.rows.len);
    const cells = try a.alloc(Value, d.rows.len * d.columns.len);
    for (d.rows, 0..) |r, ri| {
        const nr = cells[ri * d.columns.len ..][0..d.columns.len];
        @memcpy(nr, r);
        if (!isMissing(r[ci])) {
            if (r[ci].asFloat()) |x| {
                if (to_float) nr[ci] = .{ .float = x };
                if (spec.lower) |lo| {
                    if (x < lo) nr[ci] = bound(lo, out_type);
                }
                if (spec.upper) |hi| {
                    if (x > hi) nr[ci] = bound(hi, out_type);
                }
            }
        }
        rows[ri] = nr;
    }
    return .{ .columns = cols, .rows = rows };
}

pub const ReplacePair = struct { from: Value, to: Value };
pub const ReplaceSpec = struct { col: []const u8, pairs: []const ReplacePair };

/// Map values of a column by key equality (pandas' `replace`); the first matching
/// pair wins, and a missing `from` matches missing cells. The declared type stays: a
/// `to` of another kind is the caller's to `cast`.
pub fn replace(a: std.mem.Allocator, d: Dataset, spec: ReplaceSpec) Error!Dataset {
    try keys.checkRect(d);
    const ci = try mustIndex(d, spec.col);
    var t = try keys.Table.initBytes(a, spec.pairs.len, keys.freshSeed(@intFromPtr(d.rows.ptr)));
    t.allow(d.rows.len);
    var scratch: std.ArrayList(u8) = .empty;
    defer scratch.deinit(a);
    const tos = try a.alloc(Value, spec.pairs.len);
    defer a.free(tos);
    var n: u32 = 0;
    for (spec.pairs) |p| {
        scratch.clearRetainingCapacity();
        try keys.encode(a, &scratch, p.from, .as_null);
        const id = try t.getOrPutBytes(a, scratch.items);
        if (id == n) {
            tos[id] = p.to;
            n += 1;
        }
    }
    const rows = try a.alloc([]const Value, d.rows.len);
    const cells = try a.alloc(Value, d.rows.len * d.columns.len);
    for (d.rows, 0..) |r, ri| {
        const nr = cells[ri * d.columns.len ..][0..d.columns.len];
        @memcpy(nr, r);
        scratch.clearRetainingCapacity();
        try keys.encode(a, &scratch, r[ci], .as_null);
        if (try t.getBytes(scratch.items)) |id| nr[ci] = tos[id];
        rows[ri] = nr;
    }
    return .{ .columns = d.columns, .rows = rows };
}

pub const CutSpec = struct {
    col: []const u8,
    out: []const u8,
    /// Ascending bin edges, at least two: `edges.len - 1` bins.
    edges: []const f64,
    /// One per bin. Empty: the output is the bin's 0-based number (pandas'
    /// `labels=False`), `.int`.
    labels: []const []const u8 = &.{},
    /// Bins `(a, b]` (pandas' default) or, false, `[a, b)`.
    right: bool = true,
    /// The first bin (or, with `right = false`, the last) also takes its outer edge.
    include_lowest: bool = false,
};

pub const CutError = Error || error{BadEdges};

/// Bin a numeric column (pandas' `cut`). Outside every bin, missing, or not a number:
/// null. Edges not strictly ascending or NaN, or a label count that is not the bin
/// count: `error.BadEdges`.
pub fn cut(a: std.mem.Allocator, d: Dataset, spec: CutSpec) CutError!Dataset {
    try keys.checkRect(d);
    const ci = try mustIndex(d, spec.col);
    const e = spec.edges;
    if (e.len < 2) return error.BadEdges;
    for (e[0 .. e.len - 1], e[1..]) |l, m| {
        if (!(l < m)) return error.BadEdges;
    }
    if (spec.labels.len != 0 and spec.labels.len != e.len - 1) return error.BadEdges;
    const cols = try a.alloc(Column, d.columns.len + 1);
    @memcpy(cols[0..d.columns.len], d.columns);
    cols[d.columns.len] = .{ .name = spec.out, .type = if (spec.labels.len != 0) .text else .int };
    const rows = try a.alloc([]const Value, d.rows.len);
    const cells = try a.alloc(Value, d.rows.len * cols.len);
    for (d.rows, 0..) |r, ri| {
        const nr = cells[ri * cols.len ..][0..cols.len];
        @memcpy(nr[0..d.columns.len], r);
        nr[d.columns.len] = .null;
        rows[ri] = nr;
        if (isMissing(r[ci])) continue;
        const x = r[ci].asFloat() orelse continue;
        const bin: ?usize = blk: {
            // First edge above x (or at or above it, for right-closed bins).
            var lo: usize = 0;
            var hi: usize = e.len;
            while (lo < hi) {
                const mid = lo + (hi - lo) / 2;
                if (if (spec.right) e[mid] < x else e[mid] <= x) lo = mid + 1 else hi = mid;
            }
            if (lo == 0) {
                break :blk if (spec.right and spec.include_lowest and x == e[0]) 0 else null;
            }
            if (lo == e.len) {
                break :blk if (!spec.right and spec.include_lowest and x == e[e.len - 1]) e.len - 2 else null;
            }
            break :blk lo - 1;
        };
        if (bin) |b| {
            nr[d.columns.len] = if (spec.labels.len != 0) .{ .text = spec.labels[b] } else .{ .int = @intCast(b) };
        }
    }
    return .{ .columns = cols, .rows = rows };
}

// ── format ──────────────────────────────────────────────────────────────────

pub const FormatKind = enum { num, money, pct, compact, signed };
pub const FormatSpec = struct {
    kind: FormatKind = .num,
    decimals: u8 = 2,
    /// Symbol prefix for `money` (e.g. "$", "€", "" for none).
    symbol: []const u8 = "",
};

/// Format a numeric value for presentation. (Formatting is a presentation
/// modifier, not a dataset node — this is the value-level helper; `formatColumn`
/// wraps it into a dataset transform.)
pub fn format(a: std.mem.Allocator, value: f64, spec: FormatSpec) Error![]const u8 {
    const p: usize = spec.decimals; // runtime precision via named "{[n]d:.[p]}"
    return switch (spec.kind) {
        .num => a.print("{[n]d:.[p]}", .{ .n = value, .p = p }),
        .money => a.print("{[s]s}{[n]d:.[p]}", .{ .s = spec.symbol, .n = value, .p = p }),
        .pct => a.print("{[n]d:.[p]}%", .{ .n = value * 100, .p = p }),
        .signed => a.print("{[s]s}{[n]d:.[p]}", .{ .s = if (value >= 0) "+" else "", .n = value, .p = p }),
        .compact => blk: {
            const av = @abs(value);
            const suffix: []const u8, const div: f64 = if (av >= 1e9)
                .{ "B", 1e9 }
            else if (av >= 1e6)
                .{ "M", 1e6 }
            else if (av >= 1e3)
                .{ "K", 1e3 }
            else
                .{ "", 1 };
            break :blk a.print("{[n]d:.[p]}{[s]s}", .{ .n = value / div, .p = p, .s = suffix });
        },
    };
}

/// Append a text column `out` = `format(row[src], spec)` (non-numeric → "").
pub fn formatColumn(a: std.mem.Allocator, d: Dataset, src: []const u8, out: []const u8, spec: FormatSpec) Error!Dataset {
    try keys.checkRect(d);
    const si = try mustIndex(d, src);
    const cols = try a.alloc(Column, d.columns.len + 1);
    @memcpy(cols[0..d.columns.len], d.columns);
    cols[d.columns.len] = .{ .name = out, .type = .text };
    const rows = try a.alloc([]const Value, d.rows.len);
    for (d.rows, 0..) |r, ri| {
        const txt: []const u8 = if (r[si].asFloat()) |f| try format(a, f, spec) else "";
        const nr = try a.alloc(Value, cols.len);
        @memcpy(nr[0..d.columns.len], r);
        nr[d.columns.len] = .{ .text = txt };
        rows[ri] = nr;
    }
    return .{ .columns = cols, .rows = rows };
}

// ── tests ───────────────────────────────────────────────────────────────────
const testing = std.testing;

/// A fixture arena that frees everything on deinit — mirrors the pipeline arena.
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

test "map: pl = mv - cost" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{ .{ .name = "mv", .type = .float }, .{ .name = "cost", .type = .float } };
    const rows = [_][]const Value{
        &.{ .{ .float = 100 }, .{ .float = 70 } },
        &.{ .{ .float = 50 }, .{ .float = 80 } },
    };
    const out = try map(f.a(), .{ .columns = &cols, .rows = &rows }, .{
        .out = "pl",
        .lhs = .{ .col = "mv" },
        .op = .sub,
        .rhs = .{ .col = "cost" },
    });
    try testing.expectEqual(@as(usize, 3), out.columns.len);
    try testing.expectEqual(@as(f64, 30), out.cell(0, "pl").?.float);
    try testing.expectEqual(@as(f64, -30), out.cell(1, "pl").?.float);
}

test "aggregate: group sum" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{ .{ .name = "cat", .type = .text }, .{ .name = "v", .type = .float } };
    const rows = [_][]const Value{
        &.{ .{ .text = "a" }, .{ .float = 1 } },
        &.{ .{ .text = "b" }, .{ .float = 10 } },
        &.{ .{ .text = "a" }, .{ .float = 2 } },
    };
    const out = try aggregate(f.a(), .{ .columns = &cols, .rows = &rows }, .{
        .group_by = &.{"cat"},
        .aggs = &.{.{ .src = "v", .out = "total", .func = .sum }},
    });
    try testing.expectEqual(@as(usize, 2), out.rows.len); // a, b in first-seen order
    try testing.expectEqualStrings("a", out.cell(0, "cat").?.text);
    try testing.expectEqual(@as(f64, 3), out.cell(0, "total").?.float);
    try testing.expectEqual(@as(f64, 10), out.cell(1, "total").?.float);
}

test "aggregate: fx-convert-before-sum (null rate = 1.0)" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{
        .{ .name = "ccy", .type = .text },
        .{ .name = "amt", .type = .float },
        .{ .name = "fx", .type = .float },
    };
    const rows = [_][]const Value{
        &.{ .{ .text = "x" }, .{ .float = 100 }, .{ .float = 2 } }, // 200
        &.{ .{ .text = "x" }, .{ .float = 50 }, .null }, // null rate → 50
    };
    const out = try aggregate(f.a(), .{ .columns = &cols, .rows = &rows }, .{
        .group_by = &.{"ccy"},
        .aggs = &.{.{ .src = "amt", .out = "base", .func = .sum }},
        .fx = .{ .rate_col = "fx" },
    });
    try testing.expectEqual(@as(f64, 250), out.cell(0, "base").?.float);
}

test "aggregate: mean/min/max/count/first/last" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{ .{ .name = "g", .type = .text }, .{ .name = "v", .type = .float } };
    const rows = [_][]const Value{
        &.{ .{ .text = "g" }, .{ .float = 4 } },
        &.{ .{ .text = "g" }, .{ .float = 2 } },
        &.{ .{ .text = "g" }, .{ .float = 6 } },
    };
    const out = try aggregate(f.a(), .{ .columns = &cols, .rows = &rows }, .{
        .group_by = &.{"g"},
        .aggs = &.{
            .{ .src = "v", .out = "mean", .func = .mean },
            .{ .src = "v", .out = "min", .func = .min },
            .{ .src = "v", .out = "max", .func = .max },
            .{ .src = "v", .out = "n", .func = .count },
            .{ .src = "v", .out = "first", .func = .first },
            .{ .src = "v", .out = "last", .func = .last },
        },
    });
    try testing.expectEqual(@as(f64, 4), out.cell(0, "mean").?.float);
    try testing.expectEqual(@as(f64, 2), out.cell(0, "min").?.float);
    try testing.expectEqual(@as(f64, 6), out.cell(0, "max").?.float);
    try testing.expectEqual(@as(i64, 3), out.cell(0, "n").?.int);
    try testing.expectEqual(@as(f64, 4), out.cell(0, "first").?.float);
    try testing.expectEqual(@as(f64, 6), out.cell(0, "last").?.float);
}

test "weightedGroupSum: weighted alloc + unassigned bucket" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{
        .{ .name = "cat", .type = .text },
        .{ .name = "mv", .type = .float },
        .{ .name = "w", .type = .float },
    };
    const rows = [_][]const Value{
        &.{ .{ .text = "equity" }, .{ .float = 100 }, .{ .float = 0.6 } }, // 60
        &.{ .{ .text = "bond" }, .{ .float = 100 }, .{ .float = 0.4 } }, // 40
        &.{ .null, .{ .float = 25 }, .{ .float = 1 } }, // 25 → (unassigned)
    };
    const out = try weightedGroupSum(f.a(), .{ .columns = &cols, .rows = &rows }, .{
        .group_col = "cat",
        .value_col = "mv",
        .weight_col = "w",
    });
    try testing.expectEqual(@as(usize, 3), out.rows.len);
    try testing.expectEqual(@as(f64, 60), out.cell(0, "value").?.float);
    try testing.expectEqual(@as(f64, 40), out.cell(1, "value").?.float);
    try testing.expectEqualStrings("(unassigned)", out.cell(2, "group").?.text);
    try testing.expectEqual(@as(f64, 25), out.cell(2, "value").?.float);
}

test "percentOfTotal shares sum to 100" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{ .{ .name = "cat", .type = .text }, .{ .name = "v", .type = .float } };
    const rows = [_][]const Value{
        &.{ .{ .text = "a" }, .{ .float = 30 } },
        &.{ .{ .text = "b" }, .{ .float = 10 } },
        &.{ .{ .text = "c" }, .{ .float = 60 } },
    };
    const out = try percentOfTotal(f.a(), .{ .columns = &cols, .rows = &rows }, .{ .value_col = "v", .out = "pct" });
    try testing.expectApproxEqAbs(@as(f64, 30), out.cell(0, "pct").?.float, 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 60), out.cell(2, "pct").?.float, 1e-9);
}

test "sort: desc by value" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{ .{ .name = "s", .type = .text }, .{ .name = "v", .type = .float } };
    const rows = [_][]const Value{
        &.{ .{ .text = "a" }, .{ .float = 1 } },
        &.{ .{ .text = "b" }, .{ .float = 3 } },
        &.{ .{ .text = "c" }, .{ .float = 2 } },
    };
    const out = try sort(f.a(), .{ .columns = &cols, .rows = &rows }, .{ .key = "v", .dir = .desc });
    try testing.expectEqualStrings("b", out.cell(0, "s").?.text);
    try testing.expectEqualStrings("c", out.cell(1, "s").?.text);
    try testing.expectEqualStrings("a", out.cell(2, "s").?.text);
}

test "sort: multi-column tie-break" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{ .{ .name = "grp", .type = .text }, .{ .name = "v", .type = .float }, .{ .name = "s", .type = .text } };
    const rows = [_][]const Value{
        &.{ .{ .text = "b" }, .{ .float = 1 }, .{ .text = "b1" } },
        &.{ .{ .text = "a" }, .{ .float = 2 }, .{ .text = "a2" } },
        &.{ .{ .text = "a" }, .{ .float = 1 }, .{ .text = "a1" } },
    };
    // primary key `grp` alone would leave the two "a" rows in input order
    // (a2 before a1) — the tie-break on `v` must reorder them to a1, a2.
    const out = try sort(f.a(), .{ .columns = &cols, .rows = &rows }, .{
        .key = "grp",
        .then_by = &.{.{ .key = "v" }},
    });
    try testing.expectEqualStrings("a1", out.cell(0, "s").?.text);
    try testing.expectEqualStrings("a2", out.cell(1, "s").?.text);
    try testing.expectEqualStrings("b1", out.cell(2, "s").?.text);
}

test "page: limit/offset windows correctly" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{.{ .name = "v", .type = .int }};
    const rows = [_][]const Value{
        &.{.{ .int = 0 }}, &.{.{ .int = 1 }}, &.{.{ .int = 2 }}, &.{.{ .int = 3 }}, &.{.{ .int = 4 }},
    };
    const mid = try page(f.a(), .{ .columns = &cols, .rows = &rows }, .{ .offset = 1, .limit = 2 });
    try testing.expectEqual(@as(usize, 2), mid.rows.len);
    try testing.expectEqual(@as(i64, 1), mid.cell(0, "v").?.int);
    try testing.expectEqual(@as(i64, 2), mid.cell(1, "v").?.int);

    const rest = try page(f.a(), .{ .columns = &cols, .rows = &rows }, .{ .offset = 3 }); // no limit → to the end
    try testing.expectEqual(@as(usize, 2), rest.rows.len);
    try testing.expectEqual(@as(i64, 3), rest.cell(0, "v").?.int);

    const past_end = try page(f.a(), .{ .columns = &cols, .rows = &rows }, .{ .offset = 99, .limit = 5 });
    try testing.expectEqual(@as(usize, 0), past_end.rows.len);
}

test "topN with tail fold" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{ .{ .name = "s", .type = .text }, .{ .name = "v", .type = .float } };
    const rows = [_][]const Value{
        &.{ .{ .text = "a" }, .{ .float = 10 } },
        &.{ .{ .text = "b" }, .{ .float = 5 } },
        &.{ .{ .text = "c" }, .{ .float = 3 } },
        &.{ .{ .text = "d" }, .{ .float = 2 } },
    };
    const out = try topN(f.a(), .{ .columns = &cols, .rows = &rows }, .{
        .n = 2,
        .tail = .{ .label_col = "s", .label = "Other", .value_col = "v" },
    });
    try testing.expectEqual(@as(usize, 3), out.rows.len);
    try testing.expectEqualStrings("Other", out.cell(2, "s").?.text);
    try testing.expectEqual(@as(f64, 5), out.cell(2, "v").?.float); // 3 + 2
}

test "pivot: month x year" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{
        .{ .name = "year", .type = .text },
        .{ .name = "month", .type = .text },
        .{ .name = "ret", .type = .float },
    };
    const rows = [_][]const Value{
        &.{ .{ .text = "2023" }, .{ .text = "01" }, .{ .float = 1 } },
        &.{ .{ .text = "2023" }, .{ .text = "02" }, .{ .float = 2 } },
        &.{ .{ .text = "2024" }, .{ .text = "01" }, .{ .float = 3 } },
    };
    const out = try pivot(f.a(), .{ .columns = &cols, .rows = &rows }, .{
        .row_key = "year",
        .col_key = "month",
        .value_col = "ret",
    });
    try testing.expectEqual(@as(usize, 3), out.columns.len); // year, "01", "02"
    try testing.expectEqual(@as(usize, 2), out.rows.len);
    try testing.expectEqual(@as(f64, 1), out.cell(0, "01").?.float);
    try testing.expectEqual(@as(f64, 2), out.cell(0, "02").?.float);
    try testing.expectEqual(@as(f64, 3), out.cell(1, "01").?.float);
    try testing.expect(out.cell(1, "02").?.isNull()); // 2024-02 missing
}

test "pivot: numeric-aware column ordering puts 10 after 2, not before" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{
        .{ .name = "row", .type = .text },
        .{ .name = "week", .type = .text }, // unpadded numeric text: "2", "10"
        .{ .name = "v", .type = .float },
    };
    const rows = [_][]const Value{
        &.{ .{ .text = "r1" }, .{ .text = "10" }, .{ .float = 1 } },
        &.{ .{ .text = "r1" }, .{ .text = "2" }, .{ .float = 2 } },
        &.{ .{ .text = "r1" }, .{ .text = "9" }, .{ .float = 3 } },
    };
    const out = try pivot(f.a(), .{ .columns = &cols, .rows = &rows }, .{ .row_key = "row", .col_key = "week", .value_col = "v" });
    // lexicographic would order "10" < "2" < "9"; numeric-aware must be 2, 9, 10.
    try testing.expectEqualStrings("2", out.columns[1].name);
    try testing.expectEqualStrings("9", out.columns[2].name);
    try testing.expectEqualStrings("10", out.columns[3].name);
}

test "pivot: non-numeric column keys still sort lexicographically" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{
        .{ .name = "row", .type = .text },
        .{ .name = "cat", .type = .text },
        .{ .name = "v", .type = .float },
    };
    const rows = [_][]const Value{
        &.{ .{ .text = "r1" }, .{ .text = "beta" }, .{ .float = 1 } },
        &.{ .{ .text = "r1" }, .{ .text = "alpha" }, .{ .float = 2 } },
    };
    const out = try pivot(f.a(), .{ .columns = &cols, .rows = &rows }, .{ .row_key = "row", .col_key = "cat", .value_col = "v" });
    try testing.expectEqualStrings("alpha", out.columns[1].name);
    try testing.expectEqualStrings("beta", out.columns[2].name);
}

test "unpivot: wide -> long round-trips a known wide table" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{
        .{ .name = "id", .type = .text },
        .{ .name = "jan", .type = .float },
        .{ .name = "feb", .type = .float },
    };
    const rows = [_][]const Value{
        &.{ .{ .text = "AAA" }, .{ .float = 10 }, .{ .float = 20 } },
        &.{ .{ .text = "BBB" }, .{ .float = 30 }, .{ .float = 40 } },
    };
    const out = try unpivot(f.a(), .{ .columns = &cols, .rows = &rows }, .{ .id_cols = &.{"id"} });
    try testing.expectEqual(@as(usize, 4), out.rows.len); // 2 rows x 2 melted cols
    try testing.expectEqual(@as(usize, 3), out.columns.len); // id, variable, value
    try testing.expectEqualStrings("AAA", out.cell(0, "id").?.text);
    try testing.expectEqualStrings("jan", out.cell(0, "variable").?.text);
    try testing.expectApproxEqAbs(@as(f64, 10), out.cell(0, "value").?.float, 1e-9);
    try testing.expectEqualStrings("feb", out.cell(1, "variable").?.text);
    try testing.expectApproxEqAbs(@as(f64, 20), out.cell(1, "value").?.float, 1e-9);
    try testing.expectEqualStrings("BBB", out.cell(2, "id").?.text);
    try testing.expectEqualStrings("jan", out.cell(2, "variable").?.text);
    try testing.expectApproxEqAbs(@as(f64, 30), out.cell(2, "value").?.float, 1e-9);

    // round-trip: pivot the melted table back and recover the original cells.
    const back = try pivot(f.a(), out, .{ .row_key = "id", .col_key = "variable", .value_col = "value" });
    try testing.expectApproxEqAbs(@as(f64, 10), back.cell(0, "jan").?.float, 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 20), back.cell(0, "feb").?.float, 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 30), back.cell(1, "jan").?.float, 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 40), back.cell(1, "feb").?.float, 1e-9);
}

test "resample: monthly compound + sum" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{ .{ .name = "d", .type = .date }, .{ .name = "r", .type = .float } };
    const rows = [_][]const Value{
        &.{ .{ .text = "2024-01-10" }, .{ .float = 0.1 } },
        &.{ .{ .text = "2024-01-20" }, .{ .float = 0.1 } },
        &.{ .{ .text = "2024-02-05" }, .{ .float = 0.5 } },
    };
    const comp = try resample(f.a(), .{ .columns = &cols, .rows = &rows }, .{
        .date_col = "d",
        .value_col = "r",
        .freq = .month,
        .agg = .compound,
    });
    try testing.expectEqual(@as(usize, 2), comp.rows.len);
    try testing.expectEqualStrings("2024-01", comp.cell(0, "period").?.text);
    try testing.expectApproxEqAbs(@as(f64, 0.21), comp.cell(0, "value").?.float, 1e-9); // 1.1*1.1-1
    try testing.expectApproxEqAbs(@as(f64, 0.5), comp.cell(1, "value").?.float, 1e-9);
}

test "resample: sum/mean/first/last aggregations" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{ .{ .name = "d", .type = .date }, .{ .name = "r", .type = .float } };
    const rows = [_][]const Value{
        &.{ .{ .text = "2024-01-10" }, .{ .float = 1 } },
        &.{ .{ .text = "2024-01-20" }, .{ .float = 2 } },
        &.{ .{ .text = "2024-01-25" }, .{ .float = 3 } },
    };
    const sum_out = try resample(f.a(), .{ .columns = &cols, .rows = &rows }, .{
        .date_col = "d",
        .value_col = "r",
        .freq = .month,
        .agg = .sum,
    });
    try testing.expectApproxEqAbs(@as(f64, 6), sum_out.cell(0, "value").?.float, 1e-9);

    const mean_out = try resample(f.a(), .{ .columns = &cols, .rows = &rows }, .{
        .date_col = "d",
        .value_col = "r",
        .freq = .month,
        .agg = .mean,
    });
    try testing.expectApproxEqAbs(@as(f64, 2), mean_out.cell(0, "value").?.float, 1e-9);

    const first_out = try resample(f.a(), .{ .columns = &cols, .rows = &rows }, .{
        .date_col = "d",
        .value_col = "r",
        .freq = .month,
        .agg = .first,
    });
    try testing.expectApproxEqAbs(@as(f64, 1), first_out.cell(0, "value").?.float, 1e-9);

    const last_out = try resample(f.a(), .{ .columns = &cols, .rows = &rows }, .{
        .date_col = "d",
        .value_col = "r",
        .freq = .month,
        .agg = .last,
    });
    try testing.expectApproxEqAbs(@as(f64, 3), last_out.cell(0, "value").?.float, 1e-9);
}

test "formatColumn: numeric cells formatted, non-numeric -> empty string" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{ .{ .name = "amt", .type = .float }, .{ .name = "tag", .type = .text } };
    const rows = [_][]const Value{
        &.{ .{ .float = 1234.5 }, .{ .text = "x" } },
        &.{ .{ .text = "n/a" }, .{ .text = "y" } }, // non-numeric src cell
    };
    const out = try formatColumn(f.a(), .{ .columns = &cols, .rows = &rows }, "amt", "amt_fmt", .{ .kind = .money, .symbol = "$" });
    try testing.expectEqual(@as(usize, 3), out.columns.len);
    try testing.expectEqualStrings("$1234.50", out.cell(0, "amt_fmt").?.text);
    try testing.expectEqualStrings("", out.cell(1, "amt_fmt").?.text);
}

test "reduce: table to one KPI row" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{.{ .name = "v", .type = .float }};
    const rows = [_][]const Value{
        &.{.{ .float = 3 }}, &.{.{ .float = 4 }}, &.{.{ .float = 5 }},
    };
    const out = try reduce(f.a(), .{ .columns = &cols, .rows = &rows }, &.{
        .{ .src = "v", .out = "total", .func = .sum },
        .{ .src = "v", .out = "n", .func = .count },
    });
    try testing.expectEqual(@as(usize, 1), out.rows.len);
    try testing.expectEqual(@as(f64, 12), out.cell(0, "total").?.float);
    try testing.expectEqual(@as(i64, 3), out.cell(0, "n").?.int);
}

test "clampRange: inclusive date window" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{ .{ .name = "d", .type = .date }, .{ .name = "v", .type = .float } };
    const rows = [_][]const Value{
        &.{ .{ .text = "2024-01-01" }, .{ .float = 1 } },
        &.{ .{ .text = "2024-06-15" }, .{ .float = 2 } },
        &.{ .{ .text = "2024-12-31" }, .{ .float = 3 } },
    };
    const out = try clampRange(f.a(), .{ .columns = &cols, .rows = &rows }, .{
        .date_col = "d",
        .from = "2024-03-01",
        .to = "2024-09-01",
    });
    try testing.expectEqual(@as(usize, 1), out.rows.len);
    try testing.expectEqual(@as(f64, 2), out.cell(0, "v").?.float);
}

test "clampRange: from/to bounds are inclusive at the exact edge" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{ .{ .name = "d", .type = .date }, .{ .name = "v", .type = .float } };
    const rows = [_][]const Value{
        &.{ .{ .text = "2024-03-01" }, .{ .float = 1 } }, // exactly `from`
        &.{ .{ .text = "2024-06-15" }, .{ .float = 2 } },
        &.{ .{ .text = "2024-09-01" }, .{ .float = 3 } }, // exactly `to`
    };
    const out = try clampRange(f.a(), .{ .columns = &cols, .rows = &rows }, .{
        .date_col = "d",
        .from = "2024-03-01",
        .to = "2024-09-01",
    });
    try testing.expectEqual(@as(usize, 3), out.rows.len); // all three kept, boundaries included
}

test "format: kinds" {
    var f = Fix.init();
    defer f.deinit();
    try testing.expectEqualStrings("1234.50", try format(f.a(), 1234.5, .{ .kind = .num }));
    try testing.expectEqualStrings("$1234.50", try format(f.a(), 1234.5, .{ .kind = .money, .symbol = "$" }));
    try testing.expectEqualStrings("12.30%", try format(f.a(), 0.123, .{ .kind = .pct }));
    try testing.expectEqualStrings("+5.00", try format(f.a(), 5, .{ .kind = .signed }));
    try testing.expectEqualStrings("-5.00", try format(f.a(), -5, .{ .kind = .signed }));
    try testing.expectEqualStrings("1.50M", try format(f.a(), 1_500_000, .{ .kind = .compact, .decimals = 2 }));
}

// ── 2026-10-04: filter / columns / NA / map ops / statistics ────────────────

const nan = std.math.nan(f64);

const filt_cols = [_]Column{ .{ .name = "x", .type = .float }, .{ .name = "s", .type = .text } };
const filt_rows = [_][]const Value{
    &.{ .{ .float = 1 }, .{ .text = "a" } },
    &.{ .null, .{ .text = "b" } },
    &.{ .{ .float = 3 }, .null },
    &.{ .{ .float = nan }, .{ .text = "a" } },
    &.{ .{ .int = 5 }, .{ .text = "c" } },
};
const filt_ds: Dataset = .{ .columns = &filt_cols, .rows = &filt_rows };

fn keptRows(d: Dataset) [8]usize {
    // Index of each kept row in `filt_rows` (they are borrowed, so pointer
    // identity tells which), padded with maxInt.
    var out = @as([8]usize, @splat(std.math.maxInt(usize)));
    for (d.rows, 0..) |r, i| {
        for (filt_rows, 0..) |orig, j| if (r.ptr == orig.ptr) {
            out[i] = j;
        };
    }
    return out;
}

fn expectKept(d: Dataset, want: []const usize) !void {
    try testing.expectEqual(want.len, d.rows.len);
    const got = keptRows(d);
    try testing.expectEqualSlices(usize, want, got[0..want.len]);
}

test "filter: SQL three-valued rule — a missing cell (null or NaN) matches only is_null" {
    var f = Fix.init();
    defer f.deinit();
    const a = f.a();
    // x > 2: 3 and the int 5 (int and float compare by value).
    try expectKept(try filter(a, filt_ds, .{ .where = &.{.{ .col = "x", .op = .gt, .value = .{ .float = 2 } }} }), &.{ 2, 4 });
    // x != 1: NOT the null row and NOT the NaN row — unknown is not "different".
    try expectKept(try filter(a, filt_ds, .{ .where = &.{.{ .col = "x", .op = .ne, .value = .{ .int = 1 } }} }), &.{ 2, 4 });
    try expectKept(try filter(a, filt_ds, .{ .where = &.{.{ .col = "x", .op = .is_null }} }), &.{ 1, 3 });
    try expectKept(try filter(a, filt_ds, .{ .where = &.{.{ .col = "x", .op = .not_null }} }), &.{ 0, 2, 4 });
    try expectKept(try filter(a, filt_ds, .{ .where = &.{.{ .col = "x", .op = .le, .value = .{ .float = 3 } }} }), &.{ 0, 2 });
    try expectKept(try filter(a, filt_ds, .{ .where = &.{.{ .col = "x", .op = .ge, .value = .{ .float = 3 } }} }), &.{ 2, 4 });
    try expectKept(try filter(a, filt_ds, .{ .where = &.{.{ .col = "x", .op = .lt, .value = .{ .float = 3 } }} }), &.{0});
    try expectKept(try filter(a, filt_ds, .{ .where = &.{.{ .col = "x", .op = .eq, .value = .{ .float = 3 } }} }), &.{2});
    // Text compares bytewise; a number never equals text, either way round.
    try expectKept(try filter(a, filt_ds, .{ .where = &.{.{ .col = "s", .op = .eq, .value = .{ .text = "a" } }} }), &.{ 0, 3 });
    try expectKept(try filter(a, filt_ds, .{ .where = &.{.{ .col = "s", .op = .gt, .value = .{ .text = "a" } }} }), &.{ 1, 4 });
    try expectKept(try filter(a, filt_ds, .{ .where = &.{.{ .col = "x", .op = .eq, .value = .{ .text = "1" } }} }), &.{});
    try expectKept(try filter(a, filt_ds, .{ .where = &.{.{ .col = "x", .op = .ne, .value = .{ .text = "1" } }} }), &.{});
    // A null literal compares with nothing.
    try expectKept(try filter(a, filt_ds, .{ .where = &.{.{ .col = "x", .op = .ne }} }), &.{});
    // AND / OR, and the empty identities (all-of-nothing = true, any-of-nothing = false).
    const two = [_]Predicate{
        .{ .col = "x", .op = .lt, .value = .{ .float = 2 } },
        .{ .col = "s", .op = .eq, .value = .{ .text = "c" } },
    };
    try expectKept(try filter(a, filt_ds, .{ .where = &two, .mode = .any }), &.{ 0, 4 });
    try expectKept(try filter(a, filt_ds, .{ .where = &two }), &.{});
    const both = [_]Predicate{
        .{ .col = "x", .op = .not_null },
        .{ .col = "s", .op = .eq, .value = .{ .text = "a" } },
    };
    try expectKept(try filter(a, filt_ds, .{ .where = &both }), &.{0});
    try expectKept(try filter(a, filt_ds, .{ .where = &.{} }), &.{ 0, 1, 2, 3, 4 });
    try expectKept(try filter(a, filt_ds, .{ .where = &.{}, .mode = .any }), &.{});
    try testing.expectError(error.NoSuchColumn, filter(a, filt_ds, .{ .where = &.{.{ .col = "nope", .op = .is_null }} }));
    // Two decimals one raw unit apart are different values; f64 could not tell.
    const dc = [_]Column{.{ .name = "m", .type = .decimal }};
    const dr = [_][]const Value{ &.{.{ .decimal = (1 << 60) + 1 }}, &.{.{ .decimal = 1 << 60 }} };
    const dd = try filter(a, .{ .columns = &dc, .rows = &dr }, .{ .where = &.{.{ .col = "m", .op = .gt, .value = .{ .decimal = 1 << 60 } }} });
    try testing.expectEqual(@as(usize, 1), dd.rows.len);
    try testing.expectEqual(@as(i128, (1 << 60) + 1), dd.rows[0][0].decimal);
}

fn evenX(min: f64, row: []const Value) bool {
    const x = row[0].asFloat() orelse return false;
    return x >= min and @mod(x, 2) == 1;
}

test "filterBy: arbitrary predicate with context" {
    var f = Fix.init();
    defer f.deinit();
    try expectKept(try filterBy(f.a(), filt_ds, @as(f64, 2), evenX), &.{ 2, 4 });
}

test "select / drop / rename" {
    var f = Fix.init();
    defer f.deinit();
    const a = f.a();
    const cols = [_]Column{ .{ .name = "a", .type = .int }, .{ .name = "b", .type = .text }, .{ .name = "c", .type = .float } };
    const rows = [_][]const Value{&.{ .{ .int = 1 }, .{ .text = "x" }, .{ .float = 2.5 } }};
    const d: Dataset = .{ .columns = &cols, .rows = &rows };

    const s1 = try select(a, d, &.{ "c", "a" });
    try testing.expectEqual(@as(usize, 2), s1.columns.len);
    try testing.expectEqualStrings("c", s1.columns[0].name);
    try testing.expectEqual(ColumnType.float, s1.columns[0].type);
    try testing.expectEqual(@as(f64, 2.5), s1.rows[0][0].float);
    try testing.expectEqual(@as(i64, 1), s1.rows[0][1].int);
    try testing.expectError(error.DuplicateColumn, select(a, d, &.{ "a", "a" }));
    try testing.expectError(error.NoSuchColumn, select(a, d, &.{"z"}));

    const d1 = try drop(a, d, &.{"b"});
    try testing.expectEqual(@as(usize, 2), d1.columns.len);
    try testing.expectEqualStrings("a", d1.columns[0].name);
    try testing.expectEqualStrings("c", d1.columns[1].name);
    try testing.expectEqual(@as(f64, 2.5), d1.rows[0][1].float);
    try testing.expectError(error.NoSuchColumn, drop(a, d, &.{"z"}));
    try testing.expectEqual(@as(usize, 0), (try drop(a, d, &.{ "a", "b", "c" })).columns.len);

    // Simultaneous: a<->b swaps names, the cells stay where they were.
    const r1 = try rename(a, d, &.{ .{ .from = "a", .to = "b" }, .{ .from = "b", .to = "a" } });
    try testing.expectEqualStrings("b", r1.columns[0].name);
    try testing.expectEqualStrings("a", r1.columns[1].name);
    try testing.expectEqual(ColumnType.int, r1.columns[0].type);
    try testing.expect(r1.rows.ptr == d.rows.ptr); // rows shared, only the schema is new
    try testing.expectEqualStrings("a", d.columns[0].name); // input untouched
    try testing.expectError(error.DuplicateColumn, rename(a, d, &.{.{ .from = "a", .to = "c" }}));
    try testing.expectError(error.DuplicateColumn, rename(a, d, &.{ .{ .from = "a", .to = "p" }, .{ .from = "a", .to = "q" } }));
    try testing.expectError(error.NoSuchColumn, rename(a, d, &.{.{ .from = "z", .to = "y" }}));
    // Renaming to its own name is not a collision.
    _ = try rename(a, d, &.{.{ .from = "a", .to = "a" }});
}

test "dropna / fillna: null and NaN are missing" {
    var f = Fix.init();
    defer f.deinit();
    const a = f.a();
    try expectKept(try dropna(a, filt_ds, .{}), &.{ 0, 4 });
    try expectKept(try dropna(a, filt_ds, .{ .subset = &.{"x"} }), &.{ 0, 2, 4 });
    try expectKept(try dropna(a, filt_ds, .{ .subset = &.{"s"} }), &.{ 0, 1, 3, 4 });
    // how=all: no row here has BOTH cells missing.
    try expectKept(try dropna(a, filt_ds, .{ .how = .all }), &.{ 0, 1, 2, 3, 4 });
    const allnull = [_][]const Value{ &.{ .null, .null }, &.{ .{ .float = nan }, .{ .text = "k" } } };
    try testing.expectEqual(@as(usize, 1), (try dropna(a, .{ .columns = &filt_cols, .rows = &allnull }, .{ .how = .all })).rows.len);
    try testing.expectError(error.NoSuchColumn, dropna(a, filt_ds, .{ .subset = &.{"z"} }));

    const filled = try fillna(a, filt_ds, .{ .subset = &.{"x"}, .value = .{ .float = 0 } });
    try testing.expectEqual(@as(usize, 5), filled.rows.len);
    try testing.expectEqual(@as(f64, 0), filled.rows[1][0].float);
    try testing.expectEqual(@as(f64, 0), filled.rows[3][0].float); // NaN filled too
    try testing.expect(filled.rows[2][1] == .null); // outside the subset
    try testing.expect(filled.rows[0].ptr == filt_rows[0].ptr); // untouched rows shared
    try testing.expect(filled.rows[1].ptr != filt_rows[1].ptr);
    try testing.expect(filt_rows[1][0] == .null); // input not mutated
    const all = try fillna(a, filt_ds, .{ .value = .{ .text = "?" } });
    try testing.expectEqualStrings("?", all.rows[2][1].text);
    try testing.expectEqualStrings("?", all.rows[1][0].text);
}

test "map: abs / sqrt / min / max, and on_missing" {
    var f = Fix.init();
    defer f.deinit();
    const a = f.a();
    const cols = [_]Column{ .{ .name = "x", .type = .float }, .{ .name = "y", .type = .float } };
    const rows = [_][]const Value{
        &.{ .{ .float = -4 }, .{ .float = 1 } },
        &.{ .{ .float = 9 }, .{ .float = 2 } },
        &.{ .null, .{ .float = 3 } },
        &.{ .{ .float = 6 }, .{ .float = 0 } },
    };
    const d: Dataset = .{ .columns = &cols, .rows = &rows };
    const Case = struct { op: BinOp, zero: [4]?f64, nul: [4]?f64 };
    const cases = [_]Case{
        // abs ignores rhs; null reads as 0 under .zero.
        .{ .op = .abs, .zero = .{ 4, 9, 0, 6 }, .nul = .{ 4, 9, null, 6 } },
        // sqrt(-4) has no real root: 0 / null; sqrt(9) = 3, sqrt(6) = 2.449…
        .{ .op = .sqrt, .zero = .{ 0, 3, 0, @sqrt(6.0) }, .nul = .{ null, 3, null, @sqrt(6.0) } },
        .{ .op = .min, .zero = .{ -4, 2, 0, 0 }, .nul = .{ -4, 2, null, 0 } },
        .{ .op = .max, .zero = .{ 1, 9, 3, 6 }, .nul = .{ 1, 9, null, 6 } },
        // 6 / 0 is undefined: 0 (historical) or null.
        .{ .op = .div, .zero = .{ -4, 4.5, 0, 0 }, .nul = .{ -4, 4.5, null, null } },
    };
    for (cases) |c| {
        for ([_]OnMissing{ .zero, .null }) |om| {
            const out = try map(a, d, .{ .out = "o", .lhs = .{ .col = "x" }, .op = c.op, .rhs = .{ .col = "y" }, .on_missing = om });
            const want = if (om == .zero) c.zero else c.nul;
            for (want, 0..) |w, i| {
                const got = out.rows[i][2];
                if (w) |wv| try testing.expectEqual(wv, got.float) else try testing.expect(got == .null);
            }
        }
    }
    // A unary op needs no rhs column — not even an existing one.
    const u = try map(a, d, .{ .out = "o", .lhs = .{ .col = "x" }, .op = .abs, .rhs = .{ .col = "missing" } });
    try testing.expectEqual(@as(f64, 4), u.rows[0][2].float);
    try testing.expectError(error.NoSuchColumn, map(a, d, .{ .out = "o", .lhs = .{ .col = "x" }, .op = .min, .rhs = .{ .col = "missing" } }));
}

test "aggregate: std / var / median / quantile / nunique skip missing values" {
    var f = Fix.init();
    defer f.deinit();
    const a = f.a();
    // Group "g": 2 4 4 4 5 5 7 9 plus a null, a NaN and a text cell. The
    // eight numbers are the textbook example with population sd 2: Σ(x−5)² = 32,
    // so the sample variance is 32/7.
    const cols = [_]Column{ .{ .name = "k", .type = .text }, .{ .name = "v", .type = .float } };
    var rows: std.ArrayList([]const Value) = .empty;
    for ([_]f64{ 2, 4, 4, 4, 5, 5, 7, 9 }) |x| try rows.append(a, try a.dupe(Value, &.{ .{ .text = "g" }, .{ .float = x } }));
    try rows.append(a, try a.dupe(Value, &.{ .{ .text = "g" }, .null }));
    try rows.append(a, try a.dupe(Value, &.{ .{ .text = "g" }, .{ .float = nan } }));
    try rows.append(a, try a.dupe(Value, &.{ .{ .text = "g" }, .{ .text = "x" } }));
    try rows.append(a, try a.dupe(Value, &.{ .{ .text = "h" }, .{ .int = 3 } }));
    const d: Dataset = .{ .columns = &cols, .rows = rows.items };
    const out = try aggregate(a, d, .{ .group_by = &.{"k"}, .aggs = &.{
        .{ .src = "v", .out = "sd", .func = .std },
        .{ .src = "v", .out = "var", .func = .@"var" },
        .{ .src = "v", .out = "med", .func = .median },
        .{ .src = "v", .out = "q25", .func = .quantile, .q = 0.25 },
        .{ .src = "v", .out = "q90", .func = .quantile, .q = 0.9 },
        .{ .src = "v", .out = "qbad", .func = .quantile, .q = 1.5 },
        .{ .src = "v", .out = "qnan", .func = .quantile, .q = nan },
        .{ .src = "v", .out = "nu", .func = .nunique },
        .{ .src = "v", .out = "q0", .func = .quantile, .q = 0 },
        .{ .src = "v", .out = "q1", .func = .quantile, .q = 1 },
    } });
    try testing.expectEqual(@as(usize, 2), out.rows.len);
    const g = out.rows[0];
    try testing.expectApproxEqRel(@sqrt(32.0 / 7.0), g[1].float, 1e-15);
    try testing.expectApproxEqRel(32.0 / 7.0, g[2].float, 1e-15);
    // Median of 8: mean of the 4th and 5th order statistics, (4 + 5) / 2.
    try testing.expectEqual(@as(f64, 4.5), g[3].float);
    // Type 7: h = 7·0.25 = 1.75 → x[1] + 0.75·(x[2] − x[1]) = 4 + 0.75·0 = 4.
    try testing.expectEqual(@as(f64, 4), g[4].float);
    // h = 7·0.9 = 6.3 → x[6] + 0.3·(x[7] − x[6]) = 7 + 0.3·2 = 7.6.
    try testing.expectApproxEqAbs(@as(f64, 7.6), g[5].float, 1e-12);
    try testing.expect(g[6] == .null);
    try testing.expect(g[7] == .null);
    // Distinct non-missing: 2 4 5 7 9 and the text "x" = 6 (null and NaN skipped).
    try testing.expectEqual(@as(i64, 6), g[8].int);
    try testing.expectEqual(@as(f64, 2), g[9].float);
    try testing.expectEqual(@as(f64, 9), g[10].float);
    // Group "h" has one value: no sample variance; the median is the value.
    const h = out.rows[1];
    try testing.expect(h[1] == .null);
    try testing.expect(h[2] == .null);
    try testing.expectEqual(@as(f64, 3), h[3].float);
    try testing.expectEqual(@as(i64, 1), h[8].int);
    try testing.expectEqual(ColumnType.float, out.columns[1].type);
    try testing.expectEqual(ColumnType.int, out.columns[8].type);
}

test "aggregate: nunique keys by kind — text \"1\" is not the number 1, float 1.0 is" {
    var f = Fix.init();
    defer f.deinit();
    const a = f.a();
    const cols = [_]Column{.{ .name = "v", .type = .text }};
    const rows = [_][]const Value{ &.{.{ .text = "1" }}, &.{.{ .int = 1 }}, &.{.{ .float = 1.0 }}, &.{.null} };
    const out = try reduce(a, .{ .columns = &cols, .rows = &rows }, &.{.{ .src = "v", .out = "n", .func = .nunique }});
    try testing.expectEqual(@as(i64, 2), out.rows[0][0].int);
}

test "aggregate: sum_exact is i128 addition, null on overflow" {
    var f = Fix.init();
    defer f.deinit();
    const a = f.a();
    const tenth: i128 = @divExact(ds.decimal_scale, 10);
    const cols = [_]Column{ .{ .name = "k", .type = .text }, .{ .name = "m", .type = .decimal }, .{ .name = "fx", .type = .float } };
    const rows = [_][]const Value{
        &.{ .{ .text = "a" }, .{ .decimal = tenth }, .null },
        &.{ .{ .text = "a" }, .{ .decimal = tenth }, .null },
        &.{ .{ .text = "a" }, .{ .decimal = tenth }, .null },
        &.{ .{ .text = "a" }, .{ .int = 2 }, .null },
        &.{ .{ .text = "a" }, .null, .null },
        &.{ .{ .text = "b" }, .{ .decimal = std.math.maxInt(i128) }, .null },
        &.{ .{ .text = "b" }, .{ .decimal = 1 }, .null },
        &.{ .{ .text = "b" }, .{ .decimal = -5 }, .null },
        &.{ .{ .text = "c" }, .{ .decimal = 3 * @divExact(ds.decimal_scale, 2) }, .{ .float = 2 } },
    };
    const d: Dataset = .{ .columns = &cols, .rows = &rows };
    const out = try aggregate(a, d, .{ .group_by = &.{"k"}, .aggs = &.{
        .{ .src = "m", .out = "exact", .func = .sum_exact },
        .{ .src = "m", .out = "f64", .func = .sum },
    } });
    try testing.expectEqual(ColumnType.decimal, out.columns[1].type);
    // 0.1 + 0.1 + 0.1 + 2 = 2.3 exactly; the null is skipped.
    try testing.expectEqual(@as(i128, 23 * tenth), out.rows[0][1].decimal);
    // Ten 0.1s: exactly 1 in i128; the f64 path gives Python's well-known
    // sum([0.1] * 10) = 0.9999999999999999.
    var ten: [10][]const Value = undefined;
    for (&ten) |*r| r.* = &.{ .{ .text = "a" }, .{ .decimal = tenth }, .null };
    const t = try aggregate(a, .{ .columns = &cols, .rows = &ten }, .{ .group_by = &.{"k"}, .aggs = &.{
        .{ .src = "m", .out = "exact", .func = .sum_exact },
        .{ .src = "m", .out = "f64", .func = .sum },
    } });
    try testing.expectEqual(ds.decimal_scale, t.rows[0][1].decimal);
    try testing.expectEqual(@as(f64, 0.9999999999999999), t.rows[0][2].float);
    // maxInt + 1 overflows; a later −5 must not "repair" it.
    try testing.expect(out.rows[1][1] == .null);
    // With fx: a null rate keeps decimals exact (groups a/b above went through
    // the same code without fx); rate 2 goes through f64: 1.5 × 2 = 3 exactly.
    const fxd = try aggregate(a, d, .{ .group_by = &.{"k"}, .aggs = &.{.{ .src = "m", .out = "exact", .func = .sum_exact }}, .fx = .{ .rate_col = "fx" } });
    try testing.expectEqual(@as(i128, 23 * tenth), fxd.rows[0][1].decimal);
    try testing.expectEqual(@as(i128, 3 * ds.decimal_scale), fxd.rows[2][1].decimal);
}

test "pivot: a statistical agg per cell" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{ .{ .name = "r", .type = .text }, .{ .name = "c", .type = .text }, .{ .name = "v", .type = .float } };
    const rows = [_][]const Value{
        &.{ .{ .text = "x" }, .{ .text = "p" }, .{ .float = 1 } },
        &.{ .{ .text = "x" }, .{ .text = "p" }, .{ .float = 10 } },
        &.{ .{ .text = "x" }, .{ .text = "p" }, .{ .float = 2 } },
    };
    // Median of {1, 10, 2} is 2; quantile 0.75: h = 1.5 → 2 + 0.5·(10 − 2) = 6.
    const med = try pivot(f.a(), .{ .columns = &cols, .rows = &rows }, .{ .row_key = "r", .col_key = "c", .value_col = "v", .agg = .median });
    try testing.expectEqual(@as(f64, 2), med.rows[0][1].float);
    const q = try pivot(f.a(), .{ .columns = &cols, .rows = &rows }, .{ .row_key = "r", .col_key = "c", .value_col = "v", .agg = .quantile, .q = 0.75 });
    try testing.expectEqual(@as(f64, 6), q.rows[0][1].float);
}

test "resample / clampRange read a .timestamp column (UTC calendar day)" {
    var f = Fix.init();
    defer f.deinit();
    const a = f.a();
    const us = ds.timestamp_units_per_second;
    const cols = [_]Column{ .{ .name = "t", .type = .timestamp }, .{ .name = "v", .type = .float } };
    const rows = [_][]const Value{
        // 1969-12-31T23:59:59Z — one second before the epoch is still 1969.
        &.{ .{ .int = -us }, .{ .float = 1 } },
        // 2024-01-31T23:00:00Z and 2024-02-01T01:00:00Z (1706742000, 1706749200).
        &.{ .{ .int = 1706742000 * us }, .{ .float = 2 } },
        &.{ .{ .int = 1706749200 * us }, .{ .float = 4 } },
        &.{ .null, .{ .float = 8 } },
    };
    const d: Dataset = .{ .columns = &cols, .rows = &rows };
    const m = try resample(a, d, .{ .date_col = "t", .value_col = "v", .freq = .month });
    try testing.expectEqual(@as(usize, 3), m.rows.len);
    try testing.expectEqualStrings("1969-12", m.rows[0][0].text);
    try testing.expectEqualStrings("2024-01", m.rows[1][0].text);
    try testing.expectEqualStrings("2024-02", m.rows[2][0].text);
    try testing.expectEqual(@as(f64, 4), m.rows[2][1].float);
    const c = try clampRange(a, d, .{ .date_col = "t", .from = "2024-02-01" });
    try testing.expectEqual(@as(usize, 1), c.rows.len);
    try testing.expectEqual(@as(f64, 4), c.rows[0][1].float);
}

test "edge cases the mutation run asked for (transforms)" {
    var f = Fix.init();
    defer f.deinit();
    const a = f.a();
    const cols = [_]Column{ .{ .name = "x", .type = .float }, .{ .name = "y", .type = .float } };
    const rows = [_][]const Value{
        &.{ .{ .float = -0.25 }, .null },
        &.{ .{ .float = 4 }, .{ .float = 1 } },
    };
    const d: Dataset = .{ .columns = &cols, .rows = &rows };
    // A null RHS is missing too (only the LHS was checked by the earlier test).
    const m = try map(a, d, .{ .out = "o", .lhs = .{ .col = "x" }, .op = .add, .rhs = .{ .col = "y" }, .on_missing = .null });
    try testing.expect(m.rows[0][2] == .null);
    try testing.expectEqual(@as(f64, 5), m.rows[1][2].float);
    // sqrt of a negative number above −1 is still undefined (not NaN).
    const s = try map(a, d, .{ .out = "o", .lhs = .{ .col = "x" }, .op = .sqrt, .rhs = .{ .col = "no such" }, .on_missing = .null });
    try testing.expect(s.rows[0][2] == .null);
    try testing.expectEqual(@as(f64, 2), s.rows[1][2].float);
    // A NaN literal is missing: `x < NaN` holds for no row (Value.order would
    // otherwise rank NaN above every number).
    try expectKept(try filter(a, filt_ds, .{ .where = &.{.{ .col = "x", .op = .lt, .value = .{ .float = nan } }} }), &.{});
    // fillna leaves a row's present cells alone.
    const all = try fillna(a, filt_ds, .{ .value = .{ .text = "?" } });
    try testing.expectEqual(@as(f64, 3), all.rows[2][0].float);
    // dropna(how = all) over zero columns: "all of nothing is missing" must
    // not drop every row.
    const empty_rows = [_][]const Value{ &.{}, &.{} };
    try testing.expectEqual(@as(usize, 2), (try dropna(a, .{ .columns = &.{}, .rows = &empty_rows }, .{ .how = .all })).rows.len);
    // An int in a column that is NOT `.timestamp` is not a date.
    const dc = [_]Column{ .{ .name = "t", .type = .date }, .{ .name = "v", .type = .float } };
    const dr = [_][]const Value{ &.{ .{ .int = 0 }, .{ .float = 1 } }, &.{ .{ .text = "2024-05-06" }, .{ .float = 2 } } };
    const r = try resample(a, .{ .columns = &dc, .rows = &dr }, .{ .date_col = "t", .value_col = "v", .freq = .year });
    try testing.expectEqual(@as(usize, 1), r.rows.len);
    try testing.expectEqualStrings("2024", r.rows[0][0].text);
    // sum_exact with a null fx rate keeps a decimal that f64 cannot hold:
    // 123456789.012345678901 has 21 significant digits, f64 carries ~16.
    const big: i128 = 123456789_012345678901;
    const fc = [_]Column{ .{ .name = "m", .type = .decimal }, .{ .name = "fx", .type = .float } };
    const fr = [_][]const Value{&.{ .{ .decimal = big }, .null }};
    const fx = try aggregate(a, .{ .columns = &fc, .rows = &fr }, .{ .group_by = &.{}, .aggs = &.{.{ .src = "m", .out = "s", .func = .sum_exact }}, .fx = .{ .rate_col = "fx" } });
    try testing.expectEqual(big, fx.rows[0][0].decimal);
}
