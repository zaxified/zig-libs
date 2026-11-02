// SPDX-License-Identifier: MIT
//! Window functions, optionally per group: pandas' `groupby(...).shift/rolling/
//! cumsum/rank/transform`, polars' `.over(...)`, SQL's `OVER (PARTITION BY ...)`.
//! One verb, `window`: partition, compute one column in each partition, in row order
//! within it, and put the result back at the rows' original places.
//!
//! These follow pandas' skip-NA defaults, unlike the older `series` verbs (which read
//! a missing cell as 0, a rule kept for wgs's dashboards): a missing value is skipped
//! and a row whose value is missing gets null where pandas' NaN stays NaN.

const std = @import("std");
const ds = @import("dataset");
const keys = @import("keys.zig");
const t0 = @import("transforms.zig");
const Dataset = ds.Dataset;
const Column = ds.Column;
const ColumnType = ds.ColumnType;
const Value = ds.Value;

pub const Error = error{ NoSuchColumn, OutOfMemory, TooLarge, InvalidDecay };

/// Most element visits one `rolling`/time-window call may do: as `series.max_rolling_work`.
pub const max_window_work: usize = 1 << 30;

pub const WinFn = enum { mean, sum, std, @"var", min, max, count, median };

pub const Rolling = struct {
    window: usize,
    func: WinFn = .mean,
    /// Least non-missing values in the window for a result; null = `window`
    /// (pandas), except `count`, for which it is 0.
    min_periods: ?usize = null,
    /// Label the window's middle row rather than its last (pandas' `center`).
    center: bool = false,
};

pub const RollingTime = struct {
    /// The partition's time column: `.int` cells (e.g. microseconds in a
    /// `.timestamp` column) ascending within the partition; a row breaking the
    /// order or with a missing time gets null.
    time_col: []const u8,
    /// Window `(t - period, t]`, in the time column's units (pandas' `"7D"`,
    /// polars' `rolling_*_by`). `> 0`, else every row is null.
    period: i64,
    func: WinFn = .mean,
    min_periods: usize = 1,
};

pub const Ewm = struct {
    /// As `series.EwmSpec`: exactly one of the four.
    alpha: ?f64 = null,
    span: ?f64 = null,
    com: ?f64 = null,
    halflife: ?f64 = null,
    adjust: bool = true,
    /// pandas' `ignore_na`: true lets a missing row not age the history.
    ignore_na: bool = false,
    min_periods: usize = 0,
    func: enum { mean, @"var", std } = .mean,
};

pub const RankMethod = enum { average, min, max, first, dense };

pub const Op = union(enum) {
    /// Lag (`n` > 0) or lead (`n` < 0); rows off the end get `fill`.
    shift: struct { n: i64 = 1, fill: Value = .null },
    /// `x[i] - x[i-n]`, null where either is missing or off the end.
    diff: i64,
    /// `x[i] / x[i-n] - 1`, same rule (pandas 3: no implicit fill).
    pct_change: i64,
    cum_sum,
    cum_prod,
    cum_min,
    cum_max,
    /// 0, 1, 2, ... (pandas' `cumcount`), missing cells included.
    cum_count,
    /// 1, 2, 3, ... (SQL's `row_number()`).
    row_number,
    rolling: Rolling,
    rolling_time: RollingTime,
    /// Every row sees the partition's prefix, itself included. `min_periods` 0 = 1.
    expanding: struct { func: WinFn = .mean, min_periods: usize = 1 },
    ewm: Ewm,
    /// 1-based rank by `Value.order`; a missing cell gets null. `dense` and the
    /// others follow pandas' method names.
    rank: struct { method: RankMethod = .average, descending: bool = false },
    /// Carry the last non-missing value forward at most `limit` rows (null = no
    /// limit). A cell of any kind.
    ffill: ?usize,
    /// Carry the next non-missing value backward.
    bfill: ?usize,
    /// Linear, by row position, between non-missing numbers. Leading gaps stay null;
    /// trailing ones too unless `extend_last`: pandas' default fills them with the
    /// last value, polars leaves them null.
    interpolate: struct { extend_last: bool = false },
    /// The partition's aggregate, on every row of it (pandas' `transform`). Takes
    /// `transforms.AggFn`, skipping missing cells.
    transform: struct { func: t0.AggFn, q: f64 = 0.5 },
};

pub const Spec = struct {
    value_col: []const u8,
    out: []const u8,
    op: Op,
    /// Empty = one partition, the whole table.
    partition_by: []const []const u8 = &.{},
};

const missing = keys.isMissing;

fn outType(d: Dataset, vi: usize, op: Op) ColumnType {
    return switch (op) {
        .shift, .ffill, .bfill => d.columns[vi].type,
        .cum_count, .row_number => .int,
        .transform => |t| switch (t.func) {
            .sum, .mean, .std, .@"var", .median, .quantile, .prod, .sem, .skew, .kurt => .float,
            .count, .nunique, .size, .arg_min, .arg_max => .int,
            .any, .all => .bool,
            .sum_exact => .decimal,
            .min, .max, .first, .last, .mode => d.columns[vi].type,
        },
        .rank => |r| if (r.method == .average) .float else .int,
        else => .float,
    };
}

/// Append `spec.out` computed per partition. Row order and the other columns are
/// untouched. Sort first when the window depends on an order (`sort`, then this).
pub fn window(a: std.mem.Allocator, d: Dataset, spec: Spec) Error!Dataset {
    const vi = d.columnIndex(spec.value_col) orelse return error.NoSuchColumn;
    const pidx = try a.alloc(usize, spec.partition_by.len);
    defer a.free(pidx);
    for (spec.partition_by, pidx) |name, *ix| ix.* = d.columnIndex(name) orelse return error.NoSuchColumn;
    const time_ci: ?usize = switch (spec.op) {
        .rolling_time => |rt| d.columnIndex(rt.time_col) orelse return error.NoSuchColumn,
        else => null,
    };

    const out = try a.alloc(Value, d.rows.len);
    defer a.free(out);
    const f = try keys.factorize(a, d.rows, pidx, .as_null);
    defer a.free(f.ids);

    if (spec.op == .transform) {
        try transform(a, d, vi, f, spec.op.transform.func, spec.op.transform.q, out);
    } else {
        const mem = try keys.members(a, f.ids, f.groups());
        const cells = try a.alloc(Value, d.rows.len);
        defer a.free(cells);
        const res = try a.alloc(Value, d.rows.len);
        defer a.free(res);
        const times = try a.alloc(?i64, if (time_ci != null) d.rows.len else 0);
        defer a.free(times);
        for (0..f.groups()) |g| {
            const idx = mem.of(g);
            for (idx, cells[0..idx.len]) |ri, *c| c.* = d.rows[ri][vi];
            if (time_ci) |tc| {
                for (idx, times[0..idx.len]) |ri, *t| t.* = if (d.rows[ri][tc] == .int) d.rows[ri][tc].int else null;
            }
            try computeOne(a, cells[0..idx.len], if (time_ci != null) times[0..idx.len] else &.{}, spec.op, res[0..idx.len]);
            for (idx, res[0..idx.len]) |ri, v| out[ri] = v;
        }
    }

    const cols = try a.alloc(Column, d.columns.len + 1);
    @memcpy(cols[0..d.columns.len], d.columns);
    cols[d.columns.len] = .{ .name = spec.out, .type = outType(d, vi, spec.op) };
    const rows = try a.alloc([]const Value, d.rows.len);
    const block = try a.alloc(Value, d.rows.len * cols.len);
    for (d.rows, out, 0..) |r, v, ri| {
        const nr = block[ri * cols.len ..][0..cols.len];
        @memcpy(nr[0..d.columns.len], r);
        nr[d.columns.len] = v;
        rows[ri] = nr;
    }
    return .{ .columns = cols, .rows = rows };
}

fn transform(a: std.mem.Allocator, d: Dataset, vi: usize, f: keys.Factors, func: t0.AggFn, q: f64, out: []Value) Error!void {
    // The partition keys are already ids: aggregate over a one-column view of them.
    const cols = [_]Column{ .{ .name = "g", .type = .int }, .{ .name = "v", .type = d.columns[vi].type } };
    const rows = try a.alloc([]const Value, d.rows.len);
    defer a.free(rows);
    const block = try a.alloc(Value, 2 * d.rows.len);
    defer a.free(block);
    for (d.rows, f.ids, 0..) |r, g, ri| {
        block[2 * ri] = .{ .int = g };
        block[2 * ri + 1] = r[vi];
        rows[ri] = block[2 * ri ..][0..2];
    }
    const res = try t0.aggregate(a, .{ .columns = &cols, .rows = rows }, .{
        .group_by = &.{"g"},
        .aggs = &.{.{ .src = "v", .out = "r", .func = func, .q = q }},
        .skip_na = true,
    });
    // Ids are first-seen, and so are the aggregate's rows.
    for (f.ids, out) |g, *o| o.* = res.rows[g][1];
}

fn numOrNull(v: Value) ?f64 {
    const x = v.asFloat() orelse return null;
    return if (std.math.isNan(x)) null else x;
}

fn computeOne(a: std.mem.Allocator, cells: []const Value, times: []const ?i64, op: Op, out: []Value) Error!void {
    const n = cells.len;
    switch (op) {
        .shift => |s| {
            for (out, 0..) |*o, i| {
                const j = offset(i, s.n, n);
                o.* = if (j) |k| cells[k] else s.fill;
            }
        },
        .diff, .pct_change => |p| {
            for (out, 0..) |*o, i| {
                o.* = .null;
                const k = offset(i, p, n) orelse continue;
                const x = numOrNull(cells[i]) orelse continue;
                const y = numOrNull(cells[k]) orelse continue;
                o.* = .{ .float = if (op == .diff) x - y else x / y - 1 };
            }
        },
        .cum_sum, .cum_prod, .cum_min, .cum_max => {
            var acc: ?f64 = null;
            for (cells, out) |c, *o| {
                const x = numOrNull(c) orelse {
                    o.* = .null;
                    continue;
                };
                acc = if (acc) |v| switch (op) {
                    .cum_sum => v + x,
                    .cum_prod => v * x,
                    .cum_min => @min(v, x),
                    else => @max(v, x),
                } else x;
                o.* = .{ .float = acc.? };
            }
        },
        .cum_count => for (out, 0..) |*o, i| {
            o.* = .{ .int = @intCast(i) };
        },
        .row_number => for (out, 0..) |*o, i| {
            o.* = .{ .int = @intCast(i + 1) };
        },
        .rolling => |r| try rolling(a, cells, r, out),
        .rolling_time => |r| try rollingTime(a, cells, times, r, out),
        .expanding => |e| try expanding(a, cells, e.func, @max(e.min_periods, 1), out),
        .ewm => |e| try ewm(cells, e, out),
        .rank => |r| try rank(a, cells, r.method, r.descending, out),
        .ffill => |limit| {
            var last: ?Value = null;
            var since: usize = 0;
            for (cells, out) |c, *o| {
                if (!missing(c)) {
                    last = c;
                    since = 0;
                    o.* = c;
                    continue;
                }
                since += 1;
                o.* = if (last != null and (limit == null or since <= limit.?)) last.? else .null;
            }
        },
        .bfill => |limit| {
            var next: ?Value = null;
            var since: usize = 0;
            var i = n;
            while (i > 0) {
                i -= 1;
                if (!missing(cells[i])) {
                    next = cells[i];
                    since = 0;
                    out[i] = cells[i];
                    continue;
                }
                since += 1;
                out[i] = if (next != null and (limit == null or since <= limit.?)) next.? else .null;
            }
        },
        .interpolate => |ip| {
            var prev: ?usize = null;
            for (cells, out, 0..) |c, *o, i| {
                const x = numOrNull(c);
                o.* = if (x) |v| .{ .float = v } else .null;
                if (x == null) continue;
                if (prev) |p| {
                    const y0 = numOrNull(cells[p]).?;
                    const steps: f64 = @floatFromInt(i - p);
                    for (out[p + 1 .. i], 1..) |*g, k| {
                        g.* = .{ .float = y0 + (x.? - y0) * @as(f64, @floatFromInt(k)) / steps };
                    }
                }
                prev = i;
            }
            if (ip.extend_last) {
                if (prev) |p| {
                    for (out[p + 1 ..]) |*g| g.* = out[p];
                }
            }
        },
        .transform => unreachable, // `window` handles it whole, not per partition
    }
}

/// The index `n` rows behind `i` (ahead for negative `n`), when in range.
fn offset(i: usize, by: i64, n: usize) ?usize {
    const target = std.math.sub(i128, @intCast(i), by) catch return null;
    if (target < 0 or target >= n) return null;
    return @intCast(target);
}

fn winStat(vals: []f64, func: WinFn) Value {
    const n = vals.len;
    switch (func) {
        .count => return .{ .float = @floatFromInt(n) },
        .sum, .mean => {
            var s: f64 = 0;
            for (vals) |x| s += x;
            return .{ .float = if (func == .sum) s else s / @as(f64, @floatFromInt(n)) };
        },
        .min => {
            var m = vals[0];
            for (vals) |x| m = @min(m, x);
            return .{ .float = m };
        },
        .max => {
            var m = vals[0];
            for (vals) |x| m = @max(m, x);
            return .{ .float = m };
        },
        .std, .@"var" => {
            if (n < 2) return .null;
            var mean: f64 = 0;
            var m2: f64 = 0;
            for (vals, 1..) |x, k| {
                const dl = x - mean;
                mean += dl / @as(f64, @floatFromInt(k));
                m2 += dl * (x - mean);
            }
            const v = m2 / @as(f64, @floatFromInt(n - 1));
            return .{ .float = if (func == .std) @sqrt(v) else v };
        },
        .median => {
            const h = n / 2;
            keys.selectKth(vals, h);
            if (n % 2 == 1) return .{ .float = vals[h] };
            var lo = vals[0];
            for (vals[0..h]) |x| lo = @max(lo, x);
            return .{ .float = (lo + vals[h]) / 2 };
        },
    }
}

fn rolling(a: std.mem.Allocator, cells: []const Value, r: Rolling, out: []Value) Error!void {
    const n = cells.len;
    if (r.window == 0) {
        @memset(out, .null);
        return;
    }
    const w = @min(r.window, n);
    const work = std.math.mul(usize, n, w) catch return error.TooLarge;
    if (work > max_window_work) return error.TooLarge;
    const min_p = r.min_periods orelse (if (r.func == .count) 0 else r.window);
    const buf = try a.alloc(f64, w);
    defer a.free(buf);
    // Centered: the label is `(window - 1) / 2` rows before the window's end, as in
    // pandas (an even window leans forward by one row less than it looks back).
    const lead = if (r.center) (r.window - 1) / 2 else 0;
    for (out, 0..) |*o, i| {
        const end = @min(n, i +| lead +| 1); // exclusive
        const logical_end = i +| lead +| 1;
        const start = logical_end -| r.window;
        var k: usize = 0;
        if (start < end) {
            for (cells[start..end]) |c| {
                if (numOrNull(c)) |x| {
                    buf[k] = x;
                    k += 1;
                }
            }
        }
        o.* = if (k >= @max(min_p, @as(usize, @intFromBool(r.func != .count)))) winStat(buf[0..k], r.func) else .null;
    }
}

fn rollingTime(a: std.mem.Allocator, cells: []const Value, times: []const ?i64, r: RollingTime, out: []Value) Error!void {
    const n = cells.len;
    const buf = try a.alloc(f64, n);
    defer a.free(buf);
    var start: usize = 0;
    var work: usize = 0;
    var prev: ?i64 = null;
    for (out, 0..) |*o, i| {
        o.* = .null;
        const t = times[i] orelse continue;
        if (r.period <= 0) continue;
        if (prev != null and t < prev.?) continue;
        prev = t;
        // A time so early that subtracting overflows has no row before its window.
        const lo = std.math.sub(i64, t, r.period) catch std.math.minInt(i64);
        while (start < i and (times[start] == null or times[start].? <= lo)) start += 1;
        var k: usize = 0;
        for (cells[start .. i + 1]) |c| {
            if (numOrNull(c)) |x| {
                buf[k] = x;
                k += 1;
            }
        }
        work += i + 1 - start;
        if (work > max_window_work) return error.TooLarge;
        if (k >= @max(r.min_periods, @as(usize, @intFromBool(r.func != .count)))) o.* = winStat(buf[0..k], r.func);
    }
}

fn expanding(a: std.mem.Allocator, cells: []const Value, func: WinFn, min_p: usize, out: []Value) Error!void {
    if (func == .median) {
        // Insertion into a sorted prefix: O(n^2) moves, capped as a window is.
        const n = cells.len;
        const work = std.math.mul(usize, n, n) catch return error.TooLarge;
        if (work > max_window_work) return error.TooLarge;
        const buf = try a.alloc(f64, n);
        defer a.free(buf);
        var k: usize = 0;
        for (cells, out) |c, *o| {
            if (numOrNull(c)) |x| {
                var j = k;
                while (j > 0 and buf[j - 1] > x) : (j -= 1) buf[j] = buf[j - 1];
                buf[j] = x;
                k += 1;
            }
            if (k < min_p) {
                o.* = .null;
                continue;
            }
            o.* = .{ .float = if (k % 2 == 1) buf[k / 2] else (buf[k / 2 - 1] + buf[k / 2]) / 2 };
        }
        return;
    }
    var sum: f64 = 0;
    var mn = std.math.inf(f64);
    var mx = -std.math.inf(f64);
    var mean: f64 = 0;
    var m2: f64 = 0;
    var k: f64 = 0;
    for (cells, out) |c, *o| {
        if (numOrNull(c)) |x| {
            k += 1;
            sum += x;
            mn = @min(mn, x);
            mx = @max(mx, x);
            const dl = x - mean;
            mean += dl / k;
            m2 += dl * (x - mean);
        }
        if (k < @as(f64, @floatFromInt(min_p))) {
            o.* = if (func == .count) .{ .float = k } else .null;
            continue;
        }
        o.* = switch (func) {
            .count => .{ .float = k },
            .sum => .{ .float = sum },
            .mean => .{ .float = sum / k },
            .min => .{ .float = mn },
            .max => .{ .float = mx },
            .@"var" => if (k < 2) .null else .{ .float = m2 / (k - 1) },
            .std => if (k < 2) .null else .{ .float = @sqrt(m2 / (k - 1)) },
            .median => unreachable, // above
        };
    }
}

fn ewmAlpha(e: Ewm) Error!f64 {
    var given: u8 = 0;
    var alpha: f64 = 0;
    if (e.alpha) |x| {
        given += 1;
        if (!(x > 0 and x <= 1)) return error.InvalidDecay;
        alpha = x;
    }
    if (e.span) |x| {
        given += 1;
        if (!(x >= 1)) return error.InvalidDecay;
        alpha = 2 / (x + 1);
    }
    if (e.com) |x| {
        given += 1;
        if (!(x >= 0)) return error.InvalidDecay;
        alpha = 1 / (1 + x);
    }
    if (e.halflife) |x| {
        given += 1;
        if (!(x > 0)) return error.InvalidDecay;
        alpha = 1 - @exp(-std.math.ln2 / x);
    }
    if (given != 1 or !std.math.isFinite(alpha) or alpha <= 0) return error.InvalidDecay;
    return alpha;
}

/// Weighted mean and (with the reliability-weights correction pandas' `bias=False`
/// documents) weighted variance, online, weights decaying by row or by observation.
fn ewm(cells: []const Value, e: Ewm, out: []Value) Error!void {
    const alpha = try ewmAlpha(e);
    const decay = 1 - alpha;
    const new_w: f64 = if (e.adjust) 1 else alpha;
    var mean: ?f64 = null;
    var cov: f64 = 0;
    var sum_w: f64 = 0;
    var sum_w2: f64 = 0;
    var old_w: f64 = 0;
    var seen: usize = 0;
    for (cells, out) |c, *o| {
        const x = numOrNull(c);
        if (x != null) seen += 1;
        if (mean) |m| {
            if (x != null or !e.ignore_na) {
                sum_w *= decay;
                sum_w2 *= decay * decay;
                old_w *= decay;
                if (x) |v| {
                    const m1 = (old_w * m + new_w * v) / (old_w + new_w);
                    cov = (old_w * (cov + (m - m1) * (m - m1)) + new_w * (v - m1) * (v - m1)) / (old_w + new_w);
                    mean = m1;
                    sum_w += new_w;
                    sum_w2 += new_w * new_w;
                    old_w += new_w;
                    if (!e.adjust) {
                        sum_w /= old_w;
                        sum_w2 /= old_w * old_w;
                        old_w = 1;
                    }
                }
            }
        } else if (x) |v| {
            mean = v;
            sum_w = 1;
            sum_w2 = 1;
            old_w = 1;
        }
        if (mean == null or seen < @max(e.min_periods, 1)) {
            o.* = .null;
            continue;
        }
        o.* = switch (e.func) {
            .mean => .{ .float = mean.? },
            .@"var", .std => blk: {
                const num = sum_w * sum_w;
                const den = num - sum_w2;
                if (!(den > 0)) break :blk .null;
                const v = num / den * cov;
                break :blk .{ .float = if (e.func == .std) @sqrt(v) else v };
            },
        };
    }
}

fn rank(a: std.mem.Allocator, cells: []const Value, method: RankMethod, desc: bool, out: []Value) Error!void {
    var order: std.ArrayList(u32) = .empty;
    defer order.deinit(a);
    for (cells, 0..) |c, i| {
        if (!missing(c)) try order.append(a, @intCast(i));
    }
    const Ctx = struct {
        cells: []const Value,
        desc: bool,
        fn lt(s: @This(), l: u32, m: u32) bool {
            const o = s.cells[l].order(s.cells[m]);
            return if (s.desc) o == .gt else o == .lt;
        }
    };
    const ctx: Ctx = .{ .cells = cells, .desc = desc };
    std.mem.sort(u32, order.items, ctx, Ctx.lt); // stable: `first` keeps row order
    @memset(out, .null);
    const xs = order.items;
    var i: usize = 0;
    var dense: i64 = 0;
    while (i < xs.len) {
        var j = i + 1;
        while (j < xs.len and !ctx.lt(xs[i], xs[j])) j += 1;
        dense += 1;
        for (xs[i..j], i..) |ri, k| {
            out[ri] = switch (method) {
                .first => .{ .int = @intCast(k + 1) },
                .min => .{ .int = @intCast(i + 1) },
                .max => .{ .int = @intCast(j) },
                .dense => .{ .int = dense },
                .average => .{ .float = @as(f64, @floatFromInt(i + 1 + j)) / 2 },
            };
        }
        i = j;
    }
}

// ── tests ───────────────────────────────────────────────────────────────────
const testing = std.testing;

fn oneCol(a: std.mem.Allocator, vals: []const ?f64) !Dataset {
    const cols = try a.dupe(Column, &.{.{ .name = "x", .type = .float }});
    const rows = try a.alloc([]const Value, vals.len);
    for (rows, vals) |*r, v| {
        r.* = try a.dupe(Value, &.{if (v) |f| .{ .float = f } else .null});
    }
    return .{ .columns = cols, .rows = rows };
}

fn expectCol(d: Dataset, want: []const ?f64) !void {
    for (d.rows, want) |r, w| {
        const v = r[r.len - 1];
        if (w) |f| {
            try testing.expectApproxEqRel(f, v.asFloat().?, 1e-12);
        } else {
            try testing.expect(v == .null);
        }
    }
}

test "window: partitions keep original row positions; cumulative and shift inside each" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{ .{ .name = "g", .type = .text }, .{ .name = "x", .type = .float } };
    const rows = [_][]const Value{
        &.{ .{ .text = "a" }, .{ .float = 1 } },
        &.{ .{ .text = "b" }, .{ .float = 10 } },
        &.{ .{ .text = "a" }, .{ .float = 2 } },
        &.{ .{ .text = "b" }, .null },
        &.{ .{ .text = "b" }, .{ .float = 30 } },
    };
    const d: Dataset = .{ .columns = &cols, .rows = &rows };
    const cs = try window(a, d, .{ .value_col = "x", .out = "o", .op = .cum_sum, .partition_by = &.{"g"} });
    try expectCol(cs, &.{ 1, 10, 3, null, 40 });
    const sh = try window(a, d, .{ .value_col = "x", .out = "o", .op = .{ .shift = .{} }, .partition_by = &.{"g"} });
    try expectCol(sh, &.{ null, null, 1, 10, null });
    const tr = try window(a, d, .{ .value_col = "x", .out = "o", .op = .{ .transform = .{ .func = .sum } }, .partition_by = &.{"g"} });
    try expectCol(tr, &.{ 3, 40, 3, 40, 40 });
    try testing.expectError(error.NoSuchColumn, window(a, d, .{ .value_col = "zz", .out = "o", .op = .cum_sum }));
}

test "window: extreme shift, zero window and a bad decay are answers, not panics" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const d = try oneCol(a, &.{ 1, 2, 3 });
    try expectCol(try window(a, d, .{ .value_col = "x", .out = "o", .op = .{ .shift = .{ .n = std.math.minInt(i64) } } }), &.{ null, null, null });
    try expectCol(try window(a, d, .{ .value_col = "x", .out = "o", .op = .{ .diff = std.math.maxInt(i64) } }), &.{ null, null, null });
    try expectCol(try window(a, d, .{ .value_col = "x", .out = "o", .op = .{ .rolling = .{ .window = 0 } } }), &.{ null, null, null });
    try expectCol(try window(a, d, .{ .value_col = "x", .out = "o", .op = .{ .rolling = .{ .window = std.math.maxInt(usize), .min_periods = 1 } } }), &.{ 1, 1.5, 2 });
    try expectCol(try window(a, d, .{ .value_col = "x", .out = "o", .op = .{ .rolling = .{ .window = std.math.maxInt(usize), .min_periods = 1, .center = true } } }), &.{ 2, 2, 2 });
    try testing.expectError(error.InvalidDecay, window(a, d, .{ .value_col = "x", .out = "o", .op = .{ .ewm = .{} } }));
}
