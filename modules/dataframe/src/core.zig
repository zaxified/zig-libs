// SPDX-License-Identifier: MIT
//! The group accumulators, the predicate and the window aggregates the verbs share.
//! Not a public namespace. Taken from `tabular` (the same authors, MIT), where its row
//! verbs run the same code: that is what makes their answers this module's oracle.

const std = @import("std");
const ds = @import("value.zig");
const keys = @import("keys.zig");
const spec = @import("spec.zig");
const fm = @import("frame.zig");
const Value = ds.Value;
const ColumnType = ds.ColumnType;
const Error = spec.Error;
const AggFn = spec.AggFn;
const CmpOp = spec.CmpOp;
const Predicate = spec.Predicate;
const isMissing = keys.isMissing;

/// Row indexes are `u32` and `keys.none` (`maxInt(u32)`) is the "no row" marker, so a
/// frame of `keys.none` rows or more cannot be indexed: `error.TooLarge`. Every verb that
/// builds row indexes calls this with the frame's `len` before it allocates (SPEC §
/// Limits). Only a hand-built `Frame` can claim that many rows; a real one holds them.
pub fn checkRowsU32(n: usize) error{TooLarge}!void {
    if (n >= keys.none) return error.TooLarge;
}

/// Effective fx rate for a row: value in `rate_col` (null / missing → 1.0).
pub fn fxRate(row: []const Value, rate_idx: ?usize) f64 {
    const ri = rate_idx orelse return 1.0;
    return row[ri].asFloat() orelse 1.0;
}

/// The fx-converted cell, as `aggregate` sees it.
pub inline fn fxCell(r: []const Value, ci: usize, rate_idx: ?usize) Value {
    const v = r[ci];
    if (rate_idx == null) return v;
    return if (v.asFloat()) |f| .{ .float = f * fxRate(r, rate_idx) } else v;
}

pub inline fn truthy(v: Value) ?bool {
    return switch (v) {
        .bool => |b| b,
        .int => |i| i != 0,
        .uint => |u| u != 0,
        .float => |f| f != 0,
        .decimal => |d| d != 0,
        else => null,
    };
}

/// Where one aggregate column's per-group results go.
pub const Sink = struct {
    cells: []Value,
    stride: usize,
    offset: usize,
    pub inline fn set(s: Sink, g: usize, v: Value) void {
        s.cells[g * s.stride + s.offset] = v;
    }
};

/// Online central moments (Welford/Terriberry), stable where the textbook
/// sums cancel.
pub const Moments = struct {
    n: f64 = 0,
    mean: f64 = 0,
    m2: f64 = 0,
    m3: f64 = 0,
    m4: f64 = 0,

    pub inline fn add2(s: *Moments, x: f64) void {
        s.n += 1;
        const delta = x - s.mean;
        s.mean += delta / s.n;
        s.m2 += delta * (x - s.mean);
    }

    pub inline fn add4(s: *Moments, x: f64) void {
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
pub fn accumulate(
    a: std.mem.Allocator,
    rows: []const []const Value,
    ids: []const u32,
    n: usize,
    ci: usize,
    rate_idx: ?usize,
    func: AggFn,
    o: Opts,
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
            for (st, 0..) |s, g| out.set(g, momentResult(s, func, o.ddof));
        },
        .implode => try accumulateImplode(a, rows, ids, n, ci, out),
        .median, .quantile => try accumulateQuantile(a, rows, ids, n, ci, rate_idx, if (func == .median) 0.5 else o.q, if (func == .median) .linear else o.interp, out),
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
                    .uint => |u| @as(i128, u) * ds.decimal_scale, // u < 2^64: fits
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
            for (acc, over, 0..) |x, ovf, g| out.set(g, if (ovf) .null else .{ .decimal = x });
        },
    }
}

/// The options an `AggCol` carries past its function: `quantile`'s probability and
/// interpolation, the delta degrees of freedom of `std`/`var`/`sem`.
pub const Opts = struct {
    q: f64 = 0.5,
    ddof: u32 = 1,
    interp: spec.Interpolation = .linear,
};

pub fn momentResult(s: Moments, func: AggFn, ddof: u32) Value {
    const n = s.n;
    // pandas: NaN once `n - ddof <= 0`; `ddof = 1` is null below 2 values.
    const d: f64 = @floatFromInt(ddof);
    switch (func) {
        .@"var" => return if (n - d <= 0) .null else .{ .float = s.m2 / (n - d) },
        .std => return if (n - d <= 0) .null else .{ .float = @sqrt(s.m2 / (n - d)) },
        .sem => return if (n - d <= 0) .null else .{ .float = @sqrt(s.m2 / (n - d)) / @sqrt(n) },
        .skew => {
            if (n < 3) return .null;
            if (s.m2 == 0) return .{ .float = 0 }; // no spread: both engines say NaN (`oracle2_test.zig`), `tabular`, the twin, 0
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
pub fn accumulateQuantile(a: std.mem.Allocator, rows: []const []const Value, ids: []const u32, n: usize, ci: usize, rate_idx: ?usize, q: f64, interp: spec.Interpolation, out: Sink) Error!void {
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
    for (0..n) |g| out.set(g, quantileInterp(vals[offs[g]..offs[g + 1]], q, interp));
}

/// `implode`: each group's cells, in row order and missing ones kept, as one list. Every
/// group's elements go into one column (group by group), and each result is a view of
/// its run, so the cost is one copy of the column whatever the group count.
pub fn accumulateImplode(a: std.mem.Allocator, rows: []const []const Value, ids: []const u32, n: usize, ci: usize, out: Sink) Error!void {
    if (rows.len > std.math.maxInt(u32)) return error.TooLarge;
    // Counting sort of the rows by group: `starts[g]` is where group g's run begins.
    const starts = try a.alloc(u32, n + 1);
    defer a.free(starts);
    @memset(starts, 0);
    for (ids) |g| starts[g + 1] += 1;
    for (1..n + 1) |g| starts[g] += starts[g - 1];
    const next = try a.dupe(u32, starts[0..n]);
    defer a.free(next);
    const order = try a.alloc(u32, rows.len);
    defer a.free(order);
    for (ids, 0..) |g, ri| {
        order[next[g]] = @intCast(ri);
        next[g] += 1;
    }
    var b: fm.ColBuilder = .{ .a = a, .hint = rows.len, .depth = 1 };
    for (order) |ri| try b.append(rows[ri][ci]);
    const items = try a.create(fm.ColumnData);
    items.* = b.finish();
    for (0..n) |g| out.set(g, .{ .list = .{ .items = items, .start = starts[g], .end = starts[g + 1] } });
}

/// `nunique` and `mode`: a table over (group, value).
pub fn accumulateDistinct(a: std.mem.Allocator, rows: []const []const Value, ids: []const u32, n: usize, ci: usize, rate_idx: ?usize, func: AggFn, out: Sink) Error!void {
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

/// The functions `accumulateClean` has a loop for.
pub fn cleanFn(func: AggFn) bool {
    return switch (func) {
        .sum, .mean, .std, .@"var", .median, .quantile => true,
        else => false,
    };
}

/// `accumulate` for a column that holds a number in every row (NaN allowed).
pub fn accumulateClean(a: std.mem.Allocator, vals: []const f64, ids: []const u32, n: usize, func: AggFn, o: Opts, skip: bool, out: Sink) Error!void {
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
            for (st, 0..) |s, g| out.set(g, momentResult(s, func, o.ddof));
        },
        .median, .quantile => {
            const p: f64 = if (func == .median) 0.5 else o.q;
            const interp: spec.Interpolation = if (func == .median) .linear else o.interp;
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
            for (0..n) |g| out.set(g, quantileInterp(block[offs[g]..offs[g + 1]], p, interp));
        },
        else => unreachable, // `cleanFn` names these
    }
}

/// Type-7 quantile of `xs` (no NaN), reordering it.
pub fn quantileInPlace(xs: []f64, q: f64) Value {
    return quantileInterp(xs, q, .linear);
}

/// The quantile at `q` (in [0, 1]) of `xs` (no NaN) between the order statistics
/// `floor(h)` and `ceil(h)`, `h = (n - 1) q`, as numpy's and pandas' `interpolation`
/// says: `linear` (type 7), `lower`, `higher`, `midpoint`, `nearest` (`h` rounded half
/// to even, numpy's `around`). Reorders `xs`.
pub fn quantileInterp(xs: []f64, q: f64, interp: spec.Interpolation) Value {
    if (interp == .linear) return quantileLinear(xs, q);
    if (xs.len == 0) return .null;
    const h = @as(f64, @floatFromInt(xs.len - 1)) * q;
    const lo: usize = @intFromFloat(@floor(h));
    const frac = h - @floor(h);
    const hi_i = if (frac == 0) lo else @min(lo + 1, xs.len - 1);
    const pick: usize = switch (interp) {
        .lower => lo,
        .higher => hi_i,
        .nearest => blk: {
            const r = @round(h);
            const even: f64 = if (@abs(h - @trunc(h)) == 0.5) 2 * @round(h / 2) else r;
            break :blk @min(@as(usize, @intFromFloat(even)), xs.len - 1);
        },
        .equiprobable => blk: {
            const c = @ceil(@as(f64, @floatFromInt(xs.len)) * q);
            break :blk if (c < 1) 0 else @min(@as(usize, @intFromFloat(c)) - 1, xs.len - 1);
        },
        .midpoint, .linear => {
            keys.selectKth(xs, lo);
            const x_lo = xs[lo];
            if (hi_i == lo) return .{ .float = x_lo };
            var x_hi = xs[lo + 1];
            for (xs[lo + 2 ..]) |x| x_hi = @min(x_hi, x);
            return .{ .float = (x_lo + x_hi) / 2 };
        },
    };
    keys.selectKth(xs, pick);
    return .{ .float = xs[pick] };
}

fn quantileLinear(xs: []f64, q: f64) Value {
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
pub fn aggregateCellsWithin(groups: usize, aggs: usize) Error!void {
    const cells = std.math.mul(usize, groups, aggs) catch return error.TooLarge;
    if (cells > spec.max_aggregate_cells) return error.TooLarge;
}

/// An integer or float type, the widths included (the fx conversion applies to all of them).
fn isNumericType(t: ds.ColumnType) bool {
    return @import("dtype.zig").isNumeric(t);
}

pub fn aggOutType(columns: []const ds.Column, src_idx: usize, func: AggFn, fx: bool) ColumnType {
    return switch (func) {
        // fx writes a converted cell as a float, whatever the source's numeric kind.
        .min, .max, .first, .last, .mode => if (fx and (columns[src_idx].type == .decimal or isNumericType(columns[src_idx].type)))
            .float
        else
            columns[src_idx].type,
        .sum, .mean, .std, .@"var", .median, .quantile, .prod, .sem, .skew, .kurt => .float,
        .count, .nunique, .size, .arg_min, .arg_max => .int,
        .any, .all => .bool,
        .sum_exact => .decimal,
        .implode => .list,
    };
}

/// `aggOutType`, except that a duration or timestamp source keeps its kind of time where the
/// engines do (pandas `timedelta64`/`datetime64` arithmetic, polars `Duration`/`Datetime`):
/// `sum`, `mean`, `median`, `quantile` and `std` of a duration are a duration; `mean`,
/// `median` and `quantile` of a timestamp are a timestamp and its `std` a duration. The cells
/// `accumulate` produces are floats of microseconds; `aggregate` truncates them toward zero
/// to whole microseconds. `sum` of timestamps, `prod` and `var` stay `.float` (no engine has
/// a time of that kind).
pub fn aggOutTypeTemporal(columns: []const ds.Column, src_idx: usize, func: AggFn, fx: bool) ColumnType {
    const base = aggOutType(columns, src_idx, func, fx);
    if (fx) return base;
    return switch (columns[src_idx].type) {
        .duration => switch (func) {
            .sum, .mean, .median, .quantile, .std => .duration,
            else => base,
        },
        .timestamp => switch (func) {
            .mean, .median, .quantile => .timestamp,
            .std => .duration,
            else => base,
        },
        else => base,
    };
}

pub fn kindOf(v: Value) enum { number, text, bool, list, record, other } {
    return switch (v) {
        .int, .uint, .float, .decimal => .number,
        .text => .text,
        .bool => .bool,
        .list => .list,
        .record => .record,
        .null => .other,
    };
}

pub inline fn cmpHolds(op: CmpOp, comptime T: type, x: T, y: T) bool {
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

pub fn holds(p: Predicate, cell: Value) bool {
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

pub fn windowAgg(w: []const f64, func: spec.RollFn) f64 {
    switch (func) {
        .sum, .mean => {
            var s: f64 = 0;
            for (w) |x| s += x;
            return if (func == .sum) s else s / @as(f64, @floatFromInt(w.len));
        },
        .std_sample => return stdSample(w),
        .min => {
            var m: f64 = std.math.inf(f64);
            for (w) |x| m = @min(m, x);
            return m;
        },
        .max => {
            var m: f64 = -std.math.inf(f64);
            for (w) |x| m = @max(m, x);
            return m;
        },
    }
}

/// Sample (n−1) standard deviation; 0 below two values.
pub fn stdSample(xs: []const f64) f64 {
    if (xs.len < 2) return 0;
    var mean: f64 = 0;
    for (xs) |x| mean += x;
    mean /= @floatFromInt(xs.len);
    var ss: f64 = 0;
    for (xs) |x| ss += (x - mean) * (x - mean);
    return @sqrt(ss / @as(f64, @floatFromInt(xs.len - 1)));
}
