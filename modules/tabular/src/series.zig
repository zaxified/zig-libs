// SPDX-License-Identifier: MIT
//! Dataset algebra **Tier 1** — series math over an (already date-ordered)
//! Dataset. Pure `dataset → dataset` nodes. Callers `sort` by date first where
//! order matters. Most nodes append one derived column; `merge_by_key`/`join`
//! reshape.
//!
//! T1 set: cumsum · cumreturn · drawdown · rolling · pct_change · rebase ·
//! forward_fill · outlier_flag · merge_by_key · date_part · join.

const std = @import("std");
const dsmod = @import("dataset");
const Dataset = dsmod.Dataset;
const Column = dsmod.Column;
const ColumnType = dsmod.ColumnType;
const Value = dsmod.Value;

pub const Error = error{ NoSuchColumn, OutOfMemory };

fn mustIndex(d: Dataset, name: []const u8) Error!usize {
    return d.columnIndex(name) orelse Error.NoSuchColumn;
}

/// Append one float column computed per row from an f64 accumulator closure over
/// the source column values (in current row order). `compute(prev_values_index)`.
fn appendComputed(
    a: std.mem.Allocator,
    d: Dataset,
    out: []const u8,
    values: []const f64,
) Error!Dataset {
    const cols = try a.alloc(Column, d.columns.len + 1);
    @memcpy(cols[0..d.columns.len], d.columns);
    cols[d.columns.len] = .{ .name = out, .type = .float };
    const rows = try a.alloc([]const Value, d.rows.len);
    for (d.rows, 0..) |r, i| {
        const nr = try a.alloc(Value, cols.len);
        @memcpy(nr[0..d.columns.len], r);
        nr[d.columns.len] = .{ .float = values[i] };
        rows[i] = nr;
    }
    return .{ .columns = cols, .rows = rows };
}

fn floatCol(a: std.mem.Allocator, d: Dataset, name: []const u8) Error![]f64 {
    const i = try mustIndex(d, name);
    const out = try a.alloc(f64, d.rows.len);
    for (d.rows, 0..) |r, ri| out[ri] = r[i].asFloat() orelse 0;
    return out;
}

pub const ColSpec = struct { value_col: []const u8, out: []const u8 };

/// Running sum.
pub fn cumsum(a: std.mem.Allocator, d: Dataset, spec: ColSpec) Error!Dataset {
    const v = try floatCol(a, d, spec.value_col);
    var acc: f64 = 0;
    for (v) |*x| {
        acc += x.*;
        x.* = acc;
    }
    return appendComputed(a, d, spec.out, v);
}

/// Running compounded return Π(1+r) − 1 (the TWR curve, fractional).
pub fn cumreturn(a: std.mem.Allocator, d: Dataset, spec: ColSpec) Error!Dataset {
    const v = try floatCol(a, d, spec.value_col);
    var prod: f64 = 1;
    for (v) |*x| {
        prod *= (1 + x.*);
        x.* = prod - 1;
    }
    return appendComputed(a, d, spec.out, v);
}

/// Running-peak underwater curve of a LEVEL series: (v − peak) / peak (≤ 0).
pub fn drawdown(a: std.mem.Allocator, d: Dataset, spec: ColSpec) Error!Dataset {
    const v = try floatCol(a, d, spec.value_col);
    var peak: f64 = -std.math.inf(f64);
    for (v) |*x| {
        if (x.* > peak) peak = x.*;
        x.* = if (peak != 0) (x.* - peak) / peak else 0;
    }
    return appendComputed(a, d, spec.out, v);
}

pub const RollFn = enum { mean, sum, std_sample, min, max };
pub const RollSpec = struct {
    value_col: []const u8,
    out: []const u8,
    window: usize,
    func: RollFn = .mean,
};

/// Rolling window aggregate. The first `window-1` rows (insufficient history)
/// are null.
pub fn rolling(a: std.mem.Allocator, d: Dataset, spec: RollSpec) Error!Dataset {
    const v = try floatCol(a, d, spec.value_col);
    const cols = try a.alloc(Column, d.columns.len + 1);
    @memcpy(cols[0..d.columns.len], d.columns);
    cols[d.columns.len] = .{ .name = spec.out, .type = .float };
    const rows = try a.alloc([]const Value, d.rows.len);
    for (d.rows, 0..) |r, i| {
        const nr = try a.alloc(Value, cols.len);
        @memcpy(nr[0..d.columns.len], r);
        nr[d.columns.len] = if (i + 1 < spec.window or spec.window == 0)
            .null
        else
            .{ .float = windowAgg(v[i + 1 - spec.window .. i + 1], spec.func) };
        rows[i] = nr;
    }
    return .{ .columns = cols, .rows = rows };
}

fn windowAgg(w: []const f64, func: RollFn) f64 {
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

/// Sample (n−1) standard deviation.
pub fn stdSample(xs: []const f64) f64 {
    if (xs.len < 2) return 0;
    var mean: f64 = 0;
    for (xs) |x| mean += x;
    mean /= @floatFromInt(xs.len);
    var ss: f64 = 0;
    for (xs) |x| ss += (x - mean) * (x - mean);
    return @sqrt(ss / @as(f64, @floatFromInt(xs.len - 1)));
}

/// (v − prev) / prev; first row null.
pub fn pctChange(a: std.mem.Allocator, d: Dataset, spec: ColSpec) Error!Dataset {
    const v = try floatCol(a, d, spec.value_col);
    const cols = try a.alloc(Column, d.columns.len + 1);
    @memcpy(cols[0..d.columns.len], d.columns);
    cols[d.columns.len] = .{ .name = spec.out, .type = .float };
    const rows = try a.alloc([]const Value, d.rows.len);
    for (d.rows, 0..) |r, i| {
        const nr = try a.alloc(Value, cols.len);
        @memcpy(nr[0..d.columns.len], r);
        nr[d.columns.len] = if (i == 0 or v[i - 1] == 0) .null else .{ .float = (v[i] - v[i - 1]) / v[i - 1] };
        rows[i] = nr;
    }
    return .{ .columns = cols, .rows = rows };
}

pub const RebaseSpec = struct { value_col: []const u8, out: []const u8, anchor: f64 = 100 };

/// Index a series to `anchor` at its first value: v / first · anchor.
pub fn rebase(a: std.mem.Allocator, d: Dataset, spec: RebaseSpec) Error!Dataset {
    const v = try floatCol(a, d, spec.value_col);
    const base = if (v.len > 0 and v[0] != 0) v[0] else 1;
    for (v) |*x| x.* = x.* / base * spec.anchor;
    return appendComputed(a, d, spec.out, v);
}

/// Replace nulls in `value_col` with the last non-null value (carry forward).
pub fn forwardFill(a: std.mem.Allocator, d: Dataset, value_col: []const u8) Error!Dataset {
    const ci = try mustIndex(d, value_col);
    const rows = try a.alloc([]const Value, d.rows.len);
    var last: ?Value = null;
    for (d.rows, 0..) |r, i| {
        const nr = try a.alloc(Value, d.columns.len);
        @memcpy(nr, r);
        if (r[ci].isNull()) {
            if (last) |lv| nr[ci] = lv;
        } else {
            last = r[ci];
        }
        rows[i] = nr;
    }
    return .{ .columns = d.columns, .rows = rows };
}

pub const OutlierSpec = struct {
    value_col: []const u8,
    out: []const u8,
    threshold: f64,
    /// Optional guard: only flag when |guard_col| < guard_max (a quote/split
    /// jump is |ret|>0.15 AND ~0 external flow).
    guard_col: ?[]const u8 = null,
    guard_max: f64 = 0,
};

/// Append a bool column: true where |value| > threshold (and, if a guard is set,
/// |guard| < guard_max).
pub fn outlierFlag(a: std.mem.Allocator, d: Dataset, spec: OutlierSpec) Error!Dataset {
    const vi = try mustIndex(d, spec.value_col);
    const gi: ?usize = if (spec.guard_col) |g| try mustIndex(d, g) else null;
    const cols = try a.alloc(Column, d.columns.len + 1);
    @memcpy(cols[0..d.columns.len], d.columns);
    cols[d.columns.len] = .{ .name = spec.out, .type = .bool };
    const rows = try a.alloc([]const Value, d.rows.len);
    for (d.rows, 0..) |r, i| {
        const val = r[vi].asFloat() orelse 0;
        var flag = @abs(val) > spec.threshold;
        if (gi) |g| flag = flag and @abs(r[g].asFloat() orelse 0) < spec.guard_max;
        const nr = try a.alloc(Value, cols.len);
        @memcpy(nr[0..d.columns.len], r);
        nr[d.columns.len] = .{ .bool = flag };
        rows[i] = nr;
    }
    return .{ .columns = cols, .rows = rows };
}

/// Merge rows sharing `key_col`: numeric columns are summed, others keep the
/// first-seen value. One output row per key (first-seen order).
pub fn mergeByKey(a: std.mem.Allocator, d: Dataset, key_col: []const u8) Error!Dataset {
    const ki = try mustIndex(d, key_col);
    var order: std.StringArrayHashMapUnmanaged(usize) = .empty; // key → merged row index
    var merged: std.ArrayList([]Value) = .empty;
    for (d.rows) |r| {
        var kbuf: std.ArrayList(u8) = .empty;
        try appendKey(&kbuf, a, r[ki]);
        const key = try kbuf.toOwnedSlice(a);
        const gop = try order.getOrPut(a, key);
        if (!gop.found_existing) {
            const nr = try a.alloc(Value, d.columns.len);
            @memcpy(nr, r);
            gop.value_ptr.* = merged.items.len;
            try merged.append(a, nr);
        } else {
            const nr = merged.items[gop.value_ptr.*];
            for (nr, 0..) |*cell, ci| {
                if (ci == ki) continue;
                if (cell.asFloat()) |base| {
                    if (r[ci].asFloat()) |add| cell.* = .{ .float = base + add };
                }
            }
        }
    }
    const rows = try a.alloc([]const Value, merged.items.len);
    for (merged.items, 0..) |m, i| rows[i] = m;
    return .{ .columns = d.columns, .rows = rows };
}

fn appendKey(buf: *std.ArrayList(u8), a: std.mem.Allocator, v: Value) Error!void {
    switch (v) {
        .text => |t| try buf.appendSlice(a, t),
        .int => |i| try buf.print(a, "i{d}", .{i}),
        .float => |f| try buf.print(a, "f{d}", .{f}),
        .bool => |b| try buf.append(a, if (b) 'T' else 'F'),
        .null => try buf.append(a, 0),
    }
}

pub const DatePartSpec = struct {
    /// Source column holding "YYYY-MM-DD" or "YYYY-MM" (or "YYYY") text.
    src: []const u8,
    /// Names for the extracted int columns (null = don't emit that part).
    year_out: ?[]const u8 = null,
    month_out: ?[]const u8 = null,
    day_out: ?[]const u8 = null,
};

/// Append integer year/month/day columns extracted from a date/period text
/// column (handles "YYYY", "YYYY-MM", "YYYY-MM-DD"). Missing parts → null cell.
pub fn datePart(a: std.mem.Allocator, d: Dataset, spec: DatePartSpec) Error!Dataset {
    const si = try mustIndex(d, spec.src);
    var extra: usize = 0;
    if (spec.year_out != null) extra += 1;
    if (spec.month_out != null) extra += 1;
    if (spec.day_out != null) extra += 1;

    const cols = try a.alloc(Column, d.columns.len + extra);
    @memcpy(cols[0..d.columns.len], d.columns);
    var ci = d.columns.len;
    if (spec.year_out) |n| {
        cols[ci] = .{ .name = n, .type = .int };
        ci += 1;
    }
    if (spec.month_out) |n| {
        cols[ci] = .{ .name = n, .type = .int };
        ci += 1;
    }
    if (spec.day_out) |n| {
        cols[ci] = .{ .name = n, .type = .int };
        ci += 1;
    }

    const rows = try a.alloc([]const Value, d.rows.len);
    for (d.rows, 0..) |r, ri| {
        const txt = r[si].asText() orelse "";
        const nr = try a.alloc(Value, cols.len);
        @memcpy(nr[0..d.columns.len], r);
        var w = d.columns.len;
        if (spec.year_out != null) {
            nr[w] = intPart(txt, 0, 4);
            w += 1;
        }
        if (spec.month_out != null) {
            nr[w] = intPart(txt, 5, 7);
            w += 1;
        }
        if (spec.day_out != null) {
            nr[w] = intPart(txt, 8, 10);
            w += 1;
        }
        rows[ri] = nr;
    }
    return .{ .columns = cols, .rows = rows };
}

fn intPart(s: []const u8, from: usize, to: usize) Value {
    if (s.len < to) return .null;
    return .{ .int = std.fmt.parseInt(i64, s[from..to], 10) catch return .null };
}

pub const JoinHow = enum { inner, left };
pub const JoinSpec = struct {
    on: []const u8,
    how: JoinHow = .inner,
};

/// Join `left` and `right` on a shared key column. Output columns = all of left,
/// then right's columns except the join key. Right is indexed by key (last row
/// wins on dup). Unmatched left rows: dropped (inner) or right-side null (left).
pub fn join(a: std.mem.Allocator, left: Dataset, right: Dataset, spec: JoinSpec) Error!Dataset {
    const lki = try mustIndex(left, spec.on);
    const rki = try mustIndex(right, spec.on);

    // right index: key → row
    var idx: std.StringArrayHashMapUnmanaged(usize) = .empty;
    for (right.rows, 0..) |r, i| {
        var kbuf: std.ArrayList(u8) = .empty;
        try appendKey(&kbuf, a, r[rki]);
        try idx.put(a, try kbuf.toOwnedSlice(a), i);
    }

    // output columns: left + right (minus join key)
    const rcount = right.columns.len - 1;
    const cols = try a.alloc(Column, left.columns.len + rcount);
    @memcpy(cols[0..left.columns.len], left.columns);
    {
        var w = left.columns.len;
        for (right.columns, 0..) |c, ci| {
            if (ci == rki) continue;
            cols[w] = c;
            w += 1;
        }
    }

    var rows: std.ArrayList([]const Value) = .empty;
    for (left.rows) |lr| {
        var kbuf: std.ArrayList(u8) = .empty;
        try appendKey(&kbuf, a, lr[lki]);
        const key = try kbuf.toOwnedSlice(a);
        const match = idx.get(key);
        if (match == null and spec.how == .inner) continue;
        const nr = try a.alloc(Value, cols.len);
        @memcpy(nr[0..left.columns.len], lr);
        var w = left.columns.len;
        for (right.columns, 0..) |_, ci| {
            if (ci == rki) continue;
            nr[w] = if (match) |mi| right.rows[mi][ci] else .null;
            w += 1;
        }
        try rows.append(a, nr);
    }
    return .{ .columns = cols, .rows = try rows.toOwnedSlice(a) };
}

// ── tests ────────────────────────────────────────────────────────────────────
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

fn dsOf(cols: []const Column, rows: []const []const Value) Dataset {
    return .{ .columns = cols, .rows = rows };
}

test "cumsum / cumreturn" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{.{ .name = "r", .type = .float }};
    const rows = [_][]const Value{
        &.{.{ .float = 0.1 }}, &.{.{ .float = 0.1 }}, &.{.{ .float = -0.05 }},
    };
    const cs = try cumsum(f.a(), dsOf(&cols, &rows), .{ .value_col = "r", .out = "cs" });
    try testing.expectApproxEqAbs(@as(f64, 0.15), cs.cell(2, "cs").?.float, 1e-9);
    const cr = try cumreturn(f.a(), dsOf(&cols, &rows), .{ .value_col = "r", .out = "cr" });
    // 1.1*1.1*0.95 - 1 = 0.1495
    try testing.expectApproxEqAbs(@as(f64, 0.1495), cr.cell(2, "cr").?.float, 1e-9);
}

test "drawdown running peak" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{.{ .name = "v", .type = .float }};
    const rows = [_][]const Value{
        &.{.{ .float = 100 }}, &.{.{ .float = 120 }}, &.{.{ .float = 90 }}, &.{.{ .float = 108 }},
    };
    const dd = try drawdown(f.a(), dsOf(&cols, &rows), .{ .value_col = "v", .out = "dd" });
    try testing.expectApproxEqAbs(@as(f64, 0), dd.cell(1, "dd").?.float, 1e-9); // new peak
    try testing.expectApproxEqAbs(@as(f64, -0.25), dd.cell(2, "dd").?.float, 1e-9); // (90-120)/120
    try testing.expectApproxEqAbs(@as(f64, -0.10), dd.cell(3, "dd").?.float, 1e-9); // (108-120)/120
}

test "rolling mean and std" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{.{ .name = "v", .type = .float }};
    const rows = [_][]const Value{
        &.{.{ .float = 1 }}, &.{.{ .float = 2 }}, &.{.{ .float = 3 }}, &.{.{ .float = 4 }},
    };
    const rm = try rolling(f.a(), dsOf(&cols, &rows), .{ .value_col = "v", .out = "m", .window = 2, .func = .mean });
    try testing.expect(rm.cell(0, "m").?.isNull());
    try testing.expectApproxEqAbs(@as(f64, 1.5), rm.cell(1, "m").?.float, 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 3.5), rm.cell(3, "m").?.float, 1e-9);
}

test "pct_change / rebase / forward_fill" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{.{ .name = "v", .type = .float }};
    const rows = [_][]const Value{
        &.{.{ .float = 100 }}, &.{.{ .float = 110 }}, &.{.null}, &.{.{ .float = 121 }},
    };
    const pc = try pctChange(f.a(), dsOf(&cols, &rows), .{ .value_col = "v", .out = "pc" });
    try testing.expect(pc.cell(0, "pc").?.isNull());
    try testing.expectApproxEqAbs(@as(f64, 0.1), pc.cell(1, "pc").?.float, 1e-9);

    const rb = try rebase(f.a(), dsOf(&cols, &rows), .{ .value_col = "v", .out = "rb", .anchor = 100 });
    try testing.expectApproxEqAbs(@as(f64, 110), rb.cell(1, "rb").?.float, 1e-9);

    const ff = try forwardFill(f.a(), dsOf(&cols, &rows), "v");
    try testing.expectApproxEqAbs(@as(f64, 110), ff.cell(2, "v").?.float, 1e-9); // filled from prev
}

test "outlier_flag with guard" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{ .{ .name = "ret", .type = .float }, .{ .name = "flow", .type = .float } };
    const rows = [_][]const Value{
        &.{ .{ .float = 0.2 }, .{ .float = 0 } }, // jump, ~0 flow → flagged
        &.{ .{ .float = 0.2 }, .{ .float = 999 } }, // jump but big flow → not a quote artifact
        &.{ .{ .float = 0.01 }, .{ .float = 0 } }, // small → no
    };
    const of = try outlierFlag(f.a(), dsOf(&cols, &rows), .{ .value_col = "ret", .out = "jump", .threshold = 0.15, .guard_col = "flow", .guard_max = 1 });
    try testing.expect(of.cell(0, "jump").?.bool);
    try testing.expect(!of.cell(1, "jump").?.bool);
    try testing.expect(!of.cell(2, "jump").?.bool);
}

test "merge_by_key sums numerics" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{ .{ .name = "sym", .type = .text }, .{ .name = "mv", .type = .float }, .{ .name = "qty", .type = .int } };
    const rows = [_][]const Value{
        &.{ .{ .text = "AAA" }, .{ .float = 100 }, .{ .int = 3 } },
        &.{ .{ .text = "BBB" }, .{ .float = 50 }, .{ .int = 1 } },
        &.{ .{ .text = "AAA" }, .{ .float = 20 }, .{ .int = 2 } },
    };
    const m = try mergeByKey(f.a(), dsOf(&cols, &rows), "sym");
    try testing.expectEqual(@as(usize, 2), m.rows.len);
    try testing.expectEqualStrings("AAA", m.cell(0, "sym").?.text);
    try testing.expectApproxEqAbs(@as(f64, 120), m.cell(0, "mv").?.float, 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 5), m.cell(0, "qty").?.float, 1e-9); // summed (int→float)
}

test "datePart extracts year/month from period text" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{ .{ .name = "period", .type = .text }, .{ .name = "ret", .type = .float } };
    const rows = [_][]const Value{
        &.{ .{ .text = "2024-01" }, .{ .float = 0.02 } },
        &.{ .{ .text = "2024-12" }, .{ .float = -0.01 } },
    };
    const out = try datePart(f.a(), dsOf(&cols, &rows), .{ .src = "period", .year_out = "y", .month_out = "m" });
    try testing.expectEqual(@as(usize, 4), out.columns.len);
    try testing.expectEqual(@as(i64, 2024), out.cell(0, "y").?.int);
    try testing.expectEqual(@as(i64, 1), out.cell(0, "m").?.int);
    try testing.expectEqual(@as(i64, 12), out.cell(1, "m").?.int);
}

test "join inner and left" {
    var f = Fix.init();
    defer f.deinit();
    const lcols = [_]Column{ .{ .name = "sym", .type = .text }, .{ .name = "mv", .type = .float } };
    const lrows = [_][]const Value{
        &.{ .{ .text = "AAA" }, .{ .float = 100 } },
        &.{ .{ .text = "BBB" }, .{ .float = 50 } },
    };
    const rcols = [_]Column{ .{ .name = "sym", .type = .text }, .{ .name = "sector", .type = .text } };
    const rrows = [_][]const Value{
        &.{ .{ .text = "AAA" }, .{ .text = "Tech" } },
    };
    const ij = try join(f.a(), dsOf(&lcols, &lrows), dsOf(&rcols, &rrows), .{ .on = "sym", .how = .inner });
    try testing.expectEqual(@as(usize, 1), ij.rows.len);
    try testing.expectEqual(@as(usize, 3), ij.columns.len); // sym, mv, sector
    try testing.expectEqualStrings("Tech", ij.cell(0, "sector").?.text);

    const lj = try join(f.a(), dsOf(&lcols, &lrows), dsOf(&rcols, &rrows), .{ .on = "sym", .how = .left });
    try testing.expectEqual(@as(usize, 2), lj.rows.len);
    try testing.expect(lj.cell(1, "sector").?.isNull()); // BBB unmatched
}
