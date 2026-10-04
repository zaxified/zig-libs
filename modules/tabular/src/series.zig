// SPDX-License-Identifier: MIT
//! Dataset algebra **Tier 1** — series math over an (already date-ordered)
//! Dataset. Pure `dataset → dataset` nodes. Callers `sort` by date first where
//! order matters. Most nodes append one derived column; `merge_by_key`/`join`
//! reshape.
//!
//! T1 set: cumsum · cumreturn · drawdown · rolling · pct_change · rebase ·
//! forward_fill · outlier_flag · merge_by_key · distinct · date_part · join
//! (inner/left/right/full/semi/anti, single- or composite-key).

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

// ── expanding / ewm ─────────────────────────────────────────────────────────

pub const ExpandingSpec = struct {
    value_col: []const u8,
    out: []const u8,
    func: RollFn = .mean,
    /// Rows before the `min_periods`-th are null (pandas' default for
    /// `expanding` is 1; 0 behaves as 1, since row i always has i+1 values).
    min_periods: usize = 1,
};

/// Expanding (cumulative) window: row i aggregates rows 0..=i. Same value rule
/// and `std_sample` convention as `rolling` (null/non-numeric reads as 0; fewer
/// than 2 values → 0). O(n): running sum/min/max, Welford for the variance.
pub fn expanding(a: std.mem.Allocator, d: Dataset, spec: ExpandingSpec) Error!Dataset {
    const v = try floatCol(a, d, spec.value_col);
    const out = try a.alloc(Value, v.len);
    var sum: f64 = 0;
    var mn: f64 = std.math.inf(f64);
    var mx: f64 = -std.math.inf(f64);
    var mean: f64 = 0;
    var m2: f64 = 0;
    for (v, 0..) |x, i| {
        const n: f64 = @floatFromInt(i + 1);
        sum += x;
        mn = @min(mn, x);
        mx = @max(mx, x);
        const delta = x - mean;
        mean += delta / n;
        m2 += delta * (x - mean);
        out[i] = if (i + 1 < spec.min_periods) .null else .{ .float = switch (spec.func) {
            .sum => sum,
            .mean => sum / n,
            .std_sample => if (i == 0) 0 else @sqrt(m2 / (n - 1)),
            .min => mn,
            .max => mx,
        } };
    }
    return appendValues(a, d, spec.out, out);
}

pub const EwmSpec = struct {
    value_col: []const u8,
    out: []const u8,
    /// The decay, given exactly one way (pandas' four spellings):
    /// `alpha` in (0, 1]; `span` ≥ 1 (α = 2/(span+1)); `com` ≥ 0
    /// (α = 1/(1+com)); `halflife` > 0 (α = 1 − exp(−ln 2 / halflife)).
    alpha: ?f64 = null,
    span: ?f64 = null,
    com: ?f64 = null,
    halflife: ?f64 = null,
    /// pandas' `adjust`: true divides by the sum of the weights (the default);
    /// false is the recursive form y = (1−α)·y + α·x.
    adjust: bool = true,
};

pub const EwmError = Error || error{InvalidDecay};

fn ewmAlpha(spec: EwmSpec) EwmError!f64 {
    var given: u8 = 0;
    var alpha: f64 = 0;
    if (spec.alpha) |x| {
        given += 1;
        if (!(x > 0 and x <= 1)) return error.InvalidDecay;
        alpha = x;
    }
    if (spec.span) |x| {
        given += 1;
        if (!(x >= 1)) return error.InvalidDecay;
        alpha = 2 / (x + 1);
    }
    if (spec.com) |x| {
        given += 1;
        if (!(x >= 0)) return error.InvalidDecay;
        alpha = 1 / (1 + x);
    }
    if (spec.halflife) |x| {
        given += 1;
        if (!(x > 0)) return error.InvalidDecay;
        alpha = 1 - @exp(-std.math.ln2 / x);
    }
    if (given != 1 or !std.math.isFinite(alpha) or alpha <= 0) return error.InvalidDecay;
    return alpha;
}

/// Exponentially weighted mean, pandas' `ewm(...).mean()` with its defaults
/// `ignore_na=False`, `min_periods=0`: weights follow ABSOLUTE positions, so a
/// missing value (null, non-numeric, NaN) still ages the history — for
/// `[x0, missing, x2]` the weights are (1−α)² and 1 (adjust) or (1−α)² and α
/// (not adjust), normalized. A missing row repeats the previous mean; rows
/// before the first value are null. Kept as (mean, total weight) rather than
/// (Σwx, Σw), so a long gap that underflows the weight degrades to "the next
/// value", never to 0/0.
pub fn ewm(a: std.mem.Allocator, d: Dataset, spec: EwmSpec) EwmError!Dataset {
    const alpha = try ewmAlpha(spec);
    const ci = try mustIndex(d, spec.value_col);
    const out = try a.alloc(Value, d.rows.len);
    var y: ?f64 = null;
    var w: f64 = 0; // weight of the history behind `y`
    for (d.rows, 0..) |r, i| {
        w *= 1 - alpha;
        const x = r[ci].asFloat();
        if (x != null and !std.math.isNan(x.?)) {
            if (y) |prev| {
                const wx: f64 = if (spec.adjust) 1 else alpha;
                y = (w * prev + wx * x.?) / (w + wx);
            } else y = x.?;
            w = if (spec.adjust) w + 1 else 1;
        }
        out[i] = if (y) |m| .{ .float = m } else .null;
    }
    return appendValues(a, d, spec.out, out);
}

fn appendValues(a: std.mem.Allocator, d: Dataset, out: []const u8, values: []const Value) Error!Dataset {
    const cols = try a.alloc(Column, d.columns.len + 1);
    @memcpy(cols[0..d.columns.len], d.columns);
    cols[d.columns.len] = .{ .name = out, .type = .float };
    const rows = try a.alloc([]const Value, d.rows.len);
    for (d.rows, 0..) |r, i| {
        const nr = try a.alloc(Value, cols.len);
        @memcpy(nr[0..d.columns.len], r);
        nr[d.columns.len] = values[i];
        rows[i] = nr;
    }
    return .{ .columns = cols, .rows = rows };
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
        .decimal => |r| try buf.print(a, "d{d}", .{r}), // raw i128, exact key
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

pub const JoinHow = enum { inner, left, right, full, semi, anti };
pub const JoinSpec = struct {
    /// Single-column join key. Ignored when `keys` is non-empty (kept optional,
    /// rather than required, purely so `keys`-only callers don't need to set it).
    on: []const u8 = "",
    /// Composite join key (same column names assumed on both sides). When
    /// non-empty, overrides `on`.
    keys: []const []const u8 = &.{},
    how: JoinHow = .inner,
};

fn joinKeyIdxs(a: std.mem.Allocator, d: Dataset, spec: JoinSpec) Error![]const usize {
    if (spec.keys.len > 0) {
        const idxs = try a.alloc(usize, spec.keys.len);
        for (spec.keys, 0..) |name, i| idxs[i] = try mustIndex(d, name);
        return idxs;
    }
    const idxs = try a.alloc(usize, 1);
    idxs[0] = try mustIndex(d, spec.on);
    return idxs;
}

/// Composite-key bytes for a row across one or more column indices (unit-
/// separator joined, mirroring `transforms.keyString`).
fn multiKeyString(a: std.mem.Allocator, row: []const Value, idxs: []const usize) Error![]const u8 {
    var buf: std.ArrayList(u8) = .empty;
    for (idxs, 0..) |ci, n| {
        if (n > 0) try buf.append(a, 0x1f);
        try appendKey(&buf, a, row[ci]);
    }
    return buf.toOwnedSlice(a);
}

fn containsIdx(idxs: []const usize, i: usize) bool {
    for (idxs) |x| if (x == i) return true;
    return false;
}

const RowList = std.ArrayList(usize);

/// key → all row indices sharing that key (fan-out, not last-wins).
fn buildJoinIndex(a: std.mem.Allocator, d: Dataset, key_idxs: []const usize) Error!std.StringArrayHashMapUnmanaged(RowList) {
    var idx: std.StringArrayHashMapUnmanaged(RowList) = .empty;
    for (d.rows, 0..) |r, i| {
        const key = try multiKeyString(a, r, key_idxs);
        const gop = try idx.getOrPut(a, key);
        if (!gop.found_existing) gop.value_ptr.* = .empty;
        try gop.value_ptr.append(a, i);
    }
    return idx;
}

/// Build one output row: left cell block (real row or all-null) + right cell
/// block minus the right-side join-key columns (real row or all-null).
fn emitJoinRow(
    a: std.mem.Allocator,
    out_len: usize,
    left: Dataset,
    lr: ?[]const Value,
    right: Dataset,
    rr: ?[]const Value,
    rkey_idxs: []const usize,
) Error![]Value {
    const nr = try a.alloc(Value, out_len);
    if (lr) |row| {
        @memcpy(nr[0..left.columns.len], row);
    } else {
        @memset(nr[0..left.columns.len], .null);
    }
    var w = left.columns.len;
    for (right.columns, 0..) |_, ci| {
        if (containsIdx(rkey_idxs, ci)) continue;
        nr[w] = if (rr) |row| row[ci] else .null;
        w += 1;
    }
    return nr;
}

/// Join `left` and `right` on shared key column(s) (`spec.on`, or `spec.keys`
/// for a composite key). `inner`/`left`/`right`/`full`: output columns = all of
/// left, then right's columns except the join key(s); the unmatched side is
/// null-filled per `how`. Rows sharing a key fan out (every left×right pair is
/// emitted), matching SQL join semantics rather than a last-wins dedup.
/// `semi`/`anti`: output = left rows only (schema unchanged, one row per left
/// row, never fanned) — kept iff a match exists (`semi`) or doesn't (`anti`).
pub fn join(a: std.mem.Allocator, left: Dataset, right: Dataset, spec: JoinSpec) Error!Dataset {
    const lk = try joinKeyIdxs(a, left, spec);
    const rk = try joinKeyIdxs(a, right, spec);

    if (spec.how == .semi or spec.how == .anti) {
        const ridx = try buildJoinIndex(a, right, rk);
        var rows: std.ArrayList([]const Value) = .empty;
        for (left.rows) |lr| {
            const key = try multiKeyString(a, lr, lk);
            const has = ridx.contains(key);
            if ((spec.how == .semi) == has) try rows.append(a, lr);
        }
        return .{ .columns = left.columns, .rows = try rows.toOwnedSlice(a) };
    }

    // output columns: left + right (minus join key(s))
    const rcount = right.columns.len - rk.len;
    const cols = try a.alloc(Column, left.columns.len + rcount);
    @memcpy(cols[0..left.columns.len], left.columns);
    {
        var w = left.columns.len;
        for (right.columns, 0..) |c, ci| {
            if (containsIdx(rk, ci)) continue;
            cols[w] = c;
            w += 1;
        }
    }

    var rows: std.ArrayList([]const Value) = .empty;

    if (spec.how == .inner or spec.how == .left or spec.how == .full) {
        const ridx = try buildJoinIndex(a, right, rk);
        for (left.rows) |lr| {
            const key = try multiKeyString(a, lr, lk);
            if (ridx.get(key)) |ms| {
                for (ms.items) |mi| try rows.append(a, try emitJoinRow(a, cols.len, left, lr, right, right.rows[mi], rk));
            } else if (spec.how != .inner) {
                try rows.append(a, try emitJoinRow(a, cols.len, left, lr, right, null, rk));
            }
        }
        if (spec.how == .full) {
            // right rows whose key never appears on the left at all (matched
            // pairs are already covered by the loop above).
            const lidx = try buildJoinIndex(a, left, lk);
            for (right.rows) |rr| {
                const key = try multiKeyString(a, rr, rk);
                if (!lidx.contains(key)) try rows.append(a, try emitJoinRow(a, cols.len, left, null, right, rr, rk));
            }
        }
    } else { // .right
        const lidx = try buildJoinIndex(a, left, lk);
        for (right.rows) |rr| {
            const key = try multiKeyString(a, rr, rk);
            if (lidx.get(key)) |ms| {
                for (ms.items) |mi| try rows.append(a, try emitJoinRow(a, cols.len, left, left.rows[mi], right, rr, rk));
            } else {
                try rows.append(a, try emitJoinRow(a, cols.len, left, null, right, rr, rk));
            }
        }
    }
    return .{ .columns = cols, .rows = try rows.toOwnedSlice(a) };
}

pub const DistinctSpec = struct {
    /// Columns forming the row-identity composite key.
    keys: []const []const u8,
    /// Which occurrence's *values* win on a duplicate key. Either way the
    /// output keeps one row per key, in first-seen key order.
    keep: enum { first, last } = .first,
};

/// Dataset-level dedup on a key set — unlike `mergeByKey`, non-key columns are
/// NOT summed: the kept row's cells are simply the first- or last-seen row's,
/// verbatim. One output row per distinct key, first-seen order.
pub fn distinct(a: std.mem.Allocator, d: Dataset, spec: DistinctSpec) Error!Dataset {
    const idxs = try a.alloc(usize, spec.keys.len);
    for (spec.keys, 0..) |name, i| idxs[i] = try mustIndex(d, name);

    var order: std.StringArrayHashMapUnmanaged(usize) = .empty; // key → slot in `rows`
    var rows: std.ArrayList([]const Value) = .empty;
    for (d.rows) |r| {
        const key = try multiKeyString(a, r, idxs);
        const gop = try order.getOrPut(a, key);
        if (!gop.found_existing) {
            gop.value_ptr.* = rows.items.len;
            try rows.append(a, r);
        } else if (spec.keep == .last) {
            rows.items[gop.value_ptr.*] = r;
        }
    }
    return .{ .columns = d.columns, .rows = try rows.toOwnedSlice(a) };
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

test "join right and full outer null-fill correctly" {
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
        &.{ .{ .text = "DDD" }, .{ .text = "Health" } }, // no left match
    };

    const rj = try join(f.a(), dsOf(&lcols, &lrows), dsOf(&rcols, &rrows), .{ .on = "sym", .how = .right });
    try testing.expectEqual(@as(usize, 2), rj.rows.len); // AAA (matched), DDD (left-null)
    try testing.expectEqualStrings("AAA", rj.cell(0, "sym").?.text);
    try testing.expectApproxEqAbs(@as(f64, 100), rj.cell(0, "mv").?.float, 1e-9);
    try testing.expect(rj.cell(1, "mv").?.isNull()); // DDD: no left row
    try testing.expect(rj.cell(1, "sym").?.isNull()); // left's own "sym" cell is also null-filled
    try testing.expectEqualStrings("Health", rj.cell(1, "sector").?.text);

    const fj = try join(f.a(), dsOf(&lcols, &lrows), dsOf(&rcols, &rrows), .{ .on = "sym", .how = .full });
    try testing.expectEqual(@as(usize, 3), fj.rows.len); // AAA matched, BBB left-only, DDD right-only
    try testing.expectEqualStrings("AAA", fj.cell(0, "sym").?.text);
    try testing.expectEqualStrings("Tech", fj.cell(0, "sector").?.text);
    try testing.expectEqualStrings("BBB", fj.cell(1, "sym").?.text);
    try testing.expect(fj.cell(1, "sector").?.isNull()); // BBB: no right row
    try testing.expect(fj.cell(2, "sym").?.isNull()); // DDD: no left row
    try testing.expectEqualStrings("Health", fj.cell(2, "sector").?.text);
}

test "join semi and anti return the correct subset" {
    var f = Fix.init();
    defer f.deinit();
    const lcols = [_]Column{ .{ .name = "sym", .type = .text }, .{ .name = "mv", .type = .float } };
    const lrows = [_][]const Value{
        &.{ .{ .text = "AAA" }, .{ .float = 100 } },
        &.{ .{ .text = "BBB" }, .{ .float = 50 } },
        &.{ .{ .text = "CCC" }, .{ .float = 30 } },
    };
    const rcols = [_]Column{.{ .name = "sym", .type = .text }};
    const rrows = [_][]const Value{
        &.{.{ .text = "AAA" }},
    };

    const sj = try join(f.a(), dsOf(&lcols, &lrows), dsOf(&rcols, &rrows), .{ .on = "sym", .how = .semi });
    try testing.expectEqual(@as(usize, 1), sj.rows.len);
    try testing.expectEqual(@as(usize, 2), sj.columns.len); // schema unchanged (left only)
    try testing.expectEqualStrings("AAA", sj.cell(0, "sym").?.text);

    const aj = try join(f.a(), dsOf(&lcols, &lrows), dsOf(&rcols, &rrows), .{ .on = "sym", .how = .anti });
    try testing.expectEqual(@as(usize, 2), aj.rows.len);
    try testing.expectEqualStrings("BBB", aj.cell(0, "sym").?.text);
    try testing.expectEqualStrings("CCC", aj.cell(1, "sym").?.text);
}

test "join with composite key disambiguates rows a single key would wrongly fan out" {
    var f = Fix.init();
    defer f.deinit();
    // Both regions reuse sym "AAA" — a sym-only join would match EVERY left row
    // against BOTH right rows (4 result rows, wrong sectors); the composite
    // (region, sym) key must pair each region with its own sector (2 rows).
    const lcols = [_]Column{ .{ .name = "region", .type = .text }, .{ .name = "sym", .type = .text }, .{ .name = "mv", .type = .float } };
    const lrows = [_][]const Value{
        &.{ .{ .text = "US" }, .{ .text = "AAA" }, .{ .float = 100 } },
        &.{ .{ .text = "EU" }, .{ .text = "AAA" }, .{ .float = 200 } },
    };
    const rcols = [_]Column{ .{ .name = "region", .type = .text }, .{ .name = "sym", .type = .text }, .{ .name = "sector", .type = .text } };
    const rrows = [_][]const Value{
        &.{ .{ .text = "US" }, .{ .text = "AAA" }, .{ .text = "Tech" } },
        &.{ .{ .text = "EU" }, .{ .text = "AAA" }, .{ .text = "Bank" } },
    };
    const out = try join(f.a(), dsOf(&lcols, &lrows), dsOf(&rcols, &rrows), .{ .keys = &.{ "region", "sym" }, .how = .inner });
    try testing.expectEqual(@as(usize, 2), out.rows.len); // NOT 4
    try testing.expectEqual(@as(usize, 4), out.columns.len); // region, sym, mv, sector (key not duplicated)
    try testing.expectEqualStrings("Tech", out.cell(0, "sector").?.text);
    try testing.expectEqualStrings("Bank", out.cell(1, "sector").?.text);
}

test "distinct keeps first (or last) row without summing" {
    var f = Fix.init();
    defer f.deinit();
    const cols = [_]Column{ .{ .name = "sym", .type = .text }, .{ .name = "v", .type = .float } };
    const rows = [_][]const Value{
        &.{ .{ .text = "AAA" }, .{ .float = 1 } },
        &.{ .{ .text = "BBB" }, .{ .float = 2 } },
        &.{ .{ .text = "AAA" }, .{ .float = 3 } },
    };
    const first = try distinct(f.a(), dsOf(&cols, &rows), .{ .keys = &.{"sym"} });
    try testing.expectEqual(@as(usize, 2), first.rows.len); // right COUNT (not 3)
    try testing.expectEqualStrings("AAA", first.cell(0, "sym").?.text);
    try testing.expectApproxEqAbs(@as(f64, 1), first.cell(0, "v").?.float, 1e-9); // first-seen, NOT summed to 4
    try testing.expectEqualStrings("BBB", first.cell(1, "sym").?.text);

    const last = try distinct(f.a(), dsOf(&cols, &rows), .{ .keys = &.{"sym"}, .keep = .last });
    try testing.expectEqual(@as(usize, 2), last.rows.len);
    try testing.expectEqualStrings("AAA", last.cell(0, "sym").?.text); // position = first-seen
    try testing.expectApproxEqAbs(@as(f64, 3), last.cell(0, "v").?.float, 1e-9); // value = last-seen
}

test "ewm: pandas' documented example, adjust true and false" {
    var f = Fix.init();
    defer f.deinit();
    const a = f.a();
    // pandas DataFrame.ewm docs: B = [0, 1, 2, NaN, 4], com = 0.5 →
    // 0, 0.75, 1.615385, 1.615385, 3.670213. Exactly (α = 2/3): 21/13, 345/94.
    const cols = [_]Column{.{ .name = "b", .type = .float }};
    const rows = [_][]const Value{ &.{.{ .float = 0 }}, &.{.{ .float = 1 }}, &.{.{ .float = 2 }}, &.{.null}, &.{.{ .float = 4 }} };
    const d = dsOf(&cols, &rows);
    const want = [_]f64{ 0, 0.75, 21.0 / 13.0, 21.0 / 13.0, 345.0 / 94.0 };
    const spellings = [_]EwmSpec{
        .{ .value_col = "b", .out = "e", .com = 0.5 },
        .{ .value_col = "b", .out = "e", .span = 2 }, // α = 2/(2+1)
        .{ .value_col = "b", .out = "e", .alpha = 2.0 / 3.0 },
    };
    for (spellings) |sp| {
        const out = try ewm(a, d, sp);
        for (want, 0..) |w, i| try testing.expectApproxEqRel(w, out.rows[i][1].float, 1e-12);
    }
    // adjust = false, same data, from y = ((1−α)^k·y + α·x) / ((1−α)^k + α):
    // 0, 2/3, 14/9, 14/9, then k = 2: (1/9·14/9 + 2/3·4) / (1/9 + 2/3) = 230/63.
    const nf = try ewm(a, d, .{ .value_col = "b", .out = "e", .com = 0.5, .adjust = false });
    const want_nf = [_]f64{ 0, 2.0 / 3.0, 14.0 / 9.0, 14.0 / 9.0, 230.0 / 63.0 };
    for (want_nf, 0..) |w, i| try testing.expectApproxEqRel(w, nf.rows[i][1].float, 1e-12);
    // halflife 1 is α = 1/2: two values 0, 4 (adjust) → (0.5·0 + 4) / 1.5 = 8/3.
    const hl = try ewm(a, dsOf(&cols, &.{ &.{.{ .float = 0 }}, &.{.{ .float = 4 }} }), .{ .value_col = "b", .out = "e", .halflife = 1 });
    try testing.expectApproxEqRel(@as(f64, 8.0 / 3.0), hl.rows[1][1].float, 1e-12);
}

test "ewm: leading nulls stay null; a long gap does not turn into 0/0" {
    var f = Fix.init();
    defer f.deinit();
    const a = f.a();
    const cols = [_]Column{.{ .name = "b", .type = .float }};
    var rows: std.ArrayList([]const Value) = .empty;
    try rows.append(a, &.{.null});
    try rows.append(a, &.{.{ .float = std.math.nan(f64) }});
    try rows.append(a, &.{.{ .float = 1 }});
    // 2000 missing rows: the history's weight 0.5^2000 underflows to 0.
    for (0..2000) |_| try rows.append(a, &.{.null});
    try rows.append(a, &.{.{ .float = 5 }});
    const out = try ewm(a, dsOf(&cols, rows.items), .{ .value_col = "b", .out = "e", .alpha = 0.5 });
    try testing.expect(out.rows[0][1] == .null);
    try testing.expect(out.rows[1][1] == .null);
    try testing.expectEqual(@as(f64, 1), out.rows[2][1].float);
    try testing.expectEqual(@as(f64, 1), out.rows[1000][1].float); // carried
    // Weights 0.5^2001 (→ 0) and 1: the mean is the new value.
    try testing.expectEqual(@as(f64, 5), out.rows[rows.items.len - 1][1].float);
}

test "ewm: the decay must be given exactly once and be in range" {
    var f = Fix.init();
    defer f.deinit();
    const a = f.a();
    const cols = [_]Column{.{ .name = "b", .type = .float }};
    const d = dsOf(&cols, &.{});
    const bad = [_]EwmSpec{
        .{ .value_col = "b", .out = "e" },
        .{ .value_col = "b", .out = "e", .alpha = 0.5, .span = 3 },
        .{ .value_col = "b", .out = "e", .alpha = 0 },
        .{ .value_col = "b", .out = "e", .alpha = 1.5 },
        .{ .value_col = "b", .out = "e", .alpha = std.math.nan(f64) },
        .{ .value_col = "b", .out = "e", .span = 0.5 },
        .{ .value_col = "b", .out = "e", .com = -1 },
        .{ .value_col = "b", .out = "e", .halflife = 0 },
        .{ .value_col = "b", .out = "e", .com = std.math.inf(f64) }, // α = 0
    };
    for (bad) |sp| try testing.expectError(error.InvalidDecay, ewm(a, d, sp));
    _ = try ewm(a, d, .{ .value_col = "b", .out = "e", .alpha = 1 }); // α = 1 is legal
    _ = try ewm(a, d, .{ .value_col = "b", .out = "e", .span = 1 }); // span 1 → α = 1
    try testing.expectError(error.NoSuchColumn, ewm(a, d, .{ .value_col = "z", .out = "e", .alpha = 1 }));
}

test "expanding: cumulative sum / mean / min / max / std, min_periods" {
    var f = Fix.init();
    defer f.deinit();
    const a = f.a();
    const cols = [_]Column{.{ .name = "v", .type = .float }};
    const xs = [_]f64{ 2, 4, 4, 4, 5, 5, 7, 9 };
    var rows: [xs.len][]const Value = undefined;
    for (xs, 0..) |x, i| rows[i] = try a.dupe(Value, &.{.{ .float = x }});
    const d = dsOf(&cols, &rows);
    const sum = try expanding(a, d, .{ .value_col = "v", .out = "o", .func = .sum });
    const mean = try expanding(a, d, .{ .value_col = "v", .out = "o" });
    const mn = try expanding(a, d, .{ .value_col = "v", .out = "o", .func = .min });
    const mx = try expanding(a, d, .{ .value_col = "v", .out = "o", .func = .max });
    var run: f64 = 0;
    for (xs, 0..) |x, i| {
        run += x;
        try testing.expectEqual(run, sum.rows[i][1].float);
        try testing.expectEqual(run / @as(f64, @floatFromInt(i + 1)), mean.rows[i][1].float);
        try testing.expectEqual(@as(f64, 2), mn.rows[i][1].float); // 2 is first and smallest
        try testing.expectEqual(x, mx.rows[i][1].float); // ascending input
    }
    // std: row 0 → 0 (rolling's convention); the last row is the textbook
    // sample sd sqrt(32/7); every row matches the two-pass stdSample of its prefix.
    const sd = try expanding(a, d, .{ .value_col = "v", .out = "o", .func = .std_sample, .min_periods = 3 });
    try testing.expect(sd.rows[0][1] == .null);
    try testing.expect(sd.rows[1][1] == .null);
    for (2..xs.len) |i| try testing.expectApproxEqRel(stdSample(xs[0 .. i + 1]), sd.rows[i][1].float, 1e-12);
    try testing.expectApproxEqRel(@sqrt(32.0 / 7.0), sd.rows[xs.len - 1][1].float, 1e-12);
    const sd1 = try expanding(a, d, .{ .value_col = "v", .out = "o", .func = .std_sample, .min_periods = 0 });
    try testing.expectEqual(@as(f64, 0), sd1.rows[0][1].float);
    // A falling series moves the running min.
    const down = [_][]const Value{ &.{.{ .float = 3 }}, &.{.{ .float = 1 }}, &.{.{ .float = 2 }} };
    const dmin = try expanding(a, dsOf(&cols, &down), .{ .value_col = "v", .out = "o", .func = .min });
    try testing.expectEqual(@as(f64, 1), dmin.rows[2][1].float);
    const dmax = try expanding(a, dsOf(&cols, &down), .{ .value_col = "v", .out = "o", .func = .max });
    try testing.expectEqual(@as(f64, 3), dmax.rows[2][1].float);
}

test "edge cases the mutation run asked for (series)" {
    var f = Fix.init();
    defer f.deinit();
    // window 0 has no history to aggregate: every row null, not 0/0.
    const cols = [_]Column{.{ .name = "v", .type = .float }};
    const rows = [_][]const Value{ &.{.{ .float = 1 }}, &.{.{ .float = 2 }} };
    const out = try rolling(f.a(), dsOf(&cols, &rows), .{ .value_col = "v", .out = "r", .window = 0 });
    for (out.rows) |r| try testing.expect(r[1] == .null);
    // Fewer than two values: 0 by this module's convention, not NaN.
    try testing.expectEqual(@as(f64, 0), stdSample(&.{5}));
    try testing.expectEqual(@as(f64, 0), stdSample(&.{}));
}
