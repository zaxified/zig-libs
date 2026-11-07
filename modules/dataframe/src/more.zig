// SPDX-License-Identifier: MIT
//! The smaller verbs on `Frame`: row windows (`page`, `tail`, `topN`, `nlargest`,
//! `sample`), `concatByName`, `partitionBy`, `valueCounts`, `describe`, the per-cell
//! column edits `clip`, `replace`, `cut`, and the as-of join. Each gives the cells of
//! `tabular`'s row verb of the same name (the same authors, MIT), which is the oracle
//! in `more_test.zig`, and their specs have that verb's fields and defaults.

const std = @import("std");
const vm = @import("value.zig");
const fm = @import("frame.zig");
const keys = @import("keys.zig");
const sp = @import("spec.zig");
const verbs = @import("verbs.zig");
const Column = vm.Column;
const ColumnType = vm.ColumnType;
const Value = vm.Value;
const ColumnData = fm.ColumnData;
const Frame = fm.Frame;
const Error = sp.Error;
const isMissing = keys.isMissing;

fn mustIndex(f: Frame, name: []const u8) Error!usize {
    return f.columnIndex(name) orelse error.NoSuchColumn;
}

fn checkRows(f: Frame) Error!void {
    if (f.len >= keys.none) return error.TooLarge;
}

/// Rows `lo..hi` of `f`, in order; every row shares the columns.
fn rangeRows(a: std.mem.Allocator, f: Frame, lo: usize, hi: usize) Error!Frame {
    const idx = try a.alloc(u32, hi - lo);
    for (idx, lo..) |*x, ri| x.* = @intCast(ri);
    return verbs.takeRows(a, f, idx);
}

/// `f` with column `ci` replaced by `data` (and its declared type by `ty`).
fn withColumn(a: std.mem.Allocator, f: Frame, ci: usize, ty: ColumnType, data: ColumnData) Error!Frame {
    const cols = try a.dupe(Column, f.columns);
    cols[ci].type = ty;
    const out = try a.alloc(ColumnData, f.columns.len);
    for (out, 0..) |*d, i| d.* = f.columnAt(i);
    out[ci] = data;
    return .{ .columns = cols, .data = out, .len = f.len };
}

/// `f` plus one column at the end.
fn appendColumn(a: std.mem.Allocator, f: Frame, col: Column, data: ColumnData) Error!Frame {
    const w = f.columns.len;
    const cols = try a.alloc(Column, w + 1);
    @memcpy(cols[0..w], f.columns);
    cols[w] = col;
    const out = try a.alloc(ColumnData, w + 1);
    for (out[0..w], 0..) |*d, i| d.* = f.columnAt(i);
    out[w] = data;
    return .{ .columns = cols, .data = out, .len = f.len };
}

// ── row windows ─────────────────────────────────────────────────────────────

pub const PageSpec = struct {
    offset: usize = 0,
    /// Rows to keep after `offset`; null = to the end.
    limit: ?usize = null,
};

/// Skip `offset` rows, then keep at most `limit` (pandas `iloc[a:b]`, polars `slice`;
/// `head` is `.{ .limit = n }`). An offset past the end is an empty frame.
pub fn page(a: std.mem.Allocator, f: Frame, spec: PageSpec) Error!Frame {
    try checkRows(f);
    const start = @min(spec.offset, f.len);
    const avail = f.len - start;
    const n = if (spec.limit) |l| @min(l, avail) else avail;
    return rangeRows(a, f, start, start + n);
}

/// The last `n` rows, in order (pandas and polars `tail`).
pub fn tail(a: std.mem.Allocator, f: Frame, n: usize) Error!Frame {
    try checkRows(f);
    const k = @min(n, f.len);
    return rangeRows(a, f, f.len - k, f.len);
}

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

/// Keep the first `n` rows (`sort` first to make "top" mean something), optionally
/// folding the rest into one labelled tail row.
pub fn topN(a: std.mem.Allocator, f: Frame, spec: TopNSpec) Error!Frame {
    try checkRows(f);
    const keep = @min(spec.n, f.len);
    if (spec.tail == null or f.len <= keep) return rangeRows(a, f, 0, keep);
    const t = spec.tail.?;
    const label_idx = try mustIndex(f, t.label_col);
    const value_idx = try mustIndex(f, t.value_col);
    var tail_sum: f64 = 0;
    const vcol = f.columnAt(value_idx);
    for (keep..f.len) |ri| tail_sum += vcol.get(ri).asFloat() orelse 0;
    const data = try a.alloc(ColumnData, f.columns.len);
    const cells = try a.alloc(Value, keep + 1);
    defer a.free(cells);
    for (data, 0..) |*d, ci| {
        const col = f.columnAt(ci);
        for (cells[0..keep], 0..) |*c, ri| c.* = col.get(ri);
        cells[keep] = .null;
        // The value wins when both name the same column, as in the row verb.
        if (ci == label_idx) cells[keep] = .{ .text = t.label };
        if (ci == value_idx) cells[keep] = .{ .float = tail_sum };
        d.* = try fm.columnFromCells(a, cells);
    }
    return .{ .columns = f.columns, .data = data, .len = keep + 1 };
}

pub const TopSpec = struct { col: []const u8, n: usize, dir: sp.SortDir = .desc };

/// The `n` rows with the largest (`.desc`, pandas `nlargest`) or smallest (`.asc`,
/// `nsmallest`) `col`, best first, ties in row order, missing cells never chosen.
pub fn nlargest(a: std.mem.Allocator, f: Frame, spec: TopSpec) Error!Frame {
    const present = try verbs.dropna(a, f, .{ .subset = &.{spec.col} });
    const sorted = try verbs.sort(a, present, .{ .key = spec.col, .dir = spec.dir });
    return page(a, sorted, .{ .limit = spec.n });
}

pub const SampleSpec = struct {
    /// Rows to draw; above the row count without `replace` it is the row count.
    n: usize,
    seed: u64,
    /// Draw with replacement (pandas' `replace=True`).
    replace: bool = false,
};

/// A random sample of rows, reproducible from `seed`, in draw order (pandas and
/// polars `sample`). No engine's stream is reproduced: a seed agrees only with itself.
pub fn sample(a: std.mem.Allocator, f: Frame, spec: SampleSpec) Error!Frame {
    try checkRows(f);
    var prng = std.Random.DefaultPrng.init(spec.seed);
    const r = prng.random();
    if (spec.replace) {
        if (f.len == 0) return rangeRows(a, f, 0, 0);
        const cells = std.math.mul(usize, spec.n, @max(f.columns.len, 1)) catch return error.TooLarge;
        if (cells > sp.max_aggregate_cells) return error.TooLarge;
        const idx = try a.alloc(u32, spec.n);
        for (idx) |*o| o.* = @intCast(r.uintLessThan(usize, f.len));
        return verbs.takeRows(a, f, idx);
    }
    const idx = try a.alloc(u32, f.len);
    for (idx, 0..) |*x, i| x.* = @intCast(i);
    const n = @min(spec.n, idx.len);
    // Partial Fisher-Yates: the first `n` slots are the draw.
    for (0..n) |i| {
        const j = i + r.uintLessThan(usize, idx.len - i);
        std.mem.swap(u32, &idx[i], &idx[j]);
    }
    return verbs.takeRows(a, f, idx[0..n]);
}

// ── concat / partition ──────────────────────────────────────────────────────

/// Stack frames, matching columns by name (pandas `concat`, polars `concat(how =
/// "diagonal")`). Columns in first-seen order, a frame without a column gives null
/// there, the declared type is the first frame's that has it. A name one frame
/// repeats reads as its first.
pub fn concatByName(a: std.mem.Allocator, frames: []const Frame) Error!Frame {
    var names: std.StringArrayHashMapUnmanaged(ColumnType) = .empty;
    var total: usize = 0;
    for (frames) |t| {
        try checkRows(t);
        total = std.math.add(usize, total, t.len) catch return error.TooLarge;
        for (t.columns) |c| {
            const gop = try names.getOrPut(a, c.name);
            if (!gop.found_existing) gop.value_ptr.* = c.type;
        }
    }
    const width = names.count();
    const n_cells = std.math.mul(usize, total, width) catch return error.TooLarge;
    if (n_cells > sp.max_aggregate_cells) return error.TooLarge;
    const cols = try a.alloc(Column, width);
    for (cols, names.keys(), names.values()) |*c, n, ty| c.* = .{ .name = n, .type = ty };
    const data = try a.alloc(ColumnData, width);
    const cells = try a.alloc(Value, total);
    defer a.free(cells);
    for (cols, data) |c, *d| {
        var at: usize = 0;
        for (frames) |t| {
            const col: ColumnData = if (t.columnIndex(c.name)) |ci| t.columnAt(ci) else .nulls;
            for (0..t.len) |ri| {
                cells[at] = col.get(ri);
                at += 1;
            }
        }
        d.* = try fm.columnFromCells(a, cells);
    }
    return .{ .columns = cols, .data = data, .len = total };
}

pub const Partition = struct {
    /// The partition's key cells, in `by` order, from its first row.
    key: []const Value,
    /// Its rows, in input order.
    frame: Frame,
};

/// One frame per distinct key, first-seen order (polars `partition_by`, pandas
/// `for key, group in df.groupby(...)`): the escape hatch for per-group logic no verb
/// says. A missing key is a partition of its own.
pub fn partitionBy(a: std.mem.Allocator, f: Frame, by: []const []const u8) Error![]const Partition {
    try checkRows(f);
    const idxs = try a.alloc(usize, by.len);
    for (idxs, by) |*ix, name| ix.* = try mustIndex(f, name);
    const rows = try verbs.keyRows(a, f, idxs);
    const pos = try a.alloc(usize, idxs.len);
    for (pos, 0..) |*p, i| p.* = i;
    const fac = try keys.factorize(a, rows, pos, .as_null);
    const mem = try keys.members(a, fac.ids, fac.groups());
    const out = try a.alloc(Partition, fac.groups());
    for (out, fac.firsts, 0..) |*p, first, g| {
        p.* = .{ .key = try a.dupe(Value, rows[first]), .frame = try verbs.takeRows(a, f, mem.of(g)) };
    }
    return out;
}

// ── value_counts / describe ─────────────────────────────────────────────────

pub const ValueCountsSpec = struct {
    cols: []const []const u8,
    out: []const u8 = "count",
    /// Count missing keys too (pandas' `dropna=False`).
    keep_missing: bool = false,
};

/// Rows per distinct key, most frequent first, ties in first-seen order (pandas and
/// polars `value_counts`).
pub fn valueCounts(a: std.mem.Allocator, f: Frame, spec: ValueCountsSpec) Error!Frame {
    if (spec.cols.len == 0) return error.NoSuchColumn;
    const g = try verbs.aggregate(a, f, .{
        .group_by = spec.cols,
        .aggs = &.{.{ .src = spec.cols[0], .out = spec.out, .func = .size }},
        .drop_missing_keys = !spec.keep_missing,
    });
    // By position: `out` may be numbered if a key column has that name.
    return verbs.takeRows(a, g, try verbs.sortedRows(a, g, &.{g.columns.len - 1}, &.{.desc}, .auto));
}

/// pandas' `describe()`: one row per statistic (`count`, `mean`, `std`, `min`, `25%`,
/// `50%`, `75%`, `max`), a first column `statistic`, then one float column per
/// numeric column (`cols` empty) or per named column, missing values skipped.
pub fn describe(a: std.mem.Allocator, f: Frame, cols_in: []const []const u8) Error!Frame {
    var names: std.ArrayList([]const u8) = .empty;
    if (cols_in.len > 0) {
        for (cols_in) |c| {
            _ = try mustIndex(f, c);
            try names.append(a, c);
        }
    } else {
        for (f.columns) |c| {
            if (c.type == .int or c.type == .float or c.type == .decimal) try names.append(a, c.name);
        }
    }
    const stats = [_]struct { name: []const u8, func: sp.AggFn, q: f64 = 0.5 }{
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
    const data = try a.alloc(ColumnData, cols.len);
    var cells: [stats.len]Value = undefined;
    for (&cells, stats) |*c, st| c.* = .{ .text = st.name };
    data[0] = try fm.columnFromCells(a, &cells);
    const aggs = try a.alloc(sp.AggCol, stats.len);
    defer a.free(aggs);
    for (names.items, data[1..]) |n, *d| {
        for (aggs, stats) |*ag, st| ag.* = .{ .src = n, .out = st.name, .func = st.func, .q = st.q };
        const one = try verbs.aggregate(a, f, .{ .group_by = &.{}, .aggs = aggs, .skip_na = true });
        for (&cells, 0..) |*c, si| {
            // No rows: every statistic stays null.
            const v: Value = if (one.len == 0) .null else one.columnAt(si).get(0);
            c.* = if (v.asFloat()) |x| .{ .float = x } else .null;
        }
        d.* = try fm.columnFromCells(a, &cells);
    }
    return .{ .columns = cols, .data = data, .len = stats.len };
}

// ── clip / replace / cut ────────────────────────────────────────────────────

pub const ClipSpec = struct { col: []const u8, lower: ?f64 = null, upper: ?f64 = null };

/// Bound a numeric column in place (pandas `clip`, polars `clip`). Missing and
/// non-numeric cells stay as they are. An int column stays int under whole bounds and
/// turns float, every cell, under a bound that is not (both engines promote too).
pub fn clip(a: std.mem.Allocator, f: Frame, spec: ClipSpec) Error!Frame {
    const ci = try mustIndex(f, spec.col);
    const col_type = f.columns[ci].type;
    const whole = struct {
        fn of(b: ?f64) bool {
            const x = b orelse return true;
            if (std.math.isNan(x)) return true; // never applies
            const i = Value.floatToInt(i64, x) orelse return false;
            return @as(f64, @floatFromInt(i)) == x;
        }
    }.of;
    const to_float = col_type == .int and !(whole(spec.lower) and whole(spec.upper));
    const out_type: ColumnType = if (to_float) .float else col_type;
    const bound = struct {
        fn of(x: f64, ty: ColumnType) Value {
            return switch (ty) {
                .int => .{ .int = Value.floatToInt(i64, x).? },
                .decimal => (Value{ .float = x }).cast(.decimal) orelse .{ .float = x },
                else => .{ .float = x },
            };
        }
    }.of;
    const col = f.columnAt(ci);
    const cells = try a.alloc(Value, f.len);
    defer a.free(cells);
    for (cells, 0..) |*o, ri| {
        const v = col.get(ri);
        o.* = v;
        if (isMissing(v)) continue;
        const x = v.asFloat() orelse continue;
        if (to_float) o.* = .{ .float = x };
        if (spec.lower) |lo| {
            if (x < lo) o.* = bound(lo, out_type);
        }
        if (spec.upper) |hi| {
            if (x > hi) o.* = bound(hi, out_type);
        }
    }
    return withColumn(a, f, ci, out_type, try fm.columnFromCells(a, cells));
}

pub const ReplacePair = struct { from: Value, to: Value };
pub const ReplaceSpec = struct { col: []const u8, pairs: []const ReplacePair };

/// Map values of a column by key equality (pandas `replace`, polars `replace`); the
/// first matching pair wins, and a missing `from` matches missing cells. The declared
/// type stays: a `to` of another kind is the caller's to `cast`.
pub fn replace(a: std.mem.Allocator, f: Frame, spec: ReplaceSpec) Error!Frame {
    const ci = try mustIndex(f, spec.col);
    var t = try keys.Table.initBytes(a, spec.pairs.len, keys.freshSeed(@intFromPtr(f.data.ptr)));
    t.allow(f.len);
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
    const col = f.columnAt(ci);
    const cells = try a.alloc(Value, f.len);
    defer a.free(cells);
    for (cells, 0..) |*o, ri| {
        const v = col.get(ri);
        scratch.clearRetainingCapacity();
        try keys.encode(a, &scratch, v, .as_null);
        o.* = if (try t.getBytes(scratch.items)) |id| tos[id] else v;
    }
    return withColumn(a, f, ci, f.columns[ci].type, try fm.columnFromCells(a, cells));
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

/// Bin a numeric column into a new column `out` (pandas `cut`, polars `cut`). Outside
/// every bin, missing, or not a number: null. Edges not strictly ascending or NaN, or
/// a label count that is not the bin count: `error.BadEdges`.
pub fn cut(a: std.mem.Allocator, f: Frame, spec: CutSpec) CutError!Frame {
    const ci = try mustIndex(f, spec.col);
    const e = spec.edges;
    if (e.len < 2) return error.BadEdges;
    for (e[0 .. e.len - 1], e[1..]) |l, m| {
        if (!(l < m)) return error.BadEdges;
    }
    if (spec.labels.len != 0 and spec.labels.len != e.len - 1) return error.BadEdges;
    const col = f.columnAt(ci);
    const cells = try a.alloc(Value, f.len);
    defer a.free(cells);
    for (cells, 0..) |*o, ri| {
        o.* = .null;
        const v = col.get(ri);
        if (isMissing(v)) continue;
        const x = v.asFloat() orelse continue;
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
        if (bin) |b| o.* = if (spec.labels.len != 0) .{ .text = spec.labels[b] } else .{ .int = @intCast(b) };
    }
    const ty: ColumnType = if (spec.labels.len != 0) .text else .int;
    return appendColumn(a, f, .{ .name = spec.out, .type = ty }, try fm.columnFromCells(a, cells));
}

// ── as-of join ──────────────────────────────────────────────────────────────

pub const AsofSpec = struct {
    /// The ordered key, both sides, numeric or text; each `by` group of `right` must
    /// be ascending in it, or `error.NotSorted`. `left` need not be sorted.
    on: []const u8,
    /// Exact-match columns (same names both sides); matching happens per group.
    by: []const []const u8 = &.{},
    direction: enum { backward, forward, nearest } = .backward,
    /// The furthest a numeric match may be; null = any distance.
    tolerance: ?f64 = null,
    /// Let an equal `on` match (pandas' `allow_exact_matches`).
    allow_exact: bool = true,
    /// As `JoinSpec.suffix`.
    suffix: ?[]const u8 = null,
};

pub const AsofError = Error || error{NotSorted};

fn nameIdxs(a: std.mem.Allocator, f: Frame, first: usize, names: []const []const u8) Error![]const usize {
    const idxs = try a.alloc(usize, 1 + names.len);
    idxs[0] = first;
    for (names, idxs[1..]) |n, *ix| ix.* = try mustIndex(f, n);
    return idxs;
}

/// As-of join (pandas `merge_asof`, polars `join_asof`): every left row, in order, with
/// the closest right row in `direction`, or nulls. Output: left's columns (shared),
/// then right's except `on` and `by`. A missing `on` on the left matches nothing; on
/// the right such a row is skipped. `nearest` takes the earlier row on a tie.
pub fn joinAsof(a: std.mem.Allocator, left: Frame, right: Frame, spec: AsofSpec) AsofError!Frame {
    try checkRows(left);
    try checkRows(right);
    const lk = try nameIdxs(a, left, try mustIndex(left, spec.on), spec.by);
    const rk = try nameIdxs(a, right, try mustIndex(right, spec.on), spec.by);

    const rmask = try a.alloc(bool, right.columns.len);
    @memset(rmask, false);
    for (rk) |ci| rmask[ci] = true;
    var keep: std.ArrayList(usize) = .empty;
    for (rmask, 0..) |is_key, ci| if (!is_key) try keep.append(a, ci);
    const cols = try a.alloc(Column, left.columns.len + keep.items.len);
    @memcpy(cols[0..left.columns.len], left.columns);
    for (keep.items, cols[left.columns.len..]) |ci, *c| {
        c.* = right.columns[ci];
        if (spec.suffix) |sfx| {
            if (left.columnIndex(c.name) != null) c.name = try a.print("{s}{s}", .{ c.name, sfx });
        }
    }
    const cells = std.math.mul(usize, left.len, @max(cols.len, 1)) catch return error.TooLarge;
    if (cells > sp.max_join_cells) return error.TooLarge;

    // The key columns as rows: `on` first, then `by`.
    const lrows = try verbs.keyRows(a, left, lk);
    const rrows = try verbs.keyRows(a, right, rk);
    const by_pos = try a.alloc(usize, spec.by.len);
    for (by_pos, 1..) |*p, i| p.* = i;
    const fac = try keys.factorize(a, rrows, by_pos, .as_null);
    fac.table.allow(left.len);
    const mem = try keys.members(a, fac.ids, fac.groups());
    // Each group's rows with a present `on`, checked ascending.
    const usable = try a.alloc([]const u32, fac.groups());
    for (usable, 0..) |*u, g| {
        var list: std.ArrayList(u32) = .empty;
        for (mem.of(g)) |ri| {
            const c = rrows[ri][0];
            if (isMissing(c)) continue;
            if (list.items.len > 0 and rrows[list.items[list.items.len - 1]][0].order(c) == .gt) return error.NotSorted;
            try list.append(a, ri);
        }
        u.* = list.items;
    }

    const picks = try a.alloc(u32, left.len);
    var any_none = false;
    var scratch: std.ArrayList(u8) = .empty;
    defer scratch.deinit(a);
    for (lrows, picks) |lr, *pk| {
        const t = lr[0];
        const g: ?u32 = if (isMissing(t) or (spec.by.len > 0 and fac.groups() == 0))
            null
        else if (spec.by.len == 0)
            (if (fac.groups() > 0) 0 else null)
        else
            try fac.table.lookup(a, &scratch, lr, by_pos, .as_null);
        var pick: ?u32 = null;
        if (g) |gi| pick = asofPick(rrows, usable[gi], t, spec);
        pk.* = pick orelse keys.none;
        any_none = any_none or pick == null;
    }
    const data = try a.alloc(ColumnData, cols.len);
    for (data[0..left.columns.len], 0..) |*d, ci| d.* = left.columnAt(ci);
    for (keep.items, data[left.columns.len..]) |ci, *d| d.* = try verbs.take(a, right.columnAt(ci), picks, any_none);
    return .{ .columns = cols, .data = data, .len = left.len };
}

/// The match of `t` among `rows` (positions into `rr`, ascending in `rr[_][0]`).
fn asofPick(rr: []const []const Value, rows: []const u32, t: Value, spec: AsofSpec) ?u32 {
    // First row with on >= t, and first with on > t.
    var lo: usize = 0;
    var hi: usize = rows.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (rr[rows[mid]][0].order(t) == .lt) lo = mid + 1 else hi = mid;
    }
    const ge = lo;
    hi = rows.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (rr[rows[mid]][0].order(t) != .gt) lo = mid + 1 else hi = mid;
    }
    const gt = lo;
    // Candidates. Among equal keys backward takes the last, forward the first.
    const before_end = if (spec.allow_exact) gt else ge;
    const after_start = if (spec.allow_exact) ge else gt;
    const back: ?u32 = if (before_end > 0) rows[before_end - 1] else null;
    const fwd: ?u32 = if (after_start < rows.len) rows[after_start] else null;
    const dist = struct {
        fn f(r: []const []const Value, row: u32, x: Value) f64 {
            const p = r[row][0].asFloat() orelse return std.math.inf(f64);
            const q = x.asFloat() orelse return std.math.inf(f64);
            return @abs(p - q);
        }
    }.f;
    const chosen: ?u32 = switch (spec.direction) {
        .backward => back,
        .forward => fwd,
        .nearest => blk: {
            if (back == null) break :blk fwd;
            if (fwd == null) break :blk back;
            break :blk if (dist(rr, back.?, t) <= dist(rr, fwd.?, t)) back else fwd;
        },
    };
    const c = chosen orelse return null;
    if (spec.tolerance) |tol| {
        if (!(dist(rr, c, t) <= tol)) return null;
    }
    return c;
}
