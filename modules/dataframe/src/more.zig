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
const core = @import("core.zig");
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
    return core.checkRowsU32(f.len);
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
    return concatImpl(a, frames, true);
}

fn concatImpl(a: std.mem.Allocator, frames: []const Frame, comptime typed: bool) Error!Frame {
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
    var cells: []Value = &.{};
    defer if (cells.len > 0) a.free(cells);
    for (cols, data) |c, *d| {
        if (typed) {
            if (try concatTyped(a, frames, c.name, total)) |col| {
                d.* = col;
                continue;
            }
        }
        if (cells.len == 0) cells = try a.alloc(Value, total);
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

/// The column `name` of every frame stacked, from the typed arrays, when its non-null
/// cells are all of one kind (or there are none): exactly the storage `columnFromCells`
/// gives for the same cells. Null when some piece is boxed or the kinds mix (the cell
/// path then decides), with nothing kept.
fn concatTyped(a: std.mem.Allocator, frames: []const Frame, name: []const u8, total: usize) Error!?ColumnData {
    const Tag = std.meta.Tag(ColumnData);
    var kind: ?Tag = null;
    for (frames) |t| {
        const col: ColumnData = if (t.columnIndex(name)) |ci| t.columnAt(ci) else .nulls;
        const tag = std.meta.activeTag(col);
        if (tag == .boxed) return null;
        if (tag == .nulls or t.len == 0) continue;
        if (concatPresent(col, t.len) == 0) continue;
        if (kind) |k| {
            if (k != tag) return null;
        } else kind = tag;
    }
    const k = kind orelse return .nulls;
    return switch (k) {
        .int => .{ .int = try concatPlain(i64, a, frames, name, total) },
        .float => .{ .float = try concatPlain(f64, a, frames, name, total) },
        .bool => .{ .bool = try concatPlain(bool, a, frames, name, total) },
        .decimal => .{ .decimal = try concatPlain(i128, a, frames, name, total) },
        .text => .{ .text = try concatText(a, frames, name, total) },
        .nulls, .boxed => unreachable,
    };
}

/// Non-null cells among the first `n` rows of a typed column, as `get` sees them.
fn concatPresent(col: ColumnData, n: usize) usize {
    switch (col) {
        .nulls, .boxed => return 0,
        .text => |c| {
            var k: usize = 0;
            for (0..n) |i| k += @intFromBool(c.at(i) != null);
            return k;
        },
        inline else => |c| {
            const m = @min(n, c.values.len);
            const v = c.valid orelse return m;
            return bitsSet(v, m);
        },
    }
}

/// Set bits among the first `n` of `words` (missing words read as clear).
fn bitsSet(words: []const u64, n: usize) usize {
    const full = @min(n / 64, words.len);
    var k: usize = 0;
    for (words[0..full]) |w| k += @popCount(w);
    if (full == n / 64 and n % 64 != 0 and full < words.len) {
        k += @popCount(words[full] & ((@as(u64, 1) << @intCast(n % 64)) - 1));
    }
    return k;
}

/// Bits `[0, count)` of `src` (all set when null) or'd into `dst` from bit `at`, the bits at
/// or past `avail` clear.
fn orBits(dst: []u64, at: usize, src: ?[]const u64, avail: usize, count: usize) void {
    var done: usize = 0;
    while (done < count) {
        const take = @min(64, count - done);
        const live = if (avail > done) @min(take, avail - done) else 0;
        var w: u64 = 0;
        if (live > 0) {
            const mask: u64 = if (live == 64) ~@as(u64, 0) else (@as(u64, 1) << @intCast(live)) - 1;
            if (src) |s| {
                // Bit `done` of the source: word `done / 64`, which is whole (done is a multiple of 64).
                w = (if (done / 64 < s.len) s[done / 64] else 0) & mask;
            } else w = mask;
        }
        if (w != 0) {
            const pos = at + done;
            dst[pos / 64] |= w << @intCast(pos % 64);
            if (pos % 64 != 0 and pos / 64 + 1 < dst.len) dst[pos / 64 + 1] |= w >> @intCast(64 - pos % 64);
        }
        done += take;
    }
}

fn concatPlain(comptime T: type, a: std.mem.Allocator, frames: []const Frame, name: []const u8, total: usize) Error!fm.TypedColumn(T) {
    const values = try a.alloc(T, total);
    const zero: T = if (T == bool) false else 0;
    var present: usize = 0;
    // First pass: how many cells are non-null, to know whether a bitmap is needed.
    for (frames) |t| {
        const col: ColumnData = if (t.columnIndex(name)) |ci| t.columnAt(ci) else .nulls;
        present += concatPresent(col, t.len);
    }
    const valid: ?[]u64 = if (present == total) null else blk: {
        const w = try a.alloc(u64, total / 64 + 1);
        @memset(w, 0);
        break :blk w;
    };
    var at: usize = 0;
    for (frames) |t| {
        defer at += t.len;
        const dst = values[at..][0..t.len];
        const col: ColumnData = if (t.columnIndex(name)) |ci| t.columnAt(ci) else .nulls;
        const c = switch (col) {
            inline else => |x, tag| if (comptime tagIs(T, tag)) x else {
                @memset(dst, zero);
                continue;
            },
        };
        const m = @min(t.len, c.values.len);
        if (c.valid) |vb| {
            for (dst[0..m], c.values[0..m], 0..) |*o, x, i| o.* = if ((if (i / 64 < vb.len) (vb[i / 64] >> @intCast(i % 64)) & 1 else 0) == 1) x else zero;
        } else @memcpy(dst[0..m], c.values[0..m]);
        @memset(dst[m..], zero);
        if (valid) |vw| orBits(vw, at, c.valid, m, t.len);
    }
    return .{ .values = values, .valid = valid };
}

fn tagIs(comptime T: type, comptime tag: std.meta.Tag(ColumnData)) bool {
    return switch (tag) {
        .int => T == i64,
        .float => T == f64,
        .bool => T == bool,
        .decimal => T == i128,
        else => false,
    };
}

/// A text piece with no null bit whose first `rows` cells all read as present: its offsets
/// ascend and end inside `bytes`, so the cells are one contiguous run.
fn textDense(c: fm.TextColumn, rows: usize) bool {
    if (c.valid != null or rows == 0 or c.offsets.len < rows + 1) return false;
    if (c.offsets[rows] > c.bytes.len) return false;
    var prev = c.offsets[0];
    for (c.offsets[1 .. rows + 1]) |x| {
        if (x < prev) return false;
        prev = x;
    }
    return true;
}

fn concatText(a: std.mem.Allocator, frames: []const Frame, name: []const u8, total: usize) Error!fm.TextColumn {
    var bytes_n: usize = 0;
    var present: usize = 0;
    for (frames) |t| {
        const col: ColumnData = if (t.columnIndex(name)) |ci| t.columnAt(ci) else .nulls;
        if (col != .text) continue;
        if (textDense(col.text, t.len)) {
            bytes_n += col.text.offsets[t.len] - col.text.offsets[0];
            present += t.len;
            continue;
        }
        for (0..t.len) |i| {
            if (col.text.at(i)) |x| {
                bytes_n += x.len;
                present += 1;
            }
        }
    }
    // Absent or other-kind pieces are all null here: only text and null pieces reach this.
    const bytes = try a.alloc(u8, bytes_n);
    const offsets = try a.alloc(usize, total + 1);
    offsets[0] = 0;
    const valid: ?[]u64 = if (present == total) null else blk: {
        const w = try a.alloc(u64, total / 64 + 1);
        @memset(w, 0);
        break :blk w;
    };
    var at: usize = 0;
    var b: usize = 0;
    for (frames) |t| {
        const col: ColumnData = if (t.columnIndex(name)) |ci| t.columnAt(ci) else .nulls;
        if (col == .text and textDense(col.text, t.len)) {
            const o = col.text.offsets;
            const len = o[t.len] - o[0];
            @memcpy(bytes[b..][0..len], col.text.bytes[o[0]..o[t.len]]);
            for (offsets[at + 1 ..][0..t.len], o[1..][0..t.len]) |*d, x| d.* = b + (x - o[0]);
            if (valid) |vw| orBits(vw, at, null, t.len, t.len);
            b += len;
            at += t.len;
            continue;
        }
        for (0..t.len) |i| {
            if (col == .text) {
                if (col.text.at(i)) |x| {
                    @memcpy(bytes[b..][0..x.len], x);
                    b += x.len;
                    if (valid) |vw| vw[(at + i) / 64] |= @as(u64, 1) << @intCast((at + i) % 64);
                }
            }
            offsets[at + i + 1] = b;
        }
        at += t.len;
    }
    return .{ .offsets = offsets, .bytes = bytes, .valid = valid };
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
    return valueCountsImpl(a, f, spec, true);
}

fn valueCountsImpl(a: std.mem.Allocator, f: Frame, spec: ValueCountsSpec, comptime typed: bool) Error!Frame {
    if (spec.cols.len == 0) return error.NoSuchColumn;
    const g = if (typed) try groupSizes(a, f, spec) else try verbs.aggregate(a, f, .{
        .group_by = spec.cols,
        .aggs = &.{.{ .src = spec.cols[0], .out = spec.out, .func = .size }},
        .drop_missing_keys = !spec.keep_missing,
    });
    // By position: `out` may be numbered if a key column has that name.
    return verbs.takeRows(a, g, try verbs.sortedRows(a, g, &.{g.columns.len - 1}, &.{.desc}, .auto));
}

/// `verbs.aggregate(group_by = cols, size)` without the cells: the group columns of each
/// group's first row and a count column, first-seen order, groups with a missing key
/// dropped unless `keep_missing`. The same steps in the same order, so the same errors.
fn groupSizes(a: std.mem.Allocator, f: Frame, spec: ValueCountsSpec) Error!Frame {
    try core.checkRowsU32(f.len);
    const gidx = try a.alloc(usize, spec.cols.len);
    for (gidx, spec.cols) |*ci, name| ci.* = try mustIndex(f, name);
    const fac = try verbs.factorKeys(a, f, gidx);
    const n = fac.groups();
    try core.aggregateCellsWithin(n, 1);
    const cols = try a.alloc(Column, gidx.len + 1);
    for (gidx, 0..) |ci, i| cols[i] = f.columns[ci];
    cols[gidx.len] = .{ .name = spec.out, .type = core.aggOutType(f.columns, gidx[0], .size, false) };
    try keys.uniqueNames(a, cols);

    const data = try a.alloc(ColumnData, cols.len);
    for (gidx, data[0..gidx.len]) |ci, *d| d.* = try verbs.take(a, f.columnAt(ci), fac.firsts, false);
    if (n == 0) {
        data[gidx.len] = .nulls;
    } else {
        const counts = try a.alloc(i64, n);
        @memset(counts, 0);
        for (fac.ids) |id| counts[id] += 1;
        data[gidx.len] = .{ .int = .{ .values = counts } };
    }
    var out: Frame = .{ .columns = cols, .data = data, .len = n };
    if (!spec.keep_missing) out = try verbs.dropna(a, out, .{ .subset = spec.cols });
    return out;
}

/// pandas' `describe()`: one row per statistic (`count`, `mean`, `std`, `min`, `25%`,
/// `50%`, `75%`, `max`), a first column `statistic`, then one float column per
/// numeric column (`cols` empty) or per named column, missing values skipped.
pub fn describe(a: std.mem.Allocator, f: Frame, cols_in: []const []const u8) Error!Frame {
    return describeImpl(a, f, cols_in, true);
}

fn describeImpl(a: std.mem.Allocator, f: Frame, cols_in: []const []const u8, comptime typed: bool) Error!Frame {
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
        if (typed and f.len < keys.none) {
            if (try describeTyped(a, f.columnAt(try mustIndex(f, n)), f.len, &cells)) {
                d.* = try fm.columnFromCells(a, &cells);
                continue;
            }
        }
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

/// `describe`'s eight statistics of one numeric column straight from its typed array,
/// into `cells`, with the arithmetic of the `aggregate` loops it replaces: the present,
/// non-NaN values in row order, summed and folded by Welford in that order, min and max by
/// strict `<` / `>`, the quantiles by `core.quantileInterp` over a fresh copy each (it
/// reorders, and a tie between 0.0 and -0.0 depends on the order). Returns false for any
/// other storage (bool, text, boxed): the aggregate path decides.
fn describeTyped(a: std.mem.Allocator, col: ColumnData, rows: usize, cells: *[8]Value) Error!bool {
    switch (col) {
        .int => |c| try describeRun(i64, a, c, rows, cells),
        .float => |c| try describeRun(f64, a, c, rows, cells),
        .decimal => |c| try describeRun(i128, a, c, rows, cells),
        .nulls => {
            for (cells) |*c| c.* = .null;
            // No cell is present: `count` is 0, the rest are null.
            if (rows > 0) cells[0] = .{ .float = 0 };
        },
        else => return false,
    }
    return true;
}

fn describeRun(comptime T: type, a: std.mem.Allocator, c: fm.TypedColumn(T), rows: usize, cells: *[8]Value) Error!void {
    // No rows: the aggregate has no group, so every statistic is null.
    if (rows == 0) {
        for (cells) |*x| x.* = .null;
        return;
    }
    const vals = try a.alloc(f64, rows);
    defer a.free(vals);
    var m: usize = 0;
    var sum: f64 = 0;
    var mo: core.Moments = .{};
    var lo: T = undefined;
    var hi: T = undefined;
    var have = false;
    var neg_zero = false;
    for (0..rows) |i| {
        if (!c.isValid(i)) continue;
        const raw = c.values[i];
        const x: f64 = switch (T) {
            f64 => raw,
            i64 => @floatFromInt(raw),
            else => (Value{ .decimal = raw }).asFloat().?,
        };
        if (std.math.isNan(x)) continue;
        if (x == 0 and std.math.signbit(x)) neg_zero = true;
        vals[m] = x;
        m += 1;
        sum += x;
        mo.add2(x);
        if (!have) {
            lo = raw;
            hi = raw;
            have = true;
        } else {
            if (raw < lo) lo = raw;
            if (raw > hi) hi = raw;
        }
    }
    const toF = struct {
        fn f(v: Value) Value {
            return if (v.asFloat()) |x| .{ .float = x } else .null;
        }
    }.f;
    cells[0] = .{ .float = @floatFromInt(m) };
    cells[1] = if (m == 0) .null else .{ .float = sum / @as(f64, @floatFromInt(m)) };
    cells[2] = toF(core.momentResult(mo, .std, 1));
    cells[3] = if (have) toF(switch (T) {
        f64 => Value{ .float = lo },
        i64 => Value{ .int = lo },
        else => Value{ .decimal = lo },
    }) else .null;
    cells[7] = if (have) toF(switch (T) {
        f64 => Value{ .float = hi },
        i64 => Value{ .int = hi },
        else => Value{ .decimal = hi },
    }) else .null;
    const buf = try a.alloc(f64, m);
    defer a.free(buf);
    const qs = [3]f64{ 0.25, 0.5, 0.75 };
    if (m == 0) {
        cells[4] = .null;
        cells[5] = .null;
        cells[6] = .null;
    } else if (neg_zero) {
        // A -0.0 among the values: which zero a selection returns depends on the order
        // it started from, so each quantile selects from its own copy of the input order.
        for (qs, 4..) |q, at| {
            @memcpy(buf, vals[0..m]);
            cells[at] = toF(core.quantileInterp(buf, q, .linear));
        }
    } else {
        // Without -0.0 equal values are the same bits, so the order statistics do not
        // depend on the order: select the median, then the quartiles inside its halves.
        @memcpy(buf, vals[0..m]);
        var ks: [3]usize = undefined;
        var fr: [3]f64 = undefined;
        for (qs, &ks, &fr) |q, *l, *f| {
            const h = @as(f64, @floatFromInt(m - 1)) * q;
            l.* = @intFromFloat(@floor(h));
            f.* = h - @floor(h);
        }
        keys.selectKth(buf, ks[1]);
        if (ks[0] < ks[1]) keys.selectKth(buf[0..ks[1]], ks[0]);
        if (ks[2] > ks[1]) keys.selectKth(buf[ks[1] + 1 ..], ks[2] - ks[1] - 1);
        for (ks, fr, 4..) |l, f, at| {
            var v = buf[l];
            if (f != 0 and l + 1 < m) {
                var top = buf[l + 1];
                for (buf[l + 2 ..]) |x| top = @min(top, x);
                v = buf[l] + f * (top - buf[l]);
            }
            cells[at] = .{ .float = v };
        }
    }
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
    return joinAsofImpl(a, left, right, spec, true);
}

pub const test_hooks = struct {
    pub fn valueCountsCells(a: std.mem.Allocator, f: Frame, spec: ValueCountsSpec) Error!Frame {
        return valueCountsImpl(a, f, spec, false);
    }

    pub fn describeCells(a: std.mem.Allocator, f: Frame, cols_in: []const []const u8) Error!Frame {
        return describeImpl(a, f, cols_in, false);
    }

    pub fn concatByNameCells(a: std.mem.Allocator, frames: []const Frame) Error!Frame {
        return concatImpl(a, frames, false);
    }

    /// The boxed-cell path alone: the specification the typed path is tested against.
    pub fn joinAsofCells(a: std.mem.Allocator, left: Frame, right: Frame, spec: AsofSpec) AsofError!Frame {
        return joinAsofImpl(a, left, right, spec, false);
    }
};

fn joinAsofImpl(a: std.mem.Allocator, left: Frame, right: Frame, spec: AsofSpec, comptime typed: bool) AsofError!Frame {
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
    // A suffixed name the left side also has would be unreachable: number it.
    if (spec.suffix != null) try keys.uniqueNames(a, cols);
    const cells = std.math.mul(usize, left.len, @max(cols.len, 1)) catch return error.TooLarge;
    if (cells > sp.max_join_cells) return error.TooLarge;

    var picks: []u32 = undefined;
    var any_none = false;
    if (typed and spec.by.len == 0 and try asofPicksTyped(a, left.columnAt(lk[0]), right.columnAt(rk[0]), left.len, spec, &picks, &any_none)) {
        return asofFinish(a, left, right, cols, keep.items, picks, any_none);
    }

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

    picks = try a.alloc(u32, left.len);
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
    return asofFinish(a, left, right, cols, keep.items, picks, any_none);
}

fn asofFinish(a: std.mem.Allocator, left: Frame, right: Frame, cols: []Column, keep: []const usize, picks: []const u32, any_none: bool) AsofError!Frame {
    const data = try a.alloc(ColumnData, cols.len);
    for (data[0..left.columns.len], 0..) |*d, ci| d.* = left.columnAt(ci);
    for (keep, data[left.columns.len..]) |ci, *d| d.* = try verbs.take(a, right.columnAt(ci), picks, any_none);
    return .{ .columns = cols, .data = data, .len = left.len };
}

/// The typed as-of match for a single `on` key without `by`, when both `on` columns are
/// plain int or plain float arrays of one kind. Returns false (nothing allocated that
/// matters) when the storage is anything else: the caller takes the cell path.
/// Same decisions as `asofPick`: NaN and null are missing, a missing left key matches
/// nothing, a missing right row is skipped, the right keys must ascend.
fn asofPicksTyped(a: std.mem.Allocator, lcol: ColumnData, rcol: ColumnData, n: usize, spec: AsofSpec, out: *[]u32, any_none: *bool) AsofError!bool {
    if (lcol == .int and rcol == .int) {
        out.* = try asofRun(i64, a, lcol.int, rcol.int, n, spec, any_none);
        return true;
    }
    if (lcol == .float and rcol == .float) {
        out.* = try asofRun(f64, a, lcol.float, rcol.float, n, spec, any_none);
        return true;
    }
    return false;
}

inline fn asofMissing(comptime T: type, c: fm.TypedColumn(T), i: usize) bool {
    if (!c.isValid(i)) return true;
    return T == f64 and std.math.isNan(c.values[i]);
}

inline fn asofDist(comptime T: type, p: T, q: T) f64 {
    if (T == f64) return @abs(p - q);
    return @abs(@as(f64, @floatFromInt(p)) - @as(f64, @floatFromInt(q)));
}

/// The first index at or after `from` whose key is `>= t` (`strict`: `> t`), `uk.len` if
/// none, given that every key before `from` is below it. Gallops, then bisects.
fn asofSearch(comptime T: type, uk: []const T, from: usize, t: T, comptime strict: bool) usize {
    var lo = from;
    var step: usize = 1;
    var hi = from;
    while (hi < uk.len and (if (strict) uk[hi] <= t else uk[hi] < t)) {
        lo = hi + 1;
        hi = std.math.add(usize, hi, step) catch uk.len;
        step *= 2;
    }
    if (hi > uk.len) hi = uk.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (if (strict) uk[mid] <= t else uk[mid] < t) lo = mid + 1 else hi = mid;
    }
    return lo;
}

fn asofRun(comptime T: type, a: std.mem.Allocator, lc: fm.TypedColumn(T), rc: fm.TypedColumn(T), n: usize, spec: AsofSpec, any_none: *bool) AsofError![]u32 {
    // The right rows with a present key, ascending (checked), as parallel arrays.
    const rn = rc.values.len;
    const ukeys = try a.alloc(T, rn);
    const urows = try a.alloc(u32, rn);
    var m: usize = 0;
    for (0..rn) |i| {
        if (asofMissing(T, rc, i)) continue;
        const k = rc.values[i];
        if (m > 0 and ukeys[m - 1] > k) return error.NotSorted;
        ukeys[m] = k;
        urows[m] = @intCast(i);
        m += 1;
    }
    const uk = ukeys[0..m];
    const picks = try a.alloc(u32, n);
    var none = false;
    const ln = @min(n, lc.values.len);
    var prev_t: T = undefined;
    var prev_ge: usize = 0;
    var have_prev = false;
    for (picks, 0..) |*pk, i| {
        pk.* = keys.none;
        if (i >= ln or asofMissing(T, lc, i)) {
            none = true;
            continue;
        }
        const t = lc.values[i];
        // First key >= t, and first key > t. A left side that ascends (the usual one)
        // searches on from the last position: every key before it is below the last `t`.
        const from: usize = if (have_prev and t >= prev_t) prev_ge else 0;
        const ge = asofSearch(T, uk, from, t, false);
        const gt = asofSearch(T, uk, ge, t, true);
        prev_t = t;
        prev_ge = ge;
        have_prev = true;
        const before_end = if (spec.allow_exact) gt else ge;
        const after_start = if (spec.allow_exact) ge else gt;
        const back: ?usize = if (before_end > 0) before_end - 1 else null;
        const fwd: ?usize = if (after_start < m) after_start else null;
        const chosen: ?usize = switch (spec.direction) {
            .backward => back,
            .forward => fwd,
            .nearest => blk: {
                if (back == null) break :blk fwd;
                if (fwd == null) break :blk back;
                break :blk if (asofDist(T, uk[back.?], t) <= asofDist(T, uk[fwd.?], t)) back else fwd;
            },
        };
        const c = chosen orelse {
            none = true;
            continue;
        };
        if (spec.tolerance) |tol| {
            if (!(asofDist(T, uk[c], t) <= tol)) {
                none = true;
                continue;
            }
        }
        pk.* = urows[c];
    }
    any_none.* = none;
    return picks;
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

// ── resample / reduce ───────────────────────────────────────────────────────

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

/// Bucket a dated series by `freq`, aggregating the value (pandas `resample` at day,
/// week, month, quarter, year). Bucket labels: day → "YYYY-MM-DD", week → the date of
/// its Monday (ISO weeks), month → "YYYY-MM", quarter → "YYYY-Qn", year → "YYYY" (all
/// lexicographically ordered). `compound` = Π(1+v)−1 (return chaining). Rows with an
/// unparseable date are skipped; a missing value counts as 0 (`tabular`'s historical
/// rule). Output: `{out_date, out_value (float)}`, ascending.
pub fn resample(a: std.mem.Allocator, f: Frame, spec: ResampleSpec) Error!Frame {
    const di = try mustIndex(f, spec.date_col);
    const vi = try mustIndex(f, spec.value_col);
    const dcol = f.columnAt(di);
    const vcol = f.columnAt(vi);
    const is_ts = f.columns[di].type == .timestamp;

    var buckets: std.StringArrayHashMapUnmanaged(ResAcc) = .empty;
    for (0..f.len) |ri| {
        const date = cellDate(is_ts, dcol.get(ri)) orelse continue;
        const label = try bucketLabel(a, date, spec.freq);
        const bop = try buckets.getOrPut(a, label);
        if (!bop.found_existing) bop.value_ptr.* = .{};
        bop.value_ptr.observe(vcol.get(ri).asFloat() orelse 0);
    }

    const labels = try a.alloc([]const u8, buckets.count());
    for (buckets.keys(), 0..) |k, i| labels[i] = k;
    std.mem.sort([]const u8, labels, {}, strLess);

    const cols = try a.alloc(Column, 2);
    cols[0] = .{ .name = spec.out_date, .type = if (spec.freq == .day or spec.freq == .week) .date else .text };
    cols[1] = .{ .name = spec.out_value, .type = .float };
    const ks = try a.alloc(Value, labels.len);
    const vs = try a.alloc(Value, labels.len);
    for (labels, ks, vs) |k, *x, *y| {
        x.* = .{ .text = k };
        y.* = .{ .float = buckets.get(k).?.result(spec.agg) };
    }
    const data = try a.alloc(ColumnData, 2);
    data[0] = try fm.columnFromCells(a, ks);
    data[1] = try fm.columnFromCells(a, vs);
    return .{ .columns = cols, .data = data, .len = labels.len };
}

fn strLess(_: void, l: []const u8, r: []const u8) bool {
    return std.mem.order(u8, l, r) == .lt;
}

fn bucketLabel(a: std.mem.Allocator, date: vm.Date, freq: Freq) Error![]const u8 {
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
            const monday = vm.Date.fromOrdinal(ord - @mod(ord + 3, 7)) orelse date;
            const my: u32 = if (monday.y < 0) 0 else @intCast(monday.y);
            break :blk a.print("{d:0>4}-{d:0>2}-{d:0>2}", .{ my, monday.m, monday.d });
        },
    };
}

/// The calendar date (UTC) of a date cell: ISO text in any column, or, in a
/// `.timestamp` column, an `.int` of microseconds since the epoch.
fn cellDate(is_ts: bool, v: Value) ?vm.Date {
    if (is_ts and v == .int)
        return vm.Date.fromOrdinal(@divFloor(v.int, 86_400 * vm.timestamp_units_per_second));
    return vm.parseIsoDate(v.asText() orelse return null);
}

/// The whole table aggregated into one row (`aggregate` with no group-by; pandas
/// `df.agg`, polars `select(pl.col(..).sum(), ...)`): one column per `aggs` entry.
pub fn reduce(a: std.mem.Allocator, f: Frame, aggs: []const sp.AggCol) Error!Frame {
    return verbs.aggregate(a, f, .{ .group_by = &.{}, .aggs = aggs });
}
