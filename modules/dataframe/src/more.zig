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
const dtype = @import("dtype.zig");
const catfn = @import("catfn.zig");
const lf = @import("listfn.zig");
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
    if (ty != .timestamp) cols[ci].time_zone = null;
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
/// repeats reads as its first. A timestamp column that carries different zones in two frames
/// (a zone and no zone included) is `error.SchemaMismatch`: polars raises a `SchemaError`;
/// pandas would fall back to an `object` column of mixed datetimes, which has no type here.
pub fn concatByName(a: std.mem.Allocator, frames: []const Frame) ConcatError!Frame {
    return concatImpl(a, frames, true);
}

pub const ConcatError = Error || error{SchemaMismatch};

fn concatImpl(a: std.mem.Allocator, frames: []const Frame, comptime typed: bool) ConcatError!Frame {
    var names: std.StringArrayHashMapUnmanaged(Column) = .empty;
    var total: usize = 0;
    // One name lookup per frame, not a scan of its columns per output column (sweep S2-6).
    const maps = try a.alloc(fm.NameIndex, frames.len);
    defer a.free(maps);
    var built: usize = 0;
    defer for (maps[0..built]) |*m| m.deinit(a);
    for (frames, maps) |t, *m| {
        m.* = try fm.NameIndex.init(a, t.columns);
        built += 1;
    }
    for (frames) |t| {
        try checkRows(t);
        total = std.math.add(usize, total, t.len) catch return error.TooLarge;
        for (t.columns) |c| {
            const gop = try names.getOrPut(a, c.name);
            if (!gop.found_existing) {
                gop.value_ptr.* = c; // its type and inner columns
            } else if ((dtype.isWidth(gop.value_ptr.type) or dtype.isWidth(c.type)) and gop.value_ptr.type != c.type and dtype.supertype(gop.value_ptr.type, c.type) != null) {
                // Pieces of different numeric types, one of them a width, meet in their supertype
                // (polars `vertical_relaxed`, pandas `concat`; Int64 with UInt64 is Float64 here,
                // W11 D5). Int64 with Float64 keeps the first frame's type, as before W11.
                gop.value_ptr.type = dtype.supertype(gop.value_ptr.type, c.type).?;
            } else if (c.type == .timestamp and gop.value_ptr.type == .timestamp) {
                const z0 = gop.value_ptr.time_zone;
                if ((z0 == null) != (c.time_zone == null) or (z0 != null and !std.mem.eql(u8, z0.?, c.time_zone.?))) return error.SchemaMismatch;
            }
        }
    }
    const width = names.count();
    const n_cells = std.math.mul(usize, total, width) catch return error.TooLarge;
    if (n_cells > sp.max_aggregate_cells) return error.TooLarge;
    const cols = try a.alloc(Column, width);
    for (cols, names.keys(), names.values()) |*c, n, first| c.* = .{ .name = n, .type = first.type, .inner = first.inner, .time_zone = first.time_zone };
    const data = try a.alloc(ColumnData, width);
    var cells: []Value = &.{};
    defer if (cells.len > 0) a.free(cells);
    for (cols, data) |c, *d| {
        if (typed) {
            // Equal categorical pieces (same categories, same order flag) stay as they are.
            if (c.type == .categorical) if (try catfn.concatSame(a, frames, maps, c.name, total)) |col| {
                d.* = col;
                continue;
            };
            if (try concatTyped(a, frames, maps, c.name, total)) |col| {
                d.* = col;
                // Pieces stored as plain text: encoded like the cell path's result.
                if (c.type == .categorical) d.* = try fm.encodeCategorical(a, d.*, total);
                continue;
            }
        }
        if (cells.len == 0) cells = try a.alloc(Value, total);
        var at: usize = 0;
        var width_mix = false;
        for (frames, maps) |t, m| if (m.get(c.name)) |ci| {
            width_mix = width_mix or dtype.isWidth(t.columns[ci].type);
        };
        const numeric = width_mix and dtype.isNumeric(c.type);
        for (frames, maps) |t, m| {
            const col: ColumnData = if (m.get(c.name)) |ci| t.columnAt(ci) else .nulls;
            for (0..t.len) |ri| {
                const v = col.get(ri);
                // Cells of a numeric column in the column's (super)type, so a piece of another
                // width stacks as the type holds it.
                cells[at] = if (numeric and (v == .int or v == .uint or v == .float)) (v.cast(c.type) orelse .null) else v;
                at += 1;
            }
        }
        d.* = try fm.columnFromCells(a, cells);
        if (c.type == .categorical) d.* = try fm.encodeCategorical(a, d.*, total);
        d.* = try fm.conform(a, d.*, c.type, total);
    }
    return .{ .columns = cols, .data = data, .len = total };
}

/// The column `name` of every frame stacked, from the typed arrays, when its non-null
/// cells are all of one kind (or there are none): exactly the storage `columnFromCells`
/// gives for the same cells. Null when some piece is boxed or the kinds mix (the cell
/// path then decides), with nothing kept.
fn concatTyped(a: std.mem.Allocator, frames: []const Frame, maps: []const fm.NameIndex, name: []const u8, total: usize) Error!?ColumnData {
    const Tag = std.meta.Tag(ColumnData);
    var kind: ?Tag = null;
    for (frames, maps) |t, m| {
        const col: ColumnData = if (m.get(name)) |ci| t.columnAt(ci) else .nulls;
        const tag = std.meta.activeTag(col);
        // A dictionary-encoded piece goes by its cells; the result is encoded again.
        // Nested pieces go by their cells too: `columnFromCells` gathers their elements.
        // A width piece too: the cell path stacks it, the caller's `conform` narrows it.
        switch (tag) {
            .boxed, .categorical, .list, .@"struct" => return null,
            .int8, .int16, .int32, .uint8, .uint16, .uint32, .uint64, .float32 => return null,
            else => {},
        }
        if (tag == .nulls or t.len == 0) continue;
        if (concatPresent(col, t.len) == 0) continue;
        if (kind) |k| {
            if (k != tag) return null;
        } else kind = tag;
    }
    const k = kind orelse return .nulls;
    return switch (k) {
        .int => .{ .int = try concatPlain(i64, a, frames, maps, name, total) },
        .float => .{ .float = try concatPlain(f64, a, frames, maps, name, total) },
        .bool => .{ .bool = try concatPlain(bool, a, frames, maps, name, total) },
        .decimal => .{ .decimal = try concatPlain(i128, a, frames, maps, name, total) },
        .text => .{ .text = try concatText(a, frames, maps, name, total) },
        .nulls, .boxed, .categorical, .list, .@"struct" => unreachable,
        .int8, .int16, .int32, .uint8, .uint16, .uint32, .uint64, .float32 => unreachable,
    };
}

/// Non-null cells among the first `n` rows of a typed column, as `get` sees them.
fn concatPresent(col: ColumnData, n: usize) usize {
    switch (col) {
        .nulls, .boxed, .list, .@"struct" => return 0,
        .text => |c| {
            var k: usize = 0;
            for (0..n) |i| k += @intFromBool(c.at(i) != null);
            return k;
        },
        .categorical => |c| return countPresent(u32, c.codes, n),
        inline else => |c| {
            const m = @min(n, c.values.len);
            const v = c.valid orelse return m;
            return bitsSet(v, m);
        },
    }
}

fn countPresent(comptime T: type, c: fm.TypedColumn(T), n: usize) usize {
    const m = @min(n, c.values.len);
    const v = c.valid orelse return m;
    return bitsSet(v, m);
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

fn concatPlain(comptime T: type, a: std.mem.Allocator, frames: []const Frame, maps: []const fm.NameIndex, name: []const u8, total: usize) Error!fm.TypedColumn(T) {
    const values = try a.alloc(T, total);
    const zero: T = if (T == bool) false else 0;
    var present: usize = 0;
    // First pass: how many cells are non-null, to know whether a bitmap is needed.
    for (frames, maps) |t, m| {
        const col: ColumnData = if (m.get(name)) |ci| t.columnAt(ci) else .nulls;
        present += concatPresent(col, t.len);
    }
    const valid: ?[]u64 = if (present == total) null else blk: {
        const w = try a.alloc(u64, total / 64 + 1);
        @memset(w, 0);
        break :blk w;
    };
    var at: usize = 0;
    for (frames, maps) |t, nmap| {
        defer at += t.len;
        const dst = values[at..][0..t.len];
        const col: ColumnData = if (nmap.get(name)) |ci| t.columnAt(ci) else .nulls;
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

fn concatText(a: std.mem.Allocator, frames: []const Frame, maps: []const fm.NameIndex, name: []const u8, total: usize) Error!fm.TextColumn {
    var bytes_n: usize = 0;
    var present: usize = 0;
    for (frames, maps) |t, m| {
        const col: ColumnData = if (m.get(name)) |ci| t.columnAt(ci) else .nulls;
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
    for (frames, maps) |t, m| {
        const col: ColumnData = if (m.get(name)) |ci| t.columnAt(ci) else .nulls;
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
    var nm = try fm.NameIndex.init(a, f.columns);
    defer nm.deinit(a);
    for (idxs, by) |*ix, name| ix.* = try nm.must(name);
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
    /// The count column holds each key's share of the counted rows, a float (pandas
    /// `normalize=True`; polars `normalize=True`). The total is the rows counted: missing
    /// keys are in it only with `keep_missing`.
    normalize: bool = false,
    /// false keeps the first-seen order of the keys (pandas `sort=False`, polars `sort=False`);
    /// true orders by count, `ascending` choosing the direction. Ties keep first-seen order
    /// either way.
    sort: bool = true,
    /// Fewest first (pandas `ascending=True`; polars `sort` is descending only).
    ascending: bool = false,
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
    const last = g.columns.len - 1;
    const sorted = if (!spec.sort) g else try verbs.takeRows(a, g, try verbs.sortedRows(a, g, &.{last}, &.{if (spec.ascending) .asc else .desc}, .auto));
    if (!spec.normalize) return sorted;
    var total: f64 = 0;
    const counts = sorted.columnAt(last);
    for (0..sorted.len) |i| total += counts.get(i).asFloat() orelse 0;
    const cells = try a.alloc(Value, sorted.len);
    defer a.free(cells);
    for (cells, 0..) |*c, i| c.* = if (total > 0) .{ .float = (counts.get(i).asFloat() orelse 0) / total } else .null;
    return withColumn(a, sorted, last, .float, try fm.columnFromCells(a, cells));
}

/// `verbs.aggregate(group_by = cols, size)` without the cells: the group columns of each
/// group's first row and a count column, first-seen order, groups with a missing key
/// dropped unless `keep_missing`. The same steps in the same order, so the same errors.
fn groupSizes(a: std.mem.Allocator, f: Frame, spec: ValueCountsSpec) Error!Frame {
    try core.checkRowsU32(f.len);
    const gidx = try a.alloc(usize, spec.cols.len);
    var nm = try fm.NameIndex.init(a, f.columns);
    defer nm.deinit(a);
    for (gidx, spec.cols) |*ci, name| ci.* = try nm.must(name);
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

/// `f` with every column whose storage holds floats declared `.float`: a frame built cell by
/// cell can declare a duration or timestamp column over float storage, and `aggregate` would
/// convert its `min`/`max` to the declared kind (whole microseconds, losing a `-0.0`) where
/// `describeTyped` reads the floats as they are (fuzz seed 14963). Other columns unchanged.
fn floatStorageAsFloat(a: std.mem.Allocator, f: Frame) Error!Frame {
    var any = false;
    for (f.columns, 0..) |c, ci| {
        if (c.type != .float and f.columnAt(ci) == .float) any = true;
    }
    if (!any) return f;
    const cols = try a.dupe(Column, f.columns);
    for (cols, 0..) |*c, ci| {
        if (f.columnAt(ci) == .float) c.type = .float;
    }
    var g = f;
    g.columns = cols;
    return g;
}

fn describeImpl(a: std.mem.Allocator, f_in: Frame, cols_in: []const []const u8, comptime typed: bool) Error!Frame {
    const f = try floatStorageAsFloat(a, f_in);
    var names: std.ArrayList([]const u8) = .empty;
    var nm = try fm.NameIndex.init(a, f.columns);
    defer nm.deinit(a);
    if (cols_in.len > 0) {
        for (cols_in) |c| {
            _ = try nm.must(c);
            try names.append(a, c);
        }
    } else {
        // Chosen by the declared types (`f_in`), not by `floatStorageAsFloat`'s view.
        for (f_in.columns) |c| {
            if (dtype.isNumeric(c.type) or c.type == .decimal) try names.append(a, c.name);
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
            if (try describeTyped(a, f.columnAt(try nm.must(n)), f.len, &cells)) {
                d.* = try fm.columnFromCells(a, &cells);
                continue;
            }
        }
        for (aggs, stats) |*ag, st| ag.* = .{ .src = n, .out = st.name, .func = st.func, .q = st.q };
        // `describe` reports floats of the stored value, as `describeTyped` does: a duration or
        // timestamp quantile must not be cut to whole microseconds (fuzz seed 1841).
        const one = try verbs.aggregate(a, f, .{ .group_by = &.{}, .aggs = aggs, .skip_na = true, .temporal_results = false });
        for (&cells, 0..) |*c, si| {
            // No rows: every statistic stays null.
            const v: Value = if (one.len == 0) .null else one.columnAt(si).get(0);
            c.* = if (v.asFloat()) |x| .{ .float = x } else .null;
        }
        d.* = try fm.columnFromCells(a, &cells);
    }
    return .{ .columns = cols, .data = data, .len = stats.len };
}

pub const DescribeSpec = struct {
    /// Columns to describe, any kind; empty: chosen by `all`, `include` and `exclude`.
    cols: []const []const u8 = &.{},
    /// The quantile rows, each in [0, 1] (pandas `percentiles`). Exactly these rows, as
    /// pandas 3.1 prints them (its documentation says the median is always added; the
    /// release does not, checked 2026-11-09), ascending and distinct, named as pandas
    /// does: `25%`, `7.5%`.
    percentiles: []const f64 = &.{ 0.25, 0.5, 0.75 },
    /// Every column (pandas `include="all"`).
    all: bool = false,
    /// Only the columns of these types (pandas `include=[dtypes]`); empty: not restricted.
    include: []const ColumnType = &.{},
    /// Not the columns of these types (pandas `exclude=[dtypes]`).
    exclude: []const ColumnType = &.{},
};

pub const DescribeError = Error || error{BadArgument};

const DescribeKind = enum { numeric, temporal, duration, other };

fn describeKind(t: ColumnType) DescribeKind {
    return switch (t) {
        .int, .float, .decimal, .int8, .int16, .int32, .uint8, .uint16, .uint32, .uint64, .float32 => .numeric,
        .timestamp => .temporal,
        .duration => .duration,
        else => .other,
    };
}

fn typeIn(list: []const ColumnType, t: ColumnType) bool {
    for (list) |x| if (x == t) return true;
    return false;
}

/// The sorted, distinct percentile list `describeWith` prints.
fn describePercentiles(a: std.mem.Allocator, given: []const f64) DescribeError![]const f64 {
    if (given.len > 1 << 16) return error.TooLarge;
    for (given) |p| if (!(p >= 0 and p <= 1)) return error.BadArgument;
    const out = try a.alloc(f64, given.len);
    @memcpy(out, given);
    std.mem.sort(f64, out, {}, std.sort.asc(f64));
    var n: usize = 0;
    for (out) |p| {
        if (n > 0 and out[n - 1] == p) continue;
        out[n] = p;
        n += 1;
    }
    return out[0..n];
}

/// Round half to even at `digits` decimals, numpy's `around`.
fn aroundEven(x: f64, digits: i32) f64 {
    if (!std.math.isFinite(x)) return x;
    const scale = std.math.pow(f64, 10, @floatFromInt(digits));
    if (!std.math.isFinite(scale) or scale == 0) return x;
    const y = x * scale;
    if (!std.math.isFinite(y)) return x;
    const r = if (@abs(y - @trunc(y)) == 0.5) 2 * @round(y / 2) else @round(y);
    return r / scale;
}

fn percentLabel(a: std.mem.Allocator, p: f64) std.mem.Allocator.Error![]const u8 {
    // `+ 0.0` turns a percentile of -0.0 into 0 (pandas `0%`, not `-0%`).
    return a.print("{d}%", .{aroundEven(p * 100, 10) + 0.0});
}

const NamedStat = struct { name: []const u8, v: Value };

/// `describe` with pandas' options: `percentiles`, `include`/`exclude`/`all`, and the
/// non-numeric kinds. Columns: `statistic`, then one per described column. The rows are
/// the statistics the described columns have, in order of first appearance (pandas 3.1
/// puts `std` last as soon as a datetime or timedelta column is described):
///   number    `count mean std min <percentiles> max` (float cells; polars `describe` adds a
///             `null_count` row and has no `include`);
///   text, bool, categorical, date, decimal-free others (pandas object/category/bool)
///             `count unique top freq`: `top` the most frequent value, the first seen on a
///             tie, null with `unique` 0 when nothing is present;
///   timestamp `count mean min <percentiles> max`, duration the same plus `std`; the
///             cells are ISO text (pandas prints datetimes), `count` an int.
/// The default selection is pandas': the numeric and timestamp columns, or every column
/// when there is none. With only numeric columns and the default percentiles the numbers
/// are `describe`'s. Percentiles outside [0, 1]: `error.BadArgument`.
pub fn describeWith(a: std.mem.Allocator, f: Frame, spec: DescribeSpec) DescribeError!Frame {
    try checkRows(f);
    var nm = try fm.NameIndex.init(a, f.columns);
    defer nm.deinit(a);
    var sel: std.ArrayList(usize) = .empty;
    defer sel.deinit(a);
    if (spec.cols.len > 0) {
        for (spec.cols) |c| try sel.append(a, try nm.must(c));
    } else if (spec.all) {
        for (0..f.columns.len) |i| try sel.append(a, i);
    } else if (spec.include.len > 0 or spec.exclude.len > 0) {
        for (f.columns, 0..) |c, i| {
            if ((spec.include.len == 0 or typeIn(spec.include, c.type)) and !typeIn(spec.exclude, c.type)) try sel.append(a, i);
        }
    } else {
        for (f.columns, 0..) |c, i| {
            const k = describeKind(c.type);
            if (k == .numeric or k == .temporal) try sel.append(a, i);
        }
        if (sel.items.len == 0) for (0..f.columns.len) |i| try sel.append(a, i);
    }
    const pcts = try describePercentiles(a, spec.percentiles);
    // Output cells: at most the eight fixed statistic rows plus one per percentile, for every
    // selected column and the label column.
    try core.aggregateCellsWithin(pcts.len + 8, sel.items.len + 1);
    const default_pcts = pcts.len == 3 and pcts[0] == 0.25 and pcts[1] == 0.5 and pcts[2] == 0.75;
    var all_numeric = true;
    var any_time = false;
    for (sel.items) |ci| {
        const k = describeKind(f.columns[ci].type);
        if (k != .numeric) all_numeric = false;
        if (k == .temporal or k == .duration) any_time = true;
    }
    // `describe` finds its columns by name: with a repeated name it would describe the
    // first of them twice, so a selection whose names do not lead back to the same
    // columns takes the general path below.
    var by_name = true;
    for (sel.items) |ci| by_name = by_name and nm.get(f.columns[ci].name) == ci;
    if (all_numeric and default_pcts and by_name) {
        const names = try a.alloc([]const u8, sel.items.len);
        for (names, sel.items) |*n, ci| n.* = f.columns[ci].name;
        // `describe` reads an empty list as "every numeric column": say the empty selection here.
        if (names.len > 0) return describe(a, f, names);
    }

    const per = try a.alloc(std.ArrayList(NamedStat), sel.items.len);
    for (per) |*p| p.* = .empty;
    for (sel.items, per) |ci, *list| {
        const col = f.columnAt(ci);
        const kind = describeKind(f.columns[ci].type);
        if (kind == .other) {
            try describeText(a, col, f.len, list);
        } else {
            try describeNumberLike(a, col, f.len, kind, pcts, list);
        }
    }
    // The row names: first appearance across the columns (a hash set keeps this linear).
    var rows: std.ArrayList([]const u8) = .empty;
    defer rows.deinit(a);
    var row_of: std.StringHashMapUnmanaged(usize) = .empty;
    defer row_of.deinit(a);
    for (per) |list| {
        for (list.items) |st| {
            const g = try row_of.getOrPut(a, st.name);
            if (!g.found_existing) {
                g.value_ptr.* = rows.items.len;
                try rows.append(a, st.name);
            }
        }
    }
    if (any_time) {
        for (rows.items, 0..) |r, i| {
            if (std.mem.eql(u8, r, "std")) {
                _ = rows.orderedRemove(i);
                try rows.append(a, "std");
                break;
            }
        }
        for (rows.items, 0..) |r, i| row_of.getPtr(r).?.* = i;
    }
    const cols = try a.alloc(Column, 1 + sel.items.len);
    const data = try a.alloc(ColumnData, cols.len);
    cols[0] = .{ .name = "statistic", .type = .text };
    const label_cells = try a.alloc(Value, rows.items.len);
    for (label_cells, rows.items) |*c, r| c.* = .{ .text = r };
    data[0] = try fm.columnFromCells(a, label_cells);
    for (sel.items, per, cols[1..], data[1..]) |ci, list, *c, *d| {
        const numeric = describeKind(f.columns[ci].type) == .numeric;
        c.* = .{ .name = f.columns[ci].name, .type = if (numeric) .float else .text };
        const cells = try a.alloc(Value, rows.items.len);
        for (cells) |*cell| cell.* = .null;
        // A name that repeats inside one column: the later statistic wins.
        for (list.items) |st| cells[row_of.get(st.name).?] = st.v;
        d.* = try fm.columnFromCells(a, cells);
    }
    try keys.uniqueNames(a, cols);
    return .{ .columns = cols, .data = data, .len = rows.items.len };
}

/// count / unique / top / freq of any column.
fn describeText(a: std.mem.Allocator, col: ColumnData, rows: usize, out: *std.ArrayList(NamedStat)) DescribeError!void {
    var t = try keys.Table.initBytes(a, rows, keys.freshSeed(rows));
    var scratch: std.ArrayList(u8) = .empty;
    defer scratch.deinit(a);
    var firsts: std.ArrayList(Value) = .empty;
    defer firsts.deinit(a);
    var counts: std.ArrayList(u64) = .empty;
    defer counts.deinit(a);
    var present: i64 = 0;
    for (0..rows) |i| {
        const v = col.get(i);
        if (isMissing(v)) continue;
        present += 1;
        scratch.clearRetainingCapacity();
        try keys.encode(a, &scratch, v, .as_null);
        const id = try t.getOrPutBytes(a, scratch.items);
        if (id == counts.items.len) {
            try counts.append(a, 0);
            try firsts.append(a, v);
        }
        counts.items[id] += 1;
    }
    var best: usize = 0;
    for (counts.items, 0..) |c, i| {
        if (c > counts.items[best]) best = i;
    }
    try out.append(a, .{ .name = "count", .v = .{ .int = present } });
    try out.append(a, .{ .name = "unique", .v = .{ .int = @intCast(counts.items.len) } });
    try out.append(a, .{ .name = "top", .v = if (counts.items.len == 0) .null else firsts.items[best] });
    try out.append(a, .{ .name = "freq", .v = if (counts.items.len == 0) .null else .{ .int = @intCast(counts.items[best]) } });
}

/// count / mean / std / min / percentiles / max of a number, timestamp or duration column.
fn describeNumberLike(a: std.mem.Allocator, col: ColumnData, rows: usize, kind: DescribeKind, pcts: []const f64, out: *std.ArrayList(NamedStat)) DescribeError!void {
    const vals = try a.alloc(f64, rows);
    defer a.free(vals);
    var m: usize = 0;
    var sum: f64 = 0;
    var mo: core.Moments = .{};
    for (0..rows) |i| {
        const v = col.get(i);
        if (isMissing(v)) continue;
        const x = v.asFloat() orelse continue;
        if (std.math.isNan(x)) continue;
        vals[m] = x;
        m += 1;
        sum += x;
        mo.add2(x);
    }
    const xs = vals[0..m];
    std.mem.sort(f64, xs, {}, std.sort.asc(f64));
    const mk = struct {
        fn of(al: std.mem.Allocator, k: DescribeKind, x: f64) std.mem.Allocator.Error!Value {
            if (k == .numeric) return .{ .float = x };
            const us = Value.floatToInt(i64, @round(x)) orelse return .null;
            if (k == .temporal) {
                var buf: [vm.max_iso_timestamp_len]u8 = undefined;
                return .{ .text = try al.dupe(u8, vm.formatIsoTimestamp(&buf, us)) };
            }
            var buf: [vm.max_duration_len]u8 = undefined;
            return .{ .text = try al.dupe(u8, vm.formatIsoDuration(&buf, us)) };
        }
    }.of;
    try out.append(a, .{ .name = "count", .v = if (kind == .numeric) .{ .float = @floatFromInt(m) } else .{ .int = @intCast(m) } });
    try out.append(a, .{ .name = "mean", .v = if (m == 0) .null else try mk(a, kind, sum / @as(f64, @floatFromInt(m))) });
    if (kind != .temporal) {
        const sd = core.momentResult(mo, .std, 1);
        try out.append(a, .{ .name = "std", .v = if (sd.asFloat()) |x| try mk(a, kind, x) else .null });
    }
    try out.append(a, .{ .name = "min", .v = if (m == 0) .null else try mk(a, kind, xs[0]) });
    for (pcts) |p| {
        const h = if (m == 0) 0 else @as(f64, @floatFromInt(m - 1)) * p;
        var v: Value = .null;
        if (m > 0) {
            const lo: usize = @intFromFloat(@floor(h));
            const frac = h - @floor(h);
            const q = if (frac == 0 or lo + 1 >= m) xs[lo] else xs[lo] + frac * (xs[lo + 1] - xs[lo]);
            v = try mk(a, kind, q);
        }
        try out.append(a, .{ .name = try percentLabel(a, p), .v = v });
    }
    try out.append(a, .{ .name = "max", .v = if (m == 0) .null else try mk(a, kind, xs[m - 1]) });
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

pub const QuantilesSpec = struct {
    /// Columns to take the quantiles of; empty = every int, float and decimal column.
    cols: []const []const u8 = &.{},
    /// The probabilities, each in [0, 1]: one output row each, in this order.
    qs: []const f64,
    interpolation: sp.Interpolation = .linear,
    /// The first output column, holding the probabilities.
    q_name: []const u8 = "quantile",
};

pub const QuantilesError = Error || error{BadArgument};

/// Most row visits one `quantiles` call may make (probabilities × (rows + 1) × (columns + 1)):
/// each probability selects over every column. 2^30.
pub const max_quantile_work: usize = 1 << 30;

/// Several quantiles of several columns in one call (pandas `DataFrame.quantile([q, ...])`:
/// a row per probability, a column per input column; polars asks `quantile` once per
/// probability). Missing and non-number cells are skipped; a column with no number
/// gives null. A probability outside [0, 1] or NaN: `error.BadArgument` (pandas raises).
/// `interpolation` follows pandas, plus polars' `equiprobable`.
pub fn quantiles(a: std.mem.Allocator, f: Frame, spec: QuantilesSpec) QuantilesError!Frame {
    for (spec.qs) |q| if (!(q >= 0 and q <= 1)) return error.BadArgument;
    var idxs: std.ArrayList(usize) = .empty;
    defer idxs.deinit(a);
    if (spec.cols.len > 0) {
        var nm = try fm.NameIndex.init(a, f.columns);
        defer nm.deinit(a);
        for (spec.cols) |c| try idxs.append(a, try nm.must(c));
    } else {
        for (f.columns, 0..) |c, i| {
            if (dtype.isNumeric(c.type) or c.type == .decimal) try idxs.append(a, i);
        }
    }
    try core.aggregateCellsWithin(spec.qs.len, idxs.items.len + 1);
    // Each probability costs a pass over the rows of every column: bound that work too, by a
    // work budget (as `max_window_work`), not the output-cell cap — 3 quantiles of a 3M-row
    // column are a sane request.
    const per_q = std.math.mul(usize, f.len + 1, idxs.items.len + 1) catch return error.TooLarge;
    const work = std.math.mul(usize, spec.qs.len, per_q) catch return error.TooLarge;
    if (work > max_quantile_work) return error.TooLarge;
    const cols = try a.alloc(Column, idxs.items.len + 1);
    const data = try a.alloc(ColumnData, cols.len);
    cols[0] = .{ .name = spec.q_name, .type = .float };
    const qcells = try a.alloc(Value, spec.qs.len);
    defer a.free(qcells);
    for (qcells, spec.qs) |*c, q| c.* = .{ .float = q };
    data[0] = try fm.columnFromCells(a, qcells);
    const vals = try a.alloc(f64, f.len);
    defer a.free(vals);
    const buf = try a.alloc(f64, f.len);
    defer a.free(buf);
    for (idxs.items, cols[1..], data[1..]) |ci, *c, *d| {
        c.* = .{ .name = f.columns[ci].name, .type = .float };
        const col = f.columnAt(ci);
        var m: usize = 0;
        for (0..f.len) |ri| {
            const v = col.get(ri);
            if (isMissing(v)) continue;
            const x = v.asFloat() orelse continue;
            if (std.math.isNan(x)) continue;
            vals[m] = x;
            m += 1;
        }
        for (qcells, spec.qs) |*cell, q| {
            @memcpy(buf[0..m], vals[0..m]);
            cell.* = core.quantileInterp(buf[0..m], q, spec.interpolation);
        }
        d.* = try fm.columnFromCells(a, qcells);
    }
    try keys.uniqueNames(a, cols);
    return .{ .columns = cols, .data = data, .len = spec.qs.len };
}

pub const OhlcSpec = struct {
    group_by: []const []const u8,
    /// The price column; its type is the type of all four outputs.
    value_col: []const u8,
    /// Output names are `open high low close`, or `{prefix}_open` ... when set.
    prefix: []const u8 = "",
    /// Order the groups by key, as `AggregateSpec.sort_groups`.
    sort_groups: bool = false,
    /// As `AggregateSpec.drop_missing_keys`.
    drop_missing_keys: bool = false,
};

/// The four aggregations of an open-high-low-close bar over `value_col`, named as `OhlcSpec`
/// says: first, max, min, last present value, in row order. For `groupByDynamic`'s `aggs`
/// (pandas `resample(...).ohlc()`).
pub fn ohlcAggs(a: std.mem.Allocator, value_col: []const u8, prefix: []const u8) std.mem.Allocator.Error![]const sp.AggCol {
    const names = [4][]const u8{ "open", "high", "low", "close" };
    const funcs = [4]sp.AggFn{ .first, .max, .min, .last };
    const out = try a.alloc(sp.AggCol, 4);
    for (out, names, funcs) |*c, n, fnc| {
        c.* = .{ .src = value_col, .out = if (prefix.len == 0) n else try a.print("{s}_{s}", .{ prefix, n }), .func = fnc };
    }
    return out;
}

/// Per group, the open, high, low and close of `value_col` (pandas `groupby(...)[col].ohlc()`,
/// the `ohlc` of `resample`): the first, largest, smallest and last present value in row
/// order; a group with none has nulls. polars has no `ohlc`; its `first/max/min/last` in
/// one `agg` is the same. Groups in first-seen order.
pub fn ohlc(a: std.mem.Allocator, f: Frame, spec: OhlcSpec) Error!Frame {
    return verbs.aggregate(a, f, .{
        .group_by = spec.group_by,
        .aggs = try ohlcAggs(a, spec.value_col, spec.prefix),
        .skip_na = true,
        .sort_groups = spec.sort_groups,
        .drop_missing_keys = spec.drop_missing_keys,
    });
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
    // A width (W11) stays in its type under whole bounds it holds, else turns float.
    const holds = struct {
        fn of(b: ?f64, ty: ColumnType) bool {
            const x = b orelse return true;
            if (std.math.isNan(x)) return true;
            const i = Value.floatToInt(i128, x) orelse return false;
            return dtype.fits(i, ty);
        }
    }.of;
    const to_float = dtype.isInteger(col_type) and !(whole(spec.lower) and whole(spec.upper) and holds(spec.lower, col_type) and holds(spec.upper, col_type));
    const out_type: ColumnType = if (to_float) .float else col_type;
    const bound = struct {
        fn of(x: f64, ty: ColumnType) Value {
            if (dtype.isInteger(ty)) return dtype.fitInt(Value.floatToInt(i128, x) orelse 0, ty) orelse .null; // `holds` checked it
            return switch (ty) {
                .decimal => (Value{ .float = x }).cast(.decimal) orelse .{ .float = x },
                .float32 => .{ .float = dtype.roundF32(x) },
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
    return withColumn(a, f, ci, out_type, try fm.conform(a, try fm.columnFromCells(a, cells), out_type, f.len));
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
    /// Ascending bin edges, at least two: `edges.len - 1` bins. Empty: `bins` decides.
    edges: []const f64 = &.{},
    /// pandas `cut(x, bins=n)`: that many equal-width bins over the column's min..max, the
    /// outer edge moved out by 0.1 % of the range (the left one, or with `right = false`
    /// the right one) so the extreme lies inside; a constant column's range is 0.1 % of
    /// its value either way. Used only when `edges` is empty; 0 is `error.BadEdges`.
    bins: usize = 0,
    /// One per bin. Empty: the output is the bin's 0-based number (pandas'
    /// `labels=False`), `.int`, or with `interval_labels` its interval as text.
    labels: []const []const u8 = &.{},
    /// pandas' default `labels=None`: the output is each bin's interval as text, `(a, b]`
    /// (`[a, b)` with `right = false`), the edges rounded to `precision` decimals as
    /// pandas' `_round_frac` does (more of them when two edges would print alike). Without
    /// `labels`; the text is the one pandas prints, with `inf` for an infinite edge.
    interval_labels: bool = false,
    /// pandas' `precision`, the decimals the interval labels keep (default 3).
    precision: u8 = 3,
    /// Also write each row's bin right edge as a float column of this name: polars `include_breaks`
    /// (its `breakpoint` field; give `-inf`/`inf` as outer edges for polars' open ends).
    break_out: ?[]const u8 = null,
    /// Bins `(a, b]` (pandas' default) or, false, `[a, b)`.
    right: bool = true,
    /// The first bin (or, with `right = false`, the last) also takes its outer edge.
    include_lowest: bool = false,
};

pub const CutError = Error || error{BadEdges};

/// pandas' `cut(x, bins=n, retbins=True)` edges: `n + 1` ascending edges for the present
/// numbers of `col`. `error.BadEdges` for `bins == 0`, no number, or a non-finite
/// extreme; `error.TooLarge` above 2^20 bins. (`cut` with `interval_labels` and `bins` also gives
/// `error.TooLarge` above `max(rows, 4096)` bins: the texts are built for every bin.)
pub fn binEdges(a: std.mem.Allocator, f: Frame, col: []const u8, bins: usize, right: bool) CutError![]const f64 {
    const ci = try mustIndex(f, col);
    if (bins == 0) return error.BadEdges;
    if (bins > 1 << 20) return error.TooLarge;
    const c = f.columnAt(ci);
    var mn: f64 = 0;
    var mx: f64 = 0;
    var have = false;
    for (0..f.len) |ri| {
        const v = c.get(ri);
        if (isMissing(v)) continue;
        const x = v.asFloat() orelse continue;
        if (std.math.isNan(x)) continue;
        if (!have) {
            mn = x;
            mx = x;
            have = true;
        } else {
            mn = @min(mn, x);
            mx = @max(mx, x);
        }
    }
    if (!have or !std.math.isFinite(mn) or !std.math.isFinite(mx)) return error.BadEdges;
    if (!std.math.isFinite(mx - mn)) return error.BadEdges;
    const out = try a.alloc(f64, bins + 1);
    if (mn == mx) {
        const adj = if (mn != 0) 0.001 * @abs(mn) else 0.001;
        mn -= adj;
        mx += adj;
    }
    const step = (mx - mn) / @as(f64, @floatFromInt(bins));
    for (out, 0..) |*e, i| e.* = mn + step * @as(f64, @floatFromInt(i));
    out[bins] = mx;
    const adj = (mx - mn) * 0.001;
    if (right) out[0] -= adj else out[bins] += adj;
    return out;
}

/// pandas' `_round_frac`: `x` rounded so `p` significant decimals survive below a leading zero.
fn roundFrac(x: f64, p: i32) f64 {
    if (x == 0 or !std.math.isFinite(x)) return x;
    const frac = x - @trunc(x);
    const digits: i32 = if (@trunc(x) == 0) p - 1 - @as(i32, @intFromFloat(@floor(std.math.log10(@abs(frac))))) else p;
    return aroundEven(x, digits);
}

fn edgeText(a: std.mem.Allocator, x: f64) std.mem.Allocator.Error![]const u8 {
    if (std.math.isInf(x)) return if (x > 0) "inf" else "-inf";
    const t = try a.print("{d}", .{x});
    return if (std.mem.indexOfScalar(u8, t, '.') == null) try a.print("{s}.0", .{t}) else t;
}

/// The texts pandas gives the bins: `(a, b]` / `[a, b)` of the rounded edges.
fn intervalLabels(a: std.mem.Allocator, e: []const f64, right: bool, include_lowest: bool, precision: u8) std.mem.Allocator.Error![]const []const u8 {
    var p: i32 = precision;
    var found = false;
    var tries: i32 = precision;
    while (tries < 20 and !found) : (tries += 1) {
        found = true;
        var prev: f64 = 0;
        for (e, 0..) |b, i| {
            const r = roundFrac(b, tries);
            if (i > 0 and r == prev) found = false;
            prev = r;
        }
        if (found) p = tries;
    }
    const br = try a.alloc(f64, e.len);
    defer a.free(br);
    for (br, e) |*x, b| x.* = roundFrac(b, p);
    if (right and include_lowest) br[0] -= std.math.pow(f64, 10, @floatFromInt(-p));
    const out = try a.alloc([]const u8, e.len - 1);
    for (out, 0..) |*l, i| {
        l.* = try a.print("{s}{s}, {s}{s}", .{ if (right) "(" else "[", try edgeText(a, br[i]), try edgeText(a, br[i + 1]), if (right) "]" else ")" });
    }
    return out;
}

/// Bin a numeric column into a new column `out` (pandas `cut`, polars `cut`). Outside
/// every bin, missing, or not a number: null. Edges not strictly ascending or NaN, or
/// a label count that is not the bin count: `error.BadEdges`. The bins come from `edges`
/// or, when empty, from `bins` (see `binEdges`, which also returns them: pandas'
/// `retbins`). The output is the label text, the interval text (`interval_labels`) or the
/// bin number; `break_out` adds the bin's right edge (polars `include_breaks`).
pub fn cut(a: std.mem.Allocator, f: Frame, spec: CutSpec) CutError!Frame {
    const ci = try mustIndex(f, spec.col);
    // Interval texts (two prints per bin and the precision search) are built for every bin,
    // used or not: with `bins` as a count, bound them by the rows (or 4096 bins).
    if (spec.edges.len == 0 and spec.interval_labels and spec.labels.len == 0 and spec.bins > @max(f.len, 4096)) return error.TooLarge;
    const e = if (spec.edges.len > 0) spec.edges else try binEdges(a, f, spec.col, spec.bins, spec.right);
    if (e.len < 2) return error.BadEdges;
    for (e[0 .. e.len - 1], e[1..]) |l, m| {
        if (!(l < m)) return error.BadEdges;
    }
    if (spec.labels.len != 0 and spec.labels.len != e.len - 1) return error.BadEdges;
    const labels: []const []const u8 = if (spec.labels.len != 0) spec.labels else if (spec.interval_labels)
        try intervalLabels(a, e, spec.right, spec.include_lowest, spec.precision)
    else
        &.{};
    const col = f.columnAt(ci);
    const cells = try a.alloc(Value, f.len);
    defer a.free(cells);
    const brk: []Value = if (spec.break_out != null) try a.alloc(Value, f.len) else &.{};
    defer if (spec.break_out != null) a.free(brk);
    for (cells, 0..) |*o, ri| {
        o.* = .null;
        if (spec.break_out != null) brk[ri] = .null;
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
        if (bin) |b| {
            o.* = if (labels.len != 0) .{ .text = labels[b] } else .{ .int = @intCast(b) };
            if (spec.break_out != null) brk[ri] = .{ .float = e[b + 1] };
        }
    }
    const ty: ColumnType = if (labels.len != 0) .text else .int;
    var out = try appendColumn(a, f, .{ .name = spec.out, .type = ty }, try fm.columnFromCells(a, cells));
    if (spec.break_out) |name| out = try appendColumn(a, out, .{ .name = name, .type = .float }, try fm.columnFromCells(a, brk));
    return out;
}

// ── polars bin_intervals / bin_quantiles / bin_ranks (dataframe S2 wave W10) ─

pub const BinError = Error || error{
    /// Breakpoints that decrease or are not comparable with the column, a fraction outside
    /// [0, 1] or decreasing, or a bin count of zero.
    BadEdges,
    /// A label count that is not the bin count, or a label twice (polars: `ShapeError`, and an
    /// `Enum` refuses a repeated category).
    BadLabels,
    /// A column that has no order here (bool, decimal, categorical, nested), or `bin_quantiles` /
    /// a bin count over a text column.
    NotOrderable,
};

/// Most bins one `bin_*` call may make (labels, intervals and breakpoints are built per bin).
pub const max_bins: usize = 1 << 20;

/// The breakpoints of `binIntervals`: given (non-decreasing, any orderable cell kind the column
/// has), or a count of equal-width bins over the column's min..max (numeric columns).
pub const BinPoints = union(enum) { at: []const Value, count: usize };

/// The fractions of `binQuantiles` / `binRanks` (each in [0, 1], non-decreasing), or a count of
/// equal bins.
pub const BinFractions = union(enum) { at: []const f64, count: usize };

pub const BinIntervalsSpec = struct {
    col: []const u8,
    out: []const u8,
    breaks: BinPoints,
    /// One per bin (`breaks.len + 1`, or the count). Empty: the bin number, an int (polars
    /// `labels=False`, UInt32). Labels make a text column (polars: an `Enum`; `catSetCategories`
    /// makes one here).
    labels: []const []const u8 = &.{},
    /// polars `include_intervals`: `out` is a record `{bin, left, right}`; the first bin's
    /// `left` and the last bin's `right` are null.
    include_intervals: bool = false,
    /// `(left, right]` bins instead of polars' default `[left, right)`.
    right_closed: bool = false,
};

pub const BinQuantilesSpec = struct {
    col: []const u8,
    out: []const u8,
    quantiles: BinFractions,
    labels: []const []const u8 = &.{},
    include_intervals: bool = false,
    right_closed: bool = false,
};

pub const BinRanksSpec = struct {
    col: []const u8,
    out: []const u8,
    ranks: BinFractions,
    labels: []const []const u8 = &.{},
    include_intervals: bool = false,
};

fn orderableType(t: ColumnType) bool {
    return switch (t) {
        .int, .float, .text, .timestamp, .duration, .date => true,
        else => false,
    };
}

fn numericType(t: ColumnType) bool {
    return t == .int or t == .float or t == .timestamp or t == .duration;
}

fn checkLabels(a: std.mem.Allocator, labels: []const []const u8, bins: usize) BinError!void {
    if (labels.len == 0) return;
    if (labels.len != bins) return error.BadLabels;
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(a);
    for (labels) |l| if ((try seen.getOrPut(a, l)).found_existing) return error.BadLabels;
}

fn checkFractions(xs: []const f64) BinError!void {
    var prev: f64 = 0;
    for (xs) |x| {
        if (!(x >= 0 and x <= 1) or x < prev) return error.BadEdges;
        prev = x;
    }
}

/// The present (non-missing) cells of column `ci` as `Value`s, the row of each in `rows`.
const BinPresent = struct { vals: []Value, rows: []u32 };

fn binPresent(a: std.mem.Allocator, f: Frame, ci: usize) Error!BinPresent {
    const col = f.columnAt(ci);
    var vals: std.ArrayList(Value) = .empty;
    var rows: std.ArrayList(u32) = .empty;
    for (0..f.len) |ri| {
        const v = col.get(ri);
        if (isMissing(v)) continue;
        try vals.append(a, v);
        try rows.append(a, @intCast(ri)); // `checkRows` holds the length
    }
    return .{ .vals = vals.items, .rows = rows.items };
}

fn valueLess(_: void, x: Value, y: Value) bool {
    return Value.order(x, y) == .lt;
}

/// The bins' output column(s) for the bin number of each row (`null` = no bin) and the
/// breakpoints between bins (`breaks[k]` separates bin `k` from `k + 1`; null = no value).
fn binOutput(a: std.mem.Allocator, f: Frame, out: []const u8, labels: []const []const u8, include: bool, in_type: ColumnType, bin_of: []const ?u32, breaks: []const Value) Error!Frame {
    const cells = try a.alloc(Value, f.len);
    defer a.free(cells);
    const bins = breaks.len + 1;
    if (!include) {
        for (cells, bin_of) |*c, b| c.* = if (b) |k| (if (labels.len != 0) Value{ .text = labels[k] } else Value{ .int = k }) else .null;
        return appendColumn(a, f, .{ .name = out, .type = if (labels.len != 0) .text else .int }, try fm.columnFromCells(a, cells));
    }
    // Break values in the column's own type: an int break in a float column is a float.
    const bv = try a.alloc(Value, breaks.len);
    var left_type: ColumnType = in_type;
    for (breaks) |b| if (in_type == .int and b == .float) {
        left_type = .float;
    };
    for (bv, breaks) |*o, b| o.* = if (left_type == .float and b == .int) Value{ .float = @floatFromInt(b.int) } else b;
    const names: []const []const u8 = &.{ "bin", "left", "right" };
    for (cells, bin_of) |*c, b| {
        var vals: [3]Value = .{ .null, .null, .null };
        if (b) |k| {
            vals[0] = if (labels.len != 0) .{ .text = labels[k] } else .{ .int = k };
            if (k > 0) vals[1] = bv[k - 1];
            if (k + 1 < bins) vals[2] = bv[k];
        }
        c.* = try lf.makeRecord(a, names, &vals);
    }
    const inner = try a.dupe(Column, &.{
        .{ .name = "bin", .type = if (labels.len != 0) .text else .int },
        .{ .name = "left", .type = left_type },
        .{ .name = "right", .type = left_type },
    });
    return appendColumn(a, f, .{ .name = out, .type = .@"struct", .inner = inner }, try fm.columnFromCells(a, cells));
}

/// `f` with column `ci`, when it is of a width type (W11), declared Int64 or Float64 over the
/// same cells (a UInt64 above `maxInt(i64)` is missing there); null for any other column.
/// The binning verbs read the column's kind, not its width: the interval ends and bin numbers
/// are the Int64 / Float64 ones (polars keeps the column's dtype for the ends: a written
/// difference), and `restoreColumn` puts the caller's column back in the result.
fn widened(a: std.mem.Allocator, f: Frame, ci: usize) Error!?Frame {
    const t = f.columns[ci].type;
    if (!dtype.isWidth(t)) return null;
    const cells = try a.alloc(Value, f.len);
    defer a.free(cells);
    const src = f.columnAt(ci);
    for (cells, 0..) |*c, ri| {
        const v = src.get(ri);
        c.* = if (v == .uint) .null else v;
    }
    const cols = try a.dupe(Column, f.columns);
    cols[ci].type = if (dtype.isFloat(t)) .float else .int;
    const data = try a.alloc(ColumnData, cols.len);
    for (data, 0..) |*d, i| d.* = f.columnAt(i);
    data[ci] = try fm.columnFromCells(a, cells);
    return .{ .columns = cols, .data = data, .len = f.len };
}

/// `res` (made from `widened(f, ci)`) with the caller's own column `ci` put back; any other
/// layout is returned as it is.
fn restoreColumn(a: std.mem.Allocator, res: Frame, f: Frame, ci: usize) Error!Frame {
    if (ci >= res.columns.len or !std.mem.eql(u8, res.columns[ci].name, f.columns[ci].name)) return res;
    const cols = try a.dupe(Column, res.columns);
    const data = try a.alloc(ColumnData, cols.len);
    for (data, 0..) |*d, i| d.* = res.columnAt(i);
    cols[ci] = f.columns[ci];
    data[ci] = f.columnAt(ci);
    return .{ .columns = cols, .data = data, .len = res.len };
}

/// The bin of `x` among `breaks` (non-decreasing): the number of breaks at or below `x`, or
/// below it for right-closed bins.
fn binOf(breaks: []const Value, x: Value, right_closed: bool) u32 {
    var lo: usize = 0;
    var hi: usize = breaks.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const o = Value.order(breaks[mid], x);
        if (if (right_closed) o == .lt else o != .gt) lo = mid + 1 else hi = mid;
    }
    return @intCast(lo); // breaks.len <= max_bins
}

fn compatible(col_type: ColumnType, v: Value) bool {
    return switch (v) {
        .int, .float => numericType(col_type),
        .text => col_type == .text or col_type == .date,
        else => false,
    };
}

/// polars `Expr.bin_intervals(intervals, labels=, include_intervals=, right_closed=)`: each
/// present cell gets the number (or label) of the interval between the breakpoints it falls
/// in: `breaks.len + 1` bins, the first and last open-ended. A count instead of breakpoints
/// makes that many equal-width bins over the column's min..max; for an int-like column the
/// derived breakpoints are rounded to the side that keeps the bins' integers those of the
/// exact ones (up for `[a, b)`, down for `(a, b]`, in exact arithmetic), for a float column
/// they are floats. The column is `int`, `float`, `timestamp`, `duration`, `date` or `text`
/// (a count needs a numeric one); breakpoints must be non-decreasing and of the column's
/// kind (`error.BadEdges`). Null and NaN cells (the module's one missing rule; polars bins
/// a NaN last) give null. A result of `include_intervals` is a record column. Bins are capped
/// at `max_bins` (`error.TooLarge`). Unlike `cut` there is no pandas finite-range edge: the
/// outer bins are open.
pub fn binIntervals(a: std.mem.Allocator, f: Frame, spec: BinIntervalsSpec) BinError!Frame {
    const ci = try mustIndex(f, spec.col);
    const g = (try widened(a, f, ci)) orelse return binIntervalsImpl(a, f, spec);
    return restoreColumn(a, try binIntervalsImpl(a, g, spec), f, ci);
}

fn binIntervalsImpl(a: std.mem.Allocator, f: Frame, spec: BinIntervalsSpec) BinError!Frame {
    try checkRows(f);
    const ci = try mustIndex(f, spec.col);
    const ty = f.columns[ci].type;
    if (!orderableType(ty)) return error.NotOrderable;
    const pr = try binPresent(a, f, ci);
    const breaks: []const Value = switch (spec.breaks) {
        .at => |bs| blk: {
            if (bs.len >= max_bins) return error.TooLarge;
            for (bs, 0..) |b, i| {
                if (!compatible(ty, b)) return error.BadEdges;
                if (i > 0 and Value.order(bs[i - 1], b) == .gt) return error.BadEdges;
            }
            break :blk bs;
        },
        .count => |n| blk: {
            if (n == 0) return error.BadEdges;
            if (n > max_bins) return error.TooLarge;
            if (!numericType(ty)) return error.NotOrderable;
            const out = try a.alloc(Value, n - 1);
            if (pr.vals.len == 0) {
                @memset(out, .null);
                break :blk out;
            }
            var mn = pr.vals[0];
            var mx = pr.vals[0];
            for (pr.vals) |v| {
                if (Value.order(v, mn) == .lt) mn = v;
                if (Value.order(v, mx) == .gt) mx = v;
            }
            for (out, 1..) |*o, i| {
                if (ty == .float) {
                    const lo = mn.asFloat().?; // a float column's cell
                    const hi = mx.asFloat().?;
                    o.* = .{ .float = lo + (hi - lo) * @as(f64, @floatFromInt(i)) / @as(f64, @floatFromInt(n)) };
                } else {
                    // (min * (n - i) + max * i) / n in exact arithmetic, rounded as the bin side asks.
                    const lo: i128 = mn.int;
                    const hi: i128 = mx.int;
                    const num = lo * @as(i128, @intCast(n - i)) + hi * @as(i128, @intCast(i));
                    const q = if (spec.right_closed) @divFloor(num, @as(i128, @intCast(n))) else -@divFloor(-num, @as(i128, @intCast(n)));
                    o.* = .{ .int = @intCast(q) }; // between min and max
                }
            }
            break :blk out;
        },
    };
    try checkLabels(a, spec.labels, breaks.len + 1);
    const bin_of = try a.alloc(?u32, f.len);
    defer a.free(bin_of);
    @memset(bin_of, null);
    for (pr.vals, pr.rows) |v, ri| bin_of[ri] = binOf(breaks, v, spec.right_closed);
    return binOutput(a, f, spec.out, spec.labels, spec.include_intervals, ty, bin_of, breaks);
}

/// polars `Expr.bin_quantiles(quantiles, labels=, include_intervals=, right_closed=)`: the
/// breakpoints are values of the column, the sorted present value at `floor(q * (n - 1))` for
/// each quantile `q` (a count `k`: at `floor(i * (n - 1) / k)` for `i = 1..k-1`, in integer
/// arithmetic), and the cells are binned as in `binIntervals`; equal quantiles delimit an
/// empty bin and equal values stay in one bin. The column is `int` or `float`
/// (`error.NotOrderable`); quantiles outside [0, 1] or decreasing are `error.BadEdges`. Null and
/// NaN cells give null and are not counted in `n`.
pub fn binQuantiles(a: std.mem.Allocator, f: Frame, spec: BinQuantilesSpec) BinError!Frame {
    const ci = try mustIndex(f, spec.col);
    const g = (try widened(a, f, ci)) orelse return binQuantilesImpl(a, f, spec);
    return restoreColumn(a, try binQuantilesImpl(a, g, spec), f, ci);
}

fn binQuantilesImpl(a: std.mem.Allocator, f: Frame, spec: BinQuantilesSpec) BinError!Frame {
    try checkRows(f);
    const ci = try mustIndex(f, spec.col);
    const ty = f.columns[ci].type;
    if (ty != .int and ty != .float) return error.NotOrderable;
    const nb: usize = switch (spec.quantiles) {
        .at => |qs| blk: {
            try checkFractions(qs);
            break :blk qs.len;
        },
        .count => |n| blk: {
            if (n == 0) return error.BadEdges;
            break :blk n - 1;
        },
    };
    if (nb >= max_bins) return error.TooLarge;
    try checkLabels(a, spec.labels, nb + 1);
    const pr = try binPresent(a, f, ci);
    const sorted = try a.dupe(Value, pr.vals);
    std.mem.sort(Value, sorted, {}, valueLess);
    const breaks = try a.alloc(Value, nb);
    for (breaks, 0..) |*b, i| {
        if (sorted.len == 0) {
            b.* = .null;
            continue;
        }
        const last = sorted.len - 1;
        const idx: usize = switch (spec.quantiles) {
            .at => |qs| @min(last, @as(usize, @intFromFloat(@floor(qs[i] * @as(f64, @floatFromInt(last)))))),
            .count => |n| @intCast(@divFloor(@as(u128, i + 1) * last, @as(u128, n))),
        };
        b.* = sorted[idx];
    }
    const bin_of = try a.alloc(?u32, f.len);
    defer a.free(bin_of);
    @memset(bin_of, null);
    for (pr.vals, pr.rows) |v, ri| bin_of[ri] = binOf(breaks, v, spec.right_closed);
    return binOutput(a, f, spec.out, spec.labels, spec.include_intervals, ty, bin_of, breaks);
}

/// polars `Expr.bin_ranks(ranks, labels=, include_intervals=)`: bins by position in sorted
/// order. A cumulative fraction `r` cuts after `round(r * n)` of the `n` present cells (a
/// count `k`: `k` near-equal bins, the first `n mod k` one larger); the cells are taken in
/// sorted order, equal values in row order, so equal values can land in different bins. With
/// `include_intervals`, `left` and `right` are the values at the bin's first and the next
/// bin's first position (null where there is none). Column types as `binIntervals`; fractions
/// as `binQuantiles`. Null and NaN cells give null and are not counted.
pub fn binRanks(a: std.mem.Allocator, f: Frame, spec: BinRanksSpec) BinError!Frame {
    const ci = try mustIndex(f, spec.col);
    const g = (try widened(a, f, ci)) orelse return binRanksImpl(a, f, spec);
    return restoreColumn(a, try binRanksImpl(a, g, spec), f, ci);
}

fn binRanksImpl(a: std.mem.Allocator, f: Frame, spec: BinRanksSpec) BinError!Frame {
    try checkRows(f);
    const ci = try mustIndex(f, spec.col);
    const ty = f.columns[ci].type;
    if (!orderableType(ty)) return error.NotOrderable;
    const nb: usize = switch (spec.ranks) {
        .at => |rs| blk: {
            try checkFractions(rs);
            break :blk rs.len;
        },
        .count => |n| blk: {
            if (n == 0) return error.BadEdges;
            break :blk n - 1;
        },
    };
    if (nb >= max_bins) return error.TooLarge;
    try checkLabels(a, spec.labels, nb + 1);
    const pr = try binPresent(a, f, ci);
    const n = pr.vals.len;
    const order = try a.alloc(u32, n);
    for (order, 0..) |*o, i| o.* = @intCast(i);
    std.mem.sort(u32, order, pr.vals, struct {
        fn lt(vals: []Value, l: u32, r: u32) bool {
            return switch (Value.order(vals[l], vals[r])) {
                .lt => true,
                .gt => false,
                .eq => l < r,
            };
        }
    }.lt);
    // starts[k]: the sorted position where bin k + 1 starts.
    const starts = try a.alloc(usize, nb);
    for (starts, 0..) |*c, k| {
        c.* = switch (spec.ranks) {
            .at => |rs| @min(n, @as(usize, @intFromFloat(@round(rs[k] * @as(f64, @floatFromInt(n)))))),
            .count => |cnt| blk: {
                const base = n / cnt;
                const rem = n % cnt;
                break :blk (k + 1) * base + @min(k + 1, rem);
            },
        };
    }
    const breaks = try a.alloc(Value, nb);
    for (breaks, starts) |*b, c| b.* = if (c < n) pr.vals[order[c]] else .null;
    const bin_of = try a.alloc(?u32, f.len);
    defer a.free(bin_of);
    @memset(bin_of, null);
    var bin: usize = 0;
    for (order, 0..) |o, pos| {
        while (bin < nb and starts[bin] <= pos) bin += 1;
        bin_of[pr.rows[o]] = @intCast(bin);
    }
    return binOutput(a, f, spec.out, spec.labels, spec.include_intervals, ty, bin_of, breaks);
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
    if (names.len == 0) return idxs;
    var nm = try fm.NameIndex.init(a, f.columns);
    defer nm.deinit(a);
    for (names, idxs[1..]) |n, *ix| ix.* = try nm.must(n);
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

    pub fn concatByNameCells(a: std.mem.Allocator, frames: []const Frame) ConcatError!Frame {
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
    // The left names in one pass: a scan per kept right column was width x width (sweep S2-6).
    var left_names = if (spec.suffix != null) try fm.NameIndex.init(a, left.columns) else fm.NameIndex{};
    defer left_names.deinit(a);
    for (keep.items, cols[left.columns.len..]) |ci, *c| {
        c.* = right.columns[ci];
        if (spec.suffix) |sfx| {
            if (left_names.get(c.name) != null) c.name = try a.print("{s}{s}", .{ c.name, sfx });
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
