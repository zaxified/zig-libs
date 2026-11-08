// SPDX-License-Identifier: MIT
//! Frame structure: copies, row gathers, column edits, names, selectors, schema
//! summaries, equality, transpose and the concat modes (survey rows 2, 4, 10, 12, 13,
//! 20, 43, 58, 68, 82). The semantics are pandas' and polars' documented defaults; where
//! they differ the choice is stated on the verb. Original work of the zig-libs authors
//! (MIT); the engines' documentation was read, no source.

const std = @import("std");
const vm = @import("value.zig");
const fm = @import("frame.zig");
const keys = @import("keys.zig");
const core = @import("core.zig");
const sp = @import("spec.zig");
const verbs = @import("verbs.zig");
const regex = @import("regex");
const Column = vm.Column;
const ColumnType = vm.ColumnType;
const Value = vm.Value;
const ColumnData = fm.ColumnData;
const Frame = fm.Frame;
const Series = fm.Series;
const isMissing = keys.isMissing;

pub const StructureError = sp.ColumnsError || error{
    /// A row or column position past the end.
    IndexOutOfBounds,
    /// A column whose length is not the frame's (polars' `ShapeError`).
    LengthMismatch,
    /// `concat(.vertical)` over frames whose column names or types differ.
    SchemaMismatch,
    /// An argument the verb cannot use (`gatherEvery` step 0, a selector too deep).
    BadArgument,
    /// A `Selector.matches` pattern that `regex` (Rust syntax) refuses.
    BadPattern,
};

const Error = StructureError;

fn mustIndex(f: Frame, name: []const u8) Error!usize {
    return f.columnIndex(name) orelse error.NoSuchColumn;
}

fn checkRows(f: Frame) Error!void {
    return core.checkRowsU32(f.len);
}

fn checkUniqueHashed(a: std.mem.Allocator, cols: []const Column) Error!void {
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(a);
    for (cols) |c| {
        const gop = try seen.getOrPut(a, c.name);
        if (gop.found_existing) return error.DuplicateColumn;
    }
}

// ── copy / clear ────────────────────────────────────────────────────────────

/// A deep copy (pandas `copy(deep=True)`, polars `clone`): every array is new, text
/// included, so the copy outlives the input's arena. Column names are copied too.
pub fn clone(a: std.mem.Allocator, f: Frame) Error!Frame {
    try checkRows(f);
    const cols = try a.alloc(Column, f.columns.len);
    for (cols, f.columns) |*c, src| c.* = .{ .name = try a.dupe(u8, src.name), .type = src.type };
    const data = try a.alloc(ColumnData, f.columns.len);
    const cells = try a.alloc(Value, f.len);
    defer a.free(cells);
    for (data, 0..) |*d, ci| {
        const col = f.columnAt(ci);
        for (cells, 0..) |*c, ri| c.* = col.get(ri);
        // `columnFromCells` copies text; the boxed path copies it as well.
        d.* = try fm.columnFromCells(a, cells);
    }
    return .{ .columns = cols, .data = data, .len = f.len };
}

/// The schema with `n` rows of nulls (polars `clear(n)`; `n = 0` is pandas'
/// `df.iloc[0:0]`, an empty frame of the same columns).
pub fn clear(a: std.mem.Allocator, f: Frame, n: usize) Error!Frame {
    if (n >= keys.none) return error.TooLarge;
    const data = try a.alloc(ColumnData, f.columns.len);
    @memset(data, .nulls);
    return .{ .columns = f.columns, .data = data, .len = n };
}

// ── take / gather / reverse ─────────────────────────────────────────────────

/// The rows at `idx`, in that order, repeats allowed (pandas `take`, polars
/// `gather`). A negative index counts from the end (both engines); one outside
/// `-len..len` is `error.IndexOutOfBounds`.
pub fn take(a: std.mem.Allocator, f: Frame, idx: []const i64) Error!Frame {
    try checkRows(f);
    const cells = std.math.mul(usize, idx.len, @max(f.columns.len, 1)) catch return error.TooLarge;
    if (cells > sp.max_join_cells) return error.TooLarge;
    const rows = try a.alloc(u32, idx.len);
    const n: i64 = @intCast(f.len);
    for (rows, idx) |*o, i| {
        const r = if (i < 0) n + i else i;
        if (r < 0 or r >= n) return error.IndexOutOfBounds;
        o.* = @intCast(r);
    }
    return verbs.takeRows(a, f, rows);
}

/// Every `step`-th row from `offset` (polars `gather_every`, pandas `iloc[offset::step]`).
/// `step = 0` is `error.BadArgument`.
pub fn gatherEvery(a: std.mem.Allocator, f: Frame, step: usize, offset: usize) Error!Frame {
    try checkRows(f);
    if (step == 0) return error.BadArgument;
    const start = @min(offset, f.len);
    // Not `(rest + step - 1) / step`: that overflows for a step near maxInt (review 2026-11-07, HIGH 2).
    const rest = f.len - start;
    const count = if (rest == 0) 0 else (rest - 1) / step + 1;
    const rows = try a.alloc(u32, count);
    for (rows, 0..) |*o, k| o.* = @intCast(start + k * step);
    return verbs.takeRows(a, f, rows);
}

/// The rows in reverse order (polars `reverse`, pandas `iloc[::-1]`).
pub fn reverse(a: std.mem.Allocator, f: Frame) Error!Frame {
    try checkRows(f);
    const rows = try a.alloc(u32, f.len);
    for (rows, 0..) |*o, k| o.* = @intCast(f.len - 1 - k);
    return verbs.takeRows(a, f, rows);
}

// ── column edits ────────────────────────────────────────────────────────────

fn checkLength(f: Frame, s: Series) Error!void {
    // A frame with no columns takes its height from the first column it gets.
    if (f.columns.len == 0) return;
    if (s.len != f.len) return error.LengthMismatch;
}

/// `s` as column number `at` (pandas `insert(loc, column, value)`, polars
/// `insert_column`); `at == width` appends. A name the frame has is
/// `error.DuplicateColumn`, a series of another length `error.LengthMismatch`.
pub fn insertColumn(a: std.mem.Allocator, f: Frame, at: usize, s: Series) Error!Frame {
    if (at > f.columns.len) return error.IndexOutOfBounds;
    try checkLength(f, s);
    if (f.columnIndex(s.name) != null) return error.DuplicateColumn;
    const w = f.columns.len;
    const cols = try a.alloc(Column, w + 1);
    const data = try a.alloc(ColumnData, w + 1);
    var k: usize = 0;
    for (0..w + 1) |i| {
        if (i == at) {
            cols[i] = .{ .name = s.name, .type = s.type };
            data[i] = s.data;
            continue;
        }
        cols[i] = f.columns[k];
        data[i] = f.columnAt(k);
        k += 1;
    }
    return .{ .columns = cols, .data = data, .len = if (w == 0) s.len else f.len };
}

/// Append columns (polars `hstack`, pandas `concat(axis=1)` of series): each must have
/// the frame's length and a new name.
pub fn hstack(a: std.mem.Allocator, f: Frame, series: []const Series) Error!Frame {
    if (series.len == 0) return f;
    // One validation pass and one allocation: inserting one series at a time
    // copied the column arrays per series and scanned names linearly, O(n^2)
    // time and arena memory (review 2026-11-07, MED 6).
    const len = if (f.columns.len == 0) series[0].len else f.len;
    for (series) |s| if (s.len != len) return error.LengthMismatch;
    const w = std.math.add(usize, f.columns.len, series.len) catch return error.TooLarge;
    const cols = try a.alloc(Column, w);
    const data = try a.alloc(ColumnData, w);
    @memcpy(cols[0..f.columns.len], f.columns);
    for (0..f.columns.len) |i| data[i] = f.columnAt(i);
    for (series, f.columns.len..) |s, i| {
        cols[i] = .{ .name = s.name, .type = s.type };
        data[i] = s.data;
    }
    try checkUniqueHashed(a, cols);
    return .{ .columns = cols, .data = data, .len = len };
}

/// Column `at` replaced by `s`, name and type included (polars `replace_column`,
/// pandas `df[name] = values`). `s` must have the frame's length; its name must not be
/// another column's.
pub fn replaceColumn(a: std.mem.Allocator, f: Frame, at: usize, s: Series) Error!Frame {
    if (at >= f.columns.len) return error.IndexOutOfBounds;
    if (s.len != f.len) return error.LengthMismatch;
    if (f.columnIndex(s.name)) |ci| if (ci != at) return error.DuplicateColumn;
    const cols = try a.dupe(Column, f.columns);
    cols[at] = .{ .name = s.name, .type = s.type };
    const data = try a.alloc(ColumnData, f.columns.len);
    for (data, 0..) |*d, ci| d.* = f.columnAt(ci);
    data[at] = s.data;
    return .{ .columns = cols, .data = data, .len = f.len };
}

pub const Popped = struct { frame: Frame, series: Series };

/// Take a column out (pandas `pop`, polars `drop_in_place`): the frame without it, and
/// it as a `Series`. Nothing is copied.
pub fn popColumn(a: std.mem.Allocator, f: Frame, name: []const u8) Error!Popped {
    const ci = try mustIndex(f, name);
    const s = f.series(name).?;
    const cols = try a.alloc(Column, f.columns.len - 1);
    const data = try a.alloc(ColumnData, f.columns.len - 1);
    var k: usize = 0;
    for (0..f.columns.len) |i| {
        if (i == ci) continue;
        cols[k] = f.columns[i];
        data[k] = f.columnAt(i);
        k += 1;
    }
    return .{ .frame = .{ .columns = cols, .data = data, .len = f.len }, .series = s };
}

pub const AffixSpec = struct {
    prefix: []const u8 = "",
    suffix: []const u8 = "",
    /// Columns to rename; empty = every column (pandas' `add_prefix`); polars'
    /// `name.prefix` applies to the columns an expression selects.
    cols: []const []const u8 = &.{},
};

/// Column names with `prefix` before and `suffix` after (pandas `add_prefix`/
/// `add_suffix`, polars `name.prefix`/`name.suffix`). A result with two equal names is
/// `error.DuplicateColumn`.
pub fn addAffix(a: std.mem.Allocator, f: Frame, spec: AffixSpec) Error!Frame {
    const cols = try a.dupe(Column, f.columns);
    const touch = try a.alloc(bool, cols.len);
    defer a.free(touch);
    @memset(touch, spec.cols.len == 0);
    for (spec.cols) |n| touch[try mustIndex(f, n)] = true;
    for (cols, touch) |*c, t| {
        if (t) c.name = try std.mem.concat(a, u8, &.{ spec.prefix, c.name, spec.suffix });
    }
    try checkUniqueHashed(a, cols);
    const data = try a.alloc(ColumnData, cols.len);
    for (data, 0..) |*d, ci| d.* = f.columnAt(ci);
    return .{ .columns = cols, .data = data, .len = f.len };
}

// ── selectors ───────────────────────────────────────────────────────────────

/// Columns by type or name: polars' selectors (`cs.numeric()`, `cs.by_dtype`,
/// `cs.starts_with`, `~`, `|`, `&`) and pandas' `select_dtypes(include, exclude)`
/// (`.all_of = &.{ include, .{ .not = &exclude } }`).
pub const Selector = union(enum) {
    all,
    /// `.int`, `.float`, `.decimal` (pandas `"number"`, polars `cs.numeric()`).
    numeric,
    /// `.date`, `.timestamp` (polars `cs.temporal()`).
    temporal,
    /// `.text` (polars `cs.string()`).
    text,
    /// `.bool` (polars `cs.boolean()`).
    boolean,
    by_type: []const ColumnType,
    by_name: []const []const u8,
    by_index: []const usize,
    starts_with: []const u8,
    ends_with: []const u8,
    contains: []const u8,
    /// Names the pattern matches somewhere in (polars `cs.matches`, pandas
    /// `filter(regex=)`): the `regex` module's Rust grammar, polars' own; anchor with
    /// `^…$` for a whole name.
    matches: []const u8,
    first,
    last,
    not: *const Selector,
    any_of: []const Selector,
    all_of: []const Selector,
};

/// Deepest `Selector` nesting `selectColumns` follows: it recurses on caller data.
pub const max_selector_depth: usize = 64;

/// Most nodes `selectColumns` visits for one column (and for the name check), a node
/// shared by several parents counted each time it is reached: a `Selector` is a graph of
/// pointers and slices, and a node shared 64 deep is 2^64 visits. Past it `BadArgument`.
pub const max_selector_visits: usize = 4096;

/// The compiled `matches` patterns of one `selectColumns` call, by the pattern slice's
/// address and length (the same node reached twice compiles once).
const Patterns = std.AutoHashMapUnmanaged([2]usize, *regex.Regex);

fn patternKey(p: []const u8) [2]usize {
    return .{ @intFromPtr(p.ptr), p.len };
}

fn matches(f: Frame, ci: usize, s: Selector, depth: usize, budget: *usize, pats: *const Patterns) Error!bool {
    if (depth >= max_selector_depth or budget.* == 0) return error.BadArgument;
    budget.* -= 1;
    const c = f.columns[ci];
    return switch (s) {
        .all => true,
        .numeric => c.type == .int or c.type == .float or c.type == .decimal,
        .temporal => c.type == .date or c.type == .timestamp,
        .text => c.type == .text,
        .boolean => c.type == .bool,
        .by_type => |ts| std.mem.findScalar(ColumnType, ts, c.type) != null,
        .by_name => |ns| blk: {
            for (ns) |n| if (std.mem.eql(u8, n, c.name)) break :blk true;
            break :blk false;
        },
        .by_index => |is| std.mem.findScalar(usize, is, ci) != null,
        .starts_with => |p| std.mem.startsWith(u8, c.name, p),
        .ends_with => |p| std.mem.endsWith(u8, c.name, p),
        .contains => |p| std.mem.find(u8, c.name, p) != null,
        // `checkNamed` compiled every pattern of the tree before any column is matched.
        .matches => |p| (pats.get(patternKey(p)) orelse return error.BadArgument).isMatch(c.name),
        .first => ci == 0,
        .last => ci + 1 == f.columns.len,
        .not => |inner| !try matches(f, ci, inner.*, depth + 1, budget, pats),
        .any_of => |xs| blk: {
            for (xs) |x| if (try matches(f, ci, x, depth + 1, budget, pats)) break :blk true;
            break :blk false;
        },
        .all_of => |xs| blk: {
            for (xs) |x| if (!try matches(f, ci, x, depth + 1, budget, pats)) break :blk false;
            break :blk true;
        },
    };
}

/// The names `sel` picks, in the frame's order. A `by_name` entry or `by_index`
/// position that is not in the frame is `error.NoSuchColumn` / `IndexOutOfBounds`
/// (polars raises on a missing name in `cs.by_name`).
pub fn selectColumns(a: std.mem.Allocator, f: Frame, sel: Selector) Error![]const []const u8 {
    var named_budget: usize = max_selector_visits;
    var pats: Patterns = .empty;
    defer {
        var it = pats.valueIterator();
        while (it.next()) |re| {
            re.*.deinit(a);
            a.destroy(re.*);
        }
        pats.deinit(a);
    }
    try checkNamed(a, f, sel, 0, &named_budget, &pats);
    var out: std.ArrayList([]const u8) = .empty;
    errdefer out.deinit(a);
    for (0..f.columns.len) |ci| {
        var budget: usize = max_selector_visits;
        if (try matches(f, ci, sel, 0, &budget, &pats)) try out.append(a, f.columns[ci].name);
    }
    return out.toOwnedSlice(a);
}

fn checkNamed(a: std.mem.Allocator, f: Frame, s: Selector, depth: usize, budget: *usize, pats: *Patterns) Error!void {
    if (depth >= max_selector_depth or budget.* == 0) return error.BadArgument;
    budget.* -= 1;
    switch (s) {
        .by_name => |ns| for (ns) |n| {
            _ = try mustIndex(f, n);
        },
        .by_index => |is| for (is) |i| if (i >= f.columns.len) return error.IndexOutOfBounds,
        .matches => |p| {
            const gop = try pats.getOrPut(a, patternKey(p));
            if (gop.found_existing) return;
            errdefer pats.removeByPtr(gop.key_ptr);
            const re = try a.create(regex.Regex);
            errdefer a.destroy(re);
            re.* = regex.Regex.compileOptions(a, p, .{ .syntax = .rust }) catch |e| return switch (e) {
                error.OutOfMemory => error.OutOfMemory,
                else => error.BadPattern,
            };
            gop.value_ptr.* = re;
        },
        .not => |inner| try checkNamed(a, f, inner.*, depth + 1, budget, pats),
        .any_of, .all_of => |xs| for (xs) |x| try checkNamed(a, f, x, depth + 1, budget, pats),
        else => {},
    }
}

/// The columns `sel` picks, shared (polars `select(cs...)`, pandas `select_dtypes`).
pub fn selectBy(a: std.mem.Allocator, f: Frame, sel: Selector) Error!Frame {
    return verbs.select(a, f, try selectColumns(a, f, sel));
}

// ── summaries ───────────────────────────────────────────────────────────────

/// Missing cells (null or NaN, the module's one rule; polars' `null_count` counts
/// null only, pandas' `isna().sum()` counts NaN too) per column: one row, one `.int`
/// column per input column (polars `null_count`).
pub fn nullCount(a: std.mem.Allocator, f: Frame) Error!Frame {
    const data = try a.alloc(ColumnData, f.columns.len);
    const cols = try a.alloc(Column, f.columns.len);
    for (cols, data, 0..) |*c, *d, ci| {
        c.* = .{ .name = f.columns[ci].name, .type = .int };
        const n = (Series{ .name = c.name, .type = c.type, .data = f.columnAt(ci), .len = f.len }).nullCount();
        d.* = try fm.columnFromCells(a, &.{.{ .int = @intCast(n) }});
    }
    return .{ .columns = cols, .data = data, .len = 1 };
}

/// Some cell of some column is missing (polars `has_nulls`, pandas `isna().any().any()`).
pub fn hasNulls(f: Frame) bool {
    for (0..f.columns.len) |ci| {
        const s: Series = .{ .name = "", .type = f.columns[ci].type, .data = f.columnAt(ci), .len = f.len };
        if (s.nullCount() > 0) return true;
    }
    return false;
}

fn bitmapBytes(v: ?[]const u64, rows: usize) usize {
    const w = v orelse return 0;
    return @min(w.len, (rows + 63) / 64) * 8;
}

/// Bytes the cells of column `ci` occupy within the frame's `len` rows: the values,
/// the bitmap, text offsets and bytes, a boxed cell's `Value` plus its text. What
/// polars' `estimated_size` and pandas' `memory_usage(deep=True)` count; capacity
/// past `len` and shared storage are not counted twice-aware (each column alone).
pub fn columnBytes(f: Frame, ci: usize) usize {
    const n = f.len;
    return switch (f.columnAt(ci)) {
        .nulls => 0,
        inline .int, .float, .bool, .decimal => |c| @min(c.values.len, n) * @sizeOf(std.meta.Elem(@TypeOf(c.values))) + bitmapBytes(c.valid, n),
        .text => |c| blk: {
            const rows = @min(n, c.offsets.len -| 1);
            const span = if (rows == 0) 0 else c.offsets[rows] -| c.offsets[0];
            break :blk (rows + @intFromBool(rows > 0)) * @sizeOf(usize) + @min(span, c.bytes.len) + bitmapBytes(c.valid, n);
        },
        // The codes and the dictionary (a dictionary shared by columns counts in each).
        .categorical => |c| @min(c.codes.values.len, n) * @sizeOf(u32) + bitmapBytes(c.codes.valid, n) +
            c.dict.offsets.len * @sizeOf(usize) + c.dict.bytes.len,
        .boxed => |c| blk: {
            var s: usize = @min(c.len, n) * @sizeOf(Value);
            for (c[0..@min(c.len, n)]) |v| s += if (v == .text) v.text.len else 0;
            break :blk s;
        },
    };
}

/// The bytes of every column (polars `estimated_size`).
pub fn estimatedSize(f: Frame) usize {
    var s: usize = 0;
    for (0..f.columns.len) |ci| s +|= columnBytes(f, ci);
    return s;
}

/// pandas' `info()` and `memory_usage(deep=True)` as a frame: one row per column with
/// `column` (text), `type` (text, the `ColumnType` tag), `non_null` and `null` (int,
/// missing = null or NaN), `bytes` (int, `columnBytes`).
pub fn info(a: std.mem.Allocator, f: Frame) Error!Frame {
    const w = f.columns.len;
    const names = try a.alloc(Value, w);
    const types = try a.alloc(Value, w);
    const non_null = try a.alloc(Value, w);
    const nulls = try a.alloc(Value, w);
    const bytes = try a.alloc(Value, w);
    for (0..w) |ci| {
        const s: Series = .{ .name = f.columns[ci].name, .type = f.columns[ci].type, .data = f.columnAt(ci), .len = f.len };
        const nc = s.nullCount();
        names[ci] = .{ .text = s.name };
        types[ci] = .{ .text = @tagName(s.type) };
        non_null[ci] = .{ .int = @intCast(f.len - nc) };
        nulls[ci] = .{ .int = @intCast(nc) };
        bytes[ci] = .{ .int = @intCast(@min(columnBytes(f, ci), std.math.maxInt(i64))) };
    }
    const cols = try a.dupe(Column, &.{
        .{ .name = "column", .type = .text },
        .{ .name = "type", .type = .text },
        .{ .name = "non_null", .type = .int },
        .{ .name = "null", .type = .int },
        .{ .name = "bytes", .type = .int },
    });
    const data = try a.alloc(ColumnData, 5);
    for (data, [_][]const Value{ names, types, non_null, nulls, bytes }) |*d, cells| d.* = try fm.columnFromCells(a, cells);
    return .{ .columns = cols, .data = data, .len = w };
}

// ── equality ────────────────────────────────────────────────────────────────

fn sameCell(x: Value, y: Value) bool {
    const xn = x == .float and std.math.isNan(x.float);
    const yn = y == .float and std.math.isNan(y.float);
    if (xn or yn) return xn and yn;
    if (x == .null or y == .null) return x == .null and y == .null;
    const xnum = x == .int or x == .float or x == .decimal;
    const ynum = y == .int or y == .float or y == .decimal;
    if (xnum != ynum) return false;
    if (!xnum and std.meta.activeTag(x) != std.meta.activeTag(y)) return false;
    return x.order(y) == .eq;
}

/// The same column names, types, row count and cells (pandas `equals`, polars
/// `equals` with `null_equal=True`): null equals null and NaN equals NaN, but null is
/// not NaN; numbers compare by value (`1` and `1.0` in two `.float` columns are equal,
/// `-0.0` equals `0.0`).
pub fn equals(f: Frame, g: Frame) bool {
    if (f.len != g.len or f.columns.len != g.columns.len) return false;
    for (f.columns, g.columns) |x, y| {
        if (x.type != y.type or !std.mem.eql(u8, x.name, y.name)) return false;
    }
    for (0..f.columns.len) |ci| {
        const xc = f.columnAt(ci);
        const yc = g.columnAt(ci);
        for (0..f.len) |ri| if (!sameCell(xc.get(ri), yc.get(ri))) return false;
    }
    return true;
}

// ── transpose ───────────────────────────────────────────────────────────────

pub const TransposeSpec = struct {
    /// A first output column holding the input's column names (polars
    /// `include_header=True`, `header_name`); null leaves it out (polars' default).
    header_name: ?[]const u8 = null,
    /// The output's column names, one per input row. Empty: `column_0`, `column_1`, …
    /// (polars' default; pandas uses the index labels, which this module has not).
    names: []const []const u8 = &.{},
    /// A column whose cells (as text) name the output columns and which is not itself
    /// transposed (pandas' `set_index(col).T`). Overrides `names`.
    names_from: ?[]const u8 = null,
};

/// The widest frame `transpose` builds (output columns).
pub const max_transpose_width: usize = 1 << 20;

/// Rows become columns (pandas `T`, polars `transpose`). The output type: the input
/// columns' common type; numbers of different kinds as `.float` (polars' supertype); a
/// mix with text or bool keeps each cell as it is (a boxed column) declared `.text`,
/// pandas' `object`. At most `max_aggregate_cells` cells.
pub fn transpose(a: std.mem.Allocator, f: Frame, spec: TransposeSpec) Error!Frame {
    try checkRows(f);
    const skip: ?usize = if (spec.names_from) |n| try mustIndex(f, n) else null;
    var src: std.ArrayList(usize) = .empty;
    for (0..f.columns.len) |ci| if (ci != skip) try src.append(a, ci);
    const m = src.items.len;
    const n_cells = std.math.mul(usize, m, f.len) catch return error.TooLarge;
    if (n_cells > sp.max_aggregate_cells) return error.TooLarge;
    // The output is `f.len` columns wide whatever `m` is: with no value
    // columns the cell cap above does not bound it (review 2026-11-07, LOW 7).
    if (f.len > max_transpose_width) return error.TooLarge;
    if (skip == null and spec.names.len != 0 and spec.names.len != f.len) return error.LengthMismatch;

    var ty: ?ColumnType = null;
    var mixed = false;
    var all_num = true;
    for (src.items) |ci| {
        const t = f.columns[ci].type;
        all_num = all_num and (t == .int or t == .float or t == .decimal);
        if (ty) |u| mixed = mixed or u != t else ty = t;
    }
    const out_ty: ColumnType = if (!mixed) (ty orelse .float) else if (all_num) .float else .text;
    const to_float = mixed and all_num;

    const has_header = spec.header_name != null;
    const width = f.len + @intFromBool(has_header);
    const cols = try a.alloc(Column, width);
    const data = try a.alloc(ColumnData, width);
    const cells = try a.alloc(Value, m);
    defer a.free(cells);
    var k: usize = 0;
    if (spec.header_name) |h| {
        for (cells, src.items) |*c, ci| c.* = .{ .text = f.columns[ci].name };
        cols[0] = .{ .name = h, .type = .text };
        data[0] = try fm.columnFromCells(a, cells);
        k = 1;
    }
    for (0..f.len) |ri| {
        const name: []const u8 = if (skip) |s| blk: {
            const v = f.columnAt(s).get(ri);
            if (v == .text) break :blk v.text;
            // A NaN casts to null: both read as "null", as a missing name does.
            const t = @import("expr.zig").castValue(a, v, .text) catch return error.OutOfMemory;
            break :blk if (t == .text) t.text else "null";
        } else if (spec.names.len != 0) spec.names[ri] else try a.print("column_{d}", .{ri});
        for (cells, src.items) |*c, ci| {
            const v = f.columnAt(ci).get(ri);
            // A declared number column may hold a text or bool cell (the builder does not
            // check): it stays as it is, in the boxed column.
            c.* = if (to_float and v != .null) (if (v.asFloat()) |x| .{ .float = x } else v) else v;
        }
        cols[k + ri] = .{ .name = name, .type = out_ty };
        data[k + ri] = try fm.columnFromCells(a, cells);
    }
    try checkUniqueHashed(a, cols);
    return .{ .columns = cols, .data = data, .len = m };
}

// ── concat ──────────────────────────────────────────────────────────────────

pub const ConcatHow = enum {
    /// Stack rows; every frame must have the same column names in the same order and
    /// the same types (polars `how="vertical"`), else `error.SchemaMismatch`.
    vertical,
    /// Stack rows; the same names in the same order, types may differ: the first
    /// frame's type is declared (polars `vertical_relaxed` casts to a supertype).
    vertical_relaxed,
    /// Stack rows matching columns by name, a missing column null (`concatByName`;
    /// polars `diagonal`, pandas `concat` with `join="outer"`).
    diagonal,
    /// Side by side; every name must be new (else `error.DuplicateColumn`), and a
    /// shorter frame is padded with nulls (polars `horizontal`, pandas `axis=1`).
    horizontal,
};

/// Combine frames (pandas `concat`, polars `concat(how=...)`).
pub fn concat(a: std.mem.Allocator, frames: []const Frame, how: ConcatHow) Error!Frame {
    switch (how) {
        .diagonal => return @import("more.zig").concatByName(a, frames),
        .vertical, .vertical_relaxed => {
            if (frames.len == 0) return .{ .columns = &.{}, .data = &.{}, .len = 0 };
            const first = frames[0];
            for (frames[1..]) |t| {
                if (t.columns.len != first.columns.len) return error.SchemaMismatch;
                for (t.columns, first.columns) |x, y| {
                    if (!std.mem.eql(u8, x.name, y.name)) return error.SchemaMismatch;
                    if (how == .vertical and x.type != y.type) return error.SchemaMismatch;
                }
            }
            try checkUniqueHashed(a, first.columns);
            return @import("more.zig").concatByName(a, frames);
        },
        .horizontal => {
            var width: usize = 0;
            var rows: usize = 0;
            var in_cells: usize = 0;
            for (frames) |t| {
                try checkRows(t);
                width = std.math.add(usize, width, t.columns.len) catch return error.TooLarge;
                rows = @max(rows, t.len);
                in_cells +|= t.columns.len *| t.len;
            }
            // Padding the shorter frames multiplies width by height.
            try verbs.growthWithin(std.math.mul(usize, width, rows) catch return error.TooLarge, in_cells);
            const cols = try a.alloc(Column, width);
            const data = try a.alloc(ColumnData, width);
            var k: usize = 0;
            for (frames) |t| {
                for (0..t.columns.len) |ci| {
                    cols[k] = t.columns[ci];
                    // A shorter frame's columns read as null past their end, so they are
                    // shared; padding a column whose arrays run longer than its frame
                    // (capacity behind a slice) needs a cut first.
                    data[k] = if (t.len == rows) t.columnAt(ci) else try padded(a, t, ci, rows);
                    k += 1;
                }
            }
            try checkUniqueHashed(a, cols);
            return .{ .columns = cols, .data = data, .len = rows };
        },
    }
}

fn padded(a: std.mem.Allocator, t: Frame, ci: usize, rows: usize) Error!ColumnData {
    const idx = try a.alloc(u32, rows);
    defer a.free(idx);
    for (idx, 0..) |*o, i| o.* = if (i < t.len) @intCast(i) else keys.none;
    return verbs.take(a, t.columnAt(ci), idx, true);
}
