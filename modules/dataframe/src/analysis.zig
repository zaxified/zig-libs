// SPDX-License-Identifier: MIT
//! Row-set and column analysis verbs (survey rows 31, 45, 50, 61, 62, 85): duplicate
//! masks, row-wise (horizontal) reductions, fill strategies, `replace_strict`,
//! sortedness and arg functions, `factorize`, multi-column top-k and `qcut`. The
//! semantics are pandas' and polars' documented defaults, the choice stated where they
//! differ. Original work of the zig-libs authors (MIT); documentation read, no source.

const std = @import("std");
const vm = @import("value.zig");
const fm = @import("frame.zig");
const keys = @import("keys.zig");
const sp = @import("spec.zig");
const core = @import("core.zig");
const verbs = @import("verbs.zig");
const more = @import("more.zig");
const Column = vm.Column;
const ColumnType = vm.ColumnType;
const Value = vm.Value;
const ColumnData = fm.ColumnData;
const Frame = fm.Frame;
const Series = fm.Series;
const isMissing = keys.isMissing;

pub const AnalysisError = sp.ColumnsError || error{
    /// `qcut` edges that repeat with `duplicates = .raise`, or no values to cut.
    BadEdges,
    /// `replaceStrict` met a cell no pair maps and there is no default.
    Unmatched,
    /// An argument the verb cannot use (`qcut` with fewer than one bin).
    BadArgument,
};

const Error = AnalysisError;

fn mustIndex(f: Frame, name: []const u8) Error!usize {
    return f.columnIndex(name) orelse error.NoSuchColumn;
}

fn checkRows(f: Frame) Error!void {
    if (f.len >= keys.none) return error.TooLarge;
}

fn appendColumn(a: std.mem.Allocator, f: Frame, col: Column, data: ColumnData) Error!Frame {
    if (f.columnIndex(col.name) != null) return error.DuplicateColumn;
    const w = f.columns.len;
    const cols = try a.alloc(Column, w + 1);
    @memcpy(cols[0..w], f.columns);
    cols[w] = col;
    const out = try a.alloc(ColumnData, w + 1);
    for (out[0..w], 0..) |*d, i| d.* = f.columnAt(i);
    out[w] = data;
    return .{ .columns = cols, .data = out, .len = f.len };
}

fn subsetIdxs(a: std.mem.Allocator, f: Frame, subset: []const []const u8) Error![]const usize {
    const n = if (subset.len == 0) f.columns.len else subset.len;
    const idxs = try a.alloc(usize, n);
    for (idxs, 0..) |*ix, i| ix.* = if (subset.len == 0) i else try mustIndex(f, subset[i]);
    return idxs;
}

fn boolColumn(a: std.mem.Allocator, bits: []const bool) Error!ColumnData {
    return .{ .bool = .{ .values = try a.dupe(bool, bits) } };
}

// ── duplicate masks ─────────────────────────────────────────────────────────

pub const DupMask = enum {
    /// Every occurrence but the first (pandas `duplicated()`, `keep="first"`).
    duplicated_first,
    /// Every occurrence but the last (pandas `duplicated(keep="last")`).
    duplicated_last,
    /// Every row whose key occurs more than once (pandas `keep=False`, polars
    /// `is_duplicated`).
    is_duplicated,
    /// A key that occurs once (polars `is_unique`).
    is_unique,
    /// The first occurrence of its key (polars `is_first_distinct`).
    is_first_distinct,
    /// The last occurrence of its key (polars `is_last_distinct`).
    is_last_distinct,
};

pub const DupMaskSpec = struct {
    /// Key columns; empty = every column (pandas' `subset=None`).
    keys: []const []const u8 = &.{},
    mask: DupMask = .duplicated_first,
    /// Name of the appended `.bool` column.
    out: []const u8 = "duplicated",
};

/// A `.bool` column per row saying how its key repeats. Missing cells are one key
/// (null and NaN alike), as pandas and polars group them.
pub fn duplicateMask(a: std.mem.Allocator, f: Frame, spec: DupMaskSpec) Error!Frame {
    try checkRows(f);
    const idxs = try subsetIdxs(a, f, spec.keys);
    const fac = try verbs.factorKeys(a, f, idxs);
    const n = fac.groups();
    const counts = try a.alloc(u32, n);
    defer a.free(counts);
    @memset(counts, 0);
    const last = try a.alloc(u32, n);
    defer a.free(last);
    for (fac.ids, 0..) |g, ri| {
        counts[g] += 1;
        last[g] = @intCast(ri);
    }
    const bits = try a.alloc(bool, f.len);
    defer a.free(bits);
    for (bits, fac.ids, 0..) |*b, g, ri| {
        const first = fac.firsts[g] == ri;
        const is_last = last[g] == ri;
        b.* = switch (spec.mask) {
            .duplicated_first => !first,
            .duplicated_last => !is_last,
            .is_duplicated => counts[g] > 1,
            .is_unique => counts[g] == 1,
            .is_first_distinct => first,
            .is_last_distinct => is_last,
        };
    }
    return appendColumn(a, f, .{ .name = spec.out, .type = .bool }, try boolColumn(a, bits));
}

// ── row-wise reductions ─────────────────────────────────────────────────────

pub const HorizontalFn = enum { sum, min, max, mean, all, any, count };

pub const HorizontalSpec = struct {
    /// Columns to reduce across; empty = every column.
    cols: []const []const u8 = &.{},
    func: HorizontalFn,
    out: []const u8,
    /// Skip missing cells (pandas `skipna=True`, polars `ignore_nulls=True`). false:
    /// any missing cell makes the row's `sum`/`min`/`max`/`mean` null, and `all`/`any`
    /// are three-valued (Kleene, polars' `all_horizontal`).
    skip_na: bool = true,
    /// `sum` of fewer than this many present values is null (pandas `min_count`).
    min_count: usize = 0,
};

/// One value per row across `cols` (pandas `sum(axis=1)` …, polars
/// `sum_horizontal`, `min_horizontal`, `max_horizontal`, `mean_horizontal`,
/// `all_horizontal`, `any_horizontal`). A non-numeric cell counts as missing for the
/// numeric functions; `all`/`any` read numbers as non-zero, text as present. `sum` of
/// int columns stays int (overflow null), any other number makes it float; `min`/`max`
/// keep the winning cell's kind; `mean` is float; `count` counts present cells.
pub fn horizontal(a: std.mem.Allocator, f: Frame, spec: HorizontalSpec) Error!Frame {
    const idxs = try subsetIdxs(a, f, spec.cols);
    var all_int = true;
    for (idxs) |ci| all_int = all_int and f.columns[ci].type == .int;
    const cells = try a.alloc(Value, f.len);
    defer a.free(cells);
    for (cells, 0..) |*o, ri| {
        var isum: i64 = 0;
        var iover = false;
        var fsum: f64 = 0;
        var any_float = false;
        var present: usize = 0;
        var missing: usize = 0;
        var best: Value = .null;
        var t_seen = false;
        var f_seen = false;
        for (idxs) |ci| {
            const v = f.columnAt(ci).get(ri);
            if (spec.func == .all or spec.func == .any or spec.func == .count) {
                if (isMissing(v)) {
                    missing += 1;
                    continue;
                }
                present += 1;
                const tv: bool = core.truthy(v) orelse (v == .text);
                if (tv) t_seen = true else f_seen = true;
                continue;
            }
            if (isMissing(v) or v.asFloat() == null) {
                missing += 1;
                continue;
            }
            present += 1;
            switch (spec.func) {
                .sum, .mean => {
                    if (v == .int and !iover) {
                        if (std.math.add(i64, isum, v.int)) |s| isum = s else |_| iover = true;
                    }
                    if (v != .int) any_float = true;
                    fsum += v.asFloat().?;
                },
                .min => best = if (best == .null or v.order(best) == .lt) v else best,
                .max => best = if (best == .null or v.order(best) == .gt) v else best,
                else => unreachable, // the branch above took the boolean ones
            }
        }
        o.* = switch (spec.func) {
            .count => .{ .int = @intCast(present) },
            .all => if (f_seen) .{ .bool = false } else if (missing > 0 and !spec.skip_na) .null else .{ .bool = true },
            .any => if (t_seen) .{ .bool = true } else if (missing > 0 and !spec.skip_na) .null else .{ .bool = false },
            else => blk: {
                if (missing > 0 and !spec.skip_na) break :blk .null;
                switch (spec.func) {
                    .sum => {
                        if (present < spec.min_count) break :blk .null;
                        if (all_int and !any_float) break :blk if (iover) .null else .{ .int = isum };
                        break :blk .{ .float = fsum };
                    },
                    .mean => break :blk if (present == 0) .null else .{ .float = fsum / @as(f64, @floatFromInt(present)) },
                    else => {
                        if (best == .null) break :blk .null;
                        // Mixed numeric columns: polars casts to the supertype.
                        break :blk if (!all_int and best == .int) .{ .float = best.asFloat().? } else best;
                    },
                }
            },
        };
    }
    const ty: ColumnType = switch (spec.func) {
        .sum => if (all_int) .int else .float,
        .min, .max => if (all_int) .int else .float,
        .mean => .float,
        .all, .any => .bool,
        .count => .int,
    };
    var out_ty = ty;
    // A float cell among int-declared columns (storage follows the cells) promotes.
    if (out_ty == .int and spec.func != .count) {
        for (cells) |c| {
            if (c == .float) out_ty = .float;
        }
    }
    if (out_ty == .float) {
        // An all-int row of a mixed frame still answers float, as a decimal does.
        for (cells) |*c| {
            if (c.* == .int or c.* == .decimal) c.* = .{ .float = c.asFloat().? };
        }
    }
    return appendColumn(a, f, .{ .name = spec.out, .type = out_ty }, try fm.columnFromCells(a, cells));
}

// ── fill strategies / replace_strict ────────────────────────────────────────

pub const FillStrategy = enum {
    /// The previous present cell (pandas `ffill`, polars `strategy="forward"`).
    forward,
    /// The next present cell (pandas `bfill`, polars `"backward"`).
    backward,
    /// The column's mean (polars `"mean"`); an int column becomes float.
    mean,
    /// The column's smallest / largest present cell (polars `"min"`, `"max"`).
    min,
    max,
    /// 0 / 1 of the column's kind (polars `"zero"`, `"one"`).
    zero,
    one,
};

pub const FillNullSpec = struct {
    /// Columns to fill; empty = every column.
    subset: []const []const u8 = &.{},
    strategy: FillStrategy,
    /// `forward`/`backward`: fill at most this many consecutive missing cells
    /// (pandas and polars `limit`); null = no limit.
    limit: ?usize = null,
};

/// Fill the missing cells (null, NaN) of `subset` by a strategy (polars
/// `fill_null(strategy=...)`, pandas `ffill`/`bfill`/`fillna(df.mean())`). A column
/// with nothing to fill, or nothing to fill it with, is shared. `mean`, `min`, `max`
/// read only the numbers of a column (`min`/`max` any kind for text); `zero`/`one` of a
/// text or bool column fill nothing.
pub fn fillNull(a: std.mem.Allocator, f: Frame, spec: FillNullSpec) Error!Frame {
    const idxs = try subsetIdxs(a, f, spec.subset);
    const cols = try a.dupe(Column, f.columns);
    const data = try a.alloc(ColumnData, f.columns.len);
    for (data, 0..) |*d, ci| d.* = f.columnAt(ci);
    const cells = try a.alloc(Value, f.len);
    defer a.free(cells);
    for (idxs) |ci| {
        const col = f.columnAt(ci);
        var any = false;
        for (cells, 0..) |*c, ri| {
            c.* = col.get(ri);
            any = any or isMissing(c.*);
        }
        if (!any) continue;
        switch (spec.strategy) {
            .forward, .backward => {
                const limit = spec.limit orelse std.math.maxInt(usize);
                var last: Value = .null;
                var run: usize = 0;
                var k: usize = 0;
                while (k < cells.len) : (k += 1) {
                    const i = if (spec.strategy == .forward) k else cells.len - 1 - k;
                    if (!isMissing(cells[i])) {
                        last = cells[i];
                        run = 0;
                    } else if (last != .null and run < limit) {
                        cells[i] = last;
                        run += 1;
                    }
                }
            },
            .mean, .min, .max, .zero, .one => {
                const fill: Value = switch (spec.strategy) {
                    .mean => blk: {
                        var s: f64 = 0;
                        var n: usize = 0;
                        for (cells) |c| {
                            if (isMissing(c)) continue;
                            const x = c.asFloat() orelse continue;
                            s += x;
                            n += 1;
                        }
                        if (n == 0) break :blk .null;
                        const m = s / @as(f64, @floatFromInt(n));
                        // An int column stays int, the mean cut toward zero (polars: the
                        // mean of 1, 4, 6, 10 fills 5, not 5.25; pandas refuses to).
                        break :blk if (f.columns[ci].type == .int) .{ .int = std.math.lossyCast(i64, @trunc(m)) } else .{ .float = m };
                    },
                    .min, .max => blk: {
                        var best: Value = .null;
                        for (cells) |c| {
                            if (isMissing(c)) continue;
                            if (best == .null) {
                                best = c;
                                continue;
                            }
                            const o = c.order(best);
                            if ((spec.strategy == .min and o == .lt) or (spec.strategy == .max and o == .gt)) best = c;
                        }
                        break :blk best;
                    },
                    else => blk: {
                        const one = spec.strategy == .one;
                        break :blk switch (f.columns[ci].type) {
                            .int, .timestamp => .{ .int = @intFromBool(one) },
                            .float => .{ .float = if (one) 1 else 0 },
                            .decimal => .{ .decimal = if (one) vm.decimal_scale else 0 },
                            // polars: `zero` fills "" and False, `one` True; "one" of text is refused
                            .bool => .{ .bool = one },
                            .text => if (one) .null else .{ .text = "" },
                            else => .null,
                        };
                    },
                };
                if (fill == .null) continue;
                for (cells) |*c| {
                    if (isMissing(c.*)) c.* = fill;
                }
                if (spec.strategy == .mean and f.columns[ci].type != .float and f.columns[ci].type != .int) {
                    cols[ci].type = .float;
                    for (cells) |*c| {
                        if (c.* == .null) continue;
                        if (c.asFloat()) |x| c.* = .{ .float = x };
                    }
                }
            },
        }
        data[ci] = try fm.columnFromCells(a, cells);
    }
    return .{ .columns = cols, .data = data, .len = f.len };
}

pub const ReplaceStrictSpec = struct {
    col: []const u8,
    pairs: []const more.ReplacePair,
    /// What a cell no pair maps becomes; null: `error.Unmatched` (polars'
    /// `replace_strict` without `default`). A missing cell stays missing unless a
    /// pair maps null.
    default: ?Value = null,
    /// The output column's declared type; null keeps the input's.
    type: ?ColumnType = null,
};

/// Every cell mapped through `pairs` (polars `replace_strict`): unlike `replace`, a
/// cell no pair names is not kept but becomes `default`, or is an error.
pub fn replaceStrict(a: std.mem.Allocator, f: Frame, spec: ReplaceStrictSpec) Error!Frame {
    const ci = try mustIndex(f, spec.col);
    const col = f.columnAt(ci);
    const cells = try a.alloc(Value, f.len);
    defer a.free(cells);
    for (cells, 0..) |*o, ri| {
        const v = col.get(ri);
        var hit: ?Value = null;
        for (spec.pairs) |p| {
            const both_missing = isMissing(v) and isMissing(p.from);
            if (both_missing or (!isMissing(v) and v.eql(p.from))) {
                hit = p.to;
                break;
            }
        }
        if (hit) |h| {
            o.* = h;
        } else if (isMissing(v)) {
            o.* = .null;
        } else {
            o.* = spec.default orelse return error.Unmatched;
        }
    }
    const cols = try a.dupe(Column, f.columns);
    if (spec.type) |t| cols[ci].type = t;
    const data = try a.alloc(ColumnData, f.columns.len);
    for (data, 0..) |*d, i| d.* = f.columnAt(i);
    data[ci] = try fm.columnFromCells(a, cells);
    return .{ .columns = cols, .data = data, .len = f.len };
}

// ── sortedness / arg functions / factorize ──────────────────────────────────

fn sortIdxs(a: std.mem.Allocator, f: Frame, spec: sp.SortSpec) Error!struct { idxs: []usize, dirs: []sp.SortDir } {
    const n = 1 + spec.then_by.len;
    const idxs = try a.alloc(usize, n);
    const dirs = try a.alloc(sp.SortDir, n);
    idxs[0] = try mustIndex(f, spec.key);
    dirs[0] = spec.dir;
    for (spec.then_by, 0..) |tb, i| {
        idxs[1 + i] = try mustIndex(f, tb.key);
        dirs[1 + i] = tb.dir;
    }
    return .{ .idxs = idxs, .dirs = dirs };
}

/// The row positions `sort` would put in order (pandas `argsort`, polars `arg_sort`):
/// the same keys, directions, tie order and missing placement.
pub fn argSort(a: std.mem.Allocator, f: Frame, spec: sp.SortSpec) Error![]const u32 {
    try checkRows(f);
    const s = try sortIdxs(a, f, spec);
    return verbs.sortedRows(a, f, s.idxs, s.dirs, spec.missing);
}

/// The frame is already in `spec`'s order (pandas `is_monotonic_increasing` /
/// `_decreasing` for one key, polars `is_sorted`): equal keys count as sorted, so it is
/// the order `sort` would keep. Missing cells must sit where `spec.missing` puts them.
pub fn isSorted(a: std.mem.Allocator, f: Frame, spec: sp.SortSpec) Error!bool {
    const order = try argSort(a, f, spec);
    defer a.free(order);
    for (order, 0..) |o, i| if (o != i) return false;
    return true;
}

pub const SearchSide = enum {
    /// The first position where `v` could go (numpy's and pandas' default).
    left,
    /// The position after the last cell equal to `v`.
    right,
};

/// Where `v` would go in `s`, sorted ascending as `Value.order` sorts (null first,
/// NaN last) (pandas `searchsorted`, polars `search_sorted`). A column that is not sorted
/// gives some position, as in both engines.
pub fn searchSorted(s: Series, v: Value, side: SearchSide) usize {
    var lo: usize = 0;
    var hi: usize = s.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const o = s.get(mid).order(v);
        const go_right = if (side == .left) o == .lt else o != .gt;
        if (go_right) lo = mid + 1 else hi = mid;
    }
    return lo;
}

/// The first row whose cell equals `v` by key equality, null when none (polars
/// `index_of`; a missing `v` finds the first missing cell).
pub fn indexOf(s: Series, v: Value) ?usize {
    const vm_ = isMissing(v);
    for (0..s.len) |ri| {
        const c = s.get(ri);
        if (vm_) {
            if (isMissing(c)) return ri;
        } else if (!isMissing(c) and c.eql(v)) return ri;
    }
    return null;
}

pub const FactorizeSpec = struct {
    /// Key columns (one: pandas `factorize`; several: their combination).
    cols: []const []const u8,
    /// Name of the appended `.int` code column.
    out: []const u8 = "code",
    /// Number the uniques in sorted order (pandas `sort=True`); false: first-seen.
    sort: bool = false,
    /// A missing key's code: -1 (pandas' `use_na_sentinel=True`), or null.
    missing: enum { minus_one, null } = .minus_one,
};

pub const Factorized = struct {
    /// The input with the code column appended.
    frame: Frame,
    /// One row per code, the key columns only, code `i` at row `i` (pandas' `uniques`).
    uniques: Frame,
};

/// Dense integer codes for a key (pandas `factorize`, polars `rank("dense") - 1` or a
/// categorical's physical codes). A row with any missing key cell has no code.
pub fn factorize(a: std.mem.Allocator, f: Frame, spec: FactorizeSpec) Error!Factorized {
    try checkRows(f);
    if (spec.cols.len == 0) return error.NoSuchColumn;
    const idxs = try subsetIdxs(a, f, spec.cols);
    const fac = try verbs.factorKeys(a, f, idxs);
    const n = fac.groups();
    // A group whose first row has a missing key cell is the missing group(s).
    const code = try a.alloc(i64, n);
    defer a.free(code);
    var firsts: std.ArrayList(u32) = .empty;
    for (fac.firsts, 0..) |r, g| {
        var miss = false;
        for (idxs) |ci| miss = miss or isMissing(f.columnAt(ci).get(r));
        if (miss) {
            code[g] = -1;
        } else {
            code[g] = @intCast(firsts.items.len);
            try firsts.append(a, r);
        }
    }
    var uniques = try verbs.takeRows(a, try verbs.select(a, f, spec.cols), firsts.items);
    if (spec.sort and firsts.items.len > 1) {
        const dirs = try a.alloc(sp.SortDir, idxs.len);
        @memset(dirs, .asc);
        const upos = try a.alloc(usize, idxs.len);
        for (upos, 0..) |*u, i| u.* = i;
        const order = try verbs.sortedRows(a, uniques, upos, dirs, .last);
        // `order[k]` is the old code of the k-th smallest unique.
        const remap = try a.alloc(i64, order.len);
        defer a.free(remap);
        for (order, 0..) |old, k| remap[old] = @intCast(k);
        for (code) |*c| {
            if (c.* >= 0) c.* = remap[@intCast(c.*)];
        }
        uniques = try verbs.takeRows(a, uniques, order);
    }
    const cells = try a.alloc(Value, f.len);
    defer a.free(cells);
    for (cells, fac.ids) |*o, g| {
        const c = code[g];
        o.* = if (c < 0 and spec.missing == .null) .null else .{ .int = c };
    }
    return .{
        .frame = try appendColumn(a, f, .{ .name = spec.out, .type = .int }, try fm.columnFromCells(a, cells)),
        .uniques = uniques,
    };
}

// ── top-k over several columns ──────────────────────────────────────────────

pub const TopKSpec = struct {
    /// Sort keys, most significant first (pandas `nlargest(n, columns)`, polars
    /// `top_k_by(by)`).
    by: []const []const u8,
    n: usize,
    /// Largest first (`nlargest`, `top_k_by`); false: smallest (`nsmallest`,
    /// `bottom_k_by`).
    largest: bool = true,
    /// Ties at the cut (pandas `keep`): `first` keeps the earlier rows, `last` the later
    /// ones, `all` every row tied with the `n`-th (so more than `n` may come back).
    keep: enum { first, last, all } = .first,
};

/// The `n` best rows by several keys, best first; a row missing any key is never
/// chosen (pandas drops NaN in `nlargest`).
pub fn topK(a: std.mem.Allocator, f: Frame, spec: TopKSpec) Error!Frame {
    try checkRows(f);
    if (spec.by.len == 0) return error.NoSuchColumn;
    const idxs = try subsetIdxs(a, f, spec.by);
    var present = try verbs.dropna(a, f, .{ .subset = spec.by });
    if (spec.keep == .last) present = try verbs.takeRows(a, present, blk: {
        const r = try a.alloc(u32, present.len);
        for (r, 0..) |*o, k| o.* = @intCast(present.len - 1 - k);
        break :blk r;
    });
    const pidx = try a.alloc(usize, idxs.len);
    for (pidx, spec.by) |*p, name| p.* = present.columnIndex(name).?;
    const dirs = try a.alloc(sp.SortDir, idxs.len);
    @memset(dirs, if (spec.largest) .desc else .asc);
    const order = try verbs.sortedRows(a, present, pidx, dirs, .last);
    var k = @min(spec.n, order.len);
    if (spec.keep == .all and k > 0) {
        const last = order[k - 1];
        while (k < order.len) : (k += 1) {
            var tie = true;
            for (pidx) |ci| {
                const col = present.columnAt(ci);
                tie = tie and col.get(order[k]).order(col.get(last)) == .eq;
            }
            if (!tie) break;
        }
    }
    return verbs.takeRows(a, present, order[0..k]);
}

// ── qcut ────────────────────────────────────────────────────────────────────

pub const QcutSpec = struct {
    col: []const u8,
    out: []const u8,
    /// Equal-frequency bins (pandas `qcut(x, q=4)`); ignored when `probs` is set.
    bins: usize = 4,
    /// Quantile probabilities, ascending in [0, 1], e.g. `{0, 0.1, 0.5, 1}` (pandas'
    /// list form; polars' `quantiles`).
    probs: []const f64 = &.{},
    /// One per bin; empty: the bin's number (pandas `labels=False`).
    labels: []const []const u8 = &.{},
    /// Repeating edges: `error.BadEdges` (pandas' default `"raise"`) or dropped
    /// (`"drop"`; polars `allow_duplicates=True`).
    duplicates: enum { raise, drop } = .raise,
};

/// Type-7 quantile of sorted, NaN-free, non-empty `xs` (`core.quantileInPlace`'s arithmetic).
fn sortedQuantile7(xs: []const f64, q: f64) f64 {
    const h = @as(f64, @floatFromInt(xs.len - 1)) * q;
    const lo: usize = @intFromFloat(@floor(h));
    const frac = h - @floor(h);
    if (frac == 0 or lo + 1 >= xs.len) return xs[lo];
    return xs[lo] + frac * (xs[lo + 1] - xs[lo]);
}

/// Quantile-based bins (pandas `qcut`, polars `qcut`): the edges are the column's type-7
/// quantiles of its present numbers, the bins `(a, b]` with the lowest edge included,
/// then `cut`. No numbers to cut: `error.BadEdges`.
pub fn qcut(a: std.mem.Allocator, f: Frame, spec: QcutSpec) (Error || more.CutError)!Frame {
    const ci = try mustIndex(f, spec.col);
    var probs: []const f64 = spec.probs;
    if (probs.len == 0) {
        if (spec.bins == 0) return error.BadArgument;
        if (spec.bins > 1 << 20) return error.TooLarge;
        const p = try a.alloc(f64, spec.bins + 1);
        for (p, 0..) |*x, i| x.* = @as(f64, @floatFromInt(i)) / @as(f64, @floatFromInt(spec.bins));
        probs = p;
    }
    if (probs.len < 2) return error.BadEdges;
    for (probs, 0..) |p, i| {
        if (!(p >= 0 and p <= 1)) return error.BadEdges;
        if (i > 0 and !(p > probs[i - 1])) return error.BadEdges;
    }
    var vals: std.ArrayList(f64) = .empty;
    defer vals.deinit(a);
    const col = f.columnAt(ci);
    for (0..f.len) |ri| {
        const v = col.get(ri);
        if (isMissing(v)) continue;
        if (v.asFloat()) |x| try vals.append(a, x);
    }
    if (vals.items.len == 0) return error.BadEdges;
    // Sorted once, each edge then read by index: a selection per edge was
    // O(bins x rows), a hang at 2^20 bins over a million rows (review
    // 2026-11-07, MED 5). Same type-7 formula as `core.quantileInPlace`.
    std.mem.sort(f64, vals.items, {}, std.sort.asc(f64));
    var edges: std.ArrayList(f64) = .empty;
    for (probs) |p| {
        const e = sortedQuantile7(vals.items, p);
        if (edges.items.len > 0 and e == edges.items[edges.items.len - 1]) {
            if (spec.duplicates == .raise) return error.BadEdges;
            continue;
        }
        try edges.append(a, e);
    }
    if (edges.items.len < 2) return error.BadEdges;
    if (spec.labels.len != 0 and spec.labels.len != edges.items.len - 1) return error.BadEdges;
    if (f.columnIndex(spec.out) != null) return error.DuplicateColumn;
    return more.cut(a, f, .{ .col = spec.col, .out = spec.out, .edges = edges.items, .labels = spec.labels, .include_lowest = true });
}
