// SPDX-License-Identifier: MIT
//! Ordered categoricals and the `cat` verbs (dataframe S2 wave W6): polars `Enum`
//! (a fixed category list given up front, the order of the list is the order of the
//! values), pandas `CategoricalDtype(categories, ordered=True)` and the `Series.cat`
//! accessor (`codes`, `categories`, `add_categories`, `remove_categories`,
//! `remove_unused_categories`, `set_categories`, `reorder_categories`, `rename_categories`,
//! `as_ordered`, `as_unordered`), polars' `cat.get_categories` / `to_physical`.
//!
//! **Model.** `ColumnData.categorical` (`CatColumn`) holds a dictionary that is no longer
//! always the observed values in lexical order: a column made by `cast` with `categories`,
//! or by these verbs, has the dictionary the caller gave, in that order, with categories no
//! row uses. The code of a value is its position in the dictionary. `CatColumn.ordered`
//! says whether the order means something (pandas `ordered`, polars `Enum`): `<`, `<=`,
//! `>`, `>=` in an `Expr` compare codes then (`error.BadExpr` for a value that is no
//! category, pandas `TypeError`, polars `InvalidOperationError`), and an unordered one
//! compares as text, as before. `sort` orders every categorical by its codes (pandas does,
//! and polars' `Enum`; for a dictionary built by `cast` without categories the codes are the
//! lexical order, so nothing changed). Equality, grouping, joining and the writers go by the
//! cell's text, so they do not care about the order.
//!
//! Every verb returns a new `Frame`; the column's other cells are shared. A column declared
//! `.categorical` whose storage is still plain text is encoded first (lexical dictionary).
//! The failures are one error, `BadCategories`: pandas raises `ValueError` and polars
//! `InvalidOperationError` for every one of them (a duplicate category, a category missing
//! where one is required, a count that does not match).

const std = @import("std");
const vm = @import("value.zig");
const fm = @import("frame.zig");
const Frame = fm.Frame;
const ColumnData = fm.ColumnData;
const CatColumn = fm.CatColumn;
const TextColumn = fm.TextColumn;
const Column = vm.Column;
const Value = vm.Value;

pub const CatError = error{
    OutOfMemory,
    /// More rows than `u32`, or more categories than fit a `u32` code.
    TooLarge,
    NoSuchColumn,
    /// The column is neither stored as a categorical nor declared one.
    NotCategorical,
    /// A category list with a duplicate, a name to add that is already there, a name to
    /// remove or rename that is not, a reorder that is not a permutation, or a rename list
    /// of the wrong length.
    BadCategories,
};

/// The categories of `cat` in order, each borrowed from its dictionary.
pub fn dictTexts(a: std.mem.Allocator, d: TextColumn) std.mem.Allocator.Error![]const []const u8 {
    const n = d.offsets.len -| 1;
    const out = try a.alloc([]const u8, n);
    for (out, 0..) |*o, i| o.* = d.at(i) orelse "";
    return out;
}

/// A dictionary of `texts` (copied), in that order.
fn makeDict(a: std.mem.Allocator, texts: []const []const u8) std.mem.Allocator.Error!TextColumn {
    var total: usize = 0;
    for (texts) |t| total += t.len;
    const offsets = try a.alloc(usize, texts.len + 1);
    const bytes = try a.alloc(u8, total);
    var at: usize = 0;
    for (texts, 0..) |t, i| {
        offsets[i] = at;
        @memcpy(bytes[at..][0..t.len], t);
        at += t.len;
    }
    offsets[texts.len] = at;
    return .{ .offsets = offsets, .bytes = bytes };
}

/// `error.BadCategories` when a text appears twice.
fn requireUnique(a: std.mem.Allocator, texts: []const []const u8) CatError!void {
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(a);
    for (texts) |t| if ((try seen.getOrPut(a, t)).found_existing) return error.BadCategories;
}

/// What `encodeWith` made and whether a present cell had no category.
pub const Encoded = struct { data: ColumnData, lost: bool };

/// `col`'s cells (text or null; any other cell reads as null, as `encodeCategorical`) coded
/// against `cats` in that order: a cell that is no category is null and sets `lost`
/// (polars `cast(Enum)`: an error with `strict`, null without; pandas `astype` gives NaN).
/// `cats` must be unique, else `error.BadCategories`.
pub fn encodeWith(a: std.mem.Allocator, col: ColumnData, len: usize, cats: []const []const u8, ordered: bool) CatError!Encoded {
    if (len > std.math.maxInt(u32) or cats.len > std.math.maxInt(u32)) return error.TooLarge;
    try requireUnique(a, cats);
    var map: std.StringHashMapUnmanaged(u32) = .empty;
    defer map.deinit(a);
    for (cats, 0..) |t, i| try map.put(a, t, @intCast(i));
    const out = try a.alloc(u32, len);
    const bits = try a.alloc(u64, (len + 63) / 64);
    @memset(bits, 0);
    var lost = false;
    var all_valid = true;
    for (out, 0..) |*code, ri| {
        code.* = 0;
        const v = col.get(ri);
        if (v == .text) {
            if (map.get(v.text)) |k| {
                code.* = k;
                bits[ri / 64] |= @as(u64, 1) << @intCast(ri % 64);
                continue;
            }
            lost = true;
        }
        all_valid = false;
    }
    return .{ .data = .{ .categorical = .{
        .codes = .{ .values = out, .valid = if (all_valid) null else bits },
        .dict = try makeDict(a, cats),
        .ordered = ordered,
    } }, .lost = lost };
}

const Target = struct { ci: usize, cat: CatColumn };

/// Column `name` as a `CatColumn`: its storage, or, for a column declared `.categorical`
/// that is still plain text, the lexical encoding of it.
fn target(a: std.mem.Allocator, f: Frame, name: []const u8) CatError!Target {
    const ci = f.columnIndex(name) orelse return error.NoSuchColumn;
    switch (f.columnAt(ci)) {
        .categorical => |c| return .{ .ci = ci, .cat = c },
        else => |d| {
            if (f.columns[ci].type != .categorical) return error.NotCategorical;
            const enc = try fm.encodeCategorical(a, d, f.len);
            return switch (enc) {
                .categorical => |c| .{ .ci = ci, .cat = c },
                // No cell at all: an empty dictionary.
                else => .{ .ci = ci, .cat = .{ .codes = .{ .values = &.{} }, .dict = .{ .offsets = &.{0}, .bytes = &.{} } } },
            };
        },
    }
}

/// `f` with column `ci` replaced by `data` of type `ty`.
fn withColumn(a: std.mem.Allocator, f: Frame, ci: usize, data: ColumnData, ty: vm.ColumnType) std.mem.Allocator.Error!Frame {
    const cols = try a.dupe(Column, f.columns);
    cols[ci].type = ty;
    if (ty != .timestamp) cols[ci].time_zone = null;
    cols[ci].inner = &.{};
    const out = try a.alloc(ColumnData, f.columns.len);
    for (out, 0..) |*d, i| d.* = f.columnAt(i);
    out[ci] = data;
    return .{ .columns = cols, .data = out, .len = f.len };
}

fn withCat(a: std.mem.Allocator, f: Frame, t: Target, cat: CatColumn) std.mem.Allocator.Error!Frame {
    return withColumn(a, f, t.ci, .{ .categorical = cat }, .categorical);
}

/// The categories in order (pandas `cat.categories`, polars `Enum.categories` /
/// `cat.get_categories()`), unused ones included. The slice is the caller's, the texts
/// borrow from the column.
pub fn categories(a: std.mem.Allocator, f: Frame, name: []const u8) CatError![]const []const u8 {
    const t = try target(a, f, name);
    return dictTexts(a, t.cat.dict);
}

/// Whether the column's order means something (pandas `cat.ordered`; true for a polars
/// `Enum`).
pub fn isOrdered(a: std.mem.Allocator, f: Frame, name: []const u8) CatError!bool {
    return (try target(a, f, name)).cat.ordered;
}

/// pandas `cat.codes`, polars `to_physical()`: the column as ints, each the position of the
/// cell's category (a null cell stays null; pandas writes -1 there). The column becomes
/// `.int`.
pub fn codes(a: std.mem.Allocator, f: Frame, name: []const u8) CatError!Frame {
    const t = try target(a, f, name);
    const c = t.cat;
    const vals = try a.alloc(i64, f.len);
    for (vals, 0..) |*o, ri| o.* = if (c.codes.isValid(ri)) c.codes.values[ri] else 0;
    return withColumn(a, f, t.ci, .{ .int = .{ .values = vals, .valid = c.codes.valid } }, .int);
}

/// pandas `cat.as_ordered()` / `as_unordered()`: only the flag changes.
pub fn setOrdered(a: std.mem.Allocator, f: Frame, name: []const u8, ordered: bool) CatError!Frame {
    const t = try target(a, f, name);
    var c = t.cat;
    c.ordered = ordered;
    return withCat(a, f, t, c);
}

/// Codes of `c` moved through `map` (old code to new code, `none` for a category that
/// goes), under the dictionary `texts`; a cell whose category went becomes null.
fn remap(a: std.mem.Allocator, f: Frame, t: Target, texts: []const []const u8, map: []const u32, ordered: bool) CatError!Frame {
    const c = t.cat;
    const none = std.math.maxInt(u32);
    const out = try a.alloc(u32, f.len);
    const bits = try a.alloc(u64, (f.len + 63) / 64);
    @memset(bits, 0);
    var all_valid = true;
    for (out, 0..) |*o, ri| {
        o.* = 0;
        if (c.codes.isValid(ri)) {
            const old = c.codes.values[ri];
            const nw: u32 = if (old < map.len) map[old] else none;
            if (nw != none) {
                o.* = nw;
                bits[ri / 64] |= @as(u64, 1) << @intCast(ri % 64);
                continue;
            }
        }
        all_valid = false;
    }
    return withCat(a, f, t, .{ .codes = .{ .values = out, .valid = if (all_valid) null else bits }, .dict = try makeDict(a, texts), .ordered = ordered });
}

fn indexMap(a: std.mem.Allocator, texts: []const []const u8) std.mem.Allocator.Error!std.StringHashMapUnmanaged(u32) {
    var m: std.StringHashMapUnmanaged(u32) = .empty;
    errdefer m.deinit(a);
    for (texts, 0..) |t, i| try m.put(a, t, @intCast(i));
    return m;
}

/// pandas `cat.add_categories(new)`: `new` after the existing ones. A name already a
/// category, or twice in `new`, is `error.BadCategories` (pandas `ValueError`).
pub fn addCategories(a: std.mem.Allocator, f: Frame, name: []const u8, new: []const []const u8) CatError!Frame {
    const t = try target(a, f, name);
    const old = try dictTexts(a, t.cat.dict);
    if (old.len +| new.len > std.math.maxInt(u32)) return error.TooLarge;
    const all = try a.alloc([]const u8, old.len + new.len);
    @memcpy(all[0..old.len], old);
    @memcpy(all[old.len..], new);
    try requireUnique(a, all);
    return withCat(a, f, t, .{ .codes = t.cat.codes, .dict = try makeDict(a, all), .ordered = t.cat.ordered });
}

/// pandas `cat.remove_categories(gone)`: the cells of a removed category become null. A name
/// that is no category is `error.BadCategories` (pandas `ValueError`).
pub fn removeCategories(a: std.mem.Allocator, f: Frame, name: []const u8, gone: []const []const u8) CatError!Frame {
    const t = try target(a, f, name);
    const old = try dictTexts(a, t.cat.dict);
    var idx = try indexMap(a, old);
    defer idx.deinit(a);
    const none = std.math.maxInt(u32);
    const map = try a.alloc(u32, old.len);
    @memset(map, 0);
    for (gone) |g| map[idx.get(g) orelse return error.BadCategories] = none;
    var kept: std.ArrayList([]const u8) = .empty;
    for (old, map) |o, *m| {
        if (m.* == none) continue;
        m.* = @intCast(kept.items.len);
        try kept.append(a, o);
    }
    return remap(a, f, t, kept.items, map, t.cat.ordered);
}

/// pandas `cat.remove_unused_categories()`: the categories no row uses go; the rest keep
/// their order.
pub fn removeUnusedCategories(a: std.mem.Allocator, f: Frame, name: []const u8) CatError!Frame {
    const t = try target(a, f, name);
    const old = try dictTexts(a, t.cat.dict);
    const used = try a.alloc(bool, old.len);
    defer a.free(used);
    @memset(used, false);
    for (0..f.len) |ri| if (t.cat.codes.isValid(ri) and t.cat.codes.values[ri] < old.len) {
        used[t.cat.codes.values[ri]] = true;
    };
    const map = try a.alloc(u32, old.len);
    var kept: std.ArrayList([]const u8) = .empty;
    for (old, used, map) |o, u, *m| {
        m.* = if (u) @intCast(kept.items.len) else std.math.maxInt(u32);
        if (u) try kept.append(a, o);
    }
    return remap(a, f, t, kept.items, map, t.cat.ordered);
}

/// pandas `cat.set_categories(new, ordered)`, polars `cast(Enum(new), strict=False)`: the
/// dictionary becomes `new` in that order; a cell whose category is not in `new` becomes
/// null. `ordered` null keeps the flag. A name twice in `new` is `error.BadCategories`.
pub fn setCategories(a: std.mem.Allocator, f: Frame, name: []const u8, new: []const []const u8, ordered: ?bool) CatError!Frame {
    const t = try target(a, f, name);
    try requireUnique(a, new);
    if (new.len > std.math.maxInt(u32)) return error.TooLarge;
    const old = try dictTexts(a, t.cat.dict);
    var idx = try indexMap(a, new);
    defer idx.deinit(a);
    const map = try a.alloc(u32, old.len);
    for (map, old) |*m, o| m.* = idx.get(o) orelse std.math.maxInt(u32);
    return remap(a, f, t, new, map, ordered orelse t.cat.ordered);
}

/// pandas `cat.reorder_categories(new, ordered)`: `new` must hold exactly the existing
/// categories (a permutation), else `error.BadCategories` (pandas `ValueError`); no cell
/// changes, the codes follow the new order.
pub fn reorderCategories(a: std.mem.Allocator, f: Frame, name: []const u8, new: []const []const u8, ordered: ?bool) CatError!Frame {
    const t = try target(a, f, name);
    const old = try dictTexts(a, t.cat.dict);
    if (new.len != old.len) return error.BadCategories;
    try requireUnique(a, new);
    var idx = try indexMap(a, new);
    defer idx.deinit(a);
    const map = try a.alloc(u32, old.len);
    for (map, old) |*m, o| m.* = idx.get(o) orelse return error.BadCategories;
    return remap(a, f, t, new, map, ordered orelse t.cat.ordered);
}

/// How `renameCategories` names the new categories.
pub const CatRename = union(enum) {
    /// One new name per category, in dictionary order (pandas list-like).
    list: []const []const u8,
    /// `{old, new}` pairs; a category not named keeps its name (pandas dict-like; an extra
    /// key is ignored there too).
    map: []const [2][]const u8,
};

/// pandas `cat.rename_categories`: the cells keep their codes, the categories their
/// positions, only the names change. The new names must be unique and, for a list, as
/// many as the categories (else `error.BadCategories`, pandas `ValueError`).
pub fn renameCategories(a: std.mem.Allocator, f: Frame, name: []const u8, how: CatRename) CatError!Frame {
    const t = try target(a, f, name);
    const old = try dictTexts(a, t.cat.dict);
    const names = try a.alloc([]const u8, old.len);
    switch (how) {
        .list => |l| {
            if (l.len != old.len) return error.BadCategories;
            @memcpy(names, l);
        },
        .map => |pairs| {
            for (names, old) |*n, o| {
                n.* = o;
                for (pairs) |p| if (std.mem.eql(u8, p[0], o)) {
                    n.* = p[1];
                    break;
                };
            }
        },
    }
    try requireUnique(a, names);
    return withCat(a, f, t, .{ .codes = t.cat.codes, .dict = try makeDict(a, names), .ordered = t.cat.ordered });
}

/// The `name` column of every frame stacked, when each is stored as the same categorical
/// (same categories in the same order, same `ordered`): the codes concatenated, the
/// dictionary kept (pandas `concat` of equal `CategoricalDtype`s, polars' of equal `Enum`s,
/// unused categories included). Null otherwise: the cell path encodes the union again,
/// lexically. A frame without the column makes it null.
pub fn concatSame(a: std.mem.Allocator, frames: []const Frame, maps: []const fm.NameIndex, name: []const u8, total: usize) std.mem.Allocator.Error!?ColumnData {
    var first: ?CatColumn = null;
    for (frames, maps) |t, m| {
        const ci = m.get(name) orelse return null;
        const c = switch (t.columnAt(ci)) {
            .categorical => |c| c,
            else => return null,
        };
        if (first) |f0| {
            if (c.ordered != f0.ordered or !sameDict(c.dict, f0.dict)) return null;
        } else first = c;
    }
    const f0 = first orelse return null;
    const out = try a.alloc(u32, total);
    const bits = try a.alloc(u64, (total + 63) / 64);
    @memset(bits, 0);
    var at: usize = 0;
    var all_valid = true;
    for (frames, maps) |t, m| {
        const c = t.columnAt(m.get(name).?).categorical;
        for (0..t.len) |ri| {
            if (c.codes.isValid(ri)) {
                out[at] = c.codes.values[ri];
                bits[at / 64] |= @as(u64, 1) << @intCast(at % 64);
            } else {
                out[at] = 0;
                all_valid = false;
            }
            at += 1;
        }
    }
    return .{ .categorical = .{ .codes = .{ .values = out, .valid = if (all_valid) null else bits }, .dict = f0.dict, .ordered = f0.ordered } };
}

/// Whether two dictionaries hold the same texts in the same order.
pub fn sameDict(x: TextColumn, y: TextColumn) bool {
    const n = x.offsets.len -| 1;
    if (n != y.offsets.len -| 1) return false;
    for (0..n) |i| {
        const a = x.at(i) orelse "";
        const b = y.at(i) orelse "";
        if (!std.mem.eql(u8, a, b)) return false;
    }
    return true;
}

/// The position of `text` among the categories of `d`, or null.
pub fn rankOf(d: TextColumn, text: []const u8) ?u32 {
    const n = d.offsets.len -| 1;
    for (0..n) |i| if (std.mem.eql(u8, d.at(i) orelse "", text)) return @intCast(i);
    return null;
}

/// A column the readers should hold as a fixed category list (`CsvReadOptions.enums`,
/// `JsonReadOptions.enums`): polars `schema_overrides={name: pl.Enum(categories)}`, pandas
/// `dtype={name: CategoricalDtype(categories, ordered)}`.
pub const EnumDecl = struct {
    name: []const u8,
    categories: []const []const u8,
    /// polars' `Enum` is always ordered; pandas' default is not.
    ordered: bool = true,
};

/// `f` with the columns named by `decls` coded against their lists (see `encodeWith`). A
/// value that is no category is `error.BadValue`: polars raises reading an `Enum` column
/// with one (`InvalidOperationError`), and so does pandas' `read_csv` of an ordered dtype
/// only through `astype`, which gives NaN; the reader takes the strict reading. A category twice
/// is `error.BadValue`; the readers name a column that does not exist `error.NoSuchColumn`, as for
/// `types`.
pub fn applyEnums(a: std.mem.Allocator, f: Frame, decls: []const EnumDecl) error{ OutOfMemory, TooLarge, BadValue }!Frame {
    if (decls.len == 0) return f;
    const cols = try a.dupe(Column, f.columns);
    const data = try a.alloc(ColumnData, cols.len);
    for (data, 0..) |*d, i| d.* = f.columnAt(i);
    for (decls) |dc| {
        const ci = f.columnIndex(dc.name) orelse continue;
        const enc = encodeWith(a, f.columnAt(ci), f.len, dc.categories, dc.ordered) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.TooLarge => error.TooLarge,
            else => error.BadValue,
        };
        if (enc.lost) return error.BadValue;
        cols[ci].type = .categorical;
        cols[ci].time_zone = null;
        cols[ci].inner = &.{};
        data[ci] = enc.data;
    }
    return .{ .columns = cols, .data = data, .len = f.len };
}
