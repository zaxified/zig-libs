// SPDX-License-Identifier: MIT
//! Bulk renaming of columns (dataframe S2 wave W3): polars' `name` namespace
//! (`name.map`, `name.replace`, `name.to_lowercase`, `name.to_uppercase`) and pandas'
//! `rename(columns=func)`, `df.columns.str.replace`, `str.lower()`/`str.upper()` on the
//! labels. Each verb renames the columns a `Selector` picks (polars applies a name
//! function to the columns its expression selects; pandas to all of them, the default
//! here) and shares every array. Two columns ending with one name are
//! `error.DuplicateColumn` (polars' `DuplicateError`).
//!
//! Case is ASCII for now; Unicode case mapping comes with the `unitext` tables, and
//! `renameWith` takes any function meanwhile. Original work of the zig-libs authors (MIT).

const std = @import("std");
const vm = @import("value.zig");
const fm = @import("frame.zig");
const st = @import("structure.zig");
const callback = @import("callback.zig");
const regex = @import("regex");
const Column = vm.Column;
const ColumnData = fm.ColumnData;
const Frame = fm.Frame;
const Selector = st.Selector;

/// `error.DuplicateColumn` for a result name given twice, `error.BadPattern` for a regex
/// `regex` refuses, plus `Selector`'s errors.
pub const NamesError = st.StructureError;

/// Which columns a rename touches and the names it gives them.
fn touched(a: std.mem.Allocator, f: Frame, sel: Selector) NamesError![]bool {
    const picked = try st.selectColumns(a, f, sel);
    defer a.free(picked);
    const flags = try a.alloc(bool, f.columns.len);
    @memset(flags, false);
    var idx = try fm.NameIndex.init(a, f.columns);
    defer idx.deinit(a);
    for (picked) |n| flags[idx.get(n) orelse continue] = true;
    return flags;
}

/// `f` with `names[i]` as the name of every column `flags[i]` marks; arrays shared.
fn withNames(a: std.mem.Allocator, f: Frame, flags: []const bool, names: []const []const u8) NamesError!Frame {
    const cols = try a.dupe(Column, f.columns);
    for (cols, flags, names) |*c, t, n| {
        if (t) c.name = n;
    }
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(a);
    for (cols) |c| if ((try seen.getOrPut(a, c.name)).found_existing) return error.DuplicateColumn;
    const data = try a.alloc(ColumnData, cols.len);
    for (data, 0..) |*d, ci| d.* = f.columnAt(ci);
    return .{ .columns = cols, .data = data, .len = f.len };
}

/// polars `name.map(function)`, pandas `rename(columns=function)`: the columns `sel` picks
/// get the name `func(ctx, a, name)` returns, a text `a` owns or one that outlives the
/// result. `func`: `fn (C, std.mem.Allocator, []const u8) E![]const u8`.
pub fn renameWith(a: std.mem.Allocator, f: Frame, sel: Selector, ctx: anytype, comptime func: anytype) (callback.ErrorOf(func) || NamesError)!Frame {
    const E = callback.ErrorOf(func) || NamesError;
    const flags = try touched(a, f, sel);
    defer a.free(flags);
    const names = try a.alloc([]const u8, f.columns.len);
    defer a.free(names);
    for (names, flags, f.columns) |*n, t, c| {
        n.* = if (t) try @as(E![]const u8, func(ctx, a, c.name)) else c.name;
    }
    return withNames(a, f, flags, names);
}

/// polars `name.to_lowercase()`, pandas `columns.str.lower()`: ASCII letters of the picked
/// columns' names to lower case.
pub fn renameLower(a: std.mem.Allocator, f: Frame, sel: Selector) (NamesError || callback.CallbackError)!Frame {
    return renameWith(a, f, sel, {}, struct {
        fn go(_: void, al: std.mem.Allocator, n: []const u8) NamesError![]const u8 {
            return std.ascii.allocLowerString(al, n);
        }
    }.go);
}

/// polars `name.to_uppercase()`, pandas `columns.str.upper()`: the ASCII upper-case form.
pub fn renameUpper(a: std.mem.Allocator, f: Frame, sel: Selector) (NamesError || callback.CallbackError)!Frame {
    return renameWith(a, f, sel, {}, struct {
        fn go(_: void, al: std.mem.Allocator, n: []const u8) NamesError![]const u8 {
            return std.ascii.allocUpperString(al, n);
        }
    }.go);
}

pub const ReplaceNamesSpec = struct {
    /// The columns to rename; default every column.
    sel: Selector = .all,
    /// A regex (the `regex` module's Rust grammar, polars' own) or, with `literal`, text.
    pattern: []const u8,
    /// The replacement: a template (`$1`, `${name}`, `$$`) unless `literal`.
    with: []const u8,
    literal: bool = false,
    /// Every occurrence (pandas `str.replace`, polars `name.replace` with `literal=True`);
    /// false only the first (polars `name.replace` of a regex).
    all: bool = true,
};

/// polars `name.replace(pattern, value, literal)`, pandas `columns.str.replace(pat, repl,
/// regex=)`. An empty literal pattern is `error.BadArgument`. A name nothing matches stays.
pub fn renameReplace(a: std.mem.Allocator, f: Frame, spec: ReplaceNamesSpec) NamesError!Frame {
    if (spec.literal and spec.pattern.len == 0) return error.BadArgument;
    const flags = try touched(a, f, spec.sel);
    defer a.free(flags);
    var re: regex.Regex = undefined;
    if (!spec.literal) {
        re = regex.Regex.compileOptions(a, spec.pattern, .{ .syntax = .rust }) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.BadPattern,
        };
    }
    const names = try a.alloc([]const u8, f.columns.len);
    defer a.free(names);
    for (names, flags, f.columns) |*n, t, c| {
        n.* = c.name;
        if (!t) continue;
        if (spec.literal) {
            if (spec.all) {
                n.* = try std.mem.replaceOwned(u8, a, c.name, spec.pattern, spec.with);
            } else if (std.mem.find(u8, c.name, spec.pattern)) |at| {
                n.* = try std.mem.concat(a, u8, &.{ c.name[0..at], spec.with, c.name[at + spec.pattern.len ..] });
            }
        } else {
            n.* = try re.replaceN(a, c.name, spec.with, if (spec.all) null else 1);
        }
    }
    return withNames(a, f, flags, names);
}
