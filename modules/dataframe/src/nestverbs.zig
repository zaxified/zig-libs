// SPDX-License-Identifier: MIT
//! The frame verbs over list and struct columns (S3 step 3, 2026-11-08): `explode`
//! (pandas and polars `explode`: one row per element) and `unnest` (polars `unnest`:
//! a struct column's fields as columns). The per-cell functions are in `listfn.zig`.
//! Original work of the zig-libs authors (MIT).

const std = @import("std");
const ds = @import("value.zig");
const fm = @import("frame.zig");
const sp = @import("spec.zig");
const keys = @import("keys.zig");
const core = @import("core.zig");
const verbs = @import("verbs.zig");
const Frame = fm.Frame;
const ColumnData = fm.ColumnData;
const Column = ds.Column;
const ColumnType = ds.ColumnType;
const Value = ds.Value;

pub const NestError = sp.ColumnsError || error{
    /// A column given to `explode` that is not a list column, or to `unnest` that is not
    /// a struct column.
    NotNested,
    /// `explode` over several columns whose lists differ in length on some row (pandas
    /// "columns must have matching element counts", polars `ShapeError`).
    LengthMismatch,
};

/// Most cells (output rows x columns) one `explode` may build: every other column is
/// repeated once per element, so a wide frame with long lists multiplies. 2^28 cells;
/// past it `error.TooLarge`.
pub const max_explode_cells: usize = 1 << 28;

/// One row per element of the list columns `cols` (pandas `explode`, polars `explode`),
/// the other columns' cells repeated, rows in order. A null or empty list gives one row
/// with a null there (both engines). Several columns explode together, so their lists
/// must have the same length on every row (null and empty count 0), else
/// `error.LengthMismatch`. In a column of mixed cells a non-list cell stays one element
/// (pandas). The column takes its declared element type (`Column.inner[0]`), else the
/// type its elements' storage says. No columns: `f` as it is.
pub fn explode(a: std.mem.Allocator, f: Frame, cols: []const []const u8) NestError!Frame {
    try core.checkRowsU32(f.len);
    if (cols.len == 0) return f;
    const idx = try a.alloc(usize, cols.len);
    defer a.free(idx);
    for (cols, idx, 0..) |name, *ci, i| {
        ci.* = f.columnIndex(name) orelse return error.NoSuchColumn;
        for (idx[0..i]) |prev| if (prev == ci.*) return error.DuplicateColumn;
        const d = f.columnAt(ci.*);
        const declared = f.columns[ci.*].type == .list;
        if (!(d == .list or (declared and (d == .nulls or d == .boxed)))) return error.NotNested;
    }
    // Rows out: one per element, at least one per row.
    var rows: usize = 0;
    for (0..f.len) |ri| {
        const n = elemCount(f.columnAt(idx[0]), ri);
        for (idx[1..]) |ci| if (elemCount(f.columnAt(ci), ri) != n) return error.LengthMismatch;
        rows += @max(n, 1);
        if (rows >= keys.none) return error.TooLarge;
    }
    const cells = std.math.mul(usize, rows, f.columns.len) catch return error.TooLarge;
    if (cells > max_explode_cells) return error.TooLarge;

    const row_of = try a.alloc(u32, rows);
    defer a.free(row_of);
    var at: usize = 0;
    for (0..f.len) |ri| {
        const n = @max(elemCount(f.columnAt(idx[0]), ri), 1);
        @memset(row_of[at..][0..n], @intCast(ri));
        at += n;
    }
    const out_cols = try a.dupe(Column, f.columns);
    const data = try a.alloc(ColumnData, f.columns.len);
    for (data, 0..) |*d, ci| {
        if (std.mem.findScalar(usize, idx, ci) == null) {
            d.* = try verbs.take(a, f.columnAt(ci), row_of, false);
            continue;
        }
        d.* = try explodeColumn(a, f.columnAt(ci), f.len, rows);
        const src = f.columns[ci];
        out_cols[ci] = if (src.inner.len == 1)
            .{ .name = src.name, .type = src.inner[0].type, .inner = src.inner[0].inner }
        else
            .{ .name = src.name, .type = storageType(d.*) };
    }
    return .{ .columns = out_cols, .data = data, .len = rows };
}

/// Elements of row `ri` for `explode`: a list's length, 0 for null, 1 for any other cell.
fn elemCount(col: ColumnData, ri: usize) usize {
    return switch (col.get(ri)) {
        .null => 0,
        .list => |l| l.len(),
        else => 1,
    };
}

fn explodeColumn(a: std.mem.Allocator, col: ColumnData, len: usize, rows: usize) NestError!ColumnData {
    if (col == .list) {
        // Positions into the one element column, `keys.none` for a null or empty row: a
        // typed gather, no cell boxed.
        const lc = col.list;
        const pos = try a.alloc(u32, rows);
        defer a.free(pos);
        var at: usize = 0;
        for (0..len) |ri| {
            const l = lc.at(ri) orelse vm_empty;
            if (l.len() == 0) {
                pos[at] = keys.none;
                at += 1;
                continue;
            }
            for (0..l.len()) |k| pos[at + k] = l.start + @as(u32, @intCast(k)); // k < len, a u32 difference
            at += l.len();
        }
        return verbs.take(a, lc.items.*, pos, true);
    }
    var b: fm.ColBuilder = .{ .a = a, .hint = rows };
    for (0..len) |ri| switch (col.get(ri)) {
        .list => |l| if (l.len() == 0) try b.appendNull() else for (0..l.len()) |k| try b.append(l.get(k)),
        else => |v| try b.append(v),
    };
    return b.finish();
}

const vm_empty: ds.ListView = .{ .items = &empty_items, .start = 0, .end = 0 };
const empty_items: ColumnData = .nulls;

/// The type a column's storage stands for, when no schema says: its array's kind, a
/// mix by its first present cell, no cells `.float` (as `mutate` with no results).
pub fn storageType(d: ColumnData) ColumnType {
    return switch (d) {
        .nulls => .float,
        .int => .int,
        .float => .float,
        .bool => .bool,
        .decimal => .decimal,
        .text => .text,
        .categorical => .categorical,
        .list => .list,
        .@"struct" => .@"struct",
        .boxed => |cells| for (cells) |c| switch (c) {
            .null => {},
            .int => break .int,
            .float => break .float,
            .bool => break .bool,
            .decimal => break .decimal,
            .text => break .text,
            .list => break .list,
            .record => break .@"struct",
        } else .float,
    };
}

/// Most fields `unnest` makes of one column of mixed records (their names are cell
/// data, and each becomes a column of `len` rows). 2^16; past it `error.TooLarge`.
pub const max_unnest_fields: usize = 1 << 16;

pub const UnnestSpec = struct {
    /// Struct columns to unnest, each replaced in place by its fields.
    cols: []const []const u8,
    /// Name the fields `<column><separator><field>` (polars `unnest(separator=)`);
    /// null keeps the field names as they are (polars' default).
    separator: ?[]const u8 = null,
};

/// The fields of each struct column in `spec.cols` as columns of their own, in field
/// order, where the struct column was (polars `unnest`). A null record's fields are null.
/// A field's type is the declared one (`Column.inner`), else its storage's. A column of
/// mixed records (boxed storage) gives the union of their field names, in the order
/// they first appear. A resulting name equal to another column's is
/// `error.DuplicateColumn` (polars), a column that is not a struct `error.NotNested`.
pub fn unnest(a: std.mem.Allocator, f: Frame, spec: UnnestSpec) NestError!Frame {
    const which = try a.alloc(bool, f.columns.len);
    defer a.free(which);
    @memset(which, false);
    for (spec.cols) |name| {
        const ci = f.columnIndex(name) orelse return error.NoSuchColumn;
        if (which[ci]) return error.DuplicateColumn;
        const d = f.columnAt(ci);
        const declared = f.columns[ci].type == .@"struct";
        if (!(d == .@"struct" or (declared and (d == .nulls or d == .boxed)))) return error.NotNested;
        which[ci] = true;
    }
    var cols: std.ArrayList(Column) = .empty;
    var data: std.ArrayList(ColumnData) = .empty;
    for (f.columns, 0..) |c, ci| {
        if (!which[ci]) {
            try cols.append(a, c);
            try data.append(a, f.columnAt(ci));
            continue;
        }
        const d = f.columnAt(ci);
        const names = try fieldNames(a, d, c, f.len);
        for (names, 0..) |fname, k| {
            const fd = try fieldData(a, d, fname, k, f.len);
            const decl = c.innerAt(k, fname);
            const out_name = if (spec.separator) |sep| try std.mem.concat(a, u8, &.{ c.name, sep, fname }) else fname;
            try cols.append(a, if (decl) |dc|
                .{ .name = out_name, .type = dc.type, .inner = dc.inner }
            else
                .{ .name = out_name, .type = storageType(fd) });
            try data.append(a, fd);
        }
    }
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(a);
    for (cols.items) |c| if ((try seen.getOrPut(a, c.name)).found_existing) return error.DuplicateColumn;
    return .{ .columns = cols.items, .data = data.items, .len = f.len };
}

/// The field names of a struct column: its storage's, a mix's union in first-seen
/// order, none stored but declared: the declared ones.
fn fieldNames(a: std.mem.Allocator, d: ColumnData, c: Column, len: usize) NestError![]const []const u8 {
    switch (d) {
        .@"struct" => |st| return st.names,
        .nulls => {
            const names = try a.alloc([]const u8, c.inner.len);
            for (names, c.inner) |*n, ic| n.* = ic.name;
            return names;
        },
        .boxed => {
            var names: std.ArrayList([]const u8) = .empty;
            var seen: std.StringHashMapUnmanaged(void) = .empty;
            defer seen.deinit(a);
            for (c.inner) |ic| if (!(try seen.getOrPut(a, ic.name)).found_existing) try names.append(a, ic.name);
            for (0..len) |ri| {
                const v = d.get(ri);
                if (v != .record) continue;
                for (0..v.record.len()) |k| {
                    const n = v.record.name(k);
                    if ((try seen.getOrPut(a, n)).found_existing) continue;
                    if (names.items.len >= max_unnest_fields) return error.TooLarge;
                    try names.append(a, n);
                }
            }
            return names.items;
        },
        else => unreachable, // `unnest` checked the storage
    }
}

/// Field `name` (the `k`-th of the storage's names) of every row.
fn fieldData(a: std.mem.Allocator, d: ColumnData, name: []const u8, k: usize, len: usize) NestError!ColumnData {
    switch (d) {
        .@"struct" => |st| {
            const child: ColumnData = if (k < st.children.len) st.children[k] else .nulls;
            // A plain struct column: its child IS the field column, shared.
            if (st.valid == null and st.len == len and childLen(child) == len) return child;
        },
        .nulls => return .nulls,
        else => {},
    }
    var b: fm.ColBuilder = .{ .a = a, .hint = len };
    for (0..len) |ri| {
        const v = d.get(ri);
        try b.append(if (v == .record) v.record.field(name) orelse .null else .null);
    }
    return b.finish();
}

/// Rows a column's storage holds (no more than a frame of that length reads).
fn childLen(c: ColumnData) usize {
    return switch (c) {
        .nulls => std.math.maxInt(usize),
        .int => |x| x.values.len,
        .float => |x| x.values.len,
        .bool => |x| x.values.len,
        .decimal => |x| x.values.len,
        .text => |x| x.offsets.len -| 1,
        .categorical => |x| x.codes.values.len,
        .list => |x| x.offsets.len -| 1,
        .@"struct" => |x| x.len,
        .boxed => |x| x.len,
    };
}
