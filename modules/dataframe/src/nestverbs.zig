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

/// Most bytes of text and nested elements the repeated (not exploded) columns of one
/// `explode` may copy: 1 GiB; past it `error.TooLarge`.
pub const max_explode_bytes: usize = 1 << 30;

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
    // What the repeated cells carry besides themselves: text bytes and nested elements, each
    // copied once per element of its row (review R2 M4: 1e7 cells under the cap were 100 GB of
    // repeated text).
    var bytes: usize = 0;
    for (0..f.len) |ri| {
        const reps = @max(elemCount(f.columnAt(idx[0]), ri), 1);
        for (0..f.columns.len) |ci| {
            if (std.mem.findScalar(usize, idx, ci) != null) continue;
            bytes +|= reps *| payloadBytes(f.columnAt(ci).get(ri));
        }
        if (bytes > max_explode_bytes) return error.TooLarge;
    }

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

/// `explode` of every list column of `f` at once (polars `explode(cs.list())`, pandas
/// `DataFrame.explode(list of every list column)`): the columns declared `.list`, or stored
/// as lists, explode together, so their lists must have the same length on every row
/// (`error.LengthMismatch`). No list column: `f` as it is.
pub fn explodeAll(a: std.mem.Allocator, f: Frame) NestError!Frame {
    var names: std.ArrayList([]const u8) = .empty;
    defer names.deinit(a);
    for (f.columns, 0..) |c, ci| {
        if (c.type == .list or f.columnAt(ci) == .list) try names.append(a, c.name);
    }
    return explode(a, f, names.items);
}

/// pandas `Series.list.flatten()`: the elements of every list of column `col`, in order, as
/// a one-column frame (null and empty lists contribute nothing; a row that is not a list
/// is skipped, as pandas' accessor needs a list dtype). The column takes the declared
/// element type (`Column.inner[0]`), else the type its storage says. `error.NotNested` when
/// `col` is not a list column; `error.TooLarge` past `u32` elements.
pub fn flattenList(a: std.mem.Allocator, f: Frame, col: []const u8) NestError!Frame {
    try core.checkRowsU32(f.len);
    const ci = f.columnIndex(col) orelse return error.NoSuchColumn;
    const d = f.columnAt(ci);
    if (d != .list) {
        if (f.columns[ci].type != .list or d != .nulls) return error.NotNested;
        const cols = try a.alloc(Column, 1);
        cols[0] = elementColumn(f.columns[ci], .nulls);
        const data = try a.alloc(ColumnData, 1);
        data[0] = .nulls;
        return .{ .columns = cols, .data = data, .len = 0 };
    }
    const lc = d.list;
    var total: usize = 0;
    for (0..f.len) |ri| total += if (lc.at(ri)) |l| l.len() else 0;
    if (total >= keys.none) return error.TooLarge;
    const pos = try a.alloc(u32, total);
    defer a.free(pos);
    var at: usize = 0;
    for (0..f.len) |ri| {
        const l = lc.at(ri) orelse continue;
        for (0..l.len()) |k| pos[at + k] = l.start + @as(u32, @intCast(k)); // k < len, a u32 difference
        at += l.len();
    }
    const items = try verbs.take(a, lc.items.*, pos, false);
    const cols = try a.alloc(Column, 1);
    cols[0] = elementColumn(f.columns[ci], items);
    const data = try a.alloc(ColumnData, 1);
    data[0] = items;
    return .{ .columns = cols, .data = data, .len = total };
}

/// The column a list column's elements make: the declared `inner[0]` named like the list,
/// else the storage's kind.
fn elementColumn(src: Column, items: ColumnData) Column {
    if (src.inner.len == 1) return .{ .name = src.name, .type = src.inner[0].type, .inner = src.inner[0].inner };
    return .{ .name = src.name, .type = storageType(items) };
}

/// pandas `Series.struct.dtypes`: the fields of struct column `col` with their types, in
/// order (the declared `Column.inner`, else the storage of each field). Not a struct
/// column: `error.NotNested`. The slice is owned by `a`.
pub fn structDtypes(a: std.mem.Allocator, f: Frame, col: []const u8) NestError![]const Column {
    const ci = f.columnIndex(col) orelse return error.NoSuchColumn;
    const d = f.columnAt(ci);
    const decl = f.columns[ci];
    if (d != .@"struct") {
        if (decl.type == .@"struct" and d == .nulls) return a.dupe(Column, decl.inner);
        return error.NotNested;
    }
    const sc = d.@"struct";
    const out = try a.alloc(Column, sc.names.len);
    for (out, sc.names, 0..) |*o, nm, i| {
        o.* = decl.innerAt(i, nm) orelse .{ .name = nm, .type = storageType(if (i < sc.children.len) sc.children[i] else .nulls) };
        o.name = nm;
    }
    return out;
}

/// What copying cell `v` costs beyond its slot: a text's bytes, a list's elements or a
/// record's fields (16 bytes each, the smallest nested slot), one level deep.
fn payloadBytes(v: Value) usize {
    return switch (v) {
        .text => |t| t.len,
        .list => |l| l.len() *| 16,
        .record => |r| r.len() *| 16,
        else => 0,
    };
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
        const fields = try fieldsOf(a, f.columnAt(ci), c, f.len);
        // The declared fields by name, looked up once each (`innerAt` scans on a miss).
        var decl: std.StringHashMapUnmanaged(Column) = .empty;
        defer decl.deinit(a);
        for (c.inner) |ic| _ = try decl.getOrPutValue(a, ic.name, ic);
        for (fields.names, fields.data) |fname, fd| {
            const out_name = if (spec.separator) |sep| try std.mem.concat(a, u8, &.{ c.name, sep, fname }) else fname;
            try cols.append(a, if (decl.get(fname)) |dc|
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

const Fields = struct { names: []const []const u8, data: []const ColumnData };

/// The field columns of one struct column, each read once per row (review R2 M2: a name
/// lookup per field per row was O(fields^2 x rows)). Its storage's fields; with no storage
/// the declared ones, all null; a mixed (boxed) column's union of names in first-seen
/// order, at most `max_unnest_fields`, and with every row a record or not. Building more
/// cells than the column holds past `sp.max_join_cells` is `error.TooLarge` (disjoint
/// names over many records multiply).
fn fieldsOf(a: std.mem.Allocator, d: ColumnData, c: Column, len: usize) NestError!Fields {
    switch (d) {
        .@"struct" => |st| {
            const out = try a.alloc(ColumnData, st.names.len);
            for (out, 0..) |*o, k| {
                const child: ColumnData = if (k < st.children.len) st.children[k] else .nulls;
                // A plain struct column: its child IS the field column, shared.
                if (st.valid == null and st.len == len and (child.storedLen() orelse len) == len) {
                    o.* = child;
                    continue;
                }
                var b: fm.ColBuilder = .{ .a = a, .hint = len };
                for (0..len) |ri| try b.append(if (st.isValid(ri)) child.get(ri) else .null);
                o.* = b.finish();
            }
            return .{ .names = st.names, .data = out };
        },
        .nulls => {
            const names = try a.alloc([]const u8, c.inner.len);
            for (names, c.inner) |*n, ic| n.* = ic.name;
            const out = try a.alloc(ColumnData, c.inner.len);
            @memset(out, .nulls);
            return .{ .names = names, .data = out };
        },
        .boxed => {
            var names: std.ArrayList([]const u8) = .empty;
            var index: std.StringHashMapUnmanaged(u32) = .empty;
            defer index.deinit(a);
            var in_cells: usize = 0;
            for (c.inner) |ic| try addName(a, &names, &index, ic.name);
            for (0..len) |ri| {
                const v = d.get(ri);
                if (v != .record) continue;
                in_cells +|= v.record.len();
                for (0..v.record.len()) |k| try addName(a, &names, &index, v.record.name(k));
            }
            try verbs.growthWithin(names.items.len *| len, in_cells);
            const builders = try a.alloc(fm.ColBuilder, names.items.len);
            for (builders) |*b| b.* = .{ .a = a, .hint = len };
            const row = try a.alloc(Value, names.items.len);
            defer a.free(row);
            for (0..len) |ri| {
                @memset(row, .null);
                const v = d.get(ri);
                if (v == .record) {
                    // Backwards, so a name repeated in one record keeps its first field
                    // (`RecordView.field`'s answer).
                    var k = v.record.len();
                    while (k > 0) {
                        k -= 1;
                        row[index.get(v.record.name(k)).?] = v.record.get(k);
                    }
                }
                for (builders, row) |*b, x| try b.append(x);
            }
            const out = try a.alloc(ColumnData, builders.len);
            for (out, builders) |*o, *b| o.* = b.finish();
            return .{ .names = names.items, .data = out };
        },
        else => unreachable, // `unnest` checked the storage
    }
}

fn addName(a: std.mem.Allocator, names: *std.ArrayList([]const u8), index: *std.StringHashMapUnmanaged(u32), n: []const u8) NestError!void {
    const gop = try index.getOrPut(a, n);
    if (gop.found_existing) return;
    if (names.items.len >= max_unnest_fields) return error.TooLarge;
    gop.value_ptr.* = @intCast(names.items.len);
    try names.append(a, n);
}
