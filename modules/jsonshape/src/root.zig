// SPDX-License-Identifier: MIT
//! jsonshape — reshape JSON into a canonical `dataset`: dot-path descent to an
//! array node + typed column projection (jq-style minimal subset).
//!
//! Remote-feed shaping (`getDataview` / `dataviewGet`): walk a **dot-path** to
//! an array node, then project each item into columns. Two modes:
//!   * **columns** (generic): `[]JsonCol{name,key,type}` — one column per field.
//!   * **[x,y] default** (when `columns` is empty): 2 columns from
//!     `x`/`y` keys, or positional `item[0]/item[1]` for array items, or
//!     `[index, item]` for scalars.
//!
//! Values are parsed into canonical `dataset.Value`s honoring each column's
//! declared `ColumnType`. Allocates into `a` (a caller-owned arena); the parsed
//! JSON tree lives in the same arena, so string cells borrow it.
//!
//! Provenance: original work of the zig-libs authors (MIT).

const std = @import("std");
const ds = @import("dataset");
const Dataset = ds.Dataset;
const Column = ds.Column;
const ColumnType = ds.ColumnType;
const Value = ds.Value;

pub const meta = .{
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "jq-style path projection (minimal: one dot-path + field extraction)",
    .deps = .{"dataset"},
};

// ── public API ──────────────────────────────────────────────────────────────

pub const Error = error{ BadJson, OutOfMemory };

pub const JsonCol = struct {
    name: []const u8,
    /// Field name inside each item (object key). Empty = positional/whole-item.
    key: []const u8 = "",
    type: ColumnType = .float,
};

pub const ShapeSpec = struct {
    /// Dot-path from the root to the array node (e.g. "data.prices"). Empty = root.
    path: []const u8 = "",
    /// Generic projection. When empty, falls back to the poc `[x,y]` default.
    columns: []const JsonCol = &.{},
    /// poc-compatible shorthand (only used when `columns` is empty).
    x: []const u8 = "",
    y: []const u8 = "",
};

/// Parse `bytes`, descend `spec.path` to an array, project each item to a row.
pub fn shape(a: std.mem.Allocator, bytes: []const u8, spec: ShapeSpec) Error!Dataset {
    const root = std.json.parseFromSliceLeaky(std.json.Value, a, bytes, .{}) catch return Error.BadJson;
    const node = descend(root, spec.path);
    const items: []const std.json.Value = switch (node) {
        .array => |arr| arr.items,
        else => &.{}, // not an array → empty dataset with the declared columns
    };

    if (spec.columns.len == 0) return shapeXY(a, items, spec);

    const cols = try a.alloc(Column, spec.columns.len);
    for (spec.columns, 0..) |jc, i| cols[i] = .{ .name = jc.name, .type = jc.type };

    const rows = try a.alloc([]const Value, items.len);
    for (items, 0..) |item, ri| {
        const row = try a.alloc(Value, spec.columns.len);
        for (spec.columns, 0..) |jc, ci| {
            const jv: ?std.json.Value = if (jc.key.len == 0) item else itemField(item, jc.key);
            row[ci] = if (jv) |v| try jsonToValue(a, v, jc.type) else .null;
        }
        rows[ri] = row;
    }
    return .{ .columns = cols, .rows = rows };
}

/// poc `[x,y]` default: 2 columns, one row per item.
fn shapeXY(a: std.mem.Allocator, items: []const std.json.Value, spec: ShapeSpec) Error!Dataset {
    const cols = try a.alloc(Column, 2);
    cols[0] = .{ .name = "x", .type = .text };
    cols[1] = .{ .name = "y", .type = .float };
    const rows = try a.alloc([]const Value, items.len);
    for (items, 0..) |item, ri| {
        const row = try a.alloc(Value, 2);
        const xv: ?std.json.Value, const yv: ?std.json.Value = switch (item) {
            .object => .{
                if (spec.x.len > 0) itemField(item, spec.x) else null,
                if (spec.y.len > 0) itemField(item, spec.y) else null,
            },
            .array => |arr| .{
                if (arr.items.len > 0) arr.items[0] else null,
                if (arr.items.len > 1) arr.items[1] else null,
            },
            else => .{ null, item }, // scalar → [index, item]
        };
        row[0] = if (xv) |v| try jsonToValue(a, v, .text) else .{ .int = @intCast(ri) };
        row[1] = if (yv) |v| try jsonToValue(a, v, .float) else .null;
        rows[ri] = row;
    }
    return .{ .columns = cols, .rows = rows };
}

fn descend(root: std.json.Value, path: []const u8) std.json.Value {
    if (path.len == 0) return root;
    var node = root;
    var it = std.mem.splitScalar(u8, path, '.');
    while (it.next()) |seg| {
        if (seg.len == 0) continue;
        node = switch (node) {
            .object => |o| o.get(seg) orelse return .null,
            else => return .null,
        };
    }
    return node;
}

fn itemField(item: std.json.Value, key: []const u8) ?std.json.Value {
    return switch (item) {
        .object => |o| o.get(key),
        else => null,
    };
}

/// Coerce a JSON value into a canonical Value honoring `want` (the column type).
fn jsonToValue(a: std.mem.Allocator, jv: std.json.Value, want: ColumnType) Error!Value {
    return switch (want) {
        .int => .{ .int = jsonToInt(jv) orelse return .null },
        .float => .{ .float = jsonToFloat(jv) orelse return .null },
        .bool => switch (jv) {
            .bool => |b| .{ .bool = b },
            else => .null,
        },
        .text, .date => switch (jv) {
            .string => |s| .{ .text = s }, // borrows arena-backed parse tree
            .number_string => |s| .{ .text = s },
            .integer => |i| .{ .text = try std.fmt.allocPrint(a, "{d}", .{i}) },
            .float => |f| .{ .text = try std.fmt.allocPrint(a, "{d}", .{f}) },
            .bool => |b| .{ .text = if (b) "true" else "false" },
            else => .null,
        },
    };
}

fn jsonToFloat(jv: std.json.Value) ?f64 {
    return switch (jv) {
        .integer => |i| @floatFromInt(i),
        .float => |f| f,
        .number_string => |s| std.fmt.parseFloat(f64, s) catch null,
        .string => |s| std.fmt.parseFloat(f64, s) catch null,
        else => null,
    };
}

fn jsonToInt(jv: std.json.Value) ?i64 {
    return switch (jv) {
        .integer => |i| i,
        .float => |f| @intFromFloat(f),
        .number_string => |s| std.fmt.parseInt(i64, s, 10) catch null,
        .string => |s| std.fmt.parseInt(i64, s, 10) catch null,
        else => null,
    };
}

// ── tests ───────────────────────────────────────────────────────────────────
const testing = std.testing;

test "shape: dotpath + generic columns" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const json =
        \\{ "data": { "prices": [
        \\   { "d": "2024-01-01", "close": 100.5, "vol": 10 },
        \\   { "d": "2024-01-02", "close": 101, "vol": 20 }
        \\ ] } }
    ;
    const d = try shape(a, json, .{
        .path = "data.prices",
        .columns = &.{
            .{ .name = "date", .key = "d", .type = .date },
            .{ .name = "close", .key = "close", .type = .float },
            .{ .name = "vol", .key = "vol", .type = .int },
        },
    });
    try testing.expectEqual(@as(usize, 2), d.rows.len);
    try testing.expectEqualStrings("2024-01-01", d.cell(0, "date").?.text);
    try testing.expectEqual(@as(f64, 100.5), d.cell(0, "close").?.float);
    try testing.expectEqual(@as(f64, 101), d.cell(1, "close").?.float); // int coerced to float
    try testing.expectEqual(@as(i64, 20), d.cell(1, "vol").?.int);
}

test "shape: poc [x,y] default from object items" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const json =
        \\[ { "t": "2024-01-01", "v": 1.5 }, { "t": "2024-01-02", "v": 2.5 } ]
    ;
    const d = try shape(a, json, .{ .x = "t", .y = "v" });
    try testing.expectEqual(@as(usize, 2), d.columns.len);
    try testing.expectEqualStrings("x", d.columns[0].name);
    try testing.expectEqualStrings("2024-01-02", d.cell(1, "x").?.text);
    try testing.expectEqual(@as(f64, 1.5), d.cell(0, "y").?.float);
}

test "shape: [x,y] default from array items" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const d = try shape(a, "[[1, 10], [2, 20], [3, 30]]", .{});
    try testing.expectEqual(@as(usize, 3), d.rows.len);
    try testing.expectEqualStrings("2", d.cell(1, "x").?.text);
    try testing.expectEqual(@as(f64, 30), d.cell(2, "y").?.float);
}

test "shape: missing path node → empty dataset (not an error)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const d = try shape(a, "{\"a\":1}", .{ .path = "nope.array", .columns = &.{
        .{ .name = "v", .key = "v", .type = .float },
    } });
    try testing.expectEqual(@as(usize, 0), d.rows.len);
    try testing.expectEqual(@as(usize, 1), d.columns.len);
}

test "shape: malformed JSON → BadJson" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(Error.BadJson, shape(arena.allocator(), "{not json", .{}));
}
