// SPDX-License-Identifier: MIT
//! jsonshape — reshape JSON into a canonical `dataset`: path descent to
//! array item(s) + typed column projection (jq-style minimal subset — a
//! bounded JSONPath dialect, not the full JSONPath spec).
//!
//! Remote-feed shaping (`getDataview` / `dataviewGet`): resolve `spec.path`
//! to the item(s) to project, then project each item into columns. The path
//! is one of two auto-detected dialects: the original **legacy dot-path**
//! (a dot-separated chain of object-key lookups to one array node, e.g.
//! `"data.prices"`), or a **JSONPath subset** — object keys, array indices
//! (`a.b[2]`), wildcards (`a.b[*]`, `a.*`), recursive descent (`..name`),
//! and single-comparison filter expressions (`items[?(@.n > 5)]`). Projection
//! has two modes:
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

/// Parse `bytes`, resolve `spec.path` to array item(s), project each item to a row.
///
/// `spec.path` accepts two dialects:
///   * **legacy dot-path** (back-compat, unchanged semantics): a plain
///     dot-separated chain of object-key lookups to exactly one array node
///     (e.g. `"data.prices"`). A single non-array match → empty dataset.
///   * **JSONPath subset** (triggered by any of `[`, `*`, `?`, `..`, or a
///     leading `$`): array **indices** (`a.b[2]`), **wildcards** (`a.b[*]`,
///     `a.*`), **recursive descent** (`..name`), and **filter expressions**
///     (`a.b[?(@.field == "x")]`, ops `== != < <= > >=` against a number/
///     string/bool/null literal). May yield multiple matched nodes (e.g.
///     paginated arrays under a wildcard); each match contributes rows: an
///     `.array` match is flattened (its elements become items), any other
///     match becomes a single item itself.
pub fn shape(a: std.mem.Allocator, bytes: []const u8, spec: ShapeSpec) Error!Dataset {
    const root = std.json.parseFromSliceLeaky(std.json.Value, a, bytes, .{}) catch return Error.BadJson;
    const items = try resolveItems(a, root, spec.path);

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
        // `cols[0]` is declared `.text`, so the fallback index must be text
        // too. It used to be stored as `.int`, which made the column
        // heterogeneous and the declaration a lie: a consumer trusting the
        // declared type and reading `.text` panics on the union, and one
        // using `dataset.Value.asText()` silently gets null for exactly the
        // rows that took this branch. Found by mutation audit (1A).
        row[0] = if (xv) |v|
            try jsonToValue(a, v, .text)
        else
            .{ .text = try std.fmt.allocPrint(a, "{d}", .{ri}) };
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

// ── JSONPath subset (indices, wildcards, recursive descent, filters) ──────────
//
// `descend` above stays untouched and is the sole code path for legacy plain
// dot-paths, guaranteeing byte-identical back-compat. Any path using `[`,
// `*`, `?`, `..`, or a leading `$` routes through this richer engine instead.

/// Bounds recursive-descent (`..name`) and general segment-eval recursion so
/// a crafted path can't blow the stack on a deeply-nested document — a
/// document-shaped DoS is the only real "unbounded recursion" risk here
/// (filter predicates are single-level, no recursion of their own).
const MAX_PATH_DEPTH: u32 = 64;

const CmpOp = enum { eq, ne, lt, le, gt, ge };

const FilterLit = union(enum) {
    number: f64,
    string: []const u8,
    boolean: bool,
    is_null,
};

const Filter = struct {
    field: []const u8,
    op: CmpOp,
    lit: FilterLit,
};

const Seg = union(enum) {
    key: []const u8,
    index: usize,
    wildcard,
    recursive: []const u8,
    filter: Filter,
    /// A syntactically-invalid segment: matches nothing, but doesn't fail
    /// the whole shape() call — same "degrade, don't error" philosophy as
    /// the rest of this module (only malformed *JSON* raises Error.BadJson).
    never,
};

fn isLegacyPath(path: []const u8) bool {
    if (path.len > 0 and path[0] == '$') return false;
    for (path) |c| {
        if (c == '[' or c == '*' or c == '?') return false;
    }
    if (std.mem.indexOf(u8, path, "..") != null) return false;
    return true;
}

/// Resolve `path` to the item list rows get projected from. Legacy dot-paths
/// go through `descend` unchanged; anything else through the segment engine,
/// flattening `.array` matches (their elements become items) and treating
/// any other match as a single item itself.
fn resolveItems(a: std.mem.Allocator, root: std.json.Value, path: []const u8) Error![]const std.json.Value {
    if (isLegacyPath(path)) {
        const node = descend(root, path);
        return switch (node) {
            .array => |arr| arr.items,
            else => &.{}, // not an array → empty dataset with the declared columns
        };
    }

    const segs = try parsePath(a, path);
    var matches: std.ArrayList(std.json.Value) = .empty;
    try evalSegs(a, root, segs, &matches, 0);

    var items: std.ArrayList(std.json.Value) = .empty;
    for (matches.items) |m| {
        switch (m) {
            .array => |arr| try items.appendSlice(a, arr.items),
            else => try items.append(a, m),
        }
    }
    return try items.toOwnedSlice(a);
}

/// Tokenize `path` into segments. Never fails on bad syntax — an
/// unparseable index/filter/name becomes `.never` (matches nothing) so a
/// malformed path degrades to an empty dataset like everything else here.
fn parsePath(a: std.mem.Allocator, path: []const u8) Error![]Seg {
    var segs: std.ArrayList(Seg) = .empty;
    var i: usize = 0;
    if (path.len > 0 and path[0] == '$') i = 1;

    while (i < path.len) {
        switch (path[i]) {
            '.' => {
                i += 1;
                if (i < path.len and path[i] == '.') {
                    i += 1;
                    const start = i;
                    while (i < path.len and path[i] != '.' and path[i] != '[') i += 1;
                    const name = path[start..i];
                    if (name.len == 0) {
                        try segs.append(a, .never);
                    } else {
                        try segs.append(a, .{ .recursive = name });
                    }
                } else {
                    const start = i;
                    while (i < path.len and path[i] != '.' and path[i] != '[') i += 1;
                    const name = path[start..i];
                    if (name.len == 0) continue; // tolerate stray/doubled '.' like legacy descend
                    if (std.mem.eql(u8, name, "*")) {
                        try segs.append(a, .wildcard);
                    } else {
                        try segs.append(a, .{ .key = name });
                    }
                }
            },
            '[' => {
                i += 1;
                const start = i;
                while (i < path.len and path[i] != ']') i += 1;
                if (i >= path.len) {
                    try segs.append(a, .never);
                    break; // unterminated '[' — nothing sensible follows
                }
                const inner = path[start..i];
                i += 1; // skip ']'
                if (inner.len == 0) {
                    try segs.append(a, .never);
                } else if (std.mem.eql(u8, inner, "*")) {
                    try segs.append(a, .wildcard);
                } else if (inner[0] == '?') {
                    if (parseFilter(inner[1..])) |f| {
                        try segs.append(a, .{ .filter = f });
                    } else {
                        try segs.append(a, .never);
                    }
                } else {
                    const idx: ?usize = std.fmt.parseInt(usize, inner, 10) catch null;
                    if (idx) |v| {
                        try segs.append(a, .{ .index = v });
                    } else {
                        try segs.append(a, .never);
                    }
                }
            },
            else => {
                const start = i;
                while (i < path.len and path[i] != '.' and path[i] != '[') i += 1;
                const name = path[start..i];
                if (name.len > 0) {
                    if (std.mem.eql(u8, name, "*")) {
                        try segs.append(a, .wildcard);
                    } else {
                        try segs.append(a, .{ .key = name });
                    }
                }
            },
        }
    }
    return try segs.toOwnedSlice(a);
}

fn evalSegs(a: std.mem.Allocator, node: std.json.Value, segs: []const Seg, out: *std.ArrayList(std.json.Value), depth: u32) Error!void {
    if (depth > MAX_PATH_DEPTH) return;
    if (segs.len == 0) {
        try out.append(a, node);
        return;
    }
    const seg = segs[0];
    const rest = segs[1..];
    switch (seg) {
        .never => {},
        .key => |k| switch (node) {
            .object => |o| if (o.get(k)) |v| try evalSegs(a, v, rest, out, depth + 1),
            else => {},
        },
        .index => |idx| switch (node) {
            .array => |arr| if (idx < arr.items.len) try evalSegs(a, arr.items[idx], rest, out, depth + 1),
            else => {},
        },
        .wildcard => switch (node) {
            .array => |arr| for (arr.items) |it| try evalSegs(a, it, rest, out, depth + 1),
            .object => |o| for (o.values()) |v| try evalSegs(a, v, rest, out, depth + 1),
            else => {},
        },
        .recursive => |name| try recursiveFind(a, node, name, rest, out, depth),
        .filter => |f| switch (node) {
            .array => |arr| for (arr.items) |it| {
                if (matchFilter(it, f)) try evalSegs(a, it, rest, out, depth + 1);
            },
            else => {},
        },
    }
}

/// Depth-first search for every object field named `name`, anywhere under
/// `node` (any nesting) — the `..name` recursive-descent operator.
fn recursiveFind(a: std.mem.Allocator, node: std.json.Value, name: []const u8, rest: []const Seg, out: *std.ArrayList(std.json.Value), depth: u32) Error!void {
    if (depth > MAX_PATH_DEPTH) return;
    switch (node) {
        .object => |o| {
            if (o.get(name)) |v| try evalSegs(a, v, rest, out, depth + 1);
            for (o.values()) |v| try recursiveFind(a, v, name, rest, out, depth + 1);
        },
        .array => |arr| for (arr.items) |it| try recursiveFind(a, it, name, rest, out, depth + 1),
        else => {},
    }
}

/// Parse a bounded `[?( @.field OP literal )]` predicate body (the `?` is
/// already stripped by the caller). One field, one comparison, one literal
/// — no boolean composition, no nesting. `OP` is one of `== != < <= > >=`;
/// `literal` is a quoted string, `true`/`false`, `null`, or a number.
fn parseFilter(raw: []const u8) ?Filter {
    var s = std.mem.trim(u8, raw, " \t");
    if (s.len >= 2 and s[0] == '(' and s[s.len - 1] == ')') {
        s = std.mem.trim(u8, s[1 .. s.len - 1], " \t");
    }
    if (!std.mem.startsWith(u8, s, "@.")) return null;
    s = s[2..];

    var fi: usize = 0;
    while (fi < s.len and isFieldChar(s[fi])) fi += 1;
    const field = s[0..fi];
    if (field.len == 0) return null;
    var rest = std.mem.trim(u8, s[fi..], " \t");

    const Op = struct { txt: []const u8, op: CmpOp };
    const ops = [_]Op{
        .{ .txt = "==", .op = .eq },
        .{ .txt = "!=", .op = .ne },
        .{ .txt = "<=", .op = .le },
        .{ .txt = ">=", .op = .ge },
        .{ .txt = "<", .op = .lt },
        .{ .txt = ">", .op = .gt },
    };
    var matched_op: ?CmpOp = null;
    for (ops) |o| {
        if (std.mem.startsWith(u8, rest, o.txt)) {
            matched_op = o.op;
            rest = std.mem.trim(u8, rest[o.txt.len..], " \t");
            break;
        }
    }
    const op = matched_op orelse return null;
    if (rest.len == 0) return null;

    const lit: FilterLit = blk: {
        if (rest[0] == '"' or rest[0] == '\'') {
            const quote = rest[0];
            if (rest.len < 2 or rest[rest.len - 1] != quote) return null;
            break :blk .{ .string = rest[1 .. rest.len - 1] };
        } else if (std.mem.eql(u8, rest, "true")) {
            break :blk .{ .boolean = true };
        } else if (std.mem.eql(u8, rest, "false")) {
            break :blk .{ .boolean = false };
        } else if (std.mem.eql(u8, rest, "null")) {
            break :blk .is_null;
        } else {
            const n = std.fmt.parseFloat(f64, rest) catch return null;
            break :blk .{ .number = n };
        }
    };
    return .{ .field = field, .op = op, .lit = lit };
}

fn isFieldChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_' or c == '-';
}

fn matchFilter(item: std.json.Value, f: Filter) bool {
    const fv = itemField(item, f.field) orelse return false;
    return switch (f.lit) {
        .number => |n| cmpNumber(fv, f.op, n),
        .string => |s| cmpString(fv, f.op, s),
        .boolean => |b| cmpBool(fv, f.op, b),
        .is_null => cmpNull(fv, f.op),
    };
}

fn cmpNumber(fv: std.json.Value, op: CmpOp, n: f64) bool {
    const v: f64 = switch (fv) {
        .integer => |i| @floatFromInt(i),
        .float => |fl| fl,
        .number_string => |s| std.fmt.parseFloat(f64, s) catch return false,
        else => return false,
    };
    return switch (op) {
        .eq => v == n,
        .ne => v != n,
        .lt => v < n,
        .le => v <= n,
        .gt => v > n,
        .ge => v >= n,
    };
}

fn cmpString(fv: std.json.Value, op: CmpOp, s: []const u8) bool {
    const v: []const u8 = switch (fv) {
        .string => |vs| vs,
        .number_string => |vs| vs,
        else => return false,
    };
    const order = std.mem.order(u8, v, s);
    return switch (op) {
        .eq => order == .eq,
        .ne => order != .eq,
        .lt => order == .lt,
        .le => order != .gt,
        .gt => order == .gt,
        .ge => order != .lt,
    };
}

fn cmpBool(fv: std.json.Value, op: CmpOp, b: bool) bool {
    return switch (fv) {
        .bool => |vb| switch (op) {
            .eq => vb == b,
            .ne => vb != b,
            else => false,
        },
        else => false,
    };
}

fn cmpNull(fv: std.json.Value, op: CmpOp) bool {
    const is_null = switch (fv) {
        .null => true,
        else => false,
    };
    return switch (op) {
        .eq => is_null,
        .ne => !is_null,
        else => false,
    };
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
        // JSON has no fixed-point type; go through the same numeric parse as
        // .float, then widen via Value.cast (float*scale, truncated — see
        // dataset's Value.cast doc comment). No dependency on the `decimal`
        // module for text parsing here (same limitation `Value.cast` documents).
        .decimal => blk: {
            const f = jsonToFloat(jv) orelse break :blk .null;
            break :blk (Value{ .float = f }).cast(.decimal) orelse .null;
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

test "shape: a missing intermediate segment fails the whole path — a sibling key of the SAME name is not picked up" {
    // Audit F1. The `orelse return .null` in `descend` must abandon the walk at
    // the FIRST missing segment. The existing "missing path" test above cannot
    // see this: mutate that line to `orelse node` (silently stay put) and its
    // `{"a":1}` / `"nope.array"` case still lands on a non-array node, so it
    // still passes. The decoy here is the point — the root object also carries
    // an `"array"` key, so a `descend` that skips the missing `"nope"` segment
    // instead of failing walks straight into the SIBLING and returns rows that
    // the requested path does not name at all.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const json =
        \\{"a":1,"array":[{"v":7},{"v":8}]}
    ;
    const d = try shape(a, json, .{ .path = "nope.array", .columns = &.{
        .{ .name = "v", .key = "v", .type = .float },
    } });
    try testing.expectEqual(@as(usize, 0), d.rows.len);

    // Control: the same document at the path that DOES exist yields the rows,
    // so the assertion above is about the missing segment and not about the
    // fixture being unreadable.
    const ok = try shape(a, json, .{ .path = "array", .columns = &.{
        .{ .name = "v", .key = "v", .type = .float },
    } });
    try testing.expectEqual(@as(usize, 2), ok.rows.len);
    try testing.expectEqual(@as(f64, 7), ok.cell(0, "v").?.float);

    // The same trap one level deeper: a missing FINAL segment must not resolve
    // to the object it was looked up in.
    const deep = try shape(a, "{\"outer\":{\"a\":1,\"array\":[{\"v\":9}]}}", .{ .path = "outer.nope.array", .columns = &.{
        .{ .name = "v", .key = "v", .type = .float },
    } });
    try testing.expectEqual(@as(usize, 0), deep.rows.len);
}

test "shape: malformed JSON → BadJson" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(Error.BadJson, shape(arena.allocator(), "{not json", .{}));
}

test "shape: back-compat — existing legacy dot-path resolves identically" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const json =
        \\{ "data": { "prices": [
        \\   { "d": "2024-01-01", "close": 100.5, "vol": 10 },
        \\   { "d": "2024-01-02", "close": 101, "vol": 20 }
        \\ ] } }
    ;
    // Same spec as the "dotpath + generic columns" test above — the path
    // contains none of `[ * ? ..` so it must route through the untouched
    // legacy `descend`, with byte-identical results before and after the
    // JSONPath-subset engine was added.
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
    try testing.expectEqual(@as(i64, 20), d.cell(1, "vol").?.int);
}

test "shape: JSONPath array index — a.b[2]" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const d = try shape(a, "{\"a\":{\"b\":[10,20,30,40]}}", .{
        .path = "a.b[2]",
        .columns = &.{.{ .name = "v", .type = .int }},
    });
    try testing.expectEqual(@as(usize, 1), d.rows.len);
    try testing.expectEqual(@as(i64, 30), d.cell(0, "v").?.int);
}

test "shape: JSONPath array wildcard — a.b[*]" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const json = "{\"a\":{\"b\":[{\"n\":1},{\"n\":2},{\"n\":3}]}}";
    const d = try shape(a, json, .{
        .path = "a.b[*]",
        .columns = &.{.{ .name = "n", .key = "n", .type = .int }},
    });
    try testing.expectEqual(@as(usize, 3), d.rows.len);
    try testing.expectEqual(@as(i64, 1), d.cell(0, "n").?.int);
    try testing.expectEqual(@as(i64, 2), d.cell(1, "n").?.int);
    try testing.expectEqual(@as(i64, 3), d.cell(2, "n").?.int);
}

test "shape: JSONPath object wildcard — a.*" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const d = try shape(a, "{\"a\":{\"x\":1,\"y\":2,\"z\":3}}", .{
        .path = "a.*",
        .columns = &.{.{ .name = "v", .type = .int }},
    });
    try testing.expectEqual(@as(usize, 3), d.rows.len);
    try testing.expectEqual(@as(i64, 1), d.cell(0, "v").?.int);
    try testing.expectEqual(@as(i64, 2), d.cell(1, "v").?.int);
    try testing.expectEqual(@as(i64, 3), d.cell(2, "v").?.int);
}

test "shape: JSONPath recursive descent — ..name" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const json =
        \\{ "a": { "name": "top", "b": { "name": "nested1", "c": [
        \\   { "name": "deep1" }, { "other": 1 }
        \\ ] } } }
    ;
    const d = try shape(a, json, .{
        .path = "..name",
        .columns = &.{.{ .name = "v", .type = .text }},
    });
    try testing.expectEqual(@as(usize, 3), d.rows.len);
    try testing.expectEqualStrings("top", d.cell(0, "v").?.text);
    try testing.expectEqualStrings("nested1", d.cell(1, "v").?.text);
    try testing.expectEqualStrings("deep1", d.cell(2, "v").?.text);
}

test "shape: JSONPath multiple array nodes concatenate — pages[*].items" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const json = "{\"pages\":[{\"items\":[1,2]},{\"items\":[3,4,5]}]}";
    const d = try shape(a, json, .{
        .path = "pages[*].items",
        .columns = &.{.{ .name = "v", .type = .int }},
    });
    try testing.expectEqual(@as(usize, 5), d.rows.len);
    try testing.expectEqual(@as(i64, 1), d.cell(0, "v").?.int);
    try testing.expectEqual(@as(i64, 5), d.cell(4, "v").?.int);
}

test "shape: filter expression selects exactly the matching elements" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const json =
        \\{ "list": [
        \\  { "id": 1, "status": "ok" },
        \\  { "id": 2, "status": "bad" },
        \\  { "id": 3, "status": "ok" }
        \\ ] }
    ;
    const d = try shape(a, json, .{
        .path = "list[?(@.status == \"ok\")]",
        .columns = &.{
            .{ .name = "id", .key = "id", .type = .int },
            .{ .name = "status", .key = "status", .type = .text },
        },
    });
    try testing.expectEqual(@as(usize, 2), d.rows.len);
    try testing.expectEqual(@as(i64, 1), d.cell(0, "id").?.int);
    try testing.expectEqual(@as(i64, 3), d.cell(1, "id").?.int);
    // Positive control: id=2 ("bad") must be excluded, not merely
    // deprioritized — assert it's gone from every row.
    for (0..d.rows.len) |ri| {
        try testing.expect(d.cell(ri, "id").?.int != 2);
    }
}

test "shape: numeric filter operators (>, no spaces around op)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const d = try shape(a, "{\"arr\":[{\"n\":1},{\"n\":10},{\"n\":5}]}", .{
        .path = "arr[?(@.n>5)]",
        .columns = &.{.{ .name = "n", .key = "n", .type = .int }},
    });
    try testing.expectEqual(@as(usize, 1), d.rows.len);
    try testing.expectEqual(@as(i64, 10), d.cell(0, "n").?.int);
}

test "shape: numeric filter operators — ne, lt, le, ge (all previously untested)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const json = "{\"arr\":[{\"n\":1},{\"n\":5},{\"n\":10}]}";

    const ne = try shape(a, json, .{ .path = "arr[?(@.n != 5)]", .columns = &.{.{ .name = "n", .key = "n", .type = .int }} });
    try testing.expectEqual(@as(usize, 2), ne.rows.len);

    const lt = try shape(a, json, .{ .path = "arr[?(@.n < 5)]", .columns = &.{.{ .name = "n", .key = "n", .type = .int }} });
    try testing.expectEqual(@as(usize, 1), lt.rows.len);
    try testing.expectEqual(@as(i64, 1), lt.cell(0, "n").?.int);

    const le = try shape(a, json, .{ .path = "arr[?(@.n <= 5)]", .columns = &.{.{ .name = "n", .key = "n", .type = .int }} });
    try testing.expectEqual(@as(usize, 2), le.rows.len);

    // `>=` — distinguishes from `>`: 5 must be INCLUDED here.
    const ge = try shape(a, json, .{ .path = "arr[?(@.n >= 5)]", .columns = &.{.{ .name = "n", .key = "n", .type = .int }} });
    try testing.expectEqual(@as(usize, 2), ge.rows.len);
    try testing.expectEqual(@as(i64, 5), ge.cell(0, "n").?.int);
    try testing.expectEqual(@as(i64, 10), ge.cell(1, "n").?.int);
}

test "shape: string filter operators — ne, lt, le, gt, ge (all previously untested)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const json = "{\"arr\":[{\"s\":\"a\"},{\"s\":\"b\"},{\"s\":\"c\"}]}";

    const ne = try shape(a, json, .{ .path = "arr[?(@.s != \"b\")]", .columns = &.{.{ .name = "s", .key = "s", .type = .text }} });
    try testing.expectEqual(@as(usize, 2), ne.rows.len);

    const lt = try shape(a, json, .{ .path = "arr[?(@.s < \"b\")]", .columns = &.{.{ .name = "s", .key = "s", .type = .text }} });
    try testing.expectEqual(@as(usize, 1), lt.rows.len);
    try testing.expectEqualStrings("a", lt.cell(0, "s").?.text);

    const gt = try shape(a, json, .{ .path = "arr[?(@.s > \"b\")]", .columns = &.{.{ .name = "s", .key = "s", .type = .text }} });
    try testing.expectEqual(@as(usize, 1), gt.rows.len);
    try testing.expectEqualStrings("c", gt.cell(0, "s").?.text);

    // `<=` / `>=` must include the boundary "b", distinguishing them from `<`/`>`.
    const le = try shape(a, json, .{ .path = "arr[?(@.s <= \"b\")]", .columns = &.{.{ .name = "s", .key = "s", .type = .text }} });
    try testing.expectEqual(@as(usize, 2), le.rows.len);

    const ge = try shape(a, json, .{ .path = "arr[?(@.s >= \"b\")]", .columns = &.{.{ .name = "s", .key = "s", .type = .text }} });
    try testing.expectEqual(@as(usize, 2), ge.rows.len);
}

test "shape: boolean and null filter literals (cmpBool/cmpNull were entirely dead code)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const json =
        \\{ "arr": [
        \\  { "id": 1, "active": true },
        \\  { "id": 2, "active": false },
        \\  { "id": 3, "note": null }
        \\ ] }
    ;

    const eq_true = try shape(a, json, .{ .path = "arr[?(@.active == true)]", .columns = &.{.{ .name = "id", .key = "id", .type = .int }} });
    try testing.expectEqual(@as(usize, 1), eq_true.rows.len);
    try testing.expectEqual(@as(i64, 1), eq_true.cell(0, "id").?.int);

    const ne_true = try shape(a, json, .{ .path = "arr[?(@.active != true)]", .columns = &.{.{ .name = "id", .key = "id", .type = .int }} });
    try testing.expectEqual(@as(usize, 1), ne_true.rows.len);
    try testing.expectEqual(@as(i64, 2), ne_true.cell(0, "id").?.int);

    const is_null = try shape(a, json, .{ .path = "arr[?(@.note == null)]", .columns = &.{.{ .name = "id", .key = "id", .type = .int }} });
    try testing.expectEqual(@as(usize, 1), is_null.rows.len);
    try testing.expectEqual(@as(i64, 3), is_null.cell(0, "id").?.int);
}

test "shape: [x,y] default from a top-level array of bare scalars (else branch of shapeXY, untested)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const d = try shape(a, "[10, 20, 30]", .{});
    try testing.expectEqual(@as(usize, 3), d.rows.len);
    // scalar item → x = positional index, y = the scalar itself. The index is
    // TEXT: `cols[0]` declares `.text`, and this branch used to contradict it
    // by storing `.int` (fixed in the 1A audit — see `shapeXY`).
    try testing.expectEqualStrings("1", d.cell(1, "x").?.text);
    try testing.expectEqual(@as(f64, 20), d.cell(1, "y").?.float);
}

test "shape: stringified-number JSON values coerce through number_string/string paths (untested)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const json = "{\"arr\":[{\"n\":\"42\"}]}";
    const d = try shape(a, json, .{
        .path = "arr",
        .columns = &.{
            .{ .name = "as_int", .key = "n", .type = .int },
            .{ .name = "as_float", .key = "n", .type = .float },
        },
    });
    try testing.expectEqual(@as(usize, 1), d.rows.len);
    try testing.expectEqual(@as(i64, 42), d.cell(0, "as_int").?.int);
    try testing.expectEqual(@as(f64, 42), d.cell(0, "as_float").?.float);
}

test "shape: malformed JSONPath syntax → empty dataset, not a crash" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // Unterminated '[' — invalid syntax degrades to "no match", same
    // leniency contract as a missing key.
    const d = try shape(a, "{\"a\":[1,2,3]}", .{
        .path = "a[0",
        .columns = &.{.{ .name = "v", .type = .int }},
    });
    try testing.expectEqual(@as(usize, 0), d.rows.len);
}

test "shape: the x column honours its declared .text type on every branch" {
    // The declared type is the contract `dataset` consumers rely on. Before
    // this, the index fallback stored `.int` into a column declared `.text`,
    // so the two branches of the same column had different active union
    // fields — invisible to every test that only exercised the object branch.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // A top-level array of bare scalars takes the index fallback for x.
    const d = try shape(a, "[10, 20, 30]", .{});
    try testing.expectEqual(ColumnType.text, d.columns[0].type);
    try testing.expectEqual(@as(usize, 3), d.rows.len);
    for (d.rows, 0..) |row, i| {
        // `.asText()` must answer for EVERY row, not just the ones that
        // happened to come from an object.
        const got = row[0].asText() orelse return error.XColumnNotText;
        var buf: [8]u8 = undefined;
        try testing.expectEqualStrings(try std.fmt.bufPrint(&buf, "{d}", .{i}), got);
    }
}
