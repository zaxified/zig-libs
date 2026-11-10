// SPDX-License-Identifier: MIT
//! Replays `oracle2j_vectors.json` (dataframe S2 wave W11, real dtype widths) for the kinds the
//! verbs of part B own: `join` (a key of one width against a key of another), `unique` (the
//! distinct values of two columns stacked), `sort` and `group_by` (a UInt64 key above 2^63) and
//! `repr` (the dtype names and cell text of a rendered frame). The polars cases only; pandas'
//! answers agree where the module follows pandas and are written in the SPEC. Part A replays the
//! arithmetic kinds, the core `cast`, `read` and `write` (`s2w11_oracle_test.zig`).
const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const vm = @import("value.zig");
const fm = @import("frame.zig");
const dtype = @import("dtype.zig");
const Frame = fm.Frame;
const Column = vm.Column;
const ColumnType = vm.ColumnType;
const Value = vm.Value;
const J = std.json.Value;

const vectors = @embedFile("oracle2j_vectors.json");

/// Deliberate differences from what polars answered: id substring, the input cell (null: all
/// cells of the case) and why.
const Known = struct { id: []const u8, cell: ?[]const u8 = null, why: []const u8 };
const known = [_]Known{
    .{ .id = "key-join-i32-f64", .why = "polars refuses to join Int32 with Float64 keys (SchemaError); this module joins by exact value across numeric types (D10, a superset: 1 joins 1.0 and 2.5 joins nothing)" },
    .{ .id = "key-join-u64-f64", .why = "as key-join-i32-f64: polars refuses UInt64 with Float64, this module joins by exact value" },
    .{ .id = "key-join-i64-f64", .why = "as key-join-i32-f64: polars refuses Int64 with Float64, this module joins by exact value" },
    .{ .id = "key-concat-unique-u64-i64", .why = "polars stacks UInt64 and Int64 into Int128, which this module does not have: they meet in Float64 (D5), the values the same (2^63 is exact in a double)" },
    .{ .id = "repr-str", .why = "the dtype row of `format` (`show_dtypes`) names a text column by its type tag, `text`; polars writes `str`. The tag names of Int64 and Float64 (`int`, `float`) stay as before W11; the widths read `i8`..`u64`, `f32`" },
    .{ .id = "repr-bool", .why = "this module renders a bool as `True`/`False` (pandas' form, its `format` rule before W11); polars prints `true`/`false`" },
};

fn knownCell(id: []const u8, cell: ?[]const u8) bool {
    _ = cell;
    for (known) |k| if (std.mem.find(u8, id, k.id) != null) return true;
    return false;
}

fn typeOf(name: []const u8) ?ColumnType {
    const map = [_]struct { []const u8, ColumnType }{
        .{ "i8", .int8 },     .{ "i16", .int16 },  .{ "i32", .int32 },  .{ "i64", .int },
        .{ "u8", .uint8 },    .{ "u16", .uint16 }, .{ "u32", .uint32 }, .{ "u64", .uint64 },
        .{ "f32", .float32 }, .{ "f64", .float },  .{ "str", .text },   .{ "bool", .bool },
    };
    for (map) |m| if (std.mem.eql(u8, m[0], name)) return m[1];
    return null;
}

fn strOf(o: J, k: []const u8) []const u8 {
    return o.object.get(k).?.string;
}

/// A cell of the vectors: an integer (a u64 above `maxInt(i64)` comes as a number string),
/// a float, "nan"/"inf"/"-inf" in a float column, text, null.
fn jcell(j: J, ty: ColumnType) Value {
    return switch (j) {
        .null => .null,
        .bool => |b| .{ .bool = b },
        .integer => |i| if (dtype.isFloat(ty)) .{ .float = @floatFromInt(i) } else .{ .int = i },
        .float => |x| .{ .float = x },
        .number_string => |s| dtype.intValue(std.fmt.parseInt(i128, s, 10) catch unreachable).?, // the oracle writes only integers so
        .string => |s| if (dtype.isFloat(ty)) .{ .float = std.fmt.parseFloat(f64, s) catch unreachable } else .{ .text = s },
        else => unreachable, // the oracle writes no other cell
    };
}

fn cellText(a: std.mem.Allocator, j: J) []const u8 {
    return switch (j) {
        .string => |s| s,
        .integer => |i| a.print("{d}", .{i}) catch "?",
        .float => |x| a.print("{d}", .{x}) catch "?",
        .number_string => |s| s,
        .null => "null",
        else => "?",
    };
}

fn isErr(j: J) bool {
    return j == .object and j.object.get("error") != null;
}

fn frameOf(a: std.mem.Allocator, name: []const u8, ty: ColumnType, vals: []const J) !Frame {
    const cols = try a.alloc(Column, 1);
    cols[0] = .{ .name = name, .type = ty };
    var b = try fm.FrameBuilder.init(a, cols, vals.len);
    for (vals) |j| try b.appendRow(&.{jcell(j, ty)});
    return b.toOwned();
}

/// Whether `got` is the expected cell `want` of a column of `ty`: exact, NaN equal to NaN,
/// a Float32 cell by its f32 bits (`bits`, when the oracle wrote them).
fn same(want: J, got: Value, ty: ColumnType, bits: ?[]const u8) bool {
    if (want == .null) return got == .null;
    if (got == .null) return false;
    if (dtype.isFloat(ty)) {
        const g = got.asFloat() orelse return false;
        if (bits) |b| {
            const w = std.fmt.parseInt(u32, b[2..], 16) catch return false;
            const gf: f32 = @floatCast(g);
            const gb: u32 = @bitCast(gf);
            return gb == w or (std.math.isNan(gf) and std.math.isNan(@as(f32, @bitCast(w))));
        }
        const w = jcell(want, ty).asFloat() orelse return false;
        if (std.math.isNan(w)) return std.math.isNan(g);
        return @as(u64, @bitCast(w)) == @as(u64, @bitCast(g));
    }
    const w = jcell(want, ty);
    return w.eql(got) and std.meta.activeTag(w) == std.meta.activeTag(got);
}

const Tally = struct {
    run: usize = 0,
    bad: usize = 0,
    known: usize = 0,
    out: std.Io.Writer.Allocating,

    fn miss(t: *Tally, id: []const u8, comptime fmt: []const u8, args: anytype) void {
        if (knownCell(id, null)) {
            t.known += 1;
            return;
        }
        t.bad += 1;
        if (t.bad <= 200) t.out.writer.print("{s}: " ++ fmt ++ "\n", .{id} ++ args) catch {};
    }
};

fn colOf(c: J, name: []const u8) J {
    return c.object.get("in").?.object.get(name).?;
}

fn framePair(a: std.mem.Allocator, k: J, kname: []const u8, v: J, vname: []const u8) !Frame {
    const kt = typeOf(strOf(k, "dtype")).?;
    const vt = typeOf(strOf(v, "dtype")).?;
    const kv = k.object.get("values").?.array.items;
    const vv = v.object.get("values").?.array.items;
    const cols = try a.dupe(Column, &.{ .{ .name = kname, .type = kt }, .{ .name = vname, .type = vt } });
    var b = try fm.FrameBuilder.init(a, cols, kv.len);
    for (kv, vv) |x, y| try b.appendRow(&.{ jcell(x, kt), jcell(y, vt) });
    return b.toOwned();
}

fn replayJoin(a: std.mem.Allocator, c: J, t: *Tally) !void {
    const id = strOf(c, "id");
    if (!std.mem.eql(u8, strOf(c, "op"), "inner_join_rows_v_w_k")) return;
    t.run += 1;
    const left = try framePair(a, colOf(c, "left_k"), "k", colOf(c, "left_v"), "v");
    const right = try framePair(a, colOf(c, "right_k"), "k", colOf(c, "right_w"), "w");
    const r = df.join(a, left, right, .{ .on = "k", .how = .inner });
    if (isErr(c.object.get("expect").?) or c.object.get("error").?.bool) {
        if (r) |_| t.miss(id, "polars refused, the join answered", .{}) else |_| {}
        return;
    }
    const g = r catch |e| return t.miss(id, "{s}", .{@errorName(e)});
    if (!fm.widthsConform(g)) t.miss(id, "a width column does not hold its array", .{});
    const kt = typeOf(strOf(c, "dtype_out")).?;
    if (g.columnType("k").? != kt) t.miss(id, "key type {s}, polars {s}", .{ @tagName(g.columnType("k").?), strOf(c, "dtype_out") });
    const want = c.object.get("expect").?.array.items;
    if (g.len != want.len) return t.miss(id, "{d} rows, polars {d}", .{ g.len, want.len });
    for (want, 0..) |row, i| {
        const rows = row.array.items; // v, w, k
        const got = [3]Value{ g.cell(i, "v").?, g.cell(i, "w").?, g.cell(i, "k").? };
        const tys = [3]ColumnType{ .int, .int, kt };
        for (rows, got, tys, 0..) |wv, gv, ty, k| {
            if (!same(wv, gv, ty, null)) t.miss(id, "row {d} cell {d}: want {s}, got {any}", .{ i, k, cellText(a, wv), gv });
        }
    }
}

fn replayUnique(a: std.mem.Allocator, c: J, t: *Tally) !void {
    const id = strOf(c, "id");
    const op = strOf(c, "op");
    const is_values = std.mem.eql(u8, op, "concat_unique");
    if (!is_values and !std.mem.eql(u8, op, "concat_n_unique")) return;
    t.run += 1;
    const ja = colOf(c, "a");
    const jb = colOf(c, "b");
    const ta = typeOf(strOf(ja, "dtype")).?;
    const tb = typeOf(strOf(jb, "dtype")).?;
    // The two columns stacked in the supertype (what `concat` declares, D11), then `distinct`:
    // the keys compare by exact value across the widths.
    const st = dtype.supertype(ta, tb) orelse return t.miss(id, "no supertype of {s} and {s}", .{ @tagName(ta), @tagName(tb) });
    const cols = try a.dupe(Column, &.{.{ .name = "x", .type = st }});
    const va = ja.object.get("values").?.array.items;
    const vb = jb.object.get("values").?.array.items;
    var b = try fm.FrameBuilder.init(a, cols, va.len + vb.len);
    for (va) |x| try b.appendRow(&.{jcell(x, ta)});
    for (vb) |x| try b.appendRow(&.{jcell(x, tb)});
    const stacked = try b.toOwned();
    const u = try df.distinct(a, stacked, .{ .keys = &.{} });
    const want = c.object.get("expect").?.array.items;
    if (!is_values) {
        if (u.len != @as(usize, @intCast(want[0].integer))) t.miss(id, "{d} distinct, polars {d}", .{ u.len, want[0].integer });
        return;
    }
    if (!fm.widthsConform(u)) t.miss(id, "a width column does not hold its array", .{});
    const out_ty = typeOf(strOf(c, "dtype_out"));
    if (out_ty) |ot| if (ot != st) t.miss(id, "type {s}, polars {s}", .{ @tagName(st), strOf(c, "dtype_out") });
    if (out_ty == null) t.miss(id, "polars type {s}, this module {s}", .{ strOf(c, "dtype_out"), @tagName(st) });
    if (u.len != want.len) return t.miss(id, "{d} distinct, polars {d}", .{ u.len, want.len });
    for (want, 0..) |w, i| {
        const got = u.columnAt(0).get(i);
        const wf = jcell(w, st).asFloat().?;
        if (got.asFloat() == null or got.asFloat().? != wf) t.miss(id, "value {d}: want {s}, got {any}", .{ i, cellText(a, w), got });
    }
}

fn replaySort(a: std.mem.Allocator, c: J, t: *Tally) !void {
    const id = strOf(c, "id");
    const op = strOf(c, "op");
    const desc = std.mem.eql(u8, op, "sort_desc");
    if (!desc and !std.mem.eql(u8, op, "sort")) return;
    t.run += 1;
    const ja = colOf(c, "a");
    const ty = typeOf(strOf(ja, "dtype")).?;
    const f = try frameOf(a, "a", ty, ja.object.get("values").?.array.items);
    const g = try df.sort(a, f, .{ .key = "a", .dir = if (desc) .desc else .asc });
    if (!fm.widthsConform(g)) t.miss(id, "a width column does not hold its array", .{});
    const want = c.object.get("expect").?.array.items;
    for (want, 0..) |w, i| {
        if (!same(w, g.columnAt(0).get(i), ty, null)) t.miss(id, "row {d}: want {s}, got {any}", .{ i, cellText(a, w), g.columnAt(0).get(i) });
    }
}

fn replayGroupBy(a: std.mem.Allocator, c: J, t: *Tally) !void {
    const id = strOf(c, "id");
    if (!std.mem.eql(u8, strOf(c, "op"), "group_by_sum_len")) return;
    t.run += 1;
    const f = try framePair(a, colOf(c, "k"), "k", colOf(c, "v"), "v");
    const g = try df.aggregate(a, f, .{ .group_by = &.{"k"}, .aggs = &.{ .{ .src = "v", .out = "s", .func = .sum }, .{ .src = "v", .out = "n", .func = .size } } });
    const kt = typeOf(strOf(c, "dtype_out")).?;
    if (g.columnType("k").? != kt) t.miss(id, "key type {s}, polars {s}", .{ @tagName(g.columnType("k").?), strOf(c, "dtype_out") });
    const want = c.object.get("expect").?.array.items;
    if (g.len != want.len) return t.miss(id, "{d} groups, polars {d}", .{ g.len, want.len });
    for (want, 0..) |row, i| {
        const rows = row.array.items; // k, sum, len
        const got = [3]Value{ g.cell(i, "k").?, g.cell(i, "s").?, g.cell(i, "n").? };
        const tys = [3]ColumnType{ kt, .int, .int };
        for (rows, got, tys, 0..) |wv, gv, ty, k| {
            if (same(wv, gv, ty, null)) continue;
            t.miss(id, "group {d} cell {d}: want {s}, got {any}", .{ i, k, cellText(a, wv), gv });
        }
    }
}

/// polars' long dtype names (`dtype.parseName` of D1 is not in the core).
fn polarsTypeName(name: []const u8) ?ColumnType {
    const map = [_]struct { []const u8, ColumnType }{
        .{ "Int8", .int8 },       .{ "Int16", .int16 },   .{ "Int32", .int32 },   .{ "Int64", .int },
        .{ "UInt8", .uint8 },     .{ "UInt16", .uint16 }, .{ "UInt32", .uint32 }, .{ "UInt64", .uint64 },
        .{ "Float32", .float32 }, .{ "Float64", .float }, .{ "String", .text },   .{ "Boolean", .bool },
    };
    for (map) |m| if (std.mem.eql(u8, m[0], name)) return m[1];
    return null;
}

/// The text between the `│` of a polars table line.
fn cellOfLine(line: []const u8) []const u8 {
    return std.mem.trim(u8, std.mem.trim(u8, line, "\u{2502}"), " ");
}

fn replayRepr(a: std.mem.Allocator, c: J, t: *Tally) !void {
    const id = strOf(c, "id");
    if (!std.mem.eql(u8, strOf(c, "op"), "dtype_str_and_frame")) return;
    t.run += 1;
    const ja = colOf(c, "a");
    const ty = typeOf(strOf(ja, "dtype")) orelse return;
    const want = c.object.get("expect").?.array.items;
    // The dtype's long name parses back to the type, its short name is the label under the column.
    const parsed = polarsTypeName(want[0].string);
    if (parsed == null or parsed.? != ty) t.miss(id, "polars name {s} is {any}, the case says {s}", .{ want[0].string, parsed, @tagName(ty) });
    var lines = std.mem.splitScalar(u8, want[1].string, '\n');
    var label: []const u8 = "";
    var cell: []const u8 = "";
    var n: usize = 0;
    while (lines.next()) |l| : (n += 1) {
        if (n == 4) label = cellOfLine(l);
        if (n == 6) cell = cellOfLine(l);
    }
    if (!std.mem.eql(u8, label, dtype.name(ty))) t.miss(id, "short name {s}, polars {s}", .{ dtype.name(ty), label });
    const f = try frameOf(a, "x", ty, ja.object.get("values").?.array.items);
    const out = try df.format(a, f, .{ .show_dtypes = true });
    // Our table: header row, the dtype row, the cells; every token of it is separated by blanks.
    var has_label = false;
    var has_cell = false;
    var it = std.mem.tokenizeAny(u8, out, " \n");
    while (it.next()) |tok| {
        if (std.mem.eql(u8, tok, dtype.name(ty)) or (!dtype.isWidth(ty) and std.mem.eql(u8, tok, @tagName(ty)))) has_label = true;
        if (std.mem.eql(u8, tok, cell)) has_cell = true;
    }
    if (!has_label and dtype.isWidth(ty)) t.miss(id, "the dtype row of `format` lacks {s}: {f}", .{ dtype.name(ty), std.zig.fmtString(out) });
    if (!has_cell) t.miss(id, "the cell text {s} is not in {f}", .{ cell, std.zig.fmtString(out) });
}

test "W11B oracle: polars join, unique, sort, group_by and repr of the width types" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const doc = try std.json.parseFromSliceLeaky(J, a, vectors, .{});
    var t: Tally = .{ .out = .init(a) };
    var kinds: [5]usize = @splat(0);
    for (doc.array.items) |c| {
        if (!std.mem.eql(u8, strOf(c, "engine"), "pl")) continue;
        const kind = strOf(c, "kind");
        const before = t.run;
        if (std.mem.eql(u8, kind, "join")) try replayJoin(a, c, &t);
        if (std.mem.eql(u8, kind, "unique")) try replayUnique(a, c, &t);
        if (std.mem.eql(u8, kind, "sort")) try replaySort(a, c, &t);
        if (std.mem.eql(u8, kind, "group_by")) try replayGroupBy(a, c, &t);
        if (std.mem.eql(u8, kind, "repr")) try replayRepr(a, c, &t);
        for ([_][]const u8{ "join", "unique", "sort", "group_by", "repr" }, 0..) |k, i| {
            if (std.mem.eql(u8, kind, k)) kinds[i] += t.run - before;
        }
    }
    if (t.bad != 0) {
        std.debug.print("W11B oracle: {d} of {d} cases differ:\n{s}", .{ t.bad, t.run, t.out.written() });
        return error.TestUnexpectedResult;
    }
    // The polars cases of each kind (join 14, unique 4 + 4, sort 2, group_by 1, repr 12).
    try testing.expectEqual([5]usize{ 14, 8, 2, 1, 12 }, kinds);
    try testing.expect(t.known >= 1);
}
