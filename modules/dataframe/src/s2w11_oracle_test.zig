// SPDX-License-Identifier: MIT
//! Replays `oracle2j_vectors.json` (dataframe S2 wave W11, real dtype widths): what polars 2.1
//! and pandas 3.1 answered for Int8..UInt64 and Float32 (`tools/oracle2j.py` asked the engines;
//! no line of this module is consulted there). This file replays the polars cases of the kinds
//! the core of the wave owns: `cast` (strict, non-strict, wrap, f64 <-> f32), `read` (a declared
//! width in `readCsv`/`readJson`) and `write` (`writeCsv`, `writeJson`, `writeNdjson`).
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
    .{ .id = "cast-nonstrict-str-", .cell = " 7", .why = "polars' str -> int cast refuses a blank around the digits; `castValue` trims blanks and tabs (its rule since D1, shared with `readCsv`, which polars' own `read_csv` trims too)" },
    .{ .id = "cast-strict-str-", .cell = " 7", .why = "as cast-nonstrict-str: the blank is trimmed" },
    .{ .id = "cast-wrap-str-", .cell = " 7", .why = "as cast-nonstrict-str: the blank is trimmed" },
    .{ .id = "cast-nonstrict-str-", .cell = "1e3", .why = "polars refuses an exponent in a str -> int cast; `castValue` reads a whole number written with one (its rule since D1)" },
    .{ .id = "cast-strict-str-", .cell = "1e3", .why = "as cast-nonstrict-str: a whole number with an exponent is read" },
    .{ .id = "cast-wrap-str-", .cell = "1e3", .why = "as cast-nonstrict-str: a whole number with an exponent is read" },
    .{ .id = "cast-nonstrict-str-", .cell = "7.0", .why = "polars refuses `7.0` as an int; `castValue` reads a whole number with a zero fraction (its rule since D1)" },
    .{ .id = "cast-strict-str-", .cell = "7.0", .why = "as cast-nonstrict-str: a zero fraction is read" },
    .{ .id = "cast-wrap-str-", .cell = "7.0", .why = "as cast-nonstrict-str: a zero fraction is read" },
    .{ .id = "wr-csv-f", .cell = "nan", .why = "polars writes NaN as `NaN` in CSV; this module writes a NaN as the null text, its one rule for missing (D1)" },
    .{ .id = "wr-csv-", .cell = "null", .why = "a null in a one-column CSV is written `\"\"` (pandas' form: a blank line is a skipped line to every reader, polars' own included); polars writes the blank line. Checked by the CSV writer's own tests" },
    .{ .id = "cast-", .cell = "nan", .why = "NaN is missing here, the module's one rule: `castValue` gives null for it, so a strict cast does not refuse it and a float cast keeps it null (polars keeps NaN, and refuses it to an int)" },
    .{ .id = "f32-f64_to_f32", .cell = "nan", .why = "as cast-: NaN is missing, the cast gives null" },
    .{ .id = "rd-json-", .why = "polars' `read_json` with a schema casts each value leniently (out of range null, `1.0` and `true` 1, a quoted `\"5\"` refused); `readJson` reads a cell as `readCsv` reads the same text, its documented rule before W11 (the Int64 and Float64 cases differ the same way): out of range or not an integer's text is `error.BadValue`, as polars' `read_csv` answers" },
    .{ .id = "-str-u", .cell = "-0", .why = "`-0` is the integer 0, which an unsigned type holds; polars refuses the sign" },
};

fn knownCell(id: []const u8, cell: ?[]const u8) bool {
    for (known) |k| {
        if (std.mem.find(u8, id, k.id) == null) continue;
        if (k.cell == null) return true;
        if (cell) |c| if (std.mem.eql(u8, c, k.cell.?)) return true;
    }
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
    out: std.Io.Writer.Allocating,

    fn miss(t: *Tally, comptime fmt: []const u8, args: anytype) void {
        t.bad += 1;
        if (t.bad <= 200) t.out.writer.print(fmt ++ "\n", args) catch {};
    }
};

fn castOp(op: []const u8) ?@FieldType(df.CastSpec, "on_error") {
    if (std.mem.eql(u8, op, "strict")) return .fail;
    if (std.mem.eql(u8, op, "nonstrict") or std.mem.eql(u8, op, "f64_to_f32") or std.mem.eql(u8, op, "f32_to_f64")) return .null;
    if (std.mem.eql(u8, op, "wrap")) return .wrap;
    return null;
}

fn replayCast(a: std.mem.Allocator, c: J, t: *Tally) !void {
    const id = strOf(c, "id");
    const on_error = castOp(strOf(c, "op")) orelse return;
    const input = c.object.get("in").?.object.get("a").?;
    const from = typeOf(strOf(input, "dtype")) orelse return;
    const to = typeOf(strOf(c, "dtype_out")) orelse return;
    const vals = input.object.get("values").?.array.items;
    const want = c.object.get("expect").?.array.items;
    const bits = if (c.object.get("bits")) |b| b.array.items else &[_]J{};
    // A strict case: each cell alone, so one refused cell does not hide the others.
    for (vals, want, 0..) |v, w, i| {
        t.run += 1;
        const f = try frameOf(a, "a", from, &.{v});
        const r = df.cast(a, f, .{ .col = "a", .to = to, .on_error = on_error });
        const cell_txt = cellText(a, v);
        if (isErr(w)) {
            if (r) |g| {
                if (on_error == .fail or g.columnAt(0).get(0) != .null) {
                    if (!knownCell(id, cell_txt)) t.miss("{s} [{s}]: polars refused, got {any}", .{ id, cell_txt, g.columnAt(0).get(0) });
                }
            } else |_| {}
            continue;
        }
        const g = r catch |e| {
            if (!knownCell(id, cell_txt)) t.miss("{s} [{s}]: {s}", .{ id, cell_txt, @errorName(e) });
            continue;
        };
        if (!fm.widthsConform(g)) t.miss("{s}: storage {s} under {s}", .{ id, @tagName(std.meta.activeTag(g.columnAt(0))), @tagName(to) });
        const b: ?[]const u8 = if (i < bits.len and bits[i] == .string) bits[i].string else null;
        if (!same(w, g.columnAt(0).get(0), to, b) and !knownCell(id, cell_txt))
            t.miss("{s} [{s}]: want {s}, got {any}", .{ id, cell_txt, cellText(a, w), g.columnAt(0).get(0) });
    }
}

fn replayRead(a: std.mem.Allocator, c: J, t: *Tally) !void {
    const id = strOf(c, "id");
    const op = strOf(c, "op");
    const csv = std.mem.eql(u8, op, "read_csv");
    if (!csv and !std.mem.eql(u8, op, "read_json")) return;
    const input = c.object.get("in").?.object;
    const ty = typeOf(strOf(input.get("schema").?, "dtype")) orelse return;
    const vals = input.get("x").?.object.get("values").?.array.items;
    const want = c.object.get("expect").?.array.items;
    const types = [_]df.TypeOverride{.{ .name = "x", .type = ty }};
    for (vals, want) |v, w| {
        t.run += 1;
        const text = v.string;
        const doc = if (csv) try a.print("x\n{s}\n", .{text}) else try a.print("[{{\"x\":{s}}}]", .{text});
        const r = if (csv) df.readCsv(a, doc, .{ .types = &types }) else df.readJson(a, doc, .{ .types = &types });
        if (isErr(w)) {
            if (r) |g| {
                if (!knownCell(id, text)) t.miss("{s} [{s}]: polars refused, got {any}", .{ id, text, g.columnAt(0).get(0) });
            } else |_| {}
            continue;
        }
        const g = r catch |e| {
            if (!knownCell(id, text)) t.miss("{s} [{s}]: {s}", .{ id, text, @errorName(e) });
            continue;
        };
        if (g.columns[0].type != ty) t.miss("{s}: type {s}", .{ id, @tagName(g.columns[0].type) });
        if (!fm.widthsConform(g)) t.miss("{s}: storage {s} under {s}", .{ id, @tagName(std.meta.activeTag(g.columnAt(0))), @tagName(ty) });
        const got: Value = if (g.len == 0) .null else g.columnAt(0).get(0);
        if (!same(w, got, ty, null) and !knownCell(id, text)) t.miss("{s} [{s}]: want {s}, got {any}", .{ id, text, cellText(a, w), got });
    }
}

fn replayWrite(a: std.mem.Allocator, c: J, t: *Tally) !void {
    const id = strOf(c, "id");
    const op = strOf(c, "op");
    const input = c.object.get("in").?.object.get("a").?;
    const ty = typeOf(strOf(input, "dtype")) orelse return;
    const vals = input.object.get("values").?.array.items;
    const want = c.object.get("expect").?.array.items[0].string;
    // NaN rows: written by the module's missing rule (`known`), checked by the plain tests.
    var keep: std.ArrayList(J) = .empty;
    var want_lines: std.ArrayList(u8) = .empty;
    var lines = std.mem.splitScalar(u8, want, '\n');
    const csv = std.mem.eql(u8, op, "csv");
    if (csv) {
        try want_lines.appendSlice(a, lines.next().?); // header
        try want_lines.append(a, '\n');
    }
    var rows: std.ArrayList([]const u8) = .empty;
    if (std.mem.eql(u8, op, "json")) {
        // `[{"x":..},{"x":..}]`: one element per row.
        var it = std.mem.splitSequence(u8, want[1 .. want.len - 1], "},{");
        while (it.next()) |r| try rows.append(a, r);
    } else while (lines.next()) |l| try rows.append(a, l);
    for (vals, 0..) |v, i| {
        if (v == .string and std.mem.eql(u8, v.string, "nan") and knownCell(id, "nan")) continue;
        if (v == .null and knownCell(id, "null")) continue;
        try keep.append(a, v);
        if (csv or std.mem.eql(u8, op, "ndjson")) {
            try want_lines.appendSlice(a, rows.items[i]);
            try want_lines.append(a, '\n');
        }
    }
    t.run += 1;
    const f = try frameOf(a, "x", ty, keep.items);
    var out: std.Io.Writer.Allocating = .init(a);
    if (csv) {
        try df.writeCsv(a, &out.writer, f, .{});
    } else if (std.mem.eql(u8, op, "ndjson")) {
        try df.writeNdjson(&out.writer, f);
    } else if (std.mem.eql(u8, op, "json")) {
        try df.writeJson(&out.writer, f, .records);
        // Compared element by element, without the NaN rows dropped above (JSON writes them null).
        if (keep.items.len != vals.len) return;
        if (!std.mem.eql(u8, out.written(), want)) t.miss("{s}: want {s}\n   got {s}", .{ id, want, out.written() });
        return;
    } else return;
    if (!std.mem.eql(u8, out.written(), want_lines.items)) t.miss("{s}: want {f}\n   got {f}", .{ id, std.zig.fmtString(want_lines.items), std.zig.fmtString(out.written()) });
}

test "W11 oracle: polars cast, read and write of the width types" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const doc = try std.json.parseFromSliceLeaky(J, a, vectors, .{});
    var t: Tally = .{ .out = .init(a) };
    for (doc.array.items) |c| {
        if (!std.mem.eql(u8, strOf(c, "engine"), "pl")) continue;
        const kind = strOf(c, "kind");
        if (std.mem.eql(u8, kind, "cast")) try replayCast(a, c, &t);
        if (std.mem.eql(u8, kind, "read")) try replayRead(a, c, &t);
        if (std.mem.eql(u8, kind, "write")) try replayWrite(a, c, &t);
    }
    if (t.bad != 0) {
        std.debug.print("W11 oracle: {d} of {d} cells differ:\n{s}", .{ t.bad, t.run, t.out.written() });
        return error.TestUnexpectedResult;
    }
    try testing.expect(t.run > 500);
}
