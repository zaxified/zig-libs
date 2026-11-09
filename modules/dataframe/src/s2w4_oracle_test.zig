// SPDX-License-Identifier: MIT
//! Replays `oracle2c_vectors.json` (dataframe S2 wave W4): what pandas 3.1 and polars 2.1
//! answered for the str, dt and duration functions that wave added (`tools/oracle2c.py` asked
//! the engines; no line of this module is consulted there). The expected values are the
//! engines' alone, so a failure is a difference from them.
const std = @import("std");
const testing = std.testing;
const vm = @import("value.zig");
const fm = @import("frame.zig");
const ex = @import("expr.zig");
const dtf = @import("dtfn.zig");
const sf = @import("strfn.zig");
const jr = @import("jsonread.zig");
const vb = @import("verbs.zig");
const sp = @import("spec.zig");
const Frame = fm.Frame;
const Column = vm.Column;
const Value = vm.Value;
const J = std.json.Value;

const vectors = @embedFile("oracle2c_vectors.json");

/// Deliberate differences from what the engines answered: id substring and why.
const known = [_]struct { id: []const u8, why: []const u8 }{
    .{ .id = "infer-pl-name", .why = "polars infers no month-name pattern (null); `infer` here knows pandas' English month names" },
    .{ .id = "infer-pd-isots-False", .why = "pandas fixes the 'T' or ' ' separator from the first cell and nulls the other; an inferred ISO column is read cell by cell here" },
};

fn jcell(j: J) Value {
    return switch (j) {
        .null => .null,
        .bool => |b| .{ .bool = b },
        .integer => |i| .{ .int = i },
        .float => |f| .{ .float = f },
        .string => |s| .{ .text = s },
        else => .null,
    };
}

fn colFromJson(a: std.mem.Allocator, name: []const u8, arr: []const J, ty_name: ?[]const u8) !struct { Column, fm.ColumnData } {
    const cs = try a.alloc(Value, arr.len);
    var ty: vm.ColumnType = .float;
    var seen = false;
    for (cs, arr) |*c, j| {
        c.* = jcell(j);
        if (!seen and c.* != .null) {
            seen = true;
            ty = switch (c.*) {
                .int => .int,
                .float => .float,
                .text => .text,
                .bool => .bool,
                else => .float,
            };
        }
    }
    if (ty_name) |t| ty = std.meta.stringToEnum(vm.ColumnType, t).?;
    return .{ .{ .name = name, .type = ty }, try fm.columnFromCells(a, cs) };
}

fn frameOf(a: std.mem.Allocator, obj: J, types: ?J) !Frame {
    const n = obj.object.count();
    const cols = try a.alloc(Column, n);
    const data = try a.alloc(fm.ColumnData, n);
    var len: usize = 0;
    for (obj.object.keys(), obj.object.values(), cols, data) |k, v, *c, *d| {
        const tn: ?[]const u8 = if (types) |t| (if (t.object.get(k)) |x| x.string else null) else null;
        c.*, d.* = try colFromJson(a, k, v.array.items, tn);
        len = v.array.items.len;
    }
    return .{ .columns = cols, .data = data, .len = len };
}

fn missing(v: Value) bool {
    return v == .null or (v == .float and std.math.isNan(v.float));
}

fn same(want: J, got: Value) bool {
    switch (want) {
        .null => return missing(got),
        .bool => |b| return (got == .bool and got.bool == b) or (got == .int and (got.int != 0) == b and (got.int == 0 or got.int == 1)),
        .integer => |i| return switch (got) {
            .int => |x| x == i,
            .float => |x| x == @as(f64, @floatFromInt(i)),
            else => false,
        },
        .float => |f| {
            const x = got.asFloat() orelse return false;
            if (f == x) return true;
            // pandas computes total_seconds as 1e-9 * ns, 3e-11 off the exact quotient.
            return @abs(f - x) <= 1e-9 * @max(@abs(f), @abs(x)) + 1e-300;
        },
        .string => |s| return got == .text and std.mem.eql(u8, got.text, s),
        .array => |arr| {
            if (got != .list or got.list.len() != arr.items.len) return false;
            for (arr.items, 0..) |w, i| if (!same(w, got.list.get(i))) return false;
            return true;
        },
        else => return false,
    }
}

fn isKnown(id: []const u8) bool {
    for (known) |k| if (std.mem.find(u8, id, k.id) != null) return true;
    return false;
}

var fails: usize = 0;
var ran: usize = 0;

fn fail(id: []const u8, comptime fmt: []const u8, args: anytype) void {
    fails += 1;
    std.debug.print("MISMATCH {s}: " ++ fmt ++ "\n", .{id} ++ args);
}

fn compareColumn(id: []const u8, want: []const J, f: Frame, col: []const u8) void {
    const s = f.series(col) orelse return fail(id, "no column {s}", .{col});
    if (s.len != want.len) return fail(id, "column {s}: {d} rows, want {d}", .{ col, s.len, want.len });
    for (want, 0..) |w, i| {
        if (!same(w, s.get(i))) return fail(id, "column {s} row {d}: got {any}, want {any}", .{ col, i, s.get(i), w });
    }
}

fn strOf(o: J, k: []const u8) ?[]const u8 {
    const v = o.object.get(k) orelse return null;
    return if (v == .string) v.string else null;
}

fn boolOr(o: J, k: []const u8, d: bool) bool {
    const v = o.object.get(k) orelse return d;
    return if (v == .bool) v.bool else d;
}

fn limitOf(o: J, k: []const u8) ?usize {
    const v = o.object.get(k) orelse return null;
    return if (v == .integer) @intCast(v.integer) else null;
}

fn optInt(o: J, k: []const u8) ?i64 {
    const v = o.object.get(k) orelse return null;
    return if (v == .integer) v.integer else null;
}

fn mask7(o: J) [7]bool {
    var m = dtf.monday_to_friday;
    if (o.object.get("week_mask")) |w| if (w == .array) for (w.array.items, 0..) |b, i| {
        m[i] = b.bool;
    };
    return m;
}

fn holidaysOf(a: std.mem.Allocator, o: J) ![]const vm.Date {
    var out: std.ArrayList(vm.Date) = .empty;
    if (o.object.get("holidays")) |h| for (h.array.items) |d| try out.append(a, vm.parseIsoDate(d.string).?);
    return out.items;
}

fn enumOf(comptime E: type, s: []const u8) E {
    return std.meta.stringToEnum(E, s).?;
}

fn build(a: std.mem.Allocator, c: J, p: []const ex.Expr) !ex.Expr {
    const op = strOf(c, "op").?;
    const x = try a.create(ex.Expr);
    x.* = p[0];
    const eq = std.mem.eql;
    if (eq(u8, op, "split_ws")) return .{ .split_ws = .{ .x = x, .limit = limitOf(c, "limit") } };
    if (eq(u8, op, "rsplit")) return .{ .rsplit = .{ .x = x, .by = strOf(c, "by").?, .limit = limitOf(c, "limit") } };
    if (eq(u8, op, "partition")) return .{ .partition = .{ .x = x, .sep = strOf(c, "sep").?, .last = boolOr(c, "last", false) } };
    if (eq(u8, op, "split_fields")) return .{ .split_fields = .{ .x = x, .by = strOf(c, "by").?, .n = limitOf(c, "n").?, .rest = boolOr(c, "rest", false) } };
    if (eq(u8, op, "wrap")) return .{ .wrap = .{ .x = x, .width = limitOf(c, "width").?, .break_long_words = boolOr(c, "break_long_words", true), .break_on_hyphens = boolOr(c, "break_on_hyphens", true) } };
    if (eq(u8, op, "slice_replace")) return .{ .slice_replace = .{ .x = x, .start = optInt(c, "start"), .stop = optInt(c, "stop"), .with = strOf(c, "repl").? } };
    if (eq(u8, op, "encode")) return .{ .encode = .{ .x = x, .how = enumOf(ex.Encoding, strOf(c, "how").?) } };
    if (eq(u8, op, "decode")) return .{ .decode = .{ .x = x, .how = enumOf(ex.Encoding, strOf(c, "how").?) } };
    if (eq(u8, op, "affix_any")) {
        const arr = c.object.get("patterns").?.array.items;
        const pats = try a.alloc([]const u8, arr.len);
        for (pats, arr) |*o, j| o.* = j.string;
        return .{ .affix_any = .{ .x = x, .patterns = pats, .end = boolOr(c, "end", false) } };
    }
    if (eq(u8, op, "replace_n")) return .{ .replace_n = .{ .x = x, .from = strOf(c, "frm").?, .to = strOf(c, "to").?, .n = limitOf(c, "n").? } };
    if (eq(u8, op, "replace_regex")) return .{ .replace_regex = .{ .x = x, .pattern = strOf(c, "pattern").?, .with = strOf(c, "to").?, .literal = true, .n = limitOf(c, "n") } };
    if (eq(u8, op, "match_regex")) return .{ .match_regex = .{ .x = x, .pattern = strOf(c, "pattern").?, .full = boolOr(c, "full", false) } };
    if (eq(u8, op, "is_ascii")) return .{ .unary = .{ .op = .is_ascii, .x = x } };
    if (eq(u8, op, "to_datetime")) return .{ .to_datetime = .{ .x = x, .mode = enumOf(ex.DateMode, strOf(c, "mode").?), .dayfirst = boolOr(c, "dayfirst", false), .to = enumOf(ex.ParseTo, strOf(c, "to").?) } };
    if (eq(u8, op, "dt_part")) return .{ .dt = .{ .x = x, .part = enumOf(dtf.DtPart, strOf(c, "part").?) } };
    if (eq(u8, op, "td_components")) return .{ .td_components = .{ .x = x } };
    if (eq(u8, op, "dt_replace")) {
        const parts = c.object.get("parts").?.object;
        var r: ex.Expr = .{ .dt_replace = .{ .x = x } };
        inline for (.{ "year", "month", "day", "hour", "minute", "second", "microsecond" }) |nm| {
            if (parts.get(nm)) |v| {
                const lit = try a.create(ex.Expr);
                lit.* = .{ .lit = .{ .int = v.integer } };
                @field(r.dt_replace, nm) = lit;
            }
        }
        return r;
    }
    if (eq(u8, op, "dt_combine")) {
        const y = try a.create(ex.Expr);
        y.* = p[1];
        return .{ .dt_combine = .{ .date = x, .time = y } };
    }
    if (eq(u8, op, "tz_offset")) return .{ .tz_offset = .{ .x = x, .zone = strOf(c, "zone").?, .kind = enumOf(dtf.OffsetKind, strOf(c, "offset").?) } };
    if (eq(u8, op, "is_business_day")) return .{ .is_business_day = .{ .x = x, .week_mask = mask7(c), .holidays = try holidaysOf(a, c) } };
    if (eq(u8, op, "add_business_days")) return .{ .add_business_days = .{ .x = x, .n = optInt(c, "n").?, .week_mask = mask7(c), .holidays = try holidaysOf(a, c), .roll = enumOf(dtf.Roll, strOf(c, "roll").?) } };
    return error.UnknownOp;
}

fn runExpr(a: std.mem.Allocator, c: J, rec: bool) !void {
    const id = strOf(c, "id").?;
    const f = try frameOf(a, c.object.get("cols").?, c.object.get("types"));
    var lits: std.ArrayList(ex.Expr) = .empty;
    for (c.object.get("cols").?.object.keys()) |k| try lits.append(a, .{ .col = k });
    const e = try build(a, c, lits.items);
    const exp = c.object.get("expect").?;
    if (!rec) {
        const out = try ex.mutate(a, f, &.{.{ .out = "o", .expr = e }});
        compareColumn(id, exp.array.items, out, "o");
        return;
    }
    var assigns: std.ArrayList(ex.Assign) = .empty;
    try assigns.append(a, .{ .out = "o", .expr = e });
    const oc = try a.create(ex.Expr);
    oc.* = .{ .col = "o" };
    for (exp.object.keys()) |k| {
        try assigns.append(a, .{ .out = try std.mem.concat(a, u8, &.{ "f_", k }), .expr = .{ .field = .{ .x = oc, .name = k } } });
    }
    const out = try ex.mutate(a, f, assigns.items);
    for (exp.object.keys(), exp.object.values()) |k, v| compareColumn(id, v.array.items, out, try std.mem.concat(a, u8, &.{ "f_", k }));
}

fn runFrame(a: std.mem.Allocator, c: J) !void {
    const id = strOf(c, "id").?;
    const fn_name = strOf(c, "fn").?;
    const f = try frameOf(a, c.object.get("cols").?, null);
    const ar = c.object.get("args").?;
    const exp = c.object.get("expect").?;
    const out = if (std.mem.eql(u8, fn_name, "splitColumns"))
        try sf.splitColumns(a, f, .{
            .col = "x",
            .by = strOf(ar, "by"),
            .regex = boolOr(ar, "regex", false),
            .limit = limitOf(ar, "limit"),
        })
    else
        try sf.getDummies(a, f, .{ .col = "x", .sep = strOf(ar, "sep").? });
    for (exp.object.keys(), exp.object.values()) |k, v| compareColumn(id, v.array.items, out, k);
    if (out.columns.len != exp.object.count()) fail(id, "{d} columns, want {d}", .{ out.columns.len, exp.object.count() });
}

fn runAgg(a: std.mem.Allocator, c: J) !void {
    const id = strOf(c, "id").?;
    const f = try frameOf(a, c.object.get("cols").?, c.object.get("types"));
    const func = enumOf(sp.AggFn, strOf(c, "func").?);
    const out = try vb.aggregate(a, f, .{ .group_by = &.{"g"}, .aggs = &.{.{ .src = "d", .out = "o", .func = func }}, .skip_na = true });
    const exp = c.object.get("expect").?;
    for (exp.object.keys(), exp.object.values()) |k, v| compareColumn(id, v.array.items, out, k);
    // The kind of time is kept: a duration column in, a duration (or timestamp) column out.
    const ci = out.columnIndex("o").?;
    const src_ty = f.columns[f.columnIndex("d").?].type;
    const want: vm.ColumnType = if (func == .std) .duration else src_ty;
    if (out.columns[ci].type != want) fail(id, "column o has type {s}, want {s}", .{ @tagName(out.columns[ci].type), @tagName(want) });
}

fn runJson(a: std.mem.Allocator, c: J) !void {
    const id = strOf(c, "id").?;
    const unit = enumOf(@import("jsonio.zig").JsonDateUnit, strOf(c, "unit").?);
    const col = strOf(c, "col").?;
    const out = try jr.readJson(a, strOf(c, "text").?, .{ .epoch_durations = &.{col}, .date_unit = unit });
    for (c.object.get("expect").?.object.keys(), c.object.get("expect").?.object.values()) |k, v| compareColumn(id, v.array.items, out, k);
    if (out.columns[out.columnIndex(col).?].type != .duration) fail(id, "column {s} is not a duration", .{col});
}

test "oracle2c: replay the engines' answers" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const root = try std.json.parseFromSliceLeaky(J, a, vectors, .{});
    fails = 0;
    ran = 0;
    for (root.array.items) |c| {
        const id = strOf(c, "id").?;
        if (isKnown(id)) continue;
        const kind = strOf(c, "kind").?;
        const r = if (std.mem.eql(u8, kind, "expr")) runExpr(a, c, false) else if (std.mem.eql(u8, kind, "expr_rec")) runExpr(a, c, true) else if (std.mem.eql(u8, kind, "frame")) runFrame(a, c) else if (std.mem.eql(u8, kind, "agg")) runAgg(a, c) else runJson(a, c);
        r catch |e| fail(id, "error {s}", .{@errorName(e)});
        ran += 1;
    }
    std.debug.print("oracle2c: {d} cases replayed, {d} mismatches\n", .{ ran, fails });
    try testing.expect(ran > 200);
    try testing.expectEqual(@as(usize, 0), fails);
}
