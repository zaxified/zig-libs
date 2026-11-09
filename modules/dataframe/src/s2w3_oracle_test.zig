// SPDX-License-Identifier: MIT
//! Replays `oracle2b_vectors.json` (dataframe S2 wave W3): what polars 2.1, pandas 3.1 and,
//! where neither has the function, numpy or Python's `math` answered for the constructors,
//! small `Expr` functions, selectors, name verbs and column functions that wave added
//! (`tools/oracle2b.py` asked the engines; no line of this module is consulted there).
//! The expected values are the engines' alone, so a failure is a difference from them.
const std = @import("std");
const testing = std.testing;
const vm = @import("value.zig");
const fm = @import("frame.zig");
const ex = @import("expr.zig");
const st = @import("structure.zig");
const rg = @import("ranges.zig");
const nm = @import("names.zig");
const cf = @import("colfn.zig");
const Frame = fm.Frame;
const Column = vm.Column;
const Value = vm.Value;
const J = std.json.Value;

const vectors = @embedFile("oracle2b_vectors.json");

/// Deliberate differences from what the engines answered: id substring and why.
const known = [_]struct { id: []const u8, why: []const u8 }{
    .{ .id = "hist-const", .why = "none" },
};

fn jcell(j: J) Value {
    return switch (j) {
        .null => .null,
        .bool => |b| .{ .bool = b },
        .integer => |i| .{ .int = i },
        .float => |f| .{ .float = f },
        .string => |s| .{ .text = s },
        .number_string => .null,
        else => .null,
    };
}

fn colFromJson(a: std.mem.Allocator, name: []const u8, arr: []const J) !struct { Column, fm.ColumnData } {
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
    return .{ .{ .name = name, .type = ty }, try fm.columnFromCells(a, cs) };
}

fn frameOf(a: std.mem.Allocator, obj: J) !Frame {
    const n = obj.object.count();
    const cols = try a.alloc(Column, n);
    const data = try a.alloc(fm.ColumnData, n);
    var len: usize = 0;
    for (obj.object.keys(), obj.object.values(), cols, data) |k, v, *c, *d| {
        c.*, d.* = try colFromJson(a, k, v.array.items);
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
        .bool => |b| return got == .bool and got.bool == b,
        .integer => |i| return switch (got) {
            .int => |x| x == i,
            .float => |x| x == @as(f64, @floatFromInt(i)),
            else => false,
        },
        .float => |f| {
            const x = got.asFloat() orelse return false;
            if (f == x) return true;
            return @abs(f - x) <= 1e-12 * @max(@abs(f), @abs(x)) + 1e-300;
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
    for (known) |k| if (std.mem.find(u8, id, k.id) != null and !std.mem.eql(u8, k.why, "none")) return true;
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
        if (!same(w, s.get(i))) return fail(id, "column {s} row {d}: got {any}", .{ col, i, s.get(i) });
    }
}

fn closedOf(s: []const u8) ex.Closed {
    return std.meta.stringToEnum(ex.Closed, s).?;
}

fn strOf(o: J, k: []const u8) ?[]const u8 {
    const v = o.object.get(k) orelse return null;
    return if (v == .string) v.string else null;
}

fn runExpr(a: std.mem.Allocator, c: J) !void {
    const id = strOf(c, "id").?;
    const op = strOf(c, "op").?;
    const f = try frameOf(a, c.object.get("cols").?);
    const cols = c.object.get("cols").?.object;
    var lits: std.ArrayList(ex.Expr) = .empty;
    for (cols.keys()) |k| try lits.append(a, .{ .col = k });
    const p = lits.items;
    const x = try a.create(ex.Expr);
    x.* = p[0];
    const y = try a.create(ex.Expr);
    y.* = if (p.len > 1) p[1] else p[0];
    const z = try a.create(ex.Expr);
    z.* = if (p.len > 2) p[2] else p[0];
    const e: ex.Expr = blk: {
        if (std.mem.eql(u8, op, "truncdiv")) break :blk .{ .binary = .{ .op = .truncdiv, .l = x, .r = y } };
        if (std.mem.eql(u8, op, "erfc")) break :blk .{ .unary = .{ .op = .erfc, .x = x } };
        if (std.mem.eql(u8, op, "escape_regex")) break :blk .{ .unary = .{ .op = .escape_regex, .x = x } };
        if (std.mem.eql(u8, op, "is_between")) break :blk .{ .is_between = .{ .x = x, .lower = y, .upper = z, .closed = closedOf(strOf(c, "closed").?) } };
        if (std.mem.eql(u8, op, "concat_str")) {
            const sep = strOf(c, "separator") orelse "";
            const ign = if (c.object.get("ignore_nulls")) |v| v.bool else false;
            break :blk .{ .concat_str = .{ .parts = p, .separator = sep, .ignore_nulls = ign, .na_rep = strOf(c, "na_rep") } };
        }
        if (std.mem.eql(u8, op, "fold_add")) {
            const zero = try a.create(ex.Expr);
            zero.* = .{ .lit = .{ .int = 0 } };
            break :blk .{ .fold = .{ .op = .add, .parts = p, .acc = zero } };
        }
        if (std.mem.eql(u8, op, "reduce_mul")) break :blk .{ .fold = .{ .op = .mul, .parts = p } };
        if (std.mem.eql(u8, op, "business_day_count")) {
            var mask = @import("dtfn.zig").monday_to_friday;
            if (c.object.get("week_mask")) |m| for (m.array.items, 0..) |b, i| {
                mask[i] = b.bool;
            };
            var hol: std.ArrayList(vm.Date) = .empty;
            if (c.object.get("holidays")) |h| for (h.array.items) |d| try hol.append(a, vm.parseIsoDate(d.string).?);
            break :blk .{ .business_day_count = .{ .start = x, .end = y, .week_mask = mask, .holidays = hol.items } };
        }
        if (std.mem.eql(u8, op, "from_epoch")) break :blk .{ .from_epoch = .{ .x = x, .unit = if (std.mem.eql(u8, strOf(c, "unit").?, "d")) ex.EpochUnit.day else std.meta.stringToEnum(ex.EpochUnit, strOf(c, "unit").?).? } };
        if (std.mem.eql(u8, op, "make_date")) break :blk .{ .make_date = .{ .year = x, .month = y, .day = z } };
        if (std.mem.eql(u8, op, "make_datetime")) {
            const q = try a.alloc(ex.Expr, 4);
            @memcpy(q, p[3..7]);
            break :blk .{ .make_datetime = .{ .year = x, .month = y, .day = z, .hour = &q[0], .minute = &q[1], .second = &q[2], .microsecond = &q[3] } };
        }
        if (std.mem.eql(u8, op, "make_duration")) break :blk .{ .make_duration = .{ .weeks = x, .days = y, .hours = z } };
        if (std.mem.eql(u8, op, "trunc_decimals")) {
            const d: i32 = @intCast(c.object.get("decimals").?.integer);
            break :blk .{ .round = .{ .x = x, .decimals = d, .mode = .toward_zero } };
        }
        return error.UnknownOp;
    };
    const out = try ex.mutate(a, f, &.{.{ .out = "o", .expr = e }});
    compareColumn(id, c.object.get("expect").?.array.items, out, "o");
}

fn intArg(j: J) i64 {
    return j.integer;
}

fn floatArg(j: J) f64 {
    return switch (j) {
        .integer => |i| @floatFromInt(i),
        .float => |f| f,
        else => 0,
    };
}

fn optInts(a: std.mem.Allocator, arr: []const J) ![]?i64 {
    const out = try a.alloc(?i64, arr.len);
    for (out, arr) |*o, j| o.* = if (j == .null) null else j.integer;
    return out;
}

fn tsOf(s: []const u8) i64 {
    return vm.parseIsoTimestamp(s).?;
}

fn runCtor(a: std.mem.Allocator, c: J) !void {
    const id = strOf(c, "id").?;
    const fn_name = strOf(c, "fn").?;
    const args = c.object.get("args").?.array.items;
    const want = c.object.get("expect").?.array.items;
    const f: Frame = blk: {
        if (std.mem.eql(u8, fn_name, "intRange")) break :blk try rg.intRange(a, "r", intArg(args[0]), intArg(args[1]), intArg(args[2]));
        if (std.mem.eql(u8, fn_name, "intRanges")) break :blk try rg.intRanges(a, "r", try optInts(a, args[0].array.items), try optInts(a, args[1].array.items), intArg(args[2]));
        if (std.mem.eql(u8, fn_name, "linearSpace")) break :blk try rg.linearSpace(a, "r", floatArg(args[0]), floatArg(args[1]), @intCast(intArg(args[2])), closedOf(args[3].string));
        if (std.mem.eql(u8, fn_name, "dateRange") or std.mem.eql(u8, fn_name, "dateRangeBusiness")) {
            const spec: rg.CalendarSpec = .{ .interval = args[2].string, .closed = closedOf(args[3].string), .business = std.mem.eql(u8, fn_name, "dateRangeBusiness") };
            break :blk try rg.dateRange(a, "r", vm.parseIsoDate(args[0].string).?, vm.parseIsoDate(args[1].string).?, spec);
        }
        if (std.mem.eql(u8, fn_name, "datetimeRange")) break :blk try rg.datetimeRange(a, "r", tsOf(args[0].string), tsOf(args[1].string), .{ .interval = args[2].string, .closed = closedOf(args[3].string) });
        if (std.mem.eql(u8, fn_name, "dateRangePeriods")) break :blk try rg.dateRangePeriods(a, "r", vm.parseIsoDate(args[0].string).?, @intCast(intArg(args[1])), .{ .interval = args[2].string, .business = args[3].bool });
        if (std.mem.eql(u8, fn_name, "datetimeRangePeriods")) break :blk try rg.datetimeRangePeriods(a, "r", tsOf(args[0].string), @intCast(intArg(args[1])), .{ .interval = args[2].string, .business = args[3].bool });
        if (std.mem.eql(u8, fn_name, "datetimeSpace")) break :blk try rg.datetimeSpace(a, "r", tsOf(args[0].string), tsOf(args[1].string), @intCast(intArg(args[2])));
        if (std.mem.eql(u8, fn_name, "ones")) break :blk try rg.ones(a, "r", @intCast(intArg(args[0])), args[1].bool);
        if (std.mem.eql(u8, fn_name, "zeros")) break :blk try rg.zeros(a, "r", @intCast(intArg(args[0])), args[1].bool);
        return error.UnknownFn;
    };
    compareColumn(id, want, f, "r");
}

fn namesOf(a: std.mem.Allocator, names: []const J) !Frame {
    const cols = try a.alloc(Column, names.len);
    const data = try a.alloc(fm.ColumnData, names.len);
    for (cols, data, names) |*c, *d, n| {
        c.* = .{ .name = n.string, .type = .int };
        d.* = try fm.columnFromCells(a, &.{.{ .int = 1 }});
    }
    return .{ .columns = cols, .data = data, .len = 1 };
}

fn stripUsUpper(_: void, al: std.mem.Allocator, n: []const u8) error{OutOfMemory}![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (n) |ch| if (ch != '_') try out.append(al, std.ascii.toUpper(ch));
    return out.toOwnedSlice(al);
}

fn expectNames(id: []const u8, want: []const J, got: []const Column) void {
    if (want.len != got.len) return fail(id, "{d} names, want {d}", .{ got.len, want.len });
    for (want, got) |w, g| if (!std.mem.eql(u8, w.string, g.name)) return fail(id, "name {s}, want {s}", .{ g.name, w.string });
}

fn runFrame(a: std.mem.Allocator, c: J) !void {
    const id = strOf(c, "id").?;
    const fn_name = strOf(c, "fn").?;
    const exp = c.object.get("expect").?;
    if (std.mem.eql(u8, fn_name, "hist")) {
        const f = try frameOf(a, c.object.get("col").?);
        const ar = c.object.get("args").?.object;
        var spec: cf.HistSpec = .{ .col = "x" };
        if (ar.get("bins")) |b| {
            const bins = try a.alloc(f64, b.array.items.len);
            for (bins, b.array.items) |*o, j| o.* = floatArg(j);
            spec.bins = bins;
        }
        if (ar.get("bin_count")) |n| spec.bin_count = @intCast(n.integer);
        if (ar.get("include_category")) |v| spec.include_category = v.bool;
        const out = try cf.hist(a, f, spec);
        for (exp.object.keys(), exp.object.values()) |k, v| compareColumn(id, v.array.items, out, k);
    } else if (std.mem.eql(u8, fn_name, "uniqueCounts")) {
        const f = try frameOf(a, c.object.get("col").?);
        const out = try cf.uniqueCounts(a, f, "x");
        compareColumn(id, exp.object.get("x").?.array.items, out, "x");
    } else if (std.mem.eql(u8, fn_name, "cumSumHorizontal")) {
        const f = try frameOf(a, c.object.get("cols").?);
        const out = try cf.cumSumHorizontal(a, f, &.{});
        for (exp.object.keys(), exp.object.values()) |k, v| compareColumn(id, v.array.items, out, k);
    } else if (std.mem.eql(u8, fn_name, "alignFrames")) {
        const fr = c.object.get("frames").?.array.items;
        const frames = try a.alloc(Frame, fr.len);
        for (frames, fr) |*o, j| o.* = try frameOf(a, j);
        const ar = c.object.get("args").?.object;
        const on = try a.alloc([]const u8, ar.get("on").?.array.items.len);
        for (on, ar.get("on").?.array.items) |*o, j| o.* = j.string;
        const out = try cf.alignFrames(a, frames, .{ .on = on, .reverse = ar.get("reverse").?.bool });
        for (exp.array.items, out) |w, o| {
            for (w.object.keys(), w.object.values()) |k, v| compareColumn(id, v.array.items, o, k);
            if (o.columns.len != w.object.count()) fail(id, "{d} columns, want {d}", .{ o.columns.len, w.object.count() });
        }
    } else if (std.mem.eql(u8, fn_name, "names")) {
        const f = try namesOf(a, c.object.get("cols").?.array.items);
        const ar = c.object.get("args").?.object;
        const op = ar.get("op").?.string;
        const out = if (std.mem.eql(u8, op, "lower"))
            try nm.renameLower(a, f, .all)
        else if (std.mem.eql(u8, op, "upper"))
            try nm.renameUpper(a, f, .all)
        else if (std.mem.eql(u8, op, "replace"))
            try nm.renameReplace(a, f, .{ .pattern = ar.get("pattern").?.string, .with = ar.get("with").?.string, .literal = ar.get("literal").?.bool })
        else
            try nm.renameWith(a, f, .all, {}, stripUsUpper);
        expectNames(id, exp.array.items, out.columns);
    } else if (std.mem.eql(u8, fn_name, "selector")) {
        const f = try namesOf(a, c.object.get("cols").?.array.items);
        const op = c.object.get("args").?.object.get("op").?.string;
        const sel: st.Selector = if (std.mem.eql(u8, op, "alpha")) .alpha else if (std.mem.eql(u8, op, "alphanumeric")) .alphanumeric else .digit;
        const picked = try st.selectColumns(a, f, sel);
        if (picked.len != exp.array.items.len) return fail(id, "{d} picked, want {d}", .{ picked.len, exp.array.items.len });
        for (picked, exp.array.items) |g, w| if (!std.mem.eql(u8, g, w.string)) fail(id, "picked {s}, want {s}", .{ g, w.string });
    } else return error.UnknownFn;
}

test "oracle2b: replay the engines' answers" {
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
        const n0 = fails;
        if (std.mem.eql(u8, kind, "expr")) runExpr(a, c) catch |e| fail(id, "error {s}", .{@errorName(e)}) else if (std.mem.eql(u8, kind, "ctor")) runCtor(a, c) catch |e| fail(id, "error {s}", .{@errorName(e)}) else runFrame(a, c) catch |e| fail(id, "error {s}", .{@errorName(e)});
        _ = n0;
        ran += 1;
    }
    // Silent when green: a full lane treats any stderr from a passing test as a failure.
    if (fails != 0) std.debug.print("oracle2b: {d} cases replayed, {d} mismatches\n", .{ ran, fails });
    try testing.expect(ran > 50);
    try testing.expectEqual(@as(usize, 0), fails);
}
