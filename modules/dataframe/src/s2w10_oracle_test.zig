// SPDX-License-Identifier: MIT
//! Replays `oracle2i_vectors.json` (dataframe S2 wave W10): what polars 2.1 and pandas 3.1
//! answered for `str.find`, `corrwith`, `struct.json_encode`, `unstack`, `wide_to_long`, the
//! `bin_*` expressions and `dt.offset_by` on a zoned column (`tools/oracle2i.py` asked the
//! engines; no line of this module is consulted there).
const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const vm = @import("value.zig");
const fm = @import("frame.zig");
const lf = @import("listfn.zig");
const Frame = fm.Frame;
const Column = vm.Column;
const Value = vm.Value;
const Expr = df.Expr;
const J = std.json.Value;

const vectors = @embedFile("oracle2i_vectors.json");

/// Deliberate differences from what the engines answered: id substring and why.
const known = [_]struct { id: []const u8, why: []const u8 }{
    .{ .id = "json-float-exp", .why = "polars writes a small float as `1e-7`, the JSON writer of this module (`writeJson`, which `json_encode` reuses; pandas and the CSV writer agree with it) as `1e-07`; both are valid JSON numbers and the shared writer is kept" },
    .{ .id = "nan-", .why = "polars bins a NaN with the largest values (and counts it in the positions of `bin_quantiles` and `bin_ranks`); NaN is missing here, the module's one rule, so it gets no bin and is not counted; the NaN row of these cases is sent as null and checked by the plain tests" },
    .{ .id = "find-lit", .why = "pandas `str.find` is a literal search that counts characters and answers -1; `find_regex` follows polars (a regex or literal pattern, a byte offset, null when absent)" },
};

fn isKnown(id: []const u8) bool {
    for (known) |k| if (std.mem.find(u8, id, k.id) != null) return true;
    return false;
}

fn strOf(o: J, k: []const u8) ?[]const u8 {
    const v = o.object.get(k) orelse return null;
    return if (v == .string) v.string else null;
}

fn arrOf(o: J, k: []const u8) []const J {
    return o.object.get(k).?.array.items;
}

fn boolOf(o: J, k: []const u8) bool {
    const v = o.object.get(k) orelse return false;
    return v == .bool and v.bool;
}

fn jcell(a: std.mem.Allocator, j: J) !Value {
    return switch (j) {
        .null => .null,
        .bool => |b| .{ .bool = b },
        .integer => |i| .{ .int = i },
        .float => |x| .{ .float = x },
        .string => |s| .{ .text = s },
        .array => |xs| blk: {
            const vals = try a.alloc(Value, xs.items.len);
            for (vals, xs.items) |*v, x| v.* = try jcell(a, x);
            break :blk try lf.makeList(a, vals);
        },
        .object => |o| blk: {
            const names = try a.alloc([]const u8, o.count());
            const vals = try a.alloc(Value, o.count());
            for (names, vals, o.keys(), o.values()) |*n, *v, k, x| {
                n.* = k;
                v.* = try jcell(a, x);
            }
            break :blk try lf.makeRecord(a, names, vals);
        },
        .number_string => .null,
    };
}

fn same(want: J, got: Value) bool {
    return switch (want) {
        .null => got == .null or (got == .float and std.math.isNan(got.float)),
        .bool => |b| got == .bool and got.bool == b,
        .integer => |i| (got == .int and got.int == i) or (got == .float and got.float == @as(f64, @floatFromInt(i))),
        .float => |x| (got == .float and (got.float == x or @abs(got.float - x) <= 1e-9 * @max(1.0, @abs(x)))) or (got == .int and @as(f64, @floatFromInt(got.int)) == x),
        .string => |s| got == .text and std.mem.eql(u8, got.text, s),
        else => false,
    };
}

var fails: usize = 0;
var ran: usize = 0;

fn fail(id: []const u8, comptime fmt_: []const u8, args: anytype) void {
    fails += 1;
    std.debug.print("MISMATCH {s}: " ++ fmt_ ++ "\n", .{id} ++ args);
}

/// A frame from `{"names": [...], "cols": [[...], ...]}`, the types read off the cells (or
/// `types` when given): any float makes a float column, else ints, else text.
fn frameOf(a: std.mem.Allocator, j: J) !Frame {
    const names = arrOf(j, "names");
    const colsj = arrOf(j, "cols");
    const types = j.object.get("types");
    const cols = try a.alloc(Column, names.len);
    const data = try a.alloc(fm.ColumnData, names.len);
    var len: usize = 0;
    for (cols, data, names, colsj, 0..) |*c, *d, n, cj, k| {
        const cells = try a.alloc(Value, cj.array.items.len);
        var has_float = false;
        var has_int = false;
        var has_text = false;
        var has_bool = false;
        for (cells, cj.array.items) |*v, x| {
            v.* = try jcell(a, x);
            switch (v.*) {
                .float => has_float = true,
                .int => has_int = true,
                .text => has_text = true,
                .bool => has_bool = true,
                else => {},
            }
        }
        const ty: vm.ColumnType = if (types) |t| std.meta.stringToEnum(vm.ColumnType, t.array.items[k].string).? else if (has_text) .text else if (has_float) .float else if (has_int) .int else if (has_bool) .bool else .float;
        c.* = .{ .name = n.string, .type = ty };
        d.* = try fm.columnFromCells(a, cells);
        len = cells.len;
    }
    return .{ .columns = cols, .data = data, .len = len };
}

fn checkFrame(id: []const u8, got: Frame, want: J) void {
    const wn = arrOf(want, "names");
    const wc = arrOf(want, "cols");
    if (got.columns.len != wn.len) return fail(id, "{d} columns, want {d}", .{ got.columns.len, wn.len });
    for (got.columns, wn, wc, 0..) |c, n, col, ci| {
        if (!std.mem.eql(u8, c.name, n.string)) return fail(id, "column {d} is {s}, want {s}", .{ ci, c.name, n.string });
        if (got.len != col.array.items.len) return fail(id, "{s}: {d} rows, want {d}", .{ c.name, got.len, col.array.items.len });
        for (col.array.items, 0..) |w, ri| {
            const g = got.columnAt(ci).get(ri);
            if (!same(w, g)) return fail(id, "{s} row {d}: got {any}, want {any}", .{ c.name, ri, g, w });
        }
    }
}

fn runFind(a: std.mem.Allocator, c: J) !void {
    const id = strOf(c, "id").?;
    const texts = arrOf(c.object.get("cols").?, "x");
    const cs = try a.alloc(Value, texts.len);
    for (cs, texts) |*v, t| v.* = try jcell(a, t);
    const cols = try a.dupe(Column, &.{.{ .name = "x", .type = .text }});
    const data = try a.alloc(fm.ColumnData, 1);
    data[0] = try fm.columnFromCells(a, cs);
    const f: Frame = .{ .columns = cols, .data = data, .len = texts.len };
    const x = try a.create(Expr);
    x.* = .{ .col = "x" };
    const e: Expr = .{ .find_regex = .{ .x = x, .pattern = strOf(c, "pattern").?, .literal = boolOf(c, "literal") } };
    if (boolOf(c, "error")) {
        try testing.expectError(error.BadPattern, df.mutate(a, f, &.{.{ .out = "o", .expr = e }}));
        return;
    }
    const out = try df.mutate(a, f, &.{.{ .out = "o", .expr = e }});
    const s = out.series("o") orelse return fail(id, "no output", .{});
    const want = arrOf(c, "expect");
    for (want, 0..) |w, i| {
        if (!same(w, s.get(i))) fail(id, "input {any}: got {any}, want {any}", .{ texts[i], s.get(i), w });
    }
}

fn runCorrwith(a: std.mem.Allocator, c: J) !void {
    const id = strOf(c, "id").?;
    const l = try frameOf(a, c.object.get("left").?);
    const r = try frameOf(a, c.object.get("right").?);
    const method: df.CorrMethod = if (std.mem.eql(u8, strOf(c, "method").?, "spearman")) .spearman else .pearson;
    const got = try df.corrWith(a, l, r, .{ .method = method, .drop = boolOf(c, "drop") });
    const want = c.object.get("expect").?;
    const wn = arrOf(want, "names");
    const wc = arrOf(want, "corr");
    if (got.len != wn.len) return fail(id, "{d} rows, want {d}", .{ got.len, wn.len });
    for (wn, wc, 0..) |n, w, ri| {
        const gn = got.columnAt(0).get(ri);
        if (gn != .text or !std.mem.eql(u8, gn.text, n.string)) return fail(id, "row {d} is {any}, want {s}", .{ ri, gn, n.string });
        const g = got.columnAt(1).get(ri);
        if (!same(w, g)) fail(id, "{s}: got {any}, want {any}", .{ n.string, g, w });
    }
}

fn runJson(a: std.mem.Allocator, c: J) !void {
    const id = strOf(c, "id").?;
    const rows = arrOf(c.object.get("cols").?, "a");
    const cells = try a.alloc(Value, rows.len);
    for (cells, rows) |*v, x| v.* = try jcell(a, x);
    const cols = try a.dupe(Column, &.{.{ .name = "a", .type = .@"struct" }});
    const data = try a.alloc(fm.ColumnData, 1);
    data[0] = try fm.columnFromCells(a, cells);
    const f: Frame = .{ .columns = cols, .data = data, .len = rows.len };
    const x = try a.create(Expr);
    x.* = .{ .col = "a" };
    const out = try df.mutate(a, f, &.{.{ .out = "o", .expr = .{ .json_encode = .{ .x = x } } }});
    const s = out.series("o") orelse return fail(id, "no output", .{});
    for (arrOf(c, "expect"), 0..) |w, i| {
        if (!same(w, s.get(i))) fail(id, "row {d}: got {any}, want {any}", .{ i, s.get(i), w });
    }
}

fn runUnstack(a: std.mem.Allocator, c: J) !void {
    const id = strOf(c, "id").?;
    const f = try frameOf(a, c.object.get("frame").?);
    const sj = c.object.get("spec").?;
    var cols: std.ArrayList([]const u8) = .empty;
    if (sj.object.get("columns")) |cj| switch (cj) {
        .string => |s| try cols.append(a, s),
        .array => |xs| for (xs.items) |x| try cols.append(a, x.string),
        else => {},
    };
    var fills: std.ArrayList(Value) = .empty;
    var fill_one: Value = .null;
    if (sj.object.get("fill_values")) |fj| switch (fj) {
        .array => |xs| for (xs.items) |x| try fills.append(a, try jcell(a, x)),
        else => fill_one = try jcell(a, fj),
    };
    const spec: df.UnstackSpec = .{
        .step = @intCast(sj.object.get("step").?.integer),
        .how = if (sj.object.get("how")) |h| (if (std.mem.eql(u8, h.string, "horizontal")) .horizontal else .vertical) else .vertical,
        .columns = cols.items,
        .fill_value = fill_one,
        .fill_values = fills.items,
    };
    if (boolOf(c, "error")) {
        try testing.expect(std.meta.isError(df.unstack(a, f, spec)));
        return;
    }
    const got = try df.unstack(a, f, spec);
    checkFrame(id, got, c.object.get("expect").?);
}

fn runWide(a: std.mem.Allocator, c: J) !void {
    const id = strOf(c, "id").?;
    const f = try frameOf(a, c.object.get("frame").?);
    const stubs = try a.alloc([]const u8, arrOf(c, "stubnames").len);
    for (stubs, arrOf(c, "stubnames")) |*s, x| s.* = x.string;
    const iv = try a.alloc([]const u8, arrOf(c, "i").len);
    for (iv, arrOf(c, "i")) |*s, x| s.* = x.string;
    const spec: df.WideToLongSpec = .{ .stubnames = stubs, .i = iv, .j = strOf(c, "j").?, .sep = strOf(c, "sep").?, .suffix = strOf(c, "suffix").? };
    if (boolOf(c, "error")) {
        try testing.expectError(error.NotUnique, df.wideToLong(a, f, spec));
        return;
    }
    const got = try df.wideToLong(a, f, spec);
    checkFrame(id, got, c.object.get("expect").?);
}

fn num(j: J) f64 {
    return switch (j) {
        .integer => |i| @floatFromInt(i),
        .float => |x| x,
        else => std.math.nan(f64),
    };
}

fn sameBin(want: J, got: Value) bool {
    if (want != .object) return same(want, got);
    if (got != .record) return false;
    const names = [_][]const u8{ "bin", "left", "right" };
    for (names, 0..) |n, i| {
        if (got.record.len() != 3 or !std.mem.eql(u8, got.record.name(i), n)) return false;
        if (!same(want.object.get(n).?, got.record.get(i))) return false;
    }
    return true;
}

fn runBins(a: std.mem.Allocator, c: J) !void {
    const id = strOf(c, "id").?;
    const f = try frameOf(a, c.object.get("frame").?);
    const sj = c.object.get("spec").?;
    const op = strOf(sj, "op").?;
    var labels: std.ArrayList([]const u8) = .empty;
    if (sj.object.get("labels")) |lj| if (lj == .array) for (lj.array.items) |l| try labels.append(a, l.string);
    const inc = boolOf(sj, "include_intervals");
    const arg = sj.object.get("arg").?;
    var res: anyerror!Frame = undefined;
    if (std.mem.eql(u8, op, "intervals")) {
        const pts: df.BinPoints = if (arg == .integer) .{ .count = @intCast(@max(arg.integer, 0)) } else blk: {
            const bs = try a.alloc(Value, arg.array.items.len);
            for (bs, arg.array.items) |*b, x| b.* = try jcell(a, x);
            break :blk .{ .at = bs };
        };
        if (arg == .integer and arg.integer < 0) return testing.expect(boolOf(c, "error"));
        res = df.binIntervals(a, f, .{ .col = "x", .out = "o", .breaks = pts, .labels = labels.items, .include_intervals = inc, .right_closed = boolOf(sj, "right_closed") });
    } else {
        const fr: df.BinFractions = if (arg == .integer) .{ .count = @intCast(arg.integer) } else blk: {
            const xs = try a.alloc(f64, arg.array.items.len);
            for (xs, arg.array.items) |*x, j| x.* = num(j);
            break :blk .{ .at = xs };
        };
        res = if (std.mem.eql(u8, op, "quantiles"))
            df.binQuantiles(a, f, .{ .col = "x", .out = "o", .quantiles = fr, .labels = labels.items, .include_intervals = inc, .right_closed = boolOf(sj, "right_closed") })
        else
            df.binRanks(a, f, .{ .col = "x", .out = "o", .ranks = fr, .labels = labels.items, .include_intervals = inc });
    }
    if (boolOf(c, "error")) {
        try testing.expect(std.meta.isError(res));
        return;
    }
    const out = try res;
    const s = out.series("o") orelse return fail(id, "no output", .{});
    const want = arrOf(c, "expect");
    if (out.len != want.len) return fail(id, "{d} rows, want {d}", .{ out.len, want.len });
    for (want, 0..) |w, i| {
        if (!sameBin(w, s.get(i))) return fail(id, "row {d}: got {any}, want {any}", .{ i, s.get(i), w });
    }
}

fn runOffset(a: std.mem.Allocator, c: J) !void {
    const id = strOf(c, "id").?;
    const inst = arrOf(c, "inst");
    const cells = try a.alloc(Value, inst.len);
    for (cells, inst) |*v, x| v.* = try jcell(a, x);
    const cols = try a.dupe(Column, &.{.{ .name = "ts", .type = .timestamp, .time_zone = strOf(c, "zone").? }});
    const data = try a.alloc(fm.ColumnData, 1);
    data[0] = try fm.columnFromCells(a, cells);
    const f: Frame = .{ .columns = cols, .data = data, .len = inst.len };
    const x = try a.create(Expr);
    x.* = .{ .col = "ts" };
    const out = try df.mutate(a, f, &.{.{ .out = "o", .expr = .{ .offset_by = .{ .x = x, .by = strOf(c, "by").? } } }});
    const s = out.series("o") orelse return fail(id, "no output", .{});
    for (arrOf(c, "expect"), 0..) |w, i| {
        if (!same(w, s.get(i))) fail(id, "input {d}: got {any}, want {any}", .{ inst[i].integer, s.get(i), w });
    }
}

test "oracle2i: replay the engines' answers" {
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
        const r = if (std.mem.eql(u8, kind, "expr"))
            runFind(a, c)
        else if (std.mem.eql(u8, kind, "corrwith"))
            runCorrwith(a, c)
        else if (std.mem.eql(u8, kind, "json_encode"))
            runJson(a, c)
        else if (std.mem.eql(u8, kind, "unstack"))
            runUnstack(a, c)
        else if (std.mem.eql(u8, kind, "wide_to_long"))
            runWide(a, c)
        else if (std.mem.eql(u8, kind, "offset_by_tz"))
            runOffset(a, c)
        else if (std.mem.eql(u8, kind, "bins"))
            runBins(a, c)
        else
            error.UnknownKind;
        r catch |e| fail(id, "error {s}", .{@errorName(e)});
        ran += 1;
    }
    // Silent when green: a full lane treats any stderr from a passing test as a failure.
    if (fails != 0) std.debug.print("oracle2i: {d} cases replayed, {d} mismatches\n", .{ ran, fails });
    try testing.expect(ran > 200);
    try testing.expectEqual(@as(usize, 0), fails);
}
