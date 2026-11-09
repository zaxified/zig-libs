// SPDX-License-Identifier: MIT
//! Replays `oracle2d_vectors.json` (dataframe S2 wave W5): what pandas 3.1 and polars 2.1
//! answered for rolling windows with `closed`/`step`/forward/weights/`win_type`, time
//! windows (`rolling_*_by`, `rank_by`, `corr`/`cov`), `ewm` with `times`, `sum`, `_by`,
//! `cov`/`corr`, `cum_*(reverse)`, `over(order_by, mapping_strategy)`, and
//! `group_by_dynamic` / `resample` with their options (`tools/oracle2d.py` asked the
//! engines; no line of this module is consulted there). SciPy was not installed: the
//! `win_type` vectors are pandas' own aggregation over windows computed from the formulas
//! in SciPy's documentation, so they check the aggregation and the window shapes against
//! that documentation, not against SciPy's code. The expected values are the engines'
//! alone, so a failure is a difference from them.
const std = @import("std");
const testing = std.testing;
const vm = @import("value.zig");
const fm = @import("frame.zig");
const win = @import("window.zig");
const fo = @import("frameops.zig");
const sp = @import("spec.zig");
const Frame = fm.Frame;
const Column = vm.Column;
const Value = vm.Value;
const J = std.json.Value;

const vectors = @embedFile("oracle2d_vectors.json");

/// Deliberate differences from what the engines answered: id substring and why.
const known = [_]struct { id: []const u8, why: []const u8 }{
    .{ .id = "none-yet", .why = "none" },
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
            return @abs(f - x) <= 1e-9 * @max(1.0, @max(@abs(f), @abs(x)));
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

var fails: usize = 0;
var ran: usize = 0;

fn fail(id: []const u8, comptime fmt: []const u8, args: anytype) void {
    fails += 1;
    if (fails <= 40) std.debug.print("MISMATCH {s}: " ++ fmt ++ "\n", .{id} ++ args);
}

fn strOf(o: J, k: []const u8) ?[]const u8 {
    const v = o.object.get(k) orelse return null;
    return if (v == .string) v.string else null;
}

fn fOf(o: J, k: []const u8) ?f64 {
    const v = o.object.get(k) orelse return null;
    return switch (v) {
        .float => |x| x,
        .integer => |i| @floatFromInt(i),
        else => null,
    };
}

fn iOf(o: J, k: []const u8) ?i64 {
    const v = o.object.get(k) orelse return null;
    return switch (v) {
        .integer => |i| i,
        .float => |x| @intFromFloat(x),
        else => null,
    };
}

fn uOf(o: J, k: []const u8) ?usize {
    return if (iOf(o, k)) |i| @intCast(i) else null;
}

fn bOf(o: J, k: []const u8, dflt: bool) bool {
    const v = o.object.get(k) orelse return dflt;
    return if (v == .bool) v.bool else dflt;
}

fn enumOf(comptime E: type, o: J, k: []const u8, dflt: E) E {
    const s = strOf(o, k) orelse return dflt;
    return std.meta.stringToEnum(E, s).?;
}

fn winType(o: J) !win.WinType {
    const name = strOf(o, "name").?;
    const eq = std.mem.eql;
    const plain = [_]struct { []const u8, win.WinType }{
        .{ "boxcar", .boxcar },
        .{ "triang", .triang },
        .{ "hamming", .hamming },
        .{ "hann", .hann },
        .{ "bartlett", .bartlett },
        .{ "barthann", .barthann },
        .{ "blackman", .blackman },
        .{ "blackmanharris", .blackmanharris },
        .{ "nuttall", .nuttall },
        .{ "flattop", .flattop },
        .{ "parzen", .parzen },
        .{ "bohman", .bohman },
        .{ "cosine", .cosine },
    };
    for (plain) |p| if (eq(u8, name, p[0])) return p[1];
    if (eq(u8, name, "exponential")) return .{ .exponential = .{ .tau = fOf(o, "tau").? } };
    if (eq(u8, name, "gaussian")) return .{ .gaussian = .{ .std = fOf(o, "std").? } };
    if (eq(u8, name, "general_gaussian")) return .{ .general_gaussian = .{ .p = fOf(o, "p").?, .sig = fOf(o, "sig").? } };
    if (eq(u8, name, "kaiser")) return .{ .kaiser = .{ .beta = fOf(o, "beta").? } };
    return error.UnknownWindow;
}

fn ewmOf(o: J) win.Ewm {
    return .{
        .alpha = fOf(o, "alpha"),
        .span = fOf(o, "span"),
        .com = fOf(o, "com"),
        .halflife = fOf(o, "halflife"),
        .adjust = bOf(o, "adjust", true),
        .ignore_na = bOf(o, "ignore_na", false),
        .min_periods = uOf(o, "min_periods") orelse 0,
        .func = enumOf(@FieldType(win.Ewm, "func"), o, "func", .mean),
        .times_col = strOf(o, "times_col"),
    };
}

fn opOf(a: std.mem.Allocator, o: J) !win.WindowOp {
    const k = strOf(o, "k").?;
    const eq = std.mem.eql;
    if (eq(u8, k, "cum_sum")) return .cum_sum;
    if (eq(u8, k, "cum_prod")) return .cum_prod;
    if (eq(u8, k, "cum_min")) return .cum_min;
    if (eq(u8, k, "cum_max")) return .cum_max;
    if (eq(u8, k, "cum_count")) return .cum_count;
    if (eq(u8, k, "shift")) return .{ .shift = .{ .n = iOf(o, "n").? } };
    if (eq(u8, k, "rolling")) {
        var r: win.Rolling = .{ .window = uOf(o, "window").? };
        r.func = enumOf(win.WinFn, o, "func", .mean);
        r.min_periods = uOf(o, "min_periods");
        r.center = bOf(o, "center", false);
        r.closed = enumOf(win.Closed, o, "closed", .right);
        r.step = uOf(o, "step") orelse 1;
        r.forward = bOf(o, "forward", false);
        if (o.object.get("weights")) |w| {
            const ws = try a.alloc(f64, w.array.items.len);
            for (ws, w.array.items) |*x, j| x.* = switch (j) {
                .float => |f| f,
                .integer => |i| @floatFromInt(i),
                else => unreachable,
            };
            r.weights = ws;
        }
        if (o.object.get("win_type")) |w| r.win_type = try winType(w);
        return .{ .rolling = r };
    }
    if (eq(u8, k, "rolling_time")) {
        return .{ .rolling_time = .{
            .time_col = strOf(o, "time_col").?,
            .period = iOf(o, "period").?,
            .func = enumOf(win.WinFn, o, "func", .mean),
            .min_periods = uOf(o, "min_periods") orelse 1,
            .closed = enumOf(win.Closed, o, "closed", .right),
        } };
    }
    if (eq(u8, k, "rolling_rank")) {
        return .{ .rolling_rank = .{
            .window = null,
            .min_periods = uOf(o, "min_periods"),
            .method = enumOf(win.RankMethod, o, "method", .average),
            .time_col = strOf(o, "time_col"),
            .period = iOf(o, "period") orelse 0,
            .closed = enumOf(win.Closed, o, "closed", .right),
        } };
    }
    if (eq(u8, k, "rolling_corr") or eq(u8, k, "rolling_cov")) {
        const p: win.RollingPair = .{
            .other = strOf(o, "other").?,
            .window = null,
            .min_periods = uOf(o, "min_periods"),
            .time_col = strOf(o, "time_col"),
            .period = iOf(o, "period") orelse 0,
            .closed = enumOf(win.Closed, o, "closed", .right),
        };
        return if (eq(u8, k, "rolling_corr")) .{ .rolling_corr = p } else .{ .rolling_cov = p };
    }
    if (eq(u8, k, "ewm")) return .{ .ewm = ewmOf(o) };
    if (eq(u8, k, "ewm_by")) {
        return .{ .ewm_by = .{
            .time_col = strOf(o, "time_col").?,
            .half_life = iOf(o, "half_life").?,
            .func = enumOf(@FieldType(win.EwmBy, "func"), o, "func", .mean),
        } };
    }
    if (eq(u8, k, "ewm_cov") or eq(u8, k, "ewm_corr")) {
        const p: win.EwmPair = .{ .other = strOf(o, "other").?, .ewm = ewmOf(o), .bias = bOf(o, "bias", false) };
        return if (eq(u8, k, "ewm_cov")) .{ .ewm_cov = p } else .{ .ewm_corr = p };
    }
    return error.UnknownOp;
}

fn strList(a: std.mem.Allocator, o: J, k: []const u8) ![]const []const u8 {
    const v = o.object.get(k) orelse return &.{};
    const out = try a.alloc([]const u8, v.array.items.len);
    for (out, v.array.items) |*s, j| s.* = j.string;
    return out;
}

fn runWindow(a: std.mem.Allocator, c: J) !void {
    const id = strOf(c, "id").?;
    const f = try frameOf(a, c.object.get("frame").?);
    const spec: win.WindowSpec = .{
        .value_col = strOf(c, "value").?,
        .out = "r",
        .op = try opOf(a, c.object.get("op").?),
        .partition_by = try strList(a, c, "partition"),
        .order_by = try strList(a, c, "order_by"),
        .order_descending = bOf(c, "desc", false),
        .reverse = bOf(c, "reverse", false),
        .mapping = enumOf(win.Mapping, c, "mapping", .group_to_rows),
    };
    const out = try win.window(a, f, spec);
    const want = c.object.get("expect").?.array.items;
    const s = out.series("r") orelse return fail(id, "no column r", .{});
    if (s.len != want.len) return fail(id, "{d} rows, want {d}", .{ s.len, want.len });
    for (want, 0..) |w, i| {
        if (!same(w, s.get(i))) return fail(id, "row {d}: got {any}, want {any}", .{ i, s.get(i), w });
    }
}

fn runDynamic(a: std.mem.Allocator, c: J) !void {
    const id = strOf(c, "id").?;
    const f = try frameOf(a, c.object.get("frame").?);
    const sj = c.object.get("spec").?;
    const aj = c.object.get("aggs").?.array.items;
    const aggs = try a.alloc(sp.AggCol, aj.len);
    for (aggs, aj) |*g, j| g.* = .{ .src = strOf(j, "src").?, .out = strOf(j, "out").?, .func = std.meta.stringToEnum(sp.AggFn, strOf(j, "func").?).? };
    const spec: fo.DynamicSpec = .{
        .index = "t",
        .every = strOf(sj, "every") orelse "",
        .rule = strOf(sj, "rule"),
        .period = strOf(sj, "period"),
        .offset = strOf(sj, "offset"),
        .closed = enumOf(fo.DynamicClosed, sj, "closed", .left),
        .label = enumOf(fo.DynamicLabel, sj, "label", .left),
        .start_by = enumOf(fo.StartBy, sj, "start_by", .window),
        .origin = if (strOf(sj, "origin")) |s| std.meta.stringToEnum(fo.Origin, s).? else null,
        .include_boundaries = bOf(sj, "include_boundaries", false),
        .by = try strList(a, sj, "by"),
        .aggs = aggs,
    };
    const out = try fo.groupByDynamic(a, f, spec);
    const exp = c.object.get("expect").?.object;
    const cols = exp.get("cols").?.array.items;
    const rows = exp.get("rows").?.array.items;
    if (out.columns.len != cols.len) return fail(id, "{d} columns, want {d}", .{ out.columns.len, cols.len });
    if (out.len != rows.len) return fail(id, "{d} rows, want {d}", .{ out.len, rows.len });
    for (cols, 0..) |cn, ci| {
        if (!std.mem.eql(u8, out.columns[ci].name, cn.string)) return fail(id, "column {d} is {s}, want {s}", .{ ci, out.columns[ci].name, cn.string });
        for (rows, 0..) |r, ri| {
            const got = out.columnAt(ci).get(ri);
            if (!same(r.array.items[ci], got)) return fail(id, "column {s} row {d}: got {any}, want {any}", .{ cn.string, ri, got, r.array.items[ci] });
        }
    }
}

fn isKnown(id: []const u8) bool {
    for (known) |k| if (std.mem.find(u8, id, k.id) != null and !std.mem.eql(u8, k.why, "none")) return true;
    return false;
}

test "oracle2d: replay the engines' answers" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const root = try std.json.parseFromSliceLeaky(J, a, vectors, .{});
    fails = 0;
    ran = 0;
    for (root.object.get("cases").?.array.items) |c| {
        const id = strOf(c, "id").?;
        if (isKnown(id)) continue;
        const kind = strOf(c, "kind").?;
        if (std.mem.eql(u8, kind, "window")) {
            runWindow(a, c) catch |e| fail(id, "error {s}", .{@errorName(e)});
        } else {
            runDynamic(a, c) catch |e| fail(id, "error {s}", .{@errorName(e)});
        }
        ran += 1;
    }
    // Silent when green: a full lane treats any stderr from a passing test as a failure.
    if (fails != 0) std.debug.print("oracle2d: {d} cases replayed, {d} mismatches\n", .{ ran, fails });
    try testing.expect(ran > 600);
    try testing.expectEqual(@as(usize, 0), fails);
}
