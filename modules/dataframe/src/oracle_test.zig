// SPDX-License-Identifier: MIT
//! Replays `oracle_vectors.json`: what pandas and polars answered over generated
//! tables, for the verbs this module has: since 2026-11-07 all of them, every case of
//! `tabular`'s frozen vectors (`tools/filter_vectors.py`, the recipe that copies them;
//! `tabular`'s `tools/oracle.py` asked the engines). The expected rows come from the engines alone,
//! so a failure here is a difference from them, never a restatement of this module.
const std = @import("std");
const testing = std.testing;
const vm = @import("value.zig");
const fm = @import("frame.zig");
const verbs = @import("verbs.zig");
const sp = @import("spec.zig");
const ex = @import("expr.zig");
const win = @import("window.zig");
const more = @import("more.zig");
const Frame = fm.Frame;
const Column = vm.Column;
const ColumnType = vm.ColumnType;
const Value = vm.Value;
const J = std.json.Value;

const vectors = @embedFile("oracle_vectors.json");

/// Deliberate differences from what the engines answered: id substring, and why.
/// A case listed here must still DIFFER, or the entry is stale and the test fails.
const known = [_]struct { id: []const u8, why: []const u8, always: bool = true }{
    .{ .id = "-big-agg-sum", .why = "`aggregate` `sum` adds in f64, so 2^53 + 1 is lost; both engines keep int64. `sum_exact` is exact; the default moves to the engines' in D2" },
    .{ .id = "-cast-text-int", .why = "text \"1e2\" to int: a whole number here (and pandas' to_numeric), null in polars. Not every seed draws it", .always = false },
};

/// Deliberate differences in output TYPE from BOTH engines, listed the same way.
const known_types = [_]struct { id: []const u8, why: []const u8 }{
    .{ .id = "-agg-sum-h-n", .why = "`aggregate` `sum` of an int column is float (`.big-agg-sum`); both engines int" },
    .{ .id = "-agg-sum-g-n", .why = "the same" },
    .{ .id = "-agg-sum-g+h-n", .why = "the same" },
    .{ .id = "-agg-prod-h-n", .why = "`prod` is float; both engines int, wrapping" },
    .{ .id = "-agg-prod-g-n", .why = "the same" },
    .{ .id = "-agg-prod-g+h-n", .why = "the same" },
};

fn jstr(o: J, k: []const u8) []const u8 {
    return o.object.get(k).?.string;
}

fn jopt(o: J, k: []const u8) ?J {
    const v = o.object.get(k) orelse return null;
    return if (v == .null) null else v;
}

fn jbool(o: J, k: []const u8, d: bool) bool {
    return if (jopt(o, k)) |v| v.bool else d;
}

fn jnum(v: J) f64 {
    return switch (v) {
        .integer => |i| @floatFromInt(i),
        .float => |f| f,
        else => unreachable, // the vectors put a number here
    };
}

fn cellOf(v: J) Value {
    return switch (v) {
        .null => .null,
        .bool => |b| .{ .bool = b },
        .integer => |i| .{ .int = i },
        .float => |f| .{ .float = f },
        .string => |s| if (std.mem.eql(u8, s, "NaN")) .{ .float = std.math.nan(f64) } else .{ .text = s },
        else => unreachable, // no other cell in the vectors
    };
}

fn loadTable(a: std.mem.Allocator, tj: J) !Frame {
    const cj = tj.object.get("columns").?.array.items;
    const cols = try a.alloc(Column, cj.len);
    for (cols, cj) |*c, x| {
        // `mixnum`: declared float, ints and floats side by side, what a key column
        // assembled from several sources holds. Both engines only ever see floats.
        const ty = jstr(x, "type");
        c.* = .{ .name = jstr(x, "name"), .type = if (std.mem.eql(u8, ty, "mixnum")) .float else std.meta.stringToEnum(ColumnType, ty).? };
    }
    const rj = tj.object.get("rows").?.array.items;
    var b = try fm.FrameBuilder.init(a, cols, rj.len);
    const row = try a.alloc(Value, cols.len);
    for (rj) |x| {
        for (row, x.array.items, cols, cj) |*n, v, c, cdef| {
            n.* = cellOf(v);
            // A float column's integral JSON number is still a float cell.
            if (c.type == .float and n.* == .int and !std.mem.eql(u8, jstr(cdef, "type"), "mixnum")) {
                const f: f64 = @floatFromInt(n.int);
                n.* = .{ .float = f };
            }
        }
        try b.appendRow(row);
    }
    return b.toOwned();
}

fn strs(a: std.mem.Allocator, v: ?J) ![]const []const u8 {
    const xs = (v orelse return &.{}).array.items;
    const out = try a.alloc([]const u8, xs.len);
    for (out, xs) |*o, x| o.* = x.string;
    return out;
}

fn parseExpr(a: std.mem.Allocator, e: J) anyerror!ex.Expr {
    const one = struct {
        fn f(al: std.mem.Allocator, x: J) anyerror!*const ex.Expr {
            const p = try al.create(ex.Expr);
            p.* = try parseExpr(al, x);
            return p;
        }
    }.f;
    const o = e.object;
    if (o.get("col")) |c| return .{ .col = c.string };
    if (o.get("lit")) |v| return .{ .lit = cellOf(v) };
    if (o.get("un")) |op| return .{ .unary = .{ .op = std.meta.stringToEnum(ex.Unary, op.string).?, .x = try one(a, o.get("x").?) } };
    if (o.get("bin")) |op| return .{ .binary = .{ .op = std.meta.stringToEnum(ex.Binary, op.string).?, .l = try one(a, o.get("l").?), .r = try one(a, o.get("r").?) } };
    if (o.get("in")) |x| {
        const vs = o.get("vals").?.array.items;
        const out = try a.alloc(Value, vs.len);
        for (out, vs) |*c, v| c.* = cellOf(v);
        return .{ .is_in = .{ .x = try one(a, x), .values = out } };
    }
    if (o.get("if")) |c| return .{ .if_else = .{ .cond = try one(a, c), .then = try one(a, o.get("then").?), .otherwise = try one(a, o.get("else").?) } };
    if (o.get("coalesce")) |xs| {
        const out = try a.alloc(ex.Expr, xs.array.items.len);
        for (out, xs.array.items) |*c, x| c.* = try parseExpr(a, x);
        return .{ .coalesce = out };
    }
    if (o.get("replace")) |x| return .{ .replace = .{ .x = try one(a, x), .from = jstr(e, "from"), .to = jstr(e, "to") } };
    return error.BadVector;
}

fn parseOp(op: J) !win.WindowOp {
    const o = op.object;
    if (o.get("shift")) |n| return .{ .shift = .{ .n = n.integer } };
    if (o.get("diff")) |n| return .{ .diff = n.integer };
    if (o.get("pct_change")) |n| return .{ .pct_change = n.integer };
    if (o.get("cum")) |c| {
        const s = c.string;
        if (std.mem.eql(u8, s, "sum")) return .cum_sum;
        if (std.mem.eql(u8, s, "prod")) return .cum_prod;
        if (std.mem.eql(u8, s, "min")) return .cum_min;
        if (std.mem.eql(u8, s, "max")) return .cum_max;
        return .cum_count;
    }
    if (o.get("ffill")) |n| return .{ .ffill = if (n == .null) null else @intCast(n.integer) };
    if (o.get("bfill")) |n| return .{ .bfill = if (n == .null) null else @intCast(n.integer) };
    if (o.get("rank")) |m| return .{ .rank = .{ .method = std.meta.stringToEnum(win.RankMethod, m.string).?, .descending = o.get("desc").?.bool } };
    if (o.get("rolling")) |w| {
        const mp = o.get("min_periods").?;
        return .{ .rolling = .{
            .window = @intCast(w.integer),
            .func = std.meta.stringToEnum(win.WinFn, o.get("func").?.string).?,
            .min_periods = if (mp == .null) null else @intCast(mp.integer),
            .center = o.get("center").?.bool,
        } };
    }
    if (o.get("expanding")) |f| return .{ .expanding = .{ .func = std.meta.stringToEnum(win.WinFn, f.string).?, .min_periods = @intCast(o.get("min_periods").?.integer) } };
    if (o.get("ewm_com")) |c| return .{ .ewm = .{
        .com = jnum(c),
        .adjust = o.get("adjust").?.bool,
        .ignore_na = o.get("ignore_na").?.bool,
        .min_periods = @intCast(o.get("min_periods").?.integer),
        .func = std.meta.stringToEnum(@FieldType(win.Ewm, "func"), o.get("func").?.string).?,
    } };
    if (o.get("interpolate")) |b| return .{ .interpolate = .{ .extend_last = b.bool } };
    if (o.get("transform")) |f| return .{ .transform = .{ .func = std.meta.stringToEnum(sp.AggFn, f.string).? } };
    if (o.get("rolling_time")) |c| return .{ .rolling_time = .{
        .time_col = c.string,
        .period = o.get("period").?.integer,
        .func = std.meta.stringToEnum(win.WinFn, o.get("func").?.string).?,
        .min_periods = @intCast(o.get("min_periods").?.integer),
    } };
    return error.BadVector;
}

/// `error.NotCovered`: the case needs a verb this module does not have yet.
fn runCase(a: std.mem.Allocator, c: J, tables: std.json.ObjectMap) !Frame {
    const verb = jstr(c, "verb");
    const s = c.object.get("spec").?;
    var d = try loadTable(a, tables.get(jstr(c, "table")).?);
    const right: ?Frame = if (c.object.get("right")) |r| try loadTable(a, tables.get(r.string).?) else null;
    const eq = std.mem.eql;

    if (jopt(c, "pre_select")) |names| d = try verbs.select(a, d, try strs(a, names));
    if (jopt(c, "pre_drop_null")) |n| d = try verbs.dropna(a, d, .{ .subset = &.{n.string} });
    if (jopt(c, "pre_cast_int")) |n| d = try ex.cast(a, d, .{ .col = n.string, .to = .int });

    if (eq(u8, verb, "aggregate")) {
        const aj = s.object.get("aggs").?.array.items;
        const aggs = try a.alloc(sp.AggCol, aj.len);
        for (aggs, aj) |*g, x| g.* = .{
            .src = jstr(x, "src"),
            .out = jstr(x, "out"),
            .func = std.meta.stringToEnum(sp.AggFn, jstr(x, "func")).?,
            .q = if (jopt(x, "q")) |q| jnum(q) else 0.5,
        };
        return verbs.aggregate(a, d, .{
            .group_by = try strs(a, s.object.get("by")),
            .aggs = aggs,
            .skip_na = jbool(s, "skip_na", false),
            .sort_groups = jbool(s, "sort", false),
            .drop_missing_keys = jbool(s, "dropkeys", false),
        });
    }
    if (eq(u8, verb, "sort")) {
        const ks = s.object.get("keys").?.array.items;
        const then = try a.alloc(sp.SortKey, ks.len - 1);
        for (then, ks[1..]) |*t, k| t.* = .{ .key = jstr(k, "k"), .dir = std.meta.stringToEnum(sp.SortDir, jstr(k, "dir")).? };
        return verbs.sort(a, d, .{
            .key = jstr(ks[0], "k"),
            .dir = std.meta.stringToEnum(sp.SortDir, jstr(ks[0], "dir")).?,
            .then_by = then,
            .missing = if (eq(u8, jstr(s, "missing"), "last")) .last else .first,
        });
    }
    if (eq(u8, verb, "mutate")) return ex.mutate(a, d, &.{.{ .out = jstr(s, "out"), .expr = try parseExpr(a, s.object.get("expr").?) }});
    if (eq(u8, verb, "where")) {
        const e = try parseExpr(a, s.object.get("expr").?);
        return ex.where(a, d, &e);
    }
    if (eq(u8, verb, "cast")) return ex.cast(a, d, .{ .col = jstr(s, "col"), .to = std.meta.stringToEnum(ColumnType, jstr(s, "to")).? });
    if (eq(u8, verb, "window")) return win.window(a, d, .{
        .value_col = jstr(s, "value"),
        .out = "o",
        .op = try parseOp(s.object.get("op").?),
        .partition_by = try strs(a, s.object.get("by")),
    });
    if (eq(u8, verb, "nlargest")) return more.nlargest(a, d, .{
        .col = jstr(s, "col"),
        .n = @intCast(s.object.get("n").?.integer),
        .dir = std.meta.stringToEnum(sp.SortDir, jstr(s, "dir")).?,
    });
    if (eq(u8, verb, "asof")) {
        const by = try strs(a, s.object.get("by"));
        const keep = try a.alloc([]const u8, 2 + by.len);
        keep[0] = "on";
        keep[1] = "rv";
        @memcpy(keep[2..], by);
        return more.joinAsof(a, d, try verbs.select(a, right.?, keep), .{
            .on = jstr(s, "on"),
            .by = by,
            .direction = std.meta.stringToEnum(@FieldType(more.AsofSpec, "direction"), jstr(s, "direction")).?,
            .allow_exact = jbool(s, "allow_exact", true),
            .tolerance = if (jopt(s, "tolerance")) |x| jnum(x) else null,
        });
    }
    if (eq(u8, verb, "join")) {
        const r = try verbs.select(a, right.?, try strs(a, s.object.get("keep")));
        const how = std.meta.stringToEnum(sp.JoinHow, jstr(s, "how")).?;
        return verbs.join(a, d, r, .{
            .keys = try strs(a, s.object.get("on")),
            .how = how,
            .on = "",
            .right_on = try strs(a, s.object.get("right_on")),
            .suffix = if (jopt(s, "suffix")) |x| x.string else null,
            .null_keys = if (jopt(s, "null_keys")) |x| (if (eq(u8, x.string, "match")) .match else .no_match) else .match,
            .coalesce_keys = jbool(s, "coalesce", false),
        });
    }
    if (eq(u8, verb, "pivot")) return verbs.pivot(a, d, .{
        .row_key = jstr(s, "r"),
        .col_key = jstr(s, "c"),
        .value_col = jstr(s, "v"),
        .agg = std.meta.stringToEnum(sp.AggFn, jstr(s, "agg")).?,
        .skip_na = jbool(s, "skip_na", false),
        .fill_value = if (jopt(s, "fill")) |x| jnum(x) else null,
    });
    if (eq(u8, verb, "melt")) return verbs.unpivot(a, d, .{ .id_cols = try strs(a, s.object.get("ids")), .value_cols = try strs(a, s.object.get("vals")) });
    if (eq(u8, verb, "distinct")) return verbs.distinct(a, d, .{
        .keys = try strs(a, s.object.get("keys")),
        .keep = std.meta.stringToEnum(@FieldType(sp.DistinctSpec, "keep"), jstr(s, "keep")).?,
    });
    if (eq(u8, verb, "dropna")) return verbs.dropna(a, d, .{
        .subset = try strs(a, s.object.get("subset")),
        .how = if (eq(u8, jstr(s, "how"), "any")) .any else .all,
    });
    if (eq(u8, verb, "fillna")) return verbs.fillna(a, d, .{ .subset = try strs(a, s.object.get("subset")), .value = .{ .float = jnum(s.object.get("value").?) } });
    if (eq(u8, verb, "value_counts")) return more.valueCounts(a, d, .{ .cols = try strs(a, s.object.get("cols")) });
    if (eq(u8, verb, "describe")) return more.describe(a, d, try strs(a, s.object.get("cols")));
    if (eq(u8, verb, "clip")) return more.clip(a, d, .{ .col = jstr(s, "col"), .lower = jnum(s.object.get("lower").?), .upper = jnum(s.object.get("upper").?) });
    if (eq(u8, verb, "replace")) {
        const pj = s.object.get("pairs").?.array.items;
        const pairs = try a.alloc(more.ReplacePair, pj.len);
        for (pairs, pj) |*p, x| p.* = .{ .from = cellOf(x.array.items[0]), .to = cellOf(x.array.items[1]) };
        return more.replace(a, d, .{ .col = jstr(s, "col"), .pairs = pairs });
    }
    if (eq(u8, verb, "cut")) {
        const ej = s.object.get("edges").?.array.items;
        const edges = try a.alloc(f64, ej.len);
        for (edges, ej) |*e, x| e.* = jnum(x);
        return more.cut(a, d, .{ .col = jstr(s, "col"), .out = "o", .edges = edges, .right = jbool(s, "right", true), .include_lowest = jbool(s, "lowest", false) });
    }
    if (eq(u8, verb, "tail")) return more.tail(a, d, @intCast(s.object.get("n").?.integer));
    if (eq(u8, verb, "concat")) {
        const l = try verbs.select(a, d, try strs(a, c.object.get("left_cols")));
        const r = try verbs.select(a, right.?, try strs(a, c.object.get("right_cols")));
        return more.concatByName(a, &.{ l, r });
    }
    return error.NotCovered;
}

fn rankOf(v: Value) u8 {
    return switch (v) {
        .null => 0,
        .bool => 1,
        .int, .float, .decimal => 2,
        .text => 3,
        .list, .record => 4, // the engines' vectors hold none
    };
}

fn missing(v: Value) bool {
    return v == .null or (v == .float and std.math.isNan(v.float));
}

fn normCell(v: Value) Value {
    return if (missing(v)) .null else v;
}

fn rounded(x: f64) f64 {
    return @round(x * 1e9) / 1e9;
}

const RowCtx = struct {
    fn lt(_: void, l: []const Value, m: []const Value) bool {
        for (l, m) |x, y| {
            const rx = rankOf(x);
            const ry = rankOf(y);
            if (rx != ry) return rx < ry;
            switch (x) {
                .bool => if (x.bool != y.bool) return !x.bool,
                .int, .float, .decimal => {
                    if (x == .int and y == .int) {
                        if (x.int != y.int) return x.int < y.int;
                        continue;
                    }
                    const p = rounded(x.asFloat().?);
                    const q = rounded(y.asFloat().?);
                    if (p != q) return p < q;
                },
                .text => {
                    const o = std.mem.order(u8, x.text, y.text);
                    if (o != .eq) return o == .lt;
                },
                .null, .list, .record => {},
            }
        }
        return false;
    }
};

fn nearCell(want: Value, got: Value) bool {
    const w = normCell(want);
    const g = normCell(got);
    if (w == .null or g == .null) return w == .null and g == .null;
    if (w == .text and std.mem.eql(u8, w.text, "inf")) return g == .float and g.float == std.math.inf(f64);
    if (w == .text and std.mem.eql(u8, w.text, "-inf")) return g == .float and g.float == -std.math.inf(f64);
    if (w == .text or g == .text) return w == .text and g == .text and std.mem.eql(u8, w.text, g.text);
    if (w == .bool or g == .bool) {
        const x: f64 = if (w == .bool) @floatFromInt(@intFromBool(w.bool)) else w.asFloat().?;
        const y: f64 = if (g == .bool) @floatFromInt(@intFromBool(g.bool)) else g.asFloat().?;
        return x == y;
    }
    // The engines' integer exactly: past 2^53 a float near it is a different number.
    if (w == .int) return w.order(g) == .eq or (@abs(w.int) < (1 << 53) and nearFloat(w.asFloat().?, g.asFloat().?));
    return nearFloat(w.asFloat().?, g.asFloat().?);
}

fn nearFloat(x: f64, y: f64) bool {
    if (std.math.isInf(x) or std.math.isInf(y)) return x == y;
    return @abs(x - y) <= 1e-9 * @max(1.0, @max(@abs(x), @abs(y)));
}

/// null = same, else what differs.
fn compare(a: std.mem.Allocator, c: J, got: Frame) !?[]const u8 {
    const exp = c.object.get("expect").?;
    const names = try strs(a, exp.object.get("columns"));
    const width = c.object.get("width").?.integer;
    if (got.columns.len != width) return try a.print("width {d}, engines {d}", .{ got.columns.len, width });
    const idx = try a.alloc(usize, names.len);
    for (idx, names) |*ix, n| ix.* = got.columnIndex(n) orelse return try a.print("no column {s}", .{n});
    const rj = exp.object.get("rows").?.array.items;
    if (got.len != rj.len) return try a.print("{d} rows, engines {d}", .{ got.len, rj.len });
    const want = try a.alloc([]const Value, rj.len);
    const have = try a.alloc([]const Value, rj.len);
    for (want, have, rj, 0..) |*w, *h, x, ri| {
        const nw = try a.alloc(Value, names.len);
        const nh = try a.alloc(Value, names.len);
        for (nw, nh, x.array.items, idx) |*p, *q, v, ci| {
            p.* = normCell(cellOf(v));
            q.* = normCell(got.columnAt(ci).get(ri));
        }
        w.* = nw;
        h.* = nh;
    }
    if (std.mem.eql(u8, jstr(c, "order"), "any")) {
        std.mem.sort([]const Value, want, {}, RowCtx.lt);
        std.mem.sort([]const Value, have, {}, RowCtx.lt);
    }
    for (want, have, 0..) |w, h, ri| {
        for (w, h, names) |x, y, n| {
            if (!nearCell(x, y)) return try a.print("row {d} col {s}: engines {any}, ours {any}", .{ ri, n, x, y });
        }
    }
    return null;
}

fn kindName(ty: ColumnType) []const u8 {
    return switch (ty) {
        .int, .timestamp, .duration => "int",
        .float => "float",
        .text, .date, .categorical => "text",
        .bool => "bool",
        .decimal => "decimal",
        .list => "list",
        .@"struct" => "struct",
    };
}

fn cellFits(ty: ColumnType, v: Value) bool {
    if (missing(v)) return true;
    return switch (ty) {
        .int, .timestamp, .duration => v == .int,
        .float => v == .float,
        .text, .date, .categorical => v == .text,
        .bool => v == .bool,
        .decimal => v == .decimal,
        .list => v == .list,
        .@"struct" => v == .record,
    };
}

/// null = the type is one an engine gives and every cell fits it, else what differs.
/// A column named `mx` holds ints in a float column on purpose (see `loadTable`).
fn compareTypes(a: std.mem.Allocator, c: J, got: Frame) !?[]const u8 {
    const names = try strs(a, c.object.get("expect").?.object.get("columns"));
    const pt = c.object.get("ptypes");
    const qt = c.object.get("qtypes");
    for (names, 0..) |n, i| {
        const ci = got.columnIndex(n).?;
        const ty = got.columns[ci].type;
        var ok = false;
        for ([_]?J{ pt, qt }) |ts| {
            const k = (ts orelse continue).array.items[i].string;
            if (std.mem.eql(u8, k, kindName(ty)) or std.mem.eql(u8, k, "null")) ok = true;
        }
        if (!ok) return try a.print("column {s} is {s}", .{ n, kindName(ty) });
        if (std.mem.eql(u8, n, "mx")) continue;
        for (0..got.len) |ri| {
            const v = got.columnAt(ci).get(ri);
            if (!cellFits(ty, v)) return try a.print("column {s} declared {s} holds {any}", .{ n, kindName(ty), v });
        }
    }
    return null;
}

test "oracle: the comparison sees a wrong cell, a wrong count and a wrong width" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const c = try std.json.parseFromSliceLeaky(J, a,
        \\{"order":"exact","width":1,"expect":{"columns":["o"],"rows":[[1.5],[null]]}}
    , .{});
    const cols = [_]Column{.{ .name = "o", .type = .float }};
    const good = [_]fm.ColumnData{.{ .float = .{ .values = &.{ 1.5, std.math.nan(f64) } } }};
    const off = [_]fm.ColumnData{.{ .float = .{ .values = &.{ 1.5000001, 0 }, .valid = &.{1} } }};
    const short = [_]fm.ColumnData{.{ .float = .{ .values = &.{1.5} } }};
    try testing.expect((try compare(a, c, .{ .columns = &cols, .data = &good, .len = 2 })) == null);
    try testing.expect((try compare(a, c, .{ .columns = &cols, .data = &off, .len = 2 })) != null);
    try testing.expect((try compare(a, c, .{ .columns = &cols, .data = &short, .len = 1 })) != null);
    const wide = [_]Column{ cols[0], .{ .name = "z", .type = .float } };
    try testing.expect((try compare(a, c, .{ .columns = &wide, .data = &.{}, .len = 0 })) != null);
}

test "oracle: pandas and polars vectors" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const root = try std.json.parseFromSliceLeaky(J, a, vectors, .{});
    const tables = root.object.get("tables").?.object;
    const cases = root.object.get("cases").?.array.items;
    try testing.expect(cases.len > 500);
    var failed: usize = 0;
    var shown: usize = 0;
    var type_diffs: usize = 0;
    var not_covered: usize = 0;
    var ran: usize = 0;
    for (cases) |c| {
        var case_arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer case_arena.deinit();
        const ca = case_arena.allocator();
        const id = jstr(c, "id");
        var why: ?[]const u8 = null;
        var type_why: ?[]const u8 = null;
        if (runCase(ca, c, tables)) |got| {
            ran += 1;
            why = try compare(ca, c, got);
            if (why == null) type_why = try compareTypes(ca, c, got);
        } else |e| {
            if (e == error.NotCovered) {
                not_covered += 1;
                continue;
            }
            why = @errorName(e);
        }
        var type_listed = false;
        for (known_types) |k| {
            if (std.mem.find(u8, id, k.id) != null) type_listed = true;
        }
        if (type_why != null) type_diffs += 1;
        if (type_why != null and !type_listed) {
            failed += 1;
            if (shown < 80) {
                shown += 1;
                std.debug.print("ORACLE TYPE {s}: {s}\n", .{ id, type_why.? });
            }
        }
        if (type_why == null and why == null and type_listed) {
            failed += 1;
            std.debug.print("ORACLE stale known-type entry: {s}\n", .{id});
        }
        var listed = false;
        for (known) |k| {
            if (std.mem.find(u8, id, k.id) != null) listed = true;
        }
        if (why != null and !listed) {
            failed += 1;
            if (shown < 80) {
                shown += 1;
                std.debug.print("ORACLE {s}: {s}\n", .{ id, why.? });
            }
        }
        var must_differ = false;
        for (known) |k| {
            if (std.mem.find(u8, id, k.id) != null) must_differ = k.always;
        }
        if (why == null and must_differ) {
            failed += 1;
            std.debug.print("ORACLE stale known-difference entry: {s}\n", .{id});
        }
    }
    // Every case of the filtered file has its verb here.
    try testing.expectEqual(@as(usize, 0), not_covered);
    try testing.expectEqual(cases.len, ran);
    if (failed != 0) {
        std.debug.print("ORACLE {d} of {d} cases differ\n", .{ failed, cases.len });
        return error.OracleMismatch;
    }
}
