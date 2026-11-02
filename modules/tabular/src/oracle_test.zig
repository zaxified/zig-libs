// SPDX-License-Identifier: MIT
//! Replays `oracle_vectors.json`: what pandas and polars answered over generated
//! tables (`tools/oracle.py`, frozen; every engine disagreement labelled there). The
//! expected rows come from the engines alone, so a failure here is a difference from
//! them, never a restatement of this module.
const std = @import("std");
const testing = std.testing;
const dsmod = @import("dataset");
const t0 = @import("transforms.zig");
const t1 = @import("series.zig");
const ex = @import("expr.zig");
const win = @import("window.zig");
const Dataset = dsmod.Dataset;
const Column = dsmod.Column;
const ColumnType = dsmod.ColumnType;
const Value = dsmod.Value;
const J = std.json.Value;

const vectors = @embedFile("oracle_vectors.json");

/// Deliberate differences from what the engines answered: id substring, and why.
/// A case listed here must still DIFFER, or the entry is stale and the test fails.
const known = [_]struct { id: []const u8, why: []const u8 }{};

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

fn loadTable(a: std.mem.Allocator, tj: J) !Dataset {
    const cj = tj.object.get("columns").?.array.items;
    const cols = try a.alloc(Column, cj.len);
    for (cols, cj) |*c, x| c.* = .{ .name = jstr(x, "name"), .type = std.meta.stringToEnum(ColumnType, jstr(x, "type")).? };
    const rj = tj.object.get("rows").?.array.items;
    const rows = try a.alloc([]const Value, rj.len);
    for (rows, rj) |*r, x| {
        const nr = try a.alloc(Value, cols.len);
        for (nr, x.array.items, cols) |*n, v, c| {
            n.* = cellOf(v);
            // A float column's integral JSON number is still a float cell.
            if (c.type == .float and n.* == .int) n.* = .{ .float = @floatFromInt(n.int) };
        }
        r.* = nr;
    }
    return .{ .columns = cols, .rows = rows };
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

fn parseOp(op: J) !win.Op {
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
    if (o.get("transform")) |f| return .{ .transform = .{ .func = std.meta.stringToEnum(t0.AggFn, f.string).? } };
    if (o.get("rolling_time")) |c| return .{ .rolling_time = .{
        .time_col = c.string,
        .period = o.get("period").?.integer,
        .func = std.meta.stringToEnum(win.WinFn, o.get("func").?.string).?,
        .min_periods = @intCast(o.get("min_periods").?.integer),
    } };
    return error.BadVector;
}

fn runCase(a: std.mem.Allocator, c: J, tables: std.json.ObjectMap) !Dataset {
    const verb = jstr(c, "verb");
    const s = c.object.get("spec").?;
    var d = try loadTable(a, tables.get(jstr(c, "table")).?);
    const right: ?Dataset = if (c.object.get("right")) |r| try loadTable(a, tables.get(r.string).?) else null;
    const eq = std.mem.eql;

    if (jopt(c, "pre_select")) |names| d = try t0.select(a, d, try strs(a, names));
    if (jopt(c, "pre_drop_null")) |n| d = try t0.dropna(a, d, .{ .subset = &.{n.string} });
    if (jopt(c, "pre_cast_int")) |n| d = try ex.cast(a, d, .{ .col = n.string, .to = .int });

    if (eq(u8, verb, "aggregate")) {
        const aj = s.object.get("aggs").?.array.items;
        const aggs = try a.alloc(t0.AggCol, aj.len);
        for (aggs, aj) |*g, x| g.* = .{
            .src = jstr(x, "src"),
            .out = jstr(x, "out"),
            .func = std.meta.stringToEnum(t0.AggFn, jstr(x, "func")).?,
            .q = if (jopt(x, "q")) |q| jnum(q) else 0.5,
        };
        return t0.aggregate(a, d, .{
            .group_by = try strs(a, s.object.get("by")),
            .aggs = aggs,
            .skip_na = jbool(s, "skip_na", false),
            .sort_groups = jbool(s, "sort", false),
            .drop_missing_keys = jbool(s, "dropkeys", false),
        });
    }
    if (eq(u8, verb, "sort")) {
        const ks = s.object.get("keys").?.array.items;
        const then = try a.alloc(t0.SortKey, ks.len - 1);
        for (then, ks[1..]) |*t, k| t.* = .{ .key = jstr(k, "k"), .dir = std.meta.stringToEnum(t0.SortDir, jstr(k, "dir")).? };
        return t0.sort(a, d, .{
            .key = jstr(ks[0], "k"),
            .dir = std.meta.stringToEnum(t0.SortDir, jstr(ks[0], "dir")).?,
            .then_by = then,
            .missing = if (eq(u8, jstr(s, "missing"), "last")) .last else .first,
        });
    }
    if (eq(u8, verb, "nlargest")) return t0.nlargest(a, d, .{
        .col = jstr(s, "col"),
        .n = @intCast(s.object.get("n").?.integer),
        .dir = std.meta.stringToEnum(t0.SortDir, jstr(s, "dir")).?,
    });
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
    if (eq(u8, verb, "join")) {
        const r = try t0.select(a, right.?, try strs(a, s.object.get("keep")));
        const how = std.meta.stringToEnum(t1.JoinHow, jstr(s, "how")).?;
        return t1.join(a, d, r, .{
            .keys = try strs(a, s.object.get("on")),
            .how = how,
            .on = "",
            .right_on = try strs(a, s.object.get("right_on")),
            .suffix = if (jopt(s, "suffix")) |x| x.string else null,
            .null_keys = if (jopt(s, "null_keys")) |x| (if (eq(u8, x.string, "match")) .match else .no_match) else .match,
            .coalesce_keys = jbool(s, "coalesce", false),
        });
    }
    if (eq(u8, verb, "asof")) {
        const by = try strs(a, s.object.get("by"));
        const keep = try a.alloc([]const u8, 2 + by.len);
        keep[0] = "on";
        keep[1] = "rv";
        @memcpy(keep[2..], by);
        return t1.joinAsof(a, d, try t0.select(a, right.?, keep), .{
            .on = jstr(s, "on"),
            .by = by,
            .direction = std.meta.stringToEnum(@FieldType(t1.AsofSpec, "direction"), jstr(s, "direction")).?,
            .allow_exact = jbool(s, "allow_exact", true),
            .tolerance = if (jopt(s, "tolerance")) |x| jnum(x) else null,
        });
    }
    if (eq(u8, verb, "pivot")) return t0.pivot(a, d, .{
        .row_key = jstr(s, "r"),
        .col_key = jstr(s, "c"),
        .value_col = jstr(s, "v"),
        .agg = std.meta.stringToEnum(t0.AggFn, jstr(s, "agg")).?,
        .skip_na = jbool(s, "skip_na", false),
        .fill_value = if (jopt(s, "fill")) |x| jnum(x) else null,
    });
    if (eq(u8, verb, "melt")) return t0.unpivot(a, d, .{ .id_cols = try strs(a, s.object.get("ids")), .value_cols = try strs(a, s.object.get("vals")) });
    if (eq(u8, verb, "distinct")) return t1.distinct(a, d, .{
        .keys = try strs(a, s.object.get("keys")),
        .keep = std.meta.stringToEnum(@FieldType(t1.DistinctSpec, "keep"), jstr(s, "keep")).?,
    });
    if (eq(u8, verb, "dropna")) return t0.dropna(a, d, .{
        .subset = try strs(a, s.object.get("subset")),
        .how = if (eq(u8, jstr(s, "how"), "any")) .any else .all,
    });
    if (eq(u8, verb, "fillna")) return t0.fillna(a, d, .{ .subset = try strs(a, s.object.get("subset")), .value = .{ .float = jnum(s.object.get("value").?) } });
    if (eq(u8, verb, "value_counts")) return t0.valueCounts(a, d, .{ .cols = try strs(a, s.object.get("cols")) });
    if (eq(u8, verb, "describe")) return t0.describe(a, d, try strs(a, s.object.get("cols")));
    if (eq(u8, verb, "clip")) return t0.clip(a, d, .{ .col = jstr(s, "col"), .lower = jnum(s.object.get("lower").?), .upper = jnum(s.object.get("upper").?) });
    if (eq(u8, verb, "replace")) {
        const pj = s.object.get("pairs").?.array.items;
        const pairs = try a.alloc(t0.ReplacePair, pj.len);
        for (pairs, pj) |*p, x| p.* = .{ .from = cellOf(x.array.items[0]), .to = cellOf(x.array.items[1]) };
        return t0.replace(a, d, .{ .col = jstr(s, "col"), .pairs = pairs });
    }
    if (eq(u8, verb, "cut")) {
        const ej = s.object.get("edges").?.array.items;
        const edges = try a.alloc(f64, ej.len);
        for (edges, ej) |*e, x| e.* = jnum(x);
        return t0.cut(a, d, .{ .col = jstr(s, "col"), .out = "o", .edges = edges, .right = jbool(s, "right", true), .include_lowest = jbool(s, "lowest", false) });
    }
    if (eq(u8, verb, "tail")) return t0.tail(a, d, @intCast(s.object.get("n").?.integer));
    if (eq(u8, verb, "concat")) {
        const l = try t0.select(a, d, try strs(a, c.object.get("left_cols")));
        const r = try t0.select(a, right.?, try strs(a, c.object.get("right_cols")));
        return t0.concatByName(a, &.{ l, r });
    }
    return error.BadVector;
}

fn rankOf(v: Value) u8 {
    return switch (v) {
        .null => 0,
        .bool => 1,
        .int, .float, .decimal => 2,
        .text => 3,
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
                    const p = rounded(x.asFloat().?);
                    const q = rounded(y.asFloat().?);
                    if (p != q) return p < q;
                },
                .text => {
                    const o = std.mem.order(u8, x.text, y.text);
                    if (o != .eq) return o == .lt;
                },
                .null => {},
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
    const x = w.asFloat().?;
    const y = g.asFloat().?;
    if (std.math.isInf(x) or std.math.isInf(y)) return x == y;
    return @abs(x - y) <= 1e-9 * @max(1.0, @max(@abs(x), @abs(y)));
}

/// null = same, else what differs.
fn compare(a: std.mem.Allocator, c: J, got: Dataset) !?[]const u8 {
    const exp = c.object.get("expect").?;
    const names = try strs(a, exp.object.get("columns"));
    const width = c.object.get("width").?.integer;
    if (got.columns.len != width) return try a.print("width {d}, engines {d}", .{ got.columns.len, width });
    const idx = try a.alloc(usize, names.len);
    for (idx, names) |*ix, n| ix.* = got.columnIndex(n) orelse return try a.print("no column {s}", .{n});
    const rj = exp.object.get("rows").?.array.items;
    if (got.rows.len != rj.len) return try a.print("{d} rows, engines {d}", .{ got.rows.len, rj.len });
    const want = try a.alloc([]const Value, rj.len);
    const have = try a.alloc([]const Value, rj.len);
    for (want, have, rj, got.rows) |*w, *h, x, r| {
        const nw = try a.alloc(Value, names.len);
        const nh = try a.alloc(Value, names.len);
        for (nw, nh, x.array.items, idx) |*p, *q, v, ci| {
            p.* = normCell(cellOf(v));
            q.* = normCell(r[ci]);
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

test "oracle: the comparison sees a wrong cell, a wrong count and a wrong width" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const c = try std.json.parseFromSliceLeaky(J, a,
        \\{"order":"exact","width":1,"expect":{"columns":["o"],"rows":[[1.5],[null]]}}
    , .{});
    const cols = [_]Column{.{ .name = "o", .type = .float }};
    const good = [_][]const Value{ &.{.{ .float = 1.5 }}, &.{.{ .float = std.math.nan(f64) }} };
    const off = [_][]const Value{ &.{.{ .float = 1.5000001 }}, &null_row };
    const short = [_][]const Value{&.{.{ .float = 1.5 }}};
    try testing.expect((try compare(a, c, .{ .columns = &cols, .rows = &good })) == null);
    try testing.expect((try compare(a, c, .{ .columns = &cols, .rows = &off })) != null);
    try testing.expect((try compare(a, c, .{ .columns = &cols, .rows = &short })) != null);
    const wide = [_]Column{ cols[0], .{ .name = "z", .type = .float } };
    try testing.expect((try compare(a, c, .{ .columns = &wide, .rows = &.{} })) != null);
}

const null_row = [_]Value{.null};

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
    for (cases) |c| {
        var case_arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer case_arena.deinit();
        const ca = case_arena.allocator();
        const id = jstr(c, "id");
        var why: ?[]const u8 = null;
        if (runCase(ca, c, tables)) |got| {
            why = try compare(ca, c, got);
        } else |e| {
            why = @errorName(e);
        }
        var listed = false;
        for (known) |k| {
            if (std.mem.indexOf(u8, id, k.id) != null) listed = true;
        }
        if (why != null and !listed) {
            failed += 1;
            if (shown < 60) {
                shown += 1;
                std.debug.print("ORACLE {s}: {s}\n", .{ id, why.? });
            }
        }
        if (why == null and listed) {
            failed += 1;
            std.debug.print("ORACLE stale known-difference entry: {s}\n", .{id});
        }
    }
    if (failed != 0) {
        std.debug.print("ORACLE {d} of {d} cases differ\n", .{ failed, cases.len });
        return error.OracleMismatch;
    }
}
