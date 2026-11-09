// SPDX-License-Identifier: MIT
//! Replays `oracle2e_vectors.json` (dataframe S2 wave W6): what polars 2.1 and pandas 3.1
//! answered for the list set operations, `gather`, `gather_every`, `shift`, `diff`, `item`,
//! `to_struct`, `repeat_by`, `concat`, `list.eval`/`filter`/`agg`, the struct field
//! operations, and for `Enum` / ordered `CategoricalDtype`: sort, order comparison, codes,
//! min/max, a cast with a value outside the list, and the `Series.cat` verbs
//! (`tools/oracle2e.py` asked the engines; no line of this module is consulted there). The
//! expected values are the engines' alone, so a failure is a difference from them.
const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const Frame = df.Frame;
const Value = df.Value;
const Expr = df.Expr;
const J = std.json.Value;

const vectors = @embedFile("oracle2e_vectors.json");

/// Deliberate differences from what the engines answered: id substring and why.
const known = [_]struct { id: []const u8, why: []const u8 }{
    .{ .id = "none-yet", .why = "none" },
};

fn same(want: J, got: Value) bool {
    switch (want) {
        .null => return got == .null or (got == .float and std.math.isNan(got.float)),
        .bool => |b| return got == .bool and got.bool == b,
        .integer => |i| return switch (got) {
            .int => |x| x == i,
            .float => |x| x == @as(f64, @floatFromInt(i)),
            else => false,
        },
        .float => |f| {
            const x = got.asFloat() orelse return false;
            return f == x or @abs(f - x) <= 1e-9 * @max(1.0, @max(@abs(f), @abs(x)));
        },
        .string => |s| return got == .text and std.mem.eql(u8, got.text, s),
        .array => |arr| {
            if (got != .list or got.list.len() != arr.items.len) return false;
            for (arr.items, 0..) |w, i| if (!same(w, got.list.get(i))) return false;
            return true;
        },
        .object => |o| {
            if (got != .record or got.record.len() != o.count()) return false;
            for (o.keys(), o.values(), 0..) |k, w, i| {
                if (!std.mem.eql(u8, got.record.name(i), k)) return false;
                if (!same(w, got.record.get(i))) return false;
            }
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

fn iOf(o: J, k: []const u8) ?i64 {
    const v = o.object.get(k) orelse return null;
    return if (v == .integer) v.integer else null;
}

fn strList(a: std.mem.Allocator, o: J, k: []const u8) ![]const []const u8 {
    const v = o.object.get(k) orelse return &.{};
    if (v != .array) return &.{};
    const out = try a.alloc([]const u8, v.array.items.len);
    for (out, v.array.items) |*s, j| s.* = j.string;
    return out;
}

fn box(a: std.mem.Allocator, e: Expr) !*const Expr {
    const p = try a.create(Expr);
    p.* = e;
    return p;
}

fn col(a: std.mem.Allocator, name: []const u8) !*const Expr {
    return box(a, .{ .col = name });
}

fn lit(a: std.mem.Allocator, v: i64) !*const Expr {
    return box(a, .{ .lit = .{ .int = v } });
}

fn setOp(op: []const u8) ?df.SetOp {
    if (std.mem.eql(u8, op, "set_union")) return .@"union";
    if (std.mem.eql(u8, op, "set_intersection")) return .intersection;
    if (std.mem.eql(u8, op, "set_difference")) return .difference;
    if (std.mem.eql(u8, op, "set_symmetric_difference")) return .symmetric_difference;
    return null;
}

/// The expression of a list or struct case, over the frame's columns `a`, `b`, `i`, `y`, `v`,
/// `n`, `s`.
fn caseExpr(a: std.mem.Allocator, c: J) !Expr {
    const op = strOf(c, "op").?;
    const args = c.object.get("args").?;
    const elem = try box(a, .element);
    if (setOp(op)) |so| return .{ .list_set = .{ .x = try col(a, "a"), .y = try col(a, "b"), .op = so } };
    if (std.mem.eql(u8, op, "concat")) {
        const parts = try a.alloc(Expr, 2);
        parts[0] = .{ .col = "a" };
        parts[1] = .{ .col = "b" };
        return .{ .concat_list = parts };
    }
    const lx = try col(a, "a");
    if (std.mem.eql(u8, op, "shift")) return .{ .list = .{ .x = lx, .op = .{ .shift = iOf(args, "n").? } } };
    if (std.mem.eql(u8, op, "gather_every")) return .{ .list = .{ .x = lx, .op = .{ .gather_every = .{ .n = @intCast(iOf(args, "n").?), .offset = @intCast(iOf(args, "offset").?) } } } };
    if (std.mem.eql(u8, op, "diff")) return .{ .list = .{ .x = lx, .op = .{ .diff = .{ .n = @intCast(iOf(args, "n").?), .drop = args.object.get("drop").?.bool } } } };
    if (std.mem.eql(u8, op, "item")) return .{ .list = .{ .x = try col(a, "y"), .op = .item } };
    if (std.mem.eql(u8, op, "gather")) return .{ .list_gather = .{ .x = lx, .idx = try col(a, "i") } };
    if (std.mem.eql(u8, op, "to_struct")) return .{ .list_to_struct = .{ .x = lx, .names = try strList(a, args, "names") } };
    if (std.mem.eql(u8, op, "repeat_by")) return .{ .repeat_by = .{ .x = try col(a, "v"), .by = try col(a, "n") } };
    if (std.mem.eql(u8, op, "eval_mul") or std.mem.eql(u8, op, "eval_add")) {
        const body = try box(a, .{ .binary = .{ .op = if (op[5] == 'm') .mul else .add, .l = elem, .r = try lit(a, iOf(args, "k").?) } });
        return .{ .list_eval = .{ .x = lx, .body = body } };
    }
    if (std.mem.eql(u8, op, "filter_gt")) {
        const pred = try box(a, .{ .binary = .{ .op = .gt, .l = elem, .r = try lit(a, iOf(args, "k").?) } });
        return .{ .list_filter = .{ .x = lx, .pred = pred } };
    }
    if (std.mem.eql(u8, op, "agg_sum")) return .{ .list = .{ .x = try box(a, .{ .list_eval = .{ .x = lx, .body = elem } }), .op = .sum } };
    const sx = try col(a, "s");
    if (std.mem.eql(u8, op, "rename_fields")) return .{ .struct_op = .{ .x = sx, .op = .{ .rename_fields = try strList(a, args, "names") } } };
    if (std.mem.eql(u8, op, "prefix_fields")) return .{ .struct_op = .{ .x = sx, .op = .{ .map_fields = .{ .prefix = strOf(args, "text").? } } } };
    if (std.mem.eql(u8, op, "suffix_fields")) return .{ .struct_op = .{ .x = sx, .op = .{ .map_fields = .{ .suffix = strOf(args, "text").? } } } };
    if (std.mem.eql(u8, op, "upper_fields")) return .{ .struct_op = .{ .x = sx, .op = .{ .map_fields = .upper } } };
    if (std.mem.eql(u8, op, "with_fields")) {
        const fields = try a.alloc(df.NamedExpr, 2);
        fields[0] = .{ .name = "c", .x = .{ .binary = .{ .op = .mul, .l = try col(a, "a"), .r = try lit(a, iOf(args, "k").?) } } };
        fields[1] = .{ .name = "b", .x = .{ .unary = .{ .op = .upper, .x = try col(a, "b") } } };
        return .{ .struct_fields = .{ .x = sx, .fields = fields } };
    }
    if (std.mem.eql(u8, op, "struct_eval")) {
        const fields = try a.alloc(df.NamedExpr, 1);
        fields[0] = .{ .name = "a", .x = .{ .binary = .{ .op = .add, .l = try col(a, "a"), .r = try lit(a, iOf(args, "k").?) } } };
        return .{ .struct_fields = .{ .x = sx, .fields = fields, .keep = false } };
    }
    return error.UnknownOp;
}

/// Whether `got` holds the elements of `want` in any order (each once).
fn sameSet(want: J, got: Value) bool {
    if (want == .null) return got == .null;
    if (want != .array or got != .list or got.list.len() != want.array.items.len) return false;
    const used = std.testing.allocator.alloc(bool, want.array.items.len) catch return false;
    defer std.testing.allocator.free(used);
    @memset(used, false);
    for (want.array.items) |w| {
        var hit = false;
        for (0..got.list.len()) |k| {
            if (used[k] or !same(w, got.list.get(k))) continue;
            used[k] = true;
            hit = true;
            break;
        }
        if (!hit) return false;
    }
    return true;
}

fn runExpr(a: std.mem.Allocator, c: J) !void {
    const id = strOf(c, "id").?;
    const f = try df.readJson(a, strOf(c, "rows").?, .{});
    const e = try caseExpr(a, c);
    const out = try df.mutate(a, f, &.{.{ .out = "r", .expr = e }});
    const want = c.object.get("expect").?.array.items;
    if (out.len != want.len) return fail(id, "{d} rows, want {d}", .{ out.len, want.len });
    for (want, 0..) |w, ri| {
        const got = out.cell(ri, "r").?;
        // polars' set_difference lists the distinct elements in an order of its own (hash
        // order: not the list's, not stable across inputs); ours keeps the first appearance in
        // `x`. The set is the same, so that one operation is compared as a set.
        const ok = if (std.mem.eql(u8, strOf(c, "op").?, "set_difference")) sameSet(w, got) else same(w, got);
        if (!ok) return fail(id, "row {d}: got {any}, want {any}", .{ ri, got, w });
    }
}

// ── categoricals ────────────────────────────────────────────────────────────────

fn textCol(a: std.mem.Allocator, c: J) !Frame {
    return df.readJson(a, strOf(c, "rows").?, .{});
}

fn enumFrame(a: std.mem.Allocator, c: J) !Frame {
    const args = c.object.get("args").?;
    return df.cast(a, try textCol(a, c), .{ .col = "s", .to = .categorical, .categories = try strList(a, args, "categories"), .ordered = true });
}

fn expectValues(id: []const u8, f: Frame, want: []const J) bool {
    if (f.len != want.len) {
        fail(id, "{d} rows, want {d}", .{ f.len, want.len });
        return false;
    }
    for (want, 0..) |w, ri| {
        const got = f.cell(ri, "s").?;
        if (!same(w, got)) {
            fail(id, "row {d}: got {any}, want {any}", .{ ri, got, w });
            return false;
        }
    }
    return true;
}

fn runCatEngine(a: std.mem.Allocator, c: J) !void {
    const id = strOf(c, "id").?;
    const op = strOf(c, "op").?;
    const args = c.object.get("args").?;
    const want = c.object.get("expect").?;
    const f = if (std.mem.eql(u8, op, "cat_values"))
        try df.cast(a, try textCol(a, c), .{ .col = "s", .to = .categorical, .categories = try strList(a, args, "categories"), .ordered = true })
    else
        try enumFrame(a, c);
    if (std.mem.eql(u8, op, "cat_values")) {
        _ = expectValues(id, f, want.array.items);
    } else if (std.mem.eql(u8, op, "cat_sort")) {
        const desc = args.object.get("desc").?.bool;
        const g = try df.sort(a, f, .{ .key = "s", .dir = if (desc) .desc else .asc, .missing = .first });
        _ = expectValues(id, g, want.array.items);
    } else if (std.mem.eql(u8, op, "cat_cmp")) {
        const cmp = strOf(args, "cmp").?;
        const bop: df.Binary = if (std.mem.eql(u8, cmp, "lt")) .lt else if (std.mem.eql(u8, cmp, "le")) .le else if (std.mem.eql(u8, cmp, "gt")) .gt else .ge;
        const e: Expr = .{ .binary = .{ .op = bop, .l = try col(a, "s"), .r = try box(a, .{ .lit = .{ .text = strOf(args, "lit").? } }) } };
        const g = try df.mutate(a, f, &.{.{ .out = "r", .expr = e }});
        for (want.array.items, 0..) |w, ri| {
            const got = g.cell(ri, "r").?;
            if (!same(w, got)) return fail(id, "row {d}: got {any}, want {any}", .{ ri, got, w });
        }
    } else if (std.mem.eql(u8, op, "cat_codes")) {
        const g = try df.catCodes(a, f, "s");
        _ = expectValues(id, g, want.array.items);
    } else if (std.mem.eql(u8, op, "cat_min") or std.mem.eql(u8, op, "cat_max")) {
        const k = try df.mutate(a, f, &.{.{ .out = "g", .expr = .{ .lit = .{ .int = 1 } } }});
        const g = try df.aggregate(a, k, .{ .group_by = &.{"g"}, .aggs = &.{.{ .src = "s", .out = "r", .func = if (op[5] == 'i') .min else .max }}, .skip_na = true });
        const got = g.cell(0, "r").?;
        if (!same(want, got)) return fail(id, "got {any}, want {any}", .{ got, want });
    } else return error.UnknownOp;
}

fn catState(a: std.mem.Allocator, id: []const u8, f: Frame, want: J) !void {
    const w = want.object;
    if (!expectValues(id, f, w.get("values").?.array.items)) return;
    const cats = try df.catCategories(a, f, "s");
    const wc = w.get("categories").?.array.items;
    if (cats.len != wc.len) return fail(id, "{d} categories, want {d}", .{ cats.len, wc.len });
    for (cats, wc) |g, x| if (!std.mem.eql(u8, g, x.string)) return fail(id, "category {s}, want {s}", .{ g, x.string });
    if (try df.catIsOrdered(a, f, "s") != w.get("ordered").?.bool) return fail(id, "ordered flag", .{});
    const codes = try df.catCodes(a, f, "s");
    const wk = w.get("codes").?.array.items;
    for (wk, 0..) |x, ri| {
        const got = codes.cell(ri, "s").?;
        if (!same(x, got)) return fail(id, "code row {d}: got {any}, want {any}", .{ ri, got, x });
    }
}

fn runCatVerb(a: std.mem.Allocator, c: J) !void {
    const id = strOf(c, "id").?;
    const op = strOf(c, "op").?;
    const args = c.object.get("args").?;
    const want = c.object.get("expect").?;
    const base = try df.cast(a, try textCol(a, c), .{ .col = "s", .to = .categorical });
    const cats = try strList(a, args, "cats");
    const ordered: ?bool = if (args.object.get("ordered")) |o| (if (o == .bool) o.bool else null) else null;
    const res: df.CatError!Frame = if (std.mem.eql(u8, op, "add_categories"))
        df.catAddCategories(a, base, "s", cats)
    else if (std.mem.eql(u8, op, "remove_categories"))
        df.catRemoveCategories(a, base, "s", cats)
    else if (std.mem.eql(u8, op, "remove_unused"))
        df.catRemoveUnusedCategories(a, base, "s")
    else if (std.mem.eql(u8, op, "set_categories"))
        df.catSetCategories(a, base, "s", cats, ordered)
    else if (std.mem.eql(u8, op, "reorder_categories"))
        df.catReorderCategories(a, base, "s", cats, ordered)
    else if (std.mem.eql(u8, op, "rename_list"))
        df.catRenameCategories(a, base, "s", .{ .list = cats })
    else if (std.mem.eql(u8, op, "rename_map")) blk: {
        const ps = args.object.get("pairs").?.array.items;
        const pairs = try a.alloc([2][]const u8, ps.len);
        for (pairs, ps) |*p, j| p.* = .{ j.array.items[0].string, j.array.items[1].string };
        break :blk df.catRenameCategories(a, base, "s", .{ .map = pairs });
    } else if (std.mem.eql(u8, op, "as_ordered"))
        df.catSetOrdered(a, base, "s", true)
    else if (std.mem.eql(u8, op, "as_unordered"))
        df.catSetOrdered(a, base, "s", false)
    else
        return error.UnknownOp;
    if (want == .string) { // "error": pandas raised
        if (res) |_| return fail(id, "no error, pandas raised", .{}) else |e| {
            if (e != error.BadCategories) return fail(id, "error {s}, want BadCategories", .{@errorName(e)});
        }
        return;
    }
    try catState(a, id, res catch |e| return fail(id, "error {s}", .{@errorName(e)}), want);
}

fn isKnown(id: []const u8) bool {
    for (known) |k| if (std.mem.find(u8, id, k.id) != null and !std.mem.eql(u8, k.why, "none")) return true;
    return false;
}

test "oracle2e: replay the engines' answers" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const root = try std.json.parseFromSliceLeaky(J, a, vectors, .{});
    fails = 0;
    ran = 0;
    for (root.object.get("cases").?.array.items) |c| {
        const id = strOf(c, "id").?;
        if (isKnown(id)) continue;
        const op = strOf(c, "op").?;
        const r = if (std.mem.startsWith(u8, id, "cat-"))
            (if (std.mem.startsWith(u8, op, "cat_")) runCatEngine(a, c) else runCatVerb(a, c))
        else
            runExpr(a, c);
        r catch |e| fail(id, "error {s}", .{@errorName(e)});
        ran += 1;
    }
    std.debug.print("oracle2e: {d} cases replayed, {d} mismatches\n", .{ ran, fails });
    try testing.expect(ran > 300);
    try testing.expectEqual(@as(usize, 0), fails);
}
