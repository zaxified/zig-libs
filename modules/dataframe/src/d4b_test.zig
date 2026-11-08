// SPDX-License-Identifier: MIT
//! Differential tests of the typed kernels of `more.zig` and `structure.zig` against the
//! boxed-cell paths they replaced (`more.test_hooks`, `structure.test_hooks`): random
//! frames, every spec option, and the result compared structurally, ColumnData tag and
//! validity nullness included.

const std = @import("std");
const testing = std.testing;
const vm = @import("value.zig");
const fm = @import("frame.zig");
const more = @import("more.zig");
const Value = vm.Value;
const Column = vm.Column;
const ColumnData = fm.ColumnData;
const Frame = fm.Frame;

pub const Kind = enum { int, float, text, bool, boxed, decimal };

pub const lens = [_]usize{ 0, 1, 2, 63, 64, 65, 1000 };
pub const null_pcts = [_]u8{ 0, 1, 50, 100 };

const special_f = [_]f64{ std.math.nan(f64), std.math.inf(f64), -std.math.inf(f64), -0.0, 0.0, 1.5, -2.25, 1e300, -1e-300 };
const special_i = [_]i64{ std.math.minInt(i64), std.math.maxInt(i64), 0, -1, 1 };

pub fn randInt(r: std.Random) i64 {
    if (r.uintLessThan(u8, 8) == 0) return special_i[r.uintLessThan(usize, special_i.len)];
    return r.intRangeAtMost(i64, -50, 50);
}

pub fn randFloat(r: std.Random) f64 {
    if (r.uintLessThan(u8, 5) == 0) return special_f[r.uintLessThan(usize, special_f.len)];
    return @as(f64, @floatFromInt(r.intRangeAtMost(i32, -40, 40))) / 4.0;
}

pub fn randText(a: std.mem.Allocator, r: std.Random) ![]const u8 {
    const n = r.uintLessThan(usize, 5);
    const b = try a.alloc(u8, n);
    for (b) |*c| c.* = 'a' + r.uintLessThan(u8, 4);
    return b;
}

pub fn randCell(a: std.mem.Allocator, r: std.Random, kind: Kind) !Value {
    return switch (kind) {
        .int => .{ .int = randInt(r) },
        .float => .{ .float = randFloat(r) },
        .text => .{ .text = try randText(a, r) },
        .bool => .{ .bool = r.boolean() },
        .decimal => .{ .decimal = @as(i128, randInt(r)) * 250_000_000_000 },
        .boxed => switch (r.uintLessThan(u8, 4)) {
            0 => .{ .int = randInt(r) },
            1 => .{ .float = randFloat(r) },
            2 => .{ .text = try randText(a, r) },
            else => .{ .bool = r.boolean() },
        },
    };
}

pub fn colType(k: Kind) vm.ColumnType {
    return switch (k) {
        .int => .int,
        .float, .boxed => .float,
        .text => .text,
        .bool => .bool,
        .decimal => .decimal,
    };
}

pub fn randCol(a: std.mem.Allocator, r: std.Random, kind: Kind, n: usize, null_pct: u8) !ColumnData {
    const cells = try a.alloc(Value, n);
    for (cells) |*c| c.* = if (r.uintLessThan(u8, 100) < null_pct) .null else try randCell(a, r, kind);
    return fm.columnFromCells(a, cells);
}

pub fn mkFrame(a: std.mem.Allocator, names: []const []const u8, kinds: []const Kind, datas: []const ColumnData, n: usize) !Frame {
    const cols = try a.alloc(Column, names.len);
    for (cols, names, kinds) |*c, nm, k| c.* = .{ .name = nm, .type = colType(k) };
    return .{ .columns = cols, .data = try a.dupe(ColumnData, datas), .len = n };
}

fn bitsEq(x: Value, y: Value) bool {
    return switch (x) {
        .null => y == .null,
        .int => |v| y == .int and y.int == v,
        .float => |v| y == .float and @as(u64, @bitCast(y.float)) == @as(u64, @bitCast(v)),
        .text => |v| y == .text and std.mem.eql(u8, v, y.text),
        .bool => |v| y == .bool and y.bool == v,
        .decimal => |v| y == .decimal and y.decimal == v,
    };
}

fn validEq(x: ?[]const u64, y: ?[]const u64) bool {
    return (x == null) == (y == null);
}

/// The two columns are the same storage: tag, validity presence, every cell bit for bit.
pub fn sameColumn(x: ColumnData, y: ColumnData, n: usize) bool {
    if (std.meta.activeTag(x) != std.meta.activeTag(y)) return false;
    const ok = switch (x) {
        .nulls, .boxed => true,
        .int => |c| validEq(c.valid, y.int.valid) and c.values.len == y.int.values.len,
        .float => |c| validEq(c.valid, y.float.valid) and c.values.len == y.float.values.len,
        .bool => |c| validEq(c.valid, y.bool.valid) and c.values.len == y.bool.values.len,
        .decimal => |c| validEq(c.valid, y.decimal.valid) and c.values.len == y.decimal.values.len,
        .text => |c| validEq(c.valid, y.text.valid),
    };
    if (!ok) return false;
    for (0..n) |i| if (!bitsEq(x.get(i), y.get(i))) return false;
    return true;
}

pub fn sameFrame(f: Frame, g: Frame) bool {
    if (f.len != g.len or f.columns.len != g.columns.len) return false;
    for (f.columns, g.columns) |x, y| {
        if (x.type != y.type or !std.mem.eql(u8, x.name, y.name)) return false;
    }
    for (0..f.columns.len) |ci| if (!sameColumn(f.columnAt(ci), g.columnAt(ci), f.len)) return false;
    return true;
}

/// Both Ok and the same frame, or both the same error.
pub fn agree(comptime what: []const u8, new: anytype, old: anytype) !void {
    if (new) |nf| {
        if (old) |of| {
            if (!sameFrame(nf, of)) {
                std.debug.print("{s}: frames differ\n", .{what});
                return error.TestUnexpectedResult;
            }
        } else |e| {
            std.debug.print("{s}: new ok, old {s}\n", .{ what, @errorName(e) });
            return error.TestUnexpectedResult;
        }
    } else |ne| {
        if (old) |_| {
            std.debug.print("{s}: new {s}, old ok\n", .{ what, @errorName(ne) });
            return error.TestUnexpectedResult;
        } else |oe| {
            if (ne != oe) {
                std.debug.print("{s}: errors {s} vs {s}\n", .{ what, @errorName(ne), @errorName(oe) });
                return error.TestUnexpectedResult;
            }
        }
    }
}

// ── join_asof ───────────────────────────────────────────────────────────────

/// A key column of `n` cells, ascending among the present ones when `sorted`.
fn keyCol(a: std.mem.Allocator, r: std.Random, kind: Kind, n: usize, null_pct: u8, sorted: bool) !ColumnData {
    const cells = try a.alloc(Value, n);
    for (cells) |*c| c.* = try randCell(a, r, kind);
    if (sorted) std.mem.sort(Value, cells, {}, struct {
        fn lt(_: void, x: Value, y: Value) bool {
            if (x == .float and std.math.isNan(x.float)) return false;
            if (y == .float and std.math.isNan(y.float)) return true;
            return x.order(y) == .lt;
        }
    }.lt);
    for (cells) |*c| {
        if (r.uintLessThan(u8, 100) < null_pct) c.* = .null;
        // NaN lands anywhere: a present-key NaN is missing and skipped.
        if (kind == .float and r.uintLessThan(u8, 30) == 0) c.* = .{ .float = std.math.nan(f64) };
    }
    return fm.columnFromCells(a, cells);
}

test "joinAsof: typed path agrees with the cell path" {
    var cases: usize = 0;
    const key_kinds = [_][2]Kind{ .{ .int, .int }, .{ .float, .float }, .{ .int, .float }, .{ .float, .int }, .{ .boxed, .boxed }, .{ .text, .text } };
    var prng = std.Random.DefaultPrng.init(0xd4b0);
    const r = prng.random();
    for (key_kinds) |kk| for (lens) |ln| for (null_pcts) |np| for (0..2) |rep| {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const rn = lens[r.uintLessThan(usize, lens.len)];
        // The right side is unsorted in one case in twelve: both paths say NotSorted.
        const sorted = r.uintLessThan(u8, 12) != 0;
        const lkey = try keyCol(a, r, kk[0], ln, np, false);
        const rkey = try keyCol(a, r, kk[1], rn, r.uintLessThan(u8, 3) * 20 * @as(u8, @intFromBool(rep == 1)), sorted);
        const lpay = try randCol(a, r, .text, ln, 10);
        const rpay_i = try randCol(a, r, .int, rn, 10);
        const rpay_f = try randCol(a, r, .float, rn, np);
        const rpay_b = try randCol(a, r, .boxed, rn, 5);
        const left = try mkFrame(a, &.{ "on", "lp" }, &.{ kk[0], .text }, &.{ lkey, lpay }, ln);
        const right = try mkFrame(a, &.{ "on", "ri", "rf", "rb" }, &.{ kk[1], .int, .float, .boxed }, &.{ rkey, rpay_i, rpay_f, rpay_b }, rn);
        for (0..3) |dir_i| {
            const dir: @FieldType(more.AsofSpec, "direction") = @fromBackingInt(@intCast(dir_i));
            const spec: more.AsofSpec = .{
                .on = "on",
                .direction = dir,
                .allow_exact = r.boolean(),
                .tolerance = switch (r.uintLessThan(u8, 4)) {
                    0 => null,
                    1 => 0,
                    2 => 3.5,
                    else => if (r.boolean()) std.math.nan(f64) else std.math.inf(f64),
                },
                .suffix = if (r.boolean()) "_r" else null,
            };
            try agree("joinAsof", more.joinAsof(a, left, right, spec), more.test_hooks.joinAsofCells(a, left, right, spec));
            cases += 1;
        }
    };
    try testing.expect(cases >= 200);
}

// ── concat ──────────────────────────────────────────────────────────────────

/// Dirty a typed int/float column the way a hand-built frame may be: garbage in the
/// slots of null cells.
fn dirty(a: std.mem.Allocator, col: ColumnData) !ColumnData {
    switch (col) {
        .int => |c| {
            const v = try a.dupe(i64, c.values);
            for (v, 0..) |*x, i| if (!c.isValid(i)) {
                x.* = 77;
            };
            return .{ .int = .{ .values = v, .valid = c.valid } };
        },
        .float => |c| {
            const v = try a.dupe(f64, c.values);
            for (v, 0..) |*x, i| if (!c.isValid(i)) {
                x.* = 7.5;
            };
            return .{ .float = .{ .values = v, .valid = c.valid } };
        },
        else => return col,
    }
}

test "concat: typed path agrees with the cell path" {
    var cases: usize = 0;
    var prng = std.Random.DefaultPrng.init(0xd4b1);
    const r = prng.random();
    const pool = [_][]const u8{ "a", "b", "c", "d" };
    const all_kinds = [_]Kind{ .int, .float, .text, .bool, .boxed };
    for (0..400) |case| {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const nf = 1 + r.uintLessThan(usize, 4);
        const frames = try a.alloc(Frame, nf);
        // Per name, mostly one kind across frames; now and then a different one.
        var base: [4]Kind = undefined;
        for (&base) |*k| k.* = all_kinds[r.uintLessThan(usize, all_kinds.len)];
        const np = null_pcts[case % null_pcts.len];
        for (frames) |*f| {
            const n = lens[r.uintLessThan(usize, lens.len)];
            const w = 1 + r.uintLessThan(usize, 4);
            var names: [4][]const u8 = undefined;
            var kinds: [4]Kind = undefined;
            var datas: [4]ColumnData = undefined;
            var k: usize = 0;
            for (pool) |nm| {
                if (k == w) break;
                if (r.uintLessThan(u8, 4) == 0 and nf > 1) continue; // absent in this frame
                const kind = if (r.uintLessThan(u8, 12) == 0) all_kinds[r.uintLessThan(usize, all_kinds.len)] else base[k % 4];
                names[k] = nm;
                kinds[k] = kind;
                const d = try randCol(a, r, kind, n, if (r.boolean()) np else r.uintLessThan(u8, 3) * 10);
                datas[k] = if (r.uintLessThan(u8, 5) == 0) try dirty(a, d) else d;
                k += 1;
            }
            f.* = try mkFrame(a, names[0..k], kinds[0..k], datas[0..k], n);
            // Arrays running past the frame's length (a cut slice).
            if (n > 1 and r.uintLessThan(u8, 6) == 0) f.len = n - 1;
        }
        try agree("concatByName", more.concatByName(a, frames), more.test_hooks.concatByNameCells(a, frames));
        cases += 1;
    }
    try testing.expect(cases >= 200);
}

// ── describe ────────────────────────────────────────────────────────────────

test "describe: typed path agrees with the cell path" {
    var cases: usize = 0;
    var prng = std.Random.DefaultPrng.init(0xd4b2);
    const r = prng.random();
    const kinds = [_]Kind{ .int, .float, .decimal, .bool, .text, .boxed };
    for (lens) |ln| for (null_pcts) |np| for (0..3) |rep| {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        var datas: [6]ColumnData = undefined;
        var ks: [6]Kind = undefined;
        const names = [_][]const u8{ "c0", "c1", "c2", "c3", "c4", "c5" };
        for (&datas, &ks, 0..) |*d, *k, i| {
            k.* = if (rep == 0) kinds[i] else kinds[r.uintLessThan(usize, kinds.len)];
            d.* = try dirty(a, try randCol(a, r, k.*, ln, np));
        }
        // A column of integers only that is the whole frame: the all-valid clean shape.
        const f = try mkFrame(a, &names, &ks, &datas, ln);
        try agree("describe all numeric", more.describe(a, f, &.{}), more.test_hooks.describeCells(a, f, &.{}));
        try agree("describe named", more.describe(a, f, &.{ "c1", "c0", "c2" }), more.test_hooks.describeCells(a, f, &.{ "c1", "c0", "c2" }));
        try agree("describe every", more.describe(a, f, &names), more.test_hooks.describeCells(a, f, &names));
        try agree("describe missing", more.describe(a, f, &.{"zz"}), more.test_hooks.describeCells(a, f, &.{"zz"}));
        cases += 4;
    };
    try testing.expect(cases >= 200);
}

// ── value_counts ────────────────────────────────────────────────────────────

test "valueCounts: typed path agrees with the cell path" {
    var cases: usize = 0;
    var prng = std.Random.DefaultPrng.init(0xd4b3);
    const r = prng.random();
    const kinds = [_]Kind{ .int, .float, .text, .bool, .boxed, .decimal };
    for (lens) |ln| for (null_pcts) |np| for (0..4) |_| {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const names = [_][]const u8{ "k0", "k1", "count" };
        var ks: [3]Kind = undefined;
        var datas: [3]ColumnData = undefined;
        for (&ks, &datas) |*k, *d| {
            k.* = kinds[r.uintLessThan(usize, kinds.len)];
            d.* = try randCol(a, r, k.*, ln, np);
        }
        const f = try mkFrame(a, &names, &ks, &datas, ln);
        const specs = [_]more.ValueCountsSpec{
            .{ .cols = &.{"k0"} },
            .{ .cols = &.{"k1"}, .keep_missing = true },
            .{ .cols = &.{ "k0", "k1" }, .out = "n" },
            .{ .cols = &.{ "k1", "k0" }, .keep_missing = true, .out = "n" },
            .{ .cols = &.{"count"} },
            .{ .cols = &.{ "k0", "count" }, .keep_missing = true },
            .{ .cols = &.{ "k0", "k0" } },
            .{ .cols = &.{"nope"} },
            .{ .cols = &.{} },
        };
        for (specs) |sp| {
            try agree("valueCounts", more.valueCounts(a, f, sp), more.test_hooks.valueCountsCells(a, f, sp));
            cases += 1;
        }
    };
    try testing.expect(cases >= 200);
}
