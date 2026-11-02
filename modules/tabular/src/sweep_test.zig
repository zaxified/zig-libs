// SPDX-License-Identifier: MIT
//! No-panic sweep tests for tabular, wave GW. Findings TB1..TB7, see
//! ~/CML/20261029-panic-sweep/tabular-sweep.report.md.
const std = @import("std");
const testing = std.testing;
const dsmod = @import("dataset");
const t0 = @import("transforms.zig");
const t1 = @import("series.zig");
const ex = @import("expr.zig");
const win = @import("window.zig");
const Dataset = dsmod.Dataset;
const Column = dsmod.Column;
const Value = dsmod.Value;

/// An allocator that refuses the first request of exactly `target` bytes and
/// passes everything else to `child`. It turns "this call got past its size
/// check" into `error.OutOfMemory` at the next big allocation, without the
/// call having to build millions of cells.
const FailOnSize = struct {
    child: std.mem.Allocator,
    target: usize,
    hit: bool = false,

    fn allocator(self: *FailOnSize) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(ctx: *anyopaque, len: usize, al: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *FailOnSize = @ptrCast(@alignCast(ctx));
        if (len == self.target and !self.hit) {
            self.hit = true;
            return null;
        }
        return self.child.rawAlloc(len, al, ra);
    }
    fn resize(ctx: *anyopaque, m: []u8, al: std.mem.Alignment, n: usize, ra: usize) bool {
        const self: *FailOnSize = @ptrCast(@alignCast(ctx));
        return self.child.rawResize(m, al, n, ra);
    }
    fn remap(ctx: *anyopaque, m: []u8, al: std.mem.Alignment, n: usize, ra: usize) ?[*]u8 {
        const self: *FailOnSize = @ptrCast(@alignCast(ctx));
        return self.child.rawRemap(m, al, n, ra);
    }
    fn free(ctx: *anyopaque, m: []u8, al: std.mem.Alignment, ra: usize) void {
        const self: *FailOnSize = @ptrCast(@alignCast(ctx));
        self.child.rawFree(m, al, ra);
    }
};

test "join: a composite key naming a column twice builds the right schema (sweep TB1)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const lc = [_]Column{ .{ .name = "id", .type = .int }, .{ .name = "x", .type = .int } };
    const rc = [_]Column{ .{ .name = "id", .type = .int }, .{ .name = "y", .type = .int } };
    const lrows = [_][]const Value{
        &.{ .{ .int = 1 }, .{ .int = 10 } },
        &.{ .{ .int = 2 }, .{ .int = 20 } },
    };
    const rrows = [_][]const Value{&.{ .{ .int = 1 }, .{ .int = 100 } }};
    const l: Dataset = .{ .columns = &lc, .rows = &lrows };
    const r: Dataset = .{ .columns = &rc, .rows = &rrows };
    for ([_]t1.JoinHow{ .inner, .left, .right, .full }) |how| {
        const j = try t1.join(a, l, r, .{ .keys = &.{ "id", "id" }, .how = how });
        try testing.expectEqual(@as(usize, 3), j.columns.len);
        try testing.expectEqualStrings("y", j.columns[2].name);
        for (j.rows) |row| try testing.expectEqual(@as(usize, 3), row.len);
    }
    const inner = try t1.join(a, l, r, .{ .keys = &.{ "id", "id" } });
    try testing.expectEqual(@as(usize, 1), inner.rows.len);
    try testing.expectEqual(@as(i64, 100), inner.rows[0][2].int);
    // one right column which IS the key: the old `columns.len - keys.len` wrapped around
    const rc1 = [_]Column{.{ .name = "id", .type = .int }};
    const rrows1 = [_][]const Value{&.{.{ .int = 1 }}};
    const r1: Dataset = .{ .columns = &rc1, .rows = &rrows1 };
    const j1 = try t1.join(a, l, r1, .{ .keys = &.{ "id", "id" }, .how = .left });
    try testing.expectEqual(@as(usize, 2), j1.columns.len);
}

/// (k, v) -- plus a third column "w" when `wide` -- one row per key.
fn keyedDsW(a: std.mem.Allocator, keys: []const []const u8, wide: bool) !Dataset {
    const cols = try a.alloc(Column, if (wide) 3 else 2);
    cols[0] = .{ .name = "k", .type = .text };
    cols[1] = .{ .name = "v", .type = .int };
    if (wide) cols[2] = .{ .name = "w", .type = .int };
    const rows = try a.alloc([]const Value, keys.len);
    for (keys, 0..) |k, i| {
        rows[i] = if (wide)
            try a.dupe(Value, &.{ .{ .text = k }, .{ .int = @intCast(i) }, .null })
        else
            try a.dupe(Value, &.{ .{ .text = k }, .{ .int = @intCast(i) } });
    }
    return .{ .columns = cols, .rows = rows };
}

fn keyedDs(a: std.mem.Allocator, keys: []const []const u8) !Dataset {
    return keyedDsW(a, keys, false);
}

/// `n_k` rows of key "k", then `n_x` rows of key `other`.
fn repKeys(a: std.mem.Allocator, n_k: usize, n_x: usize, other: []const u8) ![]const []const u8 {
    const out = try a.alloc([]const u8, n_k + n_x);
    @memset(out[0..n_k], "k");
    @memset(out[n_k..], other);
    return out;
}

/// Join and report whether it got past the size check: `true` = it reached the
/// big allocation (and was refused there), `false`-by-error = TooLarge.
fn joinGetsPast(a: std.mem.Allocator, l: Dataset, r: Dataset, how: t1.JoinHow, big_bytes: usize) !bool {
    var fo: FailOnSize = .{ .child = a, .target = big_bytes };
    if (t1.join(fo.allocator(), l, r, .{ .on = "k", .how = how })) |_| {
        return error.TestUnexpectedSuccess;
    } else |e| switch (e) {
        error.TooLarge => return false,
        error.OutOfMemory => {
            try testing.expect(fo.hit);
            return true;
        },
        else => return e,
    }
}

test "join: more than max_join_cells output cells is TooLarge, exactly the cap is accepted (sweep TB2)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // output = 3 left columns + (2 right - 1 key) = 4 columns, so the cell cap is 2^22 rows
    try testing.expectEqual(@as(usize, 1 << 24), t1.max_join_cells);
    const cap = t1.max_join_cells / 4;
    const w = 2048; // w x w = cap rows
    const big = cap * @sizeOf([]const Value);
    const lk = try keyedDsW(a, try repKeys(a, w, 0, ""), true);
    const rk = try keyedDs(a, try repKeys(a, w, 0, ""));
    const lk_over = try keyedDsW(a, try repKeys(a, w + 1, 0, ""), true);
    for ([_]t1.JoinHow{ .inner, .left, .right }) |how| {
        try testing.expect(try joinGetsPast(a, lk, rk, how, big));
        try testing.expect(!(try joinGetsPast(a, lk_over, rk, how, big)));
    }
    // full: 2048 x 2047 matched + 1024 unmatched left + 1024 right-only = cap
    const fl = try keyedDsW(a, try repKeys(a, w, 1024, "x"), true);
    const fr = try keyedDs(a, try repKeys(a, w - 1, 1024, "z"));
    try testing.expect(try joinGetsPast(a, fl, fr, .full, big));
    const fl_over = try keyedDsW(a, try repKeys(a, w, 1025, "x"), true);
    try testing.expect(!(try joinGetsPast(a, fl_over, fr, .full, big + 0)));
    // right join: unmatched right rows count too (2047 x 2048 matched + 2048 unmatched = cap)
    const rl = try keyedDsW(a, try repKeys(a, w - 1, 0, ""), true);
    const rr_at = try keyedDs(a, try repKeys(a, w, 2048, "z"));
    const rr_over = try keyedDs(a, try repKeys(a, w, 2049, "z"));
    try testing.expect(try joinGetsPast(a, rl, rr_at, .right, big));
    try testing.expect(!(try joinGetsPast(a, rl, rr_over, .right, big)));
    // semi / anti never fan out: not capped
    const semi = try t1.join(a, lk, rk, .{ .on = "k", .how = .semi });
    try testing.expectEqual(w, semi.rows.len);
}

/// `nr` distinct row keys and `nc` distinct col keys (one row per `max(nr, nc)`).
fn pivotDs(a: std.mem.Allocator, nr: usize, nc: usize) !Dataset {
    const n = @max(nr, nc);
    const cols = try a.alloc(Column, 3);
    cols[0] = .{ .name = "r", .type = .text };
    cols[1] = .{ .name = "c", .type = .text };
    cols[2] = .{ .name = "v", .type = .float };
    const rows = try a.alloc([]const Value, n);
    for (0..n) |i| {
        const rk = try std.fmt.allocPrint(a, "{d}", .{i % nr});
        const ck = try std.fmt.allocPrint(a, "{d}", .{i % nc});
        rows[i] = try a.dupe(Value, &.{ .{ .text = rk }, .{ .text = ck }, .{ .float = 1 } });
    }
    return .{ .columns = cols, .rows = rows };
}

test "pivot: row keys x col keys above max_pivot_cells is TooLarge, exactly the cap is accepted (sweep TB3)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const w = 2048; // w x w = 2^22
    try testing.expectEqual(@as(usize, 1 << 22), t0.max_pivot_cells);
    const spec: t0.PivotSpec = .{ .row_key = "r", .col_key = "c", .value_col = "v" };
    // after the check the next big request is the output column array
    var fo: FailOnSize = .{ .child = a, .target = (1 + w) * @sizeOf(Column) };
    try testing.expectError(error.OutOfMemory, t0.pivot(fo.allocator(), try pivotDs(a, w, w), spec));
    try testing.expect(fo.hit);
    // cap + 2048 cells (the closest product above 2^22 with small key counts)
    // (a dropped check answers OutOfMemory at the output column array, instead of building 4M cells)
    var fo_a: FailOnSize = .{ .child = a, .target = (2 + w) * @sizeOf(Column) };
    try testing.expectError(error.TooLarge, t0.pivot(fo_a.allocator(), try pivotDs(a, w, w + 1), spec));
    try testing.expect(!fo_a.hit);
    var fo_b: FailOnSize = .{ .child = a, .target = (1 + w) * @sizeOf(Column) };
    try testing.expectError(error.TooLarge, t0.pivot(fo_b.allocator(), try pivotDs(a, w + 1, w), spec));
    try testing.expect(!fo_b.hit);
}

test "pivot: a NaN column key falls back to the lexicographic order, finite keys stay ordered (sweep TB4)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{ .{ .name = "r", .type = .text }, .{ .name = "c", .type = .text }, .{ .name = "v", .type = .float } };
    const ck = [_][]const u8{ "3", "nan", "1", "2" };
    var rows: [4][]const Value = undefined;
    for (ck, 0..) |c, i| rows[i] = try a.dupe(Value, &.{ .{ .text = "row" }, .{ .text = c }, .{ .float = 1 } });
    const p = try t0.pivot(a, .{ .columns = &cols, .rows = &rows }, .{ .row_key = "r", .col_key = "c", .value_col = "v" });
    try testing.expectEqual(@as(usize, 5), p.columns.len);
    const want = [_][]const u8{ "1", "2", "3", "nan" };
    for (want, 0..) |w, i| try testing.expectEqualStrings(w, p.columns[1 + i].name);
    // and an all-numeric key set still sorts numerically ("10" after "9")
    const ck2 = [_][]const u8{ "10", "9", "inf", "-1" };
    for (ck2, 0..) |c, i| rows[i] = try a.dupe(Value, &.{ .{ .text = "row" }, .{ .text = c }, .{ .float = 1 } });
    const p2 = try t0.pivot(a, .{ .columns = &cols, .rows = &rows }, .{ .row_key = "r", .col_key = "c", .value_col = "v" });
    const want2 = [_][]const u8{ "-1", "9", "10", "inf" };
    for (want2, 0..) |w, i| try testing.expectEqualStrings(w, p2.columns[1 + i].name);
}

test "rolling: rows x window above max_rolling_work is TooLarge, the cap itself is accepted (sweep TB5)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const w: usize = 1 << 15;
    const cols = [_]Column{.{ .name = "v", .type = .float }};
    const cell = [_]Value{.{ .float = 1 }};
    const at_cap = try a.alloc([]const Value, 2 * w - 1);
    @memset(at_cap, &cell);
    const over = try a.alloc([]const Value, 2 * w);
    @memset(over, &cell);
    try testing.expectEqual(t1.max_rolling_work, (at_cap.len - w + 1) * w);
    // allocations: floatCol (0), cols (1), rows (2)
    var f1 = std.testing.FailingAllocator.init(a, .{ .fail_index = 1 });
    try testing.expectError(error.OutOfMemory, t1.rolling(f1.allocator(), .{ .columns = &cols, .rows = at_cap }, .{ .value_col = "v", .out = "o", .window = w }));
    var f2 = std.testing.FailingAllocator.init(a, .{ .fail_index = 1 });
    try testing.expectError(error.TooLarge, t1.rolling(f2.allocator(), .{ .columns = &cols, .rows = over }, .{ .value_col = "v", .out = "o", .window = w }));
    // window 0 and a window past the end stay the documented all-null result
    const small = try t1.rolling(a, .{ .columns = &cols, .rows = at_cap[0..3] }, .{ .value_col = "v", .out = "o", .window = std.math.maxInt(usize) });
    try testing.expect(small.rows[2][1] == .null);
    const zero = try t1.rolling(a, .{ .columns = &cols, .rows = at_cap[0..3] }, .{ .value_col = "v", .out = "o", .window = 0 });
    try testing.expect(zero.rows[0][1] == .null);
}

test "format: any decimals / kind / non-finite or extreme value formats without a panic (sweep TB6)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const vals = [_]f64{ 0, -0.0, 1, -1.5, 1e308, -1e308, 5e-324, std.math.nan(f64), std.math.inf(f64), -std.math.inf(f64), 1e21, 123456789.987654321 };
    const decimals = [_]u8{ 0, 1, 2, 17, 100, 255 };
    for (std.enums.values(t0.FormatKind)) |kind| {
        for (decimals) |dec| {
            for (vals) |v| {
                const s = try t0.format(a, v, .{ .kind = kind, .decimals = dec, .symbol = "$" });
                try testing.expect(s.len < 2048);
            }
        }
    }
}

test "sort: a column of mixed kinds incl. NaN, decimals and nulls sorts to a permutation without a panic (sweep TB7)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var prng = std.Random.DefaultPrng.init(0xC0FFEE);
    const rnd = prng.random();
    const cols = [_]Column{ .{ .name = "k", .type = .float }, .{ .name = "id", .type = .int } };
    for (0..200) |round| {
        const n = rnd.uintLessThan(usize, 150) + 1;
        const rows = try a.alloc([]const Value, n);
        for (rows, 0..) |*row, i| {
            const k: Value = switch (rnd.uintLessThan(u8, 8)) {
                0 => .null,
                1 => .{ .float = std.math.nan(f64) },
                2 => .{ .float = std.math.inf(f64) },
                3 => .{ .decimal = @as(i128, rnd.int(i32)) * 1_000_000_000_000 },
                4 => .{ .int = rnd.int(i16) },
                5 => .{ .text = if (rnd.boolean()) "a" else "b" },
                6 => .{ .bool = rnd.boolean() },
                else => .{ .float = rnd.float(f64) * 10 - 5 },
            };
            row.* = try a.dupe(Value, &.{ k, .{ .int = @intCast(i) } });
        }
        const d: Dataset = .{ .columns = &cols, .rows = rows };
        const s = try t0.sort(a, d, .{ .key = "k", .dir = if (round % 2 == 0) .asc else .desc, .then_by = &.{.{ .key = "id" }} });
        try testing.expectEqual(n, s.rows.len);
        const seen = try a.alloc(bool, n);
        @memset(seen, false);
        for (s.rows) |r| {
            const id: usize = @intCast(r[1].int);
            try testing.expect(!seen[id]);
            seen[id] = true;
        }
    }
}

test "unpivot: rows x melted columns above max_unpivot_cells is TooLarge, exactly the cap is accepted (sweep TB8)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqual(@as(usize, 1 << 22), t0.max_unpivot_cells);
    const cols = [_]Column{ .{ .name = "id", .type = .int }, .{ .name = "x", .type = .int } };
    const cell = [_]Value{ .{ .int = 1 }, .{ .int = 2 } };
    const rows = try a.alloc([]const Value, 2048);
    @memset(rows, &cell);
    const d: Dataset = .{ .columns = &cols, .rows = rows };
    // value_cols may repeat a column: 2048 rows x 2048 names = cap, x 2049 names = cap + 2048
    const names = try a.alloc([]const u8, 2049);
    @memset(names, "x");
    var fo: FailOnSize = .{ .child = a, .target = t0.max_unpivot_cells * @sizeOf([]const Value) };
    // past the check, the next request is the reserved row array (64 MiB)
    try testing.expectError(error.OutOfMemory, t0.unpivot(fo.allocator(), d, .{ .id_cols = &.{"id"}, .value_cols = names[0..2048] }));
    try testing.expect(fo.hit);
    // (a dropped check answers OutOfMemory at the reserved row array, instead of building 4M rows)
    var fo_over: FailOnSize = .{ .child = a, .target = 2048 * 2049 * @sizeOf([]const Value) };
    try testing.expectError(error.TooLarge, t0.unpivot(fo_over.allocator(), d, .{ .id_cols = &.{"id"}, .value_cols = names }));
    try testing.expect(!fo_over.hit);
    // the default (all non-id columns) is unaffected
    const small = try t0.unpivot(a, d, .{ .id_cols = &.{"id"} });
    try testing.expectEqual(@as(usize, 2048), small.rows.len);
}

test "aggregate: groups x aggs above max_aggregate_cells is TooLarge, exactly the cap is built (sweep TB9)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqual(@as(usize, 1 << 24), t0.max_aggregate_cells);
    const n_aggs = 4096; // 4096 groups x 4096 aggs = cap
    const aggs = try a.alloc(t0.AggCol, n_aggs);
    @memset(aggs, .{ .src = "v", .out = "o", .func = .count });
    const cols = [_]Column{ .{ .name = "g", .type = .text }, .{ .name = "v", .type = .int } };
    const spec: t0.AggregateSpec = .{ .group_by = &.{"g"}, .aggs = aggs };
    const at_cap = try groupedDs(a, &cols, 4096);
    const over = try groupedDs(a, &cols, 4097);
    // At the cap it reaches the output block (refused here, 512 MiB); one group
    // more is TooLarge before anything of that size is asked for.
    var fo: FailOnSize = .{ .child = a, .target = 4096 * (1 + n_aggs) * @sizeOf(Value) };
    try testing.expectError(error.OutOfMemory, t0.aggregate(fo.allocator(), at_cap, spec));
    try testing.expect(fo.hit);
    var fo_over: FailOnSize = .{ .child = a, .target = 4097 * (1 + n_aggs) * @sizeOf(Value) };
    try testing.expectError(error.TooLarge, t0.aggregate(fo_over.allocator(), over, spec));
    try testing.expect(!fo_over.hit);
    // no group-by cells at all (aggs.len == 0) is never capped
    const none = try t0.aggregate(a, over, .{ .group_by = &.{"g"}, .aggs = &.{} });
    try testing.expectEqual(@as(usize, 4097), none.rows.len);
}

fn groupedDs(a: std.mem.Allocator, cols: []const Column, groups: usize) !Dataset {
    const rows = try a.alloc([]const Value, groups);
    for (rows, 0..) |*r, i| {
        const key = try std.fmt.allocPrint(a, "g{d}", .{i});
        r.* = try a.dupe(Value, &.{ .{ .text = key }, .{ .int = 1 } });
    }
    return .{ .columns = cols, .rows = rows };
}

test "select: duplicate names are refused, distinct names (including many) are served (sweep TB10)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{ .{ .name = "a", .type = .int }, .{ .name = "b", .type = .int } };
    const row = [_]Value{ .{ .int = 1 }, .{ .int = 2 } };
    const rows = [_][]const Value{&row};
    const d: Dataset = .{ .columns = &cols, .rows = &rows };
    try testing.expectError(error.DuplicateColumn, t0.select(a, d, &.{ "a", "b", "a" }));
    try testing.expectError(error.DuplicateColumn, t0.select(a, d, &.{ "b", "b" }));
    try testing.expectError(error.NoSuchColumn, t0.select(a, d, &.{ "a", "zz" }));
    const ok = try t0.select(a, d, &.{ "b", "a" });
    try testing.expectEqual(@as(i64, 2), ok.rows[0][0].int);
    // a long list of the same name: refused at the second entry, not after a quadratic scan
    const many = try a.alloc([]const u8, 100_000);
    @memset(many, "a");
    try testing.expectError(error.DuplicateColumn, t0.select(a, d, many));
}

// ── 2026-11-02: every new pub input, at its extremes ───────────────────────────

fn mixedDs(a: std.mem.Allocator) !Dataset {
    const cols = try a.dupe(Column, &.{ .{ .name = "k", .type = .text }, .{ .name = "x", .type = .float }, .{ .name = "t", .type = .int } });
    const nan = std.math.nan(f64);
    const inf = std.math.inf(f64);
    const rows = try a.dupe([]const Value, &.{
        try a.dupe(Value, &.{ .{ .text = "a" }, .{ .float = 1 }, .{ .int = 1 } }),
        try a.dupe(Value, &.{ .null, .{ .float = nan }, .{ .int = std.math.minInt(i64) } }),
        try a.dupe(Value, &.{ .{ .int = 7 }, .{ .float = inf }, .null }),
        try a.dupe(Value, &.{ .{ .text = "" }, .{ .text = "x" }, .{ .bool = true } }),
        try a.dupe(Value, &.{ .{ .decimal = std.math.minInt(i128) }, .{ .float = -inf }, .{ .float = 1e300 } }),
        try a.dupe(Value, &.{ .{ .bool = false }, .null, .{ .int = std.math.maxInt(i64) } }),
    });
    return .{ .columns = cols, .rows = rows };
}

const all_aggs = std.enums.values(t0.AggFn);

test "aggregate, pivot, sort: every function and key kind over a mixed column" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const d = try mixedDs(a);
    const empty: Dataset = .{ .columns = d.columns, .rows = &.{} };
    for (all_aggs) |func| {
        for ([_]f64{ 0.5, -1, 2, std.math.nan(f64) }) |q| {
            for ([_]bool{ false, true }) |skip| {
                const ag = [_]t0.AggCol{.{ .src = "x", .out = "o", .func = func, .q = q }};
                const g = try t0.aggregate(a, d, .{ .group_by = &.{"k"}, .aggs = &ag, .skip_na = skip, .sort_groups = true, .drop_missing_keys = skip });
                try testing.expect(g.rows.len <= d.rows.len);
                _ = try t0.aggregate(a, empty, .{ .group_by = &.{"k"}, .aggs = &ag, .skip_na = skip });
                _ = try t0.reduce(a, d, &ag);
                _ = try t0.pivot(a, d, .{ .row_key = "k", .col_key = "t", .value_col = "x", .agg = func, .q = q, .skip_na = skip, .fill_value = -1 });
                _ = try t0.pivot(a, empty, .{ .row_key = "k", .col_key = "t", .value_col = "x", .agg = func, .q = q });
            }
        }
    }
    for ([_]@FieldType(t0.SortSpec, "missing"){ .auto, .first, .last }) |m| {
        for ([_]t0.SortDir{ .asc, .desc }) |dir| {
            for ([_][]const u8{ "k", "x", "t" }) |key| {
                const s = try t0.sort(a, d, .{ .key = key, .dir = dir, .missing = m, .then_by = &.{.{ .key = "t", .dir = dir }} });
                try testing.expectEqual(d.rows.len, s.rows.len);
                _ = try t0.sort(a, empty, .{ .key = key, .dir = dir, .missing = m });
            }
        }
    }
    try testing.expectError(error.NoSuchColumn, t0.sort(a, d, .{ .key = "zz" }));
}

test "window: every op over a mixed column, empty table, per group" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const d = try mixedDs(a);
    const empty: Dataset = .{ .columns = d.columns, .rows = &.{} };
    const big = std.math.maxInt(i64);
    const small = std.math.minInt(i64);
    var ops: std.ArrayList(win.Op) = .empty;
    try ops.appendSlice(a, &.{
        .{ .shift = .{ .n = big } },                  .{ .shift = .{ .n = small } }, .{ .diff = big },                                           .{ .diff = small },
        .{ .pct_change = 1 },                         .cum_sum,                      .cum_prod,                                                  .cum_min,
        .cum_max,                                     .cum_count,                    .row_number,                                                .{ .ffill = 0 },
        .{ .ffill = null },                           .{ .bfill = 1 },               .{ .bfill = null },                                         .{ .interpolate = .{} },
        .{ .interpolate = .{ .extend_last = true } }, .{ .ewm = .{ .alpha = 1 } },   .{ .ewm = .{ .com = 0, .func = .std, .min_periods = 99 } }, .{ .ewm = .{ .span = 1, .adjust = false, .ignore_na = true, .func = .@"var" } },
        .{ .ewm = .{ .halflife = 1e-300 } },
    });
    for (std.enums.values(win.WinFn)) |f| {
        try ops.append(a, .{ .rolling = .{ .window = 2, .func = f } });
        try ops.append(a, .{ .rolling = .{ .window = 1, .func = f, .min_periods = 0, .center = true } });
        try ops.append(a, .{ .rolling = .{ .window = 1 << 40, .func = f, .min_periods = 1 } });
        try ops.append(a, .{ .expanding = .{ .func = f, .min_periods = 0 } });
        try ops.append(a, .{ .rolling_time = .{ .time_col = "t", .period = 5, .func = f } });
        try ops.append(a, .{ .rolling_time = .{ .time_col = "t", .period = big, .func = f, .min_periods = 0 } });
        try ops.append(a, .{ .rolling_time = .{ .time_col = "t", .period = small, .func = f } });
    }
    for (std.enums.values(win.RankMethod)) |m| {
        try ops.append(a, .{ .rank = .{ .method = m } });
        try ops.append(a, .{ .rank = .{ .method = m, .descending = true } });
    }
    for (all_aggs) |f| try ops.append(a, .{ .transform = .{ .func = f, .q = 2 } });
    for (ops.items) |op| {
        for ([_][]const []const u8{ &.{}, &.{"k"} }) |by| {
            for ([_][]const u8{ "x", "k", "t" }) |col| {
                const w = try win.window(a, d, .{ .value_col = col, .out = "o", .op = op, .partition_by = by });
                try testing.expectEqual(d.rows.len, w.rows.len);
                _ = try win.window(a, empty, .{ .value_col = col, .out = "o", .op = op, .partition_by = by });
            }
        }
    }
    try testing.expectError(error.NoSuchColumn, win.window(a, d, .{ .value_col = "x", .out = "o", .op = .cum_sum, .partition_by = &.{"zz"} }));
    try testing.expectError(error.NoSuchColumn, win.window(a, d, .{ .value_col = "x", .out = "o", .op = .{ .rolling_time = .{ .time_col = "zz", .period = 1 } } }));
    for ([_]f64{ 0, -1, 2, std.math.nan(f64), std.math.inf(f64) }) |bad| {
        try testing.expectError(error.InvalidDecay, win.window(a, d, .{ .value_col = "x", .out = "o", .op = .{ .ewm = .{ .alpha = bad } } }));
    }
    try testing.expectError(error.InvalidDecay, win.window(a, d, .{ .value_col = "x", .out = "o", .op = .{ .ewm = .{ .alpha = 0.5, .com = 1 } } }));
}

test "window: the work caps are TooLarge" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{.{ .name = "x", .type = .float }};
    const n = 40_000;
    const rows = try a.alloc([]const Value, n);
    const cell = [_]Value{.{ .float = 1 }};
    @memset(rows, &cell);
    const d: Dataset = .{ .columns = &cols, .rows = rows };
    try testing.expectError(error.TooLarge, win.window(a, d, .{ .value_col = "x", .out = "o", .op = .{ .rolling = .{ .window = n } } }));
    try testing.expectError(error.TooLarge, win.window(a, d, .{ .value_col = "x", .out = "o", .op = .{ .expanding = .{ .func = .median } } }));
}

test "expr: every operator over every kind of operand" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const d = try mixedDs(a);
    const empty: Dataset = .{ .columns = d.columns, .rows = &.{} };
    const k: ex.Expr = .{ .col = "k" };
    const x: ex.Expr = .{ .col = "x" };
    const t: ex.Expr = .{ .col = "t" };
    const operands = [_]*const ex.Expr{ &k, &x, &t, &.{ .lit = .{ .int = 0 } }, &.{ .lit = .{ .int = -1 } }, &.{ .lit = .{ .float = 0 } }, &.{ .lit = .{ .decimal = std.math.maxInt(i128) } }, &.{ .lit = .null }, &.{ .lit = .{ .int = std.math.minInt(i64) } }, &.{ .lit = .{ .int = std.math.maxInt(i64) } }, &.{ .lit = .{ .int = -2 } }, &.{ .lit = .{ .int = 3 } }, &.{ .lit = .{ .float = -std.math.inf(f64) } } };
    for (std.enums.values(ex.Unary)) |op| {
        for (operands) |o| {
            const e: ex.Expr = .{ .unary = .{ .op = op, .x = o } };
            // The table's columns hold every kind: refusing to type one is an answer too.
            if (ex.mutate(a, d, &.{.{ .out = "o", .expr = e }})) |m| {
                try testing.expectEqual(d.rows.len, m.rows.len);
            } else |err| try testing.expectEqual(error.BadExpr, err);
            _ = try ex.where(a, d, &e);
        }
    }
    for (std.enums.values(ex.Binary)) |op| {
        for (operands) |l| {
            for (operands) |r| {
                const e: ex.Expr = .{ .binary = .{ .op = op, .l = l, .r = r } };
                _ = ex.mutate(a, d, &.{.{ .out = "x", .expr = e }}) catch |err| try testing.expectEqual(error.BadExpr, err); // replaces "x"
            }
        }
    }
    const shapes = [_]ex.Expr{
        .{ .is_in = .{ .x = &k, .values = &.{ .null, .{ .int = 7 }, .{ .text = "a" } } } },
        .{ .is_in = .{ .x = &x, .values = &.{} } },
        .{ .if_else = .{ .cond = &k, .then = &x, .otherwise = &t } },
        .{ .coalesce = &.{ k, x, t } },
        .{ .replace = .{ .x = &k, .from = "a", .to = "" } },
    };
    for (shapes) |e| {
        _ = ex.mutate(a, d, &.{.{ .out = "o", .expr = e }}) catch |err| try testing.expectEqual(error.BadExpr, err);
        _ = try ex.mutate(a, empty, &.{.{ .out = "o", .expr = e, .type = .text }});
    }
    try testing.expectError(error.BadExpr, ex.where(a, d, &.{ .replace = .{ .x = &k, .from = "", .to = "y" } }));
    for (std.enums.values(dsmod.ColumnType)) |to| {
        for ([_][]const u8{ "k", "x", "t" }) |col| {
            _ = try ex.cast(a, d, .{ .col = col, .to = to });
        }
    }
    try testing.expectError(error.CastFailed, ex.cast(a, d, .{ .col = "k", .to = .float, .on_error = .fail }));
    try testing.expectError(error.NoSuchColumn, ex.cast(a, d, .{ .col = "zz", .to = .float }));
}

test "join: new options at their edges" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const d = try mixedDs(a);
    const empty: Dataset = .{ .columns = d.columns, .rows = &.{} };
    for (std.enums.values(t1.JoinHow)) |how| {
        for ([_]bool{ false, true }) |co| {
            for ([_][]const []const u8{ &.{"k"}, &.{"x"}, &.{"t"}, &.{ "k", "t" }, &.{ "k", "k" } }) |ks| {
                const m = try t1.join(a, d, d, .{ .keys = ks, .how = how, .coalesce_keys = co, .suffix = "_r" });
                for (m.rows) |row| try testing.expectEqual(m.columns.len, row.len);
                _ = try t1.join(a, d, empty, .{ .keys = ks, .how = how, .null_keys = .no_match, .coalesce_keys = co });
                _ = try t1.join(a, empty, d, .{ .keys = ks, .how = how, .null_keys = .no_match, .coalesce_keys = co });
            }
        }
    }
    try testing.expectError(error.NoSuchColumn, t1.join(a, d, d, .{ .keys = &.{ "k", "t" }, .right_on = &.{"k"} }));
    try testing.expectError(error.NoSuchColumn, t1.join(a, d, d, .{ .on = "k", .right_on = &.{"zz"} }));
    // cross: the product is refused before a row is built, overflow included.
    const wide_rows = try a.alloc([]const Value, 4096);
    @memset(wide_rows, d.rows[0]);
    const wide: Dataset = .{ .columns = d.columns, .rows = wide_rows };
    try testing.expectError(error.TooLarge, t1.join(a, wide, wide, .{ .how = .cross }));

    // asof
    const lc = [_]Column{ .{ .name = "on", .type = .int }, .{ .name = "v", .type = .float } };
    const sorted = [_][]const Value{ &.{ .{ .int = 1 }, .{ .float = 1 } }, &.{ .null, .{ .float = 2 } }, &.{ .{ .int = 5 }, .{ .float = 3 } } };
    const unsorted = [_][]const Value{ &.{ .{ .int = 5 }, .{ .float = 1 } }, &.{ .{ .int = 1 }, .{ .float = 2 } } };
    const s: Dataset = .{ .columns = &lc, .rows = &sorted };
    const u: Dataset = .{ .columns = &lc, .rows = &unsorted };
    const dirs = std.enums.values(@FieldType(t1.AsofSpec, "direction"));
    for (dirs) |dir| {
        for ([_]?f64{ null, 0, -1, std.math.nan(f64), std.math.inf(f64) }) |tol| {
            const o = try t1.joinAsof(a, u, s, .{ .on = "on", .direction = dir, .tolerance = tol, .suffix = "_r" });
            try testing.expectEqual(u.rows.len, o.rows.len);
            _ = try t1.joinAsof(a, s, .{ .columns = &lc, .rows = &.{} }, .{ .on = "on", .direction = dir, .tolerance = tol });
            _ = try t1.joinAsof(a, .{ .columns = &lc, .rows = &.{} }, s, .{ .on = "on", .direction = dir, .by = &.{"v"} });
            _ = try t1.joinAsof(a, s, s, .{ .on = "on", .direction = dir, .by = &.{"v"} });
        }
    }
    try testing.expectError(error.NotSorted, t1.joinAsof(a, s, u, .{ .on = "on" }));
    try testing.expectError(error.NoSuchColumn, t1.joinAsof(a, s, u, .{ .on = "zz" }));
}

test "table verbs: empty tables, empty lists, absurd numbers" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const d = try mixedDs(a);
    const empty: Dataset = .{ .columns = d.columns, .rows = &.{} };
    const nocols: Dataset = .{ .columns = &.{}, .rows = &.{} };
    const big = std.math.maxInt(usize);

    try testing.expectEqual(d.rows.len, (try t0.tail(a, d, big)).rows.len);
    try testing.expectEqual(@as(usize, 0), (try t0.tail(a, d, 0)).rows.len);
    _ = try t0.nlargest(a, d, .{ .col = "x", .n = big });
    _ = try t0.nlargest(a, empty, .{ .col = "x", .n = 3, .dir = .asc });
    try testing.expectEqual(d.rows.len, (try t0.sample(a, d, .{ .n = big, .seed = 1 })).rows.len);
    try testing.expectEqual(@as(usize, 0), (try t0.sample(a, empty, .{ .n = 3, .seed = 1, .replace = true })).rows.len);
    try testing.expectError(error.TooLarge, t0.sample(a, d, .{ .n = big, .seed = 1, .replace = true }));
    try testing.expectEqual(@as(usize, 4), (try t0.sample(a, d, .{ .n = 4, .seed = 1, .replace = true })).rows.len);

    const parts = try t0.partitionBy(a, d, &.{"k"});
    var seen: usize = 0;
    for (parts) |p| seen += p.table.rows.len;
    try testing.expectEqual(d.rows.len, seen);
    try testing.expectEqual(@as(usize, 1), (try t0.partitionBy(a, d, &.{})).len);
    try testing.expectEqual(@as(usize, 0), (try t0.partitionBy(a, empty, &.{"k"})).len);
    try testing.expectError(error.NoSuchColumn, t0.partitionBy(a, d, &.{"zz"}));

    _ = try t0.concatByName(a, &.{});
    _ = try t0.concatByName(a, &.{ nocols, empty, d, d });
    try testing.expectError(error.NoSuchColumn, t0.valueCounts(a, d, .{ .cols = &.{} }));
    _ = try t0.valueCounts(a, d, .{ .cols = &.{ "k", "x" }, .keep_missing = true });
    _ = try t0.valueCounts(a, empty, .{ .cols = &.{"k"} });
    _ = try t0.describe(a, d, &.{});
    _ = try t0.describe(a, empty, &.{});
    _ = try t0.describe(a, d, &.{"k"});
    try testing.expectError(error.NoSuchColumn, t0.describe(a, d, &.{"zz"}));

    for ([_]?f64{ null, 0, std.math.nan(f64), std.math.inf(f64) }) |lo| {
        _ = try t0.clip(a, d, .{ .col = "x", .lower = lo, .upper = lo });
    }
    _ = try t0.replace(a, d, .{ .col = "k", .pairs = &.{} });
    _ = try t0.replace(a, d, .{ .col = "k", .pairs = &.{ .{ .from = .null, .to = .{ .int = 1 } }, .{ .from = .null, .to = .{ .int = 2 } }, .{ .from = .{ .text = "a" }, .to = .null } } });

    const edges = [_]f64{ -1, 0, 1 };
    for ([_]bool{ false, true }) |right| {
        for ([_]bool{ false, true }) |low| {
            const c = try t0.cut(a, d, .{ .col = "x", .out = "o", .edges = &edges, .right = right, .include_lowest = low });
            try testing.expectEqual(d.rows.len, c.rows.len);
            _ = try t0.cut(a, empty, .{ .col = "k", .out = "o", .edges = &edges, .labels = &.{ "l", "m" }, .right = right, .include_lowest = low });
        }
    }
    try testing.expectError(error.BadEdges, t0.cut(a, d, .{ .col = "x", .out = "o", .edges = &.{} }));
    try testing.expectError(error.BadEdges, t0.cut(a, d, .{ .col = "x", .out = "o", .edges = &.{1} }));
    try testing.expectError(error.BadEdges, t0.cut(a, d, .{ .col = "x", .out = "o", .edges = &.{ 1, 1 } }));
    try testing.expectError(error.BadEdges, t0.cut(a, d, .{ .col = "x", .out = "o", .edges = &.{ 0, std.math.nan(f64) } }));
    try testing.expectError(error.BadEdges, t0.cut(a, d, .{ .col = "x", .out = "o", .edges = &edges, .labels = &.{"l"} }));

    for (std.enums.values(@FieldType(t1.DistinctSpec, "keep"))) |keep| {
        _ = try t1.distinct(a, d, .{ .keys = &.{}, .keep = keep });
        _ = try t1.distinct(a, empty, .{ .keys = &.{}, .keep = keep });
        _ = try t1.distinct(a, nocols, .{ .keys = &.{}, .keep = keep });
        _ = try t1.distinct(a, d, .{ .keys = &.{ "k", "x" }, .keep = keep });
    }
    for (std.enums.values(t0.Freq)) |freq| {
        for (std.enums.values(t0.ResampleAgg)) |agg| {
            _ = try t0.resample(a, d, .{ .date_col = "k", .value_col = "x", .freq = freq, .agg = agg });
        }
    }
}
