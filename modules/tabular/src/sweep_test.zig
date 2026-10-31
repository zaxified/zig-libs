// SPDX-License-Identifier: MIT
//! No-panic sweep tests for tabular, wave GW. Findings TB1..TB7, see
//! ~/CML/20261029-panic-sweep/tabular-sweep.report.md.
const std = @import("std");
const testing = std.testing;
const dsmod = @import("dataset");
const t0 = @import("transforms.zig");
const t1 = @import("series.zig");
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
    try testing.expectError(error.TooLarge, t0.pivot(a, try pivotDs(a, w, w + 1), spec));
    try testing.expectError(error.TooLarge, t0.pivot(a, try pivotDs(a, w + 1, w), spec));
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
    try testing.expectError(error.TooLarge, t0.unpivot(a, d, .{ .id_cols = &.{"id"}, .value_cols = names }));
    // the default (all non-id columns) is unaffected
    const small = try t0.unpivot(a, d, .{ .id_cols = &.{"id"} });
    try testing.expectEqual(@as(usize, 2048), small.rows.len);
}

/// Returns one shared buffer for every request of at least `big` bytes or of
/// exactly `row` bytes (the per-group accumulator array and output row of
/// `aggregate`), so a 2^24-cell aggregate neither needs nor touches gigabytes:
/// the test only asks whether the call is refused, never what it computed.
const AliasOnSize = struct {
    child: std.mem.Allocator,
    big: usize,
    row: usize,
    shared: []align(16) u8,
    shared_row: []align(16) u8,

    fn allocator(self: *AliasOnSize) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn isAlias(self: *AliasOnSize, p: [*]u8) bool {
        return p == self.shared.ptr or p == self.shared_row.ptr;
    }
    fn alloc(ctx: *anyopaque, len: usize, al: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *AliasOnSize = @ptrCast(@alignCast(ctx));
        if (al.toByteUnits() <= 16) {
            if (len == self.row and len <= self.shared_row.len) return self.shared_row.ptr;
            if (len >= self.big and len <= self.shared.len) return self.shared.ptr;
        }
        return self.child.rawAlloc(len, al, ra);
    }
    fn resize(ctx: *anyopaque, m: []u8, al: std.mem.Alignment, n: usize, ra: usize) bool {
        const self: *AliasOnSize = @ptrCast(@alignCast(ctx));
        if (self.isAlias(m.ptr)) return false;
        return self.child.rawResize(m, al, n, ra);
    }
    fn remap(ctx: *anyopaque, m: []u8, al: std.mem.Alignment, n: usize, ra: usize) ?[*]u8 {
        const self: *AliasOnSize = @ptrCast(@alignCast(ctx));
        if (self.isAlias(m.ptr)) return null;
        return self.child.rawRemap(m, al, n, ra);
    }
    fn free(ctx: *anyopaque, m: []u8, al: std.mem.Alignment, ra: usize) void {
        const self: *AliasOnSize = @ptrCast(@alignCast(ctx));
        if (self.isAlias(m.ptr)) return;
        self.child.rawFree(m, al, ra);
    }
};

test "aggregate: groups x aggs above max_aggregate_cells is TooLarge, exactly the cap is built (sweep TB9)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqual(@as(usize, 1 << 24), t0.max_aggregate_cells);
    const n_aggs = 4096; // 4096 groups x 4096 aggs = cap
    const aggs = try a.alloc(t0.AggCol, n_aggs);
    @memset(aggs, .{ .src = "v", .out = "o", .func = .count });
    const cols = [_]Column{ .{ .name = "g", .type = .text }, .{ .name = "v", .type = .int } };
    const shared = try a.alignedAlloc(u8, .@"16", 8 << 20); // >= n_aggs * @sizeOf(Acc)
    var ali: AliasOnSize = .{
        .child = a,
        .big = 1 << 20, // the accumulator arrays (~1.4 MB); the map's own arrays stay below
        .row = (1 + n_aggs) * @sizeOf(Value),
        .shared = shared,
        .shared_row = try a.alignedAlloc(u8, .@"16", 1 << 18),
    };
    const spec: t0.AggregateSpec = .{ .group_by = &.{"g"}, .aggs = aggs };
    const at_cap = try groupedDs(a, &cols, 4096);
    const over = try groupedDs(a, &cols, 4097);
    const ok = try t0.aggregate(ali.allocator(), at_cap, spec);
    try testing.expectEqual(@as(usize, 4096), ok.rows.len);
    try testing.expectError(error.TooLarge, t0.aggregate(ali.allocator(), over, spec));
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
