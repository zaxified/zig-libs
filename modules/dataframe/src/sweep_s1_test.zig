// SPDX-License-Identifier: MIT
//! D5 no-panic sweep, group S1 (verbs, keys, core, frame, value, spec, root, frameops,
//! structure, reshape, and the u32 row-index class over the whole module): one test per
//! finding, each shown to fail with its fix switched off (see the CHANGELOG entry).

const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const core = @import("core.zig");
const verbs = @import("verbs.zig");

fn nowNs() i96 {
    return std.Io.Timestamp.now(testing.io, .awake).nanoseconds;
}

/// A hand-built frame of `w` int columns `<prefix>0`... (all null: no data arrays) and, with
/// `key`, a leading int column `k` of 0, 1, 2, ...
fn wideFrame(a: std.mem.Allocator, prefix: []const u8, w: usize, len: usize, key: bool) !df.Frame {
    const extra: usize = @intFromBool(key);
    const cols = try a.alloc(df.Column, w + extra);
    if (key) cols[0] = .{ .name = "k", .type = .int };
    for (cols[extra..], 0..) |*c, i| c.* = .{ .name = try std.fmt.allocPrint(a, "{s}{d}", .{ prefix, i }), .type = .int };
    const data = try a.alloc(df.ColumnData, cols.len);
    @memset(data, .nulls);
    if (key) {
        const ks = try a.alloc(i64, len);
        for (ks, 0..) |*k, i| k.* = @intCast(i);
        data[0] = .{ .int = .{ .values = ks } };
    }
    return .{ .columns = cols, .data = data, .len = len };
}

/// Counts a verb that took 3 s or more (a linear scan per name at this width takes 10 s
/// and more); the test fails at its end, after naming every slow verb.
fn expectFast(slow: *usize, what: []const u8, t0: i96) void {
    const ms = @divTrunc(nowNs() - t0, 1_000_000);
    if (ms > 3000) {
        std.debug.print("{s}: {d} ms\n", .{ what, ms });
        slow.* += 1;
    }
}

// ── S1-1 ────────────────────────────────────────────────────────────────────

test "transpose: a text cell in a number column stays a cell, no panic (sweep S1-1)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // `FrameBuilder` does not check a cell against its column's declared type.
    const cols = [_]df.Column{ .{ .name = "a", .type = .int }, .{ .name = "b", .type = .float } };
    var b = try df.FrameBuilder.init(a, &cols, 2);
    try b.appendRow(&.{ .{ .int = 1 }, .{ .float = 1.5 } });
    try b.appendRow(&.{ .{ .int = 2 }, .{ .text = "x" } });
    const f = try b.toOwned();
    const t = try df.transpose(a, f, .{});
    try testing.expectEqual(@as(usize, 2), t.columns.len);
    try testing.expectEqual(df.Value{ .float = 1 }, t.cell(0, "column_0").?);
    try testing.expectEqual(df.Value{ .float = 1.5 }, t.cell(1, "column_0").?);
    try testing.expectEqual(df.Value{ .float = 2 }, t.cell(0, "column_1").?);
    try testing.expectEqualStrings("x", t.cell(1, "column_1").?.text);
}

// ── S1-2 ────────────────────────────────────────────────────────────────────

test "selectColumns: a node shared 24 deep is refused, not visited 2^24 times (sweep S1-2)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]df.Column{.{ .name = "x", .type = .int }};
    const f: df.Frame = .{ .columns = &cols, .data = &.{}, .len = 0 };
    // Level i is `any_of{ level i-1, level i-1 }`: 25 nodes as a graph, 2^24 as a tree.
    // The leaf matches no int column, so `any_of` never stops early.
    var pairs: [24][2]df.Selector = undefined;
    var node: df.Selector = .text;
    for (&pairs) |*p| {
        p.* = .{ node, node };
        node = .{ .any_of = p };
    }
    try testing.expectError(error.BadArgument, df.selectColumns(a, f, node));
    // An ordinary selector is untouched.
    const names = try df.selectColumns(a, f, .{ .any_of = &.{ .text, .numeric } });
    try testing.expectEqual(@as(usize, 1), names.len);
    try testing.expectEqualStrings("x", names[0]);
}

// ── S1-3 ────────────────────────────────────────────────────────────────────

/// 2048 rows over 1025 row keys and 2048 column keys: one `pivot` is 2 099 200 cells, under
/// `max_pivot_cells` (4 194 304); two of them are over.
fn pivotFrame(a: std.mem.Allocator) !df.Frame {
    const cols = [_]df.Column{ .{ .name = "r", .type = .int }, .{ .name = "c", .type = .int }, .{ .name = "v", .type = .float } };
    var b = try df.FrameBuilder.init(a, &cols, 2048);
    for (0..2048) |i| try b.appendRow(&.{ .{ .int = @intCast(i % 1025) }, .{ .int = @intCast(i) }, .{ .float = 1 } });
    return b.toOwned();
}

test "pivotMany: the blocks together are capped, not each (sweep S1-3)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try pivotFrame(a);
    const one = try df.pivotMany(a, f, .{ .row_key = "r", .col_key = "c", .values = &.{"v"} });
    try testing.expectEqual(@as(usize, 1025), one.len);
    try testing.expectEqual(@as(usize, 2049), one.columns.len);
    try testing.expectError(error.TooLarge, df.pivotMany(a, f, .{ .row_key = "r", .col_key = "c", .values = &.{ "v", "v" } }));
}

test "pivotKeys: the blocks together are capped, not each (sweep S1-3)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try pivotFrame(a);
    try testing.expectError(error.TooLarge, df.pivotKeys(a, f, .{ .row_keys = &.{"r"}, .col_keys = &.{"c"}, .values = &.{ "v", "v" } }));
}

// ── S1-4 ────────────────────────────────────────────────────────────────────

test "dummies: the dummies of all encoded columns are capped together (sweep S1-4)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // 4096 rows, 2049 distinct texts: 8 392 704 cells for one pass over the column, under
    // `max_aggregate_cells` (16 777 216); naming the column twice doubles it.
    const names = try a.alloc([]const u8, 2049);
    for (names, 0..) |*n, i| n.* = try std.fmt.allocPrint(a, "v{d}", .{i});
    const cols = [_]df.Column{.{ .name = "c", .type = .text }};
    var b = try df.FrameBuilder.init(a, &cols, 4096);
    for (0..4096) |i| try b.appendRow(&.{.{ .text = names[i % 2049] }});
    const f = try b.toOwned();
    const one = try df.dummies(a, f, .{ .cols = &.{"c"} });
    try testing.expectEqual(@as(usize, 2049), one.columns.len);
    try testing.expectError(error.TooLarge, df.dummies(a, f, .{ .cols = &.{ "c", "c" } }));
}

// ── S1-5 ────────────────────────────────────────────────────────────────────

/// 301 columns by 60 000 rows are 18 million cells out of 60 300 in.
fn paddingFrames(a: std.mem.Allocator) ![2]df.Frame {
    return .{ try wideFrame(a, "c", 300, 1, false), try wideFrame(a, "g", 1, 60_000, false) };
}

test "arith: padding a shorter frame to a taller one is capped beyond the inputs (sweep S1-5)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const wide, const tall = try paddingFrames(a);
    try testing.expectError(error.TooLarge, df.arith(a, wide, tall, .add, .{}));
    // A modest padding still works.
    const short = try wideFrame(a, "g", 1, 1000, false);
    const r = try df.arith(a, wide, short, .add, .{});
    try testing.expectEqual(@as(usize, 1000), r.len);
}

test "combineFirst: padding a shorter frame to a taller one is capped beyond the inputs (sweep S1-5)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const wide, const tall = try paddingFrames(a);
    try testing.expectError(error.TooLarge, df.combineFirst(a, wide, tall));
    const short = try wideFrame(a, "g", 1, 1000, false);
    const r = try df.combineFirst(a, wide, short);
    try testing.expectEqual(@as(usize, 1000), r.len);
}

test "concat horizontal: padding a shorter frame to a taller one is capped beyond the inputs (sweep S1-5)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const wide, const tall = try paddingFrames(a);
    try testing.expectError(error.TooLarge, df.concat(a, &.{ wide, tall }, .horizontal));
    const short = try wideFrame(a, "g", 1, 1000, false);
    const r = try df.concat(a, &.{ wide, short }, .horizontal);
    try testing.expectEqual(@as(usize, 1000), r.len);
}

// ── S1-6 ────────────────────────────────────────────────────────────────────

test "matchToSchema: casting many columns copies one column each (sweep S1-6)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const w = 1500;
    const f = try wideFrame(a, "c", w, 3, false);
    const schema = try a.alloc(df.Column, w);
    for (schema, f.columns) |*s, c| s.* = .{ .name = c.name, .type = .float };
    // A cast of the whole frame per column copied every column's schema and array each
    // time: 1500 x 1500 entries, about 165 MB of arena. One column each is under 4 MB.
    const before = arena.queryCapacity();
    const r = try df.matchToSchema(a, f, schema, .{ .cast = true });
    try testing.expect(arena.queryCapacity() - before < 32 * 1024 * 1024);
    try testing.expectEqual(@as(usize, w), r.columns.len);
    try testing.expectEqual(df.ColumnType.float, r.columns[7].type);
    try testing.expectEqual(@as(usize, 3), r.len);
    // The refusals are as they were.
    try testing.expectError(error.SchemaMismatch, df.matchToSchema(a, f, schema, .{}));
    const cols = [_]df.Column{.{ .name = "t", .type = .text }};
    var b = try df.FrameBuilder.init(a, &cols, 1);
    try b.appendRow(&.{.{ .text = "abc" }});
    const tf = try b.toOwned();
    try testing.expectError(error.CastFailed, df.matchToSchema(a, tf, &.{.{ .name = "t", .type = .int }}, .{ .cast = true }));
}

// ── S1-7 ────────────────────────────────────────────────────────────────────

test "wide frames: name lookups are not quadratic in the width (sweep S1-7)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const w = 20_000;
    const f = try wideFrame(a, "c", w, 2, true);
    const g = try wideFrame(a, "c", w, 2, true);
    var slow: usize = 0;

    var t0 = nowNs();
    const j = try df.join(a, f, g, .{ .on = "k", .how = .left, .suffix = "_r" });
    expectFast(&slow, "join suffix", t0);
    try testing.expectEqual(@as(usize, 2 * w + 1), j.columns.len);
    try testing.expectEqualStrings("c0_r", j.columns[w + 1].name);

    t0 = nowNs();
    const r1 = try df.arith(a, f, g, .add, .{});
    expectFast(&slow, "arith", t0);
    try testing.expectEqual(@as(usize, w + 1), r1.columns.len);

    t0 = nowNs();
    const r2 = try df.combineFirst(a, f, g);
    expectFast(&slow, "combineFirst", t0);
    try testing.expectEqual(@as(usize, w + 1), r2.columns.len);

    t0 = nowNs();
    const r3 = try df.update(a, f, g);
    expectFast(&slow, "update", t0);
    try testing.expectEqual(@as(usize, w + 1), r3.columns.len);

    t0 = nowNs();
    const r4 = try df.joinWhere(a, f, g, &.{.{ .left = "k", .op = .eq, .right = "k" }}, "_r");
    expectFast(&slow, "joinWhere", t0);
    try testing.expectEqual(@as(usize, 2 * w + 2), r4.columns.len);

    t0 = nowNs();
    const r5 = try df.matchToSchema(a, f, f.columns, .{});
    expectFast(&slow, "matchToSchema", t0);
    try testing.expectEqual(@as(usize, w + 1), r5.columns.len);

    const names = try a.alloc([]const u8, f.columns.len);
    for (names, f.columns) |*n, c| n.* = c.name;
    t0 = nowNs();
    const r6 = try df.select(a, f, names);
    expectFast(&slow, "select", t0);
    try testing.expectEqual(@as(usize, w + 1), r6.columns.len);
    t0 = nowNs();
    const r7 = try df.drop(a, f, names);
    expectFast(&slow, "drop", t0);
    try testing.expectEqual(@as(usize, 0), r7.columns.len);

    t0 = nowNs();
    const r8 = try df.mergeOrdered(a, f, g, .{ .on = &.{"k"}, .fill_forward = true });
    expectFast(&slow, "mergeOrdered", t0);
    try testing.expect(r8.columns.len > w);
    try testing.expectEqual(@as(usize, 0), slow);
}

// ── S1-8 ────────────────────────────────────────────────────────────────────

test "row-index limit: the shared check (sweep S1-8)" {
    try core.checkRowsU32(0);
    try core.checkRowsU32(std.math.maxInt(u32) - 1);
    try testing.expectError(error.TooLarge, core.checkRowsU32(std.math.maxInt(u32)));
    try testing.expectError(error.TooLarge, core.checkRowsU32(std.math.maxInt(usize)));
}

/// Passes when `r` is `error.TooLarge`; any other error, or a result, fails the test.
fn refuses(r: anytype) !void {
    if (r) |_| return error.TestUnexpectedResult else |e| if (e != error.TooLarge) return e;
}

test "row-index limit: every verb that builds u32 indexes refuses 2^32 - 1 rows before it allocates (sweep S1-8)" {
    // A hand-built frame may claim any length. The allocator holds 64 KiB, so a verb that
    // went on would end in OutOfMemory, never in a real allocation of 16 GB.
    var buf: [1 << 16]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const a = fba.allocator();
    const cols = [_]df.Column{.{ .name = "a", .type = .int }};
    const big: df.Frame = .{ .columns = &cols, .data = &.{}, .len = std.math.maxInt(u32) };
    const small: df.Frame = .{ .columns = &cols, .data = &.{}, .len = 0 };
    const one_agg: df.AggCol = .{ .src = "a", .out = "o", .func = .count };

    // verbs.zig
    try refuses(verbs.sortedRows(a, big, &.{0}, &.{.asc}, .auto));
    try refuses(df.filter(a, big, .{ .where = &.{} }));
    try refuses(df.distinct(a, big, .{ .keys = &.{} }));
    try refuses(df.aggregate(a, big, .{ .group_by = &.{}, .aggs = &.{} }));
    try refuses(df.unpivot(a, big, .{ .id_cols = &.{} }));
    try refuses(df.join(a, big, small, .{ .on = "a" }));
    try refuses(df.join(a, small, big, .{ .on = "a" }));
    try refuses(df.sort(a, big, .{ .key = "a" }));
    try refuses(df.dropna(a, big, .{}));
    try refuses(df.pivot(a, big, .{ .row_key = "a", .col_key = "a", .value_col = "a" }));
    try refuses(df.cumsum(a, big, .{ .value_col = "a", .out = "o" }));
    // structure.zig
    try refuses(df.clone(a, big));
    try refuses(df.clear(a, small, std.math.maxInt(u32)));
    try refuses(df.take(a, big, &.{0}));
    try refuses(df.gatherEvery(a, big, 1, 0));
    try refuses(df.reverse(a, big));
    try refuses(df.transpose(a, big, .{}));
    try refuses(df.concat(a, &.{big}, .horizontal));
    try refuses(df.concat(a, &.{big}, .vertical));
    // reshape.zig
    try refuses(df.groupFilter(a, big, .{ .by = &.{"a"}, .agg = one_agg, .op = .gt, .value = .{ .int = 0 } }));
    try refuses(df.joinWhere(a, big, small, &.{}, "_r"));
    try refuses(df.joinWhere(a, small, big, &.{}, "_r"));
    try refuses(df.pivotKeys(a, big, .{ .row_keys = &.{"a"}, .col_keys = &.{"a"}, .values = &.{"a"} }));
    try refuses(df.dummies(a, big, .{}));
    try refuses(df.combineFirst(a, big, small));
    try refuses(df.combineFirst(a, small, big));
    try refuses(df.update(a, big, small));
    try refuses(df.repeatRows(a, big, .{ .times = 1 }));
    try refuses(df.dropNans(a, big, &.{}));
    try refuses(df.betweenTime(a, big, .{ .col = "a", .start = "00:00", .end = "01:00" }));
    // frameops.zig
    try refuses(df.arith(a, big, small, .add, .{}));
    try refuses(df.arith(a, small, big, .add, .{}));
    try refuses(df.compare(a, big, small));
    try refuses(df.interpolate(a, big, .{ .col = "a" }));
    try refuses(df.upsample(a, big, .{ .time = "a", .every = "1d" }));
    // the other files' entry points (S2's group; the class is S1's)
    try refuses(df.page(a, big, .{}));
    try refuses(df.tail(a, big, 1));
    try refuses(df.topN(a, big, .{ .n = 1 }));
    try refuses(df.sample(a, big, .{ .n = 1, .seed = 1 }));
    try refuses(df.partitionBy(a, big, &.{"a"}));
    try refuses(df.valueCounts(a, big, .{ .cols = &.{"a"} }));
    try refuses(df.duplicateMask(a, big, .{}));
    try refuses(df.argSort(a, big, .{ .key = "a" }));
    try refuses(df.factorize(a, big, .{ .cols = &.{"a"}, .out = "o" }));
    try refuses(df.topK(a, big, .{ .by = &.{"a"}, .n = 1 }));
    try refuses(df.window(a, big, .{ .value_col = "a", .out = "o", .op = .cum_sum }));
    const e: df.Expr = .{ .col = "a" };
    try refuses(df.where(a, big, &e));
}
