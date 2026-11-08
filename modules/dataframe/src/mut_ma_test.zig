// SPDX-License-Identifier: MIT
//! D5 whole-module mutation run, group MA (verbs, keys, core, frame, value, frameops,
//! structure, reshape): one test per surviving mutant that is not equivalent. Test names end
//! "(mut <id>)"; each id is a mutant of `d5-mut-ma`, killed by its test.

const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const core = @import("core.zig");
const keys = @import("keys.zig");
const verbs = @import("verbs.zig");
const vm = @import("value.zig");
const fm = @import("frame.zig");
const sp = @import("spec.zig");

const Value = df.Value;
const Column = df.Column;
const Frame = df.Frame;
const ColumnData = df.ColumnData;

fn build(a: std.mem.Allocator, cols: []const Column, rows: []const []const Value) !Frame {
    var b = try df.FrameBuilder.init(a, cols, rows.len);
    for (rows) |r| try b.appendRow(r);
    return b.toOwned();
}

const empty: Frame = .{ .columns = &.{}, .data = &.{}, .len = 0 };
const huge: Frame = .{ .columns = &.{}, .data = &.{}, .len = std.math.maxInt(u32) };

fn isNull(v: ?Value) bool {
    return v != null and v.? == .null;
}

fn sameCells(f: Frame, g: Frame) !void {
    try testing.expectEqual(f.len, g.len);
    try testing.expectEqual(f.columns.len, g.columns.len);
    for (f.columns, 0..) |c, ci| {
        try testing.expectEqualStrings(c.name, g.columns[ci].name);
        for (0..f.len) |ri| {
            const x = f.columnAt(ci).get(ri);
            const y = g.columnAt(ci).get(ri);
            const both_missing = (x == .null or (x == .float and std.math.isNan(x.float))) and (y == .null or (y == .float and std.math.isNan(y.float)));
            try testing.expect(both_missing or x.order(y) == .eq);
        }
    }
}

// ── core ────────────────────────────────────────────────────────────────────

test "aggregate: median is linear whatever the interpolation field says (mut 38)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try build(a, &.{ .{ .name = "g", .type = .int }, .{ .name = "x", .type = .float } }, &.{
        &.{ .{ .int = 1 }, .{ .float = 1 } },
        &.{ .{ .int = 1 }, .{ .float = 2 } },
        &.{ .{ .int = 1 }, .null }, // a missing cell: the row-reading path, not the all-numbers one
    });
    const r = try df.aggregate(a, f, .{ .group_by = &.{"g"}, .aggs = &.{.{ .src = "x", .out = "m", .func = .median, .interpolation = .lower }} });
    try testing.expectEqual(Value{ .float = 1.5 }, r.cell(0, "m").?);
}

test "aggregate: sum_exact overflow is sticky, a later opposite term does not undo it (mut 43, 44)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const mx = std.math.maxInt(i128);
    const f = try build(a, &.{ .{ .name = "g", .type = .int }, .{ .name = "x", .type = .decimal } }, &.{
        &.{ .{ .int = 1 }, .{ .decimal = mx } },
        &.{ .{ .int = 1 }, .{ .decimal = 1 } }, // overflows; a wrapped total plus the next term would fit again
        &.{ .{ .int = 1 }, .{ .decimal = mx } },
    });
    const r = try df.aggregate(a, f, .{ .group_by = &.{"g"}, .aggs = &.{.{ .src = "x", .out = "s", .func = .sum_exact }} });
    try testing.expect(isNull(r.cell(0, "s")));
}

test "aggregate: a quantile of an empty group is null for every interpolation (mut 58)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try build(a, &.{ .{ .name = "g", .type = .int }, .{ .name = "x", .type = .float } }, &.{
        &.{ .{ .int = 1 }, .{ .float = std.math.nan(f64) } },
    });
    const r = try df.aggregate(a, f, .{ .group_by = &.{"g"}, .aggs = &.{.{ .src = "x", .out = "q", .func = .quantile, .interpolation = .lower }} });
    try testing.expect(isNull(r.cell(0, "q")));
}

test "aggregateCellsWithin: the limit is exact and the product cannot wrap (mut 71, 72)" {
    try core.aggregateCellsWithin(1 << 24, 1);
    try core.aggregateCellsWithin(1 << 12, 1 << 12);
    try testing.expectError(error.TooLarge, core.aggregateCellsWithin((1 << 24) + 1, 1));
    try testing.expectError(error.TooLarge, core.aggregateCellsWithin(std.math.maxInt(usize), 2));
}

test "windowAgg and stdSample on their edges (mut 89, 90, 91, 92, 93)" {
    try testing.expectEqual(@as(f64, 2), core.windowAgg(&.{ 1, 2, 3 }, .mean));
    try testing.expectEqual(@as(f64, 6), core.windowAgg(&.{ 1, 2, 3 }, .sum));
    try testing.expectEqual(@as(f64, 1), core.windowAgg(&.{ 3, 1, 2 }, .min));
    try testing.expectEqual(@as(f64, 5), core.windowAgg(&.{ 3, 5, 2 }, .max));
    try testing.expectEqual(@as(f64, -1), core.windowAgg(&.{ -3, -1, -2 }, .max));
    try testing.expectEqual(@as(f64, 0), core.stdSample(&.{5}));
    try testing.expectApproxEqAbs(@sqrt(2.0), core.stdSample(&.{ 1, 3 }), 1e-12);
}

// ── keys ────────────────────────────────────────────────────────────────────

test "exactInt: -2^63 as a float is the int minInt (mut 101)" {
    try testing.expectEqual(@as(?i64, std.math.minInt(i64)), keys.exactInt(.{ .float = -9223372036854775808.0 }));
}

test "encode: a decimal needing a 54-bit significand is not keyed as a float (mut 109)" {
    const a = testing.allocator;
    const q: i128 = (1 << 53) + 3;
    const dec: Value = .{ .decimal = q * 244_140_625 };
    const flt: Value = .{ .float = 9007199254740996.0 / 4096.0 };
    try testing.expect(dec.order(flt) != .eq);
    var x: std.ArrayList(u8) = .empty;
    defer x.deinit(a);
    var y: std.ArrayList(u8) = .empty;
    defer y.deinit(a);
    try keys.encode(a, &x, dec, .own);
    try keys.encode(a, &y, flt, .own);
    try testing.expect(!std.mem.eql(u8, x.items, y.items));
}

test "Table: the work cap allows exactly its limit and stops at the next step (mut 118)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var t = try keys.Table.initInt(a, 8, 1);
    t.work.limit = 1;
    var k: i64 = 0;
    while (k < 60) : (k += 1) {
        _ = t.getOrPutInt(a, k) catch break;
    }
    try testing.expect(k < 60); // a second collision step happened
    try testing.expectEqual(@as(u64, 2), t.work.steps);
}

test "Table: the work limit is the floor plus a share per row, and allow adds a share (mut 119, 120, 121)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const t = try keys.Table.initInt(a, 4, 1);
    try testing.expectEqual(keys.work_floor + keys.work_per_row * 4, t.work.limit);
    t.allow(10);
    try testing.expectEqual(keys.work_floor + keys.work_per_row * 14, t.work.limit);
}

test "Table: two keys with one 32-bit tag and one slot stay two keys (mut 127)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const seed: u64 = 1234;
    var seen: std.AutoHashMapUnmanaged(u64, u32) = .empty;
    var pair: ?[2]u32 = null;
    var i: u32 = 0;
    while (i < 6_000_000) : (i += 1) {
        const h = std.hash.Wyhash.hash(seed, std.mem.asBytes(&i));
        const tag = (h >> 32) << 6 | (h & 63);
        const gop = try seen.getOrPut(a, tag);
        if (gop.found_existing) {
            pair = .{ gop.value_ptr.*, i };
            break;
        }
        gop.value_ptr.* = i;
    }
    try testing.expect(pair != null);
    var t = try keys.Table.initBytes(a, 8, seed);
    const k0 = pair.?[0];
    const k1 = pair.?[1];
    try testing.expectEqual(@as(u32, 0), try t.getOrPutBytes(a, std.mem.asBytes(&k0)));
    try testing.expectEqual(@as(u32, 1), try t.getOrPutBytes(a, std.mem.asBytes(&k1)));
}

test "Table.lookup: no key columns finds nothing in an empty table (mut 132)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const t: keys.Table = .{};
    var scratch: std.ArrayList(u8) = .empty;
    try testing.expect((try t.lookup(a, &scratch, &.{}, &.{}, .as_null)) == null);
}

test "factorizeInts: a length at the u32 limit is TooLarge before anything is allocated (mut 137)" {
    var fa = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    const fake: []const i64 = @as([*]const i64, @ptrFromInt(@alignOf(i64)))[0..std.math.maxInt(u32)];
    try testing.expectError(error.TooLarge, keys.factorizeInts(fa.allocator(), fake));
}

test "keyColPut: a cell that does not fit frees the extracted array (mut 149, 150)" {
    const a = testing.allocator;
    const ri = [_][]const Value{ &.{.{ .int = 1 }}, &.{.{ .text = "x" }} };
    var c1 = try keys.keyColFor(a, &ri, 0);
    keys.keyColPut(&c1, a, 0, ri[0][0]);
    keys.keyColPut(&c1, a, 1, ri[1][0]);
    try testing.expect(c1 == .generic);
    const rt = [_][]const Value{ &.{.{ .text = "x" }}, &.{.{ .int = 1 }} };
    var c2 = try keys.keyColFor(a, &rt, 0);
    keys.keyColPut(&c2, a, 0, rt[0][0]);
    keys.keyColPut(&c2, a, 1, rt[1][0]);
    try testing.expect(c2 == .generic);
}

test "factorizeMany: tuples whose span passes 2^16 take the table path, not a span-sized array (mut 162)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const n = 60_000;
    const rows = try a.alloc([]const Value, n);
    for (rows, 0..) |*r, i| r.* = try a.dupe(Value, &.{ .{ .int = @intCast(i) }, .{ .int = @intCast((i * 7) % 60_001) } });
    const idxs = [_]usize{ 0, 1 };
    var cols = [_]keys.KeyCol{ try keys.keyColFor(a, rows, 0), try keys.keyColFor(a, rows, 1) };
    for (rows, 0..) |r, i| {
        keys.keyColPut(&cols[0], a, i, r[0]);
        keys.keyColPut(&cols[1], a, i, r[1]);
    }
    const f = try keys.factorizeMany(a, &cols, rows, &idxs, .as_null);
    try testing.expectEqual(@as(usize, n), f.groups());
    try testing.expectEqual(@as(u32, 59_999), f.ids[59_999]);
}

test "factorizeMany: one key column gives that column's groups and firsts (mut 167)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const rows = [_][]const Value{ &.{.{ .int = 5 }}, &.{.{ .int = 6 }}, &.{.{ .int = 5 }} };
    var cols = [_]keys.KeyCol{try keys.keyColFor(a, &rows, 0)};
    for (rows, 0..) |r, i| keys.keyColPut(&cols[0], a, i, r[0]);
    const f = try keys.factorizeMany(a, &cols, &rows, &.{0}, .as_null);
    try testing.expectEqualSlices(u32, &.{ 0, 1, 0 }, f.ids);
    try testing.expectEqualSlices(u32, &.{ 0, 1 }, f.firsts);
}

test "probeAll: every probe adds its share to the work limit (mut 170)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try keys.factorizeInts(a, &.{ 1, 2, 3 });
    const before = f.table.work.limit;
    const rows = [_][]const Value{ &.{.{ .int = 1 }}, &.{.{ .int = 9 }} };
    var hits: [2]u32 = undefined;
    try keys.probeAll(a, &f.table, &rows, &.{0}, .as_null, false, &hits);
    try testing.expectEqual(before + keys.work_per_row * 2, f.table.work.limit);
    try testing.expectEqual(@as(u32, 0), hits[0]);
    try testing.expectEqual(keys.none, hits[1]);
}

test "floatKey: a NaN with the sign bit set is still the largest key (mut 183)" {
    const neg_nan: f64 = @bitCast(@as(u64, 0xfff8000000000001));
    try testing.expect(std.math.isNan(neg_nan));
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), keys.floatKey(neg_nan));
}

// ── frame, value ────────────────────────────────────────────────────────────

test "NameIndex: of equal names the first wins (mut 217)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{ .{ .name = "a", .type = .int }, .{ .name = "b", .type = .int }, .{ .name = "a", .type = .int } };
    var idx = try fm.NameIndex.init(a, &cols);
    defer idx.deinit(a);
    try testing.expectEqual(@as(?usize, 0), idx.get("a"));
    try testing.expectEqual(@as(?usize, 1), idx.get("b"));
}

test "Date.fromOrdinal: days beyond i64 or beyond an i32 year are null (mut 348, 355)" {
    try testing.expect(vm.Date.fromOrdinal(std.math.maxInt(i64)) == null);
    try testing.expect(vm.Date.fromOrdinal(800_000_000_000) == null);
}

test "ISO parsing: a bad separator is refused (mut 363, 371)" {
    try testing.expect(vm.parseIsoDate("2024-01x15") == null);
    try testing.expect(vm.parseIsoTimestamp("2024-01-01T10x30") == null);
}

// ── verbs ───────────────────────────────────────────────────────────────────

test "growthWithin: allowed growth is exactly max_join_cells (mut 502, 503)" {
    try verbs.growthWithin(sp.max_join_cells + 5, 5);
    try testing.expectError(error.TooLarge, verbs.growthWithin(sp.max_join_cells + 6, 5));
}

test "filter: a float array shorter than the frame reads as null past its end (mut 536)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{.{ .name = "x", .type = .float }};
    const data = [_]ColumnData{.{ .float = .{ .values = &[_]f64{ 1, 2 } } }};
    const f: Frame = .{ .columns = &cols, .data = &data, .len = 4 };
    const r = try df.filter(a, f, .{ .where = &.{.{ .col = "x", .op = .gt, .value = .{ .float = 0 } }} });
    try testing.expectEqual(@as(usize, 2), r.len);
}

test "distinct: an int array longer than the frame is read for len rows only (mut 546)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{.{ .name = "k", .type = .int }};
    const data = [_]ColumnData{.{ .int = .{ .values = &[_]i64{ 1, 2, 3, 4 } } }};
    const f: Frame = .{ .columns = &cols, .data = &data, .len = 2 };
    const r = try df.distinct(a, f, .{ .keys = &.{"k"} });
    try testing.expectEqual(@as(usize, 2), r.len);
}

test "aggregate: min_count applies to sum and prod only, and counts numbers only (mut 624, 626)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try build(a, &.{ .{ .name = "g", .type = .int }, .{ .name = "x", .type = .float } }, &.{
        &.{ .{ .int = 1 }, .{ .float = 1 } },
        &.{ .{ .int = 1 }, .{ .text = "x" } },
    });
    const m = try df.aggregate(a, f, .{ .group_by = &.{"g"}, .aggs = &.{.{ .src = "x", .out = "m", .func = .mean, .min_count = 5 }} });
    try testing.expect(!isNull(m.cell(0, "m")));
    const s = try df.aggregate(a, f, .{ .group_by = &.{"g"}, .aggs = &.{.{ .src = "x", .out = "s", .func = .sum, .min_count = 2 }} });
    try testing.expect(isNull(s.cell(0, "s")));
}

test "unpivot: an empty typed frame keeps the cell path's storage kinds (mut 635, 640)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{ .{ .name = "a", .type = .int }, .{ .name = "b", .type = .int } };
    const data = [_]ColumnData{ .{ .int = .{ .values = &.{} } }, .{ .int = .{ .values = &.{} } } };
    const f: Frame = .{ .columns = &cols, .data = &data, .len = 0 };
    inline for (.{
        df.UnpivotSpec{ .id_cols = &.{"a"}, .value_cols = &.{"b"} },
        df.UnpivotSpec{ .id_cols = &.{ "a", "b" } },
    }) |spec| {
        const r = try df.unpivot(a, f, spec);
        const rc = try verbs.test_hooks.unpivotCells(a, f, spec);
        try testing.expectEqual(rc.data.len, r.data.len);
        for (r.data, rc.data) |x, y| try testing.expectEqual(std.meta.activeTag(y), std.meta.activeTag(x));
    }
}

test "unpivot and join over int arrays shorter than the frame agree with the cell path (mut 638, 654)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{ .{ .name = "a", .type = .int }, .{ .name = "b", .type = .int } };
    const data = [_]ColumnData{ .{ .int = .{ .values = &[_]i64{ 1, 2 } } }, .{ .int = .{ .values = &[_]i64{ 3, 4 } } } };
    const f: Frame = .{ .columns = &cols, .data = &data, .len = 3 };
    const spec: df.UnpivotSpec = .{ .id_cols = &.{}, .value_cols = &.{ "a", "b" } };
    try sameCells(try df.unpivot(a, f, spec), try verbs.test_hooks.unpivotCells(a, f, spec));

    const kc = [_]Column{.{ .name = "k", .type = .int }};
    const left: Frame = .{ .columns = &kc, .data = &[_]ColumnData{.{ .int = .{ .values = &[_]i64{ 1, 2 } } }}, .len = 3 };
    const right = try build(a, &.{.{ .name = "k", .type = .int }}, &.{ &.{.{ .int = 1 }}, &.{.{ .int = 2 }}, &.{.{ .int = 3 }} });
    const js: df.JoinSpec = .{ .on = "k", .how = .left };
    try sameCells(try df.join(a, left, right, js), try verbs.test_hooks.joinCells(a, left, right, js));
}

test "take: a boxed array shorter than the frame gives null past its end (mut 670)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const bx = [_]Value{ .{ .int = 1 }, .{ .int = 2 } };
    const r = try verbs.take(a, .{ .boxed = &bx }, &[_]u32{ 3, 1 }, false);
    try testing.expect(r.get(0) == .null);
    try testing.expectEqual(Value{ .int = 2 }, r.get(1));
}

test "take: texts of 17 bytes and more are copied whole (mut 669)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cells = [_]Value{
        .{ .text = "abcdefghijklmnopq" },
        .{ .text = "ABCDEFGHIJKLMNOPQR" },
        .{ .text = "0123456789012345678901234567890" },
        .{ .text = "z" },
    };
    const col = try df.columnFromCells(a, &cells);
    const r = try verbs.take(a, col, &[_]u32{ 2, 0, 1, 3 }, false);
    try testing.expectEqualStrings("0123456789012345678901234567890", r.get(0).text);
    try testing.expectEqualStrings("abcdefghijklmnopq", r.get(1).text);
    try testing.expectEqualStrings("ABCDEFGHIJKLMNOPQR", r.get(2).text);
    try testing.expectEqualStrings("z", r.get(3).text);
}

test "join: a cross join of two column-less frames is capped at max_join_cells cells, width counted as 1 (mut 686, 687)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const l: Frame = .{ .columns = &.{}, .data = &.{}, .len = 4096 };
    const r: Frame = .{ .columns = &.{}, .data = &.{}, .len = 4096 };
    const ok = try df.join(a, l, r, .{ .how = .cross });
    try testing.expectEqual(@as(usize, 1 << 24), ok.len);
    const l2: Frame = .{ .columns = &.{}, .data = &.{}, .len = 4097 };
    try testing.expectError(error.TooLarge, df.join(a, l2, r, .{ .how = .cross }));
}

test "join: exactly max_join_cells output cells on a repeated key are allowed (mut 698)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const vals = try a.alloc(i64, 4096);
    @memset(vals, 1);
    const cols = [_]Column{.{ .name = "k", .type = .int }};
    const f: Frame = .{ .columns = &cols, .data = &[_]ColumnData{.{ .int = .{ .values = vals } }}, .len = 4096 };
    const r = try df.join(a, f, f, .{ .on = "k", .how = .inner });
    try testing.expectEqual(@as(usize, 1 << 24), r.len);
}

test "dropna: how = all on a frame with no columns keeps every row (mut 709)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f: Frame = .{ .columns = &.{}, .data = &.{}, .len = 5 };
    const r = try df.dropna(a, f, .{ .how = .all });
    try testing.expectEqual(@as(usize, 5), r.len);
}

test "sort: arrays shorter than the frame sort their missing cells as missing (mut 711, 715, 716, 724)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const bx = [_]Value{ .{ .int = 3 }, .{ .int = 1 } };
    const fb: Frame = .{ .columns = &.{.{ .name = "x", .type = .int }}, .data = &[_]ColumnData{.{ .boxed = &bx }}, .len = 3 };
    const rb = try df.sort(a, fb, .{ .key = "x" });
    try testing.expect(isNull(rb.cell(0, "x")));
    try testing.expectEqual(Value{ .int = 1 }, rb.cell(1, "x").?);

    const ff: Frame = .{ .columns = &.{.{ .name = "x", .type = .float }}, .data = &[_]ColumnData{.{ .float = .{ .values = &[_]f64{ 5, -3 } } }}, .len = 4 };
    const rf = try df.sort(a, ff, .{ .key = "x" });
    try testing.expect(isNull(rf.cell(0, "x")));
    try testing.expect(isNull(rf.cell(1, "x")));
    try testing.expectEqual(Value{ .float = -3 }, rf.cell(2, "x").?);

    const fi: Frame = .{ .columns = &.{.{ .name = "x", .type = .int }}, .data = &[_]ColumnData{.{ .int = .{ .values = &[_]i64{ 5, -3 } } }}, .len = 4 };
    const ri = try df.sort(a, fi, .{ .key = "x" });
    try testing.expect(isNull(ri.cell(0, "x")));
    try testing.expect(isNull(ri.cell(1, "x")));
    try testing.expectEqual(Value{ .int = -3 }, ri.cell(2, "x").?);
}

test "rename: duplicate names in columns that are not renamed are left alone (mut 746)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f: Frame = .{ .columns = &.{ .{ .name = "a", .type = .int }, .{ .name = "a", .type = .int }, .{ .name = "b", .type = .int } }, .data = &.{}, .len = 0 };
    const r = try df.rename(a, f, &.{.{ .from = "b", .to = "c" }});
    try testing.expectEqualStrings("c", r.columns[2].name);
}

test "fillna: a column with nothing missing is shared, not rebuilt (mut 748)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try build(a, &.{.{ .name = "x", .type = .int }}, &.{ &.{.{ .int = 1 }}, &.{.{ .int = 2 }} });
    const r = try df.fillna(a, f, .{ .value = .{ .int = 0 } });
    try testing.expect(r.data[0].int.values.ptr == f.data[0].int.values.ptr);
}

// ── frameops ────────────────────────────────────────────────────────────────

test "arith: arrays longer than their frame are not read past len (mut 808, 809)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{.{ .name = "x", .type = .int }};
    const long_f: Frame = .{ .columns = &cols, .data = &[_]ColumnData{.{ .int = .{ .values = &[_]i64{ 1, 99 } } }}, .len = 1 };
    const short_g: Frame = .{ .columns = &cols, .data = &[_]ColumnData{.{ .int = .{ .values = &[_]i64{ 1, 1 } } }}, .len = 2 };
    const r1 = try df.arith(a, long_f, short_g, .add, .{});
    try testing.expectEqual(Value{ .int = 2 }, r1.cell(0, "x").?);
    try testing.expect(isNull(r1.cell(1, "x")));
    const r2 = try df.arith(a, short_g, long_f, .add, .{});
    try testing.expect(isNull(r2.cell(1, "x")));
}

test "arith: an all-null result column is float (mut 814)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const n = try build(a, &.{.{ .name = "x", .type = .float }}, &.{&.{.null}});
    const rn = try df.arith(a, n, n, .add, .{});
    try testing.expectEqual(df.ColumnType.float, rn.columns[0].type);
}

test "arithScalar: a non-arithmetic operator is refused, defaults pick decimals, cols picks only its own (mut 817, 818, 819)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try build(a, &.{ .{ .name = "a", .type = .int }, .{ .name = "d", .type = .decimal }, .{ .name = "b", .type = .int } }, &.{
        &.{ .{ .int = 1 }, .{ .decimal = df.decimal_scale }, .{ .int = 5 } },
    });
    try testing.expectError(error.BadArgument, df.arithScalar(a, f, .eq, .{ .int = 1 }, .{}));
    const r = try df.arithScalar(a, f, .add, .{ .int = 1 }, .{});
    try testing.expectEqual(Value{ .decimal = 2 * df.decimal_scale }, r.cell(0, "d").?);
    const r2 = try df.arithScalar(a, f, .add, .{ .int = 1 }, .{ .cols = &.{"a"} });
    try testing.expectEqual(Value{ .int = 2 }, r2.cell(0, "a").?);
    try testing.expectEqual(Value{ .int = 5 }, r2.cell(0, "b").?);
}

test "compare: NaN differs from a number, null from a value; shapes and names are checked; unchanged columns are left out (mut 821, 822, 826, 827, 828)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const fa = try build(a, &.{.{ .name = "x", .type = .float }}, &.{&.{.{ .float = std.math.nan(f64) }}});
    const ga = try build(a, &.{.{ .name = "x", .type = .float }}, &.{&.{.{ .float = 1 }}});
    try testing.expectEqual(@as(usize, 1), (try df.compare(a, fa, ga)).len);
    const fn_ = try build(a, &.{.{ .name = "x", .type = .int }}, &.{&.{.null}});
    const gn = try build(a, &.{.{ .name = "x", .type = .int }}, &.{&.{.{ .int = 5 }}});
    try testing.expectEqual(@as(usize, 1), (try df.compare(a, fn_, gn)).len);
    const two = try build(a, &.{ .{ .name = "x", .type = .int }, .{ .name = "y", .type = .int } }, &.{&.{ .{ .int = 1 }, .{ .int = 1 } }});
    const one = try build(a, &.{.{ .name = "x", .type = .int }}, &.{&.{.{ .int = 1 }}});
    try testing.expectError(error.SchemaMismatch, df.compare(a, two, one));
    const renamed = try build(a, &.{ .{ .name = "x", .type = .int }, .{ .name = "z", .type = .int } }, &.{&.{ .{ .int = 1 }, .{ .int = 1 } }});
    try testing.expectError(error.SchemaMismatch, df.compare(a, two, renamed));
    const two2 = try build(a, &.{ .{ .name = "x", .type = .int }, .{ .name = "y", .type = .int } }, &.{&.{ .{ .int = 2 }, .{ .int = 1 } }});
    const c = try df.compare(a, two, two2);
    try testing.expectEqual(@as(usize, 3), c.columns.len); // row, x_self, x_other
}

test "dot: exactly max_aggregate_cells output cells are allowed (mut 831)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f: Frame = .{ .columns = &.{}, .data = &.{}, .len = 1 << 24 };
    const g: Frame = .{ .columns = &.{.{ .name = "o", .type = .float }}, .data = &[_]ColumnData{.nulls}, .len = 0 };
    const r = try df.dot(a, f, g);
    try testing.expectEqual(@as(usize, 1 << 24), r.len);
    const f2: Frame = .{ .columns = &.{}, .data = &.{}, .len = (1 << 24) + 1 };
    try testing.expectError(error.TooLarge, df.dot(a, f2, g));
}

fn interp(a: std.mem.Allocator, ys: []const Value, ts: ?[]const i64, method: anytype) !Frame {
    const rows = try a.alloc([]const Value, ys.len);
    for (rows, ys, 0..) |*r, y, i| r.* = try a.dupe(Value, &.{ .{ .int = if (ts) |t| t[i] else @intCast(i) }, y });
    const f = try build(a, &.{ .{ .name = "t", .type = .int }, .{ .name = "y", .type = .float } }, rows);
    return df.interpolate(a, f, .{ .col = "y", .by = if (ts != null) "t" else null, .method = method });
}

test "interpolate: NaN and text cells are interpolated over, the points are sorted, a tie takes the earlier (mut 837, 838, 839, 840, 841, 842, 843, 846)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const nan = std.math.nan(f64);
    const r1 = try interp(a, &.{ .{ .float = 1 }, .{ .float = nan }, .{ .float = 3 } }, null, .linear);
    try testing.expectEqual(Value{ .float = 2 }, r1.cell(1, "y").?);
    const r2 = try interp(a, &.{ .{ .float = 1 }, .{ .text = "x" }, .{ .float = 3 } }, null, .linear);
    try testing.expectEqual(Value{ .float = 2 }, r2.cell(1, "y").?);
    const r3 = try interp(a, &.{ .{ .float = 30 }, .{ .float = 10 }, .null }, &.{ 3, 1, 2 }, .linear);
    try testing.expectEqual(Value{ .float = 20 }, r3.cell(2, "y").?);
    const r4 = try interp(a, &.{ .{ .float = 1 }, .null, .{ .float = 3 } }, &.{ 0, 0, 5 }, .linear);
    try testing.expectEqual(Value{ .float = 1 }, r4.cell(1, "y").?);
    const r5 = try interp(a, &.{ .{ .float = 1 }, .{ .float = 3 }, .null }, &.{ 0, 5, 5 }, .linear);
    try testing.expectEqual(Value{ .float = 3 }, r5.cell(2, "y").?);
    const r6 = try interp(a, &.{ .{ .float = 1 }, .null, .{ .float = 3 } }, null, .nearest);
    try testing.expectEqual(Value{ .float = 1 }, r6.cell(1, "y").?);
}

test "upsample: a zero or negative step is refused (mut 854, 855, 856)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try build(a, &.{.{ .name = "t", .type = .timestamp }}, &.{ &.{.{ .int = 0 }}, &.{.{ .int = 3_600_000_000 }} });
    try testing.expectError(error.BadArgument, df.upsample(a, f, .{ .time = "t", .every = "0s" }));
    try testing.expectError(error.BadArgument, df.upsample(a, f, .{ .time = "t", .every = "-1h" }));
    try testing.expectError(error.BadArgument, df.upsample(a, f, .{ .time = "t", .every = "-1mo" }));
}

// ── structure ───────────────────────────────────────────────────────────────

test "take: output cells are capped at max_join_cells, a column-less frame counting width 1 (mut 902, 903)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f: Frame = .{ .columns = &.{}, .data = &.{}, .len = 1 };
    const idx = try a.alloc(i64, (1 << 24) + 1);
    @memset(idx, 0);
    const r = try df.take(a, f, idx[0 .. 1 << 24]);
    try testing.expectEqual(@as(usize, 1 << 24), r.len);
    try testing.expectError(error.TooLarge, df.take(a, f, idx));
}

test "column edits: a first column sets the height, insert may append, replace checks bounds, length and name (mut 915, 917, 919, 920, 925, 926, 927)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const s: df.Series = .{ .name = "n", .type = .int, .data = .{ .int = .{ .values = &[_]i64{ 1, 2, 3 } } }, .len = 3 };
    const r = try df.insertColumn(a, empty, 0, s);
    try testing.expectEqual(@as(usize, 3), r.len);
    const f1 = try build(a, &.{.{ .name = "x", .type = .int }}, &.{ &.{.{ .int = 1 }}, &.{.{ .int = 2 }}, &.{.{ .int = 3 }} });
    const s2: df.Series = .{ .name = "m", .type = .int, .data = s.data, .len = 3 };
    const r2 = try df.insertColumn(a, f1, 1, s2);
    try testing.expectEqual(@as(usize, 2), r2.columns.len);
    const same = try df.hstack(a, empty, &.{});
    try testing.expectEqual(@as(usize, 0), same.columns.len);
    try testing.expectError(error.IndexOutOfBounds, df.replaceColumn(a, f1, 1, s2));
    const short: df.Series = .{ .name = "m", .type = .int, .data = .{ .int = .{ .values = &[_]i64{1} } }, .len = 1 };
    try testing.expectError(error.LengthMismatch, df.replaceColumn(a, f1, 0, short));
    const same_name: df.Series = .{ .name = "x", .type = .int, .data = s.data, .len = 3 };
    const r3 = try df.replaceColumn(a, f1, 0, same_name);
    try testing.expectEqualStrings("x", r3.columns[0].name);
}

test "selectors: numeric includes decimal, temporal includes timestamp, an index at the width is out of bounds, nesting stops at 64 (mut 933, 934, 939, 940)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f: Frame = .{ .columns = &.{ .{ .name = "d", .type = .decimal }, .{ .name = "t", .type = .timestamp }, .{ .name = "s", .type = .text } }, .data = &.{}, .len = 0 };
    const num = try df.selectColumns(a, f, .numeric);
    try testing.expectEqual(@as(usize, 1), num.len);
    try testing.expectEqualStrings("d", num[0]);
    const tmp = try df.selectColumns(a, f, .temporal);
    try testing.expectEqual(@as(usize, 1), tmp.len);
    try testing.expectEqualStrings("t", tmp[0]);
    try testing.expectError(error.IndexOutOfBounds, df.selectColumns(a, f, .{ .by_index = &.{3} }));
    var nodes: [65]df.Selector = undefined;
    for (nodes[0..64], 0..) |*n, i| n.* = .{ .not = &nodes[i + 1] };
    nodes[64] = .all;
    try testing.expectError(error.BadArgument, df.selectColumns(a, empty, nodes[0]));
}

test "hasNulls is true for a single null (mut 941)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try build(a, &.{.{ .name = "x", .type = .int }}, &.{ &.{.{ .int = 1 }}, &.{.null} });
    try testing.expect(df.hasNulls(f));
}

test "columnBytes counts only the first len rows and the bitmap words they use (mut 943, 944, 945, 947, 949)" {
    const mk = struct {
        fn of(d: []const ColumnData, len: usize) Frame {
            return .{ .columns = &.{.{ .name = "x", .type = .int }}, .data = d, .len = len };
        }
    }.of;
    const longer = [_]i64{ 1, 2, 3, 4 };
    try testing.expectEqual(@as(usize, 16), df.columnBytes(mk(&[_]ColumnData{.{ .int = .{ .values = &longer } }}, 2), 0));
    const words = [_]u64{ 3, 0, 0 };
    try testing.expectEqual(@as(usize, 24), df.columnBytes(mk(&[_]ColumnData{.{ .int = .{ .values = longer[0..2], .valid = &words } }}, 2), 0));
    const offs = [_]usize{ 0, 1, 2 };
    try testing.expectEqual(@as(usize, 26), df.columnBytes(mk(&[_]ColumnData{.{ .text = .{ .offsets = &offs, .bytes = "ab" } }}, 10), 0));
    try testing.expectEqual(@as(usize, 0), df.columnBytes(mk(&[_]ColumnData{.{ .text = .{ .offsets = &.{}, .bytes = "" } }}, 3), 0));
    const bx = [_]Value{ .{ .int = 1 }, .{ .int = 2 }, .{ .int = 3 } };
    try testing.expectEqual(2 * @sizeOf(Value), df.columnBytes(mk(&[_]ColumnData{.{ .boxed = &bx }}, 2), 0));
}

test "equals: null is not a value, a longer frame is not equal, different widths are not equal (mut 952, 955, 956)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const fn_ = try build(a, &.{.{ .name = "x", .type = .int }}, &.{&.{.null}});
    const gn = try build(a, &.{.{ .name = "x", .type = .int }}, &.{&.{.{ .int = 5 }}});
    try testing.expect(!df.equals(fn_, gn));
    const two = try build(a, &.{.{ .name = "x", .type = .int }}, &.{ &.{.{ .int = 1 }}, &.{.null} });
    const one = try build(a, &.{.{ .name = "x", .type = .int }}, &.{&.{.{ .int = 1 }}});
    try testing.expect(!df.equals(two, one));
    const wide = try build(a, &.{ .{ .name = "x", .type = .int }, .{ .name = "y", .type = .int } }, &.{&.{ .{ .int = 1 }, .{ .int = 1 } }});
    try testing.expect(!df.equals(wide, one));
}

test "transpose: names_from overrides a wrong-length names, decimals and ints give float, a 2^20-row frame is allowed (mut 964, 965, 967)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try build(a, &.{ .{ .name = "n", .type = .text }, .{ .name = "v", .type = .int } }, &.{
        &.{ .{ .text = "p" }, .{ .int = 1 } },
        &.{ .{ .text = "q" }, .{ .int = 2 } },
    });
    const t = try df.transpose(a, f, .{ .names_from = "n", .names = &.{"only"} });
    try testing.expectEqualStrings("p", t.columns[0].name);
    const g = try build(a, &.{ .{ .name = "d", .type = .decimal }, .{ .name = "i", .type = .int } }, &.{&.{ .{ .decimal = df.decimal_scale }, .{ .int = 1 } }});
    const tg = try df.transpose(a, g, .{});
    try testing.expectEqual(df.ColumnType.float, tg.columns[0].type);
    const wide: Frame = .{ .columns = &.{}, .data = &.{}, .len = 1 << 20 };
    const tw = try df.transpose(a, wide, .{});
    try testing.expectEqual(@as(usize, 1 << 20), tw.columns.len);
}

test "concat vertical: schemas are checked and the first frame's names must be unique (mut 976, 977, 979)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const x: Frame = .{ .columns = &.{ .{ .name = "a", .type = .int }, .{ .name = "b", .type = .int } }, .data = &.{}, .len = 0 };
    const y: Frame = .{ .columns = &.{.{ .name = "a", .type = .int }}, .data = &.{}, .len = 0 };
    const z: Frame = .{ .columns = &.{ .{ .name = "a", .type = .int }, .{ .name = "c", .type = .int } }, .data = &.{}, .len = 0 };
    try testing.expectError(error.SchemaMismatch, df.concat(a, &.{ x, y }, .vertical));
    try testing.expectError(error.SchemaMismatch, df.concat(a, &.{ x, z }, .vertical));
    const d: Frame = .{ .columns = &.{ .{ .name = "a", .type = .int }, .{ .name = "a", .type = .int } }, .data = &.{}, .len = 0 };
    try testing.expectError(error.DuplicateColumn, df.concat(a, &.{d}, .vertical));
}

// ── reshape ─────────────────────────────────────────────────────────────────

test "groupFilter: the group statistic skips missing cells (mut 1001)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const nan = std.math.nan(f64);
    const f = try build(a, &.{ .{ .name = "g", .type = .int }, .{ .name = "x", .type = .float } }, &.{
        &.{ .{ .int = 1 }, .{ .float = 1 } },
        &.{ .{ .int = 1 }, .{ .float = nan } },
        &.{ .{ .int = 1 }, .{ .float = nan } },
    });
    const r = try df.groupFilter(a, f, .{ .by = &.{"g"}, .agg = .{ .src = "x", .out = "c", .func = .count }, .op = .ge, .value = .{ .int = 2 } });
    try testing.expectEqual(@as(usize, 0), r.len);
}

test "joinWhere: NaN satisfies no comparison, not_null is refused, 2^24 cells are allowed (mut 1002, 1010, 1015)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const l = try build(a, &.{.{ .name = "x", .type = .float }}, &.{&.{.{ .float = std.math.nan(f64) }}});
    const r = try build(a, &.{.{ .name = "y", .type = .float }}, &.{&.{.{ .float = 1 }}});
    const j = try df.joinWhere(a, l, r, &.{.{ .left = "x", .op = .gt, .right = "y" }}, "_r");
    try testing.expectEqual(@as(usize, 0), j.len);
    try testing.expectError(error.BadArgument, df.joinWhere(a, l, r, &.{.{ .left = "x", .op = .not_null, .right = "y" }}, "_r"));
    const lv = try a.alloc(i64, 4096);
    @memset(lv, 1);
    const rv = try a.alloc(i64, 2048);
    @memset(rv, 1);
    const lf: Frame = .{ .columns = &.{.{ .name = "x", .type = .int }}, .data = &[_]ColumnData{.{ .int = .{ .values = lv } }}, .len = 4096 };
    const rf: Frame = .{ .columns = &.{.{ .name = "y", .type = .int }}, .data = &[_]ColumnData{.{ .int = .{ .values = rv } }}, .len = 2048 };
    const big = try df.joinWhere(a, lf, rf, &.{.{ .left = "x", .op = .eq, .right = "y" }}, "_r");
    try testing.expectEqual(@as(usize, 1 << 23), big.len);
}

test "mergeOrdered and mergeSorted: arguments, missing keys last, types must agree (mut 1016, 1018, 1024)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const l = try build(a, &.{ .{ .name = "k", .type = .int }, .{ .name = "v", .type = .int } }, &.{ &.{ .null, .{ .int = 1 } }, &.{ .{ .int = 1 }, .{ .int = 2 } } });
    const r = try build(a, &.{ .{ .name = "k", .type = .int }, .{ .name = "w", .type = .int } }, &.{&.{ .{ .int = 2 }, .{ .int = 3 } }});
    try testing.expectError(error.NoSuchColumn, df.mergeOrdered(a, l, r, .{ .on = &.{} }));
    const m = try df.mergeOrdered(a, l, r, .{ .on = &.{"k"} });
    try testing.expectEqual(@as(usize, 3), m.len);
    try testing.expect(isNull(m.cell(2, "k")));
    const lx = try build(a, &.{.{ .name = "x", .type = .int }}, &.{&.{.{ .int = 1 }}});
    const rx = try build(a, &.{.{ .name = "x", .type = .float }}, &.{&.{.{ .float = 1 }}});
    try testing.expectError(error.SchemaMismatch, df.mergeSorted(a, lx, rx, "x"));
}

test "pivotMany and pivotKeys: empty keys or values are refused, the row limit is checked first (mut 1025, 1032, 1033, 1034)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try build(a, &.{ .{ .name = "a", .type = .int }, .{ .name = "b", .type = .int }, .{ .name = "v", .type = .int } }, &.{&.{ .{ .int = 1 }, .{ .int = 1 }, .{ .int = 1 } }});
    try testing.expectError(error.NoSuchColumn, df.pivotMany(a, f, .{ .row_key = "a", .col_key = "b", .values = &.{} }));
    try testing.expectError(error.NoSuchColumn, df.pivotKeys(a, f, .{ .row_keys = &.{}, .col_keys = &.{"b"}, .values = &.{"v"} }));
    try testing.expectError(error.NoSuchColumn, df.pivotKeys(a, f, .{ .row_keys = &.{"a"}, .col_keys = &.{}, .values = &.{"v"} }));
    try testing.expectError(error.TooLarge, df.pivotKeys(a, huge, .{ .row_keys = &.{"a"}, .col_keys = &.{"b"}, .values = &.{"v"} }));
}

test "dummies: dates are encoded by default, drop_first on an empty column is safe, 2^24 cells are allowed, names must stay unique (mut 1040, 1044, 1046, 1051)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const fd = try build(a, &.{.{ .name = "d", .type = .date }}, &.{&.{.{ .text = "2024-01-01" }}});
    const rd = try df.dummies(a, fd, .{});
    try testing.expect(rd.columnIndex("d_2024-01-01") != null);
    const fn_ = try build(a, &.{.{ .name = "s", .type = .text }}, &.{ &.{.null}, &.{.null} });
    const rn = try df.dummies(a, fn_, .{ .drop_first = true });
    try testing.expectEqual(@as(usize, 0), rn.columns.len);
    const rows = try a.alloc([]const Value, 4096);
    for (rows, 0..) |*r, i| r.* = try a.dupe(Value, &.{.{ .text = try std.fmt.allocPrint(a, "s{d}", .{i}) }});
    const fb = try build(a, &.{.{ .name = "s", .type = .text }}, rows);
    const rb = try df.dummies(a, fb, .{});
    try testing.expectEqual(@as(usize, 4096), rb.columns.len);
    const fc = try build(a, &.{ .{ .name = "a", .type = .text }, .{ .name = "a_x", .type = .int } }, &.{&.{ .{ .text = "x" }, .{ .int = 1 } }});
    try testing.expectError(error.DuplicateColumn, df.dummies(a, fc, .{}));
}

test "combineFirst and update: row limits, arrays longer than their frame (mut 1052, 1053, 1057, 1059, 1062)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var fa = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    try testing.expectError(error.TooLarge, df.combineFirst(fa.allocator(), huge, empty));
    try testing.expectError(error.TooLarge, df.combineFirst(fa.allocator(), empty, huge));
    const cols = [_]Column{.{ .name = "x", .type = .int }};
    const f_long: Frame = .{ .columns = &cols, .data = &[_]ColumnData{.{ .int = .{ .values = &[_]i64{ 1, 99 } } }}, .len = 1 };
    const g2 = try build(a, &.{.{ .name = "x", .type = .int }}, &.{ &.{.{ .int = 5 }}, &.{.{ .int = 6 }} });
    const r1 = try df.combineFirst(a, f_long, g2);
    try testing.expectEqual(Value{ .int = 6 }, r1.cell(1, "x").?);
    const f2 = try build(a, &.{.{ .name = "x", .type = .int }}, &.{ &.{.null}, &.{.null} });
    const g_long: Frame = .{ .columns = &cols, .data = &[_]ColumnData{.{ .int = .{ .values = &[_]i64{ 5, 6, 7 } } }}, .len = 1 };
    const r2 = try df.combineFirst(a, f2, g_long);
    try testing.expectEqual(Value{ .int = 5 }, r2.cell(0, "x").?);
    try testing.expect(isNull(r2.cell(1, "x")));
    const f3 = try build(a, &.{.{ .name = "x", .type = .int }}, &.{ &.{.{ .int = 1 }}, &.{.{ .int = 2 }} });
    const u = try df.update(a, f3, g_long);
    try testing.expectEqual(Value{ .int = 5 }, u.cell(0, "x").?);
    try testing.expectEqual(Value{ .int = 2 }, u.cell(1, "x").?);
}

test "repeatRows: text counts are refused, the cap holds for a column-less frame and is exact (mut 1066, 1070, 1071)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const ft = try build(a, &.{.{ .name = "n", .type = .text }}, &.{&.{.{ .text = "a" }}});
    try testing.expectError(error.BadArgument, df.repeatRows(a, ft, .{ .by = "n" }));
    const one: Frame = .{ .columns = &.{}, .data = &.{}, .len = 1 };
    var fa = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 1 });
    try testing.expectError(error.TooLarge, df.repeatRows(fa.allocator(), one, .{ .times = 3_000_000_000 }));
    const fi = try build(a, &.{.{ .name = "x", .type = .int }}, &.{&.{.{ .int = 7 }}});
    const r = try df.repeatRows(a, fi, .{ .times = 1 << 24 });
    try testing.expectEqual(@as(usize, 1 << 24), r.len);
}

test "scatter: a position before -len is out of bounds (mut 1076)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try build(a, &.{.{ .name = "x", .type = .int }}, &.{ &.{.{ .int = 1 }}, &.{.{ .int = 2 }} });
    try testing.expectError(error.IndexOutOfBounds, df.scatter(a, f, .{ .col = "x", .idx = &.{-5}, .values = &.{.{ .int = 9 }} }));
}

test "matchToSchema and hashRows refuse duplicate names (mut 1086, 1089)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try build(a, &.{.{ .name = "h", .type = .int }}, &.{&.{.{ .int = 1 }}});
    try testing.expectError(error.DuplicateColumn, df.matchToSchema(a, f, &.{ .{ .name = "h", .type = .int }, .{ .name = "h", .type = .int } }, .{}));
    try testing.expectError(error.DuplicateColumn, df.hashRows(a, f, 0, "h"));
}

test "betweenTime: inclusive left and right, at_time, and instants before the epoch (mut 1092, 1093, 1095, 1096)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const h: i64 = 3_600_000_000;
    const f = try build(a, &.{.{ .name = "t", .type = .timestamp }}, &.{ &.{.{ .int = 9 * h }}, &.{.{ .int = 10 * h }}, &.{.{ .int = 11 * h }} });
    const left = try df.betweenTime(a, f, .{ .col = "t", .start = "09:00", .end = "11:00", .inclusive = .left });
    try testing.expectEqual(@as(usize, 2), left.len);
    try testing.expectEqual(Value{ .int = 9 * h }, left.cell(0, "t").?);
    const right = try df.betweenTime(a, f, .{ .col = "t", .start = "09:00", .end = "11:00", .inclusive = .right });
    try testing.expectEqual(@as(usize, 2), right.len);
    try testing.expectEqual(Value{ .int = 11 * h }, right.cell(1, "t").?);
    const at = try df.betweenTime(a, f, .{ .col = "t", .start = "10:00", .end = "10:00" });
    try testing.expectEqual(@as(usize, 1), at.len);
    const before = try build(a, &.{.{ .name = "t", .type = .timestamp }}, &.{&.{.{ .int = -h }}});
    const rb = try df.betweenTime(a, before, .{ .col = "t", .start = "22:00", .end = "23:30" });
    try testing.expectEqual(@as(usize, 1), rb.len);
}

test "aggregate over typed arrays shorter than the frame reads the missing rows as null (mut 603, 607)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const gs = [_]i64{ 1, 1, 1 };
    const fs = [_]f64{ 1, 2 };
    const ds = [_]i128{ df.decimal_scale, 2 * df.decimal_scale };
    const ff: Frame = .{
        .columns = &.{ .{ .name = "g", .type = .int }, .{ .name = "x", .type = .float } },
        .data = &[_]ColumnData{ .{ .int = .{ .values = &gs } }, .{ .float = .{ .values = &fs } } },
        .len = 3,
    };
    const rf = try df.aggregate(a, ff, .{ .group_by = &.{"g"}, .aggs = &.{.{ .src = "x", .out = "s", .func = .sum }} });
    try testing.expectEqual(Value{ .float = 3 }, rf.cell(0, "s").?);
    const fd: Frame = .{
        .columns = &.{ .{ .name = "g", .type = .int }, .{ .name = "x", .type = .decimal } },
        .data = &[_]ColumnData{ .{ .int = .{ .values = &gs } }, .{ .decimal = .{ .values = &ds } } },
        .len = 3,
    };
    const rd = try df.aggregate(a, fd, .{ .group_by = &.{"g"}, .aggs = &.{.{ .src = "x", .out = "s", .func = .sum }} });
    try testing.expectEqual(Value{ .float = 3 }, rd.cell(0, "s").?);
}

test "sort: missing = last places the cells past a short int array last (mut 724)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const vals = [_]i64{ 5, -3 };
    const f: Frame = .{ .columns = &.{.{ .name = "x", .type = .int }}, .data = &[_]ColumnData{.{ .int = .{ .values = &vals } }}, .len = 4 };
    const r = try df.sort(a, f, .{ .key = "x", .missing = .last });
    try testing.expectEqual(Value{ .int = -3 }, r.cell(0, "x").?);
    try testing.expectEqual(Value{ .int = 5 }, r.cell(1, "x").?);
    try testing.expect(isNull(r.cell(2, "x")));
}
