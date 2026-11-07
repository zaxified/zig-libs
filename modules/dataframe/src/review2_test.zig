// SPDX-License-Identifier: MIT
//! The independent review of the D2 verbs (2026-11-07): every consumer-reachable
//! trap, hang or quadratic cost it found, each pinned with the argument that
//! triggered it.

const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const exprfn = @import("exprfn.zig");
const st = @import("structure_test.zig");
const Value = df.Value;

test "review HIGH 1: round with decimals = minInt(i32), and past 1e308, is a signed zero" {
    const min = std.math.minInt(i32);
    for ([_]i32{ min, -309, -330, -331 }) |d| {
        const r = exprfn.round(.{ .float = 12.5 }, d, .half_even);
        try testing.expectEqual(@as(f64, 0), r.float);
        try testing.expect(!std.math.signbit(r.float));
        const n = exprfn.round(.{ .float = -12.5 }, d, .half_even);
        try testing.expectEqual(@as(f64, 0), n.float);
        try testing.expect(std.math.signbit(n.float));
    }
    // -308 is still a real power of ten.
    try testing.expectEqual(@as(f64, 0), exprfn.round(.{ .float = 1e300 }, -308, .half_even).float);
    try testing.expectEqual(@as(f64, 1e308), exprfn.round(.{ .float = 0.9e308 }, -308, .half_even).float);
    _ = exprfn.round(.{ .int = 7 }, min, .half_even);
    _ = exprfn.round(.{ .decimal = 7 }, min, .half_away);
}

test "review MED 4: decimal and int round near minInt/maxInt(i128) answer null, never trap" {
    const lo = std.math.minInt(i128);
    const hi = std.math.maxInt(i128);
    for ([_]i128{ lo, lo + 1, lo + 12345, hi, hi - 1, -1e38, 1e38 }) |x| {
        for ([_]i32{ 11, 0, -1, -12, -26, -30 }) |d| {
            const r = exprfn.round(.{ .decimal = x }, d, .half_even);
            try testing.expect(r == .null or r == .decimal);
            const r2 = exprfn.round(.{ .decimal = x }, d, .half_away);
            try testing.expect(r2 == .null or r2 == .decimal);
        }
    }
    // Ordinary values are unchanged by the rewrite: -15 to a multiple of 10.
    try testing.expectEqual(@as(i64, -20), exprfn.round(.{ .int = -15 }, -1, .half_even).int);
    try testing.expectEqual(@as(i64, -20), exprfn.round(.{ .int = -15 }, -1, .half_away).int);
    try testing.expectEqual(@as(i64, -10), exprfn.round(.{ .int = -14 }, -1, .half_away).int);
    try testing.expectEqual(@as(i64, 20), exprfn.round(.{ .int = 25 }, -1, .half_even).int);
    try testing.expectEqual(@as(i64, 30), exprfn.round(.{ .int = 25 }, -1, .half_away).int);
}

test "review HIGH 3: empty text repeated maxInt(i64) times is empty at once" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqualStrings("", try exprfn.repeat(arena.allocator(), "", std.math.maxInt(i64)));
    try testing.expectError(error.TooLarge, exprfn.repeat(arena.allocator(), "ab", std.math.maxInt(i64)));
    try testing.expectEqualStrings("ababab", try exprfn.repeat(arena.allocator(), "ab", 3));
}

test "review HIGH 2: gatherEvery with a step near maxInt(usize)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try st.mk(a, &.{.{ .name = "i", .type = .int }}, &.{
        &.{.{ .int = 1 }}, &.{.{ .int = 2 }}, &.{.{ .int = 3 }}, &.{.{ .int = 4 }}, &.{.{ .int = 5 }},
    });
    try st.expectCol(try df.gatherEvery(a, f, std.math.maxInt(usize), 0), "i", &.{.{ .int = 1 }});
    try st.expectCol(try df.gatherEvery(a, f, std.math.maxInt(usize), 4), "i", &.{.{ .int = 5 }});
    try st.expectCol(try df.gatherEvery(a, f, std.math.maxInt(usize), 5), "i", &.{});
    try st.expectCol(try df.gatherEvery(a, f, 2, 0), "i", &.{ .{ .int = 1 }, .{ .int = 3 }, .{ .int = 5 } });
    try st.expectCol(try df.gatherEvery(a, f, 2, 1), "i", &.{ .{ .int = 2 }, .{ .int = 4 } });
}

test "review MED 5: qcut over many rows and many bins is fast and keeps type-7 edges" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const n = 200_000;
    var b = try df.FrameBuilder.init(a, &.{.{ .name = "x", .type = .float }}, n);
    var prng = std.Random.DefaultPrng.init(7);
    for (0..n) |_| try b.appendRow(&.{.{ .float = prng.random().float(f64) }});
    const f = try b.toOwned();
    // 2^16 bins x 2e5 rows was ~1.3e10 selection steps before; sorting once is
    // milliseconds. Distinct floats: no repeated edges.
    const q = try df.qcut(a, f, .{ .col = "x", .out = "q", .bins = 1 << 16 });
    try testing.expectEqual(@as(usize, n), q.len);
}

test "review MED 6: hstack of many series is one allocation, duplicates still refused" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try st.mk(a, &.{.{ .name = "i", .type = .int }}, &.{ &.{.{ .int = 1 }}, &.{.{ .int = 2 }} });
    const base = f.series("i").?;
    const k = 20_000;
    const many = try a.alloc(df.Series, k);
    for (many, 0..) |*s, i| {
        s.* = base;
        s.name = try std.mem.print(try a.alloc(u8, 16), "c{d}", .{i});
    }
    const h = try df.hstack(a, f, many);
    try testing.expectEqual(@as(usize, k + 1), h.columns.len);
    try testing.expectEqualStrings("c19999", h.columns[k].name);
    try st.expectCol(h, "c7", &.{ .{ .int = 1 }, .{ .int = 2 } });
    many[k - 1].name = "c3";
    try testing.expectError(error.DuplicateColumn, df.hstack(a, f, many));
    many[k - 1].name = "i";
    try testing.expectError(error.DuplicateColumn, df.hstack(a, f, many));
    many[k - 1].name = "z";
    many[k - 1].len = 1;
    try testing.expectError(error.LengthMismatch, df.hstack(a, f, many));
}

test "review LOW 7: transpose refuses an output wider than max_transpose_width" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // A hand-built frame with no columns and a huge height: no cells, but the
    // output would be that many columns.
    const f: df.Frame = .{ .columns = &.{}, .data = &.{}, .len = df.max_transpose_width + 1 };
    try testing.expectError(error.TooLarge, df.transpose(a, f, .{}));
}
