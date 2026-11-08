// SPDX-License-Identifier: MIT
//! Time zones in `Expr`: `to_local` (polars `convert_time_zone`, pandas `tz_convert`)
//! and `from_local` (polars `replace_time_zone`, pandas `tz_localize`) over the sibling
//! `tz` module. Europe/Prague 2024: the clocks went forward on 31 March at 02:00 (gap
//! 02:00-03:00) and back on 27 October at 03:00 (02:00-03:00 shown twice).

const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const st = @import("structure_test.zig");
const Value = df.Value;
const Expr = df.Expr;

const X: Expr = .{ .col = "x" };
const s_us: i64 = 1_000_000;

fn run(a: std.mem.Allocator, x: Value, e: Expr) !Value {
    const f = try st.mk(a, &.{.{ .name = "x", .type = .timestamp }}, &.{&.{x}});
    const g = try df.mutate(a, f, &.{.{ .out = "out", .expr = e }});
    return g.cell(0, "out").?;
}

fn expectV(want: Value, got: Value) !void {
    if (!st.same(got, want)) {
        std.debug.print("got {any}, want {any}\n", .{ got, want });
        return error.TestUnexpectedResult;
    }
}

fn txt(t: []const u8) Value {
    return .{ .text = t };
}

test "to_local: winter and summer offsets, int and text shapes, a date and null give null" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const winter: i64 = 1705320000; // 2024-01-15T12:00:00Z
    const summer: i64 = 1721044800; // 2024-07-15T12:00:00Z
    const prague: Expr = .{ .to_local = .{ .x = &X, .zone = "Europe/Prague" } };
    try expectV(.{ .int = (winter + 3600) * s_us }, try run(a, .{ .int = winter * s_us }, prague));
    try expectV(.{ .int = (summer + 7200) * s_us + 250 }, try run(a, .{ .int = summer * s_us + 250 }, prague));
    try expectV(txt("2024-07-15T14:00:00"), try run(a, txt("2024-07-15T12:00:00Z"), prague));
    try expectV(txt("2024-07-15T08:00:00.5"), try run(a, txt("2024-07-15T12:00:00.5Z"), .{ .to_local = .{ .x = &X, .zone = "America/New_York" } }));
    try expectV(.null, try run(a, txt("2024-07-15"), prague));
    try expectV(.null, try run(a, .null, prague));
    try testing.expectError(error.BadExpr, run(a, .{ .int = 0 }, .{ .to_local = .{ .x = &X, .zone = "Europe/Atlantis" } }));
}

test "from_local: a gap and a fold under each policy" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const P = "Europe/Prague";
    // 02:30 on 31 March does not exist: with the offset after the jump (+2) it is
    // 00:30Z, with the one before (+1) 01:30Z (= 03:30 CEST, "moved forward").
    const gap = txt("2024-03-31T02:30:00");
    try expectV(txt("2024-03-31T01:30:00Z"), try run(a, gap, .{ .from_local = .{ .x = &X, .zone = P } }));
    try expectV(txt("2024-03-31T00:30:00Z"), try run(a, gap, .{ .from_local = .{ .x = &X, .zone = P, .policy = .earlier } }));
    try expectV(txt("2024-03-31T01:30:00Z"), try run(a, gap, .{ .from_local = .{ .x = &X, .zone = P, .policy = .later } }));
    try expectV(.null, try run(a, gap, .{ .from_local = .{ .x = &X, .zone = P, .policy = .null } }));
    // 02:30 on 27 October happened twice: first in CEST (00:30Z), then in CET (01:30Z).
    const fold = txt("2024-10-27T02:30:00");
    try expectV(txt("2024-10-27T00:30:00Z"), try run(a, fold, .{ .from_local = .{ .x = &X, .zone = P } }));
    try expectV(txt("2024-10-27T00:30:00Z"), try run(a, fold, .{ .from_local = .{ .x = &X, .zone = P, .policy = .earlier } }));
    try expectV(txt("2024-10-27T01:30:00Z"), try run(a, fold, .{ .from_local = .{ .x = &X, .zone = P, .policy = .later } }));
    try expectV(.null, try run(a, fold, .{ .from_local = .{ .x = &X, .zone = P, .policy = .null } }));
}

test "from_local undoes to_local away from folds; extreme instants are null, not a panic" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const zones = [_][]const u8{ "Europe/Prague", "America/New_York", "Asia/Kolkata", "Pacific/Chatham", "UTC" };
    var t: i64 = -2_000_000_000;
    while (t < 4_000_000_000) : (t += 86_399_937) {
        for (zones) |z| {
            const local = try run(a, .{ .int = t * s_us + 17 }, .{ .to_local = .{ .x = &X, .zone = z } });
            const back = try run(a, local, .{ .from_local = .{ .x = &X, .zone = z, .policy = .earlier } });
            const later = try run(a, local, .{ .from_local = .{ .x = &X, .zone = z, .policy = .later } });
            // A fold time maps back to one of its two instants; every other time exactly.
            try testing.expect(st.same(back, .{ .int = t * s_us + 17 }) or st.same(later, .{ .int = t * s_us + 17 }));
        }
    }
    for ([_]i64{ std.math.maxInt(i64), std.math.minInt(i64), std.math.maxInt(i64) - 1 }) |x| {
        _ = try run(a, .{ .int = x }, .{ .to_local = .{ .x = &X, .zone = "Pacific/Kiritimati" } });
        _ = try run(a, .{ .int = x }, .{ .from_local = .{ .x = &X, .zone = "Pacific/Kiritimati" } });
        _ = try run(a, .{ .int = x }, .{ .from_local = .{ .x = &X, .zone = "America/Adak" } });
    }
}
