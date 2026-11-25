// SPDX-License-Identifier: MIT
//! Tests of the no-panic sweep (2026-11-25): every finding `YS-n` of
//! the sweep has the test that kills its mutant, named "(sweep YS-n)".
//! Hostile-input costs are pinned on deterministic counters or on outcomes a
//! quadratic implementation cannot reach, with one coarse wall-clock bound
//! where neither exists (the bound is >20x above the measured time).

const std = @import("std");
const yaml = @import("root.zig");
const scanner = @import("scanner.zig");
const testing = std.testing;

fn nowNs() i96 {
    return std.Io.Clock.awake.now(testing.io).nanoseconds;
}

fn elapsedMs(t0: i96) i96 {
    return @divTrunc(nowNs() - t0, 1_000_000);
}

test "many distinct %TAG handles: lookup and duplicate check are not O(directives) (sweep YS-1)" {
    const gpa = testing.allocator;
    var src: std.ArrayList(u8) = .empty;
    defer src.deinit(gpa);
    const n = 12_000;
    for (0..n) |i| try src.print(gpa, "%TAG !h{d}! t:{d}/\n", .{ i, i });
    try src.appendSlice(gpa, "---\n");
    for (0..n) |i| try src.print(gpa, "- !h{d}!x v\n", .{i});
    const t0 = nowNs();
    const d = try yaml.compose(gpa, src.items, .{});
    defer d.deinit();
    try testing.expectEqual(@as(usize, n), d.root.sequence.len);
    // Measured 80 ms fixed (Debug); the list took ~10 s.
    try testing.expect(elapsedMs(t0) < 3000);
}

test "a tab-only line under a deep indent is scanned in linear time (sweep YS-3)" {
    const gpa = testing.allocator;
    var src: std.ArrayList(u8) = .empty;
    defer src.deinit(gpa);
    const n = 100_000;
    try src.appendNTimes(gpa, ' ', n);
    try src.appendSlice(gpa, "k: v\n");
    try src.appendNTimes(gpa, '\t', n);
    try src.appendSlice(gpa, "\n");
    try src.appendNTimes(gpa, ' ', n);
    try src.appendSlice(gpa, "j: w\n");
    const t0 = nowNs();
    const d = try yaml.compose(gpa, src.items, .{});
    defer d.deinit();
    try testing.expectEqual(@as(usize, 2), d.root.mapping.len);
    try testing.expect(elapsedMs(t0) < 3000);
}

test "thousands of sequence keys in one mapping compose within the default budget (sweep YS-4)" {
    const gpa = testing.allocator;
    var src: std.ArrayList(u8) = .empty;
    defer src.deinit(gpa);
    for (0..3000) |i| try src.print(gpa, "? [{d}]\n: 1\n", .{i});
    const d = try yaml.compose(gpa, src.items, .{});
    defer d.deinit();
    try testing.expectEqual(@as(usize, 3000), d.root.mapping.len);
}

test "collection keys that are equal are still duplicates, including 0.0 and -0.0 (sweep YS-4)" {
    const gpa = testing.allocator;
    try testing.expectError(error.DuplicateKey, yaml.compose(gpa, "? [1, {a: [x]}]\n: 1\n? [1, {a: [x]}]\n: 2\n", .{}));
    try testing.expectError(error.DuplicateKey, yaml.compose(gpa, "? [0.0]\n: 1\n? [-0.0]\n: 2\n", .{}));
    try testing.expectError(error.DuplicateKey, yaml.compose(gpa, "? {a: 1}\n: 1\n? {a: 1}\n: 2\n", .{}));
    // Same shape, different content: not duplicates (int vs float, order, length).
    const d = try yaml.compose(gpa, "? [1]\n: a\n? [1.0]\n: b\n? [1, 2]\n: c\n? [2, 1]\n: d\n? {a: 1}\n: e\n? {a: 2}\n: f\n", .{});
    defer d.deinit();
    try testing.expectEqual(@as(usize, 6), d.root.mapping.len);
}

test "a deeply nested flow collection costs O(possible keys) per token, not O(depth) (sweep YS-5)" {
    const gpa = testing.allocator;
    var src: std.ArrayList(u8) = .empty;
    defer src.deinit(gpa);
    try src.appendNTimes(gpa, '[', 1000);
    for (0..50_000) |_| try src.appendSlice(gpa, "a,");
    try src.appendNTimes(gpa, ']', 1000);
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    var s = scanner.Scanner.init(arena.allocator(), src.items);
    while ((try s.next()).kind != .stream_end) {}
    // 1000 openings see up to 1000 fresh keys (~5e5 probes in all); the rest is
    // O(1) per token. Walking every level would be ~1000 * 100 000 = 1e8.
    try testing.expect(s.key_probes < 2_000_000);
}

test "typed: an int too large for a narrow float type is Overflow, not a trap (sweep clean-check)" {
    const typed = yaml.typed;
    try testing.expectError(error.Overflow, typed.fromValue(f16, testing.allocator, .{ .int = 1_000_000_000_000_000_000 }, .{}));
    try testing.expectError(error.Overflow, typed.fromValue(f32, testing.allocator, .{ .float = 1e300 }, .{}));
    try testing.expectEqual(@as(f16, 1024), try typed.fromValue(f16, testing.allocator, .{ .int = 1024 }, .{}));
}

test "a long %TAG prefix cannot be amplified through a bare Parser (sweep YS-8)" {
    const gpa = testing.allocator;
    var src: std.ArrayList(u8) = .empty;
    defer src.deinit(gpa);
    try src.appendSlice(gpa, "%TAG !e! ");
    try src.appendNTimes(gpa, 'p', 100_000);
    try src.appendSlice(gpa, "\n---\n");
    for (0..2000) |_| try src.appendSlice(gpa, "- !e!a x\n");
    var p = yaml.Parser.init(gpa, src.items);
    defer p.deinit();
    var tag_bytes: usize = 0;
    const err = while (true) {
        const ev = p.next() catch |e| break e;
        const e = ev orelse return error.TestUnexpectedResult;
        switch (e) {
            .scalar => |s| tag_bytes += if (s.tag) |t| t.len else 0,
            else => {},
        }
    };
    try testing.expectEqual(error.InvalidYaml, err);
    try testing.expectEqualStrings("tag expansion over budget", p.problem);
    try testing.expect(tag_bytes < 16 * src.items.len);

    // An ordinary document with a custom handle used many times still parses.
    var ok: std.ArrayList(u8) = .empty;
    defer ok.deinit(gpa);
    try ok.appendSlice(gpa, "%TAG !e! tag:example.com,2000:app/\n---\n");
    for (0..2000) |_| try ok.appendSlice(gpa, "- !e!foo bar\n");
    const d = try yaml.compose(gpa, ok.items, .{});
    defer d.deinit();
    try testing.expectEqual(@as(usize, 2000), d.root.sequence.len);
}
