// SPDX-License-Identifier: MIT
//! Whole-module mutation tests (2026-11-25): the UTF-8 reading of `unit = .codepoint`
//! against `osaDistanceCodepoints` (std.unicode) over every sequence shape, the
//! reference helper's size limits and invalid-byte symbols, an empty result slice
//! and the depth boundary of the walk.

const std = @import("std");
const testing = std.testing;
const trie = @import("trie");
const root = @import("root.zig");

const max_ref_len: usize = 4096; // distance.zig's limit

const fragments = [_][]const u8{
    "a", "b", "\xC3\xA9", // é
    "\xC3\x80", "\xC3\xBF", // the two ends of the continuation range
    "\xE2\x82\xAC", // €
    "\xF0\x9F\x98\x80", // U+1F600
    "\xE0\x80", "\xE0\xA0\x80", // overlong 3-byte lead / the smallest valid one
    "\xED\xA0\x80", // surrogate
    "\xED\x9F\xBF", // the largest scalar below the surrogates
    "\xF0\x80\x80\x80", "\xF0\x90\x80\x80", // overlong 4-byte lead / the smallest valid one
    "\xF4\x8F\xBF\xBF", "\xF4\x90\x80\x80", // U+10FFFF / above it
    "\xC0\x80", "\xC1\xBF", // overlong 2-byte leads
    "\xF5\x80\x80\x80", // above F4
    "\x80", "\xBF", "\xFF", // stray continuation / invalid bytes
    "\xF0\x9F\x98", "\xE2\x82", "\xC3", // truncated sequences of 3, 2 and 1 bytes
};

const OracleHit = struct { distance: u32, value: u32, key: []const u8 };

fn before(_: void, a: OracleHit, b: OracleHit) bool {
    if (a.distance != b.distance) return a.distance < b.distance;
    if (a.value != b.value) return a.value > b.value;
    return std.mem.lessThan(u8, a.key, b.key);
}

test "mutation 2026-11-25: unit = .codepoint reads every UTF-8 shape like std.unicode (differential, both trie formats)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var seen = std.StringHashMap(void).init(arena);
    var pairs: std.ArrayList(trie.Pair) = .empty;
    const add = struct {
        fn f(a: std.mem.Allocator, s: *std.StringHashMap(void), p: *std.ArrayList(trie.Pair), key: []const u8) !void {
            if (s.contains(key)) return;
            try s.put(key, {});
            try p.append(a, .{ .key = key, .value = @intCast(p.items.len + 1) });
        }
    }.f;
    for (fragments) |a| {
        try add(arena, &seen, &pairs, a);
        for (fragments) |b| try add(arena, &seen, &pairs, try std.mem.concat(arena, u8, &.{ a, b }));
    }
    const n = pairs.items.len;

    for ([_]trie.FreezeOptions{ .v1, .{ .v2 = .{} } }) |fmt| {
        const buf = try trie.freezeFromPairsWith(testing.allocator, testing.allocator, pairs.items, fmt);
        defer testing.allocator.free(buf);
        const f = try root.Frozen.load(buf);
        const results = try arena.alloc(root.Match, n);
        const kb = try arena.alloc(u8, n * 16);
        for ([_]u8{ 1, 2 }) |k| {
            for (pairs.items) |q| {
                var want: std.ArrayList(OracleHit) = .empty;
                for (pairs.items) |p| {
                    const d = try root.osaDistanceCodepoints(q.key, p.key);
                    if (d <= k) try want.append(arena, .{ .distance = d, .value = p.value, .key = p.key });
                }
                std.mem.sort(OracleHit, want.items, {}, before);
                const r = try f.search(q.key, k, results, kb, .{ .unit = .codepoint, .max_visited = 0 });
                try testing.expectEqual(want.items.len, r.items.len);
                for (want.items, r.items) |w, got| {
                    try testing.expectEqual(w.distance, got.distance);
                    try testing.expectEqual(w.value, got.value);
                    try testing.expectEqualStrings(w.key, got.key);
                }
            }
        }
    }
}

test "mutation 2026-11-25: osaDistanceCodepoints: the 4096-byte limit of each input, and an invalid byte never equals a scalar value" {
    var a: [max_ref_len]u8 = undefined;
    @memset(&a, 'a');
    try testing.expectEqual(@as(u32, 0), try root.osaDistanceCodepoints(&a, &a));
    var big: [max_ref_len + 1]u8 = undefined;
    @memset(&big, 'a');
    try testing.expectError(error.TooLong, root.osaDistanceCodepoints(&big, "a"));
    try testing.expectError(error.TooLong, root.osaDistanceCodepoints("a", &big));
    // The byte 0x80 is an invalid symbol, never the scalar U+0180 (C6 80): a base of 0x100 would collide.
    try testing.expectEqual(@as(u32, 1), try root.osaDistanceCodepoints("\x80", "\xC6\x80"));
}

test "mutation 2026-11-25: an empty results slice answers complete with no items, even when keys match" {
    const buf = try trie.freezeFromPairs(testing.allocator, testing.allocator, &.{.{ .key = "praha", .value = 1 }});
    defer testing.allocator.free(buf);
    const f = try root.Frozen.load(buf);
    var results: [0]root.Match = .{};
    var kb: [0]u8 = .{};
    const r = try f.search("praha", 1, &results, &kb, .{});
    try testing.expectEqual(@as(usize, 0), r.items.len);
    try testing.expectEqual(root.SearchStatus.complete, r.status);
    const p = try f.searchPrefix("pra", 1, &results, &kb, .{});
    try testing.expectEqual(@as(usize, 0), p.items.len);
}

test "mutation 2026-11-25: a key exactly max_depth deep is walked, one byte more is KeyTooLong" {
    var key: [root.max_depth + 1]u8 = undefined;
    @memset(&key, 'a');
    var results: [1]root.Match = undefined;
    var kb: [root.max_depth + 1]u8 = undefined;
    {
        const buf = try trie.freezeFromPairsWith(testing.allocator, testing.allocator, &.{.{ .key = key[0..root.max_depth], .value = 7 }}, .v1);
        defer testing.allocator.free(buf);
        const f = try root.Frozen.load(buf);
        const r = try f.searchPrefix("aaaa", 0, &results, &kb, .{ .max_visited = 0 });
        try testing.expectEqual(@as(usize, 1), r.items.len);
        try testing.expectEqual(@as(usize, root.max_depth), r.items[0].key.len);
    }
    {
        const buf = try trie.freezeFromPairsWith(testing.allocator, testing.allocator, &.{.{ .key = &key, .value = 7 }}, .v1);
        defer testing.allocator.free(buf);
        const f = try root.Frozen.load(buf);
        try testing.expectError(error.KeyTooLong, f.searchPrefix("aaaa", 0, &results, &kb, .{ .max_visited = 0 }));
    }
}
