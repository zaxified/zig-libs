// SPDX-License-Identifier: MIT

//! The card's encoding lead (`**Ahead:**` in SPEC.md), pinned. On a truncated
//! but otherwise valid prefix every measured Go writer of JSON log lines --
//! `encoding/json`, `log/slog`'s JSONHandler, rs/zerolog v1.35.1, uber-go/zap
//! v1.28.0 and phuslu/log v1.0.138 -- puts one U+FFFD per BYTE in place of the
//! sequence; Unicode 16 §3.9 (and the WHATWG Encoding Standard, normatively)
//! ask for one per maximal subpart, which Python's
//! `bytes.decode("utf-8", "replace")` gives and this module writes.
//! Measured 2026-10-25 by `tools/go_utf8_probe` over the cases below; the Go
//! counts are recorded in each case. The rows where the two policies agree are
//! here too, so the lead is not read as "more U+FFFD is wrong".

const std = @import("std");
const testing = std.testing;
const accesslog = @import("root.zig");

const Case = struct {
    bytes: []const u8,
    /// Python 3.14 `decode("utf-8", "replace")` (= Unicode §3.9) over "a" ++ bytes ++ "z".
    want: usize,
    /// What all five Go writers answered.
    go: usize,
};

const cases = [_]Case{
    .{ .bytes = "\xe1\x80", .want = 1, .go = 2 },
    .{ .bytes = "\xf0\x9f\x98", .want = 1, .go = 3 },
    .{ .bytes = "\xf1\x80\x80", .want = 1, .go = 3 },
    .{ .bytes = "\xe2\x82A", .want = 1, .go = 2 },
    .{ .bytes = "\xed\xa0\x80", .want = 3, .go = 3 },
    .{ .bytes = "\xc0\xaf", .want = 2, .go = 2 },
    .{ .bytes = "\xe0\x80\xaf", .want = 3, .go = 3 },
    .{ .bytes = "\xf4\x90\x80\x80", .want = 4, .go = 4 },
    .{ .bytes = "\x80\x80", .want = 2, .go = 2 },
    .{ .bytes = "\xf5\xff", .want = 2, .go = 2 },
};

test "lead: one U+FFFD per maximal subpart where five Go JSON loggers write one per byte" {
    var differs: usize = 0;
    for (cases) |c| {
        var target_buf: [16]u8 = undefined;
        const target = try std.fmt.bufPrint(&target_buf, "a{s}z", .{c.bytes});
        var out: std.Io.Writer.Allocating = .init(testing.allocator);
        defer out.deinit();
        try accesslog.writeJsonLines(.{ .timestamp_ns = 0, .method = "GET", .target = target, .status = 200 }, &out.writer);
        const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, out.written(), .{});
        defer parsed.deinit();
        const got = parsed.value.object.get("target").?.string;
        try testing.expect(std.mem.startsWith(u8, got, "a") and std.mem.endsWith(u8, got, "z"));
        try testing.expectEqual(c.want, std.mem.count(u8, got, "\u{FFFD}"));
        if (c.go != c.want) differs += 1;
    }
    // The truncated-prefix rows: the ones the lead is about.
    try testing.expectEqual(@as(usize, 4), differs);
}
