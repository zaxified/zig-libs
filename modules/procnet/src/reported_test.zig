// SPDX-License-Identifier: MIT

//! Test support for the `read*Reporting` twins (`arp.zig`, `routes.zig`,
//! `counters.zig`): imported only from their test blocks, never from
//! `root.zig`, so it is not part of the module's API.

const std = @import("std");
const testing = std.testing;
const procnet = @import("root.zig");

/// Writes `text` (a fixture ending in a newline)
/// to a temp file and checks the truncation plumbing of `readFrom(gpa, io,
/// path, limit)` — a limit inside the last row yields `truncated` and exactly
/// one row fewer, a roomy limit yields the whole table and no flag.
pub fn expectReportedCut(comptime T: type, comptime readFrom: anytype, text: []const u8) !void {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var f = try tmp.dir.createFile(io, "t.txt", .{});
        defer f.close(io);
        var wbuf: [256]u8 = undefined;
        var w = f.writer(io, &wbuf);
        try w.interface.writeAll(text);
        try w.interface.flush();
    }
    var path_buf: [128]u8 = undefined;
    const path = try std.mem.print(&path_buf, ".zig-cache/tmp/{s}/t.txt", .{&tmp.sub_path});

    const whole: procnet.Reported(T) = try readFrom(testing.allocator, io, path, text.len + 64);
    defer testing.allocator.free(whole.entries);
    try testing.expect(!whole.truncated);
    try testing.expect(whole.entries.len > 1);

    const cut: procnet.Reported(T) = try readFrom(testing.allocator, io, path, text.len - 5);
    defer testing.allocator.free(cut.entries);
    try testing.expect(cut.truncated);
    try testing.expectEqual(whole.entries.len - 1, cut.entries.len);
}
