// SPDX-License-Identifier: MIT
//! Deflate64 (ZIP method 9): archives 7-Zip wrote (`tools/deflate64_fixtures.sh`) decode to
//! their content, the decoder agrees with `std.compress.flate` on plain Deflate streams
//! (which share every code but length 285 and the two far distance codes), and damaged
//! input ends in an error, never a panic.

const std = @import("std");
const testing = std.testing;
const zs = @import("root.zig");
const d64 = @import("deflate64.zig");

const fixture = @embedFile("testdata/deflate64.zip");

fn lcg(buf: []u8, seed: u32) void {
    var x: u32 = seed;
    for (buf) |*b| {
        x = (x *% 1103515245 +% 12345) & 0x7fffffff;
        b.* = @truncate(x >> 16);
    }
}

fn readAll(a: std.mem.Allocator, archive: *zs.Archive, e: *const zs.Entry) ![]u8 {
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var er: zs.EntryReader = undefined;
    try er.init(archive, e, &window);
    defer er.deinit();
    var out: std.Io.Writer.Allocating = .init(a);
    errdefer out.deinit();
    _ = try er.reader().streamRemaining(&out.writer);
    return out.toOwnedSlice();
}

test "7-Zip Deflate64 archive: far distances, long matches, fixed and dynamic blocks decode to the content" {
    const a = testing.allocator;
    var ms: zs.MemorySource = .{ .bytes = fixture };
    var archive: zs.Archive = undefined;
    try archive.initSource(a, ms.source(), .{});
    defer archive.deinit();
    try testing.expectEqual(@as(usize, 5), archive.entries.items.len);

    // far.bin: a 40000-byte block twice (distance 40000), 70000 zeros (one match of 65538 at most), the block's head, a tail.
    const far = archive.find("far.bin").?;
    try testing.expectEqual(@as(u16, 9), far.method());
    const block = try a.alloc(u8, 40000);
    defer a.free(block);
    lcg(block, 12345);
    var want: std.ArrayList(u8) = .empty;
    defer want.deinit(a);
    try want.appendSlice(a, block);
    try want.appendSlice(a, block);
    try want.appendNTimes(a, 0, 70000);
    try want.appendSlice(a, block[0..5000]);
    try want.appendSlice(a, "tail\n");
    const got = try readAll(a, &archive, far);
    defer a.free(got);
    try testing.expectEqualSlices(u8, want.items, got);

    for ([_][]const u8{ "text.txt", "small.txt" }) |name| {
        const e = archive.find(name).?;
        try testing.expectEqual(@as(u16, 9), e.method());
        const g = try readAll(a, &archive, e); // the CRC-32 is checked at the end
        defer a.free(g);
        try testing.expectEqual(@as(usize, @intCast(e.uncompressed_size)), g.len);
    }
    const small = try readAll(a, &archive, archive.find("small.txt").?);
    defer a.free(small);
    try testing.expectEqualStrings("abcabcabcabcabcabc hello hello hello\n", small);
    const text = try readAll(a, &archive, archive.find("text.txt").?);
    defer a.free(text);
    try testing.expect(std.mem.startsWith(u8, text, "line 0: Pr"));
    try testing.expectEqual(@as(?zs.Archive.Problem, null), try archive.verify(.{}));
}

fn inflateAll(a: std.mem.Allocator, comp: []const u8) ![]u8 {
    var in: std.Io.Reader = .fixed(comp);
    const st = try a.create(d64.Inflate);
    defer a.destroy(st);
    st.init(&in);
    var out: std.Io.Writer.Allocating = .init(a);
    errdefer out.deinit();
    _ = try st.reader.streamRemaining(&out.writer);
    return out.toOwnedSlice();
}

test "plain Deflate streams (no 258-byte match, distances under 32768) decode the same as std" {
    const a = testing.allocator;
    var data: [20000]u8 = undefined;
    lcg(&data, 7);
    for (&data, 0..) |*b, i| b.* = if (i % 3 == 0) b.* & 0x0f else b.* | 0x40 & 0x7f; // some redundancy, no long runs
    for ([_]std.compress.flate.Compress.Options{ .level_1, .level_6, .level_9 }) |level| {
        var comp: std.Io.Writer.Allocating = .init(a);
        defer comp.deinit();
        try comp.ensureTotalCapacityPrecise(4096);
        var window: [std.compress.flate.max_window_len]u8 = undefined;
        var c = try std.compress.flate.Compress.init(&comp.writer, &window, .raw, level);
        try c.writer.writeAll(&data);
        try c.finish();
        const got = try inflateAll(a, comp.written());
        defer a.free(got);
        try testing.expectEqualSlices(u8, &data, got);
    }
    // A stored block and an empty final block.
    const stored = [_]u8{ 0x01, 0x03, 0x00, 0xfc, 0xff, 'a', 'b', 'c' };
    const got = try inflateAll(a, &stored);
    defer a.free(got);
    try testing.expectEqualStrings("abc", got);
}

test "damaged Deflate64 streams end in an error or a different result, never a panic" {
    const a = testing.allocator;
    var ms: zs.MemorySource = .{ .bytes = fixture };
    var archive: zs.Archive = undefined;
    try archive.initSource(a, ms.source(), .{});
    defer archive.deinit();
    const e = archive.find("text.txt").?;
    var rr: zs.RawReader = undefined;
    try archive.openRaw(&rr, e);
    const raw = try rr.reader().allocRemaining(a, .unlimited);
    defer a.free(raw);
    const whole = try inflateAll(a, raw);
    defer a.free(whole);
    try testing.expectEqual(@as(usize, @intCast(e.uncompressed_size)), whole.len);

    // Every prefix: Truncated (ReadFailed) or, for a prefix that ends on a block boundary, a short result.
    var cut: usize = 0;
    while (cut < raw.len) : (cut += 37) {
        const r = inflateAll(a, raw[0..cut]);
        if (r) |g| {
            defer a.free(g);
            try testing.expect(g.len <= whole.len);
        } else |err| try testing.expect(err == error.ReadFailed);
    }
    // Every byte of the first 600, flipped.
    const copy = try a.dupe(u8, raw);
    defer a.free(copy);
    for (0..600) |i| {
        copy[i] ^= 0x5a;
        const r = inflateAll(a, copy);
        if (r) |g| a.free(g) else |err| try testing.expect(err == error.ReadFailed);
        copy[i] ^= 0x5a;
    }
    // The cause is reported.
    var in: std.Io.Reader = .fixed(raw[0 .. raw.len / 2]);
    const st = try a.create(d64.Inflate);
    defer a.destroy(st);
    st.init(&in);
    var sink: std.Io.Writer.Allocating = .init(a);
    defer sink.deinit();
    try testing.expectError(error.ReadFailed, st.reader.streamRemaining(&sink.writer));
    try testing.expectEqual(@as(?d64.DecodeError, error.Truncated), st.err);
    // A block type of 3.
    var bad: std.Io.Reader = .fixed(&[_]u8{0x07});
    st.init(&bad);
    try testing.expectError(error.ReadFailed, st.reader.streamRemaining(&sink.writer));
    try testing.expectEqual(@as(?d64.DecodeError, error.BadBlockType), st.err);
}
