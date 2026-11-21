// SPDX-License-Identifier: MIT

//! BCJ / delta filters, multi-block and threaded `.xz` output, pinned against
//! the `xz` program's bytes (recipe in `tools/interop.zig`, case table
//! `filterAndBlockParity`; the digests and the two embedded streams were made
//! by `xz` 5.8.3 from `input()`).

const std = @import("std");
const lzma = @import("root.zig");

const gpa = std.testing.allocator;

/// Compressible bytes with branch opcodes planted for every converter.
fn input(buf: []u8) void {
    var x: u32 = 12345;
    for (buf) |*b| {
        x = x *% 1664525 +% 1013904223;
        b.* = @truncate((x >> 24) & 0x1F);
    }
    for (buf, 0..) |*b, i| switch (i % 32) {
        0 => b.* = 0xE8,
        4 => b.* = 0,
        5 => b.* = 0xFF,
        7 => b.* = 0xEB,
        11 => b.* = 0x94,
        16 => b.* = 0x48,
        19 => b.* = 1,
        20 => b.* = 0x40,
        21 => b.* = 0x10,
        25 => b.* = 0xF0 | (b.* & 7),
        27 => b.* = 0xF8 | (b.* & 7),
        else => {},
    };
}

fn sha(bytes: []const u8) [32]u8 {
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &h, .{});
    return h;
}

fn expectDigest(hex: []const u8, bytes: []const u8) !void {
    var want: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, hex);
    try std.testing.expectEqualSlices(u8, &want, &sha(bytes));
}

const Case = struct {
    name: []const u8,
    opts: lzma.EncodeOptions,
    len: usize,
    sha: []const u8,
};

const cases = [_]Case{
    .{ .name = "x86", .opts = .{ .lzma = lzma.preset(1, false), .filters = &.{.{ .x86 = .{} }} }, .len = 2208, .sha = "e524ba9da55e673177acdd5387567f76d5db717efe54a0fa216aa655d992f472" },
    .{ .name = "arm", .opts = .{ .lzma = lzma.preset(1, false), .filters = &.{.{ .arm = .{} }} }, .len = 2280, .sha = "58efe2e9d5ee29d9669840bbb7f9f30e5df03db1d386232141436559603ac47e" },
    .{ .name = "armthumb", .opts = .{ .lzma = lzma.preset(1, false), .filters = &.{.{ .armthumb = .{} }} }, .len = 2184, .sha = "9647500e0a02b0d2c96e868bdaba9225a4939092d43de3b1e9187d1f52cda169" },
    .{ .name = "arm64 start=16", .opts = .{ .lzma = lzma.preset(1, false), .filters = &.{.{ .arm64 = .{ .start_offset = 16 } }} }, .len = 2196, .sha = "6beefedcf84233ee97b37257e0c5926b1fb7dc2e431eddc2f67ac10bd59de966" },
    .{ .name = "powerpc", .opts = .{ .lzma = lzma.preset(1, false), .filters = &.{.{ .powerpc = .{} }} }, .len = 2172, .sha = "91162959e209eeebc73def2482b4a2856d085ba673ab06671ef81dfd15fb604a" },
    .{ .name = "sparc", .opts = .{ .lzma = lzma.preset(1, false), .filters = &.{.{ .sparc = .{} }} }, .len = 2188, .sha = "23a8e29ac09ba2b4416512278485e87729c2423455c925ac514fd80b8599025a" },
    .{ .name = "delta 4", .opts = .{ .lzma = lzma.preset(1, false), .filters = &.{.{ .delta = 4 }} }, .len = 2676, .sha = "605aa0f49d9549df5755b600f4a79b38fe68cd5b45a3834a36ef20dde92e692a" },
    .{ .name = "delta 3 + x86", .opts = .{ .lzma = lzma.preset(1, false), .filters = &.{ .{ .delta = 3 }, .{ .x86 = .{} } } }, .len = 2792, .sha = "e3a7be6883d2645b60abb3fbde430035477158c7ba9d433d6af6abcdc8056a9b" },
    .{ .name = "blocks of 1000", .opts = .{ .lzma = lzma.preset(1, false), .block_size = 1000 }, .len = 2412, .sha = "485077c14ee5eba5a2008b2e0353fb1b154e4e845b1c4a5b51700f025812cb70" },
    .{ .name = "2 threads, blocks of 1000", .opts = .{ .lzma = lzma.preset(1, false), .block_size = 1000, .threads = 2 }, .len = 2424, .sha = "82d3757d061aa3a7e0c9cb91a50a59de9057b81cecfbc7985223578827089f29" },
    .{ .name = "2 threads, x86, blocks of 1000", .opts = .{ .lzma = lzma.preset(1, false), .filters = &.{.{ .x86 = .{} }}, .block_size = 1000, .threads = 2 }, .len = 2488, .sha = "6051c2c21c252713ba39c9d7e0280b8eb76f3826d41f48c0ed9c6fdc941cc195" },
};

test "xz: filters, blocks and threads produce the xz program's bytes, and decode back" {
    var plain: [3000]u8 = undefined;
    input(&plain);
    for (cases) |cs| {
        const z = try lzma.compress(gpa, &plain, .xz, cs.opts);
        defer gpa.free(z);
        expectDigest(cs.sha, z) catch |e| {
            std.debug.print("case {s}: {d} bytes (xz: {d})\n", .{ cs.name, z.len, cs.len });
            return e;
        };
        try std.testing.expectEqual(cs.len, z.len);
        const back = try lzma.decompress(gpa, z, .xz, .{});
        defer gpa.free(back);
        try std.testing.expectEqualSlices(u8, &plain, back);
    }
}

test "xz: streams the xz program made with a filter chain and with threaded blocks decode" {
    var plain: [3000]u8 = undefined;
    input(&plain);
    for ([_][]const u8{ @embedFile("testdata/xz_delta_x86_chain.xz"), @embedFile("testdata/xz_mt_blocks.xz") }) |z| {
        const back = try lzma.decompress(gpa, z, .xz, .{});
        defer gpa.free(back);
        try std.testing.expectEqualSlices(u8, &plain, back);
        // Through the reader one byte at a time as well.
        var in: std.Io.Reader = .fixed(z);
        var buf: [1]u8 = undefined;
        var r = try lzma.DecompressReader.init(gpa, &in, &buf, .xz, .{});
        defer r.deinit();
        var out: [3000]u8 = undefined;
        try r.reader.readSliceAll(&out);
        try std.testing.expectEqualSlices(u8, &plain, &out);
    }
}

test "xz: a damaged stored check of a filtered block is reported after the tail" {
    var plain: [3000]u8 = undefined;
    input(&plain);
    const z = try lzma.compress(gpa, &plain, .xz, .{ .lzma = lzma.preset(1, false), .filters = &.{.{ .x86 = .{} }}, .check = .crc32 });
    defer gpa.free(z);
    // The check (4 bytes) sits right before the index; the footer is 12 bytes.
    var bad = try gpa.dupe(u8, z);
    defer gpa.free(bad);
    const index_size = (@as(usize, std.mem.readInt(u32, z[z.len - 8 ..][0..4], .little)) + 1) * 4;
    const check_at = bad.len - 12 - index_size - 4;
    bad[check_at] ^= 0x55;
    try std.testing.expectError(error.CheckMismatch, lzma.decompress(gpa, bad, .xz, .{}));
}

test "block size and threads: options are validated, empty input and exact multiples have no empty block" {
    try std.testing.expectError(error.InvalidOptions, lzma.compress(gpa, "x", .lzma_alone, .{ .block_size = 10 }));
    try std.testing.expectError(error.InvalidOptions, lzma.compress(gpa, "x", .lzma1, .{ .filters = &.{.{ .x86 = .{} }} }));
    try std.testing.expectError(error.InvalidOptions, lzma.compress(gpa, "x", .xz, .{ .filters = &.{.{ .delta = 0 }} }));
    try std.testing.expectError(error.InvalidOptions, lzma.compress(gpa, "x", .xz, .{ .filters = &.{.{ .arm64 = .{ .start_offset = 2 } }} }));
    try std.testing.expectError(error.InvalidOptions, lzma.compress(gpa, "x", .xz, .{ .filters = &.{ .{ .delta = 1 }, .{ .delta = 1 }, .{ .delta = 1 }, .{ .delta = 1 } } }));
    for ([_]u32{ 1, 2 }) |threads| {
        const empty = try lzma.compress(gpa, "", .xz, .{ .block_size = 100, .threads = threads });
        defer gpa.free(empty);
        const none = try lzma.decompress(gpa, empty, .xz, .{});
        defer gpa.free(none);
        try std.testing.expectEqual(@as(usize, 0), none.len);
        // 300 bytes in blocks of 100: exactly three blocks.
        var plain: [300]u8 = undefined;
        input(&plain);
        const z = try lzma.compress(gpa, &plain, .xz, .{ .block_size = 100, .threads = threads });
        defer gpa.free(z);
        const back = try lzma.decompress(gpa, z, .xz, .{});
        defer gpa.free(back);
        try std.testing.expectEqualSlices(u8, &plain, back);
        // The index (before the 12-byte footer) says three records.
        const index_size = (@as(usize, std.mem.readInt(u32, z[z.len - 8 ..][0..4], .little)) + 1) * 4;
        try std.testing.expectEqual(@as(u8, 3), z[z.len - 12 - index_size + 1]);
    }
}

test "the streaming encoder over any write size gives the same blocks" {
    var plain: [3000]u8 = undefined;
    input(&plain);
    const o: lzma.EncodeOptions = .{ .lzma = lzma.preset(1, false), .filters = &.{.{ .x86 = .{} }}, .block_size = 700 };
    const whole = try lzma.compress(gpa, &plain, .xz, o);
    defer gpa.free(whole);
    for ([_]usize{ 1, 7, 699, 700, 701 }) |piece| {
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var e = try lzma.Encoder.init(gpa, &out.writer, .xz, o);
        defer e.deinit();
        var p: usize = 0;
        while (p < plain.len) : (p += piece) try e.write(plain[p..@min(p + piece, plain.len)]);
        try e.finish();
        try std.testing.expectEqualSlices(u8, whole, out.written());
    }
}
