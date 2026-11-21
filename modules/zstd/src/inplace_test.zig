// SPDX-License-Identifier: MIT
//! In-place decompression (`ZSTD_decompress` with `src` inside `dst`): the
//! output buffer holds `decompressionMargin(src)` bytes more than the output,
//! the compressed frames sit at its end.

const std = @import("std");
const zstd = @import("root.zig");
const params = @import("params.zig");

/// Compressible text, noise (raw blocks), a run (RLE blocks), and a mix of all
/// three, each `n` bytes.
fn make(gpa: std.mem.Allocator, kind: usize, n: usize) ![]u8 {
    const b = try gpa.alloc(u8, n);
    var prng = std.Random.DefaultPrng.init(0x1a9ace + kind);
    const rnd = prng.random();
    const words = [_][]const u8{ "alpha ", "beta ", "gamma ", "delta ", "epsilon ", "zeta\n", "eta ", "theta " };
    var i: usize = 0;
    while (i < n) {
        const seg = @min(n - i, 1 + rnd.uintLessThan(usize, 40000));
        const k = if (kind == 3) rnd.uintLessThan(usize, 3) else kind;
        switch (k) {
            0 => {
                var j: usize = 0;
                while (j < seg) {
                    const w = words[rnd.uintLessThan(usize, words.len)];
                    const m = @min(w.len, seg - j);
                    @memcpy(b[i + j ..][0..m], w[0..m]);
                    j += m;
                }
            },
            1 => rnd.bytes(b[i..][0..seg]),
            else => @memset(b[i..][0..seg], 0x5a),
        }
        i += seg;
    }
    return b;
}

fn inPlace(gpa: std.mem.Allocator, frames: []const u8, expect: []const u8, slack: usize) !void {
    const margin = try zstd.decompressionMargin(frames);
    const buf = try gpa.alloc(u8, expect.len + margin + slack);
    defer gpa.free(buf);
    @memset(buf, 0xee);
    const src = buf[buf.len - frames.len ..];
    @memcpy(src, frames);
    var d = try zstd.Decompressor.init(gpa, .{});
    defer d.deinit();
    const n = try d.decompress(buf, src);
    try std.testing.expectEqual(expect.len, n);
    try std.testing.expectEqualSlices(u8, expect, buf[0..n]);
}

test "in-place decompression: every block type, several frames, the margin and a little more" {
    const gpa = std.testing.allocator;
    const levels = [_]i32{ 1, 3, 19 };
    for (0..4) |kind| {
        for (levels) |level| {
            if (level > 4 and !params.all_strategies) continue;
            const data = try make(gpa, kind, 300_000 + kind * 7919);
            defer gpa.free(data);
            const one = try zstd.compressAlloc(gpa, data, .{ .level = level, .checksum = true });
            defer gpa.free(one);
            // two frames back to back, with a skippable one between
            const skip = [_]u8{ 0x50, 0x2a, 0x4d, 0x18, 3, 0, 0, 0, 1, 2, 3 };
            const two = try std.mem.concat(gpa, u8, &.{ one, &skip, one });
            defer gpa.free(two);
            const both = try std.mem.concat(gpa, u8, &.{ data, data });
            defer gpa.free(both);
            for ([_]usize{ 0, 1, 4096 }) |slack| {
                try inPlace(gpa, one, data, slack);
                try inPlace(gpa, two, both, slack);
            }
        }
    }
}

test "in-place decompression with too little margin is an error or exact output, never a memory error" {
    const gpa = std.testing.allocator;
    for (0..4) |kind| {
        const data = try make(gpa, kind, 200_000);
        defer gpa.free(data);
        const frame = try zstd.compressAlloc(gpa, data, .{ .level = 3, .checksum = true });
        defer gpa.free(frame);
        const margin = try zstd.decompressionMargin(frame);
        var d = try zstd.Decompressor.init(gpa, .{});
        defer d.deinit();
        var cut: usize = 1;
        while (cut <= margin) : (cut = cut * 3 + 1) {
            const buf = try gpa.alloc(u8, data.len + margin - cut);
            defer gpa.free(buf);
            if (buf.len < frame.len) continue;
            const src = buf[buf.len - frame.len ..];
            @memcpy(src, frame);
            if (d.decompress(buf, src)) |n| {
                try std.testing.expectEqualSlices(u8, data, buf[0..n]);
            } else |_| {}
        }
    }
}
