// SPDX-License-Identifier: MIT

//! What a program archiving its own data does with `zstd`: compress a day of
//! CSV samples into a checksummed frame at the level that fits the job, then
//! read it back with std's decoder and verify the checksum.
//!
//! Built by `zig build check-examples` against the PUBLISHED module, so a type
//! or error the caller needs but the module does not export stops this file
//! compiling.

const std = @import("std");
const zstd = @import("zstd");

/// A check that survives every optimize mode (a debug assert would vanish in
/// the ReleaseFast lane, where this example is also run).
fn must(ok: bool, src: std.builtin.SourceLocation) void {
    if (!ok) std.debug.panic("example check failed at {s}:{d}", .{ src.file, src.line });
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // A day of samples: series id, unix time, value.
    var csv: std.Io.Writer.Allocating = .init(gpa);
    defer csv.deinit();
    var t: u64 = 1_758_499_200;
    for (0..20_000) |i| {
        t += 5;
        try csv.writer.print("{d},{d},{d}.{d}\n", .{ i % 28, t, (i * 7919) % 5000, i % 1000 });
    }
    const data = csv.written();

    // Level 1 for a fast rotation, 3 (the default) for the archive; a negative
    // level trades ratio for speed; above 22 there is no level, and asking
    // for one is an error rather than a quiet clamp.
    const fast = try zstd.compressAlloc(gpa, data, .{ .level = 1 });
    defer gpa.free(fast);
    const archive = try zstd.compressAlloc(gpa, data, .{ .level = 3, .checksum = true });
    defer gpa.free(archive);
    std.debug.print("{d} bytes -> level 1: {d}, level 3 + checksum: {d}\n", .{ data.len, fast.len, archive.len });
    must(archive.len < data.len / 3, @src());

    var buf: [16]u8 = undefined;
    const refused = zstd.compress(gpa, &buf, data, .{ .level = 23 });
    must(refused == error.LevelUnsupported, @src());

    // Read it back: std decodes, the caller checks the frame checksum.
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var in: std.Io.Reader = .fixed(archive);
    var d: std.compress.zstd.Decompress = .init(&in, &.{}, .{});
    _ = try d.reader.streamRemaining(&out.writer);
    must(std.mem.eql(u8, out.written(), data), @src());
    const stored = std.mem.readInt(u32, archive[archive.len - 4 ..][0..4], .little);
    must(stored == @as(u32, @truncate(std.hash.XxHash64.hash(0, data))), @src());
    std.debug.print("round trip ok, checksum {x:0>8}\n", .{stored});
}
