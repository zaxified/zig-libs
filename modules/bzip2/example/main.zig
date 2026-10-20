// SPDX-License-Identifier: MIT

//! What a program that writes and reads `.bz2` does with `bzip2`: stream a
//! day of CSV samples through a `StreamWriter`, read them back line by line
//! through a `DecompressReader`, refuse a decompression bomb with the cap,
//! and name the error a damaged file gives.
//!
//! Built by `zig build check-examples` against the PUBLISHED module, so a type
//! or error the caller needs but the module does not export stops this file
//! compiling.

const std = @import("std");
const bzip2 = @import("bzip2");

/// A check that survives every optimize mode (a debug assert would vanish in
/// the ReleaseFast lane, where this example is also run).
fn must(ok: bool, src: std.builtin.SourceLocation) void {
    if (!ok) std.debug.panic("example check failed at {s}:{d}", .{ src.file, src.line });
}

pub fn main() !void {
    var sa: std.heap.SafeAllocator = .init(std.heap.page_allocator, .{});
    defer if (sa.deinit() != 0) @panic("leak");
    const gpa = sa.allocator();

    // Write: the rows go through the stream writer as they are produced.
    var file: std.Io.Writer.Allocating = .init(gpa);
    defer file.deinit();
    var wbuf: [4096]u8 = undefined;
    var sw = try bzip2.StreamWriter.init(gpa, &file.writer, &wbuf, .{ .level = 9 });
    defer sw.deinit();
    var t: u64 = 1_758_499_200;
    for (0..20_000) |i| {
        t += 5;
        try sw.writer.print("{d},{d},{d}.{d}\n", .{ i % 28, t, (i * 7919) % 5000, i % 1000 });
    }
    try sw.finish();
    const archive = file.written();
    std.debug.print("{d} bytes of .bz2\n", .{archive.len});
    must(std.mem.startsWith(u8, archive, "BZh9"), @src());

    // Read: line by line, one block in memory, the CRCs checked on the way.
    var in: std.Io.Reader = .fixed(archive);
    var rbuf: [256]u8 = undefined;
    var r = try bzip2.DecompressReader.init(gpa, &in, &rbuf, .{});
    defer r.deinit();
    var rows: usize = 0;
    var last: [64]u8 = undefined;
    var last_len: usize = 0;
    while (try r.reader.takeDelimiter('\n')) |l| {
        rows += 1;
        last_len = l.len;
        @memcpy(last[0..l.len], l);
    }
    must(rows == 20_000, @src());
    must(std.mem.startsWith(u8, last[0..last_len], "7,"), @src());

    // The same bytes with the whole-buffer helpers, under a cap: a stream of
    // zeros is the classic bomb, and the cap stops it at the limit.
    const zeros = try gpa.alloc(u8, 4 << 20);
    defer gpa.free(zeros);
    @memset(zeros, 0);
    const bomb = try bzip2.compress(gpa, zeros, .{ .level = 1 });
    defer gpa.free(bomb);
    must(bomb.len < 200, @src());
    must(bzip2.decompress(gpa, bomb, .{ .max_output = 1 << 20 }) == error.OutputTooLarge, @src());

    // A damaged file says which check failed.
    var damaged = try gpa.dupe(u8, archive);
    defer gpa.free(damaged);
    damaged[damaged.len / 2] ^= 0x10;
    if (bzip2.decompress(gpa, damaged, .{})) |_| {
        must(false, @src());
    } else |e| std.debug.print("damaged archive: {t}\n", .{e});
    must(bzip2.decompress(gpa, archive[0 .. archive.len - 3], .{}) == error.TruncatedInput, @src());
}
