// SPDX-License-Identifier: MIT

//! What a program that writes and reads `.xz` and ZIP-style raw LZMA does with
//! `lzma`: stream CSV rows through a `StreamWriter`, read them back line by
//! line through a `DecompressReader`, bound the dictionary and the output of a
//! hostile stream, and carry LZMA1 the way ZIP method 14 does (properties out
//! of band, end marker).
//!
//! Built by `zig build check-examples` against the PUBLISHED module, so a type
//! or error the caller needs but the module does not export stops this file
//! compiling.

const std = @import("std");
const lzma = @import("lzma");

/// A check that survives every optimize mode.
fn must(ok: bool, src: std.builtin.SourceLocation) void {
    if (!ok) std.debug.panic("example check failed at {s}:{d}", .{ src.file, src.line });
}

pub fn main() !void {
    var sa: std.heap.SafeAllocator = .init(std.heap.page_allocator, .{});
    defer if (sa.deinit() != 0) @panic("leak");
    const gpa = sa.allocator();

    // A small dictionary keeps the example light; the presets are xz's.
    var opts: lzma.EncodeOptions = .{ .lzma = lzma.preset(6, false), .check = .crc64 };
    opts.lzma.dict_size = 1 << 20;

    // Write: the rows go through the stream writer as they are produced.
    var file: std.Io.Writer.Allocating = .init(gpa);
    defer file.deinit();
    var wbuf: [4096]u8 = undefined;
    var sw = try lzma.StreamWriter.init(gpa, &file.writer, &wbuf, .xz, opts);
    defer sw.deinit();
    var t: u64 = 1_758_499_200;
    for (0..20_000) |i| {
        t += 5;
        try sw.writer.print("{d},{d},{d}.{d}\n", .{ i % 28, t, (i * 7919) % 5000, i % 1000 });
    }
    try sw.finish();
    const archive = file.written();
    std.debug.print("{d} bytes of .xz\n", .{archive.len});
    must(std.mem.startsWith(u8, archive, "\xfd7zXZ\x00"), @src());

    // Read: line by line, the dictionary in memory, the check verified at the end.
    var in: std.Io.Reader = .fixed(archive);
    var rbuf: [256]u8 = undefined;
    var r = try lzma.DecompressReader.init(gpa, &in, &rbuf, .xz, .{});
    defer r.deinit();
    var rows: usize = 0;
    while (try r.reader.takeDelimiter('\n')) |_| rows += 1;
    must(rows == 20_000, @src());

    // ZIP method 14: the 5 property bytes travel apart from the data, the end
    // marker is optional when the size is known.
    const line = "to be or not to be, that is the question; ";
    var text_buf: [line.len * 50]u8 = undefined;
    for (0..50) |i| @memcpy(text_buf[i * line.len ..][0..line.len], line);
    const text: []const u8 = &text_buf;
    const raw = try lzma.compress(gpa, text, .lzma1, opts);
    defer gpa.free(raw);
    const props: lzma.Lzma1Props = .{ .lc = 3, .lp = 0, .pb = 2, .dict_size = opts.lzma.dict_size };
    const back = try lzma.decompress(gpa, raw, .{ .lzma1 = .{ .props = props, .uncompressed_size = text.len } }, .{});
    defer gpa.free(back);
    must(std.mem.eql(u8, back, text), @src());
    must(std.mem.eql(u8, &props.toBytes(), &(try lzma.Lzma1Props.fromBytes(&props.toBytes())).toBytes()), @src());

    // A hostile stream: the dictionary the header asks for and the output the
    // stream produces are both capped.
    const zeros = try gpa.alloc(u8, 4 << 20);
    defer gpa.free(zeros);
    @memset(zeros, 0);
    const bomb = try lzma.compress(gpa, zeros, .xz, opts);
    defer gpa.free(bomb);
    must(bomb.len < 2000, @src());
    must(lzma.decompress(gpa, bomb, .xz, .{ .max_output = 1 << 20 }) == error.OutputTooLarge, @src());
    must(lzma.decompress(gpa, bomb, .xz, .{ .max_dict = 4096 }) == error.DictTooLarge, @src());

    // A damaged file says which check failed.
    var damaged = try gpa.dupe(u8, archive);
    defer gpa.free(damaged);
    damaged[damaged.len / 2] ^= 0x10;
    if (lzma.decompress(gpa, damaged, .xz, .{})) |_| {
        must(false, @src());
    } else |e| std.debug.print("damaged archive: {t}\n", .{e});
    must(lzma.decompress(gpa, archive[0 .. archive.len - 3], .xz, .{}) == error.TruncatedInput, @src());
}
