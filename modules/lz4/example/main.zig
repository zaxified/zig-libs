// SPDX-License-Identifier: MIT

//! What a consumer of `lz4` does: compress a block and a frame at the fast
//! and the optimal-parser levels and read them back, stream a frame through
//! `std.Io` writers and readers, use a dictionary, and see a malformed frame
//! refused by name. Built by `zig build check-examples` against the published
//! module only.

const std = @import("std");
const lz4 = @import("lz4");

/// A check that survives every optimize mode (an `assert` does not).
fn must(ok: bool, src: std.builtin.SourceLocation) void {
    if (!ok) std.debug.panic("example check failed at {s}:{d}", .{ src.file, src.line });
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(gpa);
    for (0..400) |i| try text.print(gpa, "record {d}: status ok, retries {d}, path /var/lib/data/{d}\n", .{ i, i % 7, i * 13 });
    const data = text.items;

    // A block, at the fast matcher and at the optimal parser (levels 10..12).
    const dst = try gpa.alloc(u8, lz4.compressBlockBound(data.len));
    defer gpa.free(dst);
    const back = try gpa.alloc(u8, data.len);
    defer gpa.free(back);
    const fast = try lz4.compressBlock(data, dst, .{});
    must(try lz4.decompressBlock(dst[0..fast], back) == data.len and std.mem.eql(u8, back, data), @src());
    const best = try lz4.compressBlock(data, dst, .{ .hc_level = 12 });
    must(try lz4.decompressBlock(dst[0..best], back) == data.len and std.mem.eql(u8, back, data), @src());
    must(best < fast, @src());
    std.debug.print("block: {d} bytes -> {d} fast, {d} at level 12\n", .{ data.len, fast, best });

    // A frame with checksums.
    const z = try lz4.compress(gpa, data, .{ .hc_level = 9, .content_checksum = true, .block_checksum = true });
    defer gpa.free(z);
    const unz = try lz4.decompress(gpa, z, .{});
    defer gpa.free(unz);
    must(std.mem.eql(u8, unz, data), @src());

    // Streaming: a Writer in, a Reader out.
    var sink: std.Io.Writer.Allocating = .init(gpa);
    defer sink.deinit();
    const c = try lz4.Compressor.init(gpa, &sink.writer, .{ .frame = .{ .content_checksum = true } });
    defer c.deinit();
    var at: usize = 0;
    while (at < data.len) : (at += 1000) try c.writer.writeAll(data[at..@min(at + 1000, data.len)]);
    try c.writer.flush();
    try c.finish();
    var in: std.Io.Reader = .fixed(sink.written());
    var rbuf: [256]u8 = undefined;
    const d = try lz4.Decompressor.init(gpa, &in, &rbuf, .{});
    defer d.deinit();
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(gpa);
    var tmp: [333]u8 = undefined;
    while (true) {
        const n = try d.reader.readSliceShort(&tmp);
        if (n == 0) break;
        try got.appendSlice(gpa, tmp[0..n]);
    }
    must(std.mem.eql(u8, got.items, data), @src());

    // A dictionary: the frame is smaller with it, and needs it to decode.
    const dict = data[0..2000];
    const small = data[2000..2600];
    const plain = try lz4.compress(gpa, small, .{});
    defer gpa.free(plain);
    const with = try lz4.compressDict(gpa, small, dict, 7, .{});
    defer gpa.free(with);
    must(with.len < plain.len, @src());
    const small_back = try lz4.decompressDict(gpa, with, dict, .{});
    defer gpa.free(small_back);
    must(std.mem.eql(u8, small_back, small), @src());

    // A damaged frame is refused, not decoded to something else.
    var bad = try gpa.dupe(u8, z);
    defer gpa.free(bad);
    bad[bad.len / 2] ^= 0xff;
    must(std.meta.isError(lz4.decompress(gpa, bad, .{})), @src());
    std.debug.print("lz4 example ok\n", .{});
}
