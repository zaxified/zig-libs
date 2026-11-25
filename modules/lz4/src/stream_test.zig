// SPDX-License-Identifier: MIT

//! `Compressor` and `Decompressor` (`std.Io` streaming), judged against the
//! one-shot codec and, for frames our `Compressor` writes, against the same
//! decoder reading them whole.

const std = @import("std");
const testing = std.testing;
const lz4 = @import("root.zig");

const gpa = testing.allocator;

fn compressStream(data: []const u8, opts: lz4.CompressorOptions, chunk: usize) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    const c = try lz4.Compressor.init(gpa, &out.writer, opts);
    defer c.deinit();
    var i: usize = 0;
    while (i < data.len) {
        const k = @min(chunk, data.len - i);
        try c.writer.writeAll(data[i..][0..k]);
        i += k;
    }
    try c.writer.flush();
    try c.finish();
    return out.toOwnedSlice();
}

fn decompressStream(z: []const u8, opts: lz4.DecompressorOptions, chunk: usize) ![]u8 {
    var in: std.Io.Reader = .fixed(z);
    var buf: [64]u8 = undefined;
    const d = try lz4.Decompressor.init(gpa, &in, &buf, opts);
    defer d.deinit();
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var tmp = try gpa.alloc(u8, chunk);
    defer gpa.free(tmp);
    while (true) {
        const n = d.reader.readSliceShort(tmp) catch return error.ReadFailed;
        if (n == 0) break;
        try out.appendSlice(gpa, tmp[0..n]);
    }
    return out.toOwnedSlice(gpa);
}

test "Compressor: frames decode with the one-shot decoder, every shape, option and write size" {
    const variants = [_]lz4.CompressorOptions{
        .{},
        .{ .frame = .{ .independent_blocks = true, .block_checksum = true, .content_checksum = true } },
        .{ .frame = .{ .block_size = .max256KB, .content_checksum = true } },
        .{ .frame = .{ .hc_level = 6, .content_checksum = true } },
        .{ .frame = .{ .content_size = true, .content_checksum = true }, .content_size = 0 },
    };
    for (lz4.interop_corpus.shapes) |sh| {
        if (sh.len > (1 << 20) + 7) continue;
        const data = try lz4.interop_corpus.generate(gpa, sh);
        defer gpa.free(data);
        for (variants, 0..) |v0, vi| {
            var v = v0;
            if (v.frame.content_size) v.content_size = data.len;
            for ([_]usize{ 1000, 70_000, 1 << 21 }) |chunk| {
                const z = try compressStream(data, v, chunk);
                defer gpa.free(z);
                const back = try lz4.decompress(gpa, z, .{});
                defer gpa.free(back);
                testing.expectEqualSlices(u8, data, back) catch |e| {
                    std.debug.print("shape {s} variant {d} chunk {d}\n", .{ sh.name, vi, chunk });
                    return e;
                };
            }
        }
    }
}

test "Decompressor: frames of the one-shot compressor and of Compressor, tiny reads and big reads" {
    for (lz4.interop_corpus.shapes) |sh| {
        if (sh.len > (1 << 20) + 7) continue;
        const data = try lz4.interop_corpus.generate(gpa, sh);
        defer gpa.free(data);
        for ([_]lz4.EncodeOptions{ .{}, .{ .independent_blocks = true, .block_checksum = true, .content_checksum = true, .content_size = true }, .{ .block_size = .max1MB, .hc_level = 4 } }) |eo| {
            const z = try lz4.compress(gpa, data, eo);
            defer gpa.free(z);
            for ([_]usize{ 1, 777, 1 << 20 }) |chunk| {
                if (chunk == 1 and data.len > 70_000) continue; // byte reads: small inputs only
                const back = try decompressStream(z, .{}, chunk);
                defer gpa.free(back);
                try testing.expectEqualSlices(u8, data, back);
            }
        }
    }
}

test "Decompressor: concatenated frames, skippable frames, empty frame; dictionary" {
    const a = try lz4.compress(gpa, "first frame, first frame, first frame", .{});
    defer gpa.free(a);
    const b = try lz4.compress(gpa, "", .{});
    defer gpa.free(b);
    const c = try lz4.compress(gpa, "third", .{ .independent_blocks = true });
    defer gpa.free(c);
    var skip: [12]u8 = undefined;
    std.mem.writeInt(u32, skip[0..4], lz4.skippable_magic_base + 3, .little);
    std.mem.writeInt(u32, skip[4..8], 4, .little);
    @memcpy(skip[8..12], "skip");
    const all = try std.mem.concat(gpa, u8, &.{ a, &skip, b, c });
    defer gpa.free(all);
    const back = try decompressStream(all, .{}, 5);
    defer gpa.free(back);
    try testing.expectEqualStrings("first frame, first frame, first frame" ++ "third", back);

    const dict = try lz4.interop_corpus.generate(gpa, .{ .name = "d", .kind = .text, .len = 20_000, .seed = 2 });
    defer gpa.free(dict);
    const data = try lz4.interop_corpus.generate(gpa, .{ .name = "d", .kind = .text, .len = 200_000, .seed = 2 });
    defer gpa.free(data);
    for ([_]bool{ false, true }) |indep| {
        const z = try lz4.compressDict(gpa, data, dict, 1, .{ .independent_blocks = indep });
        defer gpa.free(z);
        const got = try decompressStream(z, .{ .dictionary = dict }, 4096);
        defer gpa.free(got);
        try testing.expectEqualSlices(u8, data, got);
    }
}

test "Decompressor: a header with both content size and dictionary id (15-byte descriptor)" {
    // Regression 2026-11-25 (lz4 mutation audit): the descriptor buffer held 11
    // bytes, so FLG 0x08|0x01 indexed out of bounds (a panic in safe builds,
    // an out-of-bounds write in ReleaseFast).
    const dict = try lz4.interop_corpus.generate(gpa, .{ .name = "d", .kind = .text, .len = 8_000, .seed = 3 });
    defer gpa.free(dict);
    const data = try lz4.interop_corpus.generate(gpa, .{ .name = "d", .kind = .text, .len = 50_000, .seed = 3 });
    defer gpa.free(data);
    const z = try lz4.compressDict(gpa, data, dict, 0xA1B2C3D4, .{ .content_size = true });
    defer gpa.free(z);
    try testing.expectEqual(@as(u8, 0x09), z[4] & 0x09);
    for ([_]usize{ 1, 7, 4096 }) |chunk| {
        const got = try decompressStream(z, .{ .dictionary = dict }, chunk);
        defer gpa.free(got);
        try testing.expectEqualSlices(u8, data, got);
    }
}

test "Decompressor: malformed input is ReadFailed with the reason in err; the output cap holds" {
    const data = try lz4.interop_corpus.generate(gpa, .{ .name = "t", .kind = .text, .len = 100_000 });
    defer gpa.free(data);
    const z = try lz4.compress(gpa, data, .{ .content_checksum = true, .block_checksum = true });
    defer gpa.free(z);
    // Truncated at every kind of place: a header byte, a block, the end mark.
    for ([_]usize{ 3, 7, 100, z.len / 2, z.len - 5, z.len - 1 }) |cut| {
        var in: std.Io.Reader = .fixed(z[0..cut]);
        var buf: [16]u8 = undefined;
        const d = try lz4.Decompressor.init(gpa, &in, &buf, .{});
        defer d.deinit();
        var sink: [4096]u8 = undefined;
        var failed = false;
        while (true) {
            const n = d.reader.readSliceShort(&sink) catch {
                failed = true;
                break;
            };
            if (n == 0) break;
        }
        try testing.expect(failed);
        try testing.expectEqual(@as(?lz4.DecodeError, error.TruncatedInput), d.err);
    }
    // A flipped payload bit: checksum or block error, never the data.
    const bad = try gpa.dupe(u8, z);
    defer gpa.free(bad);
    bad[500] ^= 0x10;
    var in: std.Io.Reader = .fixed(bad);
    const d = try lz4.Decompressor.init(gpa, &in, &.{}, .{});
    defer d.deinit();
    var sink: [1 << 17]u8 = undefined;
    try testing.expectError(error.ReadFailed, d.reader.readSliceAll(sink[0..data.len]));
    try testing.expect(d.err != null);
    // The cap.
    var in2: std.Io.Reader = .fixed(z);
    const d2 = try lz4.Decompressor.init(gpa, &in2, &.{}, .{ .max_output = 50_000 });
    defer d2.deinit();
    try testing.expectError(error.ReadFailed, d2.reader.readSliceAll(sink[0..data.len]));
    try testing.expectEqual(@as(?lz4.DecodeError, error.OutputTooLarge), d2.err);
    // Not an LZ4 stream.
    var in3: std.Io.Reader = .fixed("not lz4 at all");
    const d3 = try lz4.Decompressor.init(gpa, &in3, &.{}, .{});
    defer d3.deinit();
    try testing.expectError(error.ReadFailed, d3.reader.readSliceAll(sink[0..4]));
    try testing.expectEqual(@as(?lz4.DecodeError, error.BadMagic), d3.err);
}

test "Compressor/Decompressor round trip through each other with a flush in the middle" {
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    const c = try lz4.Compressor.init(gpa, &out.writer, .{ .frame = .{ .content_checksum = true } });
    defer c.deinit();
    try c.writer.writeAll("hello hello hello hello ");
    try c.writer.flush(); // a short block
    try c.writer.writeAll("hello hello hello world");
    try c.finish();
    const back = try decompressStream(out.written(), .{}, 3);
    defer gpa.free(back);
    try testing.expectEqualStrings("hello hello hello hello hello hello hello world", back);
    // An empty stream is a valid empty frame.
    var out2: std.Io.Writer.Allocating = .init(gpa);
    defer out2.deinit();
    const c2 = try lz4.Compressor.init(gpa, &out2.writer, .{});
    defer c2.deinit();
    try c2.finish();
    const e = try lz4.decompress(gpa, out2.written(), .{});
    defer gpa.free(e);
    try testing.expectEqual(@as(usize, 0), e.len);
}
