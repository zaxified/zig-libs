// SPDX-License-Identifier: MIT

const std = @import("std");
const lzma = @import("root.zig");
const corpus = @import("shapes.zig");

const gpa = std.testing.allocator;

test "encoder: round trip, every format, small dictionary" {
    const plain = try corpus.generate(gpa, corpus.find("text-small").?);
    defer gpa.free(plain);
    var o = lzma.preset(6, false);
    o.dict_size = 65536;
    inline for (.{ .xz, .lzma_alone, .lzma1, .lzma2 }) |f| {
        const z = try lzma.compress(gpa, plain, f, .{ .lzma = o });
        defer gpa.free(z);
        const fmt: lzma.Format = switch (f) {
            .xz => .xz,
            .lzma_alone => .lzma_alone,
            .lzma1 => .{ .lzma1 = .{ .props = .{ .lc = 3, .lp = 0, .pb = 2, .dict_size = 65536 } } },
            else => .{ .lzma2 = .{ .dict_size = 65536 } },
        };
        const back = try lzma.decompress(gpa, z, fmt, .{});
        defer gpa.free(back);
        try std.testing.expectEqualSlices(u8, plain, back);
    }
}

test "preset table is xz's" {
    const p6 = lzma.preset(6, false);
    try std.testing.expectEqual(@as(u32, 8 << 20), p6.dict_size);
    try std.testing.expectEqual(@as(u32, 64), p6.nice_len);
    try std.testing.expectEqual(lzma.MatchFinder.bt4, p6.mf);
    const p0 = lzma.preset(0, false);
    try std.testing.expectEqual(lzma.Mode.fast, p0.mode);
    try std.testing.expectEqual(lzma.MatchFinder.hc3, p0.mf);
    const e9 = lzma.preset(9, true);
    try std.testing.expectEqual(@as(u32, 273), e9.nice_len);
    try std.testing.expectEqual(@as(u32, 512), e9.depth);
}

test "price table: first and last entries of price_table.c" {
    const r = @import("rangeenc.zig");
    try std.testing.expectEqual(@as(u8, 128), r.prices[0]);
    try std.testing.expectEqual(@as(u8, 103), r.prices[1]);
    try std.testing.expectEqual(@as(u8, 2), r.prices[122]);
    try std.testing.expectEqual(@as(u8, 1), r.prices[123]);
    try std.testing.expectEqual(@as(u8, 1), r.prices[127]);
}

test "encoder: empty input, every format" {
    var o = lzma.preset(1, false);
    o.dict_size = 4096;
    const xz = try lzma.compress(gpa, "", .xz, .{ .lzma = o });
    defer gpa.free(xz);
    // Header, empty index, footer: no block at all.
    try std.testing.expectEqual(@as(usize, 32), xz.len);
    const e = try lzma.decompress(gpa, xz, .xz, .{});
    gpa.free(e);
    const al = try lzma.compress(gpa, "", .lzma_alone, .{ .lzma = o });
    defer gpa.free(al);
    const e2 = try lzma.decompress(gpa, al, .lzma_alone, .{});
    gpa.free(e2);
    const l2 = try lzma.compress(gpa, "", .lzma2, .{ .lzma = o });
    defer gpa.free(l2);
    try std.testing.expectEqualSlices(u8, &.{0}, l2);
}

test "encoder: options are validated" {
    var o = lzma.preset(1, false);
    o.lc = 4;
    o.lp = 1;
    try std.testing.expectError(error.InvalidOptions, lzma.compress(gpa, "x", .xz, .{ .lzma = o }));
    o = lzma.preset(1, false);
    o.dict_size = 100;
    try std.testing.expectError(error.InvalidOptions, lzma.compress(gpa, "x", .xz, .{ .lzma = o }));
    o = lzma.preset(1, false);
    o.nice_len = 1;
    try std.testing.expectError(error.InvalidOptions, lzma.compress(gpa, "x", .xz, .{ .lzma = o }));
}

test "encoder: incompressible input is stored, and compressInto reports a short buffer" {
    var data: [200_000]u8 = undefined;
    lzma.interop_corpus.fill(&data, .{ .name = "", .kind = .random, .len = data.len });
    var o = lzma.preset(1, false);
    o.dict_size = 65536;
    const z = try lzma.compress(gpa, &data, .xz, .{ .lzma = o });
    defer gpa.free(z);
    // Stored LZMA2 chunks: a few bytes of framing per 64 KiB.
    try std.testing.expect(z.len < data.len + 200);
    const back = try lzma.decompress(gpa, z, .xz, .{});
    defer gpa.free(back);
    try std.testing.expectEqualSlices(u8, &data, back);
    var small: [100]u8 = undefined;
    try std.testing.expectError(error.OutputTooLarge, lzma.compressInto(gpa, &small, &data, .xz, .{ .lzma = o }));
    const big = try gpa.alloc(u8, lzma.compressBound(data.len));
    defer gpa.free(big);
    const n = try lzma.compressInto(gpa, big, &data, .xz, .{ .lzma = o });
    try std.testing.expectEqualSlices(u8, z, big[0..n]);
}

test "encoder: a long match crossing the dictionary and the window slide" {
    const gpa2 = std.testing.allocator;
    // 3 MiB of a 100 000-byte period with a 4096-byte dictionary and the
    // default window: the finder must slide and normalise without a difference.
    const period = try gpa2.alloc(u8, 100_000);
    defer gpa2.free(period);
    lzma.interop_corpus.fill(period, .{ .name = "", .kind = .random, .len = period.len });
    const data = try gpa2.alloc(u8, 1_500_000);
    defer gpa2.free(data);
    for (data, 0..) |*b, i| b.* = period[i % period.len];
    var o = lzma.preset(3, false);
    o.dict_size = 150_000;
    const z = try lzma.compress(gpa2, data, .xz, .{ .lzma = o });
    defer gpa2.free(z);
    try std.testing.expect(z.len < 250_000);
    const back = try lzma.decompress(gpa2, z, .xz, .{});
    defer gpa2.free(back);
    try std.testing.expectEqualSlices(u8, data, back);
}

test "compressBound holds for incompressible input in every format; encoder refuses use after finish" {
    const a = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(7);
    const data = try a.alloc(u8, 256 * 1024);
    defer a.free(data);
    prng.random().bytes(data);
    const buf = try a.alloc(u8, lzma.compressBound(data.len));
    defer a.free(buf);
    const formats = [_]lzma.EncodeFormat{ .xz, .lzma_alone, .lzma1, .lzma2 };
    for (formats) |f| {
        const n = try lzma.compressInto(a, buf, data, f, .{ .lzma = lzma.preset(1, false) });
        try std.testing.expect(n <= buf.len);
    }
    var out: std.Io.Writer.Allocating = .init(a);
    defer out.deinit();
    var e = try lzma.Encoder.init(a, &out.writer, .xz, .{});
    defer e.deinit();
    try e.write("abc");
    try e.finish();
    try std.testing.expectError(error.AlreadyFinished, e.finish());
    try std.testing.expectError(error.AlreadyFinished, e.write("x"));
}
