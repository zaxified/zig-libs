// SPDX-License-Identifier: MIT

const std = @import("std");
const lz = @import("root.zig");

test "xz: empty stream from xz 5.8" {
    // printf '' | xz -c
    const data = [_]u8{ 0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x04, 0xe6, 0xd6, 0xb4, 0x46, 0x00, 0x00, 0x00, 0x00, 0x1c, 0xdf, 0x44, 0x21, 0x1f, 0xb6, 0xf3, 0x7d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x59, 0x5a };
    const out = try lz.decompress(std.testing.allocator, &data, .xz, .{});
    defer std.testing.allocator.free(out);
    try std.testing.expectEqual(@as(usize, 0), out.len);
}

const gpa = std.testing.allocator;

fn lzma2Stored(comptime parts: []const []const u8) []const u8 {
    comptime {
        var out: []const u8 = "";
        for (parts, 0..) |p, i| {
            out = out ++ &[_]u8{ if (i == 0) 1 else 2, @intCast((p.len - 1) >> 8), @intCast((p.len - 1) & 0xFF) } ++ p;
        }
        return out ++ &[_]u8{0};
    }
}

test "lzma2: stored chunks, dictionary reset only on the first" {
    const s = comptime lzma2Stored(&.{ "hello, ", "world" });
    const out = try lz.decompress(gpa, s, .{ .lzma2 = .{ .dict_size = 4096 } }, .{});
    defer gpa.free(out);
    try std.testing.expectEqualStrings("hello, world", out);
}

test "lzma2: refusals" {
    const opts: lz.DecodeOptions = .{};
    const f: lz.Format = .{ .lzma2 = .{ .dict_size = 4096 } };
    // A chunk without the first dictionary reset.
    try std.testing.expectError(error.CorruptData, lz.decompress(gpa, &.{ 2, 0, 0, 'a', 0 }, f, opts));
    // A control byte in the reserved range.
    try std.testing.expectError(error.CorruptData, lz.decompress(gpa, &.{ 3, 0, 0, 'a', 0 }, f, opts));
    // An LZMA chunk before any properties.
    try std.testing.expectError(error.CorruptData, lz.decompress(gpa, &.{ 1, 0, 0, 'a', 0x80, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0 }, f, opts));
    // Truncated: the end byte is missing, a chunk body is short.
    try std.testing.expectError(error.TruncatedInput, lz.decompress(gpa, &.{ 1, 0, 0, 'a' }, f, opts));
    try std.testing.expectError(error.TruncatedInput, lz.decompress(gpa, &.{ 1, 0, 3, 'a' }, f, opts));
    // The bomb caps.
    const s = comptime lzma2Stored(&.{"0123456789"});
    try std.testing.expectError(error.OutputTooLarge, lz.decompress(gpa, s, f, .{ .max_output = 9 }));
    const exact = try lz.decompress(gpa, s, f, .{ .max_output = 10 });
    gpa.free(exact);
    try std.testing.expectError(error.DictTooLarge, lz.decompress(gpa, s, .{ .lzma2 = .{ .dict_size = 1 << 30 } }, .{}));
}

test "lzma1: properties byte" {
    const p: lz.Lzma1Props = .{ .lc = 3, .lp = 0, .pb = 2, .dict_size = 1 << 16 };
    const b = p.toBytes();
    try std.testing.expectEqual(@as(u8, 0x5D), b[0]);
    const q = try lz.Lzma1Props.fromBytes(&b);
    try std.testing.expectEqual(p, q);
    try std.testing.expectError(error.BadProperties, lz.Lzma1Props.fromBytes(&.{ 225, 0, 0, 1, 0 }));
    // lc + lp over 4 is liblzma's refusal too.
    try std.testing.expectError(error.BadProperties, lz.Lzma1Props.fromBytes(&.{ 4 + 9 * 1, 0, 0, 1, 0 }));
}

test "xz: block header refusals" {
    const header = [_]u8{ 0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x04, 0xe6, 0xd6, 0xb4, 0x46 };
    // A block header whose CRC is wrong.
    var bad = header ++ [_]u8{ 0x02, 0x00, 0x21, 0x01, 0x16, 0, 0, 0, 0, 0, 0, 0 };
    try std.testing.expectError(error.BadHeader, lz.decompress(gpa, &bad, .xz, .{}));
    // A BCJ filter with a correct CRC: refused by name, not misread.
    var h = [_]u8{ 0x02, 0x00, 0x04, 0x00, 0, 0, 0, 0, 0, 0, 0, 0 };
    std.mem.writeInt(u32, h[8..12], std.hash.Crc32.hash(h[0..8]), .little);
    const s = header ++ h;
    try std.testing.expectError(error.UnsupportedFilter, lz.decompress(gpa, &s, .xz, .{}));
    // Not an xz file at all.
    try std.testing.expectError(error.BadMagic, lz.decompress(gpa, "hello world, hello world", .xz, .{}));
    try std.testing.expectError(error.TruncatedInput, lz.decompress(gpa, "", .xz, .{}));
}

test "xz: the reader API, one byte at a time, across a wrapped dictionary" {
    var plain: [150_000]u8 = undefined;
    lz.interop_corpus.fill(&plain, .{ .name = "", .kind = .text, .len = plain.len });
    var o = lz.preset(1, false);
    o.dict_size = 4096;
    const z = try lz.compress(gpa, &plain, .xz, .{ .lzma = o });
    defer gpa.free(z);
    var in: std.Io.Reader = .fixed(z);
    var buf: [1]u8 = undefined;
    var r = try lz.DecompressReader.init(gpa, &in, &buf, .xz, .{});
    defer r.deinit();
    var at: usize = 0;
    while (r.reader.takeByte()) |b| : (at += 1) {
        if (b != plain[at]) return error.WrongByte;
    } else |e| try std.testing.expectEqual(error.EndOfStream, e);
    try std.testing.expectEqual(plain.len, at);
}

test "xz: concatenated streams, padding, and the single-stream option" {
    const a = try lz.compress(gpa, "first ", .xz, .{});
    defer gpa.free(a);
    const b = try lz.compress(gpa, "second", .xz, .{});
    defer gpa.free(b);
    const two = try std.mem.concat(gpa, u8, &.{ a, &.{ 0, 0, 0, 0 }, b, &.{ 0, 0, 0, 0 } });
    defer gpa.free(two);
    const out = try lz.decompress(gpa, two, .xz, .{});
    defer gpa.free(out);
    try std.testing.expectEqualStrings("first second", out);
    try std.testing.expectError(error.TrailingData, lz.decompress(gpa, two, .xz, .{ .multi_stream = false }));
    const one = try lz.decompress(gpa, two, .xz, .{ .multi_stream = false, .ignore_trailing_garbage = true });
    defer gpa.free(one);
    try std.testing.expectEqualStrings("first ", one);
    // Padding must be a multiple of four.
    const odd = try std.mem.concat(gpa, u8, &.{ a, &.{ 0, 0 } });
    defer gpa.free(odd);
    try std.testing.expectError(error.BadFooter, lz.decompress(gpa, odd, .xz, .{}));
}

test "xz: every check type is verified" {
    const plain = "check me, check me, check me";
    for ([_]lz.Check{ .none, .crc32, .crc64, .sha256 }) |chk| {
        const z = try lz.compress(gpa, plain, .xz, .{ .check = chk });
        defer gpa.free(z);
        const ok = try lz.decompress(gpa, z, .xz, .{});
        gpa.free(ok);
        if (chk == .none) continue;
        // The check field sits right before the index; the footer says how long that is.
        const check_len: usize = switch (chk) {
            .crc32 => 4,
            .crc64 => 8,
            else => 32,
        };
        const index_len = (@as(usize, std.mem.readInt(u32, z[z.len - 8 ..][0..4], .little)) + 1) * 4;
        const at = z.len - 12 - index_len - check_len;
        var bad = try gpa.dupe(u8, z);
        defer gpa.free(bad);
        bad[at] ^= 1;
        try std.testing.expectError(error.CheckMismatch, lz.decompress(gpa, bad, .xz, .{}));
    }
}
