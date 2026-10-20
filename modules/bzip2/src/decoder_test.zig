// SPDX-License-Identifier: MIT

const std = @import("std");
const testing = std.testing;
const bz = @import("root.zig");
const corpus = @import("shapes.zig");

fn shapeBytes(gpa: std.mem.Allocator, name: []const u8, len: ?usize) ![]u8 {
    var s = corpus.find(name).?;
    if (len) |l| s.len = l;
    return corpus.generate(gpa, s);
}

fn packed_(gpa: std.mem.Allocator, plain: []const u8, level: u4) ![]u8 {
    return bz.compress(gpa, plain, .{ .level = level });
}

test "decoder: pulled through a reader that gives a few bytes at a time" {
    const gpa = testing.allocator;
    const plain = try shapeBytes(gpa, "text-150k", null);
    defer gpa.free(plain);
    const z = try packed_(gpa, plain, 1);
    defer gpa.free(z);
    for ([_]usize{ 1, 5, 13, 4096 }) |piece| {
        var calls: [1]std.testing.Reader.Call = .{.{ .buffer = z }};
        var ibuf: [16]u8 = undefined;
        var tr: std.testing.Reader = .init(&ibuf, &calls);
        tr.artificial_limit = .limited(piece);
        var r = try bz.DecompressReader.init(gpa, &tr.interface, &.{}, .{});
        defer r.deinit();
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        _ = try r.reader.streamRemaining(&out.writer);
        try testing.expectEqualSlices(u8, plain, out.written());
        try testing.expect(r.err == null);
    }
}

test "decoder: a buffered DecompressReader reads lines and ints like any reader" {
    const gpa = testing.allocator;
    const z = try packed_(gpa, "alpha\nbeta\ngamma\n", 1);
    defer gpa.free(z);
    var in: std.Io.Reader = .fixed(z);
    var buf: [8]u8 = undefined;
    var r = try bz.DecompressReader.init(gpa, &in, &buf, .{});
    defer r.deinit();
    try testing.expectEqualStrings("alpha", (try r.reader.takeDelimiter('\n')).?);
    try testing.expectEqualStrings("beta", (try r.reader.takeDelimiter('\n')).?);
    try testing.expectEqualStrings("gamma", (try r.reader.takeDelimiter('\n')).?);
    try testing.expect((try r.reader.takeDelimiter('\n')) == null);
}

test "decoder: a failure is ReadFailed with the cause in err" {
    const gpa = testing.allocator;
    var bad = try packed_(gpa, "hello world, hello world", 1);
    defer gpa.free(bad);
    bad[bad.len - 6] ^= 0x40;
    var in: std.Io.Reader = .fixed(bad);
    var r = try bz.DecompressReader.init(gpa, &in, &.{}, .{});
    defer r.deinit();
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try testing.expectError(error.ReadFailed, r.reader.streamRemaining(&out.writer));
    try testing.expect(r.err != null);
}

test "bomb cap: output past max_output is refused, at the cap it is not" {
    const gpa = testing.allocator;
    const plain = try shapeBytes(gpa, "zeros-2m", null);
    defer gpa.free(plain);
    const z = try packed_(gpa, plain, 9);
    defer gpa.free(z);
    try testing.expect(z.len < 1000);
    const ok = try bz.decompress(gpa, z, .{ .max_output = plain.len });
    gpa.free(ok);
    try testing.expectError(error.OutputTooLarge, bz.decompress(gpa, z, .{ .max_output = plain.len - 1 }));
    try testing.expectError(error.OutputTooLarge, bz.decompress(gpa, z, .{ .max_output = 1000 }));
    try testing.expectError(error.OutputTooLarge, bz.decompress(gpa, z, .{ .max_output = 0 }));
    const empty = try packed_(gpa, "", 1);
    defer gpa.free(empty);
    const none = try bz.decompress(gpa, empty, .{ .max_output = 0 });
    gpa.free(none);
}

test "every proper prefix of a stream is refused, and none panics" {
    const gpa = testing.allocator;
    const plain = try shapeBytes(gpa, "text-small", 700);
    defer gpa.free(plain);
    const z = try packed_(gpa, plain, 1);
    defer gpa.free(z);
    for (0..z.len) |n| {
        if (bz.decompress(gpa, z[0..n], .{})) |out| {
            gpa.free(out);
            return error.PrefixAccepted;
        } else |e| try testing.expect(e == error.TruncatedInput or e == error.TrailingData or e == error.BadMagic);
    }
}

test "every single-bit flip is refused or reads back exactly; the error paths are all reached" {
    const gpa = testing.allocator;
    const plain = try shapeBytes(gpa, "text-small", 600);
    defer gpa.free(plain);
    const z = try packed_(gpa, plain, 1);
    defer gpa.free(z);
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(gpa);
    for (0..z.len * 8) |bit| {
        z[bit / 8] ^= @as(u8, 1) << @intCast(bit % 8);
        defer z[bit / 8] ^= @as(u8, 1) << @intCast(bit % 8);
        if (bz.decompress(gpa, z, .{})) |out| {
            defer gpa.free(out);
            try testing.expectEqualSlices(u8, plain, out);
        } else |e| try seen.put(gpa, @errorName(e), {});
    }
    for ([_][]const u8{ "BadMagic", "BadBlockHeader", "BlockCrcMismatch", "StreamCrcMismatch" }) |e| {
        try testing.expect(seen.contains(e));
    }
}

test "headers: what is and is not a stream" {
    const gpa = testing.allocator;
    try testing.expectError(error.TruncatedInput, bz.decompress(gpa, "", .{}));
    try testing.expectError(error.TruncatedInput, bz.decompress(gpa, "BZh", .{}));
    try testing.expectError(error.BadMagic, bz.decompress(gpa, "BZh0\x17rE8P\x90\x00\x00\x00\x00", .{}));
    try testing.expectError(error.BadMagic, bz.decompress(gpa, "BZhA\x17rE8P\x90\x00\x00\x00\x00", .{}));
    try testing.expectError(error.BadMagic, bz.decompress(gpa, "bzh9", .{}));
    try testing.expectError(error.BadMagic, bz.decompress(gpa, "\x1f\x8b\x08\x00", .{}));
    // The empty stream: header, trailer, combined CRC 0.
    const e = try bz.decompress(gpa, "BZh9\x17rE8P\x90\x00\x00\x00\x00", .{});
    defer gpa.free(e);
    try testing.expectEqual(@as(usize, 0), e.len);
    try testing.expectError(error.StreamCrcMismatch, bz.decompress(gpa, "BZh9\x17rE8P\x90\x00\x00\x00\x01", .{}));
    try testing.expectError(error.BadTrailer, bz.decompress(gpa, "BZh9\x17rE8P\x91\x00\x00\x00\x00", .{}));
    try testing.expectError(error.BadBlockHeader, bz.decompress(gpa, "BZh9\x18rE8P\x90\x00\x00\x00\x00", .{}));
}

test "streams back to back; trailing bytes; the options" {
    const gpa = testing.allocator;
    const a = try packed_(gpa, "first stream, ", 1);
    defer gpa.free(a);
    const b = try packed_(gpa, "second stream", 9);
    defer gpa.free(b);
    const ab = try std.mem.concat(gpa, u8, &.{ a, b, a });
    defer gpa.free(ab);
    const out = try bz.decompress(gpa, ab, .{});
    defer gpa.free(out);
    try testing.expectEqualStrings("first stream, second streamfirst stream, ", out);

    const one = try bz.decompress(gpa, ab, .{ .multi_stream = false });
    defer gpa.free(one);
    try testing.expectEqualStrings("first stream, ", one);

    for ([_][]const u8{ "junk", "BZ", "\x00\x00\x00\x00" }) |tail| {
        const with_tail = try std.mem.concat(gpa, u8, &.{ a, tail });
        defer gpa.free(with_tail);
        try testing.expectError(error.TrailingData, bz.decompress(gpa, with_tail, .{}));
        const lenient = try bz.decompress(gpa, with_tail, .{ .ignore_trailing_garbage = true });
        defer gpa.free(lenient);
        try testing.expectEqualStrings("first stream, ", lenient);
        const first_only = try bz.decompress(gpa, with_tail, .{ .multi_stream = false });
        defer gpa.free(first_only);
        try testing.expectEqualStrings("first stream, ", first_only);
    }
}

test "a second stream that starts and is cut short is a truncation, not trailing garbage" {
    const gpa = testing.allocator;
    const a = try packed_(gpa, "first", 1);
    defer gpa.free(a);
    const cut = try std.mem.concat(gpa, u8, &.{ a, "BZh9" });
    defer gpa.free(cut);
    try testing.expectError(error.TruncatedInput, bz.decompress(gpa, cut, .{}));
    try testing.expectError(error.TruncatedInput, bz.decompress(gpa, cut, .{ .ignore_trailing_garbage = true }));
}

test "randomised blocks (bzip2 0.9.0) are read, and differ on the wire" {
    const gpa = testing.allocator;
    for ([_][]const u8{ "text-small", "run259", "all-bytes", "runs-300" }) |name| {
        const plain = try shapeBytes(gpa, name, 5000);
        defer gpa.free(plain);
        const normal = try packed_(gpa, plain, 1);
        defer gpa.free(normal);
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var enc = try bz.Encoder.init(gpa, &out.writer, .{ .level = 1 });
        defer enc.deinit();
        enc.randomise = true;
        try enc.write(plain);
        try enc.finish();
        try testing.expect(!std.mem.eql(u8, normal, out.written()));
        const back = try bz.decompress(gpa, out.written(), .{});
        defer gpa.free(back);
        try testing.expectEqualSlices(u8, plain, back);
    }
}

test "a failed decoder stays failed (every later read returns the first error)" {
    const a = std.testing.allocator;
    var r: std.Io.Reader = .fixed("BZh9" ++ "\x31\x41\x59\x26\x53\x59" ++ "\xff\xff\xff\xff\xff\xff\xff\xff");
    var d = try @import("decoder.zig").Decoder.init(a, &r, .{});
    defer d.deinit();
    var buf: [64]u8 = undefined;
    const first = d.read(&buf);
    try std.testing.expect(std.meta.isError(first));
    const e1 = if (first) |_| unreachable else |e| e;
    for (0..64) |_| try std.testing.expectError(e1, d.read(&buf));
}

test "the encoder refuses a second finish and a write after finish" {
    const a = std.testing.allocator;
    var out: std.Io.Writer.Allocating = .init(a);
    defer out.deinit();
    var e = try @import("encoder.zig").Encoder.init(a, &out.writer, .{});
    defer e.deinit();
    try e.write("abc");
    try e.finish();
    try std.testing.expectError(error.AlreadyFinished, e.finish());
    try std.testing.expectError(error.AlreadyFinished, e.write("x"));
}
