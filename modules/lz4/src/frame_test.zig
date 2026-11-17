// SPDX-License-Identifier: MIT

//! Frame decoder and encoder tests on hand-built frames. Every verdict below
//! was first observed on liblz4 1.10.0 (`lz4.frame.decompress` of
//! python-lz4 4.4.5 and `lz4 -d`), except where a comment says the module
//! departs from it on purpose (see SPEC.md "Behaviour choices").

const std = @import("std");
const testing = std.testing;
const lz4 = @import("root.zig");
const XxHash32 = std.hash.XxHash32;

const gpa = testing.allocator;

/// A frame assembled by hand.
const Builder = struct {
    list: std.ArrayList(u8) = .empty,

    fn deinit(b: *Builder) void {
        b.list.deinit(gpa);
    }

    fn bytes(b: *Builder, s: []const u8) !void {
        try b.list.appendSlice(gpa, s);
    }

    fn u32le(b: *Builder, v: u32) !void {
        var w: [4]u8 = undefined;
        std.mem.writeInt(u32, &w, v, .little);
        try b.bytes(&w);
    }

    const Header = struct {
        flg: u8 = 0x60,
        bd: u8 = 0x40,
        size: ?u64 = null,
        dict_id: ?u32 = null,
        hc: ?u8 = null,
    };

    fn header(b: *Builder, h: Header) !void {
        try b.u32le(lz4.frame_magic);
        var desc: [14]u8 = undefined;
        desc[0] = h.flg | @as(u8, if (h.size != null) 0x08 else 0) | @as(u8, if (h.dict_id != null) 0x01 else 0);
        desc[1] = h.bd;
        var n: usize = 2;
        if (h.size) |s| {
            std.mem.writeInt(u64, desc[n..][0..8], s, .little);
            n += 8;
        }
        if (h.dict_id) |d| {
            std.mem.writeInt(u32, desc[n..][0..4], d, .little);
            n += 4;
        }
        try b.bytes(desc[0..n]);
        try b.list.append(gpa, h.hc orelse @truncate(XxHash32.hash(0, desc[0..n]) >> 8));
    }

    fn stored(b: *Builder, data: []const u8) !void {
        try b.u32le(@as(u32, @intCast(data.len)) | 0x8000_0000);
        try b.bytes(data);
    }

    fn compressed(b: *Builder, data: []const u8) !void {
        try b.u32le(@intCast(data.len));
        try b.bytes(data);
    }

    fn end(b: *Builder) !void {
        try b.u32le(0);
    }
};

fn expectDecodes(want: []const u8, frame: []const u8, opts: lz4.DecodeOptions) !void {
    const got = try lz4.decompress(gpa, frame, opts);
    defer gpa.free(got);
    try testing.expectEqualSlices(u8, want, got);
}

test "frame: stored and compressed blocks, content size, dictionary id" {
    {
        var b: Builder = .{};
        defer b.deinit();
        try b.header(.{});
        try b.stored("hello ");
        try b.compressed("\x50world");
        try b.end();
        try expectDecodes("hello world", b.list.items, .{});
    }
    {
        var b: Builder = .{};
        defer b.deinit();
        try b.header(.{ .size = 11, .dict_id = 7 });
        try b.stored("hello world");
        try b.end();
        try expectDecodes("hello world", b.list.items, .{});
    }
    {
        // A declared size of 0 is "unknown" to liblz4.
        var b: Builder = .{};
        defer b.deinit();
        try b.header(.{ .size = 0 });
        try b.stored("hello world");
        try b.end();
        try expectDecodes("hello world", b.list.items, .{});
    }
    {
        // A stored block of length 0 (the size word 0x80000000) is no end mark.
        var b: Builder = .{};
        defer b.deinit();
        try b.header(.{});
        try b.stored("");
        try b.stored("x");
        try b.end();
        try expectDecodes("x", b.list.items, .{});
    }
}

test "frame: header refusals" {
    const Case = struct { h: Builder.Header, err: anyerror };
    const cases = [_]Case{
        .{ .h = .{ .flg = 0x62 }, .err = error.ReservedBitSet },
        .{ .h = .{ .bd = 0xc0 }, .err = error.ReservedBitSet },
        .{ .h = .{ .bd = 0x41 }, .err = error.ReservedBitSet },
        .{ .h = .{ .bd = 0x48 }, .err = error.ReservedBitSet },
        .{ .h = .{ .bd = 0x30 }, .err = error.BadBlockSize },
        .{ .h = .{ .bd = 0x00 }, .err = error.BadBlockSize },
        .{ .h = .{ .flg = 0x20 }, .err = error.BadVersion },
        .{ .h = .{ .flg = 0xa0 }, .err = error.BadVersion },
        .{ .h = .{ .flg = 0xe0 }, .err = error.BadVersion },
        .{ .h = .{ .hc = 0 }, .err = error.HeaderChecksumMismatch },
    };
    for (cases) |c| {
        var b: Builder = .{};
        defer b.deinit();
        try b.header(c.h);
        try b.stored("hello world");
        try b.end();
        try testing.expectError(c.err, lz4.decompress(gpa, b.list.items, .{}));
    }
    // The header checksum covers the optional fields too.
    var b: Builder = .{};
    defer b.deinit();
    try b.header(.{ .size = 11 });
    try b.stored("hello world");
    try b.end();
    b.list.items[7] ^= 1;
    try testing.expectError(error.HeaderChecksumMismatch, lz4.decompress(gpa, b.list.items, .{}));
}

test "frame: content size must match" {
    for ([_]u64{ 5, 10, 12, 50 }) |declared| {
        var b: Builder = .{};
        defer b.deinit();
        try b.header(.{ .size = declared });
        try b.stored("hello world");
        try b.end();
        try testing.expectError(error.ContentSizeMismatch, lz4.decompress(gpa, b.list.items, .{}));
    }
}

test "frame: block size limits per block maximum" {
    const big = try gpa.alloc(u8, 4 << 20 | 1);
    defer gpa.free(big);
    @memset(big, 'a');
    const maxes = [_]struct { bd: u8, n: usize }{
        .{ .bd = 0x40, .n = 64 << 10 },
        .{ .bd = 0x50, .n = 256 << 10 },
        .{ .bd = 0x60, .n = 1 << 20 },
        .{ .bd = 0x70, .n = 4 << 20 },
    };
    for (maxes) |m| {
        {
            var b: Builder = .{};
            defer b.deinit();
            try b.header(.{ .bd = m.bd });
            try b.stored(big[0..m.n]);
            try b.end();
            const got = try lz4.decompress(gpa, b.list.items, .{});
            defer gpa.free(got);
            try testing.expectEqual(m.n, got.len);
        }
        {
            var b: Builder = .{};
            defer b.deinit();
            try b.header(.{ .bd = m.bd });
            try b.stored(big[0 .. m.n + 1]);
            try b.end();
            try testing.expectError(error.BlockTooLarge, lz4.decompress(gpa, b.list.items, .{}));
        }
        {
            // A compressed block that decodes to one byte more than the maximum.
            var z: std.ArrayList(u8) = .empty;
            defer z.deinit(gpa);
            try z.appendSlice(gpa, "\x1fa\x01\x00");
            var rest = m.n + 1 - 1 - 5 - 4 - 15;
            while (rest >= 255) : (rest -= 255) try z.append(gpa, 255);
            try z.append(gpa, @intCast(rest));
            try z.appendSlice(gpa, "\x50aaaaa");
            var b: Builder = .{};
            defer b.deinit();
            try b.header(.{ .bd = m.bd });
            try b.compressed(z.items);
            try b.end();
            try testing.expectError(error.BlockTooLarge, lz4.decompress(gpa, b.list.items, .{}));
            // ... and with the match one shorter it fits exactly.
            var c = z.items[z.items.len - 7];
            c -%= 1;
            z.items[z.items.len - 7] = c;
            var b2: Builder = .{};
            defer b2.deinit();
            try b2.header(.{ .bd = m.bd });
            try b2.compressed(z.items);
            try b2.end();
            const got = try lz4.decompress(gpa, b2.list.items, .{});
            defer gpa.free(got);
            try testing.expectEqual(m.n, got.len);
        }
    }
}

test "frame: checksums" {
    const data = "hello world";
    const good = XxHash32.hash(0, data);
    {
        var b: Builder = .{};
        defer b.deinit();
        try b.header(.{ .flg = 0x64 });
        try b.stored(data);
        try b.end();
        try b.u32le(good);
        try expectDecodes(data, b.list.items, .{});
        b.list.items[b.list.items.len - 1] ^= 0x80;
        try testing.expectError(error.ContentChecksumMismatch, lz4.decompress(gpa, b.list.items, .{}));
        try expectDecodes(data, b.list.items, .{ .verify_checksums = false });
        // The checksum itself missing.
        try testing.expectError(error.TruncatedInput, lz4.decompress(gpa, b.list.items[0 .. b.list.items.len - 1], .{}));
    }
    {
        var b: Builder = .{};
        defer b.deinit();
        try b.header(.{ .flg = 0x70 });
        try b.stored(data);
        try b.u32le(good);
        try b.compressed("\x10!");
        try b.u32le(XxHash32.hash(0, "\x10!")); // over the stored bytes, not the output
        try b.end();
        try expectDecodes("hello world!", b.list.items, .{});
        b.list.items[b.list.items.len - 5] ^= 1;
        try testing.expectError(error.BlockChecksumMismatch, lz4.decompress(gpa, b.list.items, .{}));
        try expectDecodes("hello world!", b.list.items, .{ .verify_checksums = false });
    }
}

test "frame: XxHash32 agrees with the values the lz4 CLI writes" {
    // Content checksums of `printf %s <s> | lz4 -c` (lz4 v1.10.0).
    try testing.expectEqual(@as(u32, 0x02CC5D05), XxHash32.hash(0, ""));
    try testing.expectEqual(@as(u32, 0x550D7456), XxHash32.hash(0, "a"));
    try testing.expectEqual(@as(u32, 0x32D153FF), XxHash32.hash(0, "abc"));
    try testing.expectEqual(@as(u32, 0xE2293B2F), XxHash32.hash(0, "Nobody inspects the spammish repetition"));
}

test "frame: linked and independent blocks" {
    // Block 2 refers 6 bytes back, into block 1.
    var b: Builder = .{};
    defer b.deinit();
    try b.header(.{ .flg = 0x40 });
    try b.compressed("\x60hello ");
    try b.compressed("\x01\x06\x00\x10!");
    try b.end();
    try expectDecodes("hello hello!", b.list.items, .{});
    b.list.items[4] = 0x60; // the same blocks, declared independent
    b.list.items[6] = @truncate(XxHash32.hash(0, b.list.items[4..6]) >> 8);
    try testing.expectError(error.BadOffset, lz4.decompress(gpa, b.list.items, .{}));
}

test "frame: a match never reaches into the previous frame" {
    var b: Builder = .{};
    defer b.deinit();
    try b.header(.{ .flg = 0x40 });
    try b.compressed("\x60hello ");
    try b.end();
    try b.header(.{ .flg = 0x40 });
    try b.compressed("\x00\x06\x00\x10!");
    try b.end();
    try testing.expectError(error.BadOffset, lz4.decompress(gpa, b.list.items, .{}));
}

test "frame: malformed compressed blocks" {
    for ([_][]const u8{ "\x10a\x01\x00", "\x20a", "\x10ab" }) |blk| {
        var b: Builder = .{};
        defer b.deinit();
        try b.header(.{});
        try b.compressed(blk);
        try b.end();
        try testing.expectError(error.CorruptBlock, lz4.decompress(gpa, b.list.items, .{}));
    }
    // Offset 0: liblz4 decodes it as zero bytes; the format calls the block
    // corrupted and so does this module.
    var b: Builder = .{};
    defer b.deinit();
    try b.header(.{});
    try b.compressed("\x50hello\x00\x00\x50world");
    try b.end();
    try testing.expectError(error.BadOffset, lz4.decompress(gpa, b.list.items, .{}));
}

test "frame: truncation anywhere is TruncatedInput" {
    var b: Builder = .{};
    defer b.deinit();
    try b.header(.{ .flg = 0x74, .size = 11 });
    try b.stored("hello world");
    try b.u32le(XxHash32.hash(0, "hello world"));
    try b.end();
    try b.u32le(XxHash32.hash(0, "hello world"));
    try expectDecodes("hello world", b.list.items, .{});
    for (1..b.list.items.len) |cut| {
        const r = lz4.decompress(gpa, b.list.items[0..cut], .{});
        if (r) |ok| {
            gpa.free(ok);
            return error.TestUnexpectedResult;
        } else |e| try testing.expectEqual(error.TruncatedInput, e);
    }
}

test "frame: concatenation, skippable frames, trailing data" {
    var one: Builder = .{};
    defer one.deinit();
    try one.header(.{});
    try one.stored("ab");
    try one.end();

    var b: Builder = .{};
    defer b.deinit();
    try b.bytes(one.list.items);
    try b.u32le(lz4.skippable_magic_base + 0xF);
    try b.u32le(3);
    try b.bytes("xyz");
    try b.bytes(one.list.items);
    try expectDecodes("abab", b.list.items, .{});
    // One frame only, the rest is trailing data unless ignored.
    try testing.expectError(error.TrailingData, lz4.decompress(gpa, b.list.items, .{ .multi_frame = false }));
    try expectDecodes("ab", b.list.items, .{ .multi_frame = false, .ignore_trailing_garbage = true });
    // A skippable frame alone.
    try expectDecodes("", b.list.items[one.list.items.len..][0..11], .{});
    // A truncated skippable frame.
    try testing.expectError(error.TruncatedInput, lz4.decompress(gpa, b.list.items[one.list.items.len..][0..10], .{}));
    try testing.expectError(error.TruncatedInput, lz4.decompress(gpa, b.list.items[one.list.items.len..][0..7], .{}));

    // Junk after a frame: whole words, a partial word, zeros.
    for ([_][]const u8{ "junkjunk", "ju", "\x00\x00\x00\x00", "\x04\x22\x4d" }) |junk| {
        var t: Builder = .{};
        defer t.deinit();
        try t.bytes(one.list.items);
        try t.bytes(junk);
        try testing.expectError(error.TrailingData, lz4.decompress(gpa, t.list.items, .{}));
        try expectDecodes("ab", t.list.items, .{ .ignore_trailing_garbage = true });
    }
    // Junk first is not a frame at all.
    try testing.expectError(error.BadMagic, lz4.decompress(gpa, "junkjunk", .{ .ignore_trailing_garbage = true }));
    try testing.expectError(error.TruncatedInput, lz4.decompress(gpa, "\x04\x22\x4d", .{}));
    // Empty input is empty output (the lz4 CLI).
    try expectDecodes("", "", .{});
    // A header alone, without blocks or end mark.
    try testing.expectError(error.TruncatedInput, lz4.decompress(gpa, one.list.items[0..7], .{}));
}

test "frame: legacy frames" {
    // `printf 'hello hello hello hello world\n' | lz4 -l` (lz4 v1.10.0).
    const leg = "\x02\x21\x4c\x18\x10\x00\x00\x00\x6e\x68\x65\x6c\x6c\x6f\x20\x06\x00\x60\x77\x6f\x72\x6c\x64\x0a";
    const text = "hello hello hello hello world\n";
    try expectDecodes(text, leg, .{});
    // Two legacy frames, a legacy frame then an LZ4 frame and the reverse.
    var lz: [64]u8 = undefined;
    const n = try lz4.compressInto(text, &lz, .{});
    var b: Builder = .{};
    defer b.deinit();
    try b.bytes(leg);
    try b.bytes(leg);
    try b.bytes(lz[0..n]);
    try b.bytes(leg);
    try expectDecodes(text ++ text ++ text ++ text, b.list.items, .{});
    // The magic alone is an empty legacy frame.
    try expectDecodes("", leg[0..4], .{});
    // A partial block size, a block size of 0, a truncated block.
    try testing.expectError(error.TruncatedInput, lz4.decompress(gpa, leg ++ "\x01\x00", .{}));
    try testing.expectError(error.CorruptBlock, lz4.decompress(gpa, leg ++ "\x00\x00\x00\x00", .{}));
    try testing.expectError(error.TruncatedInput, lz4.decompress(gpa, leg[0 .. leg.len - 1], .{}));
    // A block size over LZ4_COMPRESSBOUND(8 MiB).
    try testing.expectError(error.BlockTooLarge, lz4.decompress(gpa, leg[0..4] ++ "\x00\x00\x90\x00", .{}));
    // Legacy blocks are independent of each other.
    try testing.expectError(error.BadOffset, lz4.decompress(gpa, leg ++ "\x05\x00\x00\x00\x00\x02\x00\x10!", .{}));
}

test "frame: the output cap" {
    const zeros = try gpa.alloc(u8, 1 << 20);
    defer gpa.free(zeros);
    @memset(zeros, 0);
    const z = try lz4.compress(gpa, zeros, .{});
    defer gpa.free(z);
    try testing.expect(z.len < 10_000);
    try testing.expectError(error.OutputTooLarge, lz4.decompress(gpa, z, .{ .max_output = (1 << 20) - 1 }));
    try expectDecodes(zeros, z, .{ .max_output = 1 << 20 });
    try expectDecodes(zeros, z, .{ .max_output = null });
    // Stored blocks are capped too.
    var b: Builder = .{};
    defer b.deinit();
    try b.header(.{});
    try b.stored("hello world");
    try b.end();
    try testing.expectError(error.OutputTooLarge, lz4.decompress(gpa, b.list.items, .{ .max_output = 10 }));
    try expectDecodes("hello world", b.list.items, .{ .max_output = 11 });
    // A declared size over the cap is refused before any block is read.
    var d: Builder = .{};
    defer d.deinit();
    try d.header(.{ .size = 1 << 40 });
    try testing.expectError(error.OutputTooLarge, lz4.decompress(gpa, d.list.items, .{}));
    // The cap counts the frames before this one.
    var two: Builder = .{};
    defer two.deinit();
    try two.bytes(b.list.items);
    try two.header(.{ .size = 11 });
    try two.stored("hello world");
    try two.end();
    try testing.expectError(error.OutputTooLarge, lz4.decompress(gpa, two.list.items, .{ .max_output = 21 }));
    try expectDecodes("hello worldhello world", two.list.items, .{ .max_output = 22 });
}

test "frame: encoder options round trip and set the header bits" {
    var prng = std.Random.DefaultPrng.init(11);
    const r = prng.random();
    const input = try gpa.alloc(u8, 300_000);
    defer gpa.free(input);
    for (input, 0..) |*c, i| c.* = if (r.uintLessThan(u8, 8) == 0) r.int(u8) else "lz4 frame test "[i % 15];
    for ([_]lz4.BlockSize{ .max64KB, .max256KB, .max1MB, .max4MB }) |bs| {
        for (0..16) |bits| {
            const opts: lz4.EncodeOptions = .{
                .block_size = bs,
                .independent_blocks = bits & 1 != 0,
                .block_checksum = bits & 2 != 0,
                .content_checksum = bits & 4 != 0,
                .content_size = bits & 8 != 0,
            };
            const z = try lz4.compress(gpa, input, opts);
            defer gpa.free(z);
            try testing.expect(z.len <= lz4.compressBound(input.len, opts));
            try testing.expectEqual(@as(u8, 0x40 | @as(u8, @intCast((bits & 1) << 5 | (bits & 2) << 3 | (bits & 4) | (bits & 8)))), z[4]);
            try testing.expectEqual(@as(u8, @backingInt(bs)) << 4, z[5]);
            try expectDecodes(input, z, .{});
        }
    }
}

test "frame: linked blocks compress better than independent ones" {
    // 64 KB blocks of the same random 40 KB pattern: a linked block can match
    // the previous block, an independent one cannot.
    var prng = std.Random.DefaultPrng.init(5);
    const input = try gpa.alloc(u8, 400_000);
    defer gpa.free(input);
    var pat: [40_000]u8 = undefined;
    prng.random().bytes(&pat);
    for (input, 0..) |*c, i| c.* = pat[i % pat.len];
    const linked = try lz4.compress(gpa, input, .{});
    defer gpa.free(linked);
    const indep = try lz4.compress(gpa, input, .{ .independent_blocks = true });
    defer gpa.free(indep);
    try testing.expect(linked.len * 4 < indep.len);
    try expectDecodes(input, linked, .{});
    try expectDecodes(input, indep, .{});
}

test "frame: incompressible blocks are stored, empty input is a header and an end mark" {
    var buf: [100_000]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(9);
    prng.random().bytes(&buf);
    const z = try lz4.compress(gpa, &buf, .{});
    defer gpa.free(z);
    // Header 7, two stored blocks with their size words, end mark.
    try testing.expectEqual(@as(usize, 7 + 4 + 65536 + 4 + (100_000 - 65536) + 4), z.len);
    try testing.expect(std.mem.readInt(u32, z[7..11], .little) & 0x8000_0000 != 0);
    try expectDecodes(&buf, z, .{});

    const e = try lz4.compress(gpa, "", .{ .content_checksum = true });
    defer gpa.free(e);
    try testing.expectEqualSlices(u8, "\x04\x22\x4d\x18\x44\x40\x5e\x00\x00\x00\x00\x05\x5d\xcc\x02", e);
}

test "frame: compressInto reports a short buffer" {
    var buf: [1000]u8 = undefined;
    @memset(&buf, 'x');
    var dst: [64]u8 = undefined;
    for (0..20) |n| try testing.expectError(error.NoSpaceLeft, lz4.compressInto(&buf, dst[0..n], .{}));
    var prng = std.Random.DefaultPrng.init(2);
    prng.random().bytes(&buf);
    var big: [2000]u8 = undefined;
    const need = lz4.compressBound(buf.len, .{ .block_checksum = true, .content_checksum = true });
    try testing.expect(need <= big.len);
    _ = try lz4.compressInto(&buf, big[0..need], .{ .block_checksum = true, .content_checksum = true });
    for ([_]usize{ need - 1, need - 4, need - 5, need - 8, 900 }) |n| {
        try testing.expectError(error.NoSpaceLeft, lz4.compressInto(&buf, big[0..n], .{ .block_checksum = true, .content_checksum = true }));
    }
}

test "block API: compressBlock then decompressBlock" {
    const text = "lz4 block api lz4 block api lz4 block api lz4 block api";
    var z: [lz4.compressBlockBound(text.len)]u8 = undefined;
    const n = try lz4.compressBlock(text, &z, .{});
    try testing.expect(n < text.len);
    var out: [text.len]u8 = undefined;
    try testing.expectEqual(text.len, try lz4.decompressBlock(z[0..n], &out));
    try testing.expectEqualStrings(text, &out);
    try testing.expectError(error.OutputTooSmall, lz4.decompressBlock(z[0..n], out[0 .. text.len - 1]));
}
