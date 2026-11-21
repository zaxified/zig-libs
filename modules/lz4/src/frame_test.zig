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
    // `decompressInto` agrees, into an exact buffer and into a larger one.
    const buf = try gpa.alloc(u8, want.len + 7);
    defer gpa.free(buf);
    try testing.expectEqual(want.len, try lz4.decompressInto(frame, buf[0..want.len], opts));
    try testing.expectEqualSlices(u8, want, buf[0..want.len]);
    @memset(buf, 0xAA);
    try testing.expectEqual(want.len, try lz4.decompressInto(frame, buf, opts));
    try testing.expectEqualSlices(u8, want, buf[0..want.len]);
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
    // A word over LZ4_COMPRESSBOUND(8 MiB) is not a block size: it ends the
    // legacy frame and is read as what follows, here junk (the lz4 CLI:
    // "Stream followed by undecodable data", the legacy output written).
    inline for (.{ "\x00\x00\x90\x00", "\x00\x00\x90\x00more junk", "junk", "\xff\xff\xff\xff" }) |junk| {
        try testing.expectError(error.TrailingData, lz4.decompress(gpa, leg ++ junk, .{}));
        try expectDecodes(text, leg ++ junk, .{ .ignore_trailing_garbage = true });
        try testing.expectError(error.TrailingData, lz4.decompress(gpa, leg[0..4] ++ junk, .{}));
        try expectDecodes("", leg[0..4] ++ junk, .{ .ignore_trailing_garbage = true });
    }
    // One frame only: the junk after the legacy frame is trailing data too.
    try testing.expectError(error.TrailingData, lz4.decompress(gpa, leg ++ "junk", .{ .multi_frame = false }));
    try expectDecodes(text, leg ++ "junk", .{ .multi_frame = false, .ignore_trailing_garbage = true });
    // A word within the bound is a block size, junk or not.
    try testing.expectError(error.TruncatedInput, lz4.decompress(gpa, leg ++ "\x00\x00\x80\x00", .{ .ignore_trailing_garbage = true }));
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

test "decompressInto: the buffer is the cap, nothing past the output is needed" {
    // A compressed block (1 MiB of zeros in 16 blocks), a stored block, a
    // declared size, a legacy frame: one byte short is OutputTooLarge, exact
    // and larger buffers decode, the smaller of `dst.len` and `max_output` wins.
    const zeros = try gpa.alloc(u8, 1 << 20);
    defer gpa.free(zeros);
    @memset(zeros, 0);
    const z = try lz4.compress(gpa, zeros, .{});
    defer gpa.free(z);
    var s: Builder = .{};
    defer s.deinit();
    try s.header(.{});
    try s.stored("hello world");
    try s.end();
    var sized: Builder = .{};
    defer sized.deinit();
    try sized.header(.{ .size = 11 });
    try sized.stored("hello world");
    try sized.end();
    // `printf 'hello hello hello hello world\n' | lz4 -l` (lz4 v1.10.0).
    const leg = "\x02\x21\x4c\x18\x10\x00\x00\x00\x6e\x68\x65\x6c\x6c\x6f\x20\x06\x00\x60\x77\x6f\x72\x6c\x64\x0a";
    const cases = [_]struct { want: []const u8, frame: []const u8 }{
        .{ .want = zeros, .frame = z },
        .{ .want = "hello world", .frame = s.list.items },
        .{ .want = "hello world", .frame = sized.list.items },
        .{ .want = "hello hello hello hello world\n", .frame = leg },
    };
    const buf = try gpa.alloc(u8, (1 << 20) + 64);
    defer gpa.free(buf);
    for (cases) |c| {
        try testing.expectError(error.OutputTooLarge, lz4.decompressInto(c.frame, buf[0 .. c.want.len - 1], .{}));
        try testing.expectError(error.OutputTooLarge, lz4.decompressInto(c.frame, buf, .{ .max_output = c.want.len - 1 }));
        try testing.expectError(error.OutputTooLarge, lz4.decompressInto(c.frame, buf[0 .. c.want.len - 1], .{ .max_output = null }));
        try testing.expectEqual(c.want.len, try lz4.decompressInto(c.frame, buf[0..c.want.len], .{ .max_output = null }));
        try testing.expectEqualSlices(u8, c.want, buf[0..c.want.len]);
        try testing.expectEqual(c.want.len, try lz4.decompressInto(c.frame, buf, .{ .max_output = c.want.len }));
        try testing.expectEqualSlices(u8, c.want, buf[0..c.want.len]);
    }
    // A declared size over the buffer is refused before any block is read: a
    // frame whose only block is truncated still says OutputTooLarge.
    try testing.expectError(error.OutputTooLarge, lz4.decompressInto(sized.list.items[0 .. sized.list.items.len - 6], buf[0..10], .{}));
    try testing.expectError(error.TruncatedInput, lz4.decompressInto(sized.list.items[0 .. sized.list.items.len - 6], buf[0..11], .{}));
    // Empty input into an empty buffer; malformed input keeps its own error.
    try testing.expectEqual(@as(usize, 0), try lz4.decompressInto("", buf[0..0], .{}));
    try testing.expectError(error.BadMagic, lz4.decompressInto("junkjunk", buf, .{}));
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
    for ([_]usize{ need - 1, need - 4, need - 5, need - 8, need - 9, need - 12, 900 }) |n| {
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

test "frame: the cap at exactly one block maximum, and a declared size over what is left" {
    // A 64 KiB-maximum frame whose block decodes to one byte more than the
    // maximum, with exactly the maximum left of the cap: the block is at
    // fault, not the cap.
    var z: std.ArrayList(u8) = .empty;
    defer z.deinit(gpa);
    try z.appendSlice(gpa, "\x1fa\x01\x00");
    var rest: usize = 65_537 - 1 - 5 - 4 - 15;
    while (rest >= 255) : (rest -= 255) try z.append(gpa, 255);
    try z.append(gpa, @intCast(rest));
    try z.appendSlice(gpa, "\x50aaaaa");
    var b: Builder = .{};
    defer b.deinit();
    try b.header(.{});
    try b.compressed(z.items);
    try b.end();
    try testing.expectError(error.BlockTooLarge, lz4.decompress(gpa, b.list.items, .{ .max_output = 65_536 }));
    try testing.expectError(error.OutputTooLarge, lz4.decompress(gpa, b.list.items, .{ .max_output = 65_535 }));

    // The second frame declares 11 bytes with 10 left of the cap: refused
    // before its (missing) blocks are read.
    var two: Builder = .{};
    defer two.deinit();
    try two.header(.{});
    try two.stored("hello world");
    try two.end();
    try two.header(.{ .size = 11 });
    try testing.expectError(error.OutputTooLarge, lz4.decompress(gpa, two.list.items, .{ .max_output = 21 }));
    try testing.expectError(error.TruncatedInput, lz4.decompress(gpa, two.list.items, .{ .max_output = 22 }));
}

test "frame: content checksums of concatenated frames cover their own frame" {
    const one = try lz4.compress(gpa, "first frame", .{ .content_checksum = true });
    defer gpa.free(one);
    const two = try lz4.compress(gpa, "second", .{ .content_checksum = true, .block_checksum = true });
    defer gpa.free(two);
    var b: Builder = .{};
    defer b.deinit();
    try b.bytes(one);
    try b.bytes(two);
    try expectDecodes("first framesecond", b.list.items, .{});
}

test "frame: a legacy block at exactly LZ4_COMPRESSBOUND(8 MiB) is read" {
    // The size word is the largest allowed: what follows is short, so the
    // input is truncated rather than the block too large.
    var b: Builder = .{};
    defer b.deinit();
    try b.u32le(lz4.legacy_frame_magic);
    try b.u32le(@intCast(lz4.compressBlockBound(8 << 20)));
    try b.bytes("\x10a");
    try testing.expectError(error.TruncatedInput, lz4.decompress(gpa, b.list.items, .{}));
    var c: Builder = .{};
    defer c.deinit();
    try c.u32le(lz4.legacy_frame_magic);
    try c.u32le(@intCast(lz4.compressBlockBound(8 << 20) + 1));
    try c.bytes("\x10a");
    // One more is not a block size: the legacy frame (empty) ends before it.
    try testing.expectError(error.TrailingData, lz4.decompress(gpa, c.list.items, .{}));
    try expectDecodes("", c.list.items, .{ .ignore_trailing_garbage = true });
}

test "frame: every independent block decodes alone" {
    // Blocks that repeat each other: a linked frame would match across them;
    // independent ones must not, so block k decodes with no history (liblz4
    // starts each independent block with an empty table,
    // `LZ4F_compressBlock`). With block checksums the stored blocks are
    // walked by their size words.
    var prng = std.Random.DefaultPrng.init(11);
    var pat: [3000]u8 = undefined;
    prng.random().bytes(&pat);
    const input = try gpa.alloc(u8, 6 * 65_536);
    defer gpa.free(input);
    for (input, 0..) |*c, i| c.* = pat[(i * 7 + i / 5000) % pat.len];
    for ([_]u32{ 1, 3 }) |accel| {
        const z = try lz4.compress(gpa, input, .{ .independent_blocks = true, .block_checksum = true, .acceleration = accel });
        defer gpa.free(z);
        var at: usize = 7;
        var k: usize = 0;
        var compressed: usize = 0;
        var out: [65_536]u8 = undefined;
        while (true) : (k += 1) {
            const word = std.mem.readInt(u32, z[at..][0..4], .little);
            at += 4;
            if (word == 0) break;
            const len = word & 0x7FFF_FFFF;
            const data = z[at..][0..len];
            at += len + 4;
            const want = input[k * 65_536 .. @min(input.len, (k + 1) * 65_536)];
            if (word & 0x8000_0000 != 0) {
                try testing.expectEqualSlices(u8, want, data);
                continue;
            }
            compressed += 1;
            try testing.expectEqual(want.len, try lz4.decompressBlock(data, &out));
            try testing.expectEqualSlices(u8, want, out[0..want.len]);
        }
        try testing.expectEqual(@as(usize, 6), k);
        try testing.expectEqual(@as(usize, 6), compressed);
        try expectDecodes(input, z, .{});
    }
}

test "block API: a match may end exactly at the end of the output" {
    // 'a', a 4-byte match at offset 1 that fills dst, then the empty last token.
    var out: [5]u8 = undefined;
    try testing.expectEqual(@as(usize, 5), try lz4.decompressBlock("\x10a\x01\x00\x00", &out));
    try testing.expectEqualStrings("aaaaa", &out);
    try testing.expectError(error.OutputTooSmall, lz4.decompressBlock("\x10a\x01\x00\x00", out[0..4]));
}

test "block API: a match is extended to the exact first differing byte" {
    // 16 distinct bytes, the first 11 again, then 30 more distinct bytes: the
    // greedy parse is 16 literals + an 11-byte match at offset 16, then 30
    // literals: (1 + 1 + 16 + 2) + (1 + 1 + 30) = 52 bytes.
    var input: [57]u8 = undefined;
    for (input[0..16], 0..) |*c, i| c.* = @intCast(1 + 3 * i);
    @memcpy(input[16..27], input[0..11]);
    for (input[27..], 0..) |*c, i| c.* = @intCast(100 + i);
    var z: [lz4.compressBlockBound(57)]u8 = undefined;
    const n = try lz4.compressBlock(&input, &z, .{});
    try testing.expectEqual(@as(usize, 52), n);
    try testing.expectEqualSlices(u8, &.{ 0xf7, 0x01 }, z[0..2]); // 15+1 literals, match 4+7
    var back: [57]u8 = undefined;
    try testing.expectEqual(@as(usize, 57), try lz4.decompressBlock(z[0..n], &back));
    try testing.expectEqualSlices(u8, &input, &back);
}

// ── dictionaries ────────────────────────────────────────────────────────

fn dictText(a: std.mem.Allocator, n: usize, seed: u64) ![]u8 {
    return lz4.interop_corpus.generate(a, .{ .name = "dict", .kind = .text, .len = n, .seed = seed });
}

test "block dictionary: round trip, smaller than without, wrong dictionary is not silently accepted" {
    const dict = try dictText(gpa, 8000, 1);
    defer gpa.free(dict);
    // Data that repeats the dictionary's phrases but is not a copy of it.
    const data = try dictText(gpa, 3000, 1);
    defer gpa.free(data);
    var with: [4096]u8 = undefined;
    var without: [4096]u8 = undefined;
    const bound = lz4.compressBlockBound(data.len);
    try testing.expect(bound <= with.len);
    const n_dict = try lz4.compressBlockDict(gpa, data, dict, &with, .{});
    const n_plain = try lz4.compressBlock(data, &without, .{});
    try testing.expect(n_dict < n_plain);
    var out: [3000]u8 = undefined;
    const got = try lz4.decompressBlockDict(gpa, with[0..n_dict], dict, &out);
    try testing.expectEqualSlices(u8, data, out[0..got]);
    // Without the dictionary the block cannot decode (an offset reaches before its start).
    try testing.expectError(error.BadOffset, lz4.decompressBlock(with[0..n_dict], &out));
    // An empty dictionary is the plain block.
    const n_empty = try lz4.compressBlockDict(gpa, data, "", &with, .{});
    try testing.expectEqualSlices(u8, without[0..n_plain], with[0..n_empty]);
}

test "block dictionary: only the last 64 KiB - 1 bytes count; tiny inputs and dictionaries" {
    var big: [100_000]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(7);
    prng.random().bytes(&big);
    const data = big[100_000 - 5000 ..][0..2000]; // inside the tail
    var dst: [lz4.compressBlockBound(2000)]u8 = undefined;
    const n = try lz4.compressBlockDict(gpa, data, &big, &dst, .{});
    try testing.expect(n < 200); // one long match into the dictionary
    var out: [2000]u8 = undefined;
    try testing.expectEqual(@as(usize, 2000), try lz4.decompressBlockDict(gpa, dst[0..n], &big, &out));
    try testing.expectEqualSlices(u8, data, &out);
    // The same data against the first bytes only (outside the window): no help.
    const head = big[0..20_000];
    const n2 = try lz4.compressBlockDict(gpa, data, head, &dst, .{});
    try testing.expect(n2 > 1500);
    for ([_]usize{ 0, 1, 3, 12, 13 }) |len| {
        var d2: [64]u8 = undefined;
        const m = try lz4.compressBlockDict(gpa, data[0..len], "abcdefghijklmnop", &d2, .{});
        var o2: [16]u8 = undefined;
        const g = try lz4.decompressBlockDict(gpa, d2[0..m], "abcdefghijklmnop", &o2);
        try testing.expectEqualSlices(u8, data[0..len], o2[0..g]);
    }
}

fn frameDictRoundTrip(opts: lz4.EncodeOptions, id: ?u32) !void {
    const dict = try dictText(gpa, 20_000, 3);
    defer gpa.free(dict);
    const data = try dictText(gpa, 300_000, 3);
    defer gpa.free(data);
    const z = try lz4.compressDict(gpa, data, dict, id, opts);
    defer gpa.free(z);
    const back = try lz4.decompressDict(gpa, z, dict, .{});
    defer gpa.free(back);
    try testing.expectEqualSlices(u8, data, back);
    // The id field is in the header when asked for.
    try testing.expectEqual(id != null, z[4] & 1 != 0);
    if (id) |v| try testing.expectEqual(v, std.mem.readInt(u32, z[if (opts.content_size) 14 else 6..][0..4], .little));
    // Plain compress of the same data is bigger (the dictionary helps the first block at least).
    const plain = try lz4.compress(gpa, data, opts);
    defer gpa.free(plain);
    try testing.expect(z.len <= plain.len);
    // The plain decoder, without the dictionary, refuses or differs: never returns the data.
    if (lz4.decompress(gpa, z, .{})) |wrong| {
        defer gpa.free(wrong);
        try testing.expect(!std.mem.eql(u8, wrong, data));
    } else |_| {}
}

test "frame dictionary: linked and independent blocks, with and without id, size and checksums" {
    try frameDictRoundTrip(.{}, null);
    try frameDictRoundTrip(.{}, 0xCAFEBABE);
    try frameDictRoundTrip(.{ .independent_blocks = true }, 42);
    try frameDictRoundTrip(.{ .independent_blocks = true, .block_checksum = true, .content_checksum = true, .content_size = true }, null);
    try frameDictRoundTrip(.{ .block_size = .max256KB, .content_checksum = true, .content_size = true }, 7);
    try frameDictRoundTrip(.{ .acceleration = 8 }, null);
}

test "frame dictionary: empty dictionary is a plain frame plus the id; tiny and empty content; max_output holds" {
    const z0 = try lz4.compressDict(gpa, "", "dictionary bytes", 5, .{});
    defer gpa.free(z0);
    const b0 = try lz4.decompressDict(gpa, z0, "dictionary bytes", .{});
    defer gpa.free(b0);
    try testing.expectEqual(@as(usize, 0), b0.len);
    const z1 = try lz4.compressDict(gpa, "hello hello hello", "", 5, .{});
    defer gpa.free(z1);
    const b1 = try lz4.decompressDict(gpa, z1, "", .{});
    defer gpa.free(b1);
    try testing.expectEqualStrings("hello hello hello", b1);
    const dict = try dictText(gpa, 5000, 9);
    defer gpa.free(dict);
    const data = try dictText(gpa, 4000, 9);
    defer gpa.free(data);
    const z = try lz4.compressDict(gpa, data, dict, null, .{ .content_size = true });
    defer gpa.free(z);
    // The cap counts output, not the dictionary placed ahead of it.
    const ok = try lz4.decompressDict(gpa, z, dict, .{ .max_output = data.len });
    defer gpa.free(ok);
    try testing.expectEqualSlices(u8, data, ok);
    try testing.expectError(error.OutputTooLarge, lz4.decompressDict(gpa, z, dict, .{ .max_output = data.len - 1 }));
    const fa = testing.checkAllAllocationFailures(gpa, struct {
        fn f(a: std.mem.Allocator, zz: []const u8, dd: []const u8) !void {
            const r = try lz4.decompressDict(a, zz, dd, .{});
            a.free(r);
        }
    }.f, .{ z, dict });
    try fa;
}

// ── HC levels ───────────────────────────────────────────────────────────

test "hc levels: every shape round-trips as a block and a frame, linked and independent, and shrinks text" {
    const levels = [_]u8{ 3, 6, 9, 12 };
    for (lz4.interop_corpus.shapes) |sh| {
        if (sh.len > (1 << 20) + 7) continue; // the 5 MiB shape is for the bench
        const data = try lz4.interop_corpus.generate(gpa, sh);
        defer gpa.free(data);
        for (levels) |lv| {
            const dst = try gpa.alloc(u8, lz4.compressBlockBound(data.len));
            defer gpa.free(dst);
            const n = try lz4.compressBlock(data, dst, .{ .hc_level = lv });
            const back = try gpa.alloc(u8, data.len);
            defer gpa.free(back);
            try testing.expectEqual(data.len, try lz4.decompressBlock(dst[0..n], back));
            try testing.expectEqualSlices(u8, data, back);
            for ([_]bool{ false, true }) |indep| {
                const z = try lz4.compress(gpa, data, .{ .hc_level = lv, .independent_blocks = indep, .block_checksum = true, .content_checksum = true });
                defer gpa.free(z);
                const b2 = try lz4.decompress(gpa, z, .{});
                defer gpa.free(b2);
                try testing.expectEqualSlices(u8, data, b2);
            }
        }
    }
}

test "hc levels: smaller than the fast matcher on text, more attempts never grow it much, level below 3 is the fast matcher" {
    const data = try dictText(gpa, 400_000, 11);
    defer gpa.free(data);
    const dst = try gpa.alloc(u8, lz4.compressBlockBound(data.len));
    defer gpa.free(dst);
    const fast = try lz4.compressBlock(data, dst, .{});
    var prev: usize = fast;
    for ([_]u8{ 3, 5, 7, 9, 12 }) |lv| {
        const n = try lz4.compressBlock(data, dst, .{ .hc_level = lv });
        try testing.expect(n < fast);
        try testing.expect(n <= prev + prev / 50); // deeper search: no worse than 2 % up
        prev = n;
    }
    const f1 = try lz4.compressBlock(data, dst, .{ .hc_level = 1 });
    try testing.expectEqual(fast, f1);
    const too_high = try lz4.compressBlock(data, dst, .{ .hc_level = 200 });
    const l12 = try lz4.compressBlock(data, dst, .{ .hc_level = 12 });
    try testing.expectEqual(l12, too_high);
    // Into a buffer that is too small: the exact error, no overrun.
    const tiny = try gpa.alloc(u8, 100);
    defer gpa.free(tiny);
    try testing.expectError(error.NoSpaceLeft, lz4.compressBlock(data, tiny, .{ .hc_level = 9 }));
}

test "hc levels with a dictionary: block and frame, linked and independent" {
    const dict = try dictText(gpa, 30_000, 5);
    defer gpa.free(dict);
    const data = try dictText(gpa, 150_000, 5);
    defer gpa.free(data);
    const dst = try gpa.alloc(u8, lz4.compressBlockBound(data.len));
    defer gpa.free(dst);
    const fast = try lz4.compressBlockDict(gpa, data, dict, dst, .{});
    const n = try lz4.compressBlockDict(gpa, data, dict, dst, .{ .hc_level = 9 });
    try testing.expect(n < fast);
    const back = try gpa.alloc(u8, data.len);
    defer gpa.free(back);
    try testing.expectEqual(data.len, try lz4.decompressBlockDict(gpa, dst[0..n], dict, back));
    try testing.expectEqualSlices(u8, data, back);
    for ([_]bool{ false, true }) |indep| {
        const z = try lz4.compressDict(gpa, data, dict, 9, .{ .hc_level = 7, .independent_blocks = indep });
        defer gpa.free(z);
        const b2 = try lz4.decompressDict(gpa, z, dict, .{});
        defer gpa.free(b2);
        try testing.expectEqualSlices(u8, data, b2);
    }
}
