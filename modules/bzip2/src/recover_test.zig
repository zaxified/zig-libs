// SPDX-License-Identifier: MIT

const std = @import("std");
const testing = std.testing;
const bz = @import("root.zig");
const recover = bz.recover;

fn textInput(gpa: std.mem.Allocator, n: usize, seed: u64) ![]u8 {
    const words = [_][]const u8{ "alpha ", "beta ", "gamma ", "delta\n", "epsilon ", "zeta ", "eta ", "theta " };
    var prng: std.Random.DefaultPrng = .init(seed);
    const out = try gpa.alloc(u8, n);
    var i: usize = 0;
    while (i < n) {
        const w = words[prng.random().uintLessThan(usize, words.len)];
        const k = @min(w.len, n - i);
        @memcpy(out[i..][0..k], w[0..k]);
        i += k;
    }
    return out;
}

/// The recovered streams of `z`, each decoded, concatenated; `bad` counts the ones that failed to decode.
fn recoverAll(gpa: std.mem.Allocator, z: []const u8, bad: *usize) ![]u8 {
    const blocks = try recover.findBlocks(gpa, z, .{});
    defer gpa.free(blocks);
    var all: std.ArrayList(u8) = .empty;
    errdefer all.deinit(gpa);
    for (blocks) |b| {
        var w: std.Io.Writer.Allocating = .init(gpa);
        defer w.deinit();
        try recover.writeBlockStream(z, b, &w.writer);
        if (bz.decompress(gpa, w.written(), .{})) |plain| {
            defer gpa.free(plain);
            try all.appendSlice(gpa, plain);
        } else |_| bad.* += 1;
    }
    return all.toOwnedSlice(gpa);
}

test "recover: every block of an intact file comes back as a stream of its own, in order" {
    const gpa = testing.allocator;
    const text = try textInput(gpa, 450_000, 11);
    defer gpa.free(text);
    const z = try bz.compress(gpa, text, .{ .level = 1 }); // 100 kB blocks: five of them
    defer gpa.free(z);
    const blocks = try recover.findBlocks(gpa, z, .{});
    defer gpa.free(blocks);
    try testing.expectEqual(@as(usize, 5), blocks.len);
    for (blocks[1..], blocks[0 .. blocks.len - 1]) |b, a| try testing.expect(b.first_bit > a.last_bit);
    var bad: usize = 0;
    const back = try recoverAll(gpa, z, &bad);
    defer gpa.free(back);
    try testing.expectEqual(@as(usize, 0), bad);
    try testing.expectEqualSlices(u8, text, back);
}

test "recover: a damaged block fails to decode, the others survive; a lost header still leaves the rest" {
    const gpa = testing.allocator;
    const text = try textInput(gpa, 450_000, 12);
    defer gpa.free(text);
    const z = try bz.compress(gpa, text, .{ .level = 1 });
    defer gpa.free(z);
    const blocks = try recover.findBlocks(gpa, z, .{});
    defer gpa.free(blocks);
    try testing.expectEqual(@as(usize, 5), blocks.len);
    // Rot one byte inside block 3 (index 2).
    const dmg = try gpa.dupe(u8, z);
    defer gpa.free(dmg);
    dmg[@intCast((blocks[2].first_bit + blocks[2].last_bit) / 2 / 8)] ^= 0x55;
    var bad: usize = 0;
    const back = try recoverAll(gpa, dmg, &bad);
    defer gpa.free(back);
    try testing.expectEqual(@as(usize, 1), bad);
    // Four blocks' worth of the text, the damaged one missing: the first block and the last two are exact.
    try testing.expect(back.len < text.len);
    const first = blocks_plain_len(text, 1);
    try testing.expectEqualSlices(u8, text[0..first], back[0..first]);
    try testing.expect(std.mem.endsWith(u8, text, back[back.len - 100_000 ..]));
    // Cut the file in the middle of block 4: the blocks before it are intact, the cut one is "incomplete" and not reported.
    const cut = z[0..@intCast((blocks[3].first_bit + blocks[3].last_bit) / 2 / 8)];
    const part = try recover.findBlocks(gpa, cut, .{});
    defer gpa.free(part);
    try testing.expectEqual(@as(usize, 3), part.len);
}

fn blocks_plain_len(text: []const u8, n: usize) usize {
    return @min(text.len, n * 100_000 - 19); // a level 1 block holds 99,981 bytes (100,000 less the 19 bytes the block sort keeps)
}

test "recover: bit offsets, short regions, the block limit and the empty cases" {
    const gpa = testing.allocator;
    try testing.expectEqual(@as(usize, 0), (try recover.findBlocks(gpa, "", .{})).len);
    const none = try recover.findBlocks(gpa, "not a bzip2 file at all, no magic anywhere in here.", .{});
    try testing.expectEqual(@as(usize, 0), none.len);
    const text = try textInput(gpa, 250_000, 13);
    defer gpa.free(text);
    const z = try bz.compress(gpa, text, .{ .level = 1 });
    defer gpa.free(z);
    // The same file shifted by 3 bits: the same blocks, 3 bits later (the magics are found at any bit offset).
    const sh = try gpa.alloc(u8, z.len + 1); // `z` shifted right by three bits
    defer gpa.free(sh);
    var carry: u8 = 0;
    for (z, 0..) |byte, i| {
        sh[i] = carry | (byte >> 3);
        carry = byte << 5;
    }
    sh[z.len] = carry;
    const a = try recover.findBlocks(gpa, z, .{});
    defer gpa.free(a);
    const b = try recover.findBlocks(gpa, sh, .{});
    defer gpa.free(b);
    try testing.expectEqual(a.len, b.len);
    for (a, b) |x, y| {
        try testing.expectEqual(x.first_bit + 3, y.first_bit);
        try testing.expectEqual(x.last_bit + 3, y.last_bit);
    }
    // ... and a shifted block still comes out as a decodable stream, byte-for-byte the one of the unshifted file.
    var w1: std.Io.Writer.Allocating = .init(gpa);
    defer w1.deinit();
    var w2: std.Io.Writer.Allocating = .init(gpa);
    defer w2.deinit();
    try recover.writeBlockStream(z, a[1], &w1.writer);
    try recover.writeBlockStream(sh, b[1], &w2.writer);
    try testing.expectEqualSlices(u8, w1.written(), w2.written());
    // The block limit.
    try testing.expectError(error.TooManyBlocks, recover.findBlocks(gpa, z, .{ .max_blocks = 1 }));
    const exact = try recover.findBlocks(gpa, z, .{ .max_blocks = a.len });
    gpa.free(exact);
}

/// A most-significant-bit-first bit string, for building inputs and expected streams bit by bit.
const BitStr = struct {
    gpa: std.mem.Allocator,
    bytes: std.ArrayList(u8) = .empty,
    n: usize = 0,

    fn deinit(self: *BitStr) void {
        self.bytes.deinit(self.gpa);
    }

    fn bit(self: *BitStr, b: u1) !void {
        if (self.n % 8 == 0) try self.bytes.append(self.gpa, 0);
        if (b == 1) self.bytes.items[self.n / 8] |= @as(u8, 0x80) >> @intCast(self.n % 8);
        self.n += 1;
    }

    fn put(self: *BitStr, v: u64, count: u7) !void {
        var k = count;
        while (k > 0) {
            k -= 1;
            try self.bit(@intCast((v >> @as(u6, @intCast(k))) & 1));
        }
    }

    fn zeros(self: *BitStr, count: usize) !void {
        for (0..count) |_| try self.bit(0);
    }
};

const mut_block_magic: u64 = 0x314159265359;
const mut_end_magic: u64 = 0x177245385090;

/// Input bit `pos` of `input`, zero past the end.
fn inputBit(input: []const u8, pos: usize) u1 {
    if (pos / 8 >= input.len) return 0;
    return @intCast((input[pos / 8] >> @intCast(7 - pos % 8)) & 1);
}

test "mutation 2026-11-25: writeBlockStream equals a bit-by-bit reference for every length mod 32 and mod 8, offsets, and past the end of the input" {
    const gpa = testing.allocator;
    var prng: std.Random.DefaultPrng = .init(0x62_7a_32);
    var input: [64]u8 = undefined;
    prng.random().bytes(&input);
    const firsts = [_]u64{ 0, 3, 8, 13 };
    const lens = [_]u64{ 32, 33, 34, 63, 64, 65, 96, 97, 128, 129, 130, 131, 136, 160, 200 };
    for (firsts) |first| for (lens) |n| {
        var want: BitStr = .{ .gpa = gpa };
        defer want.deinit();
        try want.put(0x425A6839, 32); // "BZh9"
        try want.put(mut_block_magic, 48);
        for (0..n) |k| try want.bit(inputBit(&input, @intCast(first + k)));
        try want.put(mut_end_magic, 48);
        var crc: u64 = 0;
        for (0..32) |k| crc = (crc << 1) | inputBit(&input, @intCast(first + k));
        try want.put(crc, 32);
        var got: std.Io.Writer.Allocating = .init(gpa);
        defer got.deinit();
        try recover.writeBlockStream(&input, .{ .first_bit = first, .last_bit = first + n - 1 }, &got.writer);
        try testing.expectEqualSlices(u8, want.bytes.items, got.written());
    };
    // A block that runs past the end of the input reads zeros there (documented), it does not read out of bounds.
    var want: BitStr = .{ .gpa = gpa };
    defer want.deinit();
    try want.put(0x425A6839, 32);
    try want.put(mut_block_magic, 48);
    for (0..100) |k| try want.bit(inputBit(&input, 480 + k));
    try want.put(mut_end_magic, 48);
    var crc: u64 = 0;
    for (0..32) |k| crc = (crc << 1) | inputBit(&input, 480 + k);
    try want.put(crc, 32);
    var got: std.Io.Writer.Allocating = .init(gpa);
    defer got.deinit();
    try recover.writeBlockStream(&input, .{ .first_bit = 480, .last_bit = 579 }, &got.writer);
    try testing.expectEqualSlices(u8, want.bytes.items, got.written());
}

test "mutation 2026-11-25: findBlocks at the edges: a magic at bit 0, adjacent magics, a 130/131-bit region, junk before the first magic, the block limit" {
    const gpa = testing.allocator;
    // magic at bit 0, then 131 bits, then the end magic: one block, bits 48 ..= 178 (131 bits).
    {
        var s: BitStr = .{ .gpa = gpa };
        defer s.deinit();
        try s.put(mut_block_magic, 48);
        try s.zeros(131);
        try s.put(mut_end_magic, 48);
        const bl = try recover.findBlocks(gpa, s.bytes.items, .{});
        defer gpa.free(bl);
        try testing.expectEqual(@as(usize, 1), bl.len);
        try testing.expectEqual(@as(u64, 48), bl[0].first_bit);
        try testing.expectEqual(@as(u64, 178), bl[0].last_bit);
    }
    // 130 bits between the magics is too short to be a block.
    {
        var s: BitStr = .{ .gpa = gpa };
        defer s.deinit();
        try s.put(mut_block_magic, 48);
        try s.zeros(130);
        try s.put(mut_end_magic, 48);
        const bl = try recover.findBlocks(gpa, s.bytes.items, .{});
        defer gpa.free(bl);
        try testing.expectEqual(@as(usize, 0), bl.len);
    }
    // Two magics back to back: an empty region, no block and no arithmetic underflow.
    {
        var s: BitStr = .{ .gpa = gpa };
        defer s.deinit();
        try s.put(mut_block_magic, 48);
        try s.put(mut_end_magic, 48);
        const bl = try recover.findBlocks(gpa, s.bytes.items, .{});
        defer gpa.free(bl);
        try testing.expectEqual(@as(usize, 0), bl.len);
    }
    // 200 bits of junk before the first magic are not a block; the block after it is found 200 bits later.
    {
        var s: BitStr = .{ .gpa = gpa };
        defer s.deinit();
        try s.zeros(200);
        try s.put(mut_block_magic, 48);
        try s.zeros(131);
        try s.put(mut_end_magic, 48);
        const bl = try recover.findBlocks(gpa, s.bytes.items, .{});
        defer gpa.free(bl);
        try testing.expectEqual(@as(usize, 1), bl.len);
        try testing.expectEqual(@as(u64, 248), bl[0].first_bit);
        try testing.expectEqual(@as(u64, 378), bl[0].last_bit);
    }
    // The block limit is exact: two blocks need max_blocks 2, one fewer is TooManyBlocks, 0 refuses the first.
    {
        var s: BitStr = .{ .gpa = gpa };
        defer s.deinit();
        try s.put(mut_block_magic, 48);
        try s.zeros(131);
        try s.put(mut_block_magic, 48);
        try s.zeros(131);
        try s.put(mut_end_magic, 48);
        const two = try recover.findBlocks(gpa, s.bytes.items, .{ .max_blocks = 2 });
        defer gpa.free(two);
        try testing.expectEqual(@as(usize, 2), two.len);
        try testing.expectError(error.TooManyBlocks, recover.findBlocks(gpa, s.bytes.items, .{ .max_blocks = 1 }));
        try testing.expectError(error.TooManyBlocks, recover.findBlocks(gpa, s.bytes.items, .{ .max_blocks = 0 }));
    }
}

test "mutation 2026-11-25: a level 9 block of more than 100 kB is recovered as a stream that decodes (the recovered header is level 9)" {
    const gpa = testing.allocator;
    const text = try textInput(gpa, 250_000, 14);
    defer gpa.free(text);
    const z = try bz.compress(gpa, text, .{ .level = 9 });
    defer gpa.free(z);
    var bad: usize = 0;
    const back = try recoverAll(gpa, z, &bad);
    defer gpa.free(back);
    try testing.expectEqual(@as(usize, 0), bad);
    try testing.expectEqualSlices(u8, text, back);
}
