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
