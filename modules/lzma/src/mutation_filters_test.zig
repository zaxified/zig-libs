// SPDX-License-Identifier: MIT

//! Tests added by the 2026-11-27 delta mutation run over the BCJ/delta filters,
//! the multi-block / threaded `.xz` encoder, the filtered-block decoder and the
//! ZIP method 14 header. Every expected value is derived from the xz file
//! format (section 5.3: filter ids, property bytes, alignments) or from the
//! converters' definition in liblzma's `simple/*.c` worked by hand (each vector
//! shows its arithmetic), never from running this module.

const std = @import("std");
const testing = std.testing;
const lzma = @import("root.zig");
const filters = @import("filters.zig");

const gpa = testing.allocator;
const Filter = filters.Filter;
const zero16: [16]u8 = @splat(0);

/// Run `f` over `data` in one chain, `piece` bytes at a time.
fn runChain(f: []const Filter, data: []const u8, encode: bool, piece: usize, out: []u8) !void {
    const ch = try gpa.create(filters.Chain);
    defer gpa.destroy(ch);
    ch.init(f, encode);
    var n: usize = 0;
    var p: usize = 0;
    while (p < data.len) {
        const m = @min(piece, data.len - p);
        @memcpy(ch.input()[0..m], data[p..][0..m]);
        p += m;
        const e = ch.feed(m, false);
        @memcpy(out[n..][0..e.len], e);
        n += e.len;
    }
    const e = ch.feed(0, true);
    @memcpy(out[n..][0..e.len], e);
    n += e.len;
    try testing.expectEqual(data.len, n);
}

/// `plain` encodes to `coded` and `coded` decodes to `plain`, for one piece size and for the whole buffer at once.
fn expectKat(f: []const Filter, plain: []const u8, coded: []const u8) !void {
    var out: [64]u8 = undefined;
    for ([_]usize{ plain.len, 1, 7 }) |piece| {
        try runChain(f, plain, true, piece, out[0..plain.len]);
        try testing.expectEqualSlices(u8, coded, out[0..plain.len]);
        try runChain(f, coded, false, piece, out[0..plain.len]);
        try testing.expectEqualSlices(u8, plain, out[0..plain.len]);
    }
}

test "mutation 2026-11-27: filter ids are the xz file format's (section 5.3.1)" {
    try testing.expectEqual(@as(u8, 0x03), (Filter{ .delta = 1 }).id());
    try testing.expectEqual(@as(u8, 0x04), (Filter{ .x86 = .{} }).id());
    try testing.expectEqual(@as(u8, 0x05), (Filter{ .powerpc = .{} }).id());
    try testing.expectEqual(@as(u8, 0x06), (Filter{ .ia64 = .{} }).id());
    try testing.expectEqual(@as(u8, 0x07), (Filter{ .arm = .{} }).id());
    try testing.expectEqual(@as(u8, 0x08), (Filter{ .armthumb = .{} }).id());
    try testing.expectEqual(@as(u8, 0x09), (Filter{ .sparc = .{} }).id());
    try testing.expectEqual(@as(u8, 0x0A), (Filter{ .arm64 = .{} }).id());
}

test "mutation 2026-11-27: fromProps maps every id to its own filter, empty props mean offset 0" {
    const ids = [_]u8{ 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A };
    for (ids) |id| {
        const f = Filter.fromProps(id, &.{}).?;
        try testing.expectEqual(id, f.id());
        try testing.expect(f.valid());
        var b: [4]u8 = undefined;
        try testing.expectEqual(@as(usize, 0), f.props(&b));
        // a 4-byte property is the start offset, little-endian (a multiple of 16 is valid for every filter)
        const g = Filter.fromProps(id, &.{ 0x10, 0x02, 0x00, 0x00 }).?;
        try testing.expectEqual(id, g.id());
        try testing.expectEqual(@as(usize, 4), g.props(&b));
        try testing.expectEqualSlices(u8, &.{ 0x10, 0x02, 0x00, 0x00 }, &b);
        switch (g) {
            .delta => unreachable,
            inline else => |o| try testing.expectEqual(@as(u32, 0x210), o.start_offset),
        }
    }
    // delta: one property byte, distance - 1
    try testing.expectEqual(@as(u16, 1), Filter.fromProps(0x03, &.{0}).?.delta);
    try testing.expectEqual(@as(u16, 256), Filter.fromProps(0x03, &.{255}).?.delta);
    var b: [4]u8 = undefined;
    try testing.expectEqual(@as(usize, 1), (Filter{ .delta = 256 }).props(&b));
    try testing.expectEqual(@as(u8, 255), b[0]);
    try testing.expectEqual(@as(usize, 1), (Filter{ .delta = 1 }).props(&b));
    try testing.expectEqual(@as(u8, 0), b[0]);
}

test "mutation 2026-11-27: property sizes are exact: delta takes one byte, a branch filter none or four" {
    try testing.expect(Filter.fromProps(0x03, &.{ 1, 2 }) == null);
    for ([_]u8{ 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A }) |id| {
        try testing.expect(Filter.fromProps(id, &.{1}) == null);
        try testing.expect(Filter.fromProps(id, &.{ 0, 0, 0 }) == null);
        try testing.expect(Filter.fromProps(id, &.{ 0, 0, 0, 0, 0 }) == null);
        try testing.expect(Filter.fromProps(id, &.{ 0, 0, 0, 0, 0, 0, 0, 0 }) == null);
    }
    try testing.expect(Filter.fromProps(0x0B, &.{}) == null);
    try testing.expect(Filter.fromProps(0x02, &.{0}) == null);
}

test "mutation 2026-11-27: start offsets must be aligned as liblzma says (x86 1, ARM Thumb 2, IA-64 16, the others 4)" {
    try testing.expect((Filter{ .x86 = .{ .start_offset = 1 } }).valid());
    try testing.expect((Filter{ .x86 = .{ .start_offset = 3 } }).valid());
    try testing.expect((Filter{ .armthumb = .{ .start_offset = 2 } }).valid());
    try testing.expect(!(Filter{ .armthumb = .{ .start_offset = 1 } }).valid());
    try testing.expect(!(Filter{ .armthumb = .{ .start_offset = 3 } }).valid());
    try testing.expect((Filter{ .ia64 = .{ .start_offset = 16 } }).valid());
    try testing.expect(!(Filter{ .ia64 = .{ .start_offset = 8 } }).valid());
    try testing.expect(!(Filter{ .ia64 = .{ .start_offset = 4 } }).valid());
    inline for (.{ "powerpc", "arm", "sparc", "arm64" }) |name| {
        const ok = @unionInit(Filter, name, .{ .start_offset = 4 });
        const bad2 = @unionInit(Filter, name, .{ .start_offset = 2 });
        const bad1 = @unionInit(Filter, name, .{ .start_offset = 1 });
        try testing.expect(ok.valid());
        try testing.expect(!bad2.valid());
        try testing.expect(!bad1.valid());
        try testing.expect(@unionInit(Filter, name, .{ .start_offset = 8 }).valid());
    }
    // delta: distance 1..256, both ends valid
    try testing.expect((Filter{ .delta = 1 }).valid());
    try testing.expect((Filter{ .delta = 256 }).valid());
    try testing.expect(!(Filter{ .delta = 0 }).valid());
    try testing.expect(!(Filter{ .delta = 257 }).valid());
}

test "mutation 2026-11-27: delta filter, distance 2: out[i] = in[i] - in[i - 2]" {
    const plain = [_]u8{ 1, 2, 3, 5, 10, 0, 255 };
    // 1, 2, 3-1, 5-2, 10-3, 0-5 (mod 256), 255-10
    const coded = [_]u8{ 1, 2, 2, 3, 7, 251, 245 };
    try expectKat(&.{.{ .delta = 2 }}, &plain, &coded);
    // distance 1 is the plain difference; distance 256 reaches back one full history
    try expectKat(&.{.{ .delta = 1 }}, &.{ 5, 7, 7, 4 }, &.{ 5, 2, 0, 253 });
}

test "mutation 2026-11-27: ARM converter, vectors worked by hand" {
    // word at i = 4: BL with imm24 = 0x10; src = 0x10 << 2 = 0x40; dest = (0 + 4 + 8) + 0x40 = 0x4C; >> 2 = 0x13.
    // the word at i = 0 is not a BL (top byte 0xEA) and stays.
    const plain = [_]u8{ 1, 2, 3, 0xEA, 0x10, 0x00, 0x00, 0xEB };
    const coded = [_]u8{ 1, 2, 3, 0xEA, 0x13, 0x00, 0x00, 0xEB };
    try expectKat(&.{.{ .arm = .{} }}, &plain, &coded);
    // start offset 0x100: dest = 0x100 + 4 + 8 + 0x40 = 0x14C; >> 2 = 0x53
    try expectKat(&.{.{ .arm = .{ .start_offset = 0x100 } }}, &plain, &.{ 1, 2, 3, 0xEA, 0x53, 0x00, 0x00, 0xEB });
    // the byte-1 / byte-2 positions of the immediate: imm24 = 0x010203 -> src = 0x40_80C; dest = 8 + src = 0x40814, >> 2 = 0x10205
    try expectKat(&.{.{ .arm = .{} }}, &.{ 0x03, 0x02, 0x01, 0xEB }, &.{ 0x05, 0x02, 0x01, 0xEB });
}

test "mutation 2026-11-27: ARM Thumb converter, vector worked by hand" {
    // pair at i = 2: bytes [0x00, 0xF0, 0x10, 0xF8]: src = (0 << 19) | (0 << 11) | (0 << 8) | 0x10; src <<= 1 = 0x20;
    // dest = (0 + 2 + 4) + 0x20 = 0x26; >> 1 = 0x13: bytes [0x00, 0xF0, 0x13, 0xF8].
    try expectKat(&.{.{ .armthumb = .{} }}, &.{ 0, 0, 0x00, 0xF0, 0x10, 0xF8 }, &.{ 0, 0, 0x00, 0xF0, 0x13, 0xF8 });
    // all immediate fields: buf[i] = 0x01 (bits 11..18), buf[i+1] low 3 bits = 5 (bits 19..21), buf[i+3] low 3 bits = 2 (bits 8..10), buf[i+2] = 0x34.
    // src = (5 << 19) | (1 << 11) | (2 << 8) | 0x34 = 0x280000 + 0x800 + 0x200 + 0x34 = 0x280A34; << 1 = 0x501468;
    // dest = (0 + 0 + 4) + 0x501468 = 0x50146C; >> 1 = 0x280A36: buf[i+1] = 0xF0 | 5, buf[i] = (0x280A36 >> 11) & 0xFF = 0x01,
    // buf[i+3] = 0xF8 | ((0x280A36 >> 8) & 7) = 0xFA, buf[i+2] = 0x36
    try expectKat(&.{.{ .armthumb = .{} }}, &.{ 0x01, 0xF5, 0x34, 0xFA }, &.{ 0x01, 0xF5, 0x36, 0xFA });
}

test "mutation 2026-11-27: PowerPC converter, vector worked by hand" {
    // word at i = 4: [0x48, 0x00, 0x01, 0x01] (opcode 18 = b, AA = 0, LK = 1): src = 0x100 (the low two bits are flags);
    // dest = 4 + 0x100 = 0x104: bytes [0x48, 0x00, 0x01, (0x01 & 3) | 0x04 = 0x05].
    const plain = [_]u8{ 0, 0, 0, 0, 0x48, 0x00, 0x01, 0x01 };
    const coded = [_]u8{ 0, 0, 0, 0, 0x48, 0x00, 0x01, 0x05 };
    try expectKat(&.{.{ .powerpc = .{} }}, &plain, &coded);
    // not a branch: low bits 0 or 2 stay
    try expectKat(&.{.{ .powerpc = .{} }}, &.{ 0x48, 0, 1, 0, 0x48, 0, 1, 2 }, &.{ 0x48, 0, 1, 0, 0x48, 0, 1, 2 });
    // the top bits of the 26-bit target: [0x4B, 0x80, 0x00, 0x01] at i = 4 (src = 0x3800000 | ... ) : src = ((0x4B & 3) << 24) | (0x80 << 16) = 0x3800000;
    // dest = 4 + 0x3800000 = 0x3800004: buf[i] = 0x48 | ((dest >> 24) & 3) = 0x4B, buf[i+1] = 0x80, buf[i+2] = 0, buf[i+3] = 1 | 0x04
    try expectKat(&.{.{ .powerpc = .{} }}, &.{ 0, 0, 0, 0, 0x4B, 0x80, 0x00, 0x01 }, &.{ 0, 0, 0, 0, 0x4B, 0x80, 0x00, 0x05 });
}

test "mutation 2026-11-27: SPARC converter, vector worked by hand" {
    // word at i = 4: big-endian 0x40000010: src = 0x40000010 << 2 = 0x40 (mod 2^32); dest = 4 + 0x40 = 0x44; >> 2 = 0x11;
    // bit 22 of dest is 0, so the result is 0x40000011.
    try expectKat(&.{.{ .sparc = .{} }}, &.{ 0, 0, 0, 0, 0x40, 0x00, 0x00, 0x10 }, &.{ 0, 0, 0, 0, 0x40, 0x00, 0x00, 0x11 });
    // the 0x7F form with the 0xC0 mask: 0x7FC00004 at i = 0: src = 0x7FC00004 << 2 = 0xFF000010; dest = 0 + src = 0xFF000010; >> 2 = 0x3FC00004;
    // bit 22 of 0x3FC00004 is 1: (0 - 1) << 22 & 0x3FFFFFFF = 0x3FC00000; | (dest & 0x3FFFFF) = 0x4 | 0x40000000 = 0x7FC00004 (unchanged)
    try expectKat(&.{.{ .sparc = .{} }}, &.{ 0x7F, 0xC0, 0x00, 0x04 }, &.{ 0x7F, 0xC0, 0x00, 0x04 });
    // not a call: 0x40 with a non-zero top of byte 1, 0x7F with byte 1 below 0xC0
    try expectKat(&.{.{ .sparc = .{} }}, &.{ 0x40, 0x40, 0x00, 0x10, 0x7F, 0x80, 0x00, 0x10 }, &.{ 0x40, 0x40, 0x00, 0x10, 0x7F, 0x80, 0x00, 0x10 });
}

test "mutation 2026-11-27: ARM64 converter, BL and ADRP vectors worked by hand" {
    // BL at i = 8: instr 0x94000010; pc = 8 >> 2 = 2; encode: 0x94000000 | ((0x94000010 + 2) & 0x03FFFFFF) = 0x94000012
    try expectKat(&.{.{ .arm64 = .{} }}, &.{ 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x00, 0x00, 0x94 }, &.{ 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x00, 0x00, 0x94 });
    // a BL with imm26 near the top: 0x97FFFFFF at i = 4: pc = 1: (0x97FFFFFF + 1) & 0x03FFFFFF = 0, so 0x94000000
    try expectKat(&.{.{ .arm64 = .{} }}, &.{ 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0x97 }, &.{ 0, 0, 0, 0, 0x00, 0x00, 0x00, 0x94 });
    // ADRP with start offset 0x3000 at i = 0: instr 0x90000200 (immlo 0, immhi 0x10, Rd 0): src = 0 | ((0x90000200 >> 3) & 0x1FFFFC) = 0x40;
    // (0x40 + 0x20000) & 0x1C0000 = 0, so it is converted; pc = 0x3000 >> 12 = 3; dest = 0x43;
    // instr = (0x90000200 & 0x9000001F) | ((0x43 & 3) << 29) | ((0x43 & 0x3FFFC) << 3) = 0x90000000 | 0x60000000 | 0x200 = 0xF0000200
    try expectKat(&.{.{ .arm64 = .{ .start_offset = 0x3000 } }}, &.{ 0x00, 0x02, 0x00, 0x90 }, &.{ 0x00, 0x02, 0x00, 0xF0 });
    // sign extension: 0x90FFFFE0 has src = 0x1FFFFC (-4 as 21 bits), (src + 0x20000) & 0x1C0000 = 0, converted;
    // pc = 3, dest = 0x1FFFFF (bit 17 set), instr = 0x90000000 | (3 << 29) | ((0x1FFFFF & 0x3FFFC) << 3) | 0xE00000 = 0xF0FFFFE0
    try expectKat(&.{.{ .arm64 = .{ .start_offset = 0x3000 } }}, &.{ 0xE0, 0xFF, 0xFF, 0x90 }, &.{ 0xE0, 0xFF, 0xFF, 0xF0 });
    // an ADRP whose target is too far: 0x90200000 has src = 0x40000, (0x40000 + 0x20000) & 0x1C0000 = 0x40000 != 0: left alone
    try expectKat(&.{.{ .arm64 = .{ .start_offset = 0x3000 } }}, &.{ 0x00, 0x00, 0x20, 0x90 }, &.{ 0x00, 0x00, 0x20, 0x90 });
    // a word that is neither: unchanged
    try expectKat(&.{.{ .arm64 = .{} }}, &.{ 1, 2, 3, 4 }, &.{ 1, 2, 3, 4 });
}

// Vectors made by working the converter of liblzma's ia64.c on paper (see the comments),
// cross-checked against an independent reimplementation of that C code.
test "mutation 2026-11-27: IA-64 converter, one-slot and three-slot bundles" {
    // Bundle 0 is all zero (template 0, no branch slot). Bundle 1 at i = 16 has template 0x10 (branch table entry 4: slot 2 only).
    // Slot 2 starts at bit 5 + 82 = 87: byte 10 of the bundle, bit 7. Its opcode (bits 37..40) is 5, imm20 (bits 13..32) = 0x10.
    // inst_norm = (5 << 37) | (0x10 << 13) = 0xA000020000; instruction = inst_norm << 7 = 0x500001000000 -> bytes (LE) 00 00 00 01 00 50.
    // src = 0x10 << 4 = 0x100; dest = (0 + 16) + 0x100 = 0x110; >> 4 = 0x11; inst_norm = (5 << 37) | (0x11 << 13) = 0xA000022000;
    // instruction = 0x500001100000 -> bytes 00 00 10 01 00 50.
    const plain1 = zero16 ++ [16]u8{ 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0, 0x50 };
    const coded1 = zero16 ++ [16]u8{ 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x01, 0, 0x50 };
    try expectKat(&.{.{ .ia64 = .{} }}, &plain1, &coded1);
    // Template 0x16 (entry 7: all three slots), start offset 0x20, bundle 1 at i = 16 (so pc = 0x30 for it):
    // slot 0: imm20 = 1, slot 1: imm20 = 0x7FFFF with the sign bit set, slot 2: imm20 = 2 (all opcode 5).
    // slot 0: src = 1 << 4 = 0x10, dest = 0x30 + 0x10 = 0x40, >> 4 = 4; slot 1: src = (0x7FFFF | 1 << 20) << 4 = 0xFFFFF0,
    // dest = 0x30 + 0xFFFFF0 = 0x1000020 (mod 2^32), >> 4 = 0x100002: imm20 = 2, sign bit set; slot 2: src = 0x20, dest = 0x50, >> 4 = 5.
    const plain2 = zero16 ++ [16]u8{ 0x16, 0x00, 0x04, 0x00, 0x00, 0x14, 0x00, 0xF8, 0xFF, 0x3F, 0x2C, 0x00, 0x20, 0x00, 0x00, 0x50 };
    const coded2 = zero16 ++ [16]u8{ 0x16, 0x00, 0x10, 0x00, 0x00, 0x14, 0x00, 0x10, 0x00, 0x40, 0x2C, 0x00, 0x50, 0x00, 0x00, 0x50 };
    try expectKat(&.{.{ .ia64 = .{ .start_offset = 0x20 } }}, &plain2, &coded2);
    // an instruction whose opcode is not 5, or whose bits 9..11 are not 0, is not a branch: the all-zero bundle 0 and 0x16 with zero slots stay
    const other = zero16 ++ [16]u8{ 0x16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    try expectKat(&.{.{ .ia64 = .{} }}, &other, &other);
}

// ── multi-block / threaded .xz output ────────────────────────────────────

/// Compressible text bytes (16 letters) from a linear congruential stream.
fn textBytes(buf: []u8, seed: u32) void {
    var x = seed;
    for (buf) |*b| {
        x = x *% 1664525 +% 1013904223;
        b.* = 0x61 + @as(u8, @truncate((x >> 24) & 15));
    }
}

/// The record count of a one-byte-count `.xz` index (the stream's footer says how long the index is).
fn indexRecords(z: []const u8) u8 {
    const index_size = (@as(usize, std.mem.readInt(u32, z[z.len - 8 ..][0..4], .little)) + 1) * 4;
    return z[z.len - 12 - index_size + 1];
}

test "mutation 2026-11-27: mtBlockSize is three times the dictionary, at least 1 MiB" {
    try testing.expectEqual(@as(u64, 1 << 20), lzma.mtBlockSize(1 << 16));
    try testing.expectEqual(@as(u64, 1 << 20), lzma.mtBlockSize(349525)); // 3 * 349525 = 1048575, one short of 1 MiB
    try testing.expectEqual(@as(u64, 1048578), lzma.mtBlockSize(349526)); // 3 * 349526
    try testing.expectEqual(@as(u64, 3 << 20), lzma.mtBlockSize(1 << 20));
    try testing.expectEqual(@as(u64, 3 << 23), lzma.mtBlockSize(1 << 23));
    try testing.expectEqual(@as(u64, 3) * std.math.maxInt(u32), lzma.mtBlockSize(std.math.maxInt(u32)));
}

test "mutation 2026-11-27: threads other than 1 write the sizes into the block header, other formats ignore threads" {
    var plain: [3000]u8 = undefined;
    textBytes(&plain, 5);
    const o1 = lzma.EncodeOptions{ .lzma = lzma.preset(1, false), .threads = 1 };
    const serial = try lzma.compress(gpa, &plain, .xz, o1);
    defer gpa.free(serial);
    // stream header is 12 bytes; the block header follows: size byte, flags (bits 6 and 7 = sizes present)
    try testing.expectEqual(@as(u8, 0x00), serial[13] & 0xC0);
    for ([_]u32{ 0, 2, 3 }) |threads| {
        var o = o1;
        o.threads = threads;
        const z = try lzma.compress(gpa, &plain, .xz, o);
        defer gpa.free(z);
        try testing.expectEqual(@as(u8, 0xC0), z[13] & 0xC0);
        const back = try lzma.decompress(gpa, z, .xz, .{});
        defer gpa.free(back);
        try testing.expectEqualSlices(u8, &plain, back);
        // compressInto gives the same bytes as compress
        var dest: [4096]u8 = undefined;
        const n = try lzma.compressInto(gpa, &dest, &plain, .xz, o);
        try testing.expectEqualSlices(u8, z, dest[0..n]);
        // and refuses exactly when the buffer is one byte short
        try testing.expectEqual(n, try lzma.compressInto(gpa, dest[0..n], &plain, .xz, o));
        try testing.expectError(error.OutputTooLarge, lzma.compressInto(gpa, dest[0 .. n - 1], &plain, .xz, o));
        // the other formats do not look at threads
        for ([_]lzma.EncodeFormat{ .lzma_alone, .lzma1, .lzma2 }) |fmt| {
            const a = try lzma.compress(gpa, &plain, fmt, o);
            defer gpa.free(a);
            const b = try lzma.compress(gpa, &plain, fmt, o1);
            defer gpa.free(b);
            try testing.expectEqualSlices(u8, b, a);
        }
    }
}

test "mutation 2026-11-27: threaded output without block_size splits at 3 x dictionary, at least 1 MiB" {
    const n = (1 << 20) + (1 << 19); // 1.5 MiB
    const plain = try gpa.alloc(u8, n);
    defer gpa.free(plain);
    textBytes(plain, 9);
    var o = lzma.EncodeOptions{ .lzma = lzma.preset(1, false), .threads = 2 };
    o.lzma.dict_size = 1 << 18; // 3 x 256 KiB < 1 MiB: blocks of 1 MiB -> 2 blocks
    const z = try lzma.compress(gpa, plain, .xz, o);
    defer gpa.free(z);
    try testing.expectEqual(@as(u8, 2), indexRecords(z));
    const back = try lzma.decompress(gpa, z, .xz, .{});
    defer gpa.free(back);
    try testing.expectEqualSlices(u8, plain, back);
    // an explicit block size wins, and a partial last block is kept: 1.5 MiB in blocks of 1 MiB / 512 KiB
    o.block_size = 1 << 19;
    const z3 = try lzma.compress(gpa, plain, .xz, o);
    defer gpa.free(z3);
    try testing.expectEqual(@as(u8, 3), indexRecords(z3));
    o.block_size = (1 << 20) + 1;
    const z2 = try lzma.compress(gpa, plain, .xz, o);
    defer gpa.free(z2);
    try testing.expectEqual(@as(u8, 2), indexRecords(z2)); // 1 MiB + 1 byte, then the rest
    const back2 = try lzma.decompress(gpa, z2, .xz, .{});
    defer gpa.free(back2);
    try testing.expectEqualSlices(u8, plain, back2);
}

test "mutation 2026-11-27: threaded compress validates its options even for empty input" {
    const bad = [_]lzma.EncodeOptions{
        .{ .threads = 2, .filters = &.{.{ .delta = 0 }} },
        .{ .threads = 2, .filters = &.{.{ .arm64 = .{ .start_offset = 2 } }} },
        .{ .threads = 2, .filters = &.{ .{ .delta = 1 }, .{ .delta = 2 }, .{ .delta = 3 }, .{ .delta = 4 } } },
        .{ .threads = 2, .lzma = .{ .dict_size = 1024 } },
        .{ .threads = 2, .lzma = .{ .lc = 4, .lp = 1 } },
    };
    for (bad) |o| {
        try testing.expectError(error.InvalidOptions, lzma.compress(gpa, "", .xz, o));
        try testing.expectError(error.InvalidOptions, lzma.compress(gpa, "abc", .xz, o));
    }
}

/// An allocator that fails exactly one allocation (the `fail_at`-th, counted over all threads) and serves every other one,
/// unlike `std.testing.FailingAllocator`, which keeps failing after the first: a failed worker would be hidden by the
/// later failures of the thread that assembles the stream.
const OnceFailing = struct {
    child: std.mem.Allocator,
    fail_at: usize,
    count: std.atomic.Value(usize) = .init(0),
    hit: std.atomic.Value(bool) = .init(false),

    fn allocator(self: *OnceFailing) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *OnceFailing = @ptrCast(@alignCast(ctx));
        if (self.count.fetchAdd(1, .monotonic) == self.fail_at) {
            self.hit.store(true, .monotonic);
            return null;
        }
        return self.child.rawAlloc(len, alignment, ra);
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const self: *OnceFailing = @ptrCast(@alignCast(ctx));
        return self.child.rawResize(memory, alignment, new_len, ra);
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const self: *OnceFailing = @ptrCast(@alignCast(ctx));
        return self.child.rawRemap(memory, alignment, new_len, ra);
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *OnceFailing = @ptrCast(@alignCast(ctx));
        self.child.rawFree(memory, alignment, ra);
    }
};

test "mutation 2026-11-27: a failure in a worker thread is reported, never an incomplete stream" {
    var plain: [3000]u8 = undefined;
    textBytes(&plain, 11);
    const o = lzma.EncodeOptions{ .lzma = lzma.preset(1, false), .block_size = 1000, .threads = 2, .filters = &.{.{ .x86 = .{} }} };
    const want = try lzma.compress(gpa, &plain, .xz, o);
    defer gpa.free(want);
    var errors: usize = 0;
    var fail_at: usize = 0;
    // Every single allocation of the compression (workers included) fails once: an error, or the complete correct stream.
    while (fail_at < 80) : (fail_at += 1) {
        var of: OnceFailing = .{ .child = gpa, .fail_at = fail_at };
        if (lzma.compress(of.allocator(), &plain, .xz, o)) |z| {
            defer gpa.free(z);
            try testing.expectEqualSlices(u8, want, z);
        } else |e| {
            // a Writer.Allocating reports its allocator's failure as WriteFailed
            try testing.expect(e == error.OutOfMemory or e == error.WriteFailed);
            try testing.expect(of.hit.load(.monotonic));
            errors += 1;
        }
    }
    try testing.expect(errors > 5);
}

test "mutation 2026-11-27: the reserved header size covers an incompressible block at the varint boundaries" {
    // `lzma2Bound(n)` = n + 3 * ceil(n / 65536) + 1 must fit the stored size of a block that does not compress:
    // 124 bytes are stored as 1 + 2 + 124 + 1 = 128 bytes (a 2-byte varint), 16380 as 16384 (a 3-byte varint). The block header
    // is padded to a multiple of 4, so a bound that is one varint byte short only breaks the header when the filter list
    // leaves no slack: the two filtered cases are those (header 12 and 16 bytes with the right bound).
    var prng = std.Random.DefaultPrng.init(0x7a11);
    var plain: [2 * 16380]u8 = undefined;
    prng.random().bytes(&plain);
    const Case = struct { bs: usize, f: []const Filter };
    const cases = [_]Case{
        .{ .bs = 124, .f = &.{} },
        .{ .bs = 16380, .f = &.{} },
        .{ .bs = 124, .f = &.{ .{ .x86 = .{} }, .{ .delta = 1 } } },
        .{ .bs = 16380, .f = &.{.{ .x86 = .{} }} },
    };
    for (cases) |cs| {
        for ([_]u32{ 2, 3 }) |threads| {
            const o = lzma.EncodeOptions{ .lzma = lzma.preset(0, false), .block_size = cs.bs, .threads = threads, .filters = cs.f };
            const z = try lzma.compress(gpa, plain[0 .. cs.bs * 2], .xz, o);
            defer gpa.free(z);
            const back = try lzma.decompress(gpa, z, .xz, .{});
            defer gpa.free(back);
            try testing.expectEqualSlices(u8, plain[0 .. cs.bs * 2], back);
            try testing.expectEqual(@as(u8, 2), indexRecords(z));
        }
    }
}

test "mutation 2026-11-27: PowerPC converter carries into the middle byte" {
    // [0x48, 0x00, 0xFF, 0xFD] at i = 4: src = 0xFFFC (the low two bits are flags), dest = 4 + 0xFFFC = 0x10000:
    // bytes [0x48, 0x01, 0x00, 0x01]
    try expectKat(&.{.{ .powerpc = .{} }}, &.{ 0, 0, 0, 0, 0x48, 0x00, 0xFF, 0xFD }, &.{ 0, 0, 0, 0, 0x48, 0x01, 0x00, 0x01 });
}

test "mutation 2026-11-27: IA-64 converter checks bits 9..11, clears the old sign bit, sign-extends" {
    // Slot 2 of the bundle at i = 16 (template 0x10). inst_norm = (5 << 37) | (1 << 9) | (0x10 << 13): opcode 5 but bits 9..11 = 1,
    // so it is not a branch and stays (vector confirmed with xz 5.8.3).
    const not_branch = zero16 ++ [16]u8{ 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x01, 0x00, 0x50 };
    try expectKat(&.{.{ .ia64 = .{} }}, &not_branch, &not_branch);
    // A negative displacement that turns positive: sign = 1, imm20 = 0xFFFFF is src = 0x1FFFFF0 (-16 in 21 bits); at i = 16
    // dest = 16 + 0x1FFFFF0 = 0x2000000; >> 4 = 0x200000: imm20 = 0 and the sign bit (bit 20) is 0, so the instruction becomes
    // (5 << 37) << 7 = 0x500000000000, bytes 00 00 00 00 00 50.
    const neg = zero16 ++ [16]u8{ 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xF0, 0xFF, 0xFF, 0x58 };
    const pos = zero16 ++ [16]u8{ 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x50 };
    try expectKat(&.{.{ .ia64 = .{} }}, &neg, &pos);
}

// ── x86 converter: vectors made by xz 5.8.3 itself ──
// Each input was packed with `xz --format=raw --x86[=start=0x1000] --lzma2=preset=0,dict=64KiB` and unpacked with the LZMA2 filter
// only, which leaves the converted bytes: `x86_kats[k].plain` converts to `.coded` (start 0) and `.coded_1000` (start 0x1000).
// The inputs are runs of 0xE8/0xE9 opcodes, 0x00/0xFF sign bytes and fillers, so the `prev_mask` history is exercised
// (a branch opcode within 1..5 bytes of the previous one, allowed and refused masks).

const X86Kat = struct { plain: []const u8, coded: []const u8, coded_1000: []const u8 };
const x86_kats = [_]X86Kat{
    .{
        .plain = "\xff\xe9\xe8\xe8\xe8\x00\xe8\xe8\xff\x80\xe8\xe8\x00\xe8\x00\xff\x12\x80\x80\xe8\xff\xe8\xe8\xe8\xe8\xe8\xff\x00\xe8\xe8\xff\xff\x00\x00\xff\xff\x80\x00\xe9\x00",
        .coded = "\xff\xe9\xee\xe8\xe8\x00\xe8\xe8\xff\x80\xe8\xf7\x00\xe8\x00\xff\x12\x80\x80\xe8\xff\xe8\xe8\xe8\xe8\xe8\xff\x00\xe8\x09\x00\x00\xff\x00\xff\xff\x80\x00\xe9\x00",
        .coded_1000 = "\xff\xe9\xee\xf8\xe8\x00\xe8\xe8\xff\x80\xe8\xf7\x10\xe8\x00\xff\x12\x80\x80\xe8\xff\xe8\xe8\xe8\xe8\xe8\xff\x00\xe8\x09\x10\x00\xff\x00\xff\xff\x80\x00\xe9\x00",
    },
    .{
        .plain = "\xff\x80\xff\xe8\x00\x12\xe9\xe8\x00\x00\x12\x00\x12\xff\x80\xe8\xe9\xff\xe8\x00\xff\xe8\x00\x12\xe8\xe8\x12\xe9\xe8\x00\xff\xff\xe8\x80\xff\xff\xe8\x00\xe8\xff\xff\x12\xff\xe8\xe8\xff\x12\x80\xe8\xff\xff\x12\xff\x00\xff\xe8\xe8\x00\xff\xe8\xff\x00\xe9\xe9\x12\xe8\xe8\x12\xff\xe8\xe8\xff\xe8\xff\xe8\xff\xe9\x12\x12\x00\xff\x12\x12\x12\x00\xe8\xff\x12\xe8\x12\x12\xe8\xe8\xe8\x12\xe8\xff",
        .coded = "\xff\x80\xff\xe8\x00\x12\xe9\xe8\x0c\x00\x12\x00\x12\xff\x80\xe8\xfd\xff\xe8\x00\xff\xe8\x00\x12\xe8\xe8\x30\xe9\xe8\x00\xff\xff\xe8\x80\xff\xff\xe8\x29\xe8\xff\xff\x12\xff\xe8\xe8\xff\x12\x80\xe8\x34\x00\x13\xff\x00\xff\xe8\xe8\x3d\xff\xe8\xff\x00\xe9\xe9\x12\xe8\xe8\x12\xff\xe8\x32\x00\xe9\xff\xe8\xff\xe9\x63\x12\x00\xff\x12\x12\x12\x00\xe8\xff\x12\xe8\x12\x12\xe8\xe8\x49\x13\xe8\xff",
        .coded_1000 = "\xff\x80\xff\xe8\x00\x12\xe9\xe8\x0c\x10\x12\x00\x12\xff\x80\xe8\xfd\x0f\xe9\x00\xff\xe8\x00\x12\xe8\xe8\x30\xf9\xe8\x00\xff\xff\xe8\x80\xff\xff\xe8\x29\xf8\xff\xff\x12\xff\xe8\xe8\xff\x12\x80\xe8\x34\x10\x13\xff\x00\xff\xe8\xe8\x3d\x0f\xe9\xff\x00\xe9\xe9\x12\xe8\xe8\x12\xff\xe8\x32\x10\xe9\xff\xe8\xff\xe9\x63\x22\x00\xff\x12\x12\x12\x00\xe8\xff\x12\xe8\x12\x12\xe8\xe8\x49\x23\xe8\xff",
    },
    .{
        .plain = "\xff\xe8\xff\xe8\x00\xff\xe8\xff\xe8\x00\xe8\xff\xe8\xff\xe8\xe9\xff\xff\xff\xff\x80\x12\xff\xe8\x12\xe9\xe9\xff\xff\x12\x12\xe9\xe9\xff\xff\xe9\xff\x12\x80\xff\xff\x80\xff\xff\xff\xe9\xe9\x00\xe8\xe9\x00\xe8\x80\x80\x00\xff\x80\xe9\xff\x80\xff\x80\xff\x80",
        .coded = "\xff\xe8\x05\xe9\x00\xff\xe8\xff\xe8\x00\xe8\xff\xe8\x10\xe9\xe9\xff\xff\xff\xff\x80\x12\xff\xe8\x2e\xe9\xe9\xff\xff\x12\x12\xe9\xe9\x24\x00\xea\xff\x12\x80\xff\xff\x80\xff\xff\xff\xe9\xe9\x33\xe8\xe9\x00\xe8\xb8\x80\x00\xff\x80\xe9\xff\x80\xff\x80\xff\x80",
        .coded_1000 = "\xff\xe8\x05\xf9\x00\xff\xe8\xff\xe8\x00\xe8\xff\xe8\x10\xf9\xe9\xff\xff\xff\xff\x80\x12\xff\xe8\x2e\xf9\xe9\xff\xff\x12\x12\xe9\xe9\x24\x10\xea\xff\x12\x80\xff\xff\x80\xff\xff\xff\xe9\xe9\x33\xf8\xe9\x00\xe8\xb8\x90\x00\xff\x80\xe9\xff\x80\xff\x80\xff\x80",
    },
    .{
        .plain = "\x12\x80\xe8\xe8\xe8\xe9\xff\xff\xff\x80\xe8\xe8\xe9\xff\xe8\xe8\xe8\xe8\xff\x12\x00\xe9\xe8\xe9\x80\xff\xff\xe9\x12\x00\xe8\x00\x80\x00\xe9\xe9\xe8\x12\x00\xe9\xe8\xff\xff\x00\x00\xff\xff\xe8\x00\xe8\xff\xff\x80\xff\xe9\x00\xe8\xe8\xe8\xe9\xe8\xe9\x00\x80",
        .coded = "\x12\x80\xe8\xef\xe8\xe9\xff\xff\xff\x80\xe8\xe8\xe9\xff\xe8\xe8\xe8\xe8\xff\x12\x00\xe9\x02\xea\x80\xff\xff\xe9\x32\x00\xe8\x00\x80\x00\xe9\x10\xe9\x12\x00\xe9\x14\x00\x00\xff\x00\xff\xff\xe8\x34\xe8\xff\xff\x80\xff\xe9\x00\xe8\xe8\xe8\xe9\xe8\xe9\x00\x80",
        .coded_1000 = "\x12\x80\xe8\xef\xf8\xe9\xff\xff\xff\x80\xe8\xe8\xe9\xff\xe8\xe8\xe8\xe8\xff\x12\x00\xe9\x02\xfa\x80\xff\xff\xe9\x32\x10\xe8\x00\x80\x00\xe9\x10\xf9\x12\x00\xe9\x14\x10\x00\xff\x00\xff\xff\xe8\x34\xf8\xff\xff\x80\xff\xe9\x00\xe8\xe8\xe8\xe9\xe8\xe9\x00\x80",
    },
    .{
        .plain = "\xff\xe9\xe8\x00\xe9\xe9\xe9\xe9\xe8\x80\xe8\xff\x12\x00\x00\x80\x00\x00\x00\x00\xe8\x80\x80\xe8\xe9\xe8\x80\x80\x12\x80\x12\xe8\xe8\x12\xff\xff\x80\xff\x00\xe9\xe9\xff\xe8\x00\x80\xe8\xff\x00\x00\xe9\xe9\x00\xe8\xe8\x12\xe8\xe8\xff\xe8\x00\xe8\x80\xe9\xe8\xe8\xff\xff\x00\x00\xe8\x12\xe9\x00\xe8\xff\xe8\x00\xff\x00\x12\xff\xe8\xe8\x00\x00\x00\xff\x00\x00\xe8\xff\x12\x00\x12\x12\x00\x12",
        .coded = "\xff\xe9\xe8\x00\xe9\xe9\xe9\xe9\xe8\x80\xe8\xff\x12\x00\x00\x80\x00\x00\x00\x00\xe8\x80\x80\xe8\xe9\xe8\x80\x80\x12\x80\x12\xe8\x0c\x13\xff\xff\x80\xff\x00\xe9\x15\x00\xe9\x00\x80\xe8\xff\x00\x00\xe9\xe9\x00\xe8\xe8\x12\xe8\xe8\xff\xe8\x00\xe8\x80\xe9\x2b\xe9\xff\xff\x00\x00\xe8\x12\xe9\x00\xe8\x4d\xe9\x00\xff\x00\x12\xff\xe8\x3e\x01\x00\x00\xff\x00\x00\xe8\xff\x12\x00\x12\x12\x00\x12",
        .coded_1000 = "\xff\xe9\xe8\x00\xe9\xe9\xe9\xe9\xe8\x80\xe8\xff\x12\x00\x00\x80\x00\x00\x00\x00\xe8\x80\x80\xe8\xe9\xe8\x80\x80\x12\x80\x12\xe8\x0c\x23\xff\xff\x80\xff\x00\xe9\x15\x10\xe9\x00\x80\xe8\xff\x00\x00\xe9\xe9\x00\xe8\xe8\x12\xe8\xe8\xff\xe8\x00\xe8\x80\xe9\x2b\xf9\xff\xff\x00\x00\xe8\x12\xe9\x00\xe8\x4d\xf9\x00\xff\x00\x12\xff\xe8\x3e\x11\x00\x00\xff\x00\x00\xe8\xff\x12\x00\x12\x12\x00\x12",
    },
    .{
        .plain = "\x00\xe9\x80\x80\x00\x00\x00\x80\x00\xe8\xe8\x80\x00\xe8\xe8\xe8\xff\xff\xe8\x00\xe8\x00\xff\xff\x00\x80\xe8\x80\x00\xff\xe9\x80\xff\xff\x00\xe9\x80\x80\x00\xff\x80\xe9\x00\xe8\x00\xe8\x00\x80\xe9\x80\x00\x00\x80\xe8\xe9\x00\x12\xe8\x00\xe9\xff\x00\x00\x00",
        .coded = "\x00\xe9\x86\x80\x00\x00\x00\x80\x00\xe8\xe8\x80\x00\xe8\xfa\xe8\xff\xff\xe8\x17\xe8\x00\xff\xff\x00\x80\xe8\x80\x00\xff\xe9\xa3\xff\xff\x00\xe9\xa8\x80\x00\xff\x80\xe9\x00\xe8\x00\xe8\x00\x80\xe9\x80\x00\x00\x80\xe8\xe9\x3b\x12\xe8\x00\xe9\x3f\x01\x00\x00",
        .coded_1000 = "\x00\xe9\x86\x90\x00\x00\x00\x80\x00\xe8\xe8\x80\x00\xe8\xfa\xf8\xff\xff\xe8\x17\xf8\x00\xff\xff\x00\x80\xe8\x80\x00\xff\xe9\xa3\x0f\x00\xff\xe9\xa8\x90\x00\xff\x80\xe9\x00\xe8\x00\xe8\x00\x80\xe9\x80\x00\x00\x80\xe8\xe9\x3b\x22\xe8\x00\xe9\x3f\x11\x00\x00",
    },
    .{
        .plain = "\xe8\x10\x20\x30\x00\xe8\x10\x20\x30\x00\x00\xe8\x10\x20\x30\x00\x00\x00\xe8\x10\x20\x30\x00\x00\x00\x00\xe8\x10\x20\x30\x00\x00\x00\x00\x00\xe8\x10\x20\x30\x00\x00\x00\x00\x00\x00\xe8\x10\x20\x30\x00\x00\x00\x00\x00\x00\x00\xe8\x10\x20\x30\x00\x00\x00\x00\x00\x00\x00\x00\xe9\x01\x02\x03\xff\xe9\x01\x02\x03\xff\xe8\xe9\x01\x02\x03\xff\xe8\xe8\xe9\x01\x02\x03\xff\xe8\xe8\xe8\xe9\x01\x02\x03\xff\xe8\xe8\xe8\xe8\xe9\x01\x02\x03\xff\xe8\xe8\xe8\xe8\xe8\xe9\x01\x02\x03\xff\xe8\xe8\xe8\xe8\xe8\xe8\xe9\x01\x02\x03\xff\xe8\xe8\xe8\xe8\xe8\xe8\xe8",
        .coded = "\xe8\x15\x20\x30\x00\xe8\x1a\x20\x30\x00\x00\xe8\x20\x20\x30\x00\x00\x00\xe8\x27\x20\x30\x00\x00\x00\x00\xe8\x2f\x20\x30\x00\x00\x00\x00\x00\xe8\x38\x20\x30\x00\x00\x00\x00\x00\x00\xe8\x42\x20\x30\x00\x00\x00\x00\x00\x00\x00\xe8\x4d\x20\x30\x00\x00\x00\x00\x00\x00\x00\x00\xe9\x4a\x02\x03\xff\xe9\x4f\x02\x03\xff\xe8\xe9\x55\x02\x03\xff\xe8\xe8\xe9\x01\x02\x03\xff\xe8\xe8\xe8\xe9\x01\x02\x03\xff\xe8\xe8\xe8\xe8\xe9\x01\x02\x03\xff\xe8\xe8\xe8\xe8\xe8\xe9\x01\x02\x03\xff\xe8\xe8\xe8\xe8\xe8\xe8\xe9\x01\x02\x03\xff\xe8\xe8\xe8\xe8\xe8\xe8\xe8",
        .coded_1000 = "\xe8\x15\x30\x30\x00\xe8\x1a\x30\x30\x00\x00\xe8\x20\x30\x30\x00\x00\x00\xe8\x27\x30\x30\x00\x00\x00\x00\xe8\x2f\x30\x30\x00\x00\x00\x00\x00\xe8\x38\x30\x30\x00\x00\x00\x00\x00\x00\xe8\x42\x30\x30\x00\x00\x00\x00\x00\x00\x00\xe8\x4d\x30\x30\x00\x00\x00\x00\x00\x00\x00\x00\xe9\x4a\x12\x03\xff\xe9\x4f\x12\x03\xff\xe8\xe9\x55\x12\x03\xff\xe8\xe8\xe9\x01\x02\x03\xff\xe8\xe8\xe8\xe9\x01\x02\x03\xff\xe8\xe8\xe8\xe8\xe9\x01\x02\x03\xff\xe8\xe8\xe8\xe8\xe8\xe9\x01\x02\x03\xff\xe8\xe8\xe8\xe8\xe8\xe8\xe9\x01\x02\x03\xff\xe8\xe8\xe8\xe8\xe8\xe8\xe8",
    },
    .{
        .plain = "\xff\xe9\xe8\xff\xe8\xe9\x80\xe8\x00\x80\x12\xe8\xe9\xff\xe9\x80\xe9\x80\x00\xe9\x00\xe8\xff\xe9",
        .coded = "\xff\xe9\xe8\xff\xe8\xe9\x80\xe8\x00\x80\x12\xe8\xe9\xff\xe9\x80\xe9\x80\x00\xe9\x00\xe8\xff\xe9",
        .coded_1000 = "\xff\xe9\xe8\xff\xe8\xe9\x80\xe8\x00\x80\x12\xe8\xe9\xff\xe9\x80\xe9\x80\x00\xe9\x00\xe8\xff\xe9",
    },
    .{
        .plain = "\xe8\xe9\x00\x00\xe8\x00\x80\x12\xff\xe9\x80\xe9\x00\xe9\x80\xe9\x80\x80\xe8\xe9\x00\x12\xff\x80\xe9\x80\xe9\x80\xff\x00\xff\x00\xe9\xff\xe9\x00",
        .coded = "\xe8\xe9\x06\x00\xe8\x00\x80\x12\xff\xe9\x80\xe9\x00\xe9\x80\xe9\x80\x80\xe8\x16\x02\x12\xff\x80\xe9\x9d\xe9\x80\xff\x00\xff\x00\xe9\xff\xe9\x00",
        .coded_1000 = "\xe8\xe9\x06\x10\xe8\x00\x80\x12\xff\xe9\x80\xe9\x00\xe9\x80\xe9\x80\x80\xe8\x16\x22\x12\xff\x80\xe9\x9d\xf9\x80\xff\x00\xff\x00\xe9\xff\xe9\x00",
    },
};

test "mutation 2026-11-27: x86 converter equals xz's on opcode runs of every spacing, with and without a start offset" {
    var buf: [256]u8 = undefined;
    for (x86_kats) |k| {
        try runChain(&.{.{ .x86 = .{} }}, k.plain, true, k.plain.len, buf[0..k.plain.len]);
        try testing.expectEqualSlices(u8, k.coded, buf[0..k.plain.len]);
        try runChain(&.{.{ .x86 = .{} }}, k.coded, false, k.plain.len, buf[0..k.plain.len]);
        try testing.expectEqualSlices(u8, k.plain, buf[0..k.plain.len]);
        // a piece size of 1 and of 7 gives the same bytes (state kept across calls)
        for ([_]usize{ 1, 7 }) |piece| {
            try runChain(&.{.{ .x86 = .{} }}, k.plain, true, piece, buf[0..k.plain.len]);
            try testing.expectEqualSlices(u8, k.coded, buf[0..k.plain.len]);
        }
        const f1000 = [_]Filter{.{ .x86 = .{ .start_offset = 0x1000 } }};
        try runChain(&f1000, k.plain, true, k.plain.len, buf[0..k.plain.len]);
        try testing.expectEqualSlices(u8, k.coded_1000, buf[0..k.plain.len]);
        try runChain(&f1000, k.coded_1000, false, k.plain.len, buf[0..k.plain.len]);
        try testing.expectEqualSlices(u8, k.plain, buf[0..k.plain.len]);
    }
}

// ── block header with filters ────────────────────────────────────────────

/// A block header of `body.len + 4` bytes: the size byte, the body and the CRC32 of both.
fn blockHeader(comptime body_len: usize, body: [body_len]u8) [body_len + 5]u8 {
    var h: [body_len + 5]u8 = undefined;
    h[0] = (body_len + 5) / 4 - 1;
    @memcpy(h[1..][0..body_len], &body);
    std.mem.writeInt(u32, h[body_len + 1 ..][0..4], std.hash.Crc32.hash(h[0 .. body_len + 1]), .little);
    return h;
}

test "mutation 2026-11-27: a filter the decoder does not know, or one with refused properties, is UnsupportedFilter, not skipped" {
    const xzfmt = @import("xzfmt.zig");
    // flags 0x01: two filters. Filter 0x0B (RISC-V BCJ, not supported here), then LZMA2 (id 0x21, one property byte 0x16);
    // body padded to a multiple of 4 with the size byte and the CRC (header 12 bytes).
    const unknown = blockHeader(7, .{ 0x01, 0x0B, 0x00, 0x21, 0x01, 0x16, 0x00 });
    try testing.expectError(error.UnsupportedFilter, xzfmt.parseBlockHeader(&unknown));
    // a known filter with a property size it refuses: x86 takes none or four property bytes, here two
    const refused = blockHeader(11, .{ 0x01, 0x04, 0x02, 0x00, 0x00, 0x21, 0x01, 0x16, 0x00, 0x00, 0x00 });
    try testing.expectError(error.UnsupportedFilter, xzfmt.parseBlockHeader(&refused));
    // the same header with a good x86 and no property bytes parses and lists the filter
    const good = blockHeader(7, .{ 0x01, 0x04, 0x00, 0x21, 0x01, 0x16, 0x00 });
    const h = try xzfmt.parseBlockHeader(&good);
    try testing.expectEqual(@as(u8, 1), h.n_filters);
    try testing.expectEqual(@as(u8, 0x04), h.filters[0].id());
}

test "mutation 2026-11-27: a filtered stream longer than one 64 KiB chunk round-trips, with branches across the chunk edges" {
    const n = 3 * filters.chunk + 1234;
    const plain = try gpa.alloc(u8, n);
    defer gpa.free(plain);
    textBytes(plain, 21);
    // x86 branches (0xE8 with a 0x00 sign byte four bytes on) all over the data...
    var p: usize = 5;
    while (p + 5 < n) : (p += 997) {
        plain[p] = 0xE8;
        plain[p + 4] = 0x00;
    }
    // ...and one in the last four bytes of each of the first three chunks, so its operand reaches into the next one
    for ([_]usize{ filters.chunk - 4, 2 * filters.chunk - 3, 3 * filters.chunk - 2 }) |q| {
        plain[q] = 0xE8;
        plain[q + 4] = 0xFF;
    }
    const lists = [_][]const Filter{ &.{.{ .x86 = .{} }}, &.{.{ .ia64 = .{} }}, &.{ .{ .delta = 3 }, .{ .x86 = .{} } } };
    for (lists) |fl| {
        const o = lzma.EncodeOptions{ .lzma = lzma.preset(0, false), .filters = fl };
        const z = try lzma.compress(gpa, plain, .xz, o);
        defer gpa.free(z);
        const back = try lzma.decompress(gpa, z, .xz, .{});
        defer gpa.free(back);
        try testing.expectEqualSlices(u8, plain, back);
    }
}

// ── one filter chain per block: each block restarts it, as xz does ───────

/// The same 3000 bytes as `filters_test.zig`'s `input` (compressible, with branch opcodes planted for every converter).
fn planted(buf: []u8) void {
    var x: u32 = 12345;
    for (buf) |*b| {
        x = x *% 1664525 +% 1013904223;
        b.* = @truncate((x >> 24) & 0x1F);
    }
    for (buf, 0..) |*b, i| switch (i % 32) {
        0 => b.* = 0xE8,
        4 => b.* = 0,
        5 => b.* = 0xFF,
        7 => b.* = 0xEB,
        11 => b.* = 0x94,
        16 => b.* = 0x48,
        19 => b.* = 1,
        20 => b.* = 0x40,
        21 => b.* = 0x10,
        25 => b.* = 0xF0 | (b.* & 7),
        27 => b.* = 0xF8 | (b.* & 7),
        else => {},
    };
}

test "mutation 2026-11-27: filtered multi-block streams equal xz's (the chain restarts at every block), up to three filters" {
    const Case = struct { opts: lzma.EncodeOptions, len: usize, sha: []const u8 };
    // made by xz 5.8.3: `xz --format=xz --check=crc64 -T1 <filters> --lzma2=preset=1 --block-size=N` over `planted` (3000 bytes)
    const cases = [_]Case{
        .{ .opts = .{ .lzma = lzma.preset(1, false), .filters = &.{.{ .x86 = .{} }}, .block_size = 1000 }, .len = 2476, .sha = "3be3e78de7e9ab760ff1af0a148e686e7a8a8201e35cae8b195ff46375be6fb0" },
        .{ .opts = .{ .lzma = lzma.preset(1, false), .filters = &.{ .{ .delta = 3 }, .{ .x86 = .{} } }, .block_size = 1000 }, .len = 2980, .sha = "dec7fcf1bfea50ca893fea29c02eca1cb4ed0defc7dd0ee78119aba4e054407b" },
        .{ .opts = .{ .lzma = lzma.preset(1, false), .filters = &.{.{ .arm64 = .{} }}, .block_size = 700 }, .len = 2624, .sha = "2271a71ed5dffb1a47f955413973c5a969b054fea99a63dfe716d9a885be6d02" },
    };
    var plain: [3000]u8 = undefined;
    planted(&plain);
    for (cases) |cs| {
        const z = try lzma.compress(gpa, &plain, .xz, cs.opts);
        defer gpa.free(z);
        var h: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(z, &h, .{});
        var want: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&want, cs.sha);
        try testing.expectEqual(cs.len, z.len);
        try testing.expectEqualSlices(u8, &want, &h);
        const back = try lzma.decompress(gpa, z, .xz, .{});
        defer gpa.free(back);
        try testing.expectEqualSlices(u8, &plain, back);
    }
    // three filters before LZMA2 are allowed (a fourth is refused, see filters_test)
    const three = lzma.EncodeOptions{ .lzma = lzma.preset(0, false), .filters = &.{ .{ .delta = 1 }, .{ .x86 = .{} }, .{ .arm = .{} } } };
    const z3 = try lzma.compress(gpa, &plain, .xz, three);
    defer gpa.free(z3);
    const back3 = try lzma.decompress(gpa, z3, .xz, .{});
    defer gpa.free(back3);
    try testing.expectEqualSlices(u8, &plain, back3);
}
