//! brotli — pure-Zig Brotli (RFC 7932) decompressor + minimal encoder.
//!
//! Decoder: byte-exact RFC 7932 decompression (bit stream, meta-blocks,
//! simple + complex Huffman codes, block-type/count machinery, literal context
//! modeling, the postfix/direct/ring-buffer distance model, and the normative
//! static dictionary + transforms of Appendix A/B). Malformed input never
//! panics — it returns a typed `BrotliError`. Output is bounded by
//! `Options.max_output` (a decompression-bomb guard).
//!
//! Encoder: LZ77 backward references plus a per-meta-block Huffman code for
//! literals, insert-and-copy commands and distances, with a store-mode fallback
//! for anything that would not shrink. Roughly 2.8x on English text. Its output
//! is checked against the reference implementation (google/brotli), not only
//! against this module's own decoder; see SPEC.md.

const std = @import("std");

const decoder = @import("decoder.zig");
const encoder = @import("encoder.zig");

pub const BrotliError = @import("errors.zig").BrotliError;
pub const Options = decoder.Options;

/// Decompress a complete Brotli stream. Caller owns the returned slice.
pub const decompress = decoder.decompress;

/// Compress `input` into a valid Brotli stream. Caller owns the returned slice.
/// Fails only on allocation: any block that will not compress is stored
/// verbatim, so the result is always a conformant `br` body.
pub const compress = encoder.compress;

// ===========================================================================
// Tests
// ===========================================================================
const testing = std.testing;

test {
    // Live interop against the reference implementation (skips loudly when
    // python3 / the `brotli` package is unavailable).
    _ = @import("reference_interop.zig");
}

fn expectDecodes(comptime name: []const u8) !void {
    const plain = @embedFile("testdata/" ++ name);
    const comp = @embedFile("testdata/" ++ name ++ ".compressed");
    const got = try decompress(testing.allocator, comp, .{});
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, plain, got);
}

test "decode: empty stream" {
    try expectDecodes("empty");
}

test "decode: single byte (x)" {
    try expectDecodes("x");
}

test "decode: short literals (xyzzy)" {
    try expectDecodes("xyzzy");
}

test "decode: simple LZ77 (10x10y)" {
    try expectDecodes("10x10y");
}

test "decode: run copy (64x)" {
    try expectDecodes("64x");
}

test "decode: static dictionary (quickfox)" {
    try expectDecodes("quickfox");
}

test "decode: dictionary + backward refs (quickfox_repeated)" {
    try expectDecodes("quickfox_repeated");
}

test "decode: classic (ukkonooa)" {
    try expectDecodes("ukkonooa");
}

test "decode: long run of zeros (zeros)" {
    try expectDecodes("zeros");
}

test "decode: zeros + dictionary (zerosukkanooa)" {
    try expectDecodes("zerosukkanooa");
}

test "decode: mixed text (monkey)" {
    try expectDecodes("monkey");
}

test "decode: large backward window (backward65536)" {
    try expectDecodes("backward65536");
}

test "decode: incompressible random (random_org_10k.bin)" {
    try expectDecodes("random_org_10k.bin");
}

test "decode: compressed-then-recompressed (compressed_file)" {
    try expectDecodes("compressed_file");
}

test "decode: UTF-8 text (cp852-utf8)" {
    try expectDecodes("cp852-utf8");
}

test "decode: UTF-16LE bytes (cp1251-utf16le)" {
    try expectDecodes("cp1251-utf16le");
}

test "decode: full English text, complex Huffman (alice29.txt)" {
    try expectDecodes("alice29.txt");
}

test "decode: output cap enforced (DoS guard)" {
    const comp = @embedFile("testdata/zeros.compressed");
    try testing.expectError(error.OutputTooLarge, decompress(testing.allocator, comp, .{ .max_output = 1000 }));
}

test "decode: truncated input errors, never panics" {
    const comp = @embedFile("testdata/alice29.txt.compressed");
    // A batch of truncations must all error cleanly (no panic, no crash).
    var len: usize = 0;
    while (len < comp.len) : (len += 97) {
        const r = decompress(testing.allocator, comp[0..len], .{});
        if (r) |ok| testing.allocator.free(ok) else |_| {}
    }
}

test "decode: hostile garbage errors, never panics" {
    var seed: u32 = 0x1234_5678;
    var i: usize = 0;
    while (i < 400) : (i += 1) {
        var buf: [64]u8 = undefined;
        for (&buf) |*b| {
            seed = seed *% 1664525 +% 1013904223;
            b.* = @truncate(seed >> 16);
        }
        const r = decompress(testing.allocator, &buf, .{ .max_output = 1 << 20 });
        if (r) |ok| testing.allocator.free(ok) else |_| {}
    }
}

test "decode: empty input is truncated error" {
    try testing.expectError(error.TruncatedInput, decompress(testing.allocator, "", .{}));
}

fn roundTrip(data: []const u8) !void {
    const comp = try compress(testing.allocator, data);
    defer testing.allocator.free(comp);
    const back = try decompress(testing.allocator, comp, .{});
    defer testing.allocator.free(back);
    try testing.expectEqualSlices(u8, data, back);
}

test "encode: round-trip empty" {
    try roundTrip("");
}

test "encode: round-trip small text" {
    try roundTrip("Hello, Brotli! The quick brown fox jumps over the lazy dog.");
}

test "encode: round-trip highly repetitive" {
    const data = "abcabcabc" ** 5000;
    try roundTrip(data);
}

test "encode: round-trip incompressible random" {
    var buf: [4096]u8 = undefined;
    var seed: u32 = 0xC0FFEE;
    for (&buf) |*b| {
        seed = seed *% 1664525 +% 1013904223;
        b.* = @truncate(seed >> 16);
    }
    try roundTrip(&buf);
}

test "encode: multi-block (> 16 MiB) round-trip" {
    const gpa = testing.allocator;
    const size = (16 * 1024 * 1024) + 4096; // spans two uncompressed meta-blocks
    const data = try gpa.alloc(u8, size);
    defer gpa.free(data);
    var seed: u32 = 42;
    for (data) |*b| {
        seed = seed *% 1103515245 +% 12345;
        b.* = @truncate(seed >> 16);
    }
    const comp = try compress(gpa, data);
    defer gpa.free(comp);
    const back = try decompress(gpa, comp, .{});
    defer gpa.free(back);
    try testing.expectEqualSlices(u8, data, back);
}

test "encode: output is a valid stream our decoder accepts for real corpus" {
    const plain = @embedFile("testdata/alice29.txt");
    try roundTrip(plain);
}

// --- encoder: compression, and the store-mode fallback ----------------------

test "encode: really compresses English text" {
    const plain = @embedFile("testdata/alice29.txt");
    const comp = try compress(testing.allocator, plain);
    defer testing.allocator.free(comp);
    // Store mode would be ~1.00; the reference manages ~2.9x at quality 1.
    // Anything above half the original means the compressed path silently
    // stopped being taken.
    try testing.expect(comp.len * 2 < plain.len);
    const back = try decompress(testing.allocator, comp, .{});
    defer testing.allocator.free(back);
    try testing.expectEqualSlices(u8, plain, back);
}

test "encode: incompressible input falls back to store mode" {
    var buf: [4096]u8 = undefined;
    var seed: u32 = 0xBADF00D;
    for (&buf) |*b| {
        seed = seed *% 1664525 +% 1013904223;
        b.* = @truncate(seed >> 16);
    }
    const comp = try compress(testing.allocator, &buf);
    defer testing.allocator.free(comp);
    // Store mode costs the window bits, one meta-block header, byte alignment
    // and the final empty meta-block — a handful of bytes, never a factor.
    try testing.expect(comp.len <= buf.len + 8);
    try roundTrip(&buf);
}

test "encode: output never blows up, whatever the input looks like" {
    const gpa = testing.allocator;
    var seed: u64 = 0x1234_5678_9abc_def0;
    var iter: usize = 0;
    while (iter < 60) : (iter += 1) {
        seed = seed *% 6364136223846793005 +% 1442695040888963407;
        const n: usize = @as(usize, @truncate(seed >> 12)) % 9000;
        const alphabet: usize = 1 + @as(usize, @truncate(seed >> 40)) % 256;
        const data = try gpa.alloc(u8, n);
        defer gpa.free(data);
        for (data) |*b| {
            seed = seed *% 6364136223846793005 +% 1442695040888963407;
            b.* = @intCast(@as(usize, @truncate(seed >> 21)) % alphabet);
        }
        const comp = try compress(gpa, data);
        defer gpa.free(comp);
        // Worst case is store mode plus its framing; a compressed block is only
        // kept when it is strictly smaller than storing the same bytes.
        try testing.expect(comp.len <= n + 16);
        const back = try decompress(gpa, comp, .{});
        defer gpa.free(back);
        try testing.expectEqualSlices(u8, data, back);
    }
}

test "encode: round-trip every input shape" {
    const gpa = testing.allocator;
    try roundTrip("a");
    try roundTrip("ab");
    try roundTrip("abc");
    try roundTrip(&[_]u8{0} ** 5);
    try roundTrip(&[_]u8{0xff} ** 100000);
    {
        // Every byte value present, so the literal code spans the alphabet.
        var buf: [256]u8 = undefined;
        for (&buf, 0..) |*b, i| b.* = @intCast(i);
        try roundTrip(&buf);
    }
    {
        // Matches at exactly the window edge, both sides of the wbits switch.
        for ([_]usize{ 65519, 65520, 65521 }) |n| {
            const buf = try gpa.alloc(u8, n + 8);
            defer gpa.free(buf);
            @memset(buf, 'z');
            @memcpy(buf[0..8], "preamble");
            @memcpy(buf[n..][0..8], "preamble");
            try roundTrip(buf);
        }
    }
    {
        // Two meta-blocks of compressible data.
        const alice = @embedFile("testdata/alice29.txt");
        const buf = try gpa.alloc(u8, (1 << 20) + 5000);
        defer gpa.free(buf);
        for (buf, 0..) |*b, i| b.* = alice[i % alice.len];
        try roundTrip(buf);
    }
}
