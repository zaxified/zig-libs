//! brotli — pure-Zig Brotli (RFC 7932) decompressor + minimal encoder.
//!
//! Decoder: byte-exact RFC 7932 decompression (bit stream, meta-blocks,
//! simple + complex Huffman codes, block-type/count machinery, literal context
//! modeling, the postfix/direct/ring-buffer distance model, and the normative
//! static dictionary + transforms of Appendix A/B). Malformed input never
//! panics — it returns a typed `BrotliError`. Output is bounded by
//! `Options.max_output` (a decompression-bomb guard).
//!
//! Encoder: emits a valid `Content-Encoding: br` stream in store mode
//! (uncompressed meta-blocks). It round-trips and is accepted by compliant
//! decoders, but does not compress; see SPEC.md.

const std = @import("std");

const decoder = @import("decoder.zig");
const encoder = @import("encoder.zig");

pub const BrotliError = @import("errors.zig").BrotliError;
pub const Options = decoder.Options;

/// Decompress a complete Brotli stream. Caller owns the returned slice.
pub const decompress = decoder.decompress;

/// Compress `input` into a valid (store-mode) Brotli stream. Caller owns it.
pub const compress = encoder.compress;

// ===========================================================================
// Tests
// ===========================================================================
const testing = std.testing;

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
