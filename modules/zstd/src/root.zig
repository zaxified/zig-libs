// SPDX-License-Identifier: MIT
//! zstd — Zstandard (RFC 8878) compressor for every level, 1-22 and the
//! negative ("fast") levels, byte-identical to libzstd 1.5.7.
//!
//! Decoding is std's job (`std.compress.zstd.Decompress`); this module fills
//! the other half. It is a port of every libzstd strategy — `fast`, `dfast`,
//! `greedy`, `lazy`, `lazy2` (hash-chain and row match finders), `btlazy2`,
//! and the optimal parsers `btopt`, `btultra`, `btultra2` — with the frame
//! and block driver, the block pre- and post-splitters, long-distance
//! matching (which libzstd switches on at level 22 for inputs over 64 MB),
//! and the Huffman and FSE encoders. For the same input and level it emits exactly the bytes
//! `ZSTD_compress2()` from libzstd v1.5.7 does (one-shot, content size in the
//! header, checksum optional) — that equality is what the tests pin, not
//! merely round-trips.
//!
//! `Stream` is libzstd's streaming compression (`ZSTD_compressStream2`):
//! the same bytes for the same sequence of calls, at levels up to 3 so far.
//!
//! Level 22 on an input over 64 MB uses a 128 MB window: about 820 MB of
//! match tables, as in libzstd. See SPEC.md.

const std = @import("std");
const frame = @import("frame.zig");
const params = @import("params.zig");
const frame_writer = @import("frame_writer.zig");
const stream = @import("stream.zig");

pub const meta = .{
    .doc = "Zstandard (RFC 8878) compressor, levels 1-22 and negative levels — byte-identical to libzstd 1.5.7 `ZSTD_compress2` (and `ZSTD_compressStream2` at levels up to 3); decode with `std.compress.zstd`",
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "libzstd 1.5.7 (facebook/zstd), every strategy fast..btultra2; output checked byte-for-byte against it",
    .deps = .{},
};

pub const Options = struct {
    /// 1..22, 0 for the default (3), or negative for the faster "fast" levels
    /// (down to -131072; lower values are clamped, as libzstd does).
    level: i32 = params.default_level,
    /// Append the XXH64-based content checksum (frame header flag + 4 bytes).
    checksum: bool = false,
};

pub const Error = frame.Error || error{
    /// Level above `max_level` (22). libzstd clamps it to 22; this module
    /// refuses rather than silently compress at another level.
    LevelUnsupported,
};

pub const max_level = params.max_level;
pub const min_level = params.min_level;
pub const default_level = params.default_level;

/// Worst-case compressed size of `src_size` bytes (`ZSTD_compressBound`).
pub fn compressBound(src_size: usize) usize {
    return frame.compressBound(src_size);
}

/// Compress `src` into one frame in `dst`, which must hold at least
/// `compressBound(src.len)` bytes. Returns the frame length. `gpa` is used
/// for the match tables and block buffers only, all freed before returning.
pub fn compress(gpa: std.mem.Allocator, dst: []u8, src: []const u8, opts: Options) Error!usize {
    if (opts.level > max_level) return error.LevelUnsupported;
    return frame.compress(gpa, dst, src, .{ .level = opts.level, .checksum = opts.checksum });
}

/// A `std.Io.Writer` that emits one frame per buffer fill and per flush
/// (see frame_writer.zig): streaming output, not yet libzstd's streaming
/// bytes.
pub const FrameWriter = frame_writer.FrameWriter;
pub const FrameWriterOptions = frame_writer.Options;

/// Streaming compression, byte-identical to libzstd's `ZSTD_compressStream2`
/// for the same sequence of calls (see stream.zig). Levels up to
/// `stream_max_level` for now.
pub const Stream = stream.Stream;
pub const StreamOptions = stream.Options;
pub const StreamError = stream.Error;
pub const EndDirective = stream.EndDirective;
pub const InBuffer = stream.InBuffer;
pub const OutBuffer = stream.OutBuffer;
pub const stream_max_level = stream.max_level;

/// Compress `src` into a newly allocated frame owned by the caller.
pub fn compressAlloc(gpa: std.mem.Allocator, src: []const u8, opts: Options) Error![]u8 {
    const buf = try gpa.alloc(u8, compressBound(src.len));
    errdefer gpa.free(buf);
    const n = try compress(gpa, buf, src, opts);
    return gpa.realloc(buf, n) catch buf[0..n];
}

test {
    _ = @import("bitstream.zig");
    _ = @import("hist.zig");
    _ = @import("fse.zig");
    _ = @import("huf.zig");
    _ = @import("sequences.zig");
    _ = @import("literals.zig");
    _ = @import("params.zig");
    _ = @import("match.zig");
    _ = @import("lazy.zig");
    _ = @import("opt.zig");
    _ = @import("ldm.zig");
    _ = @import("presplit.zig");
    _ = @import("frame.zig");
    _ = @import("frame_writer.zig");
    _ = @import("stream.zig");
    _ = @import("stream_test.zig");
    _ = @import("golden_test.zig");
    _ = @import("fuzz_test.zig");
}

/// Decode with std. std's own checksum verification is a TODO panic in the
/// streaming path (0.16), so a checksummed frame is checked here instead.
fn decompress(gpa: std.mem.Allocator, compressed: []const u8, has_checksum: bool) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var in: std.Io.Reader = .fixed(compressed);
    var d: std.compress.zstd.Decompress = .init(&in, &.{}, .{ .verify_checksum = false });
    _ = try d.reader.streamRemaining(&out.writer);
    const plain = try out.toOwnedSlice();
    errdefer gpa.free(plain);
    try std.testing.expectEqual(has_checksum, compressed[4] & 4 != 0);
    if (has_checksum) {
        const want: u32 = @truncate(std.hash.XxHash64.hash(0, plain));
        try std.testing.expectEqual(want, std.mem.readInt(u32, compressed[compressed.len - 4 ..][0..4], .little));
    }
    return plain;
}

test "empty input is the 9-byte frame libzstd emits" {
    const gpa = std.testing.allocator;
    const z = try compressAlloc(gpa, "", .{});
    defer gpa.free(z);
    try std.testing.expectEqualSlices(u8, &.{ 0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x00, 0x01, 0x00, 0x00 }, z);
}

test "round trip through std's decoder at every implemented level" {
    const gpa = std.testing.allocator;
    var src: [40000]u8 = undefined;
    var prng: std.Random.DefaultPrng = .init(0x5eed);
    const words = [_][]const u8{ "alpha ", "beta ", "gamma ", "delta,", "42;", "\n", "zstd " };
    var i: usize = 0;
    while (i < src.len) {
        const w = words[prng.random().uintLessThan(usize, words.len)];
        const n = @min(w.len, src.len - i);
        @memcpy(src[i..][0..n], w[0..n]);
        i += n;
    }
    for ([_]i32{ -5, -1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 16, 19, 21, 22 }) |level| {
        for ([_]bool{ false, true }) |ck| {
            const z = try compressAlloc(gpa, &src, .{ .level = level, .checksum = ck });
            defer gpa.free(z);
            try std.testing.expect(z.len < src.len / 2);
            const back = try decompress(gpa, z, ck);
            defer gpa.free(back);
            try std.testing.expectEqualSlices(u8, &src, back);
        }
    }
}

test "levels above 22 are refused, not clamped" {
    var buf: [64]u8 = undefined;
    try std.testing.expectError(error.LevelUnsupported, compress(std.testing.allocator, &buf, "x", .{ .level = 23 }));
}

test "a destination below the bound is refused" {
    var buf: [8]u8 = undefined;
    try std.testing.expectError(error.NoSpaceLeft, compress(std.testing.allocator, &buf, "hello", .{}));
}
