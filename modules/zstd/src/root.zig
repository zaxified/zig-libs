// SPDX-License-Identifier: MIT
//! zstd — Zstandard (RFC 8878) compressor for every level, 1-22 and the
//! negative ("fast") levels, byte-identical to libzstd 1.5.7, and a decoder
//! ported from libzstd's, one-shot and streaming.
//!
//! The compressor is a port of every libzstd strategy — `fast`, `dfast`,
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
//! the same bytes for the same sequence of calls. `Advanced` holds libzstd's
//! advanced parameters (`ZSTD_CCtx_setParameter`), with the same effect.
//!
//! Level 22 on an input over 64 MB uses a 128 MB window: about 820 MB of
//! match tables, as in libzstd.
//!
//! `Decompressor` / `decompress` / `decompressAlloc` decode whole frames
//! one-shot (`ZSTD_decompress`), with content checksums, concatenated and
//! skippable frames, and the frame queries (`getFrameContentSize`,
//! `decompressBound`, ...); `DecompressStream` (`ZSTD_decompressStream`)
//! and `DecompressReader` (a `std.Io.Reader`) decode in any pieces. Errors
//! carry libzstd's names. See SPEC.md.

const std = @import("std");
const frame = @import("frame.zig");
const params = @import("params.zig");
const frame_writer = @import("frame_writer.zig");
const stream = @import("stream.zig");
const dec = @import("decompress.zig");
const dstream = @import("dstream.zig");

pub const meta = .{
    .doc = "Zstandard (RFC 8878) compressor, levels 1-22 and negative levels — byte-identical to libzstd 1.5.7 `ZSTD_compress2` and `ZSTD_compressStream2`, with libzstd's advanced parameters (magicless frames, explicit window/strategy, splitters, block size) — and a decoder ported from libzstd's, one-shot and streaming (`ZSTD_decompressStream`, a `std.Io.Reader`), checksums, concatenated and skippable frames, frame queries",
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
    /// libzstd's advanced parameters (window, hash, strategy, frame flags,
    /// ...); each left to the level by default. Same bytes as libzstd with
    /// the same parameters set.
    advanced: Advanced = .{},
};

/// libzstd's advanced compression parameters (`ZSTD_CCtx_setParameter`),
/// with its bounds.
pub const Advanced = params.Advanced;
/// `ZSTD_strategy`.
pub const Strategy = params.Strategy;
/// `ZSTD_ParamSwitch_e`: auto / enable / disable.
pub const Switch = params.Switch;
/// `ZSTD_format_e`: with or without the magic number, for both directions.
pub const Format = params.Format;

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
    return frame.compress(gpa, dst, src, .{ .level = opts.level, .checksum = opts.checksum, .advanced = opts.advanced });
}

/// `ZSTD_SKIPPABLEHEADERSIZE`.
pub const skippable_header_size = dec.skippable_header_size;

pub const SkippableError = error{
    /// `dst` holds fewer than `src.len + skippable_header_size` bytes.
    NoSpaceLeft,
    /// `src` is 4 GiB or more (`srcSize_wrong`).
    SrcSizeWrong,
    /// `magic_variant` above 15 (`parameter_outOfBound`).
    ParameterOutOfBound,
};

/// `ZSTD_writeSkippableFrame`: a skippable frame holding `src`, with magic
/// number 0x184D2A50 + `magic_variant` (0..15). Decoders pass over it;
/// `readSkippableFrame` gives `src` back. Returns the bytes written.
pub fn writeSkippableFrame(dst: []u8, src: []const u8, magic_variant: u32) SkippableError!usize {
    if (dst.len < src.len + skippable_header_size) return error.NoSpaceLeft;
    if (src.len > std.math.maxInt(u32)) return error.SrcSizeWrong;
    if (magic_variant > 15) return error.ParameterOutOfBound;
    std.mem.writeInt(u32, dst[0..4], dec.magic_skippable_start + magic_variant, .little);
    std.mem.writeInt(u32, dst[4..8], @intCast(src.len), .little);
    @memcpy(dst[skippable_header_size..][0..src.len], src);
    return src.len + skippable_header_size;
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

/// Decoding context (libzstd's `ZSTD_DCtx`): reuse it across calls to
/// avoid reallocating its ~190 KB of tables.
pub const Decompressor = dec.Decompressor;
pub const DecompressOptions = dec.Options;
/// Errors named after libzstd's error codes (`ZSTD_error_*`).
pub const DecompressError = dec.Error;
pub const FrameHeader = dec.FrameHeader;
pub const FrameType = dec.FrameType;
pub const HeaderResult = dec.HeaderResult;
pub const SkippableFrame = dec.SkippableFrame;
pub const getFrameHeader = dec.getFrameHeader;
pub const getFrameHeaderAdvanced = dec.getFrameHeaderAdvanced;
pub const frameHeaderSize = dec.frameHeaderSize;
pub const getFrameContentSize = dec.getFrameContentSize;
pub const findFrameCompressedSize = dec.findFrameCompressedSize;
pub const findDecompressedSize = dec.findDecompressedSize;
pub const decompressBound = dec.decompressBound;
pub const decompressionMargin = dec.decompressionMargin;
pub const readSkippableFrame = dec.readSkippableFrame;
pub const getDictIdFromFrame = dec.getDictIdFromFrame;
pub const isFrame = dec.isFrame;
pub const isSkippableFrame = dec.isSkippableFrame;

/// Streaming decompression (`ZSTD_decompressStream`): input and output in
/// any pieces, through a window-sized output ring (or straight into a
/// stable output buffer); frames asking for more than 2^27 bytes of window
/// are refused unless `window_log_max` allows them.
pub const DecompressStream = dstream.DecompressStream;
pub const DecompressStreamOptions = dstream.Options;
pub const DecompressStreamError = dstream.Error;
/// A `std.Io.Reader` of the decompressed content of another reader.
pub const DecompressReader = dstream.Reader;

/// Decode every frame in `src` into `dst` (`ZSTD_decompress`): returns
/// the number of bytes written. Concatenated and skippable frames are
/// allowed; content checksums are verified.
pub fn decompress(gpa: std.mem.Allocator, dst: []u8, src: []const u8) (DecompressError || error{OutOfMemory})!usize {
    var d = try Decompressor.init(gpa, .{});
    defer d.deinit();
    return d.decompress(dst, src);
}

/// Decode `src` into a newly allocated buffer owned by the caller. The
/// buffer is sized from the frame headers (`findDecompressedSize`), or
/// from `decompressBound` when a frame does not record its size; either
/// way at most `max_size` bytes, beyond which the call fails with
/// `error.DstSizeTooSmall`.
pub fn decompressAlloc(gpa: std.mem.Allocator, src: []const u8, max_size: usize) (DecompressError || error{OutOfMemory})![]u8 {
    const size: usize = if (try findDecompressedSize(src)) |n| blk: {
        if (n > max_size) return error.DstSizeTooSmall;
        break :blk @intCast(n);
    } else @intCast(@min(try decompressBound(src), max_size));
    const buf = try gpa.alloc(u8, size);
    errdefer gpa.free(buf);
    const n = try decompress(gpa, buf, src);
    return gpa.realloc(buf, n) catch buf[0..n];
}

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
    _ = @import("dbits.zig");
    _ = @import("huf_dec.zig");
    _ = @import("dblock.zig");
    _ = @import("decompress.zig");
    _ = @import("dstream.zig");
    _ = @import("dstream_test.zig");
    _ = @import("decoder_test.zig");
    _ = @import("golden_test.zig");
    _ = @import("param_test.zig");
    _ = @import("fuzz_test.zig");
}

/// Decode with std. std's own checksum verification is a TODO panic in the
/// streaming path (0.16), so a checksummed frame is checked here instead.
fn stdDecompress(gpa: std.mem.Allocator, compressed: []const u8, has_checksum: bool) ![]u8 {
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

test "round trip through std's decoder and this one at every implemented level" {
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
            const back = try stdDecompress(gpa, z, ck);
            defer gpa.free(back);
            try std.testing.expectEqualSlices(u8, &src, back);
            const ours = try decompressAlloc(gpa, z, src.len);
            defer gpa.free(ours);
            try std.testing.expectEqualSlices(u8, &src, ours);
        }
    }
}

test "levels above 22 are refused, not clamped" {
    var buf: [64]u8 = undefined;
    try std.testing.expectError(error.LevelUnsupported, compress(std.testing.allocator, &buf, "x", .{ .level = 23 }));
}

test "a skippable frame is written as libzstd writes it and read back" {
    var buf: [16]u8 = undefined;
    const n = try writeSkippableFrame(&buf, "hey", 5);
    try std.testing.expectEqualSlices(u8, &.{ 0x55, 0x2a, 0x4d, 0x18, 3, 0, 0, 0, 'h', 'e', 'y' }, buf[0..n]);
    var back: [3]u8 = undefined;
    const r = try readSkippableFrame(&back, buf[0..n]);
    try std.testing.expectEqual(@as(u32, 5), r.magic_variant);
    try std.testing.expectEqualSlices(u8, "hey", &back);
    try std.testing.expectError(error.ParameterOutOfBound, writeSkippableFrame(&buf, "hey", 16));
    try std.testing.expectError(error.NoSpaceLeft, writeSkippableFrame(buf[0..10], "hey", 0));
    // decoders pass over it
    const z = try compressAlloc(std.testing.allocator, "abc", .{});
    defer std.testing.allocator.free(z);
    var both: [64]u8 = undefined;
    @memcpy(both[0..n], buf[0..n]);
    @memcpy(both[n..][0..z.len], z);
    var out: [8]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 3), try decompress(std.testing.allocator, &out, both[0 .. n + z.len]));
}

test "a destination below the bound is refused" {
    var buf: [8]u8 = undefined;
    try std.testing.expectError(error.NoSpaceLeft, compress(std.testing.allocator, &buf, "hello", .{}));
}
