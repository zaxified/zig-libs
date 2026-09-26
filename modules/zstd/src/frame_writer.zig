// SPDX-License-Identifier: MIT
//! `FrameWriter`: a `std.Io.Writer` that compresses into a stream of
//! one-shot frames (SPEC.md backlog Z1a, the interim before Z1's streaming).
//!
//! Input collects in the caller's buffer. Each time the buffer fills, and at
//! every `flush` and `finish` with something in it, its contents become one
//! frame -- the same bytes `compress` gives for them -- written to `output`.
//! A zstd decoder reads concatenated frames as one stream (RFC 8878 §3.1),
//! so the result decodes to the input. The price is ratio: a frame starts
//! with no history, so small flushes compress worse than one frame would.

const std = @import("std");
const Writer = std.Io.Writer;
const frame = @import("frame.zig");
const params = @import("params.zig");

pub const Options = struct {
    level: i32 = params.default_level,
    checksum: bool = false,
    advanced: params.Advanced = .{},
};

pub const InitError = error{
    /// See `zstd.Error.LevelUnsupported`.
    LevelUnsupported,
    /// An advanced parameter outside libzstd's bounds.
    ParameterOutOfBound,
    OutOfMemory,
};

pub const FrameWriter = struct {
    /// The interface. Its buffer is the one passed to `init`: bytes written
    /// here stay in it until they are compressed.
    writer: Writer,
    output: *Writer,
    gpa: std.mem.Allocator,
    opts: frame.Options,
    /// The compression context, reused for every frame.
    ctx: frame.Compressor,
    /// `compressBound(buffer.len)` bytes: where a frame is built before it
    /// is written to `output`.
    scratch: []u8,
    frames: u64 = 0,
    /// Why the last `error.WriteFailed` came from here rather than from
    /// `output` (`Writer.Error` has room for one error only). Null when
    /// `output` failed.
    err: ?frame.Error = null,

    /// `buffer` sets the frame size for a stream written without flushes; it
    /// must be nonempty. `gpa` holds the frame scratch and the compression
    /// context's workspace (allocated at the first frame) for the writer's
    /// life.
    pub fn init(gpa: std.mem.Allocator, output: *Writer, buffer: []u8, opts: Options) InitError!FrameWriter {
        std.debug.assert(buffer.len != 0);
        if (opts.level > params.max_level) return error.LevelUnsupported;
        try opts.advanced.check();
        return .{
            .writer = .{
                .buffer = buffer,
                .vtable = &.{ .drain = drain, .flush = flush },
            },
            .output = output,
            .gpa = gpa,
            .opts = .{ .level = opts.level, .checksum = opts.checksum, .advanced = opts.advanced },
            .ctx = .initEmpty(gpa),
            .scratch = try gpa.alloc(u8, frame.compressBound(buffer.len)),
        };
    }

    pub fn deinit(fw: *FrameWriter) void {
        fw.ctx.deinit();
        fw.gpa.free(fw.scratch);
        fw.* = undefined;
    }

    /// Compress what is buffered into a last frame -- or, if no frame has
    /// been written at all, the empty frame, so that an empty stream is
    /// still a valid one -- and stop accepting writes. `output` is not
    /// flushed.
    pub fn finish(fw: *FrameWriter) Writer.Error!void {
        defer fw.writer = .failing;
        if (fw.writer.end != 0 or fw.frames == 0) try fw.emit();
    }

    /// One frame of `buffer[0..end]` to `output`; the buffer is empty after.
    fn emit(fw: *FrameWriter) Writer.Error!void {
        const w = &fw.writer;
        const n = fw.ctx.compressFrame(fw.scratch, w.buffer[0..w.end], fw.opts) catch |e| {
            fw.err = e;
            return error.WriteFailed;
        };
        try fw.output.writeAll(fw.scratch[0..n]);
        w.end = 0;
        fw.frames += 1;
    }

    /// Called when the data does not fit in what is left of the buffer (or,
    /// from `rebase`, with nothing to write): fill the buffer, compress it.
    /// All input passes through the buffer, so frame boundaries depend on
    /// the buffer length and the flushes, not on how the writes were cut.
    fn drain(w: *Writer, data: []const []const u8, splat: usize) Writer.Error!usize {
        // `@alignCast`: on `mips-linux-musl` (soft-float, `check-portable`'s
        // `.linux32`) `@fieldParentPtr` alone reports the result as only
        // 2-aligned and refuses to widen it back to `*FrameWriter`'s
        // alignment, even though `writer`'s actual offset in `FrameWriter`
        // is a multiple of 8 there (`@offsetOf`, checked by hand) -- a
        // conservative bound `@fieldParentPtr` computes for this target's
        // pointer ABI, not a real alignment hazard: `w` always points at
        // the `writer` field of an actual `FrameWriter` value (`init`
        // returns the struct by value with `writer` embedded in it, and
        // nothing else ever constructs one), so the parent is genuinely
        // aligned.
        const fw: *FrameWriter = @alignCast(@fieldParentPtr("writer", w));
        const before = w.end;
        _ = w.fixedDrain(data, splat) catch {}; // fills the buffer; the rest waits
        const consumed = w.end - before;
        if (w.end != 0) try fw.emit();
        return consumed;
    }

    /// Buffered bytes become a frame. Nothing buffered, no frame: a flush
    /// never emits an empty one. `output` is not flushed.
    fn flush(w: *Writer) Writer.Error!void {
        const fw: *FrameWriter = @alignCast(@fieldParentPtr("writer", w));
        if (w.end != 0) try fw.emit();
    }
};

const testing = std.testing;
const zstd = @import("root.zig");

/// The expected stream: one `compressAlloc` frame per chunk. The chunks are
/// cut by the test from the buffer length and the flush points, not by the
/// writer's own logic.
fn expectFrames(chunks: []const []const u8, opts: Options, got: []const u8) !void {
    var want: std.ArrayList(u8) = .empty;
    defer want.deinit(testing.allocator);
    for (chunks) |c| {
        const z = try zstd.compressAlloc(testing.allocator, c, .{ .level = opts.level, .checksum = opts.checksum });
        defer testing.allocator.free(z);
        try want.appendSlice(testing.allocator, z);
    }
    try testing.expectEqualSlices(u8, want.items, got);
}

fn decodeAll(z: []const u8) ![]u8 {
    var out: Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var in: std.Io.Reader = .fixed(z);
    var d: std.compress.zstd.Decompress = .init(&in, &.{}, .{ .verify_checksum = false });
    _ = try d.reader.streamRemaining(&out.writer);
    return out.toOwnedSlice();
}

fn text(buf: []u8) void {
    var prng: std.Random.DefaultPrng = .init(0xf1a5);
    const words = [_][]const u8{ "flush ", "frame ", "window ", "block,", "7;", "\n" };
    var i: usize = 0;
    while (i < buf.len) {
        const wd = words[prng.random().uintLessThan(usize, words.len)];
        const n = @min(wd.len, buf.len - i);
        @memcpy(buf[i..][0..n], wd[0..n]);
        i += n;
    }
}

test "a frame per buffer fill, whatever the write sizes" {
    const gpa = testing.allocator;
    var src: [10_000]u8 = undefined;
    text(&src);
    // 10 000 bytes through a 3 000-byte buffer: 3 full frames and a tail.
    const chunks = [_][]const u8{ src[0..3000], src[3000..6000], src[6000..9000], src[9000..] };
    for ([_]usize{ 1, 7, 2999, 3000, 3001, 10_000 }) |step| {
        var out: Writer.Allocating = .init(gpa);
        defer out.deinit();
        var buf: [3000]u8 = undefined;
        var fw: FrameWriter = try .init(gpa, &out.writer, &buf, .{ .level = 5, .checksum = true });
        defer fw.deinit();
        var i: usize = 0;
        while (i < src.len) : (i += step) try fw.writer.writeAll(src[i..@min(i + step, src.len)]);
        try fw.finish();
        try expectFrames(&chunks, .{ .level = 5, .checksum = true }, out.written());
        const back = try decodeAll(out.written());
        defer gpa.free(back);
        try testing.expectEqualSlices(u8, &src, back);
    }
}

test "flush cuts a frame; an empty flush cuts none" {
    const gpa = testing.allocator;
    var out: Writer.Allocating = .init(gpa);
    defer out.deinit();
    var buf: [4096]u8 = undefined;
    var fw: FrameWriter = try .init(gpa, &out.writer, &buf, .{});
    defer fw.deinit();
    try fw.writer.writeAll("HTTP chunk one, ");
    try fw.writer.flush();
    try fw.writer.flush();
    try fw.writer.print("chunk {d}, ", .{2});
    try fw.writer.flush();
    try fw.finish(); // nothing buffered: no trailing frame
    try testing.expectEqual(2, fw.frames);
    try expectFrames(&.{ "HTTP chunk one, ", "chunk 2, " }, .{}, out.written());
}

test "splat writes fill frames like any other" {
    const gpa = testing.allocator;
    var out: Writer.Allocating = .init(gpa);
    defer out.deinit();
    var buf: [1000]u8 = undefined;
    var fw: FrameWriter = try .init(gpa, &out.writer, &buf, .{ .level = -1 });
    defer fw.deinit();
    try fw.writer.writeAll("head:");
    try fw.writer.splatByteAll('z', 2500);
    try fw.writer.splatBytesAll("ab", 300);
    try fw.finish();
    const src = "head:" ++ "z" ** 2500 ++ "ab" ** 300;
    try expectFrames(&.{ src[0..1000], src[1000..2000], src[2000..3000], src[3000..] }, .{ .level = -1 }, out.written());
}

test "an empty stream is the empty frame" {
    const gpa = testing.allocator;
    var out: Writer.Allocating = .init(gpa);
    defer out.deinit();
    var buf: [64]u8 = undefined;
    var fw: FrameWriter = try .init(gpa, &out.writer, &buf, .{});
    defer fw.deinit();
    try fw.writer.flush();
    try fw.finish();
    try testing.expectEqualSlices(u8, &.{ 0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x00, 0x01, 0x00, 0x00 }, out.written());
    try testing.expectError(error.WriteFailed, fw.writer.writeAll("late"));
}

test "levels above 22 are refused at init" {
    var buf: [64]u8 = undefined;
    var out: Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try testing.expectError(error.LevelUnsupported, FrameWriter.init(testing.allocator, &out.writer, &buf, .{ .level = 23 }));
}

test "out of memory in a frame is WriteFailed with the cause kept" {
    var buf: [256]u8 = undefined;
    var sink: [1024]u8 = undefined;
    var out: Writer = .fixed(&sink);
    // scratch allocation succeeds, the frame's match tables do not
    var fa: std.testing.FailingAllocator = .init(testing.allocator, .{ .fail_index = 1 });
    var fw: FrameWriter = try .init(fa.allocator(), &out, &buf, .{});
    defer fw.deinit();
    try fw.writer.writeAll("some bytes worth a frame, some bytes worth a frame");
    try testing.expectError(error.WriteFailed, fw.writer.flush());
    try testing.expectEqual(error.OutOfMemory, fw.err.?);
}

test "a failing output is WriteFailed with no cause of our own" {
    var buf: [256]u8 = undefined;
    var sink: [4]u8 = undefined;
    var out: Writer = .fixed(&sink);
    var fw: FrameWriter = try .init(testing.allocator, &out, &buf, .{});
    defer fw.deinit();
    try fw.writer.writeAll("more than four bytes of frame");
    try testing.expectError(error.WriteFailed, fw.writer.flush());
    try testing.expectEqual(null, fw.err);
}
