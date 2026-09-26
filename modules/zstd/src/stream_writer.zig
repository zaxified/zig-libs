// SPDX-License-Identifier: MIT
//! `StreamWriter`: a `std.Io.Writer` over `Stream` (SPEC.md backlog Z1) --
//! one frame for everything written, the bytes libzstd's
//! `ZSTD_compressStream2` gives for the same calls: the written bytes as
//! `ZSTD_e_continue`, `flush` as `ZSTD_e_flush`, `finish` as `ZSTD_e_end`.
//! `finish` sends what is buffered as `ZSTD_e_end` -- when nothing reached
//! the stream before, that one call records the size in the header, as in
//! libzstd. In libzstd's default (buffered) modes the frame does not depend
//! on how the writes were cut, nor on the buffer's length, only on where the
//! flushes fall: the output goes through a scratch of `compressBound` of one
//! block, so libzstd's shortcut for an `end` with room for all of it takes
//! at most one block, which is also what the ordinary path makes of it.

const std = @import("std");
const Writer = std.Io.Writer;
const stream = @import("stream.zig");
const frame = @import("frame.zig");

pub const InitError = stream.Error || error{
    /// `Advanced.stable_in_buffer` / `stable_out_buffer`: the writer's
    /// buffer is reused from write to write, so neither holds.
    ParameterCombinationUnsupported,
};

pub const StreamWriter = struct {
    /// The interface. Its buffer is the one passed to `init`; bytes wait
    /// there until the buffer fills or is flushed.
    writer: Writer,
    output: *Writer,
    s: stream.Stream,
    /// Where compressed bytes go before `output`.
    scratch: []u8,
    gpa: std.mem.Allocator,
    /// Why the last `error.WriteFailed` came from here rather than from
    /// `output` (`Writer.Error` has room for one error only). Null when
    /// `output` failed.
    err: ?stream.Error = null,

    /// `buffer` must be nonempty. `gpa` holds the stream's workspace
    /// (allocated at its first call) and a scratch of
    /// `compressBound(128 KB)` bytes for the writer's life.
    pub fn init(gpa: std.mem.Allocator, output: *Writer, buffer: []u8, opts: stream.Options) InitError!StreamWriter {
        std.debug.assert(buffer.len != 0);
        if (opts.advanced.stable_in_buffer or opts.advanced.stable_out_buffer) return error.ParameterCombinationUnsupported;
        var s: stream.Stream = try .init(gpa, opts);
        errdefer s.deinit();
        return .{
            .writer = .{ .buffer = buffer, .vtable = &.{ .drain = drain, .flush = flush } },
            .output = output,
            .s = s,
            .scratch = try gpa.alloc(u8, frame.compressBound(128 * 1024)),
            .gpa = gpa,
        };
    }

    pub fn deinit(sw: *StreamWriter) void {
        sw.s.deinit();
        sw.gpa.free(sw.scratch);
        sw.* = undefined;
    }

    /// End the frame with what is buffered (`ZSTD_e_end`) and stop accepting
    /// writes. With nothing written at all, the empty frame. `output` is not
    /// flushed.
    pub fn finish(sw: *StreamWriter) Writer.Error!void {
        defer sw.writer = .failing;
        const w = &sw.writer;
        try sw.call(w.buffer[0..w.end], .end);
        w.end = 0;
    }

    /// One `compressStream2` call over `src` (repeated until `continue` has
    /// taken it all, or `flush`/`end` has nothing left to write), the output
    /// to `output`.
    fn call(sw: *StreamWriter, src: []const u8, op: stream.EndDirective) Writer.Error!void {
        var in: stream.InBuffer = .{ .src = src };
        while (true) {
            var o: stream.OutBuffer = .{ .dst = sw.scratch };
            const remaining = sw.s.compressStream2(&o, &in, op) catch |e| {
                sw.err = e;
                return error.WriteFailed;
            };
            try sw.output.writeAll(sw.scratch[0..o.pos]);
            if (if (op == .@"continue") in.pos == in.src.len else remaining == 0) return;
        }
    }

    /// The buffer, then `data` (the last slice `splat` times), go to the
    /// stream as `continue`.
    fn drain(w: *Writer, data: []const []const u8, splat: usize) Writer.Error!usize {
        const sw: *StreamWriter = @alignCast(@fieldParentPtr("writer", w));
        try sw.call(w.buffer[0..w.end], .@"continue");
        w.end = 0;
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            try sw.call(d, .@"continue");
            n += d.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| try sw.call(last, .@"continue");
        return n + last.len * splat;
    }

    /// `ZSTD_e_flush`: everything written so far is in `output` as whole
    /// blocks (a flush with nothing new writes nothing). `output` is not
    /// flushed.
    fn flush(w: *Writer) Writer.Error!void {
        const sw: *StreamWriter = @alignCast(@fieldParentPtr("writer", w));
        try sw.call(w.buffer[0..w.end], .flush);
        w.end = 0;
    }
};

const testing = std.testing;
const zstd = @import("root.zig");

/// The stream the writer must give: `Stream` driven directly with the
/// schedule the test spells out (`continue` for each piece of `parts`
/// except where it says flush, then `end`), not by the writer's logic.
fn expected(src: []const u8, opts: stream.Options, flush_at: []const usize) ![]u8 {
    var s: stream.Stream = try .init(testing.allocator, opts);
    defer s.deinit();
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(testing.allocator);
    var buf: [1 << 17]u8 = undefined;
    var at: usize = 0;
    for (0..flush_at.len + 1) |i| {
        const to = if (i == flush_at.len) src.len else flush_at[i];
        const op: stream.EndDirective = if (i == flush_at.len) .end else .flush;
        var in: stream.InBuffer = .{ .src = src[at..to] };
        for ([_]stream.EndDirective{ .@"continue", op }) |d| {
            while (true) {
                var o: stream.OutBuffer = .{ .dst = &buf };
                const rem = try s.compressStream2(&o, &in, d);
                try out.appendSlice(testing.allocator, buf[0..o.pos]);
                if (if (d == .@"continue") in.pos == in.src.len else rem == 0) break;
            }
        }
        at = to;
    }
    return out.toOwnedSlice(testing.allocator);
}

fn text(buf: []u8) void {
    var prng: std.Random.DefaultPrng = .init(0x57e4);
    const words = [_][]const u8{ "stream ", "writer ", "window ", "block,", "7;", "\n" };
    var i: usize = 0;
    while (i < buf.len) {
        const wd = words[prng.random().uintLessThan(usize, words.len)];
        const n = @min(wd.len, buf.len - i);
        @memcpy(buf[i..][0..n], wd[0..n]);
        i += n;
    }
}

test "the stream Stream gives for the same calls, whatever the writes and the buffer" {
    const gpa = testing.allocator;
    const src = try gpa.alloc(u8, 700_000);
    defer gpa.free(src);
    text(src);
    const opts: stream.Options = .{ .level = 5, .checksum = true };
    const flushes = [_]usize{ 1000, 300_000 };
    const want = try expected(src, opts, &flushes);
    defer gpa.free(want);
    for ([_]usize{ 1, 999, 4096, 200_000 }) |blen| for ([_]usize{ 1, 7, 5000, 700_000 }) |step| {
        if (step == 1 and blen > 4096) continue; // (slow, adds nothing)
        var out: Writer.Allocating = .init(gpa);
        defer out.deinit();
        const buf = try gpa.alloc(u8, blen);
        defer gpa.free(buf);
        var sw: StreamWriter = try .init(gpa, &out.writer, buf, opts);
        defer sw.deinit();
        var i: usize = 0;
        var f: usize = 0;
        while (i < src.len) {
            const end = @min(i + step, src.len, if (f < flushes.len) flushes[f] else src.len);
            try sw.writer.writeAll(src[i..end]);
            i = end;
            if (f < flushes.len and i == flushes[f]) {
                try sw.writer.flush();
                f += 1;
            }
        }
        try sw.finish();
        try testing.expectEqualSlices(u8, want, out.written());
    };
    var d = try zstd.Decompressor.init(gpa, .{});
    defer d.deinit();
    const back = try gpa.alloc(u8, src.len);
    defer gpa.free(back);
    try testing.expectEqualSlices(u8, src, back[0..try d.decompress(back, want)]);
}

test "splat writes go to the stream like any other" {
    const gpa = testing.allocator;
    const src = "head:" ++ "z" ** 250_000 ++ "ab" ** 30_000;
    const want = try expected(src, .{ .level = 1 }, &.{});
    defer gpa.free(want);
    var out: Writer.Allocating = .init(gpa);
    defer out.deinit();
    var buf: [1000]u8 = undefined;
    var sw: StreamWriter = try .init(gpa, &out.writer, &buf, .{ .level = 1 });
    defer sw.deinit();
    try sw.writer.writeAll("head:");
    try sw.writer.splatByteAll('z', 250_000);
    try sw.writer.splatBytesAll("ab", 30_000);
    try sw.finish();
    try testing.expectEqualSlices(u8, want, out.written());
}

test "nothing drained before finish: one end, the size in the header" {
    const gpa = testing.allocator;
    var out: Writer.Allocating = .init(gpa);
    defer out.deinit();
    var buf: [256]u8 = undefined;
    var sw: StreamWriter = try .init(gpa, &out.writer, &buf, .{ .level = 3 });
    defer sw.deinit();
    try sw.writer.writeAll("a small body, all in the buffer");
    try sw.finish();
    const one = try zstd.compressAlloc(gpa, "a small body, all in the buffer", .{ .level = 3 });
    defer gpa.free(one);
    try testing.expectEqualSlices(u8, one, out.written());
    try testing.expectError(error.WriteFailed, sw.writer.writeAll("late"));
}

test "an empty stream is the empty frame" {
    const gpa = testing.allocator;
    var out: Writer.Allocating = .init(gpa);
    defer out.deinit();
    var buf: [64]u8 = undefined;
    var sw: StreamWriter = try .init(gpa, &out.writer, &buf, .{});
    defer sw.deinit();
    try sw.finish();
    const e = try zstd.compressAlloc(gpa, "", .{});
    defer gpa.free(e);
    try testing.expectEqualSlices(u8, e, out.written());
}

test "stable buffer modes are refused; failures keep their cause" {
    const gpa = testing.allocator;
    var buf: [256]u8 = undefined;
    var out: Writer.Allocating = .init(gpa);
    defer out.deinit();
    try testing.expectError(error.ParameterCombinationUnsupported, StreamWriter.init(gpa, &out.writer, &buf, .{ .advanced = .{ .stable_in_buffer = true } }));
    try testing.expectError(error.ParameterCombinationUnsupported, StreamWriter.init(gpa, &out.writer, &buf, .{ .advanced = .{ .stable_out_buffer = true } }));
    // more than pledged: the stream's error, kept
    var sw: StreamWriter = try .init(gpa, &out.writer, &buf, .{ .pledged_size = 3 });
    defer sw.deinit();
    try sw.writer.writeAll("four");
    try testing.expectError(error.WriteFailed, sw.writer.flush());
    try testing.expectEqual(error.SrcSizeWrong, sw.err.?);
    // a failing output: no cause of our own
    var sink: [4]u8 = undefined;
    var small: Writer = .fixed(&sink);
    var sw2: StreamWriter = try .init(gpa, &small, &buf, .{});
    defer sw2.deinit();
    try sw2.writer.writeAll("more than four bytes of frame");
    try testing.expectError(error.WriteFailed, sw2.finish());
    try testing.expectEqual(null, sw2.err);
}
