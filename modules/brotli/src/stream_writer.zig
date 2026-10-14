// SPDX-License-Identifier: MIT
//! `StreamWriter`: a `std.Io.Writer` that compresses everything written to it
//! into one Brotli stream (SPEC.md backlog R1) — the window and the match
//! finder kept from write to write, `flush` (everything so far decodable at
//! the other end), `finish` (ISLAST), `reset` (the next stream on the same
//! tables and buffers, for a server compressing response after response).
//!
//! The bytes depend only on the options and on where the flushes fall, not
//! on how the writes were cut nor on the buffer's length: input is cut into
//! meta-blocks of `block_size` exactly as `compressWith` cuts it, each
//! compressed only once `lookahead` bytes past it have arrived too (the match
//! finder hashes a few bytes past a block's end, as it does in one piece), so
//! a stream without a flush is the bytes `compressWith` gives with the same
//! `window_bits` and `block_size`. A flush ends the meta-block where it falls and byte-aligns
//! the output with an empty metadata meta-block, as google/brotli's
//! `BROTLI_OPERATION_FLUSH` does.
//!
//! (`compressWith` sizes the match finder's table to its input, the stream
//! to its window or `size_hint`: the same bytes hold for an input of at least
//! the window, or with the input's length as the hint.)
//!
//! Memory: the history the window needs, the block being gathered, and the
//! match finder's table — one allocation each, kept across `reset` (a
//! block's prefix codes still take short-lived allocations, as in
//! `compressWith`).

const std = @import("std");
const Writer = std.Io.Writer;
const encoder = @import("encoder.zig");
const Core = encoder.Core;

pub const StreamOptions = struct {
    effort: encoder.Effort = .default,
    /// As `CompressOptions.block_size`. Also how much input waits before
    /// anything is compressed, unless a flush comes first.
    block_size: usize = encoder.compressed_block_size,
    /// log2 of the window (`min_window_bits`..`max_window_bits`, or a
    /// large-window stream up to `max_large_window_bits`, as
    /// `CompressOptions.window_bits`). The history kept grows to about twice
    /// the window plus a block. 22 is google/brotli's default.
    window_bits: u5 = 22,
    /// About how many bytes the stream will carry: the match finder's table
    /// is sized for that rather than for the window (a short response costs
    /// a small table). With the input's exact length, the stream without a
    /// flush is `compressWith`'s bytes for any input length. More input than
    /// hinted is fine, only searched with a smaller table.
    size_hint: ?usize = null,
    /// A raw prefix dictionary (as `CompressOptions.dictionary`), copied at
    /// `init`/`reset` (the caller's bytes are not kept). It stays searchable
    /// for the whole stream; once the output has slid, a copy from it no
    /// longer runs on into the output.
    dictionary: []const u8 = &.{},

    fn tableSize(o: StreamOptions) usize {
        const window = @as(usize, 1) << o.window_bits;
        return @min(window, o.size_hint orelse window) + o.dictionary.len;
    }
};

/// Bytes past a block that must have arrived before it is compressed: what
/// the match finders read past a position (`FastMatcher` hashes eight).
const lookahead = 8;
/// History is dropped in multiples of this, which keeps every position's
/// low bits — `FastMatcher` picks a slot by them.
const shift_align = 32;

pub const StreamWriter = struct {
    /// The interface. Its buffer is the one passed to `init`; bytes wait
    /// there until it fills or is flushed.
    writer: Writer,
    output: *Writer,
    core: Core,
    opts: StreamOptions,
    /// The window's history, then the input not compressed yet
    /// (`hist.items[done..]`).
    hist: std.ArrayListUnmanaged(u8) = .empty,
    done: usize = 0,
    /// `hist.items[0..dict_len]` is the dictionary (`StreamOptions`).
    dict_len: usize = 0,
    /// The buffer given at init, for `reset` (`finish` takes it off
    /// `writer`).
    buffer: []u8,
    /// Why the last `error.WriteFailed` came from here rather than from
    /// `output`. Null when `output` failed.
    err: ?std.mem.Allocator.Error = null,

    const vtable: Writer.VTable = .{ .drain = drain, .flush = flush };

    /// `buffer` must be nonempty and outlive the writer. `gpa` holds the
    /// history and the match finder's table.
    pub fn init(gpa: std.mem.Allocator, output: *Writer, buffer: []u8, opts: StreamOptions) std.mem.Allocator.Error!StreamWriter {
        std.debug.assert(buffer.len != 0);
        var core = try Core.init(gpa, opts.effort, opts.block_size, opts.window_bits, opts.tableSize());
        errdefer core.deinit();
        var sw: StreamWriter = .{
            .writer = .{ .buffer = buffer, .vtable = &vtable },
            .output = output,
            .core = core,
            .opts = opts,
            .buffer = buffer,
        };
        errdefer sw.hist.deinit(gpa);
        try sw.start();
        return sw;
    }

    /// The history holds the dictionary, the stream header is written.
    fn start(sw: *StreamWriter) std.mem.Allocator.Error!void {
        const d = sw.opts.dictionary;
        try sw.hist.appendSlice(sw.core.gpa, d);
        sw.done = d.len;
        sw.core.setData(sw.hist.items);
        sw.core.loadDictionary(d.len);
        sw.dict_len = d.len;
        try sw.core.writeHeader();
    }

    pub fn deinit(sw: *StreamWriter) void {
        sw.hist.deinit(sw.core.gpa);
        sw.core.deinit();
        sw.* = undefined;
    }

    /// The next stream, to `output` with `opts`: the table and the history
    /// are kept when the effort and the table's size (window, `size_hint`)
    /// are the same (else the table is made anew). A stream not yet finished
    /// is abandoned. On an error the writer is unusable until another
    /// successful `reset`.
    pub fn reset(sw: *StreamWriter, output: *Writer, opts: StreamOptions) std.mem.Allocator.Error!void {
        std.debug.assert(opts.window_bits >= encoder.min_window_bits and opts.window_bits <= encoder.max_large_window_bits);
        if (opts.effort != sw.opts.effort or Core.tableLog(opts.effort, opts.tableSize()) != sw.core.table_log) {
            const gpa = sw.core.gpa;
            sw.core.deinit();
            sw.core = try Core.init(gpa, opts.effort, opts.block_size, opts.window_bits, opts.tableSize());
        } else {
            sw.core.reset();
            sw.core.block_size = opts.block_size;
            sw.core.wbits = opts.window_bits;
        }
        sw.opts = opts;
        sw.hist.clearRetainingCapacity();
        sw.output = output;
        sw.err = null;
        sw.writer = .{ .buffer = sw.buffer, .vtable = &vtable };
        try sw.start();
    }

    /// End the stream with what is buffered (its last meta-block ISLAST)
    /// and stop accepting writes until `reset`. With nothing written, the
    /// empty stream. `output` is not flushed.
    pub fn finish(sw: *StreamWriter) Writer.Error!void {
        defer sw.writer = .failing;
        const w = &sw.writer;
        try sw.feed(w.buffer[0..w.end]);
        w.end = 0;
        sw.compressTo(sw.hist.items.len, true) catch |e| return sw.fail(e);
        sw.core.finish() catch |e| return sw.fail(e);
        try sw.send();
    }

    /// Flush (see `flush`), then `bytes` as metadata meta-blocks (google/
    /// brotli's `BROTLI_OPERATION_EMIT_METADATA`): carried in the stream,
    /// skipped by decoders — at most 16 MiB per meta-block, split beyond.
    /// The output is byte aligned after it.
    pub fn writeMetadata(sw: *StreamWriter, bytes: []const u8) Writer.Error!void {
        try sw.writer.flush();
        sw.core.writeMetadata(bytes) catch |e| return sw.fail(e);
        try sw.send();
    }

    fn fail(sw: *StreamWriter, e: std.mem.Allocator.Error) Writer.Error {
        sw.err = e;
        return error.WriteFailed;
    }

    /// Append `bytes` to the pending input, compressing every block that
    /// has its lookahead.
    fn feed(sw: *StreamWriter, bytes: []const u8) Writer.Error!void {
        const gpa = sw.core.gpa;
        var rest = bytes;
        while (rest.len != 0) {
            // A block at a time, so a long write never holds more than one.
            const n = @min(rest.len, sw.opts.block_size);
            sw.hist.appendSlice(gpa, rest[0..n]) catch |e| return sw.fail(e);
            rest = rest[n..];
            sw.core.setData(sw.hist.items);
            const bs = sw.opts.block_size;
            while (sw.hist.items.len - sw.done >= bs + lookahead) {
                sw.compressTo(sw.done + bs, false) catch |e| return sw.fail(e);
            }
            try sw.send();
            sw.slide();
        }
    }

    /// Compress the pending input up to `end` (blocks of `block_size`), the
    /// last block ISLAST when `last`.
    fn compressTo(sw: *StreamWriter, end: usize, last: bool) std.mem.Allocator.Error!void {
        if (sw.done == end) return;
        while (sw.done < end) {
            const to = @min(end, sw.done + sw.opts.block_size);
            try sw.core.compressBlock(sw.done, to, last and to == end);
            sw.done = to;
        }
    }

    /// The whole bytes written so far, to `output`.
    fn send(sw: *StreamWriter) Writer.Error!void {
        const buf = &sw.core.w.buf;
        try sw.output.writeAll(buf.items);
        buf.clearRetainingCapacity();
    }

    /// Drop output no copy can reach any more, once there is a window's
    /// worth of it (so the bytes moved stay about the bytes written). A
    /// dictionary at the history's start stays.
    fn slide(sw: *StreamWriter) void {
        const window = @as(usize, 1) << sw.opts.window_bits;
        const dl = sw.dict_len;
        const out_done = sw.done - dl;
        if (out_done < 2 * window) return;
        const by = std.mem.alignBackward(usize, out_done - window, shift_align);
        const items = sw.hist.items;
        std.mem.copyForwards(u8, items[dl .. items.len - by], items[dl + by ..]);
        sw.hist.items.len -= by;
        sw.done -= by;
        sw.core.shift(by);
        sw.core.setData(sw.hist.items);
    }

    fn drain(w: *Writer, data: []const []const u8, splat: usize) Writer.Error!usize {
        const sw: *StreamWriter = @alignCast(@fieldParentPtr("writer", w));
        try sw.feed(w.buffer[0..w.end]);
        w.end = 0;
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            try sw.feed(d);
            n += d.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| try sw.feed(last);
        return n + last.len * splat;
    }

    /// Everything written so far into meta-blocks and out to `output`, byte
    /// aligned (see the file comment). `output` is not flushed.
    fn flush(w: *Writer) Writer.Error!void {
        const sw: *StreamWriter = @alignCast(@fieldParentPtr("writer", w));
        try sw.feed(w.buffer[0..w.end]);
        w.end = 0;
        sw.compressTo(sw.hist.items.len, false) catch |e| return sw.fail(e);
        sw.core.flushToByte() catch |e| return sw.fail(e);
        try sw.send();
    }
};

const testing = std.testing;
const decoder = @import("decoder.zig");

fn text(buf: []u8, seed: u64) void {
    var prng: std.Random.DefaultPrng = .init(seed);
    const words = [_][]const u8{ "stream ", "writer ", "window ", "block,", "7;", "\n", "brotli ", "meta-block " };
    var i: usize = 0;
    while (i < buf.len) {
        const wd = words[prng.random().uintLessThan(usize, words.len)];
        const n = @min(wd.len, buf.len - i);
        @memcpy(buf[i..][0..n], wd[0..n]);
        i += n;
    }
}

/// `src` cut into `writeAll`s of `step`, a flush after each offset in
/// `flush_at`, then `finish`.
fn writeStream(sw: *StreamWriter, src: []const u8, step: usize, flush_at: []const usize) !void {
    var i: usize = 0;
    var f: usize = 0;
    while (i < src.len) {
        const end = @min(i + step, src.len, if (f < flush_at.len) flush_at[f] else src.len);
        try sw.writer.writeAll(src[i..end]);
        i = end;
        if (f < flush_at.len and i == flush_at[f]) {
            try sw.writer.flush();
            f += 1;
        }
    }
    try sw.finish();
}

fn expectRoundTrip(src: []const u8, stream: []const u8) !void {
    const back = try decoder.decompress(testing.allocator, stream, .{});
    defer testing.allocator.free(back);
    try testing.expectEqualSlices(u8, src, back);
}

test "without a flush: the bytes compressWith gives, whatever the writes and the buffer" {
    const gpa = testing.allocator;
    const src = try gpa.alloc(u8, 300_000);
    defer gpa.free(src);
    text(src, 0x51);
    // A 64 KiB window over 300 KB slides the history several times; blocks
    // of 40 000 bytes cut it into eight, the last one short.
    inline for (.{ encoder.Effort.fast, .default, .best }) |effort| {
        const opts: StreamOptions = .{ .effort = effort, .window_bits = 16, .block_size = 40_000 };
        const want = try encoder.compressWith(gpa, src, .{ .effort = effort, .window_bits = 16, .block_size = 40_000 });
        defer gpa.free(want);
        try expectRoundTrip(src, want);
        for ([_]usize{ 1, 999, 65_536 }) |blen| for ([_]usize{ 7, 5_000, 40_000, 300_000 }) |step| {
            if (step == 7 and (blen > 1 or effort != .fast)) continue; // (slow, adds nothing)
            var out: Writer.Allocating = .init(gpa);
            defer out.deinit();
            const buf = try gpa.alloc(u8, blen);
            defer gpa.free(buf);
            var sw: StreamWriter = try .init(gpa, &out.writer, buf, opts);
            defer sw.deinit();
            try writeStream(&sw, src, step, &.{});
            try testing.expectEqualSlices(u8, want, out.written());
        };
    }
}

test "an input of whole blocks, or a few bytes past them: cut as in one piece" {
    const gpa = testing.allocator;
    const bs = 16_384;
    const src = try gpa.alloc(u8, 5 * bs);
    defer gpa.free(src);
    text(src, 0x52);
    // At least the window (16 bits), so `compressWith` sizes its tables alike.
    for ([_]usize{ 4 * bs, 5 * bs, 5 * bs - 5, 5 * bs - 8, 4 * bs + 9 }) |n| {
        const want = try encoder.compressWith(gpa, src[0..n], .{ .effort = .fast, .window_bits = 16, .block_size = bs });
        defer gpa.free(want);
        var out: Writer.Allocating = .init(gpa);
        defer out.deinit();
        var buf: [100]u8 = undefined;
        var sw: StreamWriter = try .init(gpa, &out.writer, &buf, .{ .effort = .fast, .window_bits = 16, .block_size = bs });
        defer sw.deinit();
        try writeStream(&sw, src[0..n], 1000, &.{});
        try testing.expectEqualSlices(u8, want, out.written());
    }
}

test "flushes: each one byte-aligns what came before; the bytes depend only on where they fall" {
    const gpa = testing.allocator;
    const src = try gpa.alloc(u8, 200_000);
    defer gpa.free(src);
    text(src, 0x53);
    const flushes = [_]usize{ 0, 1, 1000, 1000, 150_000 };
    var first: ?[]u8 = null;
    defer if (first) |f| gpa.free(f);
    for ([_]usize{ 13, 4096, 200_000 }) |step| {
        var out: Writer.Allocating = .init(gpa);
        defer out.deinit();
        var buf: [777]u8 = undefined;
        var sw: StreamWriter = try .init(gpa, &out.writer, &buf, .{ .window_bits = 18, .block_size = 65_536 });
        defer sw.deinit();
        var i: usize = 0;
        var f: usize = 0;
        while (i < src.len) {
            const end = @min(i + step, src.len, if (f < flushes.len) flushes[f] else src.len);
            try sw.writer.writeAll(src[i..end]);
            i = end;
            while (f < flushes.len and i == flushes[f]) : (f += 1) {
                try sw.writer.flush();
                // Every bit out, so a decoder has all it needs for src[0..i].
                try testing.expectEqual(@as(u6, 0), sw.core.w.cnt);
                try testing.expectEqual(@as(usize, 0), sw.core.w.buf.items.len);
            }
        }
        try sw.finish();
        try expectRoundTrip(src, out.written());
        if (first) |f0| {
            try testing.expectEqualSlices(u8, f0, out.written());
        } else first = try gpa.dupe(u8, out.written());
    }
}

test "an empty stream, and one with only flushes, are the empty stream" {
    const gpa = testing.allocator;
    const empty = try encoder.compressWith(gpa, "", .{ .window_bits = 22 });
    defer gpa.free(empty);
    for ([_]usize{ 0, 3 }) |nflush| {
        var out: Writer.Allocating = .init(gpa);
        defer out.deinit();
        var buf: [16]u8 = undefined;
        var sw: StreamWriter = try .init(gpa, &out.writer, &buf, .{});
        defer sw.deinit();
        for (0..nflush) |_| try sw.writer.flush();
        try sw.finish();
        try expectRoundTrip("", out.written());
        if (nflush == 0) try testing.expectEqualSlices(u8, empty, out.written());
        try testing.expectError(error.WriteFailed, sw.writer.writeAll("late"));
    }
}

test "reset: stream after stream, each the bytes a fresh writer gives" {
    const gpa = testing.allocator;
    const src = try gpa.alloc(u8, 150_000);
    defer gpa.free(src);
    text(src, 0x54);
    var junk: Writer.Allocating = .init(gpa);
    defer junk.deinit();
    var buf: [4096]u8 = undefined;
    var sw: StreamWriter = try .init(gpa, &junk.writer, &buf, .{});
    defer sw.deinit();
    try sw.writer.writeAll(src[0..90_000]); // abandoned half-way
    const streams = [_]struct { n: usize, opts: StreamOptions }{
        .{ .n = 150_000, .opts = .{} },
        .{ .n = 5_000, .opts = .{ .effort = .fast } },
        .{ .n = 150_000, .opts = .{ .effort = .fast, .window_bits = 16, .block_size = 30_000 } },
        .{ .n = 0, .opts = .{ .effort = .fast, .window_bits = 16 } },
        .{ .n = 150_000, .opts = .{ .effort = .best, .window_bits = 17 } },
        .{ .n = 150_000, .opts = .{} },
    };
    for (streams) |st| {
        var o: Writer.Allocating = .init(gpa);
        defer o.deinit();
        try sw.reset(&o.writer, st.opts);
        try writeStream(&sw, src[0..st.n], 7_001, &.{});
        const want = try encoder.compressWith(gpa, src[0..st.n], .{ .effort = st.opts.effort, .window_bits = st.opts.window_bits, .block_size = st.opts.block_size });
        defer gpa.free(want);
        try testing.expectEqualSlices(u8, want, o.written());
    }
}

test "a warm writer keeps its table and history from stream to stream" {
    const gpa = testing.allocator;
    const src = try gpa.alloc(u8, 100_000);
    defer gpa.free(src);
    text(src, 0x55);
    var out: Writer.Allocating = .init(gpa);
    defer out.deinit();
    var buf: [16 * 1024]u8 = undefined;
    inline for (.{ encoder.Effort.fast, .default }) |effort| {
        const opts: StreamOptions = .{ .effort = effort, .window_bits = 18 };
        out.clearRetainingCapacity();
        var sw: StreamWriter = try .init(gpa, &out.writer, &buf, opts);
        defer sw.deinit();
        try writeStream(&sw, src, 10_000, &.{5_000});
        const table = if (effort == .fast) sw.core.matcher.fast.table.ptr else sw.core.matcher.deep.slots.ptr;
        const hist = sw.hist.items.ptr;
        const first = try gpa.dupe(u8, out.written());
        defer gpa.free(first);
        for (0..3) |_| {
            out.clearRetainingCapacity();
            try sw.reset(&out.writer, opts);
            try writeStream(&sw, src, 10_000, &.{5_000});
            try testing.expectEqualSlices(u8, first, out.written());
        }
        try testing.expectEqual(table, if (effort == .fast) sw.core.matcher.fast.table.ptr else sw.core.matcher.deep.slots.ptr);
        try testing.expectEqual(hist, sw.hist.items.ptr);
        try expectRoundTrip(src, out.written());
    }
}

test "failures keep their cause: allocation here, or the output's" {
    const gpa = testing.allocator;
    var buf: [256]u8 = undefined;
    // a failing output: no cause of our own
    var sink: [4]u8 = undefined;
    var small: Writer = .fixed(&sink);
    var sw: StreamWriter = try .init(gpa, &small, &buf, .{});
    defer sw.deinit();
    try sw.writer.writeAll("more than four bytes of stream, surely, once compressed and finished");
    try testing.expectError(error.WriteFailed, sw.finish());
    try testing.expectEqual(null, sw.err);
    // the history cannot grow
    var failing: std.testing.FailingAllocator = .init(gpa, .{});
    var out: Writer.Allocating = .init(gpa);
    defer out.deinit();
    var sw2: StreamWriter = try .init(failing.allocator(), &out.writer, &buf, .{ .effort = .fast, .window_bits = 16 });
    defer sw2.deinit();
    failing.fail_index = failing.alloc_index;
    try testing.expectError(error.WriteFailed, sw2.writer.writeAll("x" ** 1000));
    try testing.expectEqual(error.OutOfMemory, sw2.err.?);
}

test "metadata: carried in the stream, skipped by the decoder" {
    const gpa = testing.allocator;
    const src = try gpa.alloc(u8, 50_000);
    defer gpa.free(src);
    text(src, 0x56);
    const big = try gpa.alloc(u8, 70_000);
    defer gpa.free(big);
    @memset(big, 0xa5);
    var out: Writer.Allocating = .init(gpa);
    defer out.deinit();
    var buf: [512]u8 = undefined;
    var sw: StreamWriter = try .init(gpa, &out.writer, &buf, .{});
    defer sw.deinit();
    try sw.writeMetadata("before anything");
    try sw.writer.writeAll(src[0..20_000]);
    try sw.writeMetadata("");
    try sw.writeMetadata(big[0..1]);
    try sw.writeMetadata(big[0..256]);
    try sw.writeMetadata(big[0..257]);
    try sw.writeMetadata(big);
    try sw.writer.writeAll(src[20_000..]);
    try sw.finish();
    try expectRoundTrip(src, out.written());
    // Every metadata byte is in the stream as written.
    try testing.expect(std.mem.indexOf(u8, out.written(), "before anything") != null);
    try testing.expect(std.mem.indexOf(u8, out.written(), big) != null);
}

test "size_hint: a table for the input, and compressWith's bytes for a short one too" {
    const gpa = testing.allocator;
    const src = try gpa.alloc(u8, 3_000);
    defer gpa.free(src);
    text(src, 0x57);
    var out: Writer.Allocating = .init(gpa);
    defer out.deinit();
    var buf: [512]u8 = undefined;
    inline for (.{ encoder.Effort.fast, .default, .best }) |effort| {
        const want = try encoder.compressWith(gpa, src, .{ .effort = effort, .window_bits = 22 });
        defer gpa.free(want);
        out.clearRetainingCapacity();
        var sw: StreamWriter = try .init(gpa, &out.writer, &buf, .{ .effort = effort, .size_hint = src.len });
        defer sw.deinit();
        try writeStream(&sw, src, 700, &.{});
        try testing.expectEqualSlices(u8, want, out.written());
        const small = if (effort == .fast) sw.core.matcher.fast.table.len else sw.core.matcher.deep.count.len;
        // The same hint keeps the table; a bigger one makes a bigger table;
        // more input than hinted still round-trips.
        out.clearRetainingCapacity();
        try sw.reset(&out.writer, .{ .effort = effort, .size_hint = src.len });
        try writeStream(&sw, src, 700, &.{});
        try testing.expectEqualSlices(u8, want, out.written());
        out.clearRetainingCapacity();
        try sw.reset(&out.writer, .{ .effort = effort, .size_hint = 1 << 20 });
        // (`.best`'s 256-deep buckets reach their cap of 2^12 at 3 000 bytes.)
        const big = if (effort == .fast) sw.core.matcher.fast.table.len else sw.core.matcher.deep.count.len;
        try testing.expect(if (effort == .best) small == big else small < big);
        out.clearRetainingCapacity();
        try sw.reset(&out.writer, .{ .effort = effort, .size_hint = 10 });
        try writeStream(&sw, src, 700, &.{});
        try expectRoundTrip(src, out.written());
    }
}

test "a raw prefix dictionary: compressWith's bytes, and every decoder's round trip" {
    const gpa = testing.allocator;
    const src = try gpa.alloc(u8, 200_000);
    defer gpa.free(src);
    text(src, 0x58);
    const dict = src[0..30_000];
    const input = src[20_000..];
    inline for (.{ encoder.Effort.fast, .default, .best }) |effort| {
        const plain_one = try encoder.compressWith(gpa, input, .{ .effort = effort, .window_bits = 16 });
        defer gpa.free(plain_one);
        const want = try encoder.compressWith(gpa, input, .{ .effort = effort, .window_bits = 16, .dictionary = dict });
        defer gpa.free(want);
        // The dictionary is used: smaller than without it.
        try testing.expect(want.len < plain_one.len);
        const back = try decoder.decompress(gpa, want, .{ .dictionary = dict });
        defer gpa.free(back);
        try testing.expectEqualSlices(u8, input, back);
        // Without it the stream does not decode to the input.
        if (decoder.decompress(gpa, want, .{})) |other| {
            defer gpa.free(other);
            try testing.expect(!std.mem.eql(u8, input, other));
        } else |_| {}
        // Streamed, with the slide past twice a 64 KiB window: the same bytes.
        var out: Writer.Allocating = .init(gpa);
        defer out.deinit();
        var buf: [999]u8 = undefined;
        const opts: StreamOptions = .{ .effort = effort, .window_bits = 16, .size_hint = input.len, .dictionary = dict };
        var sw: StreamWriter = try .init(gpa, &out.writer, &buf, opts);
        defer sw.deinit();
        try writeStream(&sw, input, 5_000, &.{});
        try testing.expectEqualSlices(u8, want, out.written());
        // And after a reset, again.
        out.clearRetainingCapacity();
        try sw.reset(&out.writer, opts);
        try writeStream(&sw, input, 70_000, &.{});
        try testing.expectEqualSlices(u8, want, out.written());
        // With flushes: still decodes.
        out.clearRetainingCapacity();
        try sw.reset(&out.writer, opts);
        try writeStream(&sw, input, 3_333, &.{ 1, 10_000, 100_000 });
        const back2 = try decoder.decompress(gpa, out.written(), .{ .dictionary = dict });
        defer gpa.free(back2);
        try testing.expectEqualSlices(u8, input, back2);
    }
}
