// SPDX-License-Identifier: MIT

//! Streaming frames over `std.Io`: `Compressor` is a `std.Io.Writer` that writes
//! one LZ4 frame to another writer, block by block; `Decompressor` is a
//! `std.Io.Reader` that reads LZ4 frames from another reader, block by block.
//! Memory is bounded by the frame's block size, never by the content: a
//! compressor holds its history window (64 KiB, linked blocks) and one block
//! of input plus one compressed block; a decompressor one compressed block, one
//! decoded block and the history window.

const std = @import("std");
const block = @import("block.zig");
const frame = @import("frame.zig");
const Writer = std.Io.Writer;
const Reader = std.Io.Reader;
const XxHash32 = std.hash.XxHash32;

const history_len = block.max_offset;

pub const CompressorOptions = struct {
    frame: frame.EncodeOptions = .{},
    /// The content size for the header (`EncodeOptions.content_size` needs it
    /// before the first byte is written; a stream cannot know it otherwise).
    /// The end of the stream is not checked against it.
    content_size: ?u64 = null,
};

/// One LZ4 frame, written through `writer`. `finish` ends the frame (the end
/// mark and the content checksum); `flush` on `writer` writes the buffered
/// bytes as a (short) block. The output writer is not flushed by `finish`.
pub const Compressor = struct {
    gpa: std.mem.Allocator,
    out: *Writer,
    opts: frame.EncodeOptions,
    content_size: ?u64,
    /// `[history][block]`: `writer.buffer` is the block part.
    work: []u8,
    /// Where a compressed block is built.
    zbuf: []u8,
    hist: usize = 0,
    table: block.Table = @splat(0),
    hc: ?*block.HcTable = null,
    content_hash: XxHash32,
    wrote_header: bool = false,
    finished: bool = false,
    writer: Writer,

    pub const Error = Writer.Error || std.mem.Allocator.Error;

    pub fn init(gpa: std.mem.Allocator, out: *Writer, options: CompressorOptions) std.mem.Allocator.Error!*Compressor {
        const self = try gpa.create(Compressor);
        errdefer gpa.destroy(self);
        const bmax = options.frame.block_size.bytes();
        const work = try gpa.alloc(u8, history_len + bmax);
        errdefer gpa.free(work);
        const zbuf = try gpa.alloc(u8, block.compressBound(bmax));
        errdefer gpa.free(zbuf);
        var hc: ?*block.HcTable = null;
        if (options.frame.hc_level >= block.hc_min_level) {
            hc = try gpa.create(block.HcTable);
            hc.?.init();
        }
        self.* = .{
            .gpa = gpa,
            .out = out,
            .opts = options.frame,
            .content_size = options.content_size,
            .work = work,
            .zbuf = zbuf,
            .hc = hc,
            .content_hash = XxHash32.init(0),
            .writer = .{
                .vtable = &.{ .drain = drain },
                .buffer = work[history_len..],
            },
        };
        return self;
    }

    pub fn deinit(self: *Compressor) void {
        const gpa = self.gpa;
        if (self.hc) |t| gpa.destroy(t);
        gpa.free(self.work);
        gpa.free(self.zbuf);
        gpa.destroy(self);
    }

    fn writeHeader(self: *Compressor) Writer.Error!void {
        if (self.wrote_header) return;
        self.wrote_header = true;
        var h: [15]u8 = undefined;
        std.mem.writeInt(u32, h[0..4], frame.magic, .little);
        var flg: u8 = 0x40;
        if (self.opts.independent_blocks) flg |= 0x20;
        if (self.opts.block_checksum) flg |= 0x10;
        const size = if (self.opts.content_size) self.content_size else null;
        if (size != null) flg |= 0x08;
        if (self.opts.content_checksum) flg |= 0x04;
        h[4] = flg;
        h[5] = @as(u8, @backingInt(self.opts.block_size)) << 4;
        var at: usize = 6;
        if (size) |sz| {
            std.mem.writeInt(u64, h[6..14], sz, .little);
            at = 14;
        }
        h[at] = @truncate(XxHash32.hash(0, h[4..at]) >> 8);
        at += 1;
        try self.out.writeAll(h[0..at]);
    }

    /// Compress and write the bytes in `writer.buffer[0..end]` as one block.
    fn flushBlock(self: *Compressor) Writer.Error!void {
        const n = self.writer.end;
        if (n == 0) return;
        try self.writeHeader();
        const start = history_len;
        const end = start + n;
        const raw = self.work[start..end];
        if (self.opts.content_checksum) self.content_hash.update(raw);
        const independent = self.opts.independent_blocks;
        const history = if (independent) start else start - self.hist;
        const room = @min(self.zbuf.len, raw.len -| 1);
        const accel = block.clampAcceleration(self.opts.acceleration);
        const z: ?usize = blk: {
            if (raw.len < 2) break :blk null;
            if (self.hc) |t| {
                // The chain table indexes positions modulo 64 Ki, which a
                // slide of the window shifts: rebuild it from the history.
                t.init();
                break :blk block.encodeHc(self.work, start, end, history, t, self.opts.hc_level, self.zbuf[0..room]) catch null;
            }
            break :blk block.encodeRange(self.work, start, end, history, &self.table, accel, self.zbuf[0..room]) catch null;
        };
        var size_word: u32 = undefined;
        var body: []const u8 = undefined;
        if (z) |zn| {
            size_word = @intCast(zn);
            body = self.zbuf[0..zn];
        } else {
            size_word = @as(u32, @intCast(raw.len)) | 0x8000_0000;
            body = raw;
        }
        var w4: [4]u8 = undefined;
        std.mem.writeInt(u32, &w4, size_word, .little);
        try self.out.writeAll(&w4);
        try self.out.writeAll(body);
        if (self.opts.block_checksum) {
            std.mem.writeInt(u32, &w4, XxHash32.hash(0, body), .little);
            try self.out.writeAll(&w4);
        }
        // Slide the window: the last (up to) 64 KiB - 1 bytes become the history.
        if (independent) {
            self.hist = 0;
        } else {
            const keep = @min(history_len, self.hist + n);
            std.mem.copyForwards(u8, self.work[history_len - keep .. history_len], self.work[end - keep .. end]);
            // Table positions move down by what the window moved.
            const shift = end - history_len;
            for (&self.table) |*e| e.* = @intCast(@as(usize, e.*) -| shift);
            self.hist = keep;
        }
        if (independent) self.table = @splat(0);
        self.writer.end = 0;
    }

    fn drain(w: *Writer, data: []const []const u8, splat: usize) Writer.Error!usize {
        const self: *Compressor = @fieldParentPtr("writer", w);
        try self.flushBlock();
        var consumed: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            try self.append(d);
            consumed += d.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| try self.append(last);
        consumed += last.len * splat;
        return consumed;
    }

    fn append(self: *Compressor, bytes: []const u8) Writer.Error!void {
        var rest = bytes;
        while (rest.len > 0) {
            const w = &self.writer;
            const room = w.buffer.len - w.end;
            const k = @min(room, rest.len);
            @memcpy(w.buffer[w.end..][0..k], rest[0..k]);
            w.end += k;
            rest = rest[k..];
            if (w.end == w.buffer.len) try self.flushBlock();
        }
    }

    /// Write what is buffered, the end mark and the content checksum. The
    /// frame is complete; nothing more may be written. Does not flush `out`.
    pub fn finish(self: *Compressor) Writer.Error!void {
        if (self.finished) return;
        try self.flushBlock();
        try self.writeHeader(); // an empty stream is still a frame
        var t: [8]u8 = undefined;
        std.mem.writeInt(u32, t[0..4], 0, .little);
        var n: usize = 4;
        if (self.opts.content_checksum) {
            std.mem.writeInt(u32, t[4..8], self.content_hash.final(), .little);
            n = 8;
        }
        try self.out.writeAll(t[0..n]);
        self.finished = true;
    }
};

pub const DecompressorOptions = struct {
    /// Bomb cap on the total output, as `DecodeOptions.max_output`; null = none.
    max_output: ?usize = frame.default_max_output,
    verify_checksums: bool = true,
    /// A dictionary for frames made with one (its last 64 KiB - 1 bytes); the
    /// first block of a frame, or every block when they are independent, may
    /// reach into it.
    dictionary: []const u8 = "",
};

/// LZ4 frames (concatenated, skippable frames skipped) read through `reader`.
/// A malformed stream ends the read with `error.ReadFailed`; `err` says why.
/// The legacy frame is not supported (`error.BadMagic`).
pub const Decompressor = struct {
    gpa: std.mem.Allocator,
    input: *Reader,
    opts: DecompressorOptions,
    dict: []const u8,
    /// `[history][block]`, the decode target.
    work: []u8 = &.{},
    cbuf: []u8 = &.{},
    hist: usize = 0,
    /// Decoded bytes of the current block not yet handed out: `work[from..to]`.
    from: usize = 0,
    to: usize = 0,
    // frame state
    in_frame: bool = false,
    block_max: usize = 0,
    independent: bool = false,
    has_block_sum: bool = false,
    has_content_sum: bool = false,
    content_size: ?u64 = null,
    frame_out: u64 = 0,
    content_hash: XxHash32 = XxHash32.init(0),
    total: u64 = 0,
    first_frame: bool = true,
    done: bool = false,
    err: ?frame.DecodeError = null,
    reader: Reader,

    pub fn init(gpa: std.mem.Allocator, input: *Reader, buffer: []u8, opts: DecompressorOptions) std.mem.Allocator.Error!*Decompressor {
        const self = try gpa.create(Decompressor);
        self.* = .{
            .gpa = gpa,
            .input = input,
            .opts = opts,
            .dict = block.dictTail(opts.dictionary),
            .reader = .{ .vtable = &.{ .stream = stream }, .buffer = buffer, .seek = 0, .end = 0 },
        };
        return self;
    }

    pub fn deinit(self: *Decompressor) void {
        const gpa = self.gpa;
        gpa.free(self.work);
        gpa.free(self.cbuf);
        gpa.destroy(self);
    }

    fn fail(self: *Decompressor, e: frame.DecodeError) Reader.StreamError {
        self.err = e;
        return error.ReadFailed;
    }

    fn take32(self: *Decompressor) Reader.StreamError!u32 {
        const b = self.input.takeArray(4) catch |e| switch (e) {
            error.EndOfStream => return self.fail(error.TruncatedInput),
            error.ReadFailed => return error.ReadFailed,
        };
        return std.mem.readInt(u32, b, .little);
    }

    fn readExact(self: *Decompressor, dst: []u8) Reader.StreamError!void {
        self.input.readSliceAll(dst) catch |e| switch (e) {
            error.EndOfStream => return self.fail(error.TruncatedInput),
            error.ReadFailed => return error.ReadFailed,
        };
    }

    /// Start the next frame: false at the end of the input.
    fn startFrame(self: *Decompressor) Reader.StreamError!bool {
        while (true) {
            // The first word, or the end of the input.
            const peek = self.input.peekArray(4) catch |e| switch (e) {
                error.EndOfStream => {
                    if (self.first_frame) return self.fail(error.TruncatedInput);
                    // A few bytes that are not a magic number.
                    if (self.input.buffered().len != 0) return self.fail(error.TrailingData);
                    return false;
                },
                error.ReadFailed => return error.ReadFailed,
            };
            const m = std.mem.readInt(u32, peek, .little);
            self.input.toss(4);
            if (m == frame.magic) break;
            if (m & 0xFFFF_FFF0 == frame.skippable_magic_base) {
                const len = try self.take32();
                self.input.discardAll(len) catch |e| switch (e) {
                    error.EndOfStream => return self.fail(error.TruncatedInput),
                    error.ReadFailed => return error.ReadFailed,
                };
                self.first_frame = false;
                continue;
            }
            return self.fail(if (self.first_frame) error.BadMagic else error.TrailingData);
        }
        self.first_frame = false;
        var d: [11]u8 = undefined;
        try self.readExact(d[0..2]);
        const flg = d[0];
        const bd = d[1];
        if (flg >> 6 != 1) return self.fail(error.BadVersion);
        if (flg & 0x02 != 0 or bd & 0x8F != 0) return self.fail(error.ReservedBitSet);
        const bsid: u3 = @intCast(bd >> 4);
        if (bsid < 4) return self.fail(error.BadBlockSize);
        self.block_max = frame.BlockSize.bytes(@fromBackingInt(@intCast(bsid)));
        self.independent = flg & 0x20 != 0;
        self.has_block_sum = flg & 0x10 != 0;
        self.has_content_sum = flg & 0x04 != 0;
        const has_size = flg & 0x08 != 0;
        const has_dict = flg & 0x01 != 0;
        var at: usize = 2;
        const extra: usize = (if (has_size) @as(usize, 8) else 0) + (if (has_dict) @as(usize, 4) else 0);
        try self.readExact(d[2 .. 2 + extra + 1]);
        at += extra;
        const hc: u8 = @truncate(XxHash32.hash(0, d[0..at]) >> 8);
        if (hc != d[at]) return self.fail(error.HeaderChecksumMismatch);
        self.content_size = null;
        if (has_size) {
            const v = std.mem.readInt(u64, d[2..10], .little);
            if (v != 0) self.content_size = v;
        }
        if (self.content_size) |cs| if (self.opts.max_output) |cap| {
            if (cs > cap -| self.total) return self.fail(error.OutputTooLarge);
        };
        // Buffers sized for this frame's blocks (kept when large enough).
        const need_work = history_len + self.block_max;
        if (self.work.len < need_work) {
            self.gpa.free(self.work);
            self.work = &.{};
            self.work = self.gpa.alloc(u8, need_work) catch return self.fail(error.OutOfMemory);
        }
        const need_c = self.block_max;
        if (self.cbuf.len < need_c) {
            self.gpa.free(self.cbuf);
            self.cbuf = &.{};
            self.cbuf = self.gpa.alloc(u8, need_c) catch return self.fail(error.OutOfMemory);
        }
        self.frame_out = 0;
        self.content_hash = XxHash32.init(0);
        self.hist = 0;
        // Linked blocks: the dictionary is the history of the first block.
        if (self.dict.len > 0 and !self.independent) {
            @memcpy(self.work[history_len - self.dict.len .. history_len], self.dict);
            self.hist = self.dict.len;
        }
        self.in_frame = true;
        return true;
    }

    /// Decode the next block of the frame into `work`; false at the end mark.
    fn nextBlock(self: *Decompressor) Reader.StreamError!bool {
        const word = try self.take32();
        if (word == 0) {
            if (self.content_size) |cs| if (self.frame_out != cs) return self.fail(error.ContentSizeMismatch);
            if (self.has_content_sum) {
                const want = try self.take32();
                if (self.opts.verify_checksums and self.content_hash.final() != want) return self.fail(error.ContentChecksumMismatch);
            }
            self.in_frame = false;
            return false;
        }
        const stored = word & 0x8000_0000 != 0;
        const len: usize = word & 0x7FFF_FFFF;
        if (len > self.block_max) return self.fail(error.BlockTooLarge);
        const data = self.cbuf[0..len];
        try self.readExact(data);
        if (self.has_block_sum) {
            const want = try self.take32();
            if (self.opts.verify_checksums and XxHash32.hash(0, data) != want) return self.fail(error.BlockChecksumMismatch);
        }
        const start = history_len;
        var n: usize = undefined;
        if (stored) {
            @memcpy(self.work[start..][0..len], data);
            n = len;
        } else {
            // Independent blocks start from the dictionary (or nothing).
            if (self.independent) {
                self.hist = self.dict.len;
                if (self.dict.len > 0) @memcpy(self.work[history_len - self.dict.len .. history_len], self.dict);
            }
            const buf = self.work[0 .. start + self.block_max];
            const end = block.decodeInto(data, buf, start, start - self.hist) catch |e| return self.fail(switch (e) {
                error.Truncated => error.CorruptBlock,
                error.BadOffset => error.BadOffset,
                error.OutputTooSmall => error.BlockTooLarge,
            });
            n = end - start;
        }
        if (self.opts.max_output) |cap| if (n > cap -| self.total) return self.fail(error.OutputTooLarge);
        self.total += n;
        self.frame_out += n;
        if (self.has_content_sum) self.content_hash.update(self.work[start..][0..n]);
        self.from = start;
        self.to = start + n;
        // The history for the next block: the last bytes of this one (and the
        // old history, if this block was short), moved just below `start`.
        if (!self.independent) {
            const keep = @min(history_len, self.hist + n);
            std.mem.copyForwards(u8, self.work[start - keep .. start], self.work[start + n - keep .. start + n]);
            self.hist = keep;
        }
        return true;
    }

    fn stream(r: *Reader, w: *Writer, limit: std.Io.Limit) Reader.StreamError!usize {
        const self: *Decompressor = @fieldParentPtr("reader", r);
        if (self.err != null) return error.ReadFailed;
        while (self.from == self.to) {
            if (self.done) return error.EndOfStream;
            if (!self.in_frame) {
                if (!try self.startFrame()) {
                    self.done = true;
                    return error.EndOfStream;
                }
            }
            _ = try self.nextBlock();
        }
        const k = limit.minInt(self.to - self.from);
        if (k == 0) return 0;
        // The history of a linked block sits below `work[history_len..]`; the
        // decoded block is still in place there, so this reads it directly.
        try w.writeAll(self.work[self.from..][0..k]);
        self.from += k;
        return k;
    }
};
