// SPDX-License-Identifier: BSD-3-Clause AND MIT (port of libzstd 1.5.7 -- see ../NOTICE)
//! Streaming decompression: `ZSTD_decompressStream` over buffered input and
//! output, and a `std.Io.Reader` on top of it.
//!
//! Port of the streaming half of lib/decompress/zstd_decompress.c
//! (v1.5.7). Input is taken in whatever pieces the caller has; a frame
//! header or block that arrives split is gathered in an input buffer of one
//! block. Output goes through a window-sized ring (`ZSTD_decodingBufferSize`:
//! the window plus two blocks) unless the caller promises a stable output
//! buffer, in which case blocks are decoded straight into it. A frame
//! whose whole compressed form is already in the input and whose content
//! fits the output is decoded in one go (libzstd's single-pass shortcut).
//! The window a frame may ask for is capped (`window_log_max`, default 27:
//! 128 MB), as libzstd's is.

const std = @import("std");
const dec = @import("decompress.zig");
const stream = @import("stream.zig");
const dbits = @import("dbits.zig");

pub const InBuffer = stream.InBuffer;
pub const OutBuffer = stream.OutBuffer;

pub const Error = dec.Error || error{
    OutOfMemory,
    /// Sixteen calls in a row that consumed no input and produced no output.
    NoForwardProgressDestFull,
    NoForwardProgressInputEmpty,
    /// `stable_output` was promised, but the output buffer changed.
    DstBufferWrong,
};

/// `ZSTD_WINDOWLOG_LIMIT_DEFAULT`.
pub const window_log_limit_default = 27;
const workspace_too_large_factor = 3;
const workspace_too_large_max_duration = 128;
const no_forward_progress_max = 16;

pub const Options = struct {
    /// Do not verify content checksums (`ZSTD_d_forceIgnoreChecksum`).
    ignore_checksum: bool = false,
    /// Refuse frames whose window exceeds 2^window_log_max bytes
    /// (`ZSTD_d_windowLogMax`; below 10 counts as 10); null is libzstd's
    /// default, 2^27 + 1 bytes (exactly 2^27 allowed).
    window_log_max: ?u5 = null,
    /// The caller keeps the same output buffer between calls and only lets
    /// `pos` grow (`ZSTD_d_stableOutBuffer`): blocks are decoded straight
    /// into it and no output ring is allocated. A frame whose content size
    /// is known must then fit it whole.
    stable_output: bool = false,
    /// `ZSTD_d_format`, as `DecompressOptions.format`.
    format: dec.Format = .zstd1,
};

const StreamStage = enum { init, load_header, read, load, flush };

/// `ZSTD_DStream`.
pub const DecompressStream = struct {
    d: dec.Decompressor,
    max_window_size: u64,
    stable_output: bool,
    stage: StreamStage = .init,
    /// One allocation: the input buffer, then the output ring.
    buf: []u8 = &.{},
    in_buff_size: usize = 0,
    out_buff_size: usize = 0,
    in_pos: usize = 0,
    out_start: usize = 0,
    out_end: usize = 0,
    lh_size: usize = 0,
    hostage_byte: bool = false,
    no_forward_progress: u32 = 0,
    oversized_duration: usize = 0,
    expected_out: struct { ptr: usize = 0, len: usize = 0, pos: usize = 0 } = .{},

    pub fn init(gpa: std.mem.Allocator, options: Options) error{OutOfMemory}!DecompressStream {
        return .{
            .d = try dec.Decompressor.init(gpa, .{ .ignore_checksum = options.ignore_checksum, .format = options.format }),
            .max_window_size = if (options.window_log_max) |l| @as(u64, 1) << @max(l, dec.window_log_absolute_min) else (@as(u64, 1) << window_log_limit_default) + 1,
            .stable_output = options.stable_output,
        };
    }

    pub fn deinit(s: *DecompressStream) void {
        s.d.gpa.free(s.buf);
        s.d.deinit();
        s.* = undefined;
    }

    /// `ZSTD_DCtx_reset(ZSTD_reset_session_only)`: abandon the frame in
    /// progress; the next call starts a new one. Buffers are kept.
    pub fn reset(s: *DecompressStream) void {
        s.stage = .init;
        s.no_forward_progress = 0;
    }

    fn inBuff(s: *DecompressStream) []u8 {
        return s.buf[0..s.in_buff_size];
    }
    fn outBuff(s: *DecompressStream) []u8 {
        return s.buf[s.in_buff_size..][0..s.out_buff_size];
    }

    /// `ZSTD_decompressContinueStream`.
    fn continueStream(s: *DecompressStream, out: *OutBuffer, op: *usize, src: []const u8) Error!void {
        const skip = s.d.stage == .skip_frame;
        if (!s.stable_output) {
            const dst_size = if (skip) 0 else s.out_buff_size - s.out_start;
            const decoded = try s.d.decompressContinue(s.outBuff()[s.out_start..][0..dst_size], src);
            if (decoded == 0 and !skip) {
                s.stage = .read;
            } else {
                s.out_end = s.out_start + decoded;
                s.stage = .flush;
            }
        } else {
            const dst_size = if (skip) 0 else out.dst.len - op.*;
            const decoded = try s.d.decompressContinue(out.dst[op.*..][0..dst_size], src);
            op.* += decoded;
            s.stage = .read;
        }
    }

    /// `ZSTD_decodingBufferSize_internal`.
    fn decodingBufferSize(window_size: u64, content_size: ?u64, block_size_max: usize) Error!usize {
        const block_size: u64 = @min(@min(window_size, dec.block_size_max), block_size_max);
        const needed_rb = window_size + block_size * 2 + 32 * 2;
        const needed = @min(content_size orelse std.math.maxInt(u64), needed_rb);
        return std.math.cast(usize, needed) orelse error.FrameParameterWindowTooLarge;
    }

    /// `ZSTD_decompressStream`: consumes what it can of `in`, writes what
    /// it can to `out`. Returns 0 when a frame is completely decoded and
    /// flushed, else a hint of how many more input bytes the frame needs.
    /// Concatenated and skippable frames are read one after another.
    pub fn decompressStream(s: *DecompressStream, out: *OutBuffer, in: *InBuffer) Error!usize {
        const d = &s.d;
        const istart = in.pos;
        const iend = in.src.len;
        var ip = istart;
        const ostart = out.pos;
        const oend = out.dst.len;
        var op = ostart;
        if (in.pos > in.src.len) return error.SrcSizeWrong;
        if (out.pos > out.dst.len) return error.DstSizeTooSmall;
        if (s.stable_output and s.stage != .init) {
            // ZSTD_checkOutBuffer
            if (!(s.expected_out.ptr == @intFromPtr(out.dst.ptr) and s.expected_out.len == out.dst.len and s.expected_out.pos == out.pos))
                return error.DstBufferWrong;
        }

        var more = true;
        while (more) {
            switch (s.stage) {
                .init, .load_header => {
                    if (s.stage == .init) {
                        s.stage = .load_header;
                        s.lh_size = 0;
                        s.in_pos = 0;
                        s.out_start = 0;
                        s.out_end = 0;
                        s.hostage_byte = false;
                        s.expected_out = .{ .ptr = @intFromPtr(out.dst.ptr), .len = out.dst.len, .pos = out.pos };
                    }
                    const format = d.options.format;
                    switch (try dec.getFrameHeaderAdvanced(d.header_buffer[0..s.lh_size], format)) {
                        .need => |h_size| {
                            const to_load = h_size - s.lh_size;
                            const remaining = iend - ip;
                            if (to_load > remaining) {
                                if (remaining > 0) {
                                    @memcpy(d.header_buffer[s.lh_size..][0..remaining], in.src[ip..iend]);
                                    s.lh_size += remaining;
                                }
                                in.pos = in.src.len;
                                // the first few bytes may already show it is no frame
                                _ = try dec.getFrameHeaderAdvanced(d.header_buffer[0..s.lh_size], format);
                                return (@max(dec.headerSizeMin(format), h_size) - s.lh_size) + dec.block_header_size;
                            }
                            @memcpy(d.header_buffer[s.lh_size..][0..to_load], in.src[ip..][0..to_load]);
                            s.lh_size = h_size;
                            ip += to_load;
                            continue;
                        },
                        .header => |h| d.fparams = h,
                    }

                    // single-pass shortcut: the whole frame is here and fits
                    if (d.fparams.content_size) |fcs| if (d.fparams.frame_type != .skippable and oend - op >= fcs) {
                        if (dec.findFrameCompressedSizeAdvanced(in.src[istart..iend], format)) |c_size| {
                            const n = try d.decompress(out.dst[op..oend], in.src[istart..][0..c_size]);
                            ip = istart + c_size;
                            op += n;
                            d.expected = 0;
                            s.stage = .init;
                            more = false;
                            continue;
                        } else |_| {}
                    };

                    if (s.stable_output and d.fparams.frame_type != .skippable) {
                        if (d.fparams.content_size) |fcs| if (oend - op < fcs) return error.DstSizeTooSmall;
                    }

                    // consume the header
                    d.begin();
                    if (format == .zstd1 and dec.isSkippableFrame(d.header_buffer[0..s.lh_size])) {
                        d.expected = dbits.readLE32(&d.header_buffer, 4);
                        d.stage = .skip_frame;
                    } else {
                        try d.decodeFrameHeader(d.header_buffer[0..s.lh_size]);
                        d.expected = dec.block_header_size;
                        d.stage = .decode_block_header;
                    }

                    // control memory usage
                    d.fparams.window_size = @max(d.fparams.window_size, @as(u64, 1) << dec.window_log_absolute_min);
                    if (d.fparams.window_size > s.max_window_size) return error.FrameParameterWindowTooLarge;
                    {
                        const needed_in: usize = @max(d.fparams.block_size_max, 4);
                        const needed_out: usize = if (s.stable_output) 0 else try decodingBufferSize(d.fparams.window_size, d.fparams.content_size, d.fparams.block_size_max);
                        // ZSTD_DCtx_updateOversizedDuration
                        if (s.in_buff_size + s.out_buff_size >= (needed_in + needed_out) * workspace_too_large_factor)
                            s.oversized_duration += 1
                        else
                            s.oversized_duration = 0;
                        const too_small = s.in_buff_size < needed_in or s.out_buff_size < needed_out;
                        const too_large = s.oversized_duration >= workspace_too_large_max_duration;
                        if (too_small or too_large) {
                            d.gpa.free(s.buf);
                            s.buf = &.{};
                            s.in_buff_size = 0;
                            s.out_buff_size = 0;
                            s.buf = try d.gpa.alloc(u8, needed_in + needed_out);
                            s.in_buff_size = needed_in;
                            s.out_buff_size = needed_out;
                        }
                    }
                    s.stage = .read;
                    continue;
                },
                .read => {
                    const needed = d.nextSrcSizeWithInputSize(iend - ip);
                    if (needed == 0) { // end of frame
                        s.stage = .init;
                        more = false;
                        continue;
                    }
                    if (iend - ip >= needed) { // decode directly from the input
                        try s.continueStream(out, &op, in.src[ip..][0..needed]);
                        ip += needed;
                        continue;
                    }
                    if (ip == iend) { // no more input
                        more = false;
                        continue;
                    }
                    s.stage = .load;
                    continue;
                },
                .load => {
                    const needed = d.nextSrcSizeToDecompress();
                    const to_load = needed - s.in_pos;
                    var loaded: usize = undefined;
                    if (d.stage == .skip_frame) {
                        loaded = @min(to_load, iend - ip);
                    } else {
                        if (to_load > s.in_buff_size - s.in_pos) return error.CorruptionDetected; // should never happen
                        loaded = @min(to_load, iend - ip);
                        @memcpy(s.inBuff()[s.in_pos..][0..loaded], in.src[ip..][0..loaded]);
                    }
                    ip += loaded;
                    s.in_pos += loaded;
                    if (loaded < to_load) { // not enough input, wait for more
                        more = false;
                        continue;
                    }
                    // decode the loaded input
                    s.in_pos = 0;
                    try s.continueStream(out, &op, s.inBuff()[0..needed]);
                    continue;
                },
                .flush => {
                    const to_flush = s.out_end - s.out_start;
                    const flushed = @min(oend - op, to_flush);
                    @memcpy(out.dst[op..][0..flushed], s.outBuff()[s.out_start..][0..flushed]);
                    op += flushed;
                    s.out_start += flushed;
                    if (flushed == to_flush) { // flush completed
                        s.stage = .read;
                        if (s.out_buff_size < (d.fparams.content_size orelse std.math.maxInt(u64)) and
                            s.out_start + d.fparams.block_size_max > s.out_buff_size)
                        {
                            s.out_start = 0;
                            s.out_end = 0;
                        }
                        continue;
                    }
                    more = false; // cannot complete the flush
                    continue;
                },
            }
        }

        in.pos = ip;
        out.pos = op;
        s.expected_out = .{ .ptr = @intFromPtr(out.dst.ptr), .len = out.dst.len, .pos = out.pos };
        if (ip == istart and op == ostart) {
            s.no_forward_progress += 1;
            if (s.no_forward_progress >= no_forward_progress_max) {
                if (op == oend) return error.NoForwardProgressDestFull;
                if (ip == iend) return error.NoForwardProgressInputEmpty;
            }
        } else {
            s.no_forward_progress = 0;
        }

        var hint = d.nextSrcSizeToDecompress();
        if (hint == 0) { // frame fully decoded
            if (s.out_end == s.out_start) { // output fully flushed
                if (s.hostage_byte) {
                    if (in.pos >= in.src.len) {
                        // cannot release the hostage byte yet
                        s.stage = .read;
                        return 1;
                    }
                    in.pos += 1; // release the hostage byte
                }
                return 0;
            }
            // output not fully flushed: keep one input byte hostage so that
            // the caller does not see all input consumed
            if (!s.hostage_byte and in.pos > 0) {
                in.pos -= 1;
                s.hostage_byte = true;
            }
            return 1;
        }
        if (d.stage == .decompress_block) hint += dec.block_header_size; // the next block header comes with it
        hint -= s.in_pos;
        return hint;
    }
};

/// A `std.Io.Reader` of the decompressed content of every frame read from
/// `input` (concatenated and skippable frames included), through a
/// `DecompressStream`. Memory: one window plus two blocks of output ring
/// (at most `window_log_max`), one block of input buffer, and the
/// decoder's ~190 KB of tables.
pub const Reader = struct {
    s: DecompressStream,
    input: *std.Io.Reader,
    interface: std.Io.Reader,
    /// Why the last read failed with `error.ReadFailed` when `input` did
    /// not fail: a decoding error, or `error.SrcSizeWrong` when the input
    /// ended inside a frame.
    err: ?Error = null,
    /// The last call left a frame unfinished.
    in_frame: bool = false,

    /// `buffer` may be empty; reads then go straight into the caller's
    /// writer.
    pub fn init(gpa: std.mem.Allocator, input: *std.Io.Reader, buffer: []u8, options: Options) error{OutOfMemory}!Reader {
        var o = options;
        o.stable_output = false;
        return .{
            .s = try DecompressStream.init(gpa, o),
            .input = input,
            .interface = .{ .vtable = &vtable, .buffer = buffer, .seek = 0, .end = 0 },
        };
    }

    pub fn deinit(r: *Reader) void {
        r.s.deinit();
        r.* = undefined;
    }

    const vtable: std.Io.Reader.VTable = .{ .stream = streamFn };

    fn streamFn(io_r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const r: *Reader = @alignCast(@fieldParentPtr("interface", io_r));
        const dest = limit.slice(try w.writableSliceGreedy(1));
        if (dest.len == 0) return 0;
        while (true) {
            // between frames with nothing buffered: the input's end is the
            // stream's end, not a truncated frame
            if (!r.in_frame and r.input.buffered().len == 0) {
                r.input.fillMore() catch |e| switch (e) {
                    error.EndOfStream => return error.EndOfStream,
                    error.ReadFailed => return error.ReadFailed,
                };
            }
            var in: InBuffer = .{ .src = r.input.buffered() };
            var out: OutBuffer = .{ .dst = dest };
            const hint = r.s.decompressStream(&out, &in) catch |e| {
                r.err = e;
                return error.ReadFailed;
            };
            r.input.toss(in.pos);
            r.in_frame = hint != 0;
            if (out.pos > 0) {
                w.advance(out.pos);
                return out.pos;
            }
            if (in.pos > 0) continue; // consumed input without output yet
            r.input.fillMore() catch |e| switch (e) {
                error.EndOfStream => {
                    if (r.in_frame) {
                        r.err = error.SrcSizeWrong;
                        return error.ReadFailed;
                    }
                    return error.EndOfStream;
                },
                error.ReadFailed => return error.ReadFailed,
            };
        }
    }
};
