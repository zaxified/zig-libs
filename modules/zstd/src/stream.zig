// SPDX-License-Identifier: BSD-3-Clause AND MIT (port of libzstd 1.5.7 -- see ../NOTICE)
//! Streaming compression (port of `ZSTD_compressStream2` and
//! `ZSTD_compressStream_generic`, lib/compress/zstd_compress.c, v1.5.7, with
//! buffered input and output — libzstd's default buffer modes).
//!
//! The bytes a stream produces depend on how its input arrives: libzstd
//! copies input into a buffer of one window plus one block and compresses a
//! chunk each time a block's worth is buffered, at each flush, and at the
//! end; the pre-splitter then only ever sees one chunk. When the buffer
//! wraps, the window becomes two segments (the old one is the "extDict"),
//! and every match finder runs its extDict variant from then on. Mirroring
//! the buffer and those decisions exactly is what makes the output
//! byte-identical to libzstd for the same sequence of calls.

const std = @import("std");
const frame = @import("frame.zig");
const params = @import("params.zig");

pub const EndDirective = enum {
    /// Buffer the input; compress only full blocks (`ZSTD_e_continue`).
    @"continue",
    /// Compress what is buffered and emit it, ending the current block
    /// (`ZSTD_e_flush`).
    flush,
    /// Compress everything and end the frame (`ZSTD_e_end`).
    end,
};

/// `ZSTD_inBuffer`: `pos` advances over what was consumed.
pub const InBuffer = struct {
    src: []const u8,
    pos: usize = 0,
};

/// `ZSTD_outBuffer`: `pos` advances over what was written.
pub const OutBuffer = struct {
    dst: []u8,
    pos: usize = 0,
};

pub const Options = struct {
    /// Up to `max_level`; 0 for the default, or negative.
    level: i32 = params.default_level,
    checksum: bool = false,
    /// `ZSTD_CCtx_setPledgedSrcSize`: the exact number of bytes the frame
    /// will hold, which goes into the header and sizes the parameters as a
    /// one-shot compression would. Null is unknown — unless the first call
    /// already ends the frame, in which case its input is the size, as in
    /// libzstd.
    pledged_size: ?u64 = null,
};

/// The highest level a stream accepts for now: levels up to 10 use
/// `fast` .. `btlazy2` for every input size (level 11 is `btopt` on inputs
/// of 16 KB or less), the match finders whose extDict variants are ported.
pub const max_level = 10;

pub const Error = error{
    /// Level above `max_level`.
    LevelUnsupported,
    OutOfMemory,
    /// More input than pledged, or, at the end, less (`srcSize_wrong`).
    SrcSizeWrong,
    /// `pos` beyond the end of a buffer.
    InvalidBuffer,
    /// A call after the frame ended. libzstd would start a new frame on the
    /// same context, reusing its tables (which changes the output); that is
    /// not supported yet.
    FrameEnded,
};

/// A compression context in streaming mode (`ZSTD_CCtx` driven by
/// `ZSTD_compressStream2`), for one frame.
pub const Stream = struct {
    gpa: std.mem.Allocator,
    opts: Options,
    stage: enum { init, load, flush, done } = .init,
    comp: frame.Compressor = undefined,
    in_buff: []u8 = &.{},
    in_buff_pos: usize = 0,
    in_buff_target: usize = 0,
    in_to_compress: usize = 0,
    out_buff: []u8 = &.{},
    out_content: usize = 0,
    out_flushed: usize = 0,
    frame_ended: bool = false,
    /// Test seam, set before the first call: `ZSTD_c_windowLog`, a window
    /// smaller than the level's, so the input buffer wraps within kilobytes.
    window_log: ?u32 = null,
    /// Test seam, set before the first call: index overflow corrected as
    /// libzstd's fuzzing build does it (`frame.Options.
    /// overflow_correct_frequently`), which reaches the correction of a
    /// two-segment window within kilobytes.
    overflow_correct_frequently: bool = false,

    /// Nothing is allocated until the first `compressStream2`, which knows
    /// whether that call ends the frame (and so the size).
    pub fn init(gpa: std.mem.Allocator, opts: Options) Error!Stream {
        if (opts.level > max_level) return error.LevelUnsupported;
        return .{ .gpa = gpa, .opts = opts };
    }

    pub fn deinit(s: *Stream) void {
        if (s.stage != .init) {
            s.comp.deinit();
            s.gpa.free(s.in_buff);
            s.gpa.free(s.out_buff);
        }
        s.* = undefined;
    }

    /// `ZSTD_compressStream2`. Consumes input and writes output as far as
    /// the buffers allow; returns how many compressed bytes are still held
    /// back for lack of output room (for `flush` and `end`, call again
    /// until it is 0 — for `end`, the frame is then complete).
    pub fn compressStream2(s: *Stream, output: *OutBuffer, input: *InBuffer, end_op: EndDirective) Error!usize {
        if (output.pos > output.dst.len or input.pos > input.src.len) return error.InvalidBuffer;
        if (s.stage == .done) return error.FrameEnded;
        if (s.stage == .init) try s.begin(end_op, input.src.len - input.pos);
        try s.generic(output, input, end_op);
        return s.out_content - s.out_flushed; // remaining to flush
    }

    /// `ZSTD_CCtx_init_compressStream2`: parameters from the pledged size
    /// (the whole input when the first call ends the frame), then
    /// `ZSTD_compressBegin_internal` with buffers of one window plus one
    /// block in and one compressed block out.
    fn begin(s: *Stream, end_op: EndDirective, in_size: usize) Error!void {
        const pledged: ?u64 = if (end_op == .end) in_size else s.opts.pledged_size;
        const cp = params.getOverridden(s.opts.level, pledged orelse params.unknown_size, null, false, s.window_log);
        std.debug.assert(@intFromEnum(cp.strategy) <= @intFromEnum(params.Strategy.btlazy2));
        var comp = try frame.Compressor.init(s.gpa, cp, pledged, .{
            .level = s.opts.level,
            .checksum = s.opts.checksum,
            .overflow_correct_frequently = s.overflow_correct_frequently,
        });
        errdefer comp.deinit();
        const window_size: usize = @intCast(@max(1, @min(@as(u64, 1) << @intCast(cp.window_log), pledged orelse std.math.maxInt(u64))));
        const block_size = comp.block_size_max;
        const in_buff = try s.gpa.alloc(u8, window_size + block_size);
        errdefer s.gpa.free(in_buff);
        // libzstd's workspace comes from the allocator unwritten; a stream
        // can read a few bytes past the end of the old window segment (see
        // SPEC.md), which a fresh large allocation holds as zeros.
        @memset(in_buff, 0);
        const out_buff = try s.gpa.alloc(u8, frame.compressBound(block_size) + 1);
        s.comp = comp;
        s.comp.c.ms.buffer = in_buff;
        s.in_buff = in_buff;
        s.out_buff = out_buff;
        s.in_to_compress = 0;
        s.in_buff_pos = 0;
        // for small input: avoid automatic flush on reaching end of block,
        // since it would require to add a 3-bytes null block to end frame
        s.in_buff_target = block_size + @intFromBool(pledged != null and block_size == pledged.?);
        s.out_content = 0;
        s.out_flushed = 0;
        s.stage = .load;
        s.frame_ended = false;
    }

    /// `ZSTD_compressEnd_public`: the last chunk, the epilogue, and the
    /// pledged-size check.
    fn compressEnd(s: *Stream, dst: []u8, chunk: []const u8) Error!usize {
        const n = try s.comp.compressContinue(dst, chunk, true);
        const m = s.comp.writeEpilogue(dst[n..]);
        if (s.comp.pledged) |p| if (p != s.comp.consumed) return error.SrcSizeWrong;
        return n + m;
    }

    /// `ZSTD_compressStream_generic`.
    fn generic(s: *Stream, output: *OutBuffer, input: *InBuffer, end_op: EndDirective) Error!void {
        const iend = input.src.len;
        var ip = input.pos;
        const oend = output.dst.len;
        var op = output.pos;
        defer {
            input.pos = ip;
            output.pos = op;
        }

        while (true) switch (s.stage) {
            .init, .done => unreachable,
            .load => {
                if (end_op == .end and oend - op >= frame.compressBound(iend - ip) and s.in_buff_pos == 0) {
                    // shortcut to compression pass directly into output buffer
                    const c_size = try s.compressEnd(output.dst[op..], input.src[ip..iend]);
                    ip = iend;
                    op += c_size;
                    s.frame_ended = true;
                    s.stage = .done;
                    return;
                }
                // complete loading into inBuffer
                const to_load = s.in_buff_target - s.in_buff_pos;
                const loaded = @min(to_load, iend - ip);
                @memcpy(s.in_buff[s.in_buff_pos..][0..loaded], input.src[ip..][0..loaded]);
                s.in_buff_pos += loaded;
                ip += loaded;
                // not enough input to fill full block: stop here
                if (end_op == .@"continue" and s.in_buff_pos < s.in_buff_target) return;
                // empty
                if (end_op == .flush and s.in_buff_pos == s.in_to_compress) return;

                // compress current block (this stage cannot be stopped in
                // the middle)
                const i_size = s.in_buff_pos - s.in_to_compress;
                const direct = oend - op >= frame.compressBound(i_size);
                const c_dst = if (direct) output.dst[op..] else s.out_buff;
                const chunk = s.in_buff[s.in_to_compress..s.in_buff_pos];
                const last_block = end_op == .end and ip == iend;
                const c_size = if (last_block)
                    try s.compressEnd(c_dst, chunk)
                else
                    try s.comp.compressContinue(c_dst, chunk, false);
                s.frame_ended = last_block;
                // prepare next block
                s.in_buff_target = s.in_buff_pos + s.comp.block_size_max;
                if (s.in_buff_target > s.in_buff.len) {
                    s.in_buff_pos = 0;
                    s.in_buff_target = s.comp.block_size_max;
                }
                s.in_to_compress = s.in_buff_pos;
                if (direct) { // no need to flush
                    op += c_size;
                    if (s.frame_ended) {
                        s.stage = .done;
                        return;
                    }
                    continue;
                }
                s.out_content = c_size;
                s.out_flushed = 0;
                s.stage = .flush; // pass-through to flush stage
            },
            .flush => {
                const to_flush = s.out_content - s.out_flushed;
                const flushed = @min(to_flush, oend - op);
                @memcpy(output.dst[op..][0..flushed], s.out_buff[s.out_flushed..][0..flushed]);
                op += flushed;
                s.out_flushed += flushed;
                // flush not fully completed, presumably because dst is too small
                if (to_flush != flushed) return;
                s.out_content = 0;
                s.out_flushed = 0;
                if (s.frame_ended) {
                    s.stage = .done;
                    return;
                }
                s.stage = .load;
            },
        };
    }
};
