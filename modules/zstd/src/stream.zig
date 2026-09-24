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
    /// `ZSTD_c_srcSizeHint`, 1..2^31-1: when the size is unknown, choose
    /// and shrink the parameters as for an input of about this many bytes
    /// (the header still records no size).
    src_size_hint: ?u32 = null,
    advanced: params.Advanced = .{},
};

/// The highest level a stream accepts: every level, as one-shot.
pub const max_level = params.max_level;

pub const Error = error{
    /// Level above `max_level`.
    LevelUnsupported,
    /// An advanced parameter or `src_size_hint` outside libzstd's bounds.
    ParameterOutOfBound,
    OutOfMemory,
    /// More input than pledged, or, at the end, less (`srcSize_wrong`).
    SrcSizeWrong,
    /// `pos` beyond the end of a buffer.
    InvalidBuffer,
};

/// A compression context in streaming mode (`ZSTD_CCtx` driven by
/// `ZSTD_compressStream2`). Once a frame has ended, the next call starts
/// another on the same context, with the same options but an unknown size
/// (as libzstd); `reset` changes the options or abandons a frame. The
/// context's workspace is reused from frame to frame (see
/// `frame.Compressor`); the bytes are those of a fresh context.
pub const Stream = struct {
    opts: Options,
    /// This frame's pledged size: `opts.pledged_size` for the first frame
    /// after `init` or `reset`, unknown for the frames after it.
    pledged: ?u64,
    stage: enum { init, load, flush } = .init,
    comp: frame.Compressor,
    in_buff_pos: usize = 0,
    in_buff_target: usize = 0,
    in_to_compress: usize = 0,
    out_content: usize = 0,
    out_flushed: usize = 0,
    frame_ended: bool = false,
    /// Test seam, set before the first call: index overflow corrected as
    /// libzstd's fuzzing build does it (`frame.Options.
    /// overflow_correct_frequently`), which reaches the correction of a
    /// two-segment window within kilobytes.
    overflow_correct_frequently: bool = false,

    /// Nothing is allocated until the first `compressStream2`, which knows
    /// whether that call ends the frame (and so the size).
    pub fn init(gpa: std.mem.Allocator, opts: Options) Error!Stream {
        try checkOptions(opts);
        return .{ .opts = opts, .pledged = opts.pledged_size, .comp = .initEmpty(gpa) };
    }

    /// A stream in the caller's workspace (`ZSTD_initStaticCCtx`), which is
    /// never resized: a frame needing more than `workspace.len` bytes
    /// (`estimateStreamSize`) fails with `error.OutOfMemory`.
    pub fn initStatic(workspace: frame.Workspace, opts: Options) Error!Stream {
        try checkOptions(opts);
        return .{ .opts = opts, .pledged = opts.pledged_size, .comp = .initStatic(workspace) };
    }

    fn checkOptions(opts: Options) Error!void {
        if (opts.level > max_level) return error.LevelUnsupported;
        try opts.advanced.check();
        if (opts.src_size_hint) |h| if (h == 0 or h > std.math.maxInt(i32)) return error.ParameterOutOfBound;
    }

    pub fn deinit(s: *Stream) void {
        s.comp.deinit();
        s.* = undefined;
    }

    /// `ZSTD_CCtx_reset(ZSTD_reset_session_and_parameters)` with `opts` set
    /// anew: the current frame, if any, is abandoned (its output so far is
    /// not a complete frame), and the next call starts one with `opts`,
    /// `opts.pledged_size` included. The workspace stays.
    pub fn reset(s: *Stream, opts: Options) Error!void {
        try checkOptions(opts);
        s.opts = opts;
        s.pledged = opts.pledged_size;
        s.stage = .init;
    }

    /// The bytes the stream's workspace holds (`ZSTD_sizeof_CCtx` less the
    /// context itself).
    pub fn workspaceSize(s: *const Stream) usize {
        return s.comp.ws.len;
    }

    /// `ZSTD_compressStream2`. Consumes input and writes output as far as
    /// the buffers allow; returns how many compressed bytes are still held
    /// back for lack of output room (for `flush` and `end`, call again
    /// until it is 0 — for `end`, the frame is then complete).
    pub fn compressStream2(s: *Stream, output: *OutBuffer, input: *InBuffer, end_op: EndDirective) Error!usize {
        if (output.pos > output.dst.len or input.pos > input.src.len) return error.InvalidBuffer;
        if (s.stage == .init) try s.begin(end_op, input.src.len - input.pos);
        try s.generic(output, input, end_op);
        return s.out_content - s.out_flushed; // remaining to flush
    }

    /// `ZSTD_CCtx_init_compressStream2`: parameters from the pledged size
    /// (the whole input when the first call ends the frame), then
    /// `ZSTD_compressBegin_internal` with buffers of one window plus one
    /// block in and one compressed block out.
    fn begin(s: *Stream, end_op: EndDirective, in_size: usize) Error!void {
        const pledged: ?u64 = if (end_op == .end) in_size else s.pledged;
        const cp = frameParams(s.opts, pledged);
        try s.comp.begin(cp, pledged, s.frameOptions(), true);
        const block_size = s.comp.block_size_max;
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

    fn frameOptions(s: *const Stream) frame.Options {
        return .{
            .level = s.opts.level,
            .checksum = s.opts.checksum,
            .advanced = s.opts.advanced,
            .overflow_correct_frequently = s.overflow_correct_frequently,
        };
    }

    /// `ZSTD_CCtx_reset(ZSTD_reset_session_only)` at the end of a frame:
    /// the next call starts another, of unknown size.
    fn endFrame(s: *Stream) void {
        s.stage = .init;
        s.pledged = null;
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
        const in_buff = s.comp.in_buff;
        const out_buff = s.comp.out_buff;
        const iend = input.src.len;
        var ip = input.pos;
        const oend = output.dst.len;
        var op = output.pos;
        defer {
            input.pos = ip;
            output.pos = op;
        }

        while (true) switch (s.stage) {
            .init => unreachable,
            .load => {
                if (end_op == .end and oend - op >= frame.compressBound(iend - ip) and s.in_buff_pos == 0) {
                    // shortcut to compression pass directly into output buffer
                    const c_size = try s.compressEnd(output.dst[op..], input.src[ip..iend]);
                    ip = iend;
                    op += c_size;
                    s.frame_ended = true;
                    s.endFrame();
                    return;
                }
                // complete loading into inBuffer
                const to_load = s.in_buff_target - s.in_buff_pos;
                const loaded = @min(to_load, iend - ip);
                @memcpy(in_buff[s.in_buff_pos..][0..loaded], input.src[ip..][0..loaded]);
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
                const c_dst = if (direct) output.dst[op..] else out_buff;
                const chunk = in_buff[s.in_to_compress..s.in_buff_pos];
                const last_block = end_op == .end and ip == iend;
                const c_size = if (last_block)
                    try s.compressEnd(c_dst, chunk)
                else
                    try s.comp.compressContinue(c_dst, chunk, false);
                s.frame_ended = last_block;
                // prepare next block
                s.in_buff_target = s.in_buff_pos + s.comp.block_size_max;
                if (s.in_buff_target > in_buff.len) {
                    s.in_buff_pos = 0;
                    s.in_buff_target = s.comp.block_size_max;
                }
                s.in_to_compress = s.in_buff_pos;
                if (direct) { // no need to flush
                    op += c_size;
                    if (s.frame_ended) {
                        s.endFrame();
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
                @memcpy(output.dst[op..][0..flushed], out_buff[s.out_flushed..][0..flushed]);
                op += flushed;
                s.out_flushed += flushed;
                // flush not fully completed, presumably because dst is too small
                if (to_flush != flushed) return;
                s.out_content = 0;
                s.out_flushed = 0;
                if (s.frame_ended) {
                    s.endFrame();
                    return;
                }
                s.stage = .load;
            },
        };
    }
};

/// The parameters of a stream's frame: sized for its pledged size, else
/// for the size hint (`ZSTD_getCParamsFromCCtxParams`), else unknown.
fn frameParams(opts: Options, pledged: ?u64) params.CParams {
    const size_hint: u64 = pledged orelse if (opts.src_size_hint) |h| h else params.unknown_size;
    return params.getOverridden(opts.level, size_hint, opts.advanced);
}

/// The workspace a stream with `opts` needs for its first frame when
/// `opts.pledged_size` or `opts.src_size_hint` is set; with neither, the
/// most any of its frames can need, whatever the input and however it
/// arrives.
pub fn estimateSize(opts: Options) Error!usize {
    try Stream.checkOptions(opts);
    const fo: frame.Options = .{ .level = opts.level, .checksum = opts.checksum, .advanced = opts.advanced };
    if (opts.pledged_size != null or opts.src_size_hint != null)
        return frame.workspaceSize(frameParams(opts, opts.pledged_size), opts.pledged_size, fo, true);
    // Unknown, or known at the first call (which ends the frame): the need
    // grows with the size within each of the level's size classes, and a
    // size past the last class needs what an unknown one does.
    var most = frame.workspaceSize(frameParams(opts, null), null, fo, true);
    for (params.size_class_bounds) |size|
        most = @max(most, frame.workspaceSize(frameParams(opts, size), size, fo, true));
    return most;
}
