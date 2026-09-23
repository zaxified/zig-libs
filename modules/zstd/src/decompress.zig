// SPDX-License-Identifier: BSD-3-Clause AND MIT (port of libzstd 1.5.7 -- see ../NOTICE)
//! Frame decoder and frame utilities: frame header, block loop, content
//! checksum, concatenated and skippable frames, and the size queries
//! (`ZSTD_getFrameContentSize`, `ZSTD_findFrameCompressedSize`,
//! `ZSTD_decompressBound`, ...).
//!
//! Port of lib/decompress/zstd_decompress.c (v1.5.7): the one-shot decoder
//! and `ZSTD_decompressContinue`, the piecewise one the stream is built on.
//! As in libzstd, the one-shot decoder does not hold a block to the frame's
//! `Block_Maximum_Size` (malformed frames only): raw and RLE blocks are not
//! bounded at all, and a compressed block only by where libzstd would have
//! put its literals (see `dblock.decompressBlock`); the piecewise decoder
//! refuses any block over the maximum.

const std = @import("std");
const dbits = @import("dbits.zig");
const dblock = @import("dblock.zig");
const readLE16 = dbits.readLE16;
const readLE32 = dbits.readLE32;
const readLE64 = dbits.readLE64;
pub const Format = @import("params.zig").Format;

pub const Error = dblock.Error || error{
    ChecksumWrong,
    PrefixUnknown,
    FrameParameterUnsupported,
    FrameParameterWindowTooLarge,
    DictionaryWrong,
};

pub const magic_number: u32 = 0xFD2FB528;
pub const magic_skippable_start: u32 = 0x184D2A50;
pub const magic_skippable_mask: u32 = 0xFFFFFFF0;
pub const skippable_header_size = 8;
pub const frame_header_size_prefix = 5;
pub const frame_header_size_min = 6;
pub const frame_header_size_max = 18;
pub const block_header_size = 3;
pub const window_log_absolute_min = 10;
pub const window_log_max = 31;
pub const block_size_max = dblock.block_size_max;

const did_field_size = [4]usize{ 0, 1, 2, 4 };
const fcs_field_size = [4]usize{ 0, 2, 4, 8 };

pub const FrameType = enum { frame, skippable };

/// `ZSTD_FrameHeader`.
pub const FrameHeader = struct {
    /// Decompressed size, null when the header does not say. For a
    /// skippable frame: the size of its user data.
    content_size: ?u64,
    /// 0 for a skippable frame.
    window_size: u64,
    block_size_max: u32,
    frame_type: FrameType,
    header_size: u32,
    /// The dictionary ID the frame asks for (0 = none); for a skippable
    /// frame, the magic variant 0..15.
    dict_id: u32,
    checksum: bool,
};

/// Result of `getFrameHeader`: the header, or how many bytes of input it
/// needs before it can be read.
pub const HeaderResult = union(enum) {
    header: FrameHeader,
    need: usize,
};

fn isSkippableMagic(m: u32) bool {
    return m & magic_skippable_mask == magic_skippable_start;
}

/// `ZSTD_isFrame`: `buf` starts with a zstd or skippable frame magic.
pub fn isFrame(buf: []const u8) bool {
    if (buf.len < 4) return false;
    const m = readLE32(buf, 0);
    return m == magic_number or isSkippableMagic(m);
}

/// `ZSTD_isSkippableFrame`.
pub fn isSkippableFrame(buf: []const u8) bool {
    if (buf.len < 4) return false;
    return isSkippableMagic(readLE32(buf, 0));
}

/// `ZSTD_startingInputLength` / `ZSTD_FRAMEHEADERSIZE_PREFIX`: the bytes
/// up to and including the frame header descriptor.
pub fn headerPrefixSize(format: Format) usize {
    return if (format == .zstd1) frame_header_size_prefix else frame_header_size_prefix - 4;
}

/// `ZSTD_FRAMEHEADERSIZE_MIN`.
pub fn headerSizeMin(format: Format) usize {
    return if (format == .zstd1) frame_header_size_min else frame_header_size_min - 4;
}

/// `ZSTD_frameHeaderSize`: the full header size, from its first 5 bytes.
pub fn frameHeaderSize(src: []const u8) Error!usize {
    return frameHeaderSizeFormat(src, .zstd1);
}

/// `ZSTD_frameHeaderSize_internal`.
fn frameHeaderSizeFormat(src: []const u8, format: Format) Error!usize {
    const min_input_size = headerPrefixSize(format);
    if (src.len < min_input_size) return error.SrcSizeWrong;
    const fhd = src[min_input_size - 1];
    const dict_id = fhd & 3;
    const single_segment = (fhd >> 5) & 1;
    const fcs_id = fhd >> 6;
    return min_input_size + @as(usize, 1 - single_segment) + did_field_size[dict_id] + fcs_field_size[fcs_id] +
        @intFromBool(single_segment != 0 and fcs_id == 0);
}

/// `ZSTD_getFrameHeader`.
pub fn getFrameHeader(src: []const u8) Error!HeaderResult {
    return getFrameHeaderAdvanced(src, .zstd1);
}

/// `ZSTD_getFrameHeader_advanced`: a magicless frame header has neither
/// the magic number nor a skippable alternative.
pub fn getFrameHeaderAdvanced(src: []const u8, format: Format) Error!HeaderResult {
    const min_input_size = headerPrefixSize(format);
    if (src.len < min_input_size) {
        if (src.len > 0 and format != .magicless) {
            // what is there must at least start like a frame
            var hbuf: [4]u8 = undefined;
            std.mem.writeInt(u32, &hbuf, magic_number, .little);
            const n = @min(4, src.len);
            @memcpy(hbuf[0..n], src[0..n]);
            if (readLE32(&hbuf, 0) != magic_number) {
                std.mem.writeInt(u32, &hbuf, magic_skippable_start, .little);
                @memcpy(hbuf[0..n], src[0..n]);
                if (!isSkippableMagic(readLE32(&hbuf, 0))) return error.PrefixUnknown;
            }
        }
        return .{ .need = min_input_size };
    }
    const magic = if (format == .magicless) magic_number else readLE32(src, 0);
    if (magic != magic_number) {
        if (isSkippableMagic(magic)) {
            if (src.len < skippable_header_size) return .{ .need = skippable_header_size };
            return .{ .header = .{
                .content_size = readLE32(src, 4),
                .window_size = 0,
                .block_size_max = 0,
                .frame_type = .skippable,
                .header_size = skippable_header_size,
                .dict_id = magic - magic_skippable_start,
                .checksum = false,
            } };
        }
        return error.PrefixUnknown;
    }

    const fhsize = try frameHeaderSizeFormat(src, format);
    if (src.len < fhsize) return .{ .need = fhsize };

    const fhd = src[min_input_size - 1];
    var pos: usize = min_input_size;
    const dict_id_size_code = fhd & 3;
    const checksum_flag = (fhd >> 2) & 1 != 0;
    const single_segment = (fhd >> 5) & 1 != 0;
    const fcs_id = fhd >> 6;
    var window_size: u64 = 0;
    var dict_id: u32 = 0;
    var fcs: ?u64 = null;
    if (fhd & 0x08 != 0) return error.FrameParameterUnsupported; // reserved bit
    if (!single_segment) {
        const wl_byte = src[pos];
        pos += 1;
        const window_log: u32 = (wl_byte >> 3) + window_log_absolute_min;
        if (window_log > window_log_max) return error.FrameParameterWindowTooLarge;
        window_size = @as(u64, 1) << @intCast(window_log);
        window_size += (window_size >> 3) * (wl_byte & 7);
    }
    switch (dict_id_size_code) {
        0 => {},
        1 => {
            dict_id = src[pos];
            pos += 1;
        },
        2 => {
            dict_id = readLE16(src, pos);
            pos += 2;
        },
        else => {
            dict_id = readLE32(src, pos);
            pos += 4;
        },
    }
    switch (fcs_id) {
        0 => if (single_segment) {
            fcs = src[pos];
        },
        1 => fcs = @as(u64, readLE16(src, pos)) + 256,
        2 => fcs = readLE32(src, pos),
        else => fcs = readLE64(src, pos),
    }
    if (single_segment) window_size = fcs.?;
    return .{ .header = .{
        .content_size = fcs,
        .window_size = window_size,
        .block_size_max = @intCast(@min(window_size, block_size_max)),
        .frame_type = .frame,
        .header_size = @intCast(fhsize),
        .dict_id = dict_id,
        .checksum = checksum_flag,
    } };
}

/// `ZSTD_getFrameContentSize` for the frame at the start of `src`:
/// its decompressed size, or null when the header does not record it.
/// A skippable frame has size 0. `error.SrcSizeWrong` when `src` is too
/// short to hold the header.
pub fn getFrameContentSize(src: []const u8) Error!?u64 {
    switch (try getFrameHeader(src)) {
        .need => return error.SrcSizeWrong,
        .header => |h| return if (h.frame_type == .skippable) 0 else h.content_size,
    }
}

/// `ZSTD_getDictID_fromFrame`: 0 when the frame names no dictionary or
/// the header cannot be read.
pub fn getDictIdFromFrame(src: []const u8) u32 {
    const r = getFrameHeader(src) catch return 0;
    return switch (r) {
        .need => 0,
        .header => |h| h.dict_id,
    };
}

fn readSkippableFrameSize(src: []const u8) Error!usize {
    if (src.len < skippable_header_size) return error.SrcSizeWrong;
    const size = readLE32(src, 4);
    if (size +% skippable_header_size < size) return error.FrameParameterUnsupported;
    const skippable_size = skippable_header_size + @as(usize, size);
    if (skippable_size > src.len) return error.SrcSizeWrong;
    return skippable_size;
}

pub const SkippableFrame = struct {
    /// Bytes of user data copied into `dst`.
    len: usize,
    /// Which of the 16 skippable magics the frame used (0..15).
    magic_variant: u32,
};

/// `ZSTD_readSkippableFrame`: copies a skippable frame's user data into
/// `dst`.
pub fn readSkippableFrame(dst: []u8, src: []const u8) Error!SkippableFrame {
    if (src.len < skippable_header_size) return error.SrcSizeWrong;
    const magic = readLE32(src, 0);
    const frame_size = try readSkippableFrameSize(src);
    const content_size = frame_size - skippable_header_size;
    if (!isSkippableMagic(magic)) return error.FrameParameterUnsupported;
    if (content_size > dst.len) return error.DstSizeTooSmall;
    @memcpy(dst[0..content_size], src[skippable_header_size..][0..content_size]);
    return .{ .len = content_size, .magic_variant = magic - magic_skippable_start };
}

const BlockProperties = struct { last: bool, block_type: u2, orig_size: u32 };

/// `ZSTD_getcBlockSize`: the block's size in the input (1 for RLE).
fn getcBlockSize(src: []const u8, bp: *BlockProperties) Error!usize {
    if (src.len < block_header_size) return error.SrcSizeWrong;
    const h = dbits.readLE24(src, 0);
    const c_size = h >> 3;
    bp.last = h & 1 != 0;
    bp.block_type = @intCast((h >> 1) & 3);
    bp.orig_size = c_size;
    if (bp.block_type == 1) return 1; // RLE
    if (bp.block_type == 3) return error.CorruptionDetected; // reserved
    return c_size;
}

const FrameSizeInfo = struct {
    nb_blocks: usize,
    compressed_size: usize,
    /// null for a skippable frame (it decodes to nothing).
    decompressed_bound: u64,
};

/// `ZSTD_findFrameSizeInfo`.
fn findFrameSizeInfo(src: []const u8, format: Format) Error!FrameSizeInfo {
    if (format == .zstd1 and src.len >= skippable_header_size and isSkippableMagic(readLE32(src, 0))) {
        return .{ .nb_blocks = 0, .compressed_size = try readSkippableFrameSize(src), .decompressed_bound = 0 };
    }
    const zfh = switch (try getFrameHeaderAdvanced(src, format)) {
        .need => return error.SrcSizeWrong,
        .header => |h| h,
    };
    var ip: usize = zfh.header_size;
    var nb_blocks: usize = 0;
    while (true) {
        var bp: BlockProperties = undefined;
        const c_block_size = try getcBlockSize(src[ip..], &bp);
        if (block_header_size + c_block_size > src.len - ip) return error.SrcSizeWrong;
        ip += block_header_size + c_block_size;
        nb_blocks += 1;
        if (bp.last) break;
    }
    if (zfh.checksum) {
        if (src.len - ip < 4) return error.SrcSizeWrong;
        ip += 4;
    }
    return .{
        .nb_blocks = nb_blocks,
        .compressed_size = ip,
        .decompressed_bound = zfh.content_size orelse @as(u64, nb_blocks) * zfh.block_size_max,
    };
}

/// `ZSTD_findFrameCompressedSize`: how many bytes of `src` the first
/// (zstd or skippable) frame occupies.
pub fn findFrameCompressedSize(src: []const u8) Error!usize {
    return findFrameCompressedSizeAdvanced(src, .zstd1);
}

/// `ZSTD_findFrameCompressedSize_advanced`.
pub fn findFrameCompressedSizeAdvanced(src: []const u8, format: Format) Error!usize {
    return (try findFrameSizeInfo(src, format)).compressed_size;
}

/// `ZSTD_decompressBound`: an upper bound of the decompressed size of all
/// frames in `src` — exact where the headers record content sizes.
pub fn decompressBound(src_in: []const u8) Error!u64 {
    var src = src_in;
    var bound: u64 = 0;
    while (src.len > 0) {
        const info = try findFrameSizeInfo(src, .zstd1);
        src = src[info.compressed_size..];
        bound += info.decompressed_bound;
    }
    return bound;
}

/// `ZSTD_findDecompressedSize`: the total decompressed size of all
/// frames, or null when a frame does not record its size.
pub fn findDecompressedSize(src_in: []const u8) Error!?u64 {
    var src = src_in;
    var total: u64 = 0;
    while (src.len >= frame_header_size_prefix) {
        if (isSkippableMagic(readLE32(src, 0))) {
            src = src[try readSkippableFrameSize(src)..];
            continue;
        }
        const fcs = (try getFrameContentSize(src)) orelse return null;
        total = std.math.add(u64, total, fcs) catch return error.CorruptionDetected;
        src = src[try findFrameCompressedSize(src)..];
    }
    if (src.len != 0) return error.SrcSizeWrong;
    return total;
}

/// `ZSTD_decompressionMargin`: how far the end of the compressed data must
/// lie behind the end of the output for in-place decompression.
pub fn decompressionMargin(src_in: []const u8) Error!usize {
    var src = src_in;
    var margin: usize = 0;
    var max_block_size: usize = 0;
    while (src.len > 0) {
        const info = try findFrameSizeInfo(src, .zstd1);
        const zfh = switch (try getFrameHeader(src)) {
            .need => return error.SrcSizeWrong,
            .header => |h| h,
        };
        if (zfh.frame_type == .frame) {
            margin += zfh.header_size;
            margin += if (zfh.checksum) 4 else 0;
            margin += 3 * info.nb_blocks;
            max_block_size = @max(max_block_size, zfh.block_size_max);
        } else {
            margin += info.compressed_size;
        }
        src = src[info.compressed_size..];
    }
    return margin + max_block_size;
}

pub const Options = struct {
    /// Do not verify content checksums (`ZSTD_d_forceIgnoreChecksum`).
    ignore_checksum: bool = false,
    /// `ZSTD_d_format`: `.magicless` reads only frames written without the
    /// magic number (and no skippable frames).
    format: Format = .zstd1,
};

/// `ZSTD_dStage`: where `decompressContinue` is within a frame.
pub const Stage = enum {
    get_frame_header_size,
    decode_frame_header,
    decode_block_header,
    decompress_block,
    decompress_last_block,
    check_checksum,
    decode_skippable_header,
    skip_frame,
};

/// A decoding context (`ZSTD_DCtx`). Its tables and literal buffer (about
/// 190 KB) live on the heap, so the handle itself can be moved freely.
pub const Decompressor = struct {
    gpa: std.mem.Allocator,
    st: *dblock.State,
    options: Options,
    /// The frame header of the frame being decoded.
    fparams: FrameHeader = undefined,
    /// Dictionary ID the context holds (0 = none).
    dict_id: u32 = 0,

    // The history, as libzstd keeps it: addresses of the start of the
    // contiguous output so far (`prefixStart`) and of its end
    // (`previousDstEnd`), and the older segment still in reach
    // (`virtualStart`..`dictEnd`). Output written somewhere else than right
    // after `prev_end` starts a new prefix and demotes the old one to `ext`.
    prefix_addr: usize = 0,
    prev_end_addr: usize = 0,
    ext: []const u8 = &.{},

    // `ZSTD_decompressContinue`'s state.
    stage: Stage = .get_frame_header_size,
    expected: usize = frame_header_size_prefix,
    block_type: u2 = 3,
    rle_size: usize = 0,
    decoded_size: u64 = 0,
    header_size: usize = 0,
    header_buffer: [frame_header_size_max]u8 = undefined,
    xxh: std.hash.XxHash64 = .init(0),
    validate: bool = false,

    pub fn init(gpa: std.mem.Allocator, options: Options) error{OutOfMemory}!Decompressor {
        const st = try gpa.create(dblock.State);
        st.* = .{};
        // the slack behind the literals is read (and overwritten) by wildcopy
        @memset(st.lit_buf[block_size_max..], 0);
        return .{ .gpa = gpa, .st = st, .options = options, .expected = headerPrefixSize(options.format) };
    }

    pub fn deinit(d: *Decompressor) void {
        d.gpa.destroy(d.st);
        d.* = undefined;
    }

    /// `ZSTD_decompressBegin`.
    pub fn begin(d: *Decompressor) void {
        d.st.begin();
        d.dict_id = 0;
        d.expected = headerPrefixSize(d.options.format);
        d.stage = .get_frame_header_size;
        d.decoded_size = 0;
        d.prefix_addr = 0;
        d.prev_end_addr = 0;
        d.ext = &.{};
        d.block_type = 3;
    }

    /// `ZSTD_checkContinuity`.
    fn checkContinuity(d: *Decompressor, dst: []u8) void {
        const a = @intFromPtr(dst.ptr);
        if (a != d.prev_end_addr and dst.len > 0) {
            const n = d.prev_end_addr - d.prefix_addr;
            d.ext = if (n == 0) &.{} else @as([*]const u8, @ptrFromInt(d.prefix_addr))[0..n];
            d.prefix_addr = a;
            d.prev_end_addr = a;
        }
    }

    /// The block decoder's view of the history for output at `dst`: the
    /// prefix runs from `prefix_addr` (same buffer) up to `dst`. Returns the
    /// history and `dst`'s index in it.
    fn history(d: *const Decompressor, dst: []u8) struct { h: dblock.History, op: usize } {
        if (dst.len == 0 or d.prefix_addr == 0) return .{ .h = .{ .out = dst, .prefix = 0, .ext = d.ext }, .op = 0 };
        const back = @intFromPtr(dst.ptr) - d.prefix_addr;
        const base: [*]u8 = @ptrFromInt(d.prefix_addr);
        return .{ .h = .{ .out = base[0 .. back + dst.len], .prefix = 0, .ext = d.ext }, .op = back };
    }

    /// `ZSTD_decodeFrameHeader`.
    pub fn decodeFrameHeader(d: *Decompressor, header: []const u8) Error!void {
        d.fparams = switch (try getFrameHeaderAdvanced(header, d.options.format)) {
            .need => return error.SrcSizeWrong,
            .header => |h| h,
        };
        if (d.fparams.dict_id != 0 and d.dict_id != d.fparams.dict_id) return error.DictionaryWrong;
        d.validate = d.fparams.checksum and !d.options.ignore_checksum;
        if (d.validate) d.xxh = .init(0);
        d.st.block_size_max = d.fparams.block_size_max;
    }

    /// `ZSTD_decompressFrame`: decodes the frame at `src[ip.*..]` into
    /// `dst[op0..]`, advancing `ip`. Returns the decoded size.
    fn decompressFrame(d: *Decompressor, dst: []u8, op0: usize, src: []const u8, ip: *usize) Error!usize {
        const st = d.st;
        const format = d.options.format;
        var remaining = src.len - ip.*;
        if (remaining < headerSizeMin(format) + block_header_size) return error.SrcSizeWrong;

        {
            const fhs = try frameHeaderSizeFormat(src[ip.*..][0..headerPrefixSize(format)], format);
            if (remaining < fhs + block_header_size) return error.SrcSizeWrong;
            try d.decodeFrameHeader(src[ip.*..][0..fhs]);
            ip.* += fhs;
            remaining -= fhs;
        }

        var op = op0;
        while (true) {
            var bp: BlockProperties = undefined;
            const c_block_size = try getcBlockSize(src[ip.*..][0..remaining], &bp);
            ip.* += block_header_size;
            remaining -= block_header_size;
            if (c_block_size > remaining) return error.SrcSizeWrong;
            const block = src[ip.*..][0..c_block_size];
            const cap = dst.len - op;
            const decoded: usize = switch (bp.block_type) {
                2 => blk: {
                    const v = d.history(dst[op..]);
                    break :blk try dblock.decompressBlock(st, &v.h, v.op, cap, block, false);
                },
                0 => blk: {
                    if (c_block_size > cap) return error.DstSizeTooSmall;
                    @memcpy(dst[op..][0..c_block_size], block);
                    break :blk c_block_size;
                },
                1 => blk: {
                    if (bp.orig_size > cap) return error.DstSizeTooSmall;
                    @memset(dst[op..][0..bp.orig_size], block[0]);
                    break :blk bp.orig_size;
                },
                else => return error.CorruptionDetected,
            };
            if (d.validate) d.xxh.update(dst[op..][0..decoded]);
            op += decoded;
            ip.* += c_block_size;
            remaining -= c_block_size;
            if (bp.last) break;
        }

        if (d.fparams.content_size) |fcs| {
            if (op - op0 != fcs) return error.CorruptionDetected;
        }
        if (d.fparams.checksum) {
            if (remaining < 4) return error.ChecksumWrong;
            if (!d.options.ignore_checksum) {
                const calc: u32 = @truncate(d.xxh.final());
                if (readLE32(src, ip.*) != calc) return error.ChecksumWrong;
            }
            ip.* += 4;
        }
        return op - op0;
    }

    /// `ZSTD_decompressDCtx`: decodes every frame in `src` (concatenated
    /// frames and skippable frames allowed) into `dst`. Returns the number
    /// of bytes written. `dst` and `src` must not overlap.
    pub fn decompress(d: *Decompressor, dst: []u8, src: []const u8) Error!usize {
        var ip: usize = 0;
        var op: usize = 0;
        var more_than_1_frame = false;
        while (src.len - ip >= headerPrefixSize(d.options.format)) {
            if (d.options.format == .zstd1 and isSkippableMagic(readLE32(src, ip))) {
                ip += try readSkippableFrameSize(src[ip..]);
                continue;
            }
            d.begin();
            d.checkContinuity(dst[op..]);
            const res = d.decompressFrame(dst, op, src, &ip) catch |e| {
                // garbage after complete frames is more likely a size error
                if (e == error.PrefixUnknown and more_than_1_frame) return error.SrcSizeWrong;
                return e;
            };
            op += res;
            more_than_1_frame = true;
        }
        if (ip != src.len) return error.SrcSizeWrong;
        return op;
    }

    /// `ZSTD_nextSrcSizeToDecompress`: how many input bytes the next
    /// `decompressContinue` call takes (0: the frame is done).
    pub fn nextSrcSizeToDecompress(d: *const Decompressor) usize {
        return d.expected;
    }

    /// `ZSTD_nextSrcSizeToDecompressWithInputSize`: a raw block may be fed
    /// in pieces.
    pub fn nextSrcSizeWithInputSize(d: *const Decompressor, input_size: usize) usize {
        if (!(d.stage == .decompress_block or d.stage == .decompress_last_block)) return d.expected;
        if (d.block_type != 0) return d.expected;
        return @max(1, @min(input_size, d.expected));
    }

    /// `ZSTD_decompressContinue`: feeds exactly the next piece of a frame
    /// (`nextSrcSizeWithInputSize` bytes) and writes what it decodes to
    /// `dst`, which must directly follow the previous output to keep the
    /// history contiguous (else the previous output becomes the older
    /// segment). Returns the bytes written. Call `begin` before a frame.
    pub fn decompressContinue(d: *Decompressor, dst: []u8, src: []const u8) Error!usize {
        if (src.len != d.nextSrcSizeWithInputSize(src.len)) return error.SrcSizeWrong;
        d.checkContinuity(dst);
        switch (d.stage) {
            .get_frame_header_size => {
                if (d.options.format == .zstd1 and isSkippableMagic(readLE32(src, 0))) {
                    @memcpy(d.header_buffer[0..src.len], src);
                    d.expected = skippable_header_size - src.len;
                    d.stage = .decode_skippable_header;
                    return 0;
                }
                d.header_size = try frameHeaderSizeFormat(src, d.options.format);
                @memcpy(d.header_buffer[0..src.len], src);
                d.expected = d.header_size - src.len;
                d.stage = .decode_frame_header;
                return 0;
            },
            .decode_frame_header => {
                @memcpy(d.header_buffer[d.header_size - src.len ..][0..src.len], src);
                try d.decodeFrameHeader(d.header_buffer[0..d.header_size]);
                d.expected = block_header_size;
                d.stage = .decode_block_header;
                return 0;
            },
            .decode_block_header => {
                var bp: BlockProperties = undefined;
                const c_block_size = try getcBlockSize(src[0..block_header_size], &bp);
                if (c_block_size > d.fparams.block_size_max) return error.CorruptionDetected;
                d.expected = c_block_size;
                d.block_type = bp.block_type;
                d.rle_size = bp.orig_size;
                if (c_block_size != 0) {
                    d.stage = if (bp.last) .decompress_last_block else .decompress_block;
                    return 0;
                }
                // empty block
                if (bp.last) {
                    if (d.fparams.checksum) {
                        d.expected = 4;
                        d.stage = .check_checksum;
                    } else {
                        d.expected = 0;
                        d.stage = .get_frame_header_size;
                    }
                } else {
                    d.expected = block_header_size;
                    d.stage = .decode_block_header;
                }
                return 0;
            },
            .decompress_block, .decompress_last_block => {
                var r_size: usize = undefined;
                switch (d.block_type) {
                    2 => {
                        const v = d.history(dst);
                        r_size = try dblock.decompressBlock(d.st, &v.h, v.op, dst.len, src, true);
                        d.expected = 0;
                    },
                    0 => {
                        if (src.len > dst.len) return error.DstSizeTooSmall;
                        @memcpy(dst[0..src.len], src);
                        r_size = src.len;
                        d.expected -= r_size;
                    },
                    1 => {
                        if (d.rle_size > dst.len) return error.DstSizeTooSmall;
                        @memset(dst[0..d.rle_size], src[0]);
                        r_size = d.rle_size;
                        d.expected = 0;
                    },
                    else => return error.CorruptionDetected,
                }
                if (r_size > d.fparams.block_size_max) return error.CorruptionDetected;
                d.decoded_size += r_size;
                if (d.validate) d.xxh.update(dst[0..r_size]);
                d.prev_end_addr = @intFromPtr(dst.ptr) + r_size;
                if (d.expected > 0) return r_size; // more of this raw block to come

                if (d.stage == .decompress_last_block) {
                    if (d.fparams.content_size) |fcs| {
                        if (d.decoded_size != fcs) return error.CorruptionDetected;
                    }
                    if (d.fparams.checksum) {
                        d.expected = 4;
                        d.stage = .check_checksum;
                    } else {
                        d.expected = 0;
                        d.stage = .get_frame_header_size;
                    }
                } else {
                    d.stage = .decode_block_header;
                    d.expected = block_header_size;
                }
                return r_size;
            },
            .check_checksum => {
                if (d.validate) {
                    const h32: u32 = @truncate(d.xxh.final());
                    if (readLE32(src, 0) != h32) return error.ChecksumWrong;
                }
                d.expected = 0;
                d.stage = .get_frame_header_size;
                return 0;
            },
            .decode_skippable_header => {
                @memcpy(d.header_buffer[skippable_header_size - src.len ..][0..src.len], src);
                d.expected = readLE32(&d.header_buffer, 4);
                d.stage = .skip_frame;
                return 0;
            },
            .skip_frame => {
                d.expected = 0;
                d.stage = .get_frame_header_size;
                return 0;
            },
        }
    }
};

test "frame header of the empty frame" {
    const r = try getFrameHeader(&.{ 0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x00, 0x01, 0x00, 0x00 });
    const h = r.header;
    try std.testing.expectEqual(@as(?u64, 0), h.content_size);
    try std.testing.expectEqual(@as(u32, 6), h.header_size);
    try std.testing.expectEqual(FrameType.frame, h.frame_type);
}

test "short input: header needs more bytes, wrong magic is refused early" {
    try std.testing.expectEqual(HeaderResult{ .need = 5 }, try getFrameHeader(&.{ 0x28, 0xb5 }));
    try std.testing.expectError(error.PrefixUnknown, getFrameHeader(&.{ 0x28, 0xb6 }));
    try std.testing.expectEqual(HeaderResult{ .need = 5 }, try getFrameHeader(&.{0x5a}));
}
