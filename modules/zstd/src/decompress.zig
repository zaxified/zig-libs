// SPDX-License-Identifier: BSD-3-Clause AND MIT (port of libzstd 1.5.7 -- see ../NOTICE)
//! Frame decoder and frame utilities: frame header, block loop, content
//! checksum, concatenated and skippable frames, and the size queries
//! (`ZSTD_getFrameContentSize`, `ZSTD_findFrameCompressedSize`,
//! `ZSTD_decompressBound`, ...).
//!
//! Port of the one-shot half of lib/decompress/zstd_decompress.c (v1.5.7).
//! One deliberate difference, on malformed frames only: a block that
//! decodes to more than the frame's `Block_Maximum_Size` is refused here
//! for every block type, as RFC 8878 and libzstd's own streaming decoder
//! do; libzstd's one-shot `ZSTD_decompress` lets a raw or RLE block through.

const std = @import("std");
const dbits = @import("dbits.zig");
const dblock = @import("dblock.zig");
const readLE16 = dbits.readLE16;
const readLE32 = dbits.readLE32;
const readLE64 = dbits.readLE64;

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

/// `ZSTD_frameHeaderSize`: the full header size, from its first 5 bytes.
pub fn frameHeaderSize(src: []const u8) Error!usize {
    if (src.len < frame_header_size_prefix) return error.SrcSizeWrong;
    const fhd = src[frame_header_size_prefix - 1];
    const dict_id = fhd & 3;
    const single_segment = (fhd >> 5) & 1;
    const fcs_id = fhd >> 6;
    return frame_header_size_prefix + @as(usize, 1 - single_segment) + did_field_size[dict_id] + fcs_field_size[fcs_id] +
        @intFromBool(single_segment != 0 and fcs_id == 0);
}

/// `ZSTD_getFrameHeader`.
pub fn getFrameHeader(src: []const u8) Error!HeaderResult {
    if (src.len < frame_header_size_prefix) {
        if (src.len > 0) {
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
        return .{ .need = frame_header_size_prefix };
    }
    const magic = readLE32(src, 0);
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

    const fhsize = try frameHeaderSize(src);
    if (src.len < fhsize) return .{ .need = fhsize };

    const fhd = src[frame_header_size_prefix - 1];
    var pos: usize = frame_header_size_prefix;
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
fn findFrameSizeInfo(src: []const u8) Error!FrameSizeInfo {
    if (src.len >= skippable_header_size and isSkippableMagic(readLE32(src, 0))) {
        return .{ .nb_blocks = 0, .compressed_size = try readSkippableFrameSize(src), .decompressed_bound = 0 };
    }
    const zfh = switch (try getFrameHeader(src)) {
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
    return (try findFrameSizeInfo(src)).compressed_size;
}

/// `ZSTD_decompressBound`: an upper bound of the decompressed size of all
/// frames in `src` — exact where the headers record content sizes.
pub fn decompressBound(src_in: []const u8) Error!u64 {
    var src = src_in;
    var bound: u64 = 0;
    while (src.len > 0) {
        const info = try findFrameSizeInfo(src);
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
        const info = try findFrameSizeInfo(src);
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

    pub fn init(gpa: std.mem.Allocator, options: Options) error{OutOfMemory}!Decompressor {
        const st = try gpa.create(dblock.State);
        st.* = .{};
        // the slack behind the literals is read (and overwritten) by wildcopy
        @memset(st.lit_buf[block_size_max..], 0);
        return .{ .gpa = gpa, .st = st, .options = options };
    }

    pub fn deinit(d: *Decompressor) void {
        d.gpa.destroy(d.st);
        d.* = undefined;
    }

    /// `ZSTD_decompressBegin`.
    fn begin(d: *Decompressor) void {
        d.st.begin();
        d.dict_id = 0;
    }

    /// `ZSTD_decompressFrame`: decodes the frame at `src[ip.*..]` into
    /// `dst[op0..]`, advancing `ip`. Returns the decoded size.
    fn decompressFrame(d: *Decompressor, dst: []u8, op0: usize, src: []const u8, ip: *usize) Error!usize {
        const st = d.st;
        var remaining = src.len - ip.*;
        if (remaining < frame_header_size_min + block_header_size) return error.SrcSizeWrong;

        {
            const fhs = try frameHeaderSize(src[ip.*..][0..frame_header_size_prefix]);
            if (remaining < fhs + block_header_size) return error.SrcSizeWrong;
            // ZSTD_decodeFrameHeader
            d.fparams = switch (try getFrameHeader(src[ip.*..][0..fhs])) {
                .need => return error.SrcSizeWrong,
                .header => |h| h,
            };
            if (d.fparams.dict_id != 0 and d.dict_id != d.fparams.dict_id) return error.DictionaryWrong;
            ip.* += fhs;
            remaining -= fhs;
        }
        const validate = d.fparams.checksum and !d.options.ignore_checksum;
        var xxh = std.hash.XxHash64.init(0);
        st.block_size_max = d.fparams.block_size_max;

        const h: dblock.History = .{ .out = dst, .prefix = op0 };
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
                2 => try dblock.decompressBlock(st, &h, op, cap, block),
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
            if (decoded > st.block_size_max) return error.CorruptionDetected;
            if (validate) xxh.update(dst[op..][0..decoded]);
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
                const calc: u32 = @truncate(xxh.final());
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
        while (src.len - ip >= frame_header_size_prefix) {
            if (isSkippableMagic(readLE32(src, ip))) {
                ip += try readSkippableFrameSize(src[ip..]);
                continue;
            }
            d.begin();
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
