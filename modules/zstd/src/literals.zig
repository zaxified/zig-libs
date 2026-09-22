// SPDX-License-Identifier: BSD-3-Clause AND MIT (port of libzstd 1.5.7 -- see ../NOTICE)
//! Literals section (port of libzstd lib/compress/zstd_compress_literals.c, v1.5.7).

const std = @import("std");
const huf = @import("huf.zig");

pub const Error = error{DstSizeTooSmall};

pub const HufState = struct {
    table: huf.CTable = .{},
    repeat: huf.Repeat = .none,
};

pub const lit_huf_log = 11;
const set_basic = 0;
const set_rle = 1;
const set_compressed = 2;
const set_repeat = 3;

/// `ZSTD_noCompressLiterals`.
pub fn noCompress(dst: []u8, src: []const u8) Error!usize {
    const fl_size: usize = 1 + @as(usize, @intFromBool(src.len > 31)) + @intFromBool(src.len > 4095);
    if (src.len + fl_size > dst.len) return error.DstSizeTooSmall;
    const n: u32 = @intCast(src.len);
    switch (fl_size) {
        1 => dst[0] = @truncate(set_basic + (n << 3)),
        2 => std.mem.writeInt(u16, dst[0..2], @truncate(set_basic + (1 << 2) + (n << 4)), .little),
        3 => {
            // libzstd writes 4 bytes here (MEM_writeLE32); the 4th is overwritten
            // by the literals or lies past the section.
            const v: u32 = set_basic + (3 << 2) + (n << 4);
            dst[0] = @truncate(v);
            dst[1] = @truncate(v >> 8);
            dst[2] = @truncate(v >> 16);
        },
        else => unreachable,
    }
    @memcpy(dst[fl_size..][0..src.len], src);
    return src.len + fl_size;
}

/// `ZSTD_compressRleLiteralsBlock`.
fn rle(dst: []u8, src: []const u8) usize {
    const fl_size: usize = 1 + @as(usize, @intFromBool(src.len > 31)) + @intFromBool(src.len > 4095);
    const n: u32 = @intCast(src.len);
    switch (fl_size) {
        1 => dst[0] = @truncate(set_rle + (n << 3)),
        2 => std.mem.writeInt(u16, dst[0..2], @truncate(set_rle + (1 << 2) + (n << 4)), .little),
        3 => {
            const v: u32 = set_rle + (3 << 2) + (n << 4);
            dst[0] = @truncate(v);
            dst[1] = @truncate(v >> 8);
            dst[2] = @truncate(v >> 16);
        },
        else => unreachable,
    }
    dst[fl_size] = src[0];
    return fl_size + 1;
}

fn minLiteralsToCompress(strategy: u32, repeat: huf.Repeat) usize {
    _ = repeat; // HUF_repeat_valid (6 bytes) needs a dictionary
    const shift: u6 = @intCast(@min(9 - strategy, 3));
    return @as(usize, 8) << shift;
}

/// `ZSTD_minGain`.
pub fn minGain(src_size: usize, strategy: u32) usize {
    const min_log: u6 = if (strategy >= 8) @intCast(strategy - 1) else 6;
    return (src_size >> min_log) + 2;
}

fn allBytesIdentical(src: []const u8) bool {
    for (src[1..]) |b| if (b != src[0]) return false;
    return true;
}

/// `ZSTD_compressLiterals`. `next` starts as a copy of `prev` and ends as the
/// state the next block inherits.
pub fn compress(dst: []u8, src: []const u8, prev: *const HufState, next: *HufState, strategy: u32, disable_literal_compression: bool, suspect_uncompressible: bool) Error!usize {
    const lh_size: usize = 3 + @as(usize, @intFromBool(src.len >= 1024)) + @intFromBool(src.len >= 16 * 1024);
    const single_stream = src.len < 256;
    var h_type: u32 = set_compressed;

    next.* = prev.*;
    if (disable_literal_compression) return noCompress(dst, src);
    if (src.len < minLiteralsToCompress(strategy, prev.repeat)) return noCompress(dst, src);
    if (dst.len < lh_size + 1) return error.DstSizeTooSmall;

    var c_lit_size: usize = 0;
    var failed = false;
    {
        var repeat = prev.repeat;
        const flags: huf.Flags = .{
            .prefer_repeat = strategy < 4 and src.len <= 1024,
            .suspect_uncompressible = suspect_uncompressible,
            .optimal_depth = strategy >= 8, // HUF_OPTIMAL_DEPTH_THRESHOLD: btultra
        };
        c_lit_size = huf.compress(dst[lh_size..], src, lit_huf_log, if (single_stream) .single else .four, &next.table, &repeat, flags) catch blk: {
            failed = true;
            break :blk 0;
        };
        if (repeat != .none) h_type = set_repeat; // reused the existing table
    }

    const min_gain = minGain(src.len, strategy);
    if (failed or c_lit_size == 0 or c_lit_size >= src.len - min_gain) {
        next.* = prev.*;
        return noCompress(dst, src);
    }
    if (c_lit_size == 1) {
        // A single symbol: an RLE literals section is smaller.
        if (src.len >= 8 or allBytesIdentical(src)) {
            next.* = prev.*;
            return rle(dst, src);
        }
    }
    if (h_type == set_compressed) next.repeat = .check; // a newly built table

    const n: u32 = @intCast(src.len);
    const c: u32 = @intCast(c_lit_size);
    switch (lh_size) {
        3 => {
            const lhc: u32 = h_type + (@as(u32, @intFromBool(!single_stream)) << 2) + (n << 4) + (c << 14);
            dst[0] = @truncate(lhc);
            dst[1] = @truncate(lhc >> 8);
            dst[2] = @truncate(lhc >> 16);
        },
        4 => {
            const lhc: u32 = h_type + (2 << 2) + (n << 4) + (c << 18);
            std.mem.writeInt(u32, dst[0..4], lhc, .little);
        },
        5 => {
            const lhc: u32 = h_type + (3 << 2) + (n << 4) + (c << 22);
            std.mem.writeInt(u32, dst[0..4], lhc, .little);
            dst[4] = @truncate(c >> 10);
        },
        else => unreachable,
    }
    return lh_size + c_lit_size;
}

test "short literals are stored raw with a one-byte header" {
    var buf: [64]u8 = undefined;
    const prev: HufState = .{};
    var next: HufState = .{};
    const n = try compress(&buf, "hello", &prev, &next, 1, false, false);
    try std.testing.expectEqual(@as(usize, 6), n);
    try std.testing.expectEqual(@as(u8, 5 << 3), buf[0]);
    try std.testing.expectEqualStrings("hello", buf[1..6]);
}
