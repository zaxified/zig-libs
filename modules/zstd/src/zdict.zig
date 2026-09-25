// SPDX-License-Identifier: BSD-3-Clause AND MIT (port of libzstd 1.5.7 -- see ../NOTICE)
//! Dictionary finalization (port of libzstd lib/dictBuilder/zdict.c, v1.5.7,
//! less its legacy trainer): `ZDICT_finalizeDictionary`,
//! `ZDICT_addEntropyTablesFromBuffer`, `ZDICT_getDictID`,
//! `ZDICT_getDictHeaderSize`.
//!
//! Finalization turns dictionary content into a zstd dictionary: the magic
//! number, an ID, entropy tables and the three repcodes in front of the
//! content. The tables come from compressing the samples, each as one block
//! through the content attached as a `CDict` (`ZDICT_analyzeEntropy`), and
//! counting what the blocks' sequences and literals use -- so the tables
//! depend on the compressor's choices at the finalization level, and this
//! port gives libzstd's bytes because its compressor does.
//!
//! libzstd prints progress at `notificationLevel` 2 and up; nothing is
//! printed here.

const std = @import("std");
const Allocator = std.mem.Allocator;
const frame = @import("frame.zig");
const params = @import("params.zig");
const cdict_mod = @import("cdict.zig");
const huf = @import("huf.zig");
const fse = @import("fse.zig");
const sequences = @import("sequences.zig");

/// `ZDICT_DICTSIZE_MIN`.
pub const dict_size_min = 256;
/// `ZSTD_MAGIC_DICTIONARY`.
pub const magic_dictionary = cdict_mod.magic_dictionary;
/// `HBUFFSIZE`: room for the magic number, the ID and the entropy tables.
const hbuff_size = 256;
/// `OFFCODE_MAX`: the offset codes the dictionary's table describes.
const offcode_max_all = 30;
/// `repStartValue`: the repcodes a finalized dictionary carries.
const rep_start_value = [3]u32{ 1, 4, 8 };
/// `ZDICT_maxRep(repStartValue)`: the content must be at least this long.
const min_content_size = 8;

/// Errors named after libzstd's (`ZSTD_error_*`).
pub const Error = error{
    /// `dstSize_tooSmall`: a buffer below 256 bytes or the content, or
    /// no room for the tables and the 8 bytes of content the repcodes need.
    DstSizeTooSmall,
    /// `dictionaryCreation_failed`: content of 2 GiB − 128 KiB and up (its
    /// offsets need codes above 30).
    DictionaryCreationFailed,
    /// `dictionary_corrupted` (`getDictHeaderSize`).
    DictionaryCorrupted,
    /// `GENERIC`: an entropy table could not be built or written.
    Generic,
    /// Sizes summing past the samples' buffer (this port's check).
    SrcSizeWrong,
    /// Level above 22 (libzstd clamps it; this module refuses).
    LevelUnsupported,
    OutOfMemory,
};

/// `ZDICT_params_t`.
pub const Params = struct {
    /// `compressionLevel`: the level whose compressor the tables are
    /// measured with, and a trained dictionary is meant for; 0 = 3.
    level: i32 = 0,
    /// `dictID`: 0 = derived from the content (`defaultDictId`).
    dict_id: u32 = 0,
};

/// `ZDICT_getDictID`: the ID of a zstd dictionary, 0 if `dict` is not one.
pub fn getDictId(dict: []const u8) u32 {
    if (dict.len < 8) return 0;
    if (std.mem.readInt(u32, dict[0..4], .little) != magic_dictionary) return 0;
    return std.mem.readInt(u32, dict[4..8], .little);
}

/// `ZDICT_getDictHeaderSize`: the bytes before a zstd dictionary's content
/// (magic, ID, entropy tables, repcodes), checked as a compressor loads
/// them (`ZSTD_loadCEntropy`).
pub fn getDictHeaderSize(dict: []const u8) Error!usize {
    if (dict.len <= 8 or std.mem.readInt(u32, dict[0..4], .little) != magic_dictionary) return error.DictionaryCorrupted;
    var bs: frame.BlockState = .{};
    return cdict_mod.loadCEntropy(&bs, dict) catch error.DictionaryCorrupted;
}

/// The ID `ZDICT_finalizeDictionary` gives a dictionary when none is asked
/// for: XXH64 of the content, into 32 768 .. 2^31 − 1 (IDs below 32 768
/// and from 2^31 are reserved).
pub fn defaultDictId(content: []const u8) u32 {
    const random_id = std.hash.XxHash64.hash(0, content);
    return @intCast(random_id % ((1 << 31) - 32768) + 32768);
}

/// Samples as libzstd takes them: back to back in `buffer`, `sizes` in
/// order (`dict_builder.Samples`).
pub const Samples = struct {
    buffer: []const u8,
    sizes: []const usize,
};

fn checkSamples(s: Samples) Error!void {
    var t: u64 = 0;
    for (s.sizes) |n| t +|= n;
    if (t > s.buffer.len) return error.SrcSizeWrong;
}

/// `memmove`: `src` and `dst` may overlap.
fn move(dst: []u8, src: []const u8) void {
    std.debug.assert(dst.len == src.len);
    if (@intFromPtr(dst.ptr) <= @intFromPtr(src.ptr)) std.mem.copyForwards(u8, dst, src) else std.mem.copyBackwards(u8, dst, src);
}

fn resolveLevel(level: i32) Error!i32 {
    if (level > params.max_level) return error.LevelUnsupported;
    return if (level == 0) params.default_level else level;
}

/// `ZDICT_finalizeDictionary`: a zstd dictionary in `dict` (its capacity)
/// from `content`, with entropy tables from `samples` compressed with it at
/// `p.level`. Returns its size. `content` may lie anywhere in `dict`, as
/// the trainers leave it at the end. When the header and the content do not
/// both fit, the content's head is kept and its tail dropped -- libzstd's
/// behaviour, although the trainers put their best segments at the tail.
/// Content under 8 bytes is padded with zeros in front.
pub fn finalizeDictionary(gpa: Allocator, dict: []u8, content: []const u8, samples: Samples, p: Params) Error!usize {
    const level = try resolveLevel(p.level);
    try checkSamples(samples);
    // check conditions
    if (dict.len < content.len) return error.DstSizeTooSmall;
    if (dict.len < dict_size_min) return error.DstSizeTooSmall;

    // dictionary header
    var header: [hbuff_size]u8 = undefined;
    std.mem.writeInt(u32, header[0..4], magic_dictionary, .little);
    std.mem.writeInt(u32, header[4..8], if (p.dict_id != 0) p.dict_id else defaultDictId(content), .little);
    var h_size: usize = 8;

    // entropy tables
    h_size += try analyzeEntropy(gpa, header[h_size..], level, samples, content);

    // Shrink the content size if it doesn't fit in the buffer
    var content_size = content.len;
    if (h_size + content_size > dict.len) content_size = dict.len - h_size;

    // Pad the dictionary content with zeros if it is too small
    var padding: usize = 0;
    if (content_size < min_content_size) {
        if (h_size + min_content_size > dict.len) return error.DstSizeTooSmall; // too small to fit max repcode
        padding = min_content_size - content_size;
    }

    // The header, the padding, then the content: the "best" position in a
    // dictionary is its last byte. The content first, as it may overlap
    // `dict`.
    move(dict[h_size + padding ..][0..content_size], content[0..content_size]);
    @memcpy(dict[0..h_size], header[0..h_size]);
    @memset(dict[h_size..][0..padding], 0);
    return h_size + padding + content_size;
}

/// `ZDICT_addEntropyTablesFromBuffer` (`_advanced` with `p`): the content
/// is the last `content_size` bytes of `dict`; the header goes in front of
/// what fits of it. libzstd writes the tables straight into `dict` (over
/// the content's head, if they reach it), takes the ID's hash of the
/// content after that, and moves the content down only when there is room
/// to spare; so is it here. Returns min(capacity, header + content).
pub fn addEntropyTablesFromBuffer(gpa: Allocator, dict: []u8, content_size: usize, samples: Samples, p: Params) Error!usize {
    const level = try resolveLevel(p.level);
    try checkSamples(samples);
    // (this port's checks: libzstd reads before the buffer)
    if (content_size > dict.len or dict.len < 8) return error.DstSizeTooSmall;
    var h_size: usize = 8;

    // calculate entropy tables
    h_size += try analyzeEntropy(gpa, dict[h_size..], level, samples, dict[dict.len - content_size ..]);

    // add dictionary header (after entropy tables)
    std.mem.writeInt(u32, dict[0..4], magic_dictionary, .little);
    {
        const id = if (p.dict_id != 0) p.dict_id else defaultDictId(dict[dict.len - content_size ..]);
        std.mem.writeInt(u32, dict[4..8], id, .little);
    }

    if (h_size + content_size < dict.len)
        move(dict[h_size..][0..content_size], dict[dict.len - content_size ..]);
    return @min(dict.len, h_size + content_size);
}

/// `ZDICT_analyzeEntropy`: compress every sample through `content`, count
/// the literals and the sequences' codes, and write the Huffman table, the
/// three FSE tables and the repcodes into `dst`. Returns their size.
fn analyzeEntropy(gpa: Allocator, dst: []u8, level: i32, samples: Samples, content: []const u8) Error!usize {
    const offcode_max = fse.highbit32(@truncate(content.len + (128 << 10)));
    if (offcode_max > offcode_max_all) return error.DictionaryCreationFailed; // too large dictionary

    var count_lit: [256]u32 = @splat(1); // any character must be described
    var offcode_count: [offcode_max_all + 1]u32 = @splat(0);
    for (offcode_count[0 .. offcode_max + 1]) |*c| c.* = 1;
    var match_length_count: [sequences.max_ml + 1]u32 = @splat(1);
    var lit_length_count: [sequences.max_ll + 1]u32 = @splat(1);
    // (libzstd also ranks the most common first offsets here and then, "as
    // the impact of statistics is not properly evaluated", writes the
    // default repcodes instead; the ranking is not ported.)

    var total_src_size: usize = 0;
    for (samples.sizes) |n| total_src_size +%= n;
    const average_sample_size = total_src_size / @max(samples.sizes.len, 1);
    // ZSTD_getParams: a size hint of 0 is unknown
    const cp = params.getInternal(level, if (average_sample_size == 0) params.unknown_size else average_sample_size, content.len, .unknown);

    // ZSTD_createCDict_advanced(dictBuffer, dictBufferSize, ZSTD_dlm_byRef,
    // ZSTD_dct_rawContent, params.cParams): no level, these parameters over
    // the default level's
    var cdict = cdict_mod.CDict.initReference(gpa, content, .{
        .level = 0,
        .content_type = .raw_content,
        .advanced = .{
            .window_log = cp.window_log,
            .hash_log = cp.hash_log,
            .chain_log = cp.chain_log,
            .search_log = cp.search_log,
            .min_match = cp.min_match,
            .target_length = cp.target_length,
            .strategy = cp.strategy,
        },
    }) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => unreachable, // raw content from in-range parameters
    };
    defer cdict.deinit();
    var comp: frame.Compressor = .initEmpty(gpa);
    defer comp.deinit();
    const work_place = try gpa.alloc(u8, params.block_size_max_abs);
    defer gpa.free(work_place);

    // collect stats on all samples
    var pos: usize = 0;
    const block_size_max = @min(params.block_size_max_abs, @as(usize, 1) << @intCast(cp.window_log));
    for (samples.sizes) |size| {
        const src = samples.buffer[pos..][0..@min(size, block_size_max)]; // protection vs large samples
        pos += size;
        // ZDICT_countEStats
        comp.beginUsingCDict(&cdict) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => continue, // "ZSTD_compressBegin_usingCDict failed"
        };
        // a sample larger than the context's block (its window can be the
        // CDict's, smaller than `block_size_max`) is not counted
        const c_size = comp.compressBlockOnly(work_place, src) catch continue;
        if (c_size == 0) continue; // block is not compressible
        const ss = comp.seqStore();
        for (ss.lits[0..ss.n_lit]) |b| count_lit[b] += 1;
        ss.toCodes();
        for (ss.of_code[0..ss.n_seq]) |c| offcode_count[c] += 1;
        for (ss.ml_code[0..ss.n_seq]) |c| match_length_count[c] += 1;
        for (ss.ll_code[0..ss.n_seq]) |c| lit_length_count[c] += 1;
    }

    // analyze, build stats, starting with literals
    var huf_table: huf.CTable = .{};
    var huff_log: u32 = huf.buildCTable(&huf_table, &count_lit, 255, huf.table_log_default) catch return error.Generic;
    if (huff_log == 8) {
        // not compressible: would fail in HUF_writeCTable; a "mostly flat
        // but still compressible" distribution instead (ZDICT_flatLit)
        for (count_lit[1..]) |*c| c.* = 2;
        count_lit[0] = 4;
        count_lit[253] = 1;
        count_lit[254] = 1;
        huff_log = huf.buildCTable(&huf_table, &count_lit, 255, huf.table_log_default) catch return error.Generic;
        std.debug.assert(huff_log == 9);
    }

    var offcode_ncount: [offcode_max_all + 1]i16 = @splat(0);
    var match_length_ncount: [sequences.max_ml + 1]i16 = undefined;
    var lit_length_ncount: [sequences.max_ll + 1]i16 = undefined;
    const off_log = try normalize(&offcode_ncount, sequences.off_fse_log, &offcode_count, offcode_max);
    const ml_log = try normalize(&match_length_ncount, sequences.ml_fse_log, &match_length_count, sequences.max_ml);
    const ll_log = try normalize(&lit_length_ncount, sequences.ll_fse_log, &lit_length_count, sequences.max_ll);

    // write result to buffer
    var op: usize = 0;
    op += huf.writeCTable(dst, &huf_table, 255, huff_log) catch |e| return tableError(e);
    op += fse.writeNCount(dst[op..], &offcode_ncount, offcode_max_all, off_log) catch |e| return tableError(e);
    op += fse.writeNCount(dst[op..], &match_length_ncount, sequences.max_ml, ml_log) catch |e| return tableError(e);
    op += fse.writeNCount(dst[op..], &lit_length_ncount, sequences.max_ll, ll_log) catch |e| return tableError(e);
    if (dst.len - op < 12) return error.DstSizeTooSmall; // not enough space to write RepOffsets
    for (rep_start_value, 0..) |r, i| std.mem.writeInt(u32, dst[op + 4 * i ..][0..4], r, .little);
    return op + 12;
}

/// `FSE_normalizeCount(norm, log, count, total, max, useLowProbCount = 1)`
/// over `count[0..max]`.
fn normalize(norm: []i16, log: u32, count: []const u32, max: u32) Error!u32 {
    var total: usize = 0;
    for (count[0 .. max + 1]) |c| total += c;
    return fse.normalizeCount(norm, log, count, total, max, true) catch error.Generic;
}

fn tableError(e: anyerror) Error {
    return if (e == error.DstSizeTooSmall) error.DstSizeTooSmall else error.Generic;
}

// ---------------------------------------------------------------------------
// Tests (byte-exactness against libzstd: dict_golden_test.zig)

const testing = std.testing;

test "getDictId / getDictHeaderSize read a zstd dictionary, refuse anything else" {
    try testing.expectEqual(@as(u32, 0), getDictId("short"));
    try testing.expectEqual(@as(u32, 0), getDictId("\x00\x00\x00\x00\x01\x00\x00\x00"));
    try testing.expectEqual(@as(u32, 0x04030201), getDictId("\x37\xA4\x30\xEC\x01\x02\x03\x04"));
    try testing.expectError(error.DictionaryCorrupted, getDictHeaderSize("\x37\xA4\x30\xEC\x01\x02\x03\x04"));
    try testing.expectError(error.DictionaryCorrupted, getDictHeaderSize("raw content, not a dictionary"));
    try testing.expectError(error.DictionaryCorrupted, getDictHeaderSize("\x37\xA4\x30\xEC\x01\x02\x03\x04\xff\xff"));
}

test "defaultDictId stays in 32768 .. 2^31 - 1" {
    for ([_][]const u8{ "", "a", "abcdefgh", "the quick brown fox" }) |c| {
        const id = defaultDictId(c);
        try testing.expect(id >= 32768 and id < 1 << 31);
    }
}
