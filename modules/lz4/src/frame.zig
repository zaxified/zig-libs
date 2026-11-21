// SPDX-License-Identifier: MIT

//! The LZ4 frame format (lz4_Frame_format.md, LZ4 v1.10.0): frames, skippable
//! frames and the legacy frame of `lz4 -l`, concatenated in any order.
//!
//! Decoding is whole-buffer: the output grows block by block, bounded by
//! `DecodeOptions.max_output`; nothing is allocated from a declared size
//! before the bytes that justify it have been decoded.

const std = @import("std");
const block = @import("block.zig");
const XxHash32 = std.hash.XxHash32;

pub const magic: u32 = 0x184D2204;
pub const legacy_magic: u32 = 0x184C2102;
/// Skippable frames use 0x184D2A50..0x184D2A5F.
pub const skippable_magic_base: u32 = 0x184D2A50;
/// A legacy frame's blocks decode to at most 8 MiB each.
pub const legacy_block_size: usize = 8 << 20;

pub const DecodeError = error{
    /// The input does not start with a frame magic number.
    BadMagic,
    /// The frame descriptor's version field is not 01.
    BadVersion,
    /// A reserved bit of FLG or BD is set.
    ReservedBitSet,
    /// The block maximum size id is not 4..7.
    BadBlockSize,
    /// The descriptor's header checksum byte does not match.
    HeaderChecksumMismatch,
    /// The input ends inside a frame (header, block, checksum, skippable
    /// payload, legacy block size).
    TruncatedInput,
    /// A block is larger than the frame's block maximum size, stored or
    /// decoded (a legacy block: larger than its 8 MiB).
    BlockTooLarge,
    /// A compressed block is malformed: it ends inside a sequence or right
    /// after a match.
    CorruptBlock,
    /// A match offset of 0, or one reaching before the frame's (or, with
    /// independent blocks, the block's) first byte.
    BadOffset,
    BlockChecksumMismatch,
    ContentChecksumMismatch,
    /// The decoded size differs from the content size the header declares.
    ContentSizeMismatch,
    /// The output would exceed `DecodeOptions.max_output`.
    OutputTooLarge,
    /// Bytes after the last frame that do not start another one.
    TrailingData,
    OutOfMemory,
};

pub const default_max_output: usize = 256 << 20;

pub const DecodeOptions = struct {
    /// Bomb cap on the total output; `null` = unbounded. A frame whose header
    /// declares more is refused before decoding.
    max_output: ?usize = default_max_output,
    /// Read every frame of the input (the lz4 CLI and lz4_flex do); `false`
    /// reads the first frame only, and anything after it is
    /// `error.TrailingData` unless `ignore_trailing_garbage` is also set (the
    /// two together are python-lz4's `lz4.frame.decompress`).
    multi_frame: bool = true,
    /// Bytes after the last frame that are not a frame magic (with
    /// `multi_frame = false`: everything after the first frame) end the input
    /// quietly instead of being `error.TrailingData`; so does a word after a
    /// legacy frame's blocks that is too large to be one.
    ignore_trailing_garbage: bool = false,
    /// Check block and content checksums when the frame carries them (the
    /// lz4 CLI's `--no-crc` turns this off).
    verify_checksums: bool = true,
};

pub const BlockSize = enum(u3) {
    max64KB = 4,
    max256KB = 5,
    max1MB = 6,
    max4MB = 7,

    pub fn bytes(s: BlockSize) usize {
        return @as(usize, 1) << (8 + 2 * @as(u5, @backingInt(s)));
    }
};

pub const EncodeOptions = struct {
    /// The default is liblz4's (`LZ4F_preferences_t` zeroed): 64 KB.
    block_size: BlockSize = .max64KB,
    /// `false` (liblz4's default) lets a block's matches reach into the
    /// previous 64 KB of the frame; `true` makes every block decodable alone.
    independent_blocks: bool = false,
    /// An xxHash32 of each stored block after it.
    block_checksum: bool = false,
    /// An xxHash32 of the whole content after the end mark.
    content_checksum: bool = false,
    /// The content size in the header.
    content_size: bool = false,
    /// The block compressor's acceleration (1 = LZ4's default level), as
    /// `LZ4_compress_fast` takes it. liblz4's frame API derives it from a
    /// negative `compressionLevel` L as `1 - L` (`LZ4F_compressBlock`), so
    /// level -1 is acceleration 2.
    acceleration: u32 = 1,
    /// 3..12: the HC matcher (liblz4's `compressionLevel` 3..12: smaller
    /// output, several times slower; `lz4 -9`); 0..2 are the fast matcher and
    /// `acceleration` applies; above 12 is 12. Levels 10..12 use the same
    /// chain search as 9 and deeper, not liblz4's optimal parser. Without an
    /// allocator (`compressInto`) the matcher's tables, about 192 KiB, are on
    /// the stack.
    hc_level: u8 = 0,
};

fn markSkippable(m: u32) bool {
    return m & 0xFFFF_FFF0 == skippable_magic_base;
}

fn knownMagic(m: u32) bool {
    return m == magic or m == legacy_magic or markSkippable(m);
}

fn readU32(src: []const u8, at: usize) u32 {
    return std.mem.readInt(u32, src[at..][0..4], .little);
}

const Decoder = struct {
    gpa: std.mem.Allocator,
    src: []const u8,
    pos: usize = 0,
    out: std.ArrayList(u8) = .empty,
    max_output: usize,
    opts: DecodeOptions,
    /// The dictionary tail (`block.dictTail`), or empty.
    dict: []const u8 = "",
    /// Dictionary bytes currently sitting in `out` as history (they are not
    /// output: `room` does not count them).
    embedded: usize = 0,

    /// Output bytes that may still be produced.
    fn room(d: *const Decoder) usize {
        return d.max_output + d.embedded - d.out.items.len;
    }

    /// Put the dictionary into `out` as history; returns where it starts.
    fn embed(d: *Decoder) std.mem.Allocator.Error!usize {
        const at = d.out.items.len;
        try d.out.appendSlice(d.gpa, d.dict);
        d.embedded = d.dict.len;
        return at;
    }

    /// Take the dictionary out again (what was decoded after it moves down).
    fn unembed(d: *Decoder, at: usize) void {
        d.out.replaceRangeAssumeCapacity(at, d.dict.len, "");
        d.embedded = 0;
    }

    fn need(d: *Decoder, n: usize) DecodeError!void {
        if (d.src.len - d.pos < n) return error.TruncatedInput;
    }

    fn take32(d: *Decoder) DecodeError!u32 {
        try d.need(4);
        const v = readU32(d.src, d.pos);
        d.pos += 4;
        return v;
    }

    /// Decode one compressed block of at most `max` output bytes whose
    /// matches may reach back to `prefix_start`.
    fn compressedBlock(d: *Decoder, data: []const u8, max: usize, prefix_start: usize) DecodeError!void {
        const left = d.room();
        // No block decodes to more than 255 bytes per input byte (a length
        // byte of 255 is the densest), so a small block never reserves the
        // frame's whole block maximum.
        const dense = std.math.mul(usize, data.len, 255) catch std.math.maxInt(usize);
        const fit = @min(max, left, dense);
        try d.out.ensureUnusedCapacity(d.gpa, fit);
        const start = d.out.items.len;
        const buf = d.out.allocatedSlice()[0 .. start + fit];
        const end = block.decodeInto(data, buf, start, prefix_start) catch |e| return switch (e) {
            error.Truncated => error.CorruptBlock,
            error.BadOffset => error.BadOffset,
            error.OutputTooSmall => if (left < max) error.OutputTooLarge else error.BlockTooLarge,
        };
        d.out.items.len = end;
    }

    fn frame(d: *Decoder) DecodeError!void {
        const frame_start = d.out.items.len;
        try d.need(3);
        const flg = d.src[d.pos];
        const bd = d.src[d.pos + 1];
        if (flg >> 6 != 1) return error.BadVersion;
        if (flg & 0x02 != 0 or bd & 0x8F != 0) return error.ReservedBitSet;
        const bsid: u3 = @intCast(bd >> 4);
        if (bsid < 4) return error.BadBlockSize;
        const block_max = BlockSize.bytes(@fromBackingInt(@intCast(bsid)));
        const independent = flg & 0x20 != 0;
        const has_block_sum = flg & 0x10 != 0;
        const has_size = flg & 0x08 != 0;
        const has_content_sum = flg & 0x04 != 0;
        const has_dict_id = flg & 0x01 != 0;
        const desc_len: usize = 2 + @as(usize, if (has_size) 8 else 0) + @as(usize, if (has_dict_id) 4 else 0);
        try d.need(desc_len + 1);
        const desc = d.src[d.pos..][0..desc_len];
        const hc: u8 = @truncate(XxHash32.hash(0, desc) >> 8);
        if (hc != d.src[d.pos + desc_len]) return error.HeaderChecksumMismatch;
        // liblz4 reads 0 as "size unknown" even when the flag is set.
        const content_size: ?u64 = if (has_size) blk: {
            const v = std.mem.readInt(u64, desc[2..10], .little);
            break :blk if (v == 0) null else v;
        } else null;
        // The dictionary id is read and not acted on, as liblz4 does: the
        // dictionary a caller gives `decompressDict` applies to every frame; a
        // block that needs one the caller did not give fails on its first
        // out-of-range offset.
        d.pos += desc_len + 1;
        if (content_size) |cs| if (cs > d.max_output - frame_start) return error.OutputTooLarge;
        // Linked blocks: the dictionary is the history of the frame's first
        // block, in `out` ahead of the content for the whole frame.
        const linked_dict = d.dict.len > 0 and !independent;
        var dict_at: usize = 0;
        if (linked_dict) dict_at = d.embed() catch return error.OutOfMemory;
        const base = d.out.items.len;

        while (true) {
            const word = try d.take32();
            if (word == 0) break; // end mark
            const stored = word & 0x8000_0000 != 0;
            const len: usize = word & 0x7FFF_FFFF;
            if (len > block_max) return error.BlockTooLarge;
            try d.need(len + @as(usize, if (has_block_sum) 4 else 0));
            const data = d.src[d.pos..][0..len];
            d.pos += len;
            if (has_block_sum) {
                const want = readU32(d.src, d.pos);
                d.pos += 4;
                if (d.opts.verify_checksums and XxHash32.hash(0, data) != want) return error.BlockChecksumMismatch;
            }
            if (stored) {
                if (len > d.room()) return error.OutputTooLarge;
                try d.out.appendSlice(d.gpa, data);
            } else if (independent and d.dict.len > 0) {
                // Every block starts from the dictionary: it goes in front of
                // this block's output for the decode only.
                const at = d.embed() catch return error.OutOfMemory;
                try d.compressedBlock(data, block_max, at);
                d.unembed(at);
            } else {
                const prefix = if (independent) d.out.items.len else if (linked_dict) dict_at else base;
                try d.compressedBlock(data, block_max, prefix);
            }
        }
        const produced = d.out.items[base..];
        if (content_size) |cs| if (produced.len != cs) return error.ContentSizeMismatch;
        if (has_content_sum) {
            const want = try d.take32();
            if (d.opts.verify_checksums and XxHash32.hash(0, produced) != want) return error.ContentChecksumMismatch;
        }
        if (linked_dict) d.unembed(dict_at);
    }

    fn legacy(d: *Decoder) DecodeError!void {
        while (d.pos < d.src.len) {
            if (d.src.len - d.pos < 4) return error.TruncatedInput;
            const len: usize = readU32(d.src, d.pos);
            // A word over the largest legacy block is not a block size: it
            // ends the legacy frame and is read again as what follows it (the
            // next frame's magic number, or trailing data), as the lz4 CLI
            // does ("maybe new stream?", `LZ4IO_decodeLegacyStream`). Every
            // frame magic number is over that bound.
            if (len > block.compressBound(legacy_block_size)) return;
            d.pos += 4;
            try d.need(len);
            const data = d.src[d.pos..][0..len];
            d.pos += len;
            try d.compressedBlock(data, legacy_block_size, d.out.items.len);
        }
    }

    fn run(d: *Decoder) DecodeError!void {
        var first = true;
        while (d.pos < d.src.len) {
            if (!first and !d.opts.multi_frame) break;
            const rest = d.src.len - d.pos;
            const m: ?u32 = if (rest >= 4) readU32(d.src, d.pos) else null;
            if (m == null or !knownMagic(m.?)) {
                if (first) return if (m == null) error.TruncatedInput else error.BadMagic;
                if (d.opts.ignore_trailing_garbage) return;
                return error.TrailingData;
            }
            d.pos += 4;
            if (m.? == magic) {
                try d.frame();
            } else if (m.? == legacy_magic) {
                try d.legacy();
            } else {
                const len = try d.take32();
                try d.need(len);
                d.pos += len;
            }
            first = false;
        }
        if (d.pos < d.src.len and !d.opts.ignore_trailing_garbage) return error.TrailingData;
    }
};

/// Every frame of `src` (LZ4 frames, skippable frames, legacy frames, in any
/// order), decoded and concatenated. Caller owns the result. Empty input is
/// empty output, as for the lz4 CLI.
pub fn decompress(gpa: std.mem.Allocator, src: []const u8, opts: DecodeOptions) DecodeError![]u8 {
    var d: Decoder = .{
        .gpa = gpa,
        .src = src,
        .max_output = opts.max_output orelse std.math.maxInt(usize),
        .opts = opts,
    };
    errdefer d.out.deinit(gpa);
    try d.run();
    return d.out.toOwnedSlice(gpa);
}

/// `decompress` for frames made against a dictionary (`compressDict`, liblz4's
/// `LZ4F_decompress_usingDict`, `lz4 -d -D`): `dictionary` (its last 64 KiB - 1
/// bytes) is the history of every LZ4 frame's first block when blocks are
/// linked, of every block when they are independent. The frame's Dictionary ID
/// is not compared with anything (as in liblz4: knowing which dictionary a
/// frame needs is the caller's job). Legacy frames take none. Caller owns the
/// result. An empty `dictionary` is `decompress`.
pub fn decompressDict(gpa: std.mem.Allocator, src: []const u8, dictionary: []const u8, opts: DecodeOptions) DecodeError![]u8 {
    var d: Decoder = .{
        .gpa = gpa,
        .src = src,
        .max_output = opts.max_output orelse std.math.maxInt(usize),
        .opts = opts,
        .dict = block.dictTail(dictionary),
    };
    errdefer d.out.deinit(gpa);
    try d.run();
    return d.out.toOwnedSlice(gpa);
}

/// As `decompress`, into `dst`: returns the decoded length. `dst.len` is a
/// cap like `DecodeOptions.max_output` (the smaller of the two applies), so
/// output that would not fit is `error.OutputTooLarge`, a frame whose header
/// declares more than fits is refused before decoding, and bytes of `dst`
/// past the returned length may have been written. Allocates nothing; never
/// returns `error.OutOfMemory`.
pub fn decompressInto(src: []const u8, dst: []u8, opts: DecodeOptions) DecodeError!usize {
    var d: Decoder = .{
        // Every write is bounded by `max_output` <= `dst.len` before it is
        // made, so the list never grows past its buffer.
        .gpa = std.mem.Allocator.failing,
        .src = src,
        .out = .initBuffer(dst),
        .max_output = @min(opts.max_output orelse std.math.maxInt(usize), dst.len),
        .opts = opts,
    };
    try d.run();
    return d.out.items.len;
}

// ── encoder ─────────────────────────────────────────────────────────────

/// Frame header length for `opts` (magic, FLG, BD, optional size, HC).
pub fn headerLen(opts: EncodeOptions) usize {
    return 7 + @as(usize, if (opts.content_size) 8 else 0);
}

/// The largest frame `compress` writes for `n` input bytes.
pub fn compressBound(n: usize, opts: EncodeOptions) usize {
    const bmax = opts.block_size.bytes();
    const blocks = n / bmax + @intFromBool(n % bmax != 0);
    const per_block: usize = 4 + @as(usize, if (opts.block_checksum) 4 else 0);
    const tail: usize = 4 + @as(usize, if (opts.content_checksum) 4 else 0);
    return std.math.add(usize, headerLen(opts) + tail, std.math.add(usize, n, blocks * per_block) catch return std.math.maxInt(usize)) catch std.math.maxInt(usize);
}

pub const EncodeError = error{ NoSpaceLeft, InputTooLarge };

/// Write one frame holding `src` into `dst`; `compressBound(src.len, opts)`
/// bytes always fit. Returns the frame length.
pub fn compressInto(src: []const u8, dst: []u8, opts: EncodeOptions) EncodeError!usize {
    if (opts.hc_level >= block.hc_min_level) return compressIntoHc(src, dst, opts);
    return encodeFrame(null, src, 0, "", null, dst, opts, null) catch |e| switch (e) {
        error.OutOfMemory => unreachable, // no allocator is used without a dictionary
        else => |x| return x,
    };
}

/// `compressInto` with the HC matcher; out of line so the fast path's frame
/// does not carry its tables.
noinline fn compressIntoHc(src: []const u8, dst: []u8, opts: EncodeOptions) EncodeError!usize {
    var t: block.HcTable = undefined;
    t.init();
    return encodeFrame(null, src, 0, "", null, dst, opts, &t) catch |e| switch (e) {
        error.OutOfMemory => unreachable,
        else => |x| return x,
    };
}

/// The frame encoder. `buf[base..]` is the content; with a dictionary `buf`
/// starts with its tail (`block.dictTail`), which is `buf[0..base]`, as
/// history for linked blocks. Independent blocks with a dictionary are encoded
/// one by one against `dict` (the blocks in between are not history), which
/// takes `gpa`.
fn encodeFrame(
    gpa: ?std.mem.Allocator,
    buf: []const u8,
    base: usize,
    dict: []const u8,
    dict_id: ?u32,
    dst: []u8,
    opts: EncodeOptions,
    hc: ?*block.HcTable,
) (EncodeError || error{OutOfMemory})!usize {
    const src = buf[base..];
    if (src.len > std.math.maxInt(u32)) return error.InputTooLarge;
    const hdr = headerLen(opts) + @as(usize, if (dict_id != null) 4 else 0);
    if (dst.len < hdr) return error.NoSpaceLeft;
    var at: usize = 0;
    std.mem.writeInt(u32, dst[0..4], magic, .little);
    var flg: u8 = 0x40;
    if (opts.independent_blocks) flg |= 0x20;
    if (opts.block_checksum) flg |= 0x10;
    if (opts.content_size) flg |= 0x08;
    if (opts.content_checksum) flg |= 0x04;
    if (dict_id != null) flg |= 0x01;
    dst[4] = flg;
    dst[5] = @as(u8, @backingInt(opts.block_size)) << 4;
    at = 6;
    if (opts.content_size) {
        std.mem.writeInt(u64, dst[6..14], src.len, .little);
        at = 14;
    }
    if (dict_id) |id| {
        std.mem.writeInt(u32, dst[at..][0..4], id, .little);
        at += 4;
    }
    dst[at] = @truncate(XxHash32.hash(0, dst[4..at]) >> 8);
    at += 1;

    const bmax = opts.block_size.bytes();
    const accel = block.clampAcceleration(opts.acceleration);
    const per_block_dict = opts.independent_blocks and dict.len > 0;
    var table: block.Table = @splat(0);
    if (!per_block_dict and base > 0 and hc == null) block.seedTable(buf[0..base], &table);
    var start: usize = base;
    while (start < buf.len) {
        const end = @min(buf.len, start + bmax);
        const raw = buf[start..end];
        if (dst.len - at < 4) return error.NoSpaceLeft;
        const body = dst[at + 4 ..];
        const history = if (opts.independent_blocks) start else start -| block.max_offset;
        // Room for at most `raw.len - 1` bytes: a block that does not
        // shrink is stored instead (liblz4 does the same).
        const room = @min(body.len, raw.len - 1);
        const z: ?usize = if (per_block_dict)
            block.compressDict(gpa.?, raw, dict, body[0..room], .{ .acceleration = accel, .hc_level = opts.hc_level }) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => null,
            }
        else if (hc) |t|
            block.encodeHc(buf, start, end, history, t, opts.hc_level, body[0..room]) catch null
        else
            block.encodeRange(buf, start, end, history, &table, accel, body[0..room]) catch null;
        var stored_len: usize = undefined;
        if (z) |zn| {
            std.mem.writeInt(u32, dst[at..][0..4], @intCast(zn), .little);
            stored_len = zn;
        } else {
            if (body.len < raw.len) return error.NoSpaceLeft;
            @memcpy(body[0..raw.len], raw);
            std.mem.writeInt(u32, dst[at..][0..4], @as(u32, @intCast(raw.len)) | 0x8000_0000, .little);
            stored_len = raw.len;
        }
        at += 4;
        const stored = dst[at..][0..stored_len];
        at += stored_len;
        if (opts.block_checksum) {
            if (dst.len - at < 4) return error.NoSpaceLeft;
            std.mem.writeInt(u32, dst[at..][0..4], XxHash32.hash(0, stored), .little);
            at += 4;
        }
        start = end;
    }
    const tail: usize = 4 + @as(usize, if (opts.content_checksum) 4 else 0);
    if (dst.len - at < tail) return error.NoSpaceLeft;
    std.mem.writeInt(u32, dst[at..][0..4], 0, .little);
    at += 4;
    if (opts.content_checksum) {
        std.mem.writeInt(u32, dst[at..][0..4], XxHash32.hash(0, src), .little);
        at += 4;
    }
    return at;
}

/// One frame holding `src`. Caller owns the result.
pub fn compress(gpa: std.mem.Allocator, src: []const u8, opts: EncodeOptions) (EncodeError || error{OutOfMemory})![]u8 {
    const buf = try gpa.alloc(u8, compressBound(src.len, opts));
    errdefer gpa.free(buf);
    var n: usize = undefined;
    if (opts.hc_level >= block.hc_min_level) {
        const t = try gpa.create(block.HcTable);
        defer gpa.destroy(t);
        t.init();
        n = try encodeFrame(null, src, 0, "", null, buf, opts, t);
    } else n = try compressInto(src, buf, opts);
    return gpa.realloc(buf, n);
}

/// One frame holding `src`, compressed against `dictionary` (liblz4's
/// `LZ4F_compressBegin_usingDict`, `lz4 -D`): the header carries `dict_id`
/// (the 4-byte Dictionary ID field; null leaves the field out, as liblz4 does
/// when the caller names no id), linked blocks use the dictionary as the
/// history of the first block, independent blocks each use it. Only the last
/// 64 KiB - 1 of the dictionary counts. Decode with `decompressDict` (or any
/// LZ4 frame decoder given the same dictionary). An empty dictionary is
/// `compress`, plus the id field. Caller owns the result.
pub fn compressDict(
    gpa: std.mem.Allocator,
    src: []const u8,
    dictionary: []const u8,
    dict_id: ?u32,
    opts: EncodeOptions,
) (EncodeError || error{OutOfMemory})![]u8 {
    const d = block.dictTail(dictionary);
    const out = try gpa.alloc(u8, compressBound(src.len, opts) + 4);
    errdefer gpa.free(out);
    var n: usize = undefined;
    if (d.len == 0 or opts.independent_blocks) {
        // Independent blocks are encoded one by one against the dictionary.
        n = try encodeFrame(gpa, src, 0, d, dict_id, out, opts, null);
    } else {
        const buf = try gpa.alloc(u8, d.len + src.len);
        defer gpa.free(buf);
        @memcpy(buf[0..d.len], d);
        @memcpy(buf[d.len..], src);
        if (opts.hc_level >= block.hc_min_level) {
            const t = try gpa.create(block.HcTable);
            defer gpa.destroy(t);
            t.init();
            n = try encodeFrame(null, buf, d.len, buf[0..d.len], dict_id, out, opts, t);
        } else n = try encodeFrame(null, buf, d.len, buf[0..d.len], dict_id, out, opts, null);
    }
    return gpa.realloc(out, n);
}
