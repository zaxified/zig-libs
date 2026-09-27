// SPDX-License-Identifier: BSD-3-Clause AND MIT
//! The seekable format (libzstd 1.5.7 `contrib/seekable_format`,
//! `zstdseek_compress.c` / `zstdseek_decompress.c`): the data cut into
//! independent frames, each of at most `max_frame_size` bytes, followed by
//! a skippable frame holding a seek table -- per frame its compressed and
//! decompressed size and, optionally, the low 32 bits of the XXH64 of its
//! content. Any zstd decoder reads the whole (`zstd -d` gives the input
//! back: the table is a skippable frame); `Seekable` reads any byte range
//! by decoding only the frames it touches.
//!
//! The compressor is `ZSTD_seekable_CStream`: a `Stream` at the level (single
//! threaded, the size hint set to `max_frame_size`), a frame ended whenever
//! `max_frame_size` bytes went in or the caller asks, the table written by
//! `endStream` -- also into an output buffer too small for it, across calls.
//! Its bytes are libzstd's for the same calls (`testdata/seekable_goldens.zig`,
//! from `tools/zseekable.c`).
//!
//! Deliberate differences from the C (see SPEC.md, *Seekable format*):
//! an offset at or past the end decodes nothing (the C computes a wrapped
//! length); a frame index out of range is `error.FrameIndexTooLarge` for
//! every query (the C's decompressed-size query reads one entry past its
//! table for the index equal to the frame count); the table's size is
//! computed in 64 bits (the C's 32-bit product wraps for a forged frame
//! count, and the file is refused either way).

const std = @import("std");
const stream_mod = @import("stream.zig");
const dstream = @import("dstream.zig");

pub const InBuffer = stream_mod.InBuffer;
pub const OutBuffer = stream_mod.OutBuffer;

/// `ZSTD_SEEKABLE_MAGICNUMBER`: the table's last four bytes.
pub const magic_number: u32 = 0x8F92EAB1;
/// `ZSTD_MAGIC_SKIPPABLE_START | 0xE`: the skippable frame holding the table.
pub const skippable_magic: u32 = 0x184D2A5E;
/// `ZSTD_seekTableFooterSize`.
pub const footer_size = 9;
const skippable_header_size = 8;
/// `ZSTD_SEEKABLE_MAXFRAMES`.
pub const max_frames: u32 = 0x8000000;
/// `ZSTD_SEEKABLE_MAX_FRAME_DECOMPRESSED_SIZE`: 1 GiB, also the default
/// `max_frame_size`.
pub const max_frame_decompressed_size: u32 = 0x40000000;
/// `SEEKABLE_BUFF_SIZE` (`ZSTD_BLOCKSIZE_MAX`).
const buff_size = 128 * 1024;
/// `ZSTD_SEEKABLE_NO_OUTPUT_PROGRESS_MAX`.
const no_output_progress_max = 16;

pub const CompressError = error{
    /// `max_frame_size` above 1 GiB (`frameParameter_unsupported`).
    FrameParameterUnsupported,
    /// More than `max_frames` frames (`frameIndex_tooLarge`).
    FrameIndexTooLarge,
} || stream_mod.Error;

pub const Options = struct {
    level: i32 = 3,
    /// Store the low 32 bits of each frame's XXH64 in the seek table
    /// (`checksumFlag`); `Seekable` then verifies every frame it finishes.
    frame_checksums: bool = false,
    /// Start a new frame after this many input bytes; 0 means 1 GiB
    /// (`maxFrameSize`). Frames of about the access granularity: a byte is
    /// read by decoding its whole frame; under ~1 KiB the ratio suffers.
    max_frame_size: u32 = 0,
};

/// A seek-table entry as written (`framelogEntry_t`).
pub const LogEntry = struct { c_size: u32, d_size: u32, checksum: u32 };

/// `ZSTD_frameLog`: the frames written so far, and the table streamed out
/// of them -- usable on its own to add a seek table to frames made
/// elsewhere (`ZSTD_seekable_logFrame`, `ZSTD_seekable_writeSeekTable`).
pub const FrameLog = struct {
    entries: std.ArrayList(LogEntry) = .empty,
    checksum_flag: bool,
    /// How much of the table is written, and which entry is next.
    seek_table_pos: u32 = 0,
    seek_table_index: u32 = 0,

    pub fn init(checksum_flag: bool) FrameLog {
        return .{ .checksum_flag = checksum_flag };
    }

    pub fn deinit(fl: *FrameLog, gpa: std.mem.Allocator) void {
        fl.entries.deinit(gpa);
    }

    /// `ZSTD_seekable_logFrame`.
    pub fn logFrame(fl: *FrameLog, gpa: std.mem.Allocator, compressed_size: u32, decompressed_size: u32, checksum: u32) CompressError!void {
        if (fl.entries.items.len == max_frames) return error.FrameIndexTooLarge;
        try fl.entries.append(gpa, .{ .c_size = compressed_size, .d_size = decompressed_size, .checksum = checksum });
    }

    /// The table's whole size, skippable header included.
    pub fn seekTableSize(fl: *const FrameLog) usize {
        const per_frame: usize = if (fl.checksum_flag) 12 else 8;
        return skippable_header_size + per_frame * fl.entries.items.len + footer_size;
    }

    /// `ZSTD_stwrite32`: the part of the word at `offset` not yet written;
    /// null when it is written, else how much of the table is left.
    fn write32(fl: *FrameLog, out: *OutBuffer, value: u32, offset: u32) ?usize {
        if (fl.seek_table_pos < offset + 4) {
            var tmp: [4]u8 = undefined;
            std.mem.writeInt(u32, &tmp, value, .little);
            const len = @min(out.dst.len - out.pos, offset + 4 - fl.seek_table_pos);
            const from = fl.seek_table_pos - offset;
            @memcpy(out.dst[out.pos..][0..len], tmp[from..][0..len]);
            out.pos += len;
            fl.seek_table_pos += @intCast(len);
            if (len < 4) return fl.seekTableSize() - fl.seek_table_pos;
        }
        return null;
    }

    /// `ZSTD_seekable_writeSeekTable`: writes what fits of the table; 0 when
    /// all of it is out, else how many bytes remain (call again).
    pub fn writeSeekTable(fl: *FrameLog, out: *OutBuffer) usize {
        const per_frame: u32 = if (fl.checksum_flag) 12 else 8;
        const len: u32 = @intCast(fl.seekTableSize());
        if (fl.write32(out, skippable_magic, 0)) |left| return left;
        if (fl.write32(out, len - skippable_header_size, 4)) |left| return left;
        while (fl.seek_table_index < fl.entries.items.len) : (fl.seek_table_index += 1) {
            const e = fl.entries.items[fl.seek_table_index];
            const start = skippable_header_size + per_frame * fl.seek_table_index;
            if (fl.write32(out, e.c_size, start)) |left| return left;
            if (fl.write32(out, e.d_size, start + 4)) |left| return left;
            if (fl.checksum_flag) {
                if (fl.write32(out, e.checksum, start + 8)) |left| return left;
            }
        }
        if (fl.write32(out, @intCast(fl.entries.items.len), len - footer_size)) |left| return left;
        if (out.dst.len - out.pos < 1) return len - fl.seek_table_pos;
        if (fl.seek_table_pos < len - 4) {
            out.dst[out.pos] = @as(u8, @intFromBool(fl.checksum_flag)) << 7;
            out.pos += 1;
            fl.seek_table_pos += 1;
        }
        if (fl.write32(out, magic_number, len - 4)) |left| return left;
        std.debug.assert(fl.seek_table_pos == len);
        return 0;
    }
};

/// `ZSTD_seekable_CStream`.
pub const SeekableStream = struct {
    gpa: std.mem.Allocator,
    stream: stream_mod.Stream,
    stream_opts: stream_mod.Options,
    log: FrameLog,
    frame_c_size: u32 = 0,
    frame_d_size: u32 = 0,
    xxh: std.hash.XxHash64 = .init(0),
    max_frame_size: u32,
    writing_seek_table: bool = false,

    /// `ZSTD_seekable_createCStream` + `ZSTD_seekable_initCStream`.
    pub fn init(gpa: std.mem.Allocator, opts: Options) CompressError!SeekableStream {
        const max = try maxFrameSize(opts);
        const so: stream_mod.Options = .{ .level = opts.level, .src_size_hint = max };
        return .{
            .gpa = gpa,
            .stream = try .init(gpa, so),
            .stream_opts = so,
            .log = .init(opts.frame_checksums),
            .max_frame_size = max,
        };
    }

    pub fn deinit(s: *SeekableStream) void {
        s.stream.deinit();
        s.log.deinit(s.gpa);
    }

    fn maxFrameSize(opts: Options) CompressError!u32 {
        if (opts.max_frame_size > max_frame_decompressed_size) return error.FrameParameterUnsupported;
        return if (opts.max_frame_size != 0) opts.max_frame_size else max_frame_decompressed_size;
    }

    /// `ZSTD_seekable_initCStream` on a used stream: a new seekable
    /// stream with `opts`, the context's buffers kept.
    pub fn reset(s: *SeekableStream, opts: Options) CompressError!void {
        const max = try maxFrameSize(opts);
        s.log.entries.clearRetainingCapacity();
        s.log.checksum_flag = opts.frame_checksums;
        s.log.seek_table_pos = 0;
        s.log.seek_table_index = 0;
        s.frame_c_size = 0;
        s.frame_d_size = 0;
        s.xxh = .init(0);
        s.max_frame_size = max;
        s.writing_seek_table = false;
        s.stream_opts = .{ .level = opts.level, .src_size_hint = max };
        try s.stream.reset(s.stream_opts);
    }

    /// `ZSTD_seekable_compressStream`: takes input up to the frame's end
    /// (it may leave some -- present it again) and ends the frame when it
    /// is full; returns how much more input the frame takes.
    pub fn compressStream(s: *SeekableStream, out: *OutBuffer, in: *InBuffer) CompressError!usize {
        const avail = in.src[in.pos..];
        const in_len = @min(avail.len, s.max_frame_size - s.frame_d_size);
        if (in_len > 0) {
            var tmp: InBuffer = .{ .src = avail[0..in_len] };
            const prev_out = out.pos;
            const r = s.stream.compressStream2(out, &tmp, .@"continue");
            if (s.log.checksum_flag) s.xxh.update(avail[0..tmp.pos]);
            s.frame_c_size +%= @intCast(out.pos - prev_out);
            s.frame_d_size += @intCast(tmp.pos);
            in.pos += tmp.pos;
            _ = try r;
        }
        if (s.max_frame_size == s.frame_d_size) {
            _ = try s.endFrame(out);
            return s.max_frame_size;
        }
        return s.max_frame_size - s.frame_d_size;
    }

    /// `ZSTD_seekable_endFrame`: ends the current frame (0 when it is out
    /// and logged, else how much is left to flush -- call again) and starts
    /// the next.
    pub fn endFrame(s: *SeekableStream, out: *OutBuffer) CompressError!usize {
        const prev_out = out.pos;
        var empty: InBuffer = .{ .src = &.{} };
        const r = s.stream.compressStream2(out, &empty, .end);
        s.frame_c_size +%= @intCast(out.pos - prev_out);
        const left = try r;
        if (left != 0) return left;
        const checksum: u32 = if (s.log.checksum_flag) @truncate(s.xxh.final()) else 0;
        try s.log.logFrame(s.gpa, s.frame_c_size, s.frame_d_size, checksum);
        s.frame_c_size = 0;
        s.frame_d_size = 0;
        try s.stream.reset(s.stream_opts);
        if (s.log.checksum_flag) s.xxh = .init(0);
        return 0;
    }

    /// `ZSTD_seekable_endStream`: the last frame, then the seek table; 0
    /// when everything is out, else a size hint (call again).
    pub fn endStream(s: *SeekableStream, out: *OutBuffer) CompressError!usize {
        if (!s.writing_seek_table) {
            const left = try s.endFrame(out);
            if (left != 0) return left + s.log.seekTableSize();
        }
        s.writing_seek_table = true;
        return s.log.writeSeekTable(out);
    }
};

/// The whole of `src` as one seekable stream: frames of `max_frame_size`
/// and the seek table, in one allocation.
pub fn compressAlloc(gpa: std.mem.Allocator, src: []const u8, opts: Options) CompressError![]u8 {
    var s: SeekableStream = try .init(gpa, opts);
    defer s.deinit();
    var dst: std.ArrayList(u8) = .empty;
    errdefer dst.deinit(gpa);
    var buf: [64 * 1024]u8 = undefined;
    var in: InBuffer = .{ .src = src };
    while (in.pos < in.src.len) {
        var out: OutBuffer = .{ .dst = &buf };
        _ = try s.compressStream(&out, &in);
        try dst.appendSlice(gpa, buf[0..out.pos]);
    }
    while (true) {
        var out: OutBuffer = .{ .dst = &buf };
        const left = try s.endStream(&out);
        try dst.appendSlice(gpa, buf[0..out.pos]);
        if (left == 0) break;
    }
    return dst.toOwnedSlice(gpa);
}

// ---------------------------------------------------------------- reading

pub const ReadError = error{
    /// The source could not deliver the bytes asked (`seekableIO`).
    SeekableIO,
    /// No seek table at the end (`prefix_unknown`).
    PrefixUnknown,
    /// Reserved bits set, or a frame's content does not match its
    /// checksum (`corruption_detected`).
    CorruptionDetected,
    FrameIndexTooLarge,
    DstSizeTooSmall,
    OutOfMemory,
} || dstream.Error;

/// Where `Seekable` reads from (`ZSTD_seekable_customFile`, as positional
/// reads): bytes in memory (`ZSTD_seekable_initBuff`), a file through
/// `std.Io` (`ZSTD_seekable_initFile`), or the caller's own reader. Each
/// must outlive the `Seekable`.
pub const Source = union(enum) {
    bytes: []const u8,
    file: File,
    custom: Custom,

    pub const File = struct {
        file: std.Io.File,
        io: std.Io,
    };

    /// `readAt` fills all of `buf` from `offset` or fails.
    pub const Custom = struct {
        context: *anyopaque,
        size: u64,
        readAt: *const fn (context: *anyopaque, buf: []u8, offset: u64) error{ReadFailed}!void,
    };

    fn length(src: Source) error{ReadFailed}!u64 {
        return switch (src) {
            .bytes => |b| b.len,
            .file => |f| f.file.length(f.io) catch error.ReadFailed,
            .custom => |c| c.size,
        };
    }

    fn readAt(src: Source, buf: []u8, offset: u64) error{ReadFailed}!void {
        switch (src) {
            .bytes => |b| {
                if (offset > b.len or buf.len > b.len - offset) return error.ReadFailed;
                @memcpy(buf, b[@intCast(offset)..][0..buf.len]);
            },
            .file => |f| {
                const n = f.file.readPositionalAll(f.io, buf, offset) catch return error.ReadFailed;
                if (n != buf.len) return error.ReadFailed;
            },
            .custom => |c| try c.readAt(c.context, buf, offset),
        }
    }
};

/// A seek-table entry as read: where a frame starts, compressed and
/// decompressed (`seekEntry_t`).
pub const SeekEntry = struct { c_offset: u64, d_offset: u64, checksum: u32 };

/// `ZSTD_seekTable`: `entries` has one more element than there are frames,
/// holding the totals, so every frame's size is a difference.
pub const SeekTable = struct {
    entries: []SeekEntry,
    checksum_flag: bool,

    pub fn deinit(t: *SeekTable, gpa: std.mem.Allocator) void {
        gpa.free(t.entries);
    }

    /// `ZSTD_seekTable_create_fromSeekable`.
    pub fn dupe(t: *const SeekTable, gpa: std.mem.Allocator) error{OutOfMemory}!SeekTable {
        return .{ .entries = try gpa.dupe(SeekEntry, t.entries), .checksum_flag = t.checksum_flag };
    }

    pub fn numFrames(t: *const SeekTable) u32 {
        return @intCast(t.entries.len - 1);
    }

    pub fn frameCompressedOffset(t: *const SeekTable, index: u32) error{FrameIndexTooLarge}!u64 {
        if (index >= t.numFrames()) return error.FrameIndexTooLarge;
        return t.entries[index].c_offset;
    }

    pub fn frameDecompressedOffset(t: *const SeekTable, index: u32) error{FrameIndexTooLarge}!u64 {
        if (index >= t.numFrames()) return error.FrameIndexTooLarge;
        return t.entries[index].d_offset;
    }

    pub fn frameCompressedSize(t: *const SeekTable, index: u32) error{FrameIndexTooLarge}!u64 {
        if (index >= t.numFrames()) return error.FrameIndexTooLarge;
        return t.entries[index + 1].c_offset - t.entries[index].c_offset;
    }

    pub fn frameDecompressedSize(t: *const SeekTable, index: u32) error{FrameIndexTooLarge}!u64 {
        if (index >= t.numFrames()) return error.FrameIndexTooLarge;
        return t.entries[index + 1].d_offset - t.entries[index].d_offset;
    }

    /// The decompressed size of the whole.
    pub fn decompressedSize(t: *const SeekTable) u64 {
        return t.entries[t.entries.len - 1].d_offset;
    }

    /// `ZSTD_seekTable_offsetToFrameIndex`: the last frame starting at or
    /// before `pos`; the frame count when `pos` is past the end.
    pub fn offsetToFrameIndex(t: *const SeekTable, pos: u64) u32 {
        const n = t.numFrames();
        if (pos >= t.entries[n].d_offset) return n;
        var lo: u32 = 0;
        var hi: u32 = n;
        while (lo + 1 < hi) {
            const mid = lo + ((hi - lo) >> 1);
            if (t.entries[mid].d_offset <= pos) lo = mid else hi = mid;
        }
        return lo;
    }

    /// `ZSTD_seekable_loadSeekTable`: the table at the end of `src`.
    pub fn load(gpa: std.mem.Allocator, src: Source) ReadError!SeekTable {
        const src_size = src.length() catch return error.SeekableIO;
        var foot: [footer_size]u8 = undefined;
        if (src_size < footer_size) return error.SeekableIO;
        src.readAt(&foot, src_size - footer_size) catch return error.SeekableIO;
        if (std.mem.readInt(u32, foot[5..9], .little) != magic_number) return error.PrefixUnknown;
        const sfd = foot[4];
        const checksum_flag = sfd >> 7 != 0;
        if ((sfd >> 2) & 0x1f != 0) return error.CorruptionDetected;
        const num_frames = std.mem.readInt(u32, foot[0..4], .little);
        const per_entry: u64 = if (checksum_flag) 12 else 8;
        const frame_size: u64 = per_entry * num_frames + footer_size + skippable_header_size;
        if (frame_size > src_size) return error.SeekableIO;
        const start = src_size - frame_size;
        var head: [skippable_header_size]u8 = undefined;
        src.readAt(&head, start) catch return error.SeekableIO;
        if (std.mem.readInt(u32, head[0..4], .little) != skippable_magic) return error.PrefixUnknown;
        if (@as(u64, std.mem.readInt(u32, head[4..8], .little)) + skippable_header_size != frame_size) return error.PrefixUnknown;

        const entries = try gpa.alloc(SeekEntry, @as(usize, num_frames) + 1);
        errdefer gpa.free(entries);
        var buf: [buff_size]u8 = undefined;
        const per: usize = @intCast(per_entry);
        const per_chunk = buf.len / per;
        var c: u64 = 0;
        var d: u64 = 0;
        var idx: usize = 0;
        var pos: u64 = start + skippable_header_size;
        while (idx < num_frames) {
            const n = @min(per_chunk, num_frames - idx);
            const chunk = buf[0 .. n * per];
            src.readAt(chunk, pos) catch return error.SeekableIO;
            pos += chunk.len;
            for (0..n) |k| {
                const e = chunk[k * per ..];
                entries[idx] = .{
                    .c_offset = c,
                    .d_offset = d,
                    .checksum = if (checksum_flag) std.mem.readInt(u32, e[8..12], .little) else 0,
                };
                c += std.mem.readInt(u32, e[0..4], .little);
                d += std.mem.readInt(u32, e[4..8], .little);
                idx += 1;
            }
        }
        entries[num_frames] = .{ .c_offset = c, .d_offset = d, .checksum = 0 };
        return .{ .entries = entries, .checksum_flag = checksum_flag };
    }
};

/// `ZSTD_seekable`: random access into a seekable stream.
pub const Seekable = struct {
    gpa: std.mem.Allocator,
    dstream: dstream.DecompressStream,
    table: SeekTable,
    src: Source,
    src_size: u64,
    /// Where the next read from `src` starts (the C's file position).
    src_pos: u64 = 0,
    decompressed_offset: u64 = std.math.maxInt(u64),
    cur_frame: u32 = std.math.maxInt(u32),
    /// One allocation: `in_buf` then `out_buf`.
    bufs: []u8,
    in_buf: []u8,
    out_buf: []u8,
    in_pos: usize = 0,
    in_len: usize = 0,
    xxh: std.hash.XxHash64 = .init(0),
    /// In-memory mode (`buffWrapper.size`): guards against a table whose
    /// frames reach past the data.
    mem_size: ?u64,

    /// `ZSTD_seekable_initAdvanced`: reads the seek table from `src`.
    pub fn init(gpa: std.mem.Allocator, src: Source) ReadError!Seekable {
        var table = try SeekTable.load(gpa, src);
        errdefer table.deinit(gpa);
        const bufs = try gpa.alloc(u8, 2 * buff_size);
        errdefer gpa.free(bufs);
        return .{
            .gpa = gpa,
            .dstream = try .init(gpa, .{}),
            .table = table,
            .src = src,
            .src_size = src.length() catch return error.SeekableIO,
            .bufs = bufs,
            .in_buf = bufs[0..buff_size],
            .out_buf = bufs[buff_size..],
            .mem_size = if (src == .bytes) src.bytes.len else null,
        };
    }

    pub fn deinit(s: *Seekable) void {
        s.dstream.deinit();
        s.table.deinit(s.gpa);
        s.gpa.free(s.bufs);
    }

    pub fn numFrames(s: *const Seekable) u32 {
        return s.table.numFrames();
    }

    /// `ZSTD_seekable_decompress`: fills `dst` from decompressed `offset`
    /// (stopping at the end of the data); returns how many bytes. Reading
    /// on where the last call stopped continues the frame instead of
    /// decoding it again from its start.
    pub fn decompress(s: *Seekable, dst: []u8, offset: u64) ReadError!usize {
        const eos = s.table.decompressedSize();
        if (offset >= eos) return 0;
        const len: usize = @intCast(@min(dst.len, eos - offset));
        const end = offset + len;
        var target = s.table.offsetToFrameIndex(offset);
        var no_progress: u32 = 0;
        var src_read: u64 = 0;
        while (true) {
            if (target != s.cur_frame or offset < s.decompressed_offset) {
                s.decompressed_offset = s.table.entries[target].d_offset;
                s.cur_frame = target;
                s.src_pos = s.table.entries[target].c_offset;
                if (s.src_pos > s.src_size) return error.SeekableIO;
                s.in_pos = 0;
                s.in_len = 0;
                s.xxh = .init(0);
                s.dstream.reset();
                if (s.mem_size) |m| if (src_read > m) return error.SeekableIO;
            }
            while (s.decompressed_offset < end) {
                var out: OutBuffer = if (s.decompressed_offset < offset)
                    .{ .dst = s.out_buf[0..@intCast(@min(buff_size, offset - s.decompressed_offset))] }
                else
                    .{ .dst = dst[0..len], .pos = @intCast(s.decompressed_offset - offset) };
                const prev_out = out.pos;
                const prev_in = s.in_pos;
                var in: InBuffer = .{ .src = s.in_buf[0..s.in_len], .pos = s.in_pos };
                var to_read = try s.dstream.decompressStream(&out, &in);
                s.in_pos = in.pos;
                if (s.table.checksum_flag) s.xxh.update(out.dst[prev_out..out.pos]);
                const progress = out.pos - prev_out;
                if (progress == 0) {
                    no_progress += 1;
                    if (no_progress > no_output_progress_max + 1) return error.SeekableIO;
                } else no_progress = 0;
                s.decompressed_offset += progress;
                src_read += s.in_pos - prev_in;
                if (to_read == 0) {
                    if (s.table.checksum_flag and @as(u32, @truncate(s.xxh.final())) != s.table.entries[target].checksum)
                        return error.CorruptionDetected;
                    if (s.decompressed_offset < end) target = s.table.offsetToFrameIndex(s.decompressed_offset);
                    break;
                }
                if (s.in_pos == s.in_len) {
                    to_read = @min(to_read, buff_size);
                    s.src.readAt(s.in_buf[0..to_read], s.src_pos) catch return error.SeekableIO;
                    s.src_pos += to_read;
                    s.in_len = to_read;
                    s.in_pos = 0;
                }
            }
            if (s.decompressed_offset == end) break;
        }
        return len;
    }

    /// `ZSTD_seekable_decompressFrame`: all of frame `index` into `dst`.
    pub fn decompressFrame(s: *Seekable, dst: []u8, index: u32) ReadError!usize {
        if (index >= s.table.numFrames()) return error.FrameIndexTooLarge;
        const size = s.table.entries[index + 1].d_offset - s.table.entries[index].d_offset;
        if (dst.len < size) return error.DstSizeTooSmall;
        return s.decompress(dst[0..@intCast(size)], s.table.entries[index].d_offset);
    }
};
