// SPDX-License-Identifier: MIT
//! zipstream — streaming ZIP archive reader.
//!
//! Walks the central directory once and exposes each member as an on-demand
//! streaming reader over its *decompressed* bytes — no whole-archive or
//! whole-entry materialisation. A consumer's memory ceiling is therefore
//! O(one decompression window) regardless of archive or entry size.
//!
//! Reads the LOCAL file header directly for its own filename/extra lengths to
//! locate the compressed data, so a central-vs-local `version_needed`
//! mismatch some writers emit is irrelevant — no header patching is needed.
//! Store + Deflate only (the two methods Excel and ordinary zip tools emit);
//! an entry with any other method, or encrypted, is listed but refused when
//! opened (`error.UnsupportedCompressionMethod` / `error.ZipEncryptedEntry`).
//!
//! Lifetime contract: both `Archive` and `EntryReader` hold internal
//! self-pointers (the file reader's `interface`, the inflate stream's input
//! handle), so both are initialised in place via a `*Self` and must not be
//! moved after `init`. One `Archive` drives one file cursor — stream an
//! `EntryReader` to completion (or abandon it) before opening the next entry.
//!
//! zip64 archives/entries (> 4 GiB, or > 65535 central-directory records) are
//! supported for *reading* (zip64 end record + locator, the per-entry zip64
//! extra field) — nothing in this module's read path is 32-bit-limited. The
//! central directory is walked by this module (`findDirectory`, `parseExtra`),
//! not `std.zip.Iterator`, whose strictness refused archives `unzip` and Go
//! read (see `Archive.init`). `ArchiveWriter` (below) writes classic (non-zip64) archives
//! only; see its doc comment.
//!
//! Ceiling (documented, not a bug): no encrypted entries, no compression
//! methods beyond Store/Deflate. See README.md.
//!
//! Untrusted-archive extraction contract: like `tar`, this reader surfaces each
//! member's stored `name` verbatim and never writes to disk itself — it does
//! NOT sanitise paths. A caller that extracts entries to the filesystem MUST
//! reject unsafe names with `isSafeEntryName` (or otherwise confine the write to
//! a target directory), else a hostile archive escapes the extraction root via
//! `../` traversal / absolute / drive paths (the classic "zip slip"). Reading an
//! entry's bytes is separately bounded by `EntryReader.initMax`'s output cap so a
//! decompression bomb cannot expand unboundedly.

const std = @import("std");
const builtin = @import("builtin");
const zstd = @import("zstd");
/// Hardware-backed CRC-32 (the sibling module; std's is table-driven, ~0.4 GB/s).
const crc32 = @import("crc32");
const encoding = @import("encoding");
const crypto = @import("crypto.zig");

/// WinZip AES key strength.
pub const AesStrength = crypto.Strength;
const Allocator = std.mem.Allocator;

/// The ZIP wire format is little-endian throughout; on a big-endian host the
/// writer byte-swaps each header struct before writing it (mirroring how
/// `std.zip`'s reader side byte-swaps after reading — see its `is_le` check).
const native_endian_is_le = builtin.target.cpu.arch.endian() == .little;

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Streaming ZIP archive reader — walks the central directory once, streams decompressed member bytes on demand.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{ .linux64, .windows },
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "APPNOTE.TXT ZIP central-directory streaming reader",
    .deps = .{ "zstd", "aes192", "encoding", "crc32" },
};

/// Buffer the file reader uses for compressed bytes pulled from disk.
const READER_BUF_SIZE = 64 * 1024;

/// Default hard cap on a single entry's decompressed size (`EntryReader.init`),
/// guarding against a decompression bomb — a tiny deflate stream that expands to
/// gigabytes. A caller that legitimately needs larger entries raises it via
/// `EntryReader.initMax`.
pub const default_max_output: u64 = 1 << 30; // 1 GiB

pub const Error = error{
    UnsupportedCompressionMethod,
    ZipNameTooLong,
    ZipBadFileOffset,
    ZipBadCentralDirectory,
    /// An entry's declared uncompressed size exceeds the caller's output cap
    /// (`EntryReader.initMax`) — refused up front, no unbounded decompression.
    ZipEntryTooLarge,
    /// WRITE: `ArchiveWriter.addEntry`'s name failed the same zip-slip guard
    /// as the reader side (`isSafeEntryName`).
    ZipUnsafeEntryName,
    /// WRITE: an entry's size, or the archive's running offset/central-
    /// directory size/entry count, would overflow one of the classic
    /// (non-zip64) 32/16-bit ZIP fields. `ArchiveWriter` doesn't emit zip64
    /// records — see its doc comment.
    ZipWriteTooLarge,
    /// READ: `EntryReader.init` on an entry whose encryption flag is set.
    ZipEncryptedEntry,
    /// READ: no end-of-central-directory record (a truncated file, or not a
    /// ZIP archive at all). The same name `std.zip` gives it.
    ZipNoEndRecord,
};

/// A compression method beyond Store and Deflate, as a pair of factories —
/// Go's `RegisterDecompressor` / `RegisterCompressor`. Built in: Zstandard
/// (`zstd_codec`, method 93). A consumer plugs in another (bzip2, LZMA, …)
/// through `Archive.Options.codecs` and `AddEntryOptions.codec`.
pub const Codec = struct {
    /// The APPNOTE method id written to and matched in the headers.
    method: u16,
    context: ?*anyopaque = null,
    /// A decompressor reading the entry's compressed bytes from `input`
    /// (which ends where the entry's data ends).
    open_reader: ?*const fn (context: ?*anyopaque, gpa: Allocator, input: *std.Io.Reader) anyerror!CodecReader = null,
    /// A compressor writing to `output`; `level` 0 is the codec's default.
    open_writer: ?*const fn (context: ?*anyopaque, gpa: Allocator, output: *std.Io.Writer, level: i32) anyerror!CodecWriter = null,
};

pub const CodecReader = struct {
    reader: *std.Io.Reader,
    state: *anyopaque,
    close: *const fn (state: *anyopaque, gpa: Allocator) void,
};

pub const CodecWriter = struct {
    writer: *std.Io.Writer,
    state: *anyopaque,
    /// Ends the compressed stream (everything written reaches `output`).
    finish: *const fn (state: *anyopaque) anyerror!void,
    close: *const fn (state: *anyopaque, gpa: Allocator) void,
};

/// Zstandard (method 93) through the sibling `zstd` module: frames of any
/// window up to its default `window_log_max` (128 MiB) are read; written at
/// the level given (0 = zstd's default, 3), with the content checksum off
/// (the entry has its CRC-32), as zip2 and libzip write it.
pub const zstd_codec: Codec = .{
    .method = 93,
    .open_reader = ZstdCodec.openReader,
    .open_writer = ZstdCodec.openWriter,
};

const ZstdCodec = struct {
    const R = struct { r: zstd.DecompressReader };
    const W = struct { w: zstd.StreamWriter, buf: [4096]u8 };

    fn openReader(_: ?*anyopaque, gpa: Allocator, input: *std.Io.Reader) anyerror!CodecReader {
        const s = try gpa.create(R);
        errdefer gpa.destroy(s);
        s.r = try zstd.DecompressReader.init(gpa, input, &.{}, .{});
        return .{ .reader = &s.r.interface, .state = s, .close = closeReader };
    }

    fn closeReader(state: *anyopaque, gpa: Allocator) void {
        const s: *R = @ptrCast(@alignCast(state));
        s.r.deinit();
        gpa.destroy(s);
    }

    fn openWriter(_: ?*anyopaque, gpa: Allocator, output: *std.Io.Writer, level: i32) anyerror!CodecWriter {
        const s = try gpa.create(W);
        errdefer gpa.destroy(s);
        s.w = try zstd.StreamWriter.init(gpa, output, &s.buf, .{ .level = if (level == 0) zstd.default_level else level });
        return .{ .writer = &s.w.writer, .state = s, .finish = finishWriter, .close = closeWriter };
    }

    fn finishWriter(state: *anyopaque) anyerror!void {
        const s: *W = @ptrCast(@alignCast(state));
        try s.w.finish();
    }

    fn closeWriter(state: *anyopaque, gpa: Allocator) void {
        const s: *W = @ptrCast(@alignCast(state));
        s.w.deinit();
        gpa.destroy(s);
    }
};

const builtin_codecs = [_]Codec{zstd_codec};

/// One archive member. `name` is owned by the parent `Archive` (its name
/// arena) and stays valid until `Archive.deinit`. Backslashes in the stored
/// path are normalised to '/'. The name is otherwise UNSANITISED — a consumer
/// that extracts to disk must gate it through `isSafeEntryName` (see the
/// module's extraction contract).
pub const Entry = struct {
    name: []const u8,
    compression: std.zip.CompressionMethod,
    compressed_size: u64,
    uncompressed_size: u64,
    /// Offset of this entry's local file header within the archive.
    file_offset: u64,
    /// CRC-32 of the *uncompressed* content, from the central directory (not
    /// the local header — the local header's own copy is zero when the
    /// writer used a post-data data descriptor, e.g. real-world streaming
    /// writers like LibreOffice; the central directory's copy is always
    /// authoritative, written after all data). Verified automatically by
    /// `EntryReader` at end-of-stream — see its doc comment.
    crc32: u32,
    /// Last modification time, Unix seconds (UTC). Taken from the Info-ZIP
    /// extended-timestamp extra field (`UT`, 0x5455) when the central
    /// directory carries one — that is a real UTC instant — else from the
    /// DOS date/time fields, which carry no zone and are read as UTC. Null
    /// when neither holds a valid time (a DOS date of 0, as some writers
    /// emit).
    mtime: ?i64 = null,
    /// Unix permission bits (`0o7777` mask) when the entry was made on a Unix
    /// host (`version made by` host 3) and carries them in the high half of
    /// its external attributes; null otherwise.
    mode: ?u16 = null,
    /// General-purpose flag bit 0: the content is encrypted. Listed so the
    /// rest of the archive stays readable; `EntryReader.init` refuses it
    /// (`error.ZipEncryptedEntry`) -- this module does not decrypt.
    encrypted: bool = false,
    /// The entry comment (central directory), raw bytes; owned by the archive.
    comment: []const u8 = "",
    /// The central directory's extra field, raw (Go `FileHeader.Extra`,
    /// Python `ZipInfo.extra`); owned by the archive.
    extra: []const u8 = "",
    /// General-purpose flags as stored.
    flags: u16 = 0,
    /// `version made by` (high byte: the host, 3 = Unix) and the external
    /// attributes as stored — `isSymlink`/`isDirectory` read them.
    version_made_by: u16 = 0,
    external_attributes: u32 = 0,
    /// The name is UTF-8: flag bit 11 was set, or the Info-ZIP Unicode Path
    /// extra field (0x7075) supplied it. Otherwise the name is the stored
    /// bytes, in whatever code page the writer used (APPNOTE: IBM 437).
    name_is_utf8: bool = false,
    /// A directory entry (name ends in '/'); listed only with
    /// `Archive.Options.list_directories`.
    is_directory: bool = false,
    /// WinZip AES (extra 0x9901): strength, AE version and the real method
    /// (`compression` is then 99). Null for ZipCrypto or no encryption.
    aes: ?crypto.AesInfo = null,
    /// The DOS time field as stored (ZipCrypto's check byte with flag bit 3).
    dos_time: u16 = 0,

    /// The compression method under any encryption.
    pub fn method(self: *const Entry) u16 {
        return if (self.aes) |a| a.method else @backingInt(self.compression);
    }

    /// A Unix symlink entry (`S_IFLNK` in the external attributes' high
    /// half); its content is the link target.
    pub fn isSymlink(self: *const Entry) bool {
        return self.version_made_by >> 8 == host_unix and (self.external_attributes >> 16) & 0o170000 == 0o120000;
    }
};

/// A DOS date/time pair as ZIP headers store it (APPNOTE 4.4.6): `time` =
/// hour<<11 | minute<<5 | second/2, `date` = (year-1980)<<9 | month<<5 | day.
pub const DosDateTime = struct {
    time: u16,
    date: u16,

    /// 1980-01-01 00:00:00, the earliest DOS time — what `ArchiveWriter`
    /// writes when no `mtime` is given. (A zero date, which it wrote before
    /// 2026-09-30, is not a valid date: unzip tools list it as garbage.)
    pub const min: DosDateTime = .{ .time = 0, .date = (1 << 5) | 1 };
    /// 2107-12-31 23:59:58, the latest.
    pub const max: DosDateTime = .{ .time = (23 << 11) | (59 << 5) | 29, .date = (127 << 9) | (12 << 5) | 31 };

    /// The DOS fields for a Unix time, in UTC. Clamped to the representable
    /// range (1980..2107) and rounded down to an even second.
    pub fn fromUnix(secs: i64) DosDateTime {
        const lo: i64 = 315532800; // 1980-01-01T00:00:00Z
        const hi: i64 = 4354819198; // 2107-12-31T23:59:58Z
        if (secs <= lo) return min;
        if (secs >= hi) return max;
        const days = @divFloor(secs, 86400);
        const sod: u32 = @intCast(secs - days * 86400);
        const c = civilFromDays(days);
        return .{
            .time = @intCast((sod / 3600) << 11 | ((sod / 60) % 60) << 5 | (sod % 60) / 2),
            .date = @intCast(@as(u32, @intCast(c.year - 1980)) << 9 | @as(u32, c.month) << 5 | c.day),
        };
    }

    /// The Unix time (UTC) these fields name, or null when they are not a
    /// valid date and time (month 0, day 31 of April, hour 24, …).
    pub fn toUnix(self: DosDateTime) ?i64 {
        const year: i32 = 1980 + @as(i32, self.date >> 9);
        const month: u8 = @intCast((self.date >> 5) & 0xf);
        const day: u8 = @intCast(self.date & 0x1f);
        const hour: u32 = self.time >> 11;
        const minute: u32 = (self.time >> 5) & 0x3f;
        const second: u32 = (self.time & 0x1f) * 2;
        if (month < 1 or month > 12 or day < 1) return null;
        if (day > daysInMonth(year, month)) return null;
        if (hour > 23 or minute > 59 or second > 59) return null;
        return daysFromCivil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second;
    }
};

fn isLeap(y: i32) bool {
    return @mod(y, 4) == 0 and (@mod(y, 100) != 0 or @mod(y, 400) == 0);
}

fn daysInMonth(y: i32, m: u8) u8 {
    return switch (m) {
        2 => if (isLeap(y)) 29 else 28,
        4, 6, 9, 11 => 30,
        else => 31,
    };
}

/// Days since 1970-01-01 for a proleptic-Gregorian date (H. Hinnant's
/// `days_from_civil`).
fn daysFromCivil(y_in: i32, m: u8, d: u8) i64 {
    const y: i64 = if (m <= 2) y_in - 1 else y_in;
    const era = @divFloor(y, 400);
    const yoe = y - era * 400;
    const mp: i64 = if (m > 2) m - 3 else m + 9;
    const doy = @divFloor(153 * mp + 2, 5) + d - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

/// The inverse of `daysFromCivil` (Hinnant's `civil_from_days`).
fn civilFromDays(z_in: i64) struct { year: i32, month: u8, day: u8 } {
    const z = z_in + 719468;
    const era = @divFloor(z, 146097);
    const doe = z - era * 146097;
    const yoe = @divFloor(doe - @divFloor(doe, 1460) + @divFloor(doe, 36524) - @divFloor(doe, 146096), 365);
    const doy = doe - (365 * yoe + @divFloor(yoe, 4) - @divFloor(yoe, 100));
    const mp = @divFloor(5 * doy + 2, 153);
    const d: u8 = @intCast(doy - @divFloor(153 * mp + 2, 5) + 1);
    const m: u8 = @intCast(if (mp < 10) mp + 3 else mp - 9);
    const y = yoe + era * 400 + @as(i64, if (m <= 2) 1 else 0);
    return .{ .year = @intCast(y), .month = m, .day = d };
}

/// Info-ZIP extended timestamp extra field id ("UT").
const extra_id_ut: u16 = 0x5455;
/// `version made by` host byte for Unix (APPNOTE 4.4.2).
const host_unix: u16 = 3;
/// `S_IFREG`, the regular-file type bits Info-ZIP puts above the permissions.
const unix_regular_file: u32 = 0o100000;

/// Where an archive's bytes come from: anything that can read at an offset
/// (Go's `io.ReaderAt` + size, zip2's `Read + Seek`). `readAt` must be safe
/// to call from several threads at once when entries are read concurrently
/// — a file (`pread`) and a memory slice are.
pub const Source = struct {
    context: *const anyopaque,
    read_at: *const fn (context: *const anyopaque, offset: u64, buf: []u8) error{ReadFailed}!usize,
    size: u64,

    /// Fill `buf` from `offset` as far as the source allows; fewer bytes
    /// only at the end of the source.
    pub fn readAt(self: Source, offset: u64, buf: []u8) error{ReadFailed}!usize {
        return self.read_at(self.context, offset, buf);
    }
};

/// A file as a `Source` (positional reads: `pread`, thread-safe). Keep it
/// alive as long as the `Source` it hands out.
pub const FileSource = struct {
    io: std.Io,
    file: std.Io.File,
    size: u64,

    pub fn init(io: std.Io, file: std.Io.File) !FileSource {
        const st = file.stat(io) catch return Error.ZipBadCentralDirectory;
        return .{ .io = io, .file = file, .size = st.size };
    }

    pub fn source(self: *const FileSource) Source {
        return .{ .context = self, .read_at = readAt, .size = self.size };
    }

    fn readAt(context: *const anyopaque, offset: u64, buf: []u8) error{ReadFailed}!usize {
        const self: *const FileSource = @ptrCast(@alignCast(context));
        return self.file.readPositionalAll(self.io, buf, offset) catch error.ReadFailed;
    }
};

/// A memory slice as a `Source`; keep it alive as long as the `Source`.
pub const MemorySource = struct {
    bytes: []const u8,

    pub fn source(self: *const MemorySource) Source {
        return .{ .context = self, .read_at = readAt, .size = self.bytes.len };
    }

    fn readAt(context: *const anyopaque, offset: u64, buf: []u8) error{ReadFailed}!usize {
        const self: *const MemorySource = @ptrCast(@alignCast(context));
        if (offset >= self.bytes.len) return 0;
        const n = @min(buf.len, self.bytes.len - @as(usize, @intCast(offset)));
        @memcpy(buf[0..n], self.bytes[@intCast(offset)..][0..n]);
        return n;
    }
};

/// A buffered `std.Io.Reader` over a `Source` with its own position — one
/// per reader, so readers of the same archive never share a cursor.
const SourceReader = struct {
    src: Source,
    /// Source offset of the next byte the buffer will be filled from.
    pos: u64,
    interface: std.Io.Reader,

    fn init(src: Source, buffer: []u8, offset: u64) SourceReader {
        return .{
            .src = src,
            .pos = offset,
            .interface = .{ .vtable = &.{ .stream = stream, .readVec = readVec }, .buffer = buffer, .seek = 0, .end = 0 },
        };
    }

    /// Refill the WHOLE buffer (unread bytes moved to its front). std's
    /// default read straight into the caller's slice whenever that slice was
    /// larger than the buffer's free tail — with a full buffer, every small
    /// read (each 46-byte header, each name) became its own `pread`: 3.5
    /// system calls per central-directory entry, 4× Go's open time.
    fn readVec(r: *std.Io.Reader, data: [][]u8) std.Io.Reader.Error!usize {
        const self: *SourceReader = @alignCast(@fieldParentPtr("interface", r));
        if (r.seek != 0) {
            const live = r.end - r.seek;
            std.mem.copyForwards(u8, r.buffer[0..live], r.buffer[r.seek..r.end]);
            r.seek = 0;
            r.end = live;
        }
        if (r.end == r.buffer.len) {
            // Buffer full of unread bytes: read into the caller's slice.
            const n = try self.src.readAt(self.pos, data[0]);
            if (n == 0) return error.EndOfStream;
            self.pos += n;
            return n;
        }
        const n = try self.src.readAt(self.pos, r.buffer[r.end..]);
        if (n == 0) return error.EndOfStream;
        self.pos += n;
        r.end += n;
        return 0;
    }

    fn seekTo(self: *SourceReader, offset: u64) void {
        self.pos = offset;
        self.interface.seek = 0;
        self.interface.end = 0;
    }

    fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *SourceReader = @alignCast(@fieldParentPtr("interface", r));
        const dest = limit.slice(try w.writableSliceGreedy(1));
        const n = try self.src.readAt(self.pos, dest);
        if (n == 0) return error.EndOfStream;
        self.pos += n;
        w.advance(n);
        return n;
    }
};

/// A central-directory-parsed ZIP archive. Borrows an already-open `File` (does
/// not close it); owns the reader buffer, the entry list and the entries' name
/// storage. Initialise in place — see the lifetime contract above.
pub const Archive = struct {
    /// Where the bytes come from; every `EntryReader` reads it at its own
    /// offset, so entries may be read concurrently (`Source` doc).
    source: Source,
    /// The `Source` of an archive opened with `init` (a file).
    file_source: FileSource = undefined,
    reader_buf: []u8,
    entries: std.ArrayList(Entry),
    name_arena: std.heap.ArenaAllocator,
    alloc: Allocator,
    /// The archive comment (end record), raw bytes; owned by the archive.
    comment: []const u8 = "",
    options: Options = .{},

    pub const Options = struct {
        /// List directory entries too (`Entry.is_directory`); by default
        /// they are skipped, since they carry no content.
        list_directories: bool = false,
        /// Decompressors for methods beyond Store/Deflate, searched before
        /// the built-in ones (Zstandard).
        codecs: []const Codec = &.{},
        /// Names without the UTF-8 flag (and no Unicode Path field):
        /// `.raw` keeps the stored bytes (Go; `Entry.name_is_utf8` false),
        /// `.cp437` decodes them as IBM 437, the APPNOTE default (Python
        /// `zipfile`, zip2). ASCII names read the same either way.
        legacy_names: enum { raw, cp437 } = .raw,
    };

    fn codecFor(self: *const Archive, method: u16) ?*const Codec {
        for (self.options.codecs) |*c| if (c.method == method and c.open_reader != null) return c;
        for (&builtin_codecs) |*c| if (c.method == method) return c;
        return null;
    }

    /// Walks the central directory and records every entry (name + location +
    /// sizes). Does not read any entry's data. The `file` must outlive the
    /// archive; it is not closed by `deinit`.
    ///
    /// Tolerant where Info-ZIP `unzip` and Go's `archive/zip` are (both were
    /// asked through the Go oracle, `src/go_oracle.zig`): bytes before the
    /// archive whose offsets were not adjusted (a self-extractor stub), a
    /// central-directory size that is off, disk numbers (a multi-disk
    /// archive is read as if concatenated), an extra field that is malformed
    /// (it is advisory: the walk stops without a time, never an error). An
    /// entry this module cannot decompress -- another method, or encrypted --
    /// is listed, and refused when opened (`EntryReader.init`), so one such
    /// member does not make the rest of the archive unreadable.
    pub fn init(self: *Archive, io: std.Io, alloc: Allocator, file: std.Io.File) !void {
        return self.initOpts(io, alloc, file, .{});
    }

    pub fn initOpts(self: *Archive, io: std.Io, alloc: Allocator, file: std.Io.File, options: Options) !void {
        self.file_source = try FileSource.init(io, file);
        try self.initFields(alloc, self.file_source.source(), options);
    }

    /// `init` over any `Source` — an archive in memory (`MemorySource`), a
    /// network buffer, a custom positional reader. The source must outlive
    /// the archive.
    pub fn initSource(self: *Archive, alloc: Allocator, source: Source, options: Options) !void {
        self.file_source = undefined;
        try self.initFields(alloc, source, options);
    }

    fn initFields(self: *Archive, alloc: Allocator, source: Source, options: Options) !void {
        self.source = source;
        self.options = options;
        self.comment = "";
        self.reader_buf = try alloc.alloc(u8, READER_BUF_SIZE);
        self.entries = .empty;
        self.name_arena = std.heap.ArenaAllocator.init(alloc);
        self.alloc = alloc;
        errdefer {
            self.entries.deinit(alloc);
            self.name_arena.deinit();
            alloc.free(self.reader_buf);
        }

        var sr: SourceReader = .init(source, self.reader_buf, 0);
        const fr = &sr;
        const size = source.size;
        const dir = try findDirectory(alloc, fr, size);

        const name_alloc = self.name_arena.allocator();
        if (dir.comment_len != 0) {
            const c = try name_alloc.alloc(u8, dir.comment_len);
            if (try source.readAt(dir.comment_off, c) != c.len) return Error.ZipBadCentralDirectory;
            self.comment = c;
        }
        // A name and an extra field are each at most 65535 bytes (u16 lengths).
        const scratch = try alloc.alloc(u8, 2 * 0xffff);
        defer alloc.free(scratch);

        // One allocation for the whole list: the end record says how many
        // there are (bounded by what the file can hold — a forged count
        // must not reserve gigabytes).
        const fit = (size -| dir.start) / @sizeOf(std.zip.CentralDirectoryFileHeader);
        try self.entries.ensureTotalCapacity(alloc, @intCast(@min(dir.count, fit)));
        fr.seekTo(dir.start);
        var pos = dir.start;
        var n: u64 = 0;
        // Records are read while the central-directory signature continues,
        // then counted against the end record: a count that disagrees either
        // way is a corrupt directory (as for Go and the previous walk).
        while (pos + @sizeOf(std.zip.CentralDirectoryFileHeader) <= size) : (n += 1) {
            const h = fr.interface.takeStruct(std.zip.CentralDirectoryFileHeader, .little) catch
                return Error.ZipBadCentralDirectory;
            if (!std.mem.eql(u8, &h.signature, &std.zip.central_file_header_sig)) break;
            const rec_len = @as(u64, @sizeOf(std.zip.CentralDirectoryFileHeader)) + h.filename_len + h.extra_len + h.comment_len;
            if (pos + rec_len > size) return Error.ZipBadCentralDirectory;
            pos += rec_len;

            const raw = scratch[0..h.filename_len];
            const extra = scratch[0xffff..][0..h.extra_len];
            fr.interface.readSliceAll(raw) catch return Error.ZipBadCentralDirectory;
            fr.interface.readSliceAll(extra) catch return Error.ZipBadCentralDirectory;
            const comment = try name_alloc.alloc(u8, h.comment_len);
            fr.interface.readSliceAll(comment) catch return Error.ZipBadCentralDirectory;
            if (raw.len > std.Io.Dir.max_path_bytes) return Error.ZipNameTooLong;
            const x = parseExtra(extra, h);
            const flags: u16 = @bitCast(h.flags);
            // Info-ZIP Unicode Path (0x7075): the UTF-8 name, valid while the
            // CRC-32 it carries matches the stored name (else a later tool
            // renamed the entry without updating it — APPNOTE 4.6.9).
            var name_is_utf8 = flags & (1 << 11) != 0;
            var stored: []const u8 = raw;
            if (x.unicode_path) |up| if (!name_is_utf8 and up.crc == crc32.Crc32.hash(raw) and std.unicode.utf8ValidateSlice(up.name)) {
                stored = up.name;
                name_is_utf8 = true;
            };
            const legacy = !name_is_utf8 and options.legacy_names == .cp437 and !isAscii(stored);
            const name = if (legacy) try encoding.decodeToUtf8(name_alloc, stored, .cp437) else try name_alloc.dupe(u8, stored);
            if (legacy) name_is_utf8 = true;
            std.mem.replaceScalar(u8, name, '\\', '/'); // some writers emit Windows paths

            // Directory entries carry no content. An EMPTY name is not one:
            // it is listed (unzip and Go both list it, with its content), so
            // a member is never hidden from the caller; `isSafeEntryName`
            // refuses it for extraction.
            const is_dir = name.len > 0 and name[name.len - 1] == '/';
            if (is_dir and !options.list_directories) continue;

            // Checked when the entry is opened (its local signature), like
            // the method: one bad member does not hide the others.
            const local = x.local_offset +| dir.base;
            const dos: DosDateTime = .{ .time = h.last_modification_time, .date = h.last_modification_date };
            const perm: u32 = h.external_file_attributes >> 16;

            try self.entries.append(self.alloc, .{
                .name = name,
                .compression = h.compression_method,
                .compressed_size = x.compressed_size,
                .uncompressed_size = x.uncompressed_size,
                .file_offset = local,
                .crc32 = h.crc32,
                .mtime = x.mtime orelse dos.toUnix(),
                .mode = if (h.version_made_by >> 8 == host_unix and perm != 0) @intCast(perm & 0o7777) else null,
                .encrypted = flags & 1 != 0,
                .comment = comment,
                .extra = try name_alloc.dupe(u8, extra),
                .flags = flags,
                .version_made_by = h.version_made_by,
                .external_attributes = h.external_file_attributes,
                .name_is_utf8 = name_is_utf8,
                .is_directory = is_dir,
                .aes = x.aes,
                .dos_time = h.last_modification_time,
            });
        }
        if (n != dir.count) return Error.ZipBadCentralDirectory;
    }

    pub fn deinit(self: *Archive) void {
        self.entries.deinit(self.alloc);
        self.name_arena.deinit();
        self.alloc.free(self.reader_buf);
    }

    /// First entry whose name exactly equals `name`, else null.
    pub fn find(self: *const Archive, name: []const u8) ?*const Entry {
        for (self.entries.items) |*e| {
            if (std.mem.eql(u8, e.name, name)) return e;
        }
        return null;
    }

    /// First entry whose name ends with `suffix` (e.g. a known basename), else
    /// null. Handy when the member sits under a directory prefix.
    pub fn findSuffix(self: *const Archive, suffix: []const u8) ?*const Entry {
        for (self.entries.items) |*e| {
            if (std.mem.endsWith(u8, e.name, suffix)) return e;
        }
        return null;
    }
};

/// Where the central directory starts, how many records the end record
/// promises, and the archive's base offset (bytes before it that its own
/// offsets do not count).
const Directory = struct { start: u64, count: u64, base: u64, comment_off: u64 = 0, comment_len: u16 = 0 };

/// Locate the end-of-central-directory record (the last signature whose
/// record and comment fit the file), follow a zip64 locator when a classic
/// field is saturated, and find the directory itself: at its stated offset,
/// else right before the end record -- the second is a self-extractor whose
/// stub was prepended without adjusting offsets (`unzip`: "extra bytes at
/// beginning", processed anyway; Go reads it too).
fn findDirectory(alloc: Allocator, fr: *SourceReader, size: u64) !Directory {
    const eocd_len = @sizeOf(std.zip.EndRecord);
    if (size < eocd_len) return Error.ZipNoEndRecord;
    const tail_len: usize = @intCast(@min(size, eocd_len + 0xffff));
    const tail = try alloc.alloc(u8, tail_len);
    defer alloc.free(tail);
    fr.seekTo(size - tail_len);
    fr.interface.readSliceAll(tail) catch return Error.ZipBadCentralDirectory;

    var i: usize = tail_len - eocd_len + 1;
    const at: usize = while (i > 0) {
        i -= 1;
        if (!std.mem.eql(u8, tail[i..][0..4], &std.zip.end_record_sig)) continue;
        const comment_len = std.mem.readInt(u16, tail[i + 20 ..][0..2], .little);
        if (i + eocd_len + comment_len <= tail_len) break i;
    } else return Error.ZipNoEndRecord;
    const eocd_pos = size - tail_len + at;
    const r = tail[at..];
    const comment_len = std.mem.readInt(u16, r[20..22], .little);
    const comment_off = eocd_pos + eocd_len;
    var count: u64 = std.mem.readInt(u16, r[10..12], .little);
    var cd_size: u64 = std.mem.readInt(u32, r[12..16], .little);
    var cd_off: u64 = std.mem.readInt(u32, r[16..20], .little);
    // The directory ends where its end record starts -- or the zip64 one.
    var cd_end = eocd_pos;

    if (count == 0xffff or cd_size == 0xffffffff or cd_off == 0xffffffff) zip64: {
        if (eocd_pos < 20) break :zip64;
        var loc: [20]u8 = undefined;
        fr.seekTo(eocd_pos - 20);
        fr.interface.readSliceAll(&loc) catch return Error.ZipBadCentralDirectory;
        if (!std.mem.eql(u8, loc[0..4], &std.zip.end_locator64_sig)) break :zip64;
        const rec_off = std.mem.readInt(u64, loc[8..16], .little);
        if (eocd_pos < 20 + 56) return Error.ZipBadCentralDirectory;
        var rec: [56]u8 = undefined;
        // At its stated offset; else right before the locator (no extensible
        // data), where a prefixed archive's record is.
        const rec_pos = if (rec_off + 56 <= eocd_pos - 20 and try hasSigAt(fr, rec_off, &std.zip.end_record64_sig))
            rec_off
        else
            eocd_pos - 20 - 56;
        fr.seekTo(rec_pos);
        fr.interface.readSliceAll(&rec) catch return Error.ZipBadCentralDirectory;
        if (!std.mem.eql(u8, rec[0..4], &std.zip.end_record64_sig)) return Error.ZipBadCentralDirectory;
        count = std.mem.readInt(u64, rec[32..40], .little);
        cd_size = std.mem.readInt(u64, rec[40..48], .little);
        cd_off = std.mem.readInt(u64, rec[48..56], .little);
        cd_end = rec_pos;
    }

    if (cd_off < size and try hasSigAt(fr, cd_off, &std.zip.central_file_header_sig))
        return .{ .start = cd_off, .count = count, .base = 0, .comment_off = comment_off, .comment_len = comment_len };
    if (count == 0 and cd_off <= cd_end)
        return .{ .start = cd_end, .count = 0, .base = 0, .comment_off = comment_off, .comment_len = comment_len };
    if (cd_size <= cd_end and cd_end - cd_size > cd_off) {
        const start = cd_end - cd_size;
        if (try hasSigAt(fr, start, &std.zip.central_file_header_sig))
            return .{ .start = start, .count = count, .base = start - cd_off, .comment_off = comment_off, .comment_len = comment_len };
    }
    return Error.ZipBadCentralDirectory;
}

fn hasSigAt(fr: *SourceReader, pos: u64, sig: *const [4]u8) !bool {
    fr.seekTo(pos);
    const got = fr.interface.takeArray(4) catch return false;
    return std.mem.eql(u8, got, sig);
}

/// What a central-directory entry's extra field adds: the zip64 values for
/// the classic fields saturated at 0xFFFFFFFF, and a modification time.
const Extra = struct {
    compressed_size: u64,
    uncompressed_size: u64,
    local_offset: u64,
    mtime: ?i64 = null,
    /// Info-ZIP Unicode Path (0x7075): CRC-32 of the stored name, UTF-8 name.
    unicode_path: ?struct { crc: u32, name: []const u8 } = null,
    aes: ?crypto.AesInfo = null,
};

/// Walk an entry's central-directory extra field. Advisory: a record whose
/// length runs past the field ends the walk with what was found so far,
/// never an error (an extra field `unzip` and Go both read past).
///
/// Times, the LAST record carrying one wins, as Go and `zipinfo` decide it:
///  - Info-ZIP extended timestamp `UT` (0x5455): flags, then the mtime when
///    bit 0 is set, as UNSIGNED 32-bit seconds -- Go, `zipinfo` and 7-Zip all
///    read 2100-01-01 (4102444800) as 2100, not as 1963.
///  - NTFS (0x000a): attribute tag 1 carries mtime as 100 ns since 1601.
///  - PKWARE Unix (0x000d) and Info-ZIP Unix `UX` (0x5855): atime, mtime as
///    unsigned 32-bit seconds.
/// With none, the caller falls back to the zoneless DOS fields.
fn parseExtra(extra: []const u8, h: std.zip.CentralDirectoryFileHeader) Extra {
    var x: Extra = .{
        .compressed_size = h.compressed_size,
        .uncompressed_size = h.uncompressed_size,
        .local_offset = h.local_file_header_offset,
    };
    var rest = extra;
    while (rest.len >= 4) {
        const id = std.mem.readInt(u16, rest[0..2], .little);
        const len = std.mem.readInt(u16, rest[2..4], .little);
        if (len > rest.len - 4) break;
        const d = rest[4..][0..len];
        rest = rest[4 + len ..];
        switch (id) {
            0x0001 => { // zip64: only the saturated fields, in this order
                var v = d;
                if (h.uncompressed_size == 0xffffffff and v.len >= 8) {
                    x.uncompressed_size = std.mem.readInt(u64, v[0..8], .little);
                    v = v[8..];
                }
                if (h.compressed_size == 0xffffffff and v.len >= 8) {
                    x.compressed_size = std.mem.readInt(u64, v[0..8], .little);
                    v = v[8..];
                }
                if (h.local_file_header_offset == 0xffffffff and v.len >= 8)
                    x.local_offset = std.mem.readInt(u64, v[0..8], .little);
            },
            extra_id_ut => if (d.len >= 5 and d[0] & 1 != 0) {
                x.mtime = std.mem.readInt(u32, d[1..5], .little);
            },
            0x000a => { // NTFS: 4 reserved bytes, then tag/size attributes
                var v = d[@min(4, d.len)..];
                while (v.len >= 4) {
                    const tag = std.mem.readInt(u16, v[0..2], .little);
                    const tlen = std.mem.readInt(u16, v[2..4], .little);
                    if (tlen > v.len - 4) break;
                    if (tag == 1 and tlen >= 8) {
                        const ft = std.mem.readInt(u64, v[4..12], .little);
                        x.mtime = @as(i64, @intCast(ft / 10_000_000)) - 11_644_473_600;
                    }
                    v = v[4 + tlen ..];
                }
            },
            0x000d, 0x5855 => if (d.len >= 8) {
                x.mtime = std.mem.readInt(u32, d[4..8], .little);
            },
            crypto.extra_id_aes => x.aes = crypto.parseAesExtra(d),
            0x7075 => if (d.len >= 5 and d[0] == 1) {
                x.unicode_path = .{ .crc = std.mem.readInt(u32, d[1..5], .little), .name = d[5..] };
            },
            else => {},
        }
    }
    return x;
}

fn isAscii(s: []const u8) bool {
    for (s) |b| if (b >= 0x80) return false;
    return true;
}

pub const ExtractOptions = struct {
    /// Bomb guard over the whole archive: the declared sizes of what is
    /// extracted may not pass this (each entry is also capped by
    /// `max_entry`, and clamped at its declared size while streaming).
    max_total: u64 = 4 << 30,
    max_entry: u64 = default_max_output,
    /// Symlink entries: skipped (default), created (their target must be
    /// relative and free of `..`), or refused (`ZipUnsafeSymlink`).
    symlinks: enum { skip, create, refuse } = .skip,
    /// Replace existing files; by default an existing file is an error
    /// (`error.PathAlreadyExists`), never silently overwritten.
    overwrite: bool = false,
    /// Restore Unix permission bits / the modification time when the entry
    /// carries them.
    restore_mode: bool = true,
    restore_mtime: bool = true,
    password: ?[]const u8 = null,
};

pub const ExtractError = error{ ZipUnsafeSymlink, ZipExtractTooLarge };

/// Extract every entry under `dir` (Python `extractall`, zip2 `extract`).
/// Every name passes `isSafeEntryName` first (`ZipUnsafeEntryName`: no
/// absolute path, drive, or `..` segment — "zip slip"); parent directories
/// are created; directory entries are honoured when the archive lists them
/// (`Options.list_directories`). Stops at the first error.
pub fn extractAll(archive: *Archive, io: std.Io, dir: std.Io.Dir, opts: ExtractOptions) !void {
    var total: u64 = 0;
    const window = try archive.alloc.alloc(u8, std.compress.flate.max_window_len);
    defer archive.alloc.free(window);
    const wbuf = try archive.alloc.alloc(u8, 64 * 1024);
    defer archive.alloc.free(wbuf);
    for (archive.entries.items) |*e| {
        if (!isSafeEntryName(e.name)) return Error.ZipUnsafeEntryName;
        if (e.is_directory) {
            try dir.createDirPath(io, std.mem.trimEnd(u8, e.name, "/"));
            continue;
        }
        if (std.fs.path.dirnamePosix(e.name)) |parent| try dir.createDirPath(io, parent);
        if (e.isSymlink()) {
            switch (opts.symlinks) {
                .skip => continue,
                .refuse => return ExtractError.ZipUnsafeSymlink,
                .create => {},
            }
            if (e.uncompressed_size > std.Io.Dir.max_path_bytes) return ExtractError.ZipUnsafeSymlink;
            var er: EntryReader = undefined;
            try er.open(archive, e, window, .{ .max_output = std.Io.Dir.max_path_bytes, .password = opts.password });
            defer er.deinit();
            var tbuf: [std.Io.Dir.max_path_bytes]u8 = undefined;
            const n = try er.reader().readSliceShort(&tbuf);
            const target = tbuf[0..n];
            if (!isSafeEntryName(target)) return ExtractError.ZipUnsafeSymlink;
            try dir.symLink(io, target, e.name, .{});
            continue;
        }
        if (e.uncompressed_size > opts.max_total - total) return ExtractError.ZipExtractTooLarge;
        total += e.uncompressed_size;
        var er: EntryReader = undefined;
        try er.open(archive, e, window, .{ .max_output = opts.max_entry, .password = opts.password });
        defer er.deinit();
        var file = try dir.createFile(io, e.name, .{ .exclusive = !opts.overwrite, .truncate = true });
        defer file.close(io);
        var fw = file.writer(io, wbuf);
        _ = try er.reader().streamRemaining(&fw.interface);
        try fw.interface.flush();
        if (opts.restore_mode) if (e.mode) |m| {
            if (@hasDecl(std.Io.File.Permissions, "fromMode")) try file.setPermissions(io, .fromMode(m));
        };
        if (opts.restore_mtime) if (e.mtime) |t| {
            try file.setTimestamps(io, .{ .modify_timestamp = .{ .new = .fromNanoseconds(@as(i96, t) * std.time.ns_per_s) } });
        };
    }
}

/// Zip-slip guard for an extraction contract. `zipstream` is a streaming
/// *reader*: it surfaces each member's stored `name` verbatim (backslashes
/// already normalised to '/') and never itself writes to disk. A caller that
/// extracts entries to the filesystem MUST reject any name for which this
/// returns `false` (or otherwise confine the write to a target directory),
/// else a hostile archive paths an entry to `../../etc/...`, an absolute path
/// or a Windows drive/UNC location and escapes the extraction root ("zip
/// slip"). Mirrors `tar`'s contract (its reader likewise returns raw paths for
/// the caller to sanitise), offered here as a ready predicate.
///
/// Rejects: empty names; absolute paths (`/x`, `\x`); a Windows drive or
/// drive-relative prefix (`C:...`); and any `..` path segment on either
/// separator (`../x`, `a/../b`, `dir\..\x`). Accepts ordinary relative member
/// paths (`a.csv`, `sub/b.csv`), including names that merely contain dots
/// (`a..b`, `...`).
pub fn isSafeEntryName(name: []const u8) bool {
    if (name.len == 0) return false;
    if (name[0] == '/' or name[0] == '\\') return false; // absolute
    if (name.len >= 2 and name[1] == ':') return false; // "C:" drive / drive-relative
    var it = std.mem.splitAny(u8, name, "/\\");
    while (it.next()) |seg| {
        if (std.mem.eql(u8, seg, "..")) return false; // traversal segment
    }
    return true;
}

/// A streaming reader over one entry's decompressed bytes. Initialise in place
/// against an `Archive` and a caller-provided decompression `window` buffer
/// (≥ `std.compress.flate.max_window_len` for deflate). The window must outlive
/// the `EntryReader`. Opening a new `EntryReader` reseeks the shared file
/// cursor, so a previous one must be finished first.
///
/// Integrity: `reader()` accumulates a running CRC-32 over every decompressed
/// byte it yields and checks it against the entry's central-directory
/// `crc32` once the stream is exhausted — a corrupted or tampered member is
/// therefore never delivered to the end as if it were valid data. Because
/// `std.Io.Reader`'s vtable has a fixed `StreamError` set (`ReadFailed` /
/// `WriteFailed` / `EndOfStream`, no room for a dedicated error), a mismatch
/// surfaces as `error.ReadFailed` — call `crcMismatch()` after such an error
/// to tell a corrupted-content failure apart from an underlying I/O failure
/// (the same out-of-band-reason pattern `http`'s `ChunkedReader` uses).
pub const EntryReader = struct {
    /// This reader's own cursor into the archive's `Source`.
    src_reader: SourceReader,
    src_buf: [16 * 1024]u8,
    decompress: std.compress.flate.Decompress,
    limited: std.Io.Reader.Limited,
    crc_reader: CrcReader,
    /// Deflate input: the entry's `compressed_size` bytes, then zeros.
    deflate_in: PaddedInput,
    deflate_in_buf: [1024]u8,
    /// A codec's input (the entry's compressed bytes) and its decompressor.
    codec_in: std.Io.Reader.Limited = undefined,
    /// A decoder may `fill` its input (zstd does), which needs a buffer.
    codec_in_buf: [16 * 1024]u8 = undefined,
    codec: ?CodecReader = null,
    gpa: Allocator = undefined,
    /// Encrypted entries: the stored bytes and their decryption.
    raw_in: std.Io.Reader.Limited = undefined,
    aes_reader: crypto.AesReader = undefined,
    zc_reader: crypto.ZipCryptoReader = undefined,
    decrypt_buf: [4096]u8 = undefined,
    is_aes: bool = false,

    pub const OpenOptions = struct {
        /// Decompression-bomb cap (see `initMax`).
        max_output: u64 = default_max_output,
        /// Password of an encrypted entry (WinZip AES or ZipCrypto).
        password: ?[]const u8 = null,
    };

    /// True once `reader()` has failed because a WinZip AES entry's
    /// authentication code did not match (forged or corrupted ciphertext).
    pub fn authFailed(self: *const EntryReader) bool {
        return self.is_aes and self.aes_reader.auth_failed;
    }

    /// Releases a codec's decoder (Zstandard's tables); a no-op for Store
    /// and Deflate. Call it when done with an entry whose method is not one
    /// of those two.
    pub fn deinit(self: *EntryReader) void {
        if (self.codec) |c| c.close(c.state, self.gpa);
        self.codec = null;
    }

    /// Open an entry with the default decompression-bomb cap
    /// (`default_max_output`). See `initMax` to choose the cap.
    pub fn init(self: *EntryReader, archive: *Archive, entry: *const Entry, window: []u8) !void {
        return self.initMax(archive, entry, window, default_max_output);
    }

    /// Open an entry, bounding its decompressed output at `max_output`. An entry
    /// whose declared uncompressed size already exceeds the cap is refused with
    /// `error.ZipEntryTooLarge` up front (no decompression happens). For deflate
    /// the *running* output is additionally clamped to the declared size, so a
    /// crafted stream that would expand past its own central-directory bound is
    /// truncated at that bound rather than read unbounded — a decompression bomb
    /// can never force an unbounded read/allocation on the consumer.
    pub fn initMax(self: *EntryReader, archive: *Archive, entry: *const Entry, window: []u8, max_output: u64) !void {
        return self.open(archive, entry, window, .{ .max_output = max_output });
    }

    /// `initMax` with a password for an encrypted entry: WinZip AES
    /// (AE-1/AE-2, the code is verified at the end — `authFailed`) or the
    /// legacy ZipCrypto. A wrong password is `error.ZipBadPassword` (AES's
    /// verifier, ZipCrypto's check byte — 1 in 256 wrong passwords pass
    /// that one; the CRC-32 then fails).
    pub fn open(self: *EntryReader, archive: *Archive, entry: *const Entry, window: []u8, opts: OpenOptions) !void {
        const max_output = opts.max_output;
        if (entry.encrypted and opts.password == null) return Error.ZipEncryptedEntry;
        self.codec = null;
        self.is_aes = false;
        self.src_reader = .init(archive.source, &self.src_buf, entry.file_offset);
        const fr = &self.src_reader;
        // A stored entry is its own bytes: a compressed size that differs
        // from the uncompressed one is a directory that lies about where the
        // member ends. Reading the uncompressed size ran past the member
        // (unzip: "ucsize <> csize for STORED entry", then a CRC error; Go
        // refuses it too).
        if (!entry.encrypted and entry.compression == .store and entry.compressed_size != entry.uncompressed_size)
            return Error.ZipBadCentralDirectory;

        // Locate the compressed data: the local header carries its own
        // filename/extra lengths (which can differ from the central header).
        // version_needed is deliberately ignored — see the module note.
        fr.seekTo(entry.file_offset);
        const local = fr.interface.takeStruct(std.zip.LocalFileHeader, .little) catch |err| switch (err) {
            error.EndOfStream => return Error.ZipBadFileOffset, // an offset at or past the end
            error.ReadFailed => return err,
        };
        if (!std.mem.eql(u8, &local.signature, &std.zip.local_file_header_sig))
            return Error.ZipBadFileOffset;
        const data_off = entry.file_offset + @sizeOf(std.zip.LocalFileHeader) +
            @as(u64, local.filename_len) + @as(u64, local.extra_len);
        fr.seekTo(data_off);

        // Decompression-bomb guard: refuse an entry that declares more output
        // than the caller allows before any bytes are read.
        if (entry.uncompressed_size > max_output) return Error.ZipEntryTooLarge;

        // The (decrypted) compressed bytes and their count.
        var in: *std.Io.Reader = &fr.interface;
        var csize = entry.compressed_size;
        var check_crc = true;
        if (entry.encrypted) {
            self.raw_in = fr.interface.limited(.limited64(entry.compressed_size), &.{});
            if (entry.aes) |a| {
                try self.aes_reader.init(&self.raw_in.interface, entry.compressed_size, a.strength, opts.password.?, &self.decrypt_buf);
                self.is_aes = true;
                in = &self.aes_reader.interface;
                csize -= crypto.aesOverhead(a.strength);
                check_crc = a.version == 1; // AE-2 stores CRC 0; the code authenticates
            } else {
                const check: u8 = if (entry.flags & (1 << 3) != 0) @truncate(entry.dos_time >> 8) else @truncate(entry.crc32 >> 24);
                try self.zc_reader.init(&self.raw_in.interface, entry.compressed_size, opts.password.?, check, &self.decrypt_buf);
                in = &self.zc_reader.interface;
                csize -= crypto.ZipCryptoReader.header_len;
            }
        }
        if (entry.encrypted and entry.method() == 0 and csize != entry.uncompressed_size)
            return Error.ZipBadCentralDirectory;

        switch (@as(std.zip.CompressionMethod, @fromBackingInt(@intCast(entry.method())))) {
            .deflate => {
                // The decoder never sees an end of input: std 0.16's
                // `flate.Decompress` reaches `unreachable` when its input ends
                // inside a block (`tossBitsShort` adds `consumed_bits` where it
                // must subtract) -- any truncated stream did it, e.g. a last
                // entry whose data runs to end of file. So it reads exactly the
                // entry's own bytes and zeros after them; a stream that needed
                // the zeros decodes to output the CRC-32 check refuses, or
                // stops on an invalid block (a zero block header is a stored
                // block whose LEN/NLEN disagree). Bounding the input to
                // `compressed_size` is also Go's `archive/zip` (a SectionReader).
                self.deflate_in = .{
                    .source = in,
                    .remaining = csize,
                    .interface = .{ .vtable = &PaddedInput.vtable, .buffer = &self.deflate_in_buf, .seek = 0, .end = 0 },
                };
                self.decompress = .init(&self.deflate_in.interface, .raw, window);
                // Clamp the decompressed stream to the declared size. `window`
                // is already owned by `decompress`, so the Limited reads
                // straight through with no buffer of its own.
                self.limited = self.decompress.reader.limited(.limited64(entry.uncompressed_size), &.{});
            },
            .store => {
                self.limited = in.limited(.limited64(entry.uncompressed_size), window);
            },
            else => {
                const codec = archive.codecFor(entry.method()) orelse return Error.UnsupportedCompressionMethod;
                self.gpa = archive.alloc;
                self.codec_in = in.limited(.limited64(csize), &self.codec_in_buf);
                self.codec = try codec.open_reader.?(codec.context, archive.alloc, &self.codec_in.interface);
                self.limited = self.codec.?.reader.limited(.limited64(entry.uncompressed_size), window);
            },
        }
        self.crc_reader = CrcReader.init(&self.limited.interface, entry.crc32, entry.uncompressed_size);
        self.crc_reader.check = check_crc;
        self.crc_reader.aes = if (self.is_aes) &self.aes_reader else null;
    }

    /// The decompressed-byte reader, bounded by the output cap and verified
    /// against the entry's CRC-32 at end-of-stream (see the type doc).
    /// Valid until the next `EntryReader.init` against the same archive
    /// (which reseeks the file cursor).
    pub fn reader(self: *EntryReader) *std.Io.Reader {
        return &self.crc_reader.interface;
    }

    /// True once `reader()` has failed with `error.ReadFailed` *because* the
    /// accumulated CRC-32 did not match the entry's declared checksum, i.e.
    /// the member's content was corrupted or tampered with — as opposed to
    /// an unrelated I/O failure, which also surfaces as `error.ReadFailed`
    /// but leaves this false. Only meaningful after such an error.
    pub fn crcMismatch(self: *const EntryReader) bool {
        return self.crc_reader.crc_mismatch;
    }
};

/// `remaining` bytes of `source`, then zeros for ever (see `EntryReader`'s
/// deflate arm for why the decoder must never reach an end of input). A
/// source that ends early is padded the same way: the CRC-32 check, not an
/// EndOfStream inside std's decoder, reports the short entry.
const PaddedInput = struct {
    source: *std.Io.Reader,
    remaining: u64,
    interface: std.Io.Reader,

    const vtable: std.Io.Reader.VTable = .{ .stream = stream };

    fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *PaddedInput = @alignCast(@fieldParentPtr("interface", r));
        const dest = limit.slice(try w.writableSliceGreedy(1));
        if (self.remaining != 0) {
            const want: usize = @intCast(@min(dest.len, self.remaining));
            const n = self.source.readSliceShort(dest[0..want]) catch return error.ReadFailed;
            if (n != 0) {
                self.remaining -= n;
                w.advance(n);
                return n;
            }
            self.remaining = 0; // the file ended first
        }
        @memset(dest, 0);
        w.advance(dest.len);
        return dest.len;
    }
};

/// Wraps a `Reader` (the decompressed/limited stream of one ZIP entry),
/// accumulating a running CRC-32 over every byte forwarded through it. When
/// the wrapped reader reaches its own end-of-stream, the accumulated CRC is
/// compared against `expected`; on mismatch the read fails (`crc_mismatch`
/// is set and `error.ReadFailed` returned) instead of silently completing as
/// if the content were untouched — closing the gap where a corrupted or
/// tampered archive member was previously delivered as valid data (audit
/// finding `zipstream` F4). The check also runs on the read that reaches the
/// declared size, and that read's bytes are withheld on a mismatch: a
/// consumer that reads exactly `uncompressed_size` bytes never makes the
/// end-of-stream read, and until 2026-10-11 received corrupted content whole
/// with no error.
const CrcReader = struct {
    source: *std.Io.Reader,
    interface: std.Io.Reader,
    crc: crc32.Crc32,
    expected: u32,
    /// The declared uncompressed size, and how much has been forwarded.
    size: u64,
    seen: u64 = 0,
    crc_mismatch: bool = false,
    /// False for a WinZip AE-2 entry (CRC stored as 0; the AES code checks).
    check: bool = true,
    /// A WinZip AES entry's decryptor: its code is checked at the entry's end.
    aes: ?*crypto.AesReader = null,

    fn init(source: *std.Io.Reader, expected: u32, size: u64) CrcReader {
        return .{
            .source = source,
            .interface = .{ .vtable = &.{ .stream = stream }, .buffer = &.{}, .seek = 0, .end = 0 },
            .crc = crc32.Crc32.init(),
            .expected = expected,
            .size = size,
        };
    }

    fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *CrcReader = @alignCast(@fieldParentPtr("interface", r));
        // Read straight into the destination's buffer and hash it there; the
        // bytes count as delivered only after the check (`advance`). A writer
        // without a buffer (a bare `Discarding`) goes through a scratch.
        var scratch: [4096]u8 = undefined;
        const direct = w.buffer.len != 0;
        const dest = if (direct) limit.slice(try w.writableSliceGreedy(1)) else scratch[0..limit.minInt(scratch.len)];
        if (dest.len == 0) return 0;
        const n = self.source.readSliceShort(dest) catch |err| switch (err) {
            error.ReadFailed => return error.ReadFailed,
        };
        if (n == 0) {
            // `readSliceShort` returns fewer bytes than requested if and only
            // if the source stream has ended — this is the real end-of-entry.
            if (self.aes) |a| try a.drainAndVerify();
            if (self.check and self.crc.final() != self.expected) {
                self.crc_mismatch = true;
                return error.ReadFailed;
            }
            return error.EndOfStream;
        }
        self.crc.update(dest[0..n]);
        self.seen += n;
        if (self.seen == self.size) if (self.aes) |a| try a.drainAndVerify();
        if (self.check and self.seen == self.size and self.crc.final() != self.expected) {
            self.crc_mismatch = true;
            return error.ReadFailed;
        }
        if (direct) w.advance(n) else try w.writeAll(dest[0..n]);
        return n;
    }
};

/// Writes `value` to `w` in the ZIP wire format's fixed little-endian byte
/// order, regardless of host endianness (mirrors `std.zip`'s reader side,
/// which byte-swaps an in-memory header after reading on a big-endian host).
fn writeHeaderLE(comptime T: type, w: *std.Io.Writer, value: T) std.Io.Writer.Error!void {
    var v = value;
    if (!native_endian_is_le) std.mem.byteSwapAllFields(T, &v);
    try w.writeAll(std.mem.asBytes(&v));
}

/// Compression method for a written entry — Store or Deflate, the same pair
/// `Archive`/`EntryReader` read.
pub const WriteMethod = enum {
    store,
    deflate,
    /// Zstandard (method 93), `AddEntryOptions.codec_level`.
    zstd,
    /// `AddEntryOptions.codec`.
    custom,
};

pub const AddEntryOptions = struct {
    method: WriteMethod = .deflate,
    /// Deflate speed/ratio trade-off (`std.compress.flate.Compress.Options`);
    /// ignored for `.store`.
    level: std.compress.flate.Compress.Options = .default,
    /// Last modification time, Unix seconds (UTC). Written into the DOS
    /// date/time fields (clamped to 1980..2107, even seconds) and, when it
    /// fits an unsigned 32-bit time (1970..2106), into an Info-ZIP extended-timestamp extra
    /// field (`UT`) in both headers — the exact UTC instant, which unzip,
    /// zipinfo and Go's `archive/zip` prefer over the zoneless DOS fields.
    /// Null writes the earliest DOS time, 1980-01-01 00:00:00, and no extra
    /// field: a fixed, valid date, so archives stay reproducible.
    mtime: ?i64 = null,
    /// Unix permission bits (e.g. `0o644`). When set, the entry is marked as
    /// made on a Unix host and carries `S_IFREG | mode` in the high half of
    /// its external attributes, as Info-ZIP `zip` writes it; unzip restores
    /// the mode on extraction. Null leaves host 0 (MS-DOS) and no attributes.
    mode: ?u16 = null,
    /// Entry comment (central directory), at most 65535 bytes.
    comment: []const u8 = "",
    /// Caller extra-field records (each `id u16, len u16, data`), written
    /// in both headers after the module's own (`UT`, zip64). At most what
    /// fits the 65535-byte field with them.
    extra: []const u8 = "",
    /// Write the zip64 extra even when the sizes fit (Python `force_zip64`):
    /// needed when a streamed entry may outgrow 4 GiB, harmless otherwise.
    force_zip64: bool = false,
    /// `.custom`: the compressor (its `method` goes into the headers).
    codec: ?*const Codec = null,
    /// `.zstd` / `.custom`: the codec's level, 0 = its default.
    codec_level: i32 = 0,
    /// Encrypt with WinZip AES (AE-2: CRC stored as 0, the 10-byte code
    /// authenticates), as zip2 and 7-Zip write it. Never ZipCrypto.
    encryption: ?Encryption = null,

    pub const Encryption = struct {
        password: []const u8,
        strength: AesStrength = .aes256,
        /// Source of the random salt (`std.Io.randomSecure`) …
        io: ?std.Io = null,
        /// … or the salt itself (`strength.saltLen()` bytes) — for
        /// reproducible tests only: a reused salt with a reused password
        /// repeats the key stream.
        salt: ?[]const u8 = null,
    };
};

fn makeSalt(e: AddEntryOptions.Encryption, out: *[16]u8) ![]const u8 {
    const n = e.strength.saltLen();
    if (e.salt) |s| {
        if (s.len != n) return error.ZipBadSalt;
        @memcpy(out[0..n], s);
    } else {
        const io = e.io orelse return error.ZipNoRandomSource;
        try io.randomSecure(out[0..n]);
    }
    return out[0..n];
}

fn writeCodec(options: AddEntryOptions) ?*const Codec {
    return switch (options.method) {
        .zstd => &zstd_codec,
        .custom => options.codec orelse unreachable, // `.custom` needs `codec`
        else => null,
    };
}

/// Streaming ZIP archive writer: add members one at a time, then `finish()`.
/// Members are written to `out` as they are added; `finish()` writes the
/// central directory and the end record. Never buffers the archive.
///
///  - `addEntry(name, data, opts)` — the data in memory; one compressed copy
///    is made so the local header can carry the sizes (the classic layout,
///    readable by every tool).
///  - `beginEntry(name, opts)` → `*std.Io.Writer`, then `endEntry()` —
///    streamed: the bytes are compressed on the way to `out` and the CRC and
///    sizes follow in a data descriptor (general-purpose bit 3), as Go's
///    `Create` and Python's `open(name, "w")` write them. Memory: one
///    deflate window, whatever the entry size.
///  - `addDirectory`, `addSymlink`.
///
/// zip64 (since 2026-10-20): an entry or archive past a classic field
/// (4 GiB sizes or offsets, 65535 entries) gets the zip64 extra field, the
/// zip64 end record and its locator, as Go and Python write them. With
/// `allow_zip64 = false` such an archive is refused (`ZipWriteTooLarge`)
/// before anything that would overflow is written.
///
/// Entry names are gated through `isSafeEntryName` (`ZipUnsafeEntryName`),
/// so this module can never itself be the source of a zip-slip archive.
///
/// Movable, except between `beginEntry` and `endEntry` (the returned writer
/// points into heap state the writer owns, so even then moving only the
/// `ArchiveWriter` value is fine — the pointer stays valid).
pub const ArchiveWriter = struct {
    out: *std.Io.Writer,
    alloc: Allocator,
    /// Bytes written to `out` so far — doubles as the next entry's local file
    /// header offset and, after the entry loop in `finish`, the central
    /// directory's end offset.
    offset: u64 = 0,
    entries: std.ArrayList(WrittenEntry) = .empty,
    name_arena: std.heap.ArenaAllocator,
    finished: bool = false,
    /// Allow zip64 records (Python `allowZip64`); false refuses an archive
    /// that needs them.
    allow_zip64: bool = true,
    /// The archive comment, written by `finish` (at most 65535 bytes).
    comment: []const u8 = "",
    /// The entry being streamed (`beginEntry` .. `endEntry`).
    open: ?*Streamed = null,

    const WrittenEntry = struct {
        name: []const u8,
        method: std.zip.CompressionMethod,
        crc32: u32,
        compressed_size: u64,
        uncompressed_size: u64,
        local_header_offset: u64,
        /// General-purpose flags, the same in both headers.
        flags: u16,
        dos: DosDateTime,
        /// The `UT` mtime, when one is written.
        ut: ?u32,
        /// High half of the external attributes (`st_mode`), when the entry
        /// is marked Unix-made.
        unix_mode: ?u32,
        comment: []const u8,
        extra: []const u8,
        force_zip64: bool,
        aes_extra: ?[11]u8,
    };

    /// General-purpose flag bit 11 ("language encoding"): the name is UTF-8.
    /// Without it a reader takes a name as IBM code page 437 (APPNOTE 4.4.4,
    /// appendix D): Go flags `NonUTF8`, unzip shows "č" as two CP437 glyphs.
    /// Set for a name that is UTF-8 with a non-ASCII byte -- as Go's writer and
    /// Info-ZIP zip 3.0 do; plain ASCII reads the same either way, so it stays
    /// clear there (and the archives this writer made before keep their bytes).
    fn nameFlags(name: []const u8) u16 {
        for (name) |c| {
            if (c >= 0x80) return if (std.unicode.utf8ValidateSlice(name)) 1 << 11 else 0;
        }
        return 0;
    }

    /// Size of one `UT` extra record carrying just the mtime (4-byte header +
    /// flags byte + 4-byte time); the same in the local and central headers.
    const ut_extra_len = 9;

    fn writeUtExtra(w: *std.Io.Writer, t: u32) std.Io.Writer.Error!void {
        var rec: [ut_extra_len]u8 = undefined;
        std.mem.writeInt(u16, rec[0..2], extra_id_ut, .little);
        std.mem.writeInt(u16, rec[2..4], 5, .little);
        rec[4] = 1; // bit 0: mtime present
        std.mem.writeInt(u32, rec[5..9], t, .little);
        try w.writeAll(&rec);
    }

    const u32_max = std.math.maxInt(u32);
    const flag_descriptor: u16 = 1 << 3;

    /// `out` is the caller-owned destination writer (e.g. a file's buffered
    /// writer, or `std.Io.Writer.Allocating` for an in-memory archive).
    /// Flushing/closing `out` — during and after `finish()` — stays the
    /// caller's responsibility; `ArchiveWriter` never flushes it itself.
    pub fn init(alloc: Allocator, out: *std.Io.Writer) ArchiveWriter {
        return .{
            .out = out,
            .alloc = alloc,
            .name_arena = std.heap.ArenaAllocator.init(alloc),
        };
    }

    pub fn deinit(self: *ArchiveWriter) void {
        if (self.open) |s| {
            if (s.codec) |c| c.close(c.state, self.alloc);
            self.alloc.destroy(s);
        }
        self.entries.deinit(self.alloc);
        self.name_arena.deinit();
        self.* = undefined;
    }

    /// Everything about a member but its bytes, checked and with the extra
    /// fields decided.
    const Header = struct {
        method: std.zip.CompressionMethod,
        flags: u16,
        dos: DosDateTime,
        ut: ?u32,
        unix_mode: ?u32,
        /// WinZip AES record (method 99 in the headers, the real one here).
        aes_extra: ?[11]u8 = null,
    };

    fn prepare(self: *ArchiveWriter, name: []const u8, method: WriteMethod, options: AddEntryOptions, unix_type: u32) !Header {
        std.debug.assert(!self.finished);
        std.debug.assert(self.open == null); // finish the streamed entry first
        if (!isSafeEntryName(name)) return Error.ZipUnsafeEntryName;
        if (name.len > std.math.maxInt(u16)) return Error.ZipNameTooLong;
        if (options.comment.len > std.math.maxInt(u16)) return Error.ZipWriteTooLarge;
        if (options.extra.len > std.math.maxInt(u16) - ut_extra_len - zip64_local_len) return Error.ZipWriteTooLarge;
        if (!self.allow_zip64) {
            if (self.offset > u32_max) return Error.ZipWriteTooLarge;
            if (self.entries.items.len >= std.math.maxInt(u16)) return Error.ZipWriteTooLarge;
        }
        const ut: ?u32 = if (options.mtime) |t|
            // zig 0.17.0 miscompile: not `std.math.cast(u32, t)` with t: i64 --
            // it lowers to `trunc nsw`, making mtimes 2038..2106 (2^31..2^32-1)
            // poison; narrow non-negative i64 → u64 → u32 (`trunc nuw`).
            (if (t < 0) null else std.math.cast(u32, @as(u64, @bitCast(t))))
        else
            null;
        const real: std.zip.CompressionMethod = switch (method) {
            .store => .store,
            .deflate => .deflate,
            .zstd, .custom => @fromBackingInt(@intCast(writeCodec(options).?.method)),
        };
        const enc = options.encryption;
        return .{
            .method = if (enc != null) @fromBackingInt(@intCast(crypto.method_aes)) else real,
            .aes_extra = if (enc) |e| crypto.aesExtra(e.strength, @backingInt(real)) else null,
            // Bit 11 covers the name AND the comment (APPNOTE 4.4.4): a
            // UTF-8 comment on an ASCII name sets it too, as Go's writer does.
            .flags = nameFlags(name) | nameFlags(options.comment) | @as(u16, if (enc != null) 1 else 0),
            .dos = if (options.mtime) |t| .fromUnix(t) else .min,
            .ut = ut,
            .unix_mode = if (unix_type != unix_regular_file)
                unix_type | (@as(u32, options.mode orelse 0o755) & 0o7777)
            else if (options.mode) |m| unix_regular_file | (m & 0o7777) else null,
        };
    }

    /// The zip64 extra in a local header: both sizes (APPNOTE 4.5.3: a
    /// local header's zip64 record carries both or neither).
    const zip64_local_len = 4 + 16;

    fn writeLocal(self: *ArchiveWriter, name: []const u8, h: Header, crc: u32, csize: u64, usize_: u64, zip64: bool, streamed: bool, options: AddEntryOptions) !void {
        const extra_len: u16 = @intCast(@as(usize, if (h.ut != null) ut_extra_len else 0) + @as(usize, if (zip64) zip64_local_len else 0) +
            @as(usize, if (h.aes_extra != null) 11 else 0) + options.extra.len);
        const lfh: std.zip.LocalFileHeader = .{
            .signature = std.zip.local_file_header_sig,
            .version_needed_to_extract = if (zip64) 45 else 20,
            .flags = @bitCast(h.flags | (if (streamed) flag_descriptor else 0)),
            .compression_method = h.method,
            .last_modification_time = h.dos.time,
            .last_modification_date = h.dos.date,
            .crc32 = if (streamed or h.aes_extra != null) 0 else crc,
            .compressed_size = if (zip64) u32_max else if (streamed) 0 else @intCast(csize),
            .uncompressed_size = if (zip64) u32_max else if (streamed) 0 else @intCast(usize_),
            .filename_len = @intCast(name.len),
            .extra_len = extra_len,
        };
        try writeHeaderLE(std.zip.LocalFileHeader, self.out, lfh);
        try self.out.writeAll(name);
        if (h.ut) |t| try writeUtExtra(self.out, t);
        if (zip64) {
            var rec: [zip64_local_len]u8 = undefined;
            std.mem.writeInt(u16, rec[0..2], 0x0001, .little);
            std.mem.writeInt(u16, rec[2..4], 16, .little);
            // A streamed entry's sizes are not known yet: zero, the
            // descriptor carries them (as Go writes it).
            std.mem.writeInt(u64, rec[4..12], if (streamed) 0 else usize_, .little);
            std.mem.writeInt(u64, rec[12..20], if (streamed) 0 else csize, .little);
            try self.out.writeAll(&rec);
        }
        if (h.aes_extra) |*x| try self.out.writeAll(x);
        try self.out.writeAll(options.extra);
        self.offset += @sizeOf(std.zip.LocalFileHeader) + name.len + extra_len;
    }

    fn record(self: *ArchiveWriter, name: []const u8, h: Header, crc: u32, csize: u64, usize_: u64, offset: u64, streamed: bool, options: AddEntryOptions) !void {
        const arena = self.name_arena.allocator();
        try self.entries.append(self.alloc, .{
            .name = try arena.dupe(u8, name),
            .method = h.method,
            .crc32 = if (h.aes_extra != null) 0 else crc, // AE-2
            .compressed_size = csize,
            .uncompressed_size = usize_,
            .local_header_offset = offset,
            .flags = h.flags | (if (streamed) flag_descriptor else 0),
            .dos = h.dos,
            .ut = h.ut,
            .unix_mode = h.unix_mode,
            .comment = try arena.dupe(u8, options.comment),
            .extra = try arena.dupe(u8, options.extra),
            .force_zip64 = options.force_zip64,
            .aes_extra = h.aes_extra,
        });
    }

    /// Compresses (or stores) all of `data` and appends it to the archive as
    /// one member named `name`. `data` must already be fully in memory; the
    /// only extra buffering is one compressed copy of `data` for `.deflate`
    /// (freed before returning). For data that is not in memory, see
    /// `beginEntry`.
    pub fn addEntry(self: *ArchiveWriter, name: []const u8, data: []const u8, options: AddEntryOptions) !void {
        const h = try self.prepare(name, options.method, options, unix_regular_file);
        const crc = crc32.Crc32.hash(data);

        // For .store, the payload is `data` itself (no copy). For .deflate,
        // compress into a scratch Allocating writer first — the local file
        // header (written before the payload) needs the final compressed size,
        // and flate.Compress only knows that once it has produced all the
        // output.
        var deflated: std.Io.Writer.Allocating = .init(self.alloc);
        defer deflated.deinit();
        const payload: []const u8 = switch (options.method) {
            .store => data,
            .deflate => blk: {
                try deflated.ensureTotalCapacityPrecise(@max(64, data.len / 2));
                var window: [std.compress.flate.max_window_len]u8 = undefined;
                var compress = try std.compress.flate.Compress.init(&deflated.writer, &window, .raw, options.level);
                try compress.writer.writeAll(data);
                try compress.finish();
                break :blk deflated.writer.buffered();
            },
            .zstd, .custom => blk: {
                const codec = writeCodec(options).?;
                try deflated.ensureTotalCapacityPrecise(@max(64, data.len / 2));
                const cw = try codec.open_writer.?(codec.context, self.alloc, &deflated.writer, options.codec_level);
                defer cw.close(cw.state, self.alloc);
                try cw.writer.writeAll(data);
                try cw.finish(cw.state);
                break :blk deflated.writer.buffered();
            },
        };
        var sealed: std.Io.Writer.Allocating = .init(self.alloc);
        defer sealed.deinit();
        const stored: []const u8 = if (options.encryption) |e| blk: {
            var salt_buf: [16]u8 = undefined;
            const salt = try makeSalt(e, &salt_buf);
            try sealed.ensureTotalCapacityPrecise(payload.len + crypto.aesOverhead(e.strength));
            var aw_buf: [4096]u8 = undefined;
            var aw: crypto.AesWriter = undefined;
            try aw.start(&sealed.writer, e.strength, e.password, salt, &aw_buf);
            try aw.interface.writeAll(payload);
            try aw.finish();
            break :blk sealed.written();
        } else payload;
        const zip64 = options.force_zip64 or data.len > u32_max or stored.len > u32_max;
        if (zip64 and !self.allow_zip64) return Error.ZipWriteTooLarge;

        const local_header_offset = self.offset;
        try self.writeLocal(name, h, crc, stored.len, data.len, zip64, false, options);
        try self.out.writeAll(stored);
        self.offset += stored.len;
        try self.record(name, h, crc, stored.len, data.len, local_header_offset, false, options);
    }

    /// A directory member (`name/`, stored, empty; Unix mode `0o755` unless
    /// `options.mode` says otherwise). The trailing '/' is added if missing.
    pub fn addDirectory(self: *ArchiveWriter, name: []const u8, options: AddEntryOptions) !void {
        var buf: [std.math.maxInt(u16)]u8 = undefined;
        const dir = if (std.mem.endsWith(u8, name, "/")) name else blk: {
            if (name.len + 1 > buf.len) return Error.ZipNameTooLong;
            @memcpy(buf[0..name.len], name);
            buf[name.len] = '/';
            break :blk buf[0 .. name.len + 1];
        };
        var o = options;
        o.method = .store;
        const h = try self.prepare(dir, .store, o, 0o040000);
        const off = self.offset;
        try self.writeLocal(dir, h, 0, 0, 0, o.force_zip64, false, o);
        try self.record(dir, h, 0, 0, 0, off, false, o);
    }

    /// A Unix symlink member: its content is `target`, stored, mode
    /// `S_IFLNK | 0o777` unless `options.mode` says otherwise.
    pub fn addSymlink(self: *ArchiveWriter, name: []const u8, target: []const u8, options: AddEntryOptions) !void {
        var o = options;
        o.method = .store;
        if (o.mode == null) o.mode = 0o777;
        const h = try self.prepare(name, .store, o, 0o120000);
        const crc = crc32.Crc32.hash(target);
        const off = self.offset;
        try self.writeLocal(name, h, crc, target.len, target.len, o.force_zip64, false, o);
        try self.out.writeAll(target);
        self.offset += target.len;
        try self.record(name, h, crc, target.len, target.len, off, false, o);
    }

    /// State of a streamed entry: the caller writes to `input`, which hashes
    /// and counts, then compresses into `output`, which counts and forwards
    /// to `out`. On the heap, so the returned writer stays put.
    const Streamed = struct {
        input: Tap,
        output: Tap,
        out_buf: [4096]u8,
        compress: std.compress.flate.Compress,
        window: [std.compress.flate.max_window_len]u8,
        codec: ?CodecWriter,
        aes: ?crypto.AesWriter,
        aes_buf: [4096]u8,
        method: WriteMethod,
        header: Header,
        options: AddEntryOptions,
        zip64: bool,
        offset: u64,
        name: []const u8,
    };

    /// Start a streamed member: write its bytes to the returned writer, then
    /// call `endEntry`. The CRC and sizes go into a data descriptor after the
    /// data (flag bit 3), so nothing is buffered beyond one deflate window.
    /// `options.force_zip64` makes room for an entry that may pass 4 GiB
    /// (the zip64 extra and a 64-bit descriptor); without it a streamed
    /// entry past 4 GiB is refused at `endEntry` (`ZipWriteTooLarge`),
    /// because its local header already promised 32-bit sizes.
    pub fn beginEntry(self: *ArchiveWriter, name: []const u8, options: AddEntryOptions) !*std.Io.Writer {
        const h = try self.prepare(name, options.method, options, unix_regular_file);
        if (options.force_zip64 and !self.allow_zip64) return Error.ZipWriteTooLarge;
        const s = try self.alloc.create(Streamed);
        errdefer self.alloc.destroy(s);
        s.method = options.method;
        s.header = h;
        s.options = options;
        s.zip64 = options.force_zip64;
        s.offset = self.offset;
        s.name = try self.name_arena.allocator().dupe(u8, name);
        try self.writeLocal(name, h, 0, 0, 0, s.zip64, true, options);
        s.output = .{ .next = self.out, .crc = null, .interface = .{ .buffer = &s.out_buf, .vtable = &Tap.vtable } };
        s.codec = null;
        s.aes = null;
        // Compressed bytes go to the encryptor when there is one.
        var below: *std.Io.Writer = &s.output.interface;
        if (options.encryption) |e| {
            var salt_buf: [16]u8 = undefined;
            const salt = try makeSalt(e, &salt_buf);
            s.aes = @as(crypto.AesWriter, undefined);
            try s.aes.?.start(&s.output.interface, e.strength, e.password, salt, &s.aes_buf);
            below = &s.aes.?.interface;
        }
        const sink: *std.Io.Writer = switch (options.method) {
            .store => below,
            .deflate => blk: {
                s.compress = try std.compress.flate.Compress.init(below, &s.window, .raw, options.level);
                break :blk &s.compress.writer;
            },
            .zstd, .custom => blk: {
                const codec = writeCodec(options).?;
                s.codec = try codec.open_writer.?(codec.context, self.alloc, below, options.codec_level);
                break :blk s.codec.?.writer;
            },
        };
        s.input = .{ .next = sink, .crc = .init(), .interface = .{ .buffer = &.{}, .vtable = &Tap.vtable } };
        self.open = s;
        return &s.input.interface;
    }

    /// Finish the streamed member: flush the compressor, write the data
    /// descriptor, record the entry.
    pub fn endEntry(self: *ArchiveWriter) !void {
        const s = self.open orelse unreachable; // no `beginEntry`
        defer {
            if (s.codec) |c| c.close(c.state, self.alloc);
            self.alloc.destroy(s);
            self.open = null;
        }
        try s.input.interface.flush();
        if (s.method == .deflate) try s.compress.finish();
        if (s.codec) |c| try c.finish(c.state);
        if (s.aes) |*a| try a.finish();
        try s.output.interface.flush();
        const crc = if (s.aes != null) 0 else s.input.crc.?.final(); // AE-2
        const usize_ = s.input.count;
        const csize = s.output.count;
        self.offset += csize;
        if (!s.zip64 and (usize_ > u32_max or csize > u32_max)) return Error.ZipWriteTooLarge;
        // Data descriptor, with its optional signature (every tool writes it).
        var dd: [24]u8 = undefined;
        std.mem.writeInt(u32, dd[0..4], 0x08074b50, .little);
        std.mem.writeInt(u32, dd[4..8], crc, .little);
        const dd_len: usize = if (s.zip64) 24 else 16;
        if (s.zip64) {
            std.mem.writeInt(u64, dd[8..16], csize, .little);
            std.mem.writeInt(u64, dd[16..24], usize_, .little);
        } else {
            std.mem.writeInt(u32, dd[8..12], @intCast(csize), .little);
            std.mem.writeInt(u32, dd[12..16], @intCast(usize_), .little);
        }
        try self.out.writeAll(dd[0..dd_len]);
        self.offset += dd_len;
        try self.record(s.name, s.header, crc, csize, usize_, s.offset, true, s.options);
    }

    /// Writes the central directory and the end-of-central-directory record
    /// (with the zip64 end record and locator when a field needs them).
    /// Call exactly once, after all entries are added. `out` still needs a
    /// final flush by the caller — `finish()` never flushes/closes it.
    pub fn finish(self: *ArchiveWriter) !void {
        std.debug.assert(!self.finished);
        std.debug.assert(self.open == null); // `endEntry` first
        self.finished = true;
        if (self.comment.len > std.math.maxInt(u16)) return Error.ZipWriteTooLarge;

        const cd_offset = self.offset;
        if (!self.allow_zip64 and cd_offset > u32_max) return Error.ZipWriteTooLarge;
        for (self.entries.items) |e| {
            // zip64 extra in the central directory: only the saturated
            // fields, in the fixed order (APPNOTE 4.5.3).
            var z64: [4 + 24]u8 = undefined;
            var zl: usize = 4;
            const big_u = e.uncompressed_size > u32_max or e.force_zip64;
            const big_c = e.compressed_size > u32_max or e.force_zip64;
            const big_o = e.local_header_offset > u32_max;
            if (big_u) {
                std.mem.writeInt(u64, z64[zl..][0..8], e.uncompressed_size, .little);
                zl += 8;
            }
            if (big_c) {
                std.mem.writeInt(u64, z64[zl..][0..8], e.compressed_size, .little);
                zl += 8;
            }
            if (big_o) {
                std.mem.writeInt(u64, z64[zl..][0..8], e.local_header_offset, .little);
                zl += 8;
            }
            const has64 = zl > 4;
            if (has64 and !self.allow_zip64) return Error.ZipWriteTooLarge;
            std.mem.writeInt(u16, z64[0..2], 0x0001, .little);
            std.mem.writeInt(u16, z64[2..4], @intCast(zl - 4), .little);
            const extra_len: u16 = @intCast(@as(usize, if (e.ut != null) ut_extra_len else 0) + (if (has64) zl else 0) +
                @as(usize, if (e.aes_extra != null) 11 else 0) + e.extra.len);
            const cdh: std.zip.CentralDirectoryFileHeader = .{
                .signature = std.zip.central_file_header_sig,
                // Host in the high byte: 0 = MS-DOS (no attributes), 3 = Unix
                // (the high half of the external attributes is `st_mode`).
                .version_made_by = (if (e.unix_mode != null) host_unix << 8 else 0) | @as(u16, if (has64) 45 else 20),
                .version_needed_to_extract = if (has64) 45 else 20,
                .flags = @bitCast(e.flags),
                .compression_method = e.method,
                .last_modification_time = e.dos.time,
                .last_modification_date = e.dos.date,
                .crc32 = e.crc32,
                .compressed_size = if (big_c) u32_max else @intCast(e.compressed_size),
                .uncompressed_size = if (big_u) u32_max else @intCast(e.uncompressed_size),
                .filename_len = @intCast(e.name.len),
                .extra_len = extra_len,
                .comment_len = @intCast(e.comment.len),
                .disk_number = 0,
                .internal_file_attributes = 0,
                .external_file_attributes = if (e.unix_mode) |m| m << 16 else 0,
                .local_file_header_offset = if (big_o) u32_max else @intCast(e.local_header_offset),
            };
            try writeHeaderLE(std.zip.CentralDirectoryFileHeader, self.out, cdh);
            try self.out.writeAll(e.name);
            if (e.ut) |t| try writeUtExtra(self.out, t);
            if (has64) try self.out.writeAll(z64[0..zl]);
            if (e.aes_extra) |*x| try self.out.writeAll(x);
            try self.out.writeAll(e.extra);
            try self.out.writeAll(e.comment);
            self.offset += @sizeOf(std.zip.CentralDirectoryFileHeader) + e.name.len + extra_len + e.comment.len;
        }
        const cd_size = self.offset - cd_offset;
        const count = self.entries.items.len;
        const need64 = count >= 0xffff or cd_size > u32_max or cd_offset > u32_max;
        if (need64) {
            if (!self.allow_zip64) return Error.ZipWriteTooLarge;
            const rec_off = self.offset;
            var rec: [56]u8 = undefined;
            @memcpy(rec[0..4], &std.zip.end_record64_sig);
            std.mem.writeInt(u64, rec[4..12], 44, .little); // size of the rest
            std.mem.writeInt(u16, rec[12..14], 45, .little); // version made by
            std.mem.writeInt(u16, rec[14..16], 45, .little); // version needed
            std.mem.writeInt(u32, rec[16..20], 0, .little); // this disk
            std.mem.writeInt(u32, rec[20..24], 0, .little); // the directory's disk
            std.mem.writeInt(u64, rec[24..32], count, .little);
            std.mem.writeInt(u64, rec[32..40], count, .little);
            std.mem.writeInt(u64, rec[40..48], cd_size, .little);
            std.mem.writeInt(u64, rec[48..56], cd_offset, .little);
            try self.out.writeAll(&rec);
            var loc: [20]u8 = undefined;
            @memcpy(loc[0..4], &std.zip.end_locator64_sig);
            std.mem.writeInt(u32, loc[4..8], 0, .little);
            std.mem.writeInt(u64, loc[8..16], rec_off, .little);
            std.mem.writeInt(u32, loc[16..20], 1, .little); // total disks
            try self.out.writeAll(&loc);
            self.offset += rec.len + loc.len;
        }
        const eocd: std.zip.EndRecord = .{
            .signature = std.zip.end_record_sig,
            .disk_number = 0,
            .central_directory_disk_number = 0,
            .record_count_disk = if (count >= 0xffff) 0xffff else @intCast(count),
            .record_count_total = if (count >= 0xffff) 0xffff else @intCast(count),
            .central_directory_size = if (cd_size > u32_max) u32_max else @intCast(cd_size),
            .central_directory_offset = if (cd_offset > u32_max) u32_max else @intCast(cd_offset),
            .comment_len = @intCast(self.comment.len),
        };
        try writeHeaderLE(std.zip.EndRecord, self.out, eocd);
        try self.out.writeAll(self.comment);
    }
};

/// A pass-through writer that counts (and optionally CRCs) what it forwards.
const Tap = struct {
    next: *std.Io.Writer,
    crc: ?crc32.Crc32,
    count: u64 = 0,
    interface: std.Io.Writer,

    const vtable: std.Io.Writer.VTable = .{ .drain = drain, .flush = flush };

    fn consume(self: *Tap, bytes: []const u8) std.Io.Writer.Error!void {
        if (bytes.len == 0) return;
        if (self.crc) |*c| c.update(bytes);
        self.count += bytes.len;
        try self.next.writeAll(bytes);
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *Tap = @alignCast(@fieldParentPtr("interface", w));
        try self.consume(w.buffered());
        w.end = 0;
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            try self.consume(d);
            n += d.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| try self.consume(last);
        return n + last.len * splat;
    }

    fn flush(w: *std.Io.Writer) std.Io.Writer.Error!void {
        const self: *Tap = @alignCast(@fieldParentPtr("interface", w));
        try self.consume(w.buffered());
        w.end = 0;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
const testing = std.testing;

// The unit tests build tiny zips by hand (no external tool) to exercise the
// central-directory walk, name handling and the streaming read path for both
// supported compression methods, plus the error paths for truncated/corrupt
// input. `buildZip` reuses the same std.zip structs the production walk
// parses, so the byte layout can't drift out of sync with what `Archive`
// actually reads.

/// One member for the test-zip builder.
const TestMember = struct {
    name: []const u8,
    data: []const u8,
    method: std.zip.CompressionMethod = .store,
};

/// Raw-deflates `data` (no zlib/gzip container — the same framing ZIP's
/// Deflate method uses) via `std.compress.flate.Compress`. Caller owns the
/// returned slice.
fn deflateRaw(a: Allocator, data: []const u8) ![]u8 {
    var aw = try std.Io.Writer.Allocating.initCapacity(a, 256);
    defer aw.deinit();
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var compress = try std.compress.flate.Compress.init(&aw.writer, &window, .raw, .default);
    try compress.writer.writeAll(data);
    try compress.finish();
    return a.dupe(u8, aw.writer.buffered());
}

/// Builds a minimal but real ZIP byte stream from `members` (Store or
/// Deflate per member), using the same std.zip structs the production walk
/// parses.
fn buildZip(a: Allocator, members: []const TestMember) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(a);

    // Per-member compressed bytes (owned here; freed after writing).
    var compressed: std.ArrayList([]u8) = .empty;
    defer {
        for (compressed.items) |c| a.free(c);
        compressed.deinit(a);
    }
    for (members) |m| {
        const c = switch (m.method) {
            .deflate => try deflateRaw(a, m.data),
            else => try a.dupe(u8, m.data),
        };
        try compressed.append(a, c);
    }

    var offs: std.ArrayList(u32) = .empty;
    defer offs.deinit(a);

    for (members, compressed.items) |m, c| {
        try offs.append(a, @intCast(buf.items.len));
        // Real CRC-32 of the *uncompressed* content — matches what a genuine
        // writer emits, and what `EntryReader`'s CRC verification (F4 fix)
        // now checks on read. A hardcoded 0 here would make every decode
        // test below fail against its own fixture once verification exists.
        const crc = std.hash.Crc32.hash(m.data);
        const lfh = std.zip.LocalFileHeader{
            .signature = std.zip.local_file_header_sig,
            .version_needed_to_extract = 20,
            .flags = @bitCast(@as(u16, 0)),
            .compression_method = m.method,
            .last_modification_time = 0,
            .last_modification_date = 0,
            .crc32 = crc,
            .compressed_size = @intCast(c.len),
            .uncompressed_size = @intCast(m.data.len),
            .filename_len = @intCast(m.name.len),
            .extra_len = 0,
        };
        try buf.appendSlice(a, std.mem.asBytes(&lfh));
        try buf.appendSlice(a, m.name);
        try buf.appendSlice(a, c);
    }

    const cd_offset: u32 = @intCast(buf.items.len);
    for (members, offs.items, compressed.items) |m, off, c| {
        const cdh = std.zip.CentralDirectoryFileHeader{
            .signature = std.zip.central_file_header_sig,
            .version_made_by = 20,
            .version_needed_to_extract = 20,
            .flags = @bitCast(@as(u16, 0)),
            .compression_method = m.method,
            .last_modification_time = 0,
            .last_modification_date = 0,
            .crc32 = std.hash.Crc32.hash(m.data),
            .compressed_size = @intCast(c.len),
            .uncompressed_size = @intCast(m.data.len),
            .filename_len = @intCast(m.name.len),
            .extra_len = 0,
            .comment_len = 0,
            .disk_number = 0,
            .internal_file_attributes = 0,
            .external_file_attributes = 0,
            .local_file_header_offset = off,
        };
        try buf.appendSlice(a, std.mem.asBytes(&cdh));
        try buf.appendSlice(a, m.name);
    }
    const cd_size: u32 = @intCast(buf.items.len - cd_offset);

    const eocd = std.zip.EndRecord{
        .signature = std.zip.end_record_sig,
        .disk_number = 0,
        .central_directory_disk_number = 0,
        .record_count_disk = @intCast(members.len),
        .record_count_total = @intCast(members.len),
        .central_directory_size = cd_size,
        .central_directory_offset = cd_offset,
        .comment_len = 0,
    };
    try buf.appendSlice(a, std.mem.asBytes(&eocd));

    return buf.toOwnedSlice(a);
}

fn openZip(tmp: *std.testing.TmpDir, bytes: []const u8) !std.Io.File {
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "t.zip", .data = bytes });
    return tmp.dir.openFile(testing.io, "t.zip", .{});
}

/// Builds a single-entry ZIP64 archive by hand: the local *and* central-
/// directory headers carry 0xFFFFFFFF 32-bit-field placeholders with the real
/// sizes/offset relocated into a zip64 extra field (`ExtraHeader.zip64_info`),
/// and the classic EOCD's totals are likewise placeholder-0xFFFF/0xFFFFFFFF
/// with the real values living in a zip64 EOCD + zip64 EOCD locator ahead of
/// it — the same escape-to-64-bit machinery a real zip64 writer emits for a
/// >4 GiB member or a >65535-entry archive, faked here on a tiny member
/// purely to exercise `std.zip.Iterator`'s zip64 parsing path (which this
/// module's `Archive`/`EntryReader` inherit unmodified) deterministically,
/// without needing an actual multi-gigabyte test fixture.
fn buildZip64(a: Allocator, name: []const u8, data: []const u8, method: std.zip.CompressionMethod) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(a);

    const compressed = switch (method) {
        .deflate => try deflateRaw(a, data),
        else => try a.dupe(u8, data),
    };
    defer a.free(compressed);
    // Real CRC-32 of the uncompressed content — see the identical note in
    // `buildZip`; a stub 0 here would fail `EntryReader`'s new verification.
    const crc = std.hash.Crc32.hash(data);

    // --- Local file header + zip64 extra (uncompressed_size, compressed_size) ---
    const local_offset: u32 = @intCast(buf.items.len);
    const lfh = std.zip.LocalFileHeader{
        .signature = std.zip.local_file_header_sig,
        .version_needed_to_extract = 45,
        .flags = @bitCast(@as(u16, 0)),
        .compression_method = method,
        .last_modification_time = 0,
        .last_modification_date = 0,
        .crc32 = crc,
        .compressed_size = 0xFFFFFFFF,
        .uncompressed_size = 0xFFFFFFFF,
        .filename_len = @intCast(name.len),
        .extra_len = 4 + 16,
    };
    try buf.appendSlice(a, std.mem.asBytes(&lfh));
    try buf.appendSlice(a, name);
    {
        var hdr: [4]u8 = undefined;
        std.mem.writeInt(u16, hdr[0..2], @backingInt(std.zip.ExtraHeader.zip64_info), .little);
        std.mem.writeInt(u16, hdr[2..4], 16, .little);
        try buf.appendSlice(a, &hdr);
        var v64: [8]u8 = undefined;
        std.mem.writeInt(u64, &v64, data.len, .little);
        try buf.appendSlice(a, &v64);
        std.mem.writeInt(u64, &v64, compressed.len, .little);
        try buf.appendSlice(a, &v64);
    }
    try buf.appendSlice(a, compressed);

    // --- Central directory header + zip64 extra (uncompressed, compressed, local offset) ---
    const cd_offset: u32 = @intCast(buf.items.len);
    const cdh = std.zip.CentralDirectoryFileHeader{
        .signature = std.zip.central_file_header_sig,
        .version_made_by = 45,
        .version_needed_to_extract = 45,
        .flags = @bitCast(@as(u16, 0)),
        .compression_method = method,
        .last_modification_time = 0,
        .last_modification_date = 0,
        .crc32 = crc,
        .compressed_size = 0xFFFFFFFF,
        .uncompressed_size = 0xFFFFFFFF,
        .filename_len = @intCast(name.len),
        .extra_len = 4 + 24,
        .comment_len = 0,
        .disk_number = 0,
        .internal_file_attributes = 0,
        .external_file_attributes = 0,
        .local_file_header_offset = 0xFFFFFFFF,
    };
    try buf.appendSlice(a, std.mem.asBytes(&cdh));
    try buf.appendSlice(a, name);
    {
        var hdr: [4]u8 = undefined;
        std.mem.writeInt(u16, hdr[0..2], @backingInt(std.zip.ExtraHeader.zip64_info), .little);
        std.mem.writeInt(u16, hdr[2..4], 24, .little);
        try buf.appendSlice(a, &hdr);
        var v64: [8]u8 = undefined;
        std.mem.writeInt(u64, &v64, data.len, .little);
        try buf.appendSlice(a, &v64);
        std.mem.writeInt(u64, &v64, compressed.len, .little);
        try buf.appendSlice(a, &v64);
        std.mem.writeInt(u64, &v64, local_offset, .little);
        try buf.appendSlice(a, &v64);
    }
    const cd_size: u32 = @intCast(buf.items.len - cd_offset);

    // --- zip64 EOCD + zip64 EOCD locator, ahead of a classic EOCD whose own
    // totals are all forced to the 0xFFFF/0xFFFFFFFF "look in the zip64
    // record instead" placeholders (`EndRecord.need_zip64`). ---
    const record64_offset: u64 = @intCast(buf.items.len);
    const record64 = std.zip.EndRecord64{
        .signature = std.zip.end_record64_sig,
        .end_record_size = @sizeOf(std.zip.EndRecord64) - 12,
        .version_made_by = 45,
        .version_needed_to_extract = 45,
        .disk_number = 0,
        .central_directory_disk_number = 0,
        .record_count_disk = 1,
        .record_count_total = 1,
        .central_directory_size = cd_size,
        .central_directory_offset = cd_offset,
    };
    try buf.appendSlice(a, std.mem.asBytes(&record64));

    const locator = std.zip.EndLocator64{
        .signature = std.zip.end_locator64_sig,
        .zip64_disk_count = 0,
        .record_file_offset = record64_offset,
        .total_disk_count = 1,
    };
    try buf.appendSlice(a, std.mem.asBytes(&locator));

    const eocd = std.zip.EndRecord{
        .signature = std.zip.end_record_sig,
        .disk_number = 0,
        .central_directory_disk_number = 0,
        .record_count_disk = 0xFFFF,
        .record_count_total = 0xFFFF,
        .central_directory_size = 0xFFFFFFFF,
        .central_directory_offset = 0xFFFFFFFF,
        .comment_len = 0,
    };
    try buf.appendSlice(a, std.mem.asBytes(&eocd));

    return buf.toOwnedSlice(a);
}

test "Archive: enumerates members, skips dir entries, find + findSuffix" {
    const a = testing.allocator;
    const zip = try buildZip(a, &.{
        .{ .name = "dir/", .data = "" },
        .{ .name = "a.csv", .data = "x" },
        .{ .name = "sub/b.csv", .data = "y" },
    });
    defer a.free(zip);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var f = try openZip(&tmp, zip);
    defer f.close(testing.io);

    var archive: Archive = undefined;
    try archive.init(testing.io, a, f);
    defer archive.deinit();

    // The trailing-slash directory entry is skipped.
    try testing.expectEqual(@as(usize, 2), archive.entries.items.len);
    try testing.expect(archive.find("a.csv") != null);
    try testing.expect(archive.find("missing") == null);
    try testing.expect(archive.findSuffix("b.csv") != null);
    try testing.expectEqualStrings("sub/b.csv", archive.findSuffix("b.csv").?.name);
}

test "Archive.init: hostile central-directory header (filename_len 0xFFFF) is rejected, not a panic (audit CRIT)" {
    const a = testing.allocator;
    const zip = try buildZip(a, &.{.{ .name = "a.csv", .data = "x" }});
    defer a.free(zip);

    // Batch-10 audit CRIT: std.zip.Iterator.next advances by
    // (46 + filename_len + extra_len + comment_len) in u16, which overflows / panics
    // on a hostile header. Corrupt the central-directory header's filename_len to
    // 0xFFFF; our pre-validation must reject it as a bad directory, never overflow.
    const cd_sig = std.zip.central_file_header_sig;
    const cd_start = std.mem.find(u8, zip, &cd_sig).?;
    // filename_len sits at offset 28 within CentralDirectoryFileHeader.
    std.mem.writeInt(u16, zip[cd_start + 28 ..][0..2], 0xFFFF, .little);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var f = try openZip(&tmp, zip);
    defer f.close(testing.io);

    var archive: Archive = undefined;
    try testing.expectError(Error.ZipBadCentralDirectory, archive.init(testing.io, a, f));
}

test "EntryReader: streams a stored entry, then a second one (shared cursor)" {
    const a = testing.allocator;
    const zip = try buildZip(a, &.{
        .{ .name = "one.csv", .data = "hello,world" },
        .{ .name = "two.csv", .data = "a,b,c\n1,2,3" },
    });
    defer a.free(zip);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var f = try openZip(&tmp, zip);
    defer f.close(testing.io);

    var archive: Archive = undefined;
    try archive.init(testing.io, a, f);
    defer archive.deinit();

    var window: [std.compress.flate.max_window_len]u8 = undefined;

    var er1: EntryReader = undefined;
    try er1.init(&archive, archive.find("one.csv").?, &window);
    var out1: std.ArrayList(u8) = .empty;
    defer out1.deinit(a);
    try er1.reader().appendRemaining(a, &out1, .unlimited);
    try testing.expectEqualStrings("hello,world", out1.items);

    // Opening a second entry reseeks the shared file cursor.
    var er2: EntryReader = undefined;
    try er2.init(&archive, archive.find("two.csv").?, &window);
    var out2: std.ArrayList(u8) = .empty;
    defer out2.deinit(a);
    try er2.reader().appendRemaining(a, &out2, .unlimited);
    try testing.expectEqualStrings("a,b,c\n1,2,3", out2.items);
}

test "EntryReader: multi-entry archive with Store + Deflate mix" {
    const a = testing.allocator;
    const long_text =
        strRepeat("the quick brown fox jumps over the lazy dog, ", 40); // compresses well
    const zip = try buildZip(a, &.{
        .{ .name = "stored.txt", .data = "plain stored bytes", .method = .store },
        .{ .name = "deflated.txt", .data = long_text, .method = .deflate },
        .{ .name = "stored2.txt", .data = "another stored member", .method = .store },
    });
    defer a.free(zip);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var f = try openZip(&tmp, zip);
    defer f.close(testing.io);

    var archive: Archive = undefined;
    try archive.init(testing.io, a, f);
    defer archive.deinit();

    try testing.expectEqual(@as(usize, 3), archive.entries.items.len);
    try testing.expectEqual(std.zip.CompressionMethod.deflate, archive.find("deflated.txt").?.compression);
    try testing.expectEqual(std.zip.CompressionMethod.store, archive.find("stored.txt").?.compression);

    var window: [std.compress.flate.max_window_len]u8 = undefined;

    // Verify actual byte content round-trips for each method.
    var er_store1: EntryReader = undefined;
    try er_store1.init(&archive, archive.find("stored.txt").?, &window);
    var out_store1: std.ArrayList(u8) = .empty;
    defer out_store1.deinit(a);
    try er_store1.reader().appendRemaining(a, &out_store1, .unlimited);
    try testing.expectEqualStrings("plain stored bytes", out_store1.items);

    var er_deflate: EntryReader = undefined;
    try er_deflate.init(&archive, archive.find("deflated.txt").?, &window);
    var out_deflate: std.ArrayList(u8) = .empty;
    defer out_deflate.deinit(a);
    try er_deflate.reader().appendRemaining(a, &out_deflate, .unlimited);
    try testing.expectEqualStrings(long_text, out_deflate.items);

    var er_store2: EntryReader = undefined;
    try er_store2.init(&archive, archive.find("stored2.txt").?, &window);
    var out_store2: std.ArrayList(u8) = .empty;
    defer out_store2.deinit(a);
    try er_store2.reader().appendRemaining(a, &out_store2, .unlimited);
    try testing.expectEqualStrings("another stored member", out_store2.items);

    // All three reads above completed to a clean EOF with matching content,
    // so `EntryReader`'s new CRC-32 verification (audit F4) ran and agreed —
    // confirms the happy path isn't broken by the fix.
    try testing.expect(!er_store1.crcMismatch());
    try testing.expect(!er_deflate.crcMismatch());
    try testing.expect(!er_store2.crcMismatch());
}

test "EntryReader: CRC-32 mismatch on a tampered member is caught, not delivered as valid data (audit F4)" {
    // Reproduces the exact defect F4 flagged: a member whose actual bytes
    // disagree with the archive's own declared checksum was previously
    // returned to the caller as if nothing were wrong. Patch the central
    // directory's crc32 field only (data bytes untouched, still a fully
    // valid Store or Deflate stream) so this cannot be confused with a
    // decode-format error from a corrupted compressed bitstream — this
    // isolates the CRC check itself, for both compression methods.
    const a = testing.allocator;
    for ([_]std.zip.CompressionMethod{ .store, .deflate }) |method| {
        const zip = try buildZip(a, &.{.{ .name = "a.dat", .data = "not corrupted at all, honest", .method = method }});
        defer a.free(zip);

        const cd_sig = std.zip.central_file_header_sig;
        const cd_start = std.mem.find(u8, zip, &cd_sig).?;
        // crc32 sits at offset 16 within CentralDirectoryFileHeader (after
        // signature(4)+version_made_by(2)+version_needed(2)+flags(2)+
        // compression_method(2)+mtime(2)+mdate(2) = 16), same struct this
        // module's own "hostile filename_len" CRIT test patches by offset.
        const real_crc = std.mem.readInt(u32, zip[cd_start + 16 ..][0..4], .little);
        std.mem.writeInt(u32, zip[cd_start + 16 ..][0..4], real_crc ^ 0xFFFFFFFF, .little);

        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        var f = try openZip(&tmp, zip);
        defer f.close(testing.io);

        var archive: Archive = undefined;
        try archive.init(testing.io, a, f);
        defer archive.deinit();
        const entry = archive.find("a.dat").?;

        var window: [std.compress.flate.max_window_len]u8 = undefined;
        var er: EntryReader = undefined;
        try er.init(&archive, entry, &window);

        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(a);
        try testing.expectError(error.ReadFailed, er.reader().appendRemaining(a, &out, .unlimited));
        try testing.expect(er.crcMismatch());
    }
}

test "Archive: empty archive has zero entries" {
    const a = testing.allocator;
    const zip = try buildZip(a, &.{});
    defer a.free(zip);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var f = try openZip(&tmp, zip);
    defer f.close(testing.io);

    var archive: Archive = undefined;
    try archive.init(testing.io, a, f);
    defer archive.deinit();

    try testing.expectEqual(@as(usize, 0), archive.entries.items.len);
    try testing.expect(archive.find("anything") == null);
    try testing.expect(archive.findSuffix("thing") == null);
}

test "Archive.init on a truncated archive returns a clean error, not a panic" {
    const a = testing.allocator;
    const zip = try buildZip(a, &.{
        .{ .name = "one.csv", .data = "hello,world" },
    });
    defer a.free(zip);

    // Cut the file well before the end-of-central-directory record: the
    // central directory (and its EOCD signature) is entirely gone.
    const truncated = zip[0 .. zip.len / 2];

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var f = try openZip(&tmp, truncated);
    defer f.close(testing.io);

    var archive: Archive = undefined;
    try testing.expectError(error.ZipNoEndRecord, archive.init(testing.io, a, f));
}

test "EntryReader.init on a corrupted local header signature errors cleanly" {
    const a = testing.allocator;
    const zip = try buildZip(a, &.{
        .{ .name = "one.csv", .data = "hello,world" },
    });
    defer a.free(zip);

    // The central directory still parses fine (it doesn't read local
    // headers), but flip the local file header's magic bytes so opening an
    // EntryReader for this entry must fail instead of misreading garbage.
    const corrupted = try a.dupe(u8, zip);
    defer a.free(corrupted);
    corrupted[2] = 0xFF; // was 'PK\x03\x04', now 'PK\xFF\x04'

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var f = try openZip(&tmp, corrupted);
    defer f.close(testing.io);

    var archive: Archive = undefined;
    try archive.init(testing.io, a, f);
    defer archive.deinit();
    try testing.expectEqual(@as(usize, 1), archive.entries.items.len);

    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var er: EntryReader = undefined;
    try testing.expectError(Error.ZipBadFileOffset, er.init(&archive, archive.find("one.csv").?, &window));
}

test "EntryReader: a size lie beyond physical EOF errors cleanly, not UB" {
    // Simulates a central directory whose declared uncompressed_size for a
    // Store entry outruns what's actually on disk (truncated file, or a
    // corrupted/hostile size field) — the archive itself parses fine, only
    // the one entry's bookkeeping is wrong.
    const a = testing.allocator;
    const zip = try buildZip(a, &.{
        .{ .name = "one.csv", .data = "hello world, this is more than a few bytes long" },
    });
    defer a.free(zip);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var f = try openZip(&tmp, zip);
    defer f.close(testing.io);

    var archive: Archive = undefined;
    try archive.init(testing.io, a, f);
    defer archive.deinit();

    // A hand-corrupted Entry: same location/method as the real one, but a
    // declared size that vastly exceeds the entire physical file (entry data
    // + central directory + EOCD combined).
    var lying_entry = archive.find("one.csv").?.*;
    lying_entry.uncompressed_size = 1 << 20;
    lying_entry.compressed_size = 1 << 20; // a stored entry's two sizes agree

    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var er: EntryReader = undefined;
    try er.init(&archive, &lying_entry, &window);

    // `uncompressed_size` stays `u64` in production (zip64 entries can
    // legitimately exceed a 32-bit `usize`; that's what `entry.uncompressed_size
    // > max_output` at line ~290 guards before any real allocation happens).
    // This test sets it to a small literal (`1 << 20`) itself a few lines up,
    // so the value here is always in-range and the cast is safe.
    const buf = try a.alloc(u8, @as(usize, @intCast(lying_entry.uncompressed_size)));
    defer a.free(buf);
    // Reading the full (lying) declared size must hit a clean error instead
    // of looping forever or reading past the allocation. Before the CRC-32
    // check (audit F4) this surfaced as a bare `error.EndOfStream` once the
    // physical file ran out; now the extra bytes it ran into (central
    // directory + EOCD, past the true entry boundary) get folded into the
    // running CRC too, so it *also* disagrees with `lying_entry.crc32` (the
    // real short entry's checksum) — a strictly sharper diagnosis of the
    // same underlying problem ("this data doesn't match what it claims to
    // be"), not just "the stream stopped".
    try testing.expectError(error.ReadFailed, er.reader().readSliceAll(buf));
    try testing.expect(er.crcMismatch());
}

test "EntryReader: a deflate stream cut short at end of file is a clean error, not a std flate panic" {
    // std 0.16 `flate.Decompress` hits `unreachable` (`tossBitsShort` checks
    // `+ consumed_bits` where it needs `-`) when its input ENDS inside a
    // block — any proper prefix of an ordinary stream does it. The entry's
    // data here sits at the very end of the file: the archive's EOCD comment
    // holds a local header and a prefix of a real deflate stream, and the
    // entry points at it. Every prefix length, so every bit position the
    // stream can end at.
    const a = testing.allocator;
    var data: [1500]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = "the quick brown fox jumps "[i % 26] ^ @as(u8, @truncate(i *% 2654435761 >> 13 & 1));
    const full = try deflateRaw(a, &data);
    defer a.free(full);
    const base = try buildZip(a, &.{.{ .name = "a", .data = "a" }});
    defer a.free(base);
    const name = "cut";

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var out: [data.len]u8 = undefined;
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(a);
    for (1..full.len) |n| {
        bytes.clearRetainingCapacity();
        try bytes.appendSlice(a, base);
        const comment_len = @sizeOf(std.zip.LocalFileHeader) + name.len + n;
        std.mem.writeInt(u16, bytes.items[bytes.items.len - 2 ..][0..2], @intCast(comment_len), .little);
        const lfh = std.zip.LocalFileHeader{
            .signature = std.zip.local_file_header_sig,
            .version_needed_to_extract = 20,
            .flags = @bitCast(@as(u16, 0)),
            .compression_method = .deflate,
            .last_modification_time = 0,
            .last_modification_date = 0,
            .crc32 = std.hash.Crc32.hash(&data),
            .compressed_size = @intCast(n),
            .uncompressed_size = data.len,
            .filename_len = name.len,
            .extra_len = 0,
        };
        try bytes.appendSlice(a, std.mem.asBytes(&lfh));
        try bytes.appendSlice(a, name);
        try bytes.appendSlice(a, full[0..n]);

        var f = try openZip(&tmp, bytes.items);
        defer f.close(testing.io);
        var archive: Archive = undefined;
        try archive.init(testing.io, a, f);
        defer archive.deinit();
        var cut = archive.entries.items[0];
        cut.compression = .deflate;
        cut.file_offset = base.len;
        cut.compressed_size = n;
        cut.uncompressed_size = data.len;
        cut.crc32 = std.hash.Crc32.hash(&data);

        // Reading exactly the declared size: the zero padding can decode to
        // a full-length output, and the CRC-32 must stop it on that read.
        // A prefix that lost only the final block's tail bits may decode to
        // the right bytes -- then it IS the entry, and the CRC agrees.
        var er: EntryReader = undefined;
        try er.init(&archive, &cut, &window);
        if (er.reader().readSliceAll(&out)) |_| {
            if (!std.mem.eql(u8, &out, &data)) {
                std.debug.print("prefix {d}/{d}: wrong bytes delivered without an error\n", .{ n, full.len });
                return error.TestUnexpectedResult;
            }
        } else |err| switch (err) {
            // The CRC-32 check, or the decoder refusing the padding
            // (an invalid code or block); both are clean.
            error.ReadFailed, error.EndOfStream => {},
        }
    }
}

test "isSafeEntryName flags zip-slip names, accepts ordinary member paths" {
    // Traversal, absolute and Windows drive/backslash tricks are rejected.
    try testing.expect(!isSafeEntryName("../x"));
    try testing.expect(!isSafeEntryName("a/../../b"));
    try testing.expect(!isSafeEntryName("a/.."));
    try testing.expect(!isSafeEntryName(".."));
    try testing.expect(!isSafeEntryName("/abs"));
    try testing.expect(!isSafeEntryName("\\abs"));
    try testing.expect(!isSafeEntryName("C:/Windows/x"));
    try testing.expect(!isSafeEntryName("C:\\Windows\\x"));
    try testing.expect(!isSafeEntryName("dir\\..\\..\\x"));
    try testing.expect(!isSafeEntryName(""));
    // Ordinary relative member paths, and names that merely contain dots,
    // are accepted (only a whole '..' segment is traversal).
    try testing.expect(isSafeEntryName("a.csv"));
    try testing.expect(isSafeEntryName("sub/b.csv"));
    try testing.expect(isSafeEntryName("a..b/c"));
    try testing.expect(isSafeEntryName("..."));
    try testing.expect(isSafeEntryName("deep/nested/dir/file.txt"));
}

test "EntryReader: a decompression bomb (declared size over the cap) is refused, not read unbounded" {
    const a = testing.allocator;

    // A highly compressible entry: 256 KiB of zeros deflates to a handful of
    // bytes — the shape of a decompression bomb (tiny on disk, huge expanded).
    const big = try a.alloc(u8, 256 * 1024);
    defer a.free(big);
    @memset(big, 0);
    const zip = try buildZip(a, &.{.{ .name = "bomb.bin", .data = big, .method = .deflate }});
    defer a.free(zip);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var f = try openZip(&tmp, zip);
    defer f.close(testing.io);

    var archive: Archive = undefined;
    try archive.init(testing.io, a, f);
    defer archive.deinit();

    const e = archive.find("bomb.bin").?;
    try testing.expectEqual(@as(u64, 256 * 1024), e.uncompressed_size);

    var window: [std.compress.flate.max_window_len]u8 = undefined;

    // A cap below the declared size refuses the entry up front — no unbounded
    // decompression, a clean typed error.
    var er_capped: EntryReader = undefined;
    try testing.expectError(Error.ZipEntryTooLarge, er_capped.initMax(&archive, e, &window, 64 * 1024));

    // A generous cap decompresses the same entry correctly, bounded to exactly
    // its declared size.
    var er_ok: EntryReader = undefined;
    try er_ok.initMax(&archive, e, &window, 1 << 20);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(a);
    try er_ok.reader().appendRemaining(a, &out, .unlimited);
    try testing.expectEqual(@as(usize, 256 * 1024), out.items.len);
}

test "default_max_output is pinned to the documented 1 GiB decompression-bomb ceiling" {
    // audit `zipstream` F7: this is the *delivered* cap for every caller of
    // plain `EntryReader.init` (13 call sites in this suite alone), but the
    // bomb-cap tests above only exercise the mechanism through `initMax`'s
    // own explicit values (64 KiB / 1 MiB) — nothing pinned the shipped
    // default itself, so it could be loosened arbitrarily with the suite
    // staying green. Pin the literal, not an inequality on the constant.
    try testing.expectEqual(@as(u64, 1 << 30), default_max_output);
}

// ---------------------------------------------------------------------------
// Writer tests
// ---------------------------------------------------------------------------

test "ArchiveWriter: Store + Deflate round-trip through zipstream's own reader, byte-exact + CRC verified independently via std.zip.Iterator" {
    const a = testing.allocator;

    const stored_data = "plain stored payload, unmodified bytes end to end";
    const deflate_data = strRepeat("the quick brown fox jumps over the lazy dog, ", 40);

    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();

    var zw = ArchiveWriter.init(a, &aw.writer);
    defer zw.deinit();

    try zw.addEntry("stored.txt", stored_data, .{ .method = .store });
    try zw.addEntry("deflated.txt", deflate_data, .{ .method = .deflate });
    try zw.finish();

    const bytes = aw.writer.buffered();

    // Independent cross-check via std.zip.Iterator directly on the raw bytes
    // (not this module's own Archive) — the positive control: a wrong
    // CRC/size/offset written by ArchiveWriter shows up here even if
    // `Archive`/`EntryReader` happened to tolerate it.
    {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        try tmp.dir.writeFile(testing.io, .{ .sub_path = "cross.zip", .data = bytes });
        var f = try tmp.dir.openFile(testing.io, "cross.zip", .{});
        defer f.close(testing.io);
        var buf: [64 * 1024]u8 = undefined;
        var fr = f.reader(testing.io, &buf);
        var iter = try std.zip.Iterator.init(&fr);

        var seen_stored = false;
        var seen_deflated = false;
        while (try iter.next()) |e| {
            var name_buf: [64]u8 = undefined;
            try fr.seekTo(e.header_zip_offset + @sizeOf(std.zip.CentralDirectoryFileHeader));
            const nm = name_buf[0..e.filename_len];
            try fr.interface.readSliceAll(nm);
            if (std.mem.eql(u8, nm, "stored.txt")) {
                seen_stored = true;
                try testing.expectEqual(std.hash.Crc32.hash(stored_data), e.crc32);
                try testing.expectEqual(@as(u64, stored_data.len), e.uncompressed_size);
                try testing.expectEqual(@as(u64, stored_data.len), e.compressed_size); // store: equal
            } else if (std.mem.eql(u8, nm, "deflated.txt")) {
                seen_deflated = true;
                try testing.expectEqual(std.hash.Crc32.hash(deflate_data), e.crc32);
                try testing.expectEqual(@as(u64, deflate_data.len), e.uncompressed_size);
                try testing.expect(e.compressed_size < deflate_data.len); // genuinely compressed
            } else return error.UnexpectedEntry;
        }
        try testing.expect(seen_stored and seen_deflated);
    }

    // Round-trip through zipstream's own Archive/EntryReader — byte-exact.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "w.zip", .data = bytes });
    var f = try tmp.dir.openFile(testing.io, "w.zip", .{});
    defer f.close(testing.io);

    var archive: Archive = undefined;
    try archive.init(testing.io, a, f);
    defer archive.deinit();
    try testing.expectEqual(@as(usize, 2), archive.entries.items.len);

    var window: [std.compress.flate.max_window_len]u8 = undefined;

    var er1: EntryReader = undefined;
    try er1.init(&archive, archive.find("stored.txt").?, &window);
    var out1: std.ArrayList(u8) = .empty;
    defer out1.deinit(a);
    try er1.reader().appendRemaining(a, &out1, .unlimited);
    try testing.expectEqualStrings(stored_data, out1.items);

    var er2: EntryReader = undefined;
    try er2.init(&archive, archive.find("deflated.txt").?, &window);
    var out2: std.ArrayList(u8) = .empty;
    defer out2.deinit(a);
    try er2.reader().appendRemaining(a, &out2, .unlimited);
    try testing.expectEqualStrings(deflate_data, out2.items);
}

test "ArchiveWriter.addEntry rejects zip-slip names, mirroring the reader's isSafeEntryName gate" {
    const a = testing.allocator;
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var zw = ArchiveWriter.init(a, &aw.writer);
    defer zw.deinit();

    try testing.expectError(Error.ZipUnsafeEntryName, zw.addEntry("../escape.txt", "x", .{}));
    try testing.expectError(Error.ZipUnsafeEntryName, zw.addEntry("a/../../b", "x", .{}));
    try testing.expectError(Error.ZipUnsafeEntryName, zw.addEntry("/abs.txt", "x", .{}));
    try testing.expectError(Error.ZipUnsafeEntryName, zw.addEntry("C:\\Windows\\x", "x", .{}));
    try testing.expectError(Error.ZipUnsafeEntryName, zw.addEntry("", "x", .{}));

    // Rejections don't corrupt the writer's state — a legitimate entry still
    // writes correctly afterwards.
    try zw.addEntry("ok.txt", "hello, safe entry", .{ .method = .store });
    try zw.finish();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var f = try openZip(&tmp, aw.writer.buffered());
    defer f.close(testing.io);
    var archive: Archive = undefined;
    try archive.init(testing.io, a, f);
    defer archive.deinit();
    try testing.expectEqual(@as(usize, 1), archive.entries.items.len);
    try testing.expect(archive.find("ok.txt") != null);
}

test "ArchiveWriter: with allow_zip64 = false the classic 32-bit guards fail closed (ZipWriteTooLarge)" {
    const a = testing.allocator;

    // addEntry: running offset already past the classic 32-bit ceiling.
    {
        var aw: std.Io.Writer.Allocating = .init(a);
        defer aw.deinit();
        var zw = ArchiveWriter.init(a, &aw.writer);
        defer zw.deinit();
        zw.allow_zip64 = false;
        zw.offset = @as(u64, std.math.maxInt(u32)) + 1; // whitebox: fake a huge prior archive
        try testing.expectError(Error.ZipWriteTooLarge, zw.addEntry("x.txt", "data", .{ .method = .store }));
    }

    // finish(): cd_offset (== running offset once all entries are written)
    // past the classic 32-bit ceiling — exercised without writing gigabytes.
    {
        var aw: std.Io.Writer.Allocating = .init(a);
        defer aw.deinit();
        var zw = ArchiveWriter.init(a, &aw.writer);
        defer zw.deinit();
        zw.allow_zip64 = false;
        try zw.addEntry("x.txt", "data", .{ .method = .store });
        zw.offset = @as(u64, std.math.maxInt(u32)) + 1; // whitebox: force cd_offset over the ceiling
        try testing.expectError(Error.ZipWriteTooLarge, zw.finish());
    }
}

// ---------------------------------------------------------------------------
// Mutation run 2026-10-04: one test per mutant the suite above let through.
// ---------------------------------------------------------------------------

/// Offset of the (first) central-directory header in `zip`.
fn cdStart(zip: []const u8) usize {
    return std.mem.find(u8, zip, &std.zip.central_file_header_sig).?;
}

/// `Archive.init` over `zip`, returning the archive or the init error.
fn initArchive(tmp: *std.testing.TmpDir, archive: *Archive, file: *std.Io.File, zip: []const u8) !void {
    file.* = try openZip(tmp, zip);
    errdefer file.close(testing.io);
    try archive.init(testing.io, testing.allocator, file.*);
}

fn expectInitError(expected: anyerror, zip: []const u8) !void {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var f = try openZip(&tmp, zip);
    defer f.close(testing.io);
    var archive: Archive = undefined;
    if (archive.init(testing.io, testing.allocator, f)) |_| {
        archive.deinit();
        return error.TestUnexpectedResult;
    } else |err| try testing.expectEqual(expected, err);
}

test "Archive.init: the central-directory pre-check is exact and owns its errors" {
    const a = testing.allocator;
    // A record whose name runs past the end of the file (46 + 65 490 bytes
    // in a small archive). Kept from the std.zip.Iterator era, when 65 536
    // was the first advance its u16 sum could not hold; the walk is this
    // module's own since 2026-10-05 and bounds every record by the file.
    {
        const zip = try buildZip(a, &.{.{ .name = "a.csv", .data = "x" }});
        defer a.free(zip);
        std.mem.writeInt(u16, zip[cdStart(zip) + 28 ..][0..2], 65490, .little);
        try expectInitError(Error.ZipBadCentralDirectory, zip);
    }
    // A record without the central-header signature is this module's
    // `ZipBadCentralDirectory` (the pre-check), not whatever std's
    // iterator would raise later (mutation 2026-10-04: dropping the
    // signature check survived).
    {
        const zip = try buildZip(a, &.{.{ .name = "a.csv", .data = "x" }});
        defer a.free(zip);
        zip[cdStart(zip) + 3] = 0;
        try expectInitError(Error.ZipBadCentralDirectory, zip);
    }
    // A method other than Store/Deflate is listed and refused when opened
    // (APPNOTE 4.4.5 method 12 = BZIP2). It was refused at init until
    // 2026-10-05, which made every other member of such an archive
    // unreadable; unzip and Go list it and fail only that member.
    {
        const zip = try buildZip(a, &.{ .{ .name = "a.csv", .data = "x" }, .{ .name = "b.csv", .data = "y" } });
        defer a.free(zip);
        std.mem.writeInt(u16, zip[cdStart(zip) + 10 ..][0..2], 12, .little);
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        var f = try openZip(&tmp, zip);
        defer f.close(testing.io);
        var archive: Archive = undefined;
        try archive.init(testing.io, a, f);
        defer archive.deinit();
        try testing.expectEqual(@as(usize, 2), archive.entries.items.len);
        var window: [std.compress.flate.max_window_len]u8 = undefined;
        var er: EntryReader = undefined;
        try testing.expectError(Error.UnsupportedCompressionMethod, er.init(&archive, archive.find("a.csv").?, &window));
        try er.init(&archive, archive.find("b.csv").?, &window);
        var out: [1]u8 = undefined;
        try er.reader().readSliceAll(&out);
        try testing.expectEqualStrings("y", &out);
    }
}

test "Archive: backslashes are normalised; mode comes only from a Unix host's non-zero attributes" {
    const a = testing.allocator;
    const zip = try buildZip(a, &.{
        .{ .name = "dir\\win.txt", .data = "w" },
        .{ .name = "unix0.txt", .data = "u" },
        .{ .name = "dos.txt", .data = "d" },
    });
    defer a.free(zip);
    // Second record: host 3 (Unix) with all-zero attributes. Third: host 0
    // (MS-DOS) with S_IFREG|0644 in the high half anyway.
    var cd = cdStart(zip);
    cd += 46 + "dir\\win.txt".len;
    std.mem.writeInt(u16, zip[cd + 4 ..][0..2], (3 << 8) | 20, .little);
    cd += 46 + "unix0.txt".len;
    std.mem.writeInt(u32, zip[cd + 38 ..][0..4], 0o100644 << 16, .little);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var f: std.Io.File = undefined;
    var archive: Archive = undefined;
    try initArchive(&tmp, &archive, &f, zip);
    defer f.close(testing.io);
    defer archive.deinit();
    // `Entry.name` doc: "Backslashes in the stored path are normalised to
    // '/'" (APPNOTE 4.4.17: '/' is the separator).
    try testing.expect(archive.find("dir/win.txt") != null);
    // `Entry.mode` doc: set only for host 3 AND attributes that carry bits;
    // APPNOTE 4.4.15 makes the external attributes host-dependent, so an
    // MS-DOS record's high half is not a Unix mode.
    try testing.expect(archive.find("unix0.txt").?.mode == null);
    try testing.expect(archive.find("dos.txt").?.mode == null);
}

test "Archive: a UT record without the mtime flag gives no time, the DOS fields decide" {
    // Info-ZIP extended timestamp: flags bit 0 = "modification time
    // present". Without it the DOS fields decide -- an ODD Unix second makes
    // the two sources distinguishable (DOS keeps even seconds). Mutation
    // 2026-10-04: ignoring the flag survived. (A record running past the
    // extra field never reaches `readUtMtime`: std's `Iterator.next` refuses
    // it first with `ZipBadExtraFieldSize`.)
    const a = testing.allocator;
    const t: i64 = 1_000_000_001;
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var zw = ArchiveWriter.init(a, &aw.writer);
    defer zw.deinit();
    try zw.addEntry("a", "x", .{ .method = .store, .mtime = t });
    try zw.finish();
    const ut = cdStart(aw.writer.buffered()) + 46 + 1; // the CD's UT record

    const zip = try a.dupe(u8, aw.writer.buffered());
    defer a.free(zip);
    zip[ut + 4] = 0; // flags: no mtime
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var f: std.Io.File = undefined;
    var archive: Archive = undefined;
    try initArchive(&tmp, &archive, &f, zip);
    defer f.close(testing.io);
    defer archive.deinit();
    try testing.expectEqual(@as(?i64, t - 1), archive.find("a").?.mtime);
}

test "EntryReader: the cap admits an entry of exactly max_output, and deflate output stops at the declared size" {
    const a = testing.allocator;
    // `initMax` doc: an entry whose size "already exceeds the cap" is
    // refused -- equal is not over (mutation 2026-10-04: `>=` survived).
    // And "the running output is additionally clamped to the declared
    // size": a deflate stream that expands past it is cut there (mutation:
    // an unclamped stream survived). The CD here declares 5 bytes and the
    // CRC of "hello" for a stream that inflates to "hello world".
    const zip = try buildZip(a, &.{.{ .name = "z", .data = "hello world", .method = .deflate }});
    defer a.free(zip);
    const cd = cdStart(zip);
    std.mem.writeInt(u32, zip[cd + 24 ..][0..4], 5, .little);
    std.mem.writeInt(u32, zip[cd + 16 ..][0..4], std.hash.Crc32.hash("hello"), .little);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var f: std.Io.File = undefined;
    var archive: Archive = undefined;
    try initArchive(&tmp, &archive, &f, zip);
    defer f.close(testing.io);
    defer archive.deinit();
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var er: EntryReader = undefined;
    try er.initMax(&archive, archive.find("z").?, &window, 5);
    const got = try er.reader().allocRemaining(a, .unlimited);
    defer a.free(got);
    try testing.expectEqualStrings("hello", got);
}

test "DosDateTime.toUnix: month 0, second 60 and 2100-02-29 are not times; 2024-02-29 is" {
    // APPNOTE 4.4.6 / FAT: month 1..12, seconds stored /2 as 0..29 (so 30 =
    // 60 s is out of range), and the Gregorian leap rule -- 2100 is not a
    // leap year. The `toUnix` doc lists "month 0" itself. Mutation
    // 2026-10-04: all three checks could be dropped unnoticed.
    const d2020: u16 = (40 << 9) | (6 << 5) | 15;
    try testing.expect((DosDateTime{ .time = 0, .date = (40 << 9) | (0 << 5) | 15 }).toUnix() == null);
    try testing.expect((DosDateTime{ .time = 30, .date = d2020 }).toUnix() == null);
    try testing.expect((DosDateTime{ .time = 29, .date = d2020 }).toUnix() != null);
    try testing.expect((DosDateTime{ .time = 0, .date = (120 << 9) | (2 << 5) | 29 }).toUnix() == null);
    try testing.expect((DosDateTime{ .time = 0, .date = (120 << 9) | (2 << 5) | 28 }).toUnix() != null);
    try testing.expect((DosDateTime{ .time = 0, .date = (44 << 9) | (2 << 5) | 29 }).toUnix() != null); // 2024: leap
}

test "ArchiveWriter: classic (allow_zip64 = false) holds 65 534 entries; past that the count needs zip64" {
    // The EOCD record counts are u16 (APPNOTE 4.3.16) and 0xFFFF there means
    // "see the zip64 record" (Go writes zip64 from 65 535 records on), so a
    // classic archive holds at most 65 534. Mutation 2026-10-04: admitting
    // one more survived (the count would then not fit the field).
    const a = testing.allocator;
    var sink_buf: [4096]u8 = undefined;
    var sink: std.Io.Writer.Discarding = .init(&sink_buf);
    var zw = ArchiveWriter.init(a, &sink.writer);
    defer zw.deinit();
    zw.allow_zip64 = false;
    for (0..std.math.maxInt(u16) - 1) |_| try zw.addEntry("e", "", .{ .method = .store });
    try zw.addEntry("e", "", .{ .method = .store }); // 65 535th: admitted, but the count needs zip64
    try testing.expectError(Error.ZipWriteTooLarge, zw.finish());
}

test "ArchiveWriter: 65 536 entries become a zip64 archive this reader lists completely" {
    const a = testing.allocator;
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var zw = ArchiveWriter.init(a, &aw.writer);
    defer zw.deinit();
    for (0..65536) |_| try zw.addEntry("e", "x", .{ .method = .store });
    try zw.finish();
    const bytes = aw.written();
    try testing.expect(std.mem.find(u8, bytes, &std.zip.end_record64_sig) != null);
    try testing.expect(std.mem.find(u8, bytes, &std.zip.end_locator64_sig) != null);
    var ms: MemorySource = .{ .bytes = bytes };
    var archive: Archive = undefined;
    try archive.initSource(a, ms.source(), .{});
    defer archive.deinit();
    try testing.expectEqual(@as(usize, 65536), archive.entries.items.len);
}

test "ArchiveWriter: mode keeps only permission bits, the entry stays a regular file" {
    // `AddEntryOptions.mode` is "Unix permission bits" and the record is
    // marked `S_IFREG | mode`; type bits a caller passes along (0o040000,
    // a directory) must not turn the member into another file type in the
    // external attributes. Mutation 2026-10-04: an unmasked mode survived
    // because the reader masks again on the way back.
    const a = testing.allocator;
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var zw = ArchiveWriter.init(a, &aw.writer);
    defer zw.deinit();
    try zw.addEntry("f", "x", .{ .method = .store, .mode = 0o40755 });
    try zw.finish();
    const zip = aw.writer.buffered();
    const attrs = std.mem.readInt(u32, zip[cdStart(zip) + 38 ..][0..4], .little);
    try testing.expectEqual(@as(u32, 0o100755), attrs >> 16);
}

// ---------------------------------------------------------------------------
// zip64 read tests
// ---------------------------------------------------------------------------

test "Archive/EntryReader: zip64 extra fields (per-entry sizes/offset + zip64 EOCD/locator) parse and stream correctly (Store)" {
    const a = testing.allocator;
    const data = "zip64-path bytes, forced through the 64-bit extra-field machinery even though this member is tiny";
    const zip = try buildZip64(a, "big.bin", data, .store);
    defer a.free(zip);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var f = try openZip(&tmp, zip);
    defer f.close(testing.io);

    var archive: Archive = undefined;
    try archive.init(testing.io, a, f);
    defer archive.deinit();

    try testing.expectEqual(@as(usize, 1), archive.entries.items.len);
    const e = archive.find("big.bin").?;
    // These sizes came from the zip64 extra field, not the 0xFFFFFFFF
    // placeholders left in the fixed-size header fields — a positive control:
    // getting the extra-field parsing wrong surfaces immediately either as a
    // wrong (garbage-large) size here, or as EntryReader misreading the data
    // offset (also derived from the zip64 extra) below.
    try testing.expectEqual(@as(u64, data.len), e.uncompressed_size);
    try testing.expectEqual(@as(u64, data.len), e.compressed_size);

    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var er: EntryReader = undefined;
    try er.init(&archive, e, &window);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(a);
    try er.reader().appendRemaining(a, &out, .unlimited);
    try testing.expectEqualStrings(data, out.items);
}

test "Archive/EntryReader: zip64 with Deflate-compressed data" {
    const a = testing.allocator;
    const data = strRepeat("the quick brown fox jumps over the lazy dog, ", 60);
    const zip = try buildZip64(a, "deflated-big.bin", data, .deflate);
    defer a.free(zip);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var f = try openZip(&tmp, zip);
    defer f.close(testing.io);

    var archive: Archive = undefined;
    try archive.init(testing.io, a, f);
    defer archive.deinit();

    const e = archive.find("deflated-big.bin").?;
    try testing.expectEqual(std.zip.CompressionMethod.deflate, e.compression);
    try testing.expectEqual(@as(u64, data.len), e.uncompressed_size);

    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var er: EntryReader = undefined;
    try er.init(&archive, e, &window);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(a);
    try er.reader().appendRemaining(a, &out, .unlimited);
    try testing.expectEqualStrings(data, out.items);
}

// ── fuzz: central-directory parse off a hostile archive, never panics ──────
//
// `Archive.init` walks a ZIP central directory that (per the "hostile
// central-directory header" regression above) `std.zip.Iterator` itself is
// not safe to point at arbitrary bytes without this module's pre-validation
// — an archive downloaded, uploaded, or otherwise received is exactly
// untrusted input. Real ZIP tooling almost always starts with a plausible
// End Of Central Directory signature near the tail, so stamp one in about
// half the fuzz cases to get the parser past the "is this even a zip"
// rejection and into the directory-walking logic the regression above hit.
//
// audit `zipstream` F8: this used to stop at `Archive.init`+`deinit` and
// never open an `EntryReader`, so the CRC check, the bomb cap (`initMax`)
// and the local-vs-central `data_off` disagreement were never fuzzed — only
// the central-directory walk was, even though the audit's own temporary
// fuzz did "`Archive.init` then bounded-read every entry". Fixed two ways:
// (1) every path below that gets a parsed `Archive` now also opens and
// bounded-reads each entry; (2) purely-random bytes almost never assemble a
// byte-exact, walkable central directory (that is what F1 needed a crafted
// case to find), so on top of the random-bytes path this harness now also
// starts from a real, valid archive built through `ArchiveWriter` (both
// Store and Deflate members) and applies a handful of random byte mutations
// — the same "mutated-valid" shape the audit used to find F1 — which stays
// walkable far more often and is what actually drives `EntryReader` on most
// iterations.

// ⛔ AND THE FUZZED HALF OF THAT NEVER RAN. `fuzzArchiveInit` opened
// `smith.bytes(&buf)` and then drew the length with `smith.valueRangeAtMost`;
// `bytes` consumes `@min(buf.len, in.len)` octets and a ranged draw then reads
// EIGHT more as a little-endian `u64`, returning the range MINIMUM when fewer
// remain, so the length was 0 for every input a corpus can carry. The target
// had no corpus either, so the one input it ever ran was empty: path 1 wrote a
// ZERO-BYTE file and `Archive.init` refused it, and path 2's mutation count
// `smith.valueRangeAtMost(u8, 0, 24)` was likewise 0, so it walked the
// PRISTINE archive with **not one octet mutated**, every run. Measured
// 2026-09-07: 1 round, 0 non-empty inputs on path 1, 0 mutations on path 2.
// The F8 fix — "start from a real archive and apply a handful of random byte
// mutations" — was correct about the shape and bought nothing, because the
// draw that chose the mutation count was collapsed.
//
// Both paths take the same thing: the octets of a zip file. So the harness
// now draws those octets byte-first, once, and the "mutated valid archive"
// idea moves into the corpus, where `ArchiveWriter` builds a real archive and
// the seeds are deliberate corruptions of it rather than a mutation count the
// ordinary lane always drew as zero. Under `--fuzz` this is strictly better:
// the fuzzer mutates a real, walkable archive directly.

var f8_entry_reader_reached: usize = 0;

const fz = @import("fuzz_test.zig");
const fuzz_driver = @import("testkit").fuzz.driver;

/// The corpus, built at run time from this module's own `ArchiveWriter`:
/// random bytes essentially never assemble a byte-exact, walkable central
/// directory (which is why finding F1 needed a crafted case), so the only
/// archive that reaches `EntryReader` is one the encoder produced.
///
/// ⭐ The harness and the guard below both build it from HERE. A guard
/// measuring a different corpus from the one the harness gets is not a guard.
const ZipCorpus = struct {
    const cap = 4096;

    base: [cap]u8 = undefined,
    stores: [8][4 + cap]u8 = undefined,
    entries: [8][]const u8 = undefined,

    fn build(self: *ZipCorpus) ![]const []const u8 {
        const kit = @import("testkit").fuzz;

        var base_writer: std.Io.Writer = .fixed(&self.base);
        var zw = ArchiveWriter.init(testing.allocator, &base_writer);
        defer zw.deinit();
        try zw.addEntry("a.txt", "hello fuzz world, this member is stored verbatim", .{ .method = .store });
        try zw.addEntry("b.txt", strRepeat("hello fuzz world, this member is deflated ", 20), .{ .method = .deflate });
        try zw.finish();
        const good = base_writer.buffered();

        var t: [cap]u8 = undefined;
        var n: usize = 0;

        // 0: the archive as written — Store and Deflate members, both walkable.
        self.entries[n] = kit.seedInto(&self.stores[n], good);
        n += 1;

        // 1: the CRC of the first member corrupted — the check `EntryReader`
        //    performs after the last octet, which no refusal path reaches.
        @memcpy(t[0..good.len], good);
        t[14] ^= 0xFF; // local header crc-32, first octet
        self.entries[n] = kit.seedInto(&self.stores[n], t[0..good.len]);
        n += 1;

        // 2: one octet of the deflate stream corrupted — a member that opens
        //    and then fails mid-inflate.
        @memcpy(t[0..good.len], good);
        t[good.len / 2] ^= 0xFF;
        self.entries[n] = kit.seedInto(&self.stores[n], t[0..good.len]);
        n += 1;

        // 3: the EOCD signature broken — "is this even a zip" refusal.
        @memcpy(t[0..good.len], good);
        t[good.len - 22] = 0x00;
        self.entries[n] = kit.seedInto(&self.stores[n], t[0..good.len]);
        n += 1;

        // 4: the central-directory offset in the EOCD pointed past the file —
        //    the pre-validation this module exists to do ahead of
        //    `std.zip.Iterator`.
        @memcpy(t[0..good.len], good);
        std.mem.writeInt(u32, t[good.len - 6 ..][0..4], 0xFFFF_FFF0, .little);
        self.entries[n] = kit.seedInto(&self.stores[n], t[0..good.len]);
        n += 1;

        // 5: the archive truncated to its first half — no EOCD at all.
        self.entries[n] = kit.seedInto(&self.stores[n], good[0 .. good.len / 2]);
        n += 1;

        // 6: 22 octets that are nothing but an EOCD signature and zeroes —
        //    the smallest thing that gets past the tail scan.
        @memset(t[0..22], 0);
        t[0..4].* = .{ 0x50, 0x4b, 0x05, 0x06 };
        self.entries[n] = kit.seedInto(&self.stores[n], t[0..22]);
        n += 1;

        // 7: the empty file, which is what an empty corpus produced.
        self.entries[n] = kit.seedInto(&self.stores[n], t[0..0]);
        n += 1;

        std.debug.assert(n == self.entries.len);
        return &self.entries;
    }
};

test "fuzz: Archive.init never panics on an arbitrary file" {
    var corpus: ZipCorpus = .{};
    try testing.fuzz({}, fuzzArchiveInit, .{ .corpus = try corpus.build() });
}

// `zig build test` (no `--fuzz=N`) never actually invokes a
// `std.testing.fuzz` body — the "fuzz test" above is only *registered*, not
// run, in the plain test lane, so a counter incremented from inside it can't
// be asserted on there. `std.testing.Smith` documents itself as "intended to
// be initialized directly", so this drives `fuzzArchiveInit` itself,
// directly, over the corpus the harness gets — proving the harness's *logic*
// really does reach `EntryReader` (not just `Archive.init`+`deinit`) without
// depending on the opaque `--fuzz` engine.
//
// ⚠ It used to drive the harness off 64 PRNG-filled buffers instead. That was
// the only thing in the ordinary lane exercising this code — and it measured
// a DIFFERENT input distribution from the one the `--fuzz` target actually
// replays, so it could not have noticed that the target itself was running a
// single empty input. It now measures the corpus, which is the same thing the
// harness sees.
test "corpus: every archive seed reaches Archive.init, and EntryReader's reach is pinned" {
    // `f8_entry_reader_reached` is the second number and it is the
    // load-bearing one: `Archive.init` on an empty file simply fails, so a
    // guard counting refusals would have been satisfied by the collapsed
    // harness. An opened `EntryReader` can only come from a byte-exact,
    // walkable central directory.
    f8_entry_reader_reached = 0;
    var corpus: ZipCorpus = .{};
    const seeds = try corpus.build();

    var nonempty: usize = 0;
    for (seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [ZipCorpus.cap]u8 = undefined;
        var probe: std.testing.Smith = .{ .in = sd };
        if (probe.slice(&buf) != 0) nonempty += 1;
        try fuzzArchiveInit({}, &smith);
    }
    // Measured 2026-09-07. Before: the target ran one empty input, path 1 got
    // a zero-byte file and path 2 walked the pristine archive with 0 octets
    // mutated.
    try testing.expectEqual(seeds.len - 1, nonempty); // the deliberate empty seed
    try testing.expectEqual(@as(usize, 6), f8_entry_reader_reached); // three walkable archives, two members each
}

fn tryEntries(archive: *Archive) void {
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    for (archive.entries.items) |*entry| {
        var er: EntryReader = undefined;
        // A small explicit `max_output` keeps a crafted huge
        // `uncompressed_size` cheap to reject via `ZipEntryTooLarge` rather
        // than attempting a large allocation from a small fuzz input.
        // The password the mutated harness encrypts with: AES and ZipCrypto
        // entries get decrypted (and their framing parsed) too.
        er.open(archive, entry, &window, .{ .max_output = 64 * 1024, .password = "secret" }) catch continue;
        defer er.deinit();
        f8_entry_reader_reached += 1;
        fz.mark(.entry_opened);
        var sink_buf: [256]u8 = undefined;
        if ((er.reader().readSliceShort(&sink_buf) catch 0) != 0) fz.mark(.entry_read);
        _ = er.reader().discardRemaining() catch {};
    }
}

// The whole harness body, in a helper of its own — not inlined into
// `fuzzArchiveInit` — specifically so its `catch return`s bail out of the
// walk only and cannot skip the caller's remaining work (that was the shape
// of an earlier draft's bug: `return` inside a bare `{ }` block still returns
// the whole enclosing function in Zig).
fn tryArchiveBytes(gpa: std.mem.Allocator, bytes: []const u8) void {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    tmp.dir.writeFile(testing.io, .{ .sub_path = "f.zip", .data = bytes }) catch return;
    var f = tmp.dir.openFile(testing.io, "f.zip", .{}) catch return;
    defer f.close(testing.io);

    var archive: Archive = undefined;
    archive.init(testing.io, gpa, f) catch {
        fz.mark(.init_refused);
        return;
    };
    defer archive.deinit();
    fz.mark(.init_ok);
    tryEntries(&archive);
}

fn fuzzArchiveInit(_: void, smith: *std.testing.Smith) !void {
    // ⚠ ONE byte-first draw. Never `bytes` then a ranged length, and never a
    // weighted bool before the bytes: see the block comment above for what
    // that cost this target. The buffer is `ZipCorpus.cap`, which is set by
    // the largest archive `ArchiveWriter` produces for the corpus — a seed
    // longer than the buffer reads back EMPTY.
    var buf: [ZipCorpus.cap]u8 = undefined;
    const len: usize = smith.slice(&buf);
    var src: fz.ScriptSource = .{ .cur = .{ .bytes = buf[0..len] } };
    try archiveHarness(fz.ScriptSource, &src, testing.allocator);
}

fn archiveHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var buf: [ZipCorpus.cap]u8 = undefined;
    const len: usize = src.slice(&buf);
    tryArchiveBytes(gpa, buf[0..len]);
}

const mut_names = [_][]const u8{ "a.txt", "dir/b.bin", "x/y/z", strRepeat("long", 20) };

/// A valid archive from this module's own `ArchiveWriter`, then damaged: a few
/// octets flipped, maybe cut short. Random octets never assemble a walkable
/// central directory, so `archiveHarness` alone stops at `Archive.init`.
fn mutatedHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var out: [ZipCorpus.cap]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    var zw = ArchiveWriter.init(gpa, &w);
    defer zw.deinit();
    var content: [600]u8 = undefined;
    const count = src.valueRangeAtMost(u8, 1, 3);
    for (0..count) |_| {
        const clen: usize = src.valueRangeAtMost(u16, 0, content.len);
        // Compressible half the time, noise the rest: both Deflate shapes.
        if (src.value(bool)) {
            @memset(content[0..clen], src.value(u8));
        } else src.bytes(content[0..clen]);
        const methods = [_]WriteMethod{ .store, .deflate, .zstd };
        const salt = "0123456789abcdef";
        const strength: AesStrength = switch (src.valueRangeAtMost(u8, 0, 2)) {
            0 => .aes128,
            1 => .aes192,
            else => .aes256,
        };
        const opts: AddEntryOptions = .{
            // zstd 1 in 8: its compressor's set-up per member is the costly part.
            .method = if (src.valueRangeAtMost(u8, 0, 7) == 0) .zstd else methods[src.index(2)],
            // 1 in 128: each AES member costs a PBKDF2 (1000 rounds), which
            // would otherwise dominate the verdict run's budget.
            .encryption = if (src.valueRangeAtMost(u8, 0, 127) == 0) .{ .password = "secret", .strength = strength, .salt = salt[0..strength.saltLen()] } else null,
        };
        const name = mut_names[src.index(mut_names.len)];
        if (src.valueRangeAtMost(u8, 0, 3) == 0) {
            const sw = zw.beginEntry(name, opts) catch break;
            sw.writeAll(content[0..clen]) catch break;
            zw.endEntry() catch break;
        } else zw.addEntry(name, content[0..clen], opts) catch break;
    }
    zw.finish() catch {};
    var n = w.buffered().len;
    if (n == 0) return;
    const flips = src.valueRangeAtMost(u8, 0, 4);
    for (0..flips) |_| out[src.index(n)] ^= src.value(u8);
    if (src.valueRangeAtMost(u8, 0, 3) == 0) n -= src.index(n);
    tryArchiveBytes(gpa, out[0..n]);
}

test "fuzz driver: ZIPSTREAM_FUZZ (archive, mutated)" {
    try fuzz_driver.run(archiveHarness, .{ .prefix = "ZIPSTREAM_FUZZ", .name = "archive" });
    try fuzz_driver.run(mutatedHarness, .{ .prefix = "ZIPSTREAM_FUZZ", .name = "mutated" });
}

test "fuzz harnesses: 300 seeds each in every test run, and they get everywhere" {
    fz.resetReach();
    inline for (.{ archiveHarness, mutatedHarness }, .{ "archive", "mutated" }) |h, name| {
        for (0..300) |seed| {
            var prng = std.Random.DefaultPrng.init(seed);
            var rng: fuzz_driver.Rng = .{ .r = prng.random() };
            h(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
                std.debug.print("zipstream {s} seed {d}: {t}\n", .{ name, seed, err });
                return err;
            };
        }
    }
    try fz.expectAllReached();
}

// ── offline write-path anchor (real unzip/zipinfo capture, no subprocess) ─
//
// Complements SPEC.md's documented ad hoc `unzip`/`zipinfo` check (never
// previously committed as a standing test): a frozen archive verified once
// against the real tools, asserted with no subprocess — see
// write_golden_test.zig's doc comment.
test {
    _ = @import("write_golden_test.zig");
    _ = @import("xlsx_fixture_test.zig");
    _ = @import("mtime_test.zig");
    _ = @import("go_oracle.zig");
    _ = @import("s2_test.zig");
    _ = @import("crypto_test.zig");
    _ = @import("crypto.zig");
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    const rep_result = comptime blk: {
        @setEvalBranchQuota(n * (s.len + 4) + 1000);
        var buf: [s.len * n:0]u8 = undefined;
        for (0..n) |i| @memcpy(buf[i * s.len ..][0..s.len], s);
        const rep_final = buf;
        break :blk rep_final;
    };
    return &rep_result;
}
