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
//! any other method is `error.UnsupportedCompressionMethod`.
//!
//! Lifetime contract: both `Archive` and `EntryReader` hold internal
//! self-pointers (the file reader's `interface`, the inflate stream's input
//! handle), so both are initialised in place via a `*Self` and must not be
//! moved after `init`. One `Archive` drives one file cursor — stream an
//! `EntryReader` to completion (or abandon it) before opening the next entry.
//!
//! zip64 archives/entries (> 4 GiB, or > 65535 central-directory records) are
//! supported for *reading*, via `std.zip.Iterator`'s own zip64 EOCD/locator and
//! per-entry extra-field handling — nothing in this module's read path is
//! 32-bit-limited. `ArchiveWriter` (below) writes classic (non-zip64) archives
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
const Allocator = std.mem.Allocator;

/// The ZIP wire format is little-endian throughout; on a big-endian host the
/// writer byte-swaps each header struct before writing it (mirroring how
/// `std.zip`'s reader side byte-swaps after reading — see its `is_le` check).
const native_endian_is_le = builtin.target.cpu.arch.endian() == .little;

pub const meta = .{
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "APPNOTE.TXT ZIP central-directory streaming reader",
    .deps = .{},
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
};

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
};

/// A central-directory-parsed ZIP archive. Borrows an already-open `File` (does
/// not close it); owns the reader buffer, the entry list and the entries' name
/// storage. Initialise in place — see the lifetime contract above.
pub const Archive = struct {
    file: std.Io.File,
    reader_buf: []u8,
    file_reader: std.Io.File.Reader,
    entries: std.ArrayList(Entry),
    name_arena: std.heap.ArenaAllocator,
    alloc: Allocator,

    /// Walks the central directory and records every entry (name + location +
    /// sizes). Does not read any entry's data. The `file` must outlive the
    /// archive; it is not closed by `deinit`.
    pub fn init(self: *Archive, io: std.Io, alloc: Allocator, file: std.Io.File) !void {
        self.* = .{
            .file = file,
            .reader_buf = try alloc.alloc(u8, READER_BUF_SIZE),
            .file_reader = undefined,
            .entries = .empty,
            .name_arena = std.heap.ArenaAllocator.init(alloc),
            .alloc = alloc,
        };
        errdefer {
            self.entries.deinit(alloc);
            self.name_arena.deinit();
            alloc.free(self.reader_buf);
        }

        self.file_reader = file.reader(io, self.reader_buf);
        const name_alloc = self.name_arena.allocator();

        var iter = try std.zip.Iterator.init(&self.file_reader);

        // Pre-validate the central directory before walking it. `std.zip.Iterator.next`
        // advances by `46 + filename_len + extra_len + comment_len` computed in u16
        // (std/zip.zig), which overflows on a hostile CD header (filename_len >= 65490)
        // and panics in ReleaseSafe / silently misparses in ReleaseFast — reachable
        // straight through this init (batch-10 audit CRIT). Walk the directory here
        // with u64 arithmetic and reject any header whose per-record advance would
        // exceed std's u16, so the real `iter.next()` walk below can never overflow.
        // `iter`'s own cursor state is untouched (we never call next() here and it
        // re-seeks per record), so the loop that follows still starts at record 0.
        {
            var cd_off: u64 = 0;
            var i: u64 = 0;
            while (i < iter.cd_record_count) : (i += 1) {
                try self.file_reader.seekTo(iter.cd_zip_offset + cd_off);
                const h = self.file_reader.interface.takeStruct(std.zip.CentralDirectoryFileHeader, .little) catch
                    return Error.ZipBadCentralDirectory;
                if (!std.mem.eql(u8, &h.signature, &std.zip.central_file_header_sig))
                    return Error.ZipBadCentralDirectory;
                const advance = @as(u64, @sizeOf(std.zip.CentralDirectoryFileHeader)) +
                    h.filename_len + h.extra_len + h.comment_len;
                if (advance > std.math.maxInt(u16)) return Error.ZipBadCentralDirectory;
                cd_off += advance;
            }
        }

        var name_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        while (try iter.next()) |e| {
            switch (e.compression_method) {
                .store, .deflate => {},
                else => return Error.UnsupportedCompressionMethod,
            }
            if (e.filename_len > name_buf.len) return Error.ZipNameTooLong;

            // Read the filename out of the central-directory header.
            try self.file_reader.seekTo(e.header_zip_offset + @sizeOf(std.zip.CentralDirectoryFileHeader));
            const raw = name_buf[0..e.filename_len];
            try self.file_reader.interface.readSliceAll(raw);
            std.mem.replaceScalar(u8, raw, '\\', '/'); // some writers emit Windows paths

            // Directory entries carry no content.
            if (raw.len == 0 or raw[raw.len - 1] == '/') continue;

            try self.entries.append(self.alloc, .{
                .name = try name_alloc.dupe(u8, raw),
                .compression = e.compression_method,
                .compressed_size = e.compressed_size,
                .uncompressed_size = e.uncompressed_size,
                .file_offset = e.file_offset,
            });
        }
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
pub const EntryReader = struct {
    decompress: std.compress.flate.Decompress,
    limited: std.Io.Reader.Limited,

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
        const fr = &archive.file_reader;

        // Locate the compressed data: the local header carries its own
        // filename/extra lengths (which can differ from the central header).
        // version_needed is deliberately ignored — see the module note.
        try fr.seekTo(entry.file_offset);
        const local = try fr.interface.takeStruct(std.zip.LocalFileHeader, .little);
        if (!std.mem.eql(u8, &local.signature, &std.zip.local_file_header_sig))
            return Error.ZipBadFileOffset;
        const data_off = entry.file_offset + @sizeOf(std.zip.LocalFileHeader) +
            @as(u64, local.filename_len) + @as(u64, local.extra_len);
        try fr.seekTo(data_off);

        // Decompression-bomb guard: refuse an entry that declares more output
        // than the caller allows before any bytes are read.
        if (entry.uncompressed_size > max_output) return Error.ZipEntryTooLarge;

        switch (entry.compression) {
            .deflate => {
                self.decompress = .init(&fr.interface, .raw, window);
                // Clamp the decompressed stream to the declared size. `window`
                // is already owned by `decompress`, so the Limited reads
                // straight through with no buffer of its own.
                self.limited = self.decompress.reader.limited(.limited64(entry.uncompressed_size), &.{});
            },
            .store => {
                self.limited = fr.interface.limited(.limited64(entry.uncompressed_size), window);
            },
            else => return Error.UnsupportedCompressionMethod,
        }
    }

    /// The decompressed-byte reader, bounded by the output cap. Valid until the
    /// next `EntryReader.init` against the same archive (which reseeks the file
    /// cursor).
    pub fn reader(self: *EntryReader) *std.Io.Reader {
        return &self.limited.interface;
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
pub const WriteMethod = enum { store, deflate };

pub const AddEntryOptions = struct {
    method: WriteMethod = .deflate,
    /// Deflate speed/ratio trade-off (`std.compress.flate.Compress.Options`);
    /// ignored for `.store`.
    level: std.compress.flate.Compress.Options = .default,
};

/// Streaming ZIP archive writer: `addEntry` one member at a time, then
/// `finish()`. Each `addEntry` call writes that member's local file header and
/// data to `out` immediately; `finish()` writes the central directory and
/// EOCD. Memory cost while writing one entry is O(that entry's compressed
/// bytes) — `std.compress.flate.Compress` must produce the full compressed
/// output before the local header's `compressed_size` field can be written (no
/// data-descriptor / streaming-unknown-size support) — never O(whole archive);
/// the archive itself is streamed straight to `out` as it's built, not
/// buffered in memory.
///
/// Classic (non-zip64) format only: the running byte offset, each entry's
/// compressed/uncompressed size, the central directory's size, and the entry
/// count must all fit the classic 32/16-bit ZIP fields (~4 GiB / 65535
/// entries). `addEntry`/`finish` return `Error.ZipWriteTooLarge` before
/// writing anything that would overflow one of them — never a silently
/// truncated field. This is a real asymmetry with the *reader* half of this
/// module (`Archive`/`EntryReader`), which does support zip64 input via
/// `std.zip.Iterator`'s own zip64 handling (see the module doc comment); zip64
/// *writing* is deferred (SPEC.md "Backlog").
///
/// Store + Deflate only, matching the reader. Entry names are gated through
/// `isSafeEntryName` on write too (`Error.ZipUnsafeEntryName`), so this module
/// can never itself be the source of a zip-slip archive.
///
/// Not self-referential (unlike `Archive`/`EntryReader`) — no in-place `*Self`
/// init needed; `ArchiveWriter` may be moved freely before or after `init`.
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

    const WrittenEntry = struct {
        name: []const u8,
        method: std.zip.CompressionMethod,
        crc32: u32,
        compressed_size: u32,
        uncompressed_size: u32,
        local_header_offset: u32,
    };

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
        self.entries.deinit(self.alloc);
        self.name_arena.deinit();
        self.* = undefined;
    }

    /// Compresses (or stores) all of `data` and appends it to the archive as
    /// one member named `name`. `data` must already be fully in memory (this
    /// is not a streaming-input API); the only *extra* buffering `addEntry`
    /// itself does is one compressed copy of `data` for `.deflate` (freed
    /// before returning).
    pub fn addEntry(self: *ArchiveWriter, name: []const u8, data: []const u8, options: AddEntryOptions) !void {
        std.debug.assert(!self.finished);
        if (!isSafeEntryName(name)) return Error.ZipUnsafeEntryName;
        if (name.len > std.math.maxInt(u16)) return Error.ZipNameTooLong;
        if (data.len > std.math.maxInt(u32)) return Error.ZipWriteTooLarge;
        if (self.offset > std.math.maxInt(u32)) return Error.ZipWriteTooLarge;
        if (self.entries.items.len >= std.math.maxInt(u16)) return Error.ZipWriteTooLarge;

        const crc = std.hash.Crc32.hash(data);
        const method: std.zip.CompressionMethod = switch (options.method) {
            .store => .store,
            .deflate => .deflate,
        };

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
        };
        if (payload.len > std.math.maxInt(u32)) return Error.ZipWriteTooLarge;

        const local_header_offset = self.offset;
        const lfh: std.zip.LocalFileHeader = .{
            .signature = std.zip.local_file_header_sig,
            .version_needed_to_extract = 20,
            .flags = @bitCast(@as(u16, 0)),
            .compression_method = method,
            .last_modification_time = 0,
            .last_modification_date = 0,
            .crc32 = crc,
            .compressed_size = @intCast(payload.len),
            .uncompressed_size = @intCast(data.len),
            .filename_len = @intCast(name.len),
            .extra_len = 0,
        };
        try writeHeaderLE(std.zip.LocalFileHeader, self.out, lfh);
        try self.out.writeAll(name);
        try self.out.writeAll(payload);
        self.offset += @sizeOf(std.zip.LocalFileHeader) + name.len + payload.len;

        try self.entries.append(self.alloc, .{
            .name = try self.name_arena.allocator().dupe(u8, name),
            .method = method,
            .crc32 = crc,
            .compressed_size = @intCast(payload.len),
            .uncompressed_size = @intCast(data.len),
            .local_header_offset = @intCast(local_header_offset),
        });
    }

    /// Writes the central directory and the end-of-central-directory record.
    /// Call exactly once, after all entries are added. `out` still needs a
    /// final flush by the caller — `finish()` never flushes/closes it.
    pub fn finish(self: *ArchiveWriter) !void {
        std.debug.assert(!self.finished);
        self.finished = true;

        const cd_offset = self.offset;
        for (self.entries.items) |e| {
            const cdh: std.zip.CentralDirectoryFileHeader = .{
                .signature = std.zip.central_file_header_sig,
                .version_made_by = 20,
                .version_needed_to_extract = 20,
                .flags = @bitCast(@as(u16, 0)),
                .compression_method = e.method,
                .last_modification_time = 0,
                .last_modification_date = 0,
                .crc32 = e.crc32,
                .compressed_size = e.compressed_size,
                .uncompressed_size = e.uncompressed_size,
                .filename_len = @intCast(e.name.len),
                .extra_len = 0,
                .comment_len = 0,
                .disk_number = 0,
                .internal_file_attributes = 0,
                .external_file_attributes = 0,
                .local_file_header_offset = e.local_header_offset,
            };
            try writeHeaderLE(std.zip.CentralDirectoryFileHeader, self.out, cdh);
            try self.out.writeAll(e.name);
            self.offset += @sizeOf(std.zip.CentralDirectoryFileHeader) + e.name.len;
        }
        const cd_size = self.offset - cd_offset;
        if (cd_offset > std.math.maxInt(u32) or cd_size > std.math.maxInt(u32))
            return Error.ZipWriteTooLarge;

        const eocd: std.zip.EndRecord = .{
            .signature = std.zip.end_record_sig,
            .disk_number = 0,
            .central_directory_disk_number = 0,
            .record_count_disk = @intCast(self.entries.items.len),
            .record_count_total = @intCast(self.entries.items.len),
            .central_directory_size = @intCast(cd_size),
            .central_directory_offset = @intCast(cd_offset),
            .comment_len = 0,
        };
        try writeHeaderLE(std.zip.EndRecord, self.out, eocd);
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
        const lfh = std.zip.LocalFileHeader{
            .signature = std.zip.local_file_header_sig,
            .version_needed_to_extract = 20,
            .flags = @bitCast(@as(u16, 0)),
            .compression_method = m.method,
            .last_modification_time = 0,
            .last_modification_date = 0,
            .crc32 = 0,
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
            .crc32 = 0,
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

    // --- Local file header + zip64 extra (uncompressed_size, compressed_size) ---
    const local_offset: u32 = @intCast(buf.items.len);
    const lfh = std.zip.LocalFileHeader{
        .signature = std.zip.local_file_header_sig,
        .version_needed_to_extract = 45,
        .flags = @bitCast(@as(u16, 0)),
        .compression_method = method,
        .last_modification_time = 0,
        .last_modification_date = 0,
        .crc32 = 0,
        .compressed_size = 0xFFFFFFFF,
        .uncompressed_size = 0xFFFFFFFF,
        .filename_len = @intCast(name.len),
        .extra_len = 4 + 16,
    };
    try buf.appendSlice(a, std.mem.asBytes(&lfh));
    try buf.appendSlice(a, name);
    {
        var hdr: [4]u8 = undefined;
        std.mem.writeInt(u16, hdr[0..2], @intFromEnum(std.zip.ExtraHeader.zip64_info), .little);
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
        .crc32 = 0,
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
        std.mem.writeInt(u16, hdr[0..2], @intFromEnum(std.zip.ExtraHeader.zip64_info), .little);
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
    const cd_start = std.mem.indexOf(u8, zip, &cd_sig).?;
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
        "the quick brown fox jumps over the lazy dog, " ** 40; // compresses well
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

    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var er: EntryReader = undefined;
    try er.init(&archive, &lying_entry, &window);

    const buf = try a.alloc(u8, lying_entry.uncompressed_size);
    defer a.free(buf);
    // Reading the full (lying) declared size must hit the reader's own
    // EndOfStream error, cleanly, instead of looping forever or reading
    // past the allocation.
    try testing.expectError(error.EndOfStream, er.reader().readSliceAll(buf));
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

// ---------------------------------------------------------------------------
// Writer tests
// ---------------------------------------------------------------------------

test "ArchiveWriter: Store + Deflate round-trip through zipstream's own reader, byte-exact + CRC verified independently via std.zip.Iterator" {
    const a = testing.allocator;

    const stored_data = "plain stored payload, unmodified bytes end to end";
    const deflate_data = "the quick brown fox jumps over the lazy dog, " ** 40;

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
    const data = "the quick brown fox jumps over the lazy dog, " ** 60;
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
