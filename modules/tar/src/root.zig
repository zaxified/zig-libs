// SPDX-License-Identifier: MIT
//! tar — ustar/GNU tar reader + writer that preserves uid/gid/mtime, plus a
//! gzip-tar packer.
//!
//! Why not `std.tar`: its iterator surfaces only name/size/mode — the numeric
//! attrs (uid/gid/mtime) are dropped, and there is no writer. This module
//! parses/emits the 512-byte headers directly so archives round-trip with
//! their ownership and timestamps intact (rsync `--numeric-ids` style).
//!
//! Layers:
//!  - `Reader` (portable): streaming ustar/GNU parser. Supported subset
//!    (covers busybox + GNU `tar`): regular files, directories, symlinks,
//!    hard links, the GNU long-name ('L') / long-link ('K') extensions, the
//!    ustar `prefix` field, and GNU/star base-256 size fields. pax ('x'/'g')
//!    records are skipped (payload discarded), never fatal; unknown typeflags
//!    surface as `.other` so the caller decides. Every header is checksum-
//!    verified and bounds-checked — truncated/garbage input yields an error,
//!    never a panic. Bounded memory: only names are buffered (64 KiB cap),
//!    content is streamed via `read`.
//!  - `Writer` (portable): emits ustar blocks with GNU 'L'/'K' records for
//!    >100-byte paths/link targets, correct checksums, 512-byte blocking and
//!    the two zero trailer blocks. Byte-faithful round-trip with `Reader`.
//!  - `packTarGz` (portable): caller-supplied entries → gzip-compressed tar
//!    via `std.compress.flate`, streaming.
//!  - `packDir` (Linux): walk filesystem roots and pack a gzip tar with real
//!    numeric attrs read via `statx` (symlinks not followed). Only this
//!    helper touches `std.os.linux`; the codec compiles and tests anywhere.
//!
//! ```zig
//! // write
//! var tw = tar.Writer.init(dst); // dst: *std.Io.Writer
//! try tw.writeEntry(.{ .path = "etc/hostname", .mode = 0o644, .uid = 0,
//!     .gid = 0, .mtime = 1_600_000_000 }, "router\n");
//! try tw.finish();
//! // read
//! var tr = tar.Reader.init(gpa, src); // src: *std.Io.Reader
//! defer tr.deinit();
//! while (try tr.next()) |entry| {
//!     var buf: [4096]u8 = undefined;
//!     while (true) {
//!         const n = try tr.read(&buf);
//!         if (n == 0) break;
//!         // … entry.path/uid/gid/mtime + buf[0..n]
//!     }
//! }
//! ```

const std = @import("std");
const builtin = @import("builtin");
const flate = std.compress.flate;
const Allocator = std.mem.Allocator;

pub const meta = .{
    .status = .extract, // seeded in axp (axp-core/src/tar.zig + axp-vault/src/backup.zig)
    .platform = .any, // codec is platform-pure; only packDir is Linux (statx)
    .role = .both, // reader + writer
    .concurrency = .reentrant, // no globals; one Reader/Writer per stream
    .model_after = "GNU tar / libarchive (behavior only)",
    .deps = .{}, // std only — std.compress.flate for gzip
};

pub const block_size = 512;

/// Entry kinds the codec models. The writer emits `.file`/`.dir`/`.symlink`/
/// `.hardlink`; the reader additionally reports unknown typeflags as `.other`
/// (raw flag in `Entry.typeflag`, payload skippable/streamable like a file).
pub const Kind = enum { file, dir, symlink, hardlink, other };

/// One archive member's metadata. Produced by `Reader.next` (slices are owned
/// by the Reader — valid until the next `next()`/`deinit()`) and consumed by
/// `Writer.writeHeader`/`writeEntry`.
pub const Entry = struct {
    path: []const u8,
    kind: Kind = .file,
    /// Permission bits (ustar stores up to 0o7777).
    mode: u32 = 0,
    uid: u32 = 0,
    gid: u32 = 0,
    /// Seconds since the epoch. The writer clamps negative values to 0.
    mtime: i64 = 0,
    /// Content byte count (files; 0 for dirs/symlinks/hardlinks).
    size: u64 = 0,
    /// Symlink target / hard-link target ('2'/'1' entries), else "".
    link_target: []const u8 = "",
    /// Raw header typeflag as read; informative for `.other` entries.
    /// Ignored by the writer (derived from `kind`).
    typeflag: u8 = 0,
};

const gnu_longlink_name = "././@LongLink";
/// Largest accepted GNU 'L'/'K' payload — sanity cap against hostile input.
pub const max_name_len = 64 * 1024;

// ── Reader ──────────────────────────────────────────────────────────────────

pub const ReadError = error{
    /// The stream ended inside a header or declared content, or a header
    /// block was short.
    TruncatedArchive,
    /// Checksum mismatch / unparseable checksum field / bad 'L'-'K' size.
    BadHeader,
} || Allocator.Error || error{ReadFailed};

/// Streaming ustar/GNU tar parser. `next()` returns each entry's metadata;
/// `read()` streams the current entry's content. Unread content is skipped
/// automatically on the following `next()`. Memory: only path/link-target
/// strings are allocated (capped at `max_name_len`); content is never
/// buffered.
pub const Reader = struct {
    src: *std.Io.Reader,
    gpa: Allocator,
    /// Owned backing storage for the last returned entry's path/link target.
    path_buf: []u8 = &.{},
    link_buf: []u8 = &.{},
    /// Pending GNU 'L' (long name) / 'K' (long link) payloads for the next
    /// real entry.
    pending_path: ?[]u8 = null,
    pending_link: ?[]u8 = null,
    /// Unconsumed content bytes of the current entry + its block padding.
    remaining: u64 = 0,
    pad: u64 = 0,
    done: bool = false,

    pub fn init(gpa: Allocator, src: *std.Io.Reader) Reader {
        return .{ .src = src, .gpa = gpa };
    }

    pub fn deinit(self: *Reader) void {
        self.gpa.free(self.path_buf);
        self.gpa.free(self.link_buf);
        if (self.pending_path) |p| self.gpa.free(p);
        if (self.pending_link) |p| self.gpa.free(p);
        self.* = undefined;
    }

    /// Advance to the next entry, skipping any unread content of the current
    /// one. Returns null at the end-of-archive marker (a zero block) or at a
    /// clean EOF right on a block boundary (some producers omit the trailer).
    /// Returned slices are owned by the Reader and valid until the next
    /// `next()`/`deinit()`.
    pub fn next(self: *Reader) ReadError!?Entry {
        if (self.done) return null;
        try self.discard(self.remaining + self.pad);
        self.remaining = 0;
        self.pad = 0;

        var block: [block_size]u8 = undefined;
        while (true) {
            const n = self.src.readSliceShort(&block) catch return error.ReadFailed;
            if (n == 0) { // clean EOF on a block boundary
                self.done = true;
                return null;
            }
            if (n < block_size) return error.TruncatedArchive;
            if (isZeroBlock(&block)) { // end-of-archive marker
                self.done = true;
                return null;
            }
            try verifyChecksum(&block);

            const h = parseHeader(&block);
            const content_pad = padding(h.size);
            switch (h.typeflag) {
                'L' => { // GNU long name: payload is the next entry's path
                    try self.readGnuLong(&self.pending_path, h.size);
                    continue;
                },
                'K' => { // GNU long link target
                    try self.readGnuLong(&self.pending_link, h.size);
                    continue;
                },
                'x', 'g' => { // pax extended header — skip payload, not fatal
                    try self.discard(h.size + content_pad);
                    continue;
                },
                else => {},
            }

            // Materialize the path: a pending GNU 'L' wins over prefix+name.
            const new_path: []u8 = if (self.pending_path) |p| take: {
                self.pending_path = null;
                break :take p;
            } else try joinName(self.gpa, h.prefix, h.name);
            self.gpa.free(self.path_buf);
            self.path_buf = new_path;

            const new_link: []u8 = if (self.pending_link) |p| take: {
                self.pending_link = null;
                break :take p;
            } else try self.gpa.dupe(u8, h.linkname);
            self.gpa.free(self.link_buf);
            self.link_buf = new_link;

            const kind: Kind = switch (h.typeflag) {
                0, '0', '7' => .file, // '7' = contiguous, treated as regular
                '5' => .dir,
                '2' => .symlink,
                '1' => .hardlink,
                else => .other,
            };
            // Content is streamed via read(); next() skips leftovers. Some
            // producers put a size on dirs — honor it so we stay in sync.
            self.remaining = h.size;
            self.pad = content_pad;

            return .{
                .path = std.mem.sliceTo(self.path_buf, 0),
                .kind = kind,
                .mode = h.mode,
                .uid = h.uid,
                .gid = h.gid,
                .mtime = h.mtime,
                .size = h.size,
                .link_target = std.mem.sliceTo(self.link_buf, 0),
                .typeflag = h.typeflag,
            };
        }
    }

    /// Stream content of the current entry. Returns 0 once the entry is
    /// exhausted; a stream that ends before the declared size is
    /// `error.TruncatedArchive`.
    pub fn read(self: *Reader, buf: []u8) ReadError!usize {
        if (self.remaining == 0 or buf.len == 0) return 0;
        const want: usize = @intCast(@min(self.remaining, buf.len));
        const n = self.src.readSliceShort(buf[0..want]) catch return error.ReadFailed;
        if (n == 0) return error.TruncatedArchive;
        self.remaining -= n;
        return n;
    }

    fn readGnuLong(self: *Reader, slot: *?[]u8, size: u64) ReadError!void {
        if (size == 0 or size > max_name_len) return error.BadHeader;
        const buf = try self.gpa.alloc(u8, @intCast(size));
        errdefer self.gpa.free(buf);
        self.src.readSliceAll(buf) catch |e| switch (e) {
            error.EndOfStream => return error.TruncatedArchive,
            error.ReadFailed => return error.ReadFailed,
        };
        try self.discard(padding(size));
        if (slot.*) |old| self.gpa.free(old);
        slot.* = buf; // NUL-trimmed when materialized into an Entry
    }

    fn discard(self: *Reader, n: u64) ReadError!void {
        self.src.discardAll64(n) catch |e| switch (e) {
            error.EndOfStream => return error.TruncatedArchive,
            error.ReadFailed => return error.ReadFailed,
        };
    }
};

/// Raw numeric/string fields of one 512-byte header (slices into the block).
const Hdr = struct {
    name: []const u8,
    prefix: []const u8,
    linkname: []const u8,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: i64,
    size: u64,
    typeflag: u8,
};

fn parseHeader(block: *const [block_size]u8) Hdr {
    // The ustar `prefix` field only exists under the POSIX magic
    // ("ustar\0"); GNU magic ("ustar  \0") reuses those bytes for
    // atime/ctime, so honoring prefix there would corrupt paths.
    const posix_magic = std.mem.eql(u8, block[257..263], "ustar\x00");
    return .{
        .name = nullStr(block[0..100]),
        .prefix = if (posix_magic) nullStr(block[345..500]) else "",
        .linkname = nullStr(block[157..257]),
        .mode = @truncate(octal(block[100..108])),
        .uid = @truncate(octal(block[108..116])),
        .gid = @truncate(octal(block[116..124])),
        .mtime = @bitCast(octal(block[136..148])),
        .size = sizeField(block[124..136]),
        .typeflag = block[156],
    };
}

/// Header checksum: unsigned sum of all bytes with the checksum field taken
/// as spaces. Ancient tars summed signed bytes — accept that too (GNU does).
fn verifyChecksum(block: *const [block_size]u8) error{BadHeader}!void {
    const trimmed = std.mem.trim(u8, block[148..156], " \x00");
    const stored = std.fmt.parseInt(u64, trimmed, 8) catch return error.BadHeader;
    var unsigned: u64 = 0;
    var signed: i64 = 0;
    for (block, 0..) |b, i| {
        const v: u8 = if (i >= 148 and i < 156) ' ' else b;
        unsigned += v;
        signed += @as(i8, @bitCast(v));
    }
    if (stored == unsigned) return;
    if (signed >= 0 and stored == @as(u64, @intCast(signed))) return;
    return error.BadHeader;
}

/// Resolve a full path from the ustar `prefix` + `name` fields.
fn joinName(gpa: Allocator, prefix: []const u8, name: []const u8) Allocator.Error![]u8 {
    if (prefix.len == 0) return gpa.dupe(u8, name);
    const out = try gpa.alloc(u8, prefix.len + 1 + name.len);
    @memcpy(out[0..prefix.len], prefix);
    out[prefix.len] = '/';
    @memcpy(out[prefix.len + 1 ..], name);
    return out;
}

fn isZeroBlock(block: *const [block_size]u8) bool {
    for (block) |b| if (b != 0) return false;
    return true;
}

fn nullStr(s: []const u8) []const u8 {
    return std.mem.sliceTo(s, 0);
}

/// Parse a zero/space-padded octal numeric field (mode/uid/gid/mtime).
/// Lenient — garbage yields 0 (busybox emits oddly padded fields); the
/// header as a whole is validated by its checksum.
fn octal(field: []const u8) u64 {
    const trimmed = std.mem.trim(u8, field, " \x00");
    if (trimmed.len == 0) return 0;
    return std.fmt.parseInt(u64, trimmed, 8) catch 0;
}

/// The size field: octal, or GNU/star base-256 when the leading byte is 0x80.
fn sizeField(field: []const u8) u64 {
    if (field.len == 12 and field[0] == 0x80) {
        var v: u64 = 0;
        for (field[4..12]) |b| v = (v << 8) | b;
        return v;
    }
    return octal(field);
}

pub fn padding(size: u64) u64 {
    return std.mem.alignForward(u64, size, block_size) - size;
}

// ── Writer ──────────────────────────────────────────────────────────────────

pub const WriteError = error{
    /// `writeHeader`/`writeEntry` got a `.other` entry — the writer only
    /// emits files, dirs, symlinks and hard links.
    UnsupportedKind,
} || std.Io.Writer.Error;

/// ustar/GNU tar emitter. `writeEntry` for in-memory content; or
/// `writeHeader` + stream `size` bytes to `dst` + `writePadding(size)` for
/// large files. `finish()` terminates the archive (two zero blocks).
pub const Writer = struct {
    dst: *std.Io.Writer,

    pub fn init(dst: *std.Io.Writer) Writer {
        return .{ .dst = dst };
    }

    /// Write one complete entry with in-memory content. For `.file` the
    /// header size is `content.len` (`e.size` is ignored); other kinds carry
    /// no content.
    pub fn writeEntry(self: Writer, e: Entry, content: []const u8) WriteError!void {
        var h = e;
        if (e.kind == .file) {
            h.size = content.len;
        } else {
            std.debug.assert(content.len == 0);
        }
        try self.writeHeader(h);
        if (e.kind == .file) {
            try self.dst.writeAll(content);
            try self.writePadding(content.len);
        }
    }

    /// Write a header (preceded by GNU 'L'/'K' records for >100-byte
    /// strings). For a regular file the caller streams `e.size` content
    /// bytes to `self.dst` next, then calls `writePadding(e.size)`;
    /// dirs/symlinks/hardlinks have no content.
    pub fn writeHeader(self: Writer, e: Entry) WriteError!void {
        const w = self.dst;
        var block: [block_size]u8 = undefined;
        const typeflag: u8 = switch (e.kind) {
            .file => '0',
            .dir => '5',
            .symlink => '2',
            .hardlink => '1',
            .other => return error.UnsupportedKind,
        };
        if (e.path.len > 100) try writeGnuLong(w, &block, 'L', e.path);
        const has_link = e.kind == .symlink or e.kind == .hardlink;
        if (has_link and e.link_target.len > 100) try writeGnuLong(w, &block, 'K', e.link_target);
        emitHeader(
            &block,
            e.path,
            if (has_link) e.link_target else "",
            e.mode,
            e.uid,
            e.gid,
            if (e.kind == .file) e.size else 0,
            e.mtime,
            typeflag,
        );
        try w.writeAll(&block);
    }

    /// Pad a just-streamed file body to the 512-byte block boundary.
    pub fn writePadding(self: Writer, size: u64) std.Io.Writer.Error!void {
        try writeZeros(self.dst, padding(size));
    }

    /// Two zero blocks terminate the archive.
    pub fn finish(self: Writer) std.Io.Writer.Error!void {
        try writeZeros(self.dst, block_size * 2);
    }
};

fn writeGnuLong(w: *std.Io.Writer, block: *[block_size]u8, kind: u8, value: []const u8) std.Io.Writer.Error!void {
    emitHeader(block, gnu_longlink_name, "", 0, 0, 0, value.len + 1, 0, kind);
    try w.writeAll(block);
    try w.writeAll(value);
    try w.writeByte(0);
    try writeZeros(w, padding(value.len + 1));
}

/// Fill a 512-byte ustar header block. Strings over 100 bytes are truncated
/// here (a preceding GNU 'L'/'K' record carries the full value).
fn emitHeader(
    block: *[block_size]u8,
    name: []const u8,
    linkname: []const u8,
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    mtime: i64,
    typeflag: u8,
) void {
    @memset(block, 0);
    copyTrunc(block[0..100], name);
    writeOctalField(block[100..108], mode);
    writeOctalField(block[108..116], uid);
    writeOctalField(block[116..124], gid);
    writeSizeField(block[124..136], size);
    writeOctalField(block[136..148], @intCast(@max(mtime, 0)));
    block[156] = typeflag;
    copyTrunc(block[157..257], linkname);
    @memcpy(block[257..263], "ustar\x00");
    @memcpy(block[263..265], "00");

    @memset(block[148..156], ' ');
    var sum: u64 = 0;
    for (block) |b| sum += b;
    writeOctalField(block[148..155], sum); // 6 digits + NUL at [154]
    block[155] = ' ';
}

fn copyTrunc(dst: []u8, src: []const u8) void {
    const n = @min(dst.len, src.len);
    @memcpy(dst[0..n], src[0..n]);
}

/// Write `dst.len - 1` zero-padded octal digits + a trailing NUL.
fn writeOctalField(dst: []u8, value: u64) void {
    var v = value;
    var i = dst.len - 1;
    dst[i] = 0;
    while (i > 0) {
        i -= 1;
        dst[i] = '0' + @as(u8, @intCast(v & 7));
        v >>= 3;
    }
}

/// The 12-byte size field: octal up to 8 GiB - 1, GNU/star base-256 beyond
/// (0x80 marker + big-endian value — what GNU tar emits and `sizeField`
/// reads back).
fn writeSizeField(dst: *[12]u8, size: u64) void {
    if (size <= 0o77777777777) {
        writeOctalField(dst, size);
    } else {
        @memset(dst, 0);
        dst[0] = 0x80;
        std.mem.writeInt(u64, dst[4..12], size, .big);
    }
}

fn writeZeros(w: *std.Io.Writer, n: u64) std.Io.Writer.Error!void {
    const zeros: [block_size]u8 = @splat(0);
    var remaining = n;
    while (remaining > 0) {
        const chunk: usize = @intCast(@min(remaining, zeros.len));
        try w.writeAll(zeros[0..chunk]);
        remaining -= chunk;
    }
}

// ── gzip packer (portable) ──────────────────────────────────────────────────

/// One member for `packTarGz`: metadata + in-memory content (files only).
pub const ContentEntry = struct {
    entry: Entry,
    content: []const u8 = "",
};

pub const PackError = error{UnsupportedKind} || Allocator.Error || std.Io.Writer.Error;

/// Pack `entries` as a gzip-compressed tar stream onto `dst`, streaming
/// through `std.compress.flate` (one window-sized allocation, no whole-
/// archive buffering). `dst` needs a buffer capacity > 8 bytes (flate writes
/// the gzip header through it). The caller flushes `dst`.
pub fn packTarGz(gpa: Allocator, dst: *std.Io.Writer, entries: []const ContentEntry) PackError!void {
    const window = try gpa.alloc(u8, flate.max_window_len);
    defer gpa.free(window);
    var comp = try flate.Compress.init(dst, window, .gzip, .default);
    const tw = Writer.init(&comp.writer);
    for (entries) |ce| try tw.writeEntry(ce.entry, ce.content);
    try tw.finish();
    try comp.finish();
}

// ── filesystem packer (Linux — statx numeric attrs) ────────────────────────

pub const PackStats = struct {
    files: usize = 0,
    dirs: usize = 0,
    symlinks: usize = 0,
    /// Sum of file content sizes (uncompressed).
    bytes: u64 = 0,
};

pub const PackDirError = error{ PathTooLong, NoEntries } ||
    Allocator.Error || std.Io.Writer.Error || std.Io.Reader.StreamError;

/// Walk `roots` (filesystem paths) and write a gzip-compressed tar to `dst`.
/// Numeric attrs (mode/uid/gid/mtime) come from `statx`; symlinks are not
/// followed. Unstatable/unreadable entries and non-regular/dir/symlink types
/// are skipped (best-effort backup) so one bad file never fails the archive.
/// Stored paths are the given paths with any leading '/' trimmed. Linux-only
/// (raw `statx`/`readlink` syscalls); the codec above stays portable.
pub fn packDir(io: std.Io, gpa: Allocator, roots: []const []const u8, dst: *std.Io.Writer) PackDirError!PackStats {
    if (comptime builtin.os.tag != .linux)
        @compileError("tar.packDir is Linux-only (statx numeric attrs)");

    const window = try gpa.alloc(u8, flate.max_window_len);
    defer gpa.free(window);
    var comp = try flate.Compress.init(dst, window, .gzip, .default);
    const tw = Writer.init(&comp.writer);

    var stats: PackStats = .{};
    for (roots) |root| {
        if (root.len == 0) continue;
        const name = std.mem.trimStart(u8, root, "/");
        if (name.len == 0) continue;
        try emitPath(io, tw, root, name, &stats);
    }
    if (stats.files + stats.dirs + stats.symlinks == 0) return error.NoEntries;

    try tw.finish();
    try comp.finish();
    return stats;
}

fn emitPath(io: std.Io, tw: Writer, fs_path: []const u8, tar_name: []const u8, stats: *PackStats) PackDirError!void {
    const linux = std.os.linux;
    var pathz: [std.fs.max_path_bytes]u8 = undefined;
    const pz = std.fmt.bufPrintZ(&pathz, "{s}", .{fs_path}) catch return error.PathTooLong;

    var stx: linux.Statx = undefined;
    if (linux.errno(linux.statx(linux.AT.FDCWD, pz, linux.AT.SYMLINK_NOFOLLOW, linux.STATX.BASIC_STATS, &stx)) != .SUCCESS)
        return; // skip unstatable entries
    const ifmt = stx.mode & linux.S.IFMT;
    const perm: u32 = stx.mode & 0o7777;
    const mtime: i64 = stx.mtime.sec;

    if (ifmt == linux.S.IFDIR) {
        tw.writeHeader(.{ .path = tar_name, .kind = .dir, .mode = perm, .uid = stx.uid, .gid = stx.gid, .mtime = mtime }) catch |e|
            return stripUnsupported(e);
        stats.dirs += 1;
        var dir = std.Io.Dir.cwd().openDir(io, fs_path, .{ .iterate = true }) catch return;
        defer dir.close(io);
        var it = dir.iterate();
        while (it.next(io) catch null) |entry| {
            var cfs: [std.fs.max_path_bytes]u8 = undefined;
            var ctar: [std.fs.max_path_bytes]u8 = undefined;
            const child_fs = std.fmt.bufPrint(&cfs, "{s}/{s}", .{ fs_path, entry.name }) catch continue;
            const child_tar = std.fmt.bufPrint(&ctar, "{s}/{s}", .{ tar_name, entry.name }) catch continue;
            try emitPath(io, tw, child_fs, child_tar, stats);
        }
    } else if (ifmt == linux.S.IFLNK) {
        var lbuf: [std.fs.max_path_bytes]u8 = undefined;
        const n = linux.readlink(pz, &lbuf, lbuf.len);
        if (linux.errno(n) != .SUCCESS) return;
        tw.writeHeader(.{ .path = tar_name, .kind = .symlink, .link_target = lbuf[0..n], .mode = perm, .uid = stx.uid, .gid = stx.gid, .mtime = mtime }) catch |e|
            return stripUnsupported(e);
        stats.symlinks += 1;
    } else if (ifmt == linux.S.IFREG) {
        tw.writeHeader(.{ .path = tar_name, .kind = .file, .size = stx.size, .mode = perm, .uid = stx.uid, .gid = stx.gid, .mtime = mtime }) catch |e|
            return stripUnsupported(e);
        var f = std.Io.Dir.cwd().openFile(io, fs_path, .{}) catch {
            // Header already written with the declared size — keep the
            // archive well-formed by emitting that many zero bytes.
            try writeZeros(tw.dst, stx.size + padding(stx.size));
            return;
        };
        defer f.close(io);
        var rbuf: [64 * 1024]u8 = undefined;
        var fr = f.reader(io, &rbuf);
        try fr.interface.streamExact64(tw.dst, stx.size);
        try tw.writePadding(stx.size);
        stats.files += 1;
        stats.bytes += stx.size;
    }
    // other types (fifo/dev/socket) intentionally skipped
}

/// `Writer.writeHeader` can only fail with `UnsupportedKind` for `.other`
/// entries, which `emitPath` never constructs — narrow the error set.
fn stripUnsupported(e: WriteError) std.Io.Writer.Error {
    return switch (e) {
        error.UnsupportedKind => unreachable,
        else => |w| w,
    };
}

// ── tests: field primitives (ported from the seeds) ─────────────────────────

const testing = std.testing;

test "octal field emit + padding" {
    var b: [8]u8 = undefined;
    writeOctalField(&b, 0o644);
    try testing.expectEqualStrings("0000644\x00", &b);
    try testing.expectEqual(@as(u64, 412), padding(100));
    try testing.expectEqual(@as(u64, 0), padding(512));
}

test "octal + size parsing" {
    try testing.expectEqual(@as(u64, 0o644), octal("0000644\x00"));
    try testing.expectEqual(@as(u64, 0o755), octal("0000755 "));
    try testing.expectEqual(@as(u64, 0), octal("\x00\x00\x00"));
    try testing.expectEqual(@as(u64, 0), octal("garbage!"));
    var big: [12]u8 = .{ 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0 };
    try testing.expectEqual(@as(u64, 0x1000), sizeField(&big));
}

test "padding to 512" {
    try testing.expectEqual(@as(u64, 0), padding(0));
    try testing.expectEqual(@as(u64, 511), padding(1));
    try testing.expectEqual(@as(u64, 0), padding(512));
    try testing.expectEqual(@as(u64, 412), padding(100));
    try testing.expectEqual(@as(u64, 1), padding(1023));
}

test "size field base-256 round-trip (>8 GiB)" {
    const huge: u64 = 20 * 1024 * 1024 * 1024 + 7; // 20 GiB + 7
    var field: [12]u8 = undefined;
    writeSizeField(&field, huge);
    try testing.expectEqual(@as(u8, 0x80), field[0]);
    try testing.expectEqual(huge, sizeField(&field));
    // and the octal path is untouched below the cutoff
    writeSizeField(&field, 12);
    try testing.expectEqualStrings("00000000014\x00", &field);
    try testing.expectEqual(@as(u64, 12), sizeField(&field));
}

// ── tests: golden header bytes ──────────────────────────────────────────────

// First 512 bytes of `tar --format=gnu -cf - --owner=1234 --group=4321
// --mtime=@1600000000 hello.txt` (GNU tar 1.35), hello.txt = "hello world\n",
// mode 0644. Pins the on-disk header layout + checksum ("007617") we must
// parse — and, field-for-field, what we emit.
const golden_gnu_header_hex =
    "68656c6c6f2e7478740000000000000000000000000000000000000000000000" ++
    "0000000000000000000000000000000000000000000000000000000000000000" ++
    "0000000000000000000000000000000000000000000000000000000000000000" ++
    "0000000030303030363434003030303233323200303031303334310030303030" ++
    "3030303030313400313337323734313030303000303037363137002030000000" ++
    "0000000000000000000000000000000000000000000000000000000000000000" ++
    "0000000000000000000000000000000000000000000000000000000000000000" ++
    "0000000000000000000000000000000000000000000000000000000000000000" ++
    "0075737461722020000000000000000000000000000000000000000000000000" ++
    "0000000000000000000000000000000000000000000000000000000000000000" ++
    "0000000000000000000000000000000000000000000000000000000000000000" ++
    "0000000000000000000000000000000000000000000000000000000000000000" ++
    "0000000000000000000000000000000000000000000000000000000000000000" ++
    "0000000000000000000000000000000000000000000000000000000000000000" ++
    "0000000000000000000000000000000000000000000000000000000000000000" ++
    "0000000000000000000000000000000000000000000000000000000000000000";

fn goldenGnuArchive(buf: *[2048]u8) void {
    @memset(buf, 0);
    var header: [block_size]u8 = undefined;
    _ = std.fmt.hexToBytes(&header, golden_gnu_header_hex) catch unreachable;
    @memcpy(buf[0..block_size], &header);
    @memcpy(buf[block_size..][0..12], "hello world\n");
    // rest: content padding + two zero trailer blocks
}

test "reader parses a real GNU tar header (golden bytes)" {
    var archive: [2048]u8 = undefined;
    goldenGnuArchive(&archive);

    var src: std.Io.Reader = .fixed(&archive);
    var tr = Reader.init(testing.allocator, &src);
    defer tr.deinit();

    const e = (try tr.next()).?;
    try testing.expectEqualStrings("hello.txt", e.path);
    try testing.expectEqual(Kind.file, e.kind);
    try testing.expectEqual(@as(u32, 0o644), e.mode);
    try testing.expectEqual(@as(u32, 1234), e.uid);
    try testing.expectEqual(@as(u32, 4321), e.gid);
    try testing.expectEqual(@as(i64, 1_600_000_000), e.mtime);
    try testing.expectEqual(@as(u64, 12), e.size);
    try testing.expectEqualStrings("", e.link_target);

    var buf: [64]u8 = undefined;
    const n = try tr.read(&buf);
    try testing.expectEqual(@as(usize, 12), n);
    try testing.expectEqualStrings("hello world\n", buf[0..12]);
    try testing.expectEqual(@as(usize, 0), try tr.read(&buf));
    try testing.expectEqual(@as(?Entry, null), try tr.next());
}

test "writer emits the GNU header fields byte-for-byte" {
    // Same entry as the golden capture; our emit differs from GNU only where
    // allowed (magic "ustar\x0000" vs GNU "ustar  \0" — which shifts the
    // checksum). Compare every field we own.
    var golden: [block_size]u8 = undefined;
    _ = std.fmt.hexToBytes(&golden, golden_gnu_header_hex) catch unreachable;

    var buf: [4 * block_size]u8 = undefined;
    var dst: std.Io.Writer = .fixed(&buf);
    const tw = Writer.init(&dst);
    try tw.writeEntry(.{
        .path = "hello.txt",
        .mode = 0o644,
        .uid = 1234,
        .gid = 4321,
        .mtime = 1_600_000_000,
    }, "hello world\n");
    const ours = dst.buffered()[0..block_size];

    try testing.expectEqualSlices(u8, golden[0..100], ours[0..100]); // name
    try testing.expectEqualSlices(u8, golden[100..148], ours[100..148]); // mode..mtime
    try testing.expectEqual(golden[156], ours[156]); // typeflag
    try testing.expectEqualSlices(u8, golden[157..257], ours[157..257]); // linkname
    try testing.expectEqualSlices(u8, "ustar\x0000", ours[257..265]); // POSIX magic
    // Our checksum must satisfy the spec formula (and the reader).
    try verifyChecksum(ours[0..block_size]);
    // Content + padding + trailer blocking.
    try testing.expectEqualStrings("hello world\n", dst.buffered()[block_size..][0..12]);
}

// ── tests: round-trips ──────────────────────────────────────────────────────

fn readAllContent(tr: *Reader, gpa: Allocator) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var buf: [7]u8 = undefined; // deliberately tiny — exercise streaming
    while (true) {
        const n = try tr.read(&buf);
        if (n == 0) break;
        try out.appendSlice(gpa, buf[0..n]);
    }
    return out.toOwnedSlice(gpa);
}

test "write -> read round-trip preserves uid/gid/mtime/mode/size/path/link_target" {
    const gpa = testing.allocator;
    const long_path = "deep/" ** 29 ++ "leaf.txt"; // 153 bytes > 100
    const long_target = "../" ** 40 ++ "target-far-away"; // 135 bytes > 100

    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    const tw = Writer.init(&aw.writer);

    try tw.writeEntry(.{ .path = "etc", .kind = .dir, .mode = 0o755, .uid = 0, .gid = 0, .mtime = 1_500_000_000 }, "");
    try tw.writeEntry(.{ .path = "etc/hostname", .mode = 0o644, .uid = 1234, .gid = 4321, .mtime = 1_600_000_001 }, "router\n");
    try tw.writeEntry(.{ .path = "etc/link", .kind = .symlink, .link_target = "hostname", .mode = 0o777, .uid = 55, .gid = 66, .mtime = 1_600_000_002 }, "");
    try tw.writeEntry(.{ .path = "etc/hard", .kind = .hardlink, .link_target = "etc/hostname", .mode = 0o644, .uid = 1234, .gid = 4321, .mtime = 1_600_000_001 }, "");
    try tw.writeEntry(.{ .path = long_path, .mode = 0o600, .uid = 7, .gid = 8, .mtime = 1_600_000_003 }, "long path content");
    try tw.writeEntry(.{ .path = "etc/longlink", .kind = .symlink, .link_target = long_target, .mode = 0o777, .uid = 9, .gid = 10, .mtime = 1_600_000_004 }, "");
    try tw.finish();

    var src: std.Io.Reader = .fixed(aw.writer.buffered());
    var tr = Reader.init(gpa, &src);
    defer tr.deinit();

    {
        const e = (try tr.next()).?;
        try testing.expectEqualStrings("etc", e.path);
        try testing.expectEqual(Kind.dir, e.kind);
        try testing.expectEqual(@as(u32, 0o755), e.mode);
        try testing.expectEqual(@as(u32, 0), e.uid);
        try testing.expectEqual(@as(u32, 0), e.gid);
        try testing.expectEqual(@as(i64, 1_500_000_000), e.mtime);
        try testing.expectEqual(@as(u64, 0), e.size);
    }
    {
        const e = (try tr.next()).?;
        try testing.expectEqualStrings("etc/hostname", e.path);
        try testing.expectEqual(Kind.file, e.kind);
        try testing.expectEqual(@as(u32, 0o644), e.mode);
        try testing.expectEqual(@as(u32, 1234), e.uid);
        try testing.expectEqual(@as(u32, 4321), e.gid);
        try testing.expectEqual(@as(i64, 1_600_000_001), e.mtime);
        try testing.expectEqual(@as(u64, 7), e.size);
        const content = try readAllContent(&tr, gpa);
        defer gpa.free(content);
        try testing.expectEqualStrings("router\n", content);
    }
    {
        const e = (try tr.next()).?;
        try testing.expectEqualStrings("etc/link", e.path);
        try testing.expectEqual(Kind.symlink, e.kind);
        try testing.expectEqualStrings("hostname", e.link_target);
        try testing.expectEqual(@as(u32, 0o777), e.mode);
        try testing.expectEqual(@as(u32, 55), e.uid);
        try testing.expectEqual(@as(u32, 66), e.gid);
        try testing.expectEqual(@as(i64, 1_600_000_002), e.mtime);
    }
    {
        const e = (try tr.next()).?;
        try testing.expectEqualStrings("etc/hard", e.path);
        try testing.expectEqual(Kind.hardlink, e.kind);
        try testing.expectEqualStrings("etc/hostname", e.link_target);
    }
    {
        const e = (try tr.next()).?; // GNU 'L' long name
        try testing.expectEqualStrings(long_path, e.path);
        try testing.expectEqual(Kind.file, e.kind);
        try testing.expectEqual(@as(u32, 0o600), e.mode);
        try testing.expectEqual(@as(u32, 7), e.uid);
        try testing.expectEqual(@as(u32, 8), e.gid);
        try testing.expectEqual(@as(i64, 1_600_000_003), e.mtime);
        const content = try readAllContent(&tr, gpa);
        defer gpa.free(content);
        try testing.expectEqualStrings("long path content", content);
    }
    {
        const e = (try tr.next()).?; // GNU 'K' long link target
        try testing.expectEqualStrings("etc/longlink", e.path);
        try testing.expectEqual(Kind.symlink, e.kind);
        try testing.expectEqualStrings(long_target, e.link_target);
        try testing.expectEqual(@as(u32, 9), e.uid);
        try testing.expectEqual(@as(u32, 10), e.gid);
    }
    try testing.expectEqual(@as(?Entry, null), try tr.next());
    try testing.expectEqual(@as(?Entry, null), try tr.next()); // stays done
}

test "next() auto-skips unread content" {
    const gpa = testing.allocator;
    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    const tw = Writer.init(&aw.writer);
    try tw.writeEntry(.{ .path = "a.bin" }, "0123456789" ** 100); // 1000 bytes
    try tw.writeEntry(.{ .path = "b.txt" }, "b");
    try tw.finish();

    var src: std.Io.Reader = .fixed(aw.writer.buffered());
    var tr = Reader.init(gpa, &src);
    defer tr.deinit();
    try testing.expectEqualStrings("a.bin", (try tr.next()).?.path);
    // don't read a.bin's content at all
    const e = (try tr.next()).?;
    try testing.expectEqualStrings("b.txt", e.path);
    const content = try readAllContent(&tr, gpa);
    defer gpa.free(content);
    try testing.expectEqualStrings("b", content);
    try testing.expectEqual(@as(?Entry, null), try tr.next());
}

test "gzip round-trip: packTarGz -> flate.Decompress -> Reader" {
    const gpa = testing.allocator;
    const long_path = "dir-with-a-rather-long-name/" ** 5 ++ "file.dat"; // 148 bytes

    var aw: std.Io.Writer.Allocating = try .initCapacity(gpa, 4096);
    defer aw.deinit();
    try packTarGz(gpa, &aw.writer, &.{
        .{ .entry = .{ .path = "data", .kind = .dir, .mode = 0o755, .uid = 3, .gid = 4, .mtime = 1_650_000_000 } },
        .{ .entry = .{ .path = "data/report.csv", .mode = 0o640, .uid = 1000, .gid = 1000, .mtime = 1_650_000_001 }, .content = "a,b\n1,2\n" },
        .{ .entry = .{ .path = long_path, .mode = 0o400, .uid = 5, .gid = 6, .mtime = 1_650_000_002 }, .content = "payload" },
    });
    try aw.writer.flush();
    const gz = aw.writer.buffered();
    try testing.expect(gz.len >= 2 and gz[0] == 0x1f and gz[1] == 0x8b); // gzip magic

    var src: std.Io.Reader = .fixed(gz);
    const window = try gpa.alloc(u8, flate.max_window_len);
    defer gpa.free(window);
    var decomp = flate.Decompress.init(&src, .gzip, window);
    var tr = Reader.init(gpa, &decomp.reader);
    defer tr.deinit();

    {
        const e = (try tr.next()).?;
        try testing.expectEqualStrings("data", e.path);
        try testing.expectEqual(Kind.dir, e.kind);
        try testing.expectEqual(@as(u32, 3), e.uid);
    }
    {
        const e = (try tr.next()).?;
        try testing.expectEqualStrings("data/report.csv", e.path);
        try testing.expectEqual(@as(u32, 0o640), e.mode);
        try testing.expectEqual(@as(i64, 1_650_000_001), e.mtime);
        const content = try readAllContent(&tr, gpa);
        defer gpa.free(content);
        try testing.expectEqualStrings("a,b\n1,2\n", content);
    }
    {
        const e = (try tr.next()).?;
        try testing.expectEqualStrings(long_path, e.path);
        const content = try readAllContent(&tr, gpa);
        defer gpa.free(content);
        try testing.expectEqualStrings("payload", content);
    }
    try testing.expectEqual(@as(?Entry, null), try tr.next());
}

// ── tests: malformed input never panics ─────────────────────────────────────

test "empty archive: just the trailer / zero bytes" {
    const gpa = testing.allocator;
    { // two zero blocks (what Writer.finish() alone emits)
        var aw: std.Io.Writer.Allocating = .init(gpa);
        defer aw.deinit();
        try Writer.init(&aw.writer).finish();
        try testing.expectEqual(@as(usize, 2 * block_size), aw.writer.buffered().len);
        var src: std.Io.Reader = .fixed(aw.writer.buffered());
        var tr = Reader.init(gpa, &src);
        defer tr.deinit();
        try testing.expectEqual(@as(?Entry, null), try tr.next());
    }
    { // zero-length input = clean EOF
        var src: std.Io.Reader = .fixed("");
        var tr = Reader.init(gpa, &src);
        defer tr.deinit();
        try testing.expectEqual(@as(?Entry, null), try tr.next());
    }
}

test "truncated header -> error, no panic" {
    var src: std.Io.Reader = .fixed(golden_gnu_header_hex[0..300]); // 300 junk bytes
    var tr = Reader.init(testing.allocator, &src);
    defer tr.deinit();
    try testing.expectError(error.TruncatedArchive, tr.next());
}

test "truncated content -> error, no panic" {
    var archive: [2048]u8 = undefined;
    goldenGnuArchive(&archive);
    // header promises 12 bytes; cut the stream 4 bytes into the content
    var src: std.Io.Reader = .fixed(archive[0 .. block_size + 4]);
    var tr = Reader.init(testing.allocator, &src);
    defer tr.deinit();
    const e = (try tr.next()).?;
    try testing.expectEqual(@as(u64, 12), e.size);
    var buf: [64]u8 = undefined;
    try testing.expectEqual(@as(usize, 4), try tr.read(&buf)); // the 4 bytes present
    try testing.expectError(error.TruncatedArchive, tr.read(&buf));
}

test "truncated mid-archive on a block boundary after content skip" {
    var archive: [2048]u8 = undefined;
    goldenGnuArchive(&archive);
    // keep header + only half of the content block
    var src: std.Io.Reader = .fixed(archive[0 .. block_size + 256]);
    var tr = Reader.init(testing.allocator, &src);
    defer tr.deinit();
    _ = (try tr.next()).?;
    try testing.expectError(error.TruncatedArchive, tr.next()); // skip runs off the end
}

test "bad checksum -> error.BadHeader, no panic" {
    var archive: [2048]u8 = undefined;
    goldenGnuArchive(&archive);
    archive[0] ^= 0xff; // corrupt the name without fixing the checksum
    var src: std.Io.Reader = .fixed(&archive);
    var tr = Reader.init(testing.allocator, &src);
    defer tr.deinit();
    try testing.expectError(error.BadHeader, tr.next());
}

test "garbage block -> error.BadHeader, no panic" {
    const garbage: [2 * block_size]u8 = @splat('A');
    var src: std.Io.Reader = .fixed(&garbage);
    var tr = Reader.init(testing.allocator, &src);
    defer tr.deinit();
    try testing.expectError(error.BadHeader, tr.next());
}

test "hostile GNU 'L' size -> error.BadHeader" {
    var buf: [4 * block_size]u8 = undefined;
    var dst: std.Io.Writer = .fixed(&buf);
    var block: [block_size]u8 = undefined;
    // 'L' record claiming a 1 MiB name (over max_name_len)
    emitHeader(&block, gnu_longlink_name, "", 0, 0, 0, 1024 * 1024, 0, 'L');
    try dst.writeAll(&block);
    var src: std.Io.Reader = .fixed(dst.buffered());
    var tr = Reader.init(testing.allocator, &src);
    defer tr.deinit();
    try testing.expectError(error.BadHeader, tr.next());
}

test "ustar prefix field is honored (POSIX magic only)" {
    var buf: [4 * block_size]u8 = undefined;
    var dst: std.Io.Writer = .fixed(&buf);
    var block: [block_size]u8 = undefined;
    emitHeader(&block, "name.txt", "", 0o644, 1, 2, 0, 0, '0');
    copyTrunc(block[345..500], "some/prefix"); // splice in a prefix…
    // …and re-checksum
    @memset(block[148..156], ' ');
    var sum: u64 = 0;
    for (block) |b| sum += b;
    writeOctalField(block[148..155], sum);
    block[155] = ' ';
    try dst.writeAll(&block);
    try dst.splatByteAll(0, 2 * block_size);

    var src: std.Io.Reader = .fixed(dst.buffered());
    var tr = Reader.init(testing.allocator, &src);
    defer tr.deinit();
    const e = (try tr.next()).?;
    try testing.expectEqualStrings("some/prefix/name.txt", e.path);
}

test "writer rejects .other entries" {
    var buf: [2 * block_size]u8 = undefined;
    var dst: std.Io.Writer = .fixed(&buf);
    const tw = Writer.init(&dst);
    try testing.expectError(error.UnsupportedKind, tw.writeEntry(.{ .path = "x", .kind = .other }, ""));
}

// ── tests: Linux filesystem packer ──────────────────────────────────────────

test "packDir: statx numeric attrs survive the round-trip (Linux)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const linux = std.os.linux;
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "tree/sub");
    try tmp.dir.writeFile(io, .{ .sub_path = "tree/hello.txt", .data = "hello from packDir\n" });
    try tmp.dir.symLink(io, "hello.txt", "tree/sub/link", .{});

    var rootbuf: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_len = try tmp.dir.realPath(io, &rootbuf);
    var root: [std.fs.max_path_bytes]u8 = undefined;
    const root_path = try std.fmt.bufPrint(&root, "{s}/tree", .{rootbuf[0..tmp_len]});

    var aw: std.Io.Writer.Allocating = try .initCapacity(gpa, 4096);
    defer aw.deinit();
    const stats = try packDir(io, gpa, &.{root_path}, &aw.writer);
    try aw.writer.flush();
    try testing.expectEqual(@as(usize, 1), stats.files);
    try testing.expectEqual(@as(usize, 2), stats.dirs); // tree + tree/sub
    try testing.expectEqual(@as(usize, 1), stats.symlinks);
    try testing.expectEqual(@as(u64, 19), stats.bytes);

    var src: std.Io.Reader = .fixed(aw.writer.buffered());
    const window = try gpa.alloc(u8, flate.max_window_len);
    defer gpa.free(window);
    var decomp = flate.Decompress.init(&src, .gzip, window);
    var tr = Reader.init(gpa, &decomp.reader);
    defer tr.deinit();

    const my_uid: u32 = linux.getuid();
    const my_gid: u32 = linux.getgid();
    const stored_root = std.mem.trimStart(u8, root_path, "/");
    var seen_file = false;
    var seen_link = false;
    var count: usize = 0;
    while (try tr.next()) |e| {
        count += 1;
        try testing.expect(std.mem.startsWith(u8, e.path, stored_root));
        try testing.expectEqual(my_uid, e.uid);
        try testing.expectEqual(my_gid, e.gid);
        try testing.expect(e.mtime > 1_600_000_000); // real, recent timestamp
        if (std.mem.endsWith(u8, e.path, "/hello.txt")) {
            seen_file = true;
            try testing.expectEqual(Kind.file, e.kind);
            const content = try readAllContent(&tr, gpa);
            defer gpa.free(content);
            try testing.expectEqualStrings("hello from packDir\n", content);
        } else if (std.mem.endsWith(u8, e.path, "/link")) {
            seen_link = true;
            try testing.expectEqual(Kind.symlink, e.kind);
            try testing.expectEqualStrings("hello.txt", e.link_target);
        }
    }
    try testing.expectEqual(@as(usize, 4), count);
    try testing.expect(seen_file);
    try testing.expect(seen_link);
}

// ── tests: cross-check against system GNU tar (skips if absent) ─────────────

fn systemTar(gpa: Allocator, io: std.Io, cwd: std.Io.Dir, argv: []const []const u8) !?std.process.RunResult {
    const res = std.process.run(gpa, io, .{ .argv = argv, .cwd = .{ .dir = cwd } }) catch return null;
    switch (res.term) {
        .exited => |code| if (code == 0) return res,
        else => {},
    }
    gpa.free(res.stdout);
    gpa.free(res.stderr);
    return error.ChildFailed;
}

test "GNU tar extracts + lists our archive (external cross-check)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // Is a `tar` binary available at all?
    const probe = systemTar(gpa, io, tmp.dir, &.{ "tar", "--version" }) catch return error.SkipZigTest;
    const probe_res = probe orelse return error.SkipZigTest;
    gpa.free(probe_res.stdout);
    gpa.free(probe_res.stderr);

    // Write an archive with our Writer (incl. a >100-byte GNU long name).
    const long_path = "nested/" ** 16 ++ "deep-file.txt"; // 125 bytes
    {
        var f = try tmp.dir.createFile(io, "ours.tar", .{});
        defer f.close(io);
        var fbuf: [8192]u8 = undefined;
        var fw = f.writer(io, &fbuf);
        const tw = Writer.init(&fw.interface);
        try tw.writeEntry(.{ .path = "hello.txt", .mode = 0o644, .uid = 1234, .gid = 4321, .mtime = 1_600_000_000 }, "hello world\n");
        try tw.writeEntry(.{ .path = "sub", .kind = .dir, .mode = 0o755, .mtime = 1_600_000_000 }, "");
        try tw.writeEntry(.{ .path = "sub/link", .kind = .symlink, .link_target = "../hello.txt", .mode = 0o777, .mtime = 1_600_000_000 }, "");
        try tw.writeEntry(.{ .path = long_path, .mode = 0o600, .uid = 7, .gid = 8, .mtime = 1_600_000_000 }, "deep content");
        try tw.finish();
        try fw.interface.flush();
    }

    // `tar tvf` listing shows the right names, sizes and numeric ids.
    {
        const res = (try systemTar(gpa, io, tmp.dir, &.{ "tar", "--numeric-owner", "-tvf", "ours.tar" })).?;
        defer gpa.free(res.stdout);
        defer gpa.free(res.stderr);
        try testing.expect(std.mem.indexOf(u8, res.stdout, "hello.txt") != null);
        try testing.expect(std.mem.indexOf(u8, res.stdout, "1234/4321") != null);
        try testing.expect(std.mem.indexOf(u8, res.stdout, " 12 ") != null); // hello.txt size
        try testing.expect(std.mem.indexOf(u8, res.stdout, long_path) != null);
        try testing.expect(std.mem.indexOf(u8, res.stdout, "sub/link -> ../hello.txt") != null);
    }

    // `tar xf` extracts the right bytes.
    {
        try tmp.dir.createDirPath(io, "out");
        const res = (try systemTar(gpa, io, tmp.dir, &.{ "tar", "-xf", "ours.tar", "-C", "out" })).?;
        gpa.free(res.stdout);
        gpa.free(res.stderr);
        const hello = try tmp.dir.readFileAlloc(io, "out/hello.txt", gpa, .limited(1024));
        defer gpa.free(hello);
        try testing.expectEqualStrings("hello world\n", hello);
        const deep = try tmp.dir.readFileAlloc(io, "out/" ++ long_path, gpa, .limited(1024));
        defer gpa.free(deep);
        try testing.expectEqualStrings("deep content", deep);
        var lbuf: [256]u8 = undefined;
        const tlen = try tmp.dir.readLink(io, "out/sub/link", &lbuf);
        try testing.expectEqualStrings("../hello.txt", lbuf[0..tlen]);
    }

    // And the reverse: read a GNU-tar-produced archive with our Reader.
    {
        try tmp.dir.writeFile(io, .{ .sub_path = "theirs.txt", .data = "made by gnu tar\n" });
        const res = (try systemTar(gpa, io, tmp.dir, &.{
            "tar",                 "--format=gnu", "--owner=111", "--group=222",
            "--mtime=@1600000000", "-cf",          "theirs.tar",  "theirs.txt",
        })).?;
        gpa.free(res.stdout);
        gpa.free(res.stderr);

        var f = try tmp.dir.openFile(io, "theirs.tar", .{});
        defer f.close(io);
        var rbuf: [8192]u8 = undefined;
        var fr = f.reader(io, &rbuf);
        var tr = Reader.init(gpa, &fr.interface);
        defer tr.deinit();
        const e = (try tr.next()).?;
        try testing.expectEqualStrings("theirs.txt", e.path);
        try testing.expectEqual(@as(u32, 111), e.uid);
        try testing.expectEqual(@as(u32, 222), e.gid);
        try testing.expectEqual(@as(i64, 1_600_000_000), e.mtime);
        try testing.expectEqual(@as(u64, 16), e.size);
        const content = try readAllContent(&tr, gpa);
        defer gpa.free(content);
        try testing.expectEqualStrings("made by gnu tar\n", content);
        try testing.expectEqual(@as(?Entry, null), try tr.next());
    }
}
