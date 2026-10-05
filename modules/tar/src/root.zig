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
//!    ustar `prefix` field, GNU/star base-256 size fields, and pax extended
//!    headers ('x'): `path`, `linkpath`, `size`, `uid`, `gid` and `mtime`
//!    (whole seconds + nanoseconds, may be negative) override the ustar fields
//!    (what Python's tarfile, Go's archive/tar and bsdtar write for a long
//!    name, a file over 8 GiB, a large id or a fractional time), other pax
//!    records are parsed past; a malformed pax header is `error.BadHeader`. Global pax headers ('g') are
//!    skipped: a global `path`/`size` has no per-entry meaning. Unknown typeflags
//!    surface as `.other` so the caller decides. Every header is checksum-
//!    verified and bounds-checked — truncated/garbage input yields an error,
//!    never a panic. Bounded memory: only names are buffered (64 KiB cap),
//!    content is streamed via `read`.
//!  - `Writer` (portable): emits ustar blocks with GNU 'L'/'K' records for
//!    >100-byte paths/link targets, correct checksums, 512-byte blocking and
//!    the two zero trailer blocks. Byte-faithful round-trip with `Reader`.
//!    `WriteOptions.long_names = .pax` instead emits a pax 'x' record set for
//!    whatever ustar cannot hold (long path/link, size over 8 GiB, ids over
//!    2 097 151, negative or fractional mtime).
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
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "ustar/GNU tar reader+writer (preserves uid/gid/mtime) + gzip.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any (packer: linux)",
    .targets = .{ .linux64, .linux32 },
    .platform = .any, // codec is platform-pure; only packDir is Linux (statx)
    .role = .both, // reader + writer
    .concurrency = .reentrant, // no globals; one Reader/Writer per stream
    .model_after = "POSIX ustar + the documented GNU extension layout; a GNU tar binary was used as a black-box compatibility oracle only, never its source",
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
    /// Whole seconds since the epoch (floor: the instant is `mtime` plus
    /// `mtime_nsec` nanoseconds, so -1.25 s is `mtime = -2`,
    /// `mtime_nsec = 750_000_000`). Negative or over `0o77777777777` is
    /// `error.FieldOutOfRange` for a GNU-mode writer, a pax record in pax mode.
    mtime: i64 = 0,
    /// Sub-second part of the mtime, 0..999_999_999. Only a pax `mtime`
    /// record carries it: the reader fills it from one (else 0), the pax-mode
    /// writer emits it, the GNU-mode writer drops it (ustar has no room).
    mtime_nsec: u32 = 0,
    /// Content byte count (files; 0 for dirs/symlinks/hardlinks).
    size: u64 = 0,
    /// Symlink target / hard-link target ('2'/'1' entries), else "".
    link_target: []const u8 = "",
    /// Raw header typeflag as read; informative for `.other` entries.
    /// Ignored by the writer (derived from `kind`).
    typeflag: u8 = 0,

    /// Copy `path`/`link_target` into `allocator` and return an `OwnedEntry`
    /// that outlives the next `Reader.next()`/`deinit()` call — for a caller
    /// building a manifest (or anything else that needs an `Entry` to
    /// survive past the next iteration) instead of consuming it immediately.
    /// The distinct return type (not `Entry`) is deliberate: `OwnedEntry`'s
    /// own `deinit` is the tell at the call site that these two string
    /// fields are now the caller's to free, unlike a plain `Entry`, which
    /// never owns anything and has no `deinit` at all.
    pub fn dupe(self: Entry, allocator: Allocator) Allocator.Error!OwnedEntry {
        const path = try allocator.dupe(u8, self.path);
        errdefer allocator.free(path);
        const link_target = try allocator.dupe(u8, self.link_target);
        return .{
            .path = path,
            .kind = self.kind,
            .mode = self.mode,
            .uid = self.uid,
            .gid = self.gid,
            .mtime = self.mtime,
            .mtime_nsec = self.mtime_nsec,
            .size = self.size,
            .link_target = link_target,
            .typeflag = self.typeflag,
        };
    }
};

/// An `Entry` whose `path`/`link_target` are independently owned (see
/// `Entry.dupe`) — safe to keep across a `Reader.next()` call, unlike the
/// borrowed slices on a plain `Entry`. Must be `deinit`'d by the same
/// allocator passed to `dupe`.
pub const OwnedEntry = struct {
    path: []u8,
    kind: Kind = .file,
    mode: u32 = 0,
    uid: u32 = 0,
    gid: u32 = 0,
    mtime: i64 = 0,
    mtime_nsec: u32 = 0,
    size: u64 = 0,
    link_target: []u8 = &.{},
    typeflag: u8 = 0,

    pub fn deinit(self: *OwnedEntry, allocator: Allocator) void {
        allocator.free(self.path);
        allocator.free(self.link_target);
        self.* = undefined;
    }
};

const gnu_longlink_name = "././@LongLink";
/// Largest accepted GNU 'L'/'K' payload — sanity cap against hostile input.
pub const max_name_len = 64 * 1024;
/// Largest accepted pax extended header ('x') payload. Larger than
/// `max_name_len` because a pax header also carries records this reader does
/// not use (xattrs, ACLs, high-resolution times), which it must still parse
/// past; a header over the cap is refused, not truncated.
pub const max_pax_len = 1024 * 1024;

// ── Reader ──────────────────────────────────────────────────────────────────

pub const ReadError = error{
    /// The stream ended inside a header or declared content, or a header
    /// block was short.
    TruncatedArchive,
    /// Checksum mismatch / unparseable checksum field / bad 'L'-'K' size /
    /// a malformed or oversized pax extended header.
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
    /// `path`, `linkpath`, `size`, `uid`, `gid` and `mtime` from a pax extended
    /// header ('x') for the next real entry. They win over GNU 'L'/'K' and over the ustar fields:
    /// the header's own fields are only the fallback a pax-unaware reader
    /// sees (a truncated name, a size of 0 for a file over 8 GiB).
    pax_path: ?[]u8 = null,
    pax_link: ?[]u8 = null,
    pax_size: ?u64 = null,
    pax_uid: ?u32 = null,
    pax_gid: ?u32 = null,
    pax_mtime: ?PaxTime = null,
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
        if (self.pax_path) |p| self.gpa.free(p);
        if (self.pax_link) |p| self.gpa.free(p);
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

            const h = try parseHeader(&block);
            // Reject a size so large that `h.size + content_pad` (used below
            // for pax/GNU-long skip-and-discard) could overflow u64. No real
            // archive needs a size this close to maxInt(u64); a header that
            // claims one is malformed/hostile, not a legitimately huge file.
            if (h.size > std.math.maxInt(u64) - block_size) return error.BadHeader;
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
                'x' => { // pax extended header for the next entry
                    try self.readPax(h.size);
                    continue;
                },
                'g' => { // pax GLOBAL header: skipped, see the module doc
                    try self.discard(h.size + content_pad);
                    continue;
                },
                else => {},
            }

            // Materialize the path: pax `path` wins over a pending GNU 'L',
            // which wins over prefix+name.
            const new_path: []u8 = if (self.pax_path) |p| take: {
                self.pax_path = null;
                break :take p;
            } else if (self.pending_path) |p| take: {
                self.pending_path = null;
                break :take p;
            } else try joinName(self.gpa, h.prefix, h.name);
            self.gpa.free(self.path_buf);
            self.path_buf = new_path;

            const new_link: []u8 = if (self.pax_link) |p| take: {
                self.pax_link = null;
                break :take p;
            } else if (self.pending_link) |p| take: {
                self.pending_link = null;
                break :take p;
            } else try self.gpa.dupe(u8, h.linkname);
            self.gpa.free(self.link_buf);
            self.link_buf = new_link;
            // A GNU record the pax one overrode is consumed with it, so it
            // cannot leak onto the entry after this one.
            if (self.pending_path) |p| self.gpa.free(p);
            if (self.pending_link) |p| self.gpa.free(p);
            self.pending_path = null;
            self.pending_link = null;

            // pax `size` replaces the header's: past 8 GiB the ustar field
            // cannot hold it, and a reader that used the header's value would
            // desynchronise from the stream.
            const size: u64 = if (self.pax_size) |ps| ps else h.size;
            self.pax_size = null;
            // pax uid/gid/mtime likewise replace the header's fields (which a
            // pax writer leaves 0 when the real value does not fit).
            const uid: u32 = self.pax_uid orelse h.uid;
            const gid: u32 = self.pax_gid orelse h.gid;
            const mtime: PaxTime = self.pax_mtime orelse .{ .sec = h.mtime, .nsec = 0 };
            self.pax_uid = null;
            self.pax_gid = null;
            self.pax_mtime = null;
            if (size > std.math.maxInt(u64) - block_size) return error.BadHeader;

            // Pre-POSIX tars had no directory typeflag: a NUL typeflag ("old
            // regular file") whose name ends in '/' is a directory. GNU tar
            // 1.35 and Go both read it so; this reader called it an empty
            // file, which an extractor would create in place of the directory.
            // Only NUL: a '0' entry named "dir/" stays a file for both.
            const old_dir = h.typeflag == 0 and std.mem.endsWith(u8, std.mem.sliceTo(self.path_buf, 0), "/");
            const kind: Kind = if (old_dir) .dir else switch (h.typeflag) {
                0, '0', '7' => .file, // '7' = contiguous, treated as regular
                '5' => .dir,
                '2' => .symlink,
                '1' => .hardlink,
                else => .other,
            };
            // Whether this entry is followed by content blocks at all. POSIX
            // (pax, "ustar Interchange Format") is explicit: "No data logical
            // records are stored for types 1, 2, or 5", and a link's size
            // "shall be specified as zero". Device and FIFO entries ('3', '4',
            // '6') carry none either.
            //
            // This is not merely a conformance nicety: honoring a size field
            // on such an entry desynchronises the reader from the archive.
            // A header planted in the blocks the liar claims as its content
            // is then consumed as data and never reported, while a real
            // extractor still creates that file — so a scanner or policy gate
            // built on this Reader sees fewer entries than `tar -xf` writes.
            //
            // The set was established against GNU tar 1.35 rather than
            // assumed: the same 5-block archive lists 3 entries under
            // `tar tf` for each of '1','2','3','4','5','6', and 2 entries for
            // '7'. Contiguous files ('7') DO carry content, which is why they
            // are deliberately absent here and stay on the `else` arm.
            const carries_content = !old_dir and switch (h.typeflag) {
                '1', '2', '3', '4', '5', '6' => false,
                else => true,
            };
            self.remaining = if (carries_content) size else 0;
            self.pad = if (carries_content) padding(size) else 0;

            return .{
                .path = std.mem.sliceTo(self.path_buf, 0),
                .kind = kind,
                .mode = h.mode,
                .uid = uid,
                .gid = gid,
                .mtime = mtime.sec,
                .mtime_nsec = mtime.nsec,
                // Reported as the content actually present, not as the header
                // claims — matching what GNU tar reports for these types.
                .size = if (carries_content) size else 0,
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

    /// Read a pax extended header ('x') and keep the records this reader
    /// honours: `path`, `linkpath`, `size`, `uid`, `gid`, `mtime`. Every record is checked for shape
    /// — `<len> <key>=<value>\n`, `len` counting the whole record — and a
    /// malformed one refuses the archive rather than being skipped: a record
    /// a reader cannot delimit is one it cannot know it has not misread.
    /// An empty value deletes the keyword (POSIX), i.e. falls back to the
    /// header field. A numeric record that is not a number (`uid=x`,
    /// `mtime=1.2.3`, an id over `u32`, a time over `i64`) is `BadHeader` too:
    /// silently keeping the header's value would report a different owner or
    /// time than the archive states. A repeated keyword: the last one wins.
    fn readPax(self: *Reader, size: u64) ReadError!void {
        if (size > max_pax_len) return error.BadHeader;
        const buf = try self.gpa.alloc(u8, @intCast(size));
        defer self.gpa.free(buf);
        self.src.readSliceAll(buf) catch |e| switch (e) {
            error.EndOfStream => return error.TruncatedArchive,
            error.ReadFailed => return error.ReadFailed,
        };
        try self.discard(padding(size));

        var rest: []const u8 = buf;
        while (rest.len > 0) {
            const sp = std.mem.indexOfScalar(u8, rest, ' ') orelse return error.BadHeader;
            if (sp == 0) return error.BadHeader;
            for (rest[0..sp]) |c| if (!std.ascii.isDigit(c)) return error.BadHeader;
            const len = std.fmt.parseInt(usize, rest[0..sp], 10) catch return error.BadHeader;
            if (len <= sp + 1 or len > rest.len or rest[len - 1] != '\n') return error.BadHeader;
            const kv = rest[sp + 1 .. len - 1];
            rest = rest[len..];
            const eq = std.mem.indexOfScalar(u8, kv, '=') orelse return error.BadHeader;
            const key = kv[0..eq];
            const value = kv[eq + 1 ..];
            if (std.mem.eql(u8, key, "path")) {
                try self.setPaxString(&self.pax_path, value);
            } else if (std.mem.eql(u8, key, "linkpath")) {
                try self.setPaxString(&self.pax_link, value);
            } else if (std.mem.eql(u8, key, "size")) {
                if (value.len == 0) {
                    self.pax_size = null;
                    continue;
                }
                for (value) |c| if (!std.ascii.isDigit(c)) return error.BadHeader;
                self.pax_size = std.fmt.parseInt(u64, value, 10) catch return error.BadHeader;
            } else if (std.mem.eql(u8, key, "uid")) {
                self.pax_uid = try parsePaxId(value);
            } else if (std.mem.eql(u8, key, "gid")) {
                self.pax_gid = try parsePaxId(value);
            } else if (std.mem.eql(u8, key, "mtime")) {
                self.pax_mtime = try parsePaxTime(value);
            }
        }
    }

    fn setPaxString(self: *Reader, slot: *?[]u8, value: []const u8) ReadError!void {
        // An embedded NUL would silently cut the name where `Entry.path` is
        // materialized (`sliceTo(0)`), so the entry would be reported under a
        // different name than the archive states.
        if (std.mem.indexOfScalar(u8, value, 0) != null) return error.BadHeader;
        if (value.len > max_name_len) return error.BadHeader;
        if (slot.*) |old| self.gpa.free(old);
        slot.* = null;
        if (value.len == 0) return;
        slot.* = try self.gpa.dupe(u8, value);
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

/// A pax time: the instant is `sec` + `nsec`/1e9 with `nsec` in 0..999_999_999
/// (floor semantics, so a negative fractional time has `sec` one lower).
const PaxTime = struct { sec: i64, nsec: u32 };

/// A pax `uid`/`gid` value: decimal digits fitting `u32` (`Entry`'s id type).
/// Empty is `null` (the keyword is deleted).
fn parsePaxId(value: []const u8) error{BadHeader}!?u32 {
    if (value.len == 0) return null;
    for (value) |c| if (!std.ascii.isDigit(c)) return error.BadHeader;
    return std.fmt.parseInt(u32, value, 10) catch return error.BadHeader;
}

/// A pax `mtime` value: `[-]digits[.digits]`. Digits after the ninth of the
/// fraction are dropped (nanosecond resolution). Empty is `null`.
fn parsePaxTime(value: []const u8) error{BadHeader}!?PaxTime {
    if (value.len == 0) return null;
    const neg = value[0] == '-';
    const rest = if (neg) value[1..] else value;
    const dot = std.mem.indexOfScalar(u8, rest, '.');
    const int_part = if (dot) |d| rest[0..d] else rest;
    const frac_part = if (dot) |d| rest[d + 1 ..] else "";
    // "1." (an empty fraction) is 1 s: GNU tar 1.35 and Go both read it so.
    if (int_part.len == 0) return error.BadHeader;
    for (int_part) |c| if (!std.ascii.isDigit(c)) return error.BadHeader;
    for (frac_part) |c| if (!std.ascii.isDigit(c)) return error.BadHeader;
    const mag = std.fmt.parseInt(u64, int_part, 10) catch return error.BadHeader;
    if (mag > std.math.maxInt(i64)) return error.BadHeader;
    var nsec: u32 = 0;
    for (0..9) |i| nsec = nsec * 10 + (if (i < frac_part.len) @as(u32, frac_part[i] - '0') else 0);
    const m: i64 = @intCast(mag);
    if (!neg) return .{ .sec = m, .nsec = nsec };
    if (nsec == 0) return .{ .sec = -m, .nsec = 0 };
    return .{ .sec = -m - 1, .nsec = 1_000_000_000 - nsec };
}

fn parseHeader(block: *const [block_size]u8) error{BadHeader}!Hdr {
    // The ustar `prefix` field only exists under the POSIX magic
    // ("ustar\0"); GNU magic ("ustar  \0") reuses those bytes for
    // atime/ctime, so honoring prefix there would corrupt paths.
    const posix_magic = std.mem.eql(u8, block[257..263], "ustar\x00");
    return .{
        .name = nullStr(block[0..100]),
        .prefix = if (posix_magic) nullStr(block[345..500]) else "",
        .linkname = nullStr(block[157..257]),
        .mode = try numField(u32, block[100..108]),
        .uid = try numField(u32, block[108..116]),
        .gid = try numField(u32, block[116..124]),
        .mtime = try numField(i64, block[136..148]),
        .size = try sizeField(block[124..136]),
        .typeflag = block[156],
    };
}

/// A numeric header field as `T`: octal text, or the GNU/star base-256 form
/// (`numeric`). A value outside `T` -- a negative or over-`u32` id, a mode
/// that is not a mode -- is `error.BadHeader`: `Entry` cannot carry it, and
/// keeping its low bits would report a different owner than the archive
/// states (GNU tar 1.35 refuses the same values, "out of uid_t range").
fn numField(comptime T: type, field: []const u8) error{BadHeader}!T {
    return std.math.cast(T, try numeric(field)) orelse error.BadHeader;
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

/// Parse a numeric header field (mode/uid/gid/size/mtime) in either form a
/// writer uses:
///  - octal text, padded with spaces or NULs on either side (busybox and old
///    tars pad oddly); all-padding is 0. Anything else in the digits -- a
///    letter, an `8`, a sign, an inner space -- is `error.BadHeader`. Lenient
///    parsing used to read such a field as 0, which for a uid is root.
///  - GNU/star base-256: a leading 0x80 (positive; the remaining bytes are a
///    big-endian magnitude) or 0xff (negative, two's complement over the whole
///    field). GNU tar writes it for an id over 2 097 151 and for a negative or
///    far-future mtime; reading it as octal garbage reported uid 3000000 as 0.
///    Any other leading byte with the high bit set is `error.BadHeader`.
/// The result spans every 8- and 12-byte field (12 bytes are 96 bits).
fn numeric(field: []const u8) error{BadHeader}!i128 {
    std.debug.assert(field.len <= 12);
    if (field.len > 0 and field[0] & 0x80 != 0) {
        const neg = switch (field[0]) {
            0x80 => false,
            0xff => true,
            else => return error.BadHeader,
        };
        var v: i128 = if (neg) -1 else 0;
        for (field[1..]) |b| v = (v << 8) | b;
        return v;
    }
    const lead = std.mem.trimStart(u8, field, " \x00");
    const digits = std.mem.trimEnd(u8, std.mem.sliceTo(lead, 0), " ");
    // Only padding may follow a NUL: "0001750\x00" yes, "12\x0034" no.
    for (lead[std.mem.sliceTo(lead, 0).len..]) |c| if (c != 0 and c != ' ') return error.BadHeader;
    var v: i128 = 0;
    for (digits) |c| {
        if (c < '0' or c > '7') return error.BadHeader;
        v = v * 8 + (c - '0');
    }
    return v;
}

/// The size field (`numeric`): negative is `error.BadHeader`, and so is a
/// base-256 magnitude of 2^64 or more (the 11 bytes after the marker carry 88
/// bits) rather than its low 64 bits.
fn sizeField(field: []const u8) error{BadHeader}!u64 {
    return std.math.cast(u64, try numeric(field)) orelse error.BadHeader;
}

pub fn padding(size: u64) u64 {
    // Overflow-free by construction: `size % block_size` is always
    // `< block_size`, so the subtraction never underflows and the outer
    // `% block_size` folds the `size % block_size == 0` case to 0 without
    // ever computing `size + block_size` (which could wrap for `size` near
    // `maxInt(u64)`, unlike `std.mem.alignForward`).
    return (block_size - (size % block_size)) % block_size;
}

// ── Writer ──────────────────────────────────────────────────────────────────

pub const WriteError = error{
    /// `writeHeader`/`writeEntry` got a `.other` entry — the writer only
    /// emits files, dirs, symlinks and hard links.
    UnsupportedKind,
    /// A numeric header field does not fit its ustar octal field: `mode`,
    /// `uid` or `gid` above `0o7777777` (7 digits, 21 bits), or `mtime`
    /// outside `0..0o77777777777` (11 digits, 33 bits) — the latter two only
    /// in GNU mode; `WriteOptions.long_names = .pax` carries them in a pax
    /// record instead. Also `mtime_nsec` above 999_999_999, in either mode,
    /// and a `path` or link target containing a NUL byte: no tar form can
    /// carry one (a ustar field and a GNU 'L' record end at the first NUL, so
    /// the name would come back truncated; this module's pax reader refuses it).
    ///
    /// Refused rather than truncated. The octal fields discard high bits
    /// silently, and for an id that is not a cosmetic loss: uid `0o10000000`
    /// (2 097 152) truncates to `0`, so a file owned by an unprivileged
    /// high-range account — a userns/`subuid` mapping, an idmap range, the
    /// `overflowuid` — would be stored as owned by **root** and extracted
    /// that way under `--same-owner`. GNU tar 1.35 refuses the identical
    /// value ("value 2097152 out of uid_t range 0..2097151", exit 2) instead
    /// of writing it, and this writer matches it.
    ///
    /// `size` is deliberately not in this set: it has the GNU/star base-256
    /// escape (`writeSizeField`) and needs no ceiling.
    FieldOutOfRange,
} || std.Io.Writer.Error;

/// Largest value an 8-byte ustar octal field can carry (7 digits + NUL).
const max_octal_8 = 0o7777777;
/// Largest value a 12-byte ustar octal field can carry (11 digits + NUL).
const max_octal_12 = 0o77777777777;

/// How the writer carries what a ustar header cannot hold.
pub const LongNames = enum {
    /// GNU 'L'/'K' records for a path/link target over 100 bytes; a uid/gid,
    /// negative or huge mtime is `error.FieldOutOfRange`, a size over 8 GiB
    /// uses base-256, a fractional mtime loses its fraction. The default, and
    /// what every release before pax writing emitted (output byte-identical).
    gnu,
    /// A pax extended header ('x') with the records `path`, `linkpath`, `size`,
    /// `uid`, `gid`, `mtime` for exactly the fields that do not fit — read by
    /// bsdtar, Go, Python and GNU tar alike. A path over 100 bytes first tries
    /// the ustar `prefix`/`name` split (no record then); the ustar field of a
    /// value carried by a record holds 0 (a truncated name for paths; base-256
    /// for a size), as GNU tar and Python write it.
    pax,
};

pub const WriteOptions = struct {
    long_names: LongNames = .gnu,
};

/// Name of the ustar block that carries a pax 'x' record set (as bsdtar and
/// Python's tarfile name it).
const pax_header_name = "././@PaxHeader";
const max_nsec = 999_999_999;

/// ustar/GNU tar emitter. `writeEntry` for in-memory content; or
/// `writeHeader` + stream `size` bytes to `dst` + `writePadding(size)` for
/// large files. `finish()` terminates the archive (two zero blocks).
pub const Writer = struct {
    dst: *std.Io.Writer,
    options: WriteOptions = .{},

    pub fn init(dst: *std.Io.Writer) Writer {
        return .{ .dst = dst };
    }

    pub fn initOptions(dst: *std.Io.Writer, options: WriteOptions) Writer {
        return .{ .dst = dst, .options = options };
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
    /// strings, or by a pax 'x' header in `.pax` mode — see `LongNames`). For a regular file the caller streams `e.size` content
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
        // Every octal field is checked before a single byte is emitted, so a
        // refused entry never leaves a half-written header (or a 'L'/'K'
        // record with no header behind it) in the stream.
        if (e.mode > max_octal_8) return error.FieldOutOfRange;
        if (e.mtime_nsec > max_nsec) return error.FieldOutOfRange;
        if (std.mem.indexOfScalar(u8, e.path, 0) != null) return error.FieldOutOfRange;
        if ((e.kind == .symlink or e.kind == .hardlink) and std.mem.indexOfScalar(u8, e.link_target, 0) != null)
            return error.FieldOutOfRange;
        if (self.options.long_names == .pax) return writePaxHeader(w, &block, e, typeflag);
        if (e.uid > max_octal_8) return error.FieldOutOfRange;
        if (e.gid > max_octal_8) return error.FieldOutOfRange;
        if (e.mtime < 0 or e.mtime > max_octal_12) return error.FieldOutOfRange;
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

const PaxRec = struct { key: []const u8, value: []const u8 };

/// Length of one pax record `"<len> <key>=<value>\n"`, where `<len>` counts
/// the whole record including its own digits: the fixed point of
/// `len = digits(len) + 1 + body`, found by growing the digit count.
fn paxRecordLen(key: []const u8, value: []const u8) usize {
    const body = key.len + 1 + value.len + 1; // key=value\n
    var digits: usize = 1;
    while (std.fmt.count("{d}", .{body + 1 + digits}) != digits) digits += 1;
    return body + 1 + digits;
}

/// Index of the '/' at which `path` splits into a ustar `prefix` (at most 155
/// bytes) and a `name` (1..100 bytes), or null when it does not.
fn splitPrefix(path: []const u8) ?usize {
    if (path.len < 3) return null;
    var i = @min(155, path.len - 2);
    while (i > 0) : (i -= 1) {
        if (path[i] == '/' and path.len - i - 1 <= 100) return i;
    }
    return null;
}

/// `[-]sec[.frac]` for the instant `sec` + `nsec`/1e9: the fraction has its
/// trailing zeros trimmed and is omitted when zero; a negative instant with a
/// fraction prints as the negated magnitude (`-2` s + 0.75 s -> `-1.25`).
fn formatPaxTime(buf: *[32]u8, sec: i64, nsec: u32) []const u8 {
    const neg = sec < 0;
    var whole: u64 = @abs(sec);
    var frac: u32 = nsec;
    if (neg and nsec != 0) {
        whole -= 1;
        frac = 1_000_000_000 - nsec;
    }
    var w: std.Io.Writer = .fixed(buf);
    w.print("{s}{d}", .{ if (neg) "-" else "", whole }) catch unreachable;
    if (frac != 0) {
        var digits: [9]u8 = undefined;
        _ = std.fmt.bufPrint(&digits, "{d:0>9}", .{frac}) catch unreachable;
        w.print(".{s}", .{std.mem.trimEnd(u8, &digits, "0")}) catch unreachable;
    }
    return w.buffered();
}

/// `.pax` mode of `Writer.writeHeader`: a pax 'x' header for the fields the
/// ustar block cannot hold (records in key order, as Go writes them), then the
/// ustar block itself. Nothing is emitted unless every field was validated
/// (the caller checked `mode` and `mtime_nsec`; the rest cannot fail).
fn writePaxHeader(w: *std.Io.Writer, block: *[block_size]u8, e: Entry, typeflag: u8) WriteError!void {
    const link: []const u8 = if (e.kind == .symlink or e.kind == .hardlink) e.link_target else "";
    const size: u64 = if (e.kind == .file) e.size else 0;

    var name = e.path;
    var prefix: []const u8 = "";
    var pax_path = false;
    if (e.path.len > 100) {
        if (splitPrefix(e.path)) |i| {
            prefix = e.path[0..i];
            name = e.path[i + 1 ..];
        } else pax_path = true;
    }
    const time_fits = e.mtime >= 0 and e.mtime <= max_octal_12;

    var gid_buf: [16]u8 = undefined;
    var uid_buf: [16]u8 = undefined;
    var size_buf: [24]u8 = undefined;
    var time_buf: [32]u8 = undefined;
    var recs: [6]PaxRec = undefined;
    var n: usize = 0;
    if (e.gid > max_octal_8) {
        recs[n] = .{ .key = "gid", .value = std.fmt.bufPrint(&gid_buf, "{d}", .{e.gid}) catch unreachable };
        n += 1;
    }
    if (link.len > 100) {
        recs[n] = .{ .key = "linkpath", .value = link };
        n += 1;
    }
    if (!time_fits or e.mtime_nsec != 0) {
        recs[n] = .{ .key = "mtime", .value = formatPaxTime(&time_buf, e.mtime, e.mtime_nsec) };
        n += 1;
    }
    if (pax_path) {
        recs[n] = .{ .key = "path", .value = e.path };
        n += 1;
    }
    if (size > max_octal_12) {
        recs[n] = .{ .key = "size", .value = std.fmt.bufPrint(&size_buf, "{d}", .{size}) catch unreachable };
        n += 1;
    }
    if (e.uid > max_octal_8) {
        recs[n] = .{ .key = "uid", .value = std.fmt.bufPrint(&uid_buf, "{d}", .{e.uid}) catch unreachable };
        n += 1;
    }

    if (n > 0) {
        var total: usize = 0;
        for (recs[0..n]) |r| total += paxRecordLen(r.key, r.value);
        emitHeader(block, pax_header_name, "", 0o644, 0, 0, total, 0, 'x');
        try w.writeAll(block);
        for (recs[0..n]) |r|
            try w.print("{d} {s}={s}\n", .{ paxRecordLen(r.key, r.value), r.key, r.value });
        try writeZeros(w, padding(total));
    }

    emitHeader(
        block,
        name,
        link,
        e.mode,
        if (e.uid > max_octal_8) 0 else e.uid,
        if (e.gid > max_octal_8) 0 else e.gid,
        size,
        if (time_fits) e.mtime else 0,
        typeflag,
    );
    if (prefix.len > 0) {
        copyTrunc(block[345..500], prefix);
        fixChecksum(block);
    }
    try w.writeAll(block);
}

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
    fixChecksum(block);
}

/// (Re)compute the checksum field: unsigned byte sum with the field as spaces.
fn fixChecksum(block: *[block_size]u8) void {
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

// `FieldOutOfRange` is propagated here rather than skipped: unlike `packDir`,
// which walks a filesystem best-effort, `packTarGz` is handed an explicit list
// of entries, so dropping one silently would lose data the caller asked for.
pub const PackError = error{ UnsupportedKind, FieldOutOfRange } || Allocator.Error || std.Io.Writer.Error;

/// Pack `entries` as a gzip-compressed tar stream onto `dst`, streaming
/// through `std.compress.flate` (one window-sized allocation, no whole-
/// archive buffering). `dst` needs a buffer capacity > 8 bytes (flate writes
/// the gzip header through it). The caller flushes `dst`.
pub fn packTarGz(gpa: Allocator, dst: *std.Io.Writer, entries: []const ContentEntry) PackError!void {
    const window = try gpa.alloc(u8, flate.max_window_len);
    defer gpa.free(window);
    var stage: GzStage = undefined;
    const out = stage.output(dst);
    var comp = try flate.Compress.init(out, window, .gzip, .default);
    const tw = Writer.init(&comp.writer);
    for (entries) |ce| try tw.writeEntry(ce.entry, ce.content);
    try tw.finish();
    try comp.finish();
    try stage.finish(out);
}

/// `flate.Compress` asserts that its output writer buffers more than 8
/// bytes. A `std.Io.Writer.Allocating` from `.init` starts with no buffer at
/// all, and so does an unbuffered file writer: packing into either tripped
/// that assertion (a panic in safe builds, undefined behaviour in
/// ReleaseFast), found when the Go oracle's interop program packed into one.
/// Such a `dst` gets this pass-through instead: the compressed bytes are
/// staged in its own buffer and forwarded to `dst` on every drain. A `dst`
/// that buffers enough is used directly, exactly as before.
const GzStage = struct {
    dst: *std.Io.Writer,
    buf: [4096]u8,
    writer: std.Io.Writer,

    fn output(self: *GzStage, dst: *std.Io.Writer) *std.Io.Writer {
        if (dst.buffer.len > 8) return dst;
        self.* = .{ .dst = dst, .buf = undefined, .writer = .{ .buffer = &.{}, .vtable = &.{ .drain = drain } } };
        self.writer.buffer = &self.buf;
        return &self.writer;
    }

    /// Hand what is still staged to `dst` (whose own flush stays the caller's).
    fn finish(self: *GzStage, out: *std.Io.Writer) std.Io.Writer.Error!void {
        if (out == &self.writer) try self.writer.flush();
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *GzStage = @alignCast(@fieldParentPtr("writer", w));
        try self.dst.writeAll(w.buffered());
        w.end = 0;
        return self.dst.writeSplat(data, splat);
    }
};

// ── filesystem packer (Linux — statx numeric attrs) ────────────────────────

pub const PackStats = struct {
    files: usize = 0,
    dirs: usize = 0,
    symlinks: usize = 0,
    /// Sum of file content sizes (uncompressed).
    bytes: u64 = 0,
    /// Entries left out of the archive because a numeric attribute would not
    /// fit its ustar field (`WriteError.FieldOutOfRange`) — in practice a
    /// uid/gid at or above 2 097 152. `packDir` is documented best-effort, so
    /// one such file must not fail the archive; but skipping it silently
    /// would make a short archive indistinguishable from a complete one, so
    /// it is counted here. A nonzero value means the archive is incomplete.
    skipped: usize = 0,
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
    var stage: GzStage = undefined;
    const out = stage.output(dst);
    var comp = try flate.Compress.init(out, window, .gzip, .default);
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
    try stage.finish(out);
    return stats;
}

pub const PackDirToPathError = PackDirError || std.Io.File.OpenError;

/// Convenience over `packDir`: create (or truncate) `out_path` and write the
/// gzip tar straight into it — the create-file/wrap-writer/call/flush dance
/// every `packDir` caller otherwise repeats verbatim. Same walk, same
/// `PackStats`, same Linux-only ceiling (see `packDir`'s doc comment); this
/// only adds the destination-file plumbing.
pub fn packDirToPath(io: std.Io, gpa: Allocator, roots: []const []const u8, out_path: []const u8) PackDirToPathError!PackStats {
    if (comptime builtin.os.tag != .linux)
        @compileError("tar.packDirToPath is Linux-only (statx numeric attrs)");

    const file = try std.Io.Dir.cwd().createFile(io, out_path, .{});
    defer file.close(io);
    var wbuf: [64 * 1024]u8 = undefined;
    var fw = file.writer(io, &wbuf);
    const stats = try packDir(io, gpa, roots, &fw.interface);
    try fw.interface.flush();
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
            return skipOrFail(e, stats);
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
            return skipOrFail(e, stats);
        stats.symlinks += 1;
    } else if (ifmt == linux.S.IFREG) {
        tw.writeHeader(.{ .path = tar_name, .kind = .file, .size = stx.size, .mode = perm, .uid = stx.uid, .gid = stx.gid, .mtime = mtime }) catch |e|
            return skipOrFail(e, stats);
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

/// Narrow `writeHeader`'s error set for the best-effort packer.
///
/// `UnsupportedKind` is unreachable — `emitPath` never constructs a `.other`
/// entry. `FieldOutOfRange` is reachable (a uid/gid at or above 2 097 152 on
/// the filesystem being walked) and is deliberately NOT propagated: `packDir`
/// documents that "one bad file never fails the archive". It is counted in
/// `PackStats.skipped` instead, so a caller can still tell a complete archive
/// from a short one — the failure mode a silent skip would create.
fn skipOrFail(e: WriteError, stats: *PackStats) std.Io.Writer.Error!void {
    switch (e) {
        error.UnsupportedKind => unreachable,
        error.FieldOutOfRange => stats.skipped += 1,
        else => |w| return w,
    }
}

// ── tests: field primitives ──────────────────────────────────────────────────

const testing = std.testing;

test "octal field emit + padding" {
    var b: [8]u8 = undefined;
    writeOctalField(&b, 0o644);
    try testing.expectEqualStrings("0000644\x00", &b);
    try testing.expectEqual(@as(u64, 412), padding(100));
    try testing.expectEqual(@as(u64, 0), padding(512));
}

test "octal + size parsing" {
    try testing.expectEqual(@as(i128, 0o644), try numeric("0000644\x00"));
    try testing.expectEqual(@as(i128, 0o755), try numeric("0000755 "));
    try testing.expectEqual(@as(i128, 0o1750), try numeric("  1750 \x00"));
    try testing.expectEqual(@as(i128, 0), try numeric("\x00\x00\x00"));
    try testing.expectEqual(@as(i128, 0), try numeric("        "));
    var big: [12]u8 = .{ 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0 };
    try testing.expectEqual(@as(u64, 0x1000), try sizeField(&big));
}

test "numeric fields: garbage is BadHeader, never 0 (a uid of 0 is root)" {
    // Each was read as 0 before; GNU tar 1.35 refuses every one ("Archive
    // contains ... where numeric uid_t value expected"), Go as ErrHeader.
    for ([_][]const u8{ "garbage!", "12x4567\x00", "0001758\x00", "12 3456\x00", "+5\x00", "-5\x00", "12\x0034", "0644 x" }) |f| {
        testing.expectError(error.BadHeader, numeric(f)) catch |err| {
            std.debug.print("numeric field not refused: {s}\n", .{f});
            return err;
        };
    }
}

test "numeric fields: GNU/star base-256 in every field, range-checked per field" {
    // uid 3000000 as GNU tar --format=gnu writes it (over 0o7777777).
    const uid: [8]u8 = .{ 0x80, 0, 0, 0, 0, 0x2d, 0xc6, 0xc0 };
    try testing.expectEqual(@as(u32, 3_000_000), try numField(u32, &uid));
    // mtime -1 and 1960-01-01: 0xff marker, two's complement.
    const m1: [12]u8 = @splat(0xff);
    try testing.expectEqual(@as(i64, -1), try numField(i64, &m1));
    var m1960: [12]u8 = @splat(0xff);
    std.mem.writeInt(i64, m1960[4..12], -315_619_200, .big);
    try testing.expectEqual(@as(i64, -315_619_200), try numField(i64, &m1960));
    // Values an Entry cannot hold are refused, not truncated.
    const neg_id: [8]u8 = @splat(0xff);
    try testing.expectError(error.BadHeader, numField(u32, &neg_id));
    const id_2p32: [8]u8 = .{ 0x80, 0, 0, 1, 0, 0, 0, 0 };
    try testing.expectError(error.BadHeader, numField(u32, &id_2p32));
    try testing.expectError(error.BadHeader, sizeField(&m1));
    // A high-bit lead other than 0x80/0xff is neither form.
    const odd: [8]u8 = .{ 0x81, 0, 0, 0, 0, 0, 0, 1 };
    try testing.expectError(error.BadHeader, numeric(&odd));
}

test "padding to 512" {
    try testing.expectEqual(@as(u64, 0), padding(0));
    try testing.expectEqual(@as(u64, 511), padding(1));
    try testing.expectEqual(@as(u64, 0), padding(512));
    try testing.expectEqual(@as(u64, 412), padding(100));
    try testing.expectEqual(@as(u64, 1), padding(1023));
}

test "padding never overflows near maxInt(u64)" {
    // Regression for the reproduced CRIT: std.mem.alignForward's internal
    // `size + (block_size - 1)` would wrap here; our formula must not.
    // maxInt(u64) == 2^64 - 1, and 2^64 % 512 == 0, so maxInt(u64) % 512 ==
    // 511, hence padding(maxInt(u64)) == 1.
    try testing.expectEqual(@as(u64, 1), padding(std.math.maxInt(u64)));
    try testing.expectEqual(@as(u64, 2), padding(std.math.maxInt(u64) - 1));
    try testing.expectEqual(@as(u64, 0), padding(std.math.maxInt(u64) - 511));
}

test "size field base-256 round-trip (>8 GiB)" {
    const huge: u64 = 20 * 1024 * 1024 * 1024 + 7; // 20 GiB + 7
    var field: [12]u8 = undefined;
    writeSizeField(&field, huge);
    try testing.expectEqual(@as(u8, 0x80), field[0]);
    try testing.expectEqual(huge, try sizeField(&field));
    // and the octal path is untouched below the cutoff
    writeSizeField(&field, 12);
    try testing.expectEqualStrings("00000000014\x00", &field);
    try testing.expectEqual(@as(u64, 12), try sizeField(&field));
}

test "base-256 size with magnitude >= 2^64 -> error.BadHeader, not truncated" {
    // Audit finding tar W4: sizeField only read the low 8 of the 11
    // base-256 magnitude bytes (field[4..12]); the top 3 (field[1..4]) were
    // ignored. A crafted header encoding 2^64 + 5 used to read back as
    // size = 5 with a valid checksum instead of being rejected.
    var field: [12]u8 = .{ 0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 5 };
    try testing.expectError(error.BadHeader, sizeField(&field));

    // Full-header reproduction: same magnitude, through the actual reader.
    var buf: [2 * block_size]u8 = undefined;
    var dst: std.Io.Writer = .fixed(&buf);
    var block: [block_size]u8 = undefined;
    emitHeader(&block, "evil.bin", "", 0o644, 0, 0, 5, 0, '0');
    @memcpy(block[124..136], &field);
    // Recompute the checksum emitHeader wrote for the octal-encoded size 5.
    @memset(block[148..156], ' ');
    var sum: u64 = 0;
    for (block) |b| sum += b;
    writeOctalField(block[148..155], sum);
    block[155] = ' ';

    try dst.writeAll(&block);
    var src: std.Io.Reader = .fixed(dst.buffered());
    var tr = Reader.init(testing.allocator, &src);
    defer tr.deinit();
    try testing.expectError(error.BadHeader, tr.next());
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

test "Entry.dupe: an OwnedEntry's path/link_target survive a subsequent next() call" {
    const gpa = testing.allocator;
    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    const tw = Writer.init(&aw.writer);
    try tw.writeEntry(.{ .path = "first-entry.txt", .kind = .symlink, .link_target = "first-target" }, "");
    try tw.writeEntry(.{ .path = "second-entry.txt" }, "");
    try tw.finish();

    var src: std.Io.Reader = .fixed(aw.writer.buffered());
    var tr = Reader.init(gpa, &src);
    defer tr.deinit();

    const first = (try tr.next()).?;
    try testing.expectEqualStrings("first-entry.txt", first.path);
    var owned = try first.dupe(gpa);
    defer owned.deinit(gpa);

    // Advance the reader — this is exactly what invalidates `first.path` /
    // `first.link_target` (they are the Reader's own borrowed buffers, and
    // the doc comment on `Entry` says so). If `dupe` didn't actually copy
    // the bytes, `owned.path`/`owned.link_target` would now read back as
    // "second-entry.txt"/"" (or garbage) instead of the first entry's data —
    // this assertion is only meaningful because it runs AFTER the call that
    // would corrupt an un-duped borrow.
    const second = (try tr.next()).?;
    try testing.expectEqualStrings("second-entry.txt", second.path);

    try testing.expectEqualStrings("first-entry.txt", owned.path);
    try testing.expectEqualStrings("first-target", owned.link_target);
    try testing.expectEqual(Kind.symlink, owned.kind);
}

test "packTarGz into a writer with no buffer of its own (Allocating.init, an unbuffered sink)" {
    // Both tripped flate.Compress's `output.buffer.len > 8` assertion before
    // the GzStage pass-through.
    const gpa = testing.allocator;
    const entries = [_]ContentEntry{
        .{ .entry = .{ .path = "a.txt", .mode = 0o644, .mtime = 1_600_000_000 }, .content = "hello\n" ** 300 },
        .{ .entry = .{ .path = "d", .kind = .dir, .mode = 0o755 } },
    };
    var buffered: std.Io.Writer.Allocating = try .initCapacity(gpa, 4096);
    defer buffered.deinit();
    try packTarGz(gpa, &buffered.writer, &entries);

    var empty: std.Io.Writer.Allocating = .init(gpa);
    defer empty.deinit();
    try packTarGz(gpa, &empty.writer, &entries);
    try testing.expectEqualSlices(u8, buffered.written(), empty.written());

    // A writer with an 8-byte buffer: still under the assertion's floor.
    var sink: std.Io.Writer.Allocating = .init(gpa);
    defer sink.deinit();
    var tiny_buf: [8]u8 = undefined;
    const Sha256 = std.crypto.hash.sha2.Sha256;
    var tiny = std.Io.Writer.Hashed(Sha256).initHasher(&sink.writer, .init(.{}), &tiny_buf);
    try packTarGz(gpa, &tiny.writer, &entries);
    try tiny.writer.flush();
    try testing.expectEqualSlices(u8, buffered.written(), sink.written());
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

/// One pax record, `<len> <key>=<value>\n`, where `len` counts the whole
/// record including its own digits.
fn paxRecord(buf: []u8, key: []const u8, value: []const u8) []const u8 {
    const body = key.len + 1 + value.len + 1; // key=value\n
    var len: usize = body + 2; // one digit + the space
    while (std.fmt.count("{d}", .{len}) + 1 + body != len) len += 1;
    return std.fmt.bufPrint(buf, "{d} {s}={s}\n", .{ len, key, value }) catch unreachable;
}

/// An archive of one pax 'x' header carrying `payload`, then `entry_block`
/// and `content`, then the trailer.
fn paxArchive(dst: *std.Io.Writer, payload: []const u8, entry_block: *const [block_size]u8, content: []const u8) !void {
    var pax_block: [block_size]u8 = undefined;
    emitHeader(&pax_block, "PaxHeaders/entry", "", 0, 0, 0, payload.len, 0, 'x');
    try dst.writeAll(&pax_block);
    try dst.writeAll(payload);
    try writeZeros(dst, padding(payload.len));
    try dst.writeAll(entry_block);
    try dst.writeAll(content);
    try writeZeros(dst, padding(content.len));
    try writeZeros(dst, 2 * block_size); // trailer
}

test "record helper: the length prefix counts itself" {
    var b: [128]u8 = undefined;
    try testing.expectEqualStrings("8 a=bcd\n", paxRecord(&b, "a", "bcd"));
    try testing.expectEqualStrings("12 path=abc\n", paxRecord(&b, "path", "abc"));
    try testing.expectEqualStrings("99 k=" ++ "v" ** 93 ++ "\n", paxRecord(&b, "k", "v" ** 93));
    // One byte more and the prefix needs a third digit, which is one more byte again.
    try testing.expectEqualStrings("101 k=" ++ "v" ** 94 ++ "\n", paxRecord(&b, "k", "v" ** 94));
}

test "pax 'x' path overrides the header name; unused records are parsed past, padding skipped" {
    // What Python's tarfile (PAX_FORMAT, its default since 3.8), Go's
    // archive/tar and bsdtar write for a name over 100 bytes: a pax `path`,
    // and a TRUNCATED name in the ustar field. Before 2026-09-30 this reader
    // discarded the pax header and reported the truncated name.
    const long = "dir/" ** 30 ++ "file.txt"; // 128 bytes
    var rb: [3][256]u8 = undefined;
    const payload = try std.mem.concat(testing.allocator, u8, &.{
        paxRecord(&rb[0], "mtime", "1600000000.123456789"),
        paxRecord(&rb[1], "path", long),
        paxRecord(&rb[2], "SCHILY.xattr.user.k", "v"),
    });
    defer testing.allocator.free(payload);

    var buf: [8 * block_size]u8 = undefined;
    var dst: std.Io.Writer = .fixed(&buf);
    var real_block: [block_size]u8 = undefined;
    emitHeader(&real_block, long[0..99], "", 0o644, 0, 0, 5, 0, '0');
    try paxArchive(&dst, payload, &real_block, "hello");

    var src: std.Io.Reader = .fixed(dst.buffered());
    var tr = Reader.init(testing.allocator, &src);
    defer tr.deinit();
    const e = (try tr.next()).?;
    try testing.expectEqualStrings(long, e.path);
    try testing.expectEqual(@as(u64, 5), e.size);
    var content: [8]u8 = undefined;
    const n = try tr.read(&content);
    try testing.expectEqualStrings("hello", content[0..n]);
    try testing.expectEqual(@as(?Entry, null), try tr.next());
}

test "pax 'x' size overrides the header size (the >8 GiB case), so the stream stays in sync" {
    // A pax-writing tar stores size 0 in the ustar field when the real size
    // does not fit it. Reading the header's 0 would treat the content as the
    // next header. Size 5 stands in for the large case here.
    var rb: [64]u8 = undefined;
    var buf: [8 * block_size]u8 = undefined;
    var dst: std.Io.Writer = .fixed(&buf);
    var real_block: [block_size]u8 = undefined;
    emitHeader(&real_block, "big.bin", "", 0o644, 0, 0, 0, 0, '0');
    try paxArchive(&dst, paxRecord(&rb, "size", "5"), &real_block, "hello");

    var src: std.Io.Reader = .fixed(dst.buffered());
    var tr = Reader.init(testing.allocator, &src);
    defer tr.deinit();
    const e = (try tr.next()).?;
    try testing.expectEqual(@as(u64, 5), e.size);
    var content: [8]u8 = undefined;
    const n = try tr.read(&content);
    try testing.expectEqualStrings("hello", content[0..n]);
    try testing.expectEqual(@as(?Entry, null), try tr.next());
}

test "pax 'x' linkpath overrides the header link target" {
    const target = "../" ** 40 ++ "target"; // 126 bytes
    var rb: [256]u8 = undefined;
    var buf: [8 * block_size]u8 = undefined;
    var dst: std.Io.Writer = .fixed(&buf);
    var link_block: [block_size]u8 = undefined;
    emitHeader(&link_block, "link", target[0..99], 0o777, 0, 0, 0, 0, '2');
    try paxArchive(&dst, paxRecord(&rb, "linkpath", target), &link_block, "");

    var src: std.Io.Reader = .fixed(dst.buffered());
    var tr = Reader.init(testing.allocator, &src);
    defer tr.deinit();
    const e = (try tr.next()).?;
    try testing.expectEqual(Kind.symlink, e.kind);
    try testing.expectEqualStrings(target, e.link_target);
}

test "pax path wins over a GNU 'L' record, and neither leaks onto the next entry" {
    var buf: [12 * block_size]u8 = undefined;
    var dst: std.Io.Writer = .fixed(&buf);
    var block: [block_size]u8 = undefined;
    // GNU 'L' first ...
    const gnu_name = "from-gnu-L";
    emitHeader(&block, gnu_longlink_name, "", 0, 0, 0, gnu_name.len + 1, 0, 'L');
    try dst.writeAll(&block);
    try dst.writeAll(gnu_name ++ "\x00");
    try writeZeros(&dst, padding(gnu_name.len + 1));
    // ... then pax 'x', then the entry: pax is the later, richer record.
    var rb: [64]u8 = undefined;
    const rec = paxRecord(&rb, "path", "from-pax");
    emitHeader(&block, "PaxHeaders/x", "", 0, 0, 0, rec.len, 0, 'x');
    try dst.writeAll(&block);
    try dst.writeAll(rec);
    try writeZeros(&dst, padding(rec.len));
    emitHeader(&block, "from-header", "", 0o644, 0, 0, 0, 0, '0');
    try dst.writeAll(&block);
    emitHeader(&block, "second", "", 0o644, 0, 0, 0, 0, '0');
    try dst.writeAll(&block);
    try writeZeros(&dst, 2 * block_size);

    var src: std.Io.Reader = .fixed(dst.buffered());
    var tr = Reader.init(testing.allocator, &src);
    defer tr.deinit();
    try testing.expectEqualStrings("from-pax", (try tr.next()).?.path);
    try testing.expectEqualStrings("second", (try tr.next()).?.path);
    try testing.expectEqual(@as(?Entry, null), try tr.next());
}

test "pax 'x': an empty value deletes the keyword, falling back to the header field" {
    var rb: [64]u8 = undefined;
    var buf: [8 * block_size]u8 = undefined;
    var dst: std.Io.Writer = .fixed(&buf);
    var real_block: [block_size]u8 = undefined;
    emitHeader(&real_block, "header-name", "", 0o644, 0, 0, 0, 0, '0');
    try paxArchive(&dst, paxRecord(&rb, "path", ""), &real_block, "");

    var src: std.Io.Reader = .fixed(dst.buffered());
    var tr = Reader.init(testing.allocator, &src);
    defer tr.deinit();
    try testing.expectEqualStrings("header-name", (try tr.next()).?.path);
}

test "pax 'x': a malformed or hostile header -> error.BadHeader, never a misread" {
    const cases = [_][]const u8{
        "30 path=some.attr=value\n" ++ "\x00" ** 6, // length says 30, the record is 24
        "11 path=abc", // right length, but no newline
        "x2 path=abc\n", // non-digit length
        " path=abcde\n", // no length
        "11 pathabc\n", // no '='
        "13 path=a\x00bc\n", // NUL inside a path
        "11 size=1x\n", // non-digit size
        "29 size=99999999999999999999\n", // size overflows u64
        "999 path=abc\n", // length past the end of the payload
    };
    for (cases) |payload| {
        var buf: [8 * block_size]u8 = undefined;
        var dst: std.Io.Writer = .fixed(&buf);
        var real_block: [block_size]u8 = undefined;
        emitHeader(&real_block, "real.txt", "", 0o644, 0, 0, 0, 0, '0');
        try paxArchive(&dst, payload, &real_block, "");
        var src: std.Io.Reader = .fixed(dst.buffered());
        var tr = Reader.init(testing.allocator, &src);
        defer tr.deinit();
        testing.expectError(error.BadHeader, tr.next()) catch |err| {
            std.debug.print("pax payload not refused: {any}\n", .{payload});
            return err;
        };
    }

    // An 'x' header over max_pax_len is refused before anything is read.
    var buf: [2 * block_size]u8 = undefined;
    var dst: std.Io.Writer = .fixed(&buf);
    var block: [block_size]u8 = undefined;
    emitHeader(&block, "PaxHeaders/huge", "", 0, 0, 0, max_pax_len + 1, 0, 'x');
    try dst.writeAll(&block);
    var src: std.Io.Reader = .fixed(dst.buffered());
    var tr = Reader.init(testing.allocator, &src);
    defer tr.deinit();
    try testing.expectError(error.BadHeader, tr.next());
}

test "pax 'x' uid/gid/mtime override the header fields and do not leak onto the next entry" {
    var rb: [3][64]u8 = undefined;
    const payload = try std.mem.concat(testing.allocator, u8, &.{
        paxRecord(&rb[0], "uid", "3000000"),
        paxRecord(&rb[1], "gid", "4000001"),
        paxRecord(&rb[2], "mtime", "1727700007.123456789"),
    });
    defer testing.allocator.free(payload);

    var buf: [8 * block_size]u8 = undefined;
    var dst: std.Io.Writer = .fixed(&buf);
    var block: [block_size]u8 = undefined;
    emitHeader(&block, "PaxHeaders/x", "", 0, 0, 0, payload.len, 0, 'x');
    try dst.writeAll(&block);
    try dst.writeAll(payload);
    try writeZeros(&dst, padding(payload.len));
    emitHeader(&block, "first", "", 0o644, 1, 2, 0, 3, '0');
    try dst.writeAll(&block);
    emitHeader(&block, "second", "", 0o644, 1, 2, 0, 3, '0');
    try dst.writeAll(&block);
    try writeZeros(&dst, 2 * block_size);

    var src: std.Io.Reader = .fixed(dst.buffered());
    var tr = Reader.init(testing.allocator, &src);
    defer tr.deinit();
    const a = (try tr.next()).?;
    try testing.expectEqual(@as(u32, 3_000_000), a.uid);
    try testing.expectEqual(@as(u32, 4_000_001), a.gid);
    try testing.expectEqual(@as(i64, 1_727_700_007), a.mtime);
    try testing.expectEqual(@as(u32, 123_456_789), a.mtime_nsec);
    const b = (try tr.next()).?;
    try testing.expectEqual(@as(u32, 1), b.uid);
    try testing.expectEqual(@as(u32, 2), b.gid);
    try testing.expectEqual(@as(i64, 3), b.mtime);
    try testing.expectEqual(@as(u32, 0), b.mtime_nsec);
    try testing.expectEqual(@as(?Entry, null), try tr.next());
}

test "pax 'x' uid/gid/mtime: an empty value deletes the keyword, a repeated keyword's last one wins" {
    var rb: [5][64]u8 = undefined;
    const payload = try std.mem.concat(testing.allocator, u8, &.{
        paxRecord(&rb[0], "uid", "9"),
        paxRecord(&rb[1], "uid", ""), // deletes the 9
        paxRecord(&rb[2], "gid", "5"),
        paxRecord(&rb[3], "gid", "6"), // last wins
        paxRecord(&rb[4], "mtime", ""),
    });
    defer testing.allocator.free(payload);
    var buf: [8 * block_size]u8 = undefined;
    var dst: std.Io.Writer = .fixed(&buf);
    var real_block: [block_size]u8 = undefined;
    emitHeader(&real_block, "f", "", 0o644, 11, 12, 0, 13, '0');
    try paxArchive(&dst, payload, &real_block, "");

    var src: std.Io.Reader = .fixed(dst.buffered());
    var tr = Reader.init(testing.allocator, &src);
    defer tr.deinit();
    const e = (try tr.next()).?;
    try testing.expectEqual(@as(u32, 11), e.uid);
    try testing.expectEqual(@as(u32, 6), e.gid);
    try testing.expectEqual(@as(i64, 13), e.mtime);
}

test "pax mtime parsing: sign, fraction, floor semantics, digit cut-off" {
    const Case = struct { in: []const u8, sec: i64, nsec: u32 };
    const ok = [_]Case{
        .{ .in = "0", .sec = 0, .nsec = 0 },
        .{ .in = "-0", .sec = 0, .nsec = 0 },
        .{ .in = "1727700007", .sec = 1_727_700_007, .nsec = 0 },
        .{ .in = "1727700007.5", .sec = 1_727_700_007, .nsec = 500_000_000 },
        .{ .in = "1727700007.123456789", .sec = 1_727_700_007, .nsec = 123_456_789 },
        .{ .in = "1.000000001", .sec = 1, .nsec = 1 },
        .{ .in = "1.1234567899999", .sec = 1, .nsec = 123_456_789 }, // cut, not rounded
        .{ .in = "007.0", .sec = 7, .nsec = 0 },
        .{ .in = "1.", .sec = 1, .nsec = 0 },
        .{ .in = "-1.", .sec = -1, .nsec = 0 },
        .{ .in = "-1", .sec = -1, .nsec = 0 },
        .{ .in = "-1.25", .sec = -2, .nsec = 750_000_000 }, // floor: -2 + 0.75
        .{ .in = "-0.5", .sec = -1, .nsec = 500_000_000 },
        .{ .in = "-315619199.5", .sec = -315_619_200, .nsec = 500_000_000 },
        .{ .in = "9223372036854775807", .sec = std.math.maxInt(i64), .nsec = 0 },
        .{ .in = "-9223372036854775807", .sec = -std.math.maxInt(i64), .nsec = 0 },
        .{ .in = "-9223372036854775807.5", .sec = std.math.minInt(i64), .nsec = 500_000_000 },
    };
    for (ok) |c| {
        const t = (try parsePaxTime(c.in)).?;
        testing.expectEqual(c.sec, t.sec) catch |err| {
            std.debug.print("pax mtime {s}: sec\n", .{c.in});
            return err;
        };
        testing.expectEqual(c.nsec, t.nsec) catch |err| {
            std.debug.print("pax mtime {s}: nsec\n", .{c.in});
            return err;
        };
    }
    try testing.expectEqual(@as(?PaxTime, null), try parsePaxTime(""));
    const bad = [_][]const u8{
        "-",   ".5",  "-.5",  "-.",  "1.2.3", "--1",  "+1",                  " 1",                   "1 ",
        "abc", "1e9", "0x10", "1,5", "1.5x",  "1.-5", "9223372036854775808", "-9223372036854775808", "99999999999999999999999",
    };
    for (bad) |v| {
        testing.expectError(error.BadHeader, parsePaxTime(v)) catch |err| {
            std.debug.print("pax mtime not refused: {s}\n", .{v});
            return err;
        };
    }
}

test "pax 'x' uid/gid/mtime: garbage, overflow or a lying length -> error.BadHeader, never a panic" {
    const pairs = [_][2][]const u8{
        .{ "uid", "x" }, .{ "uid", "-1" }, .{ "uid", "+1" },
        .{ "uid", "1e3" },     .{ "uid", " 5" },              .{ "uid", "4294967296" }, // over u32
        .{ "gid", "0x10" },    .{ "gid", "5.5" },             .{ "gid", "99999999999999999999" },
        .{ "mtime", "abc" },   .{ "mtime", "-." },            .{ "mtime", ".5" },
        .{ "mtime", "1.2.3" }, .{ "mtime", "1727700007.5x" }, .{ "mtime", "9223372036854775808" },
    };
    for (pairs) |kv| {
        var rb: [128]u8 = undefined;
        var buf: [8 * block_size]u8 = undefined;
        var dst: std.Io.Writer = .fixed(&buf);
        var real_block: [block_size]u8 = undefined;
        emitHeader(&real_block, "real.txt", "", 0o644, 0, 0, 0, 0, '0');
        try paxArchive(&dst, paxRecord(&rb, kv[0], kv[1]), &real_block, "");
        var src: std.Io.Reader = .fixed(dst.buffered());
        var tr = Reader.init(testing.allocator, &src);
        defer tr.deinit();
        testing.expectError(error.BadHeader, tr.next()) catch |err| {
            std.debug.print("pax {s}={s} not refused\n", .{ kv[0], kv[1] });
            return err;
        };
    }

    // The length prefix lies: too long, too short, or trailing junk behind a
    // correct record.
    const lies = [_][]const u8{
        "9 uid=5\n", // real length is 8
        "7 uid=5\n",
        "20 uid=5\n",
        "8 uid=5\nzzz",
        "8 uid=5\n\n",
        "0 uid=5\n",
    };
    for (lies) |payload| {
        var buf: [8 * block_size]u8 = undefined;
        var dst: std.Io.Writer = .fixed(&buf);
        var real_block: [block_size]u8 = undefined;
        emitHeader(&real_block, "real.txt", "", 0o644, 0, 0, 0, 0, '0');
        try paxArchive(&dst, payload, &real_block, "");
        var src: std.Io.Reader = .fixed(dst.buffered());
        var tr = Reader.init(testing.allocator, &src);
        defer tr.deinit();
        testing.expectError(error.BadHeader, tr.next()) catch |err| {
            std.debug.print("pax payload not refused: {s}\n", .{payload});
            return err;
        };
    }
}

test "pax 'x': a path over max_name_len inside a payload under max_pax_len -> error.BadHeader" {
    const gpa = testing.allocator;
    const long = try gpa.alloc(u8, max_name_len + 1);
    defer gpa.free(long);
    @memset(long, 'a');
    const rb = try gpa.alloc(u8, max_name_len + 64);
    defer gpa.free(rb);
    const rec = paxRecord(rb, "path", long);
    const buf = try gpa.alloc(u8, rec.len + 8 * block_size);
    defer gpa.free(buf);
    var dst: std.Io.Writer = .fixed(buf);
    var real_block: [block_size]u8 = undefined;
    emitHeader(&real_block, "real.txt", "", 0o644, 0, 0, 0, 0, '0');
    try paxArchive(&dst, rec, &real_block, "");
    var src: std.Io.Reader = .fixed(dst.buffered());
    var tr = Reader.init(gpa, &src);
    defer tr.deinit();
    try testing.expectError(error.BadHeader, tr.next());
}

test "pax global header ('g') is still skipped, including its padding" {
    var rb: [64]u8 = undefined;
    const rec = paxRecord(&rb, "comment", "made by someone");
    var buf: [8 * block_size]u8 = undefined;
    var dst: std.Io.Writer = .fixed(&buf);
    var block: [block_size]u8 = undefined;
    emitHeader(&block, "pax_global_header", "", 0, 0, 0, rec.len, 0, 'g');
    try dst.writeAll(&block);
    try dst.writeAll(rec);
    try writeZeros(&dst, padding(rec.len));
    emitHeader(&block, "real.txt", "", 0o644, 0, 0, 0, 0, '0');
    try dst.writeAll(&block);
    try writeZeros(&dst, 2 * block_size);

    var src: std.Io.Reader = .fixed(dst.buffered());
    var tr = Reader.init(testing.allocator, &src);
    defer tr.deinit();
    try testing.expectEqualStrings("real.txt", (try tr.next()).?.path);
    try testing.expectEqual(@as(?Entry, null), try tr.next());
}

test "unrecognized typeflag surfaces as .other, content still streamable" {
    var buf: [4 * block_size]u8 = undefined;
    var dst: std.Io.Writer = .fixed(&buf);
    var block: [block_size]u8 = undefined;
    // 'V' = GNU volume-label header — not one of the kinds this module
    // models; the reader must not misclassify it as .file/.dir/etc.
    emitHeader(&block, "volume-id", "", 0, 0, 0, 4, 0, 'V');
    try dst.writeAll(&block);
    try dst.writeAll("data");
    try writeZeros(&dst, padding(4));
    try writeZeros(&dst, 2 * block_size); // trailer

    var src: std.Io.Reader = .fixed(dst.buffered());
    var tr = Reader.init(testing.allocator, &src);
    defer tr.deinit();

    const e = (try tr.next()).?;
    try testing.expectEqual(Kind.other, e.kind);
    try testing.expectEqual(@as(u8, 'V'), e.typeflag);
    try testing.expectEqualStrings("volume-id", e.path);
    var content: [8]u8 = undefined;
    const n = try tr.read(&content);
    try testing.expectEqualStrings("data", content[0..n]);
    try testing.expectEqual(@as(?Entry, null), try tr.next());
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

test "base-256 size near maxInt(u64) -> error.BadHeader, no panic" {
    // Reproduces the audit's CRIT: a crafted GNU/star base-256 size field
    // within 511 of maxInt(u64) used to overflow `padding()`'s internal
    // alignment arithmetic and panic on the very first `next()` after the
    // checksum check passed. Must now fail closed instead of crashing.
    var buf: [2 * block_size]u8 = undefined;
    var dst: std.Io.Writer = .fixed(&buf);
    var block: [block_size]u8 = undefined;
    emitHeader(&block, "evil.bin", "", 0o644, 0, 0, std.math.maxInt(u64) - 5, 0, '0');
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

test "reader: a link/dir/dev entry claiming content cannot swallow the header behind it" {
    // The archive an attacker writes: an entry of a type that carries no data
    // but whose size field claims one block, followed by a complete,
    // checksum-valid header, followed by an ordinary entry. If the reader
    // honors the size, it eats the middle header as "content" and never
    // reports it — while `tar -xf` creates that file. Verified against GNU
    // tar 1.35, which lists all three members for every typeflag below.
    //
    // '7' (contiguous) is deliberately absent: it DOES carry content, and GNU
    // tar honors its size field. It is covered by the positive control below.
    for ([_]u8{ '1', '2', '3', '4', '5', '6' }) |typeflag| {
        var buf: [5 * block_size]u8 = undefined;
        var dst: std.Io.Writer = .fixed(&buf);

        var block: [block_size]u8 = undefined;
        emitHeader(&block, "link", "target", 0o644, 0, 0, block_size, 0, typeflag);
        try dst.writeAll(&block);
        emitHeader(&block, "smuggled.sh", "", 0o755, 0, 0, 0, 0, '0');
        try dst.writeAll(&block);
        emitHeader(&block, "safe.txt", "", 0o644, 0, 0, 0, 0, '0');
        try dst.writeAll(&block);
        try dst.splatByteAll(0, 2 * block_size);

        var src: std.Io.Reader = .fixed(dst.buffered());
        var tr = Reader.init(testing.allocator, &src);
        defer tr.deinit();

        const first = (try tr.next()).?;
        try testing.expectEqualStrings("link", first.path);
        // Reported as the content actually present, not as the header claims.
        try testing.expectEqual(@as(u64, 0), first.size);

        const second = (try tr.next()).?;
        try testing.expectEqualStrings("smuggled.sh", second.path);

        const third = (try tr.next()).?;
        try testing.expectEqualStrings("safe.txt", third.path);

        try testing.expectEqual(@as(?Entry, null), try tr.next());
    }
}

test "reader: a contiguous ('7') entry still carries content, so the set above is not too wide" {
    // Positive control for the test above: the same archive shape with the one
    // typeflag that genuinely has data must behave the OTHER way, or the fix
    // would just be "ignore every size field".
    var buf: [5 * block_size]u8 = undefined;
    var dst: std.Io.Writer = .fixed(&buf);

    var block: [block_size]u8 = undefined;
    emitHeader(&block, "contig.bin", "", 0o644, 0, 0, block_size, 0, '7');
    try dst.writeAll(&block);
    emitHeader(&block, "not-an-entry", "", 0o755, 0, 0, 0, 0, '0');
    try dst.writeAll(&block);
    emitHeader(&block, "safe.txt", "", 0o644, 0, 0, 0, 0, '0');
    try dst.writeAll(&block);
    try dst.splatByteAll(0, 2 * block_size);

    var src: std.Io.Reader = .fixed(dst.buffered());
    var tr = Reader.init(testing.allocator, &src);
    defer tr.deinit();

    const first = (try tr.next()).?;
    try testing.expectEqualStrings("contig.bin", first.path);
    try testing.expectEqual(@as(u64, block_size), first.size);

    // The middle block is this entry's content, so the next entry is the last.
    const second = (try tr.next()).?;
    try testing.expectEqualStrings("safe.txt", second.path);
    try testing.expectEqual(@as(?Entry, null), try tr.next());
}

test "writer refuses a numeric field that does not fit, instead of truncating it" {
    var buf: [4 * block_size]u8 = undefined;
    var dst: std.Io.Writer = .fixed(&buf);
    const tw = Writer.init(&dst);

    // 0o7777777 = 2097151 is the largest uid ustar can hold; GNU tar 1.35
    // accepts exactly this and refuses 2097152 ("value 2097152 out of uid_t
    // range 0..2097151"). Without the guard 2097152 is written as "0000000",
    // i.e. root.
    try tw.writeEntry(.{ .path = "ok", .uid = max_octal_8, .gid = max_octal_8, .mode = max_octal_8 }, "");
    try testing.expectError(error.FieldOutOfRange, tw.writeEntry(.{ .path = "x", .uid = max_octal_8 + 1 }, ""));
    try testing.expectError(error.FieldOutOfRange, tw.writeEntry(.{ .path = "x", .gid = max_octal_8 + 1 }, ""));
    try testing.expectError(error.FieldOutOfRange, tw.writeEntry(.{ .path = "x", .mode = max_octal_8 + 1 }, ""));
    try testing.expectError(error.FieldOutOfRange, tw.writeEntry(.{ .path = "x", .mtime = max_octal_12 + 1 }, ""));
    try testing.expectError(error.FieldOutOfRange, tw.writeEntry(.{ .path = "x", .mtime = -1 }, ""));
    // A NUL in a name has no tar form in either mode (it would come back
    // truncated, or be refused by the pax reader).
    try testing.expectError(error.FieldOutOfRange, tw.writeEntry(.{ .path = "a\x00b" }, ""));
    try testing.expectError(error.FieldOutOfRange, tw.writeEntry(.{ .path = "l", .kind = .symlink, .link_target = "t\x00" }, ""));
    const pw = Writer.initOptions(tw.dst, .{ .long_names = .pax });
    try testing.expectError(error.FieldOutOfRange, pw.writeEntry(.{ .path = "p" ** 150 ++ "\x00" }, ""));

    // The refusal happens before any byte is emitted, so a rejected entry
    // leaves no partial header (and no orphan 'L' record) in the stream.
    const after_ok = dst.buffered().len;
    try testing.expectError(error.FieldOutOfRange, tw.writeEntry(.{ .path = "x" ** 60, .uid = max_octal_8 + 1 }, ""));
    try testing.expectEqual(after_ok, dst.buffered().len);
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

test "packDirToPath: round-trips through the reader, same stats as packDir" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "tree");
    try tmp.dir.writeFile(io, .{ .sub_path = "tree/hello.txt", .data = "packed via packDirToPath\n" });

    var rootbuf: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_len = try tmp.dir.realPath(io, &rootbuf);
    var root: [std.fs.max_path_bytes]u8 = undefined;
    const root_path = try std.fmt.bufPrint(&root, "{s}/tree", .{rootbuf[0..tmp_len]});

    var outbuf: [std.fs.max_path_bytes]u8 = undefined;
    const out_path = try std.fmt.bufPrint(&outbuf, "{s}/out.tar.gz", .{rootbuf[0..tmp_len]});

    const stats = try packDirToPath(io, gpa, &.{root_path}, out_path);
    try testing.expectEqual(@as(usize, 1), stats.files);
    try testing.expectEqual(@as(usize, 1), stats.dirs); // tree
    try testing.expectEqual(@as(u64, 25), stats.bytes);

    // Read it back off disk exactly like a real consumer would: open the
    // written file, decompress, and walk it with `Reader`.
    const written = try std.Io.Dir.cwd().readFileAlloc(io, out_path, gpa, .limited(1024 * 1024));
    defer gpa.free(written);

    var src: std.Io.Reader = .fixed(written);
    const window = try gpa.alloc(u8, flate.max_window_len);
    defer gpa.free(window);
    var decomp = flate.Decompress.init(&src, .gzip, window);
    var tr = Reader.init(gpa, &decomp.reader);
    defer tr.deinit();

    var seen_file = false;
    var count: usize = 0;
    while (try tr.next()) |e| {
        count += 1;
        if (std.mem.endsWith(u8, e.path, "/hello.txt")) {
            seen_file = true;
            try testing.expectEqual(Kind.file, e.kind);
            const content = try readAllContent(&tr, gpa);
            defer gpa.free(content);
            try testing.expectEqualStrings("packed via packDirToPath\n", content);
        }
    }
    try testing.expectEqual(@as(usize, 2), count); // tree/ + tree/hello.txt
    try testing.expect(seen_file);
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

// ── fuzz: streaming tar parse off an untrusted archive, never panics ───────
//
// `Reader.next`/`Reader.read` are what unpacks an archive that arrived over
// the network or off disk — a hostile ustar/GNU header (bad checksum, a GNU
// long-name/long-link payload, a base-256 size field near `maxInt(u64)`) is
// exactly this parser's threat model per its own doc comment. Drive a full
// entry-by-entry walk (headers + content) over fuzzed bytes the way a real
// extractor would.

// ⛔ And it never saw an archive. The harness opened `smith.bytes(&buf)` and
// then drew the length with `smith.valueRangeAtMost`; `bytes` consumes
// `@min(buf.len, in.len)` octets and a ranged draw then reads EIGHT more as
// a little-endian `u64`, returning the range MINIMUM when fewer remain, so
// the length was 0 for every input a corpus can carry. The target had no
// corpus either, so the one input it ever ran was empty and `Reader.next`
// answered on its first short read. Measured 2026-09-07: 1 round, 0
// non-empty inputs, 0 entries walked, 0 content octets read.
//
// ⚠ AND THE BUFFER WAS TOO SMALL FOR THE THREAT MODEL IT NAMES. At
// `4 * block_size` = 2048 octets, a GNU long-name archive does not fit: the
// 'L' record header, its name payload block, the real header, one content
// block and the two-block terminator are 3072 octets. So the long-name
// payload the comment above lists as a threat could not have passed through
// this harness even with a corpus wired up — a seed over the buffer reads
// back EMPTY. The buffer is now `8 * block_size`, set by the largest archive
// the module's own `Writer` produces below, not by taste.

/// The corpus, built at run time from this module's own `Writer`: `tar` owns
/// no captured archive, so freezing a paste of one would only track the
/// encoder until someone edited it.
///
/// ⭐ The harness and the guard below both build it from HERE. A guard
/// measuring a different corpus from the one the harness gets is not a guard.
const ArchiveCorpus = struct {
    const cap = 8 * block_size;

    scratch: [cap]u8 = undefined,
    stores: [8][4 + cap]u8 = undefined,
    entries: [8][]const u8 = undefined,

    fn build(self: *ArchiveCorpus) ![]const []const u8 {
        const kit = @import("testkit").fuzz;
        var n: usize = 0;

        // 0: one small regular file, terminated. The archive the module's own
        //    doc-comment example produces.
        {
            var w: std.Io.Writer = .fixed(&self.scratch);
            const tw = Writer.init(&w);
            try tw.writeEntry(.{ .path = "etc/hostname", .mode = 0o644, .mtime = 1_600_000_000 }, "router\n");
            try tw.finish();
            self.entries[n] = kit.seedInto(&self.stores[n], w.buffered());
            n += 1;
        }

        // 1: a dir, a file and a symlink — three typeflags in one walk.
        {
            var w: std.Io.Writer = .fixed(&self.scratch);
            const tw = Writer.init(&w);
            try tw.writeEntry(.{ .path = "tree/", .kind = .dir, .mode = 0o755 }, "");
            try tw.writeEntry(.{ .path = "tree/hello.txt", .mode = 0o644 }, "hello\n");
            try tw.writeEntry(.{ .path = "tree/link", .kind = .symlink, .link_target = "hello.txt" }, "");
            try tw.finish();
            self.entries[n] = kit.seedInto(&self.stores[n], w.buffered());
            n += 1;
        }

        // 2: a 137-octet path, past ustar's 100-octet `name` field, so the
        //    writer emits a GNU 'L' record ahead of the header. ⚠ THIS is the
        //    shape that could not fit the old 2048-octet buffer.
        {
            var w: std.Io.Writer = .fixed(&self.scratch);
            const tw = Writer.init(&w);
            try tw.writeEntry(.{ .path = "long/" ++ ("n" ** 130) ++ "/f", .mode = 0o644 }, "x");
            try tw.finish();
            self.entries[n] = kit.seedInto(&self.stores[n], w.buffered());
            n += 1;
        }

        // 3: a header and its content with NO end-of-archive blocks — the
        //    truncation a stream cut mid-transfer produces.
        {
            var w: std.Io.Writer = .fixed(&self.scratch);
            const tw = Writer.init(&w);
            try tw.writeEntry(.{ .path = "cut.txt", .mode = 0o644 }, "abcdef");
            self.entries[n] = kit.seedInto(&self.stores[n], w.buffered());
            n += 1;
        }

        // The two derived seeds start from a known-good one-file archive.
        var good_buf: [cap]u8 = undefined;
        const good_len = blk: {
            var w: std.Io.Writer = .fixed(&self.scratch);
            const tw = Writer.init(&w);
            try tw.writeEntry(.{ .path = "etc/hostname", .mode = 0o644, .mtime = 1_600_000_000 }, "router\n");
            try tw.finish();
            const b = w.buffered();
            @memcpy(good_buf[0..b.len], b);
            break :blk b.len;
        };

        // 4: one octet of the `chksum` field corrupted. `verifyChecksum` is
        //    the guard, and random bytes essentially never reach it.
        var bad: [cap]u8 = undefined;
        @memcpy(bad[0..good_len], good_buf[0..good_len]);
        bad[148] ^= 0x01;
        self.entries[n] = kit.seedInto(&self.stores[n], bad[0..good_len]);
        n += 1;

        // 5: a size field claiming 8 GiB behind a header the checksum still
        //    accepts — the size parser against a stream that cannot deliver.
        @memcpy(bad[0..good_len], good_buf[0..good_len]);
        @memcpy(bad[124..135], "77777777777");
        recomputeChecksum(bad[0..block_size]);
        self.entries[n] = kit.seedInto(&self.stores[n], bad[0..good_len]);
        n += 1;

        // 6: one block of 0xFF — every field out of range at once.
        @memset(self.scratch[0..block_size], 0xFF);
        self.entries[n] = kit.seedInto(&self.stores[n], self.scratch[0..block_size]);
        n += 1;

        // 7: the empty archive, which is what an empty corpus produced.
        self.entries[n] = kit.seedInto(&self.stores[n], self.scratch[0..0]);
        n += 1;

        std.debug.assert(n == self.entries.len);
        return &self.entries;
    }
};

/// Re-stamp a ustar header's checksum after a field was edited, so the seed
/// exercises the field's own parser rather than dying at `verifyChecksum`.
fn recomputeChecksum(block: []u8) void {
    @memset(block[148..156], ' ');
    var sum: u32 = 0;
    for (block[0..block_size]) |b| sum += b;
    _ = std.fmt.bufPrint(block[148..], "{o:0>6}\x00 ", .{sum}) catch unreachable;
}

test "fuzz: Reader.next/read never panic on an arbitrary archive" {
    var corpus: ArchiveCorpus = .{};
    try testing.fuzz({}, fuzzReader, .{ .corpus = try corpus.build() });
}

test "corpus: every archive seed reaches the reader, and what it walks is pinned" {
    // ⭐ The measurement, executable. It draws exactly the way the harness
    // does, because the defect WAS the draw.
    //
    // `octets` is the second number and it is the load-bearing one: an empty
    // stream is not an error to `Reader.next` in any interesting sense — it
    // simply ends — so a guard counting clean returns would have been
    // satisfied by the collapsed harness. Content octets read out of an entry
    // cannot come from an empty input at all.
    var corpus: ArchiveCorpus = .{};
    const seeds = try corpus.build();

    var nonempty: usize = 0;
    var entries: usize = 0;
    var octets: usize = 0;
    var refused: usize = 0;
    for (seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [ArchiveCorpus.cap]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;

        var src: std.Io.Reader = .fixed(buf[0..len]);
        var tr = Reader.init(testing.allocator, &src);
        defer tr.deinit();
        var content_buf: [256]u8 = undefined;
        var walked: usize = 0;
        while (walked < 16) : (walked += 1) {
            const entry = (tr.next() catch {
                refused += 1;
                break;
            }) orelse break;
            _ = entry;
            entries += 1;
            while (true) {
                const n = tr.read(&content_buf) catch {
                    refused += 1;
                    break;
                };
                if (n == 0) break;
                octets += n;
            }
        }
    }
    // Measured 2026-09-07. Before: 1 round, 0 non-empty, 0 entries, 0 octets.
    try testing.expectEqual(seeds.len - 1, nonempty); // the deliberate empty seed
    try testing.expectEqual(@as(usize, 7), entries);
    try testing.expectEqual(@as(usize, 1556), octets); // 20 of real content + 1536 read against the 8 GiB size claim before the stream ran out
    try testing.expectEqual(@as(usize, 4), refused); // the truncated archive, the bad checksum, the lying size, and the 0xFF block
}

fn fuzzReader(_: void, smith: *std.testing.Smith) !void {
    // ⚠ One byte-first draw. Never `bytes` then a ranged length.
    var buf: [ArchiveCorpus.cap]u8 = undefined;
    const len: usize = smith.slice(&buf);

    var src: std.Io.Reader = .fixed(buf[0..len]);
    var tr = Reader.init(testing.allocator, &src);
    defer tr.deinit();

    var content_buf: [256]u8 = undefined;
    var entries: usize = 0;
    while (entries < 16) : (entries += 1) {
        const entry = (tr.next() catch return) orelse return;
        _ = entry;
        while (true) {
            const n = tr.read(&content_buf) catch return;
            if (n == 0) break;
        }
    }
}

test "GNU tar --format=pax: a long name arrives through the pax 'x' header (external anchor)" {
    // The same archive shape Python's tarfile and Go's archive/tar write by
    // default for a long name. Before 2026-09-30 this reader reported the
    // truncated ustar name instead.
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const probe = systemTar(gpa, io, tmp.dir, &.{ "tar", "--version" }) catch return error.SkipZigTest;
    const probe_res = probe orelse return error.SkipZigTest;
    gpa.free(probe_res.stdout);
    gpa.free(probe_res.stderr);

    const long_dir = "pax-" ** 30; // 120 bytes, no slash: one path component
    const long_path = long_dir ++ "/f.txt";
    try tmp.dir.createDirPath(io, long_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = long_path, .data = "pax content\n" });
    const res = (try systemTar(gpa, io, tmp.dir, &.{
        "tar", "--format=pax", "--mtime=@1600000000", "-cf", "pax.tar", long_path,
    })).?;
    gpa.free(res.stdout);
    gpa.free(res.stderr);

    var f = try tmp.dir.openFile(io, "pax.tar", .{});
    defer f.close(io);
    var rbuf: [8192]u8 = undefined;
    var fr = f.reader(io, &rbuf);
    var tr = Reader.init(gpa, &fr.interface);
    defer tr.deinit();
    const e = (try tr.next()).?;
    try testing.expectEqualStrings(long_path, e.path);
    try testing.expectEqual(@as(u64, 12), e.size);
    var content: [32]u8 = undefined;
    const n = try tr.read(&content);
    try testing.expectEqualStrings("pax content\n", content[0..n]);
    try testing.expectEqual(@as(?Entry, null), try tr.next());
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

test "GNU tar lists + extracts our pax-mode archive (external cross-check of the pax writer)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const probe = systemTar(gpa, io, tmp.dir, &.{ "tar", "--version" }) catch return error.SkipZigTest;
    const probe_res = probe orelse return error.SkipZigTest;
    gpa.free(probe_res.stdout);
    gpa.free(probe_res.stderr);

    const long_path = "p" ** 150; // one component: no prefix split, so a pax `path`
    const long_target = "t" ** 130;
    {
        var f = try tmp.dir.createFile(io, "ours-pax.tar", .{});
        defer f.close(io);
        var fbuf: [8192]u8 = undefined;
        var fw = f.writer(io, &fbuf);
        const tw = Writer.initOptions(&fw.interface, .{ .long_names = .pax });
        try tw.writeEntry(.{
            .path = long_path,
            .mode = 0o644,
            .uid = 5_000_000,
            .gid = 6_000_000,
            .mtime = 1_727_700_007,
            .mtime_nsec = 500_000_000,
        }, "pax content\n");
        try tw.writeEntry(.{ .path = "link", .kind = .symlink, .link_target = long_target, .mode = 0o777, .mtime = 1_600_000_000 }, "");
        try tw.finish();
        try fw.interface.flush();
    }

    {
        const res = (try systemTar(gpa, io, tmp.dir, &.{ "tar", "--numeric-owner", "--full-time", "-tvvf", "ours-pax.tar" })).?;
        defer gpa.free(res.stdout);
        defer gpa.free(res.stderr);
        try testing.expect(std.mem.indexOf(u8, res.stdout, "5000000/6000000") != null);
        try testing.expect(std.mem.indexOf(u8, res.stdout, ":07.5 " ++ long_path) != null); // the .5 s survived
        try testing.expect(std.mem.indexOf(u8, res.stdout, "link -> " ++ long_target) != null);
    }
    {
        try tmp.dir.createDirPath(io, "out");
        const res = (try systemTar(gpa, io, tmp.dir, &.{ "tar", "-xf", "ours-pax.tar", "-C", "out" })).?;
        gpa.free(res.stdout);
        gpa.free(res.stderr);
        const body = try tmp.dir.readFileAlloc(io, "out/" ++ long_path, gpa, .limited(1024));
        defer gpa.free(body);
        try testing.expectEqualStrings("pax content\n", body);
        var lbuf: [256]u8 = undefined;
        const tlen = try tmp.dir.readLink(io, "out/link", &lbuf);
        try testing.expectEqualStrings(long_target, lbuf[0..tlen]);
    }
}

// ── mutation run 2026-10-04: one test per surviving mutant ─────────────────

/// Read every entry of `archive` and return the first `next()` error, or
/// null when the archive reads cleanly.
fn firstReadError(archive: []const u8) !?ReadError {
    var src: std.Io.Reader = .fixed(archive);
    var tr = Reader.init(testing.allocator, &src);
    defer tr.deinit();
    while (true) {
        // The error is the VALUE returned here, hence the `@as`.
        const e = tr.next() catch |err| return @as(?ReadError, err);
        if (e == null) return null;
    }
}

test "reader: a size near maxInt(u64) is BadHeader on every path, never a skip that overflows" {
    // The guards' own comments: no real archive needs a size this close to
    // maxInt(u64), and `size + padding` would wrap. Mutation 2026-10-04:
    // removing either guard survived -- a 'g' header reached
    // `discard(h.size + content_pad)` (a ReleaseSafe panic), a pax `size`
    // record was handed out as the entry's size.
    var buf: [6 * block_size]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var block: [block_size]u8 = undefined;
    emitHeader(&block, "global", "", 0, 0, 0, std.math.maxInt(u64), 0, 'g');
    try w.writeAll(&block);
    try writeZeros(&w, 2 * block_size);
    try testing.expectEqual(@as(?ReadError, error.BadHeader), try firstReadError(w.buffered()));

    var rb: [64]u8 = undefined;
    var abuf: [8 * block_size]u8 = undefined;
    var aw: std.Io.Writer = .fixed(&abuf);
    emitHeader(&block, "f", "", 0o644, 0, 0, 0, 0, '0');
    try paxArchive(&aw, paxRecord(&rb, "size", "18446744073709551615"), &block, "");
    try testing.expectEqual(@as(?ReadError, error.BadHeader), try firstReadError(aw.buffered()));
}

test "pax: a 'size' record applies to its own entry only" {
    // POSIX pax 'x': "the extended header records shall apply only to the
    // following file". Mutation 2026-10-04: a pax size left set for the
    // NEXT entry survived; that entry would then be read 5 bytes long.
    var rb: [64]u8 = undefined;
    const payload = paxRecord(&rb, "size", "5");
    var abuf: [10 * block_size]u8 = undefined;
    var w: std.Io.Writer = .fixed(&abuf);
    var block: [block_size]u8 = undefined;
    emitHeader(&block, "PaxHeaders/one", "", 0, 0, 0, payload.len, 0, 'x');
    try w.writeAll(&block);
    try w.writeAll(payload);
    try writeZeros(&w, padding(payload.len));
    emitHeader(&block, "one", "", 0o644, 0, 0, 0, 0, '0'); // header says 0, pax says 5
    try w.writeAll(&block);
    try w.writeAll("12345");
    try writeZeros(&w, padding(5));
    emitHeader(&block, "two", "", 0o644, 0, 0, 3, 0, '0');
    try w.writeAll(&block);
    try w.writeAll("abc");
    try writeZeros(&w, padding(3) + 2 * block_size);

    var src: std.Io.Reader = .fixed(w.buffered());
    var tr = Reader.init(testing.allocator, &src);
    defer tr.deinit();
    try testing.expectEqual(@as(u64, 5), (try tr.next()).?.size);
    const two = (try tr.next()).?;
    try testing.expectEqualStrings("two", two.path);
    try testing.expectEqual(@as(u64, 3), two.size);
    var cbuf: [8]u8 = undefined;
    try testing.expectEqualStrings("abc", cbuf[0..try tr.read(&cbuf)]);
    try testing.expect((try tr.next()) == null);
}

test "pax: an empty 'size' value deletes the keyword, the header's size stands" {
    // POSIX pax: "If the <value> field is zero length, it shall delete any
    // header block field ... of the same name" -- the readPax doc says the
    // same. Mutation 2026-10-04: refusing `size=` survived.
    var rb: [64]u8 = undefined;
    var abuf: [8 * block_size]u8 = undefined;
    var w: std.Io.Writer = .fixed(&abuf);
    var block: [block_size]u8 = undefined;
    emitHeader(&block, "f", "", 0o644, 0, 0, 3, 0, '0');
    try paxArchive(&w, paxRecord(&rb, "size", ""), &block, "abc");
    var src: std.Io.Reader = .fixed(w.buffered());
    var tr = Reader.init(testing.allocator, &src);
    defer tr.deinit();
    try testing.expectEqual(@as(u64, 3), (try tr.next()).?.size);
}

test "pax: the record length and a numeric value are plain decimal digits" {
    // POSIX pax record: "<length> <keyword>=<value>\n", length "a decimal
    // number"; `size` "a decimal number". `std.fmt.parseInt` alone also takes
    // a sign and `_` separators -- the digit loops are what refuse them.
    // Mutation 2026-10-04: dropping either digit loop survived.
    var rb: [64]u8 = undefined;
    var abuf: [8 * block_size]u8 = undefined;
    var block: [block_size]u8 = undefined;
    emitHeader(&block, "f", "", 0o644, 0, 0, 0, 0, '0');
    var w: std.Io.Writer = .fixed(&abuf);
    try paxArchive(&w, "+13 path=abc\n", &block, "");
    try testing.expectEqual(@as(?ReadError, error.BadHeader), try firstReadError(w.buffered()));
    w = .fixed(&abuf);
    try paxArchive(&w, paxRecord(&rb, "size", "+0"), &block, "");
    try testing.expectEqual(@as(?ReadError, error.BadHeader), try firstReadError(w.buffered()));
}

test "typeflag '7' (contiguous file) reads as a regular file with its content" {
    // POSIX ustar: '7' is "reserved to represent a file to which an
    // implementation has associated some high-performance attribute";
    // implementations without one treat it as a regular file, as GNU tar
    // does (the `carries_content` comment above). Mutation 2026-10-04:
    // reporting it as `.other` survived.
    var abuf: [6 * block_size]u8 = undefined;
    var w: std.Io.Writer = .fixed(&abuf);
    var block: [block_size]u8 = undefined;
    emitHeader(&block, "c", "", 0o644, 0, 0, 2, 0, '7');
    try w.writeAll(&block);
    try w.writeAll("hi");
    try writeZeros(&w, padding(2) + 2 * block_size);
    var src: std.Io.Reader = .fixed(w.buffered());
    var tr = Reader.init(testing.allocator, &src);
    defer tr.deinit();
    const e = (try tr.next()).?;
    try testing.expectEqual(Kind.file, e.kind);
    try testing.expectEqual(@as(u64, 2), e.size);
}

test "GNU 'L' record with an empty payload is BadHeader" {
    // `ReadError.BadHeader` doc: "bad 'L'-'K' size". An empty long name
    // would leave the next entry nameless. Mutation 2026-10-04: accepting
    // size 0 survived.
    var abuf: [6 * block_size]u8 = undefined;
    var w: std.Io.Writer = .fixed(&abuf);
    var block: [block_size]u8 = undefined;
    emitHeader(&block, gnu_longlink_name, "", 0, 0, 0, 0, 0, 'L');
    try w.writeAll(&block);
    emitHeader(&block, "real", "", 0o644, 0, 0, 0, 0, '0');
    try w.writeAll(&block);
    try writeZeros(&w, 2 * block_size);
    try testing.expectEqual(@as(?ReadError, error.BadHeader), try firstReadError(w.buffered()));
}

test "GNU magic: bytes 345..500 are not a ustar prefix" {
    // GNU's old header (`struct oldgnu_header`, magic "ustar  \0") keeps
    // atime/ctime/offsets where POSIX ustar has `prefix`; reading them as a
    // prefix would invent a directory. Mutation 2026-10-04: honouring the
    // prefix under GNU magic survived.
    var block: [block_size]u8 = undefined;
    emitHeader(&block, "file", "", 0o644, 0, 0, 0, 0, '0');
    @memcpy(block[257..265], "ustar  \x00");
    @memcpy(block[345..357], "14751346217\x00"); // an atime, as GNU writes it
    fixChecksum(&block);
    var abuf: [3 * block_size]u8 = undefined;
    @memcpy(abuf[0..block_size], &block);
    @memset(abuf[block_size..], 0);
    var src: std.Io.Reader = .fixed(&abuf);
    var tr = Reader.init(testing.allocator, &src);
    defer tr.deinit();
    try testing.expectEqualStrings("file", (try tr.next()).?.path);
}

test "checksum: all 8 field bytes count as spaces, and a signed sum is accepted" {
    // POSIX ustar: the checksum is "the sum of all bytes in the header block
    // ... treating each byte of the chksum field as a space", whatever those
    // bytes hold -- so a field written as 7 digits + NUL (no trailing space)
    // checks the same. And historical tars summed SIGNED bytes; GNU tar
    // accepts either (the `verifyChecksum` doc). Mutation 2026-10-04: both a
    // 7-byte space window and dropping the signed form survived.
    var abuf: [3 * block_size]u8 = undefined;
    @memset(abuf[block_size..], 0);

    var block: [block_size]u8 = undefined;
    emitHeader(&block, "seven", "", 0o644, 0, 0, 0, 0, '0');
    @memset(block[148..156], ' ');
    var sum: u64 = 0;
    for (block) |b| sum += b;
    _ = try std.fmt.bufPrint(block[148..156], "{o:0>7}\x00", .{sum});
    @memcpy(abuf[0..block_size], &block);
    try testing.expectEqual(@as(?ReadError, null), try firstReadError(&abuf));

    emitHeader(&block, "hi\xe9\xff", "", 0o644, 0, 0, 0, 0, '0');
    @memset(block[148..156], ' ');
    var signed: i64 = 0;
    for (block) |b| signed += @as(i8, @bitCast(b));
    _ = try std.fmt.bufPrint(block[148..156], "{o:0>6}\x00 ", .{@as(u64, @intCast(signed))});
    @memcpy(abuf[0..block_size], &block);
    try testing.expectEqual(@as(?ReadError, null), try firstReadError(&abuf));
}

test "writer: the ustar name/prefix limits are exact (100 / 155 bytes)" {
    // POSIX ustar: `name` is 100 bytes, `prefix` 155. A path one byte over
    // either needs the GNU 'L' record or a pax `path` record, and must come
    // back whole. Mutation 2026-10-04: off-by-one limits in the GNU 'L'
    // threshold and in `splitPrefix` (name 101, prefix 156) all survived --
    // the copy into the field silently truncated.
    const cases = [_]struct { path: []const u8, mode: LongNames }{
        .{ .path = "a" ** 101, .mode = .gnu },
        .{ .path = "d/" ++ "n" ** 101, .mode = .pax },
        .{ .path = "p" ** 156 ++ "/n", .mode = .pax },
    };
    for (cases) |c| {
        var abuf: [8 * block_size]u8 = undefined;
        var w: std.Io.Writer = .fixed(&abuf);
        const tw = Writer.initOptions(&w, .{ .long_names = c.mode });
        try tw.writeEntry(.{ .path = c.path, .mode = 0o644 }, "x");
        try tw.finish();
        var src: std.Io.Reader = .fixed(w.buffered());
        var tr = Reader.init(testing.allocator, &src);
        defer tr.deinit();
        try testing.expectEqualStrings(c.path, (try tr.next()).?.path);
    }
}

test "writer: 8 GiB - 1 is still octal; 8 GiB needs base-256, and a pax 'size' record in pax mode" {
    // The 12-byte ustar size field holds 11 octal digits, at most
    // 0o77777777777 = 8 GiB - 1 (`writeSizeField` doc: base-256 only beyond,
    // as GNU tar does); `LongNames.pax` emits records "for exactly the fields
    // that do not fit". Mutation 2026-10-04: moving either threshold by one
    // survived -- the reader decodes both encodings, so only the bytes show it.
    var abuf: [4 * block_size]u8 = undefined;
    var w: std.Io.Writer = .fixed(&abuf);
    try Writer.init(&w).writeHeader(.{ .path = "f", .size = 0o77777777777 });
    try testing.expectEqualStrings("77777777777\x00", w.buffered()[124..136]);

    w = .fixed(&abuf);
    try Writer.initOptions(&w, .{ .long_names = .pax }).writeHeader(.{ .path = "f", .size = 0o77777777777 });
    try testing.expectEqual(@as(usize, block_size), w.buffered().len); // no 'x' header
    w = .fixed(&abuf);
    try Writer.initOptions(&w, .{ .long_names = .pax }).writeHeader(.{ .path = "f", .size = 0o100000000000 });
    const out = w.buffered();
    try testing.expectEqual(@as(u8, 'x'), out[156]);
    try testing.expect(std.mem.indexOf(u8, out[block_size .. 2 * block_size], "size=8589934592\n") != null);
    try testing.expectEqual(@as(u8, 0x80), out[2 * block_size + 124]); // base-256 in the entry's own field
}

// ── offline write-path anchor (real GNU tar captures, no subprocess) ──────
//
// Complements the live cross-check above (host-gated, skips without a `tar`
// on PATH): frozen bytes captured once from real GNU tar, asserted with no
// subprocess and no skip path — see write_golden_test.zig's doc comment.
test {
    _ = @import("write_golden_test.zig");
    _ = @import("pax_test.zig");
    _ = @import("go_oracle.zig");
}
