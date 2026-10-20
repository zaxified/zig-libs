// SPDX-License-Identifier: MIT

//! OFFLINE differential anchor: Go's standard library archive/zip (go1.26,
//! BSD-3-Clause) as an independent implementation of this module. The cases
//! are ours (`tools/go_oracle/*.go`); Go's answers to them were captured by
//! that program into `go_oracle_vectors.zig`, and the tests here replay the
//! same bytes through THIS module and compare. No Go at test time. Exempt from
//! a NOTICE entry under §0's black-box-oracle carve-out: only Go's observable
//! verdicts were recorded, no Go source was read or ported.
//!
//! Three tables:
//!  - `go_written`: archives Go's own Writer produced -- our Archive and
//!    EntryReader must see what Go's Reader sees.
//!  - `crafted`: archives built record by record (central vs local header,
//!    data descriptors, integrity, methods, DOS/UT times, attributes, EOCD
//!    shapes, zip64); same requirement.
//!  - `go_write`: archives OUR ArchiveWriter produced (`tools/interop.zig`),
//!    read by Go. Replayed by writing Go's view of every entry again and
//!    requiring the identical bytes: a field Go misread would not reproduce
//!    them.
//!
//! Every table is compared with `list_directories = true`, so directory
//! entries (a name ending in '/') are compared like the rest; the default
//! (skipping them, module doc) is checked against the same list with them
//! left out.
//!
//! The replay of `go_write` is exact: Go's view of each entry (kind from the
//! directory/symlink/data-descriptor bits, comment, caller extra, zip64) is
//! written again and the archive must come out byte for byte. The one thing
//! it cannot take from Go's view is the caller's extra records: Go reports the
//! whole central extra field, so the module's own records (`UT`, the zip64
//! extra) are stripped from it -- by id, the first `UT` and every zip64 record
//! -- and the rest is what is passed as `AddEntryOptions.extra`; a stripped
//! record that was not ours would show as a byte difference.
//!
//! Go is an oracle, not an authority. Every place we answer differently is
//! listed in `divergences` with the judgement; a case that diverges without
//! an entry fails, and so does an entry whose case has started to agree.

const std = @import("std");
const testing = std.testing;
const zipstream = @import("root.zig");
const vectors = @import("go_oracle_vectors.zig");

const Divergence = struct { id: []const u8, why: []const u8 };

/// Cases where this module deliberately answers differently from Go. Info-ZIP
/// `unzip` 6.0 / `zipinfo` was asked as the tiebreaker on each (`go run .
/// -dump DIR`, then `unzip -tv` / `zipinfo -T -l`).
const divergences = [_]Divergence{
    .{ .id = "go_basic", .why = "Go's Writer left the DOS date 0 (no Modified given); see dos_zero_date" },
    .{ .id = "go_raw", .why = "CreateRaw leaves the DOS date 0 as well; see dos_zero_date" },
    .{ .id = "go_create_plain", .why = "Create (no Modified) writes the DOS date 0 as well; see dos_zero_date" },
    .{ .id = "go_extra", .why = "its second entry has no Modified: DOS date 0; see dos_zero_date" },
    .{ .id = "go_zip64_raw", .why = "CreateRaw writes the header's DOS fields as given (zero), whatever Modified says; see dos_zero_date" },
    .{ .id = "go_dirs_symlinks", .why = "its entry 'modedir' (no trailing '/', Mode() = ModeDir): Go calls an entry a directory by its mode, this module by the trailing '/' (APPNOTE 4.3.8, Python ZipInfo.is_dir); the attributes stay visible in Entry.external_attributes" },
    .{ .id = "unix_dir_attr_file_name", .why = "Unix directory attributes on a name without '/': Go says directory, this module decides by the name (see go_dirs_symlinks); Entry.external_attributes keeps them" },
    .{ .id = "dos_dir_attr", .why = "the MS-DOS directory attribute (0x10) on a name without '/': as unix_dir_attr_file_name" },
    .{ .id = "dir_entry_with_content", .why = "a directory entry ('d/') that carries 6 bytes of data: Go refuses the whole archive; this module lists it (list_directories) and reads the bytes, never hiding a member" },
    .{ .id = "dos_zero_date", .why = "DOS date 0 is month 0, day 0: no date. Go normalises it to 1979-11-30, zipinfo prints 1980-00-00; Entry.mtime is null (documented)" },
    .{ .id = "dos_month13", .why = "an invalid DOS date: Go rolls it into the next year, zipinfo prints month 13; null here" },
    .{ .id = "dos_feb30", .why = "an invalid DOS date: Go rolls it into March; null here" },
    .{ .id = "dos_hour24", .why = "an invalid DOS time: Go rolls it into the next day; null here" },
    .{ .id = "dos_sec60", .why = "an invalid DOS time (second 60): Go rolls it over; null here" },
    .{ .id = "backslash_name", .why = "'\\' in a stored name becomes '/' here (documented: Windows writers emit it); Go and unzip's listing keep it" },
    .{ .id = "usize_long_deflate", .why = "the deflate stream ends before the declared uncompressed size, but its CRC matches what it holds: unzip -t passes it (OK), as we do; Go reports unexpected EOF" },
    .{ .id = "encrypted_flag", .why = "general-purpose bit 0 set: Go ignores it and returns the stored bytes as plaintext; unzip asks for a password; we refuse the entry (ZipEncryptedEntry)" },
    .{ .id = "cd_offset_past_end", .why = "the directory offset points 1000 bytes past the end: unzip refuses (\"overlapped components\") as we do; Go lists the entry and fails to open it" },
    .{ .id = "cd_size_more", .why = "the directory size is 10 bytes too long: unzip compensates and reads the archive, as we do; Go refuses it" },
};

fn decode(gpa: std.mem.Allocator, a: vectors.Archive) ![]u8 {
    const buf = try gpa.alloc(u8, a.len);
    @memset(buf, 0);
    for (a.runs) |r| @memcpy(buf[r.off..][0..r.bytes.len], r.bytes);
    return buf;
}

/// Read `data` with this module and describe the first difference from Go's
/// verdict into `why` (empty when they agree).
fn compare(gpa: std.mem.Allocator, data: []const u8, c: vectors.Case, why: *std.Io.Writer) !void {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "t.zip", .data = data });
    var file = try tmp.dir.openFile(io, "t.zip", .{});
    defer file.close(io);

    var archive: zipstream.Archive = undefined;
    archive.initOpts(io, gpa, file, .{ .list_directories = true }) catch |err| {
        if (c.err == null) return why.print("ours: Archive.init error.{t}; go: {d} entries", .{ err, c.entries.len });
        return;
    };
    defer archive.deinit();
    if (c.err) |e| return why.print("ours: {d} entries; go: \"{s}\"", .{ archive.entries.items.len, e });
    if (!std.mem.eql(u8, archive.comment, c.comment)) return why.print("archive comment: ours \"{s}\", go \"{s}\"", .{ archive.comment, c.comment });

    // The default skips directories: it is the same list without them.
    {
        var plain: zipstream.Archive = undefined;
        try plain.initOpts(io, gpa, file, .{});
        defer plain.deinit();
        var k: usize = 0;
        for (archive.entries.items) |*e| {
            if (e.is_directory) continue;
            if (k == plain.entries.items.len or !std.mem.eql(u8, plain.entries.items[k].name, e.name))
                return why.print("default listing differs from list_directories minus directories at \"{s}\"", .{e.name});
            k += 1;
        }
        if (k != plain.entries.items.len) return why.print("default listing has {d} entries, list_directories minus directories {d}", .{ plain.entries.items.len, k });
    }

    var gi: usize = 0;
    var oi: usize = 0;
    const window = try gpa.alloc(u8, std.compress.flate.max_window_len);
    defer gpa.free(window);
    var content: std.ArrayList(u8) = .empty;
    defer content.deinit(gpa);
    while (true) : ({
        gi += 1;
        oi += 1;
    }) {
        const go_done = gi == c.entries.len;
        const ours_done = oi == archive.entries.items.len;
        if (go_done and ours_done) return;
        if (go_done) return why.print("ours: entry {d} \"{s}\"; go: no more entries", .{ oi, archive.entries.items[oi].name });
        if (ours_done) return why.print("ours: {d} entries; go: entry \"{s}\" too", .{ oi, c.entries[gi].name });
        const g = c.entries[gi];
        const o = &archive.entries.items[oi];
        if (!std.mem.eql(u8, o.name, g.name)) return why.print("entry {d} name: ours \"{s}\", go \"{s}\"", .{ oi, o.name, g.name });
        if (@backingInt(o.compression) != g.method) return why.print("entry {d} method: ours {d}, go {d}", .{ oi, @backingInt(o.compression), g.method });
        if (o.crc32 != g.crc32) return why.print("entry {d} crc32: ours {x:0>8}, go {x:0>8}", .{ oi, o.crc32, g.crc32 });
        if (o.compressed_size != g.compressed_size or o.uncompressed_size != g.uncompressed_size)
            return why.print("entry {d} sizes: ours {d}/{d}, go {d}/{d}", .{ oi, o.compressed_size, o.uncompressed_size, g.compressed_size, g.uncompressed_size });
        if (o.mtime != g.mtime) return why.print("entry {d} mtime: ours {?d}, go {?d}", .{ oi, o.mtime, g.mtime });
        if (o.mode != g.mode) return why.print("entry {d} mode: ours {?o}, go {?o}", .{ oi, o.mode, g.mode });
        if (!std.mem.eql(u8, o.comment, g.comment)) return why.print("entry {d} comment: ours \"{s}\", go \"{s}\"", .{ oi, o.comment, g.comment });
        if (!std.mem.eql(u8, o.extra, g.extra)) return why.print("entry {d} extra: ours {d} bytes, go {d} bytes (or differing)", .{ oi, o.extra.len, g.extra.len });
        if (o.flags != g.flags) return why.print("entry {d} flags: ours {x}, go {x}", .{ oi, o.flags, g.flags });
        if (o.version_made_by != g.creator) return why.print("entry {d} version made by: ours {x}, go {x}", .{ oi, o.version_made_by, g.creator });
        if (o.external_attributes != g.ext_attr) return why.print("entry {d} external attributes: ours {x}, go {x}", .{ oi, o.external_attributes, g.ext_attr });
        if (o.is_directory != g.is_dir) return why.print("entry {d} directory: ours {}, go {}", .{ oi, o.is_directory, g.is_dir });
        if (o.isSymlink() != g.is_symlink) return why.print("entry {d} symlink: ours {}, go {}", .{ oi, o.isSymlink(), g.is_symlink });
        // Go sets NonUTF8 only for a name that needs UTF-8 (or is invalid) without bit 11;
        // for an ASCII name the question has no answer.
        if (!isAscii(g.name) and o.name_is_utf8 == g.non_utf8) return why.print("entry {d} name encoding: ours utf8={}, go non_utf8={}", .{ oi, o.name_is_utf8, g.non_utf8 });

        content.clearRetainingCapacity();
        var er: zipstream.EntryReader = undefined;
        const read_err: ?anyerror = blk: {
            er.init(&archive, o, window) catch |err| break :blk err;
            const r = er.reader();
            var buf: [4096]u8 = undefined;
            while (true) {
                const n = r.readSliceShort(&buf) catch |err| break :blk err;
                if (n == 0) break;
                try content.appendSlice(gpa, buf[0..n]);
            }
            break :blk null;
        };
        if (g.open_err) |ge| {
            if (read_err == null) return why.print("entry {d} \"{s}\": ours read {d} bytes; go: \"{s}\"", .{ oi, o.name, content.items.len, ge });
        } else {
            if (read_err) |err| return why.print("entry {d} \"{s}\": ours error.{t}; go read {d} bytes", .{ oi, o.name, err, g.content.len });
            if (!std.mem.eql(u8, content.items, g.content)) return why.print("entry {d} content: ours {d} bytes, go {d}", .{ oi, content.items.len, g.content.len });
        }
    }
}

fn isAscii(name: []const u8) bool {
    for (name) |ch| if (ch >= 0x80) return false;
    return true;
}

/// `extra` without the records this module writes itself: the first `UT`
/// (0x5455) and every zip64 record (0x0001). Whether a zip64 record was there
/// goes to `zip64`.
fn callerExtra(arena: std.mem.Allocator, extra: []const u8, zip64: *bool) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    var seen_ut = false;
    var i: usize = 0;
    while (i + 4 <= extra.len) {
        const id = std.mem.readInt(u16, extra[i..][0..2], .little);
        const len = std.mem.readInt(u16, extra[i + 2 ..][0..2], .little);
        const end = i + 4 + len;
        if (end > extra.len) break;
        if (id == 0x0001) {
            zip64.* = true;
        } else if (id == 0x5455 and !seen_ut) {
            seen_ut = true;
        } else try out.appendSlice(arena, extra[i..end]);
        i = end;
    }
    try out.appendSlice(arena, extra[i..]);
    return out.items;
}

fn find(id: []const u8) ?Divergence {
    for (divergences) |d| if (std.mem.eql(u8, d.id, id)) return d;
    return null;
}

fn replayTable(comptime table: []const vectors.Case) !void {
    const gpa = testing.allocator;
    var failed: usize = 0;
    for (table) |c| {
        const data = try decode(gpa, c.archive);
        defer gpa.free(data);
        var why_buf: [512]u8 = undefined;
        var why: std.Io.Writer = .fixed(&why_buf);
        compare(gpa, data, c, &why) catch |err| switch (err) {
            error.WriteFailed => {}, // description cut at the buffer: still a divergence
            else => return err,
        };
        const differs = why.end > 0;
        const listed = find(c.id) != null;
        if (differs and !listed) {
            std.debug.print("go oracle: {s}: {s}\n", .{ c.id, why.buffered() });
            failed += 1;
        } else if (!differs and listed) {
            std.debug.print("go oracle: {s} is listed as a divergence but agrees with Go now\n", .{c.id});
            failed += 1;
        }
    }
    if (failed != 0) return error.GoOracleDisagrees;
}

test "go oracle: archives Go's Writer produced read the same here" {
    try replayTable(&vectors.go_written);
}

test "go oracle: crafted archives read the same here" {
    try replayTable(&vectors.crafted);
}

test "go oracle: every divergence names a case that exists" {
    for (divergences) |d| {
        var seen = false;
        inline for (.{ vectors.go_written, vectors.crafted, vectors.go_write }) |t| {
            for (t) |c| seen = seen or std.mem.eql(u8, c.id, d.id);
        }
        if (!seen) {
            std.debug.print("go oracle: divergence {s} names no case\n", .{d.id});
            return error.StaleDivergence;
        }
    }
}

test "go oracle: our ArchiveWriter's archives are what Go reads back" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var failed: usize = 0;
    for (vectors.go_write) |c| {
        const want = try decode(gpa, c.archive);
        defer gpa.free(want);
        if (c.err) |e| {
            std.debug.print("go oracle: {s}: Go refused our archive: {s}\n", .{ c.id, e });
            failed += 1;
            continue;
        }
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var w = zipstream.ArchiveWriter.init(gpa, &out.writer);
        defer w.deinit();
        w.comment = c.comment;
        for (c.entries) |g| {
            // A non-ASCII UTF-8 name must reach Go as UTF-8 (flag bit 11).
            if (g.non_utf8) {
                std.debug.print("go oracle: {s}: Go reads {s} as not UTF-8\n", .{ c.id, g.name });
                failed += 1;
            }
            if (g.open_err) |e| {
                std.debug.print("go oracle: {s}: Go could not read {s}: {s}\n", .{ c.id, g.name, e });
                failed += 1;
            }
            var zip64 = false;
            const opts: zipstream.AddEntryOptions = .{
                .method = if (g.method == 0) .store else .deflate,
                .mtime = g.mtime,
                .mode = g.mode,
                .comment = g.comment,
                .extra = try callerExtra(arena, g.extra, &zip64),
                .force_zip64 = zip64,
            };
            if (g.is_dir) {
                try w.addDirectory(g.name, opts);
            } else if (g.is_symlink) {
                try w.addSymlink(g.name, g.content, opts);
            } else if (g.flags & 8 != 0) {
                const sw = try w.beginEntry(g.name, opts);
                try sw.writeAll(g.content);
                try w.endEntry();
            } else {
                try w.addEntry(g.name, g.content, opts);
            }
        }
        try w.finish();
        if (!std.mem.eql(u8, out.written(), want)) {
            std.debug.print("go oracle: {s}: writing Go's view of the entries does not reproduce our archive\n", .{c.id});
            failed += 1;
        }
    }
    if (failed != 0) return error.GoOracleDisagrees;
}
