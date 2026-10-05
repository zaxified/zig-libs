// SPDX-License-Identifier: MIT

//! OFFLINE differential anchor: Go's standard library archive/tar (go1.26,
//! BSD-3-Clause) as an independent implementation of this module. The cases
//! are ours (`tools/go_oracle/*.go`); Go's answers to them were captured by
//! that program into `go_oracle_vectors.zig`, and the tests here replay the
//! same bytes through THIS module and compare. No Go at test time. Exempt from
//! a NOTICE entry under §0's black-box-oracle carve-out: only Go's observable
//! verdicts were recorded, no Go source was read or ported.
//!
//! Three tables:
//!  - `go_written`: archives Go's own Writer produced (USTAR, PAX, GNU) --
//!    our Reader must see what Go's Reader sees.
//!  - `crafted`: archives built header by header -- field shapes, typeflags,
//!    GNU and pax records, archive ends; same requirement.
//!  - `go_write`: archives OUR Writer produced (`tools/interop.zig`), read by
//!    Go. Replayed by writing Go's view of every entry again and requiring
//!    the identical bytes: a field Go misread would not reproduce them.
//!
//! Go is an oracle, not an authority. Every place we answer differently is
//! listed in `divergences` with the judgement; a case that diverges without
//! an entry fails, and so does an entry whose case has started to agree (the
//! table can only describe the present).

const std = @import("std");
const testing = std.testing;
const tar = @import("root.zig");
const vectors = @import("go_oracle_vectors.zig");

const Divergence = struct { id: []const u8, why: []const u8 };

/// Cases where this module deliberately answers differently from Go. GNU tar
/// 1.35 was asked as the tiebreaker on each (`go run . -dump DIR`, then
/// `tar -tvv --numeric-owner --full-time -f DIR/<id>.tar`); every entry
/// below sides with GNU tar unless it says otherwise.
const divergences = [_]Divergence{
    .{ .id = "prefix_gnu", .why = "GNU magic (\"ustar  \\0\"): bytes 345.. are GNU's atime/ctime, not a ustar prefix. Go joins them onto the name (\"pre/name\"); GNU tar lists \"name\", as we do" },
    .{ .id = "gnuL_empty", .why = "an empty GNU 'L' name: Go returns an entry named \"\", GNU tar warns and substitutes \".\" (a directory name for a file entry); we refuse the archive (BadHeader)" },
    .{ .id = "gnuL_then_pax", .why = "both a GNU 'L' and a pax path for one entry: Go takes the GNU name, GNU tar and we the pax one (pax is the more specific, newer record)" },
    .{ .id = "pax_then_gnuL", .why = "as gnuL_then_pax in the other order: GNU tar and we take the pax path, Go the GNU name" },
    .{ .id = "pax_size_plus", .why = "pax numbers are plain decimal digits: GNU tar (\"size=+3 is not valid\") and we refuse a sign, Go accepts it" },
    .{ .id = "pax_uid_plus", .why = "as pax_size_plus for uid: GNU tar and we refuse \"+5\"" },
    .{ .id = "pax_mtime_plus", .why = "as pax_size_plus for mtime: GNU tar and we refuse \"+1\"" },
    .{ .id = "pax_len_plus", .why = "a record length \"+13\": GNU tar (\"missing length\") and we refuse it, Go accepts it" },
    .{ .id = "pax_uid_neg", .why = "uid=-5: Go reports -5; GNU tar refuses it (\"out of range 0..4294967295\"), and an Entry id is u32, so we refuse it too" },
    .{ .id = "pax_uid_2p32", .why = "uid=4294967296: Go reports it; GNU tar refuses it as out of uid_t range, and keeping its low 32 bits would report uid 0 (root): we refuse it" },
    .{ .id = "uid_b256_neg", .why = "base-256 uid -1: Go reports -1; GNU tar refuses it as out of uid_t range, so do we" },
    .{ .id = "uid_b256_2p32", .why = "base-256 uid 2^32: as pax_uid_2p32, truncation would read root; GNU tar and we refuse it" },
    .{ .id = "pax_key_empty", .why = "a record with an empty keyword: Go refuses the archive; GNU tar ignores the record with a warning, as we do (it cannot override any field)" },
    .{ .id = "zero_block_then_header", .why = "one zero block, then a header: GNU tar stops at the lone zero block (\"A lone zero block\", without -i), as we do; Go reports an invalid header" },
    .{ .id = "zero_block_then_garbage", .why = "as zero_block_then_header: GNU tar and we end the archive at the lone zero block" },
    .{ .id = "eof_mid_padding", .why = "the stream ends inside the last entry's block padding: GNU tar (\"Unexpected EOF in archive\", exit 2) and we report truncation, Go a clean end" },
};

fn decode(gpa: std.mem.Allocator, a: vectors.Archive) ![]u8 {
    const buf = try gpa.alloc(u8, a.len);
    @memset(buf, 0);
    for (a.runs) |r| @memcpy(buf[r.off..][0..r.bytes.len], r.bytes);
    return buf;
}

fn goKind(typeflag: u8) tar.Kind {
    return switch (typeflag) {
        0, '0', '7' => .file,
        '5' => .dir,
        '2' => .symlink,
        '1' => .hardlink,
        else => .other,
    };
}

fn headerOnly(typeflag: u8) bool {
    return switch (typeflag) {
        '1', '2', '3', '4', '5', '6' => true,
        else => false,
    };
}

/// Read `data` with this module and describe the first difference from Go's
/// verdict into `why` (empty when they agree).
fn compare(gpa: std.mem.Allocator, data: []const u8, c: vectors.Case, why: *std.Io.Writer) !void {
    var src: std.Io.Reader = .fixed(data);
    var r = tar.Reader.init(gpa, &src);
    defer r.deinit();
    var content: std.ArrayList(u8) = .empty;
    defer content.deinit(gpa);

    var gi: usize = 0;
    while (true) {
        // Go returns a pax global header ('g') as an entry of its own; this
        // module skips it (module doc: a global path/size has no per-entry
        // meaning). Not a divergence in what any member is.
        while (gi < c.entries.len and c.entries[gi].typeflag == 'g') gi += 1;
        const ours = r.next() catch |err| {
            if (c.err == null) return why.print("ours: error.{t} at entry {d}; go: clean end after {d} entries", .{ err, gi, c.entries.len });
            if (gi != c.entries.len) return why.print("ours: error.{t} at entry {d}; go: {d} entries before its error", .{ err, gi, c.entries.len });
            return;
        } orelse {
            if (gi != c.entries.len) return why.print("ours: end after {d} entries; go: {d}", .{ gi, c.entries.len });
            if (c.err) |e| return why.print("ours: clean end; go: error \"{s}\"", .{e});
            return;
        };
        content.clearRetainingCapacity();
        var buf: [4096]u8 = undefined;
        const read_err: ?anyerror = while (true) {
            const n = r.read(&buf) catch |err| break err;
            if (n == 0) break null;
            try content.appendSlice(gpa, buf[0..n]);
        };
        if (gi == c.entries.len) {
            // Go records an entry only once its content was read, so an
            // error inside the content leaves Go one entry short: agreement
            // when ours failed reading that same content.
            if (c.err) |e| {
                if (read_err != null) return;
                return why.print("ours: entry {d} \"{s}\"; go: error \"{s}\"", .{ gi, ours.path, e });
            }
            return why.print("ours: entry {d} \"{s}\"; go: end", .{ gi, ours.path });
        }
        if (read_err) |err| return why.print("ours: error.{t} reading entry {d}; go read it", .{ err, gi });
        const g = c.entries[gi];
        if (!std.mem.eql(u8, ours.path, g.name)) return why.print("entry {d} name: ours \"{s}\", go \"{s}\"", .{ gi, ours.path, g.name });
        if (ours.kind != goKind(g.typeflag)) return why.print("entry {d} kind: ours {t} (typeflag 0x{x:0>2}), go typeflag 0x{x:0>2}", .{ gi, ours.kind, ours.typeflag, g.typeflag });
        if (ours.mode != g.mode) return why.print("entry {d} mode: ours {o}, go {o}", .{ gi, ours.mode, g.mode });
        if (ours.uid != g.uid) return why.print("entry {d} uid: ours {d}, go {d}", .{ gi, ours.uid, g.uid });
        if (ours.gid != g.gid) return why.print("entry {d} gid: ours {d}, go {d}", .{ gi, ours.gid, g.gid });
        if (ours.mtime != g.mtime or ours.mtime_nsec != g.nsec)
            return why.print("entry {d} mtime: ours {d}.{d:0>9}, go {d}.{d:0>9}", .{ gi, ours.mtime, ours.mtime_nsec, g.mtime, g.nsec });
        if (!headerOnly(g.typeflag) and ours.size != g.size) return why.print("entry {d} size: ours {d}, go {d}", .{ gi, ours.size, g.size });
        if (!std.mem.eql(u8, ours.link_target, g.link)) return why.print("entry {d} link: ours \"{s}\", go \"{s}\"", .{ gi, ours.link_target, g.link });
        if (!std.mem.eql(u8, content.items, g.content)) return why.print("entry {d} content: ours {d} bytes, go {d}", .{ gi, content.items.len, g.content.len });
        gi += 1;
    }
}

/// Go's view of one entry, as the Entry this module's Writer takes.
fn goEntry(g: vectors.Entry) tar.Entry {
    return .{
        .path = g.name,
        .kind = goKind(g.typeflag),
        .mode = @intCast(g.mode),
        .uid = @intCast(g.uid),
        .gid = @intCast(g.gid),
        .mtime = g.mtime,
        .mtime_nsec = g.nsec,
        .link_target = g.link,
    };
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

test "go oracle: our Writer's archives are what Go reads back" {
    const gpa = testing.allocator;
    var failed: usize = 0;
    for (vectors.go_write) |c| {
        const want = try decode(gpa, c.archive);
        defer gpa.free(want);
        // Go must have read every archive cleanly: the cases are valid by
        // construction, so any error is Go refusing our bytes.
        if (c.err) |e| {
            std.debug.print("go oracle: {s}: Go refused our archive: {s}\n", .{ c.id, e });
            failed += 1;
            continue;
        }
        const mode: tar.LongNames = if (std.mem.endsWith(u8, c.id, ".pax")) .pax else .gnu;
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        if (std.mem.endsWith(u8, c.id, ".tgz")) {
            // packTarGz: Go gunzipped our output; the case holds the tar inside.
            var entries: std.ArrayList(tar.ContentEntry) = .empty;
            defer entries.deinit(gpa);
            for (c.entries) |g| try entries.append(gpa, .{ .entry = goEntry(g), .content = g.content });
            var gz: std.Io.Writer.Allocating = .init(gpa);
            defer gz.deinit();
            try tar.packTarGz(gpa, &gz.writer, entries.items);
            var src: std.Io.Reader = .fixed(gz.written());
            var window: [std.compress.flate.max_window_len]u8 = undefined;
            var d: std.compress.flate.Decompress = .init(&src, .gzip, &window);
            _ = try d.reader.streamRemaining(&out.writer);
            if (!std.mem.eql(u8, out.written(), want)) {
                std.debug.print("go oracle: {s}: packing Go's view of the entries does not reproduce our archive\n", .{c.id});
                failed += 1;
            }
            continue;
        }
        const w = tar.Writer.initOptions(&out.writer, .{ .long_names = mode });
        for (c.entries) |g| try w.writeEntry(goEntry(g), g.content);
        try w.finish();
        if (!std.mem.eql(u8, out.written(), want)) {
            std.debug.print("go oracle: {s}: writing Go's view of the entries does not reproduce our archive\n", .{c.id});
            failed += 1;
        }
    }
    if (failed != 0) return error.GoOracleDisagrees;
}
