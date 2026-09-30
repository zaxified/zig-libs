// SPDX-License-Identifier: MIT
//! External anchors for entry modification time and Unix mode (2026-09-30),
//! both directions:
//!
//!   * WRITE — `testdata/write_mtime.zip` is `ArchiveWriter` output for two
//!     entries with `mtime` + `mode` set, captured once and checked with three
//!     independent readers (UnZip 6.00 / ZipInfo 3.00 Info-ZIP, Debian;
//!     Python 3.14 `zipfile`):
//!       - `unzip -t`: no errors;
//!       - `zipinfo -v`, entry `stored.txt`: origin Unix, DOS 2024 Sep 30
//!         12:40:06, "UT extra field modtime: 2024 Sep 30 12:40:07 UTC",
//!         Unix file attributes 100640 (-rw-r-----), extra field 9 bytes;
//!         entry `deflated.txt`: DOS 2006 Jan 2 15:04:04, UT 2006 Jan 2
//!         15:04:05 UTC, attributes 100755 (-rwxr-xr-x);
//!       - Python: `date_time` (2024,9,30,12,40,6) / (2006,1,2,15,4,4),
//!         `create_system` 3, `external_attr >> 16` 0o100640 / 0o100755,
//!         extra `5554050001279cfa66` / `5554050001e540b943`.
//!     The test asserts `ArchiveWriter` still reproduces it byte-for-byte.
//!   * READ — two archives made by Info-ZIP `zip` 3.0 from real files
//!     (`a.txt` mode 0600, mtime 2019-06-15 08:30:00 UTC = 1560587400;
//!     `b.sh` mode 0755, mtime 2001-09-09 01:46:41 UTC = 1000000001; times
//!     set with `TZ=UTC touch -d`):
//!       - `testdata/infozip_dos.zip` — `TZ=UTC zip -X -D`: no extra fields,
//!         so the DOS fields are all there is. zipinfo shows DOS 2019 Jun 15
//!         08:30:00 and 2001 Sep 9 01:46:42 — Info-ZIP rounds an odd second
//!         UP, where `ArchiveWriter` rounds down; a reader recovers what is
//!         stored, 1000000002.
//!       - `testdata/infozip_ut.zip` — `zip -D` in a UTC+2 zone: the DOS
//!         fields hold LOCAL time (10:30:00, 03:46:42) and a `UT` record the
//!         exact UTC instant, followed by an Info-ZIP `ux` (uid/gid) record.
//!         The reader must take the `UT` time — 1560587400 and 1000000001
//!         exactly — and step over `ux`.
//!     Regenerate by rerunning those commands; do not hand-edit the `.zip`s.

const std = @import("std");
const testing = std.testing;
const zs = @import("root.zig");
const Archive = zs.Archive;
const ArchiveWriter = zs.ArchiveWriter;
const DosDateTime = zs.DosDateTime;

const write_mtime: []const u8 = @embedFile("testdata/write_mtime.zip");
const infozip_dos: []const u8 = @embedFile("testdata/infozip_dos.zip");
const infozip_ut: []const u8 = @embedFile("testdata/infozip_ut.zip");
const write_golden: []const u8 = @embedFile("testdata/write_golden.zip");

const stored_data = "plain stored payload for the external zip oracle\n";
const deflated_data = "the quick brown fox jumps over the lazy dog. " ** 40;

test "mtime/mode: ArchiveWriter reproduces the zipinfo/Python-verified archive byte-for-byte" {
    const a = testing.allocator;
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var zw = ArchiveWriter.init(a, &aw.writer);
    defer zw.deinit();
    try zw.addEntry("stored.txt", stored_data, .{ .method = .store, .mtime = 1727700007, .mode = 0o640 });
    try zw.addEntry("deflated.txt", deflated_data, .{ .method = .deflate, .mtime = 1136214245, .mode = 0o755 });
    try zw.finish();
    try testing.expectEqualSlices(u8, write_mtime, aw.writer.buffered());
}

const Expect = struct { name: []const u8, mtime: ?i64, mode: ?u16 };

fn expectEntries(bytes: []const u8, want: []const Expect) !void {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "m.zip", .data = bytes });
    var f = try tmp.dir.openFile(testing.io, "m.zip", .{});
    defer f.close(testing.io);
    var archive: Archive = undefined;
    try archive.init(testing.io, testing.allocator, f);
    defer archive.deinit();
    try testing.expectEqual(want.len, archive.entries.items.len);
    for (want) |w| {
        const e = archive.find(w.name) orelse return error.TestMissingEntry;
        try testing.expectEqual(w.mtime, e.mtime);
        try testing.expectEqual(w.mode, e.mode);
    }
}

test "mtime/mode: the writer's own archive reads back the UT time and the mode" {
    try expectEntries(write_mtime, &.{
        .{ .name = "stored.txt", .mtime = 1727700007, .mode = 0o640 },
        .{ .name = "deflated.txt", .mtime = 1136214245, .mode = 0o755 },
    });
}

test "mtime/mode: an Info-ZIP archive with DOS fields only" {
    try expectEntries(infozip_dos, &.{
        .{ .name = "a.txt", .mtime = 1560587400, .mode = 0o600 },
        .{ .name = "b.sh", .mtime = 1000000002, .mode = 0o755 }, // Info-ZIP rounded :41 up
    });
}

test "mtime/mode: an Info-ZIP archive with UT + ux extra fields prefers the exact UTC time" {
    try expectEntries(infozip_ut, &.{
        .{ .name = "a.txt", .mtime = 1560587400, .mode = 0o600 },
        .{ .name = "b.sh", .mtime = 1000000001, .mode = 0o755 },
    });
}

test "mtime/mode: without options the writer stores 1980-01-01 and no mode" {
    try expectEntries(write_golden, &.{
        .{ .name = "stored.txt", .mtime = 315532800, .mode = null },
        .{ .name = "deflated.txt", .mtime = 315532800, .mode = null },
    });
}

test "DosDateTime: conversions, clamps and invalid fields" {
    // Round trips through even seconds.
    for ([_]i64{ 315532800, 951782400, 1000000000, 1560587400, 1727700006, 4102444800, 4354819198 }) |t| {
        try testing.expectEqual(@as(?i64, t), DosDateTime.fromUnix(t).toUnix());
    }
    // Odd seconds round down; out-of-range clamps.
    try testing.expectEqual(@as(?i64, 1000000000), DosDateTime.fromUnix(1000000001).toUnix());
    try testing.expectEqual(DosDateTime.min, DosDateTime.fromUnix(0));
    try testing.expectEqual(DosDateTime.min, DosDateTime.fromUnix(-1));
    try testing.expectEqual(DosDateTime.max, DosDateTime.fromUnix(std.math.maxInt(i64)));
    try testing.expectEqual(@as(?i64, 4354819198), DosDateTime.max.toUnix());
    // 2000-02-29 exists (leap by 400), 2100-02-29 does not.
    try testing.expectEqual(@as(?i64, 951782400), (DosDateTime{ .time = 0, .date = (20 << 9) | (2 << 5) | 29 }).toUnix());
    try testing.expectEqual(@as(?i64, null), (DosDateTime{ .time = 0, .date = (120 << 9) | (2 << 5) | 29 }).toUnix());
    // Invalid fields: the zero date writers used to emit, month 13, 31 April, hour 24.
    try testing.expectEqual(@as(?i64, null), (DosDateTime{ .time = 0, .date = 0 }).toUnix());
    try testing.expectEqual(@as(?i64, null), (DosDateTime{ .time = 0, .date = (13 << 5) | 1 }).toUnix());
    try testing.expectEqual(@as(?i64, null), (DosDateTime{ .time = 0, .date = (4 << 5) | 31 }).toUnix());
    try testing.expectEqual(@as(?i64, null), (DosDateTime{ .time = 24 << 11, .date = DosDateTime.min.date }).toUnix());
    // A time past the signed 32-bit range still gets DOS fields, but no UT
    // record: the header is 9 bytes shorter.
    const a = testing.allocator;
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var zw = ArchiveWriter.init(a, &aw.writer);
    defer zw.deinit();
    try zw.addEntry("x", "y", .{ .method = .store, .mtime = 4102444800 }); // 2100-01-01
    const lfh = std.mem.bytesToValue(std.zip.LocalFileHeader, aw.writer.buffered()[0..@sizeOf(std.zip.LocalFileHeader)]);
    try testing.expectEqual(@as(u16, 0), lfh.extra_len);
    try testing.expectEqual(@as(?i64, 4102444800), (DosDateTime{ .time = lfh.last_modification_time, .date = lfh.last_modification_date }).toUnix());
}
