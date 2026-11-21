// SPDX-License-Identifier: MIT
//! Raw copy (`ArchiveWriter.addRaw` / `copyEntry`, `Archive.openRaw`), append
//! (`ArchiveWriter.initAppend`) and the archive-wide check (`Archive.verify`).
//! The foreign archives are the 7-Zip (WinZip AES) and Info-ZIP (ZipCrypto)
//! fixtures of `crypto_test.zig`.

const std = @import("std");
const testing = std.testing;
const zs = @import("root.zig");

const password = "secret";

fn rep(comptime s: []const u8, comptime n: usize) *const [s.len * n]u8 {
    const f = comptime blk: {
        var b: [s.len * n]u8 = undefined;
        for (0..n) |i| @memcpy(b[i * s.len ..][0..s.len], s);
        break :blk b;
    };
    return &f;
}

fn readAll(a: std.mem.Allocator, archive: *zs.Archive, e: *const zs.Entry, pw: ?[]const u8) ![]u8 {
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var er: zs.EntryReader = undefined;
    try er.open(archive, e, &window, .{ .password = pw });
    defer er.deinit();
    var out: std.Io.Writer.Allocating = .init(a);
    errdefer out.deinit();
    _ = try er.reader().streamRemaining(&out.writer);
    return out.toOwnedSlice();
}

fn rawBytes(a: std.mem.Allocator, archive: *zs.Archive, e: *const zs.Entry) ![]u8 {
    var rr: zs.RawReader = undefined;
    try archive.openRaw(&rr, e);
    var out: std.Io.Writer.Allocating = .init(a);
    errdefer out.deinit();
    _ = try rr.reader().streamRemaining(&out.writer);
    return out.toOwnedSlice();
}

/// A source archive with every kind of entry the writer makes.
fn buildSource(a: std.mem.Allocator, out: *std.Io.Writer.Allocating) !void {
    var zw = zs.ArchiveWriter.init(a, &out.writer);
    defer zw.deinit();
    zw.comment = "archive comment";
    try zw.addEntry("plain.txt", rep("hello hello hello hello hello\n", 20), .{ .mtime = 1_700_000_001, .mode = 0o640, .comment = "entry comment", .extra = &.{ 0x78, 0x56, 0x02, 0x00, 0xab, 0xcd } });
    try zw.addEntry("stored.bin", "stored bytes", .{ .method = .store, .mtime = 1_600_000_000 });
    try zw.addEntry("empty", "", .{ .method = .store });
    try zw.addDirectory("dir/", .{ .mode = 0o750 });
    try zw.addSymlink("dir/link", "../plain.txt", .{});
    const w = try zw.beginEntry("dir/streamed.txt", .{ .mtime = 1_700_000_002 });
    try w.writeAll(rep("streamed ", 500));
    try zw.endEntry();
    try zw.addEntry("secret.txt", "top secret top secret top secret", .{ .encryption = .{ .password = password, .salt = "0123456789abcdef"[0..16] }, .mtime = 1_700_000_003 });
    try zw.addEntry("forced64.txt", rep("x", 100), .{ .force_zip64 = true });
    try zw.finish();
}

fn expectSameEntry(x: *const zs.Entry, y: *const zs.Entry) !void {
    try testing.expectEqualStrings(x.name, y.name);
    try testing.expectEqual(x.compression, y.compression);
    try testing.expectEqual(x.compressed_size, y.compressed_size);
    try testing.expectEqual(x.uncompressed_size, y.uncompressed_size);
    try testing.expectEqual(x.crc32, y.crc32);
    try testing.expectEqual(x.mtime, y.mtime);
    try testing.expectEqual(x.mode, y.mode);
    try testing.expectEqual(x.encrypted, y.encrypted);
    try testing.expectEqualStrings(x.comment, y.comment);
    try testing.expectEqual(x.version_made_by >> 8, y.version_made_by >> 8);
    try testing.expectEqual(x.external_attributes, y.external_attributes);
    try testing.expectEqual(x.dos_time, y.dos_time);
    try testing.expectEqual(x.dos_date, y.dos_date);
    try testing.expectEqual(x.is_directory, y.is_directory);
    try testing.expectEqual(x.aes, y.aes);
    // The data descriptor bit follows the layout; the rest of the flags are the source's.
    try testing.expectEqual(x.flags & 0b0110_0111, y.flags & 0b0110_0111);
}

test "copyEntry: every kind of entry is copied raw, byte for byte, metadata intact" {
    const a = testing.allocator;
    var src_bytes: std.Io.Writer.Allocating = .init(a);
    defer src_bytes.deinit();
    try buildSource(a, &src_bytes);
    var ms: zs.MemorySource = .{ .bytes = src_bytes.written() };
    var src: zs.Archive = undefined;
    try src.initSource(a, ms.source(), .{ .list_directories = true });
    defer src.deinit();

    var dst_bytes: std.Io.Writer.Allocating = .init(a);
    defer dst_bytes.deinit();
    var zw = zs.ArchiveWriter.init(a, &dst_bytes.writer);
    defer zw.deinit();
    for (src.entries.items) |*e| try zw.copyEntry(&src, e);
    try zw.finish();

    var ms2: zs.MemorySource = .{ .bytes = dst_bytes.written() };
    var dst: zs.Archive = undefined;
    try dst.initSource(a, ms2.source(), .{ .list_directories = true });
    defer dst.deinit();
    try testing.expectEqual(src.entries.items.len, dst.entries.items.len);
    try testing.expectEqual(@as(usize, 8), dst.entries.items.len);
    for (src.entries.items, dst.entries.items) |*x, *y| {
        try expectSameEntry(x, y);
        const rx = try rawBytes(a, &src, x);
        defer a.free(rx);
        const ry = try rawBytes(a, &dst, y);
        defer a.free(ry);
        try testing.expectEqualSlices(u8, rx, ry);
        if (!x.is_directory) {
            const cx = try readAll(a, &src, x, password);
            defer a.free(cx);
            const cy = try readAll(a, &dst, y, password);
            defer a.free(cy);
            try testing.expectEqualSlices(u8, cx, cy);
        }
    }
    // The caller's extra record survived; the module's own (UT) was rebuilt, not doubled.
    const plain = dst.find("plain.txt").?;
    try testing.expectEqual(@as(?i64, 1_700_000_001), plain.mtime);
    try testing.expect(std.mem.indexOf(u8, plain.extra, &.{ 0x78, 0x56, 0x02, 0x00, 0xab, 0xcd }) != null);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, plain.extra, &.{ 0x55, 0x54, 0x05, 0x00 }));
    try testing.expect(dst.find("dir/link").?.isSymlink());
    try testing.expectEqual(@as(?zs.Archive.Problem, null), try dst.verify(.{ .password = password }));
}

test "copyEntry: skip and rename make an edit by rebuilding" {
    const a = testing.allocator;
    var src_bytes: std.Io.Writer.Allocating = .init(a);
    defer src_bytes.deinit();
    try buildSource(a, &src_bytes);
    var ms: zs.MemorySource = .{ .bytes = src_bytes.written() };
    var src: zs.Archive = undefined;
    try src.initSource(a, ms.source(), .{});
    defer src.deinit();

    var dst_bytes: std.Io.Writer.Allocating = .init(a);
    defer dst_bytes.deinit();
    var zw = zs.ArchiveWriter.init(a, &dst_bytes.writer);
    defer zw.deinit();
    for (src.entries.items) |*e| {
        if (std.mem.eql(u8, e.name, "stored.bin")) continue;
        var renamed = e.*;
        if (std.mem.eql(u8, e.name, "plain.txt")) renamed.name = "renamed.txt";
        try zw.copyEntry(&src, &renamed);
    }
    try zw.addEntry("new.txt", "new", .{});
    try zw.finish();

    var ms2: zs.MemorySource = .{ .bytes = dst_bytes.written() };
    var dst: zs.Archive = undefined;
    try dst.initSource(a, ms2.source(), .{});
    defer dst.deinit();
    try testing.expect(dst.find("stored.bin") == null);
    try testing.expect(dst.find("plain.txt") == null);
    const got = try readAll(a, &dst, dst.find("renamed.txt").?, null);
    defer a.free(got);
    try testing.expectEqualStrings(rep("hello hello hello hello hello\n", 20), got);
    try testing.expect(dst.find("new.txt") != null);
}

test "copyEntry: a hand-built Entry, the unsafe-name gate, and a source that ends early" {
    const a = testing.allocator;
    var out: std.Io.Writer.Allocating = .init(a);
    defer out.deinit();
    var zw = zs.ArchiveWriter.init(a, &out.writer);
    defer zw.deinit();
    const data = "abc";
    var r: std.Io.Reader = .fixed(data);
    try zw.addRaw(&.{ .name = "h.txt", .compression = .store, .compressed_size = 3, .uncompressed_size = 3, .file_offset = 0, .crc32 = std.hash.Crc32.hash(data), .mtime = 1_700_000_000, .mode = 0o600 }, &r);
    var r2: std.Io.Reader = .fixed(data);
    try testing.expectError(error.ZipUnsafeEntryName, zw.addRaw(&.{ .name = "../x", .compression = .store, .compressed_size = 3, .uncompressed_size = 3, .file_offset = 0, .crc32 = 0 }, &r2));
    try zw.finish();
    var ms: zs.MemorySource = .{ .bytes = out.written() };
    var arc: zs.Archive = undefined;
    try arc.initSource(a, ms.source(), .{});
    defer arc.deinit();
    const e = arc.find("h.txt").?;
    try testing.expectEqual(@as(?i64, 1_700_000_000), e.mtime);
    try testing.expectEqual(@as(?u16, 0o600), e.mode);
    const got = try readAll(a, &arc, e, null);
    defer a.free(got);
    try testing.expectEqualStrings(data, got);

    // A reader that ends before `compressed_size` bytes: an error, not a short entry.
    var out2: std.Io.Writer.Allocating = .init(a);
    defer out2.deinit();
    var zw2 = zs.ArchiveWriter.init(a, &out2.writer);
    defer zw2.deinit();
    var r3: std.Io.Reader = .fixed("ab");
    try testing.expectError(error.EndOfStream, zw2.addRaw(&.{ .name = "s", .compression = .store, .compressed_size = 3, .uncompressed_size = 3, .file_offset = 0, .crc32 = 0 }, &r3));
}

test "copyEntry: foreign WinZip AES (7-Zip) and ZipCrypto (Info-ZIP) archives copy and still decrypt" {
    const a = testing.allocator;
    const files = [_][]const u8{
        @embedFile("testdata/crypto/7z_aes128_deflate.zip"),
        @embedFile("testdata/crypto/7z_aes256_store.zip"),
        @embedFile("testdata/crypto/zc_deflate.zip"),
        @embedFile("testdata/crypto/zc_store.zip"),
    };
    for (files) |bytes| {
        var ms: zs.MemorySource = .{ .bytes = bytes };
        var src: zs.Archive = undefined;
        try src.initSource(a, ms.source(), .{});
        defer src.deinit();
        var out: std.Io.Writer.Allocating = .init(a);
        defer out.deinit();
        var zw = zs.ArchiveWriter.init(a, &out.writer);
        defer zw.deinit();
        for (src.entries.items) |*e| try zw.copyEntry(&src, e);
        try zw.finish();
        var ms2: zs.MemorySource = .{ .bytes = out.written() };
        var dst: zs.Archive = undefined;
        try dst.initSource(a, ms2.source(), .{});
        defer dst.deinit();
        try testing.expectEqual(src.entries.items.len, dst.entries.items.len);
        for (src.entries.items, dst.entries.items) |*x, *y| {
            try expectSameEntry(x, y);
            const cx = try readAll(a, &src, x, password);
            defer a.free(cx);
            const cy = try readAll(a, &dst, y, password);
            defer a.free(cy);
            try testing.expectEqualSlices(u8, cx, cy);
        }
        try testing.expectEqual(@as(?zs.Archive.Problem, null), try dst.verify(.{ .password = password }));
    }
}

test "initAppend: the old directory is kept verbatim, new entries follow, the comment stays" {
    const a = testing.allocator;
    var src_bytes: std.Io.Writer.Allocating = .init(a);
    defer src_bytes.deinit();
    try buildSource(a, &src_bytes);
    var ms: zs.MemorySource = .{ .bytes = src_bytes.written() };
    var old: zs.Archive = undefined;
    try old.initSource(a, ms.source(), .{ .list_directories = true });
    defer old.deinit();

    // The destination holds the old bytes up to the old central directory.
    var out: std.Io.Writer.Allocating = .init(a);
    defer out.deinit();
    try out.writer.writeAll(src_bytes.written()[0..old.cd_start]);
    var zw = try zs.ArchiveWriter.initAppend(a, &out.writer, &old);
    defer zw.deinit();
    try zw.addEntry("appended.txt", "appended", .{ .mtime = 1_700_000_100 });
    const w = try zw.beginEntry("appended-streamed.txt", .{});
    try w.writeAll("more");
    try zw.endEntry();
    try zw.finish();
    try testing.expectEqual(out.written().len, zw.offset);

    var ms2: zs.MemorySource = .{ .bytes = out.written() };
    var now: zs.Archive = undefined;
    try now.initSource(a, ms2.source(), .{ .list_directories = true });
    defer now.deinit();
    try testing.expectEqual(old.entries.items.len + 2, now.entries.items.len);
    try testing.expectEqualStrings("archive comment", now.comment);
    for (old.entries.items, now.entries.items[0..old.entries.items.len]) |*x, *y| {
        try expectSameEntry(x, y);
        try testing.expectEqual(x.file_offset, y.file_offset);
        if (x.is_directory) continue;
        const cx = try readAll(a, &old, x, password);
        defer a.free(cx);
        const cy = try readAll(a, &now, y, password);
        defer a.free(cy);
        try testing.expectEqualSlices(u8, cx, cy);
    }
    const ap = try readAll(a, &now, now.find("appended.txt").?, null);
    defer a.free(ap);
    try testing.expectEqualStrings("appended", ap);
    const ap2 = try readAll(a, &now, now.find("appended-streamed.txt").?, null);
    defer a.free(ap2);
    try testing.expectEqualStrings("more", ap2);
    try testing.expectEqual(@as(?zs.Archive.Problem, null), try now.verify(.{ .password = password }));

    // An archive behind a stub whose offsets were not adjusted cannot be appended to.
    var stub: std.Io.Writer.Allocating = .init(a);
    defer stub.deinit();
    try stub.writer.writeAll("STUBSTUB");
    try stub.writer.writeAll(src_bytes.written());
    var ms3: zs.MemorySource = .{ .bytes = stub.written() };
    var pre: zs.Archive = undefined;
    try pre.initSource(a, ms3.source(), .{});
    defer pre.deinit();
    var sink: std.Io.Writer.Allocating = .init(a);
    defer sink.deinit();
    try testing.expectError(error.ZipAppendPrefixed, zs.ArchiveWriter.initAppend(a, &sink.writer, &pre));
}

test "initAppend: nothing new is the same archive again" {
    const a = testing.allocator;
    var src_bytes: std.Io.Writer.Allocating = .init(a);
    defer src_bytes.deinit();
    try buildSource(a, &src_bytes);
    var ms: zs.MemorySource = .{ .bytes = src_bytes.written() };
    var old: zs.Archive = undefined;
    try old.initSource(a, ms.source(), .{});
    defer old.deinit();
    var out: std.Io.Writer.Allocating = .init(a);
    defer out.deinit();
    try out.writer.writeAll(src_bytes.written()[0..old.cd_start]);
    var zw = try zs.ArchiveWriter.initAppend(a, &out.writer, &old);
    defer zw.deinit();
    try zw.finish();
    try testing.expectEqualSlices(u8, src_bytes.written(), out.written());
}

test "verify: a sound archive is clean; a flipped byte, a lying size and overlapping entries are named" {
    const a = testing.allocator;
    var src_bytes: std.Io.Writer.Allocating = .init(a);
    defer src_bytes.deinit();
    try buildSource(a, &src_bytes);
    {
        var ms: zs.MemorySource = .{ .bytes = src_bytes.written() };
        var arc: zs.Archive = undefined;
        try arc.initSource(a, ms.source(), .{});
        defer arc.deinit();
        try testing.expectEqual(@as(?zs.Archive.Problem, null), try arc.verify(.{ .password = password }));
        // Without the password the encrypted member is skipped, not a problem.
        try testing.expectEqual(@as(?zs.Archive.Problem, null), try arc.verify(.{}));
        const bad = (try arc.verify(.{ .password = "wrong" })).?;
        try testing.expectEqualStrings("secret.txt", bad.entry.name);
        try testing.expectEqual(zs.Archive.Problem.Kind.bad_password, bad.kind);
    }
    // Flip one stored byte of "stored.bin".
    {
        const copy = try a.dupe(u8, src_bytes.written());
        defer a.free(copy);
        var ms: zs.MemorySource = .{ .bytes = copy };
        var arc: zs.Archive = undefined;
        try arc.initSource(a, ms.source(), .{});
        defer arc.deinit();
        const e = arc.find("stored.bin").?;
        const lh: usize = @intCast(e.file_offset);
        copy[lh + 30 + e.name.len + std.mem.readInt(u16, copy[lh + 28 ..][0..2], .little) + 2] ^= 0x40;
        const p = (try arc.verify(.{})).?;
        try testing.expectEqualStrings("stored.bin", p.entry.name);
        try testing.expectEqual(zs.Archive.Problem.Kind.crc_mismatch, p.kind);
    }
    // Two directory records for one member, and a record inside another's data.
    for ([_]u64{ 0, 40 }) |shift| {
        const copy = try a.dupe(u8, src_bytes.written());
        defer a.free(copy);
        var ms: zs.MemorySource = .{ .bytes = copy };
        var arc: zs.Archive = undefined;
        try arc.initSource(a, ms.source(), .{});
        const first = arc.entries.items[0].file_offset;
        const second_name = try a.dupe(u8, arc.entries.items[1].name);
        defer a.free(second_name);
        // Find the second record in the directory and point it into the first entry.
        var at: usize = @intCast(arc.cd_start);
        const end: usize = @intCast(arc.cd_end);
        while (at < end) {
            const nl = std.mem.readInt(u16, copy[at + 28 ..][0..2], .little);
            const el = std.mem.readInt(u16, copy[at + 30 ..][0..2], .little);
            const cl = std.mem.readInt(u16, copy[at + 32 ..][0..2], .little);
            if (std.mem.eql(u8, copy[at + 46 ..][0..nl], second_name)) {
                std.mem.writeInt(u32, copy[at + 42 ..][0..4], @intCast(first + shift), .little);
            }
            at += 46 + nl + el + cl;
        }
        arc.deinit();
        var arc2: zs.Archive = undefined;
        try arc2.initSource(a, ms.source(), .{});
        defer arc2.deinit();
        const p = (try arc2.verify(.{})).?;
        try testing.expectEqual(zs.Archive.Problem.Kind.overlap, p.kind);
        try testing.expectEqualStrings(second_name, p.entry.name);
        // Off: the content check alone reports what it finds (the pointed-at bytes are not this entry).
        const q = try arc2.verify(.{ .check_overlap = false });
        try testing.expect(q == null or q.?.kind != .overlap);
    }
}
