// SPDX-License-Identifier: MIT
//! No-panic sweep tests (wave GM). Every test name ends with its finding ID.
const std = @import("std");
const zs = @import("root.zig");
const testing = std.testing;

fn eocd(buf: []u8, count: u16, cd_size: u32, cd_off: u32) void {
    @memcpy(buf[0..4], &std.zip.end_record_sig);
    @memset(buf[4..22], 0);
    std.mem.writeInt(u16, buf[10..12], count, .little);
    std.mem.writeInt(u32, buf[12..16], cd_size, .little);
    std.mem.writeInt(u32, buf[16..20], cd_off, .little);
}

test "zip64 locator with a record offset near 2^64 is a bad directory, not an overflow (sweep ZS-1)" {
    // 56 spare bytes where a no-extensible-data zip64 record would sit, the
    // locator, the end record (count 0xffff asks for the zip64 path).
    var bytes: [56 + 20 + 22]u8 = @splat(0);
    @memcpy(bytes[56..60], &std.zip.end_locator64_sig);
    std.mem.writeInt(u64, bytes[56 + 8 ..][0..8], std.math.maxInt(u64) - 0x10, .little);
    eocd(bytes[76..], 0xffff, 0, 0);
    var ms: zs.MemorySource = .{ .bytes = &bytes };
    var archive: zs.Archive = undefined;
    try testing.expectError(zs.Error.ZipBadCentralDirectory, archive.initSource(testing.allocator, ms.source(), .{}));
}

fn newWriter(aw: *std.Io.Writer.Allocating) zs.ArchiveWriter {
    return zs.ArchiveWriter.init(testing.allocator, &aw.writer);
}

test "a .custom entry without a writer codec is an error, not unreachable (sweep ZS-3)" {
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    var w = newWriter(&aw);
    defer w.deinit();
    try testing.expectError(zs.Error.UnsupportedCompressionMethod, w.addEntry("a", "x", .{ .method = .custom }));
    try testing.expectError(zs.Error.UnsupportedCompressionMethod, w.beginEntry("a", .{ .method = .custom }));
    // a codec that can only read
    const reader_only: zs.Codec = .{ .method = 77 };
    try testing.expectError(zs.Error.UnsupportedCompressionMethod, w.addEntry("a", "x", .{ .method = .custom, .codec = &reader_only }));
    try testing.expectError(zs.Error.UnsupportedCompressionMethod, w.beginEntry("a", .{ .method = .custom, .codec = &reader_only }));
    // nothing was written and the writer still works
    try testing.expectEqual(@as(usize, 0), aw.written().len);
    try w.addEntry("b", "y", .{});
    try w.finish();
}

test "an extra field that overflows the u16 length with the module's own records is refused (sweep ZS-2)" {
    const gpa = testing.allocator;
    const salt: [16]u8 = @splat(7);
    const big = try gpa.alloc(u8, 65500);
    defer gpa.free(big);
    @memset(big, 0);
    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    var w = newWriter(&aw);
    defer w.deinit();
    const enc: zs.AddEntryOptions.Encryption = .{ .password = "pw", .salt = &salt };
    // local: UT 9 + zip64 20 + AES 11 + 65500 > 65535
    try testing.expectError(zs.Error.ZipWriteTooLarge, w.addEntry("a", "x", .{ .mtime = 1_700_000_000, .force_zip64 = true, .encryption = enc, .extra = big }));
    try testing.expectError(zs.Error.ZipWriteTooLarge, w.beginEntry("a", .{ .mtime = 1_700_000_000, .force_zip64 = true, .encryption = enc, .extra = big }));
    // the documented limit: 65487 = 65535 - 9 - 28 - 11
    try testing.expectError(zs.Error.ZipWriteTooLarge, w.addEntry("a", "x", .{ .extra = big[0..65488] }));
    try w.addEntry("a", "x", .{ .mtime = 1_700_000_000, .force_zip64 = true, .encryption = enc, .extra = big[0..65487] });
    try w.finish();
    // and the archive it wrote is readable
    var ms: zs.MemorySource = .{ .bytes = aw.written() };
    var archive: zs.Archive = undefined;
    try archive.initSource(gpa, ms.source(), .{});
    defer archive.deinit();
    try testing.expectEqual(@as(usize, 1), archive.entries.items.len);
}

test "a symlink target past 4 GiB without zip64 is refused before anything is read (sweep ZS-4)" {
    const gpa = testing.allocator;
    const n: usize = std.math.maxInt(u32) + 1;
    // Never dereferenced when the size check runs first (a real 4 GiB buffer
    // gets the test killed under the shared memory budget).
    const target = @as([*]const u8, @ptrFromInt(0x1000))[0..n];
    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    var w = newWriter(&aw);
    defer w.deinit();
    w.allow_zip64 = false;
    try testing.expectError(zs.Error.ZipWriteTooLarge, w.addSymlink("l", target, .{}));
    try testing.expectEqual(@as(usize, 0), aw.written().len);
}

test "the zstd window limit is an Archive option: a frame asking for more is refused (sweep ZS-5)" {
    const gpa = testing.allocator;
    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    var w = newWriter(&aw);
    defer w.deinit();
    var data: [300_000]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = "zstd window limit "[i % 18];
    try w.addEntry("z", &data, .{ .method = .zstd });
    try w.finish();
    var ms: zs.MemorySource = .{ .bytes = aw.written() };
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    // default (27): reads
    {
        var archive: zs.Archive = undefined;
        try archive.initSource(gpa, ms.source(), .{});
        defer archive.deinit();
        var er: zs.EntryReader = undefined;
        try er.open(&archive, archive.find("z").?, &window, .{});
        defer er.deinit();
        const got = try er.reader().allocRemaining(gpa, .unlimited);
        defer gpa.free(got);
        try testing.expectEqualSlices(u8, &data, got);
    }
    // 10 (1 KiB; the encoder's window is larger): refused while reading
    {
        var archive: zs.Archive = undefined;
        try archive.initSource(gpa, ms.source(), .{ .zstd_window_log_max = 10 });
        defer archive.deinit();
        var er: zs.EntryReader = undefined;
        try er.open(&archive, archive.find("z").?, &window, .{});
        defer er.deinit();
        try testing.expectError(error.ReadFailed, er.reader().allocRemaining(gpa, .unlimited));
    }
}

test "extractAll drops setuid/setgid/sticky unless restore_special_bits (sweep ZS-7)" {
    if (!@hasDecl(std.Io.File.Permissions, "fromMode")) return error.SkipZigTest;
    const a = testing.allocator;
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var zw = newWriter(&aw);
    defer zw.deinit();
    try zw.addEntry("s", "x", .{ .mode = 0o6755 });
    try zw.finish();
    var ms: zs.MemorySource = .{ .bytes = aw.written() };
    var archive: zs.Archive = undefined;
    try archive.initSource(a, ms.source(), .{});
    defer archive.deinit();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try zs.extractAll(&archive, testing.io, tmp.dir, .{});
    const st = try tmp.dir.statFile(testing.io, "s", .{});
    try testing.expectEqual(@as(u32, 0o755), @as(u32, @intCast(st.permissions.toMode() & 0o7777)));

    var tmp2 = testing.tmpDir(.{});
    defer tmp2.cleanup();
    try zs.extractAll(&archive, testing.io, tmp2.dir, .{ .restore_special_bits = true });
    const st2 = try tmp2.dir.statFile(testing.io, "s", .{});
    try testing.expectEqual(@as(u32, 0o6755), @as(u32, @intCast(st2.permissions.toMode() & 0o7777)));
}

fn oneEntryArchive(aw: *std.Io.Writer.Allocating, name: []const u8, data: []const u8, opts: zs.AddEntryOptions) !void {
    var w = newWriter(aw);
    defer w.deinit();
    try w.addEntry(name, data, opts);
    try w.finish();
}

test "deinit after a failed open of an encrypted entry without a password is safe (sweep R-ZS-1)" {
    const gpa = testing.allocator;
    const salt: [16]u8 = @splat(3);
    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    try oneEntryArchive(&aw, "e", "secret", .{ .encryption = .{ .password = "pw", .salt = &salt } });
    var ms: zs.MemorySource = .{ .bytes = aw.written() };
    var archive: zs.Archive = undefined;
    try archive.initSource(gpa, ms.source(), .{});
    defer archive.deinit();
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var er: zs.EntryReader = undefined; // `undefined` is 0xaa in Debug: a garbage codec
    defer er.deinit();
    try testing.expectError(zs.Error.ZipEncryptedEntry, er.open(&archive, archive.find("e").?, &window, .{}));
}

test "addSymlink and addDirectory ignore options.encryption: the archive reads back (sweep R-ZS-3)" {
    const gpa = testing.allocator;
    const salt: [16]u8 = @splat(3);
    const enc: zs.AddEntryOptions.Encryption = .{ .password = "pw", .salt = &salt };
    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    var w = newWriter(&aw);
    defer w.deinit();
    try w.addSymlink("l", "target.txt", .{ .encryption = enc });
    try w.addDirectory("d", .{ .encryption = enc });
    try w.finish();
    var ms: zs.MemorySource = .{ .bytes = aw.written() };
    var archive: zs.Archive = undefined;
    try archive.initSource(gpa, ms.source(), .{});
    defer archive.deinit();
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var er: zs.EntryReader = undefined;
    try er.open(&archive, archive.find("l").?, &window, .{});
    defer er.deinit();
    const got = try er.reader().allocRemaining(gpa, .unlimited);
    defer gpa.free(got);
    try testing.expectEqualStrings("target.txt", got);
}

test "addDirectory with force_zip64 and no zip64 allowed fails before anything is written (sweep R-ZS-4)" {
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    var w = newWriter(&aw);
    defer w.deinit();
    w.allow_zip64 = false;
    try testing.expectError(zs.Error.ZipWriteTooLarge, w.addDirectory("d", .{ .force_zip64 = true }));
    try testing.expectEqual(@as(usize, 0), aw.written().len);
    try w.addEntry("ok", "x", .{});
    try w.finish();
}

test "a forged entry count reserves little memory (sweep R-ZS-5)" {
    var buf: [2 * 1024 * 1024]u8 = undefined;
    @memset(&buf, 0);
    @memcpy(buf[0..4], &std.zip.central_file_header_sig);
    eocd(buf[buf.len - 22 ..], 60000, buf.len - 22, 0);
    var ms: zs.MemorySource = .{ .bytes = &buf };
    var fa = std.testing.FailingAllocator.init(testing.allocator, .{});
    var archive: zs.Archive = undefined;
    if (archive.initSource(fa.allocator(), ms.source(), .{})) |_| {
        archive.deinit();
    } else |_| {}
    // the file could hold ~45000 records; reserving for them all is >= 45000 * sizeof(Entry)
    try testing.expect(fa.allocated_bytes < 10_000 * @sizeOf(zs.Entry));
}

test "a Unicode Path extra cannot smuggle in a name past the path limit (sweep R-ZS-6)" {
    const gpa = testing.allocator;
    const long: [5000]u8 = @splat('x');
    var extra: [4 + 5 + long.len]u8 = undefined;
    std.mem.writeInt(u16, extra[0..2], 0x7075, .little);
    std.mem.writeInt(u16, extra[2..4], 5 + long.len, .little);
    extra[4] = 1;
    std.mem.writeInt(u32, extra[5..9], std.hash.Crc32.hash("a"), .little);
    @memcpy(extra[9..], &long);
    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    try oneEntryArchive(&aw, "a", "x", .{ .extra = &extra });
    var ms: zs.MemorySource = .{ .bytes = aw.written() };
    var archive: zs.Archive = undefined;
    try testing.expectError(zs.Error.ZipNameTooLong, archive.initSource(gpa, ms.source(), .{}));
}

test "extractAll removes the file of an entry that fails its CRC (sweep R-ZS-7)" {
    const gpa = testing.allocator;
    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    try oneEntryArchive(&aw, "f", "hello world, hello world", .{ .method = .store });
    const bytes = try gpa.dupe(u8, aw.written());
    defer gpa.free(bytes);
    const at = std.mem.find(u8, bytes, "hello world").?;
    bytes[at] ^= 0xff;
    var ms: zs.MemorySource = .{ .bytes = bytes };
    var archive: zs.Archive = undefined;
    try archive.initSource(gpa, ms.source(), .{});
    defer archive.deinit();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    if (zs.extractAll(&archive, testing.io, tmp.dir, .{})) |_| return error.TestUnexpectedResult else |_| {}
    try testing.expectError(error.FileNotFound, tmp.dir.statFile(testing.io, "f", .{}));
}

test "a local header offset past the end is ZipBadFileOffset even when the source errors there (sweep R-ZS-10)" {
    const gpa = testing.allocator;
    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    try oneEntryArchive(&aw, "f", "data", .{});
    const Strict = struct {
        mem: zs.MemorySource,
        fn readAt(ctx: *const anyopaque, offset: u64, buf: []u8) error{ReadFailed}!usize {
            const self: *const @This() = @ptrCast(@alignCast(ctx));
            if (offset >= self.mem.bytes.len) return error.ReadFailed; // as pread's EINVAL
            return self.mem.source().readAt(offset, buf);
        }
    };
    var strict: Strict = .{ .mem = .{ .bytes = aw.written() } };
    const src: zs.Source = .{ .context = &strict, .read_at = Strict.readAt, .size = aw.written().len };
    var archive: zs.Archive = undefined;
    try archive.initSource(gpa, src, .{});
    defer archive.deinit();
    archive.entries.items[0].file_offset = std.math.maxInt(u64) - 5;
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var er: zs.EntryReader = undefined;
    try testing.expectError(zs.Error.ZipBadFileOffset, er.open(&archive, archive.find("f").?, &window, .{}));
}

test "a local header offset equal to the source size is ZipBadFileOffset (sweep audit GM-ZS-11)" {
    const gpa = testing.allocator;
    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    try oneEntryArchive(&aw, "f", "data", .{});
    var ms: zs.MemorySource = .{ .bytes = aw.written() };
    var archive: zs.Archive = undefined;
    try archive.initSource(gpa, ms.source(), .{});
    defer archive.deinit();
    archive.entries.items[0].file_offset = aw.written().len;
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var er: zs.EntryReader = undefined;
    try testing.expectError(zs.Error.ZipBadFileOffset, er.open(&archive, archive.find("f").?, &window, .{}));
}

test "deinit after a failed open sees a cleared codec even when the reader held garbage (sweep audit GM-ZS-9)" {
    const gpa = testing.allocator;
    const salt: [16]u8 = @splat(3);
    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    try oneEntryArchive(&aw, "e", "secret", .{ .encryption = .{ .password = "pw", .salt = &salt } });
    var ms: zs.MemorySource = .{ .bytes = aw.written() };
    var archive: zs.Archive = undefined;
    try archive.initSource(gpa, ms.source(), .{});
    defer archive.deinit();
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var er: zs.EntryReader = undefined;
    // A stale codec whose close must never run: `open` has to clear it before its first return.
    const Boom = struct {
        fn close(_: *anyopaque, _: std.mem.Allocator) void {
            @panic("stale codec closed by deinit after a failed open");
        }
    };
    var dummy: u8 = 0;
    er.codec = .{ .reader = undefined, .state = &dummy, .close = Boom.close };
    defer er.deinit();
    try testing.expectError(zs.Error.ZipEncryptedEntry, er.open(&archive, archive.find("e").?, &window, .{}));
}

test "addDirectory writes an unencrypted stored header when asked to encrypt (sweep audit GM-ZS-18)" {
    const salt: [16]u8 = @splat(3);
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    var w = newWriter(&aw);
    defer w.deinit();
    try w.addDirectory("d", .{ .encryption = .{ .password = "pw", .salt = &salt } });
    const b = aw.written();
    // local header: flags at 6 (bit 0 = encrypted), method at 8 (99 = AES)
    try testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, b[6..8], .little) & 1);
    try testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, b[8..10], .little));
}
