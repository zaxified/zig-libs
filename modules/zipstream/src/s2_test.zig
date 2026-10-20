// SPDX-License-Identifier: MIT
//! The 2026-10-20 reader and writer features: any `Source` (memory, file),
//! independent entry cursors (concurrent reads), streamed writes with a
//! data descriptor, zip64 writing, comments, raw extra fields, directory and
//! symlink entries, the Info-ZIP Unicode Path field.

const std = @import("std");
const testing = std.testing;
const zs = @import("root.zig");

fn readAll(a: std.mem.Allocator, archive: *zs.Archive, e: *const zs.Entry) ![]u8 {
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var er: zs.EntryReader = undefined;
    try er.init(archive, e, &window);
    defer er.deinit();
    var out: std.Io.Writer.Allocating = .init(a);
    errdefer out.deinit();
    _ = try er.reader().streamRemaining(&out.writer);
    return out.toOwnedSlice();
}

fn pattern(a: std.mem.Allocator, n: usize, seed: u64) ![]u8 {
    const buf = try a.alloc(u8, n);
    var prng = std.Random.DefaultPrng.init(seed);
    const words = [_][]const u8{ "<row>", "<c r=\"A1\">", "42", "</c>", "text ", "Příliš ", "\n" };
    var i: usize = 0;
    while (i < n) {
        const w = words[prng.random().uintLessThan(usize, words.len)];
        const k = @min(w.len, n - i);
        @memcpy(buf[i..][0..k], w[0..k]);
        i += k;
    }
    return buf;
}

test "streamed entries (store and deflate, any write sizes) read back byte-exact" {
    const a = testing.allocator;
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var zw = zs.ArchiveWriter.init(a, &aw.writer);
    defer zw.deinit();
    const sizes = [_]usize{ 0, 1, 100, 4095, 4096, 70_000, 300_000 };
    var datas: [sizes.len * 2][]u8 = undefined;
    defer for (datas) |d| a.free(d);
    for (sizes, 0..) |n, i| {
        for ([_]zs.WriteMethod{ .store, .deflate }, 0..) |m, k| {
            const d = try pattern(a, n, i * 2 + k);
            datas[i * 2 + k] = d;
            var name_buf: [32]u8 = undefined;
            const name = try std.fmt.bufPrint(&name_buf, "f{d}-{t}.xml", .{ n, m });
            const w = try zw.beginEntry(name, .{ .method = m, .mtime = 1_700_000_000 });
            // Uneven chunks.
            var off: usize = 0;
            var step: usize = 1;
            while (off < d.len) : (step = (step * 3 + 1) % 100_003) {
                const c = @min(step % 9000 + 1, d.len - off);
                try w.writeAll(d[off..][0..c]);
                off += c;
            }
            try zw.endEntry();
        }
    }
    try zw.finish();

    var ms: zs.MemorySource = .{ .bytes = aw.written() };
    var archive: zs.Archive = undefined;
    try archive.initSource(a, ms.source(), .{});
    defer archive.deinit();
    try testing.expectEqual(datas.len, archive.entries.items.len);
    for (archive.entries.items, 0..) |*e, i| {
        try testing.expect(e.flags & (1 << 3) != 0); // data descriptor
        const got = try readAll(a, &archive, e);
        defer a.free(got);
        try testing.expectEqualSlices(u8, datas[i], got);
        try testing.expectEqual(@as(?i64, 1_700_000_000), e.mtime);
    }
}

test "forced zip64 entries (addEntry and beginEntry) read back, sizes from the zip64 extra" {
    const a = testing.allocator;
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var zw = zs.ArchiveWriter.init(a, &aw.writer);
    defer zw.deinit();
    const d = try pattern(a, 50_000, 9);
    defer a.free(d);
    try zw.addEntry("buffered.xml", d, .{ .force_zip64 = true });
    const w = try zw.beginEntry("streamed.xml", .{ .force_zip64 = true, .method = .store });
    try w.writeAll(d);
    try zw.endEntry();
    try zw.addEntry("plain.txt", "plain", .{ .method = .store });
    try zw.finish();
    const bytes = aw.written();

    var ms: zs.MemorySource = .{ .bytes = bytes };
    var archive: zs.Archive = undefined;
    try archive.initSource(a, ms.source(), .{});
    defer archive.deinit();
    try testing.expectEqual(@as(usize, 3), archive.entries.items.len);
    for (archive.entries.items[0..2]) |*e| {
        try testing.expectEqual(@as(u64, d.len), e.uncompressed_size);
        const got = try readAll(a, &archive, e);
        defer a.free(got);
        try testing.expectEqualSlices(u8, d, got);
    }

    // std.zip's iterator (an independent central-directory reader) sees the
    // same sizes and CRCs.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "z.zip", .data = bytes });
    var f = try tmp.dir.openFile(testing.io, "z.zip", .{});
    defer f.close(testing.io);
    var buf: [4096]u8 = undefined;
    var fr = f.reader(testing.io, &buf);
    var iter = try std.zip.Iterator.init(&fr);
    var n: usize = 0;
    while (try iter.next()) |e| : (n += 1) {
        const want = archive.entries.items[n];
        try testing.expectEqual(want.uncompressed_size, e.uncompressed_size);
        try testing.expectEqual(want.compressed_size, e.compressed_size);
        try testing.expectEqual(want.crc32, e.crc32);
    }
    try testing.expectEqual(@as(usize, 3), n);
}

test "comments, caller extra, directories, symlinks round-trip" {
    const a = testing.allocator;
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var zw = zs.ArchiveWriter.init(a, &aw.writer);
    defer zw.deinit();
    // A caller extra record: id 0xCAFE, 3 bytes.
    const extra = "\xfe\xca\x03\x00abc";
    try zw.addDirectory("docs", .{ .mtime = 1_600_000_000 });
    try zw.addEntry("docs/a.txt", "A", .{ .comment = "entry comment", .extra = extra, .mode = 0o640 });
    try zw.addSymlink("docs/link", "a.txt", .{});
    zw.comment = "archive comment";
    try zw.finish();

    var ms: zs.MemorySource = .{ .bytes = aw.written() };
    var plain: zs.Archive = undefined;
    try plain.initSource(a, ms.source(), .{});
    defer plain.deinit();
    try testing.expectEqual(@as(usize, 2), plain.entries.items.len); // directory skipped by default
    try testing.expectEqualStrings("archive comment", plain.comment);

    var archive: zs.Archive = undefined;
    try archive.initSource(a, ms.source(), .{ .list_directories = true });
    defer archive.deinit();
    const es = archive.entries.items;
    try testing.expectEqual(@as(usize, 3), es.len);
    try testing.expectEqualStrings("docs/", es[0].name);
    try testing.expect(es[0].is_directory and !es[0].isSymlink());
    try testing.expectEqual(@as(?u16, 0o755), es[0].mode);
    try testing.expectEqualStrings("entry comment", es[1].comment);
    try testing.expect(std.mem.indexOf(u8, es[1].extra, extra) != null);
    try testing.expectEqual(@as(?u16, 0o640), es[1].mode);
    try testing.expect(es[2].isSymlink());
    const target = try readAll(a, &archive, &es[2]);
    defer a.free(target);
    try testing.expectEqualStrings("a.txt", target);
}

test "Info-ZIP Unicode Path (0x7075) supplies a UTF-8 name while its CRC matches" {
    const a = testing.allocator;
    // A CP437 name ("\x9f" ...) with a 0x7075 record naming it "č.txt".
    const raw = "\x87.txt";
    const utf8 = "č.txt";
    var up: [4 + 5 + utf8.len]u8 = undefined;
    std.mem.writeInt(u16, up[0..2], 0x7075, .little);
    std.mem.writeInt(u16, up[2..4], 5 + utf8.len, .little);
    up[4] = 1;
    std.mem.writeInt(u32, up[5..9], std.hash.Crc32.hash(raw), .little);
    @memcpy(up[9..], utf8);
    var stale = up;
    std.mem.writeInt(u32, stale[5..9], 0, .little);

    for ([_]struct { []const u8, []const u8, bool }{ .{ &up, utf8, true }, .{ &stale, raw, false } }) |c| {
        var aw: std.Io.Writer.Allocating = .init(a);
        defer aw.deinit();
        var zw = zs.ArchiveWriter.init(a, &aw.writer);
        defer zw.deinit();
        try zw.addEntry(raw, "x", .{ .extra = c[0], .method = .store });
        try zw.finish();
        var ms: zs.MemorySource = .{ .bytes = aw.written() };
        var archive: zs.Archive = undefined;
        try archive.initSource(a, ms.source(), .{});
        defer archive.deinit();
        try testing.expectEqualStrings(c[1], archive.entries.items[0].name);
        try testing.expectEqual(c[2], archive.entries.items[0].name_is_utf8);
    }
}

test "several entries read at once from one Archive, from several threads" {
    const a = testing.allocator;
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var zw = zs.ArchiveWriter.init(a, &aw.writer);
    defer zw.deinit();
    var datas: [4][]u8 = undefined;
    defer for (datas) |d| a.free(d);
    for (&datas, 0..) |*d, i| {
        d.* = try pattern(a, 200_000 + i * 1000, 100 + i);
        var nb: [8]u8 = undefined;
        try zw.addEntry(try std.fmt.bufPrint(&nb, "p{d}", .{i}), d.*, .{});
    }
    try zw.finish();

    // Interleaved on one thread: two readers alive at once.
    var ms: zs.MemorySource = .{ .bytes = aw.written() };
    var archive: zs.Archive = undefined;
    try archive.initSource(a, ms.source(), .{});
    defer archive.deinit();
    var w0: [std.compress.flate.max_window_len]u8 = undefined;
    var w1: [std.compress.flate.max_window_len]u8 = undefined;
    var r0: zs.EntryReader = undefined;
    var r1: zs.EntryReader = undefined;
    try r0.init(&archive, &archive.entries.items[0], &w0);
    try r1.init(&archive, &archive.entries.items[1], &w1);
    var got0: std.ArrayList(u8) = .empty;
    defer got0.deinit(a);
    var got1: std.ArrayList(u8) = .empty;
    defer got1.deinit(a);
    var chunk: [777]u8 = undefined;
    while (true) {
        const n0 = try r0.reader().readSliceShort(&chunk);
        try got0.appendSlice(a, chunk[0..n0]);
        const n1 = try r1.reader().readSliceShort(&chunk);
        try got1.appendSlice(a, chunk[0..n1]);
        if (n0 == 0 and n1 == 0) break;
    }
    try testing.expectEqualSlices(u8, datas[0], got0.items);
    try testing.expectEqualSlices(u8, datas[1], got1.items);

    // Threads over a file source: every entry, each in its own thread.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "t.zip", .data = aw.written() });
    var f = try tmp.dir.openFile(testing.io, "t.zip", .{});
    defer f.close(testing.io);
    var fa: zs.Archive = undefined;
    try fa.init(testing.io, a, f);
    defer fa.deinit();
    const Worker = struct {
        fn run(ar: *zs.Archive, e: *const zs.Entry, want: []const u8, ok: *bool) void {
            const got = readAll(std.heap.page_allocator, ar, e) catch return;
            defer std.heap.page_allocator.free(got);
            ok.* = std.mem.eql(u8, got, want);
        }
    };
    var oks: [4]bool = @splat(false);
    var threads: [4]std.Thread = undefined;
    for (&threads, 0..) |*t, i| t.* = try std.Thread.spawn(.{}, Worker.run, .{ &fa, &fa.entries.items[i], datas[i], &oks[i] });
    for (threads) |t| t.join();
    for (oks) |ok| try testing.expect(ok);
}

test "Zstandard entries (method 93), buffered and streamed, round-trip; a custom codec plugs in" {
    const a = testing.allocator;
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var zw = zs.ArchiveWriter.init(a, &aw.writer);
    defer zw.deinit();
    const d = try pattern(a, 150_000, 77);
    defer a.free(d);
    try zw.addEntry("z.xml", d, .{ .method = .zstd });
    const w = try zw.beginEntry("zs.xml", .{ .method = .zstd, .codec_level = 9 });
    try w.writeAll(d);
    try zw.endEntry();
    // A toy codec, method 99: XOR 0x5A, stored otherwise.
    const Xor = struct {
        const S = struct { inner: *std.Io.Reader, iface: std.Io.Reader, buf: [64]u8 };
        fn open(_: ?*anyopaque, gpa: std.mem.Allocator, input: *std.Io.Reader, _: zs.CodecEntry) anyerror!zs.CodecReader {
            const s = try gpa.create(S);
            s.inner = input;
            s.iface = .{ .vtable = &.{ .stream = stream }, .buffer = &s.buf, .seek = 0, .end = 0 };
            return .{ .reader = &s.iface, .state = s, .close = close };
        }
        fn stream(r: *std.Io.Reader, wr: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
            const s: *S = @alignCast(@fieldParentPtr("iface", r));
            const dest = limit.slice(try wr.writableSliceGreedy(1));
            const n = try s.inner.readSliceShort(dest);
            if (n == 0) return error.EndOfStream;
            for (dest[0..n]) |*b| b.* ^= 0x5A;
            wr.advance(n);
            return n;
        }
        fn close(state: *anyopaque, gpa: std.mem.Allocator) void {
            gpa.destroy(@as(*S, @ptrCast(@alignCast(state))));
        }
    };
    var xored: [5]u8 = "hello".*;
    for (&xored) |*b| b.* ^= 0x5A;
    try zw.addEntry("x.bin", &xored, .{ .method = .store }); // written as stored bytes …
    try zw.finish();
    // … then relabelled method 99 in both headers, as a foreign writer would emit it.
    const bytes = try a.dupe(u8, aw.written());
    defer a.free(bytes);
    var i: usize = 0;
    while (std.mem.findPos(u8, bytes, i, "x.bin")) |at| : (i = at + 1) {
        // the method field sits 18 (local) or 20 (central) bytes before the name … find by header kind
        const lh = at - 30;
        if (std.mem.eql(u8, bytes[lh..][0..4], &std.zip.local_file_header_sig)) std.mem.writeInt(u16, bytes[lh + 8 ..][0..2], 99, .little);
        const ch = at - 46;
        if (at >= 46 and std.mem.eql(u8, bytes[ch..][0..4], &std.zip.central_file_header_sig)) std.mem.writeInt(u16, bytes[ch + 10 ..][0..2], 99, .little);
    }
    // The CRC was of the XORed bytes; the decoded entry is "hello", so fix the CRC too.
    const good_crc = std.hash.Crc32.hash("hello");
    var j: usize = 0;
    while (std.mem.findPos(u8, bytes, j, "x.bin")) |at| : (j = at + 1) {
        const lh = at - 30;
        if (std.mem.eql(u8, bytes[lh..][0..4], &std.zip.local_file_header_sig)) std.mem.writeInt(u32, bytes[lh + 14 ..][0..4], good_crc, .little);
        if (at >= 46 and std.mem.eql(u8, bytes[at - 46 ..][0..4], &std.zip.central_file_header_sig)) std.mem.writeInt(u32, bytes[at - 46 + 16 ..][0..4], good_crc, .little);
    }

    var ms: zs.MemorySource = .{ .bytes = bytes };
    var plain: zs.Archive = undefined;
    try plain.initSource(a, ms.source(), .{});
    defer plain.deinit();
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var er: zs.EntryReader = undefined;
    try testing.expectError(error.UnsupportedCompressionMethod, er.init(&plain, plain.find("x.bin").?, &window));

    const codecs = [_]zs.Codec{.{ .method = 99, .open_reader = Xor.open }};
    var archive: zs.Archive = undefined;
    try archive.initSource(a, ms.source(), .{ .codecs = &codecs });
    defer archive.deinit();
    for ([_][]const u8{ "z.xml", "zs.xml" }) |n| {
        const e = archive.find(n).?;
        try testing.expectEqual(@as(u16, 93), @backingInt(e.compression));
        try testing.expect(e.compressed_size < e.uncompressed_size / 3);
        var r: zs.EntryReader = undefined;
        try r.init(&archive, e, &window);
        defer r.deinit();
        var out: std.Io.Writer.Allocating = .init(a);
        defer out.deinit();
        _ = try r.reader().streamRemaining(&out.writer);
        try testing.expectEqualSlices(u8, d, out.written());
    }
    var xr: zs.EntryReader = undefined;
    try xr.init(&archive, archive.find("x.bin").?, &window);
    defer xr.deinit();
    var out: std.Io.Writer.Allocating = .init(a);
    defer out.deinit();
    _ = try xr.reader().streamRemaining(&out.writer);
    try testing.expectEqualStrings("hello", out.written());
}

test "legacy CP437 names decode with legacy_names = .cp437 and stay raw by default" {
    const a = testing.allocator;
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var zw = zs.ArchiveWriter.init(a, &aw.writer);
    defer zw.deinit();
    try zw.addEntry("\x9fapek.txt", "x", .{ .method = .store }); // 0x9F = ƒ in CP437
    try zw.finish();
    var ms: zs.MemorySource = .{ .bytes = aw.written() };
    var raw: zs.Archive = undefined;
    try raw.initSource(a, ms.source(), .{});
    defer raw.deinit();
    try testing.expectEqualStrings("\x9fapek.txt", raw.entries.items[0].name);
    try testing.expect(!raw.entries.items[0].name_is_utf8);
    var dec: zs.Archive = undefined;
    try dec.initSource(a, ms.source(), .{ .legacy_names = .cp437 });
    defer dec.deinit();
    try testing.expectEqualStrings("ƒapek.txt", dec.entries.items[0].name);
    try testing.expect(dec.entries.items[0].name_is_utf8);
}

test "extractAll: files, directories, mode and mtime; zip slip and symlink policy" {
    const a = testing.allocator;
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var zw = zs.ArchiveWriter.init(a, &aw.writer);
    defer zw.deinit();
    try zw.addDirectory("d", .{});
    try zw.addEntry("d/f.txt", "content", .{ .mode = 0o640, .mtime = 1_600_000_000 });
    try zw.addEntry("g/h/deep.txt", "deep", .{});
    try zw.addSymlink("d/ln", "f.txt", .{});
    try zw.finish();
    var ms: zs.MemorySource = .{ .bytes = aw.written() };
    var archive: zs.Archive = undefined;
    try archive.initSource(a, ms.source(), .{ .list_directories = true });
    defer archive.deinit();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try zs.extractAll(&archive, testing.io, tmp.dir, .{ .symlinks = .create });
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("content", try tmp.dir.readFile(testing.io, "d/f.txt", &buf));
    try testing.expectEqualStrings("deep", try tmp.dir.readFile(testing.io, "g/h/deep.txt", &buf));
    try testing.expectEqualStrings("content", try tmp.dir.readFile(testing.io, "d/ln", &buf));
    const st = try tmp.dir.statFile(testing.io, "d/f.txt", .{});
    try testing.expectEqual(@as(i96, 1_600_000_000), @divFloor(st.mtime.nanoseconds, std.time.ns_per_s));
    // A second run refuses to overwrite.
    try testing.expectError(error.PathAlreadyExists, zs.extractAll(&archive, testing.io, tmp.dir, .{}));
    // Symlink refusal; and an escaping symlink target is refused even with .create.
    var tmp2 = testing.tmpDir(.{});
    defer tmp2.cleanup();
    try testing.expectError(error.ZipUnsafeSymlink, zs.extractAll(&archive, testing.io, tmp2.dir, .{ .symlinks = .refuse }));
    var bw: std.Io.Writer.Allocating = .init(a);
    defer bw.deinit();
    var bz = zs.ArchiveWriter.init(a, &bw.writer);
    defer bz.deinit();
    try bz.addSymlink("evil", "../../etc/passwd", .{});
    try bz.finish();
    var ms2: zs.MemorySource = .{ .bytes = bw.written() };
    var evil: zs.Archive = undefined;
    try evil.initSource(a, ms2.source(), .{});
    defer evil.deinit();
    var tmp3 = testing.tmpDir(.{});
    defer tmp3.cleanup();
    try testing.expectError(error.ZipUnsafeSymlink, zs.extractAll(&evil, testing.io, tmp3.dir, .{ .symlinks = .create }));
    // The total-size cap.
    var tmp4 = testing.tmpDir(.{});
    defer tmp4.cleanup();
    try testing.expectError(error.ZipExtractTooLarge, zs.extractAll(&archive, testing.io, tmp4.dir, .{ .max_total = 8 }));
}

test "bzip2 (method 12): Python zipfile's archive reads; ours round-trips, buffered and streamed" {
    const a = testing.allocator;
    var ms: zs.MemorySource = .{ .bytes = @embedFile("testdata/py_bzip2.zip") };
    var py: zs.Archive = undefined;
    try py.initSource(a, ms.source(), .{});
    defer py.deinit();
    var big: std.Io.Writer.Allocating = .init(a);
    defer big.deinit();
    for (0..300) |i| try big.writer.print("line {d}: Příliš žluťoučký kůň úpěl ďábelské ódy\n", .{i});
    for ([_]struct { []const u8, []const u8 }{ .{ "big.txt", big.written() }, .{ "tiny.txt", "tiny\n" } }) |c| {
        const e = py.find(c[0]).?;
        try testing.expectEqual(@as(u16, 12), @backingInt(e.compression));
        const got = try readAll(a, &py, e);
        defer a.free(got);
        try testing.expectEqualSlices(u8, c[1], got);
    }

    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var zw = zs.ArchiveWriter.init(a, &aw.writer);
    defer zw.deinit();
    const d = try pattern(a, 300_000, 5);
    defer a.free(d);
    try zw.addEntry("b.xml", d, .{ .method = .bzip2, .codec_level = 1 });
    const w = try zw.beginEntry("bs.xml", .{ .method = .bzip2 });
    try w.writeAll(d);
    try zw.endEntry();
    try zw.finish();
    var ms2: zs.MemorySource = .{ .bytes = aw.written() };
    var archive: zs.Archive = undefined;
    try archive.initSource(a, ms2.source(), .{});
    defer archive.deinit();
    for (archive.entries.items) |*e| {
        try testing.expect(e.compressed_size < e.uncompressed_size / 2);
        const got = try readAll(a, &archive, e);
        defer a.free(got);
        try testing.expectEqualSlices(u8, d, got);
    }
}

test "LZMA (14) from Python zipfile reads; LZMA and XZ (95) round-trip, buffered and streamed" {
    const a = testing.allocator;
    var ms: zs.MemorySource = .{ .bytes = @embedFile("testdata/py_lzma.zip") };
    var py: zs.Archive = undefined;
    try py.initSource(a, ms.source(), .{});
    defer py.deinit();
    var big: std.Io.Writer.Allocating = .init(a);
    defer big.deinit();
    for (0..300) |i| try big.writer.print("line {d}: Příliš žluťoučký kůň úpěl ďábelské ódy\n", .{i});
    for ([_]struct { []const u8, []const u8 }{ .{ "big.txt", big.written() }, .{ "tiny.txt", "tiny\n" } }) |c| {
        const e = py.find(c[0]).?;
        try testing.expectEqual(@as(u16, 14), @backingInt(e.compression));
        try testing.expect(e.flags & (1 << 1) != 0); // Python writes the end marker
        const got = try readAll(a, &py, e);
        defer a.free(got);
        try testing.expectEqualSlices(u8, c[1], got);
    }

    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var zw = zs.ArchiveWriter.init(a, &aw.writer);
    defer zw.deinit();
    const d = try pattern(a, 200_000, 9);
    defer a.free(d);
    try zw.addEntry("l.xml", d, .{ .method = .lzma, .codec_level = 1 });
    try zw.addEntry("x.xml", d, .{ .method = .xz, .codec_level = 1 });
    const w = try zw.beginEntry("ls.xml", .{ .method = .lzma, .codec_level = 1 });
    try w.writeAll(d);
    try zw.endEntry();
    try zw.finish();
    var ms2: zs.MemorySource = .{ .bytes = aw.written() };
    var archive: zs.Archive = undefined;
    try archive.initSource(a, ms2.source(), .{});
    defer archive.deinit();
    for (archive.entries.items) |*e| {
        try testing.expect(e.compressed_size < e.uncompressed_size / 2);
        const got = try readAll(a, &archive, e);
        defer a.free(got);
        try testing.expectEqualSlices(u8, d, got);
    }
    try testing.expect(archive.find("l.xml").?.flags & (1 << 1) != 0);
}
