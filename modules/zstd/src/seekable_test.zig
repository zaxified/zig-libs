// SPDX-License-Identifier: MIT
//! The seekable format against libzstd 1.5.7's `contrib/seekable_format`.
//!
//! Every `testdata/seekable_goldens.zig` row is compressed through
//! `SeekableStream` by the same call schedule `tools/zseekable.c` gave
//! `ZSTD_seekable_CStream`, and must have the recorded length and SHA-256;
//! then the result is read back through `Seekable` (whole, frame by frame,
//! at scattered ranges, continuing where the last read stopped) and through
//! the plain decoder, which must give the input.

const std = @import("std");
const zstd = @import("root.zig");
const seekable = @import("seekable.zig");
const corpus = @import("testdata/corpus.zig");
const goldens = @import("testdata/seekable_goldens.zig");

const gpa = std.testing.allocator;

fn findCase(name: []const u8) corpus.Case {
    for (corpus.cases) |c| if (std.mem.eql(u8, c.name, name)) return c;
    unreachable;
}

/// Drive a seekable stream over `src` as `tools/zseekable.c` does.
fn run(src: []const u8, g: goldens.Golden) ![]u8 {
    var s = try seekable.SeekableStream.init(gpa, .{ .level = g.level, .frame_checksums = g.checksum, .max_frame_size = g.max_frame_size });
    defer s.deinit();
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    const obuf = try gpa.alloc(u8, 1 << 20);
    defer gpa.free(obuf);
    var ocap: usize = 1 << 20;
    var fed: usize = 0;
    var it = std.mem.tokenizeScalar(u8, g.schedule, ',');
    while (it.next()) |tok| switch (tok[0]) {
        'o' => ocap = try std.fmt.parseInt(usize, tok[1..], 10),
        'c' => {
            const n = if (tok[1] == '*') src.len - fed else try std.fmt.parseInt(usize, tok[1..], 10);
            var in: zstd.InBuffer = .{ .src = src[fed..][0..n] };
            while (in.pos < in.src.len) {
                var o: zstd.OutBuffer = .{ .dst = obuf[0..ocap] };
                _ = try s.compressStream(&o, &in);
                try out.appendSlice(gpa, o.dst[0..o.pos]);
            }
            fed += n;
        },
        'f', 'e' => while (true) {
            var o: zstd.OutBuffer = .{ .dst = obuf[0..ocap] };
            const left = if (tok[0] == 'f') try s.endFrame(&o) else try s.endStream(&o);
            try out.appendSlice(gpa, o.dst[0..o.pos]);
            if (left == 0) break;
        },
        else => unreachable,
    };
    return out.toOwnedSlice(gpa);
}

/// Everything a reader can ask of `z`, checked against `src`.
fn readBack(z: []const u8, src: []const u8, g: goldens.Golden) !void {
    var r = try seekable.Seekable.init(gpa, .{ .bytes = z });
    defer r.deinit();
    const t = &r.table;
    try std.testing.expectEqual(src.len, t.decompressedSize());
    try std.testing.expectEqual(g.checksum, t.checksum_flag);
    const max: u64 = if (g.max_frame_size == 0) seekable.max_frame_decompressed_size else g.max_frame_size;
    // every frame full but the last (or empty ones the schedule ended)
    var total_c: u64 = 0;
    for (0..t.numFrames()) |i| {
        const d = try t.frameDecompressedSize(@intCast(i));
        try std.testing.expect(d <= max);
        try std.testing.expectEqual(total_c, try t.frameCompressedOffset(@intCast(i)));
        total_c += try t.frameCompressedSize(@intCast(i));
    }
    try std.testing.expectEqual(z.len - (8 + (@as(usize, if (g.checksum) 12 else 8)) * t.numFrames() + 9), total_c);
    try std.testing.expectError(error.FrameIndexTooLarge, t.frameDecompressedSize(t.numFrames()));

    const back = try gpa.alloc(u8, src.len + 1);
    defer gpa.free(back);
    // whole
    try std.testing.expectEqual(src.len, try r.decompress(back, 0));
    try std.testing.expectEqualSlices(u8, src, back[0..src.len]);
    // at and past the end: nothing
    try std.testing.expectEqual(@as(usize, 0), try r.decompress(back, src.len));
    try std.testing.expectEqual(@as(usize, 0), try r.decompress(back, src.len + 10));
    // the frame holding a position, and the frame count past the end
    try std.testing.expectEqual(t.numFrames(), t.offsetToFrameIndex(src.len));
    try std.testing.expectEqual(t.numFrames(), t.offsetToFrameIndex(src.len + 10));
    if (src.len > 0) {
        const last = t.offsetToFrameIndex(src.len - 1);
        try std.testing.expect(try t.frameDecompressedOffset(last) <= src.len - 1);
        try std.testing.expect(src.len - 1 < (try t.frameDecompressedOffset(last)) + (try t.frameDecompressedSize(last)));
    }
    // frame by frame
    var off: u64 = 0;
    for (0..t.numFrames()) |i| {
        const n = try r.decompressFrame(back, @intCast(i));
        try std.testing.expectEqualSlices(u8, src[@intCast(off)..][0..n], back[0..n]);
        off += n;
    }
    try std.testing.expectError(error.FrameIndexTooLarge, r.decompressFrame(back, t.numFrames()));
    // scattered ranges, including ones across frame edges, and a read that
    // continues where the previous stopped
    if (src.len > 0) {
        var prng: std.Random.DefaultPrng = .init(src.len);
        const rnd = prng.random();
        for (0..40) |_| {
            const a = rnd.uintLessThan(usize, src.len);
            const len = @min(src.len - a, 1 + rnd.uintLessThan(usize, 3000));
            try std.testing.expectEqual(len, try r.decompress(back[0..len], a));
            try std.testing.expectEqualSlices(u8, src[a..][0..len], back[0..len]);
            const b = a + len;
            const len2 = @min(src.len - b, 700);
            try std.testing.expectEqual(len2, try r.decompress(back[0..len2], b));
            try std.testing.expectEqualSlices(u8, src[b..][0..len2], back[0..len2]);
        }
    }
    // any zstd decoder reads the whole: frames, then a skippable frame
    const plain = try zstd.decompressAlloc(gpa, z, src.len);
    defer gpa.free(plain);
    try std.testing.expectEqualSlices(u8, src, plain);
}

test "seekable streams are byte-identical to libzstd 1.5.7's ZSTD_seekable_CStream, and read back" {
    var mismatches: usize = 0;
    for (goldens.rows) |g| {
        const case = findCase(g.case);
        const src = try gpa.alloc(u8, case.len);
        defer gpa.free(src);
        corpus.generate(case, src);
        const z = try run(src, g);
        defer gpa.free(z);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(z, &digest, .{});
        const hex = std.fmt.bytesToHex(digest, .lower);
        if (z.len != g.len or !std.mem.eql(u8, &hex, g.sha256)) {
            std.debug.print("MISMATCH {s} level {d} checksum {} max {d} {s}: len {d} (libzstd {d})\n", .{ g.case, g.level, g.checksum, g.max_frame_size, g.schedule, z.len, g.len });
            mismatches += 1;
            continue;
        }
        readBack(z, src, g) catch |e| {
            std.debug.print("READ BACK {s} {s}: {s}\n", .{ g.case, g.schedule, @errorName(e) });
            mismatches += 1;
        };
        // compressAlloc is the whole input in one call, then the end
        if (std.mem.eql(u8, g.schedule, "c*,e")) {
            const a = try seekable.compressAlloc(gpa, src, .{ .level = g.level, .frame_checksums = g.checksum, .max_frame_size = g.max_frame_size });
            defer gpa.free(a);
            if (!std.mem.eql(u8, a, z)) {
                std.debug.print("compressAlloc differs: {s}\n", .{g.case});
                mismatches += 1;
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 0), mismatches);
}

test "a reused stream gives a fresh one's bytes" {
    const case = findCase("words-16385");
    const src = try gpa.alloc(u8, case.len);
    defer gpa.free(src);
    corpus.generate(case, src);
    const fresh = try seekable.compressAlloc(gpa, src, .{ .level = 3, .frame_checksums = true, .max_frame_size = 4096 });
    defer gpa.free(fresh);
    var s = try seekable.SeekableStream.init(gpa, .{ .level = 19, .max_frame_size = 1000 });
    defer s.deinit();
    var buf: [1 << 16]u8 = undefined;
    for (0..2) |round| {
        try s.reset(if (round == 0) .{ .level = 19, .max_frame_size = 1000 } else .{ .level = 3, .frame_checksums = true, .max_frame_size = 4096 });
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        var in: zstd.InBuffer = .{ .src = src };
        while (in.pos < in.src.len) {
            var o: zstd.OutBuffer = .{ .dst = &buf };
            _ = try s.compressStream(&o, &in);
            try out.appendSlice(gpa, o.dst[0..o.pos]);
        }
        while (true) {
            var o: zstd.OutBuffer = .{ .dst = &buf };
            const left = try s.endStream(&o);
            try out.appendSlice(gpa, o.dst[0..o.pos]);
            if (left == 0) break;
        }
        if (round == 1) try std.testing.expectEqualSlices(u8, fresh, out.items);
    }
}

test "max_frame_size above 1 GiB is refused" {
    try std.testing.expectError(error.FrameParameterUnsupported, seekable.SeekableStream.init(gpa, .{ .max_frame_size = seekable.max_frame_decompressed_size + 1 }));
}

test "a seek table for frames made elsewhere (FrameLog)" {
    // three ordinary frames, then a table written by hand into a 5-byte
    // buffer at a time
    const parts = [_][]const u8{ "alpha " ** 50, "beta " ** 70, "gamma " ** 30 };
    var z: std.ArrayList(u8) = .empty;
    defer z.deinit(gpa);
    var log: seekable.FrameLog = .init(true);
    defer log.deinit(gpa);
    for (parts) |p| {
        const f = try zstd.compressAlloc(gpa, p, .{ .level = 5 });
        defer gpa.free(f);
        try z.appendSlice(gpa, f);
        try log.logFrame(gpa, @intCast(f.len), @intCast(p.len), @truncate(std.hash.XxHash64.hash(0, p)));
    }
    var buf: [5]u8 = undefined;
    while (true) {
        var o: zstd.OutBuffer = .{ .dst = &buf };
        const left = log.writeSeekTable(&o);
        try z.appendSlice(gpa, o.dst[0..o.pos]);
        if (left == 0) break;
    }
    var r = try seekable.Seekable.init(gpa, .{ .bytes = z.items });
    defer r.deinit();
    try std.testing.expectEqual(@as(u32, 3), r.numFrames());
    var back: [400]u8 = undefined;
    const n = try r.decompress(&back, parts[0].len - 3);
    const all = parts[0] ++ parts[1] ++ parts[2];
    try std.testing.expectEqualSlices(u8, all[parts[0].len - 3 ..][0..n], back[0..n]);
}

test "reading from a file (Source.file)" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const case = findCase("csv-131073");
    const src = try gpa.alloc(u8, case.len);
    defer gpa.free(src);
    corpus.generate(case, src);
    const z = try seekable.compressAlloc(gpa, src, .{ .max_frame_size = 20000, .frame_checksums = true });
    defer gpa.free(z);
    try tmp.dir.writeFile(io, .{ .sub_path = "s.zst", .data = z });
    const f = try tmp.dir.openFile(io, "s.zst", .{});
    defer f.close(io);
    var r = try seekable.Seekable.init(gpa, .{ .file = .{ .file = f, .io = io } });
    defer r.deinit();
    var back: [50000]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 50000), try r.decompress(&back, 70000));
    try std.testing.expectEqualSlices(u8, src[70000..][0..50000], &back);
}

test "damaged streams are refused as libzstd refuses them" {
    const case = findCase("words-16385");
    const src = try gpa.alloc(u8, case.len);
    defer gpa.free(src);
    corpus.generate(case, src);
    const z = try seekable.compressAlloc(gpa, src, .{ .max_frame_size = 4096, .frame_checksums = true });
    defer gpa.free(z);
    const bad = try gpa.dupe(u8, z);
    defer gpa.free(bad);
    var back: [20000]u8 = undefined;
    // (verdicts confirmed with tools/zseekable.c `d`: ERR 10 prefix_unknown,
    // 20 corruption_detected, 102 seekableIO)
    // the seekable magic number
    bad[bad.len - 1] ^= 1;
    try std.testing.expectError(error.PrefixUnknown, seekable.Seekable.init(gpa, .{ .bytes = bad }));
    @memcpy(bad, z);
    // a reserved bit of the descriptor
    bad[bad.len - 5] |= 1 << 2;
    try std.testing.expectError(error.CorruptionDetected, seekable.Seekable.init(gpa, .{ .bytes = bad }));
    @memcpy(bad, z);
    // the skippable frame's size field
    const table_start = bad.len - (8 + 12 * 5 + 9);
    bad[table_start + 4] ^= 1;
    try std.testing.expectError(error.PrefixUnknown, seekable.Seekable.init(gpa, .{ .bytes = bad }));
    @memcpy(bad, z);
    // a frame count whose table still fits the file: its header is not there
    bad[bad.len - 9] = 0xff;
    try std.testing.expectError(error.PrefixUnknown, seekable.Seekable.init(gpa, .{ .bytes = bad }));
    @memcpy(bad, z);
    // a frame count whose table is larger than the file
    bad[bad.len - 6] = 0x7f;
    try std.testing.expectError(error.SeekableIO, seekable.Seekable.init(gpa, .{ .bytes = bad }));
    @memcpy(bad, z);
    // a frame checksum: the frame reads, and is refused when it completes
    bad[table_start + 8 + 12 * 2 + 8] ^= 0x80;
    {
        var r = try seekable.Seekable.init(gpa, .{ .bytes = bad });
        defer r.deinit();
        try std.testing.expectEqual(@as(usize, 100), try r.decompress(back[0..100], 0));
        try std.testing.expectError(error.CorruptionDetected, r.decompress(&back, 8000));
    }
    @memcpy(bad, z);
    // truncated: the table is gone
    try std.testing.expectError(error.PrefixUnknown, seekable.Seekable.init(gpa, .{ .bytes = bad[0 .. bad.len - 20] }));
}

const MemSource = struct {
    bytes: []const u8,
    fn readAt(ctx: *anyopaque, buf: []u8, off: u64) error{ReadFailed}!void {
        const m: *MemSource = @ptrCast(@alignCast(ctx));
        if (off > m.bytes.len or buf.len > m.bytes.len - off) return error.ReadFailed;
        @memcpy(buf, m.bytes[@intCast(off)..][0..buf.len]);
    }
};

test "reset reads another source with the same buffers and decoder" {
    // a: small, in memory, checksums; b: larger, through a custom reader,
    // with frames of another size
    const ca = findCase("words-16385");
    const src_a = try gpa.alloc(u8, ca.len);
    defer gpa.free(src_a);
    corpus.generate(ca, src_a);
    const za = try seekable.compressAlloc(gpa, src_a, .{ .max_frame_size = 4096, .frame_checksums = true });
    defer gpa.free(za);
    const cb = findCase("csv-131073");
    const src_b = try gpa.alloc(u8, cb.len);
    defer gpa.free(src_b);
    corpus.generate(cb, src_b);
    const zb = try seekable.compressAlloc(gpa, src_b, .{ .max_frame_size = 20000 });
    defer gpa.free(zb);
    try std.testing.expect(zb.len > za.len);
    var mem: MemSource = .{ .bytes = zb };
    const source_b: seekable.Source = .{ .custom = .{ .context = &mem, .size = zb.len, .readAt = MemSource.readAt } };

    var fa: std.testing.FailingAllocator = .init(gpa, .{});
    var r = try seekable.Seekable.init(fa.allocator(), .{ .bytes = za });
    defer r.deinit();
    const back = try gpa.alloc(u8, src_b.len);
    defer gpa.free(back);
    // stop in the middle of a's frame 1
    try std.testing.expectEqual(@as(usize, 100), try r.decompress(back[0..100], 5000));

    // the only allocation is b's seek table; a's is freed
    const allocs = fa.allocations;
    const frees = fa.deallocations;
    try r.reset(source_b);
    try std.testing.expectEqual(allocs + 1, fa.allocations);
    try std.testing.expectEqual(frees + 1, fa.deallocations);
    try std.testing.expectEqual(@as(u64, src_b.len), r.table.decompressedSize());
    try std.testing.expect(!r.table.checksum_flag);
    // b's frame 1 at an offset past where a stopped: read from b's start
    // of that frame, not on from a's
    try std.testing.expectEqual(@as(usize, 300), try r.decompress(back[0..300], 25000));
    try std.testing.expectEqualSlices(u8, src_b[25000..][0..300], back[0..300]);
    // the whole of b, larger than a
    try std.testing.expectEqual(src_b.len, try r.decompress(back, 0));
    try std.testing.expectEqualSlices(u8, src_b, back);

    // a failed reset changes nothing: b still reads
    try std.testing.expectError(error.PrefixUnknown, r.reset(.{ .bytes = za[0 .. za.len - 1] }));
    fa.fail_index = fa.alloc_index;
    try std.testing.expectError(error.OutOfMemory, r.reset(.{ .bytes = za }));
    fa.fail_index = std.math.maxInt(usize);
    try std.testing.expectEqual(@as(usize, 500), try r.decompress(back[0..500], 60000));
    try std.testing.expectEqualSlices(u8, src_b[60000..][0..500], back[0..500]);

    // and back to a, checksums checked again
    try r.reset(.{ .bytes = za });
    try std.testing.expectEqual(src_a.len, try r.decompress(back[0..src_a.len], 0));
    try std.testing.expectEqualSlices(u8, src_a, back[0..src_a.len]);
    const bad = try gpa.dupe(u8, za);
    defer gpa.free(bad);
    bad[bad.len - (8 + 12 * 5 + 9) + 8 + 12 * 2 + 8] ^= 0x80; // frame 2's checksum
    try r.reset(.{ .bytes = bad });
    try std.testing.expectError(error.CorruptionDetected, r.decompress(back[0..src_a.len], 8000));
}

test "frames sharing their bytes: refused in memory, read through another source, as libzstd" {
    // Frames 0 and 1 have a compressed size of 0, so all three start at the
    // same frame and one read decodes it three times: more input than the
    // buffer holds. libzstd's in-memory reader refuses that (seekableIO);
    // through a file it reads (tools/zseekable.c `d`, 2026-09-28).
    var raw: [1000]u8 = undefined;
    var prng: std.Random.DefaultPrng = .init(1);
    for (&raw) |*b| b.* = 'a' + prng.random().uintLessThan(u8, 26);
    const f = try zstd.compressAlloc(gpa, &raw, .{ .level = 3 });
    defer gpa.free(f);
    var z: std.ArrayList(u8) = .empty;
    defer z.deinit(gpa);
    try z.appendSlice(gpa, f);
    var word: [4]u8 = undefined;
    for ([_]u32{ seekable.skippable_magic, 8 * 3 + seekable.footer_size, 0, 1000, 0, 1000, @intCast(f.len), 1000, 3 }) |w| {
        std.mem.writeInt(u32, &word, w, .little);
        try z.appendSlice(gpa, &word);
    }
    try z.append(gpa, 0);
    std.mem.writeInt(u32, &word, seekable.magic_number, .little);
    try z.appendSlice(gpa, &word);
    try std.testing.expect(2 * f.len > z.items.len);

    var mem: MemSource = .{ .bytes = z.items };
    var back: [3000]u8 = undefined;
    var r = try seekable.Seekable.init(gpa, .{ .custom = .{ .context = &mem, .size = z.items.len, .readAt = MemSource.readAt } });
    defer r.deinit();
    try std.testing.expectEqual(@as(usize, 3000), try r.decompress(&back, 0));
    for (0..3) |i| try std.testing.expectEqualSlices(u8, &raw, back[i * 1000 ..][0..1000]);
    {
        var m = try seekable.Seekable.init(gpa, .{ .bytes = z.items });
        defer m.deinit();
        try std.testing.expectError(error.SeekableIO, m.decompress(&back, 0));
    }
    try r.reset(.{ .bytes = z.items });
    try std.testing.expectError(error.SeekableIO, r.decompress(&back, 0));
}

test "a seek table whose frame sizes disagree with the frames is refused, never looped on" {
    // Not libzstd's behaviour: its ZSTD_seekable_decompress restarts a frame
    // that ended before the offset its table promised, forever (found by
    // seglog's fuzz driver, 2026-09-27). A frame that decodes to more than
    // its table size would hand its extra bytes out as the next frame's.
    const case = findCase("words-16385");
    const src = try gpa.alloc(u8, case.len);
    defer gpa.free(src);
    corpus.generate(case, src);
    for ([_]bool{ false, true }) |checksums| {
        const z = try seekable.compressAlloc(gpa, src, .{ .max_frame_size = 4096, .frame_checksums = checksums });
        defer gpa.free(z);
        const esz: usize = if (checksums) 12 else 8;
        const d0 = z.len - 9 - esz * 5 + 4; // frame 0's decompressed size
        for ([_]i64{ 1, -1, 4000 }) |delta| {
            const bad = try gpa.dupe(u8, z);
            defer gpa.free(bad);
            const was = std.mem.readInt(u32, bad[d0..][0..4], .little);
            std.mem.writeInt(u32, bad[d0..][0..4], @intCast(@as(i64, was) + delta), .little);
            var mem: MemSource = .{ .bytes = bad };
            const sources = [_]seekable.Source{
                .{ .bytes = bad },
                .{ .custom = .{ .context = &mem, .size = bad.len, .readAt = MemSource.readAt } },
            };
            for (sources) |source| {
                var r = try seekable.Seekable.init(gpa, source);
                defer r.deinit();
                var back: [20000]u8 = undefined;
                const got = r.decompress(&back, 0);
                try std.testing.expectError(error.CorruptionDetected, got);
            }
        }
    }
}
