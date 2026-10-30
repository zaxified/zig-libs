// SPDX-License-Identifier: MIT
//! No-panic sweep tests (wave GN). Every test name ends with its finding ID.
const std = @import("std");
const t = std.testing;
const line = @import("line.zig");
const stream = @import("stream.zig");

test "a chunk_size near maxInt reads a small file whole: no wrap, no OutOfMemory at EOF (sweep CS-1)" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(t.io, .{ .sub_path = "in.csv", .data = "a,b" });
    var f = try tmp.dir.openFile(t.io, "in.csv", .{});
    defer f.close(t.io);
    // The first read is right-sized to the 3-byte file; the probe for EOF is
    // capped at 64 KiB, so `len + chunk_size` is never asked for (it wrapped
    // before CS-1, and was OutOfMemory after it).
    var cr = try stream.ChunkReader.init(t.io, t.allocator, f, std.math.maxInt(usize));
    defer cr.deinit();
    const c = (try cr.nextChunk()).?;
    try t.expectEqualStrings("a,b", c);
    try t.expect((try cr.nextChunk()) == null);
}

fn growingRecordScanned(m: usize, span: bool) !u64 {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const data = try t.allocator.alloc(u8, m + m / 2);
    defer t.allocator.free(data);
    @memset(data, 'x');
    data[0] = '"'; // newline-free; an unclosed quote in .span mode
    try tmp.dir.writeFile(t.io, .{ .sub_path = "in.csv", .data = data });
    var f = try tmp.dir.openFile(t.io, "in.csv", .{});
    defer f.close(t.io);
    var cr = try stream.ChunkReader.initMax(t.io, t.allocator, f, 64, m);
    defer cr.deinit();
    if (span) cr.setSpan('"', .{});
    try t.expectError(error.RecordTooLong, cr.nextChunk());
    return cr.scanned;
}

test "a record growing over many refills is not rescanned quadratically (sweep CS-4)" {
    for ([_]bool{ false, true }) |span| {
        const small = try growingRecordScanned(16 * 1024, span);
        const big = try growingRecordScanned(64 * 1024, span);
        // linear ~4x, quadratic ~16x
        try t.expect(big < small * 9);
        // absolute: the old 64-byte reads scanned M^2 / 128 = 32 MiB here
        try t.expect(big < 64 * 1024 * 8);
    }
}

test "SpanScanner.scan with a start past the end is an empty tail, not a slice panic (sweep CS-2)" {
    var sc = line.SpanScanner.init('"', .{ .field_check = .first_record });
    const r = sc.scan("abc", 10, true);
    try t.expect(r == .record);
    try t.expectEqual(@as(usize, 3), r.record.next);
}

test "offsets, line and record counters saturate instead of overflowing (sweep CS-3)" {
    var it = line.LineIterator.init("a\nb\nc\n", '"', std.math.maxInt(u64) - 2);
    it.line = std.math.maxInt(u64);
    it.record = std.math.maxInt(u64);
    var n: usize = 0;
    var last_off: u64 = 0;
    while (it.next()) |rec| : (n += 1) last_off = rec.byte_offset;
    try t.expectEqual(@as(usize, 3), n);
    try t.expectEqual(@as(u64, std.math.maxInt(u64)), last_off);

    var sp = line.LineIterator.initSpan("a\n\"b\nc\"\nd\n", '"', std.math.maxInt(u64) - 1, .{});
    sp.line = std.math.maxInt(u64) - 1;
    sp.record = std.math.maxInt(u64);
    n = 0;
    while (sp.next()) |_| n += 1;
    try t.expectEqual(@as(usize, 3), n);
}

// ── delta mutation audit (sweep audit GN) ───────────────────────────────────

test "a comment line at the saturated line counter does not overflow (sweep audit GN-CS-3)" {
    var it = line.LineIterator.init("#c\na\n", '"', 0);
    it.comment = '#';
    it.line = std.math.maxInt(u64);
    const rec = it.next().?;
    try t.expectEqualStrings("a", rec.bytes);
    try t.expectEqual(@as(u64, std.math.maxInt(u64)), rec.line_number);
    try t.expect(it.next() == null);
}

fn writeAndOpen(tmp: *t.TmpDir, data: []const u8) !std.Io.File {
    try tmp.dir.writeFile(t.io, .{ .sub_path = "in.csv", .data = data });
    return tmp.dir.openFile(t.io, "in.csv", .{});
}

test "a record longer than max_record_len is RecordTooLong even if the newline is inside the buffer bound (sweep audit GN-CS-4)" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var data: [152]u8 = @splat('x');
    data[149] = '\n';
    data[151] = '\n';
    var f = try writeAndOpen(&tmp, &data);
    defer f.close(t.io);
    // chunk 64 + max 100: capacityBound is 164, so a read not clipped to the
    // record cap would reach the newline at 149 and emit a 149-byte record.
    var cr = try stream.ChunkReader.initMax(t.io, t.allocator, f, 64, 100);
    defer cr.deinit();
    try t.expectError(error.RecordTooLong, cr.nextChunk());

    // a record within the cap is still delivered
    data[89] = '\n';
    var f2 = try writeAndOpen(&tmp, data[0..90]);
    defer f2.close(t.io);
    var cr2 = try stream.ChunkReader.initMax(t.io, t.allocator, f2, 64, 100);
    defer cr2.deinit();
    try t.expectEqual(@as(usize, 90), (try cr2.nextChunk()).?.len);
}

test "refills past the file's stat size do not over-reserve the buffer (sweep audit GN-CS-4)" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var data: [20001]u8 = @splat('x');
    data[20000] = '\n';
    var f = try writeAndOpen(&tmp, &data);
    defer f.close(t.io);
    var cr = try stream.ChunkReader.initMax(t.io, t.allocator, f, 64, 1 << 20);
    defer cr.deinit();
    try t.expectEqual(@as(usize, 20001), (try cr.nextChunk()).?.len);
    // the last doubled read is trimmed to the 3681 bytes the file has left;
    // untrimmed it asks for 16384 and reserves ~32 KB
    try t.expect(cr.buffer.capacity < 30000);
}
