// SPDX-License-Identifier: MIT
//! Decoder tests for the mutants wave 6 left open, part two: Huffman tables of
//! every log (the table log a header ends with, the limits, the cell layout),
//! the four-stream paths on hand-built one-bit streams (the bytes of a
//! stream are written bit by bit, so the lengths and ends are exact), and
//! the seek table and `Seekable`.

const std = @import("std");
const zstd = @import("root.zig");
const huf = @import("huf.zig");
const huf_dec = @import("huf_dec.zig");
const seekable = @import("seekable.zig");
const dbits = @import("dbits.zig");
const fse = @import("fse.zig");
const ddict_mod = @import("ddict.zig");
const kats = @import("testdata/dict_kats.zig");

const gpa = std.testing.allocator;
const magic = [4]u8{ 0x28, 0xb5, 0x2f, 0xfd };

// ------------------------------------------------------------ Huffman tables

fn weightOf(k: usize, s: usize) u8 {
    return if (s < 2) 1 else @intCast(@min(s, k + 1));
}

/// A table header in the direct (4-bit) form: the weights 1, 1, 2, 3 .. k and
/// the implied last one, k + 1. They sum to 2^k, so the table log is k + 1
/// (up to 12 for k = 11); weight w has a code of log + 1 - w bits.
fn directHeader(buf: *[16]u8, k: usize) []u8 {
    const o_size = k + 1;
    buf[0] = @intCast(127 + o_size);
    var i: usize = 0;
    while (i < o_size) : (i += 2) {
        const lo: u8 = if (i + 1 < o_size) weightOf(k, i + 1) else 0;
        buf[1 + i / 2] = (weightOf(k, i) << 4) | lo;
    }
    return buf[0 .. 1 + (o_size + 1) / 2];
}

const Code = struct { sym: u8, nb: u32 };

/// The symbol whose code the table index `idx` starts with, in a table of
/// `log` bits made by `directHeader(k)`: runs of 2^(w-1) cells, by weight
/// and then symbol.
fn codeAt(k: usize, log: usize, idx: usize) Code {
    var pos: usize = 0;
    var w: usize = 1;
    while (w <= k + 1) : (w += 1) {
        for (0..k + 2) |s| {
            if (weightOf(k, s) != w) continue;
            const len = (@as(usize, 1) << @intCast(w)) >> 1;
            if (idx < pos + len) return .{ .sym = @intCast(s), .nb = @intCast(log + 1 - w) };
            pos += len;
        }
    }
    unreachable;
}

test "Huffman tables: the log a header ends with, the limits of a table, and its cells" {
    var dt: huf_dec.DTable = .{};
    var hb: [16]u8 = undefined;
    // the default limit: tables up to log 11 are widened to 11, log 12 stays
    for (1..12) |k| {
        const l = k + 1;
        dt = .{};
        _ = try huf_dec.readDTableX1(&dt, directHeader(&hb, k));
        try std.testing.expectEqual(@max(l, 11), @as(usize, dt.table_log));
        dt = .{};
        _ = try huf_dec.readDTableX2(&dt, directHeader(&hb, k));
        try std.testing.expectEqual(@max(l, 11), @as(usize, dt.table_log));
    }
    // a lower limit: X1 counts one more than the field, X2 exactly the field
    for ([_]usize{ 3, 5, 8, 10 }) |m| {
        dt = .{};
        dt.max_table_log = @intCast(m);
        _ = try huf_dec.readDTableX1(&dt, directHeader(&hb, m));
        try std.testing.expectEqual(m + 1, @as(usize, dt.table_log));
        dt = .{};
        dt.max_table_log = @intCast(m);
        try std.testing.expectError(error.TableLogTooLarge, huf_dec.readDTableX1(&dt, directHeader(&hb, m + 1)));
        dt = .{};
        dt.max_table_log = @intCast(m);
        _ = try huf_dec.readDTableX2(&dt, directHeader(&hb, m - 1));
        try std.testing.expectEqual(m, @as(usize, dt.table_log));
        dt = .{};
        dt.max_table_log = @intCast(m);
        try std.testing.expectError(error.TableLogTooLarge, huf_dec.readDTableX2(&dt, directHeader(&hb, m)));
    }
    // a limit above the largest log is refused outright
    dt = .{};
    dt.max_table_log = 13;
    try std.testing.expectError(error.TableLogTooLarge, huf_dec.readDTableX2(&dt, directHeader(&hb, 3)));
    // the cells, against the codes: X1 holds the symbol and its length, and nothing past the table is written
    for (1..12) |k| {
        const l = k + 1;
        dt = .{};
        @memset(std.mem.asBytes(&dt.cells), 0xEE);
        dt.max_table_log = @intCast(l - 1);
        _ = try huf_dec.readDTableX1(&dt, directHeader(&hb, k));
        try std.testing.expectEqual(l, @as(usize, dt.table_log));
        const c16: *const [2 * 4096]u16 = @ptrCast(&dt.cells);
        for (0..@as(usize, 1) << @intCast(l)) |i| {
            const c = codeAt(k, l, i);
            try std.testing.expectEqual((@as(u16, c.sym) << 8) | @as(u16, @intCast(c.nb)), c16[i]);
        }
        for (@as(usize, 1) << @intCast(l)..2 * 4096) |i| try std.testing.expectEqual(@as(u16, 0xEEEE), c16[i]);
    }
    // X2 holds two symbols where the second code fits in what the first leaves
    for (1..12) |k| {
        const l = k + 1;
        dt = .{};
        dt.max_table_log = @intCast(l);
        _ = try huf_dec.readDTableX2(&dt, directHeader(&hb, k));
        try std.testing.expectEqual(l, @as(usize, dt.table_log));
        const mask = (@as(usize, 1) << @intCast(l)) - 1;
        for (0..mask + 1) |i| {
            const c1 = codeAt(k, l, i);
            const c2 = codeAt(k, l, (i << @intCast(c1.nb)) & mask);
            const cell = dt.cells[i];
            if (c1.nb + c2.nb <= l) {
                try std.testing.expectEqual(@as(u32, 2), cell >> 24);
                try std.testing.expectEqual(c1.nb + c2.nb, (cell >> 16) & 0xff);
                try std.testing.expectEqual(@as(u32, c1.sym) | (@as(u32, c2.sym) << 8), cell & 0xffff);
            } else {
                try std.testing.expectEqual(@as(u32, 1), cell >> 24);
                try std.testing.expectEqual(c1.nb, (cell >> 16) & 0xff);
                try std.testing.expectEqual(@as(u32, c1.sym), cell & 0xffff);
            }
        }
    }
}

// ------------------------------------------------------------ hand-built one-bit streams

/// The header of a table of two symbols, one bit each (weights 1 and the implied 1).
const two_symbols = [_]u8{ 128, 0x10 };

fn setBit(out: []u8, pos: usize) void {
    out[pos / 8] |= @as(u8, 1) << @intCast(pos % 8);
}

/// A stream of `syms` (each one bit, the first read first): the end mark at
/// bit `mark` of `out` (in its last byte), the symbols below it, zeros under them.
fn mkStream(out: []u8, syms: []const u1, mark: usize) void {
    @memset(out, 0);
    std.debug.assert(mark / 8 == out.len - 1);
    setBit(out, mark);
    for (syms, 0..) |b, j| if (b == 1) setBit(out, mark - 1 - j);
}

fn pat(i: usize, j: usize) u1 {
    return @intCast(((j *% 7 +% i *% 3) / 2) & 1);
}

fn tables() !struct { x1: huf_dec.DTable, x2: huf_dec.DTable } {
    var x1: huf_dec.DTable = .{};
    var x2: huf_dec.DTable = .{};
    _ = try huf_dec.readDTableX1(&x1, &two_symbols);
    x2.max_table_log = 11; // a table of log 11, as the fast loop needs
    _ = try huf_dec.readDTableX2(&x2, &two_symbols);
    try std.testing.expectEqual(@as(u8, 11), x1.table_log);
    try std.testing.expectEqual(@as(u8, 11), x2.table_log);
    return .{ .x1 = x1, .x2 = x2 };
}

test "four streams: a section under 10 bytes and an output under 6 are refused, whatever the table" {
    const t = try tables();
    const src = [_]u8{ 1, 0, 1, 0, 1, 0, 0x03, 0x02, 0x03, 0x01 }; // three streams of a bit, one of none
    var out: [8]u8 = undefined;
    for ([_]*const huf_dec.DTable{ &t.x1, &t.x2 }) |dt| {
        try std.testing.expectError(error.CorruptionDetected, huf_dec.decompress4XUsing(dt, out[0..3], &src));
        for (0..10) |n| try std.testing.expectError(error.CorruptionDetected, huf_dec.decompress4XUsing(dt, out[0..8], src[0..n]));
        try std.testing.expectError(error.CorruptionDetected, huf_dec.decompress4XUsing(dt, out[0..0], &src));
    }
}

test "four streams: eight-byte streams take the fast path, which does not check how they end" {
    const t = try tables();
    var src: [6 + 32]u8 = undefined;
    std.mem.writeInt(u16, src[0..2], 8, .little);
    std.mem.writeInt(u16, src[2..4], 8, .little);
    std.mem.writeInt(u16, src[4..6], 8, .little);
    var syms: [4][60]u1 = undefined;
    for (0..4) |i| for (0..60) |j| {
        syms[i][j] = pat(i, j);
    };
    for (0..3) |i| mkStream(src[6 + 8 * i ..][0..8], &syms[i], 60);
    mkStream(src[6 + 24 ..][0..8], syms[3][0..58], 58); // 58 bits for the 57 symbols asked: one is left over
    var out: [237]u8 = undefined;
    try huf_dec.decompress4XUsing(&t.x1, &out, &src);
    for (0..3) |i| for (0..60) |j| try std.testing.expectEqual(@as(u8, syms[i][j]), out[i * 60 + j]);
    for (0..57) |j| try std.testing.expectEqual(@as(u8, syms[3][j]), out[180 + j]);
}

test "four streams: long streams, a segment the fast loop fills exactly, assembly on and off" {
    defer huf_dec.setAsmForTest(true);
    const t = try tables();
    const pad = 100;
    var src: [6 + 4 * pad]u8 = undefined;
    for (0..3) |i| std.mem.writeInt(u16, src[2 * i ..][0..2], pad, .little);
    var syms: [4][60]u1 = undefined;
    for (0..4) |i| {
        for (0..60) |j| syms[i][j] = pat(i + 1, j);
        mkStream(src[6 + pad * i ..][0..pad], &syms[i], pad * 8 - 1); // 60 symbols, then bytes nobody reads
    }
    var out: [240]u8 = undefined;
    for ([_]bool{ false, true }) |asm_on| {
        for ([_]*const huf_dec.DTable{ &t.x1, &t.x2 }) |dt| {
            huf_dec.setAsmForTest(asm_on);
            const before = huf_dec.asmEntriesForTest();
            @memset(&out, 0xff);
            try huf_dec.decompress4XUsing(dt, &out, &src);
            for (0..4) |i| for (0..60) |j| try std.testing.expectEqual(@as(u8, syms[i][j]), out[i * 60 + j]);
            const entered = huf_dec.asmEntriesForTest() - before;
            if (huf_dec.asm_supported) {
                if (asm_on) try std.testing.expect(entered > 0) else try std.testing.expectEqual(@as(usize, 0), entered);
            }
        }
    }
    // an output of three bytes: the fourth segment would start at its end, and an output under six is refused
    for ([_]*const huf_dec.DTable{ &t.x1, &t.x2 }) |dt| {
        try std.testing.expectError(error.CorruptionDetected, huf_dec.decompress4XUsing(dt, out[0..3], &src));
    }
    // a short output: the fast loop has nothing to do, the tails decode it all
    const small = out[0..16];
    for ([_]*const huf_dec.DTable{ &t.x1, &t.x2 }) |dt| {
        huf_dec.setAsmForTest(true);
        try huf_dec.decompress4XUsing(dt, small, &src);
        for (0..4) |i| for (0..4) |j| try std.testing.expectEqual(@as(u8, syms[i][j]), small[i * 4 + j]);
    }
}

// ------------------------------------------------------------ tables of log 12

test "tables of log 12 through every decoder: the checked loops, long codes, a stream that ends early or late" {
    var hb: [16]u8 = undefined;
    const hdr = directHeader(&hb, 11);
    var ct: huf.CTable = .{};
    var zero: bool = false;
    _ = try huf.readCTable(&ct, hdr, &zero);
    var x1: huf_dec.DTable = .{};
    var x2: huf_dec.DTable = .{};
    _ = try huf_dec.readDTableX1(&x1, hdr);
    _ = try huf_dec.readDTableX2(&x2, hdr);
    try std.testing.expectEqual(@as(u8, 12), x1.table_log);
    try std.testing.expectEqual(@as(u8, 12), x2.table_log);

    var prng = std.Random.DefaultPrng.init(0x1209);
    const rnd = prng.random();
    const n = 5000;
    var rare: [n]u8 = undefined; // only the two symbols with the longest codes
    var mixed: [n]u8 = undefined;
    for (&rare) |*b| b.* = rnd.uintLessThan(u8, 2);
    for (&mixed) |*b| b.* = rnd.uintLessThan(u8, 13);
    var comp: [3 * n]u8 = undefined;
    var out: [n + 16]u8 = undefined;
    for ([_][]const u8{ &rare, &mixed }) |data| {
        for ([_]*const huf_dec.DTable{ &x1, &x2 }) |dt| {
            const c1 = huf.compress1X(&comp, data, &ct);
            try std.testing.expect(c1 > 0);
            try huf_dec.decompress1XUsing(dt, out[0..n], comp[0..c1]);
            try std.testing.expectEqualSlices(u8, data, out[0..n]);
            // fewer symbols than the stream holds, or more: refused
            try std.testing.expectError(error.CorruptionDetected, huf_dec.decompress1XUsing(dt, out[0 .. n + 1], comp[0..c1]));
            try std.testing.expectError(error.CorruptionDetected, huf_dec.decompress1XUsing(dt, out[0 .. n - 3], comp[0..c1]));
            try std.testing.expectError(error.CorruptionDetected, huf_dec.decompress1XUsing(dt, out[0 .. n - 2], comp[0..c1]));
            const c4 = huf.compress4X(&comp, data, &ct);
            try std.testing.expect(c4 > 0);
            try huf_dec.decompress4XUsing(dt, out[0..n], comp[0..c4]);
            try std.testing.expectEqualSlices(u8, data, out[0..n]);
            try std.testing.expectError(error.CorruptionDetected, huf_dec.decompress4XUsing(dt, out[0 .. n + 8], comp[0..c4]));
        }
    }
}

// ------------------------------------------------------------ the seek table

fn tableBytes(entries: []const [2]u32, sums: ?[]const u32) ![]u8 {
    const per: usize = if (sums != null) 12 else 8;
    const buf = try gpa.alloc(u8, 8 + per * entries.len + seekable.footer_size);
    std.mem.writeInt(u32, buf[0..4], seekable.skippable_magic, .little);
    std.mem.writeInt(u32, buf[4..8], @intCast(seekable.footer_size + per * entries.len), .little);
    for (entries, 0..) |e, i| {
        const at = 8 + per * i;
        std.mem.writeInt(u32, buf[at..][0..4], e[0], .little);
        std.mem.writeInt(u32, buf[at + 4 ..][0..4], e[1], .little);
        if (sums) |s| std.mem.writeInt(u32, buf[at + 8 ..][0..4], s[i], .little);
    }
    const f = 8 + per * entries.len;
    std.mem.writeInt(u32, buf[f..][0..4], @intCast(entries.len), .little);
    buf[f + 4] = if (sums != null) 0x80 else 0;
    std.mem.writeInt(u32, buf[f + 5 ..][0..4], seekable.magic_number, .little);
    return buf;
}

test "a seek table: the smallest source, the smallest table, a wrong magic, and more entries than one read holds" {
    const gpa_ = gpa;
    // nine bytes are a footer, nothing else is needed to say what it is
    const zeros: [9]u8 = @splat(0);
    try std.testing.expectError(error.PrefixUnknown, seekable.SeekTable.load(gpa_, .{ .bytes = &zeros }));
    try std.testing.expectError(error.SeekableIO, seekable.SeekTable.load(gpa_, .{ .bytes = zeros[0..8] }));
    // a table of no frames is the whole source
    const empty = try tableBytes(&.{}, null);
    defer gpa_.free(empty);
    try std.testing.expectEqual(@as(usize, 17), empty.len);
    var t0 = try seekable.SeekTable.load(gpa_, .{ .bytes = empty });
    t0.deinit(gpa_);
    // its skippable magic is checked
    empty[0] ^= 1;
    try std.testing.expectError(error.PrefixUnknown, seekable.SeekTable.load(gpa_, .{ .bytes = empty }));
    empty[0] ^= 1;
    // and so is its size
    empty[4] ^= 1;
    try std.testing.expectError(error.PrefixUnknown, seekable.SeekTable.load(gpa_, .{ .bytes = empty }));
    // 17000 entries are read in more than one piece
    for ([_]bool{ false, true }) |with_sums| {
        const n: usize = if (with_sums) 11000 else 17000;
        const es = try gpa_.alloc([2]u32, n);
        defer gpa_.free(es);
        const ss = try gpa_.alloc(u32, n);
        defer gpa_.free(ss);
        for (es, ss, 0..) |*e, *s, i| {
            e.* = .{ @intCast(i % 7 + 1), @intCast(i % 5 + 1) };
            s.* = @truncate(@as(u64, i) *% 2654435761);
        }
        const bytes = try tableBytes(es, if (with_sums) ss else null);
        defer gpa_.free(bytes);
        var t = try seekable.SeekTable.load(gpa_, .{ .bytes = bytes });
        defer t.deinit(gpa_);
        try std.testing.expectEqual(@as(u32, @intCast(n)), t.numFrames());
        try std.testing.expectEqual(with_sums, t.checksum_flag);
        var c: u64 = 0;
        var d: u64 = 0;
        for (es, ss, 0..) |e, s, i| {
            try std.testing.expectEqual(c, t.entries[i].c_offset);
            try std.testing.expectEqual(d, t.entries[i].d_offset);
            try std.testing.expectEqual(if (with_sums) s else 0, t.entries[i].checksum);
            c += e[0];
            d += e[1];
        }
        try std.testing.expectEqual(c, t.entries[n].c_offset);
        try std.testing.expectEqual(d, t.decompressedSize());
    }
}

// ------------------------------------------------------------ writing

fn feedAll(s: *seekable.SeekableStream, data: []const u8, out: *std.ArrayList(u8)) !void {
    var buf: [4096]u8 = undefined;
    var in: zstd.InBuffer = .{ .src = data };
    while (in.pos < in.src.len) {
        var o: zstd.OutBuffer = .{ .dst = &buf };
        _ = try s.compressStream(&o, &in);
        try out.appendSlice(gpa, buf[0..o.pos]);
    }
    while (true) {
        var o: zstd.OutBuffer = .{ .dst = &buf };
        const left = try s.endStream(&o);
        try out.appendSlice(gpa, buf[0..o.pos]);
        if (left == 0) break;
    }
}

fn pattern(buf: []u8) void {
    for (buf, 0..) |*b, i| b.* = @truncate((i * i / 7) +% i / 3);
}

test "a seekable writer: the largest frame size, a reset in the middle of a frame, an input read to its end" {
    var big = try seekable.SeekableStream.init(gpa, .{ .max_frame_size = seekable.max_frame_decompressed_size });
    big.deinit();
    try std.testing.expectError(error.FrameParameterUnsupported, seekable.SeekableStream.init(gpa, .{ .max_frame_size = seekable.max_frame_decompressed_size + 1 }));

    var data: [2500]u8 = undefined;
    pattern(&data);
    var fresh = try seekable.SeekableStream.init(gpa, .{ .frame_checksums = true, .max_frame_size = 1000 });
    defer fresh.deinit();
    var a: std.ArrayList(u8) = .empty;
    defer a.deinit(gpa);
    try feedAll(&fresh, &data, &a);

    // a stream that has written part of a big frame (some of its bytes are out, so the frame's size so far is not zero)
    var used = try seekable.SeekableStream.init(gpa, .{ .frame_checksums = true });
    defer used.deinit();
    var obuf: [8192]u8 = undefined;
    const big_in = try gpa.alloc(u8, 300_000);
    defer gpa.free(big_in);
    pattern(big_in);
    var in: zstd.InBuffer = .{ .src = big_in };
    while (in.pos < in.src.len) {
        var o: zstd.OutBuffer = .{ .dst = &obuf };
        _ = try used.compressStream(&o, &in);
    }
    try used.reset(.{ .frame_checksums = true, .max_frame_size = 1000 });
    var b: std.ArrayList(u8) = .empty;
    defer b.deinit(gpa);
    try feedAll(&used, &data, &b);
    try std.testing.expectEqualSlices(u8, a.items, b.items);

    // an input already read to its end is not an error
    var s3 = try seekable.SeekableStream.init(gpa, .{});
    defer s3.deinit();
    var in2: zstd.InBuffer = .{ .src = "abc", .pos = 3 };
    var o2: zstd.OutBuffer = .{ .dst = &obuf };
    _ = try s3.compressStream(&o2, &in2);
}

// ------------------------------------------------------------ reading

const Counting = struct {
    data: []const u8,
    offsets: std.ArrayList(u64) = .empty,

    fn readAt(ctx: *anyopaque, buf: []u8, offset: u64) error{ReadFailed}!void {
        const self: *Counting = @ptrCast(@alignCast(ctx));
        if (offset > self.data.len or buf.len > self.data.len - offset) return error.ReadFailed;
        self.offsets.append(gpa, offset) catch return error.ReadFailed;
        @memcpy(buf, self.data[@intCast(offset)..][0..buf.len]);
    }
};

test "Seekable: a read that continues where the last stopped does not read its frame again" {
    var data: [3000]u8 = undefined;
    pattern(&data);
    const z = try seekable.compressAlloc(gpa, &data, .{ .max_frame_size = 1000 });
    defer gpa.free(z);
    var c: Counting = .{ .data = z };
    defer c.offsets.deinit(gpa);
    var r = try seekable.Seekable.init(gpa, .{ .custom = .{ .context = &c, .size = z.len, .readAt = Counting.readAt } });
    defer r.deinit();
    c.offsets.clearRetainingCapacity();
    var out: [200]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 100), try r.decompress(out[0..100], 0));
    try std.testing.expectEqualSlices(u8, data[0..100], out[0..100]);
    try std.testing.expectEqual(@as(u64, 0), c.offsets.items[0]); // the frame's start
    const seen = c.offsets.items.len;
    try std.testing.expectEqual(@as(usize, 100), try r.decompress(out[100..200], 100));
    try std.testing.expectEqualSlices(u8, data[100..200], out[100..200]);
    for (c.offsets.items[seen..]) |o| try std.testing.expect(o != 0);
}

test "Seekable: frames and their tables that disagree with the data" {
    const magic_frame = magic ++ [_]u8{ 0x24, 0x05, 0x29, 0x00, 0x00 } ++ "hello".*;
    // a content checksum that is wrong: a read that stops with the frame's last byte never looks at it, a read on into the next frame does
    const bad_sum = magic_frame ++ [_]u8{ 1, 2, 3, 4 };
    const next_frame = magic ++ [_]u8{ 0x20, 0x03, 0x19, 0x00, 0x00 } ++ "abc".*;
    const t1 = try tableBytes(&.{ .{ bad_sum.len, 5 }, .{ next_frame.len, 3 } }, null);
    defer gpa.free(t1);
    const z1 = try std.mem.concat(gpa, u8, &.{ &bad_sum, &next_frame, t1 });
    defer gpa.free(z1);
    var r1 = try seekable.Seekable.init(gpa, .{ .bytes = z1 });
    defer r1.deinit();
    var out: [8]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 5), try r1.decompress(out[0..5], 0));
    try std.testing.expectEqualStrings("hello", out[0..5]);
    try std.testing.expectError(error.ChecksumWrong, r1.decompress(out[0..8], 0));

    // blocks of no bytes before the data: the reader gives up after a bounded number of reads that make no progress
    var first_failure: ?usize = null;
    for (0..40) |k| {
        var f: std.ArrayList(u8) = .empty;
        defer f.deinit(gpa);
        try f.appendSlice(gpa, &(magic ++ [_]u8{ 0x20, 4 }));
        for (0..k) |_| try f.appendSlice(gpa, &.{ 0, 0, 0 });
        try f.appendSlice(gpa, &([_]u8{ 0x21, 0, 0 } ++ "abcd".*));
        const tb = try tableBytes(&.{.{ @intCast(f.items.len), 4 }}, null);
        defer gpa.free(tb);
        const z = try std.mem.concat(gpa, u8, &.{ f.items, tb });
        defer gpa.free(z);
        var r = try seekable.Seekable.init(gpa, .{ .bytes = z });
        defer r.deinit();
        if (r.decompress(out[0..4], 0)) |n| {
            try std.testing.expectEqual(@as(usize, 4), n);
            try std.testing.expectEqualStrings("abcd", out[0..4]);
            try std.testing.expectEqual(@as(?usize, null), first_failure);
        } else |e| {
            try std.testing.expect(e == error.SeekableIO);
            if (first_failure == null) first_failure = k;
        }
    }
    try std.testing.expectEqual(@as(?usize, 16), first_failure);
}

test "Seekable: a block as large as one read, a frame read whole, a source that shrank" {
    // incompressible bytes: raw blocks of 128 KiB, the first asks for its header with it, more than a read holds
    var prng = std.Random.DefaultPrng.init(0xb10c);
    const data = try gpa.alloc(u8, 300_000);
    defer gpa.free(data);
    prng.random().bytes(data);
    const z = try seekable.compressAlloc(gpa, data, .{});
    defer gpa.free(z);
    var r = try seekable.Seekable.init(gpa, .{ .bytes = z });
    defer r.deinit();
    const back = try gpa.alloc(u8, data.len);
    defer gpa.free(back);
    try std.testing.expectEqual(data.len, try r.decompress(back, 0));
    try std.testing.expectEqualSlices(u8, data, back);

    // frames of 1000 bytes: the destination of a whole frame
    var small: [3000]u8 = undefined;
    pattern(&small);
    const z2 = try seekable.compressAlloc(gpa, &small, .{ .max_frame_size = 1000 });
    defer gpa.free(z2);
    var r2 = try seekable.Seekable.init(gpa, .{ .bytes = z2 });
    defer r2.deinit();
    var out: [1000]u8 = undefined;
    try std.testing.expectError(error.DstSizeTooSmall, r2.decompressFrame(out[0..999], 0));
    try std.testing.expectEqual(@as(usize, 1000), try r2.decompressFrame(&out, 1));
    try std.testing.expectEqualSlices(u8, small[1000..2000], &out);

    // a file that lost its tail after the table was read: the read fails, it does not go on with what it has
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "s.zst", .data = z2 });
    const f = try tmp.dir.openFile(io, "s.zst", .{ .mode = .read_write });
    defer f.close(io);
    var r3 = try seekable.Seekable.init(gpa, .{ .file = .{ .file = f, .io = io } });
    defer r3.deinit();
    try f.setLength(io, 20);
    try std.testing.expectError(error.SeekableIO, r3.decompress(&out, 0));
}

// ------------------------------------------------------------ streams too short for the fast path

test "four streams: one stream under eight bytes keeps the others on the checked loop, which refuses their spare bytes" {
    const t = try tables();
    const seg = 54;
    var syms: [4][seg]u1 = undefined;
    for (0..4) |i| for (0..seg) |j| {
        syms[i][j] = pat(i + 2, j);
    };
    var out: [4 * seg]u8 = undefined;
    // every stream exact (seven bytes): all on the checked loop, which decodes them
    {
        var src: [6 + 28]u8 = undefined;
        for (0..3) |i| std.mem.writeInt(u16, src[2 * i ..][0..2], 7, .little);
        for (0..4) |i| mkStream(src[6 + 7 * i ..][0..7], &syms[i], seg);
        for ([_]*const huf_dec.DTable{ &t.x1, &t.x2 }) |dt| {
            try huf_dec.decompress4XUsing(dt, &out, &src);
            for (0..4) |i| for (0..seg) |j| try std.testing.expectEqual(@as(u8, syms[i][j]), out[i * seg + j]);
        }
    }
    // one exact stream of seven bytes, the three others padded to nine: the checked loop refuses a stream with bits left over
    for (0..4) |short| {
        var src: [6 + 3 * 9 + 7]u8 = undefined;
        var at: usize = 6;
        for (0..4) |i| {
            const len: usize = if (i == short) 7 else 9;
            if (i < 3) std.mem.writeInt(u16, src[2 * i ..][0..2], @intCast(len), .little);
            mkStream(src[at..][0..len], &syms[i], if (i == short) seg else len * 8 - 1);
            at += len;
        }
        for ([_]*const huf_dec.DTable{ &t.x1, &t.x2 }) |dt| {
            try std.testing.expectError(error.CorruptionDetected, huf_dec.decompress4XUsing(dt, &out, src[0..at]));
        }
    }
}

test "the choice between the two tables follows libzstd's timing model, and the table it chooses is kept" {
    // a compressed size equal to the output (and above) is the last row of the model
    try std.testing.expectEqual(huf_dec.selectX2(1000, 1000), huf_dec.selectX2(1000, 1001));
    try std.testing.expectEqual(huf_dec.selectX2(100, 100), huf_dec.selectX2(100, 5000));
    // row 7: with 2048 output bytes the double-symbol table is 1729 against 1768, but its 3% penalty makes it 1783
    try std.testing.expect(!huf_dec.selectX2(2048, 896));
    try std.testing.expect(huf_dec.selectX2(5120, 2240));
    // a section libzstd decodes through the double-symbol table: the table left behind is that one
    var prng = std.Random.DefaultPrng.init(0xd0d0);
    const n = 5120;
    var data: [n]u8 = undefined;
    for (&data) |*b| b.* = prng.random().uintLessThan(u8, 11);
    var comp: [2 * n]u8 = undefined;
    var old: huf.CTable = .{};
    var rep: huf.Repeat = .none;
    const c = try huf.compress(&comp, &data, 11, .four, &old, &rep, .{});
    try std.testing.expect(c > 1);
    try std.testing.expect(huf_dec.selectX2(n, c));
    var dt: huf_dec.DTable = .{};
    var out: [n]u8 = undefined;
    try huf_dec.decompress4XTable(&dt, &out, comp[0..c]);
    try std.testing.expectEqualSlices(u8, &data, &out);
    try std.testing.expectEqual(@as(u8, 1), dt.table_type);
}

// ------------------------------------------------------------ a dictionary's tables

test "a dictionary whose offset table is larger than offsets may have is corrupt" {
    var dt: huf_dec.DTable = .{};
    const huf_size = try huf_dec.readDTableX2(&dt, kats.full_dict[8..]);
    var max_sv: u32 = 31;
    var tl: u32 = 0;
    var norm: [64]i16 = undefined;
    const of_size = try dbits.readNCount(&norm, &max_sv, &tl, kats.full_dict[8 + huf_size ..]);
    const head = kats.full_dict[0 .. 8 + huf_size];
    const tail = kats.full_dict[8 + huf_size + of_size ..];
    for ([_]u32{ 8, 9 }) |log| {
        var counts = [3]i16{ 0, 0, 0 };
        counts[0] = @intCast((@as(u32, 1) << @intCast(log)) / 2);
        counts[1] = @intCast((@as(u32, 1) << @intCast(log)) / 4);
        counts[2] = counts[1];
        var h: [64]u8 = undefined;
        const hn = try fse.writeNCount(&h, &counts, 2, log);
        const dict = try std.mem.concat(gpa, u8, &.{ head, h[0..hn], tail });
        defer gpa.free(dict);
        if (log == 8) {
            var ok = try ddict_mod.DDict.init(gpa, dict, .full);
            ok.deinit(gpa);
        } else {
            try std.testing.expectError(error.DictionaryCorrupted, ddict_mod.DDict.init(gpa, dict, .full));
        }
    }
}

test "readStats: a table of log 13 is refused even when its weights are otherwise a table" {
    // weights 1, 1, 12, 12, 11 .. 2 and the implied 12: 6144 and the 2048 that completes 8192
    const src = [_]u8{ 141, 0x11, 0xcc, 0xba, 0x98, 0x76, 0x54, 0x32 };
    var w: [256]u8 = undefined;
    var rank: [13]u32 = undefined;
    var nb: u32 = 0;
    var tl: u32 = 0;
    try std.testing.expectError(error.CorruptionDetected, huf_dec.readStats(&w, &rank, &nb, &tl, &src));
}

test "a section that is only a table has no streams, whatever table the sizes call for" {
    var prng = std.Random.DefaultPrng.init(0xfeed);
    const rnd = prng.random();
    var counts: [256]u32 = undefined;
    for (&counts) |*c| c.* = @as(u32, 1) << @intCast(rnd.uintLessThan(u32, 13)); // code lengths spread over many values: a long FSE header
    var ct: huf.CTable = .{};
    const log = try huf.buildCTable(&ct, &counts, 255, 12);
    var buf: [300]u8 = undefined;
    const h = try huf.writeCTable(&buf, &ct, 255, log);
    var dt: huf_dec.DTable = .{};
    var out: [20000]u8 = undefined;
    var n: usize = 6;
    while (n < out.len) : (n += 13) {
        try std.testing.expectError(error.SrcSizeWrong, huf_dec.decompress4XTable(&dt, out[0..n], buf[0..h]));
    }
    try std.testing.expectError(error.SrcSizeWrong, huf_dec.decompress1X1Table(&dt, out[0..100], buf[0..h]));
}

// ------------------------------------------------------------ streams the fast loop reads past

/// Four hand-built streams of the lengths `lens`, each holding `syms_n` symbols and the end mark in its last bit.
fn lopsided(table: *const huf_dec.DTable, lens: [4]usize, syms_n: [4]usize, out: []u8) !void {
    var src: [6 + 4 * 200]u8 = undefined;
    var at: usize = 6;
    var syms: [4][200]u1 = undefined;
    for (0..4) |i| {
        for (0..200) |j| syms[i][j] = pat(i + 5, j);
        if (i < 3) std.mem.writeInt(u16, src[2 * i ..][0..2], @intCast(lens[i]), .little);
        mkStream(src[at..][0..lens[i]], syms[i][0..syms_n[i]], lens[i] * 8 - 1);
        at += lens[i];
    }
    try huf_dec.decompress4XUsing(table, out, src[0..at]);
}

test "four streams: the fast loop reads a short stream past its start, by a byte or by more" {
    const t = try tables();
    var out: [400]u8 = undefined;
    // 100 symbols a stream, and the second has the eight bytes of 63: the loop reads it 12 bytes down, past its start
    try std.testing.expectError(error.CorruptionDetected, lopsided(&t.x1, .{ 160, 8, 160, 160 }, .{ 100, 63, 100, 100 }, out[0..400]));
    // 65 symbols a stream: the second is read exactly eight bytes down, so its window ends where the stream began, not before
    try lopsided(&t.x1, .{ 100, 8, 100, 100 }, .{ 65, 63, 65, 65 }, out[0..260]);
}

// ------------------------------------------------------------ a table that makes the reader read as much as the source holds

const Mem = struct {
    data: []const u8,
    fn readAt(ctx: *anyopaque, buf: []u8, offset: u64) error{ReadFailed}!void {
        const self: *Mem = @ptrCast(@alignCast(ctx));
        if (offset > self.data.len or buf.len > self.data.len - offset) return error.ReadFailed;
        @memcpy(buf, self.data[@intCast(offset)..][0..buf.len]);
    }
};

fn rawFrame(list: *std.ArrayList(u8), payload: usize, fill: u8) !void {
    try list.appendSlice(gpa, &(magic ++ [_]u8{ 0x20, @intCast(payload) }));
    const bh: u32 = 1 | (@as(u32, @intCast(payload)) << 3);
    try list.appendSlice(gpa, &.{ @truncate(bh), @truncate(bh >> 8), @truncate(bh >> 16) });
    for (0..payload) |i| try list.append(gpa, fill +% @as(u8, @intCast(i)));
}

test "Seekable: frames that all start at the same bytes may be read as often as the source is long, not more" {
    // n frames of c bytes, a table of 8 + 8n + 9 bytes: the n-th frame starts after (n-1)c bytes read, the source holds c + table
    for ([_][2]usize{ .{ 3, 41 }, .{ 5, 19 }, .{ 13, 11 } }) |nc| {
        const n = nc[0];
        const c = nc[1];
        var f: std.ArrayList(u8) = .empty;
        defer f.deinit(gpa);
        try rawFrame(&f, c - 9, 'a');
        try std.testing.expectEqual(c, f.items.len);
        const es = try gpa.alloc([2]u32, n);
        defer gpa.free(es);
        for (es, 0..) |*e, i| e.* = .{ if (i + 1 < n) 0 else @intCast(c), @intCast(c - 9) };
        const tb = try tableBytes(es, null);
        defer gpa.free(tb);
        const z = try std.mem.concat(gpa, u8, &.{ f.items, tb });
        defer gpa.free(z);
        try std.testing.expectEqual((n - 1) * c, z.len);
        var r = try seekable.Seekable.init(gpa, .{ .bytes = z });
        defer r.deinit();
        const back = try gpa.alloc(u8, n * (c - 9));
        defer gpa.free(back);
        try std.testing.expectEqual(back.len, try r.decompress(back, 0));
        for (0..n) |i| try std.testing.expectEqualSlices(u8, back[0 .. c - 9], back[i * (c - 9) ..][0 .. c - 9]);
    }
}

test "Seekable: a frame that starts where the source ends is read, one that starts past it is not" {
    // the bytes behind the declared end are there (the source is longer than it says), so only the table's word keeps the reader out
    for ([_]usize{ 0, 1 }) |gap| {
        var a: std.ArrayList(u8) = .empty;
        defer a.deinit(gpa);
        try rawFrame(&a, 5, 'a');
        var b: std.ArrayList(u8) = .empty;
        defer b.deinit(gpa);
        try rawFrame(&b, 5, 'k');
        const table_len = 8 + 16 + seekable.footer_size;
        const tb = try tableBytes(&.{ .{ @intCast(a.items.len + table_len + gap), 5 }, .{ @intCast(b.items.len), 5 } }, null);
        defer gpa.free(tb);
        var all: std.ArrayList(u8) = .empty;
        defer all.deinit(gpa);
        try all.appendSlice(gpa, a.items);
        try all.appendSlice(gpa, tb);
        if (gap == 1) try all.append(gpa, 0);
        try all.appendSlice(gpa, b.items);
        var mem: Mem = .{ .data = all.items };
        var r = try seekable.Seekable.init(gpa, .{ .custom = .{ .context = &mem, .size = a.items.len + table_len, .readAt = Mem.readAt } });
        defer r.deinit();
        var out: [10]u8 = undefined;
        if (gap == 0) {
            try std.testing.expectEqual(@as(usize, 10), try r.decompress(&out, 0));
            try std.testing.expectEqualStrings("abcdeklmno", &out);
        } else {
            try std.testing.expectError(error.SeekableIO, r.decompress(&out, 0));
        }
    }
}
