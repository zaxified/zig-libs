// SPDX-License-Identifier: MIT

const std = @import("std");
const testing = std.testing;
const bz = @import("root.zig");
const corpus = @import("shapes.zig");

fn shapeBytes(gpa: std.mem.Allocator, name: []const u8, len: ?usize) ![]u8 {
    var s = corpus.find(name).?;
    if (len) |l| s.len = l;
    return corpus.generate(gpa, s);
}

fn packed_(gpa: std.mem.Allocator, plain: []const u8, level: u4) ![]u8 {
    return bz.compress(gpa, plain, .{ .level = level });
}

test "decoder: pulled through a reader that gives a few bytes at a time" {
    const gpa = testing.allocator;
    const plain = try shapeBytes(gpa, "text-150k", null);
    defer gpa.free(plain);
    const z = try packed_(gpa, plain, 1);
    defer gpa.free(z);
    for ([_]usize{ 1, 5, 13, 4096 }) |piece| {
        var calls: [1]std.testing.Reader.Call = .{.{ .buffer = z }};
        var ibuf: [16]u8 = undefined;
        var tr: std.testing.Reader = .init(&ibuf, &calls);
        tr.artificial_limit = .limited(piece);
        var r = try bz.DecompressReader.init(gpa, &tr.interface, &.{}, .{});
        defer r.deinit();
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        _ = try r.reader.streamRemaining(&out.writer);
        try testing.expectEqualSlices(u8, plain, out.written());
        try testing.expect(r.err == null);
    }
}

test "decoder: a buffered DecompressReader reads lines and ints like any reader" {
    const gpa = testing.allocator;
    const z = try packed_(gpa, "alpha\nbeta\ngamma\n", 1);
    defer gpa.free(z);
    var in: std.Io.Reader = .fixed(z);
    var buf: [8]u8 = undefined;
    var r = try bz.DecompressReader.init(gpa, &in, &buf, .{});
    defer r.deinit();
    try testing.expectEqualStrings("alpha", (try r.reader.takeDelimiter('\n')).?);
    try testing.expectEqualStrings("beta", (try r.reader.takeDelimiter('\n')).?);
    try testing.expectEqualStrings("gamma", (try r.reader.takeDelimiter('\n')).?);
    try testing.expect((try r.reader.takeDelimiter('\n')) == null);
}

test "decoder: a failure is ReadFailed with the cause in err" {
    const gpa = testing.allocator;
    var bad = try packed_(gpa, "hello world, hello world", 1);
    defer gpa.free(bad);
    bad[bad.len - 6] ^= 0x40;
    var in: std.Io.Reader = .fixed(bad);
    var r = try bz.DecompressReader.init(gpa, &in, &.{}, .{});
    defer r.deinit();
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try testing.expectError(error.ReadFailed, r.reader.streamRemaining(&out.writer));
    try testing.expect(r.err != null);
}

test "bomb cap: output past max_output is refused, at the cap it is not" {
    const gpa = testing.allocator;
    const plain = try shapeBytes(gpa, "zeros-2m", null);
    defer gpa.free(plain);
    const z = try packed_(gpa, plain, 9);
    defer gpa.free(z);
    try testing.expect(z.len < 1000);
    const ok = try bz.decompress(gpa, z, .{ .max_output = plain.len });
    gpa.free(ok);
    try testing.expectError(error.OutputTooLarge, bz.decompress(gpa, z, .{ .max_output = plain.len - 1 }));
    try testing.expectError(error.OutputTooLarge, bz.decompress(gpa, z, .{ .max_output = 1000 }));
    try testing.expectError(error.OutputTooLarge, bz.decompress(gpa, z, .{ .max_output = 0 }));
    const empty = try packed_(gpa, "", 1);
    defer gpa.free(empty);
    const none = try bz.decompress(gpa, empty, .{ .max_output = 0 });
    gpa.free(none);
}

test "every proper prefix of a stream is refused, and none panics" {
    const gpa = testing.allocator;
    const plain = try shapeBytes(gpa, "text-small", 700);
    defer gpa.free(plain);
    const z = try packed_(gpa, plain, 1);
    defer gpa.free(z);
    for (0..z.len) |n| {
        if (bz.decompress(gpa, z[0..n], .{})) |out| {
            gpa.free(out);
            return error.PrefixAccepted;
        } else |e| try testing.expect(e == error.TruncatedInput or e == error.TrailingData or e == error.BadMagic);
    }
}

test "every single-bit flip is refused or reads back exactly; the error paths are all reached" {
    const gpa = testing.allocator;
    const plain = try shapeBytes(gpa, "text-small", 600);
    defer gpa.free(plain);
    const z = try packed_(gpa, plain, 1);
    defer gpa.free(z);
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(gpa);
    for (0..z.len * 8) |bit| {
        z[bit / 8] ^= @as(u8, 1) << @intCast(bit % 8);
        defer z[bit / 8] ^= @as(u8, 1) << @intCast(bit % 8);
        if (bz.decompress(gpa, z, .{})) |out| {
            defer gpa.free(out);
            try testing.expectEqualSlices(u8, plain, out);
        } else |e| try seen.put(gpa, @errorName(e), {});
    }
    for ([_][]const u8{ "BadMagic", "BadBlockHeader", "BlockCrcMismatch", "StreamCrcMismatch" }) |e| {
        try testing.expect(seen.contains(e));
    }
}

test "headers: what is and is not a stream" {
    const gpa = testing.allocator;
    try testing.expectError(error.TruncatedInput, bz.decompress(gpa, "", .{}));
    try testing.expectError(error.TruncatedInput, bz.decompress(gpa, "BZh", .{}));
    try testing.expectError(error.BadMagic, bz.decompress(gpa, "BZh0\x17rE8P\x90\x00\x00\x00\x00", .{}));
    try testing.expectError(error.BadMagic, bz.decompress(gpa, "BZhA\x17rE8P\x90\x00\x00\x00\x00", .{}));
    // The level digit is '1'..'9': ':' is one past the top, '/' one below the bottom.
    try testing.expectError(error.BadMagic, bz.decompress(gpa, "BZh:\x17rE8P\x90\x00\x00\x00\x00", .{}));
    try testing.expectError(error.BadMagic, bz.decompress(gpa, "BZh/\x17rE8P\x90\x00\x00\x00\x00", .{}));
    try testing.expectError(error.BadMagic, bz.decompress(gpa, "bzh9", .{}));
    try testing.expectError(error.BadMagic, bz.decompress(gpa, "\x1f\x8b\x08\x00", .{}));
    // The empty stream: header, trailer, combined CRC 0.
    const e = try bz.decompress(gpa, "BZh9\x17rE8P\x90\x00\x00\x00\x00", .{});
    defer gpa.free(e);
    try testing.expectEqual(@as(usize, 0), e.len);
    try testing.expectError(error.StreamCrcMismatch, bz.decompress(gpa, "BZh9\x17rE8P\x90\x00\x00\x00\x01", .{}));
    try testing.expectError(error.BadTrailer, bz.decompress(gpa, "BZh9\x17rE8P\x91\x00\x00\x00\x00", .{}));
    try testing.expectError(error.BadBlockHeader, bz.decompress(gpa, "BZh9\x18rE8P\x90\x00\x00\x00\x00", .{}));
}

test "streams back to back; trailing bytes; the options" {
    const gpa = testing.allocator;
    const a = try packed_(gpa, "first stream, ", 1);
    defer gpa.free(a);
    const b = try packed_(gpa, "second stream", 9);
    defer gpa.free(b);
    const ab = try std.mem.concat(gpa, u8, &.{ a, b, a });
    defer gpa.free(ab);
    const out = try bz.decompress(gpa, ab, .{});
    defer gpa.free(out);
    try testing.expectEqualStrings("first stream, second streamfirst stream, ", out);

    const one = try bz.decompress(gpa, ab, .{ .multi_stream = false });
    defer gpa.free(one);
    try testing.expectEqualStrings("first stream, ", one);

    for ([_][]const u8{ "junk", "BZ", "\x00\x00\x00\x00" }) |tail| {
        const with_tail = try std.mem.concat(gpa, u8, &.{ a, tail });
        defer gpa.free(with_tail);
        try testing.expectError(error.TrailingData, bz.decompress(gpa, with_tail, .{}));
        const lenient = try bz.decompress(gpa, with_tail, .{ .ignore_trailing_garbage = true });
        defer gpa.free(lenient);
        try testing.expectEqualStrings("first stream, ", lenient);
        const first_only = try bz.decompress(gpa, with_tail, .{ .multi_stream = false });
        defer gpa.free(first_only);
        try testing.expectEqualStrings("first stream, ", first_only);
    }
}

test "a second stream that starts and is cut short is a truncation, not trailing garbage" {
    const gpa = testing.allocator;
    const a = try packed_(gpa, "first", 1);
    defer gpa.free(a);
    const cut = try std.mem.concat(gpa, u8, &.{ a, "BZh9" });
    defer gpa.free(cut);
    try testing.expectError(error.TruncatedInput, bz.decompress(gpa, cut, .{}));
    try testing.expectError(error.TruncatedInput, bz.decompress(gpa, cut, .{ .ignore_trailing_garbage = true }));
}

test "randomised blocks (bzip2 0.9.0) are read, and differ on the wire" {
    const gpa = testing.allocator;
    for ([_][]const u8{ "text-small", "run259", "all-bytes", "runs-300" }) |name| {
        const plain = try shapeBytes(gpa, name, 5000);
        defer gpa.free(plain);
        const normal = try packed_(gpa, plain, 1);
        defer gpa.free(normal);
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var enc = try bz.Encoder.init(gpa, &out.writer, .{ .level = 1 });
        defer enc.deinit();
        enc.randomise = true;
        try enc.write(plain);
        try enc.finish();
        try testing.expect(!std.mem.eql(u8, normal, out.written()));
        const back = try bz.decompress(gpa, out.written(), .{});
        defer gpa.free(back);
        try testing.expectEqualSlices(u8, plain, back);
    }
}

test "a failed decoder stays failed (every later read returns the first error)" {
    const a = std.testing.allocator;
    var r: std.Io.Reader = .fixed("BZh9" ++ "\x31\x41\x59\x26\x53\x59" ++ "\xff\xff\xff\xff\xff\xff\xff\xff");
    var d = try @import("decoder.zig").Decoder.init(a, &r, .{});
    defer d.deinit();
    var buf: [64]u8 = undefined;
    const first = d.read(&buf);
    try std.testing.expect(std.meta.isError(first));
    const e1 = if (first) |_| unreachable else |e| e;
    for (0..64) |_| try std.testing.expectError(e1, d.read(&buf));
}

test "the encoder refuses a second finish and a write after finish" {
    const a = std.testing.allocator;
    var out: std.Io.Writer.Allocating = .init(a);
    defer out.deinit();
    var e = try @import("encoder.zig").Encoder.init(a, &out.writer, .{});
    defer e.deinit();
    try e.write("abc");
    try e.finish();
    try std.testing.expectError(error.AlreadyFinished, e.finish());
    try std.testing.expectError(error.AlreadyFinished, e.write("x"));
}

// ── hand-built streams ─────────────────────────────────────────────────
//
// The encoder never writes the malformed or the extreme-but-legal shapes the
// decoder must judge (a table count of one, a selector list longer than
// libbzip2's array, a code length of 21, a run of 2^21 symbols, ...), so
// these streams are assembled bit by bit: a stream header, one block whose
// every field is a parameter, the trailer.

const crc = @import("crc.zig");

const BitWriter = struct {
    gpa: std.mem.Allocator,
    bytes: std.ArrayList(u8) = .empty,
    cur: u8 = 0,
    used: u4 = 0,

    fn deinit(w: *BitWriter) void {
        w.bytes.deinit(w.gpa);
    }

    fn bit(w: *BitWriter, b: u1) !void {
        w.cur = (w.cur << 1) | b;
        w.used += 1;
        if (w.used == 8) {
            try w.bytes.append(w.gpa, w.cur);
            w.cur = 0;
            w.used = 0;
        }
    }

    /// The low `n` bits of `value`, most significant first.
    fn put(w: *BitWriter, value: u64, n: u7) !void {
        var i: u7 = n;
        while (i > 0) {
            i -= 1;
            try w.bit(@truncate(value >> @intCast(i)));
        }
    }

    /// Zero-pads to a byte and hands the bytes over.
    fn finish(w: *BitWriter) ![]u8 {
        while (w.used != 0) try w.bit(0);
        return w.bytes.toOwnedSlice(w.gpa);
    }
};

/// One block, field by field. The symbols in use are the bytes 'a', 'b', ...
/// (`n_in_use` of them); every table gets the same code lengths and every
/// selector is table 0. The defaults are a valid block that decodes to "a".
const Block = struct {
    crc: u32 = 0xe1ec_0e0a, // overwritten by `plainCrc` where it matters
    randomised: bool = false,
    orig: u32 = 0,
    n_in_use: u32 = 1,
    /// The 3-bit table count as written, and how many tables follow.
    ng: u32 = 2,
    /// The 15-bit selector count as written, and that many '0' selector bits.
    n_sel: u32 = 1,
    lens: []const u8 = &.{ 1, 2, 2 },
    /// The 5-bit starting length of every table (default: `lens[0]`).
    start: ?u8 = null,
    /// MTF symbols as numbers (0 RUNA, 1 RUNB, 2.. MTF positions + 1, EOB last).
    syms: []const u16 = &.{ 0, 2 },
    /// Stop right after the origin pointer.
    header_only: bool = false,
};

fn putBlock(w: *BitWriter, b: Block) !void {
    for ("\x31\x41\x59\x26\x53\x59") |c| try w.put(c, 8);
    try w.put(b.crc, 32);
    try w.put(@intFromBool(b.randomised), 1);
    try w.put(b.orig, 24);
    if (b.header_only) return;

    // Symbol map: bytes 0x61.. all lie in the group of 16 that starts at 0x60 (bit 6).
    try w.put(@as(u32, 1) << 9, 16);
    var m: u32 = 0;
    for (1..b.n_in_use + 1) |j| m |= @as(u32, 1) << @intCast(15 - j);
    try w.put(m, 16);

    try w.put(b.ng, 3);
    try w.put(b.n_sel, 15);
    for (0..b.n_sel) |_| try w.bit(0);

    for (0..b.ng) |_| {
        var curr: i32 = b.start orelse b.lens[0];
        try w.put(@intCast(curr), 5);
        for (b.lens) |target| {
            while (curr < target) : (curr += 1) try w.put(0b10, 2);
            while (curr > target) : (curr -= 1) try w.put(0b11, 2);
            try w.bit(0);
        }
    }

    // Canonical codes, shortest first (libbzip2's hbAssignCodes).
    var code: [32]u64 = undefined;
    var vec: u64 = 0;
    for (1..22) |n| {
        for (b.lens, 0..) |l, i| if (l == n) {
            code[i] = vec;
            vec += 1;
        };
        vec <<= 1;
    }
    for (b.syms) |sym| try w.put(code[sym], @intCast(b.lens[sym]));
}

fn buildStream(gpa: std.mem.Allocator, level: u8, b: Block) ![]u8 {
    var w: BitWriter = .{ .gpa = gpa };
    defer w.deinit();
    for ("BZh") |c| try w.put(c, 8);
    try w.put('0' + level, 8);
    try putBlock(&w, b);
    if (!b.header_only) {
        try w.put(0x177245385090, 48);
        try w.put(b.crc, 32); // one block: the stream CRC is the block CRC
    }
    return w.finish();
}

fn plainCrc(data: []const u8) u32 {
    return crc.finalize(crc.update(crc.init, data));
}

/// The RUNA/RUNB symbols for a run of `n` (bijective base 2).
fn runSyms(gpa: std.mem.Allocator, list: *std.ArrayList(u16), n_in: u64) !void {
    var n = n_in;
    while (n > 0) {
        if (n & 1 == 1) {
            try list.append(gpa, 0);
            n = (n - 1) / 2;
        } else {
            try list.append(gpa, 1);
            n = (n - 2) / 2;
        }
    }
}

fn expectBlock(level: u8, b: Block, want: anyerror![]const u8) !void {
    const gpa = testing.allocator;
    const z = try buildStream(gpa, level, b);
    defer gpa.free(z);
    if (want) |bytes| {
        const got = try bz.decompress(gpa, z, .{});
        defer gpa.free(got);
        try testing.expectEqualSlices(u8, bytes, got);
    } else |e| try testing.expectError(e, bz.decompress(gpa, z, .{}));
}

test "hand-built: the default block is valid, so every refusal below is the one field" {
    try expectBlock(1, .{ .crc = plainCrc("a") }, "a");
    try expectBlock(9, .{ .crc = plainCrc("a"), .ng = 6 }, "a");
}

test "hand-built: a table count outside 2..6 is BadTables, even when all else is valid" {
    try expectBlock(1, .{ .crc = plainCrc("a"), .ng = 1 }, error.BadTables);
    try expectBlock(1, .{ .crc = plainCrc("a"), .ng = 0 }, error.BadTables);
    try expectBlock(1, .{ .crc = plainCrc("a"), .ng = 7 }, error.BadTables);
}

test "hand-built: the selector list may be longer than 18002; the surplus is ignored" {
    // libbzip2 reads them all, keeps the first 18002 and clamps the count.
    for ([_]u32{ 18002, 18003, 18010, 32767 }) |n_sel| {
        try expectBlock(1, .{ .crc = plainCrc("a"), .n_sel = n_sel }, "a");
        try expectBlock(9, .{ .crc = plainCrc("a"), .n_sel = n_sel }, "a");
    }
    try expectBlock(1, .{ .crc = plainCrc("a"), .n_sel = 0 }, error.BadTables);
}

test "hand-built: code lengths are 1..20" {
    // Start length 0 and 21 are out of range even though the walk would bring them in.
    try expectBlock(1, .{ .crc = plainCrc("a"), .start = 0 }, error.BadTables);
    try expectBlock(1, .{ .crc = plainCrc("a"), .start = 21 }, error.BadTables);
    try expectBlock(1, .{ .crc = plainCrc("a"), .start = 31 }, error.BadTables);
    // A length walking up to 21 is refused, 20 is a table that works (EOB = '11' + 18 zeros).
    try expectBlock(1, .{ .crc = plainCrc("a"), .lens = &.{ 1, 2, 21 } }, error.BadTables);
    try expectBlock(1, .{ .crc = plainCrc("a"), .lens = &.{ 1, 2, 20 } }, "a");
    // ... and a walk that goes down to 0.
    try expectBlock(1, .{ .crc = plainCrc("a"), .lens = &.{ 2, 1, 0 } }, error.BadTables);
}

test "hand-built: the origin pointer is judged before the block body is read" {
    // 100 010 = 10 + 100 000 is the largest legal value at level 1; with the
    // body missing the early range check is the only thing that says BadOrigPtr.
    try expectBlock(1, .{ .orig = 0xff_ffff, .header_only = true }, error.BadOrigPtr);
    try expectBlock(1, .{ .orig = 100_011, .header_only = true }, error.BadOrigPtr);
    try expectBlock(1, .{ .orig = 100_010, .header_only = true }, error.TruncatedInput);
    try expectBlock(9, .{ .orig = 900_011, .header_only = true }, error.BadOrigPtr);
    try expectBlock(9, .{ .orig = 900_010, .header_only = true }, error.TruncatedInput);
    // With a body, an origin past the block is BadOrigPtr as well (here nblock = 1).
    try expectBlock(1, .{ .crc = plainCrc("a"), .orig = 1 }, error.BadOrigPtr);
    try expectBlock(1, .{ .crc = plainCrc("a"), .orig = 0xff_ffff }, error.BadOrigPtr);
}

test "hand-built: a run of 2^21 or more is BadRun, the symbol before it is not" {
    const gpa = testing.allocator;
    // 22 RUNA in a row: the 22nd carries weight 2^21. BadRun, not the
    // BlockOverflow that the run's total would be if the limit were higher.
    var syms: std.ArrayList(u16) = .empty;
    defer syms.deinit(gpa);
    try syms.appendNTimes(gpa, 0, 22);
    try syms.append(gpa, 2);
    try expectBlock(1, .{ .syms = syms.items }, error.BadRun);
    try expectBlock(9, .{ .syms = syms.items }, error.BadRun);
    // 21 RUNA: 2^21 - 1 bytes, over the block size.
    syms.clearRetainingCapacity();
    try syms.appendNTimes(gpa, 0, 21);
    try syms.append(gpa, 2);
    try expectBlock(1, .{ .syms = syms.items }, error.BlockOverflow);
    try expectBlock(9, .{ .syms = syms.items }, error.BlockOverflow);
}

test "hand-built: a run fills a level-1 block exactly, one more byte overflows" {
    const gpa = testing.allocator;
    var syms: std.ArrayList(u16) = .empty;
    defer syms.deinit(gpa);

    // 100 000 'a' symbols: the initial run-length coding turns every 5 of them
    // (four equal bytes and a count of 'a' = 97) into 101 bytes.
    try runSyms(gpa, &syms, 100_000);
    try syms.append(gpa, 2);
    const full = try gpa.alloc(u8, 2_020_000);
    defer gpa.free(full);
    @memset(full, 'a');
    try expectBlock(1, .{ .crc = plainCrc(full), .syms = syms.items }, full);

    syms.clearRetainingCapacity();
    try runSyms(gpa, &syms, 100_001);
    try syms.append(gpa, 2);
    try expectBlock(1, .{ .syms = syms.items }, error.BlockOverflow);
    // One less passes the size check and then fails the CRC (which is 0 here).
    syms.clearRetainingCapacity();
    try runSyms(gpa, &syms, 99_995);
    try syms.append(gpa, 2);
    try expectBlock(1, .{ .crc = 0, .syms = syms.items }, error.BlockCrcMismatch);
}

test "hand-built: a symbol after a full level-1 block overflows it" {
    const gpa = testing.allocator;
    var syms: std.ArrayList(u16) = .empty;
    defer syms.deinit(gpa);
    // 100 000 from a run, then one MTF symbol (position 1 of two bytes), then EOB.
    try runSyms(gpa, &syms, 100_000);
    try syms.appendSlice(gpa, &.{ 2, 3 });
    const two: Block = .{ .n_in_use = 2, .lens = &.{ 2, 2, 2, 2 }, .syms = syms.items };
    try expectBlock(1, two, error.BlockOverflow);
    // One less from the run and the same symbol fits: the block is full, not over.
    syms.clearRetainingCapacity();
    try runSyms(gpa, &syms, 99_999);
    try syms.appendSlice(gpa, &.{ 2, 3 });
    try expectBlock(1, .{ .n_in_use = 2, .lens = &.{ 2, 2, 2, 2 }, .syms = syms.items }, error.BlockCrcMismatch);
}

test "randomised block longer than the flip table's 512 distances round-trips" {
    // The distances sum to 278 212: past that the decoder must wrap to the
    // first entry again (and must have used the 512th before).
    const gpa = testing.allocator;
    const plain = try shapeBytes(gpa, "text-1m", 600_000);
    defer gpa.free(plain);
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var enc = try bz.Encoder.init(gpa, &out.writer, .{ .level = 9 });
    defer enc.deinit();
    enc.randomise = true;
    try enc.write(plain);
    try enc.finish();
    const back = try bz.decompress(gpa, out.written(), .{});
    defer gpa.free(back);
    try testing.expectEqualSlices(u8, plain, back);
}

test "the six block-magic bytes: a flip of any bit is BadBlockHeader" {
    const gpa = testing.allocator;
    const z = try packed_(gpa, "hello, block magic", 1);
    defer gpa.free(z);
    // Bytes 0..3 are "BZh1", the block starts at offset 4 with 31 41 59 26 53 59.
    try testing.expectEqualSlices(u8, "\x31\x41\x59\x26\x53\x59", z[4..10]);
    for (4..10) |at| for (0..8) |b| {
        z[at] ^= @as(u8, 1) << @intCast(b);
        defer z[at] ^= @as(u8, 1) << @intCast(b);
        try testing.expectError(error.BadBlockHeader, bz.decompress(gpa, z, .{}));
    };
}

// Guards the std 0.17 `defaultReadVec` direct read: a reader without `.readVec = refillReadVec` fails this.
test "DecompressReader: small reads after the buffer filled are served from a refilled buffer" {
    const gpa = testing.allocator;
    var plain: [6000]u8 = undefined;
    for (&plain, 0..) |*b, i| b.* = @truncate(i *% 7 +% i / 13);
    const z = try packed_(gpa, &plain, 1);
    defer gpa.free(z);
    var in: std.Io.Reader = .fixed(z);
    var buf: [64]u8 = undefined;
    var d = try bz.DecompressReader.init(gpa, &in, &buf, .{});
    defer d.deinit();
    var got: [8]u8 = undefined;
    var off: usize = 0;
    var reads: usize = 0;
    var buffered: usize = 0;
    while (off < plain.len) : (off += got.len) {
        try d.reader.readSliceAll(&got);
        try testing.expectEqualSlices(u8, plain[off..][0..got.len], &got);
        reads += 1;
        if (d.reader.bufferedLen() > 0) buffered += 1;
    }
    try testing.expect(buffered * 2 >= reads);
}
