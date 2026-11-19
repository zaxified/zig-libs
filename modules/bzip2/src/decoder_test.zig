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
    /// Stop right after the selector list (before the coding tables).
    stop_after_sel: bool = false,
    /// MTF-coded values (unary on the wire) of the first selectors; the rest are 0.
    sel_vals: []const u8 = &.{},
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
    for (0..b.n_sel) |i| {
        const v: usize = if (i < b.sel_vals.len) b.sel_vals[i] else 0;
        for (0..v) |_| try w.bit(1);
        try w.bit(0);
    }
    if (b.stop_after_sel) {
        // A valid 5-bit start length (5) so that the first table is the next thing judged.
        try w.put(5, 5);
        return;
    }

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
    if (!b.header_only and !b.stop_after_sel) {
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

test "hand-built: a zero selector count is judged before the tables are read" {
    // With the stream cut right after the selector list, only the count check
    // can say BadTables; one selector leaves the (missing) tables to read.
    // 15 symbols in use: the first table's 17 length bits cannot fit in the padding.
    try expectBlock(1, .{ .n_in_use = 15, .n_sel = 0, .stop_after_sel = true }, error.BadTables);
    try expectBlock(1, .{ .n_in_use = 15, .n_sel = 1, .stop_after_sel = true }, error.TruncatedInput);
}

test "hand-built: a selector value is below the table count" {
    const a = plainCrc("a");
    try expectBlock(1, .{ .crc = a, .ng = 2, .sel_vals = &.{1} }, "a");
    try expectBlock(1, .{ .crc = a, .ng = 2, .sel_vals = &.{2} }, error.BadTables);
    try expectBlock(1, .{ .crc = a, .ng = 6, .sel_vals = &.{5} }, "a");
    try expectBlock(1, .{ .crc = a, .ng = 6, .sel_vals = &.{6} }, error.BadTables);
    try expectBlock(1, .{ .crc = a, .ng = 6, .sel_vals = &.{7} }, error.BadTables);
    // Cut right after: the value check fires while the selectors are read.
    try expectBlock(1, .{ .n_in_use = 15, .ng = 2, .sel_vals = &.{2}, .stop_after_sel = true }, error.BadTables);
    try expectBlock(1, .{ .n_in_use = 15, .ng = 2, .sel_vals = &.{1}, .stop_after_sel = true }, error.TruncatedInput);
}

test "hand-built: more groups of symbols than selectors is BadTables, also inside a run" {
    const gpa = testing.allocator;
    var syms: std.ArrayList(u16) = .empty;
    defer syms.deinit(gpa);
    // 60 MTF symbols (position 1 of two bytes), EOB; one selector covers 50.
    try syms.appendNTimes(gpa, 2, 60);
    try syms.append(gpa, 3);
    const two: Block = .{ .n_in_use = 2, .lens = &.{ 2, 2, 2, 2 }, .syms = syms.items };
    try expectBlock(1, two, error.BadTables);
    // 49 MTF symbols, then a run symbol that is the 50th, then its continuation
    // is the first symbol of the missing second group.
    syms.clearRetainingCapacity();
    try syms.appendNTimes(gpa, 2, 49);
    try syms.appendSlice(gpa, &.{ 0, 2, 3 });
    try expectBlock(1, .{ .n_in_use = 2, .lens = &.{ 2, 2, 2, 2 }, .syms = syms.items }, error.BadTables);
    // Two selectors cover 100 symbols: 99 + EOB passes the group check (then fails the CRC).
    syms.clearRetainingCapacity();
    try syms.appendNTimes(gpa, 2, 99);
    try syms.append(gpa, 3);
    try expectBlock(1, .{ .n_in_use = 2, .n_sel = 2, .lens = &.{ 2, 2, 2, 2 }, .syms = syms.items }, error.BlockCrcMismatch);
}

// ── whole-module mutation, 2026-11-19: tests for the survivors ──────────

test "headers: each of the three magic letters is checked alone" {
    const gpa = testing.allocator;
    const tail = "\x17rE8P\x90\x00\x00\x00\x00";
    try testing.expectError(error.BadMagic, bz.decompress(gpa, "XZh9" ++ tail, .{}));
    try testing.expectError(error.BadMagic, bz.decompress(gpa, "BXh9" ++ tail, .{}));
    try testing.expectError(error.BadMagic, bz.decompress(gpa, "BZx9" ++ tail, .{}));
    const e = try bz.decompress(gpa, "BZh1" ++ tail, .{});
    gpa.free(e);
}

test "Decoder.streams counts the streams read" {
    const gpa = testing.allocator;
    const a = try packed_(gpa, "one", 1);
    defer gpa.free(a);
    const joined = try std.mem.concat(gpa, u8, &.{ a, a, a });
    defer gpa.free(joined);
    var in: std.Io.Reader = .fixed(joined);
    var d = try bz.Decoder.init(gpa, &in, .{});
    defer d.deinit();
    var out: [64]u8 = undefined;
    var total: usize = 0;
    while (true) {
        const n = try d.read(out[total..]);
        if (n == 0) break;
        total += n;
    }
    try testing.expectEqualStrings("oneoneone", out[0..total]);
    try testing.expectEqual(@as(u32, 3), d.streams);
}

test "hand-built: a 20-bit code is decoded by the symbol loop as well as the run loop" {
    // Symbols: 0 RUNA, 1 RUNB, 2 = 'b' (MTF position 1), 3 = EOB; lengths 2,2,2,20.
    // The plain-symbol branch reads the 20-bit EOB itself here (the run loop
    // reads it in "a 20-bit code" above).
    const lens: []const u8 = &.{ 2, 2, 2, 20 };
    try expectBlock(1, .{ .crc = plainCrc("b"), .n_in_use = 2, .lens = lens, .syms = &.{ 2, 3 } }, "b");
    try expectBlock(1, .{ .crc = plainCrc("bb"), .n_in_use = 2, .lens = lens, .syms = &.{ 2, 0, 3 } }, "bb");
}

test "hand-built: a run after a symbol overflows the block as a whole" {
    const gpa = testing.allocator;
    var syms: std.ArrayList(u16) = .empty;
    defer syms.deinit(gpa);
    // One symbol, then a run that alone would fit but together with it does not.
    try syms.append(gpa, 2);
    try runSyms(gpa, &syms, 100_000);
    try syms.append(gpa, 3);
    try expectBlock(1, .{ .n_in_use = 2, .lens = &.{ 2, 2, 2, 2 }, .syms = syms.items }, error.BlockOverflow);
}

test "hand-built: blocks that end in one, two or three equal bytes" {
    const gpa = testing.allocator;
    var syms: std.ArrayList(u16) = .empty;
    defer syms.deinit(gpa);
    for ([_]usize{ 1, 2, 3 }) |n| {
        syms.clearRetainingCapacity();
        try runSyms(gpa, &syms, n);
        try syms.append(gpa, 2);
        const want = try gpa.alloc(u8, n);
        defer gpa.free(want);
        @memset(want, 'a');
        try expectBlock(1, .{ .crc = plainCrc(want), .syms = syms.items }, want);
    }
}

/// A counting allocator: the largest request and the number of allocations and resizes.
const Counting = struct {
    parent: std.mem.Allocator,
    biggest: usize = 0,
    calls: usize = 0,

    const vtable: std.mem.Allocator.VTable = .{ .alloc = alloc, .resize = resize, .remap = remap, .free = free };

    fn allocator(c: *Counting) std.mem.Allocator {
        return .{ .ptr = c, .vtable = &vtable };
    }
    fn alloc(ctx: *anyopaque, len: usize, a: std.mem.Alignment, ra: usize) ?[*]u8 {
        const c: *Counting = @ptrCast(@alignCast(ctx));
        c.biggest = @max(c.biggest, len);
        c.calls += 1;
        return c.parent.rawAlloc(len, a, ra);
    }
    fn resize(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, n: usize, ra: usize) bool {
        const c: *Counting = @ptrCast(@alignCast(ctx));
        c.biggest = @max(c.biggest, n);
        c.calls += 1;
        return c.parent.rawResize(m, a, n, ra);
    }
    fn remap(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, n: usize, ra: usize) ?[*]u8 {
        const c: *Counting = @ptrCast(@alignCast(ctx));
        c.biggest = @max(c.biggest, n);
        c.calls += 1;
        return c.parent.rawRemap(m, a, n, ra);
    }
    fn free(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, ra: usize) void {
        const c: *Counting = @ptrCast(@alignCast(ctx));
        c.parent.rawFree(m, a, ra);
    }
};

test "the block buffer grows geometrically and never past the block size" {
    // A full level-1 block: 100 000 symbols make the block buffer 4 * 100 000
    // bytes, reached in a handful of steps (the growth doubles, capped at the
    // block size).
    const gpa = testing.allocator;
    var syms: std.ArrayList(u16) = .empty;
    defer syms.deinit(gpa);
    try syms.appendNTimes(gpa, 2, 100_000);
    try syms.append(gpa, 3);
    const z = try buildStream(gpa, 1, .{ .n_in_use = 2, .n_sel = 2001, .lens = &.{ 2, 2, 2, 2 }, .syms = syms.items, .crc = 0 });
    defer gpa.free(z);
    var c: Counting = .{ .parent = gpa };
    // The CRC is 0: the decode fails after the block is read, which is all that is measured.
    var in: std.Io.Reader = .fixed(z);
    var sink: std.Io.Writer.Discarding = .init(&.{});
    try testing.expectError(error.BlockCrcMismatch, bz.decompressStream(c.allocator(), &in, &sink.writer, .{}));
    if (c.biggest > 4 * 100_000 + 64 * 1024 or c.biggest < 4 * 100_000 or c.calls >= 40) {
        std.debug.print("largest request {d}, {d} calls\n", .{ c.biggest, c.calls });
        return error.TestUnexpectedResult;
    }
}

test "Decoder.total_out stops one byte past max_output" {
    const gpa = testing.allocator;
    const plain = try shapeBytes(gpa, "zeros-2m", null);
    defer gpa.free(plain);
    const z = try packed_(gpa, plain, 9);
    defer gpa.free(z);
    for ([_]u64{ 20_000, 50_001, 1_000_000 }) |cap| {
        var in: std.Io.Reader = .fixed(z);
        var d = try bz.Decoder.init(gpa, &in, .{ .max_output = cap });
        defer d.deinit();
        var buf: [16 * 1024]u8 = undefined;
        while (true) {
            const n = d.read(&buf) catch |e| {
                try testing.expectEqual(error.OutputTooLarge, e);
                break;
            };
            try testing.expect(n > 0);
        }
        try testing.expectEqual(cap + 1, d.total_out);
    }
}

/// A writer with no buffer of its own that collects what is drained into it.
const Collect = struct {
    w: std.Io.Writer = .{ .vtable = &vtable, .buffer = &.{} },
    list: std.ArrayList(u8) = .empty,

    const vtable: std.Io.Writer.VTable = .{ .drain = drain };

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const s: *Collect = @alignCast(@fieldParentPtr("w", w));
        // What the writer has buffered goes first.
        s.list.appendSlice(testing.allocator, w.buffer[0..w.end]) catch return error.WriteFailed;
        w.end = 0;
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            s.list.appendSlice(testing.allocator, d) catch return error.WriteFailed;
            n += d.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| s.list.appendSlice(testing.allocator, last) catch return error.WriteFailed;
        return n + last.len * splat;
    }
};

test "decompressStream returns the length, flushes a buffered writer, and takes an unbuffered one" {
    const gpa = testing.allocator;
    // 2 * 16 384 + 17 bytes: the last chunk handed to the writer is shorter than its buffer.
    const plain = try shapeBytes(gpa, "text-150k", 2 * 16 * 1024 + 17);
    defer gpa.free(plain);
    const z = try packed_(gpa, plain, 3);
    defer gpa.free(z);
    // A writer with a buffer: the bytes must be out of it when the call returns.
    {
        var sink: Collect = .{};
        defer sink.list.deinit(gpa);
        var buf: [100]u8 = undefined;
        sink.w.buffer = &buf;
        var in: std.Io.Reader = .fixed(z);
        const n = try bz.decompressStream(gpa, &in, &sink.w, .{});
        try testing.expectEqual(@as(u64, plain.len), n);
        try testing.expectEqualSlices(u8, plain, sink.list.items);
    }
    // Through the pull reader into a writer without a buffer (its own tmp path),
    // and with `.nothing` as the limit (nothing is read, nothing is the end).
    {
        var sink: Collect = .{};
        defer sink.list.deinit(gpa);
        var in: std.Io.Reader = .fixed(z);
        var r = try bz.DecompressReader.init(gpa, &in, &.{}, .{});
        defer r.deinit();
        try testing.expectEqual(@as(usize, 0), try r.reader.stream(&sink.w, .nothing));
        _ = try r.reader.streamRemaining(&sink.w);
        try testing.expectEqualSlices(u8, plain, sink.list.items);
    }
}

test "decompress on a failing allocator is OutOfMemory or a result, never another error" {
    const gpa = testing.allocator;
    const plain = try shapeBytes(gpa, "text-150k", null);
    defer gpa.free(plain);
    const z = try packed_(gpa, plain, 1);
    defer gpa.free(z);
    var any_oom = false;
    for (0..24) |i| {
        var fa = testing.FailingAllocator.init(gpa, .{ .fail_index = i });
        if (bz.decompress(fa.allocator(), z, .{})) |out| {
            fa.allocator().free(out);
        } else |e| {
            try testing.expectEqual(error.OutOfMemory, e);
            any_oom = true;
        }
    }
    try testing.expect(any_oom);
}

test "DecompressReader odd-sized reads keep the unread bytes of a refill" {
    const gpa = testing.allocator;
    var plain: [9000]u8 = undefined;
    for (&plain, 0..) |*b, i| b.* = @truncate(i *% 131 +% i / 7);
    const z = try packed_(gpa, &plain, 1);
    defer gpa.free(z);
    for ([_]usize{ 7, 13, 61 }) |step| {
        var in: std.Io.Reader = .fixed(z);
        var buf: [64]u8 = undefined;
        var d = try bz.DecompressReader.init(gpa, &in, &buf, .{});
        defer d.deinit();
        var got: [61]u8 = undefined;
        var off: usize = 0;
        while (off + step <= plain.len) : (off += step) {
            try d.reader.readSliceAll(got[0..step]);
            try testing.expectEqualSlices(u8, plain[off..][0..step], got[0..step]);
        }
    }
}

test "an unbuffered input reader decodes many small streams (every bit alignment)" {
    const gpa = testing.allocator;
    var text: [80]u8 = undefined;
    for (&text, 0..) |*b, i| b.* = @intCast('a' + (i * 7 + i / 3) % 23);
    for (1..text.len) |len| {
        const z = try packed_(gpa, text[0..len], 1);
        defer gpa.free(z);
        var calls: [1]std.testing.Reader.Call = .{.{ .buffer = z }};
        var tr: std.testing.Reader = .init(&.{}, &calls);
        tr.artificial_limit = .limited(3);
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var r = try bz.DecompressReader.init(gpa, &tr.interface, &.{}, .{});
        defer r.deinit();
        _ = try r.reader.streamRemaining(&out.writer);
        try testing.expectEqualSlices(u8, text[0..len], out.written());
    }
}

test "randomised blocks: the flip table restarts with every block" {
    const gpa = testing.allocator;
    const plain = try shapeBytes(gpa, "text-1m", 250_000);
    defer gpa.free(plain);
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var enc = try bz.Encoder.init(gpa, &out.writer, .{ .level = 1 });
    defer enc.deinit();
    enc.randomise = true;
    try enc.write(plain);
    try enc.finish();
    const back = try bz.decompress(gpa, out.written(), .{});
    defer gpa.free(back);
    try testing.expectEqualSlices(u8, plain, back);
}

test "DecompressReader: lines that cross the buffer end keep their unread head" {
    // takeDelimiter needs more than what is buffered, so the refill must move the
    // unread octets to the front of the buffer first.
    const gpa = testing.allocator;
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(gpa);
    for (0..300) |i| try text.print(gpa, "line {d}: {d}\n", .{ i, i * 7919 % 10007 });
    const z = try packed_(gpa, text.items, 1);
    defer gpa.free(z);
    var in: std.Io.Reader = .fixed(z);
    var buf: [24]u8 = undefined;
    var d = try bz.DecompressReader.init(gpa, &in, &buf, .{});
    defer d.deinit();
    for (0..300) |i| {
        var want: [48]u8 = undefined;
        const line = try std.fmt.bufPrint(&want, "line {d}: {d}", .{ i, i * 7919 % 10007 });
        try testing.expectEqualStrings(line, (try d.reader.takeDelimiter('\n')).?);
    }
    try testing.expect((try d.reader.takeDelimiter('\n')) == null);
}

test "DecompressReader.readVec keeps the unread octets of the buffer it rebases" {
    const gpa = testing.allocator;
    var plain: [4000]u8 = undefined;
    for (&plain, 0..) |*b, i| b.* = @truncate(i *% 31 +% i / 5);
    const z = try packed_(gpa, &plain, 1);
    defer gpa.free(z);
    var in: std.Io.Reader = .fixed(z);
    var buf: [64]u8 = undefined;
    var d = try bz.DecompressReader.init(gpa, &in, &buf, .{});
    defer d.deinit();
    _ = try d.reader.peek(10);
    d.reader.toss(3);
    const live = d.reader.buffered().len;
    try testing.expect(live >= 7);
    var snapshot: [64]u8 = undefined;
    @memcpy(snapshot[0..live], d.reader.buffered());
    try testing.expectEqualSlices(u8, plain[3..][0..live], snapshot[0..live]);
    var dest: [4]u8 = undefined;
    var vec = [1][]u8{&dest};
    _ = try d.reader.vtable.readVec(&d.reader, &vec);
    try testing.expectEqualSlices(u8, snapshot[0..live], d.reader.buffered()[0..live]);
}
