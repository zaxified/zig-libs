// SPDX-License-Identifier: MIT
//! Encoder tests found by whole-module mutation (2026-11-19, group 2:
//! literals, sequences, FSE, Huffman, superblocks): corners the byte-parity
//! goldens do not reach. Expectations: libzstd 1.5.7's
//! `ZSTD_compressLiterals` (the one-byte `cLitSize` that is not a single
//! symbol), `ZSTD_compressRleLiteralsBlock`, `ZSTD_minGain`, `ZSTD_storeSeq`
//! (lengths of 0xFFFF and 0x10000 + MINMATCH - 1 are the last short ones),
//! RFC 8878 section 3.1.1.3.1 (literals section header sizes), and
//! libzstd's own frames for superblocks of blocks without a sequence
//! (`testdata/superblock_goldens.zig`, `tools/gen-superblock-goldens.sh`;
//! follow-up of 2026-11-19).

const std = @import("std");
const zstd = @import("root.zig");
const literals = @import("literals.zig");
const huf = @import("huf.zig");
const sequences = @import("sequences.zig");
const param_test = @import("param_test.zig");
const sb_goldens = @import("testdata/superblock_goldens.zig");

const gpa = std.testing.allocator;

fn decodes(frame: []const u8, want: []const u8) !void {
    const back = try gpa.alloc(u8, want.len + 1);
    defer gpa.free(back);
    var dec = try zstd.Decompressor.init(gpa, .{});
    defer dec.deinit();
    const got = try dec.decompress(back, frame);
    try std.testing.expectEqualSlices(u8, want, back[0..got]);
}

// -------------------------------------------------- literals: 1-byte payload

/// A literals state whose table codes 'a' and 'b' in one bit each, valid
/// for reuse (as a dictionary's would be).
fn twoSymbolState() !literals.HufState {
    var st: literals.HufState = .{ .repeat = .valid };
    var counts: [256]u32 = @splat(0);
    counts['a'] = 1;
    counts['b'] = 1;
    _ = try huf.buildCTable(&st.table, &counts, 'b', literals.lit_huf_log);
    return st;
}

test "six literals coded in one byte by a reused table are not mistaken for a single symbol" {
    // libzstd: a 1-byte cLitSize is the single-symbol signal, but below 8
    // literals it can be a real 1-byte payload; only all-identical bytes
    // become an RLE section.
    const prev = try twoSymbolState();
    var next: literals.HufState = .{};
    var dst: [64]u8 = undefined;

    _ = try literals.compress(&dst, "aaaaab", &prev, &next, 1, false, false);
    try std.testing.expectEqual(@as(u8, 3), dst[0] & 3); // set_repeat: compressed with the old table
    try std.testing.expectEqual(@as(u8, 0), (dst[0] >> 2) & 3); // one stream

    const n = try literals.compress(&dst, "aaaaaa", &prev, &next, 1, false, false);
    try std.testing.expectEqual(@as(usize, 2), n); // RLE: one header byte, the byte
    try std.testing.expectEqual(@as(u8, 1 | (6 << 3)), dst[0]);
    try std.testing.expectEqual(@as(u8, 'a'), dst[1]);
}

test "the minimum gain follows the strategy from btultra up (ZSTD_minGain)" {
    // minlog = strategy - 1 from btultra (8) up, else 6.
    try std.testing.expectEqual(@as(usize, (4096 >> 6) + 2), literals.minGain(4096, 7));
    try std.testing.expectEqual(@as(usize, (4096 >> 7) + 2), literals.minGain(4096, 8));
    try std.testing.expectEqual(@as(usize, (4096 >> 8) + 2), literals.minGain(4096, 9));
}

// ------------------------------------------- literals: RLE with 3-byte header

test "an RLE literals section of more than 4095 bytes has a 3-byte header" {
    // One block of sequences: 5000 literals of one byte, then a match of
    // 100 over them, then 7 more literals of the same byte: 5007 literals,
    // a single symbol (any other byte among them would make them Huffman
    // coded). Being the frame's first block, it is not stored as an RLE
    // block (ZSTD_compressSequences: `!cctx->isFirstBlock`).
    const lit_len = 5000;
    const src = try gpa.alloc(u8, lit_len + 100 + 7);
    defer gpa.free(src);
    @memset(src, 'x');
    const seqs = [_]zstd.Sequence{
        .{ .offset = 1, .lit_length = lit_len, .match_length = 100 },
        .{ .offset = 0, .lit_length = 7, .match_length = 0 },
    };
    const dst = try gpa.alloc(u8, zstd.compressBound(src.len) + 64);
    defer gpa.free(dst);
    @memset(dst, 0xAA);
    var c: zstd.Compressor = .init(gpa);
    defer c.deinit();
    const n = try c.compressSequences(dst, &seqs, src, .{ .level = 3, .advanced = .{ .block_delimiters = .explicit } });
    try decodes(dst[0..n], src);
    // RFC 8878 section 3.1.1.3.1.1: Literals_Block_Type 1 (RLE),
    // Size_Format 3, Regenerated_Size 5007 in 20 bits, then the byte, at
    // the start of the one compressed block.
    var blk_buf: [4][2]usize = undefined;
    const blks = blocks(dst[0..n], &blk_buf);
    try std.testing.expectEqual(@as(usize, 1), blks.len);
    try std.testing.expectEqual(@as(u8, 2), (dst[blks[0][0]] >> 1) & 3); // Block_Type compressed
    const lit_at = blks[0][0] + 3;
    try std.testing.expectEqualSlices(u8, &.{ 1 | (3 << 2) | ((5007 & 0xF) << 4), (5007 >> 4) & 0xFF, 5007 >> 12, 'x' }, dst[lit_at..][0..4]);
}

test "an RLE literals section header in each of its three sizes (RFC 8878 section 3.1.1.3.1.1)" {
    // ZSTD_compressRleLiteralsBlock: 1 byte up to 31 literals, 2 up to
    // 4095, 3 above; the bytes are the header, then the literal.
    const Case = struct { n: usize, hdr: []const u8 };
    const cases = [_]Case{
        .{ .n = 31, .hdr = &.{1 | (31 << 3)} },
        .{ .n = 32, .hdr = &.{ 1 | (1 << 2) | ((32 & 0xF) << 4), 32 >> 4 } },
        .{ .n = 4095, .hdr = &.{ 1 | (1 << 2) | ((4095 & 0xF) << 4), 4095 >> 4 } },
        .{ .n = 4096, .hdr = &.{ 1 | (3 << 2) | ((4096 & 0xF) << 4), (4096 >> 4) & 0xFF, 4096 >> 12 } },
        .{ .n = 5007, .hdr = &.{ 1 | (3 << 2) | ((5007 & 0xF) << 4), (5007 >> 4) & 0xFF, 5007 >> 12 } },
    };
    const src = try gpa.alloc(u8, 5007);
    defer gpa.free(src);
    @memset(src, 'r');
    for (cases) |k| {
        errdefer std.debug.print("{d} literals\n", .{k.n});
        var dst: [8]u8 = @splat(0xAA);
        // less room than the header and the byte: refused, nothing written
        for (0..k.hdr.len + 1) |room| {
            try std.testing.expectError(error.DstSizeTooSmall, literals.rle(dst[0..room], src[0..k.n]));
            try std.testing.expect(std.mem.allEqual(u8, &dst, 0xAA));
        }
        const n = try literals.rle(dst[0 .. k.hdr.len + 1], src[0..k.n]);
        try std.testing.expectEqual(k.hdr.len + 1, n);
        try std.testing.expectEqualSlices(u8, k.hdr, dst[0..k.hdr.len]);
        try std.testing.expectEqual(@as(u8, 'r'), dst[k.hdr.len]);
    }
}

// ---------------------------------------------------------- long lengths

fn roundTripLevels(src: []const u8, levels: []const i32) !void {
    const dst = try gpa.alloc(u8, zstd.compressBound(src.len));
    defer gpa.free(dst);
    var c: zstd.Compressor = .init(gpa);
    defer c.deinit();
    for (levels) |level| {
        errdefer std.debug.print("level {d}\n", .{level});
        const n = try c.compress(dst, src, .{ .level = level });
        try decodes(dst[0..n], src);
    }
}

test "ZSTD_storeSeq marks a length long only above 0xFFFF (literals) or 0xFFFF + MINMATCH (matches)" {
    // The match finders store through `storeOnly`; the round trips below
    // seldom land on these exact lengths, so the edges are met here.
    var seqs: [1]sequences.SeqDef = undefined;
    var none: [0]u8 = .{};
    var ss: sequences.SeqStore = .{ .seqs = &seqs, .lits = &none, .ll_code = &none, .ml_code = &none, .of_code = &none };
    const Case = struct { ll: usize, ml: usize, want: sequences.LongLengthType };
    const cases = [_]Case{
        .{ .ll = 0xFFFF, .ml = 3, .want = .none },
        .{ .ll = 0x10000, .ml = 3, .want = .literal_length },
        .{ .ll = 0, .ml = 0xFFFF + 3, .want = .none },
        .{ .ll = 0, .ml = 0xFFFF + 4, .want = .match_length },
    };
    for (cases) |k| {
        errdefer std.debug.print("lit {d} match {d}\n", .{ k.ll, k.ml });
        ss.reset();
        ss.storeOnly(k.ll, 1, k.ml);
        try std.testing.expectEqual(k.want, ss.long_length_type);
        try std.testing.expectEqual(@as(u16, @truncate(k.ll)), seqs[0].lit_length);
        try std.testing.expectEqual(@as(u16, @truncate(k.ml - sequences.min_match)), seqs[0].ml_base);
    }
}

test "a literal run of 0xFFFF and a match of 0xFFFF + 3 stay short lengths" {
    // libzstd's ZSTD_storeSeq marks a length as long only above 0xFFFF
    // (literals) or above 0xFFFF + MINMATCH (matches); the run and the
    // match are swept around the edge so that the match finders land on it.
    var prng: std.Random.DefaultPrng = .init(0x5EED_FFFF);
    const r = prng.random();
    const levels = [_]i32{ 1, 6 };
    // Literals: 16 bytes A, A again (a match), 0xFFFF + d random bytes, A.
    for ([_]usize{ 0xFFFE, 0xFFFF, 0x10000 }) |run| {
        errdefer std.debug.print("literal run {d}\n", .{run});
        const src = try gpa.alloc(u8, 32 + run + 16 + 64);
        defer gpa.free(src);
        r.bytes(src);
        @memcpy(src[16..32], src[0..16]);
        src[31 + run] = src[15] +% 1; // no backward extension into the run
        @memcpy(src[32 + run ..][0..16], src[0..16]);
        try roundTripLevels(src, &levels);
    }
    // Matches: R, then R's first 0xFFFF + 3 + d bytes again, then a byte
    // that ends the match.
    for ([_]usize{ 0xFFFF + 2, 0xFFFF + 3, 0xFFFF + 4 }) |len| {
        errdefer std.debug.print("match {d}\n", .{len});
        const head = len + 64;
        const src = try gpa.alloc(u8, head + len + 64);
        defer gpa.free(src);
        r.bytes(src);
        @memcpy(src[head..][0..len], src[0..len]);
        src[head + len] = src[len] +% 1;
        try roundTripLevels(src, &levels);
    }
}

// ------------------------------------------------- superblocks, short room

/// The blocks of a frame (RFC 8878 section 3.1.1): offset and size (header
/// included) of each.
fn blocks(frame: []const u8, out: [][2]usize) [][2]usize {
    const fhd = frame[4];
    const single = (fhd >> 5) & 1;
    const fcs = [4]usize{ single, 2, 4, 8 };
    const did = [4]usize{ 0, 1, 2, 4 };
    var at = 4 + 1 + (1 - @as(usize, single)) + did[fhd & 3] + fcs[fhd >> 6];
    var n: usize = 0;
    while (n < out.len) {
        const h = std.mem.readInt(u24, frame[at..][0..3], .little);
        const size = 3 + if ((h >> 1) & 3 == 1) 1 else h >> 3;
        out[n] = .{ at, size };
        n += 1;
        at += size;
        if (h & 1 == 1) break;
    }
    return out[0..n];
}

/// Stream `src` with one stable output buffer of `room` bytes.
fn stableRun(src: []const u8, level: i32, room: usize) ![]u8 {
    var buf: [96]u8 = undefined;
    const sched = try std.fmt.bufPrint(&buf, "stableOutBuffer=1,targetCBlockSize=1340,maxBlockSize=16384,o{d},c*,e0", .{room});
    const r = try @import("stream_test.zig").runOn(gpa, null, src, level, false, sched, .none);
    return r.out;
}

test "superblocks into a stable output buffer: at every room near a sub-block's edges, refused or a valid frame" {
    // Sub-blocks (targetCBlockSize) write straight into the caller's buffer
    // here, so each room check of compressSuperBlock meets the room it
    // guards. libzstd writes past the end at some of these rooms (see
    // stream_test.zig), so there is no golden: the answer must be
    // DstSizeTooSmall or a frame that decodes, never a panic. Two inputs:
    // 13-byte copies of a random base with one 'x' after each (RLE literal
    // sections), and copies with two letters of text between them
    // (Huffman-coded literals with a table description).
    var prng: std.Random.DefaultPrng = .init(0x5B_0CC);
    const r = prng.random();
    const base = 4096;
    const src = try gpa.alloc(u8, base + 15 * 2200);
    defer gpa.free(src);
    for (0..2) |kind| {
        r.bytes(src[0..base]);
        for (src[0..base]) |*b| b.* |= 0x80; // never a letter
        var at: usize = base;
        while (at + 15 <= src.len) {
            const from = r.uintLessThan(usize, base - 13);
            @memcpy(src[at..][0..13], src[from..][0..13]);
            at += 13;
            if (kind == 0) {
                src[at] = 'x';
                at += 1;
            } else {
                for (0..2) |_| {
                    src[at] = "eeeettaaoinsrhld"[r.uintLessThan(usize, 16)];
                    at += 1;
                }
            }
        }
        @memset(src[at..], 'x');
        for ([_]i32{ 1, 3, 7 }) |level| {
            const full = try stableRun(src, level, zstd.compressBound(src.len));
            defer gpa.free(full);
            try decodes(full, src);
            var blk_buf: [64][2]usize = undefined;
            const blks = blocks(full, &blk_buf);
            try std.testing.expect(blks.len > 4); // sub-blocks are there
            for (blks) |b| {
                const edges = [_][2]usize{ .{ b[0], b[0] + @min(b[1], 160) }, .{ b[0] + b[1] -| 24, b[0] + b[1] + 8 } };
                for (edges) |e| for (e[0]..e[1]) |room| {
                    errdefer std.debug.print("kind {d} level {d} room {d}\n", .{ kind, level, room });
                    if (stableRun(src, level, room)) |out| {
                        defer gpa.free(out);
                        try decodes(out, src);
                    } else |err| try std.testing.expectEqual(error.DstSizeTooSmall, err);
                };
            }
        }
    }
}

/// `tools/gen-superblock-goldens.sh`'s input: 1024 bytes per letter of
/// `layout` (T text, N noise of 64 high byte values, R random, W words; a count
/// before a letter or a parenthesized group repeats it).
fn superblockInput(layout: []const u8) ![]u8 {
    var kinds: std.ArrayList(u8) = .empty;
    defer kinds.deinit(gpa);
    var i: usize = 0;
    while (i < layout.len) {
        var n: usize = 0;
        while (std.ascii.isDigit(layout[i])) : (i += 1) n = n * 10 + (layout[i] - '0');
        var unit: []const u8 = layout[i..][0..1];
        if (layout[i] == '(') {
            const end = std.mem.indexOfScalarPos(u8, layout, i, ')').?;
            unit = layout[i + 1 .. end];
            i = end + 1;
        } else i += 1;
        for (0..@max(n, 1)) |_| try kinds.appendSlice(gpa, unit);
    }
    const text = "the quick brown fox jumps over the lazy dog; ";
    const words = [_][]const u8{ "zero ", "one ", "two ", "three ", "four ", "five ", "six ", "seven " };
    const buf = try gpa.alloc(u8, kinds.items.len * 1024);
    var x: u32 = 2463534242;
    var pending: []const u8 = "";
    for (buf, 0..) |*b, at| {
        const kind = kinds.items[at / 1024];
        if (kind == 'T') {
            b.* = text[(7 * at + (at >> 3)) % 44];
            continue;
        }
        if (kind != 'W' or pending.len == 0) {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
        }
        switch (kind) {
            'W' => {
                if (pending.len == 0) pending = words[x & 7];
                b.* = pending[0];
                pending = pending[1..];
            },
            'N' => b.* = 0x80 | @as(u8, @truncate(x & 63)),
            else => b.* = @truncate(x),
        }
    }
    return buf;
}

test "superblock goldens: blocks without a sequence, sub-blocks, raw tails, literal sampling and block splits are libzstd's" {
    // ZSTD_compressSuperBlock. With 1024-byte blocks the noise blocks have
    // no sequence: dummy sequence statistics (predefined tables, no repeat
    // of the old ones for the next block), one sub-block of literals and a
    // sequences section of 0 (the recipe checks libzstd's frames hold
    // such blocks). With whole blocks, mixes of text and noise are cut
    // into several sub-blocks, and what the last cannot compress (random
    // bytes) is stored raw. Two rows without targetCBlockSize ("-"):
    // HUF_compress's sampling of the first and last 4 KiB of literals
    // suspected incompressible, at 40 KiB and with only the first sample
    // looking incompressible; and the block splitter
    // (splitAfterSequences=1) over long literal runs and mixes.
    var c: zstd.Compressor = .init(gpa);
    defer c.deinit();
    for (sb_goldens.rows) |g| {
        errdefer std.debug.print("layout {s} level {d}\n", .{ g.layout, g.level });
        const src = try superblockInput(g.layout);
        defer gpa.free(src);
        const dst = try gpa.alloc(u8, zstd.compressBound(src.len));
        defer gpa.free(dst);
        var adv: zstd.Advanced = .{};
        var hint: ?u32 = null;
        var it = std.mem.tokenizeScalar(u8, g.params, ',');
        if (!std.mem.eql(u8, g.params, "-")) while (it.next()) |tok| try std.testing.expect(try param_test.applyParam(&adv, &hint, tok));
        const n = try c.compress(dst, src, .{ .level = g.level, .advanced = adv });
        try std.testing.expectEqual(g.len, n);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(dst[0..n], &digest, .{});
        const hex = std.fmt.bytesToHex(digest, .lower);
        try std.testing.expectEqualStrings(g.sha256, &hex);
        try decodes(dst[0..n], src);
    }
}

// ------------------------------------------- Huffman: reuse the old table?

const Decision = struct { h: usize, new_size: usize, old_size: usize };

/// The quantities `HUF_compress_internal` decides on, for `src` against
/// `old`: the new table's header and payload estimate, the old's estimate.
fn decision(src: []const u8, old: *const huf.CTable) !Decision {
    var counts: [256]u32 = @splat(0);
    var max: u32 = 0;
    for (src) |b| {
        counts[b] += 1;
        max = @max(max, b);
    }
    var ct: huf.CTable = .{};
    const log = try huf.buildCTable(&ct, &counts, max, huf.optimalTableLog(literals.lit_huf_log, src.len, max, &counts, false));
    var hdr: [300]u8 = undefined;
    const h = try huf.writeCTable(&hdr, &ct, max, log);
    return .{ .h = h, .new_size = huf.estimateCompressedSize(&ct, &counts, max), .old_size = huf.estimateCompressedSize(old, &counts, max) };
}

test "the old Huffman table is reused when the new one costs as much, or its header leaves no gain" {
    // HUF_compress_internal, repeat == check: reuse when
    // oldSize <= hSize + newSize or hSize + 12 >= srcSize; without a table
    // to reuse, hSize + 12 >= srcSize gives up (0). Inputs meeting each
    // edge are searched for; every edge must be met at least once.
    var prng: std.Random.DefaultPrng = .init(0x4E05_E0);
    const r = prng.random();
    var met: [5]bool = @splat(false);
    var dst: [512]u8 = undefined;
    var tries: usize = 0;
    while (tries < 200_000 and std.mem.indexOfScalar(bool, &met, false) != null) : (tries += 1) {
        const k = 2 + r.uintLessThan(u8, 10); // alphabet size
        var old_counts: [256]u32 = @splat(0);
        for (old_counts[0..k]) |*c| c.* = 1 + r.uintLessThan(u32, 40);
        var old: huf.CTable = .{};
        const old_log = huf.buildCTable(&old, &old_counts, k - 1, literals.lit_huf_log) catch continue;
        _ = old_log;
        var src_buf: [96]u8 = undefined;
        const src = src_buf[0 .. 12 + r.uintLessThan(usize, 80)];
        const skew = r.uintLessThan(u8, k);
        for (src) |*b| b.* = if (r.boolean()) skew else r.uintLessThan(u8, k);
        var largest: usize = 0;
        for (0..k) |s| largest = @max(largest, std.mem.count(u8, src, &.{@as(u8, @intCast(s))}));
        if (largest <= (src.len >> 7) + 4 or largest == src.len) continue;
        const d = decision(src, &old) catch continue;
        const reuse = d.old_size <= d.h + d.new_size or d.h + 12 >= src.len;
        // with the old table (repeat check: it has every symbol)
        var o = old;
        var rep: huf.Repeat = .check;
        const n = try huf.compress(&dst, src, literals.lit_huf_log, .single, &o, &rep, .{});
        if (reuse) {
            if (n == 0) continue; // the old table does not compress it: no edge seen
            try std.testing.expectEqual(huf.Repeat.check, rep);
            if (d.h + 12 >= src.len and d.old_size > d.h + d.new_size) met[0] = true;
            if (d.old_size == d.h + d.new_size and d.h + 12 < src.len) met[1] = true;
            if (d.h + 12 == src.len and d.old_size > d.h + d.new_size) met[2] = true;
        }
        // without one
        var fresh: huf.CTable = .{};
        var none: huf.Repeat = .none;
        const m = try huf.compress(&dst, src, literals.lit_huf_log, .single, &fresh, &none, .{});
        if (d.h + 12 >= src.len) {
            try std.testing.expectEqual(@as(usize, 0), m);
            // the edge counts only where going on would have compressed
            var probe: [512]u8 = undefined;
            var ct: huf.CTable = .{};
            var counts: [256]u32 = @splat(0);
            var max: u32 = 0;
            for (src) |b| {
                counts[b] += 1;
                max = @max(max, b);
            }
            const log = try huf.buildCTable(&ct, &counts, max, huf.optimalTableLog(literals.lit_huf_log, src.len, max, &counts, false));
            const h = try huf.writeCTable(&probe, &ct, max, log);
            const payload = huf.compress1X(probe[h..], src, &ct);
            if (payload != 0 and h + payload < src.len - 1) {
                if (d.h + 12 > src.len) met[3] = true;
                if (d.h + 12 == src.len) met[4] = true;
            }
        }
    }
    errdefer std.debug.print("edges met: {any} after {d} tries\n", .{ met, tries });
    try std.testing.expect(std.mem.indexOfScalar(bool, &met, false) == null);
}
