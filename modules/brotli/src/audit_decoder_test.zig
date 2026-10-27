// SPDX-License-Identifier: MIT

//! Tests asked for by the 2026-10-27 mutation run (A1): each names the
//! mutant it kills.

const std = @import("std");
const testing = std.testing;
const brotli = @import("root.zig");
const tables = @import("tables.zig");
const Guarded = @import("stream_test.zig").Guarded;

// Mutant 46 (decoder.zig `wlen == 0 and distance <= 120`) is equivalent: a
// transform leaves nothing only when OMIT_FIRST/LAST_N (N <= 9) removes the
// whole word, so the word is at most 9 bytes long, its length bucket has at
// least 10 size bits, and transform index >= 1 puts the address at >= 1024 --
// far above 120. For a distance of at most 120 the address is below 120, which
// is transform 0..3 of a word of 20+ bytes: never empty. No stream can tell
// `<= 120` from `< 120`, so there is no test for it.

/// LSB-first bit writer (RFC 7932 section 1.5.1), as in crafted_test.zig.
const W = struct {
    bytes: std.ArrayList(u8) = .empty,
    nbits: usize = 0,

    fn deinit(w: *W) void {
        w.bytes.deinit(testing.allocator);
    }
    fn bit(w: *W, b: u1) !void {
        if (w.nbits % 8 == 0) try w.bytes.append(testing.allocator, 0);
        if (b == 1) w.bytes.items[w.bytes.items.len - 1] |= @as(u8, 1) << @intCast(w.nbits % 8);
        w.nbits += 1;
    }
    fn bits(w: *W, v: u32, n: u6) !void {
        var i: u6 = 0;
        while (i < n) : (i += 1) try w.bit(@truncate(v >> @intCast(i)));
    }
    /// A prefix code, most significant bit first.
    fn msb(w: *W, v: u32, n: u6) !void {
        var i: u6 = n;
        while (i > 0) : (i -= 1) try w.bit(@truncate(v >> @intCast(i - 1)));
    }
    fn pad(w: *W) !void {
        while (w.nbits % 8 != 0) try w.bit(0);
    }
    fn raw(w: *W, data: []const u8) !void {
        std.debug.assert(w.nbits % 8 == 0);
        try w.bytes.appendSlice(testing.allocator, data);
        w.nbits += data.len * 8;
    }
    fn window16(w: *W) !void {
        try w.bits(0, 1);
    }
    fn lastEmpty(w: *W) !void {
        try w.bits(3, 2);
    }
    /// Header of the last, compressed meta-block of `mlen` <= 65536 bytes.
    fn lastCompressed(w: *W, mlen: u32) !void {
        try w.bits(1, 1);
        try w.bits(0, 1);
        try w.bits(0, 2);
        try w.bits(mlen - 1, 16);
    }
    /// Header of a compressed meta-block that is not the last.
    fn compressed(w: *W, mlen: u32) !void {
        try w.bits(0, 1);
        try w.bits(0, 2);
        try w.bits(mlen - 1, 16);
        try w.bits(0, 1); // ISUNCOMPRESSED
    }
    /// A metadata meta-block (not last) skipping `skip` <= 256 bytes: the
    /// bytes follow after `pad`.
    fn metadata(w: *W, skip: u32) !void {
        try w.bits(0, 1); // ISLAST
        try w.bits(3, 2); // MNIBBLES = 0
        try w.bits(0, 1); // reserved
        try w.bits(1, 2); // MSKIPBYTES = 1
        try w.bits(skip - 1, 8);
        try w.pad();
        const zeros: [256]u8 = @splat(0);
        try w.raw(zeros[0..skip]);
    }
    /// A simple prefix code (section 3.4).
    fn simple(w: *W, alphabet_bits: u6, syms: []const u16) !void {
        try w.bits(1, 2);
        try w.bits(@intCast(syms.len - 1), 2);
        for (syms) |s| try w.bits(s, alphabet_bits);
        if (syms.len == 4) try w.bits(0, 1);
    }
};

const Cmd = struct { sym: u16, ins_n: u8, ins_v: u32, cpy_n: u8, cpy_v: u32 };

fn findCmd(ins: u32, cpy: u32, implicit: bool) Cmd {
    for (tables.cmd_lut, 0..) |e, sym| {
        if ((e.distance_code >= 0) != implicit) continue;
        if (ins < e.insert_len_offset or ins >= e.insert_len_offset + (@as(u32, 1) << @intCast(e.insert_len_extra_bits))) continue;
        if (cpy < e.copy_len_offset or cpy >= e.copy_len_offset + (@as(u32, 1) << @intCast(e.copy_len_extra_bits))) continue;
        return .{
            .sym = @intCast(sym),
            .ins_n = e.insert_len_extra_bits,
            .ins_v = ins - e.insert_len_offset,
            .cpy_n = e.copy_len_extra_bits,
            .cpy_v = cpy - e.copy_len_offset,
        };
    }
    unreachable;
}

/// The command's extra bits (after its code, which is zero bits wide when
/// the command code has a single symbol).
fn cmdExtra(w: *W, c: Cmd) !void {
    try w.bits(c.ins_v, @intCast(c.ins_n));
    try w.bits(c.cpy_v, @intCast(c.cpy_n));
}

/// Decode with both decoders; they must give `want`.
fn expectOut(stream: []const u8, opts: brotli.Options, want: []const u8) !void {
    const got = try brotli.decompress(testing.allocator, stream, opts);
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, want, got);
    var in: std.Io.Reader = .fixed(stream);
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    _ = try brotli.decompressStream(testing.allocator, &in, &out.writer, opts);
    try testing.expectEqualSlices(u8, want, out.written());
}

/// Both decoders must refuse with `want`.
fn expectErr(stream: []const u8, opts: brotli.Options, want: anyerror) !void {
    if (brotli.decompress(testing.allocator, stream, opts)) |ok| {
        testing.allocator.free(ok);
        return error.TestExpectedError;
    } else |e| try testing.expectEqual(want, @as(anyerror, e));
    var in: std.Io.Reader = .fixed(stream);
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    if (brotli.decompressStream(testing.allocator, &in, &out.writer, opts)) |_| {
        return error.TestExpectedError;
    } else |e| try testing.expectEqual(want, @as(anyerror, e));
}

/// The header of a one-block-type, one-tree meta-block up to the trees:
/// NBLTYPES 1 x3, NPOSTFIX/NDIRECT 0, context mode 0, NTREES 1 x2.
fn plainHeader(w: *W) !void {
    try w.bits(0, 3);
    try w.bits(0, 6);
    try w.bits(0, 2);
    try w.bits(0, 1);
    try w.bits(0, 1);
}

// --- mutant 34: the hot loop's insert-overrun check ---------------------------

test "A1 m34: an insert longer than MLEN is InvalidLength in the hot loop" {
    // MLEN 1, one command inserting 2 literals (zero-bit code), with 40 bytes
    // of input after it so `hotCommands` runs (it needs 16 at hand). The
    // command's copy would also overrun MLEN, but its distance (the last one,
    // 4) reaches before the 2 bytes written, into the static dictionary with
    // a copy length of 2: InvalidDictionary. Without the check after the
    // insert that is the error given instead of InvalidLength.
    var w: W = .{};
    defer w.deinit();
    const c = findCmd(2, 2, false);
    try w.window16();
    try w.lastCompressed(1);
    try plainHeader(&w);
    try w.simple(8, &.{'a'});
    try w.simple(10, &.{c.sym});
    try w.simple(6, &.{0}); // distance symbol 0: the last distance, no bits
    try cmdExtra(&w, c);
    try w.pad();
    try w.raw(&(@as([40]u8, @splat(0))));
    try expectErr(w.bytes.items, .{}, error.InvalidLength);
}

// --- mutants 64: the checkless literal loop's input bound ---------------------

/// A literal code where symbol `i` (0..15) is `i + 1` bits long, the last two
/// 15: lengths 1..14, 15, 15 fill the code space. Written as a complex code
/// (section 3.5) whose code-length code gives lengths 1..4 three bits, 5..9
/// four and 10..15 five, and stops there as the space is used up.
fn longLiteralCode(w: *W) !void {
    try w.bits(0, 2); // HSKIP 0
    const order = [_]u8{ 1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    for (order) |sym| {
        const l: u8 = if (sym == 0 or sym >= 16) 0 else if (sym <= 4) 3 else if (sym <= 9) 4 else 5;
        switch (l) {
            0 => try w.bits(0, 2),
            3 => try w.bits(2, 2),
            4 => try w.bits(1, 2),
            else => try w.bits(15, 4),
        }
    }
    var i: u32 = 0;
    while (i < 16) : (i += 1) {
        const v: u32 = if (i < 14) i + 1 else 15; // the length of symbol i
        if (v <= 4) {
            try w.msb(v - 1, 3);
        } else if (v <= 9) {
            try w.msb(8 + v - 5, 4);
        } else {
            try w.msb(0b11010 + v - 10, 5);
        }
    }
}

/// Symbol `s` (0..15) of `longLiteralCode`: `s` ones and a zero (15 ones for 15).
fn longLiteral(w: *W, s: u32) !void {
    var i: u32 = 0;
    while (i < s) : (i += 1) try w.bits(1, 1);
    if (s != 15) try w.bits(0, 1);
}

test "A1 m64: a truncated insert of 14/15-bit literals is refused, not read past the input" {
    // One insert of 100 literals, symbols 14 and 13 alternating (15 and 14
    // bits), as the last bytes of the stream. The full stream decodes. Cut
    // after 85 bytes of literals (about 46 of them) it is a TruncatedInput:
    // the checkless loop may take only `(input left - 16) / 2` literals, as
    // each is at most 15 bits and so under two bytes. With `/ 1` it takes 69,
    // which need more bits than the input holds -- it reads past the end (a
    // fault at the guard page, or a bit-reader position beyond the input).
    var w: W = .{};
    defer w.deinit();
    const c = findCmd(100, 2, false);
    try w.window16();
    try w.lastCompressed(100);
    try plainHeader(&w);
    try longLiteralCode(&w);
    try w.simple(10, &.{c.sym});
    try w.simple(6, &.{0});
    try cmdExtra(&w, c);
    var want: [100]u8 = undefined;
    for (&want, 0..) |*b, k| {
        b.* = if (k % 2 == 0) 14 else 13;
        try longLiteral(&w, b.*);
    }
    try w.pad();
    try expectOut(w.bytes.items, .{}, &want);

    // The literals start at the first byte boundary after the command: find
    // it by the length of the stream without them.
    var head: W = .{};
    defer head.deinit();
    try head.window16();
    try head.lastCompressed(100);
    try plainHeader(&head);
    try longLiteralCode(&head);
    try head.simple(10, &.{c.sym});
    try head.simple(6, &.{0});
    try cmdExtra(&head, c);
    const cut = (head.nbits + 7) / 8 + 85;
    try testing.expect(cut < w.bytes.items.len);
    try expectErr(w.bytes.items[0..cut], .{}, error.TruncatedInput);

    const GuardedIn = Guarded(1 << 10);
    const at_edge = GuardedIn.tail(cut);
    @memcpy(at_edge, w.bytes.items[0..cut]);
    try testing.expectError(error.TruncatedInput, brotli.decompress(testing.allocator, at_edge, .{}));
}

// --- mutants 65, 66: a literal block switch inside an insert ------------------

/// A last-block-free stream (compressed meta-block, 100 skipped bytes, empty
/// last) with two literal block types, whose context map `map_hi` gives the
/// second type's 64 contexts and the first type all trees 0. `first_len` is
/// the first block's length code (`len_syms` is the length code's symbols),
/// the trees are `lit0`/`lit1` single-symbol codes. The insert is `insert`
/// literals; the block switch at the end of the first block selects the
/// second type and reads `second` (code, extra bits) for its length.
const TwoTypes = struct {
    insert: u32,
    len_syms: []const u16,
    first_len_code: u1, // which of the two length symbols (when two)
    first_len_extra: u32,
    first_len_extra_bits: u6,
    second_len_code: u1,
    second_len_extra: u32,
    second_len_extra_bits: u6,
    ones_from: u32, // context map of type 1: contexts >= ones_from use tree 1
    lit0: u16,
    lit1: u16,
};

fn twoTypesStream(w: *W, t: TwoTypes) !void {
    const c = findCmd(t.insert, 2, false);
    try w.window16();
    try w.compressed(t.insert);
    // NBLTYPESL = 2, its block-type code (one symbol: "next type"), block
    // length code and the first block's length.
    try w.bits(1, 1);
    try w.bits(0, 3);
    try w.simple(2, &.{1});
    try w.simple(5, t.len_syms);
    if (t.len_syms.len == 2) try w.bits(t.first_len_code, 1);
    try w.bits(t.first_len_extra, t.first_len_extra_bits);
    try w.bits(0, 1); // NBLTYPESI = 1
    try w.bits(0, 1); // NBLTYPESD = 1
    try w.bits(0, 6);
    try w.bits(0, 4); // context modes
    // Literal context map: 2 trees, no run codes, symbols 0 and 1.
    try w.bits(1, 1);
    try w.bits(0, 3);
    try w.bits(0, 1);
    try w.simple(1, &.{ 0, 1 });
    var k: u32 = 0;
    while (k < 64) : (k += 1) try w.bits(0, 1);
    k = 0;
    while (k < 64) : (k += 1) try w.bits(if (k >= t.ones_from) 1 else 0, 1);
    try w.bits(0, 1); // no inverse move-to-front
    try w.bits(0, 1); // NTREESD = 1
    try w.simple(8, &.{t.lit0});
    try w.simple(8, &.{t.lit1});
    try w.simple(10, &.{c.sym});
    try w.simple(6, &.{0});
    try cmdExtra(w, c);
    // The block switch inside the insert.
    if (t.len_syms.len == 2) try w.bits(t.second_len_code, 1);
    try w.bits(t.second_len_extra, t.second_len_extra_bits);
    // Input behind the meta-block, for the hot loop to run.
    try w.metadata(100);
    try w.lastEmpty();
}

test "A1 m65: a literal block ending inside a long insert switches the tree at its end" {
    // Insert of 30 literals; block 0 (tree 'a') is 17 long, block 1 ('b')
    // has 17 too. The checkless loop must stop at the block's end (`@min`
    // with `block_length[0]`): then the switch selects 'b' for the last 13.
    // Without the bound it takes all 30 with the first tree, and the block
    // length counter (17) underflows.
    var w: W = .{};
    defer w.deinit();
    try twoTypesStream(&w, .{
        .insert = 30,
        .len_syms = &.{4}, // 17..24, 3 extra bits
        .first_len_code = 0,
        .first_len_extra = 0,
        .first_len_extra_bits = 3,
        .second_len_code = 0,
        .second_len_extra = 0,
        .second_len_extra_bits = 3,
        .ones_from = 0, // type 1: all trees 1
        .lit0 = 'a',
        .lit1 = 'b',
    });
    const want = (@as([17]u8, @splat('a'))) ++ (@as([13]u8, @splat('b')));
    try expectOut(w.bytes.items, .{}, &want);
}

test "A1 m66: a one-literal first block, then a context-mapped block, has no second byte back" {
    // Insert of 9: block 0 is 1 literal long (tree 'a'), then block 1 with a
    // context map that is not constant (so the checkless loop takes its
    // context path). It starts with one byte of output: the second byte back
    // is 0 (`len >= 2` false); with `>= 1` it reads `back(2)` before the
    // start of the output (a safety panic).
    var w: W = .{};
    defer w.deinit();
    try twoTypesStream(&w, .{
        .insert = 9,
        .len_syms = &.{ 0, 4 }, // 1..4 (2 extra bits), 17..24 (3 extra bits)
        .first_len_code = 0,
        .first_len_extra = 0,
        .first_len_extra_bits = 2, // length 1
        .second_len_code = 1,
        .second_len_extra = 0,
        .second_len_extra_bits = 3, // length 17
        .ones_from = 32, // type 1: half tree 0, half tree 1
        .lit0 = 'a',
        .lit1 = 'a',
    });
    try expectOut(w.bytes.items, .{}, &(@as([9]u8, @splat('a'))));
}

// --- mutant 48: a prefix-dictionary copy past the dictionary's end ------------

test "A1 m48: a copy running past the end of a raw dictionary continues in the window" {
    // RFC 9841 section 3.2. Dictionary "abcdefgh", a copy of 6 at distance 3
    // from the start of the output: the last 3 dictionary bytes "fgh", then 3
    // more from the window's start, which are those same 3 -- "fghfgh". Without
    // the `@min` the whole 6 are taken from the dictionary, past its end.
    var w: W = .{};
    defer w.deinit();
    const c = findCmd(0, 6, false);
    try w.window16();
    try w.lastCompressed(6);
    try plainHeader(&w);
    try w.simple(8, &.{'a'});
    try w.simple(10, &.{c.sym});
    try w.simple(6, &.{17}); // distance code 17: 3 + one extra bit
    try cmdExtra(&w, c);
    try w.bits(0, 1);
    try expectOut(w.bytes.items, .{ .dictionary = "abcdefgh" }, "fghfgh");
}

// --- mutant 50: large-window WBITS ---------------------------------------------

test "A1 m50: a large-window WBITS below 10 is InvalidWindowBits" {
    // RFC 9841 section 6: 1 000 001 0 then six bits of WBITS, 10..30.
    for ([_]u32{ 0, 9 }) |wb| {
        var w: W = .{};
        defer w.deinit();
        try w.bits(1, 1);
        try w.bits(0, 3);
        try w.bits(1, 3);
        try w.bits(0, 1);
        try w.bits(wb, 6);
        try w.lastEmpty();
        try expectErr(w.bytes.items, .{ .large_window = true }, error.InvalidWindowBits);
    }
    // 10 is the smallest allowed.
    var ok: W = .{};
    defer ok.deinit();
    try ok.bits(1, 1);
    try ok.bits(0, 3);
    try ok.bits(1, 3);
    try ok.bits(0, 1);
    try ok.bits(10, 6);
    try ok.lastEmpty();
    try expectOut(ok.bytes.items, .{ .large_window = true }, "");
}
