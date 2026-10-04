// SPDX-License-Identifier: MIT

//! Hand-built streams for the decoder's guards (mutation run 2026-10-04).
//!
//! Every stream here is written bit by bit from RFC 7932 (section numbers in
//! the comments), not produced by this module's encoder, so each expectation is
//! the RFC's verdict: either the exact bytes the stream decodes to, or the
//! error a conformant decoder has to give. The accept/reject verdicts of the
//! reference implementation (google/brotli, python `brotli` 1.2.0) were checked
//! for the same bytes when these tests were written. Each test names the
//! guard it exists for, and why that guard is needed.

const std = @import("std");
const testing = std.testing;
const brotli = @import("root.zig");
const tables = @import("tables.zig");
const dict = @import("dictionary.zig");

/// LSB-first bit writer (RFC 7932 section 1.5.1).
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
    /// A numeric field: `n` bits of `v`, least significant first.
    fn bits(w: *W, v: u32, n: u6) !void {
        var i: u6 = 0;
        while (i < n) : (i += 1) try w.bit(@truncate(v >> @intCast(i)));
    }
    /// A prefix code, most significant bit of the code first (section 3.1).
    fn msb(w: *W, v: u32, n: u6) !void {
        var i: u6 = n;
        while (i > 0) : (i -= 1) try w.bit(@truncate(v >> @intCast(i - 1)));
    }
    /// A code given as a string of '0'/'1', first character first.
    fn code(w: *W, s: []const u8) !void {
        for (s) |c| try w.bit(if (c == '1') 1 else 0);
    }
    fn pad(w: *W) !void {
        while (w.nbits % 8 != 0) try w.bit(0);
    }
    fn raw(w: *W, data: []const u8) !void {
        std.debug.assert(w.nbits % 8 == 0);
        try w.bytes.appendSlice(testing.allocator, data);
        w.nbits += data.len * 8;
    }

    // WBITS = 16 is one 0 bit; WBITS = 10 is 1, 000, 010 (section 9.1).
    fn window16(w: *W) !void {
        try w.bits(0, 1);
    }
    fn window10(w: *W) !void {
        try w.bits(1, 1);
        try w.bits(0, 3);
        try w.bits(2, 3);
    }
    /// ISLAST = 1, ISLASTEMPTY = 1 (section 9.2).
    fn lastEmpty(w: *W) !void {
        try w.bits(3, 2);
    }
    /// A stored meta-block of up to 65536 bytes: ISLAST 0, MNIBBLES 4,
    /// MLEN-1, ISUNCOMPRESSED 1, padding (sections 9.2, 9.2).
    fn stored(w: *W, data: []const u8) !void {
        try w.bits(0, 1);
        try w.bits(0, 2);
        try w.bits(@intCast(data.len - 1), 16);
        try w.bits(1, 1);
        try w.pad();
        try w.raw(data);
    }
    /// Header of the last, compressed meta-block of `mlen` <= 65536 bytes.
    fn lastCompressed(w: *W, mlen: u32) !void {
        try w.bits(1, 1);
        try w.bits(0, 1);
        try w.bits(0, 2);
        try w.bits(mlen - 1, 16);
    }
    /// A simple prefix code (section 3.4): HSKIP 1, NSYM-1, the symbols in
    /// `alphabet_bits` each, and the tree-select bit for four symbols.
    fn simple(w: *W, alphabet_bits: u6, syms: []const u16) !void {
        try w.bits(1, 2);
        try w.bits(@intCast(syms.len - 1), 2);
        for (syms) |s| try w.bits(s, alphabet_bits);
        if (syms.len == 4) try w.bits(0, 1);
    }
};

/// What a command symbol with these lengths looks like (section 5).
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

/// Decode `stream` with both decoders; they must give the same verdict.
fn expectOut(stream: []const u8, want: []const u8) !void {
    const got = try brotli.decompress(testing.allocator, stream, .{});
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, want, got);
    var in: std.Io.Reader = .fixed(stream);
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    _ = try brotli.decompressStream(testing.allocator, &in, &out.writer, .{});
    try testing.expectEqualSlices(u8, want, out.written());
}

fn expectErr(stream: []const u8, want: anyerror) !void {
    if (brotli.decompress(testing.allocator, stream, .{})) |ok| {
        testing.allocator.free(ok);
        return error.TestExpectedError;
    } else |e| try testing.expectEqual(want, @as(anyerror, e));
    var in: std.Io.Reader = .fixed(stream);
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    if (brotli.decompressStream(testing.allocator, &in, &out.writer, .{})) |_| {
        return error.TestExpectedError;
    } else |e| try testing.expectEqual(want, @as(anyerror, e));
}

// --- meta-block headers (section 9.2) ----------------------------------------

/// Metadata header with MSKIPBYTES = `nbytes`, then `skip` as the length.
fn metadata(w: *W, is_last: bool, reserved: u1, nbytes: u2, skip_minus_1: u32) !void {
    try w.bits(@intFromBool(is_last), 1);
    if (is_last) try w.bits(0, 1); // ISLASTEMPTY
    try w.bits(3, 2); // MNIBBLES = 0 nibbles: metadata
    try w.bits(reserved, 1);
    try w.bits(nbytes, 2);
    if (nbytes > 0) try w.bits(skip_minus_1, @as(u6, nbytes) * 8);
}

test "crafted: a metadata block with MSKIPBYTES 0 skips nothing" {
    // Guard: `skip_bytes == 0` returns a zero length. Without it the length
    // would be read as 0 + 1 and a byte of the next header would be skipped.
    var w: W = .{};
    defer w.deinit();
    try w.window16();
    try metadata(&w, false, 0, 0, 0);
    try w.pad();
    try w.lastEmpty();
    try expectOut(w.bytes.items, "");
}

test "crafted: a metadata block of one skipped byte whose length byte is 0 is valid" {
    // Section 9.2: the last MSKIPLEN byte must be nonzero only when
    // MSKIPBYTES > 1; with one byte, MSKIPLEN-1 = 0 means "skip 1 byte".
    var w: W = .{};
    defer w.deinit();
    try w.window16();
    try metadata(&w, false, 0, 1, 0);
    try w.pad();
    try w.raw(&.{0xAB});
    try w.lastEmpty();
    try expectOut(w.bytes.items, "");
}

test "crafted: a metadata block of 20 skipped bytes is skipped whole" {
    // The bit reader holds up to 8 bytes ahead; skipping more than that must
    // continue from the input, not from the accumulator.
    var w: W = .{};
    defer w.deinit();
    try w.window16();
    try metadata(&w, false, 0, 1, 19);
    try w.pad();
    try w.raw(&([_]u8{0xEE} ** 20));
    try w.lastEmpty();
    try expectOut(w.bytes.items, "");
}

test "crafted: a metadata block can be the last meta-block" {
    // Section 9.2: ISLAST may be set with MNIBBLES = 3 (metadata). The stream
    // ends there; reading another header would be a truncated stream.
    var w: W = .{};
    defer w.deinit();
    try w.window16();
    try metadata(&w, true, 0, 1, 2);
    try w.pad();
    try w.raw(&.{ 1, 2, 3 });
    try expectOut(w.bytes.items, "");
}

test "crafted: metadata with the reserved bit set, a zero top length byte, or nonzero padding is refused" {
    // Section 9.2: the reserved bit must be zero; with MSKIPBYTES > 1 the last
    // length byte must be nonzero; padding bits must be zero (section 9.2).
    {
        var w: W = .{};
        defer w.deinit();
        try w.window16();
        try metadata(&w, false, 1, 0, 0);
        try w.pad();
        try w.lastEmpty();
        try expectErr(w.bytes.items, error.ReservedBitSet);
    }
    {
        var w: W = .{};
        defer w.deinit();
        try w.window16();
        try metadata(&w, false, 0, 2, 5); // bytes 05 00
        try w.pad();
        try w.raw(&([_]u8{0} ** 6));
        try w.lastEmpty();
        try expectErr(w.bytes.items, error.InvalidLength);
    }
    {
        var w: W = .{};
        defer w.deinit();
        try w.window16();
        try metadata(&w, false, 0, 0, 0);
        try w.bit(1); // a set padding bit
        try w.pad();
        try w.lastEmpty();
        try expectErr(w.bytes.items, error.InvalidPadding);
    }
}

test "crafted: MLEN with five nibbles must not have a zero top nibble" {
    // Section 9.2: "if MNIBBLES is greater than 4, the last nibble must not be zero".
    var w: W = .{};
    defer w.deinit();
    try w.window16();
    try w.bits(0, 1); // ISLAST
    try w.bits(1, 2); // MNIBBLES 5
    try w.bits(5, 20); // MLEN-1 = 5, top nibble 0
    try w.bits(0, 1); // ISUNCOMPRESSED
    try expectErr(w.bytes.items, error.InvalidLength);
}

test "crafted: a stored meta-block with a set padding bit is refused" {
    var w: W = .{};
    defer w.deinit();
    try w.window16();
    try w.bits(0, 1);
    try w.bits(0, 2);
    try w.bits(0, 16); // MLEN-1 = 0
    try w.bits(1, 1); // ISUNCOMPRESSED
    try w.bit(1); // padding must be zero
    try w.pad();
    try w.raw(&.{'x'});
    try w.lastEmpty();
    try expectErr(w.bytes.items, error.InvalidPadding);
}

test "crafted: the large-window WBITS code (1 000 001) is refused" {
    // Section 9.1 reserves it; this decoder has no large-window support.
    var w: W = .{};
    defer w.deinit();
    try w.bits(1, 1);
    try w.bits(0, 3);
    try w.bits(1, 3);
    try w.lastEmpty();
    try expectErr(w.bytes.items, error.InvalidWindowBits);
}

test "crafted: a stored meta-block above the ratio floor and exactly at max_output" {
    // The ratio bound counts a stored block's own bytes as input (a 1.5 MiB
    // block in a 1.5 MiB stream is no bomb), and max_output == the output
    // size is accepted while one byte less is not.
    const n: u32 = 3 << 19; // 1.5 MiB
    var w: W = .{};
    defer w.deinit();
    try w.window16();
    try w.bits(0, 1); // ISLAST
    try w.bits(2, 2); // MNIBBLES 6
    try w.bits(n - 1, 24);
    try w.bits(1, 1); // ISUNCOMPRESSED
    try w.pad();
    const body = try testing.allocator.alloc(u8, n);
    defer testing.allocator.free(body);
    for (body, 0..) |*b, i| b.* = @truncate(i *% 7 +% 3);
    try w.raw(body);
    try w.lastEmpty();
    const exact: brotli.Options = .{ .max_output = n };
    const got = try brotli.decompress(testing.allocator, w.bytes.items, exact);
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, body, got);
    try testing.expectError(error.OutputTooLarge, brotli.decompress(testing.allocator, w.bytes.items, .{ .max_output = n - 1 }));
    var in: std.Io.Reader = .fixed(w.bytes.items);
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try testing.expectEqual(@as(u64, n), try brotli.decompressStream(testing.allocator, &in, &out.writer, exact));
    try testing.expectEqualSlices(u8, body, out.written());
    var in2: std.Io.Reader = .fixed(w.bytes.items);
    var out2: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out2.deinit();
    try testing.expectError(error.OutputTooLarge, brotli.decompressStream(testing.allocator, &in2, &out2.writer, .{ .max_output = n - 1 }));
}

// --- prefix codes (section 3) ---------------------------------------------------

/// One last meta-block of one command (insert 1, copy 2: command 8) whose
/// command tree is `cmd_syms`, the command written as `cmd_code`; the single
/// literal is 'a'. Used to put an unusual symbol list into the command tree.
fn oneLiteralStream(w: *W, cmd_syms: []const u16, cmd_code: []const u8) !void {
    try w.window16();
    try w.lastCompressed(1);
    try w.bits(0, 3); // NBLTYPESL/I/D = 1
    try w.bits(0, 6); // NPOSTFIX, NDIRECT
    try w.bits(0, 2); // context mode
    try w.bits(0, 1); // NTREESL = 1
    try w.bits(0, 1); // NTREESD = 1
    try w.simple(8, &.{'a'}); // literal tree
    try w.simple(10, cmd_syms); // command tree
    try w.simple(6, &.{0}); // distance tree
    try w.code(cmd_code);
}

test "crafted: a simple prefix code's symbols must be below the alphabet size" {
    // Section 3.4: symbols are ALPHABET_BITS wide, which for 704 command
    // symbols reaches 1023; 704 itself is not a symbol and must be refused
    // even if the stream never uses it.
    const c = findCmd(1, 2, true);
    var w: W = .{};
    defer w.deinit();
    try oneLiteralStream(&w, &.{ c.sym, 704 }, "0");
    try expectErr(w.bytes.items, error.InvalidHuffman);
    // Control: the same stream with a legal second symbol decodes.
    var ok: W = .{};
    defer ok.deinit();
    try oneLiteralStream(&ok, &.{ c.sym, 703 }, "0");
    try expectOut(ok.bytes.items, "a");
}

test "crafted: a simple prefix code with a repeated symbol is refused" {
    // Section 3.4: the symbols of a simple prefix code are distinct.
    const c = findCmd(1, 2, true);
    var w: W = .{};
    defer w.deinit();
    try oneLiteralStream(&w, &.{ c.sym, c.sym }, "0");
    try expectErr(w.bytes.items, error.DuplicateSimpleSymbol);
}

test "crafted: a complex prefix code whose code-length code has a single symbol" {
    // Section 3.5: when only one code-length code length is nonzero the
    // symbols' lengths are read with zero bits each. Here the only code-length
    // symbol is 8, so all 256 literals get length 8 (a complete code), and the
    // literal 'a' is its 8-bit canonical code (97).
    const c = findCmd(1, 2, true);
    var w: W = .{};
    defer w.deinit();
    try w.window16();
    try w.lastCompressed(1);
    try w.bits(0, 3);
    try w.bits(0, 6);
    try w.bits(0, 2);
    try w.bits(0, 1);
    try w.bits(0, 1);
    try w.bits(0, 2); // HSKIP 0: complex code
    // Code-length code lengths in the order 1 2 3 4 0 5 17 6 16 7 8 ...:
    // symbol 8 is the 11th. Length 0 is "00", length 1 is "0111" (as a
    // numeric field: 7 in 4 bits).
    var i: u32 = 0;
    while (i < 18) : (i += 1) {
        if (i == 10) try w.bits(7, 4) else try w.bits(0, 2);
    }
    try w.simple(10, &.{c.sym});
    try w.simple(6, &.{0});
    try w.msb('a', 8);
    try expectOut(w.bytes.items, "a");
}

// --- command-level semantics ---------------------------------------------------

test "crafted: literal block types follow section 6 (explicit, previous, next, wrap)" {
    // Six literals, each its own block after the first, over three literal
    // block types whose trees give 'x', 'y', 'z' (zero bits each). The block
    // type codes: 0 = the type before the last, 1 = last + 1 (wrapping at
    // NBLTYPES), n >= 2 = type n - 2 (section 6).
    // Sequence of types: 0 (initial), then 4 -> 2, 3 -> 1, 1 -> 1+1 = 2,
    // 1 -> 2+1 = 3 wraps to 0, 0 -> the type before the last = 2.
    const c = findCmd(6, 2, true);
    var w: W = .{};
    defer w.deinit();
    try w.window16();
    try w.lastCompressed(6);
    // NBLTYPESL = 3 (VarLenUint8 of 2: 1, 001, 0), type tree, length tree, first length.
    try w.bits(1, 1);
    try w.bits(1, 3);
    try w.bits(0, 1);
    try w.simple(3, &.{ 0, 1, 3, 4 }); // block type alphabet is NBLTYPES + 2 = 5 symbols
    try w.simple(5, &.{0}); // block count alphabet: 26 symbols; code 0 = 1..4
    try w.bits(0, 2); // first block: length 1
    try w.bits(0, 1); // NBLTYPESI = 1
    try w.bits(0, 1); // NBLTYPESD = 1
    try w.bits(0, 6);
    try w.bits(0, 6); // three context modes (LSB6)
    // NTREESL = 3: context map of 3 x 64 entries, block type t -> tree t.
    try w.bits(1, 1);
    try w.bits(1, 3);
    try w.bits(0, 1);
    try w.bits(0, 1); // RLEMAX 0
    try w.simple(2, &.{ 0, 1, 2 }); // 3 symbols: 0 = "0", 1 = "10", 2 = "11"
    const tree_codes = [_][]const u8{ "0", "10", "11" };
    for (tree_codes) |tc| {
        var k: u32 = 0;
        while (k < 64) : (k += 1) try w.code(tc);
    }
    try w.bits(0, 1); // IMTF off
    try w.bits(0, 1); // NTREESD = 1
    try w.simple(8, &.{'x'});
    try w.simple(8, &.{'y'});
    try w.simple(8, &.{'z'});
    try w.simple(10, &.{c.sym});
    try w.simple(6, &.{0});
    try w.bits(c.ins_v, @intCast(c.ins_n));
    try w.bits(c.cpy_v, @intCast(c.cpy_n));
    // x; then the type symbols 4, 3, 1, 1, 0 (codes 11, 10, 01, 01, 00 in the
    // sorted 4-symbol code over 0,1,3,4), each followed by a block of length 1.
    for ([_][]const u8{ "11", "10", "01", "01", "00" }) |s| {
        try w.code(s);
        try w.bits(0, 2);
    }
    try expectOut(w.bytes.items, "xzyzxz");
}

test "crafted: a literal context map whose only odd entry is the last one is not trivial" {
    // Two literal trees ('?' and 'Z'); context map entry 63 selects tree 1 and
    // the other 63 select tree 0. In mode LSB6 the context is P1 & 63, so after
    // '?' (0x3F) the next literal uses context 63 -> 'Z'. Treating the map as
    // trivial (all entries equal) would give "??".
    const c = findCmd(2, 2, true);
    var w: W = .{};
    defer w.deinit();
    try w.window16();
    try w.lastCompressed(2);
    try w.bits(0, 3);
    try w.bits(0, 6);
    try w.bits(0, 2); // LSB6
    try w.bits(1, 1); // NTREESL = 2 (VarLenUint8 of 1: 1, 000)
    try w.bits(0, 3);
    try w.bits(0, 1); // RLEMAX 0
    try w.simple(1, &.{ 0, 1 });
    var k: u32 = 0;
    while (k < 63) : (k += 1) try w.code("0");
    try w.code("1");
    try w.bits(0, 1); // IMTF off
    try w.bits(0, 1); // NTREESD = 1
    try w.simple(8, &.{'?'});
    try w.simple(8, &.{'Z'});
    try w.simple(10, &.{c.sym});
    try w.simple(6, &.{0});
    try w.bits(c.ins_v, @intCast(c.ins_n));
    try w.bits(c.cpy_v, @intCast(c.cpy_n));
    try expectOut(w.bytes.items, "?Z");
}

/// Bits of an explicit-distance command for a last meta-block whose only
/// command copies `copy_len` bytes at the distance made of `dcode` and its
/// `dn` extra bits `dv`; the distance tree holds just `dcode`.
fn dictStream(w: *W, mlen: u32, copy_len: u32, dcode: u16, dn: u6, dv: u32) !void {
    const c = findCmd(0, copy_len, false);
    try w.window16();
    try w.lastCompressed(mlen);
    try w.bits(0, 3);
    try w.bits(0, 6);
    try w.bits(0, 2);
    try w.bits(0, 1);
    try w.bits(0, 1);
    try w.simple(8, &.{'a'});
    try w.simple(10, &.{c.sym});
    try w.simple(6, &.{dcode});
    try w.bits(c.ins_v, @intCast(c.ins_n));
    try w.bits(c.cpy_v, @intCast(c.cpy_n));
    try w.bits(dv, dn);
}

test "crafted: a static dictionary reference of the longest word length (24)" {
    // Section 8: words have 4..24 bytes. At the start of the stream distance 1
    // exceeds the (empty) history, so it is dictionary address 0 of the
    // length-24 bucket, transform 0: that bucket's first word, copied whole.
    // Distance code 16 has one extra bit (section 4): distance = bit + 1.
    var w: W = .{};
    defer w.deinit();
    try dictStream(&w, 24, 24, 16, 1, 0);
    const off = dict.offsets_by_length[24];
    try expectOut(w.bytes.items, dict.data[off..][0..24]);
}

test "crafted: dictionary transform index 121 does not exist" {
    // Section 8: there are 121 transforms (0..120). Copy length 4 has 1024
    // words (10 bits), so transform index = address >> 10. Distance
    // 123905 = 1 + 121 * 1024 + 0 with the history empty -> index 121.
    // Distance code 45: NDISTBITS = 1 + (29 >> 1) = 15, HCODE odd, offset
    // (3 << 15) - 4 = 98300; extra = 123904 - 98300 (section 4).
    var w: W = .{};
    defer w.deinit();
    try dictStream(&w, 4, 4, 45, 15, 123904 - 98300);
    try expectErr(w.bytes.items, error.InvalidDictionary);
}

test "crafted: an unusable ring-buffer distance is InvalidDistance, not a dictionary miss" {
    // Section 4: distance code 8 is "last distance - 3". After a copy at
    // distance 1 that is -2, an invalid distance. The decoder must say so
    // (InvalidDistance), not fall through to a dictionary reference (a 2-byte
    // copy would then be InvalidDictionary).
    const c1 = findCmd(1, 2, false);
    const c2 = findCmd(0, 2, false);
    // Command symbols sorted: the smaller one is code "0".
    const first_is_c1 = c1.sym < c2.sym;
    var w: W = .{};
    defer w.deinit();
    try w.window16();
    try w.lastCompressed(5);
    try w.bits(0, 3);
    try w.bits(0, 6);
    try w.bits(0, 2);
    try w.bits(0, 1);
    try w.bits(0, 1);
    try w.simple(8, &.{'a'});
    try w.simple(10, if (first_is_c1) &.{ c1.sym, c2.sym } else &.{ c2.sym, c1.sym });
    try w.simple(6, &.{ 8, 16 }); // code 8 = "0", code 16 = "1"
    // Command 1: insert 'a', copy 2 at distance 1 (code 16, extra bit 0).
    try w.code(if (first_is_c1) "0" else "1");
    try w.bits(c1.ins_v, @intCast(c1.ins_n));
    try w.bits(c1.cpy_v, @intCast(c1.cpy_n));
    try w.code("1");
    try w.bits(0, 1);
    // Command 2: copy 2 at distance code 8.
    try w.code(if (first_is_c1) "1" else "0");
    try w.bits(c2.ins_v, @intCast(c2.ins_n));
    try w.bits(c2.cpy_v, @intCast(c2.cpy_n));
    try w.code("0");
    try expectErr(w.bytes.items, error.InvalidDistance);
}

test "crafted: an implicit last distance that reaches the dictionary leaves the ring unchanged" {
    // At the start the ring of last distances is 16, 15, 11, 4 (section 4), so
    // "last distance" is 4. After the literals "ab" the history is 2 bytes:
    // distance 4 > 2 is a dictionary reference, address 4 - 2 - 1 = 1: word 1
    // of the length-4 bucket, transform 0. A dictionary reference does not
    // push onto the ring, so the next command (copy 4 at the implicit last
    // distance, now 4 <= 6 bytes of history) copies that word again.
    const ca = findCmd(2, 4, true);
    const cb = findCmd(0, 4, true);
    const a_first = cb.sym > ca.sym; // sorted: smaller symbol is "0"
    var w: W = .{};
    defer w.deinit();
    try w.window16();
    try w.lastCompressed(10);
    try w.bits(0, 3);
    try w.bits(0, 6);
    try w.bits(0, 2);
    try w.bits(0, 1);
    try w.bits(0, 1);
    try w.simple(8, &.{ 'a', 'b' });
    try w.simple(10, if (a_first) &.{ ca.sym, cb.sym } else &.{ cb.sym, ca.sym });
    try w.simple(6, &.{0});
    try w.code(if (a_first) "0" else "1"); // command A
    try w.bits(ca.ins_v, @intCast(ca.ins_n));
    try w.bits(ca.cpy_v, @intCast(ca.cpy_n));
    try w.code("0"); // 'a'
    try w.code("1"); // 'b'
    try w.code(if (a_first) "1" else "0"); // command B
    try w.bits(cb.ins_v, @intCast(cb.ins_n));
    try w.bits(cb.cpy_v, @intCast(cb.cpy_n));
    const word = dict.data[dict.offsets_by_length[4] + 4 ..][0..4];
    var want: [10]u8 = undefined;
    @memcpy(want[0..2], "ab");
    @memcpy(want[2..6], word);
    @memcpy(want[6..10], word);
    try expectOut(w.bytes.items, &want);
}

/// A 1100-byte stored meta-block, then a last compressed one whose only
/// command copies 4 bytes at `dist` (distance code 31: NDISTBITS 8, offset
/// (3 << 8) - 4 = 764, so distance = 764 + extra + 1).
fn windowEdgeStream(w: *W, history: []const u8, dist: u32) !void {
    const c = findCmd(0, 4, false);
    try w.window10();
    try w.stored(history);
    try w.lastCompressed(4);
    try w.bits(0, 3);
    try w.bits(0, 6);
    try w.bits(0, 2);
    try w.bits(0, 1);
    try w.bits(0, 1);
    try w.simple(8, &.{'a'});
    try w.simple(10, &.{c.sym});
    try w.simple(6, &.{31});
    try w.bits(c.ins_v, @intCast(c.ins_n));
    try w.bits(c.cpy_v, @intCast(c.cpy_n));
    try w.bits(dist - 765, 8);
}

test "crafted: with WBITS 10 the farthest backward distance is 1024 - 16 = 1008" {
    // Section 9.1: the window is (1 << WBITS) - 16 bytes. Distance 1008 is
    // still a backward copy; 1009 is past the window, hence a static
    // dictionary reference (section 8): address 1009 - 1008 - 1 = 0, word 0
    // of the length-4 bucket.
    var history: [1100]u8 = undefined;
    for (&history, 0..) |*b, i| b.* = @truncate(i *% 7 +% 3);
    var want: [1104]u8 = undefined;
    @memcpy(want[0..1100], &history);
    {
        var w: W = .{};
        defer w.deinit();
        try windowEdgeStream(&w, &history, 1008);
        @memcpy(want[1100..], history[1100 - 1008 ..][0..4]);
        try expectOut(w.bytes.items, &want);
    }
    {
        var w: W = .{};
        defer w.deinit();
        try windowEdgeStream(&w, &history, 1009);
        @memcpy(want[1100..], dict.data[dict.offsets_by_length[4]..][0..4]);
        try expectOut(w.bytes.items, &want);
    }
}

// --- streaming specifics --------------------------------------------------------

test "crafted: stream: a stored block longer than the ring's free tail is written out, not overwritten" {
    // WBITS 10 gives a 1 KiB ring. A 300-byte stored block leaves the write
    // position at 300; the next 1400-byte block must wrap after 724 bytes and
    // then stop at the 300 bytes that are still unwritten.
    var data: [1700]u8 = undefined;
    // Not periodic with the ring size: a byte lost to an overwrite must show.
    for (&data, 0..) |*b, i| b.* = @truncate(i *% 13 +% (i >> 8) +% 5);
    var w: W = .{};
    defer w.deinit();
    try w.window10();
    try w.stored(data[0..300]);
    try w.stored(data[300..1700]);
    try w.lastEmpty();
    try expectOut(w.bytes.items, &data);
}

test "crafted: stream: output reaches the writer at the end of each meta-block" {
    // The first meta-block is complete, the second is cut off: the stream
    // fails, but the first meta-block's bytes are already written.
    var w: W = .{};
    defer w.deinit();
    try w.window16();
    try w.stored("0123456789");
    try w.bits(0, 1);
    try w.bits(0, 2);
    try w.bits(99, 16);
    try w.bits(1, 1);
    try w.pad();
    try w.raw("short");
    var in: std.Io.Reader = .fixed(w.bytes.items);
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try testing.expectError(error.TruncatedInput, brotli.decompressStream(testing.allocator, &in, &out.writer, .{}));
    try testing.expectEqualStrings("0123456789", out.written());
}

test "crafted: stream: bytes after the stream stay in the reader (at most 8 are read ahead)" {
    // decompressStream's contract: it may consume up to 8 bytes past the end
    // of the stream, no more, and gives the rest back.
    const comp = @embedFile("testdata/quickfox.compressed");
    var all: [comp.len + 100]u8 = undefined;
    @memcpy(all[0..comp.len], comp);
    @memset(all[comp.len..], 0xEE);
    var in: std.Io.Reader = .fixed(&all);
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    _ = try brotli.decompressStream(testing.allocator, &in, &out.writer, .{});
    const left = in.bufferedLen();
    try testing.expect(left <= 100);
    try testing.expect(left >= 100 - 8);
    try testing.expectEqual(@as(u8, 0xEE), try in.peekByte());
}

test "crafted: commands that produce more than MLEN bytes are refused (insert, copy, dictionary word)" {
    // RFC 7932 section 9.2: the commands of a meta-block produce exactly MLEN
    // bytes. The reference decoder rejects each of these streams
    // (BROTLI_DECODER_ERROR_FORMAT_BLOCK_LENGTH); they used to decode to more
    // bytes than MLEN.
    // (a) MLEN = 1, the command inserts 2 literals.
    {
        const c = findCmd(2, 2, true);
        var w: W = .{};
        defer w.deinit();
        try w.window16();
        try w.lastCompressed(1);
        try w.bits(0, 3);
        try w.bits(0, 6);
        try w.bits(0, 2);
        try w.bits(0, 1);
        try w.bits(0, 1);
        try w.simple(8, &.{'a'});
        try w.simple(10, &.{c.sym});
        try w.simple(6, &.{0});
        try expectErr(w.bytes.items, error.InvalidLength);
    }
    // (b) MLEN = 2: insert 1 literal, then copy 2 bytes at distance 1.
    {
        const c = findCmd(1, 2, false);
        var w: W = .{};
        defer w.deinit();
        try w.window16();
        try w.lastCompressed(2);
        try w.bits(0, 3);
        try w.bits(0, 6);
        try w.bits(0, 2);
        try w.bits(0, 1);
        try w.bits(0, 1);
        try w.simple(8, &.{'a'});
        try w.simple(10, &.{c.sym});
        try w.simple(6, &.{16});
        try w.bits(c.ins_v, @intCast(c.ins_n));
        try w.bits(c.cpy_v, @intCast(c.cpy_n));
        try w.bits(0, 1); // distance 1
        try expectErr(w.bytes.items, error.InvalidLength);
    }
    // (c) MLEN = 2: a 4-byte dictionary word.
    {
        var w: W = .{};
        defer w.deinit();
        try dictStream(&w, 2, 4, 16, 1, 0);
        try expectErr(w.bytes.items, error.InvalidLength);
    }
    // Control: MLEN = 4 takes the same dictionary word.
    {
        var w: W = .{};
        defer w.deinit();
        try dictStream(&w, 4, 4, 16, 1, 0);
        try expectOut(w.bytes.items, dict.data[dict.offsets_by_length[4]..][0..4]);
    }
}

test "crafted: stream: a compressed meta-block longer than the ring wraps without losing unwritten bytes" {
    // WBITS 10 (1 KiB ring), nothing written out yet when the ring fills:
    // the meta-block inserts "abc" and copies 1500 bytes at distance 3 (the
    // pattern has period 3, which does not divide 1024, so a byte overwritten
    // before it was written out changes the result).
    const c = findCmd(3, 1500, false);
    var w: W = .{};
    defer w.deinit();
    try w.window10();
    try w.lastCompressed(1503);
    try w.bits(0, 3);
    try w.bits(0, 6);
    try w.bits(0, 2);
    try w.bits(0, 1);
    try w.bits(0, 1);
    try w.simple(8, &.{ 'a', 'b', 'c' }); // 'a' = "0", 'b' = "10", 'c' = "11"
    try w.simple(10, &.{c.sym});
    try w.simple(6, &.{17}); // distance code 17: one extra bit, distance 3 + bit
    try w.bits(c.ins_v, @intCast(c.ins_n));
    try w.bits(c.cpy_v, @intCast(c.cpy_n));
    try w.code("0");
    try w.code("10");
    try w.code("11");
    try w.bits(0, 1);
    var want: [1503]u8 = undefined;
    for (&want, 0..) |*b, i| b.* = "abc"[i % 3];
    try expectOut(w.bytes.items, &want);
}

test "crafted: a complex prefix code with a single used symbol is refused" {
    // Section 3.5: a complex code must be complete (code lengths use up the
    // whole code space), so one symbol of length 8 is not valid; a single
    // symbol is what the simple code (NSYM = 1) is for. The code-length code
    // here has the symbols 0 ("0") and 8 ("1"), both of length 1.
    const c = findCmd(1, 2, true);
    var w: W = .{};
    defer w.deinit();
    try w.window16();
    try w.lastCompressed(1);
    try w.bits(0, 3);
    try w.bits(0, 6);
    try w.bits(0, 2);
    try w.bits(0, 1);
    try w.bits(0, 1);
    try w.bits(0, 2); // HSKIP 0: complex code
    // Order 1 2 3 4 0 5 17 6 16 7 8: symbol 0 is the 5th, symbol 8 the 11th.
    // The space is used up at the 11th, so the list ends there.
    var i: u32 = 0;
    while (i < 11) : (i += 1) {
        if (i == 4 or i == 10) try w.bits(7, 4) else try w.bits(0, 2);
    }
    i = 0;
    while (i < 256) : (i += 1) try w.code(if (i == 'a') "1" else "0");
    try w.simple(10, &.{c.sym});
    try w.simple(6, &.{0});
    try expectErr(w.bytes.items, error.InvalidHuffman);
}
